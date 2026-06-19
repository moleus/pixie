/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * pixie-jsse demo collector ("mini-PEM").
 *
 * Loads jsse_collector.bpf.o, attaches a uprobe to
 *   <libpixie_jsse.so>:pixie_jsse_plaintext
 * and consumes decrypted JVM/Kafka TLS plaintext from a ring buffer. It does
 * per-connection (per-fd) reassembly and a best-effort decode of the Kafka wire
 * protocol, printing one "row" per request/response — the same shape Pixie's
 * kafka_events table stores. This stands in for the full Stirling pipeline so
 * the end-to-end approach can be demonstrated without building all of Pixie.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_DATA 4096
struct jsse_event {
  unsigned long fd;
  unsigned int direction;  // 0 = egress (broker->client, response), 1 = ingress (client->broker, request)
  unsigned int len;
  unsigned int cap;
  unsigned int tgid;
  unsigned char data[MAX_DATA];
};

/* ----------------------------- Kafka decoding ---------------------------- */

static const char *kafka_api_name(int16_t key) {
  switch (key) {
    case 0: return "Produce";
    case 1: return "Fetch";
    case 2: return "ListOffsets";
    case 3: return "Metadata";
    case 8: return "OffsetCommit";
    case 9: return "OffsetFetch";
    case 10: return "FindCoordinator";
    case 11: return "JoinGroup";
    case 12: return "Heartbeat";
    case 14: return "SyncGroup";
    case 15: return "DescribeGroups";
    case 16: return "ListGroups";
    case 17: return "SaslHandshake";
    case 18: return "ApiVersions";
    case 19: return "CreateTopics";
    case 20: return "DeleteTopics";
    case 22: return "InitProducerId";
    case 36: return "SaslAuthenticate";
    case 60: return "DescribeCluster";
    default: return "Api";
  }
}

static int16_t rd16(const unsigned char *p) { return (int16_t)((p[0] << 8) | p[1]); }
static int32_t rd32(const unsigned char *p) {
  return (int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]);
}

/* Print up to n bytes as a single-line "printable" preview ('.' for non-print). */
static void print_preview(const unsigned char *p, int n, int max) {
  int lim = n < max ? n : max;
  for (int i = 0; i < lim; i++) {
    unsigned char c = p[i];
    putchar((c >= 0x20 && c < 0x7f) ? c : '.');
  }
  if (n > max) printf("...");
}

/* Pull out readable ASCII runs (len>=3) — surfaces topic names & message values. */
static void print_strings(const unsigned char *p, int n, int max_runs) {
  int runs = 0, i = 0;
  while (i < n && runs < max_runs) {
    int j = i;
    while (j < n && p[j] >= 0x20 && p[j] < 0x7f) j++;
    if (j - i >= 3) {
      printf("%s'", runs ? " " : "");
      for (int k = i; k < j; k++) putchar(p[k]);
      printf("'");
      runs++;
    }
    i = (j > i) ? j : i + 1;
  }
}

/* Is this a Kafka API key we explicitly recognize (not the default)? Used to
 * decide whether a frame is a request (starts with api_key) vs a response. */
static int known_api(int16_t key) {
  return key >= 0 && key <= 74 && strcmp(kafka_api_name(key), "Api") != 0;
}

/*
 * Per-fd state: a reassembly buffer per direction, plus a set of outstanding
 * correlation IDs (the request's api keyed by corr). Kafka stitches
 * request/response by correlation ID, and the broker has BOTH client-role and
 * server-role TLS connections (single-node KRaft talks to itself), so we must
 * pair by corr id rather than trust read=request/write=response.
 */
#define MAX_CONNS 512
#define REASM_CAP (1 << 20)
#define OUT_SLOTS 2048
struct conn {
  int in_use;
  unsigned long fd;
  unsigned char *buf[2];  // [0]=egress, [1]=ingress
  int len[2];
  struct { int32_t corr; int16_t api; int used; } out[OUT_SLOTS];  // outstanding requests
};
static struct conn conns[MAX_CONNS];

static void out_put(struct conn *c, int32_t corr, int16_t api) {
  unsigned h = ((unsigned)corr) & (OUT_SLOTS - 1);
  c->out[h].corr = corr; c->out[h].api = api; c->out[h].used = 1;
}
static int16_t out_take(struct conn *c, int32_t corr) {
  unsigned h = ((unsigned)corr) & (OUT_SLOTS - 1);
  if (c->out[h].used && c->out[h].corr == corr) { c->out[h].used = 0; return c->out[h].api; }
  return -1;
}

static struct conn *get_conn(unsigned long fd) {
  int free_slot = -1;
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].in_use && conns[i].fd == fd) return &conns[i];
    if (!conns[i].in_use && free_slot < 0) free_slot = i;
  }
  if (free_slot < 0) free_slot = (int)(fd % MAX_CONNS);  // evict
  struct conn *c = &conns[free_slot];
  if (!c->buf[0]) { c->buf[0] = malloc(REASM_CAP); c->buf[1] = malloc(REASM_CAP); }
  c->in_use = 1; c->fd = fd; c->len[0] = c->len[1] = 0;
  memset(c->out, 0, sizeof(c->out));
  return c;
}

static uint64_t now_ms(void) {
  struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Decode one fully-reassembled Kafka frame body (without the 4-byte size
 * prefix). We don't trust the transport direction for req/resp; instead:
 *   - If body[0:4] is an outstanding correlation id  -> RESPONSE.
 *   - Else if body[0:2] is a known api_key           -> REQUEST.
 *   - Else                                           -> unrecognized frame.
 */
static void decode_frame(struct conn *c, const unsigned char *body, int blen) {
  uint64_t t = now_ms();
  if (blen < 4) return;

  int32_t resp_corr = rd32(body);
  int16_t paired_api = out_take(c, resp_corr);

  if (paired_api >= 0) {  // RESPONSE
    printf("%lu  fd=%-3lu  encrypted=TRUE  dir=RESP  cmd=%-14s corr=%-7d client=%-18s resp=[",
           (unsigned long)t, c->fd, kafka_api_name(paired_api), resp_corr, "-");
    print_strings(body + 4, blen - 4, 8);
    printf("]  bytes=\"");
    print_preview(body + 4, blen - 4, 56);
    printf("\"\n");
    fflush(stdout);
    return;
  }

  int16_t api = rd16(body);
  int16_t ver = rd16(body + 2);
  if (blen >= 8 && known_api(api) && ver >= 0 && ver < 18) {  // REQUEST
    int32_t corr = rd32(body + 4);
    int off = 8;
    char client[128] = "";
    if (blen >= off + 2) {
      int16_t clen = rd16(body + off);
      off += 2;
      if (clen > 0 && off + clen <= blen) {
        int n = clen < (int)sizeof(client) - 1 ? clen : (int)sizeof(client) - 1;
        memcpy(client, body + off, n); client[n] = 0; off += clen;
      }
    }
    out_put(c, corr, api);
    printf("%lu  fd=%-3lu  encrypted=TRUE  dir=REQ   cmd=%-14s corr=%-7d client=%-18s req=[",
           (unsigned long)t, c->fd, kafka_api_name(api), corr, client[0] ? client : "-");
    print_strings(body + off, blen - off, 8);
    printf("]  bytes=\"");
    print_preview(body + off, blen - off, 56);
    printf("\"\n");
    fflush(stdout);
    return;
  }

  // Unrecognized framing — still surface any readable content (proves plaintext).
  printf("%lu  fd=%-3lu  encrypted=TRUE  dir=?     kafka-frame (%d bytes) strings=[",
         (unsigned long)t, c->fd, blen);
  print_strings(body, blen, 10);
  printf("]\n");
  fflush(stdout);
}

/* Append data to a per-fd/per-direction stream and extract size-prefixed frames. */
static void ingest(unsigned long fd, int dir, const unsigned char *data, int n) {
  struct conn *c = get_conn(fd);
  int idx = dir;  // 0 egress, 1 ingress
  if (c->len[idx] + n > REASM_CAP) c->len[idx] = 0;  // overflow guard: resync
  memcpy(c->buf[idx] + c->len[idx], data, n);
  c->len[idx] += n;

  int consumed = 0;
  while (c->len[idx] - consumed >= 4) {
    const unsigned char *p = c->buf[idx] + consumed;
    int32_t size = rd32(p);
    if (size <= 0 || size > REASM_CAP) {  // not size-prefixed / garbage: resync
      consumed = c->len[idx];
      break;
    }
    if (c->len[idx] - consumed - 4 < size) break;  // wait for more
    decode_frame(c, p + 4, size);
    consumed += 4 + size;
  }
  if (consumed > 0) {
    memmove(c->buf[idx], c->buf[idx] + consumed, c->len[idx] - consumed);
    c->len[idx] -= consumed;
  }
}

/* ------------------------------- plumbing -------------------------------- */

static volatile int stop;
static void on_sig(int s) { stop = 1; }
static int verbose_hex = 0;

static int handle_event(void *ctx, void *data, size_t sz) {
  struct jsse_event *e = data;
  int n = e->cap < MAX_DATA ? e->cap : MAX_DATA;
  if (verbose_hex) {
    printf("[raw] tgid=%u fd=%lu dir=%s len=%u hex=", e->tgid, e->fd,
           e->direction ? "INGRESS" : "EGRESS", e->len);
    int hn = n < 32 ? n : 32;
    for (int i = 0; i < hn; i++) printf("%02x ", e->data[i]);
    printf("| \"");
    print_preview(e->data, n, 48);
    printf("\"\n");
  }
  ingest(e->fd, e->direction ? 1 : 0, e->data, n);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <path-to-libpixie_jsse.so> [seconds] [--hex]\n", argv[0]);
    return 1;
  }
  const char *lib = argv[1];
  int seconds = 0;
  for (int i = 2; i < argc; i++) {
    if (!strcmp(argv[i], "--hex")) verbose_hex = 1;
    else seconds = atoi(argv[i]);
  }

  struct bpf_object *obj = bpf_object__open_file("jsse_collector.bpf.o", NULL);
  if (!obj) { fprintf(stderr, "open failed\n"); return 1; }
  if (bpf_object__load(obj)) { fprintf(stderr, "load failed errno=%d\n", errno); return 1; }

  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "probe_entry_jsse_plaintext");
  LIBBPF_OPTS(bpf_uprobe_opts, uo, .func_name = "pixie_jsse_plaintext", .retprobe = false);
  struct bpf_link *link = bpf_program__attach_uprobe_opts(prog, -1, lib, 0, &uo);
  if (!link) { fprintf(stderr, "attach failed errno=%d on %s\n", errno, lib); return 1; }

  fprintf(stderr, "[collector] attached to %s:pixie_jsse_plaintext\n", lib);
  fprintf(stderr, "[collector] decoding Kafka over TLS (plaintext) ...\n\n");

  struct ring_buffer *rb =
      ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"), handle_event, NULL, NULL);
  if (!rb) { fprintf(stderr, "ringbuf failed\n"); return 1; }

  signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGALRM, on_sig);
  if (seconds > 0) alarm(seconds);
  while (!stop) {
    int n = ring_buffer__poll(rb, 200);
    if (n < 0 && n != -EINTR) break;
  }
  fprintf(stderr, "\n[collector] stopped\n");
  return 0;
}
