/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * pixie-jsse demo collector ("mini-PEM").
 *
 * Loads jsse_collector.bpf.o, attaches a uprobe to
 *   <libpixie_jsse.so>:pixie_jsse_plaintext
 * and consumes decrypted JVM/Kafka TLS plaintext from a ring buffer. It does
 * per-connection (per-fd) reassembly, correlation-id pairing, and a real
 * structured decode of the Kafka wire protocol (see kafka_parser.h) — descending
 * into Produce requests / Fetch responses down to individual records
 * (key/value). This stands in for the full Stirling pipeline so the end-to-end
 * approach is demonstrable without building all of Pixie.
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

#include "kafka_parser.h"

#define MAX_DATA 32768
struct jsse_event {
  unsigned long fd;
  unsigned int direction;  // 0 = egress, 1 = ingress
  unsigned int len;        // original plaintext length
  unsigned int cap;        // bytes actually captured (<= MAX_DATA)
  unsigned int tgid;
  unsigned char data[MAX_DATA];
};

static int verbose_hex = 0;

static int16_t rd16(const unsigned char *p) { return (int16_t)((p[0] << 8) | p[1]); }
static int32_t rd32(const unsigned char *p) {
  return (int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]);
}

/* Print up to max bytes as a single-line printable preview ('.' for non-print). */
static void print_preview(const unsigned char *p, int n, int max) {
  int lim = n < max ? n : max;
  for (int i = 0; i < lim; i++) {
    unsigned char c = p[i];
    putchar((c >= 0x20 && c < 0x7f) ? c : '.');
  }
  if (n > max) printf("...");
}

/* Print a key/value field: quoted text if printable, else a short hex note. */
static void print_field(const uint8_t *p, int n) {
  if (p == NULL) { printf("<null>"); return; }
  if (n == 0) { printf("\"\""); return; }
  int printable = 1, lim = n < 64 ? n : 64;
  for (int i = 0; i < lim; i++) if (p[i] < 0x20 || p[i] >= 0x7f) { printable = 0; break; }
  if (printable) {
    putchar('"');
    for (int i = 0; i < lim; i++) putchar(p[i]);
    if (n > lim) printf("...");
    putchar('"');
  } else {
    printf("<%d bytes: ", n);
    for (int i = 0; i < (n < 8 ? n : 8); i++) printf("%02x", p[i]);
    printf("...>");
  }
}

/* ----------------------- per-fd reassembly + pairing --------------------- */

static int known_api(int16_t key) {
  return key >= 0 && key <= 74 && strcmp(kafka_api_name(key), "Api") != 0;
}

#define MAX_CONNS 512
#define REASM_CAP (1 << 20)
#define OUT_SLOTS 2048
struct conn {
  int in_use;
  unsigned long fd;
  unsigned char *buf[2];  // [0]=egress, [1]=ingress
  int len[2];
  struct { int32_t corr; int16_t api; int16_t ver; int used; } out[OUT_SLOTS];
};
static struct conn conns[MAX_CONNS];

static void out_put(struct conn *c, int32_t corr, int16_t api, int16_t ver) {
  unsigned h = ((unsigned)corr) & (OUT_SLOTS - 1);
  c->out[h].corr = corr; c->out[h].api = api; c->out[h].ver = ver; c->out[h].used = 1;
}
static int out_take(struct conn *c, int32_t corr, int16_t *api, int16_t *ver) {
  unsigned h = ((unsigned)corr) & (OUT_SLOTS - 1);
  if (c->out[h].used && c->out[h].corr == corr) {
    *api = c->out[h].api; *ver = c->out[h].ver; c->out[h].used = 0; return 1;
  }
  return 0;
}

static struct conn *get_conn(unsigned long fd) {
  int free_slot = -1;
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].in_use && conns[i].fd == fd) return &conns[i];
    if (!conns[i].in_use && free_slot < 0) free_slot = i;
  }
  if (free_slot < 0) free_slot = (int)(fd % MAX_CONNS);
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

/* record callback: prints one indented row per Kafka record (the actual msg). */
struct row_ctx { unsigned long fd; };
static void record_cb(void *vctx, const char *topic, int32_t partition,
                      const uint8_t *key, int klen, const uint8_t *val, int vlen) {
  struct row_ctx *rc = (struct row_ctx *)vctx;
  printf("        ↳ fd=%-3lu topic=%-12s part=%d key=", rc->fd, topic, partition);
  print_field(key, klen);
  printf(" value=");
  print_field(val, vlen);
  printf("\n");
}

/*
 * Decode one reassembled Kafka frame (body without the 4-byte length prefix).
 * req/resp is determined by correlation-id pairing, not transport direction
 * (single-node KRaft makes the broker a TLS client to itself).
 */
static void decode_frame(struct conn *c, const unsigned char *body, int blen) {
  uint64_t t = now_ms();
  if (blen < 4) return;

  int32_t resp_corr = rd32(body);
  int16_t paired_api = -1, paired_ver = 0;

  if (out_take(c, resp_corr, &paired_api, &paired_ver)) {  // RESPONSE
    printf("%lu  fd=%-3lu  encrypted=TRUE  RESP  cmd=%-15s v%-2d corr=%-7d\n",
           (unsigned long)t, c->fd, kafka_api_name(paired_api), paired_ver, resp_corr);
    if (paired_api == KAPI_FETCH) {
      kafka_req_hdr_t h; memset(&h, 0, sizeof(h));
      struct row_ctx rc = { c->fd };
      kafka_parse_fetch_response(body, blen, paired_ver, record_cb, &rc, &h);
      if (h.compressed)
        printf("        ↳ (records compressed, codec=%d — not decoded)\n", h.compressed);
    }
    fflush(stdout);
    return;
  }

  kafka_req_hdr_t h;
  if (kafka_parse_request_header(body, blen, &h) == 0 && known_api(h.api_key) &&
      h.api_version >= 0 && h.api_version <= kafka_max_version(h.api_key)) {  // REQUEST
    out_put(c, h.correlation_id, h.api_key, h.api_version);
    printf("%lu  fd=%-3lu  encrypted=TRUE  REQ   cmd=%-15s v%-2d corr=%-7d client=%s\n",
           (unsigned long)t, c->fd, kafka_api_name(h.api_key), h.api_version, h.correlation_id,
           h.client_id[0] ? h.client_id : "-");
    if (h.api_key == KAPI_PRODUCE) {
      struct row_ctx rc = { c->fd };
      kafka_parse_produce(body, blen, &h, record_cb, &rc);
      if (h.compressed)
        printf("        ↳ (records compressed, codec=%d — not decoded)\n", h.compressed);
    }
    fflush(stdout);
    return;
  }

  // Unrecognized frame — still note it (proves we have plaintext).
  printf("%lu  fd=%-3lu  encrypted=TRUE  ????  kafka-frame (%d bytes) preview=\"",
         (unsigned long)t, c->fd, blen);
  print_preview(body, blen, 48);
  printf("\"\n");
  fflush(stdout);
}

/* Append data to a per-fd/per-direction stream; extract size-prefixed frames. */
static void ingest(unsigned long fd, int dir, const unsigned char *data, int n) {
  struct conn *c = get_conn(fd);
  int idx = dir;
  if (c->len[idx] + n > REASM_CAP) c->len[idx] = 0;  // overflow guard: resync
  memcpy(c->buf[idx] + c->len[idx], data, n);
  c->len[idx] += n;

  int consumed = 0;
  while (c->len[idx] - consumed >= 4) {
    const unsigned char *p = c->buf[idx] + consumed;
    int32_t size = rd32(p);
    if (size <= 0 || size > REASM_CAP) { consumed = c->len[idx]; break; }  // resync
    if (c->len[idx] - consumed - 4 < size) break;  // need more
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
static void on_sig(int s) { (void)s; stop = 1; }

static int handle_event(void *ctx, void *data, size_t sz) {
  (void)ctx; (void)sz;
  struct jsse_event *e = data;
  int n = e->cap < MAX_DATA ? e->cap : MAX_DATA;
  if (verbose_hex) {
    printf("[raw] tgid=%u fd=%lu dir=%s len=%u cap=%u hex=", e->tgid, e->fd,
           e->direction ? "INGRESS" : "EGRESS", e->len, e->cap);
    int hn = n < 32 ? n : 32;
    for (int i = 0; i < hn; i++) printf("%02x ", e->data[i]);
    printf("| \""); print_preview(e->data, n, 48); printf("\"\n");
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

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "probe_entry_jsse_plaintext");
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
