/*
 * Copyright 2018- The Pixie Authors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * kafka_parser.h — a small, dependency-free "raw" Kafka wire-protocol parser.
 *
 * This mirrors the structured decoding that Pixie's C++ Kafka parser performs
 * (protocols/kafka/decoder), but in plain C for the standalone collector. It
 * decodes the request header and descends into Produce requests / Fetch
 * responses down to individual records (key/value) inside RecordBatch (magic
 * v2), including varint/zig-zag and compact (flexible-version) encodings.
 *
 * Everything is bounds-checked and best-effort: on malformed/truncated input it
 * stops and reports what it decoded so far (the same philosophy as Pixie's
 * message_set decoder, which returns partial results).
 */
#ifndef PIXIE_JSSE_KAFKA_PARSER_H
#define PIXIE_JSSE_KAFKA_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

/* ----- Kafka API keys (subset we name) ----- */
enum {
  KAPI_PRODUCE = 0, KAPI_FETCH = 1, KAPI_LIST_OFFSETS = 2, KAPI_METADATA = 3,
  KAPI_OFFSET_COMMIT = 8, KAPI_OFFSET_FETCH = 9, KAPI_FIND_COORDINATOR = 10,
  KAPI_JOIN_GROUP = 11, KAPI_HEARTBEAT = 12, KAPI_SYNC_GROUP = 14,
  KAPI_API_VERSIONS = 18, KAPI_CREATE_TOPICS = 19, KAPI_INIT_PRODUCER_ID = 22,
};

static const char *kafka_api_name(int16_t key) {
  switch (key) {
    case 0: return "Produce";          case 1: return "Fetch";
    case 2: return "ListOffsets";      case 3: return "Metadata";
    case 8: return "OffsetCommit";     case 9: return "OffsetFetch";
    case 10: return "FindCoordinator"; case 11: return "JoinGroup";
    case 12: return "Heartbeat";       case 14: return "SyncGroup";
    case 15: return "DescribeGroups";  case 16: return "ListGroups";
    case 17: return "SaslHandshake";   case 18: return "ApiVersions";
    case 19: return "CreateTopics";    case 20: return "DeleteTopics";
    case 22: return "InitProducerId";  case 36: return "SaslAuthenticate";
    case 60: return "DescribeCluster"; default: return "Api";
  }
}

/* "flexible from" version per API (compact encoding + tagged fields). From
 * Pixie's APIVersionMap; only the APIs we descend into matter here. */
static int kafka_flexible_from(int16_t api) {
  switch (api) {
    case KAPI_PRODUCE: return 9;
    case KAPI_FETCH: return 12;
    case KAPI_METADATA: return 9;
    case KAPI_API_VERSIONS: return 3;
    case KAPI_INIT_PRODUCER_ID: return 2;
    case KAPI_JOIN_GROUP: return 6;
    case KAPI_SYNC_GROUP: return 4;
    case KAPI_OFFSET_FETCH: return 6;
    case KAPI_FIND_COORDINATOR: return 3;
    default: return 9999;  // treat as never-flexible if unknown
  }
}
static int kafka_is_flexible(int16_t api, int16_t ver) { return ver >= kafka_flexible_from(api); }

/* Max supported request version per API (Kafka ~3.9). Used to reject frames
 * whose first 2 bytes coincidentally look like a known api_key — a stricter
 * guard than "api_key is known". A static table goes stale as Kafka evolves;
 * the right long-term source is the broker's own ApiVersions response. */
static int kafka_max_version(int16_t api) {
  switch (api) {
    case KAPI_PRODUCE: return 11;
    case KAPI_FETCH: return 17;
    case KAPI_LIST_OFFSETS: return 9;
    case KAPI_METADATA: return 13;
    case KAPI_OFFSET_COMMIT: return 9;
    case KAPI_OFFSET_FETCH: return 9;
    case KAPI_FIND_COORDINATOR: return 6;
    case KAPI_JOIN_GROUP: return 9;
    case KAPI_HEARTBEAT: return 4;
    case KAPI_SYNC_GROUP: return 5;
    case KAPI_API_VERSIONS: return 4;
    case KAPI_CREATE_TOPICS: return 7;
    case KAPI_INIT_PRODUCER_ID: return 5;
    default: return 12;  /* conservative bound for the other named APIs */
  }
}

/* ----- bounds-checked cursor ----- */
typedef struct {
  const uint8_t *p;
  const uint8_t *end;
  int err;
} kd_t;

static void kd_init(kd_t *d, const void *buf, int len) {
  d->p = (const uint8_t *)buf;
  d->end = d->p + (len > 0 ? len : 0);
  d->err = 0;
}
static int kd_remaining(kd_t *d) { return (int)(d->end - d->p); }
static int kd_need(kd_t *d, int n) {
  if (d->err || n < 0 || kd_remaining(d) < n) { d->err = 1; return 0; }
  return 1;
}
static uint8_t kd_u8(kd_t *d) { if (!kd_need(d, 1)) return 0; return *d->p++; }
static int16_t kd_i16(kd_t *d) {
  if (!kd_need(d, 2)) return 0;
  int16_t v = (int16_t)((d->p[0] << 8) | d->p[1]); d->p += 2; return v;
}
static int32_t kd_i32(kd_t *d) {
  if (!kd_need(d, 4)) return 0;
  int32_t v = (int32_t)(((uint32_t)d->p[0] << 24) | ((uint32_t)d->p[1] << 16) |
                        ((uint32_t)d->p[2] << 8) | d->p[3]);
  d->p += 4; return v;
}
static int64_t kd_i64(kd_t *d) {
  if (!kd_need(d, 8)) return 0;
  int64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | d->p[i];
  d->p += 8; return v;
}
/* unsigned varint (LEB128), up to 5 bytes (35 bits like Pixie). */
static uint32_t kd_uvarint(kd_t *d) {
  uint32_t v = 0; int shift = 0;
  for (int i = 0; i < 5; i++) {
    if (!kd_need(d, 1)) return 0;
    uint8_t b = *d->p++;
    v |= (uint32_t)(b & 0x7f) << shift;
    if (!(b & 0x80)) return v;
    shift += 7;
  }
  d->err = 1; return 0;
}
/* zig-zag signed varint. */
static int32_t kd_varint(kd_t *d) {
  uint32_t u = kd_uvarint(d);
  return (int32_t)((u >> 1) ^ (~(u & 1) + 1));
}
/* zig-zag signed varlong (up to 10 bytes / 70 bits). */
static int64_t kd_varlong(kd_t *d) {
  uint64_t v = 0; int shift = 0;
  for (int i = 0; i < 10; i++) {
    if (!kd_need(d, 1)) return 0;
    uint8_t b = *d->p++;
    v |= (uint64_t)(b & 0x7f) << shift;
    if (!(b & 0x80)) return (int64_t)((v >> 1) ^ (~(v & 1) + 1));
    shift += 7;
  }
  d->err = 1; return 0;
}
static void kd_skip(kd_t *d, int n) { if (kd_need(d, n)) d->p += n; }

/* Copy a (possibly nullable) string of n bytes into out (NUL-terminated). */
static void kd_take_str(kd_t *d, int n, char *out, int outcap) {
  int m = 0;
  if (n > 0 && kd_need(d, n)) {
    m = n < outcap - 1 ? n : outcap - 1;
    memcpy(out, d->p, m);
    d->p += n;  // consume the full field even if out is smaller
  }
  out[m] = 0;
}
/* regular string: int16 len + bytes. */
static void kd_regular_string(kd_t *d, char *out, int outcap) {
  int16_t n = kd_i16(d);
  kd_take_str(d, n, out, outcap);
}
/* compact string: uvarint(len+1) + bytes. */
static void kd_compact_string(kd_t *d, char *out, int outcap) {
  uint32_t n = kd_uvarint(d);
  kd_take_str(d, (int)n - 1, out, outcap);
}
static void kd_string(kd_t *d, int flexible, char *out, int outcap) {
  if (flexible) kd_compact_string(d, out, outcap); else kd_regular_string(d, out, outcap);
}
/* Skip a tag section (flexible versions): uvarint count, then count fields. */
static void kd_skip_tags(kd_t *d) {
  uint32_t cnt = kd_uvarint(d);
  for (uint32_t i = 0; i < cnt && !d->err; i++) {
    kd_uvarint(d);                 /* tag id */
    uint32_t sz = kd_uvarint(d);   /* size   */
    kd_skip(d, (int)sz);
  }
}

/* Decompress a Kafka record blob. codec: 1=gzip,2=snappy,3=lz4,4=zstd.
 * Returns decompressed length, or -1 if unsupported/failed. */
static int kafka_decompress(int codec, const uint8_t *in, int inlen, uint8_t *out, int outcap) {
  if (inlen <= 0) return -1;
  if (codec == 1) {  /* gzip (java.util.zip.GZIPOutputStream) */
    z_stream zs; memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 + 16) != Z_OK) return -1;  /* 16 => gzip header */
    zs.next_in = (Bytef *)in; zs.avail_in = inlen;
    zs.next_out = out; zs.avail_out = outcap;
    int r = inflate(&zs, Z_FINISH);
    int n = (int)zs.total_out;
    inflateEnd(&zs);
    return (r == Z_STREAM_END || r == Z_OK) ? n : -1;
  }
  if (codec == 4) {  /* zstd */
    size_t n = ZSTD_decompress(out, outcap, in, inlen);
    return ZSTD_isError(n) ? -1 : (int)n;
  }
  return -1;  /* snappy(2)/lz4(3): libs/headers not available here */
}

/* ----- record-level callback ----- */
typedef void (*kafka_record_cb)(void *ctx, const char *topic, int32_t partition,
                                const uint8_t *key, int klen, const uint8_t *val, int vlen);

typedef struct {
  int16_t api_key, api_version;
  int32_t correlation_id;
  char client_id[128];
  int flexible;        /* header flexibility */
  int body_off;        /* offset of body within the original frame */
  int batches;         /* record batches seen */
  int records;         /* records decoded */
  int compressed;      /* compression codec of last batch (0 none) */
} kafka_req_hdr_t;

/* Parse a request header. buf/len is the frame body (no 4-byte length prefix). */
static int kafka_parse_request_header(const void *buf, int len, kafka_req_hdr_t *h) {
  memset(h, 0, sizeof(*h));
  kd_t d; kd_init(&d, buf, len);
  h->api_key = kd_i16(&d);
  h->api_version = kd_i16(&d);
  h->correlation_id = kd_i32(&d);
  h->flexible = kafka_is_flexible(h->api_key, h->api_version);
  /* client_id is a *regular* (non-compact) nullable string even in flexible
   * request headers (it lives in the header, encoded the v1 way). */
  kd_regular_string(&d, h->client_id, sizeof(h->client_id));
  if (h->flexible) kd_skip_tags(&d);  /* request header v2 tagged fields */
  h->body_off = (int)(d.p - (const uint8_t *)buf);
  return d.err ? -1 : 0;
}

/* Parse `nrec` records from a cursor whose data ends at `lim`. */
static void kafka_parse_records(kd_t *d, int32_t nrec, const uint8_t *lim, const char *topic,
                                int32_t partition, kafka_record_cb cb, void *ctx, int *records_out) {
  for (int32_t i = 0; i < nrec && !d->err && d->p < lim; i++) {
    int32_t rlen = kd_varint(d);                 /* record length (zig-zag) */
    const uint8_t *rec_end = d->p + (rlen > 0 ? rlen : 0);
    if (rec_end > lim) rec_end = lim;
    kd_u8(d);                                    /* attributes */
    kd_varlong(d);                               /* timestamp_delta */
    kd_varint(d);                                /* offset_delta */
    int32_t klen = kd_varint(d);                 /* key len (zig-zag, -1=null) */
    const uint8_t *key = NULL; int kl = 0;
    if (klen >= 0 && kd_need(d, klen)) { key = d->p; kl = klen; d->p += klen; }
    int32_t vlen = kd_varint(d);                 /* value len */
    const uint8_t *val = NULL; int vl = 0;
    if (vlen >= 0 && kd_need(d, vlen)) { val = d->p; vl = vlen; d->p += vlen; }
    if (cb) cb(ctx, topic, partition, key, kl, val, vl);
    if (records_out) (*records_out)++;
    d->p = rec_end;  /* skip headers / advance to next record */
  }
}

/* Decode one RecordBatch region (magic v2). Returns 0 if records were decoded,
 * the codec (>0) if compressed-and-not-decodable, or -1 on bad magic. */
static int kafka_decode_record_batch(kd_t *d, const char *topic, int32_t partition,
                                     kafka_record_cb cb, void *ctx, int *records_out) {
  static unsigned char decomp[1 << 20];  /* single-threaded collector: static ok */
  /* base_offset(8) batch_length(4) */
  kd_i64(d);
  int32_t batch_length = kd_i32(d);
  const uint8_t *batch_end = d->p + (batch_length > 0 ? batch_length : 0);
  if (batch_end > d->end) batch_end = d->end;
  kd_i32(d);                 /* partition_leader_epoch */
  int8_t magic = (int8_t)kd_u8(d);
  if (magic != 2) { d->p = batch_end; return -1; }
  kd_i32(d);                 /* crc */
  int16_t attributes = kd_i16(d);
  int codec = attributes & 0x07;  /* 0 none,1 gzip,2 snappy,3 lz4,4 zstd */
  kd_i32(d);                 /* last_offset_delta */
  kd_i64(d);                 /* first_timestamp */
  kd_i64(d);                 /* max_timestamp */
  kd_i64(d);                 /* producer_id */
  kd_i16(d);                 /* producer_epoch */
  kd_i32(d);                 /* base_sequence */
  int32_t nrec = kd_i32(d);  /* record count (regular int32) */

  if (codec == 0) {
    kafka_parse_records(d, nrec, batch_end, topic, partition, cb, ctx, records_out);
    d->p = batch_end;
    return 0;
  }
  /* Compressed: the records blob is [d->p, batch_end). Decompress, then parse. */
  int inlen = (int)(batch_end - d->p);
  int outlen = kafka_decompress(codec, d->p, inlen, decomp, sizeof(decomp));
  d->p = batch_end;  /* consume the batch regardless */
  if (outlen < 0) return codec;  /* unsupported codec (snappy/lz4) or failure */
  kd_t rd; kd_init(&rd, decomp, outlen);
  kafka_parse_records(&rd, nrec, decomp + outlen, topic, partition, cb, ctx, records_out);
  return 0;
}

/* Decode a "records" field (one or more record batches) of a given byte size. */
static void kafka_decode_message_set(kd_t *d, int set_size, const char *topic, int32_t partition,
                                     kafka_record_cb cb, void *ctx, kafka_req_hdr_t *h) {
  const uint8_t *set_end = d->p + (set_size > 0 ? set_size : 0);
  if (set_end > d->end) set_end = d->end;
  while (d->p + 12 <= set_end && !d->err) {
    int codec = kafka_decode_record_batch(d, topic, partition, cb, ctx, &h->records);
    h->batches++;
    if (codec > 0) h->compressed = codec;
    if (codec < 0) break;  /* unsupported magic */
  }
  d->p = set_end;
}

/* Parse a Produce request body and emit each record. */
static void kafka_parse_produce(const void *buf, int len, kafka_req_hdr_t *h,
                                kafka_record_cb cb, void *ctx) {
  kd_t d; kd_init(&d, (const uint8_t *)buf + h->body_off, len - h->body_off);
  int fx = h->flexible;
  /* transactional_id (nullable string; compact if flexible; only present v>=3) */
  if (h->api_version >= 3) { char tmp[64]; kd_string(&d, fx, tmp, sizeof(tmp)); }
  kd_i16(&d);  /* acks */
  kd_i32(&d);  /* timeout_ms */
  /* topics array */
  int32_t ntop = fx ? (int32_t)kd_uvarint(&d) - 1 : kd_i32(&d);
  for (int32_t t = 0; t < ntop && !d.err; t++) {
    char topic[256]; kd_string(&d, fx, topic, sizeof(topic));
    int32_t npart = fx ? (int32_t)kd_uvarint(&d) - 1 : kd_i32(&d);
    for (int32_t p = 0; p < npart && !d.err; p++) {
      int32_t pidx = kd_i32(&d);
      int set_size = fx ? (int)kd_uvarint(&d) - 1 : kd_i32(&d);
      kafka_decode_message_set(&d, set_size, topic, pidx, cb, ctx, h);
      if (fx) kd_skip_tags(&d);  /* partition tagged fields */
    }
    if (fx) kd_skip_tags(&d);    /* topic tagged fields */
  }
}

/* Parse a Fetch response body (the broker delivering records) and emit each one.
 * buf/len is the response frame body; resp header is [corr_id(4)] then body. */
static void kafka_parse_fetch_response(const void *buf, int len, int16_t api_version,
                                       kafka_record_cb cb, void *ctx, kafka_req_hdr_t *h) {
  int fx = kafka_is_flexible(KAPI_FETCH, api_version);
  kd_t d; kd_init(&d, buf, len);
  kd_i32(&d);  /* correlation_id */
  if (fx) kd_skip_tags(&d);  /* response header v1 tagged fields */
  if (api_version >= 1) kd_i32(&d);   /* throttle_time_ms */
  if (api_version >= 7) { kd_i16(&d); kd_i32(&d); }  /* error_code, session_id */
  int32_t ntop = fx ? (int32_t)kd_uvarint(&d) - 1 : kd_i32(&d);
  for (int32_t t = 0; t < ntop && !d.err; t++) {
    char topic[256];
    if (api_version >= 13) {
      /* Fetch v13+ identifies the topic by a 16-byte UUID (topic_id) instead of
       * by name — a breaking wire change. We render it as a short id. */
      if (kd_need(&d, 16)) {
        snprintf(topic, sizeof(topic), "id:%02x%02x%02x%02x-%02x%02x..",
                 d.p[0], d.p[1], d.p[2], d.p[3], d.p[4], d.p[5]);
        d.p += 16;
      } else { topic[0] = 0; }
    } else {
      kd_string(&d, fx, topic, sizeof(topic));
    }
    int32_t npart = fx ? (int32_t)kd_uvarint(&d) - 1 : kd_i32(&d);
    for (int32_t p = 0; p < npart && !d.err; p++) {
      int32_t pidx = kd_i32(&d);
      kd_i16(&d);                       /* error_code */
      kd_i64(&d);                       /* high_watermark */
      if (api_version >= 4) kd_i64(&d); /* last_stable_offset */
      if (api_version >= 5) kd_i64(&d); /* log_start_offset */
      if (api_version >= 4) {           /* aborted_transactions array */
        int32_t na = fx ? (int32_t)kd_uvarint(&d) - 1 : kd_i32(&d);
        for (int32_t a = 0; a < na && !d.err; a++) { kd_i64(&d); kd_i64(&d); if (fx) kd_skip_tags(&d); }
      }
      if (api_version >= 11) kd_i32(&d); /* preferred_read_replica */
      int set_size = fx ? (int)kd_uvarint(&d) - 1 : kd_i32(&d);
      kafka_decode_message_set(&d, set_size, topic, pidx, cb, ctx, h);
      if (fx) kd_skip_tags(&d);
    }
    if (fx) kd_skip_tags(&d);
  }
}

#endif  /* PIXIE_JSSE_KAFKA_PARSER_H */
