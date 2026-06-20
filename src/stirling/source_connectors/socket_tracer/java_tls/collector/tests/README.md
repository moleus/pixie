# kafka_parser.h tests (offline)

Self-contained correctness + memory-safety tests for the dependency-free Kafka
wire parser in `../kafka_parser.h`. They need **no live Kafka and no cluster** —
the complement to `../../scripts/selftest.sh`, which validates end-to-end against
a real broker.

```bash
./run.sh            # functional + a 20k-iteration sanitizer fuzz
./run.sh 200000     # longer fuzz
```

## What they cover
- **`test_kafka_parser.c`** — compresses a 300 KB payload with each codec
  (gzip, zstd, lz4 *frame* incl. multi-block, raw snappy, and multi-block xerial
  snappy), runs it back through `kafka_decompress`, and asserts an exact
  round-trip; then builds a full **Produce v9 (flexible)** frame for each codec
  and asserts the parser recovers the topic, partition, and record values.
- **`fuzz_kafka_parser.c`** — under ASan+UBSan, drives `kafka_parse_request_header`,
  `kafka_parse_produce`, `kafka_parse_fetch_response`, and `kafka_decompress` with
  truncations of a valid frame (every prefix length), byte-flip mutations, pure
  random buffers, and a malformed xerial frame whose block length is ~2 GB.

## Regression notes
- `kd_i64` accumulates into a **`uint64_t`** before casting to `int64_t`. Doing the
  byte-assembly in a signed type (`v = (v << 8) | ...`) is undefined behavior once
  the value's sign bit is set; UBSan flags it. (Found by `fuzz_kafka_parser`.)
- The xerial-snappy loop and the `[blocklen][block]` framing must reject a block
  length that runs past the input; the fuzzer exercises the ~2 GB case.
