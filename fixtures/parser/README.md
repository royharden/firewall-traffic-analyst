# Hand-written parser boundaries

`minimal.jsonl` is original synthetic documentation-range traffic, written for
parser semantics only. Its two records are independent of any future seeded
generator or frozen evaluation. No real logs or third-party sample bytes are used.

The parser accepts Zeek conn.log JSONL and declared TSV (`#separator`,
`#empty_field`, `#unset_field`, `#fields`, `#types`). Required fields are timestamp,
both addresses, both ports and protocol. Known structural numeric fields are strict;
optional absent/null values stay unknown. Exact timestamps must fit nonnegative
signed 64-bit UTC microseconds, counts unsigned 64-bit. Submicrosecond input is
rejected without rounding. Supported transports are TCP, UDP and ICMP; Zeek ICMP
ports mean type/code. Source: [Zeek Conn::Info](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

Invalid UID/service/history/conn_state metadata is nulled and flagged; service and
history are validated then discarded because EventV1 has no storage fields for them.
Unknown fields are ignored within bounded row/header shapes. Physical lines include
headers and blank lines. LF and CRLF are preserved by the generic evidence source.
Caps include line endings. Smaller caller limits are allowed; hard ceilings remain
200 MiB, 250,000 traffic candidates and 16 KiB per physical line. A row/line cap
returns partial processing with unknown original/excluded row totals. Two full byte
passes must match before provisional events are returned. A size-only rejection
has no generation digest or invented row count. Source evidence resolution rechecks
the entire file generation and returns exact bytes; it does not yet recompute claims.

No CLI analysis, detectors, windowing, calibration, scorer or provider code is
enabled by these fixtures. The public CLI still advertises its scaffold boundary.
