# Initial deterministic source policy

`detect()` consumes WP02 results, sorts `(ts_us, raw_line_number)` and returns all
flagged, suppressed and partial groups plus explicit per-rule processing status.
Status `complete` means source processing completed; it is not a claim of no attack.
Literal `denied_then_allowed` is always unsupported: selected Zeek fields carry no
firewall policy action. `rejected_then_established` is a separate TCP diagnostic.

Starting thresholds are locked as `initial-1` in `config/rules.json` before independent
Gold generation. No observed accuracy, tuning, scoring or planted acceptance exists.
The split method is independent session seeds; actual Gold manifests are future work.

| Rule | Key and starting observation policy |
| --- | --- |
| port_scan | source/protocol across destinations; 15 distinct destination ports, 60s width/30s stride |
| host_sweep | source/destination-port/protocol; 20 distinct destinations, 60s/30s |
| beaconing | source/destination/destination-port/protocol; whole bounded channel, 8 observations and 7 positive intervals, span at least 600s, median interval at least 5s, population interval CV at most 0.15 |
| unusual_outbound | same channel; known outbound, outside configured permitted destination ranges AND services |
| large_outbound | same channel; known origin-byte sum at least 10 MiB, 300s width/150s stride |
| rejected_then_established | same TCP channel; at least 3 REJ with strictly earlier timestamps, each less than 300s before SF/S1/S2/S3/RSTO; RSTR/RSTOS0/no-reply states do not establish the transition |

Sliding windows align to epoch strides and are half-open. Overlapping candidate
windows merge only for the same rule and key, with unique physical-row support and
statistics recomputed from that union. Touching windows do not merge. UID has no role
in ordering, grouping or evidence identity. Diagnostic windows begin at the earliest
supporting REJ. Rows at the exact 300s boundary are outside the diagnostic.

The 150s large-transfer stride and per-channel large-transfer key make previously
unspecified choices explicit; distributed transfers across channels are a limitation,
not a measured quality result. Byte CV is reported separately, never a beacon gate.
Unknown byte sums remain null when no measurement is known; a known partial sum is
a lower bound. Missing outbound origin bytes mark the large-transfer channel partial.
Positive inter-arrival statistics exclude equal timestamps and disclose their count.
The first observation has no preceding interval; its interval support is unknown.
Zero-mean byte CV is undefined with zero evaluable ratio support, not CV zero.

Context has explicit rule IDs, kind, source/destination CIDRs, protocol/port selectors,
finite active range, expiry and optional UTC weekday/minute schedules. The caller must
provide an analysis clock no earlier than the observed rows. All supporting rows must
match one context. Scanner permits scan/sweep, monitor only sweep, health_check only
beacon, backup only large_outbound, approved_peer only unusual_outbound, maintenance
only the TCP diagnostic. Expiry/end/minute boundaries are exclusive. Suppression is
retained in `groups` and `audit`, with context IDs and full support. On partial inputs,
status stays partial even if context matches; audit still retains that match. There
is no model-suggested context or flag-removal path.

Source caps propagate partial status, never a confident negative. A conservative
10,000 intermediate-window/channel bucket cap bounds local work before the existing
10,000 output-group cap; either cap is explicit partial. Smaller caps may be configured.
Empty permitted-service/destination lists explicitly permit nothing. Unknown direction
makes outbound channels unevaluable. ICMP remains outside service-port detectors.
This source slice has no CLI, report, generator, scorer, live model or vendor wiring.
