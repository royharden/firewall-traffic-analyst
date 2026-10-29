# Comparison proxies

`firewall_analyst.baselines` contains original, deterministic comparison observations inspired by public interval-regularity and leaky-bucket designs. These are **proxies**. RITA and CrowdSec have not been installed or executed, and no third-party implementation is included. Their full features, production configuration and product performance are not represented.

Both functions accept an already validated `ZeekFileResult` and perform no file, network, model or label reads. They require a complete physical parse, no quarantined/excluded rows, matching full-source identity, distinct physical row IDs and no declared capture-loss/incomplete flags. Processing is bounded to250000 rows and10000 groups; a caller can lower the group bound. Overflow fails instead of publishing an empty or sampled result. The publishing caller must revalidate the original source generation. Neither proxy consumes suppression contexts or internal/allowed-network configuration. Their returned context policy is `none`.

## Interval coefficient-of-variation proxy

`interval_cv_proxy` applies only to `beaconing`. It separates TCP/UDP series by source address, transport, destination port and destination address across the whole supplied input, sorting by timestamp then physical line. Source port is not a series key. A series needs at least8 observations,7 strictly positive successive intervals,600seconds total span and5seconds median positive interval. Equal-timestamp intervals are omitted. It flags population standard deviation divided by mean at or below0.15. It uses no byte feature. Full series rows remain supporting evidence, including equal-timestamp rows; the positive-interval statistic has its own known-count coverage.

## Distinct-port bucket proxy

`distinct_port_bucket_proxy` applies only to `port_scan`. Each source-address/transport pair has a FIFO distinct destination-port bucket with capacity15. An overflow requires more than15 active distinct ports. The first event anchors a persistent5second leak schedule; due leaks remove oldest ports **before** processing an event exactly on a boundary. Idle time advances that schedule. A repeated active port does not refill, refresh age, extend an incident or become a new supporting row. A port seen after eviction is a new introduction.

At overflow, evidence consists of the actual rows introducing the then-active ports. Temporally overlapping overflow windows merge with the union of those causal introduction rows; a gap creates a separate incident. This intentionally omits repeated-port traffic from proxy support. Whole-series CV support and causal bucket support differ, so episode-row overlap eligibility can differ even on the same input. Report that difference explicitly when comparing methods; do not replace proxy support with all nearby rows to improve a score.

## Interpretation and evaluation status

Each result carries a method ID, applicable patterns, fixed version and SHA256 of its exact parameters, support policy, context policy and caller group bound. Thresholds are fixed before evaluation. Unsupported patterns are outside that proxy's comparison scope. A no-flag result does not establish benign traffic. These functions do not assign Gold, match episodes, calculate precision/recall/FPR or confidence intervals, or establish model/detection quality. Only public hand fixtures have exercised their mechanics so far. The actual canonical evaluation integration and independently controlled heldout run remain pending.
