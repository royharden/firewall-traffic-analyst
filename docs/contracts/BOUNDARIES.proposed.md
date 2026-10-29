# Owned boundary status

Strict/frozen owned models live in `domain/schemas.py` and `shared/rulesengine/{schemas,parsers,fixtures}.py`. Generated JSON shapes remain in `config/schemas/`; cross-field checks exceed JSON shape validation. A declared internally consistent statistic alone is not evidence: actual source resolution and recomputation are required.

| Boundary | Actual implementation | Remaining dependency |
|---|---|---|
| Event | Full source SHA256/physical-line identity, UTC microseconds, IP/protocol, nullable counts; bounded Zeek TSV/JSONL parser with quarantine/limits | Other log formats absent |
| Group | Epoch-aligned windows, merged complete physical support, versioned policy/context/clock, statistics, flags and suppression/partial audit | Independent quality evaluation |
| Claim | Full/subset support checks, fresh source-derived catalogue, named-stat recomputation, fixed template/formatter; source changes fail closed | Own EvidenceRef staging; S5 canonical Pointer vendor pending |
| Proposal | Verified observed endpoint associations, adjacent-port-only compaction, explicit NOT APPLIED/investigate text | Human policy decision; no device writer |
| Report | Local bounded JSON/Markdown/escaped HTML/full support sidecar; new output only, explicit-source recomputation | No hosted analyzer |
| Annotation/accounting | Unchanged canonical S3 offline Provider/Ledger and S6 rules/preparation; S8 closed computed projection, packed typed questions, explicit current bindings/zero-quota allocation and separate outcomes | Live SDK/API adapters, final CLI/report wiring, model-quality calibration/testing |
| Evaluation | Gold types and provisional independent agent-authored source/label freeze with source-integrity controls | Matcher/evalkit integration, separate heldout controller/metrics and external acceptance |

The detached ResourceChange hand-fixture test exercises source -> windows/aggregation/merge -> checked observations -> neutral export while blocking owner-domain imports. It establishes that execution path's portability, not broad domain fitness. No foreign source commit, canonical Pointer, canonical evalkit result or paid mock fallback is invented here.
