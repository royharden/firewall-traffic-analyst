# Explicit offline annotation companion

Normal `fwa analyze` and `fwa verify` perform deterministic analysis/recomputation without annotation. The optional Python composer in `firewall_analyst.annotation.report` creates a **separate** companion from an already verifiable six-artifact core report. It never instantiates a provider, ledger, budget, capture fixture, SDK or live mode for the caller.

First select and retain the original ordered requested group IDs from the verified core. Prepare each group through `prepare_annotation` and explicitly admit its actual canonical S3 operation. Supply an `OfflineGroupRequest` containing that preparation and the same actual `Provider`, `Ledger`, `BudgetAuthority`, `CallContext`, `Limits` and `Allocation` objects used for admission. Only `mock`/`strict_replay` provider modes and zero outbound quota are accepted. No similarly named accounting double or inferred allocation is accepted. Existing `annotate_offline` performs the real canonical validation/lookup. Canonical S6 rules screening remains required.

```python
from pathlib import Path
from firewall_analyst.annotation.report import compose_offline_report, write_companion

# original_requested_group_ids is the trusted selection retained BEFORE preparation.
# bindings is the caller's explicit tuple of admitted OfflineGroupRequest objects.
core = Path("out/core-001")
artifacts = compose_offline_report(
    core,
    input_path=Path("synthetic-conn.jsonl"),
    requested_group_ids=original_requested_group_ids,
    requests=bindings,
)
write_companion(Path("out/core-001-annotations"), artifacts, core_directory=core)
```

This shows composition after caller-owned setup; it is not a key, provider or synthetic-answer factory. Authored test helpers are not runtime configuration. Preserve the original requested frame independently of returned outcomes or available bindings. Missing, extra, duplicate, reordered and foreign group mappings fail before lookup. The cap is256 requested groups, with no silent truncation; invalid/offline-incompatible accounting also fails. Zero explicitly requested groups produces `no_annotation` and no invented suggestions.

## What the bundle establishes

The composer brackets lookups with actual original-core/source verification and exact core-byte snapshots. Its four artifacts are `annotations.json`, `report.html`, `report.md` and a last-written `manifest.json`. The directory must be a new sibling of the core. All six core files remain unchanged, as do source statistics, checked explanations, context decisions and proposed-rule text. Original complete report HTML/Markdown is incorporated with a separate `model_annotation` section. A fallback, held screen, miss, invalid answer, low confidence, stale preparation/context or unavailable ledger remains an explicit outcome at its original requested position.

The companion binds the exact original report/manifest/source/config, current group and declared preparation, question/projection/screen-policy digests. `prepared_request_json_sha256` is the canonical JSON digest of the actual prepared request, not a claim that a provider dispatched an identical envelope. It does not retain the request state or source text. Fractional triage remains fractional. The outcome retains the actual canonical SourceCaptureRef JSON, including capture/request/usage/price identities, without recreating that wire. Replay-result normalized usage is displayed as recorded source-result metadata, never as newly dispatched model tokens. Actual origin/model/accounting references, unknown nulls, current lookup cost and original source cost/usage/latency stay separate. A mock fixture remains mock; replay does not establish live correctness. Confidence0.6 remains uncalibrated, and `model_quality_measured` is false.

The companion manifest establishes byte integrity and binds the original core manifest. It does not authenticate a provider result, establish fresh provider state, calibrate confidence or measure quality. Run `fwa verify` against the **original core directory** and explicit input; that command recomputes deterministic observations and never performs a hidden lookup. There is no companion-result authenticity verifier. Rehashing a forged companion cannot manufacture authentic model provenance.

Whole companion output is bounded to64MiB or a lower caller limit. A cap fails without returning a sampled bundle. A write failure leaves an incomplete new directory without the completion manifest; existing directories are never overwritten. Explicit caller-controlled local source/output paths are assumed, not a hostile concurrent filesystem service. Supporting evidence and endpoints already present in the incorporated core view keep the source's access restrictions.

This is an offline optional-report integration milestone. Live/native provider execution, actual annotation metrics, canonical S5 event citations, complete S8 evaluation and independent finished-app acceptance remain separate requirements.
