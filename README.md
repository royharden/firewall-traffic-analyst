# Firewall Traffic Analyst

Local Python CLI for Zeek connection logs: bounded TSV/JSONL parsing, deterministic observations, source-recomputed explanation templates, audited context suppressions and neutral proposed-rule text. No device changes or model requests occur.

The tested local CLI/citation and fresh Windows wheel supplements are accepted with notes. Independent source and semantic checks of the narrow-screen report passed, but required independent browser observations remain blocked after browser startup failed. A rebuilt current-renderer Windows wheel passed a fresh installed CLI journey and 15 focused controls; its acceptance remains pending. Whole-app acceptance remains open. See [finished work, WIP and outstanding tasks](DEVELOPMENT-STATUS.md) and [engineering lessons](LESSONS.md). The `local-cli-mvp/1` profile uses the own CLI and static artifacts; MCP distribution is explicitly deferred, with no MCP or broader quality-readiness claim.

## Keyless quickstart

Requires Python3.12 and uv. Install the frozen dependencies in your own environment:

```console
uv sync --frozen
uv run fwa --json
uv run python scripts/demo.py --out out/demo-001
uv run fwa verify out/demo-001 --input fixtures/demo/scan.jsonl
```

The output directory must be new. Open `out/demo-001/report.html` locally. It is self-contained, escaped HTML with no scripts or remote assets. JSON/Markdown, full supporting row bytes in `evidence.json`, neutral `proposed-rules.txt` and a SHA256 manifest accompany it. The demo is fifteen synthetic connections demonstrating a scan threshold, not a quality benchmark.

The report starts with input completeness and source identity, rule-channel status and each observed group's checked statistics, explanation labels, context/quality flags and human-review text. Unknown counts remain unknown; no-group coverage is N/A. The expandable complete JSON retains every support ID and recorded setting. Markdown contains the same escaped semantic HTML; use an HTML-capable Markdown reader or the standalone HTML file.

```console
uv run fwa analyze your-conn.jsonl --out out/run-001 --internal-cidr 192.0.2.0/24
uv run fwa verify out/run-001 --input your-conn.jsonl
```

Use explicit `--as-of-us` for repeatable UTC microsecond clocks. Optional `--policy` accepts typed policy JSON and `--contexts` a typed context array. Internal CIDRs must be supplied for outbound direction; absent direction makes outbound channels not evaluable. No credentials are needed. Status alone reads no files. Outputs contain source evidence and endpoints; handle them with the same access restrictions as the input logs.

For the separately declared public source-observed clock/context mapping, use `--public-profile config/evaluation-public-setup.v1.json` instead of manual clock/policy/context/CIDR flags. It requires a complete source and writes the same verifiable artifacts; it performs no scoring or model request. See [public profile CLI](docs/public-profile-cli.md) for the explicit configuration and error boundaries.

## Observations and verification

Implemented rules cover port scans, host sweeps, beacon-shaped timing, unusual outbound destination/service combinations, large observed origin-byte transfers and a separate rejected-then-established diagnostic. Starting thresholds are versioned in `config/rules.json`. Statistics bind complete physical-row support and are recomputed from the selected source. Suppressed and partial groups remain visible. Large transfers do not establish malicious intent; Zeek connection state cannot establish firewall-policy action.

Verification checks exact artifact bytes and recomputes them from the caller's explicitly supplied source, recorded policy/context/clock and implementation. It never opens a source path from an untrusted report. The manifest is an integrity aid, not a signature or an approval of policy choices. Changed/missing input, missing artifacts and tampering fail. A failed write leaves an incomplete directory without a completion manifest; choose a fresh directory for retry.

No groups means explanation coverage is N/A. Partial parsing and unsupported/not-evaluable channels remain explicit. Empty results do not mean attack-free traffic. No accuracy, baseline, latency or provider-cost result has been measured.

## Boundaries and remaining work

Owned generic parsing/window/support/claim/proposal components execute against an unrelated ResourceChange hand fixture with owner-domain imports blocked. This checks portability of that local path. Canonical S2 evalkit, S3 offline provider/ledger, S6 rules/preparation and S5 supplied-text citation packages are vendored unchanged with moved conformance. The S8 Python annotation API uses actual S6 screening and a canonical S3 packed typed request with caller-supplied Provider, real Ledger, budget, context, limits and zero-dispatch allocation. It preserves fractional triage and separate provenance/costs; confidence0.6 is uncalibrated. Its explicit [offline companion composer](docs/offline-annotation.md) keeps the original six deterministic artifacts unchanged and writes a separate bounded report using the caller's original requested IDs/accounting objects. Companion byte integrity is not provider authenticity or quality. Normal CLI analysis defaults to no annotation. No live SDK adapter is installed.

The CLI connects complete source support to the adopted canonical S5 Event producer, explicit row resolver and required-evidence assessment. Every required row remains counted; unsupported citations downgrade affected proposals. See [the reproducible normal/refusal/tamper journey](docs/local-cli-mvp.md). Scope-labelled interval-CV and distinct-port bucket proxies have public hand tests and do not execute RITA/CrowdSec. The [S8 public configuration and raw matcher](docs/evaluation-adapter.md) and [canonical S2 adapter, local comparison/report and family-bootstrap components](docs/canonical-evaluation.md) have new hand-toy conformance. Original-corpus conversion and independently admitted quality evaluation remain unrun. MCP distribution is explicitly deferred for the partial local CLI profile; actual model annotation evaluation and independent finished-app review remain unfinished. A provisional agent-authored source/Gold freeze exists; no quality result or human Gold is claimed. See [proxy mechanics](docs/baselines.md).

See [architecture](docs/architecture.md), [reusable core](docs/reuse.md), [limitations](docs/LIMITATIONS.md), [boundary status](docs/contracts/BOUNDARIES.proposed.md), [data policy](DATA.md) and [Bolt handoff](BOLT-HANDOFF.md). This is a local Python app with inert browser reports; no hosted backend or database is provided. Coding agents authored the implementation; focused tests establish implementation behavior, not independent app acceptance.
