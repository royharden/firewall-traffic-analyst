# Development status

The tested local CLI/canonical citation and fresh Windows wheel slices are accepted with notes. The narrow-screen report follow-up is awaiting independent review; whole-app acceptance remains open.
This is local construction/integration evidence, not a release or detection-quality verdict.

## Implemented

- Bounded Zeek TSV/JSONL parsing, deterministic rules, source-recomputed explanatory
  statistics, audited context suppressions and inert proposed-rule text.
- `analyze` writes six self-contained artifacts; `verify` recomputes their exact bytes
  from the explicit caller source and recorded typed settings. The HTML is escaped
  and has no script or remote asset. Public-profile settings remain optional.
- The actual CLI now connects complete source support to the adopted S5 canonical
  Event producer, explicit Registry/RowResolver and RequiredEvidenceFrame assessment.
  Literal bytes are rechecked against the full source; processing identity binds
  parser implementation/runtime/configuration/schema. Every original requirement,
  including overflow failure, remains counted. Unresolved citations downgrade affected
  explanations/proposals. Invalid produced citations or changed sources refuse.
- A durable CLI demo uses 49 new documentation-range connections to exercise all
  five supported patterns plus the connection-state diagnostic. It verifies normal
  output, rejects conflicting settings, downgrades malformed headers and rejects a
  forged row citation despite a recomputed adjacent manifest.
- Optional offline annotation/companion and canonical evaluation components retain
  their earlier scoped hand-toy evidence. The default CLI has no model dispatch.

## Current checks

The combined local regression excluding `tests/seedgen` passed 1,117 top-level tests,
with zero failures/errors/skips. This includes nested vendor relocation wrappers;
their internal cases overlap and are not added to that count. Eight new citation
controls cover CRLF/repeated UID, original support omission/reorder, literal forgery,
source mutation, canonical overflow and rehashed tampering. An earlier run retained
one failing overflow fixture that exceeded the parser cap; the corrected control
uses a parser-valid row exceeding the canonical Pointer cap.

Lint, formatting and generated-schema checks pass. A moved 60-file local CLI source
closure completed the same demo while network and original product-source reads
were blocked. It used inherited cached Python dependencies; this is not a fresh
installation test. A subsequent Windows CPython 3.12.13 wheel build and fresh, non-editable installation passed the installed console command, 49-row normal/refusal/tamper journey and eight citation controls (zero failures/errors/skips). Runtime/test dependencies matched uv.lock hashes; public build tooling and licences were recorded. The wheel excludes reference-data generator code. This is separate from the earlier 1,117-test source run. No original reference corpus/generator, Gold, heldout evaluation,
provider SDK or live model was used for these checks.

## Outstanding acceptance work

1. Required independent native browser evidence for the narrow-screen renderer remains blocked. Independent source/semantic checks and seven focused tests passed; the authorized Chrome attempt failed before any layout, scroll or keyboard observations. No renderer defect was established. Author checks at 1440x1000 and 390x844 remain author evidence. Broader finished-app/browser acceptance remains open.
2. Additional platforms and Python/Bolt runtime deployment remain unverified. The accepted historical Windows wheel predates this renderer. A separate rebuilt current-renderer wheel passed fresh Windows installation, the 49-row normal/refusal/tamper journey, 15 citation/report controls and four-artifact saved-render byte equality with source/network guards. All 132 package files match current source. Independent disposition of this new wheel remains pending; native browser evidence is a separate hold.
3. Independent admission/conversion and quality experiment for the original reference
   corpus, preserving exposure history, expected misses and benign denominators.
4. Live SDK/access/price/accounting tests and annotation quality only under exact
   additional authority. Calibration and Human reference validation are unmeasured.
5. Broader MCP delivery remains explicitly deferred for this partial CLI profile.

No cloud/Bolt project, remote push, database, migration, edge function or hosted
backend has been provisioned. Python execution is an explicit Bolt portability gap.
Canonical citation identity does not establish attack semantics or quality.

## Runnable local journey

```console
uv sync --frozen
uv run --offline --frozen python scripts/demo_local_mvp.py --out out/local-mvp-001
```

Choose a new destination. Open its `normal/report.html`; inspect `receipt.json` for
actual CLI exits and artifact hashes. See [local MVP boundaries](docs/local-cli-mvp.md),
[limitations](docs/LIMITATIONS.md), [Bolt handoff](BOLT-HANDOFF.md) and [lessons](LESSONS.md).
