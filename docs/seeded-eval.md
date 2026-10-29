# Independent seeded source inventory

The seed generator authors synthetic Zeek JSONL traffic and planted reference episodes.
It never imports or executes traffic detectors, scoring code, model adapters or providers.
Its integrity checks establish reproducibility and source/label identity, not detection
quality, human validation, shared evalkit compatibility or application acceptance.

The frozen cohort contains 60 development sources (seeds 1–60) and 120 heldout sources
(seeds 1001–1120). Each complete source is one session group; rows are never split between
cohorts. Each has one standard positive and one benign narrative. Additional challenging
positives, slow-scan/backup-shaped exfiltration expected misses and a distinct rejected-to-
established connection diagnostic produce 151 development and 300 heldout episodes.
Expected misses retain positive pattern, category, severity and full eligibility; no
case is excluded to improve a metric. Literal firewall deny-to-allow remains unsupported:
Zeek connection states do not establish firewall actions.

Observed at the first freeze, 2026-10-14 23:53:11.175246 UTC:

| Inventory | Development | Heldout |
| --- | ---: | ---: |
| Session sources / groups | 60 | 120 |
| Physical traffic rows | 1,578 | 3,652 |
| Exact raw source bytes | 343,855 | 795,675 |
| Labelled episodes | 151 | 300 |
| Positive / expected miss / benign | 87 / 4 / 60 | 174 / 6 / 120 |
| Challenging positives | 15 | 30 |
| Slow scan / backup-shaped expected miss | 2 / 2 | 3 / 3 |
| Separate connection-state diagnostic | 12 | 24 |

All ten benign strata have six development and twelve heldout episodes each. Source
lineage maps contain 20 split-exclusive families and seven within-split duplicate
signature groups; no cross-split group, family, exact source/label or declared structural
collision was found. These are bounded integrity observations, not accuracy results.

The five planted source patterns are port scan, host sweep, beaconing, unusual outbound
and large outbound. The benign mix includes DNS, NTP, health checks, sanctioned scanners,
known backups, NAT fanout, legitimate uploads, video, updates and difficult bulk traffic.
Legitimate bulk cases retain benign truth even when their observable shape can resemble
a planted positive. Public backup context also applies to backup-shaped planted exfiltration;
context does not authorize changing its reference truth. These ambiguities can cause
false positives or false negatives under a later evaluator.

Public source semantics use only documentation addresses, explicit internal ranges,
permitted peers/services and scanner/backup/health role context. The exact public setup
and its source-semantics adoption reference are in `fixtures/generator/profile.v1.json`.
This setup does not adopt an engine evaluation configuration. The original public rule
policy remains separately hashed. Owners must adopt an exact engine configuration and
mapping before claiming that evaluation used these contexts. An empty runtime allowlist
cannot silently be treated as this proposed public setup.

`gold/local-manifest.v1.json` uses the actual local `GoldManifestV1` contract. Each record
in `gold/dev.jsonl` and `gold/heldout.jsonl` wraps the actual `GoldEpisodeV1` with scorer-side
session, family, stratum, complete physical line membership and agent-provisional provenance.
The original raw bytes are serialized first, with exact numeric microsecond timestamp and
duration lexemes. Their full SHA256 then binds every physical row ID. UID is nullable
metadata and never identity. Windows are actual `[minimum timestamp, maximum timestamp+1)`
over the complete episode support. Support digests use the shared local support contract.

`gold/members.v1.jsonl`, `gold/maps.v1.json`, `gold/ordered-ids.v1.json` and `gold/freeze.v1.json` record actual
memberships, ordered IDs, byte/row/episode counts, hashes, code closure, source-policy and
schema hashes, source/label artifacts and a heldout seal. Config SHA256 means the exact
public generator-profile bytes. The code closure hashes ordered relative-path/file-hash
pairs and excludes generated outputs. The freeze clock is an explicit actual UTC event,
separate from the fixed synthetic event clock beginning 2024-01-01 UTC.

Concrete alpha and beta template lineages stay wholly in development and heldout,
respectively. Development and heldout profiles differ in source rates, host/service
distributions, beacon spacing (one minute versus five/fifteen minutes), jitter/loss,
duration and transfer sizes. The declared structural equality signature retains relative
timestamps, ordered endpoint-role graphs, protocol/destination-service sequences and exact
byte/null/duration/state profiles. It excludes absolute addresses, time, UID and origin
ephemeral ports. Cross-split exact source, label, group, family and structural collisions
are rejected. This finite synthetic policy does not establish universal independence;
different seeds or lineage names alone are insufficient.

The source projection is a strict allowlist of opaque item ID, raw input SHA256, source
reference and public config reference. Gold, family, trap, stratum, expected category,
severity and hidden contexts must never enter method or annotation state. Heldout source
and Gold bodies and source-quoted failure logs remain sealed from development/tuning reads;
only aggregate counts and path/hash metadata may be handed back until a separate grant.

The freeze is explicitly a **PROVISIONAL S8 subset / needs_owner_metadata**. Scorer,
comparator, adapter, experiment, canonical manifest, human validation, engine evaluation
configuration adoption and release acceptance are absent. No versions, runtime commits
or human Gold are invented. The ordered string-ID array hash is SHA256 of UTF8 sorted-
compact JSON with codepoints/order preserved, no BOM, normalization or final newline.
Broader canon/1 C01–C03 conformance is NOT_RUN because exact vectors/runtime were not
provided. The local integrity verifier is not a competing evaluator.

Bounded offline controls:

```console
uv run --offline --no-sync pytest tests/seedgen -q
uv run --offline --no-sync ruff check src/firewall_analyst/domain/seedgen tests/seedgen
uv run --offline --no-sync ruff format --check src/firewall_analyst/domain/seedgen tests/seedgen
uv run --offline --no-sync python -m firewall_analyst.domain.seedgen verify --root .
```

Authoring a new destination requires `freeze --root <new-root> --profile <profile-file>
--frozen-at-utc <explicit-UTC-clock>`. Existing or partial destinations are refused.
Frozen source, Gold, profile, clock and closure changes require an explicitly approved
successor; never normalize, overwrite or silently reseal a frozen artifact. Deterministic
regeneration uses a separate temporary directory with the same explicit freeze clock.
Tests cover raw-byte/line changes, missing/null/duplicate UID identity, row support,
provenance, membership, cross-split collisions, stale IDs/counts/clocks and public leakage.
Native symlink escape coverage is skipped when Windows does not grant symlink creation;
path traversal controls still execute and the capability gap remains explicit.
