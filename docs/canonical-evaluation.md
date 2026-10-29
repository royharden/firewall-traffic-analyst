# Canonical evaluation components

The S8 domain adapter uses the unchanged S2 evalkit under `shared/evalkit`: actual `GoldRecord`, `PublicMethodInput`, `Prediction`, `Outcome`, `MetricRow`, `Manifest` and projection types; corpus admission, comparison, reporting, rates, classification and whole-family resampling functions. No generic statistics, experiment wire or bootstrap clone is maintained here. These callable components have hand-authored toy conformance; the original frozen source corpus has not been evaluated by this implementation lineage.

The public method configuration and raw matcher are described in [evaluation-adapter.md](evaluation-adapter.md). The new named public profile has source-observed analysis time and finite context applicability. It does not change the ordinary empty-allowlist baseline or retroactively establish how an earlier experiment ran. The matcher retains expected-miss positives, all applicable benign support and independent benign-contamination counts. Literal firewall policy deny/allow stays unsupported; it is distinct from the separately scored Zeek connection-state diagnostic.

## Controller-owned source boundary

`TrustedSourceCatalogue` registers opaque logical handles, an expected full source checksum, a parsed source snapshot and a trusted currentness callback. It never resolves a public string as a path or URL. The actual independent controller owns source provenance, namespace/access, complete source-family grouping, raw-byte verification and callback authority. Hash strings and typed objects alone provide none of those rights or authenticity guarantees.

`DetectionAdapter.to_public_input` projects only the registered source handle, source checksum, approved public profile ref and canonical source-unit identity/config refs. It never forwards reference episodes, private family IDs, label provenance, reference counts, hidden rubric or private dataset names. A controller must assign already-public opaque unit/handle identities; an opaque field is not an automatic de-identification guarantee. References stay in canonical `DomainLabels` on the scorer side. The concrete private payload is closed to its adapter version, existing typed reference episodes and public-profile content hash.

The local method registry names rules-only, interval-CV and distinct-port bucket implementations, plus explicit never-run rules-plus-Jev and rules-plus-Luna entries. The three active methods execute actual local functions with no SDK or provider dispatch. Model fields and ledger refs remain absent. The method descriptor binds declared source/parser/runtime closure hashes and a canonical profile-content hash; each actual result also binds its distinct per-source run config. Controllers must pin the original profile bytes and actual complete dependency preimages, not treat provided descriptor hashes as attestation. The two annotation entries remain unmeasured until a separately authorized actual annotation experiment; naming them grants no API access, spend, model provenance or quality.

Currentness is checked before public projection, before and after local method execution, and before scoring. Stale/unavailable preflight sources keep explicit status metadata and the complete requested source cohort. An incomplete rule channel makes the local result invalid. Malformed method output becomes invalid through canonical comparison. A change discovered between prediction and scoring aborts comparison; the caller must retain the full requested frame as incomplete and emit no partial-success score. No branch fabricates successful empty detections, follows an unregistered path or falls back to a network/provider.

## Fixed axes and count units

Every named method, six declared pattern axes and three fixed overlap thresholds retains explicit report rows. Proxies' inapplicable patterns have null values and `not_applicable`; never-run methods have `not_run`. The five primary patterns and the separate connection-state diagnostic have distinct axes. No unsupported pattern becomes a measured zero or disappears from the requested report.

Canonical `corpus_N`, `eligible_N`, `answered_N` and other population fields count **source-generation units**. Alert/episode numerators, denominators and statistical supports are separate. Two source units containing one hundred reference positives remain source cohort2 and positive support100. A private per-source `Outcome.correct` is null: a source with mixed TP/FP/FN counts is not one Boolean classification trial.

Ratio rows call the actual canonical helpers after summing domain counts, rather than averaging per-source rates. Precision uses TP/(TP+FP-alerts), recall TP/(TP+FN), F1 the actual canonical classification result, and benign FPR affected-benign/all-applicable-benign. Internal unused TN arithmetic is zero only to call the canonical F1 helper; no measured TN population or confusion matrix is exported. False-positive alerts never substitute for affected-benign episodes. Any eligible failed/incomplete source makes the relevant entire metric unmeasured with null numerator/denominator/value/interval and `incomplete_cohort`. Empty valid denominators preserve canonical NA reasons.

Six derived raw-count rows use the same actual canonical report and statistic types, with count as value/numerator and a null denominator. Counts are sums over the complete valid source cohort; a measured zero requires such a cohort. A failed cohort yields NA for the whole raw row, never a partial subtotal. Raw counts have no intervals or bootstrap. Their frozen unit/version mapping is:

| Metric | Counted objects / statistic version suffix |
|---|---|
| raw_tp | matched_positive_pairs |
| raw_fp_alerts | unmatched_flagged_alerts |
| raw_fn | missed_positive_episodes |
| raw_positive_episodes | positive_episodes |
| raw_benign_episodes | benign_episodes |
| raw_affected_benign | affected_benign_episodes |

Each version is `s8-raw-count-1.<suffix>`. Its statistic support counts those objects; the canonical population fields still count sources. Private support dictionaries retain separately labelled episode/alert quantities. Public export uses actual `public_aggregate` with closed method/pattern/metric/version/reason/config allowlists and numeric fields. It exports no private support dictionary, endpoints, rows, reference/group IDs, source handles, assignments or provenance text. Visible null reasons distinguish NA from zero.

## Whole-family uncertainty

The fixed paired policy uses the actual S2 sampler:2000 common draws, seed20261014,95% percentile intervals, Python3.12/random, explicit frozen whole-family order, no inferred stratification, minimum target support1 and1900 valid draws, with at least2 genuinely independent families required. A family sampled twice contributes all its rows/counts twice; callbacks do not deduplicate IDs or run fixed-axis report admission on the resampled copies. Unsupported draws remain null and are never redrawn, reseeded or imputed.

For F1, the canonical helper's original support is positive episodes TP+FN, while its actual ratio denominator is2TP+FP+FN. The domain callback preserves the exact canonical value/null reason/numerator/denominator and changes only the canonical Statistic support to the target denominator for the adopted bootstrap gate. Positive-episode support is retained separately. A canonical unsupported-class null stays null even when this denominator is positive. Other ratio helpers already report their target denominator as support. No F1 formula is reimplemented.

Actual draw digests, valid draws, RNG/Python version, group count and null reasons remain in the private canonical resampling result. Pairing requires the same full fixed reference axes, eligibility and family membership. Inapplicable or never-run methods cannot enter a paired comparison. Wilson intervals require a separately declared independent-binomial trial design; traffic events or episode counts alone do not supply it.

## What remains unmeasured

The retained original corpus needs an independently admitted conversion to canonical records/manifest, complete source-family/provenance/currentness bindings, an exact frozen experiment and a controller outside the excluded implementation lineage. These components do not perform that conversion, select a split, expose a corpus CLI, admit heldout or certify the original freeze/history. Actual original-corpus quality, model annotation accuracy, confidence calibration, quality floors and finished-app acceptance remain unmeasured. Toy reports and bootstrap controls demonstrate mechanics only, with no real-network generalization or claim of human reference validation.

The D8 parent, original author, aliases, forks and children remain excluded from actual S8 corpus/Gold execution, heldout tuning/controller/adjudication and independent finished-app review. A later controller must reconcile actual exposure history and original hashes/seals before any permitted experiment. Passing source checks or replacing labels does not repair a blinding failure.
