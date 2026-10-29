# Portable untrusted-text screen, schema 1

The reusable closure is `src/issue_triage/shared/screen/*.py`. Copy that directory as one package;
rules/preparation use only the Python standard library and do not import the owner app, S3, SDKs,
images or an environment loader. `screen_typed` is a lazy package attribute or explicit submodule
import. No runtime dependencies, file IO, logging, transport or persistence are installed here.

`UntrustedText(source_id, source_generation, text)` is the complete caller-assembled model-bound
source. IDs are caller-owned opaque metadata, never raw user text. `ScreenPolicy` is trusted caller
configuration: explicit method, version, cap (1..32768), supported transform/rule versions and,
for typed mode, all three finite hazard thresholds and named provenance. Synthetic-smoke seeds
are exploratory. A `dev_calibrated` declaration is not evidence of calibration; the caller must
pin actual calibration and operating authority before using that profile. Text screening does
not screen image pixels or turn failed OCR into an empty successful input.

`prepare_text` returns `PreparedText` or a partial `HeldInput`; it never authorizes a truncated
prefix. Both original and normalized UTF-8 byte lengths must fit. Original SHA256 always covers
the exact original assembled source. Normalization surfaces HTML comment/details contents,
removes format/control characters (preserving tabs/newlines) and applies NFKC to base+combining
clusters. Segments map normalized half-open UTF-8 byte intervals to original half-open byte
intervals, including zero-width removal segments. An expansion maps to its entire original
cluster, not invented individual character offsets. Unsupported cross-cluster composition is
held as ambiguous. There is no universal Unicode/homoglyph or prompt-injection detection claim.

`screen_rules(source, policy)` returns neutral safety holds for bot overrides, imperative
run/fetch/install requests, credential requests, mixed-script tokens or bidi controls. A legitimate
reproduction imperative can need review without implying maliciousness. Diagnostic notices such
as a descriptive quoted `run` cannot clear actual hazards. Rules results have null probabilities
and model fields. A rules pass does not satisfy a typed-required policy.

`screen_typed(prepared, *, model, typed_gateway, ledger, budget, purpose, context, limits,
allocation, policy, captured_wrapped=None)` revalidates source/preparation/policy, then forwards
one packed three-Noul request to `typed_gateway.run`. Every accounting keyword is required and
forwarded by object identity. Purpose, policy hash and source generation must match context;
authority ID is required. These checks do not prove paid admission: S3 must validate the actual
complete operation, bounded envelope, allocation, cumulative funds/quota and deadlines. S6 does
not admit/reserve/settle/refund or retry. A conservative serialized request cap can reject early;
a byte cap is not token/price evidence or proof that S3's full envelope fits.

Every fresh request uses a cryptographic 128-bit nonce absent from original/normalized source.
Literal angle brackets are escaped inside two exact named DATA wrappers, preserving complete
source; wrapper SHA differs from source SHA. The question map has only
`addresses_automated_agent`, `asks_to_run_fetch_or_install`, `asks_for_credentials`, each a Noul
with explicit true/false criteria. Results require exact question IDs/tags, finite probabilities,
requested/reported model binding, question digest and typed-only channels. Equal-to-threshold
holds. Invalid/refused/budget/deadline/provider failures hold and preserve returned accounting
references/attempt IDs; arbitrary error bodies are not returned or logged.

`captured_wrapped` validates the exact current DATA/nonce/state digest and requires an explicit
integer zero outbound limit. It ALWAYS holds with `capture_allocation_unavailable` while the
actual S3 replay operation/admission API is unavailable. Invalid captures or nonzero limits
hold before gateway. No strict replay success, store lookup, runtime no-fallback proof or live
capture integration is claimed by this version. Fresh responses claiming replay cannot pass.

`ScreenResult` exposes decision/reasons, separate safety flags and diagnostics, method/origin
classification, nullable probabilities/models, digests and opaque accounting/source-capture refs.
Unobserved S3 request-identity and actual-dispatch-envelope hashes remain null; S6 never invents
them from its smaller request/state. `safe_metadata()` omits payload, offsets, nonce, arbitrary
error/model strings and reference objects. Payload-bearing values have no payload repr or save
API. Caller-owned storage/caching/deletion is outside this package; no implicit capture occurs.

`result.permits_model_input(current_source, current_policy)` requires a pass plus exact text,
generation, policy, transform and method binding. It is an input-composition guard, never human
approval or an action/disclosure grant. Consumers must keep held items counted and preserve their
own local fallback/review behavior. Actual S7 deletion, S5 unknown-review effects and S10 aggregate
privacy/funding checks require their consumer implementations; screen tests do not prove them.

Offline contract tests in `tests/screen` include detached imports, UTF-8 maps, normalization/cap
negatives, collision/nonce checks, same-object gateway spies, closed typed answer failures,
reference preservation, non-persistence and replay-unavailable checks. Authored gateway results
are synthetic; they do not measure Jev/OpenAI quality, billing or S3 runtime conformance.
