# Optional retained event and metric evidence

Install `RowResolver` explicitly with `install_rows(registry, resolver)`. The default
registry has no adapters. Old null Event/Metric locators remain unsupported. Existing
`Finding` and `assess_required_evidence` retain their meaning: evidence can preserve a
partial claim and cannot certify its semantic truth.

The backend supplies immutable retained bytes, typed raw/derived generation metadata,
and explicit access/currentness policies. Source acquisition, full-file row proofs,
metric computation, storage and retention belong to the producer. This library opens
no source files, URLs, stores, SDKs or model sessions. Imports and constructors grant
no access and install no resolver.

Events use `s8-zeek-physical-row-v1`: literal UTF-8 physical row bytes, full raw source
digest/revision, physical row number, actual processing descriptor hash and producer
event-record hash. Processing edition `s8-zeek-processing-v2` binds implementation,
runtime, effective configuration and schema digests. These are supplied producer facts;
this consumer does not reproduce the S8 parser or filesystem proof. Its additional
public-record shape check is distinct from the owner's EventV1 model. Literal CRLF
and decomposed Unicode remain unchanged.

Metrics use `s9-metric-row.v1`: complete support rows with contributors, exact support
integers, status and cohort/window counts. The new eight-field artifact contains
complete SnapshotIdentity, canonical config_json **string**, full nullable tag
provenance and platform summaries. It has its own artifact preimage and never relabels
an earlier retained-report hash. Raw generation is the declared dataset identity
fingerprint, distinct from upload-file bytes and snapshot ID. Metric strings must
already be NFC; validation never normalizes a retained quotation.

`produce_metric_rows` and `produce_event_row` serialize already-produced facts. Raw
source byte lengths and source-generation proofs are explicit trusted producer inputs.
Neither helper computes those facts from an isolated row or metric. A valid whole
metric row can exceed citation limits while its analysis and complete artifact remain
available. Atomic artifact overflow retains no prefix.

Ceilings: 16KiB event quote, 24KiB metric row, 32KiB whole Pointer and excerpt, 32MiB
retained artifact. `RowBounds` permits tighter immutable caller caps. Overflow preserves
the original reference ID and an exact measurement or explicitly marked cap+1 lower
bound. It never invents a retained digest, omits contributors, shards rows or creates
a successful null-text Pointer. Event record-input proof decoding has its separate
32MiB ceiling, so a lower retention cap can still report the actual record digest.

Only actual status `ok` with n>=5 resolves for performance support. Insufficient,
unavailable and diagnostic n1 records remain uncitable with safe status/count provenance.
Access is checked before fetching retained data and again before disclosing excerpts
or uncitable provenance. Currentness binds source/artifact/derived generation. Historical
mode requires explicit backend permission and remains `current=false`; deleted/unknown
current state never becomes an automatic historical pass. Other adapters have no
implicit historical profile.

`assess_produced_evidence` adds original-reference accounting. A trusted injected
`RequiredReferenceAuthority` owns each pre-production `RequiredEvidenceFrame`. Outcomes
cannot define the required denominator. Missing, duplicate, extra, reordered,
mismatching and unsupported outcomes remain visible. Closed Event/Metric failure
carriers contain no fake Pointer. Original evidence, probabilities, text and method
remain; unresolved or contract-invalid requirements make the verdict unsupported.

The original five exports stay in `encoded_schemas()`. `encoded_row_schemas()` supplies
five optional row schemas; `--include-row-profiles` writes both. Basic detached models
now also need `rowcanonical.py`. Optional profiles additionally need `rows.py`,
`rowproducers.py`, `production.py` and the declared base closure.

Contract and public-vector checks establish their executed structural, literal,
boundary and accounting behavior. They are not independent semantic evaluation,
human approval, source ownership, current export authority or app acceptance.
