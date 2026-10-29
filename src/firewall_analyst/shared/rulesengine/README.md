# Reusing rulesengine

These generic components operate on caller-owned records. They require Python
3.12 and Pydantic 2; they do not supply Zeek parsing, networking thresholds,
provider calls or dataset truth. Import the named submodules directly: the package
root exports only `EvidenceRef` and `FlaggedGroupV1`.

| Module | Reusable API and caller responsibility |
| --- | --- |
| [schemas.py](schemas.py) | `KeyPart`, `TimeWindow`, `EvidenceSupport`, `TypedStatV1`, `FlaggedGroupV1` and `ClaimV1` validate declared structure and support relationships. Validation alone does not prove source existence or recompute a claim. |
| [parsers.py](parsers.py) | `Parser`, `Rule`, `EvidenceRecord` and `RuleContext` define typed adapter contracts. The consumer implements parsing and its own domain rules. |
| [windows.py](windows.py) | `ordered` and `sliding_windows` use caller timestamp, tie and grouping functions. Windows are epoch-aligned and half-open. Check `WindowBatch.complete`; a bucket limit can leave partial results. |
| [aggregate.py](aggregate.py) | `support_for`, `measured_stat`, `sum_stat`, `interval_stats` and `byte_cv_stat` construct support-bound statistics. Supply the correct source digest, row identity, values and units; unknown values remain distinct from zero. |
| [rules.py](rules.py) | `Candidate`, `merge_candidates` and `identified_group` merge overlapping candidates for the same rule/key and identify the resulting group. Domain thresholds and categories belong to the consumer. |
| [context.py](context.py) | `ContextV1` provides bounded context identity/time fields. Consumers decide which domain-specific context applies and preserve suppressed evidence. |
| [evidence.py](evidence.py) | `check_group`, `EvidenceSource`, `StatSpec`, `TemplateSpec` and `EvidenceSentenceV1` resolve complete support and recompute claims using caller-supplied source, statistics and templates. Inspect the returned state and rejection reasons. |
| [proposals.py](proposals.py) | `neutral_proposal` projects verified support to inert text beginning `NOT APPLIED`. Suppressed, unclear or unverified groups yield investigation text. It applies no action. |
| [evaluation.py](evaluation.py) | `OverlapEdge` and `maximum_overlap_assignment` perform bounded one-to-one matching over caller-declared eligible edges. They do not read a corpus, establish semantic eligibility or measure detection quality. |

## Tiny non-network consumer

For a detached consumer, place unchanged `schemas.py`, `windows.py`, `aggregate.py`
and `rules.py` beside an empty `__init__.py` in a `resource_rules` package. Keep their
relative imports intact and provide Pydantic in the consumer's environment. Within
the installed application, the equivalent imports use
`firewall_analyst.shared.rulesengine` instead of `resource_rules`.

```python
from dataclasses import dataclass

from resource_rules.aggregate import sum_stat, support_for
from resource_rules.rules import Candidate, merge_candidates
from resource_rules.schemas import KeyPart
from resource_rules.windows import sliding_windows


@dataclass(frozen=True)
class ResourceChange:
    row_id: str
    at_us: int
    ordinal: int
    delta: int


# Hand example only: replace the illustrative digest with the actual source hash.
rows = (ResourceChange("resource:1", 30, 1, 1), ResourceChange("resource:2", 40, 2, 1))
key = (KeyPart(name="module", value="storage"),)
batch = sliding_windows(
    rows, timestamp=lambda r: r.at_us, tie=lambda r: r.ordinal,
    key=lambda r: key, width_us=60, stride_us=30,
)
assert batch.complete
candidates = tuple(
    Candidate("resource_change", b.key, b.window, b.rows)
    for b in batch.buckets if sum(r.delta for r in b.rows) >= 2
)
merged, = merge_candidates(
    candidates, row_id=lambda r: r.row_id,
    timestamp=lambda r: r.at_us, tie=lambda r: r.ordinal,
)
support = support_for(merged.rows, source_sha256="a" * 64, row_id=lambda r: r.row_id)
stat = sum_stat(
    merged.rows, getter=lambda r: r.delta, support=support,
    stat_id="changes", unit="count",
)
assert stat.value == 2 and stat.known_count == 2
assert len(merged.rows) == 2  # Overlapping windows did not duplicate the records.
```

This example stops at declared statistics. For a complete source-resolved
claim/check/proposal consumer, see the existing
[ResourceChange evidence example](../../../../tests/evidence/test_portable.py).
The [detached rule example](../../../../tests/rules/test_detached.py) also exercises
context and group construction. These hand examples demonstrate mechanics, not
detector quality, independent dataset eligibility or an installed-wheel origin
join. Preserve source/configuration identity and ownership when copying modules;
moving files alone does not establish verified vendoring or platform acceptance.
