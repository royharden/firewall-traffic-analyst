"""Resolve evidence and recompute named statistics before rendering fixed templates.

Trusted consumers inject source lookup, scope policy, arithmetic and templates.
No source path discovery, domain/provider import or arbitrary model-authored prose.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol

from pydantic import Field

from .parsers import EvidenceRecord
from .schemas import (
    BoundaryModel,
    ClaimSupportContractV1,
    ClaimV1,
    EvidenceRef,
    EvidenceSupport,
    FlaggedGroupV1,
    Token,
    TypedStatV1,
)


class EvidenceSentenceV1(BoundaryModel):
    sentence_id: Token
    template_id: Token
    label_kind: Literal["observed_statistic", "deterministic_inference", "model_annotation"]
    claims: Annotated[tuple[ClaimV1, ...], Field(min_length=1, max_length=8)]
    examples: Annotated[tuple[EvidenceRef, ...], Field(max_length=5)] = ()


class CheckedSentenceV1(EvidenceSentenceV1):
    text: Annotated[str, Field(min_length=1, max_length=8192)]


class EvidenceSource[T: EvidenceRecord](Protocol):
    def validate_generation(self, source_sha256: str) -> None: ...
    def resolve(self, refs: tuple[EvidenceRef, ...]) -> tuple[T, ...]: ...
    def validate_group(self, group: FlaggedGroupV1, rows: Sequence[T]) -> None: ...


@dataclass(frozen=True)
class StatSpec[T]:
    unit: str
    compute: Callable[[Sequence[T], EvidenceSupport], TypedStatV1]


@dataclass(frozen=True)
class TemplateSpec:
    stat_refs: tuple[str, ...]
    formatters: tuple[str, ...]
    segments: tuple[str, ...]
    label_kind: str = "observed_statistic"

    def __post_init__(self):
        if not 1 <= len(self.stat_refs) <= 8 or len(self.formatters) != len(self.stat_refs):
            raise ValueError("invalid_template")
        if len(self.segments) != len(self.stat_refs) + 1:
            raise ValueError("invalid_template")


@dataclass(frozen=True)
class CheckedEvidence:
    group_id: str
    source_sha256: str
    state: Literal["verified", "explanation_failed"]
    sentences: tuple[CheckedSentenceV1, ...]
    reason_codes: tuple[str, ...]


class _Invalid(ValueError):
    pass


def _rows[T: EvidenceRecord](source: EvidenceSource[T], support: EvidenceSupport) -> tuple[T, ...]:
    refs = tuple(
        EvidenceRef(source_sha256=support.source_sha256, row_id=row_id)
        for row_id in support.row_ids
    )
    rows = source.resolve(refs)
    if tuple(row.row_id for row in rows) != support.row_ids or any(
        row.source_sha256 != support.source_sha256 for row in rows
    ):
        raise _Invalid("resolved_identity_mismatch")
    return rows


def _recompute[T: EvidenceRecord](
    source: EvidenceSource[T],
    registry: Mapping[str, StatSpec[T]],
    stat_id: str,
    support: EvidenceSupport,
) -> TypedStatV1:
    spec = registry.get(stat_id)
    if spec is None:
        raise _Invalid("unsupported_statistic")
    actual = spec.compute(_rows(source, support), support)
    if actual.stat_id != stat_id or actual.unit != spec.unit or actual.support != support:
        raise _Invalid("invalid_statistic_adapter")
    return actual


def _format(value: int | float, formatter: str) -> str:
    if formatter == "integer" and type(value) is int:
        return str(value)
    if formatter in {"decimal_3", "ratio_6"} and type(value) in (int, float):
        return format(value, ".3f" if formatter == "decimal_3" else ".6f")
    raise _Invalid("unsupported_formatter")


def check_group[T: EvidenceRecord](
    group: FlaggedGroupV1,
    sentences: Sequence[EvidenceSentenceV1],
    *,
    source: EvidenceSource[T],
    registry: Mapping[str, StatSpec[T]],
    templates: Mapping[str, TemplateSpec],
) -> CheckedEvidence:
    """All declared group statistics are recomputed; display examples are never proof.

    Failed sentences are dropped. At least one checked observed-statistic sentence is
    required; inference/model-only or empty output cannot be a successful explanation.
    Source generation is checked on both sides of the operation. Diagnostics are codes.
    """

    def failed(reason: str) -> CheckedEvidence:
        return CheckedEvidence(
            group.group_id, group.support.source_sha256, "explanation_failed", (), (reason,)
        )

    try:
        source.validate_generation(group.support.source_sha256)
        source.validate_group(group, _rows(source, group.support))
    except (ValueError, OSError, KeyError):
        return failed("source_or_scope_unavailable")
    try:
        for declared in group.stats:
            actual = _recompute(source, registry, declared.stat_id, declared.support)
            if actual != declared:
                raise _Invalid("declared_statistic_mismatch")
    except _Invalid as exc:
        return failed(str(exc))
    except (ValueError, OSError, KeyError):
        return failed("statistic_unavailable")
    checked, reasons = [], []
    for sentence in sentences:
        try:
            template = templates.get(sentence.template_id)
            if template is None or sentence.label_kind != template.label_kind:
                raise _Invalid("unsupported_template")
            if tuple(claim.stat_ref for claim in sentence.claims) != template.stat_refs:
                raise _Invalid("template_claim_mismatch")
            if tuple(claim.formatter for claim in sentence.claims) != template.formatters:
                raise _Invalid("template_formatter_mismatch")
            ClaimSupportContractV1(group=group, claims=sentence.claims)
            values = []
            for claim in sentence.claims:
                actual = _recompute(source, registry, claim.stat_ref, claim.support)
                if actual.value is None or actual.value != claim.value or actual.unit != claim.unit:
                    raise _Invalid("claim_recomputation_mismatch")
                values.append(_format(claim.value, claim.formatter))
            if any(
                ref.source_sha256 != group.support.source_sha256
                or ref.row_id not in group.support.row_ids
                for ref in sentence.examples
            ):
                raise _Invalid("example_scope_mismatch")
            if sentence.examples:
                examples = source.resolve(sentence.examples)
                if tuple(row.row_id for row in examples) != tuple(
                    ref.row_id for ref in sentence.examples
                ) or any(row.source_sha256 != group.support.source_sha256 for row in examples):
                    raise _Invalid("example_scope_mismatch")
            text = template.segments[0] + "".join(
                value + suffix for value, suffix in zip(values, template.segments[1:], strict=True)
            )
            declared = {stat.stat_id: stat for stat in group.stats}
            if any(
                claim.support.support_sha256 != declared[claim.stat_ref].support.support_sha256
                for claim in sentence.claims
            ):
                text = "Selected evidence subset: " + text
            checked.append(CheckedSentenceV1(**sentence.model_dump(), text=text))
        except _Invalid as exc:
            reasons.append(str(exc))
        except (ValueError, OSError, KeyError):
            reasons.append("sentence_unavailable")
    try:
        source.validate_generation(group.support.source_sha256)
    except (ValueError, OSError):
        return failed("source_changed")
    if not any(sentence.label_kind == "observed_statistic" for sentence in checked):
        return failed("no_checked_observation")
    return CheckedEvidence(
        group.group_id,
        group.support.source_sha256,
        "verified",
        tuple(checked),
        tuple(dict.fromkeys(reasons)),
    )
