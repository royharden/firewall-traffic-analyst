"""Original-reference accounting for produced and explicitly unsupported evidence."""

from collections import Counter
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, Self

from pydantic import BeforeValidator, Field, TypeAdapter, model_validator

from .models import (
    ArtifactRef,
    Count,
    DatasetID,
    Digest,
    Finding,
    LogicalID,
    MetricField,
    MetricReason,
    MetricStatus,
    NonnegativeInt,
    Pointer,
    PositiveInt,
    Resolution,
    ResolutionContext,
    Version,
    WireModel,
    _array,
    pointer_key,
)
from .registry import Registry
from .rowcanonical import digest, metric_bytes, pointer_fits


class FailureMeasurement(WireModel):
    status: Literal["unsupported"]
    reference_id: LogicalID
    namespace_id: LogicalID
    measured_bytes: NonnegativeInt
    limit_bytes: PositiveInt
    measurement_kind: Literal["exact", "lower_bound"]

    @model_validator(mode="after")
    def exceeded(self) -> Self:
        if self.measured_bytes <= self.limit_bytes:
            raise ValueError("failure measurement must exceed effective cap")
        return self


class MetricUnsupportedProduction(FailureMeasurement):
    profile: Literal["s9-metric-row.v1"]
    dataset_id: DatasetID
    raw_dataset_sha256: Digest
    snapshot_id: Digest
    metric_id: MetricField
    n: Count
    N: Count
    metric_status: MetricStatus
    metric_status_reason: MetricReason | None
    failure_reason: Literal[
        "metric_artifact_overflow", "metric_row_overflow", "metric_pointer_overflow"
    ]

    @model_validator(mode="after")
    def actual_support(self) -> Self:
        if self.n > self.N or ((self.metric_status == "ok") != (self.metric_status_reason is None)):
            raise ValueError("failure must retain exact support counts/status")
        return self


class EventUnsupportedProduction(FailureMeasurement):
    profile: Literal["s8-zeek-physical-row-v1"]
    source_id: LogicalID
    source_sha256: Digest
    source_revision: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    processing_generation: Digest
    row_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}:[1-9][0-9]{0,7}$")]
    physical_line_number: Annotated[int, Field(ge=1, le=10000000)]
    event_record_sha256: Digest | None
    failure_reason: Literal[
        "event_row_overflow", "event_artifact_overflow", "event_pointer_overflow"
    ]

    @model_validator(mode="after")
    def original_row(self) -> Self:
        if (
            self.row_id != f"{self.source_sha256}:{self.physical_line_number}"
            or self.source_revision != f"sha256:{self.source_sha256}"
            or (self.event_record_sha256 is None and self.failure_reason != "event_row_overflow")
        ):
            raise ValueError("event failure must retain actual raw/physical/record identity")
        return self


class ProducedEvidence(WireModel):
    status: Literal["produced"]
    reference_id: LogicalID
    pointer: Pointer


UnsupportedProduction = Annotated[
    EventUnsupportedProduction | MetricUnsupportedProduction, Field(discriminator="profile")
]
EvidenceProduction = ProducedEvidence | UnsupportedProduction
PRODUCTION_ADAPTER = TypeAdapter(EvidenceProduction)


class RequiredEvidenceFrame(WireModel):
    """Trusted pre-production registration; authority, never outputs, owns this set."""

    schema_version: Version = 1
    request_id: LogicalID
    namespace_id: LogicalID
    authority_ref: ArtifactRef
    required_reference_ids: Annotated[
        tuple[LogicalID, ...], BeforeValidator(_array), Field(max_length=10000)
    ]

    @model_validator(mode="after")
    def original_ordered_set(self) -> Self:
        if len(set(self.required_reference_ids)) != len(self.required_reference_ids):
            raise ValueError("original required references must be unique")
        return self

    @property
    def frame_sha256(self):
        return digest(metric_bytes(self.model_dump(mode="json")))


class RequiredReferenceAuthority(Protocol):
    reference: ArtifactRef

    def original(self, namespace_id: str, request_id: str) -> RequiredEvidenceFrame | None: ...


@dataclass(frozen=True, slots=True)
class ProducedEvidenceAssessment:
    finding: Finding
    frame: RequiredEvidenceFrame
    resolutions: tuple[Resolution, ...]
    production_failures: tuple[EventUnsupportedProduction | MetricUnsupportedProduction | None, ...]
    reason_counts: tuple[tuple[str, int], ...]
    contract_errors: tuple[str, ...]

    @property
    def required_reference_ids(self):
        return self.frame.required_reference_ids

    @property
    def required_count(self):
        return len(self.required_reference_ids)

    @property
    def resolved_count(self):
        return sum(r.status == "resolved" for r in self.resolutions)

    @property
    def unresolved_count(self):
        return self.required_count - self.resolved_count

    @property
    def status_counts(self):
        return tuple(sorted(Counter(r.status for r in self.resolutions).items()))


def assess_produced_evidence(
    finding,
    productions,
    registry: Registry,
    context,
    frame: RequiredEvidenceFrame,
    *,
    authority: RequiredReferenceAuthority,
):
    """Keep the authoritative original denominator, including all contract failures."""
    finding = Finding.model_validate(finding)
    context = ResolutionContext.model_validate(context)
    frame = RequiredEvidenceFrame.model_validate(frame)
    errors = []
    original = None
    try:
        actual_ref = ArtifactRef.model_validate(authority.reference)
        original = authority.original(context.namespace_id, frame.request_id)
        if original is not None:
            original = RequiredEvidenceFrame.model_validate(original)
        if (
            original is None
            or actual_ref != frame.authority_ref
            or original.authority_ref != actual_ref
            or original.namespace_id != context.namespace_id
            or original.request_id != frame.request_id
        ):
            errors.append("required_frame_unavailable")
        elif original != frame:
            errors.append("required_frame_mismatch")
    except Exception:
        errors.append("required_frame_unavailable")
    # Even a forged lowered caller frame cannot define the registered denominator.
    if (
        original is not None
        and original.namespace_id == context.namespace_id
        and original.request_id == frame.request_id
    ):
        frame = original
    required = frame.required_reference_ids
    parsed = []
    if type(productions) is not tuple or len(productions) > 10000:
        errors.append("production_collection_invalid")
    else:
        for production in productions:
            try:
                candidate = (
                    production.get("pointer")
                    if type(production) is dict
                    else production.pointer
                    if isinstance(production, ProducedEvidence)
                    else None
                )
                if pointer_key(candidate) in (
                    ("row:id", "event_table", "row"),
                    ("row:id", "metric_table", "metric"),
                ):
                    if not pointer_fits(candidate):
                        raise ValueError("production Pointer byte ceiling")
                parsed.append(PRODUCTION_ADAPTER.validate_python(production))
            except Exception:
                errors.append("production_wire_invalid")
    indexed = {}
    for production in parsed:
        if production.reference_id not in required:
            errors.append("extra_production")
        elif production.reference_id in indexed:
            errors.append("duplicate_production")
        else:
            indexed[production.reference_id] = production
    produced = tuple(
        indexed[id].pointer
        for id in required
        if id in indexed and isinstance(indexed[id], ProducedEvidence)
    )
    if produced != finding.evidence:
        errors.append("production_binding_mismatch")
    resolutions = []
    failures = []
    for id in required:
        production = indexed.get(id)
        failure = (
            production
            if isinstance(production, (MetricUnsupportedProduction, EventUnsupportedProduction))
            else None
        )
        failures.append(failure)
        if production is None:
            resolution = Resolution(status="invalid", reason="missing_production")
        elif failure is not None:
            if failure.namespace_id != context.namespace_id:
                resolution = Resolution(status="invalid", reason="production_namespace_mismatch")
            else:
                resolution = Resolution(status="unsupported", reason=failure.failure_reason)
        elif errors:
            resolution = Resolution(status="invalid", reason=errors[0])
        else:
            resolution = registry.resolve(production.pointer, context)
        resolutions.append(resolution)
    try:
        final = authority.original(context.namespace_id, frame.request_id)
        if (
            final is None
            or RequiredEvidenceFrame.model_validate(final) != frame
            or ArtifactRef.model_validate(authority.reference) != frame.authority_ref
        ):
            errors.append("required_frame_changed")
            resolutions = [
                Resolution(status="invalid", reason="required_frame_changed") for _ in required
            ]
    except Exception:
        errors.append("required_frame_unavailable")
        resolutions = [
            Resolution(status="invalid", reason="required_frame_unavailable") for _ in required
        ]
    reasons = Counter(r.reason for r in resolutions if r.status != "resolved")
    if not required:
        reasons["no_required_evidence"] += 1
    if errors or reasons:
        data = finding.model_dump()
        data["verdict"] = "unsupported"
        finding = Finding.model_validate(data)
    return ProducedEvidenceAssessment(
        finding,
        frame,
        tuple(resolutions),
        tuple(failures),
        tuple(sorted(reasons.items())),
        tuple(errors),
    )
