"""Bounded evidence serialization of already-produced source facts, never source IO."""

import base64
import json
from dataclasses import dataclass

from pydantic import TypeAdapter

from .models import (
    ArtifactRef,
    EventLocator,
    EventPointer,
    MetricArtifact,
    MetricLocator,
    MetricPointer,
    NonnegativeInt,
    SourceArtifact,
)
from .production import (
    EventUnsupportedProduction,
    MetricUnsupportedProduction,
    ProducedEvidence,
    RequiredEvidenceFrame,
)
from .rowcanonical import ARTIFACT_BYTES, decode_retained, digest, encode_capped, metric_bytes
from .rows import (
    DEFAULT_ROW_BOUNDS,
    EventProcessingDescriptor,
    RetainedRows,
    RowBounds,
    RowGeneration,
    _record_shape,
)


@dataclass(frozen=True, slots=True)
class RowProductionBatch:
    retained: RetainedRows | None
    outcomes: tuple[
        ProducedEvidence | EventUnsupportedProduction | MetricUnsupportedProduction, ...
    ]


def _pointer_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf8")


def produce_metric_rows(
    artifact,
    frame,
    metric_ids,
    *,
    raw_identity_byte_length: int,
    provenance_ref: ArtifactRef | None = None,
    bounds: RowBounds = DEFAULT_ROW_BOUNDS,
):
    """Producer supplies registered IDs and actual raw canonical-identity byte length.

    This layer never recomputes a metric, source fingerprint, clock or source length.
    It retains the complete artifact atomically and reports every original overflow.
    """
    if type(bounds) is not RowBounds:
        raise TypeError("explicit immutable row bounds required")
    bounds.__post_init__()
    frame = RequiredEvidenceFrame.model_validate(frame)
    artifact = MetricArtifact.model_validate(artifact)
    if provenance_ref is not None:
        provenance_ref = ArtifactRef.model_validate(provenance_ref)
    TypeAdapter(NonnegativeInt).validate_python(raw_identity_byte_length, strict=True)
    if raw_identity_byte_length == 0:
        raise ValueError("canonical dataset identity must have actual nonempty source bytes")
    if (
        type(metric_ids) is not tuple
        or len(metric_ids) != len(frame.required_reference_ids)
        or artifact.namespace_id != frame.namespace_id
    ):
        raise ValueError("original frame/metric mapping mismatch")
    rows = {row.metric_id: row for row in artifact.rows}
    if any(type(id) is not str or id not in rows for id in metric_ids):
        raise ValueError("required metric missing from whole artifact")
    raw, measured, measurement = encode_capped(
        artifact.model_dump(mode="json"), maximum=bounds.max_artifact_bytes, metric=True
    )

    def failure(reference, row, reason, measured, limit, kind):
        return MetricUnsupportedProduction(
            status="unsupported",
            reference_id=reference,
            profile="s9-metric-row.v1",
            namespace_id=frame.namespace_id,
            dataset_id=artifact.dataset_id,
            raw_dataset_sha256=artifact.dataset_fingerprint,
            snapshot_id=artifact.snapshot_id,
            metric_id=row.metric_id,
            n=row.n,
            N=row.N,
            metric_status=row.status,
            metric_status_reason=row.status_reason,
            failure_reason=reason,
            measured_bytes=measured,
            limit_bytes=limit,
            measurement_kind=kind,
        )

    if raw is None:
        return RowProductionBatch(
            None,
            tuple(
                failure(
                    ref,
                    rows[id],
                    "metric_artifact_overflow",
                    measured,
                    bounds.max_artifact_bytes,
                    measurement,
                )
                for ref, id in zip(frame.required_reference_ids, metric_ids, strict=True)
            ),
        )
    source = SourceArtifact(
        source_id=artifact.dataset_id,
        source_type="metric_table",
        source_sha256=artifact.dataset_fingerprint,
        source_revision=artifact.dataset_fingerprint,
        evidence_artifact_sha256=digest(raw),
        raw_byte_length=raw_identity_byte_length,
    )
    generation = RowGeneration(
        namespace_id=frame.namespace_id,
        metadata=source,
        profile="s9-metric-row.v1",
        derived_generation=artifact.snapshot_id,
    )
    outcomes = []
    for reference, id in zip(frame.required_reference_ids, metric_ids, strict=True):
        row = rows[id]
        row_raw = metric_bytes(row.model_dump(mode="json"))
        if len(row_raw) > bounds.max_metric_row_bytes:
            outcomes.append(
                failure(
                    reference,
                    row,
                    "metric_row_overflow",
                    len(row_raw),
                    bounds.max_metric_row_bytes,
                    "exact",
                )
            )
            continue
        loc = MetricLocator(
            profile="s9-metric-row.v1",
            dataset_id=artifact.dataset_id,
            snapshot_id=artifact.snapshot_id,
            row_sha256=digest(row_raw),
            metric_id=id,
            scope=row.scope,
            expected=row,
        )
        fields = dict(
            schema_version=1,
            source_id=artifact.dataset_id,
            source_sha256=source.source_sha256,
            source_revision=source.source_revision,
            evidence_artifact_sha256=source.evidence_artifact_sha256,
            provenance_ref=provenance_ref,
            kind="row:id",
            source_type="metric_table",
            locator_subtype="metric",
            locator=loc,
        )
        dumped = {
            **fields,
            "locator": loc.model_dump(mode="json"),
            "provenance_ref": provenance_ref.model_dump(mode="json") if provenance_ref else None,
        }
        size = len(_pointer_bytes(dumped))
        if size > bounds.max_pointer_bytes:
            outcomes.append(
                failure(
                    reference,
                    row,
                    "metric_pointer_overflow",
                    size,
                    bounds.max_pointer_bytes,
                    "exact",
                )
            )
        else:
            outcomes.append(
                ProducedEvidence(
                    status="produced", reference_id=reference, pointer=MetricPointer(**fields)
                )
            )
    return RowProductionBatch(RetainedRows(generation, raw), tuple(outcomes))


def produce_event_row(
    *,
    reference_id,
    namespace_id,
    source_id,
    source_sha256,
    raw_source_byte_length,
    physical_line_number,
    quote: bytes,
    processing_descriptor: bytes,
    event_record: bytes | None,
    bounds: RowBounds = DEFAULT_ROW_BOUNDS,
):
    """Serialize a trusted producer physical row; full-file identity/proof stays owner-owned."""
    if type(bounds) is not RowBounds:
        raise TypeError("explicit immutable row bounds required")
    bounds.__post_init__()
    TypeAdapter(NonnegativeInt).validate_python(raw_source_byte_length, strict=True)
    if type(quote) is not bytes:
        raise TypeError("immutable physical row bytes required")
    if len(quote) > raw_source_byte_length:
        raise ValueError("physical row cannot exceed complete source byte length")
    descriptor = EventProcessingDescriptor.model_validate(
        decode_retained(processing_descriptor, maximum=16384, metric=False)
    )
    if descriptor.source_sha256 != source_sha256:
        raise ValueError("event source descriptor mismatch")
    generation_sha = digest(processing_descriptor)
    record_sha = None
    if event_record is not None:
        # This bounded input proof supplies the real digest even when retention fails.
        record = decode_retained(event_record, maximum=ARTIFACT_BYTES, metric=False)
        _record_shape(record, source_sha256, physical_line_number)
        record_sha = digest(event_record)
    common = dict(
        status="unsupported",
        reference_id=reference_id,
        profile="s8-zeek-physical-row-v1",
        namespace_id=namespace_id,
        source_id=source_id,
        source_sha256=source_sha256,
        source_revision=f"sha256:{source_sha256}",
        processing_generation=generation_sha,
        row_id=f"{source_sha256}:{physical_line_number}",
        physical_line_number=physical_line_number,
        event_record_sha256=record_sha,
    )

    def failure(reason, measured, limit, kind="exact"):
        return RowProductionBatch(
            None,
            (
                EventUnsupportedProduction(
                    **common,
                    failure_reason=reason,
                    measured_bytes=measured,
                    limit_bytes=limit,
                    measurement_kind=kind,
                ),
            ),
        )

    if len(quote) > bounds.max_event_quote_bytes:
        return failure("event_row_overflow", len(quote), bounds.max_event_quote_bytes)
    if event_record is None:
        raise ValueError("actual valid producer event record required")
    text = quote.decode("utf8", errors="strict")
    artifact = dict(
        algorithm="s8-zeek-physical-row-evidence-v1",
        source_sha256=source_sha256,
        source_revision=common["source_revision"],
        processing_generation=generation_sha,
        physical_line_number=physical_line_number,
        row_id=common["row_id"],
        event_record_sha256=record_sha,
        raw_line_base64=base64.b64encode(quote).decode("ascii"),
    )
    raw, measured, kind = encode_capped(artifact, maximum=bounds.max_artifact_bytes, metric=False)
    if raw is None:
        return failure("event_artifact_overflow", measured, bounds.max_artifact_bytes, kind)
    loc = EventLocator(
        profile_version="s8-zeek-physical-row-v1",
        row_id=common["row_id"],
        physical_line_number=physical_line_number,
        processing_generation=generation_sha,
        event_record_sha256=record_sha,
        quote=text,
        excerpt_sha256=digest(quote),
    )
    fields = dict(
        schema_version=1,
        source_id=source_id,
        source_sha256=source_sha256,
        source_revision=common["source_revision"],
        evidence_artifact_sha256=digest(raw),
        provenance_ref=None,
        kind="row:id",
        source_type="event_table",
        locator_subtype="row",
        locator=loc,
    )
    wire = {**fields, "locator": loc.model_dump(mode="json")}
    size = len(_pointer_bytes(wire))
    if size > bounds.max_pointer_bytes:
        return failure("event_pointer_overflow", size, bounds.max_pointer_bytes)
    pointer = EventPointer(**fields)
    source = SourceArtifact(
        source_id=source_id,
        source_type="event_table",
        source_sha256=source_sha256,
        source_revision=common["source_revision"],
        evidence_artifact_sha256=digest(raw),
        raw_byte_length=raw_source_byte_length,
    )
    generation = RowGeneration(
        namespace_id=namespace_id,
        metadata=source,
        profile="s8-zeek-physical-row-v1",
        derived_generation=generation_sha,
    )
    return RowProductionBatch(
        RetainedRows(generation, raw, processing_descriptor, event_record),
        (ProducedEvidence(status="produced", reference_id=reference_id, pointer=pointer),),
    )
