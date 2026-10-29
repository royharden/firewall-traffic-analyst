"""Optional retained event/metric resolvers. Backends own access and source proofs."""

import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, Protocol

from .models import (
    POINTER_ADAPTER,
    ArtifactRef,
    Digest,
    EventPointer,
    EventRowProvenance,
    LogicalID,
    MetricArtifact,
    MetricPointer,
    MetricRowProvenance,
    Resolution,
    ResolutionContext,
    ResolutionProvenance,
    SourceArtifact,
    WireModel,
)
from .registry import DuplicateResolverError, Registry
from .rowcanonical import (
    ARTIFACT_BYTES,
    EVENT_QUOTE_BYTES,
    POINTER_BYTES,
    ROW_BYTES,
    decode_retained,
    digest,
    event_bytes,
    metric_bytes,
)

EVENT_KEY = ("row:id", "event_table", "row")
METRIC_KEY = ("row:id", "metric_table", "metric")


class EventProcessingDescriptor(WireModel):
    algorithm: Literal["s8-zeek-processing-v2"]
    source_sha256: Digest
    parser_version: Literal["zeek-conn-1.1"]
    parser_implementation_sha256: Digest
    parser_runtime_sha256: Digest
    parser_config_sha256: Digest
    event_schema_sha256: Digest
    projection_version: Literal["event-v1-json-v1"]


class RowGeneration(WireModel):
    namespace_id: LogicalID
    metadata: SourceArtifact
    profile: Literal["s8-zeek-physical-row-v1", "s9-metric-row.v1"]
    derived_generation: Digest


@dataclass(frozen=True, slots=True)
class RetainedRows:
    """Immutable full retained bytes plus actual producer descriptor/record, never paths."""

    generation: RowGeneration
    artifact: bytes
    processing_descriptor: bytes | None = None
    event_record: bytes | None = None


@dataclass(frozen=True, slots=True)
class RowBounds:
    max_artifact_bytes: int = ARTIFACT_BYTES
    max_metric_row_bytes: int = ROW_BYTES
    max_pointer_bytes: int = POINTER_BYTES
    max_excerpt_bytes: int = POINTER_BYTES
    max_event_quote_bytes: int = EVENT_QUOTE_BYTES

    def __post_init__(self):
        for name, ceiling in (
            ("max_artifact_bytes", ARTIFACT_BYTES),
            ("max_metric_row_bytes", ROW_BYTES),
            ("max_pointer_bytes", POINTER_BYTES),
            ("max_excerpt_bytes", POINTER_BYTES),
            ("max_event_quote_bytes", EVENT_QUOTE_BYTES),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("row bounds must be positive integers within profile ceilings")


DEFAULT_ROW_BOUNDS = RowBounds()


class RowBackend(Protocol):
    access_policy_ref: ArtifactRef
    generation_policy_ref: ArtifactRef

    def decision(
        self, namespace_id: str, source_id: str
    ) -> Literal["allow", "deny", "unknown"]: ...
    def current(self, namespace_id: str, source_id: str) -> RowGeneration | None: ...
    def allow_historical(self, context: ResolutionContext, generation: RowGeneration) -> bool: ...
    def retained(
        self, context: ResolutionContext, pointer: EventPointer | MetricPointer
    ) -> RetainedRows | None: ...


def _record_shape(record, source_sha, line):
    """Public EventV1 JSON shape only, not the owner parser/model or row authenticity."""
    keys = {
        "schema_version",
        "input_sha256",
        "raw_line_number",
        "row_id",
        "ts_us",
        "src",
        "dst",
        "src_port",
        "dst_port",
        "protocol",
        "action",
        "direction",
        "conn_state",
        "uid",
        "duration_us",
        "orig_bytes",
        "resp_bytes",
        "total_bytes",
        "icmp_type",
        "icmp_code",
        "quality_flags",
    }
    if type(record) is not dict or set(record) != keys:
        raise ValueError("event record must retain complete public fields")
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or type(record["raw_line_number"]) is not int
        or record["raw_line_number"] != line
        or record["row_id"] != f"{source_sha}:{line}"
        or record["input_sha256"] != source_sha
        or record["action"] != "unknown"
        or record["protocol"] not in ("tcp", "udp", "icmp")
        or record["direction"] not in ("inbound", "outbound", "internal", "external", "unknown")
    ):
        raise ValueError("event record identity/enum mismatch")
    if type(record["ts_us"]) is not int or record["ts_us"] < 0:
        raise ValueError("invalid event timestamp")
    for field in ("src", "dst"):
        if type(record[field]) is not str:
            raise ValueError("invalid event address")
        ipaddress.ip_address(record[field])
    for field in (
        "src_port",
        "dst_port",
        "duration_us",
        "orig_bytes",
        "resp_bytes",
        "total_bytes",
        "icmp_type",
        "icmp_code",
    ):
        value = record[field]
        ceiling = 65535 if field.endswith("_port") else 255 if field.startswith("icmp_") else None
        if value is not None and (
            type(value) is not int or value < 0 or (ceiling is not None and value > ceiling)
        ):
            raise ValueError("invalid event numeric field")
    for field, pattern in (("uid", r"^C[A-Za-z0-9]{8,24}$"), ("conn_state", r"^[A-Z0-9]{1,16}$")):
        if record[field] is not None and (
            type(record[field]) is not str or re.fullmatch(pattern, record[field]) is None
        ):
            raise ValueError("invalid event optional identifier")
    flags = record["quality_flags"]
    if type(flags) is not list or any(
        type(f) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", f) is None
        for f in flags
    ):
        raise ValueError("invalid event quality flags")


class RowResolver:
    def __init__(self, backend: RowBackend, *, bounds: RowBounds = DEFAULT_ROW_BOUNDS):
        if type(bounds) is not RowBounds:
            raise TypeError("explicit immutable row bounds required")
        bounds.__post_init__()
        self.backend, self.bounds = backend, bounds

    def _admit(self, pointer, context, generation):
        access = ArtifactRef.model_validate(self.backend.access_policy_ref)
        current_ref = ArtifactRef.model_validate(self.backend.generation_policy_ref)
        if access != context.access_policy_ref or current_ref != context.generation_policy_ref:
            return Resolution(status="unsupported", reason="policy_reference_mismatch")
        decision = self.backend.decision(context.namespace_id, pointer.source_id)
        if type(decision) is not str or decision != "allow":
            return Resolution(status="unsupported", reason="access_not_allowed")
        current = self.backend.current(context.namespace_id, pointer.source_id)
        if current is None:
            return Resolution(status="unsupported", reason="current_generation_unknown")
        current = RowGeneration.model_validate(current)
        if (
            current.namespace_id != context.namespace_id
            or current.metadata.source_id != pointer.source_id
            or current.profile != generation.profile
            or current.metadata.source_type != pointer.source_type
        ):
            return Resolution(status="invalid", reason="current_source_identity_mismatch")
        if context.generation_mode == "current":
            if current != generation:
                return Resolution(status="stale", reason="current_generation_mismatch")
        elif self.backend.allow_historical(context, generation) is not True:
            return Resolution(status="unsupported", reason="historical_not_allowed")
        return current

    def resolve(self, pointer, context):
        try:
            pointer = POINTER_ADAPTER.validate_python(pointer)
            context = ResolutionContext.model_validate(context)
            if not isinstance(pointer, (EventPointer, MetricPointer)) or pointer.locator is None:
                return Resolution(status="unsupported", reason="row_domain_unsupported")
            if context.required_scope in ("spatial", "text_and_spatial"):
                return Resolution(status="unsupported", reason="required_scope_unavailable")
            # Access is checked before asking a backend for retained source bytes.
            if (
                ArtifactRef.model_validate(self.backend.access_policy_ref)
                != context.access_policy_ref
                or ArtifactRef.model_validate(self.backend.generation_policy_ref)
                != context.generation_policy_ref
            ):
                return Resolution(status="unsupported", reason="policy_reference_mismatch")
            decision = self.backend.decision(context.namespace_id, pointer.source_id)
            if type(decision) is not str or decision != "allow":
                return Resolution(status="unsupported", reason="access_not_allowed")
            retained = self.backend.retained(context, pointer)
            if retained is None:
                return Resolution(status="missing", reason="retained_source_missing")
            if type(retained) is not RetainedRows or type(retained.artifact) is not bytes:
                return Resolution(status="invalid", reason="retained_source_mismatch")
            generation = RowGeneration.model_validate(retained.generation)
            metadata = generation.metadata
            profile = (
                "s8-zeek-physical-row-v1"
                if isinstance(pointer, EventPointer)
                else "s9-metric-row.v1"
            )
            derived = (
                pointer.locator.processing_generation
                if isinstance(pointer, EventPointer)
                else pointer.locator.snapshot_id
            )
            if (
                generation.namespace_id != context.namespace_id
                or generation.profile != profile
                or generation.derived_generation != derived
                or metadata.source_type != pointer.source_type
                or metadata.source_id != pointer.source_id
                or metadata.source_revision != pointer.source_revision
                or metadata.source_sha256 != pointer.source_sha256
                or metadata.evidence_artifact_sha256 != pointer.evidence_artifact_sha256
            ):
                return Resolution(status="invalid", reason="retained_generation_mismatch")
            current = self._admit(pointer, context, generation)
            if isinstance(current, Resolution):
                return current
            if len(retained.artifact) > self.bounds.max_artifact_bytes:
                return Resolution(status="unsupported", reason="row_artifact_limit_exceeded")
            if digest(retained.artifact) != pointer.evidence_artifact_sha256:
                return Resolution(status="invalid", reason="retained_artifact_digest_mismatch")
            # Profile cap applies to the complete UTF8 wire Pointer, not just expected.
            import json

            wire = json.dumps(
                pointer.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf8")
            if len(wire) > self.bounds.max_pointer_bytes:
                return Resolution(status="unsupported", reason="row_pointer_limit_exceeded")
            if isinstance(pointer, EventPointer):
                excerpt, provenance = self._event(pointer, context, retained)
            else:
                excerpt, provenance = self._metric(pointer, context, retained)
            if not isinstance(excerpt, Resolution) and len(excerpt) > self.bounds.max_excerpt_bytes:
                return Resolution(status="unsupported", reason="excerpt_limit_exceeded")
            final = self._admit(pointer, context, generation)
            if isinstance(final, Resolution):
                return final
            if final != current:
                return Resolution(status="stale", reason="generation_changed_during_resolution")
            if isinstance(excerpt, Resolution):
                return excerpt
            return Resolution(
                status="resolved",
                checked_source_revision=pointer.source_revision,
                checked_source_sha256=pointer.source_sha256,
                checked_artifact_sha256=pointer.evidence_artifact_sha256,
                scope="text",
                excerpt=excerpt.decode("utf8"),
                excerpt_sha256=digest(excerpt),
                reason="literal_row_identity_checked",
                provenance=ResolutionProvenance(row=provenance),
            )
        except Exception:
            return Resolution(status="invalid", reason="row_contract_error")

    def _event(self, pointer, context, retained):
        loc = pointer.locator
        artifact = decode_retained(
            retained.artifact, maximum=self.bounds.max_artifact_bytes, metric=False
        )
        if (
            type(retained.processing_descriptor) is not bytes
            or type(retained.event_record) is not bytes
        ):
            raise ValueError("event actual producer descriptor/record required")
        descriptor = EventProcessingDescriptor.model_validate(
            decode_retained(retained.processing_descriptor, maximum=16384, metric=False)
        )
        if (
            digest(retained.processing_descriptor) != loc.processing_generation
            or descriptor.source_sha256 != pointer.source_sha256
        ):
            raise ValueError("event processing mismatch")
        record = decode_retained(retained.event_record, maximum=ARTIFACT_BYTES, metric=False)
        _record_shape(record, pointer.source_sha256, loc.physical_line_number)
        if digest(retained.event_record) != loc.event_record_sha256:
            raise ValueError("event record digest mismatch")
        quote = loc.quote.encode("utf8")
        if len(quote) > retained.generation.metadata.raw_byte_length:
            raise ValueError("event row exceeds declared complete source length")
        if len(quote) > self.bounds.max_event_quote_bytes:
            return Resolution(status="unsupported", reason="event_quote_limit_exceeded"), None
        expected = {
            "algorithm": "s8-zeek-physical-row-evidence-v1",
            "source_sha256": pointer.source_sha256,
            "source_revision": pointer.source_revision,
            "processing_generation": loc.processing_generation,
            "row_id": loc.row_id,
            "physical_line_number": loc.physical_line_number,
            "event_record_sha256": loc.event_record_sha256,
            "raw_line_base64": base64.b64encode(quote).decode("ascii"),
        }
        if artifact != expected or event_bytes(expected) != retained.artifact:
            raise ValueError("event whole artifact preimage mismatch")
        provenance = EventRowProvenance(
            profile="s8-zeek-physical-row-v1",
            namespace_id=context.namespace_id,
            source_id=pointer.source_id,
            source_sha256=pointer.source_sha256,
            artifact_sha256=pointer.evidence_artifact_sha256,
            generation_mode=context.generation_mode,
            current=context.generation_mode == "current",
            row_id=loc.row_id,
            physical_line_number=loc.physical_line_number,
            event_record_sha256=loc.event_record_sha256,
            processing_generation=loc.processing_generation,
            parser_implementation_sha256=descriptor.parser_implementation_sha256,
            parser_runtime_sha256=descriptor.parser_runtime_sha256,
            parser_config_sha256=descriptor.parser_config_sha256,
            event_schema_sha256=descriptor.event_schema_sha256,
        )
        return quote, provenance

    def _metric(self, pointer, context, retained):
        artifact = MetricArtifact.model_validate(
            decode_retained(retained.artifact, maximum=self.bounds.max_artifact_bytes, metric=True)
        )
        if metric_bytes(artifact.model_dump(mode="json")) != retained.artifact:
            raise ValueError("metric artifact omitted canonical fields/defaults")
        loc = pointer.locator
        if retained.generation.metadata.raw_byte_length == 0:
            raise ValueError("canonical dataset identity cannot be empty source bytes")
        if (
            artifact.namespace_id != context.namespace_id
            or artifact.dataset_id != pointer.source_id
            or artifact.dataset_fingerprint != pointer.source_sha256
            or artifact.snapshot_id != loc.snapshot_id
        ):
            raise ValueError("metric artifact identity mismatch")
        rows = [row for row in artifact.rows if row.metric_id == loc.metric_id]
        if not rows:
            return Resolution(status="missing", reason="metric_row_missing"), None
        row = rows[0]
        raw = metric_bytes(row.model_dump(mode="json"))
        if len(raw) > self.bounds.max_metric_row_bytes:
            return Resolution(status="unsupported", reason="metric_row_limit_exceeded"), None
        if row != loc.expected or digest(raw) != loc.row_sha256 or row.scope != loc.scope:
            raise ValueError("metric whole expected row mismatch")
        provenance = MetricRowProvenance(
            profile="s9-metric-row.v1",
            namespace_id=context.namespace_id,
            source_id=pointer.source_id,
            source_sha256=pointer.source_sha256,
            artifact_sha256=pointer.evidence_artifact_sha256,
            generation_mode=context.generation_mode,
            current=context.generation_mode == "current",
            dataset_id=artifact.dataset_id,
            snapshot_id=artifact.snapshot_id,
            row_sha256=loc.row_sha256,
            config_sha256=digest(artifact.snapshot_identity.config_json.encode("utf8")),
            tag_provenance_sha256=digest(
                metric_bytes(
                    [
                        tag.model_dump(mode="json")
                        for tag in artifact.snapshot_identity.tag_provenance
                    ]
                )
            ),
            compute_version=artifact.snapshot_identity.compute_version,
            n=row.n,
            N=row.N,
            metric_status=row.status,
            metric_status_reason=row.status_reason,
        )
        if row.status != "ok" or row.n < 5:
            return Resolution(
                status="unsupported",
                reason="metric_uncitable",
                provenance=ResolutionProvenance(row=provenance),
            ), None
        return raw, provenance


def install_rows(registry: Registry, resolver: RowResolver):
    if any(key in registry.installed_domains for key in (EVENT_KEY, METRIC_KEY)):
        raise DuplicateResolverError("event/metric tuple already registered")
    registry.register(EVENT_KEY, resolver)
    registry.register(METRIC_KEY, resolver)
