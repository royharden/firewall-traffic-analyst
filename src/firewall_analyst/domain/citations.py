"""Canonical S5 Event rows over an explicitly verified S8 source snapshot.

The private backend serves only this batch's exact retained row. Whole-file proofs
surround the batch; no path, historical access or ambient registry is exposed.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

import pydantic
import pydantic_core

from ..shared.cited.models import ArtifactRef, Finding, ResolutionContext
from ..shared.cited.production import RequiredEvidenceFrame, assess_produced_evidence
from ..shared.cited.registry import Registry
from ..shared.cited.rowproducers import produce_event_row
from ..shared.cited.rows import EventProcessingDescriptor, RowResolver, install_rows
from ..shared.rulesengine.rows import verified_scan
from .schemas import EventV1


def _bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def processing_descriptor(source, internal_cidrs, limits):
    """Hash actual installed parser closure, runtime, config and owner schema bytes."""
    root = Path(__file__).resolve().parents[1]
    names = (
        "domain/parsers/__init__.py",
        "domain/parsers/zeek.py",
        "domain/schemas.py",
        "shared/rulesengine/parsers.py",
        "shared/rulesengine/rows.py",
        "shared/rulesengine/schemas.py",
    )
    files = {}
    for name in names:
        path = root / name
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError("parser_closure_unavailable")
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("parser_closure_limit")
        files[name] = _sha(raw)
    descriptor = EventProcessingDescriptor(
        algorithm="s8-zeek-processing-v2",
        source_sha256=source.generation.source_sha256,
        parser_version="zeek-conn-1.1",
        parser_implementation_sha256=_sha(_bytes(files)),
        parser_runtime_sha256=_sha(
            _bytes(
                {
                    "python": sys.version,
                    "implementation": sys.implementation.name,
                    "pydantic": pydantic.__version__,
                    "pydantic_core": pydantic_core.__version__,
                }
            )
        ),
        parser_config_sha256=_sha(
            _bytes(
                {
                    "internal_cidrs": list(internal_cidrs),
                    "limits": limits.model_dump(mode="json"),
                }
            )
        ),
        event_schema_sha256=_sha(_bytes(EventV1.model_json_schema())),
        projection_version="event-v1-json-v1",
    )
    return _bytes(descriptor.model_dump(mode="json"))


class _BatchRow:
    """Only the producer's exact retained snapshot; no arbitrary ID/path lookup."""

    def __init__(self, retained, pointer):
        self._retained, self._pointer = retained, pointer
        self.access_policy_ref = ArtifactRef(
            artifact_id="explicit-source-snapshot",
            artifact_sha256=_sha(b"explicit-source-only/1"),
            profile_id="s8-local-snapshot/1",
        )
        self.generation_policy_ref = ArtifactRef(
            artifact_id="whole-file-two-pass",
            artifact_sha256=_sha(b"whole-batch-before-after/1"),
            profile_id="s8-local-snapshot/1",
        )

    def decision(self, namespace_id, source_id):
        generation = self._retained.generation
        return (
            "allow"
            if namespace_id == generation.namespace_id
            and source_id == generation.metadata.source_id
            else "deny"
        )

    def current(self, namespace_id, source_id):
        return (
            self._retained.generation if self.decision(namespace_id, source_id) == "allow" else None
        )

    def allow_historical(self, context, generation):
        return False

    def retained(self, context, pointer):
        return self._retained if pointer == self._pointer else None


class _RequiredRow:
    """An original source-support position registered before calling the producer."""

    def __init__(self, row_id):
        self.reference = ArtifactRef(
            artifact_id="source-group-support",
            artifact_sha256=_sha(_bytes([row_id])),
            profile_id="s8-required-row/1",
        )
        self.frame = RequiredEvidenceFrame(
            request_id=row_id,
            namespace_id="s8-local",
            authority_ref=self.reference,
            required_reference_ids=(row_id,),
        )

    def original(self, namespace_id, request_id):
        return (
            self.frame
            if (namespace_id, request_id) == ("s8-local", self.frame.request_id)
            else None
        )


def cite_support(source, evidence_rows, *, internal_cidrs, limits):
    """Keep every original required row, including canonical overflow failures.

    S8 owns parsed record/full-file proofs. S5 checks literal row/record/descriptor
    bindings. This checks identity, never attack semantics or detection accuracy.
    """
    required = sorted(
        {row_id for group in source.run.groups for row_id in group.support.row_ids},
        key=lambda row_id: int(row_id.rsplit(":", 1)[1]),
    )
    if len(required) > 5000:
        raise ValueError("canonical_reference_limit")
    if [row["row_id"] for row in evidence_rows] != required:
        raise ValueError("canonical_support_mismatch")
    generation = source.generation
    source.validate_generation(generation.source_sha256)
    supplied = {
        row["row_id"]: base64.b64decode(row["raw_base64"], validate=True) for row in evidence_rows
    }

    def check_rows(rows, digest):
        if digest != generation.source_sha256:
            raise ValueError("source_changed")
        found = set()
        for physical in rows:
            row_id = f"{digest}:{physical.number}"
            if row_id in supplied:
                if physical.raw != supplied[row_id]:
                    raise ValueError("canonical_literal_row_mismatch")
                found.add(row_id)
        if found != set(required):
            raise ValueError("canonical_support_unavailable")

    verified_scan(
        generation.path,
        check_rows,
        max_bytes=generation.max_bytes,
        max_line_bytes=generation.max_line_bytes,
    )
    records = {row.row_id: row for row in source.parsed.records}
    descriptor = processing_descriptor(source, internal_cidrs, limits)
    # Register the authoritative complete ordered set before producing any outcomes.
    authorities = {row_id: _RequiredRow(row_id) for row_id in required}

    entries, size = [], 0
    for evidence in evidence_rows:
        row_id = evidence["row_id"]
        row = records[row_id]
        quote = supplied[row_id]
        batch = produce_event_row(
            reference_id=row_id,
            namespace_id="s8-local",
            source_id=f"row-{row.raw_line_number}",
            source_sha256=generation.source_sha256,
            raw_source_byte_length=generation.size_bytes,
            physical_line_number=row.raw_line_number,
            quote=quote,
            processing_descriptor=descriptor,
            event_record=_bytes(row.model_dump(mode="json")),
        )
        outcome = batch.outcomes[0]
        authority = authorities[row_id]
        entry = {
            "reference_id": row_id,
            "production": outcome.model_dump(mode="json"),
            "resolution": None,
            "retained": None,
        }
        registry = Registry()
        backend = _BatchRow(batch.retained, getattr(outcome, "pointer", None))
        context = ResolutionContext(
            namespace_id="s8-local",
            access_policy_ref=backend.access_policy_ref,
            generation_policy_ref=backend.generation_policy_ref,
            required_scope="text",
        )
        if batch.retained is not None:
            install_rows(registry, RowResolver(backend))
            entry["retained"] = {
                "generation": batch.retained.generation.model_dump(mode="json"),
                "artifact_base64": base64.b64encode(batch.retained.artifact).decode("ascii"),
                "event_record_base64": base64.b64encode(batch.retained.event_record).decode(
                    "ascii"
                ),
            }
        finding = Finding(
            id=row_id,
            text="Literal source row support; no semantic truth verdict.",
            verdict="partial",
            evidence=(outcome.pointer,) if outcome.status == "produced" else (),
        )
        assessment = assess_produced_evidence(
            finding,
            batch.outcomes,
            registry,
            context,
            authority.frame,
            authority=authority,
        )
        if assessment.contract_errors or (
            outcome.status == "produced" and assessment.resolved_count != 1
        ):
            raise ValueError("canonical_row_unverifiable")
        entry["resolution"] = assessment.resolutions[0].model_dump(mode="json")
        entry["required_frame"] = authority.frame.model_dump(mode="json")
        entry["assessment"] = {
            "required": assessment.required_count,
            "resolved": assessment.resolved_count,
            "unresolved": assessment.unresolved_count,
            "verdict": assessment.finding.verdict,
            "reason_counts": dict(assessment.reason_counts),
            "contract_errors": list(assessment.contract_errors),
        }
        size += len(_bytes(entry))
        if size > min(limits.max_output_bytes, 64 * 1024 * 1024):
            raise ValueError("canonical_output_limit")
        entries.append(entry)
    source.validate_generation(generation.source_sha256)
    return {
        "profile": "s8-zeek-physical-row-v1",
        "meaning": "literal identity, not claim truth",
        "required_reference_ids": required,
        "processing_descriptor": json.loads(descriptor),
        "entries": entries,
    }
