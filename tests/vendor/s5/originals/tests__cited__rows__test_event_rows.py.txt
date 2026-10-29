"""Six event groups: identity, physical bytes, descriptor, tamper, bounds and access.

These are hand-authored public-wire controls, not an execution of the S8 parser.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from changelog_advisor.shared.cited.models import EventPointer
from changelog_advisor.shared.cited.production import EventUnsupportedProduction
from changelog_advisor.shared.cited.rowcanonical import ARTIFACT_BYTES, digest, event_bytes
from changelog_advisor.shared.cited.rowproducers import produce_event_row
from changelog_advisor.shared.cited.rows import DEFAULT_ROW_BOUNDS, RowBounds


def event(
    *,
    ending=b"\n",
    size=None,
    suffix=b"",
    prefix=b"",
    text="\u00e9\U0001f9ea",
    parsed=True,
    bounds=DEFAULT_ROW_BOUNDS,
):
    line = b'{"uid":"C12345678","note":"' + text.encode("utf8") + b'"}'
    if size is not None:
        line = line[:-1] + b" " * (size - len(line) - len(ending)) + b"}"
    quote = line + ending
    raw = prefix + quote + suffix
    sha = digest(raw)
    number = prefix.count(b"\n") + 1
    descriptor = dict(
        algorithm="s8-zeek-processing-v2",
        source_sha256=sha,
        parser_version="zeek-conn-1.1",
        parser_implementation_sha256="a" * 64,
        parser_runtime_sha256="b" * 64,
        parser_config_sha256="c" * 64,
        event_schema_sha256="b30d567b6109ef5e381f499be464afa74d70d67f8e76216c4ab808e82458fb9d",
        projection_version="event-v1-json-v1",
    )
    record = dict(
        schema_version=1,
        input_sha256=sha,
        raw_line_number=number,
        row_id=f"{sha}:{number}",
        ts_us=1700000000000000,
        src="192.0.2.4",
        dst="198.51.100.8",
        src_port=49152,
        dst_port=443,
        protocol="tcp",
        action="unknown",
        direction="outbound",
        conn_state=None,
        uid="C12345678",
        duration_us=None,
        orig_bytes=1,
        resp_bytes=2,
        total_bytes=3,
        icmp_type=None,
        icmp_code=None,
        quality_flags=[],
    )
    parameters = dict(
        reference_id="ref-1",
        namespace_id="namespace",
        source_id="public-event",
        source_sha256=sha,
        raw_source_byte_length=len(raw),
        physical_line_number=number,
        quote=quote,
        processing_descriptor=event_bytes(descriptor),
        event_record=event_bytes(record) if parsed else None,
        bounds=bounds,
    )
    return SimpleNamespace(
        batch=produce_event_row(**parameters),
        raw=raw,
        quote=quote,
        descriptor=descriptor,
        record=record,
        parameters=parameters,
    )


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_e01_e02_physical_full_source_identity_utf8_and_line_endings(factory, ending):
    case = event(
        ending=ending, suffix=b"quarantined suffix" if ending else b"", prefix=b"#declared header\n"
    )
    pointer = case.batch.outcomes[0].pointer
    registry, _ = factory.installed(case.batch)
    result = registry.resolve(pointer, factory.context)
    assert result.status == "resolved" and result.excerpt.encode("utf8") == case.quote
    assert pointer.source_sha256 == digest(case.raw) and pointer.source_sha256 != digest(case.quote)
    assert pointer.locator.physical_line_number == 2
    assert result.provenance.row.event_record_sha256 == digest(event_bytes(case.record))


def test_e01_repeated_uid_is_not_row_identity(factory):
    one = event()
    two = event(prefix=b"another physical row\n")
    assert one.record["uid"] == two.record["uid"]
    assert (
        one.batch.outcomes[0].pointer.locator.row_id != two.batch.outcomes[0].pointer.locator.row_id
    )


def test_e02_decomposed_event_quote_remains_literal(factory):
    case = event(text="e\u0301")
    registry, _ = factory.installed(case.batch)
    result = registry.resolve(case.batch.outcomes[0].pointer, factory.context)
    assert result.status == "resolved" and "e\u0301" in result.excerpt


@pytest.mark.parametrize("size", [16384, 16385])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_e05_actual_16384_and_16385_physical_utf8_bytes(factory, size, ending):
    case = event(ending=ending, size=size, parsed=size <= 16384)
    assert (
        len(case.quote) == size and b"\xc3\xa9" in case.quote and b"\xf0\x9f\xa7\xaa" in case.quote
    )
    outcome = case.batch.outcomes[0]
    if size == 16384:
        registry, _ = factory.installed(case.batch)
        assert (
            registry.resolve(outcome.pointer, factory.context).excerpt.encode("utf8") == case.quote
        )
    else:
        assert case.batch.retained is None and isinstance(outcome, EventUnsupportedProduction)
        assert (
            outcome.event_record_sha256 is None and outcome.failure_reason == "event_row_overflow"
        )
        assert outcome.measured_bytes == 16385 and outcome.limit_bytes == 16384


@pytest.mark.parametrize("kind", ["implementation", "runtime", "config", "schema", "source"])
def test_e03_processing_descriptor_changes_are_not_current_evidence(factory, kind):
    case = event()
    changed = dict(case.descriptor)
    field = {
        "implementation": "parser_implementation_sha256",
        "runtime": "parser_runtime_sha256",
        "config": "parser_config_sha256",
        "schema": "event_schema_sha256",
        "source": "source_sha256",
    }[kind]
    changed[field] = "e" * 64
    retained = replace(case.batch.retained, processing_descriptor=event_bytes(changed))
    registry, _ = factory.installed(replace(case.batch, retained=retained))
    assert registry.resolve(case.batch.outcomes[0].pointer, factory.context).status == "invalid"


@pytest.mark.parametrize(
    "kind", ["artifact", "record", "quote", "raw_revision", "row_number", "extra_action"]
)
def test_e04_tampered_full_artifact_record_or_pointer_fails_closed(factory, kind):
    case = event()
    pointer = case.batch.outcomes[0].pointer
    retained = case.batch.retained
    if kind == "artifact":
        retained = replace(retained, artifact=retained.artifact + b" ")
    elif kind == "record":
        retained = replace(retained, event_record=event_bytes({**case.record, "total_bytes": 4}))
    elif kind == "quote":
        pointer = pointer.model_copy(
            update={"locator": pointer.locator.model_copy(update={"quote": "changed"})}
        )
    elif kind == "raw_revision":
        pointer = pointer.model_copy(update={"source_revision": "sha256:" + "f" * 64})
    elif kind == "row_number":
        pointer = pointer.model_copy(
            update={"locator": pointer.locator.model_copy(update={"physical_line_number": 2})}
        )
    else:
        pointer = {**pointer.model_dump(), "action": "export"}
    registry, _ = factory.installed(replace(case.batch, retained=retained))
    assert registry.resolve(pointer, factory.context).status != "resolved"


@pytest.mark.parametrize(
    "bounds,reason",
    [
        (RowBounds(max_event_quote_bytes=10), "event_row_overflow"),
        (RowBounds(max_artifact_bytes=10), "event_artifact_overflow"),
        (RowBounds(max_pointer_bytes=10), "event_pointer_overflow"),
    ],
)
def test_e05_producer_lower_caps_keep_original_ref_and_actual_record_digest(bounds, reason):
    case = event(bounds=bounds)
    outcome = case.batch.outcomes[0]
    assert isinstance(outcome, EventUnsupportedProduction) and outcome.reference_id == "ref-1"
    assert outcome.failure_reason == reason and outcome.event_record_sha256 is not None
    assert outcome.measured_bytes > outcome.limit_bytes and case.batch.retained is None


def test_e05_actual_retained_artifact_32mib_overflow_rejected_before_decode(factory):
    case = event()
    retained = replace(case.batch.retained, artifact=b"x" * (ARTIFACT_BYTES + 1))
    registry, _ = factory.installed(replace(case.batch, retained=retained))
    result = registry.resolve(case.batch.outcomes[0].pointer, factory.context)
    assert result.reason == "row_artifact_limit_exceeded" and result.excerpt is None


@pytest.mark.parametrize("target", [32768, 32769])
def test_e05_actual_whole_pointer_exact_boundary_includes_escaped_quote(factory, target):
    base = event(text="")
    pointer = base.batch.outcomes[0].pointer
    encoded = json.dumps(
        pointer.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf8")
    delta = target - len(encoded)
    slashes = (delta // 2) // 2 * 2
    padding = delta - 2 * slashes
    case = event(text="\\" * slashes + "x" * padding)
    assert len(case.quote) <= 16384
    if target == 32768:
        pointer = case.batch.outcomes[0].pointer
        wire = json.dumps(
            pointer.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf8")
        assert len(wire) == target
        registry, _ = factory.installed(case.batch)
        assert registry.resolve(pointer, factory.context).status == "resolved"
    else:
        outcome = case.batch.outcomes[0]
        assert (
            outcome.failure_reason == "event_pointer_overflow" and outcome.measured_bytes == target
        )


@pytest.mark.parametrize("decisions", [["deny"], ["unknown"], ["allow", "allow", "deny"]])
def test_e06_access_denied_or_revoked_never_discloses(factory, decisions):
    case = event()
    registry, backend = factory.installed(case.batch)
    backend.decisions = decisions
    result = registry.resolve(case.batch.outcomes[0].pointer, factory.context)
    assert result.status != "resolved" and result.excerpt is None and result.provenance is None
    if decisions[0] != "allow":
        assert backend.retained_count == 0


def test_e06_historical_stale_foreign_and_deleted_are_explicit(factory):
    case = event()
    registry, backend = factory.installed(case.batch)
    pointer = case.batch.outcomes[0].pointer
    backend.current_value = backend.current_value.model_copy(
        update={"derived_generation": "f" * 64}
    )
    assert registry.resolve(pointer, factory.context).status == "stale"
    context = factory.context.model_copy(update={"generation_mode": "retained_historical"})
    assert registry.resolve(pointer, context).reason == "historical_not_allowed"
    backend.historical = True
    result = registry.resolve(pointer, context)
    assert result.status == "resolved" and result.provenance.row.current is False
    backend.current_value = None
    assert registry.resolve(pointer, context).status != "resolved"


def test_e06_null_route_stays_unsupported_even_when_installed(factory):
    case = event()
    pointer = case.batch.outcomes[0].pointer
    null = EventPointer.model_validate({**pointer.model_dump(), "locator": None})
    registry, _ = factory.installed(case.batch)
    assert registry.resolve(null, factory.context).status == "unsupported"


@pytest.mark.parametrize(
    "field,value",
    [
        ("ts_us", True),
        ("dst_port", 65536),
        ("src", "not-an-ip"),
        ("quality_flags", ["private text here"]),
        ("action", "allow"),
    ],
)
def test_e04_public_record_wire_shape_is_checked_before_production(field, value):
    case = event()
    params = {**case.parameters, "event_record": event_bytes({**case.record, field: value})}
    with pytest.raises(ValueError):
        produce_event_row(**params)


def test_e04_multiline_quote_and_impossible_source_length_rejected():
    with pytest.raises(ValueError):
        event(text="one\ntwo")
    case = event()
    with pytest.raises(ValueError):
        produce_event_row(**{**case.parameters, "raw_source_byte_length": 1})
