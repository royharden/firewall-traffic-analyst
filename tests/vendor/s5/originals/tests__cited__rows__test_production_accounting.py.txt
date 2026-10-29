"""what_bug_this_catches: outputs redefine required evidence or drop failed positions."""

import pytest
from pydantic import ValidationError

from changelog_advisor.shared.cited import Finding, Registry
from changelog_advisor.shared.cited.production import (
    EventUnsupportedProduction,
    MetricUnsupportedProduction,
    ProducedEvidence,
    assess_produced_evidence,
)


def failed(factory, ref="ref-2"):
    row = factory.row()
    return MetricUnsupportedProduction(
        status="unsupported",
        reference_id=ref,
        profile="s9-metric-row.v1",
        namespace_id="namespace",
        dataset_id=factory.artifact().dataset_id,
        raw_dataset_sha256="d" * 64,
        snapshot_id=factory.snapshot,
        metric_id=row.metric_id,
        n=5,
        N=5,
        metric_status="ok",
        metric_status_reason=None,
        failure_reason="metric_row_overflow",
        measured_bytes=24577,
        limit_bytes=24576,
        measurement_kind="exact",
    )


def test_mixed_produced_failed_missing_retains_every_original_position(factory):
    batch = factory.batch()
    registry, _ = factory.installed(batch)
    frame = factory.frame(("ref-1", "ref-2", "ref-3"))
    finding = Finding(
        id="f",
        text="original unconfirmed observation",
        verdict="partial",
        evidence=(batch.outcomes[0].pointer,),
    )
    result = assess_produced_evidence(
        finding,
        (batch.outcomes[0], failed(factory)),
        registry,
        factory.context,
        frame,
        authority=factory.Authority(frame),
    )
    assert result.required_reference_ids == ("ref-1", "ref-2", "ref-3")
    assert (
        result.required_count == 3 and result.resolved_count == 1 and result.unresolved_count == 2
    )
    assert tuple(r.status for r in result.resolutions) == ("resolved", "unsupported", "invalid")
    assert result.resolutions[2].reason == "missing_production"
    assert (
        result.production_failures[1].reference_id == "ref-2"
        and result.finding.verdict == "unsupported"
    )
    assert result.finding.evidence == finding.evidence and result.finding.text == finding.text


@pytest.mark.parametrize(
    "kind", ["duplicate", "extra", "reordered", "mismatching_pointer", "invalid_wire"]
)
def test_duplicate_extra_order_and_wire_errors_never_make_empty_pass(factory, kind):
    first = factory.batch().outcomes[0]
    frame = factory.frame(("ref-1", "ref-2"))
    other = factory.batch(rows=(factory.row(metric_id="second"),)).outcomes[0].pointer
    second = ProducedEvidence(status="produced", reference_id="ref-2", pointer=other)
    productions = (first, second)
    evidence = (first.pointer, second.pointer)
    if kind == "duplicate":
        productions = (first, first, second)
    elif kind == "extra":
        productions = (
            first,
            second,
            ProducedEvidence(status="produced", reference_id="extra", pointer=first.pointer),
        )
    elif kind == "reordered":
        evidence = (second.pointer, first.pointer)
    elif kind == "mismatching_pointer":
        evidence = ()
    else:
        productions = (first, {"status": "produced", "reference_id": "ref-2", "pointer": None})
    finding = Finding(id="f", text="not verified by outputs", verdict="partial", evidence=evidence)
    result = assess_produced_evidence(
        finding, productions, Registry(), factory.context, frame, authority=factory.Authority(frame)
    )
    assert result.required_count == result.unresolved_count == 2 and result.resolved_count == 0
    assert result.finding.verdict == "unsupported" and result.contract_errors


def test_forged_lower_original_set_cannot_redefine_authoritative_denominator(factory):
    original = factory.frame(("ref-1", "ref-2", "ref-3"))
    forged = factory.frame(("ref-1",))
    finding = Finding(
        id="f", text="must retain registered requirement", verdict="partial", evidence=()
    )
    result = assess_produced_evidence(
        finding, (), Registry(), factory.context, forged, authority=factory.Authority(original)
    )
    assert result.frame == original and result.required_count == result.unresolved_count == 3
    assert "required_frame_mismatch" in result.contract_errors


def test_no_original_requirements_is_unsupported_even_with_no_outputs(factory):
    frame = factory.frame(())
    finding = Finding(id="f", text="empty never proves a claim", verdict="partial", evidence=())
    result = assess_produced_evidence(
        finding, (), Registry(), factory.context, frame, authority=factory.Authority(frame)
    )
    assert result.required_count == 0 and result.finding.verdict == "unsupported"
    assert dict(result.reason_counts) == {"no_required_evidence": 1}


def test_failure_metadata_survives_extra_outcome_contract_error(factory):
    frame = factory.frame(("ref-1", "ref-2"))
    failure = failed(factory, "ref-1")
    finding = Finding(id="f", text="all failures remain visible", verdict="partial", evidence=())
    result = assess_produced_evidence(
        finding,
        (failure, failed(factory, "extra")),
        Registry(),
        factory.context,
        frame,
        authority=factory.Authority(frame),
    )
    assert result.required_count == 2 and result.production_failures[0] == failure
    assert (
        result.resolutions[0].reason == "metric_row_overflow"
        and "extra_production" in result.contract_errors
    )


def test_authority_change_before_return_invalidates_all_original_positions(factory):
    frame = factory.frame(("ref-1", "ref-2"))
    authority = factory.Authority(frame)
    calls = []

    def original(*args):
        calls.append(True)
        return frame if len(calls) == 1 else None

    authority.original = original
    finding = Finding(
        id="f", text="request ownership can be revoked", verdict="partial", evidence=()
    )
    result = assess_produced_evidence(
        finding,
        (failed(factory, "ref-1"), failed(factory, "ref-2")),
        Registry(),
        factory.context,
        frame,
        authority=authority,
    )
    assert result.required_count == 2 and result.unresolved_count == 2
    assert all(r.reason == "required_frame_changed" for r in result.resolutions)


@pytest.mark.parametrize(
    "change",
    [
        {"measured_bytes": 24576},
        {"limit_bytes": True},
        {"n": 6, "N": 5},
        {"measurement_kind": "guessed"},
        {"metric_status": "unavailable", "metric_status_reason": None},
        {"retained_artifact_hash": "a" * 64},
    ],
)
def test_failure_carrier_is_closed_exact_measurement_not_truncation(factory, change):
    with pytest.raises(ValidationError):
        MetricUnsupportedProduction.model_validate({**failed(factory).model_dump(), **change})


@pytest.mark.parametrize("reason", ["event_artifact_overflow", "event_pointer_overflow"])
def test_only_pre_record_row_overflow_may_have_null_record_digest(reason):
    fields = dict(
        status="unsupported",
        reference_id="ref-1",
        profile="s8-zeek-physical-row-v1",
        namespace_id="namespace",
        source_id="event",
        source_sha256="a" * 64,
        source_revision="sha256:" + "a" * 64,
        processing_generation="b" * 64,
        row_id="a" * 64 + ":1",
        physical_line_number=1,
        event_record_sha256=None,
        failure_reason=reason,
        measured_bytes=101,
        limit_bytes=100,
        measurement_kind="lower_bound",
    )
    with pytest.raises(ValidationError):
        EventUnsupportedProduction(**fields)
