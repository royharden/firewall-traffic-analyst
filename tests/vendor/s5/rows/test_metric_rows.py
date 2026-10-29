"""M01-M26-style synthetic contract controls; no independent corpus or quality score."""

from dataclasses import replace

import pytest
from pydantic import ValidationError

from firewall_analyst.shared.cited import Finding, Registry
from firewall_analyst.shared.cited.models import (
    MetricArtifact,
    MetricSupport,
    PlatformSummary,
    SnapshotIdentity,
    TagProvenance,
)
from firewall_analyst.shared.cited.production import (
    MetricUnsupportedProduction,
    ProducedEvidence,
    assess_produced_evidence,
)
from firewall_analyst.shared.cited.rowcanonical import (
    ARTIFACT_BYTES,
    ROW_BYTES,
    decode_retained,
    digest,
    encode_capped,
    metric_bytes,
)
from firewall_analyst.shared.cited.rowproducers import produce_metric_rows
from firewall_analyst.shared.cited.rows import RowBounds


def test_m01_actual_production_resolver_and_original_claim(factory):
    batch = factory.batch()
    pointer = batch.outcomes[0].pointer
    registry, backend = factory.installed(batch)
    finding = Finding(
        id="finding",
        text="A supplied metric supports a conditional observation",
        verdict="partial",
        probability=0.7,
        evidence=(pointer,),
    )
    result = assess_produced_evidence(
        finding,
        batch.outcomes,
        registry,
        factory.context,
        factory.frame(),
        authority=factory.Authority(factory.frame()),
    )
    assert result.required_count == result.resolved_count == 1 and result.unresolved_count == 0
    assert result.finding == finding and result.finding.verdict == "partial"
    resolution = result.resolutions[0]
    assert resolution.excerpt.encode() == metric_bytes(
        pointer.locator.expected.model_dump(mode="json")
    )
    assert resolution.provenance.row.n == resolution.provenance.row.N == 5
    assert backend.decision_count >= 3 and backend.retained_count == 1


@pytest.mark.parametrize(
    "status,value,reason,n",
    [
        ("ok", "2.5", None, 5),
        ("insufficient_data", "0.5", "minimum_eligible_n_5", 4),
        ("insufficient_data", None, "zero_eligible_impressions", 0),
        ("unavailable", None, "missing_time", 0),
        ("ok", "0.5", None, 1),
    ],
)
def test_m02_to_m05_exact_status_and_diagnostic_citability(factory, status, value, reason, n):
    row = factory.row(
        status=status,
        value=value,
        status_reason=reason,
        n=n,
        N=n,
        sample_size=n,
        eligible_source_ids=tuple(f"p{i}" for i in range(n)),
        cohort_semantics="diagnostic_single" if n == 1 else "rate_cohort",
    )
    batch = factory.batch(rows=(row,))
    registry, _ = factory.installed(batch)
    result = registry.resolve(batch.outcomes[0].pointer, factory.context)
    assert result.status == ("resolved" if status == "ok" and n >= 5 else "unsupported")
    if result.status != "resolved":
        assert result.reason == "metric_uncitable" and result.excerpt is None
        assert result.provenance.row.n == n


@pytest.mark.parametrize(
    "change",
    [
        {"status": "ok", "value": None},
        {"status": "ok", "sample_size": 0},
        {"status": "unavailable", "value": "0.5", "status_reason": "missing_time"},
        {"status": "insufficient_data", "status_reason": None},
        {"N": 4},
        {"n": 4},
        {"excluded_size": 1},
        {"eligible_source_ids": ("p", "p")},
        {"eligible_source_ids": ("z", "a", "b", "c", "d")},
        {"denominator": "-1"},
        {"denominator": "0"},
        {"value": "0.50"},
        {"value": "-0"},
        {"value": "1e0"},
        {"value": 0.5},
        {"value": "null"},
        {"numerator": True},
        {"n": True},
        {"numerator": "9" * 301},
    ],
)
def test_m06_m07_m10_m15_strict_counts_and_canonical_numbers(factory, change):
    with pytest.raises((ValidationError, ValueError, TypeError)):
        factory.row(**change)


def test_m08_trend_explicit_union_is_not_minimum_plus_excluded(factory):
    recent = tuple("r" + str(i) for i in range(5))
    prior = tuple("p" + str(i) for i in range(6))
    windows = (
        dict(
            start_ordinal=101,
            end_ordinal=128,
            eligible_source_ids=recent,
            cohort_source_ids=recent,
            n=5,
            N=5,
            numerator="5",
            denominator="10",
        ),
        dict(
            start_ordinal=73,
            end_ordinal=100,
            eligible_source_ids=prior,
            cohort_source_ids=prior,
            n=6,
            N=6,
            numerator="3",
            denominator="10",
        ),
    )
    row = factory.row(
        cohort_semantics="trend_union",
        unit="percentage_points",
        value="20",
        eligible_source_ids=tuple(sorted(recent + prior)),
        n=5,
        N=11,
        sample_size=5,
        numerator="2000",
        denominator="100",
        windows=windows,
    )
    assert row.N == 11 and row.n + row.excluded_size == 5
    with pytest.raises(ValidationError):
        MetricSupport.model_validate({**row.model_dump(), "N": 5})
    with pytest.raises(ValidationError):
        MetricSupport.model_validate({**row.model_dump(), "windows": tuple(reversed(row.windows))})


def test_m09_exact_large_support_and_m12_literal_cr_formula(factory):
    row = factory.row(
        numerator="9" * 300,
        denominator="9" * 300,
        definition="=literal\r\nUnicode \u00e9",
        family="rate\rwhole",
        dimension="topic",
        key="=literal\rkey",
    )
    raw = metric_bytes(row.model_dump(mode="json"))
    assert b"\\r\\n" in raw and len(row.numerator) == 300
    assert decode_retained(raw, maximum=ROW_BYTES, metric=True)["key"] == "=literal\rkey"


@pytest.mark.parametrize(
    "id", ["\U0001f600" * 256, "https://post.example/id", "path/../literal", "C:literal"]
)
def test_m13_m14_literal_post_ids_are_not_fetch_handles(factory, id):
    row = factory.row(eligible_source_ids=tuple(sorted((id, "p1", "p2", "p3", "p4"))))
    assert id in row.eligible_source_ids


@pytest.mark.parametrize("id", ["\U0001f600" * 257, " e", "e ", "e\x00", "e\x7f", "e\u0301"])
def test_m11_m13_m15_invalid_unicode_id_refused_without_normalization(factory, id):
    with pytest.raises(ValidationError):
        factory.row(eligible_source_ids=(id, "p1", "p2", "p3", "p4"))


@pytest.mark.parametrize(
    "config", ["{ }", "[]", '{"x":0.5}', '{"x":1,"x":1}', '{"e\u0301":1,"\u00e9":2}']
)
def test_m16_canonical_config_is_a_string_not_normalized_or_coerced(factory, config):
    with pytest.raises(ValidationError):
        SnapshotIdentity.model_validate({**factory.identity.model_dump(), "config_json": config})
    with pytest.raises(ValidationError):
        SnapshotIdentity.model_validate({**factory.identity.model_dump(), "config_json": {}})


def test_m17_m18_complete_snapshot_defaults_tag_and_clock_identity(factory):
    tag = TagProvenance(
        source_id="p1",
        field="topic",
        value="testing",
        method="supplied",
        taxonomy_version="labels.v1",
    )
    assert tag.model_dump()["model"] is None and tag.model_dump()["threshold"] is None
    changed = SnapshotIdentity.model_validate(
        {**factory.identity.model_dump(), "tag_provenance": (tag,)}
    )
    assert digest(metric_bytes(changed.model_dump(mode="json"))) != factory.snapshot
    with pytest.raises(ValidationError):
        SnapshotIdentity.model_validate(
            {**factory.identity.model_dump(), "tag_provenance": (tag, tag)}
        )
    with pytest.raises(ValidationError):
        TagProvenance.model_validate({**tag.model_dump(), "threshold": "1.1"})
    with pytest.raises(ValidationError):
        TagProvenance.model_validate({**tag.model_dump(), "threshold": 0.5})


@pytest.mark.parametrize("extra", ["created_at", "artifact_sha256", "invented"])
def test_m19_new_artifact_exact_eight_fields(factory, extra):
    with pytest.raises(ValidationError):
        MetricArtifact.model_validate({**factory.artifact().model_dump(), extra: "unapproved"})


def test_m20_raw_snapshot_namespace_and_currentness_bindings(factory):
    batch = factory.batch()
    registry, backend = factory.installed(batch)
    pointer = batch.outcomes[0].pointer
    foreign = factory.context.model_copy(update={"namespace_id": "foreign"})
    assert registry.resolve(pointer, foreign).status != "resolved"
    backend.current_value = backend.current_value.model_copy(
        update={"derived_generation": "e" * 64}
    )
    assert registry.resolve(pointer, factory.context).status == "stale"
    historical = factory.context.model_copy(update={"generation_mode": "retained_historical"})
    assert registry.resolve(pointer, historical).reason == "historical_not_allowed"
    backend.historical = True
    result = registry.resolve(pointer, historical)
    assert result.status == "resolved" and result.provenance.row.current is False
    assert result.provenance.row.generation_mode == "retained_historical"
    backend.current_value = None
    assert registry.resolve(pointer, historical).status != "resolved"


def test_m21_complete_platform_counts(factory):
    fields = factory.artifact().platform_summary[0].model_dump()
    assert len(fields) == 7
    with pytest.raises(ValidationError):
        PlatformSummary.model_validate(
            {k: v for k, v in fields.items() if k != "missing_time_rows"}
        )
    with pytest.raises(ValidationError):
        PlatformSummary.model_validate({**fields, "eligible_hour_rows": 5001})


@pytest.mark.parametrize("size", [ROW_BYTES, ROW_BYTES + 1])
def test_m22_exact_whole_row_boundary_keeps_original_ids(factory, size):
    original = factory.row()
    base = len(metric_bytes(original.model_dump(mode="json")))
    row = factory.row(definition=original.definition + "x" * (size - base))
    assert len(metric_bytes(row.model_dump(mode="json"))) == size
    batch = factory.batch(rows=(row,))
    assert batch.retained is not None and len(batch.outcomes) == 1
    result = batch.outcomes[0]
    assert isinstance(
        result, ProducedEvidence if size == ROW_BYTES else MetricUnsupportedProduction
    )
    if size > ROW_BYTES:
        assert result.failure_reason == "metric_row_overflow" and result.measured_bytes == size


def test_m23_atomic_artifact_cap_lower_bound_and_m24_all_failed_accounting(factory):
    artifact = factory.artifact()
    frame = factory.frame(("ref-a", "ref-b"))
    batch = produce_metric_rows(
        artifact,
        frame,
        (artifact.rows[0].metric_id,) * 2,
        raw_identity_byte_length=100,
        bounds=RowBounds(max_artifact_bytes=100),
    )
    assert batch.retained is None
    assert len(batch.outcomes) == 2 and all(
        p.failure_reason == "metric_artifact_overflow" for p in batch.outcomes
    )
    assert all(
        p.measurement_kind == "lower_bound" and p.measured_bytes == 101 for p in batch.outcomes
    )
    finding = Finding(id="f", text="no evidence was retainable", verdict="partial", evidence=())
    assessed = assess_produced_evidence(
        finding,
        batch.outcomes,
        Registry(),
        factory.context,
        frame,
        authority=factory.Authority(frame),
    )
    assert (
        assessed.required_count == assessed.unresolved_count == 2 and assessed.resolved_count == 0
    )
    assert assessed.finding.verdict == "unsupported"
    assert (
        tuple(p.reference_id for p in assessed.production_failures) == frame.required_reference_ids
    )


def test_m23_actual_32mib_cap_is_atomic_without_prefix_hash():
    value = {"padding": "x" * ARTIFACT_BYTES}
    raw, size, kind = encode_capped(value, maximum=ARTIFACT_BYTES, metric=True)
    assert raw is None and size == ARTIFACT_BYTES + 1 and kind == "lower_bound"


def test_m23_actual_closed_artifact_exact_32mib_then_one_byte_over(factory):
    rows = [factory.row(metric_id=f"metric-{i:04d}") for i in range(1400)]
    artifact = factory.artifact(rows=rows)
    remaining = ARTIFACT_BYTES - len(metric_bytes(artifact.model_dump(mode="json")))
    for index, row in enumerate(rows):
        spare = ROW_BYTES - len(metric_bytes(row.model_dump(mode="json")))
        extra = min(spare, remaining)
        rows[index] = factory.row(metric_id=row.metric_id, definition=row.definition + "x" * extra)
        remaining -= extra
    assert remaining == 0 and len(rows[-1].definition) < 200
    artifact = factory.artifact(rows=rows)
    frame = factory.frame(("ref-first", "ref-last"))
    names = (rows[0].metric_id, rows[-1].metric_id)
    exact = produce_metric_rows(artifact, frame, names, raw_identity_byte_length=1000)
    assert len(exact.retained.artifact) == ARTIFACT_BYTES
    assert all(isinstance(outcome, ProducedEvidence) for outcome in exact.outcomes)
    rows[-1] = factory.row(metric_id=rows[-1].metric_id, definition=rows[-1].definition + "x")
    over = produce_metric_rows(
        factory.artifact(rows=rows), frame, names, raw_identity_byte_length=1000
    )
    assert over.retained is None and len(over.outcomes) == 2
    assert all(outcome.failure_reason == "metric_artifact_overflow" for outcome in over.outcomes)
    assert all(
        outcome.measured_bytes == ARTIFACT_BYTES + 1 and outcome.measurement_kind == "lower_bound"
        for outcome in over.outcomes
    )


def test_m25_5000_valid_long_ids_are_kept_and_counted_unsupported(factory):
    ids = tuple(sorted("\U0001f600" * 250 + str(i) for i in range(5000)))
    row = factory.row(eligible_source_ids=ids, n=5000, N=5000, sample_size=5000)
    batch = factory.batch(rows=(row,))
    result = batch.outcomes[0]
    assert (
        isinstance(result, MetricUnsupportedProduction)
        and result.failure_reason == "metric_row_overflow"
    )
    assert result.n == result.N == 5000
    assert (
        len(
            decode_retained(batch.retained.artifact, maximum=ARTIFACT_BYTES, metric=True)["rows"][
                0
            ]["eligible_source_ids"]
        )
        == 5000
    )


def test_m26_pointer_lower_cap_and_revocation_before_any_disclosure(factory):
    artifact = factory.artifact()
    batch = produce_metric_rows(
        artifact,
        factory.frame(),
        (artifact.rows[0].metric_id,),
        raw_identity_byte_length=100,
        bounds=RowBounds(max_pointer_bytes=100),
    )
    assert batch.outcomes[0].failure_reason == "metric_pointer_overflow"
    normal = factory.batch()
    registry, backend = factory.installed(normal)
    backend.decisions = ["allow", "allow", "deny"]
    denied = registry.resolve(normal.outcomes[0].pointer, factory.context)
    assert denied.status != "resolved" and denied.excerpt is None and denied.provenance is None


def test_uncitable_metadata_also_rechecks_access_before_disclosure(factory):
    row = factory.row(
        status="insufficient_data",
        status_reason="minimum_eligible_n_5",
        n=4,
        N=4,
        sample_size=4,
        eligible_source_ids=("p0", "p1", "p2", "p3"),
    )
    batch = factory.batch(rows=(row,))
    registry, backend = factory.installed(batch)
    backend.decisions = ["allow", "allow", "deny"]
    result = registry.resolve(batch.outcomes[0].pointer, factory.context)
    assert result.provenance is None and result.reason == "access_not_allowed"


def test_canonical_defaults_cannot_be_omitted_from_retained_artifact(factory):
    batch = factory.batch()
    obj = decode_retained(batch.retained.artifact, maximum=ARTIFACT_BYTES, metric=True)
    del obj["snapshot_identity"]["schema_version"]
    raw = metric_bytes(obj)
    metadata = batch.retained.generation.metadata.model_copy(
        update={"evidence_artifact_sha256": digest(raw)}
    )
    generation = batch.retained.generation.model_copy(update={"metadata": metadata})
    changed = replace(batch, retained=replace(batch.retained, artifact=raw, generation=generation))
    pointer = batch.outcomes[0].pointer.model_copy(update={"evidence_artifact_sha256": digest(raw)})
    registry, _ = factory.installed(changed)
    assert registry.resolve(pointer, factory.context).status == "invalid"


def test_oversized_raw_python_pointer_is_bounded_before_nested_adapter(factory, monkeypatch):
    from firewall_analyst.shared.cited.models import POINTER_ADAPTER

    pointer = factory.batch().outcomes[0].pointer.model_dump(mode="json")
    pointer["locator"]["expected"]["eligible_source_ids"] = [
        "p" + str(i) + "x" * 200 for i in range(5000)
    ]

    def forbidden(*a, **k):
        pytest.fail("oversized raw Pointer reached nested validation")

    monkeypatch.setattr(POINTER_ADAPTER, "validate_python", forbidden)
    result = Registry().resolve(pointer, factory.context)
    assert result.status == "unsupported" and result.reason == "row_pointer_limit_exceeded"
