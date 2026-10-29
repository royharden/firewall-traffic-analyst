"""Independent arithmetic oracles; canonical types/helpers, no original data."""

import pytest
from test_canonical_adapter import actual_compare, sha, toy

from firewall_analyst.domain.evaluation.adapter import (
    RAW_METRICS,
    STATISTIC_VERSION,
)
from firewall_analyst.domain.evaluation.metrics import (
    bootstrap_spec,
    domain_statistic,
    raw_counts,
    report_rows,
)
from firewall_analyst.shared.evalkit.identity import canonical_bytes
from firewall_analyst.shared.evalkit.models import GoldRecord, Manifest, Outcome


def outcome(tp=3, fp=1, fn=2, benign=4, affected=1, **changes):
    expected = {"positive_episodes": tp + fn, "benign_episodes": benign}
    payload = dict(
        item_id="hand-unit",
        group_id="hand-family",
        dataset="hand-dataset",
        split="dev",
        method="rules_only",
        field="detection:1of2",
        eligibility="eligible",
        status="ok",
        correct=None,
        predicted={"tp": tp, "fp_alerts": fp, "fn": fn, "affected_benign": affected, **expected},
        expected=expected,
        human_touched_prediction=False,
        evidence_origin="synthetic",
        issues=(),
        ledger_refs=(),
    )
    payload["class"] = "port_scan"
    return Outcome.model_validate(payload | changes)


def test_actual_canonical_rates_and_distinct_f1_target_support():
    rows = (outcome(),)
    precision = domain_statistic(rows, "alert_precision")
    recall = domain_statistic(rows, "alert_recall")
    f1 = domain_statistic(rows, "alert_f1")
    benign = domain_statistic(rows, "benign_episode_fpr")
    assert precision.value == 0.75 and (
        precision.numerator,
        precision.denominator,
        precision.support,
    ) == (3, 4, 4)
    assert recall.value == 0.6 and (recall.numerator, recall.denominator, recall.support) == (
        3,
        5,
        5,
    )
    assert f1.value == pytest.approx(2 / 3) and (f1.numerator, f1.denominator, f1.support) == (
        6,
        9,
        9,
    )
    assert benign.value == 0.25 and (benign.numerator, benign.denominator) == (1, 4)
    assert raw_counts(rows)["positive_episodes"] == 5  # Not F1 target support9.


def test_unsupported_f1_null_not_imputed_when_target_support_is_positive():
    stat = domain_statistic((outcome(tp=0, fp=5, fn=0),), "alert_f1")
    assert stat.value is None and stat.null_reason == "unsupported_class"
    assert (stat.numerator, stat.denominator, stat.support) == (0, 5, 5)
    empty = domain_statistic((outcome(tp=0, fp=0, fn=0),), "alert_f1")
    assert empty.value is None and empty.support == empty.denominator == 0
    missed = domain_statistic((outcome(tp=0, fp=0, fn=1),), "alert_f1")
    assert missed.value == 0 and missed.denominator == missed.support == 1


def test_repeated_sampled_family_keeps_full_count_multiplicity():
    row = outcome()
    counts = raw_counts((row, row))
    assert counts == dict(
        tp=6, fp_alerts=2, fn=4, affected_benign=2, positive_episodes=10, benign_episodes=8
    )
    stat = domain_statistic((row, row), "alert_f1")
    assert stat.value == pytest.approx(2 / 3) and stat.support == stat.denominator == 18
    assert domain_statistic((row, row), "raw_positive_episodes").value == 10


@pytest.mark.parametrize("metric", tuple(RAW_METRICS))
def test_raw_count_complete_zero_is_measured_but_failed_cohort_and_empty_are_na(metric):
    zero = outcome(tp=0, fp=0, fn=0, benign=0, affected=0)
    actual = domain_statistic((zero,), metric)
    assert (actual.value, actual.numerator, actual.denominator, actual.support) == (0, 0, None, 0)
    failed = zero.model_copy(update={"status": "provider_error", "predicted": None})
    incomplete = domain_statistic((outcome(), failed), metric)
    assert incomplete.value is incomplete.numerator is incomplete.denominator is None
    assert incomplete.null_reason == "incomplete_cohort"
    assert domain_statistic((), metric).null_reason == "empty_cohort"


def test_bool_counts_or_reference_mismatch_never_coerce_to_integers():
    row = outcome()
    with pytest.raises(ValueError, match="domain_counts"):
        raw_counts((row.model_copy(update={"predicted": row.predicted | {"tp": True}}),))
    with pytest.raises(ValueError, match="domain_counts"):
        raw_counts(
            (row.model_copy(update={"predicted": row.predicted | {"positive_episodes": 999}}),)
        )


def test_two_actual_source_units_one_hundred_reference_episodes_keep_distinct_support(tmp_path):
    t = toy(tmp_path)
    records = []
    for record in t.records:
        original = record.label_payload.payload
        positive = original["episodes"][0]
        declared = [
            positive | {"episode_id": f"{record.item_id}-hand-reference-{i}"} for i in range(50)
        ]
        payload = record.model_dump(mode="json")
        payload["label_payload"]["payload"] = original | {
            "episodes": declared + [original["episodes"][1]]
        }
        records.append(GoldRecord.model_validate_json(canonical_bytes(payload)))
    t.records = tuple(records)
    wire = b"".join(canonical_bytes(r.model_dump(mode="json")) + b"\n" for r in t.records)
    (tmp_path / "hand-records.jsonl").write_bytes(wire)
    manifest = t.manifest.model_dump(mode="json")
    manifest["splits"][0]["items_sha256"] = sha(wire)
    manifest["source_artifacts"][0]["sha256"] = sha(wire)
    t.manifest = Manifest.model_validate_json(canonical_bytes(manifest))
    rows = report_rows(actual_compare(t), t.adapter)
    axis = [
        r
        for r in rows
        if (r.method, r.field, r.class_name) == ("rules_only", "detection:1of2", "port_scan")
    ]
    recall = next(r for r in axis if r.metric == "alert_recall")
    raw = next(r for r in axis if r.metric == "raw_positive_episodes")
    assert recall.corpus_N == recall.eligible_N == recall.answered_N == 2
    assert recall.denominator == recall.supports["positive_episode_support"] == 100
    assert recall.value == 0.02 and (recall.numerator, recall.supports["false_negative"]) == (2, 98)
    assert raw.corpus_N == 2 and (raw.value, raw.numerator, raw.denominator) == (100, 100, None)
    assert raw.supports["statistic_support"] == 100


def test_bootstrap_policy_is_fixed_and_duplicate_group_declarations_rejected():
    spec = bootstrap_spec(("hand-a", "hand-b"))
    assert (spec.draws, spec.seed, spec.level, spec.min_support, spec.min_valid_draws) == (
        2000,
        20261014,
        0.95,
        1,
        1900,
    )
    assert spec.rng_version == "Python3.12/random" and spec.statistic_version == STATISTIC_VERSION
    with pytest.raises(ValueError):
        bootstrap_spec(("hand-a", "hand-a"))


def test_raw_count_public_rows_keep_closed_metric_units_without_private_support_dict(tmp_path):
    from firewall_analyst.shared.evalkit.reporting import public_aggregate

    t = toy(tmp_path)
    rows = report_rows(actual_compare(t), t.adapter)
    raw = [r for r in rows if r.metric in RAW_METRICS and r.measurement_status == "measured"]
    assert raw and all(r.interval is None and r.denominator is None for r in raw)
    exported = [public_aggregate(r, t.adapter.public_projection_policy()) for r in raw]
    assert all(
        "supports" not in row and "group_id" not in row and "source_handle" not in row
        for row in exported
    )
    assert all(row["statistic_version"].startswith("s8-raw-count-1.") for row in exported)


def test_bounded_bootstrap_two_hand_families_common_stream_actual_methods(tmp_path):
    from firewall_analyst.domain.evaluation.metrics import paired_estimates

    t = toy(tmp_path)
    comparison = actual_compare(t)
    methods = ("rules_only", "distinct_port_bucket_proxy")
    result = paired_estimates(
        comparison,
        methods,
        "alert_recall",
        "port_scan",
        (1, 2),
        ("PRIVATE-FAMILY-0", "PRIVATE-FAMILY-1"),
    )
    assert result.draws_sha256 == "2dce767cd94f2690e00ab825655f4ad69d5283fc9b3c6773955e6cd80d0d75cf"
    assert result.group_count == 2 and result.rng_version == "Python3.12/random"
    for estimate in result.methods.values():
        assert estimate.point.value == 1 and estimate.valid_draws == 2000
        assert estimate.interval.low == estimate.interval.high == 1
        assert estimate.interval.draw_ids_sha256 == result.draws_sha256
    difference = result.differences[methods]
    assert difference.point.value == 0 and difference.valid_draws == 2000
    assert difference.interval.low == difference.interval.high == 0


def test_bounded_bootstrap_one_hand_family_has_no_interval():
    from firewall_analyst.shared.evalkit.resampling import paired_group_resample

    row = outcome(tp=1, fp=0, fn=0, benign=1, affected=0)
    estimate = paired_group_resample(
        {"rules_only": (row,)},
        bootstrap_spec(("hand-family",)),
        lambda rows: domain_statistic(rows, "alert_recall"),
    )
    actual = estimate.methods["rules_only"]
    assert actual.point.value == 1 and actual.interval is None
    assert actual.null_reason == "insufficient_independent_groups"
    assert actual.valid_draws == 2000


def test_bounded_bootstrap_unsupported_f1_remains_null_with_positive_target_support():
    from firewall_analyst.shared.evalkit.resampling import paired_group_resample

    rows = (
        outcome(tp=0, fp=1, fn=0, item_id="hand-zero-a", group_id="hand-zero-family-a"),
        outcome(tp=0, fp=0, fn=0, item_id="hand-zero-b", group_id="hand-zero-family-b"),
    )
    other = tuple(r.model_copy(update={"method": "distinct_port_bucket_proxy"}) for r in rows)
    result = paired_group_resample(
        {"rules_only": rows, "distinct_port_bucket_proxy": other},
        bootstrap_spec(("hand-zero-family-a", "hand-zero-family-b")),
        lambda sample: domain_statistic(sample, "alert_f1"),
    )
    for estimate in result.methods.values():
        assert estimate.point.value is None and estimate.point.support == 1
        assert estimate.point.null_reason == estimate.null_reason == "unsupported_class"
        assert estimate.valid_draws == 0 and estimate.interval is None
    assert result.differences[("rules_only", "distinct_port_bucket_proxy")].valid_draws == 0
