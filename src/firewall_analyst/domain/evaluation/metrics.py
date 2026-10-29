"""Domain count callbacks over actual canonical outcomes and report/statistic types."""

from collections.abc import Mapping

from ...shared.evalkit.models import ConfusionCounts, MetricRow, Outcome, ResamplingSpec
from ...shared.evalkit.reporting import metric_row, not_measured_row, public_aggregate
from ...shared.evalkit.resampling import paired_group_resample
from ...shared.evalkit.runner import Comparison, MethodEvaluation
from ...shared.evalkit.statistics import Statistic, classification_rates, rate
from ..rules.engine import RULES
from .adapter import (
    RATIO_METRICS,
    RAW_METRICS,
    STATISTIC_VERSION,
    DetectionAdapter,
    metric_specs,
    threshold_field,
)
from .matching import THRESHOLDS
from .methods import METHOD_PATTERNS

COUNT_KEYS = ("tp", "fp_alerts", "fn", "affected_benign", "positive_episodes", "benign_episodes")


def _reference_counts(row: Outcome) -> dict[str, int]:
    if (
        type(row) is not Outcome
        or type(row.expected) is not dict
        or set(row.expected) != {"positive_episodes", "benign_episodes"}
        or any(type(v) is not int or v < 0 for v in row.expected.values())
    ):
        raise ValueError("closed_reference_count_outcome_required")
    return row.expected


def raw_counts(rows: tuple[Outcome, ...]) -> dict[str, int] | None:
    """Keep repeated sampled source/family contributions: never deduplicate IDs here."""
    totals = dict.fromkeys(COUNT_KEYS, 0)
    for row in rows:
        expected = _reference_counts(row)
        if row.eligibility != "eligible" or row.status != "ok" or row.predicted is None:
            return None
        data = row.predicted
        if (
            type(data) is not dict
            or set(data) != set(COUNT_KEYS)
            or any(type(v) is not int or v < 0 for v in data.values())
            or row.correct is not None
            or row.human_touched_prediction
            or data["tp"] + data["fn"] != data["positive_episodes"]
            or data["affected_benign"] > data["benign_episodes"]
            or any(data[k] != v for k, v in expected.items())
        ):
            raise ValueError("closed_domain_counts_required")
        for key in COUNT_KEYS:
            totals[key] += data[key]
    return totals


def domain_statistic(rows: tuple[Outcome, ...], metric: str) -> Statistic:
    if metric in RAW_METRICS:
        if not rows:
            return Statistic(None, 0, "empty_cohort")
        counts = raw_counts(rows)
        if counts is None:
            return Statistic(None, 0, "incomplete_cohort")
        value = counts[RAW_METRICS[metric][0]]
        return Statistic(value, value, numerator=value, denominator=None)
    if metric not in RATIO_METRICS:
        raise ValueError("named_domain_ratio_required")
    counts = raw_counts(rows)
    if counts is None:
        return Statistic(None, 0, "incomplete_cohort")
    tp, fp, fn = counts["tp"], counts["fp_alerts"], counts["fn"]
    if metric == "alert_precision":
        return rate(tp, tp + fp)
    if metric == "alert_recall":
        return rate(tp, tp + fn)
    if metric == "benign_episode_fpr":
        return rate(counts["affected_benign"], counts["benign_episodes"])
    canonical = classification_rates(
        ConfusionCounts(true_positive=tp, false_positive=fp, false_negative=fn, true_negative=0)
    ).f1
    # Adopted target-denominator gate, preserving every actual canonical F1 value.
    # Canonical f1.support is TP+FN; retain it separately in report supports.
    return Statistic(
        canonical.value,
        canonical.denominator,
        canonical.null_reason,
        canonical.numerator,
        canonical.denominator,
    )


def _axis(comparison: Comparison, method: str, field: str, pattern: str) -> tuple[Outcome, ...]:
    evaluation = comparison.methods[method]
    if evaluation.requested_item_ids != comparison.frozen_item_ids:
        raise ValueError("fixed_source_cohort_changed")
    rows = tuple(
        row for row in evaluation.outcomes if row.field == field and row.class_name == pattern
    )
    if tuple(row.item_id for row in rows) != comparison.frozen_item_ids:
        raise ValueError("missing_duplicated_or_reordered_source_axis")
    if any(
        row.method != method
        or row.split != comparison.split
        or (row.eligibility == "eligible") != (pattern in METHOD_PATTERNS[method])
        for row in rows
    ):
        raise ValueError("method_axis_or_applicability_changed")
    return rows


def _revalidate(row: MetricRow, **updates) -> MetricRow:
    return MetricRow.model_validate(row.model_dump() | updates)


def report_rows(comparison: Comparison, adapter: DetectionAdapter) -> tuple[MetricRow, ...]:
    if (
        type(comparison) is not Comparison
        or set(comparison.methods) != set(METHOD_PATTERNS)
        or comparison.corpus_count != len(comparison.frozen_item_ids)
        or len(set(comparison.frozen_item_ids)) != comparison.corpus_count
    ):
        raise ValueError("all_named_fixed_source_methods_required")
    reports = []
    for method in METHOD_PATTERNS:
        evaluation = comparison.methods[method]
        if type(evaluation) is not MethodEvaluation or evaluation.status not in {
            "executed",
            "not_run",
        }:
            raise ValueError("actual_canonical_method_evaluation_required")
        if evaluation.requested_item_ids != comparison.frozen_item_ids:
            raise ValueError("fixed_source_cohort_changed")
        if evaluation.status == "not_run" and (
            evaluation.actual_predictions or evaluation.outcomes or evaluation.calls_observed != 0
        ):
            raise ValueError("never_run_cannot_have_fabricated_observations")
        if evaluation.status == "executed":
            expected_axes = {
                (item, threshold_field(threshold), pattern)
                for item in comparison.frozen_item_ids
                for threshold in THRESHOLDS
                for pattern in RULES
            }
            actual_axes = [(row.item_id, row.field, row.class_name) for row in evaluation.outcomes]
            if len(actual_axes) != len(expected_axes) or set(actual_axes) != expected_axes:
                raise ValueError("fixed_named_source_axes_changed")
        for threshold in THRESHOLDS:
            field = threshold_field(threshold)
            for pattern in RULES:
                applicable = pattern in METHOD_PATTERNS[method]
                executed = evaluation.status == "executed" and comparison.corpus_count > 0
                rows = _axis(comparison, method, field, pattern) if executed else ()
                for spec in metric_specs():
                    config_ref = adapter.configs[method].config_sha256
                    if not executed or not applicable:
                        row = not_measured_row(
                            comparison.frozen_item_ids,
                            comparison.frozen_item_ids if applicable else (),
                            spec,
                            method=method,
                            dataset_alias=adapter.dataset_alias,
                            split=comparison.split,
                            config_ref=config_ref,
                        )
                        reason = (
                            "not_applicable"
                            if not applicable
                            else ("not_run" if evaluation.status == "not_run" else "empty_cohort")
                        )
                        updates = {"field": field, "class": pattern, "null_reason": reason}
                        if executed:
                            updates |= {
                                "measurement_status": "unsupported",
                                "evidence_origin": adapter.configs[method].origin,
                            }
                        reports.append(_revalidate(row, **updates))
                        continue
                    row = metric_row(
                        rows,
                        comparison.frozen_item_ids,
                        spec,
                        lambda population, metric=spec.metric: domain_statistic(population, metric),
                        method=method,
                        dataset_alias=adapter.dataset_alias,
                        split=comparison.split,
                        config_ref=config_ref,
                        field=field,
                        class_name=pattern,
                    )
                    counts = raw_counts(rows)
                    if counts is None:
                        row = _revalidate(
                            row,
                            measurement_status="not_measured",
                            numerator=None,
                            denominator=None,
                            value=None,
                            interval=None,
                            null_reason="incomplete_cohort",
                        )
                    else:
                        row = _revalidate(
                            row,
                            supports=row.supports
                            | {
                                "positive_episode_support": counts["positive_episodes"],
                                "benign_episode_support": counts["benign_episodes"],
                                "true_positive": counts["tp"],
                                "false_positive_alerts": counts["fp_alerts"],
                                "false_negative": counts["fn"],
                                "affected_benign": counts["affected_benign"],
                            },
                        )
                    reports.append(row)
    return tuple(reports)


def public_rows(comparison: Comparison, adapter: DetectionAdapter) -> tuple[dict[str, object], ...]:
    policy = adapter.public_projection_policy()
    return tuple(public_aggregate(row, policy) for row in report_rows(comparison, adapter))


def bootstrap_spec(group_order: tuple[str, ...]) -> ResamplingSpec:
    return ResamplingSpec(
        version="s8-whole-family-target-denominator-1",
        unit="group_id",
        seed=20261014,
        draws=2000,
        level=0.95,
        method="percentile",
        group_order=group_order,
        stratum_map=None,
        min_support=1,
        min_valid_draws=1900,
        statistic_version=STATISTIC_VERSION,
        rng_version="Python3.12/random",
    )


def paired_estimates(
    comparison: Comparison,
    methods: tuple[str, ...],
    metric: str,
    pattern: str,
    threshold: tuple[int, int],
    group_order: tuple[str, ...],
):
    """Callable component; actual large/bootstrap experiments need allocated execution."""
    if not methods or len(set(methods)) != len(methods) or metric not in RATIO_METRICS:
        raise ValueError("named_paired_metric_required")
    if threshold not in THRESHOLDS or pattern not in RULES:
        raise ValueError("fixed_paired_axis_required")
    populations: Mapping[str, tuple[Outcome, ...]] = {
        method: _axis(comparison, method, threshold_field(threshold), pattern)
        for method in methods
        if method in comparison.methods
        and pattern in METHOD_PATTERNS[method]
        and comparison.methods[method].status == "executed"
    }
    if tuple(populations) != methods or any(
        raw_counts(rows) is None for rows in populations.values()
    ):
        raise ValueError("complete_identical_applicable_population_required")
    return paired_group_resample(
        populations, bootstrap_spec(group_order), lambda rows: domain_statistic(rows, metric)
    )
