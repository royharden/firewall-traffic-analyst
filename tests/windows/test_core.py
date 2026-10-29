"""Hand-computed generic windows/statistics/incident oracles, no detector import."""

from dataclasses import dataclass

import pytest

from firewall_analyst.shared.rulesengine.aggregate import (
    interval_stats,
    population_cv,
    sum_stat,
    support_for,
)
from firewall_analyst.shared.rulesengine.rules import Candidate, merge_candidates
from firewall_analyst.shared.rulesengine.schemas import KeyPart, TimeWindow
from firewall_analyst.shared.rulesengine.windows import ordered, sliding_windows


@dataclass(frozen=True)
class Change:
    row_id: str
    ts: int
    line: int
    value: int | None
    subject: str = "resource"


def key(row):
    return (KeyPart(name="subject", value=row.subject),)


def windows(rows, **kwargs):
    return sliding_windows(
        rows,
        timestamp=lambda row: row.ts,
        tie=lambda row: row.line,
        key=key,
        width_us=60,
        stride_us=30,
        **kwargs,
    )


def test_half_open_alignment_sorted_ties_and_bounded_gap_without_empty_windows():
    rows = (Change("c", 60, 3, 0), Change("b", 59, 2, None), Change("a", 30, 1, 2))
    batch = windows(rows)
    observed = {
        bucket.window.start_us: tuple(row.row_id for row in bucket.rows) for bucket in batch.buckets
    }
    assert observed == {30: ("a", "b", "c"), 0: ("a", "b"), 60: ("c",)}
    assert ordered(rows, timestamp=lambda row: 0, tie=lambda row: row.line) == rows[::-1]
    gap = windows((rows[0], Change("later", 10**12, 4, 1)))
    assert len(gap.buckets) <= 4  # No iteration through an epoch-sized empty gap.
    assert batch.complete


def test_bucket_cap_is_explicit_incomplete_and_never_a_complete_negative():
    batch = windows((Change("a", 30, 1, 2), Change("b", 60, 2, 3)), max_buckets=1)
    assert not batch.complete and len(batch.buckets) == 1


@pytest.mark.parametrize("width,stride", [(0, 1), (10, 0), (10, 11), (65, 1), (True, 1)])
def test_invalid_window_policy_rejected(width, stride):
    with pytest.raises(ValueError):
        sliding_windows(
            (),
            timestamp=lambda row: row.ts,
            tie=lambda row: row.line,
            key=key,
            width_us=width,
            stride_us=stride,
        )


def test_union_only_overlapping_same_rule_key_no_uid_merge_or_double_count():
    a, b, c = Change("a", 10, 1, 1), Change("b", 40, 2, 2), Change("c", 70, 3, 3)
    candidates = (
        Candidate("r", key(a), TimeWindow(start_us=0, end_us=60), (a, b)),
        Candidate("r", key(a), TimeWindow(start_us=30, end_us=90), (b, c)),
        Candidate("r", key(a), TimeWindow(start_us=90, end_us=120), (Change("d", 100, 4, 4),)),
        Candidate("other", key(a), TimeWindow(start_us=0, end_us=60), (a,)),
        Candidate(
            "r",
            (KeyPart(name="subject", value="different"),),
            TimeWindow(start_us=0, end_us=60),
            (a,),
        ),
    )
    merged = merge_candidates(
        candidates,
        row_id=lambda row: row.row_id,
        timestamp=lambda row: row.ts,
        tie=lambda row: row.line,
    )
    assert len(merged) == 4
    assert tuple(row.row_id for row in merged[0].rows) == ("a", "b", "c")
    assert merged[0].window == TimeWindow(start_us=0, end_us=90)


def test_typed_null_zero_sum_and_population_interval_cv_support_counts():
    rows = (Change("a", 0, 1, None), Change("b", 10, 2, 0), Change("c", 30, 3, 6))
    support = support_for(rows, source_sha256="a" * 64, row_id=lambda row: row.row_id)
    stat = sum_stat(
        rows, getter=lambda row: row.value, support=support, stat_id="sum", unit="bytes"
    )
    assert (stat.value, stat.known_count, stat.unknown_count) == (6, 2, 1)
    unknown = sum_stat(rows, getter=lambda row: None, support=support, stat_id="sum", unit="bytes")
    assert (unknown.value, unknown.known_count, unknown.unknown_count) == (None, 0, 3)
    stats = {
        stat.stat_id: stat
        for stat in interval_stats(rows, timestamp=lambda row: row.ts, support=support)
    }
    assert stats["interval_median_us"].value == 15
    assert stats["interval_cv"].value == pytest.approx(1 / 3)
    assert (stats["interval_cv"].known_count, stats["interval_cv"].unknown_count) == (2, 1)
    assert population_cv([0, 0]) is None and population_cv([0, 2]) == 1
    assert population_cv([]) is None


def test_equal_timestamps_positive_intervals_only_and_empty_undefined():
    rows = (Change("a", 10, 1, 0), Change("b", 10, 2, 0), Change("c", 20, 3, 0))
    support = support_for(rows, source_sha256="a" * 64, row_id=lambda row: row.row_id)
    stats = {
        stat.stat_id: stat
        for stat in interval_stats(rows, timestamp=lambda row: row.ts, support=support)
    }
    assert stats["equal_timestamps"].value == 1 and stats["positive_intervals"].value == 1
    assert stats["interval_median_us"].value == 10 and stats["interval_cv"].unknown_count == 2
    with pytest.raises(ValueError):
        interval_stats((), timestamp=lambda row: row.ts, support=support)
    with pytest.raises(ValueError):
        population_cv([float("inf")])


def test_conflicting_same_identity_rejected_instead_of_last_write_wins():
    a, b = Change("same", 10, 1, 1), Change("same", 10, 1, 999)
    values = (
        Candidate("r", key(a), TimeWindow(start_us=0, end_us=60), (a,)),
        Candidate("r", key(b), TimeWindow(start_us=0, end_us=60), (b,)),
    )
    with pytest.raises(ValueError, match="conflicting_row_identity"):
        merge_candidates(
            values,
            row_id=lambda row: row.row_id,
            timestamp=lambda row: row.ts,
            tie=lambda row: row.line,
        )


def test_stat_support_cardinality_mismatch_not_filled_with_unknown_rows():
    rows = (Change("a", 0, 1, 1), Change("b", 10, 2, 2))
    support = support_for(rows, source_sha256="a" * 64, row_id=lambda row: row.row_id)
    with pytest.raises(ValueError, match="support_cardinality"):
        sum_stat(
            rows[:1], getter=lambda row: row.value, support=support, stat_id="sum", unit="count"
        )
