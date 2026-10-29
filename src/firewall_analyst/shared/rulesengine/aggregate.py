"""Typed support-bound statistics, independent of application/network semantics."""

import math
import statistics
from collections.abc import Callable, Sequence

from .schemas import EvidenceSupport, TypedStatV1, support_digest


def support_for[T](
    rows: Sequence[T], *, source_sha256: str, row_id: Callable[[T], str]
) -> EvidenceSupport:
    ids = tuple(row_id(row) for row in rows)
    return EvidenceSupport(
        source_sha256=source_sha256, row_ids=ids, support_sha256=support_digest(ids)
    )


def measured_stat(
    stat_id: str, value: int | float | None, unit: str, support: EvidenceSupport, known: int
) -> TypedStatV1:
    return TypedStatV1(
        stat_id=stat_id,
        value=value,
        unit=unit,
        support=support,
        known_count=known,
        unknown_count=len(support.row_ids) - known,
    )


def sum_stat[T](
    rows: Sequence[T],
    *,
    getter: Callable[[T], int | None],
    support: EvidenceSupport,
    stat_id: str,
    unit: str,
) -> TypedStatV1:
    if len(rows) != len(support.row_ids):
        raise ValueError("support_cardinality_mismatch")
    values = [getter(row) for row in rows]
    if any(value is not None and (type(value) is not int or value < 0) for value in values):
        raise ValueError("invalid_measurement")
    known = [value for value in values if value is not None]
    return measured_stat(stat_id, sum(known) if known else None, unit, support, len(known))


def population_cv(values: Sequence[int | float]) -> float | None:
    if not values:
        return None
    if any(
        type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in values
    ):
        raise ValueError("invalid_measurement")
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else None


def interval_stats[T](
    rows: Sequence[T], *, timestamp: Callable[[T], int], support: EvidenceSupport
) -> tuple[TypedStatV1, ...]:
    if len(rows) != len(support.row_ids):
        raise ValueError("support_cardinality_mismatch")
    times = [timestamp(row) for row in rows]
    if (
        not times
        or any(type(value) is not int or value < 0 for value in times)
        or times != sorted(times)
    ):
        raise ValueError("unsorted_time")
    intervals = [b - a for a, b in zip(times, times[1:], strict=False) if b > a]
    equal = sum(a == b for a, b in zip(times, times[1:], strict=False))
    return (
        measured_stat("span_us", times[-1] - times[0], "microseconds", support, len(times)),
        measured_stat("positive_intervals", len(intervals), "count", support, len(times)),
        measured_stat("equal_timestamps", equal, "count", support, len(times)),
        measured_stat(
            "interval_median_us",
            statistics.median(intervals) if intervals else None,
            "microseconds",
            support,
            len(intervals),
        ),
        measured_stat("interval_cv", population_cv(intervals), "ratio", support, len(intervals)),
    )


def byte_cv_stat[T](
    rows: Sequence[T], *, getter: Callable[[T], int | None], support: EvidenceSupport
) -> TypedStatV1:
    if len(rows) != len(support.row_ids):
        raise ValueError("support_cardinality_mismatch")
    values = [getter(row) for row in rows if getter(row) is not None]
    value = population_cv(values)
    # A zero mean makes the ratio unevaluable, even when zero-byte measurements exist.
    return measured_stat(
        "orig_bytes_cv", value, "ratio", support, len(values) if value is not None else 0
    )
