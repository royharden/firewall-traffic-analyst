"""Pure half-open, epoch-aligned sliding windows over caller-owned row types."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .schemas import KeyPart, TimeWindow


@dataclass(frozen=True)
class WindowBucket[T]:
    key: tuple[KeyPart, ...]
    window: TimeWindow
    rows: tuple[T, ...]


@dataclass(frozen=True)
class WindowBatch[T]:
    buckets: tuple[WindowBucket[T], ...]
    complete: bool


def ordered[T](
    rows: Sequence[T], *, timestamp: Callable[[T], int], tie: Callable[[T], int]
) -> tuple[T, ...]:
    for row in rows:
        if type(timestamp(row)) is not int or timestamp(row) < 0 or type(tie(row)) is not int:
            raise ValueError("invalid_row_order")
    return tuple(sorted(rows, key=lambda row: (timestamp(row), tie(row))))


def sliding_windows[T](
    rows: Sequence[T],
    *,
    timestamp: Callable[[T], int],
    tie: Callable[[T], int],
    key: Callable[[T], tuple[KeyPart, ...]],
    width_us: int,
    stride_us: int,
    max_buckets: int = 10_000,
) -> WindowBatch[T]:
    if any(type(value) is not int or value <= 0 for value in (width_us, stride_us, max_buckets)):
        raise ValueError("invalid_window_policy")
    if stride_us > width_us or (width_us + stride_us - 1) // stride_us > 64:
        raise ValueError("invalid_window_policy")
    buckets: dict[tuple[tuple[KeyPart, ...], int], list[T]] = {}
    complete = True
    for row in ordered(rows, timestamp=timestamp, tie=tie):
        value = timestamp(row)
        start = value // stride_us * stride_us
        while start >= 0 and value < start + width_us:
            identity = (key(row), start)
            if identity not in buckets:
                if len(buckets) == max_buckets:
                    complete = False
                    break
                buckets[identity] = []
            buckets[identity].append(row)
            start -= stride_us
        if not complete:
            break
    return WindowBatch(
        tuple(
            WindowBucket(parts, TimeWindow(start_us=start, end_us=start + width_us), tuple(items))
            for (parts, start), items in buckets.items()
        ),
        complete,
    )
