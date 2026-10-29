"""Generic incident merge and deterministic group identity; no domain import."""

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .schemas import FlaggedGroupV1, KeyPart, TimeWindow


@dataclass(frozen=True)
class Candidate[T]:
    rule_id: str
    key: tuple[KeyPart, ...]
    window: TimeWindow
    rows: tuple[T, ...]


def merge_candidates[T](
    candidates: Sequence[Candidate[T]],
    *,
    row_id: Callable[[T], str],
    timestamp: Callable[[T], int],
    tie: Callable[[T], int],
) -> tuple[Candidate[T], ...]:
    grouped: dict[tuple[str, tuple[KeyPart, ...]], list[Candidate[T]]] = {}
    for candidate in candidates:
        if not candidate.rows:
            raise ValueError("empty_candidate")
        if any(
            not candidate.window.start_us <= timestamp(row) < candidate.window.end_us
            for row in candidate.rows
        ):
            raise ValueError("support_outside_window")
        grouped.setdefault((candidate.rule_id, candidate.key), []).append(candidate)
    merged = []

    def finish(rule, key, start, end, distinct):
        return Candidate(
            rule,
            key,
            TimeWindow(start_us=start, end_us=end),
            tuple(sorted(distinct.values(), key=lambda item: (timestamp(item), tie(item)))),
        )

    for (rule, key), values in grouped.items():
        start, end, distinct = None, None, {}
        for candidate in sorted(values, key=lambda c: (c.window.start_us, c.window.end_us)):
            if start is None or candidate.window.start_us >= end:
                if start is not None:
                    merged.append(finish(rule, key, start, end, distinct))
                start, end, distinct = candidate.window.start_us, candidate.window.end_us, {}
            else:
                end = max(end, candidate.window.end_us)
            for row in candidate.rows:
                identity = row_id(row)
                if identity in distinct and distinct[identity] != row:
                    raise ValueError("conflicting_row_identity")
                distinct[identity] = row
        if start is not None:
            merged.append(finish(rule, key, start, end, distinct))
    return tuple(merged)


def identified_group(**fields) -> FlaggedGroupV1:
    """Hash the entire serialized final group body, including status and context."""
    provisional = FlaggedGroupV1(group_id="0" * 64, **fields)
    body = provisional.model_dump(mode="json", exclude={"group_id"})
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return provisional.model_copy(update={"group_id": digest})
