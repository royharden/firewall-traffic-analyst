"""Bounded raw one-to-one assignment, not a corpus reader or canonical evalkit.

The caller supplies eligibility edges and stable window/identity order. This helper
maximizes total integer overlap first, then matched cardinality, then earlier edge
ranks. Remaining equal-rank ties use deterministic ordered Hungarian iteration.
It computes no quality metric, loads no data and supplies no semantic eligibility.
"""

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class OverlapEdge:
    left_id: str
    right_id: str
    overlap_rows: int


def maximum_overlap_assignment(
    left_ids: Sequence[str],
    right_ids: Sequence[str],
    edges: Sequence[OverlapEdge],
    *,
    max_side: int = 256,
) -> tuple[OverlapEdge, ...]:
    """Return actual eligible edges only; unmatched vertices never become zero edges.

    IDs are opaque and never normalized. Their explicit input order is the caller's
    tie policy (for S8: window start/end, then group/episode ID). Positive integer
    overlap weights are cardinal evidence counts, not rounded floating scores.
    Limits fail explicitly rather than emitting a partial or successful empty match.
    """
    if type(max_side) is not int or not 1 <= max_side <= 256:
        raise ValueError("assignment_limit")
    left, right = tuple(left_ids), tuple(right_ids)
    if len(left) > max_side or len(right) > max_side or len(edges) > max_side * max_side:
        raise ValueError("assignment_limit")
    for values in (left, right):
        if any(type(value) is not str or not value or len(value) > 256 for value in values):
            raise ValueError("assignment_identity")
        if len(set(values)) != len(values):
            raise ValueError("duplicate_assignment_identity")
    left_index = {value: index for index, value in enumerate(left)}
    right_index = {value: index for index, value in enumerate(right)}
    eligible = {}
    for edge in edges:
        if not isinstance(edge, OverlapEdge):
            raise ValueError("assignment_edge")
        if type(edge.left_id) is not str or type(edge.right_id) is not str:
            raise ValueError("assignment_identity")
        if edge.left_id not in left_index or edge.right_id not in right_index:
            raise ValueError("foreign_assignment_identity")
        if type(edge.overlap_rows) is not int or not 1 <= edge.overlap_rows <= 250_000:
            raise ValueError("assignment_weight")
        key = left_index[edge.left_id], right_index[edge.right_id]
        if key in eligible:
            raise ValueError("duplicate_assignment_edge")
        eligible[key] = edge
    if not left or not right or not eligible:
        return ()

    count = min(len(left), len(right))
    edge_count = len(eligible)
    cardinality_scale = count * edge_count + 1
    overlap_scale = count * (cardinality_scale + edge_count) + 1
    scores = {}
    for rank, (key, edge) in enumerate(sorted(eligible.items())):
        scores[key] = edge.overlap_rows * overlap_scale + cardinality_scale + edge_count - rank

    # Each left vertex gets a private pool of zero-valued dummy columns, so no
    # ineligible edge is needed to represent an unmatched item. All arithmetic is
    # exact integer arithmetic; no epsilon changes the overlap objective.
    rows, columns = len(left), len(right) + len(left)
    costs = [[-scores.get((i, j), 0) for j in range(columns)] for i in range(rows)]
    potentials_left = [0] * (rows + 1)
    potentials_right = [0] * (columns + 1)
    matched_left = [0] * (columns + 1)
    predecessor = [0] * (columns + 1)
    for row in range(1, rows + 1):
        matched_left[0] = row
        column = 0
        minimum: list[int | None] = [None] * (columns + 1)
        used = [False] * (columns + 1)
        while True:
            used[column] = True
            active_row = matched_left[column]
            delta, next_column = None, 0
            for candidate in range(1, columns + 1):
                if used[candidate]:
                    continue
                cost = (
                    costs[active_row - 1][candidate - 1]
                    - potentials_left[active_row]
                    - potentials_right[candidate]
                )
                if minimum[candidate] is None or cost < minimum[candidate]:
                    minimum[candidate] = cost
                    predecessor[candidate] = column
                if delta is None or minimum[candidate] < delta:
                    delta, next_column = minimum[candidate], candidate
            if delta is None:
                raise ValueError("assignment_internal_failure")
            for candidate in range(columns + 1):
                if used[candidate]:
                    potentials_left[matched_left[candidate]] += delta
                    potentials_right[candidate] -= delta
                elif minimum[candidate] is not None:
                    minimum[candidate] -= delta
            column = next_column
            if matched_left[column] == 0:
                break
        while column:
            previous = predecessor[column]
            matched_left[column] = matched_left[previous]
            column = previous
    pairs = sorted(
        (matched_left[column] - 1, column - 1)
        for column in range(1, len(right) + 1)
        if matched_left[column] and (matched_left[column] - 1, column - 1) in eligible
    )
    return tuple(eligible[key] for key in pairs)
