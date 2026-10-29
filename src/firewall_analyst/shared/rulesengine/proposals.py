"""Neutral text for exact observed tuples, never a device command or policy verdict."""

import hashlib
import json
from collections.abc import Callable, Sequence
from typing import Annotated, Literal

from pydantic import Field

from .evidence import CheckedEvidence, EvidenceSource
from .parsers import EvidenceRecord
from .schemas import BoundaryModel, EvidenceRef, EvidenceSupport, FlaggedGroupV1, Sha256

HEADER = "NOT APPLIED — proposal for human review"


class _ProposalLimit(ValueError):
    pass


class NeutralProposalV1(BoundaryModel):
    schema_version: Literal[1] = 1
    proposal_id: Sha256
    group_id: Sha256
    support: EvidenceSupport
    status: Literal["proposed", "investigate"]
    text: Annotated[str, Field(min_length=1, max_length=65536)]
    reason_codes: tuple[str, ...] = ()


def compact_integer_set(values: Sequence[int]) -> tuple[str, ...]:
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("invalid_integer_set")
    ordered = sorted(set(values))
    spans = []
    for value in ordered:
        if spans and value == spans[-1][1] + 1:
            spans[-1][1] = value
        else:
            spans.append([value, value])
    return tuple(str(start) if start == end else f"{start}-{end}" for start, end in spans)


def neutral_proposal[T: EvidenceRecord](
    group: FlaggedGroupV1,
    checked: CheckedEvidence,
    *,
    source: EvidenceSource[T],
    project: Callable[[Sequence[T]], Sequence[dict[str, str | int]]],
) -> NeutralProposalV1:
    def result(status: str, body: str, reasons: tuple[str, ...]) -> NeutralProposalV1:
        text = HEADER + "\n" + body
        identity = json.dumps(
            [group.group_id, group.support.support_sha256, status, text],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        return NeutralProposalV1(
            proposal_id=hashlib.sha256(identity).hexdigest(),
            group_id=group.group_id,
            support=group.support,
            status=status,
            text=text,
            reason_codes=reasons,
        )

    if (
        group.status != "flagged"
        or group.category_from_rule == "unclear"
        or checked.state != "verified"
        or checked.group_id != group.group_id
        or checked.source_sha256 != group.support.source_sha256
        or not any(sentence.label_kind == "observed_statistic" for sentence in checked.sentences)
    ):
        return result("investigate", "Investigate; no proposed rule.", ("group_not_proposable",))
    try:
        source.validate_generation(group.support.source_sha256)
        refs = tuple(
            EvidenceRef(source_sha256=group.support.source_sha256, row_id=row_id)
            for row_id in group.support.row_ids
        )
        rows = source.resolve(refs)
        if tuple(row.row_id for row in rows) != group.support.row_ids or any(
            row.source_sha256 != group.support.source_sha256 for row in rows
        ):
            raise ValueError("support_mismatch")
        source.validate_group(group, rows)
        tuples = project(rows)
        if not 1 <= len(tuples) <= 1000:
            raise _ProposalLimit()
        for item in tuples:
            if not item or any(
                type(key) is not str or type(value) not in (str, int) for key, value in item.items()
            ):
                raise ValueError("invalid_projection")
        lines = [
            json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            for item in tuples
        ]
        body = (
            "Review only these exact observed tuples; choose policy manually.\n"
            + "\n".join(sorted(set(lines)))
            + "\nGroup: "
            + group.group_id
            + "\nSupport: "
            + group.support.support_sha256
        )
        if len((HEADER + "\n" + body).encode("utf-8")) > 64 * 1024:
            raise _ProposalLimit()
        source.validate_generation(group.support.source_sha256)
        return result("proposed", body, ())
    except _ProposalLimit:
        return result("investigate", "Investigate; no proposed rule.", ("proposal_limit",))
    except (ValueError, OSError, KeyError):
        return result(
            "investigate", "Investigate; no proposed rule.", ("source_or_projection_unavailable",)
        )
