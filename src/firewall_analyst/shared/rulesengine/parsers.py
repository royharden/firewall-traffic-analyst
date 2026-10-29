"""Parser and rule protocols only: no IO, parsing, reducer or detector implementation."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Annotated, Protocol, TypeVar

from pydantic import Field

from .schemas import BoundaryModel, FlaggedGroupV1, ParseSummaryV1, Sha256, Token


class SourceLine(BoundaryModel):
    physical_line: Annotated[int, Field(ge=1)]
    text: str


class ParseIssue(BoundaryModel):
    physical_line: Annotated[int, Field(ge=1)]
    reason_code: Token


class EvidenceRecord(Protocol):
    @property
    def row_id(self) -> str: ...

    @property
    def source_sha256(self) -> str: ...


T = TypeVar("T", bound=EvidenceRecord)


@dataclass(frozen=True)
class ParseResult[T: EvidenceRecord]:
    records: tuple[T, ...]
    summary: ParseSummaryV1
    issues: tuple[ParseIssue, ...] = ()


class RuleContext(BoundaryModel):
    source_sha256: Sha256
    config_sha256: Sha256


class Parser(Protocol[T]):
    def parse(self, lines: Iterable[SourceLine], *, source_sha256: str) -> ParseResult[T]: ...


class Rule(Protocol[T]):
    def apply(
        self, records: Sequence[T], *, context: RuleContext
    ) -> tuple[FlaggedGroupV1, ...]: ...
