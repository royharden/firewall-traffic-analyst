"""Strict local contracts. These checks do not recompute evidence from source data."""

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Token = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
RowId = Annotated[str, Field(min_length=1, max_length=256)]
Count = Annotated[int, Field(ge=0)]


class BoundaryModel(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid", allow_inf_nan=False)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def require_integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema version must be an integer, never boolean or float")
        return value


def support_digest(row_ids: tuple[str, ...]) -> str:
    """Identity of a complete set, not a proof that these rows exist or support a claim."""
    return hashlib.sha256(
        json.dumps(sorted(row_ids), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class EvidenceRef(BoundaryModel):
    """S8 evidence identity, not the foreign canonical Pointer wire schema."""

    schema_version: Literal[1] = 1
    source_sha256: Sha256
    row_id: RowId


class EvidenceSupport(BoundaryModel):
    source_sha256: Sha256
    row_ids: Annotated[tuple[RowId, ...], Field(min_length=1, max_length=250_000)]
    support_sha256: Sha256

    @model_validator(mode="after")
    def check_identity(self) -> Self:
        if len(set(self.row_ids)) != len(self.row_ids):
            raise ValueError("duplicate support identities")
        if support_digest(self.row_ids) != self.support_sha256:
            raise ValueError("support digest mismatch")
        return self


class TimeWindow(BoundaryModel):
    """Half-open [start_us,end_us), integer UTC epoch microseconds."""

    start_us: Count
    end_us: Count

    @model_validator(mode="after")
    def check_order(self) -> Self:
        if self.end_us <= self.start_us:
            raise ValueError("window must have positive duration")
        return self


class KeyPart(BoundaryModel):
    name: Token
    value: str | int


class TypedStatV1(BoundaryModel):
    stat_id: Token
    value: int | float | None
    unit: Token
    support: EvidenceSupport
    known_count: Count
    unknown_count: Count

    @model_validator(mode="after")
    def check_support_counts(self) -> Self:
        if self.known_count + self.unknown_count != len(self.support.row_ids):
            raise ValueError("known/unknown counts must cover the declared support")
        if (self.value is None) != (self.known_count == 0):
            raise ValueError(
                "unknown value requires zero known support; known value requires support"
            )
        return self


class FlaggedGroupV1(BoundaryModel):
    schema_version: Literal[1] = 1
    group_id: Sha256
    rule_id: Token
    rule_version: Token
    config_sha256: Sha256
    window: TimeWindow
    grouping_key: Annotated[tuple[KeyPart, ...], Field(min_length=1)]
    support: EvidenceSupport
    stats: Annotated[tuple[TypedStatV1, ...], Field(min_length=1)]
    category_from_rule: Token
    severity_from_rule: Annotated[int, Field(ge=1, le=4)]
    status: Literal["flagged", "suppressed", "partial"] = "flagged"
    matched_context_ids: tuple[Token, ...] = ()
    quality_flags: tuple[Token, ...] = ()

    @model_validator(mode="after")
    def check_scopes(self) -> Self:
        if len({item.name for item in self.grouping_key}) != len(self.grouping_key):
            raise ValueError("duplicate grouping-key name")
        if len({item.stat_id for item in self.stats}) != len(self.stats):
            raise ValueError("duplicate statistic identity")
        for stat in self.stats:
            if stat.support.source_sha256 != self.support.source_sha256:
                raise ValueError("statistic belongs to a different generation")
            if not set(stat.support.row_ids) <= set(self.support.row_ids):
                raise ValueError("statistic support escapes group")
        if self.status == "suppressed" and not self.matched_context_ids:
            raise ValueError("suppression requires context identity")
        if self.status == "partial" and not self.quality_flags:
            raise ValueError("partial group requires explicit quality reason")
        return self


class ClaimV1(BoundaryModel):
    stat_ref: Token
    value: int | float
    unit: Token
    formatter: Token
    support: EvidenceSupport


class ClaimSupportContractV1(BoundaryModel):
    """Local relationship validation only; no source resolution/statistic recomputation."""

    group: FlaggedGroupV1
    claims: Annotated[tuple[ClaimV1, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def check_relationships(self) -> Self:
        statistics = {stat.stat_id: stat for stat in self.group.stats}
        for claim in self.claims:
            stat = statistics.get(claim.stat_ref)
            if stat is None or claim.unit != stat.unit:
                raise ValueError("claim must reference a declared statistic and matching unit")
            if claim.support.source_sha256 != stat.support.source_sha256:
                raise ValueError("claim belongs to a different generation")
            if not set(claim.support.row_ids) <= set(stat.support.row_ids):
                raise ValueError("claim support escapes statistic scope")
            if claim.support.support_sha256 == stat.support.support_sha256:
                if stat.value is None or claim.value != stat.value:
                    raise ValueError("full-support claim contradicts the declared statistic")
        return self


class ParseSummaryV1(BoundaryModel):
    schema_version: Literal[1] = 1
    state: Literal["complete", "partial", "unsupported", "error"]
    source_sha256: Sha256 | None
    original_rows: Count | None
    processed_rows: Count | None
    quarantined_rows: Count | None
    excluded_rows: Count | None
    reason_codes: tuple[Token, ...] = ()

    @model_validator(mode="after")
    def check_observation_state(self) -> Self:
        counts = (
            self.original_rows,
            self.processed_rows,
            self.quarantined_rows,
            self.excluded_rows,
        )
        if self.state == "complete":
            if self.source_sha256 is None or any(value is None for value in counts):
                raise ValueError("complete processing needs observed generation and counts")
            if self.excluded_rows != 0:
                raise ValueError("complete processing cannot exclude an unprocessed suffix")
            if self.original_rows != self.processed_rows + self.quarantined_rows:
                raise ValueError("complete row counts disagree")
        elif not self.reason_codes:
            raise ValueError("noncomplete processing requires a reason")
        if (self.processed_rows or self.quarantined_rows) and self.source_sha256 is None:
            raise ValueError("observed rows require a source generation")
        if self.original_rows is not None:
            observed = sum(value for value in counts[1:] if value is not None)
            if observed > self.original_rows:
                raise ValueError("observed counters exceed original rows")
        if "input_limit" in self.reason_codes:
            if self.state != "error" or self.source_sha256 is not None:
                raise ValueError("hard input limit has no analyzed generation")
            if any(value is not None for value in counts):
                raise ValueError("hard input limit cannot invent row counts")
        return self


class InputLimitsV1(BoundaryModel):
    """Configuration representation only; no byte/row enforcement is implemented here."""

    max_file_bytes: Annotated[int, Field(gt=0)] = 200 * 1024 * 1024
    max_analyzed_rows: Annotated[int, Field(gt=0)] = 250_000
    max_line_bytes: Annotated[int, Field(gt=0)] = 16 * 1024
    max_groups: Annotated[int, Field(gt=0)] = 10_000
    max_output_bytes: Annotated[int, Field(gt=0)] = 64 * 1024 * 1024
