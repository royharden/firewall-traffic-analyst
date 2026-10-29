"""Gold/seed convention types only. No fixture generator, splitter or scoring implementation."""

from datetime import timedelta
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, field_validator, model_validator

from .schemas import BoundaryModel, Count, EvidenceSupport, KeyPart, Sha256, TimeWindow, Token


class GoldEpisodeV1(BoundaryModel):
    schema_version: Literal[1] = 1
    episode_id: Token
    kind: Literal["positive", "benign", "expected_miss"]
    pattern: Token
    subject_key: Annotated[tuple[KeyPart, ...], Field(min_length=1)]
    window: TimeWindow
    support: EvidenceSupport
    expected_category: Token
    expected_severity: Annotated[int, Field(ge=1, le=4)]


class GoldManifestV1(BoundaryModel):
    schema_version: Literal[1] = 1
    generator_sha256: Sha256
    config_sha256: Sha256
    frozen_at_utc: AwareDatetime
    dev_seeds: Annotated[tuple[Count, ...], Field(min_length=1)]
    heldout_seeds: Annotated[tuple[Count, ...], Field(min_length=1)]

    @field_validator("frozen_at_utc")
    @classmethod
    def require_utc(cls, value: AwareDatetime) -> AwareDatetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("manifest freeze time must be UTC")
        return value

    @model_validator(mode="after")
    def check_seed_identity(self) -> Self:
        for seeds in (self.dev_seeds, self.heldout_seeds):
            if len(set(seeds)) != len(seeds):
                raise ValueError("duplicate session seed")
        if set(self.dev_seeds) & set(self.heldout_seeds):
            raise ValueError("dev and heldout session seeds overlap")
        return self
