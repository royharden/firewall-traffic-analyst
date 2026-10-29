"""Typed finite UTC context schedules; selectors and kind policy belong to consumers."""

from typing import Annotated, Self

from pydantic import Field, model_validator

from .schemas import BoundaryModel, Count, Token


class UtcSchedule(BoundaryModel):
    weekdays: Annotated[
        tuple[Annotated[int, Field(ge=0, le=6)], ...], Field(min_length=1, max_length=7)
    ]
    start_minute: Annotated[int, Field(ge=0, lt=1440)]
    end_minute: Annotated[int, Field(gt=0, le=1440)]

    @model_validator(mode="after")
    def check_range(self) -> Self:
        if self.start_minute >= self.end_minute or len(set(self.weekdays)) != len(self.weekdays):
            raise ValueError("invalid_schedule")
        return self

    def matches(self, ts_us: int) -> bool:
        day, offset = divmod(ts_us, 86_400_000_000)
        return (
            day + 3
        ) % 7 in self.weekdays and self.start_minute <= offset // 60_000_000 < self.end_minute


class ContextV1(BoundaryModel):
    context_id: Token
    kind: Token
    rule_ids: Annotated[tuple[Token, ...], Field(min_length=1, max_length=16)]
    active_from_us: Count
    active_until_us: Count
    expires_us: Count
    schedules: Annotated[tuple[UtcSchedule, ...], Field(max_length=16)] = ()

    @model_validator(mode="after")
    def check_range(self) -> Self:
        if not self.active_from_us < self.active_until_us <= self.expires_us:
            raise ValueError("invalid_context_period")
        if len(set(self.rule_ids)) != len(self.rule_ids):
            raise ValueError("duplicate_rule")
        return self

    def matches_time(self, ts_us: int, *, as_of_us: int) -> bool:
        if type(as_of_us) is not int or as_of_us < 0 or type(ts_us) is not int or ts_us < 0:
            raise ValueError("invalid_context_clock")
        return (
            as_of_us < self.expires_us
            and self.active_from_us <= ts_us < self.active_until_us
            and (not self.schedules or any(schedule.matches(ts_us) for schedule in self.schedules))
        )
