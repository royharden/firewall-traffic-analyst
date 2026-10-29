"""Versioned starting policies and explicit, rule-specific local context."""

from ipaddress import ip_network
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from ...shared.rulesengine.context import ContextV1
from ...shared.rulesengine.schemas import BoundaryModel
from ..schemas import EventV1

Port = Annotated[int, Field(ge=0, le=65535)]


class ServiceV1(BoundaryModel):
    protocol: Literal["tcp", "udp"]
    port: Port


class RulePolicyV1(BoundaryModel):
    schema_version: Literal[1] = 1
    policy_version: Literal["initial-1"] = "initial-1"
    split_method: Literal["independent_session_seed"] = "independent_session_seed"
    scan_window_us: Literal[60_000_000] = 60_000_000
    scan_stride_us: Literal[30_000_000] = 30_000_000
    port_scan_min_ports: Literal[15] = 15
    host_sweep_min_destinations: Literal[20] = 20
    beacon_min_observations: Literal[8] = 8
    beacon_min_span_us: Literal[600_000_000] = 600_000_000
    beacon_min_median_us: Literal[5_000_000] = 5_000_000
    beacon_max_interval_cv: Annotated[float, Field(ge=0, le=1)] = 0.15
    large_window_us: Literal[300_000_000] = 300_000_000
    large_stride_us: Literal[150_000_000] = 150_000_000
    large_min_orig_bytes: Literal[10_485_760] = 10_485_760
    diagnostic_window_us: Literal[300_000_000] = 300_000_000
    diagnostic_min_rejections: Literal[3] = 3
    allowed_destinations: Annotated[tuple[str, ...], Field(max_length=256)] = ()
    allowed_services: Annotated[tuple[ServiceV1, ...], Field(max_length=256)] = ()
    max_window_buckets: Annotated[int, Field(gt=0, le=10_000)] = 10_000
    max_groups: Annotated[int, Field(gt=0, le=10_000)] = 10_000

    @field_validator("beacon_max_interval_cv")
    @classmethod
    def fixed_starting_cv(cls, value: float) -> float:
        if value != 0.15:
            raise ValueError("starting_policy_locked_before_gold")
        return value

    @field_validator("allowed_destinations")
    @classmethod
    def cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for cidr in value:
            ip_network(cidr, strict=True)
        if len(set(value)) != len(value):
            raise ValueError("duplicate_cidr")
        return value


KIND_RULES = {
    "scanner": {"port_scan", "host_sweep"},
    "monitor": {"host_sweep"},
    "health_check": {"beaconing"},
    "backup": {"large_outbound"},
    "approved_peer": {"unusual_outbound"},
    "maintenance": {"rejected_then_established"},
}


class NetworkContextV1(ContextV1):
    kind: Literal["scanner", "monitor", "health_check", "backup", "approved_peer", "maintenance"]
    source_cidrs: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    destination_cidrs: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    protocols: Annotated[
        tuple[Literal["tcp", "udp", "icmp"], ...], Field(min_length=1, max_length=3)
    ]
    destination_ports: Annotated[tuple[Port, ...], Field(max_length=256)] = ()

    @field_validator("source_cidrs", "destination_cidrs")
    @classmethod
    def cidrs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for cidr in value:
            ip_network(cidr, strict=True)
        return value

    @model_validator(mode="after")
    def kind_scope(self) -> Self:
        if not set(self.rule_ids) <= KIND_RULES[self.kind]:
            raise ValueError("context_kind_cannot_suppress_rule")
        if len(set(self.protocols)) != len(self.protocols):
            raise ValueError("duplicate_protocol")
        return self

    def matches(self, event: EventV1, *, rule_id: str, as_of_us: int) -> bool:
        return (
            rule_id in self.rule_ids
            and self.matches_time(event.ts_us, as_of_us=as_of_us)
            and event.protocol in self.protocols
            and any(event.src in ip_network(cidr) for cidr in self.source_cidrs)
            and any(event.dst in ip_network(cidr) for cidr in self.destination_cidrs)
            and (not self.destination_ports or event.dst_port in self.destination_ports)
        )
