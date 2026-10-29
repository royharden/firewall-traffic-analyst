"""New source-observed method policy, never a recovered constructor clock.

The caller supplies a trusted parsed snapshot and explicitly loaded public profile.
No file, wall clock, label, split, constructor or method output is consulted here.
Current source revalidation and exact profile-byte pinning belong to the controller.
"""

import hashlib
import json
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Annotated, Literal

from pydantic import Field

from ...shared.rulesengine.rows import GenerationRows
from ...shared.rulesengine.schemas import BoundaryModel, ParseSummaryV1, Sha256
from ..parsers import ZeekFileResult
from ..rules.policy import NetworkContextV1, RulePolicyV1, ServiceV1
from ..schemas import EventV1

MAX_TIME_US = (1 << 63) - 1


class ContextSelector(BoundaryModel):
    context_id: str
    kind: Literal["scanner", "backup", "health_check"]
    rule_ids: tuple[str, ...]
    source_cidrs: tuple[str, ...]
    destination_cidrs: tuple[str, ...]
    protocols: tuple[Literal["tcp", "udp"], ...]
    destination_ports: tuple[int, ...]


class PublicEvaluationProfile(BoundaryModel):
    schema_version: Literal[1] = 1
    profile_version: Literal["s8-public-evaluation-1"]
    source_setup_sha256: Sha256
    clock_policy: Literal["maximum_observed_event_us"]
    context_period_policy: Literal["observed_min_to_max_plus_one_us"]
    internal_cidrs: Annotated[tuple[str, ...], Field(min_length=1, max_length=256)]
    allowed_destinations: tuple[str, ...]
    allowed_services: tuple[ServiceV1, ...]
    contexts: Annotated[tuple[ContextSelector, ...], Field(max_length=256)]


@dataclass(frozen=True)
class EvaluationSettings:
    profile_sha256: str
    as_of_us: int
    internal_cidrs: tuple[str, ...]
    policy: RulePolicyV1
    contexts: tuple[NetworkContextV1, ...]
    observed_rows: int


def complete_records(parsed: ZeekFileResult) -> tuple[EventV1, ...]:
    """Validate snapshot consistency, not source authenticity or present-day bytes."""
    if type(parsed) is not ZeekFileResult:
        raise ValueError("trusted_complete_source_required")
    if (
        type(parsed.records) is not tuple
        or type(parsed.issues) is not tuple
        or type(parsed.summary) is not ParseSummaryV1
    ):
        raise ValueError("typed_complete_evaluation_source_required")
    summary = parsed.summary
    ParseSummaryV1.model_validate(summary.model_dump())
    if (
        summary.state != "complete"
        or summary.source_sha256 is None
        or type(parsed.evidence) is not GenerationRows
        or parsed.evidence.source_sha256 != summary.source_sha256
        or type(parsed.size_bytes) is not int
        or type(parsed.evidence.size_bytes) is not int
        or parsed.size_bytes < 0
        or parsed.size_bytes != parsed.evidence.size_bytes
        or summary.quarantined_rows != 0
        or summary.excluded_rows != 0
        or summary.original_rows != len(parsed.records)
        or summary.processed_rows != len(parsed.records)
        or parsed.issues
        or len(parsed.records) > 250_000
    ):
        raise ValueError("incomplete_evaluation_source")
    seen = set()
    for event in parsed.records:
        if type(event) is not EventV1:
            raise ValueError("invalid_evaluation_event")
        EventV1.model_validate(event.model_dump())
        if (
            event.input_sha256 != summary.source_sha256
            or event.row_id in seen
            or event.ts_us > MAX_TIME_US
            or set(event.quality_flags) & {"capture_loss", "incomplete"}
        ):
            raise ValueError("incomplete_or_mixed_evaluation_source")
        seen.add(event.row_id)
    return parsed.records


def public_settings(parsed: ZeekFileResult, profile: PublicEvaluationProfile) -> EvaluationSettings:
    """Derive a finite, explicitly named policy from public source observations.

    profile_sha256 hashes canonical typed profile content; controllers must also pin
    the original profile bytes separately. It is not a byte hash or authorization.
    The runtime baseline file is never read or overwritten.
    """
    if type(profile) is not PublicEvaluationProfile:
        raise ValueError("typed_public_profile_required")
    profile = PublicEvaluationProfile.model_validate(profile.model_dump())
    rows = complete_records(parsed)
    as_of = max((row.ts_us for row in rows), default=0)
    if rows and as_of == MAX_TIME_US:
        raise ValueError("context_endpoint_overflow")
    start = min((row.ts_us for row in rows), default=0)
    # Validate selectors even for an empty source; no silent malformed profile.
    templates = tuple(
        NetworkContextV1(
            **selector.model_dump(),
            active_from_us=start,
            active_until_us=as_of + 1,
            expires_us=as_of + 1,
        )
        for selector in profile.contexts
    )
    if len({context.context_id for context in templates}) != len(templates):
        raise ValueError("duplicate_context_identity")
    policy = RulePolicyV1(
        allowed_destinations=profile.allowed_destinations,
        allowed_services=profile.allowed_services,
    )
    networks = tuple(ip_network(cidr, strict=True) for cidr in profile.internal_cidrs)
    if parsed.direction_status != "evaluable":
        raise ValueError("public_internal_direction_required")
    for row in rows:
        src_internal = any(row.src in network for network in networks)
        dst_internal = any(row.dst in network for network in networks)
        expected = (
            "internal"
            if src_internal and dst_internal
            else "outbound"
            if src_internal
            else "inbound"
            if dst_internal
            else "external"
        )
        if row.direction != expected:
            raise ValueError("public_internal_direction_mismatch")
    digest = hashlib.sha256(
        json.dumps(profile.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return EvaluationSettings(
        digest, as_of, profile.internal_cidrs, policy, templates if rows else (), len(rows)
    )
