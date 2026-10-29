"""Deterministic Zeek observations; flags and audited suppressions, not attack proof."""

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Literal

from ...shared.rulesengine.aggregate import (
    byte_cv_stat,
    interval_stats,
    measured_stat,
    sum_stat,
    support_for,
)
from ...shared.rulesengine.rules import Candidate, identified_group, merge_candidates
from ...shared.rulesengine.schemas import BoundaryModel, FlaggedGroupV1, KeyPart, TimeWindow, Token
from ...shared.rulesengine.windows import ordered, sliding_windows
from ..parsers import ZeekFileResult
from ..schemas import EventV1
from .policy import NetworkContextV1, RulePolicyV1

RULES = (
    "port_scan",
    "host_sweep",
    "beaconing",
    "unusual_outbound",
    "large_outbound",
    "rejected_then_established",
)
ESTABLISHED = {"SF", "S1", "S2", "S3", "RSTO"}
SEVERITY = {
    "port_scan": 3,
    "host_sweep": 3,
    "beaconing": 2,
    "unusual_outbound": 2,
    "large_outbound": 3,
    "rejected_then_established": 2,
}


class RuleChannelV1(BoundaryModel):
    rule_id: Token
    status: Literal["complete", "partial", "not_evaluable", "unsupported"]
    reason_codes: tuple[Token, ...] = ()


@dataclass(frozen=True)
class RuleRun:
    groups: tuple[FlaggedGroupV1, ...]
    channels: tuple[RuleChannelV1, ...]
    config_sha256: str

    @property
    def audit(self) -> tuple[FlaggedGroupV1, ...]:
        return tuple(group for group in self.groups if group.matched_context_ids)


def _time(row: EventV1) -> int:
    return row.ts_us


def _line(row: EventV1) -> int:
    return row.raw_line_number


def _diagnostics(values, key, policy):
    """One linear pass per channel; do not rescan every preceding TCP event."""
    pending = deque()
    new_rejects = deque()
    last_reject_ts, same_rejects = -1, 0
    incident = None
    result = []
    for row in values:
        while pending and row.ts_us - pending[0].ts_us >= policy.diagnostic_window_us:
            pending.popleft()
        if row.protocol != "tcp":
            continue
        if row.conn_state == "REJ":
            pending.append(row)
            new_rejects.append(row)
            same_rejects = same_rejects + 1 if row.ts_us == last_reject_ts else 1
            last_reject_ts = row.ts_us
            continue
        if row.conn_state not in ESTABLISHED:
            continue
        # Same-timestamp rows cannot prove a strict temporal transition.
        eligible = len(pending) - (same_rejects if last_reject_ts == row.ts_us else 0)
        if eligible < policy.diagnostic_min_rejections:
            continue
        start = pending[0].ts_us
        end = start + policy.diagnostic_window_us
        if incident is None or start >= incident[1]:
            if incident is not None:
                result.append(incident)
            incident = [
                start,
                end,
                {item.row_id: item for item in pending if item.ts_us < row.ts_us},
            ]
        else:
            incident[1] = max(incident[1], end)
        # Drain each new rejection once; same-timestamp rejects await a later event.
        while new_rejects and new_rejects[0].ts_us < row.ts_us:
            item = new_rejects.popleft()
            if row.ts_us - item.ts_us < policy.diagnostic_window_us:
                incident[2][item.row_id] = item
        incident[2][row.row_id] = row
    if incident is not None:
        result.append(incident)
    return tuple(
        Candidate(
            "rejected_then_established",
            key,
            TimeWindow(start_us=start, end_us=end),
            tuple(sorted(items.values(), key=lambda item: (item.ts_us, item.raw_line_number))),
        )
        for start, end, items in result
    )


def _key(row: EventV1, kind: str) -> tuple[KeyPart, ...]:
    parts = [KeyPart(name="src", value=str(row.src)), KeyPart(name="protocol", value=row.protocol)]
    if kind != "port_scan":
        parts.append(KeyPart(name="dst_port", value=row.dst_port))
    if kind not in {"port_scan", "host_sweep"}:
        parts.append(KeyPart(name="dst", value=str(row.dst)))
    return tuple(parts)


def _group_stats(candidate: Candidate[EventV1], digest: str):
    rows = candidate.rows
    support = support_for(rows, source_sha256=digest, row_id=lambda row: row.row_id)
    stats = [
        measured_stat("row_count", len(rows), "count", support, len(rows)),
        measured_stat(
            "distinct_destinations", len({row.dst for row in rows}), "count", support, len(rows)
        ),
        measured_stat(
            "distinct_ports", len({row.dst_port for row in rows}), "count", support, len(rows)
        ),
        sum_stat(
            rows,
            getter=lambda row: row.orig_bytes,
            support=support,
            stat_id="orig_bytes_sum",
            unit="bytes",
        ),
        sum_stat(
            rows,
            getter=lambda row: row.resp_bytes,
            support=support,
            stat_id="resp_bytes_sum",
            unit="bytes",
        ),
        sum_stat(
            rows,
            getter=lambda row: row.duration_us,
            support=support,
            stat_id="duration_sum_us",
            unit="microseconds",
        ),
        *interval_stats(rows, timestamp=_time, support=support),
        byte_cv_stat(rows, getter=lambda row: row.orig_bytes, support=support),
    ]
    if candidate.rule_id == "rejected_then_established":
        stats.extend(
            (
                measured_stat(
                    "rejection_count",
                    sum(row.conn_state == "REJ" for row in rows),
                    "count",
                    support,
                    len(rows),
                ),
                measured_stat(
                    "established_count",
                    sum(row.conn_state in ESTABLISHED for row in rows),
                    "count",
                    support,
                    len(rows),
                ),
            )
        )
    return support, tuple(stats)


def detect(
    parsed: ZeekFileResult,
    *,
    as_of_us: int,
    policy: RulePolicyV1 | None = None,
    contexts: tuple[NetworkContextV1, ...] = (),
) -> RuleRun:
    if type(as_of_us) is not int or as_of_us < 0:
        raise ValueError("explicit_nonnegative_context_clock_required")
    if len(contexts) > 256 or len({item.context_id for item in contexts}) != len(contexts):
        raise ValueError("invalid_context_inventory")
    policy = policy or RulePolicyV1()
    body = {
        "policy": policy.model_dump(mode="json"),
        "as_of_us": as_of_us,
        "contexts": [
            item.model_dump(mode="json") for item in sorted(contexts, key=lambda x: x.context_id)
        ],
    }
    config_sha = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    digest = parsed.summary.source_sha256
    rows = ordered(parsed.records, timestamp=_time, tie=_line)
    if rows and as_of_us < rows[-1].ts_us:
        raise ValueError("context_clock_before_observations")
    if len({row.row_id for row in rows}) != len(rows) or any(
        row.input_sha256 != digest for row in rows
    ):
        raise ValueError("mixed_or_duplicate_generation")
    reasons = list(parsed.summary.reason_codes)
    incomplete = parsed.summary.state != "complete"
    if parsed.summary.quarantined_rows:
        reasons.append("quarantined_input")
        incomplete = True
    capture_reasons = tuple(
        flag
        for flag in ("capture_loss", "incomplete")
        if any(flag in row.quality_flags for row in rows)
    )
    if capture_reasons:
        reasons.extend(capture_reasons)
        incomplete = True
    usable = digest is not None and parsed.summary.state in {"complete", "partial"}
    transport = tuple(row for row in rows if row.protocol in {"tcp", "udp"}) if usable else ()
    candidates = []
    limited = False

    for rule in ("port_scan", "host_sweep", "large_outbound"):
        subset = (
            transport
            if rule != "large_outbound"
            else tuple(
                row
                for row in transport
                if row.direction == "outbound" and parsed.direction_status == "evaluable"
            )
        )
        batch = sliding_windows(
            subset,
            timestamp=_time,
            tie=_line,
            key=lambda row: _key(row, rule),
            width_us=policy.large_window_us if rule == "large_outbound" else policy.scan_window_us,
            stride_us=policy.large_stride_us if rule == "large_outbound" else policy.scan_stride_us,
            max_buckets=policy.max_window_buckets,
        )
        limited |= not batch.complete
        for bucket in batch.buckets:
            hit = (
                len({row.dst_port for row in bucket.rows}) >= policy.port_scan_min_ports
                if rule == "port_scan"
                else len({row.dst for row in bucket.rows}) >= policy.host_sweep_min_destinations
                if rule == "host_sweep"
                else sum(row.orig_bytes or 0 for row in bucket.rows) >= policy.large_min_orig_bytes
            )
            if hit:
                candidates.append(Candidate(rule, bucket.key, bucket.window, bucket.rows))

    channels: dict[tuple[KeyPart, ...], list[EventV1]] = {}
    for row in transport:
        key = _key(row, "channel")
        if key not in channels and len(channels) == policy.max_window_buckets:
            limited = True
            break
        channels.setdefault(key, []).append(row)
    allowed_networks = tuple(ip_network(cidr) for cidr in policy.allowed_destinations)
    allowed_services = {(service.protocol, service.port) for service in policy.allowed_services}
    for key, values in channels.items():
        support = support_for(values, source_sha256=digest, row_id=lambda row: row.row_id)
        stats = {
            stat.stat_id: stat for stat in interval_stats(values, timestamp=_time, support=support)
        }
        span = TimeWindow(start_us=values[0].ts_us, end_us=values[-1].ts_us + 1)
        if (
            len(values) >= policy.beacon_min_observations
            and stats["positive_intervals"].value >= policy.beacon_min_observations - 1
            and stats["span_us"].value >= policy.beacon_min_span_us
            and stats["interval_median_us"].value is not None
            and stats["interval_median_us"].value >= policy.beacon_min_median_us
            and stats["interval_cv"].value <= policy.beacon_max_interval_cv
        ):
            candidates.append(Candidate("beaconing", key, span, tuple(values)))
        unusual = tuple(
            row
            for row in values
            if row.direction == "outbound"
            and not any(row.dst in network for network in allowed_networks)
            and (row.protocol, row.dst_port) not in allowed_services
        )
        if unusual and parsed.direction_status == "evaluable":
            candidates.append(Candidate("unusual_outbound", key, span, unusual))
        candidates.extend(_diagnostics(values, key, policy))
    merged = merge_candidates(candidates, row_id=lambda row: row.row_id, timestamp=_time, tie=_line)
    if len(merged) > policy.max_groups:
        limited = True
        merged = merged[: policy.max_groups]
    if limited:
        incomplete = True
        reasons.append("group_or_window_limit")
    groups = []
    for candidate in merged:
        support, stats = _group_stats(candidate, digest)
        matched = tuple(
            sorted(
                context.context_id
                for context in contexts
                if all(
                    context.matches(row, rule_id=candidate.rule_id, as_of_us=as_of_us)
                    for row in candidate.rows
                )
            )
        )
        quality = list(dict.fromkeys(reasons)) if incomplete else []
        if any(stat.stat_id == "equal_timestamps" and stat.value for stat in stats):
            quality.append("equal_timestamps")
        if candidate.rule_id == "large_outbound" and any(
            row.orig_bytes is None for row in candidate.rows
        ):
            quality.append("unknown_bytes")
        partial = incomplete or "unknown_bytes" in quality
        groups.append(
            identified_group(
                rule_id=candidate.rule_id,
                rule_version="initial-1",
                config_sha256=config_sha,
                window=candidate.window,
                grouping_key=candidate.key,
                support=support,
                stats=stats,
                category_from_rule=candidate.rule_id,
                severity_from_rule=SEVERITY[candidate.rule_id],
                status="partial" if partial else "suppressed" if matched else "flagged",
                matched_context_ids=matched,
                quality_flags=tuple(dict.fromkeys(quality)),
            )
        )
    channel_status = []
    for rule in RULES:
        reason = tuple(dict.fromkeys(reasons))
        status = "partial" if incomplete else "complete"
        if not usable:
            status, reason = "not_evaluable", ("input_not_evaluable",)
        elif (
            rule in {"unusual_outbound", "large_outbound"}
            and parsed.direction_status != "evaluable"
        ):
            status, reason = "not_evaluable", ("direction_not_evaluable",)
        elif rule == "large_outbound" and any(
            row.direction == "outbound" and row.orig_bytes is None for row in transport
        ):
            status, reason = "partial", (*reason, "unknown_orig_bytes")
        elif rule == "beaconing" and any(
            len(values) < policy.beacon_min_observations for values in channels.values()
        ):
            reason = (*reason, "insufficient_observations_in_some_channels")
        channel_status.append(RuleChannelV1(rule_id=rule, status=status, reason_codes=reason))
    channel_status.append(
        RuleChannelV1(
            rule_id="denied_then_allowed",
            status="unsupported",
            reason_codes=("no_policy_action_in_selected_schema",),
        )
    )
    return RuleRun(tuple(groups), tuple(channel_status), config_sha)
