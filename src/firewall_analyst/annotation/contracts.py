"""S8 closed computed projection; wire/answers/identity/accounting belong to canonical S3."""

import json

from ..shared.rulesengine.schemas import FlaggedGroupV1

CATEGORIES = (
    "port_scan",
    "host_sweep",
    "beaconing",
    "unusual_outbound",
    "large_outbound",
    "rejected_then_established",
    "benign",
    "unclear",
)
UNITS = {
    "row_count": "count",
    "distinct_ports": "count",
    "distinct_destinations": "count",
    "orig_bytes_sum": "bytes",
    "resp_bytes_sum": "bytes",
    "duration_sum_us": "microseconds",
    "span_us": "microseconds",
    "positive_intervals": "count",
    "equal_timestamps": "count",
    "interval_median_us": "microseconds",
    "interval_cv": "ratio",
    "orig_bytes_cv": "ratio",
    "rejection_count": "count",
    "established_count": "count",
}
TRIAGE = ("routine", "review", "priority", "urgent")


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def project(group: FlaggedGroupV1) -> bytes:
    """Closed computed state only; never endpoints, source lines or private labels."""
    if group.rule_id not in CATEGORIES[:6]:
        raise ValueError("unsupported_rule")
    statistics = []
    for stat in group.stats:
        if UNITS.get(stat.stat_id) != stat.unit:
            raise ValueError("projection_field")
        statistics.append(
            {
                "stat_id": stat.stat_id,
                "value": stat.value,
                "unit": stat.unit,
                "known_count": stat.known_count,
                "unknown_count": stat.unknown_count,
            }
        )
    state = canonical(
        {
            "rule_id": group.rule_id,
            "status": group.status,
            "deterministic_severity": group.severity_from_rule,
            "context_matched": bool(group.matched_context_ids),
            "statistics": statistics,
        }
    )
    if len(state) > 8192:
        raise ValueError("projection_limit")
    return state
