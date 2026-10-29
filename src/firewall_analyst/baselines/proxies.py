"""Fixed, scope-labelled comparison observations; not an evaluation/metric runner.

Requires a complete validated parsed snapshot. The publishing caller must separately
revalidate its original source generation. No files, labels, models or networks are
read here. These proxies omit contexts and do not implement the referenced products.
"""

import hashlib
import json
import statistics
from collections import OrderedDict
from dataclasses import dataclass

from ..domain.parsers import ZeekFileResult
from ..shared.rulesengine.aggregate import measured_stat, support_for
from ..shared.rulesengine.rules import identified_group
from ..shared.rulesengine.schemas import FlaggedGroupV1, KeyPart, TimeWindow

CV_MIN_OBSERVATIONS = 8
CV_MIN_INTERVALS = 7
CV_MIN_SPAN_US = 600_000_000
CV_MIN_MEDIAN_US = 5_000_000
CV_MAX = 0.15
BUCKET_CAPACITY = 15
LEAK_US = 5_000_000


@dataclass(frozen=True)
class ProxyRun:
    method_id: str
    applicable_patterns: tuple[str, ...]
    config_sha256: str
    groups: tuple[FlaggedGroupV1, ...]
    context_policy: str = "none"
    interpretation: str = "public_design_proxy_not_actual_product"


def _digest(method, max_groups):
    parameters = {
        "method": method,
        "version": "public-proxy-1",
        "transport": ["tcp", "udp"],
        "context_policy": "none",
        "complete_parse_required": True,
        "max_groups": max_groups,
    }
    if method == "interval_cv_proxy":
        parameters.update(
            series_key=["src", "protocol", "dst_port", "dst"],
            series_scope="whole_input_positive_intervals_equal_timestamps_omitted",
            min_observations=CV_MIN_OBSERVATIONS,
            min_positive_intervals=CV_MIN_INTERVALS,
            min_span_us=CV_MIN_SPAN_US,
            min_median_us=CV_MIN_MEDIAN_US,
            max_population_cv=CV_MAX,
        )
    else:
        parameters.update(
            series_key=["src", "protocol"],
            support_policy="active_port_introducers_at_overflow_overlap_union",
            capacity=BUCKET_CAPACITY,
            leak_us=LEAK_US,
            eviction="fifo_before_event",
            anchor="first_event_persists_through_idle",
            repeat="no_refill_no_refresh",
        )
    return hashlib.sha256(
        json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _records(parsed: ZeekFileResult, max_groups):
    if type(max_groups) is not int or not 1 <= max_groups <= 10_000:
        raise ValueError("proxy_group_limit")
    summary = parsed.summary
    if (
        summary.state != "complete"
        or summary.source_sha256 is None
        or parsed.evidence is None
        or summary.quarantined_rows != 0
        or summary.excluded_rows != 0
        or summary.processed_rows != len(parsed.records)
        or summary.original_rows != len(parsed.records)
        or len(parsed.records) > 250_000
    ):
        raise ValueError("incomplete_proxy_input")
    if parsed.evidence.source_sha256 != summary.source_sha256:
        raise ValueError("mixed_proxy_generation")
    if len({row.row_id for row in parsed.records}) != len(parsed.records) or any(
        row.input_sha256 != summary.source_sha256 for row in parsed.records
    ):
        raise ValueError("mixed_or_duplicate_proxy_generation")
    if any(set(row.quality_flags) & {"capture_loss", "incomplete"} for row in parsed.records):
        raise ValueError("incomplete_proxy_input")
    return tuple(
        sorted(
            (row for row in parsed.records if row.protocol in {"tcp", "udp"}),
            key=lambda row: (row.ts_us, row.raw_line_number),
        )
    )


def _group(rows, *, rule, key, config_sha, extra_stats=()):
    rows = tuple(sorted(rows, key=lambda row: (row.ts_us, row.raw_line_number)))
    support = support_for(rows, source_sha256=rows[0].input_sha256, row_id=lambda row: row.row_id)
    stats = [measured_stat("row_count", len(rows), "count", support, len(rows))]
    for name, value, unit, known in extra_stats:
        stats.append(measured_stat(name, value, unit, support, known))
    return identified_group(
        rule_id=rule,
        rule_version="public-proxy-1",
        config_sha256=config_sha,
        window=TimeWindow(start_us=rows[0].ts_us, end_us=rows[-1].ts_us + 1),
        grouping_key=key,
        support=support,
        stats=tuple(stats),
        category_from_rule=rule,
        severity_from_rule=2 if rule == "beaconing" else 3,
    )


def interval_cv_proxy(parsed: ZeekFileResult, *, max_groups: int = 10_000) -> ProxyRun:
    """Whole-source directional flow series; positive intervals only, no byte feature."""
    rows = _records(parsed, max_groups)
    config_sha = _digest("interval_cv_proxy", max_groups)
    flows = {}
    for row in rows:
        key = str(row.src), row.protocol, row.dst_port, str(row.dst)
        flows.setdefault(key, []).append(row)
    groups = []
    for (src, protocol, port, dst), values in sorted(flows.items()):
        times = [row.ts_us for row in values]
        intervals = [b - a for a, b in zip(times, times[1:], strict=False) if b > a]
        if len(values) < CV_MIN_OBSERVATIONS or len(intervals) < CV_MIN_INTERVALS:
            continue
        mean = statistics.fmean(intervals)
        cv = statistics.pstdev(intervals) / mean
        if (
            times[-1] - times[0] < CV_MIN_SPAN_US
            or statistics.median(intervals) < CV_MIN_MEDIAN_US
            or cv > CV_MAX
        ):
            continue
        groups.append(
            _group(
                values,
                rule="beaconing",
                config_sha=config_sha,
                key=(
                    KeyPart(name="src", value=src),
                    KeyPart(name="protocol", value=protocol),
                    KeyPart(name="dst_port", value=port),
                    KeyPart(name="dst", value=dst),
                ),
                extra_stats=(
                    ("interval_cv", cv, "ratio", len(intervals)),
                    ("span_us", times[-1] - times[0], "microseconds", len(values)),
                ),
            )
        )
        if len(groups) > max_groups:
            raise ValueError("proxy_group_limit")
    return ProxyRun("interval_cv_proxy", ("beaconing",), config_sha, tuple(groups))


def distinct_port_bucket_proxy(parsed: ZeekFileResult, *, max_groups: int = 10_000) -> ProxyRun:
    """Source/protocol FIFO distinct-port bucket, capacity15, one leak each5s.

    Overlapping overflow windows merge online with union causal introducer rows.
    Repeats never refill, refresh age, extend an incident or become new support.
    Pending introductions are retained only while active; a burst does not copy its
    growing whole bucket on every event. Updates/support union are linear in rows.
    """
    rows = _records(parsed, max_groups)
    config_sha = _digest("distinct_port_bucket_proxy", max_groups)
    sources = {}
    for row in rows:
        sources.setdefault((str(row.src), row.protocol), []).append(row)
    groups = []
    for (src, protocol), values in sorted(sources.items()):
        active, pending = OrderedDict(), {}
        next_leak = values[0].ts_us + LEAK_US
        incident, incident_end = None, None

        def emit(support, *, source=src, transport=protocol):
            groups.append(
                _group(
                    tuple(support.values()),
                    rule="port_scan",
                    config_sha=config_sha,
                    key=(
                        KeyPart(name="src", value=source),
                        KeyPart(name="protocol", value=transport),
                    ),
                    extra_stats=(
                        (
                            "distinct_ports",
                            len({r.dst_port for r in support.values()}),
                            "count",
                            len(support),
                        ),
                    ),
                )
            )
            if len(groups) > max_groups:
                raise ValueError("proxy_group_limit")

        for row in values:
            if row.ts_us >= next_leak:
                due = (row.ts_us - next_leak) // LEAK_US + 1
                for _ in range(min(due, len(active))):
                    removed, _ = active.popitem(last=False)
                    pending.pop(removed, None)
                next_leak += due * LEAK_US
            if row.dst_port in active:
                continue
            active[row.dst_port] = row
            pending[row.dst_port] = row
            if len(active) <= BUCKET_CAPACITY:
                continue
            earliest = next(iter(active.values())).ts_us
            if incident is None or earliest >= incident_end:
                if incident is not None:
                    emit(incident)
                incident = {r.row_id: r for r in active.values()}
            else:
                incident.update((r.row_id, r) for r in pending.values())
            incident_end = row.ts_us + 1
            pending.clear()
        if incident is not None:
            emit(incident)
    return ProxyRun("distinct_port_bucket_proxy", ("port_scan",), config_sha, tuple(groups))
