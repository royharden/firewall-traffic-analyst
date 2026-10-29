"""Small hand-computed policy oracles. These are not seeded quality/eval metrics."""

from dataclasses import replace

import pytest

from firewall_analyst.domain.rules import NetworkContextV1, RulePolicyV1, ServiceV1, detect
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1

BASE_US = 1_700_000_000_000_000
MIB10 = 10_485_760


def groups(result, rule):
    return tuple(group for group in result.groups if group.rule_id == rule)


def stats(group):
    return {stat.stat_id: stat for stat in group.stats}


def channel(result, rule):
    return next(item for item in result.channels if item.rule_id == rule)


def context(kind="scanner", rule="port_scan", **updates):
    return NetworkContextV1(
        **(
            {
                "context_id": kind,
                "kind": kind,
                "rule_ids": (rule,),
                "active_from_us": 0,
                "active_until_us": BASE_US + 10_000_000_000,
                "expires_us": BASE_US + 20_000_000_000,
                "source_cidrs": ("192.0.2.0/24",),
                "destination_cidrs": ("198.51.100.0/24",),
                "protocols": ("tcp",),
            }
            | updates
        )
    )


def test_spread_scan_exact_threshold_duplicate_uid_sorted_and_union_no_double_count(row, run):
    values = [
        row(index, **{"id.resp_p": 100 + index, "id.resp_h": f"198.51.100.{index + 1}"})
        for index in range(15)
    ]
    result, parsed = run(values[::-1])
    flagged = groups(result, "port_scan")
    assert len(flagged) == 1
    group = flagged[0]
    assert group.status == "flagged" and stats(group)["distinct_ports"].value == 15
    assert stats(group)["row_count"].value == 15 and len(group.support.row_ids) == 15
    assert group.support.row_ids[0] == parsed.records[-1].row_id
    assert all(row.uid == "C12345678" for row in parsed.records)
    again = detect(parsed, as_of_us=BASE_US + 14_000_001)
    assert again == result  # Exact policies, clock, ordered support and group IDs.


def test_retry_and_normal_443_fanout_not_distinct_port_scan(row, run):
    values = [row(index, **{"id.resp_h": f"198.51.100.{index + 1}"}) for index in range(15)]
    result, _ = run(values + [values[0]] * 20)
    assert not groups(result, "port_scan") and not groups(result, "host_sweep")


@pytest.mark.parametrize("proto", ["tcp", "udp"])
def test_host_sweep_ipv6_exact_threshold_and_source_role(row, run, proto):
    values = [
        row(
            index,
            **{
                "id.orig_h": "2001:db8::1",
                "id.resp_h": f"2001:db8:1::{index + 1:x}",
                "proto": proto,
            },
        )
        for index in range(20)
    ]
    result, _ = run(values)
    assert len(groups(result, "host_sweep")) == 1 and not groups(result, "port_scan")
    assert stats(groups(result, "host_sweep")[0])["distinct_destinations"].value == 20
    reverse = [
        dict(item, **{"id.orig_h": item["id.resp_h"], "id.resp_h": item["id.orig_h"]})
        for item in values
    ]
    assert not groups(run(reverse)[0], "host_sweep")


def test_scan_below_threshold_and_slow_boundary_split(row, run):
    assert not groups(run([row(i, **{"id.resp_p": i}) for i in range(14)])[0], "port_scan")
    values = [row(i, **{"id.resp_p": i}) for i in range(7)]
    values += [row(60 + i, **{"id.resp_p": 20 + i}) for i in range(8)]
    assert not groups(run(values)[0], "port_scan")


@pytest.mark.parametrize("interval", [100, 300, 900])
def test_whole_channel_beacon_positive_median_population_cv_unknown_bytes_not_gate(
    row, run, interval
):
    result, _ = run([row(index * interval) for index in range(8)])
    (group,) = groups(result, "beaconing")
    actual = stats(group)
    assert actual["positive_intervals"].value == 7
    assert actual["interval_median_us"].value == interval * 1_000_000
    assert actual["interval_cv"].value == 0
    assert (actual["interval_cv"].known_count, actual["interval_cv"].unknown_count) == (7, 1)
    assert actual["orig_bytes_sum"].value is None and actual["orig_bytes_cv"].value is None
    assert group.status == "flagged"


@pytest.mark.parametrize(
    "times",
    [
        [0, 100, 200, 300, 400, 500, 600],  # Only seven observations.
        [0, 80, 160, 240, 320, 400, 480, 560],  # Insufficient span.
        [0, 100, 300, 400, 600, 700, 900, 1000],  # Population CV above .15.
        [0, 0, 100, 200, 300, 400, 500, 600],  # Seven records cannot manufacture seven intervals.
    ],
)
def test_beacon_insufficient_span_jitter_and_equal_time_not_promoted(row, run, times):
    assert not groups(run([row(second) for second in times])[0], "beaconing")


def test_equal_timestamp_disclosed_while_distinct_positive_intervals_remain(row, run):
    result, _ = run([row(second) for second in [0, 0, 100, 200, 300, 400, 500, 600, 700]])
    (group,) = groups(result, "beaconing")
    assert "equal_timestamps" in group.quality_flags
    assert stats(group)["equal_timestamps"].value == 1


def test_unusual_requires_known_outbound_and_both_allowlists_fail(row, run):
    result, _ = run([row()])
    assert len(groups(result, "unusual_outbound")) == 1
    no_direction, _ = run([row()], direction=False)
    assert not groups(no_direction, "unusual_outbound")
    assert channel(no_direction, "unusual_outbound").status == "not_evaluable"
    for policy in (
        RulePolicyV1(allowed_services=(ServiceV1(protocol="tcp", port=443),)),
        RulePolicyV1(allowed_destinations=("198.51.100.0/24",)),
    ):
        assert not groups(run([row()], policy=policy)[0], "unusual_outbound")
    inbound = row(**{"id.orig_h": "198.51.100.2", "id.resp_h": "192.0.2.1"})
    assert not groups(run([inbound])[0], "unusual_outbound")


def test_large_exact_threshold_null_zero_lower_bound_and_no_direction(row, run):
    result, _ = run([row(orig_bytes=MIB10)])
    (group,) = groups(result, "large_outbound")
    assert stats(group)["orig_bytes_sum"].value == MIB10
    assert group.status == "flagged" and stats(group)["row_count"].value == 1
    assert not groups(run([row(orig_bytes=MIB10 - 1)])[0], "large_outbound")
    assert not groups(run([row(orig_bytes=0)])[0], "large_outbound")
    mixed, _ = run([row(orig_bytes=MIB10), row(1)])
    (mixed_group,) = groups(mixed, "large_outbound")
    assert mixed_group.status == "partial" and "unknown_bytes" in mixed_group.quality_flags
    measured = stats(mixed_group)["orig_bytes_sum"]
    assert (measured.value, measured.known_count, measured.unknown_count) == (MIB10, 1, 1)
    unknown, _ = run([row()])
    assert channel(unknown, "large_outbound").status == "partial"
    assert "unknown_orig_bytes" in channel(unknown, "large_outbound").reason_codes
    missing, _ = run([row(orig_bytes=MIB10)], direction=False)
    assert not groups(missing, "large_outbound")


@pytest.mark.parametrize("end_state", ["SF", "S1", "S2", "S3", "RSTO"])
def test_rejection_diagnostic_strict_supported_state_and_unsupported_policy(row, run, end_state):
    result, _ = run(
        [
            row(0, conn_state="REJ"),
            row(1, conn_state="REJ"),
            row(2, conn_state="REJ"),
            row(10, conn_state=end_state),
        ]
    )
    (group,) = groups(result, "rejected_then_established")
    assert stats(group)["rejection_count"].value == 3
    assert stats(group)["established_count"].value == 1
    assert channel(result, "denied_then_allowed").status == "unsupported"
    assert channel(result, "denied_then_allowed").reason_codes == (
        "no_policy_action_in_selected_schema",
    )


@pytest.mark.parametrize("end_state", ["RSTR", "RSTOS0", "S0", "OTH", "RSTRH"])
def test_ambiguous_reset_or_no_reply_not_an_establishment(row, run, end_state):
    result, _ = run([row(i, conn_state="REJ") for i in range(3)] + [row(10, conn_state=end_state)])
    assert not groups(result, "rejected_then_established")


def test_diagnostic_exact_boundary_equal_time_reverse_order_udp_and_union(row, run):
    rejects = [row(i, conn_state="REJ") for i in range(3)]
    assert not groups(run(rejects + [row(300, conn_state="SF")])[0], "rejected_then_established")
    assert not groups(
        run([row(0, conn_state="SF")] + [row(i + 1, conn_state="REJ") for i in range(3)])[0],
        "rejected_then_established",
    )
    assert not groups(
        run([row(0, conn_state="REJ")] * 3 + [row(0, conn_state="SF")])[0],
        "rejected_then_established",
    )
    assert not groups(
        run([dict(value, proto="udp") for value in rejects + [row(10, conn_state="SF")]])[0],
        "rejected_then_established",
    )
    merged, _ = run(rejects + [row(10, conn_state="SF"), row(11, conn_state="S1")])
    (group,) = groups(merged, "rejected_then_established")
    assert stats(group)["row_count"].value == 5 and len(group.support.row_ids) == 5


def test_scanner_context_audit_all_support_no_model_or_backup_flag_removal(row, run):
    values = [row(i, **{"id.resp_p": 100 + i}) for i in range(15)]
    result, _ = run(values, contexts=(context(),))
    (group,) = groups(result, "port_scan")
    assert group.status == "suppressed" and group.matched_context_ids == ("scanner",)
    assert group in result.audit and len(group.support.row_ids) == 15
    backup = context("backup", "large_outbound")
    unchanged, _ = run(values, contexts=(backup,))
    assert groups(unchanged, "port_scan")[0].status == "flagged"
    partial_match = context(active_until_us=BASE_US + 10_000_000)
    assert groups(run(values, contexts=(partial_match,))[0], "port_scan")[0].status == "flagged"
    expired = context(expires_us=BASE_US + 10_000_000_000)
    as_of = BASE_US + 10_000_000_000
    assert (
        groups(run(values, contexts=(expired,), as_of_us=as_of)[0], "port_scan")[0].status
        == "flagged"
    )


def test_backup_suppression_audit_and_partial_match_stays_partial(row, run):
    backup = context("backup", "large_outbound")
    result, _ = run([row(orig_bytes=MIB10)], contexts=(backup,))
    (group,) = groups(result, "large_outbound")
    assert group.status == "suppressed" and group in result.audit
    values = [row(i, **{"id.resp_p": i}) for i in range(16)]
    capped, _ = run(values, limits=InputLimitsV1(max_analyzed_rows=15), contexts=(context(),))
    (group,) = groups(capped, "port_scan")
    assert (
        group.status == "partial" and group in capped.audit and "row_limit" in group.quality_flags
    )
    assert all(item.status != "complete" for item in capped.channels)


def test_bucket_output_caps_and_quarantine_mark_partial_not_clean_negative(row, run):
    values = [row(i, **{"id.resp_p": i}) for i in range(15)]
    values += [row(i, **{"id.orig_h": "192.0.2.2", "id.resp_p": i}) for i in range(15)]
    limited, _ = run(values, policy=RulePolicyV1(max_groups=1))
    assert len(limited.groups) == 1 and limited.groups[0].status == "partial"
    assert "group_or_window_limit" in limited.groups[0].quality_flags
    buckets, _ = run(values, policy=RulePolicyV1(max_window_buckets=1))
    assert channel(buckets, "port_scan").status == "partial"
    corrupt, _ = run([row(**{"id.orig_h": "bad.invalid"})])
    assert not corrupt.groups and channel(corrupt, "port_scan").status == "partial"
    assert "quarantined_input" in channel(corrupt, "port_scan").reason_codes


def test_invalid_identity_clock_or_input_state_is_not_analyzable(row, run):
    _, parsed = run([row()])
    with pytest.raises(ValueError, match="clock_before"):
        detect(parsed, as_of_us=0)
    with pytest.raises(ValueError, match="duplicate_generation"):
        detect(replace(parsed, records=parsed.records * 2), as_of_us=BASE_US + 1)
    unavailable, _ = run([row()], limits=InputLimitsV1(max_file_bytes=1))
    assert not unavailable.groups
    assert channel(unavailable, "port_scan").status == "not_evaluable"


def test_icmp_type_code_never_enters_tcp_udp_service_detectors(row, run):
    values = [
        row(
            index,
            **{
                "proto": "icmp",
                "id.orig_p": 8,
                "id.resp_p": 0,
                "id.resp_h": f"198.51.100.{index + 1}",
                "orig_bytes": MIB10,
            },
        )
        for index in range(20)
    ]
    result, parsed = run(values)
    assert len(parsed.records) == 20 and not result.groups
    assert all(event.icmp_type == 8 and event.dst_port is None for event in parsed.records)
