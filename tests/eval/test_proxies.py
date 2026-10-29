"""Independent public hand sources; proxy mechanics, not product/corpus quality."""

import json
from dataclasses import replace

import pytest

from firewall_analyst.baselines.proxies import distinct_port_bucket_proxy, interval_cv_proxy
from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1


def parsed(tmp_path, times, *, ports=None, mutate=None, limits=None, suffix=b""):
    records = []
    for index, time in enumerate(times):
        row = {
            "ts": time,
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 40000,
            "id.resp_h": "198.51.100.1",
            "id.resp_p": ports[index] if ports else 443,
            "proto": "tcp",
        }
        if mutate:
            mutate(row, index)
        records.append(json.dumps(row).encode())
    path = tmp_path / "own-proxy.jsonl"
    path.write_bytes(b"\n".join(records) + b"\n" + suffix)
    return parse_zeek_file(path, limits=limits)


def test_cv_regular_positive_intervals_and_fraction_scope_without_direction(tmp_path):
    data = parsed(tmp_path, [0, 0, 90, 180, 270, 360, 450, 540, 630])
    run = interval_cv_proxy(data)
    assert run.method_id == "interval_cv_proxy" and run.applicable_patterns == ("beaconing",)
    assert run.context_policy == "none" and len(run.groups) == 1
    group = run.groups[0]
    assert len(group.support.row_ids) == 9 and group.severity_from_rule == 2
    stat = next(s for s in group.stats if s.stat_id == "interval_cv")
    assert stat.value == 0 and stat.known_count == 7 and stat.unknown_count == 2
    assert group.window.start_us == 0 and group.window.end_us == 630_000_001
    assert data.direction_status == "not_evaluable"  # Proxy does not invent outbound scope.


@pytest.mark.parametrize(
    "times",
    [
        [0, 100, 200, 300, 400, 500, 600],
        [0] * 8,
        [0, 10, 20, 40, 100, 500, 630, 1000],
        [0, 1, 2, 3, 4, 5, 6, 7],
    ],
)
def test_cv_insufficient_equal_irregular_or_too_short_not_flagged(tmp_path, times):
    assert interval_cv_proxy(parsed(tmp_path, times)).groups == ()


def test_cv_flow_key_and_sorting_are_directional_and_exact(tmp_path):
    data = parsed(tmp_path, list(reversed([i * 90 for i in range(8)])))
    assert len(interval_cv_proxy(data).groups) == 1
    data = parsed(
        tmp_path,
        [i * 90 for i in range(8)],
        mutate=lambda row, i: row.update({"id.resp_h": f"198.51.100.{i % 2 + 1}"}),
    )
    assert interval_cv_proxy(data).groups == ()


def test_bucket_threshold_repeats_never_refill_or_refresh(tmp_path):
    assert (
        distinct_port_bucket_proxy(parsed(tmp_path, [0] * 15, ports=list(range(15)))).groups == ()
    )
    run = distinct_port_bucket_proxy(parsed(tmp_path, [0] * 16, ports=list(range(16))))
    assert len(run.groups) == 1
    group = run.groups[0]
    assert len(group.support.row_ids) == 16 and group.rule_id == "port_scan"
    assert next(s.value for s in group.stats if s.stat_id == "distinct_ports") == 16
    data = parsed(tmp_path, [0] * 15 + [1] * 100, ports=list(range(15)) + [14] * 100)
    assert distinct_port_bucket_proxy(data).groups == ()
    data = parsed(tmp_path, [0] * 16 + [1] * 20, ports=list(range(16)) + [15] * 20)
    group = distinct_port_bucket_proxy(data).groups[0]
    assert len(group.support.row_ids) == 16 and group.window.end_us == 1


@pytest.mark.parametrize("last,flagged", [(4.999999, True), (5, False), (5.000001, False)])
def test_bucket_leaks_before_exact_five_second_boundary_event(tmp_path, last, flagged):
    data = parsed(tmp_path, [0] * 15 + [last], ports=list(range(16)))
    assert bool(distinct_port_bucket_proxy(data).groups) == flagged


def test_bucket_overlapping_overflows_merge_and_gap_starts_new_incident(tmp_path):
    data = parsed(tmp_path, [0] * 25, ports=list(range(25)))
    run = distinct_port_bucket_proxy(data)
    assert len(run.groups) == 1 and len(run.groups[0].support.row_ids) == 25
    data = parsed(tmp_path, [0] * 16 + [1000] * 16, ports=list(range(16)) * 2)
    run = distinct_port_bucket_proxy(data)
    assert len(run.groups) == 2 and all(len(g.support.row_ids) == 16 for g in run.groups)
    assert len({g.group_id for g in run.groups}) == 2
    with pytest.raises(ValueError, match="proxy_group_limit"):
        distinct_port_bucket_proxy(data, max_groups=1)


def test_bucket_repeat_does_not_refresh_fifo_age(tmp_path):
    data = parsed(tmp_path, [0] * 15 + [4, 5, 5.1], ports=list(range(15)) + [0, 15, 0])
    group = distinct_port_bucket_proxy(data).groups[0]
    # Port0's original introduction is evicted at5s despite the4s repeat. Its
    # new5.1s introduction overflows; neither the old nor repeated row is support.
    assert len(group.support.row_ids) == 16
    lines = {int(row_id.split(":")[1]) for row_id in group.support.row_ids}
    assert 1 not in lines and 16 not in lines and 18 in lines


@pytest.mark.parametrize("proxy", [interval_cv_proxy, distinct_port_bucket_proxy])
def test_incomplete_quarantine_captureloss_or_duplicate_is_error_not_empty_success(tmp_path, proxy):
    with pytest.raises(ValueError, match="incomplete_proxy_input"):
        proxy(parsed(tmp_path, [0] * 16, limits=InputLimitsV1(max_analyzed_rows=10)))
    with pytest.raises(ValueError, match="incomplete_proxy_input"):
        proxy(parsed(tmp_path, [0] * 16, suffix=b"{bad json}\n"))
    with pytest.raises(ValueError, match="incomplete_proxy_input"):
        proxy(parsed(tmp_path, [0] * 16, mutate=lambda row, i: row.update({"missed_bytes": 1})))
    data = parsed(tmp_path, [0] * 16)
    duplicate = replace(data, records=(*data.records[:-1], data.records[0]))
    with pytest.raises(ValueError, match="mixed_or_duplicate_proxy_generation"):
        proxy(duplicate)
    foreign = data.records[0].model_copy(update={"input_sha256": "f" * 64})
    with pytest.raises(ValueError, match="mixed_or_duplicate_proxy_generation"):
        proxy(replace(data, records=(foreign, *data.records[1:])))
    with pytest.raises(ValueError, match="proxy_group_limit"):
        proxy(data, max_groups=True)
