"""Literal public episode oracles, independently authored without corpus loading."""

import hashlib
import json
from dataclasses import replace

import pytest

from firewall_analyst.baselines.proxies import distinct_port_bucket_proxy
from firewall_analyst.domain.evaluation.matching import score_proxy, score_rules
from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.domain.rules.engine import RULES, RuleChannelV1, RuleRun
from firewall_analyst.shared.rulesengine.fixtures import GoldEpisodeV1
from firewall_analyst.shared.rulesengine.schemas import (
    EvidenceSupport,
    FlaggedGroupV1,
    KeyPart,
    TimeWindow,
    TypedStatV1,
    support_digest,
)

CONFIG = "a" * 64
KEY = (KeyPart(name="src", value="192.0.2.1"), KeyPart(name="protocol", value="tcp"))


def source(tmp_path, n=100, *, times=None, ports=None):
    path = tmp_path / "own-domain-match.jsonl"
    path.write_text(
        "".join(
            json.dumps(
                {
                    "ts": times[i] if times else 0,
                    "id.orig_h": "192.0.2.1",
                    "id.resp_h": "192.0.2.2",
                    "id.orig_p": 40000,
                    "id.resp_p": ports[i] if ports else 443,
                    "proto": "tcp",
                }
            )
            + "\n"
            for i in range(n)
        ),
        encoding="utf-8",
    )
    return parse_zeek_file(path, format="jsonl", internal_cidrs=("192.0.2.0/24",))


def support(data, indices):
    ids = tuple(data.records[i].row_id for i in indices)
    return EvidenceSupport(
        source_sha256=data.summary.source_sha256, row_ids=ids, support_sha256=support_digest(ids)
    )


def group(data, indices, name="group", **changes):
    evidence = support(data, indices)
    return FlaggedGroupV1(
        group_id=hashlib.sha256(name.encode()).hexdigest(),
        rule_id="port_scan",
        rule_version="literal-public-test",
        config_sha256=CONFIG,
        window=TimeWindow(start_us=0, end_us=1),
        grouping_key=KEY,
        support=evidence,
        stats=(
            TypedStatV1(
                stat_id="row_count",
                value=len(indices),
                unit="count",
                support=evidence,
                known_count=len(indices),
                unknown_count=0,
            ),
        ),
        category_from_rule="port_scan",
        severity_from_rule=3,
    ).model_copy(update=changes)


def episode(data, indices, name="episode", kind="positive", **changes):
    return GoldEpisodeV1(
        episode_id=name,
        kind=kind,
        pattern="port_scan",
        subject_key=KEY,
        window=TimeWindow(start_us=0, end_us=1),
        support=support(data, indices),
        expected_category="benign" if kind == "benign" else "port_scan",
        expected_severity=1 if kind == "benign" else 3,
    ).model_copy(update=changes)


def run(*groups):
    return RuleRun(
        tuple(groups), tuple(RuleChannelV1(rule_id=p, status="complete") for p in RULES), CONFIG
    )


@pytest.mark.parametrize("overlap,tp", [(49, 0), (50, 1), (51, 1)])
def test_integer_half_episode_support_boundary_not_prediction_fraction(tmp_path, overlap, tp):
    data = source(tmp_path)
    result = score_rules(
        data, run(group(data, tuple(range(overlap)))), (episode(data, tuple(range(100))),)
    )
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (
        tp,
        1 - tp,
        1 - tp,
    )


@pytest.mark.parametrize("threshold,expected", [((1, 4), 1), ((1, 2), 0), ((3, 4), 0)])
def test_fixed_sensitivity_without_float_rounding(tmp_path, threshold, expected):
    data = source(tmp_path, 4)
    result = score_rules(
        data, run(group(data, (0,))), (episode(data, (0, 1, 2, 3)),), overlap_threshold=threshold
    )
    assert result.true_positive == expected


def test_maximum_overlap_assignment_beats_greedy(tmp_path):
    data = source(tmp_path, 5)
    a, b = group(data, (0, 1, 2, 3), "a"), group(data, (0, 1), "b")
    x, y = episode(data, (0, 1, 2), "x"), episode(data, (2, 3), "y")
    result = score_rules(data, run(a, b), (x, y))
    assert {(e.left_id, e.right_id, e.overlap_rows) for e in result.assignment} == {
        (a.group_id, "y", 2),
        (b.group_id, "x", 2),
    }
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (2, 0, 0)


def test_stable_ties_ignore_supplied_inventory_order(tmp_path):
    data = source(tmp_path, 1)
    a, b = group(data, (0,), "a"), group(data, (0,), "b")
    x, y = episode(data, (0,), "x"), episode(data, (0,), "y")
    first = score_rules(data, run(a, b), (x, y))
    second = score_rules(data, run(b, a), (y, x))
    assert first == second and len(first.assignment) == 2


def test_benign_contamination_is_independent_of_positive_credit(tmp_path):
    data = source(tmp_path, 5)
    a, b = group(data, (0, 1, 2, 3), "a"), group(data, (0, 1), "b")
    episodes = (
        episode(data, (0, 1, 2, 3), "positive"),
        episode(data, (0, 1, 2), "benign-one", "benign"),
        episode(data, (2, 3), "benign-two", "benign"),
        episode(data, (4,), "benign-untouched", "benign"),
    )
    result = score_rules(data, run(a, b), episodes)
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (1, 1, 0)
    assert result.eligible_benign_episodes == 3 and result.affected_benign_episodes == 2
    assert result.affected_benign_ids == ("benign-one", "benign-two")
    assert len(result.benign_edges) == 3  # Two alerts on one episode count once.
    assert any(e.left_id == result.assignment[0].left_id for e in result.benign_edges)


def test_expected_misses_and_untouched_benign_not_excluded(tmp_path):
    data = source(tmp_path, 2)
    result = score_rules(
        data,
        run(),
        (episode(data, (0,), "expected", "expected_miss"), episode(data, (1,), "benign", "benign")),
    )
    assert (result.true_positive, result.false_negative, result.eligible_positive_episodes) == (
        0,
        1,
        1,
    )
    assert (result.eligible_benign_episodes, result.affected_benign_episodes) == (1, 0)


def test_duplicate_distinct_predictions_cannot_both_receive_one_positive(tmp_path):
    data = source(tmp_path, 1)
    result = score_rules(
        data, run(group(data, (0,), "a"), group(data, (0,), "b")), (episode(data, (0,)),)
    )
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (1, 1, 0)


def test_suppressed_is_audit_only_and_diagnostic_is_separate(tmp_path):
    data = source(tmp_path, 1)
    suppressed = group(data, (0,), status="suppressed", matched_context_ids=("public-scanner",))
    result = score_rules(data, run(suppressed), (episode(data, (0,)),))
    assert result.suppressed_audit_ids == (suppressed.group_id,)
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (0, 0, 1)
    key = (*KEY, KeyPart(name="dst_port", value=443), KeyPart(name="dst", value="192.0.2.2"))
    diagnostic = group(data, (0,), rule_id="rejected_then_established", grouping_key=key)
    truth = episode(data, (0,), pattern="rejected_then_established", subject_key=key)
    primary = score_rules(data, run(diagnostic), (truth,))
    assert primary.true_positive == primary.eligible_positive_episodes == 0
    assert primary.out_of_scope_group_ids == (diagnostic.group_id,)
    separate = score_rules(
        data, run(diagnostic), (truth,), applicable_patterns=("rejected_then_established",)
    )
    assert separate.true_positive == 1


def test_actual_proxy_has_declared_narrow_applicability(tmp_path):
    data = source(tmp_path, 16, ports=list(range(16)))
    actual = distinct_port_bucket_proxy(data)
    result = score_proxy(data, actual, (episode(data, tuple(range(16))),))
    assert result.true_positive == 1 and result.applicable_patterns == ("port_scan",)
    with pytest.raises(ValueError, match="applicability"):
        score_proxy(data, replace(actual, applicable_patterns=("port_scan", "beaconing")), ())


@pytest.mark.parametrize(
    "bad",
    [
        "duplicate_prediction",
        "duplicate_episode",
        "partial",
        "foreign_config",
        "foreign_support",
        "key_order",
        "key_type",
        "key_value",
        "window",
        "channel",
        "source_quality",
        "forged_episode",
        "limit",
        "threshold",
    ],
)
def test_invalid_or_incomplete_unit_refused_instead_of_zero_success(tmp_path, bad):
    data = source(tmp_path, 2)
    g = group(data, (0,))
    e = episode(data, (0,))
    groups, episodes, kwargs = (g,), (e,), {}
    if bad == "duplicate_prediction":
        groups = (g, g)
    elif bad == "duplicate_episode":
        episodes = (e, e)
    elif bad == "partial":
        groups = (g.model_copy(update={"status": "partial", "quality_flags": ("cap",)}),)
    elif bad == "foreign_config":
        groups = (g.model_copy(update={"config_sha256": "b" * 64}),)
    elif bad == "foreign_support":
        episodes = (e.model_copy(update={"support": support(source(tmp_path, 3), (0,))}),)
    elif bad == "key_order":
        episodes = (e.model_copy(update={"subject_key": tuple(reversed(KEY))}),)
    elif bad == "key_type":
        episodes = (e.model_copy(update={"subject_key": (KeyPart(name="src", value=1), KEY[1])}),)
    elif bad == "key_value":
        episodes = (
            e.model_copy(update={"subject_key": (KeyPart(name="src", value="192.0.2.99"), KEY[1])}),
        )
    elif bad == "window":
        episodes = (e.model_copy(update={"window": TimeWindow(start_us=1, end_us=2)}),)
    elif bad == "source_quality":
        data = replace(
            data,
            records=(
                data.records[0].model_copy(update={"quality_flags": ("capture_loss",)}),
                data.records[1],
            ),
        )
    elif bad == "forged_episode":
        episodes = (e.model_copy(update={"expected_severity": True}),)
    elif bad == "limit":
        episodes = tuple(episode(data, (0,), f"e{i}") for i in range(257))
    elif bad == "threshold":
        kwargs["overlap_threshold"] = (True, 2)
    current = run(*groups)
    if bad == "channel":
        current = replace(current, channels=())
    with pytest.raises(ValueError):
        score_rules(data, current, episodes, **kwargs)


def test_empty_complete_unit_raw_zero_counts_not_perfect_metric(tmp_path):
    result = score_rules(source(tmp_path, 0), run(), ())
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (0, 0, 0)
    assert result.eligible_positive_episodes == result.eligible_benign_episodes == 0
    assert not hasattr(result, "accuracy") and not hasattr(result, "true_negative")


def test_touching_half_open_windows_and_foreign_subject_do_not_match(tmp_path):
    data = source(tmp_path, 2, times=[0, 1])
    prediction = group(data, (0,), window=TimeWindow(start_us=0, end_us=1_000_000))
    reference = episode(data, (1,), window=TimeWindow(start_us=1_000_000, end_us=1_000_001))
    result = score_rules(data, run(prediction), (reference,))
    assert not result.positive_edges and not result.assignment
    assert (result.true_positive, result.false_positive_alerts, result.false_negative) == (0, 1, 1)


@pytest.mark.parametrize("value", [True, 443.0, "443", None])
def test_service_key_requires_actual_json_integer_without_coercion(tmp_path, value):
    data = source(tmp_path, 1)
    key = (*KEY, KeyPart.model_construct(name="dst_port", value=value))
    reference = episode(data, (0,), pattern="host_sweep", subject_key=key)
    with pytest.raises(ValueError):
        score_rules(data, run(), (reference,))


def test_malformed_pattern_frame_and_duplicate_source_rows_fail_closed(tmp_path):
    data = source(tmp_path, 2)
    with pytest.raises(ValueError, match="configuration"):
        score_rules(data, run(), (), applicable_patterns=(["port_scan"],))
    with pytest.raises(ValueError, match="configuration"):
        score_rules(data, run(), (), applicable_patterns=RULES)
    duplicate = replace(data, records=(data.records[0], data.records[0]))
    with pytest.raises(ValueError, match="mixed_evaluation_source"):
        score_rules(duplicate, run(), ())


@pytest.mark.parametrize("mode", ["mutable_records", "boolean_counters", "cap_reason", "size"])
def test_complete_snapshot_cannot_bypass_types_or_observed_counters(tmp_path, mode):
    data = source(tmp_path, 1)
    if mode == "mutable_records":
        data = replace(data, records=list(data.records))
    elif mode == "boolean_counters":
        data = replace(
            data,
            summary=data.summary.model_copy(update={"original_rows": True, "processed_rows": True}),
        )
    elif mode == "cap_reason":
        data = replace(
            data, summary=data.summary.model_copy(update={"reason_codes": ("input_limit",)})
        )
    else:
        data = replace(data, evidence=replace(data.evidence, size_bytes=data.size_bytes + 1))
    with pytest.raises(ValueError):
        score_rules(data, run(), ())
