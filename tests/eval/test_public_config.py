"""Public handwritten sources; explicit new configuration, no seeded data."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from firewall_analyst.domain.evaluation.config import (
    MAX_TIME_US,
    PublicEvaluationProfile,
    public_settings,
)
from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.domain.rules import detect
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "config/evaluation-public-setup.v1.json"


def profile():
    return PublicEvaluationProfile.model_validate_json(PROFILE.read_bytes())


def source(tmp_path, rows, *, suffix=b"", limits=None, internal=None):
    path = tmp_path / "public-config.jsonl"
    raw = b"".join(json.dumps(row).encode() + b"\n" for row in rows) + suffix
    path.write_bytes(raw)
    return parse_zeek_file(
        path,
        format="jsonl",
        internal_cidrs=profile().internal_cidrs if internal is None else internal,
        limits=limits,
    )


def row(time=0, **changes):
    value = {
        "ts": time,
        "id.orig_h": "192.0.2.240",
        "id.resp_h": "192.0.2.1",
        "id.orig_p": 40000,
        "id.resp_p": 443,
        "proto": "tcp",
    }
    return value | changes


def test_new_clock_and_finite_period_from_observations_without_baseline_edit(tmp_path):
    baseline = (ROOT / "config/rules.json").read_bytes()
    data = source(tmp_path, [row(9), row(1), row(4)])
    settings = public_settings(data, profile())
    assert settings.as_of_us == 9_000_000 and settings.observed_rows == 3
    assert all(
        (c.active_from_us, c.active_until_us, c.expires_us, c.schedules)
        == (1_000_000, 9_000_001, 9_000_001, ())
        for c in settings.contexts
    )
    scanner = settings.contexts[0]
    assert scanner.matches_time(1_000_000, as_of_us=9_000_000)
    assert scanner.matches_time(9_000_000, as_of_us=9_000_000)
    assert not scanner.matches_time(9_000_001, as_of_us=9_000_000)
    assert not scanner.matches_time(9_000_000, as_of_us=9_000_001)
    assert settings.policy.allowed_destinations == ("198.51.100.0/24", "2001:db8:2::/48")
    assert [(s.protocol, s.port) for s in settings.policy.allowed_services] == [
        ("tcp", 443),
        ("udp", 53),
        ("udp", 123),
    ]
    assert (ROOT / "config/rules.json").read_bytes() == baseline
    assert json.loads(baseline)["allowed_destinations"] == []
    assert len(settings.profile_sha256) == 64
    assert settings.profile_sha256 != hashlib.sha256(PROFILE.read_bytes()).hexdigest()


def test_empty_source_is_explicit_and_has_no_context_instances(tmp_path):
    settings = public_settings(source(tmp_path, []), profile())
    assert (settings.as_of_us, settings.observed_rows, settings.contexts) == (0, 0, ())


def test_clock_endpoint_overflow_rejected_without_clamping(tmp_path):
    data = source(tmp_path, [row()])
    data = replace(data, records=(data.records[0].model_copy(update={"ts_us": MAX_TIME_US}),))
    with pytest.raises(ValueError, match="overflow"):
        public_settings(data, profile())


def test_scanner_real_detector_suppression_is_audit_not_removed_group(tmp_path):
    data = source(tmp_path, [row(**{"id.resp_p": port}) for port in range(16)])
    settings = public_settings(data, profile())
    original = detect(data, as_of_us=settings.as_of_us, policy=settings.policy)
    contextual = detect(
        data, as_of_us=settings.as_of_us, policy=settings.policy, contexts=settings.contexts
    )
    assert any(g.rule_id == "port_scan" and g.status == "flagged" for g in original.groups)
    assert any(g.rule_id == "port_scan" and g.status == "suppressed" for g in contextual.groups)
    assert len(original.groups) == len(contextual.groups)
    assert contextual.audit and contextual.config_sha256 != original.config_sha256


@pytest.mark.parametrize(
    "context_id,src,dst,port,protocol,rule,expected",
    [
        ("public-scanner", "192.0.2.240", "192.0.2.1", 999, "tcp", "port_scan", True),
        ("public-scanner", "192.0.2.240", "2001:db8:1::1", 999, "udp", "host_sweep", True),
        ("public-scanner", "192.0.2.240", "198.51.100.1", 999, "tcp", "port_scan", False),
        ("public-scanner", "192.0.2.240", "192.0.2.1", 443, "tcp", "large_outbound", False),
        ("public-backup", "192.0.2.241", "198.51.100.241", 443, "tcp", "large_outbound", True),
        ("public-backup", "192.0.2.1", "198.51.100.241", 443, "tcp", "large_outbound", False),
        ("public-backup", "192.0.2.241", "198.51.100.1", 443, "tcp", "large_outbound", False),
        ("public-backup", "192.0.2.241", "198.51.100.241", 444, "tcp", "large_outbound", False),
        ("public-backup", "192.0.2.241", "198.51.100.241", 443, "udp", "large_outbound", False),
        ("public-health", "192.0.2.242", "198.51.100.242", 443, "tcp", "beaconing", True),
        ("public-health", "192.0.2.242", "198.51.100.242", 443, "tcp", "unusual_outbound", False),
    ],
)
def test_exact_public_selectors(tmp_path, context_id, src, dst, port, protocol, rule, expected):
    data = source(
        tmp_path,
        [row(**{"id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "proto": protocol})],
    )
    settings = public_settings(data, profile())
    context = next(c for c in settings.contexts if c.context_id == context_id)
    assert context.matches(data.records[0], rule_id=rule, as_of_us=settings.as_of_us) is expected


@pytest.mark.parametrize("mode", ["quarantine", "cap", "capture_loss", "incomplete"])
def test_partial_source_never_becomes_empty_success(tmp_path, mode):
    kwargs = {}
    rows = [row(), row(1)]
    if mode == "quarantine":
        kwargs["suffix"] = b"invalid-json\n"
    elif mode == "cap":
        kwargs["limits"] = InputLimitsV1(max_analyzed_rows=1)
    else:
        rows[0]["history"] = "g" if mode == "capture_loss" else "x"
    with pytest.raises(ValueError, match="evaluation_source"):
        public_settings(source(tmp_path, rows, **kwargs), profile())


@pytest.mark.parametrize("internal", [(), ("203.0.113.0/24",)])
def test_direction_must_use_this_exact_public_internal_configuration(tmp_path, internal):
    with pytest.raises(ValueError, match="direction"):
        public_settings(source(tmp_path, [row()], internal=internal), profile())
