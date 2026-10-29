"""Finite UTC schedule and rule-specific context authority, independent of Gold."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from firewall_analyst.domain.rules import NetworkContextV1, RulePolicyV1
from firewall_analyst.shared.rulesengine.context import ContextV1, UtcSchedule

ROOT = Path(__file__).resolve().parents[2]
MINUTE = 60_000_000
DAY = 1440 * MINUTE


def test_utc_weekday_minute_and_active_expiry_half_open():
    # Epoch 1970-01-01 is Thursday (weekday 3), midnight UTC.
    schedule = UtcSchedule(weekdays=(3,), start_minute=1, end_minute=2)
    context = ContextV1(
        context_id="demo",
        kind="resource_window",
        rule_ids=("resource_change",),
        active_from_us=0,
        active_until_us=DAY,
        expires_us=2 * DAY,
        schedules=(schedule,),
    )
    assert not context.matches_time(MINUTE - 1, as_of_us=DAY)
    assert context.matches_time(MINUTE, as_of_us=DAY)
    assert not context.matches_time(2 * MINUTE, as_of_us=DAY)
    assert not context.matches_time(DAY + MINUTE, as_of_us=DAY + MINUTE)
    assert not context.matches_time(MINUTE, as_of_us=2 * DAY)
    assert ContextV1.model_validate_json(context.model_dump_json()) == context


@pytest.mark.parametrize(
    "kwargs",
    [
        {"weekdays": (7,), "start_minute": 0, "end_minute": 1},
        {"weekdays": (3, 3), "start_minute": 0, "end_minute": 1},
        {"weekdays": (3,), "start_minute": 60, "end_minute": 60},
        {"weekdays": (3,), "start_minute": 1430, "end_minute": 10},
    ],
)
def test_invalid_schedule_never_wraps_or_widens(kwargs):
    with pytest.raises(ValidationError):
        UtcSchedule(**kwargs)


def network_context(**updates):
    return NetworkContextV1(
        **(
            {
                "context_id": "backup",
                "kind": "backup",
                "rule_ids": ("large_outbound",),
                "active_from_us": 0,
                "active_until_us": DAY,
                "expires_us": 2 * DAY,
                "source_cidrs": ("192.0.2.0/24",),
                "destination_cidrs": ("198.51.100.0/24",),
                "protocols": ("tcp",),
            }
            | updates
        )
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"rule_ids": ("port_scan",)},
        {"rule_ids": ("host_sweep",)},
        {"rule_ids": ("unusual_outbound",)},
        {"source_cidrs": ("example.com",)},
        {"destination_cidrs": ("198.51.100.1/24",)},
        {"active_until_us": 0},
        {"expires_us": DAY - 1},
        {"destination_ports": (True,)},
        {"rule_ids": ("large_outbound", "large_outbound")},
    ],
)
def test_backup_and_invalid_context_cannot_widen_authority(updates):
    with pytest.raises(ValidationError):
        network_context(**updates)


def test_actual_context_schema_and_starting_policy_are_versioned_exactly():
    assert (
        json.loads((ROOT / "config/context.schema.json").read_text())
        == NetworkContextV1.model_json_schema()
    )
    assert (
        RulePolicyV1.model_validate_json((ROOT / "config/rules.json").read_text()) == RulePolicyV1()
    )
    with pytest.raises(ValidationError):
        RulePolicyV1(beacon_max_interval_cv=0.2)
    with pytest.raises(ValidationError):
        RulePolicyV1(port_scan_min_ports=14)
    with pytest.raises(ValidationError):
        RulePolicyV1(max_groups=10001)
