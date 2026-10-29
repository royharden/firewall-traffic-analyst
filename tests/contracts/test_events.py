"""Invalid source identities, units and transport ambiguity must fail at the boundary."""

import json

import pytest
from pydantic import ValidationError

from firewall_analyst.domain.schemas import EventV1

DIGEST = "a" * 64


def event_data(**changes):
    return {
        "input_sha256": DIGEST,
        "raw_line_number": 7,
        "row_id": DIGEST + ":7",
        "ts_us": 1_700_000_000_123456,
        "src": "192.0.2.1",
        "dst": "198.51.100.2",
        "protocol": "tcp",
        "src_port": 12345,
        "dst_port": 443,
        **changes,
    }


def test_event_wire_roundtrip_keeps_full_physical_identity_and_unknowns():
    event = EventV1.model_validate_json(json.dumps(event_data()))
    assert event.evidence_ref.row_id == DIGEST + ":7"
    assert event.source_sha256 == DIGEST
    assert event.ts_us == 1_700_000_000_123456
    assert event.action == "unknown"
    assert event.direction == "unknown"
    assert event.orig_bytes is event.resp_bytes is event.duration_us is None
    assert EventV1.model_validate_json(event.model_dump_json()) == event
    assert EventV1.model_validate(event.model_dump()) == event


def test_zero_bytes_are_known_zero_not_missing():
    event = EventV1(**event_data(orig_bytes=0, resp_bytes=0, total_bytes=0, duration_us=0))
    assert event.orig_bytes == event.total_bytes == event.duration_us == 0
    unknown = EventV1(**event_data(orig_bytes=0))
    assert unknown.orig_bytes == 0 and unknown.resp_bytes is unknown.total_bytes is None


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"input_sha256": "a" * 12}, "input_sha256"),
        ({"input_sha256": "A" * 64}, "input_sha256"),
        ({"row_id": "a" * 12 + ":7"}, "row_id"),
        ({"row_id": "b" * 64 + ":7"}, "full input digest"),
        ({"raw_line_number": 8}, "physical line"),
        ({"raw_line_number": 0}, "raw_line_number"),
        ({"ts_us": "1700000000000000"}, "ts_us"),
        ({"ts_us": 1.5}, "ts_us"),
        ({"ts_us": True}, "ts_us"),
        ({"src": "example.invalid"}, "src"),
        ({"src": 123}, "explicit address text"),
        ({"src": "fe80::1%eth0"}, "zone identifier"),
        ({"dst_port": 65536}, "dst_port"),
        ({"src_port": None}, "both service ports"),
        ({"protocol": "http"}, "protocol"),
        ({"action": "allow"}, "action"),
        ({"orig_bytes": -1}, "orig_bytes"),
        ({"duration_us": False}, "duration_us"),
        ({"orig_bytes": 2, "resp_bytes": None, "total_bytes": 2}, "total bytes unavailable"),
        ({"orig_bytes": 2, "resp_bytes": 3, "total_bytes": 6}, "byte total disagrees"),
        ({"icmp_type": 8}, "TCP/UDP cannot carry"),
        ({"schema_version": True}, "schema version must be an integer"),
        ({"unexpected": "ignored?"}, "unexpected"),
    ],
)
def test_invalid_event_contracts(changes, reason):
    with pytest.raises(ValidationError, match=reason):
        EventV1(**event_data(**changes))


def test_icmp_type_and_code_have_separate_fields_for_ipv4_and_ipv6():
    for address in ("192.0.2.1", "2001:db8::1"):
        event = EventV1(
            **event_data(
                src=address,
                protocol="icmp",
                src_port=None,
                dst_port=None,
                icmp_type=8,
                icmp_code=0,
            )
        )
        assert event.icmp_code == 0 and event.src_port is event.dst_port is None
    with pytest.raises(ValidationError, match="service ports"):
        EventV1(**event_data(protocol="icmp", icmp_type=8, icmp_code=0))
    with pytest.raises(ValidationError, match="explicit type and code"):
        EventV1(**event_data(protocol="icmp", src_port=None, dst_port=None))


def test_connection_states_do_not_infer_firewall_action_or_direction():
    for state in ("REJ", "S0", "SF", "RSTO", "RSTR", "RSTOS0"):
        event = EventV1(**event_data(conn_state=state))
        assert event.conn_state == state and event.action == event.direction == "unknown"


def test_models_are_frozen_and_physical_rows_do_not_collapse():
    first = EventV1(**event_data(uid="C12345678"))
    second = EventV1(**event_data(uid="C12345678", raw_line_number=8, row_id=DIGEST + ":8"))
    assert first.uid == second.uid
    assert first.row_id != second.row_id
    with pytest.raises(ValidationError, match="frozen"):
        first.orig_bytes = 1
