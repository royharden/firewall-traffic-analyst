"""Small hand-authored observed rows, deliberately separate from independent Gold."""

import json

import pytest

from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.domain.rules import detect

BASE = 1_700_000_000


@pytest.fixture
def row():
    def make(second=0, **updates):
        return {
            "ts": BASE + second,
            "uid": "C12345678",
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 40000,
            "id.resp_h": "198.51.100.2",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": None,
            "resp_bytes": 0,
            "conn_state": "S0",
        } | updates

    return make


@pytest.fixture
def run(tmp_path):
    def execute(values, *, direction=True, limits=None, **kwargs):
        path = tmp_path / "hand-oracle.jsonl"
        path.write_bytes(("\n".join(json.dumps(item) for item in values) + "\n").encode())
        parsed = parse_zeek_file(
            path,
            internal_cidrs=("192.0.2.0/24", "2001:db8::/64") if direction else (),
            limits=limits,
        )
        kwargs.setdefault("as_of_us", max((row.ts_us for row in parsed.records), default=0) + 1)
        return detect(parsed, **kwargs), parsed

    return execute
