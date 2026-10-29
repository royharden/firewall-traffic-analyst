"""Public hand oracles: declared loss must survive normalization into safe output."""

import json

import pytest

from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.domain.parsers.zeek import PARSER_PROFILE_VERSION
from firewall_analyst.pipeline import analyze, verify, write_artifacts


def _row(**updates):
    return {
        "ts": 1700000000,
        "id.orig_h": "192.0.2.4",
        "id.resp_h": "198.51.100.8",
        "id.orig_p": 49152,
        "id.resp_p": 443,
        "proto": "tcp",
        "orig_bytes": 1,
        "resp_bytes": 1,
        "missed_bytes": None,
        "history": "ShADadFf",
    } | updates


def _write(path, rows, kind):
    if kind == "jsonl":
        raw = "".join(json.dumps(row) + "\n" for row in rows)
    else:
        fields = tuple(rows[0])
        types = {
            "ts": "time",
            "id.orig_h": "addr",
            "id.resp_h": "addr",
            "id.orig_p": "port",
            "id.resp_p": "port",
            "proto": "enum",
            "orig_bytes": "count",
            "resp_bytes": "count",
            "missed_bytes": "count",
            "history": "string",
        }
        raw = (
            "\n".join(
                [
                    "#separator \\x09",
                    "#empty_field\t(empty)",
                    "#unset_field\t-",
                    "#fields\t" + "\t".join(fields),
                    "#types\t" + "\t".join(types[key] for key in fields),
                    *(
                        "\t".join("-" if row[key] is None else str(row[key]) for key in fields)
                        for row in rows
                    ),
                ]
            )
            + "\n"
        )
    path.write_bytes(raw.encode())


@pytest.mark.parametrize("kind", ["tsv", "jsonl"])
@pytest.mark.parametrize(
    ("updates", "flags"),
    [
        ({"missed_bytes": 1}, ("capture_loss",)),
        ({"history": "Sg"}, ("capture_loss",)),
        ({"history": "SG"}, ("capture_loss",)),
        ({"history": "Sx"}, ("incomplete",)),
        ({"history": "SX"}, ("incomplete",)),
        ({"missed_bytes": 7, "history": "gGxX"}, ("capture_loss", "incomplete")),
        ({"missed_bytes": 0}, ()),
        ({"history": None}, ()),
        ({"history": "x<g"}, ("invalid_history",)),
        ({"missed_bytes": 1, "history": "x<g"}, ("invalid_history", "capture_loss")),
    ],
)
def test_loss_flags_preserve_rows_without_ancillary_guessing(tmp_path, kind, updates, flags):
    """Catches dropped count/history signals, duplicate flags and invalid-text inference."""
    path = tmp_path / "conn.log"
    _write(path, [_row(**updates)], kind)
    parsed = parse_zeek_file(path)
    assert parsed.summary.state == "complete"
    assert parsed.summary.processed_rows == parsed.summary.original_rows == 1
    assert parsed.summary.quarantined_rows == 0
    assert parsed.records[0].quality_flags == flags


@pytest.mark.parametrize("kind", ["tsv", "jsonl"])
@pytest.mark.parametrize("bad", [-1, 1.5, "one"])
def test_invalid_structural_count_is_quarantined(tmp_path, kind, bad):
    """Catches weakening strict count validation while extracting quality metadata."""
    path = tmp_path / "conn.log"
    _write(path, [_row(missed_bytes=bad)], kind)
    parsed = parse_zeek_file(path)
    assert parsed.summary.state == "complete"
    assert parsed.summary.original_rows == parsed.summary.quarantined_rows == 1
    assert parsed.records == ()


@pytest.mark.parametrize(
    ("signal", "reasons"),
    [
        ({"missed_bytes": 1}, ("capture_loss",)),
        ({"history": "g"}, ("capture_loss",)),
        ({"history": "X"}, ("incomplete",)),
        ({"history": "gX"}, ("capture_loss", "incomplete")),
    ],
)
def test_loss_propagates_through_checked_explanations_and_verified_report(
    tmp_path, signal, reasons
):
    """Catches loss disappearing between full physical parse and actionable proposals."""
    path = tmp_path / "conn.log"
    _write(
        path,
        [_row(**{"id.resp_p": 100 + i}, **(signal if i == 0 else {})) for i in range(15)],
        "jsonl",
    )
    artifacts = analyze(path, as_of_us=1700000001000000, internal_cidrs=("192.0.2.0/24",))
    report = json.loads(artifacts["report.json"])
    assert report["parser_profile_version"] == PARSER_PROFILE_VERSION == "zeek-conn-1.1"
    assert report["parse"]["state"] == "complete"
    scans = [item for item in report["groups"] if item["group"]["rule_id"] == "port_scan"]
    assert scans
    assert all(item["group"]["status"] == "partial" for item in scans)
    for item in scans:
        assert set(item["group"]["quality_flags"]) & {"capture_loss", "incomplete"} == set(reasons)
    assert all(item["explanation"]["state"] == "verified" for item in scans)
    assert all(item["proposal"]["status"] == "investigate" for item in scans)
    assert all("no proposed rule" in item["proposal"]["text"] for item in scans)
    channel = next(item for item in report["channels"] if item["rule_id"] == "port_scan")
    assert channel["status"] == "partial"
    assert set(channel["reason_codes"]) & {"capture_loss", "incomplete"} == set(reasons)
    output = tmp_path / "report"
    write_artifacts(output, artifacts)
    assert verify(output, input_path=path)
