"""Actual source -> flags -> checked claims -> inert artifacts -> recomputation."""

import base64
import hashlib
import json
import socket

import pytest

from firewall_analyst.cli import main
from firewall_analyst.pipeline import analyze, verify, write_artifacts
from firewall_analyst.reporting.render import json_bytes, render
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1

CLOCK = 1_700_000_015_000_000


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "source.jsonl"
    rows = [
        {
            "ts": 1_700_000_000 + i,
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 40000,
            "id.resp_h": "198.51.100.1",
            "id.resp_p": 100 + i,
            "proto": "tcp",
            "orig_bytes": i,
        }
        for i in range(15)
    ]
    path.write_bytes(b"\r\n".join(json.dumps(row).encode() for row in rows))
    return path


def build(source, **kwargs):
    return analyze(source, as_of_us=CLOCK, internal_cidrs=("192.0.2.0/24",), **kwargs)


def test_full_artifacts_full_raw_support_and_repeatability(source, tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("local analysis must not open a network")

    monkeypatch.setattr(socket, "socket", deny)
    artifacts = build(source)
    report = json.loads(artifacts["report.json"])
    assert report["coverage"]["verified_fraction"] == 1
    assert report["quality_evaluation"] == "not_run"
    assert report["providers_available"] is False
    evidence = json.loads(artifacts["evidence.json"])
    raw = source.read_bytes().splitlines(keepends=True)
    assert len(evidence["rows"]) == 15
    for row in evidence["rows"]:
        line = int(row["row_id"].split(":")[1])
        assert base64.b64decode(row["raw_base64"], validate=True) == raw[line - 1]
    support = {r for g in report["groups"] for r in g["group"]["support"]["row_ids"]}
    assert {r["row_id"] for r in evidence["rows"]} == support
    destination = tmp_path / "report"
    write_artifacts(destination, artifacts)
    assert verify(destination, input_path=source)
    assert artifacts == build(source)
    with pytest.raises(FileExistsError):
        write_artifacts(destination, artifacts)


@pytest.mark.parametrize(
    "name",
    [
        "report.json",
        "report.md",
        "report.html",
        "evidence.json",
        "proposed-rules.txt",
        "manifest.json",
    ],
)
def test_each_tampered_artifact_fails(source, tmp_path, name):
    destination = tmp_path / "report"
    write_artifacts(destination, build(source))
    with (destination / name).open("ab") as stream:
        stream.write(b"tamper")
    assert not verify(destination, input_path=source)


def test_rehashed_forgery_fails_recomputation(source, tmp_path):
    destination = tmp_path / "report"
    artifacts = build(source)
    report = json.loads(artifacts["report.json"])
    report["groups"][0]["group"]["severity_from_rule"] = 1
    artifacts["report.json"] = json_bytes(report)
    manifest = json.loads(artifacts["manifest.json"])
    manifest["artifacts"]["report.json"] = hashlib.sha256(artifacts["report.json"]).hexdigest()
    artifacts["manifest.json"] = json_bytes(manifest)
    write_artifacts(destination, artifacts)
    assert not verify(destination, input_path=source)


def test_source_changed_missing_explicit_or_missing_artifact(source, tmp_path):
    destination = tmp_path / "report"
    write_artifacts(destination, build(source))
    original = source.read_bytes()
    source.write_bytes(original + b"\n")
    assert not verify(destination, input_path=source)
    source.write_bytes(original)
    (destination / "manifest.json").unlink()
    assert not verify(destination, input_path=source)
    assert not verify(destination, input_path=tmp_path / "missing")


def test_empty_partial_error_and_unknown_direction_are_explicit(source, tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    report = json.loads(build(empty)["report.json"])
    assert report["coverage"]["verified_fraction"] is None
    assert report["coverage"]["groups"] == 0
    partial = json.loads(build(source, limits=InputLimitsV1(max_analyzed_rows=10))["report.json"])
    assert partial["parse"]["state"] == "partial"
    assert partial["parse"]["original_rows"] is None
    error = json.loads(build(source, limits=InputLimitsV1(max_file_bytes=1))["report.json"])
    assert error["parse"]["state"] == "error"
    assert error["parse"]["source_sha256"] is None
    assert error["coverage"]["verified_fraction"] is None
    unknown = json.loads(analyze(source, as_of_us=CLOCK)["report.json"])
    assert unknown["direction_status"] == "not_evaluable"
    assert any(c["status"] == "not_evaluable" for c in unknown["channels"])


def test_output_cap_no_publication(source, tmp_path):
    with pytest.raises(ValueError, match="output_limit"):
        build(source, limits=InputLimitsV1(max_output_bytes=100))
    assert not (tmp_path / "report").exists()


def test_caller_group_cap_is_enforced_and_partial(source):
    report = json.loads(build(source, limits=InputLimitsV1(max_groups=1))["report.json"])
    assert len(report["groups"]) == 1
    assert report["settings"]["policy"]["max_groups"] == 1
    assert any(c["status"] == "partial" for c in report["channels"])
    assert report["groups"][0]["group"]["status"] == "partial"
    assert report["groups"][0]["proposal"]["status"] == "investigate"


def test_inert_html_and_markdown_escape_hostile_data(source):
    report = json.loads(build(source)["report.json"])
    report["untrusted"] = '</pre><script src="https://evil.invalid/x"></script>```'
    artifacts = render(report)
    for name in ("report.html", "report.md"):
        content = artifacts[name].decode()
        assert "<script" not in content
        assert "&lt;/pre&gt;&lt;script" in content
    assert "default-src 'none'" in artifacts["report.html"].decode()


def test_cli_actual_analysis_verify_and_existing_output(source, tmp_path, capsys):
    destination = tmp_path / "report"
    args = ["analyze", str(source), "--out", str(destination), "--as-of-us", str(CLOCK)]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["written"] is True
    assert main(["verify", str(destination), "--input", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "local_analysis_failed"
    assert main(["analyze", str(tmp_path / "missing"), "--out", str(tmp_path / "new")]) == 2
    failed = json.loads((tmp_path / "new/report.json").read_bytes())
    assert failed["parse"]["state"] == "error"
    assert failed["parse"]["source_sha256"] is None
    assert not verify(tmp_path / "new", input_path=tmp_path / "missing")


def test_new_directory_partial_write_has_no_completion_marker(source, tmp_path, monkeypatch):
    from pathlib import Path

    original = Path.open
    destination = tmp_path / "report"

    def fail(self, *args, **kwargs):
        if self.name == "report.html":
            raise OSError("simulated disk failure")
        return original(self, *args, **kwargs)

    artifacts = build(source)
    monkeypatch.setattr(Path, "open", fail)
    with pytest.raises(OSError):
        write_artifacts(destination, artifacts)
    assert destination.is_dir()
    assert not (destination / "manifest.json").exists()


def test_changed_during_evidence_resolution_fails(source, monkeypatch):
    from firewall_analyst import pipeline

    scan = pipeline.verified_scan

    def change(*args, **kwargs):
        source.write_bytes(source.read_bytes() + b"\n")
        return scan(*args, **kwargs)

    monkeypatch.setattr(pipeline, "verified_scan", change)
    with pytest.raises(ValueError, match="source_changed"):
        build(source)
