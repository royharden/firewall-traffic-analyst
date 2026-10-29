"""Explicit profile convenience and bounded config IO on new hand-authored logs."""

import io
import json
from pathlib import Path

import pytest

from firewall_analyst.cli import _configuration_bytes, main
from firewall_analyst.pipeline import verify

ROOT = Path(__file__).resolve().parents[2]


def hand_source(tmp_path, *, loss=False, malformed=False):
    source = tmp_path / "own-profile-input.jsonl"
    rows = [
        {
            "ts": 7,
            "id.orig_h": "192.0.2.240",
            "id.orig_p": 40000,
            "id.resp_h": "192.0.2.1",
            "id.resp_p": port,
            "proto": "tcp",
            **({"history": "g"} if loss else {}),
        }
        for port in range(16)
    ]
    source.write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        + (b"malformed-hand-line\n" if malformed else b"")
    )
    profile = tmp_path / "explicit-public-profile.json"
    profile.write_bytes((ROOT / "config/evaluation-public-setup.v1.json").read_bytes())
    return source, profile


def test_real_profile_cli_writes_existing_artifact_schema_and_verifies_without_profile(
    tmp_path, capsys
):
    source, profile = hand_source(tmp_path)
    output = tmp_path / "profile-report"
    assert (
        main(["analyze", str(source), "--out", str(output), "--public-profile", str(profile)]) == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["written"] and len(result["public_profile_content_sha256"]) == 64
    report = json.loads((output / "report.json").read_bytes())
    assert set(report["settings"]) == {"as_of_us", "internal_cidrs", "policy", "contexts", "limits"}
    assert report["settings"]["as_of_us"] == 7_000_000
    assert len(report["settings"]["contexts"]) == 3
    assert report["settings"]["policy"]["allowed_destinations"] == [
        "198.51.100.0/24",
        "2001:db8:2::/48",
    ]
    assert any(
        row["group"]["rule_id"] == "port_scan" and row["group"]["status"] == "suppressed"
        for row in report["groups"]
    )
    assert report["quality_evaluation"] == "not_run"
    assert str(profile) not in (output / "report.json").read_text()
    profile.write_bytes(b"now invalid config; must not be opened by verification")
    assert verify(output, input_path=source)
    assert main(["verify", str(output), "--input", str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_manual_cli_baseline_remains_empty_allowlist_and_has_no_profile_claim(tmp_path, capsys):
    source, _ = hand_source(tmp_path)
    output = tmp_path / "baseline-report"
    assert (
        main(
            [
                "analyze",
                str(source),
                "--out",
                str(output),
                "--as-of-us",
                "7000000",
                "--internal-cidr",
                "192.0.2.0/24",
            ]
        )
        == 0
    )
    assert "public_profile_content_sha256" not in json.loads(capsys.readouterr().out)
    report = json.loads((output / "report.json").read_bytes())
    assert report["settings"]["contexts"] == []
    assert report["settings"]["policy"]["allowed_destinations"] == []
    assert any(row["group"]["status"] == "flagged" for row in report["groups"])
    assert verify(output, input_path=source)


@pytest.mark.parametrize(
    "manual",
    [
        ["--as-of-us", "0"],
        ["--internal-cidr", "192.0.2.0/24"],
        ["--policy", "manual-must-not-be-read.json"],
        ["--contexts", "manual-must-not-be-read.json"],
    ],
)
def test_profile_conflicts_are_closed_before_config_or_output_side_effect(tmp_path, capsys, manual):
    source, profile = hand_source(tmp_path)
    output = tmp_path / "must-not-exist"
    assert (
        main(
            [
                "analyze",
                str(source),
                "--out",
                str(output),
                "--public-profile",
                str(profile),
                *manual,
            ]
        )
        == 2
    )
    assert not output.exists()
    assert json.loads(capsys.readouterr().out) == {
        "written": False,
        "error": "local_analysis_failed",
    }


@pytest.mark.parametrize("mode", ["loss", "quarantine"])
def test_profile_does_not_fallback_from_incomplete_source(tmp_path, capsys, mode):
    source, profile = hand_source(tmp_path, loss=mode == "loss", malformed=mode == "quarantine")
    output = tmp_path / "must-not-exist"
    assert (
        main(["analyze", str(source), "--out", str(output), "--public-profile", str(profile)]) == 2
    )
    assert not output.exists() and json.loads(capsys.readouterr().out)["written"] is False


def test_source_change_between_clock_snapshot_and_analysis_prevents_publish(
    tmp_path, capsys, monkeypatch
):
    from firewall_analyst import pipeline

    source, profile = hand_source(tmp_path)
    original = pipeline.analyze

    def changed(path, **settings):
        rows = [json.loads(line) for line in source.read_bytes().splitlines()]
        rows[0]["id.orig_p"] = 40001
        source.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
        return original(path, **settings)

    monkeypatch.setattr(pipeline, "analyze", changed)
    output = tmp_path / "must-not-exist"
    assert (
        main(["analyze", str(source), "--out", str(output), "--public-profile", str(profile)]) == 2
    )
    assert not output.exists() and json.loads(capsys.readouterr().out)["written"] is False


def test_configuration_exact_byte_bound_and_oversize_rejection(tmp_path):
    path = tmp_path / "hand-config.json"
    data = b'{"hand":true}'
    path.write_bytes(data)
    assert _configuration_bytes(path, max_bytes=len(data)) == data
    with pytest.raises(ValueError):
        _configuration_bytes(path, max_bytes=len(data) - 1)


def test_configuration_read_stays_bounded_if_file_grows_after_stat(tmp_path, monkeypatch):
    path = tmp_path / "growing-config.json"
    path.write_bytes(b"{}")
    sizes = []

    class GrowingStream(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    original = Path.open

    def opened(self, *args, **kwargs):
        return GrowingStream(b"x" * 100) if self == path else original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    with pytest.raises(ValueError):
        _configuration_bytes(path, max_bytes=64)
    assert sizes == [65]


def test_invalid_config_error_does_not_echo_source_text_or_create_output(tmp_path, capsys):
    source, profile = hand_source(tmp_path)
    profile.write_bytes(b"hand-sensitive-marker-not-json")
    output = tmp_path / "must-not-exist"
    assert (
        main(["analyze", str(source), "--out", str(output), "--public-profile", str(profile)]) == 2
    )
    captured = capsys.readouterr()
    assert "hand-sensitive-marker" not in captured.out + captured.err
    assert not output.exists()
