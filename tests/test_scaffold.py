"""Installation boundary checks; these do not certify a traffic analyzer."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items() if not key.endswith("API_KEY")}
    return subprocess.run(
        [sys.executable, "-m", "firewall_analyst.cli", *args],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_installed_cli_is_keyless_and_reports_actual_local_stage() -> None:
    result = invoke("--json")
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["status"] == "local_deterministic"
    assert status["contracts_available"] is True
    assert status["analysis_available"] is True
    assert status["providers_available"] is False


def test_analysis_requires_explicit_output() -> None:
    result = invoke("analyze", "not-a-real-input.log")
    assert result.returncode != 0
    assert "--out" in result.stderr


def test_status_performs_no_network_or_file_io(monkeypatch, capsys) -> None:
    import builtins
    import socket

    from firewall_analyst.cli import main

    def deny(*args, **kwargs):
        raise AssertionError("Status must not access a file, credential or network")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(builtins, "open", deny)
    monkeypatch.setattr(Path, "open", deny)
    assert main(["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["analysis_available"] is True
