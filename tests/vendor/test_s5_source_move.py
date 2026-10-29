"""Exact S5 source+all schemas moved without either app or provider/network imports."""

import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def test_s5_current_source_schemas_and_conformance_move_together(tmp_path):
    root = Path(__file__).resolve().parents[2]
    meta = json.loads((root / "src/firewall_analyst/shared/cited/VENDORED.json").read_bytes())
    moved = tmp_path / "moved"
    package = moved / "src/movedapp/shared/cited"
    package.mkdir(parents=True)
    for path in [
        moved / "src/movedapp/__init__.py",
        moved / "src/movedapp/shared/__init__.py",
        moved / "tests/vendor/s5/__init__.py",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    for row in meta["files"]:
        relative = row["copied_path"].replace("src/firewall_analyst/", "src/movedapp/")
        destination = moved / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        raw = (root / row["copied_path"]).read_bytes()
        if row["kind"] == "test":
            raw = raw.replace(b"firewall_analyst", b"movedapp")
        destination.write_bytes(raw)
    shutil.copyfile(root / "src/firewall_analyst/shared/cited/NOTICE.MIT", moved / "LICENSE")
    guard = """
import socket
from pathlib import Path
import pytest

def test_declared_import_and_network_guards_are_active():
    for name in ("firewall_analyst", "changelog_advisor", "openai", "typesafe"):
        with pytest.raises(AssertionError): __import__(name)
    with pytest.raises(AssertionError): socket.create_connection(("127.0.0.1", 1))
    from movedapp.shared.cited.models import EventPointer, MetricPointer
    from movedapp.shared.cited.production import RequiredEvidenceFrame
    from movedapp.shared.cited.rows import RowResolver
    assert EventPointer.__module__==MetricPointer.__module__=="movedapp.shared.cited.models"
    assert RequiredEvidenceFrame.__module__=="movedapp.shared.cited.production"
    assert RowResolver.__module__=="movedapp.shared.cited.rows"

def test_all_ten_committed_schemas_match_actual_current_runtime_exports():
    from movedapp.shared.cited.schema import encoded_schemas,encoded_row_schemas
    selected=encoded_schemas()|encoded_row_schemas()
    assert len(selected)==10
    directory=Path("src/movedapp/shared/cited/schemas")
    assert {p.name for p in directory.iterdir()}==set(selected)
    for name,raw in selected.items(): assert (directory/name).read_bytes()==raw.encode("utf-8")
"""
    (moved / "tests/test_move_guards.py").write_text(guard, encoding="utf-8")
    script = r"""
import sys,builtins,socket,json
from pathlib import Path
import pytest,pydantic
sys.path.insert(0,str(Path("src").resolve()))
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name.startswith(("firewall_analyst","changelog_advisor","openai",
                        "typesafe","requests","httpx")):
        raise AssertionError("owner/consumer/provider import forbidden")
    return original(name,*args,**kwargs)
builtins.__import__=guarded
def denied(*args,**kwargs):raise AssertionError("network forbidden")
socket.create_connection=denied
socket.socket.connect=denied
code=pytest.main(["tests/vendor/s5","tests/test_move_guards.py","-q","--junitxml="+sys.argv[1]])
assert not any(n.startswith(("firewall_analyst","changelog_advisor","openai",
                            "typesafe","requests","httpx")) for n in sys.modules)
raise SystemExit(code)
"""
    junit = moved / "actual-moved.xml"
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(junit)],
        cwd=moved,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    suites = list(ET.parse(junit).getroot().iter("testsuite"))
    assert sum(int(s.attrib["tests"]) for s in suites) == 298
    assert all(
        int(s.attrib.get(k, 0)) == 0 for s in suites for k in ("failures", "errors", "skipped")
    )
