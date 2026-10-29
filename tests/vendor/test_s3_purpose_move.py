"""Six actual purpose controls and two explicit guards execute after namespace detachment."""

import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def test_current_canonical_purpose_controls_detached_from_both_apps_and_network(tmp_path):
    root = Path(__file__).resolve().parents[2]
    package = root / "src/firewall_analyst/shared/s3"
    inventory = json.loads((package / "VENDORED.json").read_bytes())
    target = tmp_path / "portable"
    for entry in inventory["files"]:
        if entry["test_mapping_only"]:
            continue
        source = root / entry["copied_path"]
        raw = source.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["source_sha256"]
        destination = target / source.relative_to(package)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    tests = tmp_path / "tests"
    for folder in ("callledger", "providers"):
        destination = tests / folder
        destination.mkdir(parents=True)
        for source in sorted((root / "tests/vendor/s3purpose" / folder).glob("*.py")):
            destination.joinpath(source.name).write_text(
                source.read_text(encoding="utf8").replace("firewall_analyst.shared.s3", "portable"),
                encoding="utf8",
            )
    (tests / "test_guards.py").write_text(
        r"""
import importlib,socket
import pytest
def test_both_owner_consumer_provider_import_guards_and_canonical_class_identity():
    for name in ('firewall_analyst.domain','llm_router_eval.pipeline','openai','typesafe'):
        with pytest.raises(RuntimeError,match='owner/provider forbidden'):
            importlib.import_module(name)
    from portable.providers import Provider
    from portable.providers.controller import Provider as ActualProvider
    from portable.callledger import Ledger
    from portable.callledger.ledger import Ledger as ActualLedger
    assert Provider is ActualProvider and Ledger is ActualLedger
def test_actual_network_guard():
    with pytest.raises(RuntimeError,match='network forbidden'):
        socket.create_connection(('example.invalid',443))
""",
        encoding="utf8",
    )
    script = r"""
import importlib.abc,json,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
forbidden={'firewall_analyst','llm_router_eval','openai','typesafe','requests','httpx'}
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split('.')[0] in forbidden:raise RuntimeError('owner/provider forbidden')
sys.meta_path.insert(0,Guard())
def denied(*args,**kwargs):raise RuntimeError('network forbidden')
socket.create_connection=denied;socket.socket.connect=denied
import pytest
code=pytest.main([str(Path(sys.argv[1])/'tests'),'-q','--tb=short',
    '--junitxml='+str(Path(sys.argv[1])/'nested.xml')])
assert not any(name.split('.')[0] in forbidden for name in sys.modules)
print(json.dumps({'pytest_exit':code,'actual_canonical_class_aliases':True}))
raise SystemExit(code)
"""
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    suites = list(ET.parse(tmp_path / "nested.xml").getroot().iter("testsuite"))
    assert sum(int(s.attrib["tests"]) for s in suites) == 8
    assert all(
        int(s.attrib.get(key, 0)) == 0 for s in suites for key in ("failures", "errors", "skipped")
    )
