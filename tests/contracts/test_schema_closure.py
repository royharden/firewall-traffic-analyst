"""Generated shapes and a moved non-network model consumer, without an owner app import."""

import ast
import json
import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "src/firewall_analyst/shared/rulesengine"


def test_generated_files_match_locked_models_and_negative_drift_control(tmp_path):
    generator = runpy.run_path(str(ROOT / "config/schemas/generate.py"))
    files = generator["schema_files"]()
    for name, expected in files.items():
        assert (ROOT / "config/schemas" / name).read_bytes() == expected.encode()
    assert len(files) == 12  # Eleven owned shapes and the generation manifest.
    # A real altered artifact must make --check fail; isolate the generator copy.
    copied_generator = tmp_path / "generate.py"
    shutil.copyfile(ROOT / "config/schemas/generate.py", copied_generator)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    (tmp_path / "EventV1.json").write_text("{}\n", encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(copied_generator), "--check"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert failed.returncode != 0 and "EventV1.json" in failed.stderr


def test_generic_import_closure_has_no_domain_provider_or_application_imports():
    allowed = {"hashlib", "json", "typing", "pydantic", "collections", "dataclasses", "datetime"}
    for name in ("__init__.py", "schemas.py", "parsers.py", "fixtures.py"):
        tree = ast.parse((CORE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] in allowed for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    assert node.level == 1 and node.module == "schemas"
                else:
                    assert node.module.split(".")[0] in allowed


def test_detached_resourcechange_model_construction(tmp_path):
    mini = tmp_path / "minimal"
    core = mini / "shared/rulesengine"
    core.mkdir(parents=True)
    (mini / "__init__.py").write_text("", encoding="utf-8")
    (mini / "shared/__init__.py").write_text("", encoding="utf-8")
    for name in ("__init__.py", "schemas.py", "parsers.py", "fixtures.py"):
        shutil.copyfile(CORE / name, core / name)
    code = """
import importlib.abc, json, sys
class DenyOwner(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'firewall_analyst' or fullname.startswith('firewall_analyst.'):
            raise AssertionError('Detached consumer imported owner application')
sys.meta_path.insert(0, DenyOwner())
from minimal.shared.rulesengine.schemas import (
    BoundaryModel, EvidenceSupport, KeyPart, TimeWindow, TypedStatV1,
    FlaggedGroupV1, ClaimV1, ClaimSupportContractV1, ParseSummaryV1, support_digest
)
from minimal.shared.rulesengine.parsers import ParseResult, Parser, Rule
class ResourceChange(BoundaryModel):
    source_sha256: str
    row_id: str
    attribute: str
row = ResourceChange(source_sha256='a'*64, row_id='resource:1', attribute='public_access')
support = EvidenceSupport(source_sha256=row.source_sha256,
    row_ids=(row.row_id,), support_sha256=support_digest((row.row_id,)))
stat = TypedStatV1(stat_id='changes', value=1, unit='count', support=support,
    known_count=1, unknown_count=0)
group = FlaggedGroupV1(group_id='b'*64, rule_id='resource_change', rule_version='1',
    config_sha256='c'*64, window=TimeWindow(start_us=0,end_us=10),
    grouping_key=(KeyPart(name='module',value='demo'),), support=support, stats=(stat,),
    category_from_rule='resource_change',severity_from_rule=2)
claim = ClaimV1(stat_ref='changes',value=1,unit='count',formatter='integer',support=support)
boundary = ClaimSupportContractV1(group=group,claims=(claim,))
summary = ParseSummaryV1(state='complete',source_sha256='a'*64,original_rows=1,
    processed_rows=1,quarantined_rows=0,excluded_rows=0)
result = ParseResult[ResourceChange](records=(row,),summary=summary)
assert result.records[0] == row
assert 'firewall_analyst' not in sys.modules
assert ClaimSupportContractV1.model_validate_json(boundary.model_dump_json()) == boundary
print(json.dumps({'constructed':True,'domain':'ResourceChange','processing_executed':False}))
"""
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "constructed": True,
        "domain": "ResourceChange",
        "processing_executed": False,
    }
