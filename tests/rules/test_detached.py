"""A moved ResourceChange consumer executes windows/stats/merge/context/grouping."""

import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "src/firewall_analyst/shared/rulesengine"


def test_new_generic_modules_have_no_application_domain_provider_imports():
    allowed = {
        "hashlib",
        "json",
        "typing",
        "pydantic",
        "collections",
        "dataclasses",
        "math",
        "statistics",
    }
    for name in ("windows.py", "aggregate.py", "rules.py", "context.py"):
        for node in ast.walk(ast.parse((CORE / name).read_text())):
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] in allowed for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    assert node.level == 1 and node.module == "schemas"
                else:
                    assert node.module.split(".")[0] in allowed


def test_moved_resourcechange_executes_actual_generic_rule_source(tmp_path):
    package = tmp_path / "portable"
    package.mkdir()
    (package / "__init__.py").write_text("")
    for name in ("schemas.py", "windows.py", "aggregate.py", "rules.py", "context.py"):
        shutil.copyfile(CORE / name, package / name)
    code = """
import importlib.abc,sys
from dataclasses import dataclass
class DenyOwner(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'firewall_analyst' or fullname.startswith('firewall_analyst.'):
            raise AssertionError('owner package import')
sys.meta_path.insert(0,DenyOwner())
from portable.windows import sliding_windows
from portable.aggregate import support_for,sum_stat
from portable.rules import Candidate,merge_candidates,identified_group
from portable.context import ContextV1
from portable.schemas import KeyPart
@dataclass(frozen=True)
class ResourceChange:
    row_id:str
    at:int
    ordinal:int
    public_delta:int
rows=(ResourceChange('resource:1',30,1,1),ResourceChange('resource:2',40,2,1))
key=(KeyPart(name='module',value='storage'),)
batch=sliding_windows(rows,timestamp=lambda r:r.at,tie=lambda r:r.ordinal,
    key=lambda r:key,width_us=60,stride_us=30)
assert batch.complete and len(batch.buckets)==2
candidates=tuple(Candidate('resource_change',b.key,b.window,b.rows) for b in batch.buckets
    if sum(r.public_delta for r in b.rows)>=2)
merged=merge_candidates(candidates,row_id=lambda r:r.row_id,timestamp=lambda r:r.at,
    tie=lambda r:r.ordinal)
assert len(merged)==1 and len(merged[0].rows)==2
support=support_for(merged[0].rows,source_sha256='a'*64,row_id=lambda r:r.row_id)
stat=sum_stat(merged[0].rows,getter=lambda r:r.public_delta,support=support,
    stat_id='public_changes',unit='count')
assert stat.value==2 and stat.known_count==2
context=ContextV1(context_id='change_window',kind='maintenance',rule_ids=('resource_change',),
    active_from_us=0,active_until_us=100,expires_us=200)
assert all(context.matches_time(r.at,as_of_us=100) for r in rows)
group=identified_group(rule_id='resource_change',rule_version='1',config_sha256='b'*64,
    window=merged[0].window,grouping_key=key,support=support,stats=(stat,),
    category_from_rule='public_change',severity_from_rule=2,status='suppressed',
    matched_context_ids=('change_window',))
assert group.status=='suppressed' and len(group.support.row_ids)==2
assert 'firewall_analyst' not in sys.modules
print('ResourceChange:windows+sum+merge+context+group:pass')
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
    assert result.stdout.strip() == "ResourceChange:windows+sum+merge+context+group:pass"
