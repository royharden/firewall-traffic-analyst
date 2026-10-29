"""Actual canonical S2 source runs without either owner or consumer app/provider imports."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def test_s2_actual_moved_corpus_runner_statistics_and_consumer_negative_controls(tmp_path):
    root = Path(__file__).resolve().parents[2]
    source = root / "src/firewall_analyst/shared/evalkit"
    inventory = json.loads((source / "VENDORED.json").read_bytes())
    target = tmp_path / "portable_evalkit"
    target.mkdir()
    for entry in inventory["copied"]:
        if entry["policy"] not in {"unchanged_source", "unchanged_license"}:
            continue
        raw = (root / entry["target"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        (target / Path(entry["target"]).name).write_bytes(raw)
    for name in ("test_corpus.py", "test_runner.py"):
        text = (root / "tests/vendor/s2" / name).read_text(encoding="utf8")
        (tmp_path / name).write_text(
            text.replace("firewall_analyst.shared.evalkit", "portable_evalkit"), encoding="utf8"
        )
    script = r"""
import importlib,importlib.abc,json,socket,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
forbidden={'firewall_analyst','rfr','openai','typesafe','httpx','requests','fastapi'}
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split('.')[0] in forbidden: raise RuntimeError('owner/provider denied')
sys.meta_path.insert(0,Guard())
def denied(*args,**kwargs): raise RuntimeError('network denied')
socket.create_connection=denied;socket.socket.connect=denied
for name in ('firewall_analyst.domain.rules','rfr.pipeline','openai','requests'):
    try:importlib.import_module(name)
    except RuntimeError:pass
    else:raise AssertionError('negative import control did not fire')
try:socket.create_connection(('example.invalid',443))
except RuntimeError:pass
else:raise AssertionError('negative network control did not fire')
from portable_evalkit.corpus import load_corpus,FrozenCorpusError
from portable_evalkit.runner import compare,MethodConfig
from portable_evalkit.statistics import accuracy,rate,classification_rates,typed_equal
from portable_evalkit.models import ConfusionCounts
from test_corpus import fixture
from test_runner import Adapter,Runner,lookup,H
rows,manifest,path=fixture(Path(sys.argv[1]))
assert load_corpus(Path(sys.argv[1]),manifest,'dev',Adapter())==rows
result=compare({'baseline':MethodConfig('fixture/1',H,'synthetic',Runner())},
    manifest,'dev',rows,Adapter(),None,lookup)
assert result.corpus_count==2 and accuracy(result.methods['baseline'].outcomes).value==1
stats=classification_rates(ConfusionCounts(true_positive=3,false_positive=1,
    false_negative=2,true_negative=0))
assert stats.precision.value==.75 and stats.recall.value==.6
assert rate(0,0).value is None and not typed_equal(False,0)
path.write_bytes(path.read_bytes()+b' ')
try:load_corpus(Path(sys.argv[1]),manifest,'dev',Adapter())
except FrozenCorpusError:pass
else:raise AssertionError('changed source digest accepted')
assert not any(n.split('.')[0] in forbidden for n in sys.modules)
print(json.dumps({'actual_canonical_math':True,'fixed_dev_units':2,
    'owner_and_consumer_import_canaries':4,'network_canary':True,'changed_bytes_refused':True}))
"""
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "actual_canonical_math": True,
        "fixed_dev_units": 2,
        "owner_and_consumer_import_canaries": 4,
        "network_canary": True,
        "changed_bytes_refused": True,
    }
