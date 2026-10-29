"""Actual moved vendor cores; no owner/consumer app import or network escape."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_both_cores_detached_positive_negative_required_denominator(tmp_path):
    root = Path(__file__).resolve().parents[2]
    package = tmp_path / "portable"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"")
    for name in ("cited", "screen"):
        target = package / name
        target.mkdir()
        for source in (root / "src/firewall_analyst/shared" / name).glob("*.py"):
            shutil.copyfile(source, target / source.name)
    script = r"""
import sys, builtins, socket, json
sys.path.insert(0, sys.argv[1])
from pydantic import BaseModel
assert BaseModel is not None
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.startswith(('firewall_analyst', 'changelog_advisor', 'issue_triage',
                        'httpx', 'requests', 'openai', 'typesafe')):
        raise AssertionError('forbidden dependency')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
def deny(*args, **kwargs): raise AssertionError('network forbidden')
socket.socket = deny
socket.create_connection = deny
from portable.cited import ArtifactRef, Finding, POINTER_ADAPTER, Registry, ResolutionContext
from portable.cited.memory import MemorySource, MemoryTextResolver, install_supplied_text
from portable.cited.assessment import assess_required_evidence
data = MemorySource.from_bytes(namespace_id='own', source_id='source', source_revision='raw-1',
                              raw=b'actual row\r\n', newline_policy='identity')
class Access:
    reference = ArtifactRef(artifact_id='access',artifact_sha256='a'*64,profile_id='access/1')
    def decision(self, namespace_id, source_id):
        return 'allow' if (namespace_id,source_id)==('own','source') else 'unknown'
class Generation:
    reference = ArtifactRef(artifact_id='generation',artifact_sha256='b'*64,
                            profile_id='generation/1')
    def current(self, namespace_id, source_id):
        return data.metadata if (namespace_id,source_id)==('own','source') else None
access,generation=Access(),Generation()
context=ResolutionContext(namespace_id='own',access_policy_ref=access.reference,
                          generation_policy_ref=generation.reference,required_scope='text')
registry=Registry()
install_supplied_text(registry,MemoryTextResolver((data,),access=access,generation=generation))
common=dict(schema_version=1,source_id='source',source_sha256=data.metadata.source_sha256,
            source_revision='raw-1',evidence_artifact_sha256=data.metadata.evidence_artifact_sha256)
line=POINTER_ADAPTER.validate_python(dict(**common,kind='file:line',source_type='supplied_text',
                                        locator_subtype='line',locator=dict(line_start=1,line_end=1)))
event=POINTER_ADAPTER.validate_python(dict(**common,kind='row:id',source_type='event_table',
                                         locator_subtype='row',locator=None))
assert registry.resolve(line,context).excerpt=='actual row\r\n'
assert registry.resolve(event,context).status=='unsupported'
finding=Finding(id='f1',text='Potential interpretation',verdict='partial',evidence=[line,event])
out=assess_required_evidence(finding,registry,context)
assert (out.required_count,out.resolved_count,out.unresolved_count)==(2,1,1)
assert out.finding.verdict=='unsupported'
from portable.screen import ScreenPolicy, UntrustedText, screen_rules
policy=ScreenPolicy('s8/1','rules',max_input_bytes=8192)
ok=screen_rules(UntrustedText('state','generation','{"row_count":15}'),policy)
held=screen_rules(UntrustedText('state','generation','a'*8193),policy)
assert ok.decision=='pass' and held.decision=='needs_human'
assert not any(n.startswith(('firewall_analyst','changelog_advisor','issue_triage','httpx',
                            'requests','openai','typesafe')) for n in sys.modules)
print(json.dumps({'actual_resolved':1,'required_unresolved':1,'event_unsupported':True,
                  'rules_pass':True,'whole_input_cap_held':True,'outbound':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "actual_resolved": 1,
        "required_unresolved": 1,
        "event_unsupported": True,
        "rules_pass": True,
        "whole_input_cap_held": True,
        "outbound": 0,
    }


def test_canonical_s3_real_ledger_lookup_detached_no_owner_or_network(tmp_path):
    root = Path(__file__).resolve().parents[2]
    source = root / "src/firewall_analyst/shared/s3"
    destination = tmp_path / "portable"
    destination.mkdir()
    for folder in ("", "providers", "callledger"):
        target = destination / folder
        target.mkdir(exist_ok=True)
        for file in (source / folder).glob("*.py"):
            shutil.copyfile(file, target / file.name)
    # Exact granted synthetic helper, relocated only. It is not model evidence.
    helper = (root / "tests/vendor/s3/providers/conftest.py").read_bytes()
    (tmp_path / "rig_helpers.py").write_bytes(
        helper.replace(b"firewall_analyst.shared.s3", b"portable")
    )
    script = r"""
import sys, builtins, socket, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import pytest, pydantic
original=builtins.__import__
def importing(name,*args,**kwargs):
    if name.startswith(('llm_router_eval','firewall_analyst','requests','httpx',
                        'openai','typesafe')):
        raise AssertionError('owner or network client forbidden')
    return original(name,*args,**kwargs)
builtins.__import__=importing
def denied(*args,**kwargs):raise AssertionError('network positive control')
socket.socket=denied
socket.create_connection=denied
try:socket.socket()
except AssertionError:pass
else:raise AssertionError('network control failed')
from rig_helpers import Rig
from portable.providers.captures import FixtureIndex
rig=Rig(Path(sys.argv[1])/'actual.sqlite3','typesafe',True)
capture=rig.capture()
changed=rig.request.model_copy(update={'state':{'text':'SYNTHETIC_PAYLOAD_CANARY','nonce':'nonce-2'}})
rig.register(changed)
class NoSend:
    is_test_transport=True
    def send(self,*args,**kwargs):raise AssertionError('offline lookup attempted dispatch')
provider=rig.provider('strict_replay',fixtures=FixtureIndex([capture]),
                      capture_mode='fixture_replay',transport=NoSend())
limits=rig.limits.model_copy(update={'max_outbound_attempts':0})
with rig.open(offline=True) as ledger:
    allocation=provider.admit_operation(rig.plan(offline=True),ledger=ledger,
        budget=rig.authority,context=rig.context(),limits=limits)
    kwargs=rig.kwargs(ledger,allocation,offline=True)
    before=ledger.connection.total_changes
    view=provider.validate_replay_allocation(rig.request,**kwargs)
    assert ledger.connection.total_changes==before and view.mode=='offline'
    hit=provider.run(rig.request,**kwargs)
    assert hit.status=='ok' and hit.origin=='mock' and hit.current_external_cost_usd=='0'
    assert hit.typed.answers['score'].score==1.6 and hit.attempt_ids==[]
    second=provider.admit_operation(rig.plan(offline=True,operation='op2'),ledger=ledger,
        budget=rig.authority,context=rig.context('op2'),limits=limits)
    kwargs2=rig.kwargs(ledger,second,offline=True,operation='op2')
    miss=provider.run(changed,**kwargs2)
    assert miss.status=='cache_miss' and miss.source_capture is None and miss.attempt_ids==[]
    bad=dict(kwargs2)
    bad['context']=bad['context'].model_copy(update={'source_generation':'changed-generation'})
    try:provider.run(changed,**bad)
    except ValueError:pass
    else:raise AssertionError('changed generation accepted')
    assert ledger.totals()['dispatched_attempts']==0
assert not any(n.startswith(('llm_router_eval','firewall_analyst','requests','httpx',
                            'openai','typesafe')) for n in sys.modules)
print(json.dumps({'real_ledger':True,'hit_origin':'mock','miss_no_fallback':True,
                  'changed_generation_rejected':True,'dispatched':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "real_ledger": True,
        "hit_origin": "mock",
        "miss_no_fallback": True,
        "changed_generation_rejected": True,
        "dispatched": 0,
    }
