"""A separate consumer runs source->windows->group->checked claim->neutral export."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[2] / "src/firewall_analyst/shared/rulesengine"


def test_resourcechange_full_generic_checked_text_path_without_owner_imports(tmp_path):
    target = tmp_path / "portable"
    target.mkdir()
    (target / "__init__.py").write_text("")
    for name in (
        "schemas.py",
        "parsers.py",
        "windows.py",
        "aggregate.py",
        "rules.py",
        "evidence.py",
        "proposals.py",
    ):
        shutil.copyfile(CORE / name, target / name)
    code = r"""
import hashlib,importlib.abc,json,sys
from dataclasses import dataclass
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='firewall_analyst' or fullname.startswith('firewall_analyst.'):
            raise AssertionError('owner import')
sys.meta_path.insert(0,Deny())
from portable.schemas import KeyPart,ClaimV1
from portable.windows import sliding_windows
from portable.aggregate import support_for,measured_stat
from portable.rules import Candidate,merge_candidates,identified_group
from portable.evidence import StatSpec,TemplateSpec,EvidenceSentenceV1,check_group
from portable.proposals import neutral_proposal
raw=b'{"at":30,"module":"storage","delta":1}\n{"at":40,"module":"storage","delta":1}\n'
digest=hashlib.sha256(raw).hexdigest()
@dataclass(frozen=True)
class ResourceChange:
    row_id:str
    source_sha256:str
    at:int
    line:int
    module:str
    delta:int
rows=tuple(ResourceChange(f'{digest}:{i}',digest,**json.loads(line),line=i)
    for i,line in enumerate(raw.splitlines(),1))
key=(KeyPart(name='module',value='storage'),)
windows=sliding_windows(rows,timestamp=lambda r:r.at,tie=lambda r:r.line,key=lambda r:key,
    width_us=60,stride_us=30)
candidates=tuple(Candidate('public_change',b.key,b.window,b.rows) for b in windows.buckets
    if sum(r.delta for r in b.rows)>=2)
candidate,=merge_candidates(candidates,row_id=lambda r:r.row_id,
    timestamp=lambda r:r.at,tie=lambda r:r.line)
support=support_for(candidate.rows,source_sha256=digest,row_id=lambda r:r.row_id)
def recompute(rows,support):
    return measured_stat('changes',sum(r.delta for r in rows),'count',support,len(rows))
stat=recompute(candidate.rows,support)
group=identified_group(rule_id='public_change',rule_version='1',config_sha256='b'*64,
    window=candidate.window,grouping_key=key,support=support,stats=(stat,),
    category_from_rule='public_change',severity_from_rule=2)
class Source:
    def validate_generation(self,expected):
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('stale')
    def resolve(self,refs):
        by_id={r.row_id:r for r in rows}
        return tuple(by_id[ref.row_id] for ref in refs)
    def validate_group(self,expected,actual):
        if expected!=group or tuple(actual)!=candidate.rows:raise ValueError('scope')
sentence=EvidenceSentenceV1(sentence_id='observed',template_id='changes',label_kind='observed_statistic',
    claims=(ClaimV1(stat_ref='changes',value=2,unit='count',formatter='integer',support=support),))
checked=check_group(group,(sentence,),source=Source(),registry={'changes':StatSpec('count',recompute)},
    templates={'changes':TemplateSpec(('changes',),('integer',),('Observed public changes: ','.'))})
assert checked.state=='verified' and checked.sentences[0].text=='Observed public changes: 2.'
proposal=neutral_proposal(group,checked,source=Source(),
    project=lambda rows:[{'module':r.module} for r in rows])
assert proposal.status=='proposed' and proposal.text.startswith('NOT APPLIED')
assert 'firewall_analyst' not in sys.modules
print('ResourceChange:parse-window-stat-merge-check-proposal:pass')
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
    assert result.stdout.strip() == "ResourceChange:parse-window-stat-merge-check-proposal:pass"
