"""Actual parser->rule->source-reload->named-claim path; original synthetic rows only."""

import json

from firewall_analyst.domain.rules.evidence import EventEvidenceSource, explain
from firewall_analyst.domain.rules.proposals import propose


def make_source(tmp_path):
    path = tmp_path / "original.jsonl"
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
    path.write_bytes(("\n".join(json.dumps(row) for row in rows) + "\n").encode())
    source = EventEvidenceSource(
        path, as_of_us=1_700_000_015_000_000, internal_cidrs=("192.0.2.0/24",)
    )
    group = next(group for group in source.run.groups if group.rule_id == "port_scan")
    return path, source, group


def test_real_source_explanations_and_exact_proposal(tmp_path):
    _, source, group = make_source(tmp_path)
    checked = explain(group, source)
    assert checked.state == "verified" and len(checked.sentences) >= 4
    assert any(
        sentence.text == "Known origin bytes in the supporting rows: 105 bytes."
        for sentence in checked.sentences
    )
    proposal = propose(group, checked, source)
    assert proposal.status == "proposed" and '"dst_ports":"100-114"' in proposal.text
    assert proposal.group_id == group.group_id and proposal.support == group.support
    assert proposal.text.startswith("NOT APPLIED — proposal for human review")


def test_changed_source_missing_file_and_forged_catalogue_fail(tmp_path):
    path, source, group = make_source(tmp_path)
    changed = group.model_copy(update={"severity_from_rule": 4})
    assert explain(changed, source).state == "explanation_failed"
    original = path.read_bytes()
    path.write_bytes(original.replace(b"192.0.2.1", b"192.0.2.9"))
    assert explain(group, source).state == "explanation_failed"
    path.unlink()
    assert explain(group, source).state == "explanation_failed"
