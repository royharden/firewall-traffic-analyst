"""what_bug_this_catches: source rows and canonical citation accounting diverge."""

import base64
import hashlib
import json

import pytest

from firewall_analyst.domain import citations
from firewall_analyst.domain.rules.evidence import EventEvidenceSource
from firewall_analyst.pipeline import analyze, verify, write_artifacts
from firewall_analyst.reporting.render import json_bytes
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1

CLOCK = 1_700_000_020_000_000
CIDRS = ("192.0.2.0/24",)


def hand_source(tmp_path, *, padding=0, padding_character="x"):
    path = tmp_path / "hand-rows.jsonl"
    rows = [
        {
            "ts": 1_700_000_000 + i,
            "uid": "C12345678",
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 40000,
            "id.resp_h": "198.51.100.1",
            "id.resp_p": 100 + i,
            "proto": "tcp",
            "ignored": padding_character * padding,
        }
        for i in range(15)
    ]
    path.write_bytes(b"\r\n".join(json.dumps(row).encode() for row in rows) + b"\r\n")
    return path


def build(path, **kwargs):
    return analyze(path, as_of_us=CLOCK, internal_cidrs=CIDRS, **kwargs)


def test_crlf_repeated_uid_full_rows_and_authoritative_frames(tmp_path):
    path = hand_source(tmp_path)
    artifacts = build(path)
    report = json.loads(artifacts["report.json"])
    bundle = json.loads(artifacts["evidence.json"])["canonical_citations"]
    assert report["canonical_citations"]["required_rows"] == 15
    assert report["canonical_citations"]["resolved_rows"] == 15
    assert report["canonical_citations"]["status"] == "resolved"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert bundle["required_reference_ids"] == [f"{digest}:{i}" for i in range(1, 16)]
    for entry, raw in zip(
        bundle["entries"], path.read_bytes().splitlines(keepends=True), strict=True
    ):
        assert entry["required_frame"]["required_reference_ids"] == [entry["reference_id"]]
        assert entry["assessment"]["required"] == entry["assessment"]["resolved"] == 1
        assert entry["assessment"]["contract_errors"] == []
        assert entry["production"]["pointer"]["locator"]["quote"].encode() == raw
        assert base64.b64decode(entry["retained"]["event_record_base64"])
        assert entry["resolution"]["provenance"]["row"]["current"] is True
    destination = tmp_path / "report"
    write_artifacts(destination, artifacts)
    assert verify(destination, input_path=path)


@pytest.mark.parametrize("forgery", ["quote", "omit", "duplicate", "reorder"])
def test_adapter_rechecks_source_bytes_and_original_support(tmp_path, forgery):
    path = hand_source(tmp_path)
    evidence = json.loads(build(path)["evidence.json"])["rows"]
    source = EventEvidenceSource(path, as_of_us=CLOCK, internal_cidrs=CIDRS)
    if forgery == "quote":
        evidence[0]["raw_base64"] = base64.b64encode(b"forged\r\n").decode()
    elif forgery == "omit":
        evidence.pop()
    elif forgery == "duplicate":
        evidence.append(evidence[0])
    else:
        evidence.reverse()
    with pytest.raises(ValueError, match="canonical_(support|literal)"):
        citations.cite_support(source, evidence, internal_cidrs=CIDRS, limits=InputLimitsV1())


def test_source_mutation_inside_canonical_resolution_refuses_publication(tmp_path, monkeypatch):
    path = hand_source(tmp_path)
    original = citations.RowResolver.resolve

    def mutate(self, *args):
        result = original(self, *args)
        path.write_bytes(path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(citations.RowResolver, "resolve", mutate)
    with pytest.raises(ValueError, match="source_changed"):
        build(path)


def test_overflow_retains_denominator_no_fake_pointer_and_downgrades_proposals(tmp_path):
    # Parser-accepted physical bytes can exceed the Pointer cap after JSON escaping.
    path = hand_source(tmp_path, padding=8000, padding_character="\\")
    assert max(map(len, path.read_bytes().splitlines(keepends=True))) <= 16 * 1024
    artifacts = build(path)
    report = json.loads(artifacts["report.json"])
    bundle = json.loads(artifacts["evidence.json"])["canonical_citations"]
    assert report["canonical_citations"]["required_rows"] == 15
    assert report["canonical_citations"]["resolved_rows"] == 0
    assert report["canonical_citations"]["status"] == "unsupported"
    for entry in bundle["entries"]:
        assert "pointer" not in entry["production"] and entry["retained"] is None
        assert entry["assessment"]["required"] == entry["assessment"]["unresolved"] == 1
        assert entry["resolution"]["reason"] == "event_pointer_overflow"
    for group in report["groups"]:
        assert group["explanation"]["state"] == "explanation_failed"
        assert group["proposal"]["status"] == "investigate"
    destination = tmp_path / "downgraded"
    write_artifacts(destination, artifacts)
    assert verify(destination, input_path=path)  # Reproducible downgrade, not a resolved claim.


def test_rehashed_quote_forgery_is_rejected_by_recomputation(tmp_path):
    path = hand_source(tmp_path)
    artifacts = build(path)
    evidence = json.loads(artifacts["evidence.json"])
    evidence["canonical_citations"]["entries"][0]["production"]["pointer"]["locator"]["quote"] = "x"
    artifacts["evidence.json"] = json_bytes(evidence)
    manifest = json.loads(artifacts["manifest.json"])
    manifest["artifacts"]["evidence.json"] = hashlib.sha256(artifacts["evidence.json"]).hexdigest()
    artifacts["manifest.json"] = json_bytes(manifest)
    destination = tmp_path / "forged"
    write_artifacts(destination, artifacts)
    assert not verify(destination, input_path=path)
