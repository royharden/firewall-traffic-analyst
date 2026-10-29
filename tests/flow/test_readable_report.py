"""Analyst-visible states and hostile text controls for the actual report producer."""

import base64
import copy
import hashlib
import json
from html.parser import HTMLParser

import pytest

from firewall_analyst.pipeline import analyze, verify, write_artifacts
from firewall_analyst.reporting.render import STYLE, render
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1


class Page(HTMLParser):
    def __init__(self, content):
        super().__init__(convert_charrefs=True)
        self.tags, self.attributes, self.words = [], [], []
        self.in_style = False
        self.feed(content)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if tag == "style":
            self.in_style = True

    def handle_endtag(self, tag):
        if tag == "style":
            self.in_style = False

    def handle_data(self, data):
        if not self.in_style:
            self.words.append(data)

    @property
    def text(self):
        return " ".join(self.words)


@pytest.fixture
def traffic(tmp_path):
    path = tmp_path / "public-hand.jsonl"
    rows = [
        {
            "ts": 1700000000 + i,
            "id.orig_h": "192.0.2.4",
            "id.orig_p": 49152,
            "id.resp_h": "198.51.100.8",
            "id.resp_p": 100 + i,
            "proto": "tcp",
            "orig_bytes": 1,
            "resp_bytes": None,
        }
        for i in range(15)
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf8")
    return path


def build(path, **kwargs):
    return analyze(path, as_of_us=1700000015000000, internal_cidrs=("192.0.2.0/24",), **kwargs)


def test_readable_real_snapshot_retains_units_unknowns_labels_and_full_audit(traffic, tmp_path):
    """Catches a JSON-only primary view, invented unknown zeros or missing claim labels."""
    artifacts = build(traffic)
    report = json.loads(artifacts["report.json"])
    for name in ("report.html", "report.md"):
        page = Page(artifacts[name].decode())
        assert {"h1", "h2", "h3", "table", "caption", "details", "summary"} <= set(page.tags)
        for required in (
            "Rule channels",
            "Observed groups",
            "Computed observations",
            "Unknown",
            "microseconds",
            "observed_statistic",
            "NOT APPLIED",
            "not detection accuracy",
            "not_run",
            "Disabled",
        ):
            assert required in page.text
        assert all(
            sentence["label_kind"] in page.text
            for item in report["groups"]
            for sentence in item["explanation"]["sentences"]
        )
        assert report["parse"]["source_sha256"] in page.text
        assert report["config_sha256"] in page.text
        assert all(
            row_id in page.text
            for item in report["groups"]
            for row_id in item["group"]["support"]["row_ids"]
        )
    out = tmp_path / "report"
    write_artifacts(out, artifacts)
    assert verify(out, input_path=traffic)
    assert build(traffic) == artifacts


@pytest.mark.parametrize("mode", ["empty", "partial", "error"])
def test_unavailable_and_partial_display_never_implies_benign_or_perfect_coverage(traffic, mode):
    """Catches unknown source counts/coverage represented as complete attack-free success."""
    if mode == "empty":
        traffic.write_bytes(b"")
        artifacts = build(traffic)
    else:
        limits = InputLimitsV1(
            **({"max_analyzed_rows": 2} if mode == "partial" else {"max_file_bytes": 1})
        )
        artifacts = build(traffic, limits=limits)
    report = json.loads(artifacts["report.json"])
    page = Page(artifacts["report.html"].decode())
    assert report["parse"]["state"] in page.text
    if report["coverage"]["groups"] == 0:
        assert "N/A — no groups" in page.text
    else:
        assert mode == "partial"
        assert any(channel["status"] == "partial" for channel in report["channels"])
        assert all(item["group"]["status"] == "partial" for item in report["groups"])
        assert all(item["proposal"]["status"] == "investigate" for item in report["groups"])
    assert "Empty results do not establish benign traffic" in page.text
    if mode in {"partial", "error"}:
        assert "Unknown" in page.text
    assert "100%" not in page.text


def test_all_group_statuses_and_suppression_reasons_are_visible(traffic):
    """Rendering must not hide investigation or suppressed rows behind flagged-only filters."""
    report = json.loads(build(traffic)["report.json"])
    original = report["groups"][0]
    report["groups"] = []
    for status in ("flagged", "suppressed", "partial"):
        item = copy.deepcopy(original)
        item["group"]["status"] = status
        item["group"]["matched_context_ids"] = ["public-backup"] if status == "suppressed" else []
        item["group"]["quality_flags"] = ["capture_loss"] if status == "partial" else []
        report["groups"].append(item)
    page = Page(render(report)["report.html"].decode())
    assert page.tags.count("section") == 3
    assert all(
        label in page.text
        for label in ("flagged", "suppressed", "partial", "public-backup", "capture_loss")
    )
    assert ("id", "group-3") in page.attributes


def test_renderer_preserves_supplied_sentence_kind_without_upgrading_it(traffic):
    """A future annotation/inference display cannot relabel itself as observed evidence."""
    report = json.loads(build(traffic)["report.json"])
    item = report["groups"][0]
    original = item["explanation"]["sentences"][0]
    item["explanation"]["sentences"] = [
        dict(original, label_kind=kind, text=kind + " literal")
        for kind in ("observed_statistic", "deterministic_inference", "model_annotation")
    ]
    content = render(report)["report.html"].decode()
    for kind in ("observed_statistic", "deterministic_inference", "model_annotation"):
        assert f"<strong>{kind}</strong>: {kind} literal" in content


def test_every_dynamic_display_surface_stays_text_and_static_style_is_hash_bound(traffic):
    """Catches an escaped audit JSON masking an XSS hole in the primary analyst view."""
    report = json.loads(build(traffic)["report.json"])
    hostile = '</td><script>alert(1)</script><img src="https://evil.invalid/x" onerror="x">```'
    item = report["groups"][0]
    item["group"]["rule_id"] = hostile
    item["group"]["grouping_key"][0]["value"] = hostile
    item["group"]["matched_context_ids"] = [hostile]
    item["group"]["stats"][0]["unit"] = hostile
    item["explanation"]["sentences"][0]["text"] = hostile
    item["proposal"]["text"] = hostile
    report["channels"][0]["reason_codes"] = [hostile]
    report["limitations"] = [hostile]
    artifacts = render(report)
    for name in ("report.html", "report.md"):
        page = Page(artifacts[name].decode())
        assert hostile in page.text
        assert not {"script", "img", "iframe", "form", "a", "link", "object"} & set(page.tags)
        assert not any(
            key.startswith("on") or key in {"src", "href", "srcdoc"} for key, _ in page.attributes
        )
    digest = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in artifacts["report.html"].decode()
    assert "unsafe-inline" not in artifacts["report.html"].decode()
