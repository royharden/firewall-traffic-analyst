"""Byte-generation negative controls; no filesystem writes outside pytest tmp dirs."""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.shared.rulesengine import rows

ROOT = Path(__file__).resolve().parents[2]


def test_exact_bytes_including_crlf_blank_header_unterminated_final_and_stale_ref(tmp_path):
    path = tmp_path / "source"
    raw = b"#header\r\n\r\nfirst\nlast"
    path.write_bytes(raw)
    observed, source = rows.verified_scan(
        path, lambda items, digest: (digest, tuple(items)), max_bytes=100, max_line_bytes=20
    )
    assert observed[0] == hashlib.sha256(raw).hexdigest()
    assert [(row.number, row.raw) for row in observed[1]] == [
        (1, b"#header\r\n"),
        (2, b"\r\n"),
        (3, b"first\n"),
        (4, b"last"),
    ]
    assert source.resolve(f"{source.source_sha256}:4") == b"last"
    with pytest.raises(ValueError, match="foreign_row"):
        source.resolve(f"{'0' * 64}:1")
    with pytest.raises(ValueError, match="row_unavailable"):
        source.resolve(f"{source.source_sha256}:5")
    path.write_bytes(raw.replace(b"last", b"evil"))  # Same size mutation, no mtime reliance.
    with pytest.raises(rows.SourceChanged):
        source.resolve(f"{source.source_sha256}:4")


def test_two_pass_mutation_cannot_release_events_even_when_size_is_identical(tmp_path, monkeypatch):
    path = tmp_path / "conn.log"
    raw = (ROOT / "fixtures/parser/minimal.jsonl").read_bytes()
    path.write_bytes(raw)
    original = rows._fingerprint

    def mutate(path, limit):
        result = original(path, limit)
        path.write_bytes(raw.replace(b"192.0.2.1", b"192.0.2.9"))
        return result

    monkeypatch.setattr(rows, "_fingerprint", mutate)
    result = parse_zeek_file(path)
    assert result.summary.state == "error" and result.summary.reason_codes == ("source_changed",)
    assert not result.records and result.evidence is None and result.summary.source_sha256 is None


def test_unconsumed_suffix_is_still_hashed_and_overlong_row_is_not_split(tmp_path):
    path = tmp_path / "source"
    path.write_bytes(b"one\n" + b"x" * 100 + b"\ntwo\n")
    observed, source = rows.verified_scan(
        path, lambda iterator, _: tuple(iterator), max_bytes=200, max_line_bytes=8
    )
    assert [(row.number, row.raw) for row in observed] == [(1, b"one\n"), (2, None), (3, b"two\n")]
    assert source.resolve(f"{source.source_sha256}:3") == b"two\n"
    with pytest.raises(ValueError, match="row_unavailable"):
        source.resolve(f"{source.source_sha256}:2")
    first, _ = rows.verified_scan(
        path, lambda iterator, _: next(iterator), max_bytes=200, max_line_bytes=8
    )
    assert (
        first.raw == b"one\n"
        and source.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    )


def test_mutated_unconsumed_suffix_and_growth_rejected(tmp_path, monkeypatch):
    path = tmp_path / "source"
    path.write_bytes(b"first\noriginal\n")
    original = rows._fingerprint

    def mutate(path, limit):
        result = original(path, limit)
        path.write_bytes(b"first\nreplaced\n")
        return result

    monkeypatch.setattr(rows, "_fingerprint", mutate)
    with pytest.raises(rows.SourceChanged):
        rows.verified_scan(path, lambda items, _: next(items), max_bytes=30, max_line_bytes=10)


def test_growth_past_byte_limit_during_second_pass_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / "source"
    path.write_bytes(b"short\n")
    original = rows._fingerprint

    def mutate(path, limit):
        result = original(path, limit)
        path.write_bytes(b"z" * 100)
        return result

    monkeypatch.setattr(rows, "_fingerprint", mutate)
    with pytest.raises(rows.SourceChanged):
        rows.verified_scan(path, lambda items, _: tuple(items), max_bytes=30, max_line_bytes=8)


@pytest.mark.parametrize("raw", [b"x" * 8, b"x" * 7 + b"\n", b"x" * 6 + b"\r\n"])
def test_exact_physical_line_boundary_includes_newline(tmp_path, raw):
    path = tmp_path / "source"
    path.write_bytes(raw)
    observed, _ = rows.verified_scan(
        path, lambda items, _: tuple(items), max_bytes=10, max_line_bytes=8
    )
    assert observed[0].raw == raw


def test_missing_source_safe_error_and_nonpositive_limits(tmp_path):
    result = parse_zeek_file(tmp_path / "absent")
    assert result.summary.reason_codes == ("source_unavailable",)
    assert not result.records and result.summary.source_sha256 is None
    with pytest.raises(ValueError):
        rows.verified_scan(tmp_path / "absent", lambda *_: None, max_bytes=0, max_line_bytes=8)


def test_detached_generic_byte_source_without_owner_package(tmp_path):
    """Catches owner-domain/provider dependencies in the reusable byte row source."""
    shutil.copyfile(ROOT / "src/firewall_analyst/shared/rulesengine/rows.py", tmp_path / "rows.py")
    (tmp_path / "sample").write_bytes(b"resource-change\r\n")
    code = """
import importlib.abc, sys
from pathlib import Path
class DenyOwner(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'firewall_analyst' or fullname.startswith('firewall_analyst.'):
            raise AssertionError('owner import')
sys.meta_path.insert(0, DenyOwner())
from rows import verified_scan
first, source = verified_scan(Path('sample'), lambda it, digest: next(it),
    max_bytes=100,max_line_bytes=100)
assert first.raw == b'resource-change\\r\\n'
assert source.resolve(source.source_sha256+':1') == first.raw
assert 'firewall_analyst' not in sys.modules
print('detached-byte-source:pass')
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
    assert result.stdout.strip() == "detached-byte-source:pass"
