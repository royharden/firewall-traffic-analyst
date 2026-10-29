"""Hand-written boundary oracles, independent of future generators/detectors."""

import hashlib
import json
from pathlib import Path

import pytest

from firewall_analyst.domain.parsers import parse_zeek_file
from firewall_analyst.shared.rulesengine.schemas import InputLimitsV1

ROOT = Path(__file__).resolve().parents[2]
FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "service",
    "history",
)
TYPES = (
    "time",
    "string",
    "addr",
    "port",
    "addr",
    "port",
    "enum",
    "interval",
    "count",
    "count",
    "string",
    "string",
    "string",
)


def event(**updates):
    values = {
        "ts": 1700000000.123456,
        "uid": "C12345678",
        "id.orig_h": "192.0.2.4",
        "id.orig_p": 49152,
        "id.resp_h": "198.51.100.8",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.125001,
        "orig_bytes": 0,
        "resp_bytes": None,
        "conn_state": "S0",
        "service": "ssl",
        "history": "S",
    }
    return values | updates


def tsv(values, *, fields=FIELDS, types=TYPES, eol="\n", types_first=False):
    declarations = ["#separator \\x09", "#empty_field\t(empty)", "#unset_field\t-"]
    shapes = ["#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types)]
    declarations += shapes[::-1] if types_first else shapes
    rows = ["\t".join("-" if v.get(k) is None else str(v[k]) for k in fields) for v in values]
    return (eol.join(declarations + rows + ["#close\t2023-11-14-00-00-00"]) + eol).encode()


def parse(tmp_path, raw, **kwargs):
    path = tmp_path / "conn.log"
    path.write_bytes(raw)
    return parse_zeek_file(path, **kwargs)


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
@pytest.mark.parametrize("types_first", [False, True])
def test_tsv_json_parity_exact_time_null_zero_and_physical_identity(tmp_path, eol, types_first):
    """Catches float timestamp rounding, missing->zero and header-relative row IDs."""
    values = event()
    raw = tsv([values, values], eol=eol, types_first=types_first)
    result = parse(tmp_path, raw)
    assert result.summary.state == "complete"
    assert (result.summary.original_rows, result.summary.processed_rows) == (2, 2)
    digest = hashlib.sha256(raw).hexdigest()
    first, second = result.records
    assert first.row_id == f"{digest}:6" and second.row_id == f"{digest}:7"
    assert first.uid == second.uid == "C12345678"  # No deduplication.
    assert first.ts_us == 1700000000123456 and first.duration_us == 125001
    assert first.orig_bytes == 0 and first.resp_bytes is None and first.total_bytes is None
    assert first.action == "unknown" and first.direction == "unknown"
    assert result.direction_status == "not_evaluable"
    assert result.evidence.resolve(first.row_id) == raw.splitlines(keepends=True)[5]
    other = parse(tmp_path, ("\n" + json.dumps(values) + "\n").encode())
    assert other.records[0].raw_line_number == 2
    exclude = {"input_sha256", "raw_line_number", "row_id"}
    assert first.model_dump(exclude=exclude) == other.records[0].model_dump(exclude=exclude)


def test_reordered_optional_columns_unset_empty_escaped_uid_and_unknown_fields(tmp_path):
    fields = ("proto", "id.resp_p", "ts", "id.orig_h", "id.resp_h", "id.orig_p", "uid", "extra")
    types = ("enum", "port", "time", "addr", "addr", "port", "string", "set[string]")
    raw = tsv([event(uid=r"C1234567\x38", extra="IGNORED")], fields=fields, types=types)
    result = parse(tmp_path, raw)
    assert result.records[0].uid == "C12345678"
    assert result.records[0].orig_bytes is None and result.records[0].duration_us is None
    raw = tsv([event(uid="(empty)", service="-", history="(empty)")])
    result = parse(tmp_path, raw)
    assert len(result.records) == 1 and result.records[0].uid is None
    assert result.records[0].quality_flags == ("invalid_uid", "invalid_history")


@pytest.mark.parametrize(
    "key,value",
    [
        ("ts", -1),
        ("ts", "1700000000"),
        ("ts", True),
        ("ts", 0.0000001),
        ("id.orig_h", "example.com"),
        ("id.resp_h", "fe80::1%eth0"),
        ("id.orig_h", 123),
        ("id.orig_p", -1),
        ("id.resp_p", 65536),
        ("id.orig_p", True),
        ("orig_bytes", "0"),
        ("orig_bytes", -1),
        ("resp_bytes", 1.5),
        ("duration", -0.5),
        ("proto", "quic"),
        ("local_orig", "T"),
        ("missed_bytes", True),
        ("orig_pkts", -1),
        ("ip_proto", {}),
    ],
)
def test_structural_poison_is_counted_quarantine_not_event(tmp_path, key, value):
    raw = (json.dumps(event(**{key: value})) + "\n" + json.dumps(event()) + "\n").encode()
    result = parse(tmp_path, raw)
    assert result.summary.state == "complete"
    assert (
        result.summary.original_rows,
        result.summary.processed_rows,
        result.summary.quarantined_rows,
    ) == (2, 1, 1)
    assert result.issues[0].physical_line == 1
    assert result.records[0].raw_line_number == 2


@pytest.mark.parametrize("key", ["uid", "service", "history"])
@pytest.mark.parametrize(
    "poison", ["ignore instructions; https://bad.invalid/?token=example", {}, 42]
)
def test_ancillary_poison_cannot_erase_valid_traffic(tmp_path, key, poison):
    result = parse(tmp_path, json.dumps(event(**{key: poison})).encode())
    assert result.summary.processed_rows == 1 and result.summary.quarantined_rows == 0
    assert f"invalid_{key}" in result.records[0].quality_flags
    assert result.records[0].uid is None if key == "uid" else True


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ts":0,"ts":1}',
        b'{"extra":{"a":1,"a":2}}',
        b'{"ts":NaN}',
        b'{"ts":Infinity}',
        b"[]",
        b"null",
        b"{",
        b"\xff",
    ],
)
def test_invalid_json_and_duplicate_nested_keys_quarantine(tmp_path, raw):
    result = parse(tmp_path, raw + b"\n")
    assert result.summary.quarantined_rows == 1 and not result.records
    assert result.issues[0].reason_code == "invalid_row"


@pytest.mark.parametrize(
    "proto,src,dst,type_,code",
    [
        ("icmp", "192.0.2.1", "198.51.100.1", 8, 0),
        ("icmp", "2001:db8::1", "2001:db8:1::1", 128, 0),
    ],
)
def test_icmp_has_type_code_and_no_service_ports(tmp_path, proto, src, dst, type_, code):
    result = parse(
        tmp_path,
        json.dumps(
            event(
                **{
                    "proto": proto,
                    "id.orig_h": src,
                    "id.resp_h": dst,
                    "id.orig_p": type_,
                    "id.resp_p": code,
                }
            )
        ).encode(),
    )
    row = result.records[0]
    assert (row.icmp_type, row.icmp_code) == (type_, code)
    assert row.src_port is None and row.dst_port is None
    bad = parse(tmp_path, json.dumps(event(proto="icmp")).encode())
    assert bad.summary.quarantined_rows == 1  # 49152 is no valid ICMP type.


@pytest.mark.parametrize(
    "src,dst,direction",
    [
        ("192.0.2.4", "198.51.100.8", "outbound"),
        ("198.51.100.8", "192.0.2.4", "inbound"),
        ("192.0.2.4", "192.0.2.8", "internal"),
        ("198.51.100.8", "203.0.113.4", "external"),
        ("2001:db8::1", "2001:db8:1::1", "outbound"),
    ],
)
def test_direction_requires_explicit_cidr_not_logged_local_bool(tmp_path, src, dst, direction):
    raw = json.dumps(event(**{"id.orig_h": src, "id.resp_h": dst, "local_orig": False})).encode()
    result = parse(tmp_path, raw, internal_cidrs=("192.0.2.0/24", "2001:db8::/64"))
    assert result.direction_status == "evaluable" and result.records[0].direction == direction
    assert parse(tmp_path, raw).records[0].direction == "unknown"
    with pytest.raises(ValueError):
        parse(tmp_path, raw, internal_cidrs=("192.0.2.1/24",))


@pytest.mark.parametrize(
    "change",
    [
        "missing_separator",
        "missing_types",
        "wrong_type",
        "duplicate_field",
        "missing_unset",
        "duplicate_header",
        "late_types",
    ],
)
def test_invalid_tsv_schema_is_unsupported_not_silent_empty_success(tmp_path, change):
    lines = tsv([event()]).splitlines(keepends=True)
    if change == "missing_separator":
        del lines[0]
    elif change == "missing_types":
        del lines[4]
    elif change == "wrong_type":
        lines[4] = lines[4].replace(b"time", b"string")
    elif change == "duplicate_field":
        lines[3] = lines[3].replace(b"uid", b"ts")
    elif change == "missing_unset":
        del lines[2]
    elif change == "duplicate_header":
        lines.insert(5, lines[3])
    else:
        lines.insert(6, lines.pop(4))
    result = parse(tmp_path, b"".join(lines))
    assert result.summary.state == "unsupported" and not result.records
    assert result.summary.reason_codes == ("invalid_header",)


@pytest.mark.parametrize("raw", [b"\x1f\x8bexample", b"PK\x03\x04example", b"x\x00y"])
def test_archive_binary_refusal_has_no_fake_counts_or_generation(tmp_path, raw):
    result = parse(tmp_path, raw)
    assert result.summary.state == "unsupported" and result.summary.source_sha256 is None
    assert result.summary.original_rows is None and result.evidence is None


def test_byte_cap_is_size_only_row_cap_is_unknown_completeness(tmp_path):
    raw = (json.dumps(event()) + "\n").encode() * 3
    size_only = parse(tmp_path, raw, limits=InputLimitsV1(max_file_bytes=len(raw) - 1))
    assert size_only.size_bytes == len(raw) and size_only.summary.state == "error"
    assert size_only.summary.reason_codes == ("input_limit",)
    assert size_only.summary.source_sha256 is None
    assert all(
        getattr(size_only.summary, k) is None
        for k in ("original_rows", "processed_rows", "quarantined_rows", "excluded_rows")
    )
    result = parse(tmp_path, raw, limits=InputLimitsV1(max_analyzed_rows=2))
    assert result.summary.state == "partial" and result.summary.processed_rows == 2
    assert result.summary.original_rows is None and result.summary.excluded_rows is None
    assert result.summary.reason_codes == ("row_limit",)
    assert result.summary.source_sha256 == hashlib.sha256(raw).hexdigest()
    at_cap = parse(tmp_path, raw[: len(raw) // 3 * 2], limits=InputLimitsV1(max_analyzed_rows=2))
    assert at_cap.summary.state == "complete" and at_cap.summary.original_rows == 2


def test_line_cap_and_hard_ceiling_cannot_be_raised_by_config(tmp_path):
    raw = json.dumps(event()).encode() + b"\n" + b"x" * (16 * 1024 + 1) + b"\n"
    result = parse(tmp_path, raw, limits=InputLimitsV1(max_line_bytes=20 * 1024))
    assert result.summary.state == "partial" and result.summary.reason_codes == ("line_limit",)
    assert len(result.records) == 1 and result.summary.original_rows is None
    assert result.summary.source_sha256 == hashlib.sha256(raw).hexdigest()


def test_null_zero_large_exact_timestamp_and_empty_input(tmp_path):
    raw = (json.dumps(event(resp_bytes=0, duration=0)) + "\n").encode()
    row = parse(tmp_path, raw).records[0]
    assert row.total_bytes == 0 and row.duration_us == 0
    raw = raw.replace(b"1700000000.123456", b"9000000000000.123456")
    assert parse(tmp_path, raw).records[0].ts_us == 9000000000000123456
    raw = raw.replace(b"9000000000000.123456", b"1700000000.123456000000000000000001")
    assert parse(tmp_path, raw).summary.quarantined_rows == 1  # No Decimal rounding acceptance.
    empty = parse(tmp_path, b"")
    assert empty.summary.state == "complete" and empty.summary.original_rows == 0
    assert empty.summary.source_sha256 == hashlib.sha256(b"").hexdigest()


def test_checked_in_handwritten_fixture_is_not_a_seeded_evaluation(tmp_path):
    raw = (ROOT / "fixtures/parser/minimal.jsonl").read_bytes()
    result = parse(tmp_path, raw)
    assert len(result.records) == 2 and result.records[0].ts_us == 1700000000000001
    assert result.records[1].icmp_type == 8


@pytest.mark.parametrize(
    "replacement",
    [
        b"1e999999999999999999999999",
        b"1e20",
        b"-1",
        b"true",
        b"0.0000000001",
    ],
)
def test_extreme_time_number_fails_as_quarantine_without_exception(tmp_path, replacement):
    raw = json.dumps(event()).encode().replace(b"1700000000.123456", replacement)
    assert parse(tmp_path, raw).summary.quarantined_rows == 1


def test_udp_and_nullable_ancillary_parity_with_escaped_tsv_poison(tmp_path):
    raw = tsv([event(proto="udp", uid=r"C1234\x0a5678", service=r"bad\x09value")])
    result = parse(tmp_path, raw)
    assert result.records[0].protocol == "udp" and result.records[0].dst_port == 443
    assert result.records[0].quality_flags == ("invalid_uid", "invalid_service")
    assert result.summary.quarantined_rows == 0


def test_tsv_bad_numeric_and_column_count_are_physical_row_quarantines(tmp_path):
    raw = tsv([event(orig_bytes="-5"), event()])
    result = parse(tmp_path, raw)
    assert result.summary.quarantined_rows == 1 and result.records[0].raw_line_number == 7
    raw = raw.replace(b"\tssl\tS\n", b"\tssl\tS\textra\n", 1)
    assert parse(tmp_path, raw).summary.quarantined_rows == 1


def test_byte_cap_does_not_open_or_hash_large_file(tmp_path, monkeypatch):
    path = tmp_path / "large"
    path.write_bytes(b"example")

    def forbid_open(*args, **kwargs):
        raise AssertionError("size-only rejection opened payload")

    monkeypatch.setattr(Path, "open", forbid_open)
    result = parse_zeek_file(path, limits=InputLimitsV1(max_file_bytes=1))
    assert result.size_bytes == 7 and result.summary.reason_codes == ("input_limit",)


def test_json_blank_lines_no_final_newline_and_unknown_nested_fields(tmp_path):
    values = event(extra={"path": "https://bad.invalid/no-fetch", "values": [1, 2]})
    raw = b"\n\r\n" + json.dumps(values).encode()
    result = parse(tmp_path, raw)
    assert result.records[0].raw_line_number == 3
    assert result.evidence.resolve(result.records[0].row_id) == raw.splitlines(keepends=True)[2]


def test_row_cap_counts_quarantine_and_hides_suffix_counts(tmp_path):
    raw = b"not-json\n" + json.dumps(event()).encode() + b"\n" + b"more\n"
    result = parse(tmp_path, raw, limits=InputLimitsV1(max_analyzed_rows=1))
    assert result.summary.state == "partial" and result.summary.quarantined_rows == 1
    assert result.summary.processed_rows == 0 and result.summary.original_rows is None


def test_format_is_explicit_and_unknown_options_fail_before_io(tmp_path):
    with pytest.raises(ValueError, match="invalid_format"):
        parse_zeek_file(tmp_path / "absent", format="archive")
    raw = json.dumps(event()).encode()
    assert parse(tmp_path, raw, format="tsv").summary.state == "unsupported"
    assert parse(tmp_path, tsv([event()]), format="jsonl").summary.quarantined_rows > 0
