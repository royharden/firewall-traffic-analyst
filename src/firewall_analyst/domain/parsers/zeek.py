"""Strict Zeek TSV/JSONL normalization with bounded, honest observation summaries.

Only supplied local bytes are read. Validated history contributes capture-quality
flags; its text and ancillary service text are discarded and cannot remove events.
"""

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from ipaddress import ip_network
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from ...shared.rulesengine.parsers import ParseIssue
from ...shared.rulesengine.rows import (
    GenerationRows,
    InputTooLarge,
    PhysicalRow,
    SourceChanged,
    UnsupportedInput,
    verified_scan,
)
from ...shared.rulesengine.schemas import InputLimitsV1, ParseSummaryV1
from ..schemas import EventV1

PARSER_PROFILE_VERSION = "zeek-conn-1.1"

TYPES = {
    "ts": "time",
    "uid": "string",
    "id.orig_h": "addr",
    "id.resp_h": "addr",
    "id.orig_p": "port",
    "id.resp_p": "port",
    "proto": "enum",
    "service": "string",
    "duration": "interval",
    "orig_bytes": "count",
    "resp_bytes": "count",
    "conn_state": "string",
    "history": "string",
    "local_orig": "bool",
    "local_resp": "bool",
    "missed_bytes": "count",
    "orig_pkts": "count",
    "orig_ip_bytes": "count",
    "resp_pkts": "count",
    "resp_ip_bytes": "count",
    "ip_proto": "count",
}
REQUIRED = {"ts", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto"}
ANCILLARY = {
    "uid": r"C[A-Za-z0-9]{8,24}",
    "service": r"[A-Za-z0-9_,-]{1,128}",
    "history": r"[sShHaAdDfFrRcCgGtTwWiIqQxX^]{1,128}",
    "conn_state": r"[A-Z0-9]{1,16}",
}


@dataclass(frozen=True)
class ZeekFileResult:
    records: tuple[EventV1, ...]
    summary: ParseSummaryV1
    issues: tuple[ParseIssue, ...]
    size_bytes: int | None
    evidence: GenerationRows | None
    direction_status: Literal["evaluable", "not_evaluable"]


def _integer(value: object, *, tsv: bool, maximum: int = (1 << 64) - 1) -> int | None:
    if value is None:
        return None
    if tsv and isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid_number")
    return value


def _microseconds(value: object, *, tsv: bool) -> int | None:
    if value is None:
        return None
    if (tsv and not isinstance(value, str)) or (not tsv and type(value) not in (int, Decimal)):
        raise ValueError("invalid_number")
    # No float conversion or rounding; reject sub-microsecond and huge exponent input.
    try:
        decimal = Decimal(value)
        if not decimal.is_finite() or decimal < 0 or decimal.adjusted() > 12:
            raise ValueError("invalid_number")
        # Decimal's default precision could round a long fractional value. Compare
        # its exact tuple to an integer microsecond representation instead.
        sign, digits, exponent = decimal.as_tuple()
        if exponent < -6:
            extra = -6 - exponent
            if extra > len(digits) or any(digits[-extra:]):
                raise ValueError("submicrosecond")
            digits, exponent = digits[:-extra], -6
        integer = int("".join(map(str, digits)) or "0") * 10 ** (exponent + 6)
        if sign or integer > (1 << 63) - 1:
            raise ValueError("invalid_number")
        return integer
    except (InvalidOperation, OverflowError) as exc:
        raise ValueError("invalid_number") from exc


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _json(text: str) -> dict[str, object]:
    def invalid_constant(_value: str):
        raise ValueError("nonfinite")

    value = json.loads(
        text, object_pairs_hook=_pairs, parse_float=Decimal, parse_constant=invalid_constant
    )
    if not isinstance(value, dict) or len(value) > 256:
        raise ValueError("invalid_object")
    if any(len(key) > 128 for key in value):
        raise ValueError("invalid_object")
    return value


def _unescape(text: str) -> str:
    # Zeek uses byte escapes, not Python/JSON escapes; never interpret executable text.
    raw = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "\\":
            if not re.match(r"\\x[0-9a-fA-F]{2}", text[index : index + 4]):
                raise ValueError("invalid_escape")
            raw.append(int(text[index + 2 : index + 4], 16))
            index += 4
        else:
            raw.extend(text[index].encode("utf-8"))
            index += 1
    return raw.decode("utf-8")


class _Header:
    def __init__(self):
        self.separator: str | None = None
        self.fields: tuple[str, ...] | None = None
        self.types: tuple[str, ...] | None = None
        self.unset: str | None = None
        self.empty: str | None = None
        self.seen: set[str] = set()

    def add(self, text: str) -> None:
        if text.startswith("#separator "):
            if "separator" in self.seen:
                raise ValueError("invalid_header")
            separator = _unescape(text[len("#separator ") :])
            if len(separator) != 1 or separator in "\r\n\\#" or not separator.isascii():
                raise ValueError("invalid_header")
            self.separator = separator
            self.seen.add("separator")
            return
        if self.separator is None:
            raise ValueError("invalid_header")
        name, _, value = text.partition(self.separator)
        name = name.removeprefix("#")
        if name not in {"fields", "types", "unset_field", "empty_field"}:
            return  # open/close/path/set_separator and unknown metadata are never followed.
        if name in self.seen:
            raise ValueError("invalid_header")
        self.seen.add(name)
        if name in {"fields", "types"}:
            parts = tuple(value.split(self.separator))
            if not 1 <= len(parts) <= 256 or any(not 1 <= len(x) <= 128 for x in parts):
                raise ValueError("invalid_header")
            if name == "fields":
                if len(set(parts)) != len(parts) or any(
                    not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", part) for part in parts
                ):
                    raise ValueError("invalid_header")
                self.fields = parts
            else:
                self.types = parts
        elif name == "unset_field":
            self.unset = value
        else:
            self.empty = value

    def validate(self) -> None:
        if (
            self.fields is None
            or self.types is None
            or self.unset is None
            or self.empty is None
            or not self.unset
            or not self.empty
            or self.unset == self.empty
            or len(self.fields) != len(self.types)
            or not REQUIRED.issubset(self.fields)
        ):
            raise ValueError("invalid_header")
        for field, kind in zip(self.fields, self.types, strict=True):
            if field in TYPES and kind != TYPES[field]:
                raise ValueError("invalid_header")

    def row(self, text: str) -> dict[str, object]:
        self.validate()
        cells = text.split(self.separator)
        if len(cells) != len(self.fields):
            raise ValueError("column_count")
        return {
            field: None if value == self.unset else "" if value == self.empty else value
            for field, value in zip(self.fields, cells, strict=True)
        }


def _event(values: dict[str, object], digest: str, line: int, tsv: bool, networks) -> EventV1:
    if not REQUIRED.issubset(values):
        raise ValueError("missing_required")
    flags = []
    ancillary = {}
    for key, pattern in ANCILLARY.items():
        value = values.get(key)
        try:
            if tsv and isinstance(value, str):
                value = _unescape(value)
            if value is not None and (
                not isinstance(value, str) or not re.fullmatch(pattern, value)
            ):
                raise ValueError("invalid_ancillary")
        except (ValueError, UnicodeError):
            flags.append("invalid_" + key)
            value = None
        ancillary[key] = value
    missed_bytes = _integer(values.get("missed_bytes"), tsv=tsv)
    history = ancillary["history"] or ""
    if missed_bytes is not None and missed_bytes > 0 or any(code in history for code in "gG"):
        flags.append("capture_loss")
    if any(code in history for code in "xX"):
        flags.append("incomplete")
    # Validate remaining known numeric/bool fields even when not retained.
    for key in (
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
        "ip_proto",
    ):
        _integer(values.get(key), tsv=tsv)
    for key in ("local_orig", "local_resp"):
        value = values.get(key)
        if value is not None and (value not in ("T", "F") if tsv else type(value) is not bool):
            raise ValueError("invalid_boolean")
    source_port = _integer(values["id.orig_p"], tsv=tsv, maximum=65535)
    dest_port = _integer(values["id.resp_p"], tsv=tsv, maximum=65535)
    protocol = values["proto"]
    origin = _integer(values.get("orig_bytes"), tsv=tsv)
    response = _integer(values.get("resp_bytes"), tsv=tsv)
    event = EventV1(
        input_sha256=digest,
        raw_line_number=line,
        row_id=f"{digest}:{line}",
        uid=ancillary["uid"],
        ts_us=_microseconds(values["ts"], tsv=tsv),
        src=values["id.orig_h"],
        dst=values["id.resp_h"],
        protocol=protocol,
        src_port=source_port if protocol != "icmp" else None,
        dst_port=dest_port if protocol != "icmp" else None,
        icmp_type=source_port if protocol == "icmp" else None,
        icmp_code=dest_port if protocol == "icmp" else None,
        conn_state=ancillary["conn_state"],
        orig_bytes=origin,
        resp_bytes=response,
        total_bytes=origin + response if origin is not None and response is not None else None,
        duration_us=_microseconds(values.get("duration"), tsv=tsv),
        quality_flags=tuple(flags),
    )
    if networks:
        src_local = any(event.src in net for net in networks)
        dst_local = any(event.dst in net for net in networks)
        direction = {
            (True, True): "internal",
            (True, False): "outbound",
            (False, True): "inbound",
            (False, False): "external",
        }[src_local, dst_local]
        event = event.model_copy(update={"direction": direction})
    return event


def parse_zeek_file(
    path: Path,
    *,
    format: Literal["auto", "tsv", "jsonl"] = "auto",
    internal_cidrs: tuple[str, ...] = (),
    limits: InputLimitsV1 | None = None,
) -> ZeekFileResult:
    """Rows count traffic candidates, excluding blank/header lines. On a processing
    cap, original/excluded totals are unknown, even though both byte passes finish.
    Direction requires explicit CIDRs; logged local_orig/local_resp do not supply them.
    """
    if format not in {"auto", "tsv", "jsonl"}:
        raise ValueError("invalid_format")
    if len(internal_cidrs) > 256:
        raise ValueError("too_many_cidrs")
    networks = tuple(ip_network(cidr, strict=True) for cidr in internal_cidrs)
    direction_status = "evaluable" if networks else "not_evaluable"
    limits = limits or InputLimitsV1()
    byte_cap = min(limits.max_file_bytes, 200 * 1024 * 1024)
    line_cap = min(limits.max_line_bytes, 16 * 1024)
    row_cap = min(limits.max_analyzed_rows, 250_000)

    def consume(rows: Iterator[PhysicalRow], digest: str):
        selected, header = format, _Header()
        records, issues, reasons = [], [], []
        candidates = 0
        for row in rows:
            if row.raw is None:
                reasons.append("line_limit")
                break
            try:
                text = row.raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
            except UnicodeError:
                text = None
            if text is not None and not text.strip():
                continue
            if selected == "auto":
                selected = "tsv" if text is not None and text.startswith("#") else "jsonl"
            if selected == "tsv" and text is not None and text.startswith("#"):
                # A second schema cannot silently reinterpret an already observed generation.
                try:
                    header.add(text)
                except ValueError:
                    raise UnsupportedInput("invalid_header") from None
                continue
            if candidates == row_cap:
                reasons.append("row_limit")
                break
            candidates += 1
            try:
                if text is None:
                    raise ValueError("invalid_utf8")
                if selected == "tsv":
                    try:
                        header.validate()
                    except ValueError:
                        raise UnsupportedInput("invalid_header") from None
                values = header.row(text) if selected == "tsv" else _json(text)
                records.append(_event(values, digest, row.number, selected == "tsv", networks))
            except UnsupportedInput:
                raise
            except (ValueError, ValidationError, TypeError, RecursionError, InvalidOperation):
                # Never copy untrusted text or validation messages into diagnostics.
                issues.append(ParseIssue(physical_line=row.number, reason_code="invalid_row"))
        if selected == "tsv":
            try:
                header.validate()
            except ValueError:
                raise UnsupportedInput("invalid_header") from None
        summary = ParseSummaryV1(
            state="partial" if reasons else "complete",
            source_sha256=digest,
            original_rows=None if reasons else candidates,
            processed_rows=len(records),
            quarantined_rows=len(issues),
            excluded_rows=None if reasons else 0,
            reason_codes=tuple(reasons),
        )
        return tuple(records), summary, tuple(issues)

    size = None
    try:
        result, source = verified_scan(
            Path(path), consume, max_bytes=byte_cap, max_line_bytes=line_cap
        )
        records, summary, issues = result
        return ZeekFileResult(records, summary, issues, source.size_bytes, source, direction_status)
    except InputTooLarge as exc:
        size, state, reason = exc.size_bytes, "error", "input_limit"
    except SourceChanged:
        state, reason = "error", "source_changed"
    except UnsupportedInput as exc:
        state, reason = "unsupported", str(exc)
    except OSError:
        state, reason = "error", "source_unavailable"
    return ZeekFileResult(
        (),
        ParseSummaryV1(
            state=state,
            source_sha256=None,
            original_rows=None,
            processed_rows=None,
            quarantined_rows=None,
            excluded_rows=None,
            reason_codes=(reason,),
        ),
        (),
        size,
        None,
        direction_status,
    )
