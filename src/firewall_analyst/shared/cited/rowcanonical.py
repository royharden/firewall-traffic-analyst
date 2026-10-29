"""Exact retained row bytes. No acquisition, normalization, arithmetic or permission."""

import hashlib
import json
import unicodedata

from pydantic import BaseModel

ARTIFACT_BYTES = 33554432
ROW_BYTES = 24576
POINTER_BYTES = 32768
EVENT_QUOTE_BYTES = 16384


def pointer_fits(value, maximum=POINTER_BYTES):
    """Bound raw Python row-wire trees before nested model decoding/copying."""
    used = 0

    def emit(node, depth=0):
        if depth > 32:
            raise ValueError("Pointer depth limit")
        if isinstance(node, BaseModel):
            yield b"{"
            for index, name in enumerate(type(node).model_fields):
                if index:
                    yield b","
                yield from emit(name, depth + 1)
                yield b":"
                yield from emit(getattr(node, name), depth + 1)
            yield b"}"
        elif type(node) is dict:
            yield b"{"
            for index, (key, item) in enumerate(node.items()):
                if type(key) is not str:
                    raise ValueError("wire object key type")
                if index:
                    yield b","
                yield from emit(key, depth + 1)
                yield b":"
                yield from emit(item, depth + 1)
            yield b"}"
        elif type(node) in (list, tuple):
            yield b"["
            for index, item in enumerate(node):
                if index:
                    yield b","
                yield from emit(item, depth + 1)
            yield b"]"
        elif node is None or type(node) in (bool, int, str):
            if type(node) is str and len(node) > maximum:
                raise ValueError("wire string exceeds byte ceiling")
            yield json.dumps(
                node, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf8")
        else:
            raise ValueError("wire value type")

    for chunk in emit(value):
        used += len(chunk)
        if used > maximum:
            return False
    return True


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _checked(value, depth=0):
    if depth > 32:
        raise ValueError("row canonical depth exceeded")
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("retained metric string must already be NFC")
        value.encode("utf8", errors="strict")
        return value
    if type(value) in (list, tuple):
        return [_checked(item, depth + 1) for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("canonical object keys must be strings")
        return {_checked(key, depth + 1): _checked(item, depth + 1) for key, item in value.items()}
    raise ValueError("unsupported canonical object or numeric type")


def metric_bytes(value) -> bytes:
    return json.dumps(
        _checked(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf8")


def event_bytes(value) -> bytes:
    # S8 declares ASCII JSON escaping; never NFC-normalize a physical row/record.
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf8")


def encode_capped(value, *, maximum: int, metric: bool):
    """Atomic retained output or cap+1 lower bound; never hash a retained prefix."""
    if type(maximum) is not int or maximum < 1:
        raise ValueError("positive encoding cap required")
    value = _checked(value) if metric else value
    encoder = json.JSONEncoder(
        ensure_ascii=not metric, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    chunks = []
    size = 0
    for chunk in encoder.iterencode(value):
        raw = chunk.encode("utf8")
        size += len(raw)
        if size > maximum:
            return None, maximum + 1, "lower_bound"
        chunks.append(raw)
    return b"".join(chunks), size, "exact"


def decode_retained(raw: bytes, *, maximum: int, metric: bool):
    if type(raw) is not bytes or len(raw) > maximum or not raw:
        raise ValueError("retained artifact byte limit")
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 32:
                raise ValueError("retained artifact depth limit")
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        normalized = set()
        for key, value in items:
            name = unicodedata.normalize("NFC", key) if metric else key
            if name in normalized:
                raise ValueError("duplicate canonical object key")
            normalized.add(name)
            result[key] = value
        return result

    def invalid_number(value):
        raise ValueError("unsupported JSON number")

    try:
        value = json.loads(
            raw.decode("utf8", errors="strict"),
            object_pairs_hook=pairs,
            parse_float=invalid_number,
            parse_constant=invalid_number,
        )
        encoded = metric_bytes(value) if metric else event_bytes(value)
    except (RecursionError, UnicodeError, TypeError) as error:
        raise ValueError("invalid retained canonical JSON") from error
    if encoded != raw:
        raise ValueError("retained canonical bytes mismatch")
    return value
