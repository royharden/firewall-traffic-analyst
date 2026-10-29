"""Bounded, byte-exact local rows, released only after two matching SHA256 passes.

No application/domain imports, content logging, normalization or file writes. A caller
chooses which rows to consume; the verification pass still hashes the unread suffix.
"""

import hashlib
import re
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path


class InputTooLarge(ValueError):
    def __init__(self, size_bytes: int):
        super().__init__("input_limit")
        self.size_bytes = size_bytes


class SourceChanged(ValueError):
    pass


class UnsupportedInput(ValueError):
    pass


@dataclass(frozen=True)
class PhysicalRow:
    number: int
    raw: bytes | None  # None means the entire overlong physical row was discarded.


def _positive(value: int) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError("limits must be positive integers")


def _fingerprint(path: Path, max_bytes: int) -> tuple[str, int]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise UnsupportedInput("regular_file_required")
    if info.st_size > max_bytes:
        raise InputTooLarge(info.st_size)
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > max_bytes:
                raise SourceChanged("source_changed")
            if b"\x00" in chunk:
                raise UnsupportedInput("binary_input")
            if size == len(chunk) and chunk.startswith(
                (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ", b"7z\xbc\xaf")
            ):
                raise UnsupportedInput("archive_input")
            digest.update(chunk)
    return digest.hexdigest(), size


def verified_scan[T](
    path: Path,
    consume: Callable[[Iterator[PhysicalRow], str], T],
    *,
    max_bytes: int,
    max_line_bytes: int,
) -> tuple[T, "GenerationRows"]:
    """The callback must not publish provisional results or cause external effects."""
    _positive(max_bytes)
    _positive(max_line_bytes)
    path = Path(path).absolute()
    expected, expected_size = _fingerprint(path, max_bytes)
    digest, size = hashlib.sha256(), 0

    def physical_rows(stream) -> Iterator[PhysicalRow]:
        nonlocal size
        number = 0
        while raw := stream.readline(max_line_bytes + 1):
            number += 1
            length = len(raw)
            digest.update(raw)
            size += length
            overlong = length > max_line_bytes
            while not raw.endswith(b"\n") and length > max_line_bytes:
                raw = stream.readline(max_line_bytes + 1)
                if not raw:
                    break
                digest.update(raw)
                size += len(raw)
                if size > max_bytes:
                    raise SourceChanged("source_changed")
            if size > max_bytes:
                raise SourceChanged("source_changed")
            yield PhysicalRow(number, None if overlong else raw)

    with path.open("rb") as stream:
        iterator = physical_rows(stream)
        result = consume(iterator, expected)
        for _ in iterator:
            pass
    if size != expected_size or digest.hexdigest() != expected:
        raise SourceChanged("source_changed")
    return result, GenerationRows(path, expected, size, max_bytes, max_line_bytes)


@dataclass(frozen=True)
class GenerationRows:
    """A reference to one generation, not proof that a later file is unchanged.

    Every resolution rechecks the entire file; stale, foreign or unavailable rows fail
    closed. Returned bytes include their original LF/CRLF (or lack of final newline).
    """

    path: Path
    source_sha256: str
    size_bytes: int
    max_bytes: int
    max_line_bytes: int

    def resolve(self, row_id: str) -> bytes:
        match = re.fullmatch(r"([0-9a-f]{64}):([1-9][0-9]*)", row_id)
        if match is None or match[1] != self.source_sha256:
            raise ValueError("foreign_row")
        target = int(match[2])

        def find(rows: Iterator[PhysicalRow], digest: str) -> bytes | None:
            if digest != self.source_sha256:
                raise SourceChanged("source_changed")
            for row in rows:
                if row.number == target:
                    return row.raw
            return None

        raw, _ = verified_scan(
            self.path, find, max_bytes=self.max_bytes, max_line_bytes=self.max_line_bytes
        )
        if raw is None:
            raise ValueError("row_unavailable")
        return raw
