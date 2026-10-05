"""Strict parser for uncompressed USTAR archives.

Hand-written (rather than using tarfile) so that every ambiguity can be
rejected outright: non-canonical numeric fields, bad checksums, non-USTAR
magic, links, long-name/pax extensions, truncation, malformed padding and
trailing data.

Only regular files are accepted. A valid archive is a sequence of USTAR
header/data blocks followed by two zero blocks; only zero bytes may follow
(canonical 10240-byte record padding).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha256

BLOCK = 512
NAME_LEN = 100
PREFIX_LEN = 155
MAX_FILES = 100
MAX_TOTAL_CONTENT = 6 * 1024 * 1024

# USTAR regular-file type flags. GNU sparse headers ('S') are excluded: their
# payload is not a plain byte stream.
REGULAR_TYPES = frozenset({b"0", b"\x00"})

_NON_FILE_TYPES = {
    b"1": "hard link",
    b"2": "symbolic link",
    b"3": "character device",
    b"4": "block device",
    b"5": "directory",
    b"6": "FIFO",
    b"7": "contiguous file",
    b"g": "GNU multi-volume header",
    b"x": "pax extended header",
    b"X": "pax global extended header",
    b"L": "GNU long name",
    b"K": "GNU long link",
    b"S": "GNU sparse file",
}


class TarError(ValueError):
    """A locatable violation of the accepted archive format."""

    def __init__(self, category: str, message: str, index: int | None = None):
        super().__init__(message)
        self.category = category
        self.message = message
        self.index = index

    def with_index(self, index: int) -> "TarError":
        if self.index is None:
            self.index = index
        return self

    def to_detail(self) -> str:
        where = f"entry {self.index}" if self.index is not None else "archive"
        return f"{where}: {self.message}"

    def __str__(self) -> str:
        return f"[{self.category}] {self.to_detail()}"


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    digest: bytes


def _decode_octal(raw: bytes, field: str) -> int:
    """Decode a strictly formatted POSIX.1-1988 octal field.

    Accepted form: optional leading NULs, one or more ASCII octal digits,
    then NUL or space fill. Base-256 encoding, embedded NULs among digits,
    and empty fields are all rejected.
    """
    b = raw.lstrip(b"\x00").rstrip(b" \x00")
    if not b:
        raise TarError("invalid_header", f"{field} field is empty")
    try:
        text = b.decode("ascii")
    except UnicodeDecodeError:
        raise TarError("invalid_header", f"{field} field is not ASCII")
    if any(ch < "0" or ch > "7" for ch in text):
        raise TarError("invalid_header", f"{field} field is not canonical octal")
    return int(text, 8)


def _checksum_ok(header: bytes) -> bool:
    field = header[148:156]
    # POSIX allows exactly two encodings: "dddddd\0 " or " dddddd\0".
    if not (
        re.fullmatch(rb"[0-7]{6}\x00 ", field)
        or re.fullmatch(rb" [0-7]{6}\x00", field)
    ):
        return False
    want = int(field.strip(b" \x00"), 8)
    unsigned = sum(header[:148]) + sum(b"        ") + sum(header[156:])
    if want == unsigned:
        return True
    # The historical signed-checksum interpretation is also tolerated.
    signed = sum((b - 256 if b > 127 else b) for b in (header[:148] + header[156:]))
    return want == signed


def _field_bytes(field: bytes, what: str) -> bytes:
    """Return the content of a NUL-terminated name field.

    Bytes after the terminating NUL must all be zero; a field may also fill
    its entire width without a terminator (permitted by POSIX).
    """
    if b"\x00" in field:
        content, tail = field.split(b"\x00", 1)
        if tail and any(b != 0 for b in tail):
            raise TarError("invalid_header", f"non-zero fill after {what} terminator")
        return content
    return field


def _validate_path(path: str) -> None:
    if unicodedata.normalize("NFC", path) != path:
        raise TarError("invalid_path", "path is not Unicode NFC normalized")
    if path.startswith("/"):
        raise TarError("invalid_path", "absolute paths are forbidden")
    if "\\" in path:
        raise TarError("invalid_path", "backslash is forbidden in path")
    for ch in path:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise TarError("invalid_path", "path contains control character")
    segments = path.split("/")
    if any(seg == "" for seg in segments):
        raise TarError("invalid_path", "empty path segment")
    if any(seg in (".", "..") for seg in segments):
        raise TarError("invalid_path", "'.' and '..' segments are forbidden")


def parse_tar(data: bytes) -> list[FileEntry]:
    """Parse and fully validate an uncompressed USTAR archive."""
    if len(data) < 2 * BLOCK:
        raise TarError("truncated", "archive shorter than two 512-byte blocks")

    entries: list[FileEntry] = []
    seen: set[str] = set()
    pos = 0
    zero_run = 0

    while True:
        if pos + BLOCK > len(data):
            raise TarError("truncated", "header block crosses end of input")
        block = data[pos : pos + BLOCK]

        if block == b"\x00" * BLOCK:
            zero_run += 1
            pos += BLOCK
            if zero_run == 2:
                break
            continue
        if zero_run == 1:
            raise TarError("invalid_terminator", "non-zero block between terminator blocks")

        index = len(entries) + 1
        try:
            # POSIX.1-1988 USTAR: magic "ustar\0", version "00".
            if block[257:265] != b"ustar\x00" + b"00":
                raise TarError("non_ustar", "not a POSIX USTAR header (magic/version)")
            if not _checksum_ok(block):
                raise TarError("bad_checksum", "header checksum mismatch")

            typeflag = block[156:157]
            if typeflag not in REGULAR_TYPES:
                what = _NON_FILE_TYPES.get(typeflag, f"typeflag {typeflag!r}")
                raise TarError("unsupported_type", f"{what} entries are not accepted")

            size = _decode_octal(block[124:136], "size")
            _decode_octal(block[100:108], "mode")
            _decode_octal(block[108:116], "uid")
            _decode_octal(block[116:124], "gid")
            _decode_octal(block[136:148], "mtime")
            if size > MAX_TOTAL_CONTENT:
                raise TarError("content_too_large", "single file exceeds 6 MiB content limit")

            name_part = _field_bytes(block[0:NAME_LEN], "name")
            prefix_part = _field_bytes(block[345 : 345 + PREFIX_LEN], "prefix")
            if not name_part:
                raise TarError("invalid_path", "empty name")
            link_part = _field_bytes(block[157:257], "linkname")
            if link_part:
                raise TarError("invalid_header", "regular file must not carry a linkname")

            raw_path = (
                prefix_part + b"/" + name_part if prefix_part else name_part
            )
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                raise TarError("invalid_path", "path is not valid UTF-8")
            _validate_path(path)

            if path in seen:
                raise TarError("duplicate_path", f"duplicate path: {path}")

            pos += BLOCK
            pad = -size % BLOCK
            end = pos + size + pad
            if end > len(data):
                raise TarError("truncated", "file data or padding crosses end of input")
            payload = data[pos : pos + size]
            padding = data[pos + size : end]
            if padding != b"\x00" * pad:
                raise TarError("invalid_padding", "data block padding must be zero bytes")

            entries.append(FileEntry(path=path, size=size, digest=sha256(payload).digest()))
            seen.add(path)
            if len(entries) > MAX_FILES:
                raise TarError("too_many_files", f"more than {MAX_FILES} files")
            if sum(e.size for e in entries) > MAX_TOTAL_CONTENT:
                raise TarError("content_too_large", "total file content exceeds 6 MiB")
            pos = end
        except TarError as exc:
            raise exc.with_index(index) from None

    if not entries:
        raise TarError("empty_archive", "archive contains no files")

    tail = data[pos:]
    if any(b != 0 for b in tail):
        raise TarError("trailing_data", "non-zero data after the two terminator blocks")
    return entries


def bundle_digest(entries: list[FileEntry]) -> bytes:
    """SHA-256 over the canonical concatenation of all entries.

    Entries are ordered by the UTF-8 byte sequence of their paths. For each
    entry: 4-byte big-endian path length, path bytes, 8-byte big-endian size,
    32-byte raw SHA-256 content digest.
    """
    h = sha256()
    for e in sorted(entries, key=lambda e: e.path.encode("utf-8")):
        p = e.path.encode("utf-8")
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
        h.update(e.size.to_bytes(8, "big"))
        h.update(e.digest)
    return h.digest()
