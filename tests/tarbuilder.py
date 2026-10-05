"""Byte-level USTAR archive builder used by tests."""

from __future__ import annotations

BLOCK = 512


def _octal(value: int, width: int) -> bytes:
    # POSIX.1-1988 canonical form: zero-padded octal digits, NUL terminator,
    # e.g. width 12 -> b"00000000000\x00" (11 digits).
    body = format(value, "0{}o".format(width - 1)).encode("ascii")
    return body + b"\x00"


def build_header(
    name: bytes,
    size: int,
    *,
    typeflag: bytes = b"0",
    prefix: bytes = b"",
    linkname: bytes = b"",
    mode: int = 0o644,
    uid: int = 0,
    gid: int = 0,
    mtime: int = 0,
    magic: bytes = b"ustar\x00",
    version: bytes = b"00",
    uname: bytes = b"",
    gname: bytes = b"",
    checksum: int | None = None,
    bad_checksum: bool = False,
) -> bytes:
    h = bytearray(BLOCK)

    def put(off: int, field: bytes, width: int) -> None:
        if len(field) > width:
            raise ValueError(f"field too long ({len(field)} > {width})")
        h[off : off + len(field)] = field

    put(0, name, 100)
    put(100, _octal(mode, 8), 8)
    put(108, _octal(uid, 8), 8)
    put(116, _octal(gid, 8), 8)
    put(124, _octal(size, 12), 12)
    put(136, _octal(mtime, 12), 12)
    # checksum placeholder: spaces
    h[148:156] = b"        "
    h[156:157] = typeflag
    put(157, linkname, 100)
    h[257:263] = magic
    h[263:265] = version
    put(265, uname, 32)
    put(297, gname, 32)
    put(329, _octal(0, 8), 8)  # devmajor
    put(337, _octal(0, 8), 8)  # devminor
    put(345, prefix, 155)

    if bad_checksum:
        h[148:156] = b"000000\x00 "
    else:
        value = sum(h) if checksum is None else checksum
        h[148:156] = format(value, "06o").encode("ascii") + b"\x00 "
    return bytes(h)


def file_block(name: str | bytes, payload: bytes, *, prefix: bytes = b"", **kw) -> bytes:
    name_b = name if isinstance(name, bytes) else name.encode("utf-8")
    h = build_header(name_b, len(payload), prefix=prefix, **kw)
    pad = -len(payload) % BLOCK
    return h + payload + b"\x00" * pad


def archive(*blocks: bytes, terminator: bytes | None = b"\x00" * BLOCK * 2) -> bytes:
    out = b"".join(blocks)
    if terminator is not None:
        out += terminator
    return out
