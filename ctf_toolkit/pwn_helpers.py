"""Binary exploitation helpers without external dependencies."""

from __future__ import annotations

import struct
from collections import defaultdict


def p8(x: int) -> bytes:
    return struct.pack("<B", x & 0xFF)


def p16(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def p32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def u16(data: bytes) -> int:
    return struct.unpack("<H", data[:2].ljust(2, b"\x00"))[0]


def u32(data: bytes) -> int:
    return struct.unpack("<I", data[:4].ljust(4, b"\x00"))[0]


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data[:8].ljust(8, b"\x00"))[0]


def cyclic(length: int, alphabet: bytes = b"abcdefghijklmnopqrstuvwxyz") -> bytes:
    """Generate a de Bruijn-style pattern useful for crash offset discovery."""
    if length <= 0:
        return b""
    if len(alphabet) < 2:
        raise ValueError("alphabet must contain at least two symbols")

    n = 3
    k = len(alphabet)
    a = [0] * (k * n)
    seq: list[int] = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                seq.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    raw = bytes(alphabet[i] for i in seq)
    out = (raw * ((length // len(raw)) + 1))[:length]
    return out


def cyclic_find(needle: bytes | int, max_len: int = 10000) -> int:
    if isinstance(needle, int):
        needle = p32(needle)
    hay = cyclic(max_len)
    idx = hay.find(needle)
    return idx


def fmt_offsets_probe(start: int = 1, end: int = 40, width: str = "llx") -> str:
    """Build a format string like %1$llx.%2$llx... useful for stack leaks."""
    if start < 1 or end < start:
        raise ValueError("invalid range")
    return ".".join(f"%{i}${width}" for i in range(start, end + 1))


def most_common_qwords(data: bytes, top_k: int = 10) -> list[tuple[int, int]]:
    freq: defaultdict[int, int] = defaultdict(int)
    for i in range(0, len(data) - 7, 8):
        q = u64(data[i : i + 8])
        freq[q] += 1
    return sorted(freq.items(), key=lambda x: x[1], reverse=True)[:top_k]
