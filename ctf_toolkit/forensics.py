"""Forensics and binary-file helpers for misc/network challenges."""

from __future__ import annotations

import math
import re


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
ZIP_MAGIC = b"PK\x03\x04"
ELF_MAGIC = b"\x7fELF"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    rgx = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.decode(errors="ignore") for m in rgx.findall(data)]


def has_magic(data: bytes, magic: bytes, offset: int = 0) -> bool:
    return data[offset : offset + len(magic)] == magic


def detect_common_filetype(data: bytes) -> str | None:
    if has_magic(data, PNG_MAGIC):
        return "png"
    if has_magic(data, ZIP_MAGIC):
        return "zip"
    if has_magic(data, ELF_MAGIC):
        return "elf"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    return None


def xor_bruteforce_header(data: bytes, expected_magic: bytes, keyspace: range = range(256)) -> list[tuple[int, bytes]]:
    """Find single-byte XOR keys that produce a known header."""
    out: list[tuple[int, bytes]] = []
    n = len(expected_magic)
    sample = data[:n]
    for k in keyspace:
        dec = bytes(b ^ k for b in sample)
        if dec == expected_magic:
            out.append((k, bytes(b ^ k for b in data)))
    return out
