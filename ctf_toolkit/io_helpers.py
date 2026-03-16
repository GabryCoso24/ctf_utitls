"""I/O helpers and challenge parsing shortcuts."""

from __future__ import annotations

import pathlib
import re
from typing import Iterable

FLAG_RE = re.compile(r"flag\{[^\n\r\}]{1,512}\}", re.IGNORECASE)


def read_text(path: str | pathlib.Path, encoding: str = "utf-8") -> str:
    return pathlib.Path(path).read_text(encoding=encoding)


def write_text(path: str | pathlib.Path, data: str, encoding: str = "utf-8") -> None:
    pathlib.Path(path).write_text(data, encoding=encoding)


def read_bytes(path: str | pathlib.Path) -> bytes:
    return pathlib.Path(path).read_bytes()


def write_bytes(path: str | pathlib.Path, data: bytes) -> None:
    pathlib.Path(path).write_bytes(data)


def extract_flags(text: str) -> list[str]:
    return FLAG_RE.findall(text)


def grep_lines(text: str, pattern: str, flags: int = 0) -> list[str]:
    rgx = re.compile(pattern, flags)
    return [line for line in text.splitlines() if rgx.search(line)]


def bytes_from_mixed_hex(text: str) -> bytes:
    """Extract all hex byte pairs from noisy text and decode them."""
    parts = re.findall(r"[0-9a-fA-F]{2}", text)
    return bytes.fromhex("".join(parts))


def ints_from_text(text: str) -> list[int]:
    """Extract decimal and 0x-prefixed integers from text."""
    values: list[int] = []
    for token in re.findall(r"0x[0-9a-fA-F]+|\d+", text):
        base = 16 if token.startswith("0x") else 10
        values.append(int(token, base))
    return values


def sliding_window(data: bytes, size: int) -> Iterable[bytes]:
    if size <= 0:
        raise ValueError("size must be > 0")
    for i in range(0, max(len(data) - size + 1, 0)):
        yield data[i : i + size]
