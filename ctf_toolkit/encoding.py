"""Encoding and byte-level helpers for CTF challenges."""

from __future__ import annotations

import base64
import string
from typing import Iterable


def hex_to_bytes(data: str) -> bytes:
    """Decode a hex string into bytes, tolerating spaces and 0x prefixes."""
    cleaned = data.lower().replace("0x", "").replace(" ", "").replace("\n", "")
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def bytes_to_hex(data: bytes, upper: bool = False) -> str:
    out = data.hex()
    return out.upper() if upper else out


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def b32e(data: bytes) -> str:
    return base64.b32encode(data).decode()


def b32d(data: str) -> bytes:
    return base64.b32decode(data)


def b85e(data: bytes) -> str:
    return base64.b85encode(data).decode()


def b85d(data: str) -> bytes:
    return base64.b85decode(data)


def rot_n(text: str, n: int = 13, alphabet: str = string.ascii_lowercase) -> str:
    """Apply rotation over an alphabet (lower/upper preserved when possible)."""
    m = len(alphabet)
    idx = {ch: i for i, ch in enumerate(alphabet)}
    out: list[str] = []
    for ch in text:
        low = ch.lower()
        if low in idx:
            mapped = alphabet[(idx[low] + n) % m]
            out.append(mapped.upper() if ch.isupper() else mapped)
        else:
            out.append(ch)
    return "".join(out)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("hamming_distance requires equal-length inputs")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def chunked(data: bytes, n: int) -> list[bytes]:
    if n <= 0:
        raise ValueError("n must be > 0")
    return [data[i : i + n] for i in range(0, len(data), n)]


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = set(bytes(string.printable, "ascii"))
    good = sum(b in printable for b in data)
    return good / len(data)


def _english_score(data: bytes) -> float:
    freq = b" etaoinshrdlucmfwypvbgkqjxzETAOINSHRDLU"
    score = 0.0
    for b in data:
        if b in freq:
            score += 2.0
        if 32 <= b <= 126:
            score += 0.5
        if b in (9, 10, 13):
            score += 0.2
    return score


def single_byte_xor_bruteforce(ciphertext: bytes) -> tuple[int, bytes, float]:
    """Return best (key, plaintext, score) for single-byte XOR."""
    best_key = 0
    best_plain = b""
    best_score = float("-inf")
    for key in range(256):
        plain = bytes(c ^ key for c in ciphertext)
        score = _english_score(plain)
        if score > best_score:
            best_key, best_plain, best_score = key, plain, score
    return best_key, best_plain, best_score


def repeating_key_xor_keysize_guess(data: bytes, min_k: int = 2, max_k: int = 40) -> list[tuple[int, float]]:
    """Rank candidate key sizes by normalized Hamming distance."""
    scores: list[tuple[int, float]] = []
    for k in range(min_k, max_k + 1):
        blocks = [data[i : i + k] for i in range(0, k * 4, k)]
        if len(blocks) < 4 or len(blocks[-1]) != k:
            continue
        pairs = [(blocks[0], blocks[1]), (blocks[1], blocks[2]), (blocks[2], blocks[3])]
        dist = sum(hamming_distance(x, y) / k for x, y in pairs) / len(pairs)
        scores.append((k, dist))
    return sorted(scores, key=lambda t: t[1])


def transpose_blocks(blocks: Iterable[bytes]) -> list[bytes]:
    blocks = list(blocks)
    if not blocks:
        return []
    max_len = max(len(b) for b in blocks)
    out: list[bytes] = []
    for i in range(max_len):
        out.append(bytes(b[i] for b in blocks if i < len(b)))
    return out
