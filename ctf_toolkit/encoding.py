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


# ============================================================================
# Auto-Decrypt and Encryption Detection System
# ============================================================================

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class DecryptionResult:
    """Result from an attempt to decrypt data."""
    plaintext: bytes
    method: str
    key: bytes | str | None
    confidence: float
    readable_text: str | None = None
    
    def __str__(self) -> str:
        text = self.readable_text or self.plaintext.decode("utf-8", errors="replace")
        return f"[{self.method}] (conf: {self.confidence:.2%})\n  Key: {self.key}\n  Text: {text[:100]}"


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 to 8.0 for bytes)."""
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_likely_encrypted(data: bytes, plaintext_threshold: float = 0.65) -> bool:
    """Detect if data appears to be encrypted based on printable ratio and randomness."""
    if not data:
        return False
    
    printable_pct = printable_ratio(data)
    
    # If highly printable, probably not encrypted
    if printable_pct > plaintext_threshold:
        return False
    
    # If very low entropy, likely plain/compressed
    entropy = _entropy(data)
    if entropy < 3.0:
        return False
    
    # High entropy + low printable = likely encrypted/compressed
    return entropy > 5.5 and printable_pct < 0.4


def _detect_encryption_type(data: bytes) -> list[str]:
    """Detect likely encryption types based on data characteristics."""
    methods = []
    
    # Check for single-byte XOR (very common in CTF)
    if len(data) > 4 and _entropy(data) > 4.5:
        methods.append("single_byte_xor")
    
    # Check for repeating-key XOR (IC analysis)
    if len(data) > 40:
        methods.append("repeating_xor")
    
    # Always try Caesar/ROT variants
    methods.append("caesar")
    
    # Check for null bytes (might indicate XOR with 0x00)
    if b"\x00" in data[:min(100, len(data))]:
        methods.append("xor_null")
    
    return methods


def auto_decrypt_hex(hex_string: str, top_n: int = 5) -> list[DecryptionResult]:
    """
    Automatically detect and decrypt a hex string without a provided key.
    
    Args:
        hex_string: Hex-encoded string (e.g., "48656c6c6f" or "48 65 6c 6c 6f")
        top_n: Return top N decryption attempts ranked by confidence
    
    Returns:
        List of DecryptionResult sorted by confidence (highest first)
    """
    try:
        data = hex_to_bytes(hex_string)
    except Exception:
        raise ValueError("Invalid hex string format")
    
    if not data:
        raise ValueError("Hex string decoded to empty bytes")
    
    results: list[DecryptionResult] = []
    
    # Check if already plaintext
    readable = printable_ratio(data)
    if readable > 0.85:
        results.append(
            DecryptionResult(
                plaintext=data,
                method="plaintext",
                key=None,
                confidence=readable,
                readable_text=_safe_decode(data)
            )
        )
    
    # Always try single-byte XOR (most common in CTF)
    key, plain, score = single_byte_xor_bruteforce(data)
    readable_score = printable_ratio(plain)
    
    # English score is more reliable than just printable ratio
    if score > 10.0 and readable_score > 0.5:
        results.append(
            DecryptionResult(
                plaintext=plain,
                method="single_byte_xor",
                key=f"0x{key:02x}",
                confidence=readable_score,
                readable_text=_safe_decode(plain)
            )
        )
    
    # Detect likely encryption type for more attempts
    is_encrypted = _is_likely_encrypted(data)
    methods = _detect_encryption_type(data)
    
    # Try repeating XOR if data is long enough
    if len(data) > 40 or (is_encrypted and len(data) > 20):
        keysize_guesses = repeating_key_xor_keysize_guess(data, min_k=2, max_k=min(32, len(data) // 4))
        for keysize, _ in keysize_guesses[:2]:  # Try top 2 keysizes
            # Sample key patterns
            for key_pattern in range(1, 256):
                key = bytes([key_pattern] * keysize)
                plain = xor_with_key(data, key)
                readable_score = printable_ratio(plain)
                
                if readable_score > 0.65:
                    results.append(
                        DecryptionResult(
                            plaintext=plain,
                            method=f"repeating_xor_k{keysize}",
                            key=bytes_to_hex(key),
                            confidence=readable_score,
                            readable_text=_safe_decode(plain)
                        )
                    )
    
    # Try Caesar shifts on text data
    try:
        text_attempt = data.decode("utf-8", errors="ignore")
        if printable_ratio(data) > 0.6 and len(text_attempt) > 3:
            for shift in range(1, 26):
                plain_str = rot_n(text_attempt, shift)
                plain_bytes = plain_str.encode("utf-8")
                readable_score = printable_ratio(plain_bytes)
                english_score = _english_score(plain_bytes)
                
                if readable_score > 0.7 and english_score > 5:
                    results.append(
                        DecryptionResult(
                            plaintext=plain_bytes,
                            method=f"caesar_rot{shift}",
                            key=shift,
                            confidence=readable_score,
                            readable_text=plain_str
                        )
                    )
    except Exception:
        pass
    
    # Try common XOR masks
    for xor_key in [0xFF, 0xAA, 0x55, 0x01, 0x7F, 0x80]:
        plain = bytes(b ^ xor_key for b in data)
        readable_score = printable_ratio(plain)
        
        if readable_score > 0.65:
            results.append(
                DecryptionResult(
                    plaintext=plain,
                    method=f"xor_mask_0x{xor_key:02x}",
                    key=f"0x{xor_key:02x}",
                    confidence=readable_score,
                    readable_text=_safe_decode(plain)
                )
            )
    
    # Sort by confidence (descending)
    results.sort(key=lambda r: r.confidence, reverse=True)
    
    # Remove duplicates (same plaintext)
    seen_plain = set()
    unique_results = []
    for r in results:
        if r.plaintext not in seen_plain:
            unique_results.append(r)
            seen_plain.add(r.plaintext)
    
    return unique_results[:top_n]


def detect_hex_encryption(hex_string: str) -> dict[str, float | bool | str]:
    """
    Analyze a hex string to determine if it's encrypted.
    
    Returns dict with keys:
        - is_encrypted: bool
        - entropy: float (0-8)
        - printable_ratio: float (0-1)
        - likely_methods: list[str]
        - confidence: float (0-1)
    """
    try:
        data = hex_to_bytes(hex_string)
    except Exception:
        raise ValueError("Invalid hex string format")
    
    entropy = _entropy(data)
    printable = printable_ratio(data)
    is_encrypted = _is_likely_encrypted(data)
    methods = _detect_encryption_type(data) if is_encrypted else []
    
    # Confidence in encryption detection
    conf = 0.0
    if is_encrypted:
        conf = min(0.95, (entropy / 8.0) * 0.6 + (1 - printable) * 0.4)
    else:
        conf = min(0.95, printable * 0.7)
    
    return {
        "is_encrypted": is_encrypted,
        "entropy": entropy,
        "printable_ratio": printable,
        "likely_methods": methods,
        "confidence": conf,
        "plaintext_confidence": 1.0 - conf if conf < 0.5 else conf
    }


def _safe_decode(data: bytes, max_len: int | None = None) -> str:
    """Safely decode bytes to string, handling encoding errors."""
    if max_len:
        data = data[:max_len]
    return data.decode("utf-8", errors="replace")
