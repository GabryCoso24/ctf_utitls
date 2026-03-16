"""Reusable challenge patterns extracted from common CTF scripts.

This module focuses on turning one-off scripts into generic utilities.
"""

from __future__ import annotations

import base64
import gzip
import io
import tarfile
import time
import zlib
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin

import requests


@dataclass(frozen=True)
class DecodeResult:
    decoded: bytes
    layers: list[str]


def normalize_hex_string(s: str) -> str:
    """Normalize noisy hex strings by removing separators and left-padding if needed."""
    cleaned = s.replace(" ", "").replace(":", "").replace("-", "")
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return cleaned


def is_likely_base64(data: bytes, min_len: int = 16) -> bool:
    try:
        stripped = data.strip().replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
        if len(stripped) < min_len or len(stripped) % 4 != 0:
            return False
        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        if any(c not in allowed for c in stripped):
            return False
        decoded = base64.b64decode(stripped)
        return base64.b64encode(decoded) == stripped
    except Exception:
        return False


def auto_decode_layers(data: bytes, max_layers: int = 20) -> DecodeResult:
    """Auto-decode stacked encodings/compressions: gzip, tar, zlib, base64."""
    current = data
    layers: list[str] = []

    for _ in range(max_layers):
        if current.startswith(b"\x1f\x8b"):
            current = gzip.decompress(current)
            layers.append("gzip")
            continue

        if b"ustar" in current[:512]:
            with tarfile.open(fileobj=io.BytesIO(current)) as tar:
                members = tar.getmembers()
                if not members:
                    break
                file_member = next((m for m in members if m.isfile()), members[0])
                extracted = tar.extractfile(file_member)
                if extracted is None:
                    break
                current = extracted.read()
            layers.append("tar")
            continue

        if current.startswith((b"\x78\x9c", b"\x78\xda", b"\x78\x01")):
            current = zlib.decompress(current)
            layers.append("zlib")
            continue

        if is_likely_base64(current):
            current = base64.b64decode(current.strip())
            layers.append("base64")
            continue

        break

    return DecodeResult(decoded=current, layers=layers)


def auto_decode_hex_string(hex_string: str) -> DecodeResult:
    raw = bytes.fromhex(normalize_hex_string(hex_string))
    return auto_decode_layers(raw)


@dataclass(frozen=True)
class ByteRoundOp:
    op: int
    value: int


def glibc_rand_values(seed: int, count: int) -> list[int]:
    """Generate values from libc rand() sequence (Linux/glibc)."""
    import ctypes

    libc = ctypes.CDLL("libc.so.6")
    libc.srand(seed)
    return [int(libc.rand()) for _ in range(count)]


def build_round_ops(
    rounds: int,
    state_len: int,
    *,
    seed: int = 0x1337,
    op_cycle: int = 5,
    use_glibc_rand: bool = True,
) -> list[ByteRoundOp]:
    """Build operation schedule used by ARX-like byte pipelines."""
    if use_glibc_rand:
        rands = glibc_rand_values(seed, rounds)
    else:
        import random

        rng = random.Random(seed)
        rands = [rng.getrandbits(31) for _ in range(rounds)]

    ops: list[ByteRoundOp] = []
    for i, r in enumerate(rands):
        op = i % op_cycle
        value = (r & 0xFF) if op in (0, 1, 2) else (r % state_len)
        ops.append(ByteRoundOp(op=op, value=value))
    return ops


def apply_round_ops(data: bytes, ops: list[ByteRoundOp], inverse: bool = False) -> bytes:
    """
    Apply or invert byte operations.

    Ops semantics (forward):
    - 0: xor each byte with value
    - 1: add value to each byte modulo 256
    - 2: subtract value from each byte modulo 256
    - 3: out[i] = in[(i + value) % N]
    - 4: out[i] = in[(i - value + N) % N]
    """
    state = bytearray(data)
    n = len(state)
    schedule = reversed(ops) if inverse else ops

    for item in schedule:
        op, r = item.op, item.value
        ns = bytearray(n)

        if not inverse:
            if op == 0:
                for i in range(n):
                    ns[i] = state[i] ^ r
            elif op == 1:
                for i in range(n):
                    ns[i] = (state[i] + r) & 0xFF
            elif op == 2:
                for i in range(n):
                    ns[i] = (state[i] - r) & 0xFF
            elif op == 3:
                for i in range(n):
                    ns[i] = state[(i + r) % n]
            elif op == 4:
                for i in range(n):
                    ns[i] = state[(i - r + n) % n]
            else:
                raise ValueError(f"unsupported op: {op}")
        else:
            if op == 0:
                for i in range(n):
                    ns[i] = state[i] ^ r
            elif op == 1:
                for i in range(n):
                    ns[i] = (state[i] - r) & 0xFF
            elif op == 2:
                for i in range(n):
                    ns[i] = (state[i] + r) & 0xFF
            elif op == 3:
                for i in range(n):
                    ns[i] = state[(i - r + n) % n]
            elif op == 4:
                for i in range(n):
                    ns[i] = state[(i + r) % n]
            else:
                raise ValueError(f"unsupported op: {op}")

        state = ns

    return bytes(state)


def invert_round_ops_from_hex(target_hex: str, ops: list[ByteRoundOp]) -> str:
    state = bytes.fromhex(normalize_hex_string(target_hex))
    return apply_round_ops(state, ops, inverse=True).hex()


class SQLiApiClient:
    """Generic JSON SQLi client with optional anti-CSRF token refresh."""

    def __init__(
        self,
        host: str,
        *,
        api_prefix: str = "/api/",
        token_endpoint: str = "get_token",
        token_field: str = "token",
        csrf_header: str = "X-CSRFToken",
        query_field: str = "query",
    ):
        self.base_url = host.rstrip("/") + "/" + api_prefix.strip("/") + "/"
        self.token_endpoint = token_endpoint
        self.token_field = token_field
        self.csrf_header = csrf_header
        self.query_field = query_field
        self.session = requests.Session()
        self.token: str | None = None
        self.refresh_token()

    def refresh_token(self) -> str | None:
        try:
            resp = self.session.get(urljoin(self.base_url, self.token_endpoint), timeout=8)
            data = resp.json()
            self.token = data.get(self.token_field)
        except Exception:
            self.token = None
        return self.token

    def request(self, endpoint: str, query: str) -> tuple[str | None, str | None, dict]:
        headers = {self.csrf_header: self.token} if self.token else {}
        payload = {self.query_field: query}
        url = urljoin(self.base_url, endpoint)
        data = self.session.post(url, json=payload, headers=headers, timeout=12).json()
        return data.get("result"), data.get("sql_error"), data

    def logic(self, query: str) -> tuple[str | None, str | None, dict]:
        return self.request("logic", query)

    def union(self, query: str) -> tuple[str | None, str | None, dict]:
        return self.request("union", query)

    def blind(self, query: str) -> tuple[str | None, str | None, dict]:
        return self.request("blind", query)

    def time(self, query: str) -> tuple[str | None, str | None, dict]:
        return self.request("time", query)


def extract_with_oracle(
    *,
    alphabet: str,
    is_valid_prefix: Callable[[str], bool],
    prefix: str = "",
    max_len: int = 256,
    stop_char: str | None = None,
) -> str:
    """Generic prefix extraction loop for blind/time-based challenges."""
    out = prefix
    for _ in range(max_len):
        found = False
        for ch in alphabet:
            cand = out + ch
            if is_valid_prefix(cand):
                out = cand
                found = True
                if stop_char and out.endswith(stop_char):
                    return out
                break
        if not found:
            break
    return out


def timed_oracle(send_probe: Callable[[str], None], threshold: float) -> Callable[[str], bool]:
    """Create a boolean oracle from response time threshold logic."""

    def _probe(candidate: str) -> bool:
        start = time.time()
        send_probe(candidate)
        elapsed = time.time() - start
        return elapsed >= threshold

    return _probe


def default_numeric_ocr(image_bytes: bytes) -> str:
    """Read numeric captcha text from image bytes using Pillow + Tesseract."""
    try:
        from PIL import Image  # type: ignore
        import pytesseract  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Pillow + pytesseract are required for OCR helpers. Install: pip install pillow pytesseract"
        ) from exc

    import re

    img = Image.open(io.BytesIO(image_bytes)).convert("L")
    text = pytesseract.image_to_string(img, config="--psm 7")
    return re.sub(r"\D", "", text)


def solve_numeric_captcha_loop(
    base_url: str,
    *,
    next_path: str = "/next",
    answer_field: str = "risposta",
    image_src_regex: str = r'<img src="([^"]+)"',
    success_regex: str = r"flag\{",
    max_steps: int = 200,
    ocr_reader: Callable[[bytes], str] | None = None,
    session: requests.Session | None = None,
) -> dict:
    """Solve iterative numeric captcha pages via OCR.

    Returns a dict with final html and step logs.
    """
    import re

    s = session or requests.Session()
    ocr = ocr_reader or default_numeric_ocr

    resp = s.get(base_url, timeout=12)
    html = resp.text
    logs: list[dict] = []

    for i in range(max_steps):
        if re.search(success_regex, html, flags=re.IGNORECASE):
            return {"success": True, "step": i, "html": html, "logs": logs}

        m = re.search(image_src_regex, html)
        if not m:
            return {
                "success": False,
                "step": i,
                "html": html,
                "error": "captcha image not found",
                "logs": logs,
            }

        img_url = urljoin(base_url.rstrip("/") + "/", m.group(1))
        img_bytes = s.get(img_url, timeout=12).content
        answer = ocr(img_bytes)

        post_url = urljoin(base_url.rstrip("/") + "/", next_path.lstrip("/"))
        resp = s.post(post_url, data={answer_field: answer}, timeout=12)
        html = resp.text

        logs.append({"step": i, "img_url": img_url, "answer": answer})

    return {"success": False, "step": max_steps, "html": html, "logs": logs}
