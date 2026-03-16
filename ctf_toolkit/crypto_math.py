"""Number theory and crypto helpers for CTF tasks."""

from __future__ import annotations

import math
import random
from typing import Iterable


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def crt(remainders: Iterable[int], moduli: Iterable[int]) -> tuple[int, int]:
    """Chinese remainder theorem: return (x, M) with x mod M as solution."""
    rs = list(remainders)
    ms = list(moduli)
    if len(rs) != len(ms) or not rs:
        raise ValueError("remainders/moduli mismatch")

    x = 0
    M = 1
    for m in ms:
        M *= m
    for r, m in zip(rs, ms):
        Mi = M // m
        inv = modinv(Mi, m)
        x = (x + r * Mi * inv) % M
    return x, M


def int_nth_root(value: int, n: int) -> tuple[int, bool]:
    """Return (floor_root, exact)."""
    if value < 0 or n <= 0:
        raise ValueError("invalid root arguments")
    if value in (0, 1):
        return value, True

    lo, hi = 0, value
    while lo <= hi:
        mid = (lo + hi) // 2
        p = pow(mid, n)
        if p == value:
            return mid, True
        if p < value:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi, False


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def int_to_bytes(value: int, min_len: int = 0) -> bytes:
    if value < 0:
        raise ValueError("value must be >= 0")
    raw = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    if min_len and len(raw) < min_len:
        return b"\x00" * (min_len - len(raw)) + raw
    return raw


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def fermat_factor(n: int, max_steps: int = 1_000_000) -> tuple[int, int] | None:
    """Try Fermat factorization; effective when p and q are close."""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n:
                return min(p, q), max(p, q)
        a += 1
    return None


def _miller_rabin_round(n: int, d: int, r: int, a: int) -> bool:
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def is_probable_prime(n: int, rounds: int = 10) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        if not _miller_rabin_round(n, d, r, a):
            return False
    return True


def pollard_rho(n: int, max_iters: int = 100_000) -> int | None:
    """Return a non-trivial factor of n, or None if not found quickly."""
    if n % 2 == 0:
        return 2
    if is_probable_prime(n):
        return None

    for _ in range(8):
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1

        for _ in range(max_iters):
            x = (pow(x, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            d = math.gcd(abs(x - y), n)
            if d == 1:
                continue
            if d == n:
                break
            return d
    return None
