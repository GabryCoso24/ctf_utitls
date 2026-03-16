"""Networking helpers for socket-based and packet-text challenges."""

from __future__ import annotations

import re
import socket
from typing import Iterable


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 2.0, max_bytes: int = 1_000_000) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data and len(data) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def recv_all(sock: socket.socket, timeout: float = 1.0, chunk_size: int = 4096) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(chunk_size)
        except TimeoutError:
            break
        except socket.timeout:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def tcp_request(host: str, port: int, payload: bytes, timeout: float = 2.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        return recv_all(s, timeout=timeout)


def udp_request(host: str, port: int, payload: bytes, timeout: float = 2.0, recv_size: int = 65535) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        resp, _ = s.recvfrom(recv_size)
        return resp


def parse_dns_qnames_from_text(text: str) -> list[str]:
    """Extract DNS query names from tshark/wireshark text exports."""
    out: list[str] = []
    patterns = [
        r"Queries\s*\n\s*([A-Za-z0-9._-]+)\s*: type",
        r"\b([A-Za-z0-9._-]+)\s*type\s*A",
        r"query:\s*([A-Za-z0-9._-]+)",
    ]
    for p in patterns:
        out.extend(re.findall(p, text, flags=re.IGNORECASE | re.MULTILINE))
    return out


def reassemble_subdomain_hex(labels: Iterable[str], domain_suffix: str | None = None) -> bytes:
    """Reassemble hex chunks hidden in DNS labels like <hex>.attacker.eve."""
    chunks: list[str] = []
    for label in labels:
        q = label.strip().rstrip(".")
        if domain_suffix and q.endswith(domain_suffix.rstrip(".")):
            q = q[: -len(domain_suffix.rstrip("."))].rstrip(".")
        first = q.split(".")[0]
        if re.fullmatch(r"[0-9a-fA-F]+", first):
            chunks.append(first)
    return bytes.fromhex("".join(chunks)) if chunks else b""
