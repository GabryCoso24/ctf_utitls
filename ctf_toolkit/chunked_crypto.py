"""Helpers for chunked AES-CBC file encryption/decryption workflows."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Callable


KeyDeriver = Callable[[str], bytes]


def _require_pycryptodome() -> tuple[object, object, object]:
    try:
        from Crypto.Cipher import AES  # type: ignore
        from Crypto.Util.Padding import pad, unpad  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "PyCryptodome is required for chunked AES helpers. Install with: pip install pycryptodome"
        ) from exc
    return AES, pad, unpad


def sha256_basename_key(base_name: str) -> bytes:
    """Derive a 32-byte key from basename using SHA-256."""
    return sha256(base_name.encode()).digest()


@dataclass(frozen=True)
class ChunkFile:
    index: int
    path: Path


def list_chunk_files(enc_folder: str | Path, suffix: str = ".enc") -> dict[str, list[ChunkFile]]:
    """Group chunk files by basename: '<base>_<index>.enc'."""
    folder = Path(enc_folder)
    grouped: dict[str, list[ChunkFile]] = {}

    for path in folder.iterdir():
        if not path.is_file() or not path.name.endswith(suffix):
            continue
        try:
            base, idx_ext = path.name.rsplit("_", 1)
            idx = int(idx_ext.split(".", 1)[0])
        except (ValueError, IndexError):
            continue
        grouped.setdefault(base, []).append(ChunkFile(index=idx, path=path))

    for base in grouped:
        grouped[base].sort(key=lambda c: c.index)
    return grouped


def decrypt_chunked_aes_cbc_folder(
    enc_folder: str | Path,
    output_folder: str | Path,
    *,
    key_deriver: KeyDeriver = sha256_basename_key,
    iv: bytes = b"\x00" * 16,
) -> list[Path]:
    """
    Decrypt all grouped chunks in a folder and write reconstructed files.

    Expected chunk naming: '<base>_<index>.enc'.
    Each chunk is decrypted with AES-CBC + PKCS#7 unpad using key_deriver(base).
    """
    AES, _, unpad = _require_pycryptodome()

    enc_dir = Path(enc_folder)
    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)

    grouped = list_chunk_files(enc_dir)
    written: list[Path] = []

    for base, chunks in grouped.items():
        key = key_deriver(base)
        plain_parts: list[bytes] = []

        for chunk in chunks:
            enc_data = chunk.path.read_bytes()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            dec = unpad(cipher.decrypt(enc_data), AES.block_size)
            plain_parts.append(dec)

        output_path = out_dir / base
        output_path.write_bytes(b"".join(plain_parts))
        written.append(output_path)

    return written


def encrypt_chunked_aes_cbc(
    data: bytes,
    base_name: str,
    *,
    chunk_size: int = 4096,
    key_deriver: KeyDeriver = sha256_basename_key,
    iv: bytes = b"\x00" * 16,
) -> list[tuple[int, bytes]]:
    """Encrypt bytes into indexed AES-CBC chunks compatible with the decrypt helper."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")

    AES, pad, _ = _require_pycryptodome()
    key = key_deriver(base_name)

    out: list[tuple[int, bytes]] = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(pad(chunk, AES.block_size))
        out.append((i // chunk_size, enc))
    return out


def write_encrypted_chunks(
    chunks: list[tuple[int, bytes]],
    output_folder: str | Path,
    base_name: str,
    suffix: str = ".enc",
) -> list[Path]:
    """Write encrypted chunks to disk as '<base>_<idx>.enc'."""
    out_dir = Path(output_folder)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths: list[Path] = []
    for idx, payload in chunks:
        path = out_dir / f"{base_name}_{idx:02d}{suffix}"
        path.write_bytes(payload)
        paths.append(path)
    return paths
