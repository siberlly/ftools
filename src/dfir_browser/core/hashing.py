from __future__ import annotations

import hashlib
import time
from pathlib import Path


class HashTimeout(RuntimeError):
    """Raised when hashing a file exceeds the configured time bound."""


def sha256_file(
    path: Path | str,
    timeout_seconds: float,
    chunk_size: int = 4 * 1024 * 1024,
) -> tuple[str, int]:
    """Hash a file with a hard wall-clock bound.

    Returns ``(hexdigest, bytes_hashed)``. The caller is responsible for
    converting :class:`HashTimeout` into its own domain error.
    """
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    deadline = time.monotonic() + float(timeout_seconds)
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
            size += len(chunk)
            if time.monotonic() > deadline:
                raise HashTimeout(
                    f"hashing exceeded the {timeout_seconds:g}s limit"
                )
    return digest.hexdigest(), size
