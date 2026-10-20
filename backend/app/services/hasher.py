"""SHA-256 helpers for chain of custody. Files are only ever opened read-only."""
import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: Path, expected: str) -> tuple[bool, str]:
    """Return (matches, recomputed_digest)."""
    actual = sha256_file(path)
    return actual == expected.lower(), actual