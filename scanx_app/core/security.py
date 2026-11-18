"""Security helpers and invariants for future scanning engines."""
from __future__ import annotations
import hashlib
import hmac
import html
import os
import re
from pathlib import Path

def ensure_private_directory(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        # Some Android/shared filesystems do not support POSIX permissions.
        pass
    return directory

def fingerprint_secret(value: str, *, salt: bytes) -> str:
    """Create a keyed fingerprint; caller must keep salt local and ephemeral."""
    return hmac.new(salt, value.encode("utf-8", errors="replace"), hashlib.sha256).hexdigest()

def redact(value: str, visible: int = 0) -> str:
    if not value:
        return "[EMPTY]"
    if visible <= 0:
        return "[REDACTED]"
    return value[:visible] + "…" + ("*" * min(max(len(value) - visible, 4), 24))

def safe_html(value: object) -> str:
    return html.escape(str(value), quote=True)

def safe_relative_path(value: str) -> str:
    """Normalize a report path without allowing traversal outside report roots."""
    normalized = value.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError("Path traversal is not allowed.")
    return "/".join(parts)

def is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample
