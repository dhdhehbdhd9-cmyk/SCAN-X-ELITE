"""Safe recursive filesystem discovery for Phase 2."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
from scanx_app.core.security import is_probably_binary

@dataclass(frozen=True)
class FileCandidate:
    path: Path
    relative_path: str
    size: int
    is_binary: bool = False

class FilesystemEngine:
    name = "filesystem"
    def __init__(self, settings: dict):
        scan = settings.get("scan", {})
        self.max_size = int(scan.get("max_file_size_mb", 25) * 1024 * 1024)
        self.max_files = int(scan.get("max_files", 100000))
        self.max_depth = int(scan.get("max_depth", 50))
        self.chunk_size = int(scan.get("read_chunk_size", 65536))
        self.follow_symlinks = bool(scan.get("follow_symlinks", False))
        self.excluded_dirs = set(scan.get("excluded_directories", []))
        self.excluded_ext = {str(x).lower() for x in settings.get("exclusions", {}).get("exclude_extensions", [])}
        self.excluded_paths = {str(x).replace("\\", "/").strip("/") for x in settings.get("exclusions", {}).get("exclude_paths", [])}
        self.skipped = 0
        self.errors: list[str] = []

    def discover(self, root: str | Path):
        root = Path(root).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"Scan target is not a directory: {root}")
        count = 0
        for current, dirs, files in os.walk(root, topdown=True, followlinks=self.follow_symlinks):
            current_path = Path(current)
            try:
                depth = len(current_path.relative_to(root).parts)
            except ValueError:
                dirs[:] = []
                continue
            if depth >= self.max_depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs and (self.follow_symlinks or not (current_path / d).is_symlink())]
            for filename in files:
                if count >= self.max_files:
                    self.skipped += 1
                    return
                path = current_path / filename
                try:
                    if path.is_symlink() and not self.follow_symlinks:
                        self.skipped += 1; continue
                    resolved = path.resolve()
                    if root not in resolved.parents and resolved != root:
                        self.skipped += 1; continue
                    rel = path.relative_to(root).as_posix()
                    if rel in self.excluded_paths or any(rel.startswith(p + "/") for p in self.excluded_paths):
                        self.skipped += 1; continue
                    size = path.stat().st_size
                    if size > self.max_size or path.suffix.lower() in self.excluded_ext:
                        self.skipped += 1; continue
                    with path.open("rb") as handle:
                        sample = handle.read(min(self.chunk_size, 8192))
                    binary = is_probably_binary(sample)
                    count += 1
                    yield FileCandidate(path, rel, size, binary)
                except (OSError, UnicodeError) as exc:
                    self.errors.append(f"Unreadable file skipped: {path.name} ({type(exc).__name__})")

    def read_lines(self, candidate: FileCandidate):
        if candidate.is_binary:
            return
        try:
            with candidate.path.open("r", encoding="utf-8", errors="replace") as handle:
                for number, line in enumerate(handle, 1):
                    yield number, line.rstrip("\n\r")
        except OSError as exc:
            self.errors.append(f"Unable to read file: {candidate.relative_path} ({type(exc).__name__})")
