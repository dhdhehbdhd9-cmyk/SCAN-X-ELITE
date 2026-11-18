"""Bounded in-memory archive inspection; no extraction to disk."""
from __future__ import annotations
from pathlib import Path
from io import BytesIO
import bz2, gzip, tarfile, zipfile
from scanx_app.core.models import Finding

class ArchiveEngine:
    name = "archives"
    def __init__(self, settings: dict):
        scan = settings.get("scan", {})
        self.max_depth = int(scan.get("archive_max_depth", 3))
        self.max_files = int(scan.get("archive_max_files", 2000))
        self.max_member = int(scan.get("archive_max_file_size_mb", 10) * 1024 * 1024)
        self.max_total = int(scan.get("archive_max_total_mb", 100) * 1024 * 1024)
        self.total = 0
        self.count = 0
        self.warnings: list[str] = []

    @staticmethod
    def supported(path: str | Path) -> bool:
        name = str(path).lower()
        return name.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2"))

    def scan(self, path: Path, pattern_engine, virtual_root: str, depth: int = 0):
        if depth > self.max_depth:
            self.warnings.append(f"Archive depth limit reached: {virtual_root}"); return
        try:
            if path.stat().st_size > self.max_total:
                self.warnings.append(f"Archive container size limit reached: {virtual_root}"); return
            lower = path.name.lower()
            if lower.endswith(".zip"):
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.is_dir() or (info.external_attr >> 28) == 0xA: continue
                        if not self._accept(info.filename, info.file_size, virtual_root): continue
                        with archive.open(info) as member:
                            payload = member.read(self.max_member + 1)
                        yield from self._inspect_member(payload, info.filename, pattern_engine, virtual_root, depth)
            elif lower.endswith((".tar", ".tar.gz", ".tgz")):
                with tarfile.open(path, mode="r:*") as archive:
                    for info in archive:
                        if not info.isfile() or not self._accept(info.name, info.size, virtual_root): continue
                        member = archive.extractfile(info)
                        if member is not None:
                            yield from self._inspect_member(member.read(self.max_member + 1), info.name, pattern_engine, virtual_root, depth)
            elif lower.endswith(".gz"):
                with gzip.open(path, "rb") as stream:
                    yield from self._inspect_member(stream.read(self.max_member + 1), path.stem, pattern_engine, virtual_root, depth)
            elif lower.endswith(".bz2"):
                with bz2.open(path, "rb") as stream:
                    yield from self._inspect_member(stream.read(self.max_member + 1), path.stem, pattern_engine, virtual_root, depth)
        except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
            self.warnings.append(f"Unreadable archive skipped: {virtual_root} ({type(exc).__name__})")

    def _scan_container(self, data: bytes, name: str, pattern_engine, virtual_root: str, depth: int):
        lower = name.lower()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir() or (info.external_attr >> 28) == 0xA: continue
                    if not self._accept(info.filename, info.file_size, virtual_root): continue
                    with archive.open(info) as member:
                        payload = member.read(self.max_member + 1)
                    yield from self._inspect_member(payload, info.filename, pattern_engine, virtual_root, depth)
        elif lower.endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(fileobj=BytesIO(data), mode="r:*") as archive:
                for info in archive:
                    if not info.isfile() or not self._accept(info.name, info.size, virtual_root): continue
                    member = archive.extractfile(info)
                    if member is None: continue
                    payload = member.read(self.max_member + 1)
                    yield from self._inspect_member(payload, info.name, pattern_engine, virtual_root, depth)
        elif lower.endswith(".gz"):
            with gzip.GzipFile(fileobj=BytesIO(data)) as stream:
                payload = stream.read(self.max_member + 1)
            yield from self._inspect_member(payload, Path(name).stem, pattern_engine, virtual_root, depth)
        elif lower.endswith(".bz2"):
            with bz2.BZ2File(BytesIO(data)) as stream:
                payload = stream.read(self.max_member + 1)
            yield from self._inspect_member(payload, Path(name).stem, pattern_engine, virtual_root, depth)

    def _accept(self, member_name: str, size: int, root: str) -> bool:
        normalized = member_name.replace("\\", "/")
        if normalized.startswith("/") or any(part == ".." for part in normalized.split("/")):
            self.warnings.append(f"Unsafe archive path rejected: {root}"); return False
        if size > self.max_member:
            self.warnings.append(f"Archive member size limit reached: {root}/{member_name}"); return False
        if self.count >= self.max_files or self.total + size > self.max_total:
            self.warnings.append(f"Archive resource limit reached: {root}"); return False
        self.count += 1; self.total += size
        return True

    def _inspect_member(self, payload: bytes, member_name: str, pattern_engine, virtual_root: str, depth: int):
        if len(payload) > self.max_member:
            self.warnings.append(f"Archive member rejected by size limit: {virtual_root}/{member_name}"); return
        suffix = member_name.lower()
        virtual = f"{virtual_root}!/{member_name}"
        if depth < self.max_depth and self.supported(member_name):
            yield from self._scan_container(payload, member_name, pattern_engine, virtual, depth + 1)
            return
        if b"\x00" in payload: return
        text = payload.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            for finding in pattern_engine.scan_text(virtual, suffix, line, line_no):
                yield finding
