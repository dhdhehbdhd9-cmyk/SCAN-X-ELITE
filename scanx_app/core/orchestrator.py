"""Phase 2/3 scan orchestration with isolated engine failures."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone
import hashlib, re, shutil, subprocess, tempfile
from scanx_app.core.models import ScanRequest, ScanResult
from scanx_app.core.exceptions import TargetError
from scanx_app.core.settings import load_settings, default_rules_path
from scanx_app.engines.filesystem import FilesystemEngine
from scanx_app.engines.patterns import PatternEngine, load_rules
from scanx_app.engines.archive import ArchiveEngine
from scanx_app.engines.gitleaks import GitleaksEngine
from scanx_app.engines.git_history import GitHistoryEngine

_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?/?$"
)


def _clone_github_url(url: str, timeout: int) -> tuple[Path, "tempfile.TemporaryDirectory"]:
    """Clone a public GitHub repo (all branches/tags) into a temp dir.

    Caller owns the returned TemporaryDirectory and must keep a reference
    to it until scanning is done; it self-deletes when garbage collected
    or when the caller calls .cleanup().
    """
    if not _GITHUB_URL_RE.match(url):
        raise TargetError("Only HTTPS github.com repository URLs are accepted.")
    if shutil.which("git") is None:
        raise TargetError("git is not installed; cannot clone GitHub URLs.")
    holder = tempfile.TemporaryDirectory(prefix="scanx-clone-")
    dest = Path(holder.name) / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--quiet", url, str(dest)],
            capture_output=True, text=True, timeout=timeout, check=True,
        )
        fetched = subprocess.run(
            ["git", "-C", str(dest), "fetch", "--quiet", "--all", "--tags"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if fetched.returncode != 0:
            raise TargetError("Repository cloned, but fetching all refs failed; scan was not started.")
    except subprocess.CalledProcessError as exc:
        holder.cleanup()
        raise TargetError(f"Clone failed: {(exc.stderr or '').strip()[:200]}") from exc
    except subprocess.TimeoutExpired as exc:
        holder.cleanup()
        raise TargetError("Clone timed out.") from exc
    return dest, holder

@dataclass
class PreparedScan:
    project_name: str
    target_kind: str
    deep_history: bool
    report_format: str
    output_dir: str

class ScanOrchestrator:
    def prepare(self, request: ScanRequest) -> PreparedScan:
        if request.target_kind == "local_directory":
            target = Path(request.target).expanduser().resolve()
            if not target.is_dir(): raise TargetError(f"Directory does not exist: {target}")
            project_name = target.name or str(target)
        elif request.target_kind == "github_url":
            parsed = urlparse(request.target)
            if parsed.scheme != "https" or parsed.netloc.lower() != "github.com": raise TargetError("Only HTTPS github.com URLs are accepted.")
            project_name = parsed.path.strip("/").removesuffix(".git").split("/")[-1]
            if not project_name: raise TargetError("GitHub repository URL is incomplete.")
        else: raise TargetError(f"Unsupported target type: {request.target_kind}")
        if request.report_format not in {"html", "json", "all"}: raise TargetError("Unsupported report format.")
        return PreparedScan(project_name, request.target_kind, request.deep_history, request.report_format, request.output_dir)

    def scan(self, request: ScanRequest) -> ScanResult:
        settings = load_settings()
        clone_holder = None
        if request.target_kind == "github_url":
            if not settings.get("github", {}).get("enabled", True):
                raise TargetError("GitHub URL scanning is disabled in settings.yaml.")
            timeout = int(settings.get("github", {}).get("clone_timeout_seconds", 180))
            root, clone_holder = _clone_github_url(request.target, timeout)
        elif request.target_kind == "local_directory":
            root = Path(request.target).expanduser().resolve()
            if not root.is_dir(): raise TargetError(f"Directory does not exist: {root}")
        else:
            raise TargetError(f"Unsupported target type: {request.target_kind}")
        try:
            return self._scan_root(request, settings, root)
        finally:
            if clone_holder is not None:
                clone_holder.cleanup()

    def _scan_root(self, request: ScanRequest, settings: dict, root: Path) -> ScanResult:
        exclusions_path = root.parent / "__never__"
        try:
            import yaml
            config_exclusions = Path(__file__).resolve().parents[2] / "config" / "exclusions.yaml"
            if config_exclusions.exists(): settings["exclusions"] = yaml.safe_load(config_exclusions.read_text()) or {}
        except Exception: settings["exclusions"] = {}
        result = ScanResult(hashlib.sha256(f"{root}:{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:16], str(root), "completed")
        if request.max_file_size_mb is not None:
            settings.setdefault("scan", {})["max_file_size_mb"] = request.max_file_size_mb
        fs = FilesystemEngine(settings)
        candidates = list(fs.discover(root))
        result.coverage.update({"files_discovered": len(candidates), "files_skipped": fs.skipped, "bytes_discovered": sum(c.size for c in candidates)})
        result.engine_status["filesystem"] = "completed" if not fs.errors else "completed_with_warnings"
        result.warnings.extend(fs.errors)
        pattern = PatternEngine([])
        if settings.get("engines", {}).get("patterns", True):
            try:
                rules = load_rules(default_rules_path())
                pattern = PatternEngine(rules)
                for candidate in candidates:
                    result.findings.extend(pattern.scan_candidate(candidate, fs))
                result.engine_status["patterns"] = f"completed ({len(rules)} rules)"
            except Exception as exc:
                result.engine_status["patterns"] = "failed"; result.errors.append(f"Pattern engine failed: {type(exc).__name__}")
        else:
            result.engine_status["patterns"] = "disabled"
        if request.scan_archives or settings.get("engines", {}).get("archives", False):
            archive = ArchiveEngine(settings)
            for candidate in candidates:
                if ArchiveEngine.supported(candidate.path):
                    result.findings.extend(archive.scan(candidate.path, pattern, candidate.relative_path))
            result.warnings.extend(archive.warnings); result.engine_status["archives"] = "completed" if not archive.warnings else "completed_with_warnings"
        else: result.engine_status["archives"] = "disabled"
        if request.use_gitleaks and settings.get("engines", {}).get("gitleaks", True):
            engine = GitleaksEngine(int(settings.get("engines", {}).get("gitleaks_timeout_seconds", 120)))
            findings, status, warning = engine.scan(root)
            result.findings.extend(findings); result.engine_status["gitleaks"] = status
            if warning: result.warnings.append(warning)
        else: result.engine_status["gitleaks"] = "disabled"
        if request.deep_history and settings.get("engines", {}).get("git_history", True):
            history = GitHistoryEngine(settings)
            findings, status, warning = history.scan(root, pattern)
            result.findings.extend(findings); result.engine_status["git_history"] = status
            if warning: result.warnings.append(warning)
        else: result.engine_status["git_history"] = "disabled"
        self._aggregate_history(result)
        result.coverage["findings"] = len(result.findings)
        result.coverage["history_findings"] = sum(1 for f in result.findings if "history" in f.tags)
        if result.errors:
            result.status = "partial_failure"
        elif result.warnings or any(v in {"unavailable", "skipped", "completed_with_warnings"} for v in result.engine_status.values()):
            result.status = "completed_with_warnings"
        return result

    @staticmethod
    def _aggregate_history(result: ScanResult):
        """Keep one metadata record per historical fingerprint and expose its range."""
        groups = {}
        for finding in result.findings:
            if "history" not in finding.tags or not finding.evidence_fingerprint:
                continue
            key = (finding.evidence_fingerprint, finding.rule_id, finding.file)
            groups.setdefault(key, []).append(finding)
        for rows in groups.values():
            commits = [r.commit for r in rows if r.commit]
            if not commits: continue
            keeper = rows[0]
            keeper.historical_occurrences = len(rows)
            keeper.first_seen = commits[-1]
            keeper.last_seen = commits[0]
            result.findings[:] = [f for f in result.findings if f not in rows or f is keeper]
