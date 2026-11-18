"""Bounded Git history scanner using the custom pattern engine."""
from __future__ import annotations
import hashlib, shutil, subprocess
from pathlib import Path

class GitHistoryEngine:
    name = "git_history"
    def __init__(self, settings: dict):
        scan = settings.get("scan", {})
        self.max_commits = int(scan.get("git_history_max_commits", 500))
        self.timeout = int(scan.get("git_history_timeout_seconds", 120))

    def _run(self, args: list[str], root: Path):
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=self.timeout, check=False)

    def scan(self, root: Path, pattern_engine):
        if shutil.which("git") is None:
            return [], "unavailable", "Git is not installed; history was not scanned."
        if not (root / ".git").exists():
            return [], "skipped", "Target is not a Git repository; history was not scanned."
        try:
            listed = self._run(["log", "--all", "--pretty=format:%H", f"-n{self.max_commits}"], root)
        except subprocess.TimeoutExpired:
            return [], "timeout", "Listing Git commits timed out."
        except OSError as exc:
            return [], "error", f"Git history could not start ({type(exc).__name__})."
        if listed.returncode != 0:
            return [], "failed", "Git could not list repository history."
        commits = listed.stdout.splitlines()
        findings = []
        warnings = []
        for commit in commits:
            try:
                shown = self._run(["show", "--format=", "--unified=0", "--no-color", commit], root)
            except subprocess.TimeoutExpired:
                warnings.append(f"Commit {commit[:8]} timed out; skipped."); continue
            except OSError:
                warnings.append(f"Commit {commit[:8]} could not be read; skipped."); continue
            if shown.returncode != 0:
                warnings.append(f"Commit {commit[:8]} could not be read; skipped."); continue
            current_file = None
            new_line = 0
            for raw_line in shown.stdout.splitlines():
                if raw_line.startswith("@@"):
                    try:
                        plus = raw_line.split("+")[1].split(" ")[0]
                        new_line = int(plus.split(",")[0])
                    except (IndexError, ValueError):
                        new_line = 0
                    continue
                if raw_line.startswith("+++ b/"):
                    current_file = raw_line[6:]
                    continue
                if raw_line.startswith("--- "):
                    continue
                if not raw_line.startswith("+") or current_file is None:
                    continue
                line_number = new_line
                new_line += 1
                if not line_number:
                    continue
                for finding in pattern_engine.scan_text(current_file, Path(current_file).suffix, raw_line[1:], line_number):
                    finding.commit = commit[:8]
                    finding.finding_id = hashlib.sha256(f"history:{commit}:{finding.file}:{finding.rule_id}:{finding.evidence_fingerprint}".encode()).hexdigest()[:16]
                    finding.tags = list(finding.tags) + ["history"]
                    findings.append(finding)
        status = "completed_with_warnings" if warnings else "completed"
        return findings, status, "; ".join(warnings) if warnings else None
