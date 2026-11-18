"""Optional, safely redacted Gitleaks adapter."""
from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path
from scanx_app.core.models import Finding

class GitleaksEngine:
    name = "gitleaks"
    def __init__(self, timeout: int = 120): self.timeout = timeout
    def available(self) -> bool: return shutil.which("gitleaks") is not None
    def version(self) -> str:
        if not self.available(): return "unavailable"
        try:
            result = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=10, check=False)
            return (result.stdout or result.stderr).strip()[:120]
        except (OSError, subprocess.TimeoutExpired): return "unavailable"
    def scan(self, root: Path):
        if not self.available(): return [], "unavailable", "Gitleaks is not installed; custom pattern scanning was used."
        with tempfile.TemporaryDirectory(prefix="scanx-gitleaks-") as temp:
            report = Path(temp) / "report.json"
            command = ["gitleaks", "detect", "--source", str(root), "--report-format", "json", "--report-path", str(report), "--redact=100", "--no-banner"]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, check=False)
            except subprocess.TimeoutExpired:
                return [], "timeout", "Gitleaks timed out; results from it were not used."
            except OSError as exc:
                return [], "error", f"Gitleaks could not start ({type(exc).__name__})."
            if not report.exists():
                return [], "error", "Gitleaks produced no JSON report; results from it were not used."
            try: rows = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return [], "error", "Gitleaks returned invalid JSON; results from it were not used."
            findings = []
            for index, row in enumerate(rows if isinstance(rows, list) else []):
                path = str(row.get("File", ""))
                try: relative = Path(path).resolve().relative_to(root.resolve()).as_posix()
                except ValueError: relative = Path(path).name
                findings.append(Finding(f"gitleaks-{index}", str(row.get("RuleID", "gitleaks")), "gitleaks", str(row.get("Description", "Gitleaks finding")), str(row.get("Severity", "high")), "high", relative, int(row.get("StartLine", 0) or 0), evidence_fingerprint=None, tags=["gitleaks"], rule_name=str(row.get("Description", "Gitleaks")), secret_type="gitleaks", detector=self.name, masked_value="[REDACTED]"))
            status = "completed" if completed.returncode in (0, 1) else "error"
            warning = None if status == "completed" else "Gitleaks exited with an error; its results may be incomplete."
            return findings, status, warning
