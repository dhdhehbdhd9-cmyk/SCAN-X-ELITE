"""Typed data contracts shared by scan engines."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class ScanRequest:
    target: str
    target_kind: str
    deep_history: bool = False
    report_format: str = "all"
    output_dir: str = "output/reports"
    command: str = "scan"
    use_gitleaks: bool = True
    scan_archives: bool = False
    verbose: bool = False
    max_file_size_mb: float | None = None

@dataclass
class Finding:
    """Metadata only. Raw secret values must never be stored here."""
    finding_id: str
    rule_id: str
    category: str
    key_name: str
    severity: str
    confidence: str
    file: str
    line: int
    commit: Optional[str] = None
    currently_present: Optional[bool] = None
    historical_occurrences: int = 0
    redacted: bool = True
    evidence_fingerprint: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    rule_name: str = ""
    secret_type: str = ""
    column: Optional[int] = None
    detector: str = "patterns"
    masked_value: str = "[REDACTED]"
    context: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

@dataclass
class ScanResult:
    scan_id: str
    target: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage: dict[str, object] = field(default_factory=dict)
    engine_status: dict[str, str] = field(default_factory=dict)
