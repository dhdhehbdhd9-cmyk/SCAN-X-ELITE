"""YAML-driven custom secret pattern engine."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, re, secrets
from pathlib import Path
from scanx_app.core.models import Finding
from scanx_app.core.security import fingerprint_secret
from scanx_app.engines.filesystem import FileCandidate, FilesystemEngine

@dataclass
class Rule:
    id: str
    name: str
    category: str
    pattern: re.Pattern
    severity: str = "medium"
    confidence: str = "medium"
    extensions: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    allowlist: tuple[str, ...] = ()
    enabled: bool = True
    description: str = ""

def _compile_rule(raw: dict) -> Rule | None:
    if not raw.get("enabled", True): return None
    try: pattern = re.compile(str(raw["pattern"]), re.IGNORECASE)
    except (KeyError, re.error): return None
    return Rule(str(raw["id"]), str(raw.get("name", raw["id"])), str(raw.get("category", "generic")), pattern,
                str(raw.get("severity", "medium")), str(raw.get("confidence", "medium")),
                tuple(str(x).lower() for x in raw.get("extensions", [])),
                tuple(str(x).lower() for x in raw.get("keywords", [])),
                tuple(str(x) for x in raw.get("allowlist", [])), True,
                str(raw.get("description", "")))

def load_rules(rules_dir: str | Path) -> list[Rule]:
    try:
        import yaml
    except ImportError as exc: raise RuntimeError("PyYAML is required for rules.") from exc
    result: list[Rule] = []
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        try: loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception: continue
        for raw in loaded.get("rules", []) if isinstance(loaded, dict) else []:
            if isinstance(raw, dict):
                rule = _compile_rule(raw)
                if rule: result.append(rule)
    return result

class PatternEngine:
    name = "patterns"
    def __init__(self, rules: list[Rule], salt: bytes | None = None):
        self.rules = rules
        self.salt = salt or secrets.token_bytes(32)
    def _scan_line(self, filename: str, suffix: str, line: str, line_no: int):
        lower = line.lower()
        for rule in self.rules:
            if rule.extensions and suffix.lower() not in rule.extensions: continue
            if rule.keywords and not any(k in lower for k in rule.keywords): continue
            for match in rule.pattern.finditer(line):
                raw = match.group(0)
                if any(re.search(item, raw, re.IGNORECASE) for item in rule.allowlist): continue
                digest = fingerprint_secret(raw, salt=self.salt)
                finding_id = hashlib.sha256(f"{filename}:{line_no}:{rule.id}:{digest}".encode()).hexdigest()[:16]
                yield Finding(finding_id=finding_id, rule_id=rule.id, category=rule.category,
                    key_name=rule.name, severity=rule.severity, confidence=rule.confidence,
                    file=filename, line=line_no, evidence_fingerprint=digest,
                    tags=["pattern"], rule_name=rule.name, secret_type=rule.category,
                    column=match.start() + 1, detector=self.name, masked_value="[REDACTED]")
    def scan_candidate(self, candidate: FileCandidate, filesystem: FilesystemEngine):
        if candidate.is_binary: return
        for line_no, line in filesystem.read_lines(candidate):
            yield from self._scan_line(candidate.relative_path, candidate.path.suffix, line, line_no)
    def scan_text(self, filename: str, suffix: str, line: str, line_no: int):
        yield from self._scan_line(filename, suffix, line, line_no)
