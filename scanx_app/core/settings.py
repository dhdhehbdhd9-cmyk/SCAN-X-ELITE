"""Safe configuration loading with Phase 2 defaults."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any
from scanx_app.core.exceptions import ConfigurationError

DEFAULTS: dict[str, Any] = {
    "app": {"name": "SCAN-X ELITE", "version": "0.2.0", "language": "en"},
    "scan": {
        "scope": "secrets", "git_history": "complete", "archive_max_depth": 3,
        "archive_max_files": 2000, "archive_max_file_size_mb": 10,
        "archive_max_total_mb": 100, "max_file_size_mb": 25, "max_files": 100000,
        "max_depth": 50, "read_chunk_size": 65536, "follow_symlinks": False,
        "scan_archives": False, "respect_gitignore": False,
        "excluded_directories": [".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist"],
        "git_history_max_commits": 500, "git_history_timeout_seconds": 120,
    },
    "security": {
        "redact_terminal_by_default": True, "redact_reports": True,
        "persist_secret_values": False, "network_validation": False,
    },
    "engines": {"patterns": True, "gitleaks": True, "archives": False, "git_history": True, "gitleaks_timeout_seconds": 120},
    "github": {"enabled": True, "clone_timeout_seconds": 180},
    "reports": {"formats": ["html", "json"], "output_dir": "output/reports"},
}

def default_config_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "settings.yaml"

def default_rules_path() -> Path:
    return Path(__file__).resolve().parents[2] / "rules"

def _merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged

def load_settings(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path else Path(os.environ.get("SCANX_CONFIG", default_config_path()))
    if not config_path.exists():
        if path is not None or os.environ.get("SCANX_CONFIG"):
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        return _merge({}, DEFAULTS)
    try:
        import yaml
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except ImportError as exc:
        raise ConfigurationError("PyYAML is required. Install requirements.txt.") from exc
    except Exception as exc:
        raise ConfigurationError(f"Cannot load configuration: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigurationError("Configuration root must be a YAML mapping.")
    result = _merge(DEFAULTS, loaded)
    if result["security"].get("persist_secret_values") is not False:
        raise ConfigurationError("persist_secret_values must remain false.")
    if result["security"].get("network_validation") is not False:
        raise ConfigurationError("network_validation must remain false in local-only mode.")
    return result
