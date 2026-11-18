"""Command-line interface for SCAN-X ELITE Phase 2."""
from __future__ import annotations
import argparse, json, platform, shutil, sys
from pathlib import Path
from urllib.parse import urlparse
from scanx_app import __version__
from scanx_app.core.orchestrator import ScanRequest, ScanOrchestrator
from scanx_app.core.settings import load_settings, default_rules_path
from scanx_app.core.exceptions import ScanXError

def _target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme == "https" and parsed.netloc.lower() == "github.com": return value
    path = Path(value).expanduser()
    if path.is_dir(): return str(path)
    raise argparse.ArgumentTypeError("Target must be an existing directory or HTTPS github.com URL.")

def build_parser():
    parser = argparse.ArgumentParser(prog="scanx", description="SCAN-X ELITE local secret discovery")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a local repository or public GitHub URL")
    scan.add_argument("target", type=_target)
    scan.add_argument("--deep", action="store_true", help="Also scan full Git history with custom rules")
    scan.add_argument("--report", choices=("html", "json", "all"), default="all"); scan.add_argument("--output", default="output/reports")
    scan.add_argument("--no-gitleaks", action="store_true"); scan.add_argument("--archives", action="store_true"); scan.add_argument("--max-file-size", default=None); scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--telegram", action="store_true", help="Send a redacted report via Telegram (reads ~/.scanx/telegram.yaml)")
    history = sub.add_parser("history", help="Declare a future Git history scan"); history.add_argument("target", type=_target)
    rules = sub.add_parser("rules", help="Inspect detection rules"); rules.add_argument("action", choices=("list", "validate"), nargs="?", default="list")
    sub.add_parser("doctor", help="Check local installation"); sub.add_parser("config", help="Show active configuration"); sub.add_parser("version", help="Show version")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version": print(f"SCAN-X ELITE {__version__}"); return 0
    if args.command == "config":
        try: print(json.dumps(load_settings(), indent=2, ensure_ascii=False)); return 0
        except ScanXError as exc: print(f"[ERROR] {exc}", file=sys.stderr); return 2
    if args.command == "rules":
        try:
            from scanx_app.engines.patterns import load_rules
            rules = load_rules(default_rules_path())
            if args.action == "validate": print(f"Rules valid: {len(rules)} enabled rules")
            else:
                for rule in rules: print(f"{rule.id}\t{rule.severity}\t{rule.name}")
            return 0
        except Exception as exc: print(f"[ERROR] Rules unavailable: {type(exc).__name__}", file=sys.stderr); return 2
    if args.command == "doctor":
        settings_ok = True
        try: load_settings()
        except Exception: settings_ok = False
        print(f"Python: {platform.python_version()}\nOS: {platform.platform()}\nPyYAML: {'yes' if _has_yaml() else 'no'}\nGitleaks: {'yes' if shutil.which('gitleaks') else 'no'}\nConfiguration: {'ok' if settings_ok else 'invalid'}\nRules directory: {default_rules_path()}")
        return 0 if settings_ok and _has_yaml() else 2
    if args.command == "history":
        print("Use: scanx scan <target> --deep  (history is now part of a normal scan)"); return 0
    is_url = args.target.startswith("https://")
    target_kind = "github_url" if is_url else "local_directory"
    target_value = args.target if is_url else str(Path(args.target).resolve())
    try:
        max_size = _parse_size_mb(args.max_file_size) if args.max_file_size else None
        request = ScanRequest(target_value, target_kind, args.deep, args.report, args.output, "scan", not args.no_gitleaks, args.archives, args.verbose, max_size)
        result = ScanOrchestrator().scan(request)
    except ScanXError as exc: print(f"[ERROR] {exc}", file=sys.stderr); return 2
    print(f"SCAN-X ELITE {__version__} | status={result.status}")
    print(f"Files: {result.coverage.get('files_discovered', 0)} | Findings: {len(result.findings)}")
    for name, status in result.engine_status.items(): print(f"Engine {name}: {status}")
    for finding in result.findings:
        print(f"[{finding.severity.upper()}] {finding.rule_id} {finding.file}:{finding.line} ({finding.confidence})")
    for warning in result.warnings: print(f"[WARNING] {warning}", file=sys.stderr)
    print("[INFO] HTML/JSON reports remain planned for Phase 5; no report file was created.")
    if args.telegram:
        from scanx_app.notify.telegram import send_report
        sent, message = send_report(args.target, result)
        print(("[INFO] " if sent else "[WARNING] ") + message)
    return 1 if result.status == "partial_failure" else 0

def _parse_size_mb(value):
    text = str(value).strip().lower()
    units = [("gb", 1024), ("mb", 1), ("kb", 1/1024), ("b", 1/(1024*1024))]
    for suffix, multiplier in units:
        if text.endswith(suffix):
            try: return float(text[:-len(suffix)]) * multiplier
            except ValueError: break
    try: return float(text)
    except ValueError: raise argparse.ArgumentTypeError("Invalid size; use bytes or KB/MB/GB.")

def _has_yaml():
    try: import yaml; return True
    except ImportError: return False
if __name__ == "__main__": raise SystemExit(main())
