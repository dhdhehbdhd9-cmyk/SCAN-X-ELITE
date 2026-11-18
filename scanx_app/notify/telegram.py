"""Optional Telegram notifier.

Design rules, enforced here rather than left to the caller:
  * The bot token is never read from the command line or hardcoded in
    this repository — only from a local config file the user creates
    themselves (outside git, chmod 600).
  * Only Finding metadata is ever sent: rule name, category, file,
    line, commit. ``masked_value`` is always "[REDACTED]" on Finding,
    and this module never looks at anything else on the object, so
    there is no code path that can leak a real secret value here.
  * Sending is best-effort: a Telegram failure never fails the scan.
"""
from __future__ import annotations
import json
import stat
import re
import os
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a declared dependency
    yaml = None


def default_config_path() -> Path:
    return Path(os.environ.get("SCANX_TELEGRAM_CONFIG", "~/.scanx/telegram.yaml")).expanduser()


def load_telegram_config(path: str | Path | None = None) -> Optional[dict]:
    """Load {token, chat_id} from a local file. Returns None if absent/disabled.

    The file is intentionally NOT part of this repo and NOT read from
    settings.yaml, so a `git push` of the project can never carry a
    token with it.
    """
    config_path = Path(path) if path else default_config_path()
    if not config_path.exists():
        return None
    if yaml is None:
        return None
    try:
        mode = stat.S_IMODE(config_path.stat().st_mode)
        if mode & 0o077:
            return None
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("enabled", True):
        return None
    token, chat_id = data.get("token"), data.get("chat_id")
    if not token or not chat_id:
        return None
    return {"token": str(token), "chat_id": str(chat_id)}


def _safe(value, limit=180):
    return re.sub(r"[\r\n\t]+", " ", str(value))[:limit]

def format_report(target: str, result) -> str:
    lines = [f"🔍 فحص: {_safe(target)}", f"⚠️ النتائج: {len(result.findings)}", ""]
    for finding in result.findings[:30]:  # keep message under Telegram's size limit
        where = f"{_safe(finding.file)}:{finding.line}"
        commit = f" | commit {_safe(finding.commit, 20)}" if finding.commit else ""
        lines.append(f"• {_safe(finding.rule_name or finding.rule_id)}\n  {where}{commit}")
    if len(result.findings) > 30:
        lines.append(f"\n… و{len(result.findings) - 30} نتيجة أخرى لم تُدرج هنا.")
    lines.append("\nالمعالجة: ألغِ المفتاح وأنشئ بديلًا، ثم نظّف السجل. القيم الفعلية غير معروضة.")
    return "\n".join(lines)[:4000]


def send_report(target: str, result, config: dict | None = None) -> tuple[bool, str]:
    """Send the redacted report. Returns (sent, message) and never raises."""
    cfg = config or load_telegram_config()
    if cfg is None:
        return False, "لم يُفعَّل تيليجرام (لا يوجد ~/.scanx/telegram.yaml صالح)."
    if not result.findings:
        return False, "لا نتائج؛ لم تُرسل رسالة."
    text = format_report(target, result)
    url = f"https://api.telegram.org/bot{cfg['token']}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": cfg["chat_id"], "text": text}).encode()
    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode())
        if body.get("ok"):
            return True, "📨 أُرسل التقرير إلى تيليجرام."
        return False, f"فشل الإرسال: {body.get('description', 'unknown error')}"
    except Exception as exc:  # network issues must never crash the scan
        return False, f"تعذّر الاتصال بتيليجرام ({type(exc).__name__})."
