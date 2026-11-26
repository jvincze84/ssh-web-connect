"""Structured (JSON lines) audit logging.

Every security-relevant event is written as one JSON object per line.
Secrets (private keys, passphrases, terminal contents) are never logged.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AuditConfig

_logger = logging.getLogger("ssh_manager.audit")

# Field names that must never end up in the audit log, even by accident.
_FORBIDDEN_KEYS = {"key", "key_b64", "private_key", "passphrase", "password", "data"}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "audit", {})
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def setup_audit(cfg: AuditConfig) -> None:
    _logger.handlers.clear()
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    fmt = _JsonFormatter()

    if cfg.file:
        Path(cfg.file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            cfg.file, maxBytes=cfg.max_bytes, backupCount=cfg.backup_count, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        _logger.addHandler(fh)
    if cfg.stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        _logger.addHandler(sh)
    if not _logger.handlers:
        _logger.addHandler(logging.NullHandler())


def _sanitize(value: Any) -> Any:
    """Strip control characters from strings to prevent log injection."""
    if isinstance(value, str):
        return "".join(ch if ch.isprintable() else "?" for ch in value)[:1024]
    return value


def audit(event: str, **fields: Any) -> None:
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "type": "audit",
        "event": event,
    }
    for k, v in fields.items():
        if k in _FORBIDDEN_KEYS:
            continue
        if v is None:
            continue
        record[k] = _sanitize(v)
    _logger.info(event, extra={"audit": record})
