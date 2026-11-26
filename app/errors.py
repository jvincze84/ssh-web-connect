"""Classification of connection failures into stable error codes.

``classify_error`` turns an exception raised while connecting into
``(code, user_message, detail)``:

- ``code``: stable machine-readable value, written to the audit log and sent to
  the browser (so the UI can decide whether retrying makes sense).
- ``user_message``: safe to show in the browser.
- ``detail``: sanitized ``str(exc)`` for operators. Audit log only, never sent
  to the browser.

It needs no network, so it is unit-testable by constructing exceptions.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
from typing import Optional

import asyncssh

from .config import HostConfig

# Codes after which retrying with the same input cannot succeed.
NON_RETRYABLE = frozenset({
    "unknown_host", "user_not_allowed", "host_key_mismatch", "host_key_unknown",
    "known_hosts_unreadable", "key_invalid", "key_passphrase_required",
    "key_passphrase_wrong", "auth_rejected",
})


def sanitize_detail(exc: BaseException, limit: int = 300) -> str:
    text = f"{exc.__class__.__name__}: {exc}"
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:limit]


def _host_key_state(host: HostConfig, known_hosts_path: Optional[str]) -> str:
    """Return 'mismatch' if known_hosts has an entry for the host, else 'unknown'."""
    if not known_hosts_path:
        return "unknown"
    try:
        kh = asyncssh.read_known_hosts(known_hosts_path)
        matches = kh.match(host.hostname, "", host.port)
    except Exception:  # noqa: BLE001 - classification must never raise
        return "unknown"
    # match() returns several lists (host keys, CA keys, revoked keys, x509 ...).
    return "mismatch" if any(matches) else "unknown"


def classify_error(
    exc: BaseException,
    host: HostConfig,
    known_hosts_path: Optional[str],
    username: Optional[str] = None,
) -> tuple[str, str, str]:
    detail = sanitize_detail(exc)

    # Order matters: asyncssh.PermissionDenied is a DisconnectError (not an
    # OSError), but PermissionError (local, e.g. unreadable known_hosts) is an
    # OSError, so SSH-level errors are checked first.
    if isinstance(exc, asyncssh.PermissionDenied):
        who = f" for user {username}" if username else ""
        return "auth_rejected", f"Server rejected the key{who}", detail

    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        if _host_key_state(host, known_hosts_path) == "mismatch":
            return ("host_key_mismatch",
                    "Host key has CHANGED (possible man-in-the-middle or reinstalled server)",
                    detail)
        return ("host_key_unknown",
                "Host key not found in known_hosts. Ask an administrator to add it "
                "with ssh-keyscan", detail)

    if isinstance(exc, asyncssh.DisconnectError):
        return "ssh_protocol_error", f"SSH error: {exc.reason}", detail

    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "connect_timeout", "Connection timed out", detail

    if isinstance(exc, (PermissionError, FileNotFoundError)) and known_hosts_path and (
        getattr(exc, "filename", None) == known_hosts_path
        or not os.access(known_hosts_path, os.R_OK)
    ):
        return ("known_hosts_unreadable",
                "Server cannot read its known_hosts file (contact the administrator)", detail)

    if isinstance(exc, socket.gaierror):
        return "dns_failure", "Host name could not be resolved", detail
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused", "Connection refused (is the SSH port open?)", detail
    if isinstance(exc, OSError) and exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "host_unreachable", "Host unreachable (no route to host)", detail

    return "internal_error", "Connection failed (internal error)", detail
