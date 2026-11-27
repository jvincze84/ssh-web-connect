"""Bridge between a browser WebSocket and an interactive SSH shell."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import asyncssh
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from .audit import audit
from .config import AppConfig, HostConfig
from .errors import classify_error
from .stats import STATS_COMMAND, STATS_MIN_INTERVAL, parse_stats
from .keys import KeyError_, decode_private_key, key_fingerprint

log = logging.getLogger("ssh_manager.session")

# asyncssh calls getpass.getuser(), which fails when the container UID has no
# /etc/passwd entry (e.g. `docker run --user 12345`). Provide a fallback.
os.environ.setdefault("USER", "ssh-manager")

MAX_COLS = 1000
MAX_ROWS = 500
READ_CHUNK = 64 * 1024


@dataclass
class ClientContext:
    user: str
    client_ip: str
    user_agent: str = ""
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)


class ProtocolError(Exception):
    """Client sent something invalid. Message is safe to show the user."""

    def __init__(self, message: str, code: str = "bad_request") -> None:
        super().__init__(message)
        self.code = code


def _clamp_size(cols: object, rows: object) -> tuple[int, int]:
    try:
        c, r = int(cols), int(rows)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ProtocolError("Invalid terminal size") from exc
    return max(1, min(c, MAX_COLS)), max(1, min(r, MAX_ROWS))


async def _send_json(ws: WebSocket, payload: dict) -> None:
    if ws.application_state == WebSocketState.CONNECTED:
        await ws.send_text(json.dumps(payload))


def _format_duration(seconds: int) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    if seconds >= 60 and seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


class SSHBridge:
    def __init__(self, ws: WebSocket, cfg: AppConfig, ctx: ClientContext) -> None:
        self.ws = ws
        self.cfg = cfg
        self.ctx = ctx
        self.host: Optional[HostConfig] = None
        self.username: Optional[str] = None
        self.conn: Optional[asyncssh.SSHClientConnection] = None
        self.process: Optional[asyncssh.SSHClientProcess] = None
        self.bytes_in = 0   # browser -> server
        self.bytes_out = 0  # server -> browser
        self.started = 0.0
        self.last_activity = time.monotonic()
        self.idle_timeout = cfg.server.idle_timeout
        self.close_reason = "unknown"
        self.last_stats = 0.0
        self.stats_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------ helpers
    def _audit(self, event: str, **fields: object) -> None:
        audit(
            event,
            session_id=self.ctx.session_id,
            user=self.ctx.user,
            client_ip=self.ctx.client_ip,
            host_id=self.host.id if self.host else None,
            target=f"{self.host.hostname}:{self.host.port}" if self.host else None,
            ssh_user=self.username,
            **fields,
        )

    # --------------------------------------------------------------- handshake
    async def _read_connect_request(self) -> dict:
        try:
            raw = await asyncio.wait_for(self.ws.receive_text(), timeout=120)
        except asyncio.TimeoutError as exc:
            raise ProtocolError("Timed out waiting for connection request") from exc
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError("Malformed message") from exc
        if not isinstance(msg, dict) or msg.get("type") != "connect":
            raise ProtocolError("First message must be a connect request")
        return msg

    async def run(self) -> None:
        try:
            req = await self._read_connect_request()
            await self._connect(req)
        except ProtocolError as exc:
            self._audit("ssh.connect_rejected", reason=str(exc), error_code=exc.code)
            await _send_json(self.ws, {"type": "error", "code": exc.code,
                                       "message": str(exc)})
            return
        except WebSocketDisconnect:
            return

        if self.process is None:
            return  # connect failed, already reported

        try:
            await self._pump()
        finally:
            await self._cleanup()

    async def _connect(self, req: dict) -> None:
        host_id = req.get("host_id")
        username = req.get("username")
        if not isinstance(host_id, str) or not isinstance(username, str):
            raise ProtocolError("host_id and username are required")
        host = self.cfg.get_host(host_id)
        if host is None:
            raise ProtocolError("Unknown host", "unknown_host")
        self.host = host
        if username not in host.users:
            self.username = username[:64]
            raise ProtocolError("User is not allowed for this host", "user_not_allowed")
        self.username = username
        self.idle_timeout = self.cfg.idle_timeout_for(host)
        cols, rows = _clamp_size(req.get("cols", 80), req.get("rows", 24))

        passphrase = req.get("passphrase") or None
        key_b64 = req.get("key")
        req.clear()  # drop references to secret material asap
        try:
            key = decode_private_key(key_b64, passphrase)  # type: ignore[arg-type]
        except KeyError_ as exc:
            raise ProtocolError(str(exc), exc.code) from exc
        finally:
            key_b64 = passphrase = None

        fingerprint = key_fingerprint(key)
        known_hosts = self.cfg.known_hosts_for(host)
        self._audit(
            "ssh.connect_attempt",
            key_fingerprint=fingerprint,
            host_key_check=known_hosts is not None,
            user_agent=self.ctx.user_agent,
        )
        await _send_json(self.ws, {"type": "status", "state": "connecting"})

        try:
            self.conn = await asyncio.wait_for(
                asyncssh.connect(
                    host.hostname,
                    port=host.port,
                    username=username,
                    client_keys=[key],
                    known_hosts=known_hosts,
                    config=None,              # never read ~/.ssh/config
                    agent_path=None,          # never use an agent
                    agent_forwarding=False,
                    x11_forwarding=False,
                    password_auth=False,
                    kbdint_auth=False,
                    gss_auth=False,
                    host_based_auth=False,
                    preferred_auth="publickey",
                    connect_timeout=self.cfg.ssh.connect_timeout,
                    keepalive_interval=self.cfg.ssh.keepalive_interval or None,
                ),
                timeout=self.cfg.ssh.connect_timeout + 5,
            )
            self.process = await self.conn.create_process(
                term_type=self.cfg.ssh.term_type,
                term_size=(cols, rows),
                encoding=None,
                stderr=asyncssh.STDOUT,
            )
        except Exception as exc:  # noqa: BLE001 - report every failure
            code, msg, detail = classify_error(exc, host, known_hosts, username)
            self._audit(
                "ssh.connect_failed",
                key_fingerprint=fingerprint,
                error_code=code,
                error=msg,
                error_detail=detail,  # operators only: never sent to the browser
                error_type=exc.__class__.__name__,
            )
            if code == "internal_error":
                log.error("connect failed session=%s", self.ctx.session_id, exc_info=exc)
            else:
                log.info("connect failed session=%s: %s", self.ctx.session_id, code)
            if self.conn is not None:
                self.conn.close()
                self.conn = None
            await _send_json(self.ws, {"type": "error", "code": code, "message": msg})
            return
        finally:
            del key

        self.started = time.monotonic()
        self.last_activity = self.started
        self._audit("ssh.connected", key_fingerprint=fingerprint)
        await _send_json(self.ws, {"type": "status", "state": "connected"})

    # -------------------------------------------------------------------- pump
    async def _ssh_to_ws(self) -> None:
        assert self.process is not None
        while True:
            data = await self.process.stdout.read(READ_CHUNK)
            if not data:
                self.close_reason = "remote_closed"
                return
            self.bytes_out += len(data)
            if self.cfg.server.idle_activity == "any":
                self.last_activity = time.monotonic()
            await self.ws.send_bytes(data)

    async def _ws_to_ssh(self) -> None:
        assert self.process is not None
        while True:
            try:
                raw = await self.ws.receive_text()
            except WebSocketDisconnect:
                self.close_reason = "client_closed"
                return
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(msg, dict):
                continue
            mtype = msg.get("type")
            if mtype == "input":
                data = msg.get("data")
                if isinstance(data, str) and data:
                    encoded = data.encode("utf-8", errors="replace")
                    self.bytes_in += len(encoded)
                    self.last_activity = time.monotonic()
                    self.process.stdin.write(encoded)
            elif mtype == "resize":
                try:
                    cols, rows = _clamp_size(msg.get("cols"), msg.get("rows"))
                except ProtocolError:
                    continue
                self.process.change_terminal_size(cols, rows)
            elif mtype == "ping":
                await _send_json(self.ws, {"type": "pong"})
            elif mtype == "stats":
                self._request_stats()

    def _request_stats(self) -> None:
        """Start one stats collection, unless disabled, running or too frequent."""
        now = time.monotonic()
        if (not self.cfg.ui.stats_enabled or self.conn is None
                or (self.stats_task and not self.stats_task.done())
                or now - self.last_stats < STATS_MIN_INTERVAL):
            return
        self.last_stats = now
        self.stats_task = asyncio.create_task(self._collect_stats(), name="stats")

    async def _collect_stats(self) -> None:
        # Runs on its own exec channel; does not count as terminal activity.
        values = None
        try:
            assert self.conn is not None
            result = await asyncio.wait_for(
                self.conn.run(STATS_COMMAND, check=False, encoding="utf-8",
                              errors="replace"),
                timeout=20,
            )
            if result.exit_status == 0:
                values = parse_stats(str(result.stdout or "")[:4096])
        except Exception as exc:  # noqa: BLE001 - stats are best effort
            log.debug("stats failed session=%s: %r", self.ctx.session_id, exc)
        try:
            await _send_json(self.ws, {"type": "stats", **(values or {"error": True})})
        except Exception:  # noqa: BLE001 - socket closed meanwhile
            pass

    async def _idle_watchdog(self) -> None:
        timeout = self.idle_timeout
        if timeout <= 0:
            await asyncio.Event().wait()  # sleep forever
        warning = self.cfg.server.idle_warning
        warned_for = None  # last_activity value the warning was sent for
        while True:
            remaining = timeout - (time.monotonic() - self.last_activity)
            if remaining <= 0:
                self.close_reason = "idle_timeout"
                await _send_json(self.ws, {
                    "type": "error",
                    "code": "idle_timeout",
                    "message": f"Session closed after {_format_duration(timeout)} "
                               "of inactivity (idle_timeout)",
                })
                return
            if warning and remaining <= warning and warned_for != self.last_activity:
                warned_for = self.last_activity
                await _send_json(self.ws, {"type": "idle_warning",
                                           "seconds_left": int(remaining) + 1})
            # Wake up in time for the warning and the close, at most every 30 s.
            wait = remaining if not warning or remaining <= warning else remaining - warning
            await asyncio.sleep(max(0.05, min(wait, 30)))

    async def _pump(self) -> None:
        tasks = {
            asyncio.create_task(self._ssh_to_ws(), name="ssh_to_ws"),
            asyncio.create_task(self._ws_to_ssh(), name="ws_to_ssh"),
            asyncio.create_task(self._idle_watchdog(), name="idle"),
        }
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                exc = t.exception()
                if exc is not None and not isinstance(exc, WebSocketDisconnect):
                    self.close_reason = f"error:{exc.__class__.__name__}"
                    log.warning("session %s task %s failed: %r",
                                self.ctx.session_id, t.get_name(), exc)
                elif isinstance(exc, WebSocketDisconnect):
                    self.close_reason = "client_closed"
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _cleanup(self) -> None:
        if self.stats_task is not None:
            self.stats_task.cancel()
        exit_status = None
        if self.process is not None:
            exit_status = self.process.exit_status
            self.process.close()
        if self.conn is not None:
            self.conn.close()
            try:
                await asyncio.wait_for(self.conn.wait_closed(), timeout=5)
            except Exception:  # noqa: BLE001
                pass
        self._audit(
            "ssh.disconnected",
            reason=self.close_reason,
            idle_timeout_s=self.idle_timeout if self.close_reason == "idle_timeout" else None,
            exit_status=exit_status,
            duration_s=round(time.monotonic() - self.started, 1) if self.started else 0,
            bytes_in=self.bytes_in,
            bytes_out=self.bytes_out,
        )
        await _send_json(self.ws, {"type": "status", "state": "closed",
                                   "reason": self.close_reason})
