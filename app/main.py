"""FastAPI application: static UI, host list API and the SSH WebSocket."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import audit, setup_audit
from .config import AppConfig, load_config
from .ssh_session import ClientContext, SSHBridge

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("ssh_manager")

HEALTH_TIMEOUT = 3.0  # seconds, TCP connect probe for the new-connection dialog

STATIC_DIR = Path(os.environ.get("SSH_MANAGER_STATIC", Path(__file__).parent.parent / "static"))

CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    # xterm.js injects <style> elements for its themes/renderer.
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), "
                          "clipboard-read=(self), clipboard-write=(self)",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class AccessDenied(Exception):
    pass


class SessionRegistry:
    """Tracks concurrent sessions per user (single-process, in memory)."""

    def __init__(self) -> None:
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def acquire(self, user: str, limit: int) -> bool:
        async with self._lock:
            if limit and self._counts[user] >= limit:
                return False
            self._counts[user] += 1
            return True

    async def release(self, user: str) -> None:
        async with self._lock:
            self._counts[user] -= 1
            if self._counts[user] <= 0:
                self._counts.pop(user, None)

    def total(self) -> int:
        return sum(self._counts.values())


# --------------------------------------------------------------------- context
def _peer_ip(scope: Scope) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"


def _is_trusted_peer(cfg: AppConfig, peer: str) -> bool:
    nets = cfg.server.trusted_networks()
    if not nets:
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def resolve_identity(cfg: AppConfig, headers, scope: Scope) -> tuple[str, str]:
    """Return (user, client_ip) or raise AccessDenied."""
    peer = _peer_ip(scope)
    if not _is_trusted_peer(cfg, peer):
        raise AccessDenied(f"untrusted peer {peer}")

    client_ip = peer
    if cfg.server.trusted_proxies:
        # Only honour X-Forwarded-For when the peer is a configured proxy.
        xff = headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip() or peer

    user = (headers.get(cfg.server.user_header) or "").strip()
    if not user:
        if cfg.server.require_user_header:
            raise AccessDenied(f"missing {cfg.server.user_header} header")
        user = "anonymous"
    return user[:256], client_ip


def check_origin(cfg: AppConfig, headers) -> None:
    origin = (headers.get("origin") or "").lower()
    if not origin:
        raise AccessDenied("missing Origin header")
    if cfg.server.allowed_origins:
        if origin not in cfg.server.allowed_origins:
            raise AccessDenied(f"origin not allowed: {origin}")
        return
    origin_host = urlsplit(origin).netloc
    candidates = {
        (headers.get("host") or "").lower(),
        (headers.get("x-forwarded-host") or "").lower(),
    } - {""}
    if origin_host not in candidates:
        raise AccessDenied(f"origin {origin} does not match host")


# ------------------------------------------------------------------ middleware
class IdentityMiddleware(BaseHTTPMiddleware):
    """Enforce trusted-proxy / user-header rules on every HTTP request."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/healthz":
            return await call_next(request)
        cfg: AppConfig = request.app.state.config
        try:
            user, client_ip = resolve_identity(cfg, request.headers, request.scope)
        except AccessDenied as exc:
            audit("http.access_denied", client_ip=_peer_ip(request.scope),
                  path=request.url.path, reason=str(exc))
            return JSONResponse({"detail": "Forbidden"}, status_code=403)
        request.state.user = user
        request.state.client_ip = client_ip
        return await call_next(request)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {k.lower() for k, _ in headers}
                for k, v in SECURITY_HEADERS.items():
                    kb = k.lower().encode()
                    if kb not in existing:
                        headers.append((kb, v.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ------------------------------------------------------------------------- app
def create_app(cfg: Optional[AppConfig] = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config = cfg or load_config()
        setup_audit(config.audit)
        app.state.config = config
        app.state.sessions = SessionRegistry()
        audit("app.started", hosts=len(config.hosts))
        for h in config.hosts:
            if h.insecure_skip_host_key_check:
                log.warning("host %s has host key checking DISABLED", h.id)
        yield
        audit("app.stopped")

    app = FastAPI(
        title="SSH Manager",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(IdentityMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"status": "ok"}

    @app.get("/api/hosts")
    async def list_hosts(request: Request):
        c: AppConfig = request.app.state.config
        return {
            "user": request.state.user,
            "ui": {"scrollback": c.ui.scrollback, "scrollback_max": c.ui.scrollback_max},
            "hosts": [
                {
                    "id": h.id,
                    "name": h.display_name,
                    "group": h.group_name,
                    "hostname": h.hostname,
                    "port": h.port,
                    "users": h.users,
                    "description": h.description,
                }
                for h in c.hosts
            ],
        }

    @app.get("/api/hosts/{host_id}/health")
    async def host_health(host_id: str, request: Request):
        """Cheap TCP reachability probe of a configured host (advisory only)."""
        c: AppConfig = request.app.state.config
        host = next((h for h in c.hosts if h.id == host_id), None)
        if host is None:
            raise HTTPException(status_code=404, detail="Unknown host")
        start = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host.hostname, host.port), timeout=HEALTH_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return {"reachable": False, "latency_ms": None}
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return {"reachable": True, "latency_ms": round((time.monotonic() - start) * 1000)}

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.websocket("/ws/ssh")
    async def ssh_ws(ws: WebSocket):
        c: AppConfig = ws.app.state.config
        registry: SessionRegistry = ws.app.state.sessions
        try:
            user, client_ip = resolve_identity(c, ws.headers, ws.scope)
            check_origin(c, ws.headers)
        except AccessDenied as exc:
            audit("ws.access_denied", client_ip=_peer_ip(ws.scope), reason=str(exc))
            await ws.close(code=1008)
            return

        ctx = ClientContext(user=user, client_ip=client_ip,
                            user_agent=ws.headers.get("user-agent", "")[:256])
        if not await registry.acquire(user, c.server.max_sessions_per_user):
            audit("ws.session_limit", user=user, client_ip=client_ip,
                  limit=c.server.max_sessions_per_user)
            await ws.accept()
            await ws.send_json({"type": "error", "code": "session_limit",
                                "message": "Too many concurrent sessions"})
            await ws.close(code=1008)
            return

        try:
            await ws.accept()
            await SSHBridge(ws, c, ctx).run()
        except Exception:  # noqa: BLE001
            log.exception("unexpected error in session %s", ctx.session_id)
        finally:
            await registry.release(user)
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass

    if (STATIC_DIR / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.exception_handler(HTTPException)
    async def http_exc(_: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app


app = create_app()
