import base64
import json
from pathlib import Path

import asyncssh
import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.websockets import WebSocketDisconnect

from app.audit import audit, setup_audit
from app.config import AppConfig, AuditConfig, ConfigError, HostConfig, load_config
from app.keys import KeyError_, decode_private_key
from app.main import AccessDenied, check_origin, create_app, resolve_identity


def make_cfg(tmp_path: Path, port: int = 22, **server) -> AppConfig:
    kh = tmp_path / "known_hosts"
    kh.write_text("")
    return AppConfig.model_validate({
        "server": {"require_user_header": True, **server},
        "ssh": {"known_hosts": str(kh)},
        "audit": {"file": str(tmp_path / "audit.log"), "stdout": False},
        "groups": [{"name": "G", "hosts": [{"id": "h1", "hostname": "127.0.0.1", "port": port, "users": ["alice"]}]}],
    })


# ------------------------------------------------------------------ config
def one_host_cfg(**host):
    return AppConfig.model_validate({"groups": [{"name": "G", "hosts": [
        {"id": "a", "hostname": "x", "users": ["u"], **host}]}]})


def test_groups_flatten_with_group_name():
    cfg = AppConfig.model_validate({"groups": [
        {"name": "Prod", "hosts": [{"id": "a", "hostname": "x", "users": ["u"]},
                                   {"id": "b", "hostname": "y", "users": ["u"]}]},
        {"name": "Lab", "hosts": [{"id": "c", "hostname": "z", "users": ["u"]}]},
    ]})
    assert [(h.id, h.group_name) for h in cfg.hosts] == [("a", "Prod"), ("b", "Prod"), ("c", "Lab")]
    assert cfg.get_host("c").group == "Lab"


def test_group_config_errors():
    host = {"id": "a", "hostname": "x", "users": ["u"]}
    with pytest.raises(ValueError):  # old top-level hosts: is gone
        AppConfig.model_validate({"hosts": [host]})
    with pytest.raises(ValueError):  # group set on a host
        AppConfig.model_validate({"groups": [{"name": "G", "hosts": [{**host, "group": "X"}]}]})
    with pytest.raises(ValueError):  # empty group
        AppConfig.model_validate({"groups": [{"name": "G", "hosts": []}]})
    with pytest.raises(ValueError):  # duplicate group names
        AppConfig.model_validate({"groups": [{"name": "G", "hosts": [host]},
                                             {"name": "G", "hosts": [{**host, "id": "b"}]}]})


def test_unknown_key_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("groups:\n  - name: G\n    hosts:\n      - {id: a, hostname: x, users: [u], typo: 1}\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_missing_known_hosts_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(f"ssh: {{known_hosts: {tmp_path}/nope}}\ngroups:\n  - name: G\n    hosts:\n      - {{id: a, hostname: x, users: [u]}}\n")
    with pytest.raises(ConfigError, match="known_hosts"):
        load_config(p)


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(ValueError):
        AppConfig.model_validate({"groups": [
            {"name": "A", "hosts": [{"id": "a", "hostname": "x", "users": ["u"]}]},
            {"name": "B", "hosts": [{"id": "a", "hostname": "y", "users": ["u"]}]},
        ]})


def test_invalid_user_rejected():
    with pytest.raises(ValueError):
        one_host_cfg(users=["bad user"])


# -------------------------------------------------------------------- keys
def test_decode_key_base64_and_pem():
    key = asyncssh.generate_private_key("ssh-ed25519")
    pem = key.export_private_key()
    assert decode_private_key(base64.b64encode(pem).decode()).get_algorithm() == "ssh-ed25519"
    assert decode_private_key(pem.decode()).get_algorithm() == "ssh-ed25519"


def test_decode_key_passphrase():
    key = asyncssh.generate_private_key("ssh-ed25519")
    b64 = base64.b64encode(key.export_private_key(passphrase="s3cret")).decode()
    with pytest.raises(KeyError_, match="passphrase"):
        decode_private_key(b64)
    assert decode_private_key(b64, "s3cret")


def test_decode_key_garbage():
    with pytest.raises(KeyError_):
        decode_private_key("!!!notbase64")
    with pytest.raises(KeyError_):
        decode_private_key(base64.b64encode(b"hello").decode())


def test_key_error_codes():
    key = asyncssh.generate_private_key("ssh-ed25519")
    b64 = base64.b64encode(key.export_private_key(passphrase="s3cret")).decode()
    with pytest.raises(KeyError_) as e:
        decode_private_key(b64)
    assert e.value.code == "key_passphrase_required"
    with pytest.raises(KeyError_) as e:
        decode_private_key(b64, "wrong")
    assert e.value.code == "key_passphrase_wrong"
    with pytest.raises(KeyError_) as e:
        decode_private_key(base64.b64encode(b"hello").decode())
    assert e.value.code == "key_invalid"


# ------------------------------------------------------------ classify_error
def test_classify_error(tmp_path):
    import errno
    import socket

    from app.errors import classify_error

    host = HostConfig(id="h", hostname="example.test", users=["u"])
    kh = tmp_path / "kh"
    kh.write_text("")

    def code(exc, path=str(kh)):
        return classify_error(exc, host, path, "u")[0]

    assert code(asyncssh.PermissionDenied("no")) == "auth_rejected"
    assert code(asyncssh.HostKeyNotVerifiable("x")) == "host_key_unknown"
    kh.write_text("example.test " + asyncssh.generate_private_key("ssh-ed25519")
                  .export_public_key().decode())
    assert code(asyncssh.HostKeyNotVerifiable("x")) == "host_key_mismatch"
    assert code(asyncssh.DisconnectError(2, "protocol")) == "ssh_protocol_error"
    assert code(TimeoutError()) == "connect_timeout"
    assert code(socket.gaierror(-2, "nope")) == "dns_failure"
    assert code(ConnectionRefusedError(errno.ECONNREFUSED, "refused")) == "connection_refused"
    assert code(OSError(errno.EHOSTUNREACH, "unreach")) == "host_unreachable"
    assert code(PermissionError(errno.EACCES, "denied", str(kh))) == "known_hosts_unreadable"
    assert code(FileNotFoundError(errno.ENOENT, "gone"), str(tmp_path / "missing")) \
        == "known_hosts_unreadable"
    assert code(RuntimeError("boom")) == "internal_error"


# --------------------------------------------------------- config additions
def test_idle_and_ui_config_validation():
    base = {"groups": [{"name": "G", "hosts": [{"id": "a", "hostname": "x", "users": ["u"]}]}]}
    with pytest.raises(ValueError):
        AppConfig.model_validate({**base, "server": {"idle_timeout": 30, "idle_warning": 30}})
    with pytest.raises(ValueError):
        AppConfig.model_validate({**base, "server": {"idle_activity": "nope"}})
    with pytest.raises(ValueError):
        AppConfig.model_validate({**base, "ui": {"scrollback": 5000, "scrollback_max": 1000}})
    with pytest.raises(ValueError):
        AppConfig.model_validate({**base, "ui": {"scrollback": 50}})
    with pytest.raises(ValueError):
        one_host_cfg(idle_timeout=10)
    cfg = AppConfig.model_validate({"groups": [{"name": "G", "hosts": [
        {"id": "a", "hostname": "x", "users": ["u"], "idle_timeout": 0},
        {"id": "b", "hostname": "y", "users": ["u"]}]}]})
    assert cfg.idle_timeout_for(cfg.hosts[0]) == 0
    assert cfg.idle_timeout_for(cfg.hosts[1]) == 1800


def test_unreadable_known_hosts_rejected(tmp_path):
    import os
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    kh = tmp_path / "kh"
    kh.write_text("")
    kh.chmod(0)
    p = tmp_path / "c.yaml"
    p.write_text(f"ssh: {{known_hosts: {kh}}}\ngroups:\n  - name: G\n    hosts:\n      - {{id: a, hostname: x, users: [u]}}\n")
    with pytest.raises(ConfigError, match="not readable"):
        load_config(p)


# --------------------------------------------------------------- identity
def test_identity_and_trusted_proxies(tmp_path):
    cfg = make_cfg(tmp_path, trusted_proxies=["10.0.0.0/8"])
    hdr = Headers({"x-forwarded-email": "a@example.com", "x-forwarded-for": "1.2.3.4, 10.0.0.1"})
    assert resolve_identity(cfg, hdr, {"client": ("10.1.1.1", 1)}) == ("a@example.com", "1.2.3.4")
    with pytest.raises(AccessDenied):
        resolve_identity(cfg, hdr, {"client": ("192.168.1.1", 1)})
    with pytest.raises(AccessDenied):
        resolve_identity(cfg, Headers({}), {"client": ("10.1.1.1", 1)})


def test_origin_check(tmp_path):
    cfg = make_cfg(tmp_path)
    check_origin(cfg, {"origin": "https://ssh.example.com", "host": "ssh.example.com"})
    with pytest.raises(AccessDenied):
        check_origin(cfg, {"origin": "https://evil.example", "host": "ssh.example.com"})
    with pytest.raises(AccessDenied):
        check_origin(cfg, {"host": "ssh.example.com"})


def test_audit_never_logs_secrets(tmp_path):
    log = tmp_path / "a.log"
    setup_audit(AuditConfig(file=str(log), stdout=False))
    audit("x", key="SECRET", passphrase="SECRET", user="bob\nINJECT")
    line = json.loads(log.read_text().strip())
    assert "SECRET" not in log.read_text()
    assert line["user"] == "bob?INJECT"


# -------------------------------------------------------------------- http
def test_http_requires_identity_and_sets_headers(tmp_path):
    with TestClient(create_app(make_cfg(tmp_path))) as c:
        assert c.get("/healthz").status_code == 200
        assert c.get("/api/hosts").status_code == 403
        r = c.get("/api/hosts", headers={"X-Forwarded-Email": "a@example.com"})
        assert r.status_code == 200
        assert r.json()["hosts"][0]["id"] == "h1"
        assert r.json()["hosts"][0]["group"] == "G"
        assert r.json()["ui"] == {"scrollback": 10000, "scrollback_max": 100000}
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"


def test_host_health(tmp_path):
    import socket
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    cfg = make_cfg(tmp_path, port=port)
    hdr = {"X-Forwarded-Email": "a@example.com"}
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/hosts/h1/health").status_code == 403
        assert c.get("/api/hosts/nope/health", headers=hdr).status_code == 404
        r = c.get("/api/hosts/h1/health", headers=hdr).json()
        assert r["reachable"] is True and r["latency_ms"] >= 0
        srv.close()
        r = c.get("/api/hosts/h1/health", headers=hdr).json()
        assert r == {"reachable": False, "latency_ms": None}


def test_ws_rejects_bad_origin(tmp_path):
    with TestClient(create_app(make_cfg(tmp_path))) as c:
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect("/ws/ssh", headers={
                "X-Forwarded-Email": "a@example.com", "Origin": "https://evil.example"}) as ws:
                ws.receive_text()


# -------------------------------------------------------------- end-to-end
class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def password_auth_supported(self):
        return False


async def _echo_shell(process: asyncssh.SSHServerProcess):
    process.stdout.write(f"hello {process.get_extra_info('username')}\r\n")
    line = await process.stdin.readline()
    process.stdout.write(f"got:{line.strip()}\r\n")
    process.exit(0)


def test_end_to_end_ssh_session(tmp_path):
    import asyncio
    import threading

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    authorized = asyncssh.import_authorized_keys(client_key.export_public_key().decode())

    loop = asyncio.new_event_loop()
    started = threading.Event()
    holder = {}

    async def start():
        server = await asyncssh.create_server(
            _Server, "127.0.0.1", 0, server_host_keys=[host_key],
            authorized_client_keys=authorized, process_factory=_echo_shell)
        holder["port"] = server.sockets[0].getsockname()[1]
        started.set()

    t = threading.Thread(target=lambda: (loop.run_until_complete(start()), loop.run_forever()),
                         daemon=True)
    t.start()
    started.wait(10)
    port = holder["port"]

    kh = tmp_path / "known_hosts"
    kh.write_text(f"[127.0.0.1]:{port} {host_key.export_public_key().decode()}")
    cfg = AppConfig.model_validate({
        "server": {"require_user_header": True},
        "ssh": {"known_hosts": str(kh)},
        "audit": {"file": str(tmp_path / "audit.log"), "stdout": False},
        "groups": [{"name": "G", "hosts": [
            {"id": "h1", "hostname": "127.0.0.1", "port": port, "users": ["alice"]}]}],
    })
    headers = {"X-Forwarded-Email": "op@example.com", "Origin": "http://testserver"}
    key_b64 = base64.b64encode(client_key.export_private_key()).decode()

    try:
        with TestClient(create_app(cfg)) as c:
            # disallowed user
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "root", "key": key_b64}))
                assert "not allowed" in json.loads(ws.receive_text())["message"]

            # happy path
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1", "username": "alice",
                                         "key": key_b64, "cols": 100, "rows": 30}))
                assert json.loads(ws.receive_text())["state"] == "connecting"
                assert json.loads(ws.receive_text())["state"] == "connected"
                out = b""
                while b"hello alice" not in out:
                    out += ws.receive_bytes()
                ws.send_text(json.dumps({"type": "input", "data": "ping\r"}))
                out = b""
                while True:
                    m = ws.receive()
                    if m.get("bytes"):
                        out += m["bytes"]
                    elif m.get("text") and json.loads(m["text"]).get("state") == "closed":
                        break
                assert b"got:ping" in out

        # wrong host key -> verification failure
        kh.write_text(f"[127.0.0.1]:{port} "
                      f"{asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()}")
        with TestClient(create_app(cfg)) as c:
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "alice", "key": key_b64}))
                json.loads(ws.receive_text())  # connecting
                err = json.loads(ws.receive_text())
                assert err["code"] == "host_key_mismatch"
                assert "CHANGED" in err["message"]
                assert "HostKeyNotVerifiable" not in json.dumps(err)  # no operator detail

        # host missing from known_hosts -> unknown
        kh.write_text("")
        with TestClient(create_app(cfg)) as c:
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "alice", "key": key_b64}))
                json.loads(ws.receive_text())
                assert json.loads(ws.receive_text())["code"] == "host_key_unknown"

        # key not in authorized_keys -> auth rejected
        kh.write_text(f"[127.0.0.1]:{port} {host_key.export_public_key().decode()}")
        other_b64 = base64.b64encode(
            asyncssh.generate_private_key("ssh-ed25519").export_private_key()).decode()
        with TestClient(create_app(cfg)) as c:
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "alice", "key": other_b64}))
                json.loads(ws.receive_text())
                assert json.loads(ws.receive_text())["code"] == "auth_rejected"

        # closed port -> connection refused
        refused_cfg = AppConfig.model_validate({
            **cfg.model_dump(),
            "groups": [{"name": "G", "hosts": [
                {"id": "h1", "hostname": "127.0.0.1", "port": 1, "users": ["alice"]}]}]})
        kh.write_text(f"[127.0.0.1]:1 {host_key.export_public_key().decode()}")
        with TestClient(create_app(refused_cfg)) as c:
            with c.websocket_connect("/ws/ssh", headers=headers) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "alice", "key": key_b64}))
                json.loads(ws.receive_text())
                assert json.loads(ws.receive_text())["code"] == "connection_refused"
    finally:
        loop.call_soon_threadsafe(loop.stop)

    events = [json.loads(line)["event"] for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert "ssh.connect_rejected" in events
    assert "ssh.connected" in events
    assert "ssh.disconnected" in events
    assert "ssh.connect_failed" in events
    audit_text = (tmp_path / "audit.log").read_text()
    assert key_b64 not in audit_text
    failed = [json.loads(line) for line in audit_text.splitlines()
              if json.loads(line)["event"] == "ssh.connect_failed"]
    assert [f["error_code"] for f in failed] == [
        "host_key_mismatch", "host_key_unknown", "auth_rejected", "connection_refused"]
    assert all("error_detail" in f for f in failed)


# ------------------------------------------------------------ idle timeout
def _start_ssh_server(process_factory):
    import asyncio
    import threading

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    authorized = asyncssh.import_authorized_keys(client_key.export_public_key().decode())
    loop = asyncio.new_event_loop()
    started = threading.Event()
    holder = {}

    async def start():
        server = await asyncssh.create_server(
            _Server, "127.0.0.1", 0, server_host_keys=[host_key],
            authorized_client_keys=authorized, process_factory=process_factory)
        holder["port"] = server.sockets[0].getsockname()[1]
        started.set()

    threading.Thread(target=lambda: (loop.run_until_complete(start()), loop.run_forever()),
                     daemon=True).start()
    started.wait(10)
    return holder["port"], host_key, client_key, lambda: loop.call_soon_threadsafe(loop.stop)


async def _silent_shell(process: asyncssh.SSHServerProcess):
    await process.stdin.read()


async def _chatty_shell(process: asyncssh.SSHServerProcess):
    import asyncio
    for _ in range(40):
        process.stdout.write("tick\r\n")
        await asyncio.sleep(0.25)
    process.exit(0)


def _idle_run(tmp_path, shell, server_cfg, host_extra=None):
    """Connect, then collect all JSON messages until the session is closed."""
    port, host_key, client_key, stop = _start_ssh_server(shell)
    kh = tmp_path / "known_hosts"
    kh.write_text(f"[127.0.0.1]:{port} {host_key.export_public_key().decode()}")
    cfg = AppConfig.model_validate({
        "server": {"require_user_header": True, **server_cfg},
        "ssh": {"known_hosts": str(kh)},
        "audit": {"file": str(tmp_path / "audit.log"), "stdout": False},
        "groups": [{"name": "G", "hosts": [
            {"id": "h1", "hostname": "127.0.0.1", "port": port, "users": ["alice"],
             **(host_extra or {})}]}],
    })
    key_b64 = base64.b64encode(client_key.export_private_key()).decode()
    msgs = []
    try:
        with TestClient(create_app(cfg)) as c:
            with c.websocket_connect("/ws/ssh", headers={
                    "X-Forwarded-Email": "op@example.com", "Origin": "http://testserver"}) as ws:
                ws.send_text(json.dumps({"type": "connect", "host_id": "h1",
                                         "username": "alice", "key": key_b64}))
                while True:
                    m = ws.receive()
                    if m.get("text"):
                        msg = json.loads(m["text"])
                        msgs.append(msg)
                        if msg.get("state") == "closed":
                            break
    finally:
        stop()
    audit_lines = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    return msgs, audit_lines


def test_idle_warning_then_timeout(tmp_path):
    msgs, audit_lines = _idle_run(tmp_path, _silent_shell,
                                  {"idle_timeout": 2, "idle_warning": 1})
    kinds = [m["type"] for m in msgs]
    assert kinds.index("idle_warning") < kinds.index("error")
    err = next(m for m in msgs if m["type"] == "error")
    assert err["code"] == "idle_timeout"
    assert "inactivity" in err["message"]
    disc = next(a for a in audit_lines if a["event"] == "ssh.disconnected")
    assert disc["reason"] == "idle_timeout"
    assert disc["idle_timeout_s"] == 2


def test_idle_per_host_override_wins(tmp_path):
    # global timeout is huge; the host override closes the session.
    msgs, audit_lines = _idle_run(tmp_path, _silent_shell,
                                  {"idle_timeout": 3600, "idle_warning": 1},
                                  {"idle_timeout": 2})
    disc = next(a for a in audit_lines if a["event"] == "ssh.disconnected")
    assert disc["reason"] == "idle_timeout" and disc["idle_timeout_s"] == 2


def test_idle_activity_input_ignores_output(tmp_path):
    # Server output every 250 ms would keep an "any" session alive forever.
    _, audit_lines = _idle_run(tmp_path, _chatty_shell,
                               {"idle_timeout": 2, "idle_warning": 1, "idle_activity": "input"})
    disc = next(a for a in audit_lines if a["event"] == "ssh.disconnected")
    assert disc["reason"] == "idle_timeout"


def test_idle_activity_any_output_keeps_alive(tmp_path):
    _, audit_lines = _idle_run(tmp_path, _chatty_shell,
                               {"idle_timeout": 2, "idle_warning": 1, "idle_activity": "any"})
    disc = next(a for a in audit_lines if a["event"] == "ssh.disconnected")
    assert disc["reason"] == "remote_closed"
