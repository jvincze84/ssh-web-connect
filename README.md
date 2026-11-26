# SSH Manager

A browser-based SSH client for a fixed set of servers. It is meant to run in Docker
behind an OAuth proxy (e.g. oauth2-proxy).

- **Hosts from YAML**: operators can only reach hosts and users listed in the config.
- **Key-only auth**: the private key is pasted (base64) at connect time, used once for
  the handshake and never stored on the server.
- **Tabs**: several concurrent SSH sessions in one browser tab.
- **Clipboard**: selected text is copied automatically, right-click pastes.
- **Audit log**: JSON-lines log of every connect, failure and disconnect, including the
  proxy-supplied user identity and the key fingerprint.
- **Strict host key checking** against a `known_hosts` file.

```
Browser ──HTTPS──> OAuth proxy ──HTTP──> ssh-manager (FastAPI) ──SSH──> servers
   xterm.js + WebSocket             adds X-Forwarded-Email      asyncssh
```

## Quick start

```bash
mkdir -p config logs
cp config.example.yaml config/config.yaml        # edit hosts/users
ssh-keyscan -p 22 10.0.0.10 db01.internal.example.com > config/known_hosts
sudo chown 10001:10001 logs                      # container runs as UID 10001

docker compose up -d --build
docker compose logs -f
```

The app listens on `127.0.0.1:8080`. Put your OAuth proxy in front of it (see below).

### Connecting

1. Click **+ New** and choose a host and a user.
2. Paste your private key as base64:
   ```bash
   base64 -w0 ~/.ssh/id_ed25519      # Linux
   base64 -i ~/.ssh/id_ed25519       # macOS
   ```
   You can also click **Load key file...**: the browser encodes the file locally.
   A raw `-----BEGIN ... PRIVATE KEY-----` block is accepted as well.
3. Enter the passphrase if the key is encrypted.
4. Optional: **Keep key in this tab's memory until reload** keeps the key in a
   JavaScript variable so you don't have to paste it for every new tab. It is never
   written to localStorage, cookies or the server.

Supported key types: everything asyncssh supports (Ed25519, ECDSA, RSA), in OpenSSH,
PKCS#1 or PKCS#8 format, encrypted or not.

### Reconnect and duplicate

When a session ends (idle timeout, network drop, remote exit) an overlay offers
**Reconnect** and **Close tab**; the tab also gets a reconnect icon. Reconnecting reuses
the same tab, so the terminal history is kept. The key is only reused when
"Keep key in this tab's memory" was ticked; otherwise a dialog asks for the key again
(host and user are locked). After key or authentication errors the key is always asked
again.

**Duplicate** (top bar or `Ctrl+Shift+D`) opens a new tab for the active tab's host and
user, with the same key rules.

### Connecting and tab handling

- Double-clicking a host in the **New connection** dialog connects immediately if a key is
  already filled in (and a user is selected); with an empty key it just focuses the key field.
- Tabs can be reordered by dragging one onto another (a blue marker shows the drop side).
  The order is kept only until the page is reloaded.

### Clipboard

| Action | Effect |
|---|---|
| Select text with the mouse | Copied to the clipboard automatically |
| Right-click in a terminal | Pastes the clipboard (bracketed paste aware) |

Clipboard access requires a **secure context** (HTTPS, or `http://localhost`). The
browser may ask for clipboard permission on the first paste.

## Configuration

All settings live in one YAML file (`SSH_MANAGER_CONFIG`, default
`/app/config/config.yaml`). Unknown keys are rejected at startup. See
[`config.example.yaml`](config.example.yaml) for a commented example.

| Key | Default | Description |
|---|---|---|
| `server.user_header` | `X-Forwarded-Email` | Header carrying the authenticated user, set by the proxy |
| `server.require_user_header` | `true` | Reject requests without that header |
| `server.trusted_proxies` | `[]` | IPs/CIDRs allowed to connect. When set, `X-Forwarded-For` is used for the client IP |
| `server.allowed_origins` | `[]` | Allowed WebSocket origins. Empty: Origin must match the Host header |
| `server.idle_timeout` | `1800` | Seconds of inactivity before a session is closed (0 = off). Per host: `idle_timeout` on the host |
| `server.idle_activity` | `any` | What counts as activity: `any` (keystrokes and server output, so `tail -f` keeps the session alive) or `input` (keystrokes only, stricter) |
| `server.idle_warning` | `60` | Seconds before the idle close at which the browser shows a warning (0 = off). Must be smaller than the timeout |
| `server.max_sessions_per_user` | `10` | Concurrent sessions per user (0 = unlimited) |
| `ssh.known_hosts` | `/app/config/known_hosts` | OpenSSH known_hosts file for host key verification |
| `ssh.connect_timeout` | `15` | Seconds |
| `ssh.keepalive_interval` | `30` | Seconds (0 = off) |
| `ssh.term_type` | `xterm-256color` | TERM sent to the server |
| `audit.file` | `/var/log/ssh-manager/audit.log` | Audit log path (`null` = disabled) |
| `audit.stdout` | `true` | Also write audit events to stdout |
| `audit.max_bytes` / `audit.backup_count` | `10 MiB` / `10` | Log rotation |
| `groups[].name` | (required) | Group name, unique. Shown as a section in the host picker |
| `groups[].hosts` | (required) | Non-empty list of hosts in this group |
| `groups[].hosts[].id` | (required) | Unique ID (across all groups) |
| `groups[].hosts[].hostname` / `port` | (required) / `22` | Target |
| `groups[].hosts[].users` | (required) | Users allowed for this host |
| `groups[].hosts[].name`, `description` | | Display only |
| `groups[].hosts[].known_hosts` | | Per-host known_hosts override |
| `groups[].hosts[].idle_timeout` | | Per-host override of `server.idle_timeout` (seconds, 0 = never) |
| `ui.scrollback` | `10000` | Default scrollback lines per terminal (100 to `scrollback_max`) |
| `ui.scrollback_max` | `100000` | Upper bound for the per-browser override (max 1000000) |
| `groups[].hosts[].insecure_skip_host_key_check` | `false` | **Dangerous**: disables host key verification |

Scrollback and the terminal font size (8 to 32 px, default 14) can be changed per
browser with the gear icon in the top bar. Both are stored in `localStorage` (the
scrollback is clamped to `ui.scrollback_max`) and apply to open terminals immediately.
The font size has no config key. Large scrollback multiplied by many
tabs uses a lot of browser memory: roughly 100k lines x 10 tabs can reach hundreds of MB.

Hosts are organised **by group**: the group is the top level and its hosts are listed
under it. A host cannot set `group` itself, and the old top-level `hosts:` list is no
longer accepted (startup fails with a validation error). Migrating means wrapping the
hosts of each former `group:` value:

```yaml
groups:
  - name: Production
    hosts:
      - {id: web01, hostname: 10.0.0.10, users: [deploy]}
      - {id: db01, hostname: 10.0.0.20, users: [postgres]}
  - name: Lab
    hosts:
      - {id: lab, hostname: 192.168.1.50, port: 2222, users: [root]}
```

The config is read at startup: restart the container after changes
(`docker compose restart`). `known_hosts` is re-read on every connection.

## OAuth proxy

The app does **no authentication of its own**. It trusts the user header from the
proxy, so it **must not be reachable directly**. Either:

- bind only to localhost or an internal Docker network (default compose file binds to
  `127.0.0.1`), and/or
- set `server.trusted_proxies` to the proxy's address.

The proxy must support WebSockets (`/ws/ssh`). Example with oauth2-proxy as a reverse
proxy:

```bash
oauth2-proxy \
  --upstream=http://ssh-manager:8080 \
  --pass-user-headers=true \
  --reverse-proxy=true \
  ...
```

oauth2-proxy then sends `X-Forwarded-Email` / `X-Forwarded-User`. With nginx
`auth_request` and `--set-xauthrequest`, use `X-Auth-Request-Email` and forward it:

```nginx
location / {
    auth_request /oauth2/auth;
    auth_request_set $email $upstream_http_x_auth_request_email;
    proxy_set_header X-Forwarded-Email $email;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1h;
    proxy_pass http://127.0.0.1:8080;
}
```

The proxy must overwrite (not append to) the user header coming from clients.

## Audit log

One JSON object per line, written to `audit.file` and/or stdout:

```json
{"ts":"2026-11-26T09:25:39.786+00:00","type":"audit","event":"ssh.connected","session_id":"185e5f...","user":"op@example.com","client_ip":"10.1.2.3","host_id":"web01","target":"10.0.0.10:22","ssh_user":"deploy","key_fingerprint":"SHA256:egT8nP4D..."}
```

| Event | When |
|---|---|
| `app.started` / `app.stopped` | Process lifecycle |
| `http.access_denied` / `ws.access_denied` | Missing user header, untrusted peer, bad Origin |
| `ws.session_limit` | `max_sessions_per_user` reached |
| `ssh.connect_rejected` | Invalid request: unknown host, user not allowed, bad key/passphrase |
| `ssh.connect_attempt` | Key accepted, SSH connection starting |
| `ssh.connect_failed` | Connection failed: see `error_code` below (`error_detail` is operator-only) |
| `ssh.connected` | Shell opened |
| `ssh.disconnected` | Session ended: `reason`, `exit_status`, `duration_s`, `bytes_in`, `bytes_out`; `idle_timeout_s` when `reason` is `idle_timeout` |

### Error codes

`ssh.connect_failed` and `ssh.connect_rejected` carry a stable `error_code`. The browser
receives the same `code` with a user-safe message; the sanitized `error_detail` stays in
the audit log only.

| `error_code` | Meaning / what to check |
|---|---|
| `known_hosts_unreadable` | The server cannot read its known_hosts file: `chown 10001:10001` / `chmod 644` it |
| `host_key_unknown` | Host has no entry in known_hosts: add it with `ssh-keyscan` |
| `host_key_mismatch` | Entry exists but the key differs: reinstalled host or possible MITM |
| `auth_rejected` | Server refused the key for this user (not in `authorized_keys`) |
| `key_invalid` | Not base64 / unsupported key format |
| `key_passphrase_required` / `key_passphrase_wrong` | Encrypted key problems |
| `unknown_host` / `user_not_allowed` | Request not allowed by the config |
| `connect_timeout` / `connection_refused` / `dns_failure` / `host_unreachable` | Network problems |
| `ssh_protocol_error` | Negotiation failed or the server disconnected |
| `session_limit` | `max_sessions_per_user` reached |
| `idle_timeout` | Session closed by the idle watchdog |
| `internal_error` | Anything else (traceback in the app log) |

Private keys, passphrases and terminal contents are never logged. Commands typed in
the session are **not** recorded. Use server-side auditing (auditd, `pam_tty_audit`,
shell history forwarding) if you need that.

## Security notes

- **No key storage**: the key goes over the WebSocket once (TLS through the proxy),
  is parsed in memory, used for the handshake, then dropped. Python cannot guarantee
  wiping memory, but nothing is written to disk or logs.
- **No password, keyboard-interactive, agent, GSSAPI or host-based auth.** No agent
  or X11 forwarding. `~/.ssh/config` is never read.
- **Strict host key checking**: startup fails if a host has no usable known_hosts,
  unless `insecure_skip_host_key_check` is set explicitly for that host.
- **Allow-listed targets only**: the browser sends a host ID, never a hostname. Users
  are checked against the config.
- **WebSocket Origin check** against cross-site WebSocket hijacking.
- **HTTP hardening**: strict CSP (no inline scripts, no third-party resources), `X-Frame-Options: DENY`,
  `no-referrer`, `no-store`. Front-end libraries are vendored at build time, not
  loaded from a CDN.
- **Container**: non-root (UID 10001), read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, pid/memory limits, config mounted read-only.
- **Limits**: 1 MiB WebSocket messages, 64 KiB key size, terminal size clamped,
  idle timeout, per-user session limit.
- **Log injection**: control characters are stripped from audit fields.

## Development

The code is Python 3.13 (FastAPI, asyncssh, uvicorn) with a plain JavaScript front
end using xterm.js.

```bash
# run the tests in a container (includes an end-to-end test with an in-process SSH server)
docker run --rm -v "$PWD":/w -w /w python:3.13-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q tests"

# run locally without a proxy: set require_user_header: false in your config
docker build -t ssh-manager . && docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/config:/app/config:ro" ssh-manager
```

Project layout:

```
app/            FastAPI app (main.py), SSH bridge, config, audit, key parsing
static/         index.html, assets/app.js, assets/style.css
frontend/       package.json + lock for xterm.js (vendored at image build)
tests/          pytest suite
Dockerfile      multi-stage build (node -> python builder -> slim runtime)
```

