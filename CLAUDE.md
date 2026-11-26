# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A web SSH client: FastAPI + asyncssh backend, xterm.js front end, runs in Docker
behind an OAuth proxy. Hosts and allowed users come from a YAML config. Auth is
private key only, pasted base64 per connection. See README.md for user docs.

The UI, logs, code comments and docs are all **in English**.

## Layout

- `app/main.py`: app factory `create_app(cfg=None)`, middleware (identity/trusted
  proxy, security headers), `/api/hosts`, `/healthz`, WebSocket `/ws/ssh`, per-user
  session registry.
- `app/ssh_session.py`: `SSHBridge`, which connects with asyncssh and pumps data
  between WebSocket and PTY, plus the idle watchdog and audit events per session.
- `app/config.py`: strict pydantic models (`extra="forbid"`), `load_config()`. The YAML
  is group based: `groups[].hosts[]`. `AppConfig.hosts` is a derived, flattened list in
  which each host carries its group (`host.group`/`group_name`); a host must not set
  `group` itself. Code and tests should use `cfg.hosts`, build configs with `groups`.
- `app/audit.py`: JSON-lines audit logger. `audit(event, **fields)`.
- `app/keys.py`: base64/PEM key decoding with user-safe error messages; `KeyError_`
  subclasses carry a stable `code`.
- `app/errors.py`: `classify_error(exc, host, known_hosts_path, username)` maps connect
  failures to `(error_code, user_message, detail)`. `detail` is audit-only.
- `static/`: `index.html`, `assets/app.js` (an IIFE, no build step), `assets/style.css`.
- `frontend/package.json` + lock: pinned xterm.js packages. The Dockerfile copies
  their UMD bundles to `static/assets/vendor/`. That folder is gitignored and not
  committed.
- `tests/test_app.py`: unit tests and an end-to-end test using an in-process asyncssh
  server.

## WebSocket protocol (`/ws/ssh`)

Client → server, JSON text frames:
- `{"type":"connect","host_id","username","key","passphrase","cols","rows"}`: must be first, within 120 s
- `{"type":"input","data":"..."}`
- `{"type":"resize","cols","rows"}`
- `{"type":"ping"}`

Server → client: **binary** frames carry raw terminal output. JSON text frames are
`status` (`connecting|connected|closed`, `closed` has a `reason`), `error`
(`{"type":"error","code":"<error_code>","message":"..."}`), `idle_warning`
(`{"type":"idle_warning","seconds_left":N}`) and `pong`. Never put `error_detail` in a
browser message.

## Front end behaviour notes

- `Session.doFit()` is coalesced with `requestAnimationFrame` and skips `fit()` when the
  proposed cols/rows equal the current ones. Do not call `fit.fit()` directly from a
  `ResizeObserver`: in fullscreen it caused jitter and resize-message floods.
- Tab reordering uses HTML5 drag & drop on `.tab` elements; `syncTabOrder()` keeps
  `state.tabs` (a Map) in the same order as the DOM. Order is not persisted.
- Double-clicking a host in the connect dialog submits the form when the key is filled
  (`requestSubmit()`, so `submitDialog` validation still applies).

## Commands

No local venv (python3-venv is not installed on the dev host). Use Docker:

```bash
# tests
docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/w -w /w python:3.13-slim \
  sh -c "pip install -q --user -r requirements-dev.txt && python -m pytest -q -p no:cacheprovider tests"

# build image / run
docker build -t ssh-manager .
docker compose up -d --build
```

## Security invariants (do not break)

- Never log, persist or echo private keys, passphrases or terminal data. `audit()`
  drops keys named `key`, `passphrase`, `password`, `data`, etc. Keep it that way.
- Only connect to hosts from config, by `host_id`. Never accept a hostname from the
  client. The username must be in `host.users`.
- asyncssh options stay locked down: `config=None`, `agent_path=None`, no
  forwarding, `password_auth/kbdint_auth/gss_auth/host_based_auth=False`.
- Host key checking is on by default. Missing known_hosts fails startup.
- The WebSocket checks Origin and the identity header. HTTP goes through `IdentityMiddleware`.
- CSP: no inline `<script>`, no inline event handlers, no CDNs. `style-src` allows
  `'unsafe-inline'` only because xterm.js injects `<style>` elements.
- The front end must never store the key in localStorage, sessionStorage or cookies.
  (Only the non-secret scrollback and font size numbers are kept in localStorage.) Reconnect
  and duplicate may reuse the key only when the user ticked "Keep key"; never retain
  it silently.
- Run a single uvicorn worker: the session limits are kept in process memory.
- The container runs as UID 10001 with a read-only root fs. Only `/var/log/ssh-manager`
  and `/tmp` are writable.

## Gotchas

- asyncssh calls `getpass.getuser()`. `ssh_session.py` sets `USER` as a fallback
  so arbitrary container UIDs work.
- Encrypted OpenSSH-format keys need `bcrypt` (`asyncssh[bcrypt]`).
- An encrypted key with no passphrase raises `KeyImportError`, not
  `KeyEncryptionError`. `keys.py` handles both.
- Clipboard read (right-click paste) works only in a secure context (HTTPS/localhost).
- When bumping dependencies, update `requirements.txt` (pinned), and for xterm
  update `frontend/package.json` and regenerate `package-lock.json` (e.g. with
  `docker run --rm -v "$PWD/frontend":/w -w /w node:22-alpine npm install --package-lock-only`).
  Check that the UMD global names (`Terminal`, `FitAddon.FitAddon`,
  `WebLinksAddon.WebLinksAddon`) still match `app.js`.
