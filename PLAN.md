# PLAN: next iteration

Status: **implemented** (all five items; open questions resolved as the plan assumed).
Five items, in the recommended implementation order.

| # | Item | Size | Touches |
|---|---|---|---|
| 1 | Clear error classification in the audit log | M | `ssh_session.py`, `keys.py`, `config.py`, tests |
| 2 | Idle timeout: more configurable + warning | S–M | `config.py`, `ssh_session.py`, `app.js` |
| 3 | Configurable scrollback | S | `config.py`, `main.py`, `app.js` |
| 4 | Reconnect button for dead sessions | M | `app.js`, `style.css`, `index.html` |
| 5 | "Duplicate" session button | S | `app.js`, `index.html` (reuses #4 refactor) |

---

## 1. Audit log: say *what* failed (known_hosts vs. bad key vs. network)

### Observed problem
Current audit entries for real failures look like this:

```json
{"event":"ssh.connect_failed","error":"Connection failed: Permission denied","error_type":"PermissionError"}
```

This is **not** an SSH auth failure. It is a local `PermissionError` raised while
asyncssh opened `/app/config/known_hosts` (the file was not readable by UID 10001).
Because `_friendly_error()` maps every `OSError` to "Connection failed: <strerror>",
it is indistinguishable from "server rejected the key". Also, `HostKeyNotVerifiable`
does not tell "host missing from known_hosts" apart from "host key changed".

### Changes
- **Stable `error_code` field** on `ssh.connect_failed` and `ssh.connect_rejected`,
  plus an operator-only `error_detail` (sanitized `str(exc)`; audit only, never sent
  to the browser). The user-facing message is derived from the code.

  | error_code | Cause | Detection |
  |---|---|---|
  | `known_hosts_unreadable` | known_hosts missing / no read permission | `PermissionError`/`FileNotFoundError` around connect, or pre-check with `os.access(path, R_OK)` |
  | `host_key_unknown` | host has no entry in known_hosts | `HostKeyNotVerifiable` + no match from `asyncssh.read_known_hosts(...).match(host, addr, port)` |
  | `host_key_mismatch` | entry exists but key differs (possible MITM / reinstall) | `HostKeyNotVerifiable` + entries exist |
  | `auth_rejected` | server refused the key for this user (bad key / not in authorized_keys) | `asyncssh.PermissionDenied` |
  | `key_invalid` | not base64 / unsupported format | `KeyError_` subclass |
  | `key_passphrase_required` / `key_passphrase_wrong` | encrypted key problems | `KeyError_` subclasses |
  | `user_not_allowed` / `unknown_host` | request not allowed by config | existing checks |
  | `connect_timeout` | TCP/SSH handshake timeout | `TimeoutError` |
  | `connection_refused` | port closed | `ConnectionRefusedError` |
  | `dns_failure` | hostname not resolvable | `socket.gaierror` |
  | `host_unreachable` | no route / network down | `OSError` with `EHOSTUNREACH`/`ENETUNREACH` |
  | `ssh_protocol_error` | negotiation failed, disconnect by server | `asyncssh.DisconnectError` |
  | `internal_error` | anything else | fallback, logged with traceback at app-log level |

- `keys.py`: replace the single `KeyError_` with a small hierarchy carrying a `code`.
- Implement as a `classify_error(exc, host, known_hosts_path) -> (code, user_message, detail)`
  function in a new `app/errors.py`, unit-testable without a network.
- Order matters: check `asyncssh.PermissionDenied` **before** `OSError`/`PermissionError`.
- `config.py` startup check: `is_file()` → also `os.access(path, os.R_OK)`, with a
  message like `known_hosts not readable by UID 10001: chown/chmod it`.
- Browser messages become specific, e.g. *"Host key not found in known_hosts. Add it
  with ssh-keyscan"*, *"Host key has CHANGED"*, *"Server rejected the key for user X"*,
  *"Server cannot read its known_hosts file (admin)"*.
- README: table of `error_code` values + troubleshooting section.

### Tests
- Unit: `classify_error` for each exception type (construct exceptions directly).
- E2E (existing in-process server): unknown host key, mismatched host key, rejected
  key, unreadable known_hosts (`chmod 000`), connection refused (closed port).
- Assert `error_code` in audit lines; assert `error_detail` never appears in WS messages.

---

## 2. Idle timeout

### Observed
`{"event":"ssh.disconnected","reason":"idle_timeout","duration_s":1823.6}`: the default
`server.idle_timeout: 1800` (30 min) closed the session. **It is already configurable**
(`server.idle_timeout` in config.yaml, seconds, `0` = disabled; restart required),
but it isn't discoverable and gives no warning.

### Changes
- Keep `server.idle_timeout` as the global default; add **per-host override**
  `idle_timeout` per host (under `groups[].hosts[]`) (e.g. longer for lab hosts, shorter for production).
- New `server.idle_activity: any | input` (default `any` = current behaviour; output
  such as `tail -f` keeps the session alive. `input` = only keystrokes count, which is
  stricter and better for compliance).
- New `server.idle_warning: 60` (seconds before closing; `0` = off). Server sends
  `{"type":"idle_warning","seconds_left":60}`. Front end prints a yellow notice in the
  terminal / shows a toast; any keypress resets the timer.
- Clearer close message: `Session closed after 30 min of inactivity (idle_timeout)`.
- Audit: add `idle_timeout_s` to the `ssh.disconnected` event when the reason is
  `idle_timeout`.
- Front end: an idle-closed session gets the Reconnect button from item 4.
- README + config.example.yaml: document all three keys prominently.

### Tests
- Small timeout (e.g. 2 s, warning 1 s) in the E2E test: receive `idle_warning`, then
  close with reason `idle_timeout`; per-host override wins over the global value;
  with `idle_activity: input`, server output alone does not prevent timeout.
- Config validation: `idle_warning < idle_timeout` when both are > 0.

---

## 3. Configurable scrollback (n lines)

### Changes
- Config: new section
  ```yaml
  ui:
    scrollback: 10000        # default lines per terminal
    scrollback_max: 100000   # upper bound for user override
  ```
  Validation: `100 <= scrollback <= scrollback_max <= 1_000_000`.
- API: extend `GET /api/hosts` with `"ui": {"scrollback": ..., "scrollback_max": ...}`
  (or add a `GET /api/settings` endpoint; the extension is simpler and needs one fetch).
- Front end: `new Terminal({ scrollback: settings.scrollback })` instead of the
  hard-coded `10000`.
- **Optional user override**: a small settings popover (gear icon in the top bar)
  with a "Scrollback lines" number input, clamped to `scrollback_max`, stored in
  `localStorage` (non-secret, allowed by CLAUDE.md rules). Applies to open terminals
  immediately via `term.options.scrollback = n`.
- Note in README: large scrollback × many tabs = browser memory (roughly
  100k lines × 10 tabs can reach hundreds of MB).

### Tests
- Config validation (bounds), `/api/hosts` contains `ui.scrollback`.
- Manual: change value, verify scroll history length in the browser.

---

## 4. Reconnect ("Reload") button when a session dies

### Changes (front end only, no protocol change)
- Refactor `Session` so `connect()` can be called repeatedly on the same tab:
  - new WebSocket each time; ignore events from stale sockets (`if (ws !== this.ws) return`);
  - keep the same `Terminal` (history preserved), print a separator line
    `--- reconnecting <time> ---`.
- When status becomes `closed` or `error`, show an overlay bar at the bottom of the
  pane: `[Session ended: <reason>]  [↻ Reconnect]  [Close tab]`. Also add a ↻ icon to the
  tab itself. Keyboard: `Enter` on the focused overlay reconnects.
- **Key handling (security rule: key is not kept unless the user opted in):**
  - if "Keep key in this tab's memory" is enabled → reconnect immediately;
  - otherwise → open the connect dialog **pre-filled with host + user (locked)**, so
    only the key/passphrase must be entered; on submit it reconnects *in the same tab*.
- Disable the Reconnect button while connecting (prevent double connects).
- Do not auto-reconnect on errors that can't heal by retrying (`user_not_allowed`,
  `host_key_mismatch`, `key_*`): show the button but with the error text. This uses the
  `error_code` from item 1 (sent to the browser in the `error` message as `code`).

### Tests
- Manual browser test: kill sshd / idle-timeout / network drop → overlay appears →
  reconnect with remembered key and with the dialog path; history preserved.
- Optional: Playwright smoke test (not in the repo yet; decide if it's worth adding).

---

## 5. "Duplicate session" button

### Changes
- Top bar: `[+ New] [⧉ Duplicate]`. Duplicate is disabled when there is no active tab.
- Opens a **new tab** with the active tab's host + user:
  - remembered key available → connects immediately;
  - otherwise → connect dialog pre-filled (host + user preselected but changeable),
    focus on the key field.
- Shortcut suggestion: `Ctrl+Shift+D` (must not collide with terminal keys; only
  handled when the dialog is closed).
- Context menu on a tab (right-click) is **not** used, since right-click = paste in
  the terminal; keep tab actions as buttons.
- Shared helper with item 4: `openConnectDialog({ host, username, lockHost, onSubmit })`
  and `startSession(host, username, key, passphrase, targetSession?)`.

### Tests
- Manual: duplicate with/without remembered key, duplicate of a closed session
  (allowed, it uses the same host/user), session-limit error shows properly.

---

## Follow-up: group-based config (implemented)

The YAML is now organised by group instead of a flat `hosts:` list with a `group:`
field per host:

```yaml
groups:
  - name: Production
    hosts:
      - {id: web01, hostname: 10.0.0.10, users: [deploy]}
```

- `GroupConfig(name, hosts)` in `config.py`; `AppConfig.groups` replaces `hosts`, which
  stays as a derived read-only property (flattened, `host.group` set from the group).
- Validation: group names unique, host ids unique across all groups, groups non-empty,
  `group` on a host is rejected. The old top-level `hosts:` is rejected (breaking change,
  no compatibility shim; configs must be migrated).
- `/api/hosts` output is unchanged (`group` per host), so the front end needed no change.
- Terminal font size (8 to 32 px, default 14) is a per-browser setting next to the
  scrollback in the settings dialog (gear icon), kept in `localStorage`. No config key.
- Group-level defaults (e.g. shared `users` or `known_hosts`) are not implemented.

## Follow-up: UI polish (implemented)

- **Double-click to connect**: double-click on a host in the connect dialog submits the form
  when the key field is filled; otherwise it focuses the key field.
- **Fullscreen jitter fix**: `doFit()` runs once per animation frame and only when the
  proposed cols/rows differ; `.terminals`/`.terminal-pane` use `overflow: hidden`.
- **Draggable tabs**: tabs can be reordered with drag & drop (drop marker on the left/right
  half of the target tab). Not persisted across reloads. Not yet verified in a real browser.

## Follow-up: status bar (implemented)

- Bottom status bar per terminal with remote CPU, memory and disk `/` usage as % with a 0-100 bar
  (green < 75, yellow >= 75, red >= 90).
- Collected server-side over SSH (`app/stats.py`), client-driven polling via `{"type":"stats"}`.
- Default interval 60 s (`ui.stats_interval`), user override in the settings dialog (localStorage),
  minimum 10 s enforced in config validation, server and UI. `ui.stats_enabled: false` turns it off.
- Decision: CPU is measured by two `/proc/stat` samples 1 s apart; memory uses `MemAvailable`.
- Open: not verified in a real browser; no E2E test (the in-process asyncssh test server has no exec
  support for the command), only unit tests for the parser and config bounds.

## Cross-cutting

- **Protocol additions** (update CLAUDE.md "WebSocket protocol"):
  `{"type":"error","code":"<error_code>","message":"..."}` and
  `{"type":"idle_warning","seconds_left":N}`.
- **Config additions** (update README table + `config.example.yaml`):
  `ui.scrollback`, `ui.scrollback_max`, `server.idle_activity`, `server.idle_warning`,
  `idle_timeout` per host (under `groups[].hosts[]`). All optional with defaults → existing configs keep working
  (strict `extra="forbid"` still rejects typos).
- Config is still loaded at startup only; hot reload is out of scope.
- Security invariants from CLAUDE.md stay unchanged; in particular reconnect/duplicate
  must **not** introduce silent key retention.

## Open questions (decide before implementing)

1. Scrollback: config-only, or also a per-browser user override (localStorage)? *Plan assumes both.*
2. Idle activity default: keep `any` (current) or switch to stricter `input`?
3. Should reconnect/duplicate keep the key per session in memory automatically, or only
   with the existing "Keep key" checkbox? *Plan assumes checkbox only (safer).*
4. Add a Playwright browser test to the repo for the UI flows (4, 5)?

## Immediate fix for the current deployment (no code change)

The `Permission denied` failures in `logs/audit.log` came from known_hosts permissions.
`config/known_hosts` is now `10001:10001` with mode `600`, which is readable by the
container. If it is ever recreated by another user, run
`sudo chown 10001:10001 config/known_hosts` or `chmod 644 config/known_hosts`.
To get longer sessions right now: raise `server.idle_timeout` in `config/config.yaml`
(or `0` to disable) and run `docker compose restart`.
