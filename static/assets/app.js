/* SSH Manager front-end.
 *
 * Each tab owns one xterm.js Terminal and one WebSocket to /ws/ssh.
 * The private key is sent once in the "connect" message and is never stored
 * in localStorage/sessionStorage/cookies. If the user ticks "keep key", it is
 * kept in a JS variable only, and is lost on reload.
 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const state = {
    hosts: [],
    tabs: new Map(), // id -> Session
    activeId: null,
    nextId: 1,
    rememberedKey: null, // { key, passphrase } kept only in memory
    ui: { scrollback: 10000, scrollback_max: 100000 }, // server defaults (/api/hosts)
    userScrollback: null, // per-browser override (non-secret, kept in localStorage)
    userFontSize: null,   // per-browser override (non-secret, kept in localStorage)
  };

  const SCROLLBACK_KEY = "ssh-manager.scrollback";
  const FONTSIZE_KEY = "ssh-manager.fontsize";
  const DEFAULT_FONT_SIZE = 14, MIN_FONT_SIZE = 8, MAX_FONT_SIZE = 32;
  // Errors that retrying with the same key/input cannot fix: ask for the key again.
  const KEY_ERRORS = new Set(["key_invalid", "key_passphrase_required", "key_passphrase_wrong", "auth_rejected"]);

  function effectiveScrollback() {
    return state.userScrollback || state.ui.scrollback;
  }

  function effectiveFontSize() {
    return state.userFontSize || DEFAULT_FONT_SIZE;
  }

  function loadUserFontSize() {
    try {
      const n = parseInt(localStorage.getItem(FONTSIZE_KEY), 10);
      if (n >= MIN_FONT_SIZE && n <= MAX_FONT_SIZE) state.userFontSize = n;
    } catch (e) { /* storage unavailable */ }
  }

  function loadUserScrollback() {
    try {
      const n = parseInt(localStorage.getItem(SCROLLBACK_KEY), 10);
      if (Number.isFinite(n) && n >= 100) state.userScrollback = Math.min(n, state.ui.scrollback_max);
    } catch (e) { /* storage unavailable */ }
  }

  // ------------------------------------------------------------------ utils
  let toastTimer = null;
  function toast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 1800);
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children) node.append(c);
    return node;
  }

  async function copyText(text) {
    if (!text) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = el("textarea", { class: "visually-hidden" });
        ta.value = text;
        document.body.append(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      toast("Copied to clipboard");
    } catch (e) {
      toast("Copy failed: clipboard not available");
    }
  }

  async function readClipboard() {
    if (!navigator.clipboard || !window.isSecureContext || !navigator.clipboard.readText) {
      toast("Paste requires HTTPS (secure context)");
      return null;
    }
    try {
      return await navigator.clipboard.readText();
    } catch (e) {
      toast("Clipboard read was denied by the browser");
      return null;
    }
  }

  function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  // ---------------------------------------------------------------- session
  class Session {
    constructor(host, username) {
      this.id = state.nextId++;
      this.host = host;
      this.username = username;
      this.status = "new";
      this.ws = null;

      this.container = el("div", { class: "terminal-pane", id: "pane-" + this.id });
      $("terminals").append(this.container);

      this.term = new window.Terminal({
        cursorBlink: true,
        fontFamily: 'ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace',
        fontSize: effectiveFontSize(),
        scrollback: effectiveScrollback(),
        allowProposedApi: false,
        rightClickSelectsWord: false,
        theme: { background: "#0f1115", foreground: "#d8dee9" },
      });
      this.fit = new window.FitAddon.FitAddon();
      this.term.loadAddon(this.fit);
      if (window.WebLinksAddon) {
        this.term.loadAddon(new window.WebLinksAddon.WebLinksAddon((ev, uri) => {
          const w = window.open(uri, "_blank", "noopener,noreferrer");
          if (w) w.opener = null;
        }));
      }
      this.term.open(this.container);

      // Auto-copy selected text.
      let selTimer = null;
      this.term.onSelectionChange(() => {
        clearTimeout(selTimer);
        selTimer = setTimeout(() => {
          if (this.term.hasSelection()) copyText(this.term.getSelection());
        }, 150);
      });

      // Right click = paste from clipboard.
      this.container.addEventListener("contextmenu", async (ev) => {
        ev.preventDefault();
        const text = await readClipboard();
        if (text) {
          this.term.paste(text); // honours bracketed paste mode -> onData
          this.term.focus();
        }
      });

      this.term.onData((data) => this.send({ type: "input", data }));
      this.term.onResize(({ cols, rows }) => this.send({ type: "resize", cols, rows }));

      this.resizeObserver = new ResizeObserver(() => this.doFit());
      this.resizeObserver.observe(this.container);

      this.lastError = null; // { code, message } of the last failed/closed connection
      this.closeReason = null;
      this.hasConnected = false;
      this.overlay = this.buildOverlay();
      this.container.append(this.overlay);

      this.tabEl = this.buildTab();
      $("tabs").append(this.tabEl);
    }

    get title() {
      return `${this.username}@${this.host.name}`;
    }

    buildTab() {
      const dot = el("span", { class: "status-dot" });
      const label = el("span", { class: "tab-label", text: this.title, title: `${this.username}@${this.host.hostname}:${this.host.port}` });
      const close = el("button", { class: "tab-close", type: "button", title: "Close session", "aria-label": "Close session", text: "×" });
      const redo = el("button", { class: "tab-reconnect", type: "button", title: "Reconnect", "aria-label": "Reconnect", text: "\u21bb", hidden: "" });
      const tab = el("div", { class: "tab", role: "tab", tabindex: "0" }, dot, label, redo, close);
      redo.addEventListener("click", (ev) => { ev.stopPropagation(); activate(this.id); this.reconnect(); });
      this.redoEl = redo;
      tab.addEventListener("click", (ev) => {
        if (ev.target === close) return;
        activate(this.id);
      });
      tab.addEventListener("auxclick", (ev) => {
        if (ev.button === 1) closeSession(this.id);
      });
      tab.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") activate(this.id);
      });
      close.addEventListener("click", () => closeSession(this.id));
      this.dotEl = dot;
      return tab;
    }

    setStatus(s) {
      this.status = s;
      this.dotEl.className = "status-dot status-" + s;
      this.redoEl.hidden = !(s === "closed" || s === "error");
      if (s === "connecting" || s === "connected") this.hideOverlay();
      updateToolbar();
    }

    buildOverlay() {
      this.overlayMsg = el("span", { class: "overlay-msg" });
      this.reconnectBtn = el("button", { class: "btn btn-primary btn-small", type: "button", text: "\u21bb Reconnect" });
      const closeBtn = el("button", { class: "btn btn-small", type: "button", text: "Close tab" });
      this.reconnectBtn.addEventListener("click", () => this.reconnect());
      closeBtn.addEventListener("click", () => closeSession(this.id));
      return el("div", { class: "session-overlay", role: "alert", hidden: "" }, this.overlayMsg, this.reconnectBtn, closeBtn);
    }

    showOverlay() {
      const reasons = {
        remote_closed: "The remote side closed the connection",
        client_closed: "Connection closed",
        idle_timeout: "Session closed after inactivity",
      };
      const text = (this.lastError && this.lastError.message) ||
        reasons[this.closeReason] || "Session ended";
      this.overlayMsg.textContent = `Session ended: ${text}`;
      this.overlay.hidden = false;
      if (state.activeId === this.id) this.reconnectBtn.focus();
    }

    hideOverlay() {
      this.overlay.hidden = true;
    }

    // Reconnect in this same tab (terminal history is kept). The key is only reused
    // when the user opted in via "Keep key"; otherwise ask for it again.
    reconnect() {
      if (this.status === "connecting" || this.status === "connected") return;
      const code = this.lastError && this.lastError.code;
      if (state.rememberedKey && !KEY_ERRORS.has(code)) {
        startSession(this.host, this.username, state.rememberedKey.key, state.rememberedKey.passphrase, this);
        return;
      }
      openConnectDialog({
        host: this.host,
        username: this.username,
        lockHost: true,
        title: `Reconnect to ${this.title}`,
        submitLabel: "Reconnect",
        onSubmit: ({ key, passphrase }) =>
          startSession(this.host, this.username, key, passphrase, this),
      });
    }

    doFit() {
      if (!this.container.classList.contains("active")) return;
      try { this.fit.fit(); } catch (e) { /* not visible yet */ }
    }

    send(obj) {
      if (this.ws && this.ws.readyState === WebSocket.OPEN && this.status === "connected") {
        this.ws.send(JSON.stringify(obj));
      }
    }

    connect(key, passphrase) {
      if (this.ws) { // drop the previous socket; its late events are ignored below
        const old = this.ws;
        this.ws = null;
        try { old.close(); } catch (e) { /* ignore */ }
      }
      this.lastError = null;
      this.closeReason = null;
      if (this.hasConnected) {
        this.term.writeln(`\r\n\x1b[90m--- reconnecting ${new Date().toLocaleTimeString()} ---\x1b[0m`);
      }
      this.hasConnected = true;
      this.setStatus("connecting");
      this.term.writeln(`\x1b[90mConnecting to ${this.username}@${this.host.hostname}:${this.host.port} ...\x1b[0m`);
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${proto}//${location.host}/ws/ssh`);
      ws.binaryType = "arraybuffer";
      this.ws = ws;

      ws.onopen = () => {
        if (ws !== this.ws) return;
        this.doFit();
        ws.send(JSON.stringify({
          type: "connect",
          host_id: this.host.id,
          username: this.username,
          key: key,
          passphrase: passphrase || "",
          cols: this.term.cols,
          rows: this.term.rows,
        }));
        key = passphrase = null; // drop local references
      };

      ws.onmessage = (ev) => {
        if (ws !== this.ws) return;
        if (ev.data instanceof ArrayBuffer) {
          this.term.write(new Uint8Array(ev.data));
          return;
        }
        let msg;
        try { msg = JSON.parse(ev.data); } catch (e) { return; }
        if (msg.type === "status") {
          if (msg.state === "connected") {
            this.setStatus("connected");
            this.doFit();
            this.send({ type: "resize", cols: this.term.cols, rows: this.term.rows });
            if (state.activeId === this.id) this.term.focus();
          } else if (msg.state === "closed") {
            this.closeReason = msg.reason || null;
            if (this.status !== "error") this.setStatus("closed");
          }
        } else if (msg.type === "idle_warning") {
          const n = Number(msg.seconds_left) || 0;
          this.term.writeln(`\r\n\x1b[33m[No activity: this session closes in ${n} s. Press any key to keep it open.]\x1b[0m`);
          toast(`${this.title}: closing in ${n} s due to inactivity`);
        } else if (msg.type === "error") {
          this.lastError = { code: msg.code || "", message: String(msg.message || "") };
          this.term.writeln(`\r\n\x1b[31m${msg.message}\x1b[0m`);
          this.setStatus("error");
        }
      };

      ws.onclose = (ev) => {
        if (ws !== this.ws) return;
        if (this.status !== "error") this.setStatus("closed");
        if (ev.code === 1008 && !this.lastError) {
          this.lastError = { code: "access_denied", message: "Access denied" };
        }
        const why = ev.code === 1008 ? " (access denied)" : "";
        this.term.writeln(`\r\n\x1b[90m[Connection closed${why}]\x1b[0m`);
        this.showOverlay();
      };
    }

    destroy() {
      try { if (this.ws) this.ws.close(); } catch (e) { /* ignore */ }
      this.resizeObserver.disconnect();
      this.term.dispose();
      this.container.remove();
      this.tabEl.remove();
    }
  }

  // ------------------------------------------------------------------- tabs
  function activate(id) {
    state.activeId = id;
    for (const [sid, s] of state.tabs) {
      const on = sid === id;
      s.container.classList.toggle("active", on);
      s.tabEl.classList.toggle("active", on);
      s.tabEl.setAttribute("aria-selected", on ? "true" : "false");
      if (on) {
        requestAnimationFrame(() => {
          s.doFit();
          if (s.overlay.hidden) s.term.focus(); else s.reconnectBtn.focus();
        });
      }
    }
    $("empty-state").hidden = state.tabs.size > 0;
    updateToolbar();
  }

  function updateToolbar() {
    $("dup-tab").disabled = !state.tabs.has(state.activeId);
  }

  // Create a session (or reuse `target` for a reconnect) and connect it.
  function startSession(host, username, key, passphrase, target) {
    const s = target || new Session(host, username);
    if (!target) state.tabs.set(s.id, s);
    activate(s.id);
    s.connect(key, passphrase);
    return s;
  }

  function duplicateActive() {
    const src = state.tabs.get(state.activeId);
    if (!src) return;
    if (state.rememberedKey) {
      startSession(src.host, src.username, state.rememberedKey.key, state.rememberedKey.passphrase);
      return;
    }
    openConnectDialog({ host: src.host, username: src.username, focusKey: true });
  }

  function closeSession(id) {
    const s = state.tabs.get(id);
    if (!s) return;
    if (s.status === "connected" && !confirm(`Close session ${s.title}?`)) return;
    s.destroy();
    state.tabs.delete(id);
    if (state.activeId === id) {
      const ids = [...state.tabs.keys()];
      activate(ids.length ? ids[ids.length - 1] : null);
    } else {
      $("empty-state").hidden = state.tabs.size > 0;
    }
    updateToolbar();
  }

  // ----------------------------------------------------------------- dialog
  function renderHostOptions() {
    const filter = $("host-filter").value.trim().toLowerCase();
    const sel = $("host-select");
    const prev = sel.value;
    sel.replaceChildren();
    const groups = new Map();
    for (const h of state.hosts) {
      const hay = `${h.name} ${h.id} ${h.hostname} ${h.group} ${h.description || ""}`.toLowerCase();
      if (filter && !hay.includes(filter)) continue;
      if (!groups.has(h.group)) groups.set(h.group, []);
      groups.get(h.group).push(h);
    }
    for (const [group, hosts] of groups) {
      const og = el("optgroup", { label: group });
      for (const h of hosts) {
        og.append(el("option", { value: h.id, text: `${h.name}  (${h.hostname}:${h.port})` }));
      }
      sel.append(og);
    }
    if (prev && [...sel.options].some((o) => o.value === prev)) sel.value = prev;
    else if (sel.options.length) sel.selectedIndex = 0;
    renderUserOptions();
  }

  function selectedHost() {
    return state.hosts.find((h) => h.id === $("host-select").value) || null;
  }

  // Advisory reachability probe; never blocks connecting.
  let healthSeq = 0;
  async function checkHealth(host) {
    const box = $("host-health");
    const seq = ++healthSeq;
    box.className = "host-health";
    if (!host) { box.textContent = ""; return; }
    box.textContent = "Checking reachability...";
    let msg, cls;
    try {
      const res = await fetch(`/api/hosts/${encodeURIComponent(host.id)}/health`,
        { credentials: "same-origin", cache: "no-store" });
      if (!res.ok) throw new Error(String(res.status));
      const j = await res.json();
      if (j.reachable) { cls = "up"; msg = `Reachable (${j.latency_ms} ms)`; }
      else { cls = "down"; msg = "Unreachable (you can still try to connect)"; }
    } catch (_) {
      cls = ""; msg = "Reachability unknown";
    }
    if (seq !== healthSeq) return;  // a newer selection superseded this one
    box.className = "host-health" + (cls ? " " + cls : "");
    box.textContent = msg;
  }

  function renderUserOptions() {
    const host = selectedHost();
    const sel = $("user-select");
    sel.replaceChildren();
    $("host-details").textContent = host ? (host.description || "") : "";
    checkHealth(host);
    if (!host) return;
    for (const u of host.users) sel.append(el("option", { value: u, text: u }));
  }

  // Options: { host, username, lockHost, focusKey, title, submitLabel, onSubmit }.
  // Without onSubmit the dialog opens a new tab.
  let dialogCtx = {};

  function openConnectDialog(opts) {
    dialogCtx = opts || {};
    $("connect-error").textContent = "";
    $("host-filter").value = "";
    $("dialog-title").textContent = dialogCtx.title || "New SSH connection";
    $("connect-submit").textContent = dialogCtx.submitLabel || "Connect";
    renderHostOptions();
    if (dialogCtx.host) {
      $("host-select").value = dialogCtx.host.id;
      renderUserOptions();
      if (dialogCtx.username) $("user-select").value = dialogCtx.username;
    }
    const lock = !!dialogCtx.lockHost;
    for (const id of ["host-filter", "host-select", "user-select"]) $(id).disabled = lock;
    if (state.rememberedKey) {
      $("key-input").value = state.rememberedKey.key;
      $("passphrase-input").value = state.rememberedKey.passphrase;
      $("remember-key").checked = true;
    } else {
      $("key-input").value = "";
      $("passphrase-input").value = "";
      $("remember-key").checked = false;
    }
    $("connect-dialog").showModal();
    (lock || dialogCtx.focusKey ? $("key-input") : $("host-filter")).focus();
  }

  function openDialog() {
    openConnectDialog({});
  }

  function clearSecretsFromForm() {
    $("key-input").value = "";
    $("passphrase-input").value = "";
    $("key-file").value = "";
  }

  function submitDialog(ev) {
    ev.preventDefault();
    const host = selectedHost();
    const username = $("user-select").value;
    const key = $("key-input").value.trim();
    const passphrase = $("passphrase-input").value;
    if (!host) { $("connect-error").textContent = "Select a host."; return; }
    if (!username) { $("connect-error").textContent = "Select a user."; return; }
    if (!key) { $("connect-error").textContent = "Paste your base64-encoded private key."; return; }

    state.rememberedKey = $("remember-key").checked ? { key, passphrase } : null;
    clearSecretsFromForm();
    const ctx = dialogCtx;
    $("connect-dialog").close(); // the close handler resets dialogCtx

    if (ctx.onSubmit) ctx.onSubmit({ host, username, key, passphrase });
    else startSession(host, username, key, passphrase);
  }

  // --------------------------------------------------------------- settings
  function openSettings() {
    const input = $("scrollback-input");
    input.max = String(state.ui.scrollback_max);
    input.value = String(effectiveScrollback());
    $("fontsize-input").value = String(effectiveFontSize());
    $("scrollback-hint").textContent =
      `Lines kept per terminal (100 to ${state.ui.scrollback_max}; server default ${state.ui.scrollback}). ` +
      "Large values multiplied by many tabs use a lot of browser memory.";
    $("settings-error").textContent = "";
    $("settings-dialog").showModal();
    input.focus();
  }

  function applyScrollback(n) {
    state.userScrollback = n;
    try {
      if (n) localStorage.setItem(SCROLLBACK_KEY, String(n));
      else localStorage.removeItem(SCROLLBACK_KEY);
    } catch (e) { /* storage unavailable */ }
    for (const s of state.tabs.values()) s.term.options.scrollback = effectiveScrollback();
  }

  function applyFontSize(n) {
    state.userFontSize = n;
    try {
      if (n) localStorage.setItem(FONTSIZE_KEY, String(n));
      else localStorage.removeItem(FONTSIZE_KEY);
    } catch (e) { /* storage unavailable */ }
    for (const s of state.tabs.values()) {
      s.term.options.fontSize = effectiveFontSize();
      s.doFit();
    }
  }

  function submitSettings(ev) {
    ev.preventDefault();
    const n = parseInt($("scrollback-input").value, 10);
    if (!Number.isFinite(n) || n < 100 || n > state.ui.scrollback_max) {
      $("settings-error").textContent = `Scrollback: enter a number between 100 and ${state.ui.scrollback_max}.`;
      return;
    }
    const f = parseInt($("fontsize-input").value, 10);
    if (!Number.isFinite(f) || f < MIN_FONT_SIZE || f > MAX_FONT_SIZE) {
      $("settings-error").textContent = `Font size: enter a number between ${MIN_FONT_SIZE} and ${MAX_FONT_SIZE}.`;
      return;
    }
    applyScrollback(n === state.ui.scrollback ? null : n);
    applyFontSize(f === DEFAULT_FONT_SIZE ? null : f);
    $("settings-dialog").close();
  }

  async function loadKeyFile(ev) {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    if (file.size > 32 * 1024) { $("connect-error").textContent = "Key file is too large."; return; }
    const buf = await file.arrayBuffer();
    $("key-input").value = arrayBufferToBase64(buf);
    ev.target.value = "";
  }

  // ------------------------------------------------------------------- init
  async function init() {
    loadUserFontSize();
    $("new-tab").addEventListener("click", openDialog);
    $("empty-new").addEventListener("click", openDialog);
    $("dup-tab").addEventListener("click", duplicateActive);
    $("open-settings").addEventListener("click", openSettings);
    $("settings-form").addEventListener("submit", submitSettings);
    $("settings-cancel").addEventListener("click", () => $("settings-dialog").close());
    $("settings-reset").addEventListener("click", () => {
      applyScrollback(null);
      applyFontSize(null);
      $("settings-dialog").close();
    });
    // Ctrl+Shift+D duplicates the active session (capture phase: before xterm sees it).
    document.addEventListener("keydown", (ev) => {
      if (ev.ctrlKey && ev.shiftKey && !ev.altKey && !ev.metaKey && ev.key.toLowerCase() === "d") {
        if (document.querySelector("dialog[open]")) return;
        ev.preventDefault();
        ev.stopPropagation();
        duplicateActive();
      }
    }, true);
    $("connect-form").addEventListener("submit", submitDialog);
    $("connect-cancel").addEventListener("click", () => {
      clearSecretsFromForm();
      $("connect-dialog").close();
    });
    $("connect-dialog").addEventListener("cancel", clearSecretsFromForm);
    $("connect-dialog").addEventListener("close", () => { dialogCtx = {}; });
    $("host-filter").addEventListener("input", renderHostOptions);
    $("host-filter").addEventListener("keydown", (ev) => {
      if (ev.key === "ArrowDown") { ev.preventDefault(); $("host-select").focus(); }
    });
    $("host-select").addEventListener("change", renderUserOptions);
    $("host-select").addEventListener("dblclick", () => $("key-input").focus());
    $("key-file-btn").addEventListener("click", () => $("key-file").click());
    $("key-file").addEventListener("change", loadKeyFile);
    $("remember-key").addEventListener("change", (ev) => {
      if (!ev.target.checked) state.rememberedKey = null;
    });

    window.addEventListener("beforeunload", (ev) => {
      const active = [...state.tabs.values()].some((s) => s.status === "connected");
      if (active) { ev.preventDefault(); ev.returnValue = ""; }
    });

    try {
      const res = await fetch("/api/hosts", { credentials: "same-origin", cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      state.hosts = data.hosts || [];
      if (data.ui) state.ui = data.ui;
      loadUserScrollback();
      $("current-user").textContent = data.user || "";
    } catch (e) {
      $("empty-state").replaceChildren(el("p", { class: "form-error", text: "Failed to load host list: " + e.message }));
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
