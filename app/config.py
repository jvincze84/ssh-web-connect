"""Configuration loading and validation.

The configuration is a single YAML file. It is validated strictly with
pydantic: unknown keys are rejected so that typos fail at startup instead
of silently weakening security settings.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_PATH = "/app/config/config.yaml"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# POSIX-ish user name, conservative on purpose.
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ServerConfig(_Strict):
    # Header set by the OAuth proxy that identifies the logged-in user.
    user_header: str = "X-Forwarded-Email"
    # Reject requests that do not carry the user header.
    require_user_header: bool = True
    # If non-empty, only these peers (IPs / CIDRs) may talk to the app.
    trusted_proxies: list[str] = Field(default_factory=list)
    # Allowed WebSocket Origins. Empty list = Origin must match the Host header.
    allowed_origins: list[str] = Field(default_factory=list)
    # Close a session after this many seconds of inactivity (0 = never).
    # Can be overridden per host with hosts[].idle_timeout.
    idle_timeout: int = Field(default=1800, ge=0)
    # What counts as activity: "any" = keystrokes and server output (tail -f keeps
    # the session alive), "input" = only keystrokes from the browser.
    idle_activity: Literal["any", "input"] = "any"
    # Seconds before the idle close at which the browser is warned (0 = no warning).
    idle_warning: int = Field(default=60, ge=0)
    # Maximum number of concurrent SSH sessions per user (0 = unlimited).
    max_sessions_per_user: int = Field(default=10, ge=0)

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for item in v:
            ipaddress.ip_network(item, strict=False)
        return v

    @field_validator("allowed_origins")
    @classmethod
    def _valid_origins(cls, v: list[str]) -> list[str]:
        for item in v:
            if not re.match(r"^https?://[^/]+$", item):
                raise ValueError(f"invalid origin {item!r} (expected scheme://host[:port])")
        return [o.lower() for o in v]

    @model_validator(mode="after")
    def _warning_before_timeout(self) -> "ServerConfig":
        if self.idle_timeout > 0 and self.idle_warning >= self.idle_timeout:
            raise ValueError("server.idle_warning must be smaller than server.idle_timeout")
        return self

    def trusted_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n, strict=False) for n in self.trusted_proxies]


class SSHConfig(_Strict):
    # OpenSSH known_hosts file used to verify server host keys.
    known_hosts: Optional[str] = "/app/config/known_hosts"
    connect_timeout: int = Field(default=15, ge=1, le=300)
    keepalive_interval: int = Field(default=30, ge=0)
    term_type: str = "xterm-256color"


class UIConfig(_Strict):
    # Default scrollback (lines) per terminal, and the upper bound for the
    # per-browser override.
    scrollback: int = Field(default=10000, ge=100, le=1_000_000)
    scrollback_max: int = Field(default=100_000, ge=100, le=1_000_000)

    @model_validator(mode="after")
    def _bounds(self) -> "UIConfig":
        if self.scrollback > self.scrollback_max:
            raise ValueError("ui.scrollback must be <= ui.scrollback_max")
        return self


class AuditConfig(_Strict):
    # Path of the JSON-lines audit log. None disables the file sink.
    file: Optional[str] = "/var/log/ssh-manager/audit.log"
    # Also write audit events to stdout (container logs).
    stdout: bool = True
    max_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    backup_count: int = Field(default=10, ge=0)


class HostConfig(_Strict):
    id: str
    name: Optional[str] = None
    hostname: str
    port: int = Field(default=22, ge=1, le=65535)
    users: list[str] = Field(min_length=1)
    # Filled in from the enclosing group; must not be set in the YAML.
    group: Optional[str] = None
    description: Optional[str] = None
    # Per-host known_hosts override.
    known_hosts: Optional[str] = None
    # Per-host override of server.idle_timeout (seconds, 0 = never).
    idle_timeout: Optional[int] = Field(default=None, ge=0)
    # DANGEROUS: disables host key verification for this host.
    insecure_skip_host_key_check: bool = False

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"invalid host id {v!r}")
        return v

    @field_validator("users")
    @classmethod
    def _valid_users(cls, v: list[str]) -> list[str]:
        for u in v:
            if not _USER_RE.match(u):
                raise ValueError(f"invalid user name {u!r}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate user names")
        return v

    @property
    def group_name(self) -> str:
        return self.group or "Default"

    @property
    def display_name(self) -> str:
        return self.name or self.id


class GroupConfig(_Strict):
    name: str = Field(min_length=1, max_length=64)
    hosts: list[HostConfig] = Field(min_length=1)

    @field_validator("hosts")
    @classmethod
    def _no_host_group(cls, v: list[HostConfig]) -> list[HostConfig]:
        for h in v:
            if h.group is not None:
                raise ValueError(
                    f"host {h.id!r}: 'group' must not be set on a host; "
                    "hosts belong to the group they are listed under")
        return v


class AppConfig(_Strict):
    server: ServerConfig = Field(default_factory=ServerConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    groups: list[GroupConfig] = Field(min_length=1)

    @property
    def hosts(self) -> list[HostConfig]:
        """All hosts, flattened in config order, each carrying its group name."""
        return [h.model_copy(update={"group": g.name}) for g in self.groups for h in g.hosts]

    @model_validator(mode="after")
    def _unique_groups(self) -> "AppConfig":
        names = [g.name for g in self.groups]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(f"duplicate group names: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _unique_ids(self) -> "AppConfig":
        ids = [h.id for h in self.hosts]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ValueError(f"duplicate host ids: {sorted(dupes)}")
        return self

    @model_validator(mode="after")
    def _host_idle_warning(self) -> "AppConfig":
        warn = self.server.idle_warning
        for h in self.hosts:
            if h.idle_timeout and warn and warn >= h.idle_timeout:
                raise ValueError(
                    f"host {h.id!r}: idle_timeout must be larger than server.idle_warning")
        return self

    def idle_timeout_for(self, host: HostConfig) -> int:
        return self.server.idle_timeout if host.idle_timeout is None else host.idle_timeout

    def get_host(self, host_id: str) -> Optional[HostConfig]:
        for h in self.hosts:
            if h.id == host_id:
                return h
        return None

    def known_hosts_for(self, host: HostConfig) -> Optional[str]:
        """Return the known_hosts path for a host, or None if checking is disabled."""
        if host.insecure_skip_host_key_check:
            return None
        return host.known_hosts or self.ssh.known_hosts


class ConfigError(Exception):
    pass


def load_config(path: str | os.PathLike[str] | None = None) -> AppConfig:
    path = Path(path or os.environ.get("SSH_MANAGER_CONFIG", DEFAULT_CONFIG_PATH))
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping: {path}")
    try:
        cfg = AppConfig.model_validate(raw)
    except ValueError as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc

    # Fail fast if host key verification is configured but the file is missing.
    for host in cfg.hosts:
        kh = cfg.known_hosts_for(host)
        if kh is None:
            if not host.insecure_skip_host_key_check:
                raise ConfigError(
                    f"host {host.id!r}: no known_hosts configured; set ssh.known_hosts "
                    "or explicitly enable insecure_skip_host_key_check"
                )
        elif not Path(kh).is_file():
            raise ConfigError(f"host {host.id!r}: known_hosts file not found: {kh}")
        elif not os.access(kh, os.R_OK):
            raise ConfigError(
                f"host {host.id!r}: known_hosts not readable by UID {os.getuid()}: "
                f"chown/chmod it ({kh})"
            )
    return cfg
