"""Detectors that produce early warnings without any change to the app."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from .clientip import network_prefix
from .config import HoneypotConfig, LoginConfig, SessionConfig
from .paths import path_matches
from .store import SlidingWindowCounter, TTLCache


class HoneypotDetector:
    """Decoy paths no legitimate user ever requests (e.g. /.env, /backup.zip)."""

    def __init__(self, cfg: HoneypotConfig) -> None:
        self._cfg = cfg

    def is_trap(self, path: str) -> bool:
        return self._cfg.enabled and path_matches(path, self._cfg.paths)


@dataclass(frozen=True)
class LoginSignal:
    scope: str  # "ip" | "global"
    count: int
    window_seconds: int


class LoginMonitor:
    """Detects credential stuffing / brute force from failed-login responses."""

    def __init__(self, cfg: LoginConfig, max_keys: int) -> None:
        self._cfg = cfg
        self._per_ip: SlidingWindowCounter[str] = SlidingWindowCounter(
            cfg.window_seconds, max_keys, cfg.per_ip_threshold
        )
        self._global: SlidingWindowCounter[str] = SlidingWindowCounter(cfg.window_seconds, 1, cfg.global_threshold)

    def is_login_path(self, path: str) -> bool:
        return self._cfg.enabled and path_matches(path, self._cfg.paths)

    def is_failure(self, status: int) -> bool:
        return status in self._cfg.failure_statuses

    def record_failure(self, client_ip: Optional[str]) -> list[LoginSignal]:
        """Count one failed login. Pass ``None`` when the client address is unknown:
        the failure then counts only towards the site-wide total."""
        signals = []
        if client_ip is not None:
            ip_count = self._per_ip.hit(client_ip)
            if ip_count >= self._cfg.per_ip_threshold:
                signals.append(LoginSignal("ip", ip_count, self._cfg.window_seconds))
        global_count = self._global.hit("all")
        if global_count >= self._cfg.global_threshold:
            signals.append(LoginSignal("global", global_count, self._cfg.window_seconds))
        return signals


def parse_cookies(header_values: list[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for header in header_values:
        for part in header.split(";"):
            name, sep, value = part.strip().partition("=")
            if sep and name and name not in cookies:
                cookies[name] = value.strip().strip('"')
    return cookies


@dataclass(frozen=True)
class _Fingerprint:
    user_agent: str
    accept_language: str
    net: str


@dataclass(frozen=True)
class SessionSignal:
    kind: str  # "device_change" | "network_change"
    severity: str
    detail: str
    session_hash: str


class SessionMonitor:
    """Flags a session token being used from a different device/network.

    The first fingerprint seen for a session is kept (an attacker replaying a
    stolen cookie cannot overwrite it). Session IDs are stored only as
    SHA-256 hashes.
    """

    def __init__(self, cfg: SessionConfig, max_keys: int) -> None:
        self._cfg = cfg
        self._seen: TTLCache[str, _Fingerprint] = TTLCache(max_keys, cfg.ttl_seconds)

    def observe(
        self,
        cookie_headers: list[str],
        client_ip: str,
        user_agent: str,
        accept_language: str,
    ) -> Optional[SessionSignal]:
        if not self._cfg.enabled or not self._cfg.cookie_names:
            return None
        cookies = parse_cookies(cookie_headers)
        token = next((cookies[n] for n in self._cfg.cookie_names if cookies.get(n)), None)
        if token is None:
            return None
        session_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        current = _Fingerprint(user_agent, accept_language, network_prefix(client_ip))
        known = self._seen.get(session_hash)
        if known is None:
            self._seen.set(session_hash, current)
            return None
        if known.user_agent != current.user_agent or known.accept_language != current.accept_language:
            return SessionSignal(
                "device_change",
                "high",
                f"session first seen from network {known.net}, now used by a different "
                f"browser/device from {current.net}",
                session_hash,
            )
        if known.net != current.net and self._cfg.alert_on_ip_change:
            return SessionSignal(
                "network_change",
                "low",
                f"session moved from network {known.net} to {current.net}",
                session_hash,
            )
        return None
