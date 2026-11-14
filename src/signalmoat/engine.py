"""The SignalMoat decision engine.

One engine, three ways to put it in front of an app:

* ``signalmoat.SignalMoat``   -- ASGI middleware (FastAPI, Starlette, ...)
* ``signalmoat proxy``        -- reverse proxy in front of an app in any language
* ``signalmoat sidecar``      -- decision API used by the Node and ASP.NET middleware

Pipeline per request:
    banned IP? -> honeypot? -> identify agent (Web Bot Auth / User-Agent)
    -> policy rules -> session-hijack check
and, once the app has answered, failed-login monitoring on the response status.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from .alerts import Alert, AlertDispatcher
from .clientip import resolve_client_ip
from .config import Config, load_config
from .detectors import HoneypotDetector, LoginMonitor, SessionMonitor
from .identity import AgentIdentity, classify
from .ja4 import JA4, browser_mismatch
from .ja4 import from_headers as ja4_from_headers
from .paths import normalize_decoded_path, normalize_match_path
from .policy import evaluate
from .state import StateBackend, build_state
from .webbotauth import (
    Fetcher,
    KeyDirectory,
    VerificationResult,
    WebBotAuthVerifier,
    _httpx_fetch,
    normalize_authority,
)

log = logging.getLogger("signalmoat")

UNKNOWN_IP = "unknown"
_HIGH_RISK_SIGNATURE_FAILURES = {"bad signature", "replayed nonce"}
_MAX_ALERT_PATH = 200
_MAX_ALERT_METHOD = 16


@dataclass
class RequestInfo:
    """What the engine needs to know about one HTTP request.

    ``path`` is the raw request path exactly as the client sent it (needed to
    verify signatures); ``match_path`` is its canonical form used for rules.
    Header names are lower-case; duplicates are kept in order.
    """

    method: str
    scheme: str
    authority: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    match_path: str

    def header_values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]

    @classmethod
    def from_parts(
        cls,
        *,
        method: str,
        scheme: str,
        host: str,
        target: str,
        headers: Iterable[tuple[str, str]],
    ) -> RequestInfo:
        """Build from a raw request target (``/path?query``) and header pairs."""
        raw_path, _, query = target.partition("?")
        raw_path = raw_path or "/"
        lowered = [(str(k).lower(), str(v)) for k, v in headers]
        if not host:
            host = next((v for k, v in lowered if k == "host"), "")
        scheme = scheme.lower()
        return cls(
            method=method.upper(),
            scheme=scheme,
            authority=normalize_authority(host, scheme),
            path=raw_path,
            query=query,
            headers=lowered,
            match_path=normalize_match_path(raw_path),
        )

    @classmethod
    def from_scope(cls, scope: Any) -> RequestInfo:
        """Build from an ASGI HTTP or WebSocket scope.

        A WebSocket handshake is an HTTP GET; ``ws``/``wss`` map to ``http``/``https``.
        """
        headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope.get("headers", [])]
        scheme = {"ws": "http", "wss": "https"}.get(scope.get("scheme", "http"), scope.get("scheme", "http"))
        host = next((v for k, v in headers if k == "host"), "")
        if not host and scope.get("server"):
            server_host, server_port = scope["server"][0], scope["server"][1]
            host = f"{server_host}:{server_port}" if server_port else str(server_host)
        raw = scope.get("raw_path")
        if raw:
            raw_path = raw.decode("latin-1").split("?", 1)[0] or "/"
            match_path = normalize_match_path(raw_path)
        else:  # no raw path available: scope["path"] is already percent-decoded
            raw_path = scope.get("path", "/") or "/"
            match_path = normalize_decoded_path(raw_path)
        return cls(
            method=scope.get("method", "GET").upper(),
            scheme=scheme,
            authority=normalize_authority(host, scheme),
            path=raw_path,
            query=scope.get("query_string", b"").decode("latin-1"),
            headers=headers,
            match_path=match_path,
        )


@dataclass
class Verdict:
    request: RequestInfo
    client_ip: str
    identity: AgentIdentity
    block_status: Optional[int] = None
    #: True when the caller should report the response status (login monitoring).
    watch_response: bool = False
    #: JA4 TLS fingerprint from the trusted TLS terminator, when enabled and present.
    ja4: Optional[JA4] = None

    @property
    def blocked(self) -> bool:
        return self.block_status is not None


class Engine:
    def __init__(
        self,
        config: Union[Config, str, Path, dict, None] = None,
        *,
        dispatcher: Optional[AlertDispatcher] = None,
        key_fetcher: Fetcher = _httpx_fetch,
        clock: Callable[[], float] = time.time,
        state: Optional[StateBackend] = None,
    ) -> None:
        if isinstance(config, Config):
            self.config = config
        else:
            self.config = load_config(config if config is not None else {})
        cfg = self.config
        #: Bans, counters, nonces and session fingerprints (per process, or shared via Redis).
        self.state: StateBackend = state if state is not None else build_state(cfg.state, cfg.limits.max_tracked_keys)
        shared = cfg.state.backend != "memory" or state is not None
        if dispatcher is None:
            dispatcher = AlertDispatcher.from_config(cfg.alerts, shared_state=self.state if shared else None)
        elif shared:
            dispatcher.use_shared_state(self.state)
        self.alerts = dispatcher
        self._verifier: Optional[WebBotAuthVerifier] = None
        if cfg.web_bot_auth.enabled and cfg.web_bot_auth.trusted_agents:
            directory = KeyDirectory(cfg.web_bot_auth, fetcher=key_fetcher, clock=clock)
            self._verifier = WebBotAuthVerifier(cfg.web_bot_auth, directory, clock=clock, state=self.state)
        self._honeypot = HoneypotDetector(cfg.honeypots)
        self._login = LoginMonitor(cfg.login, self.state)
        self._sessions = SessionMonitor(cfg.session, self.state)

    @property
    def enforcing(self) -> bool:
        return self.config.mode == "enforce"

    async def aclose(self) -> None:
        """Flush pending alerts and close HTTP and Redis clients (call on shutdown)."""
        await self.alerts.aclose()
        await self.state.aclose()

    # -- request side --------------------------------------------------------

    async def inspect(self, request: RequestInfo, peer_ip: Optional[str]) -> Verdict:
        """Classify the caller and decide whether the request may proceed.

        ``peer_ip`` is the address of the TCP peer (which may be your own
        load balancer); the real client is derived using ``trusted_proxy_hops``.
        """
        cfg = self.config
        client_ip = resolve_client_ip(peer_ip, request.header_values("x-forwarded-for"), cfg.trusted_proxy_hops)
        # An unknown address is shared by every client we could not identify, so it
        # must never be banned or rate-counted: that would punish everyone at once.
        ip_known = client_ip != UNKNOWN_IP
        user_agent = ", ".join(request.header_values("user-agent"))
        # Preliminary (User-Agent only) classification so early alerts carry context;
        # refined below once any agent signature has been verified.
        verdict = Verdict(
            request,
            client_ip,
            classify(user_agent, None, cfg.declared_bot_tokens, cfg.automation_tokens),
            watch_response=self._login.is_login_path(request.match_path),
        )

        if self.enforcing and ip_known and await self.state.is_banned(client_ip):
            verdict.block_status = 403
            return verdict

        if self._honeypot.is_trap(request.match_path):
            banned = self.enforcing and ip_known and cfg.honeypots.ban_seconds > 0
            if banned:
                await self.state.ban(client_ip, cfg.honeypots.ban_seconds)
            self._alert(
                verdict,
                "honeypot_hit",
                "critical",
                "Decoy path requested — someone is probing this app",
                f"User-Agent: {user_agent[:200] or '-'}",
                action=("blocked; IP banned" if banned else "blocked") if self.enforcing else "observed (monitor mode)",
                dedupe=f"honeypot|{client_ip}",
            )
            if self.enforcing:
                verdict.block_status = cfg.honeypots.response_status
                return verdict

        verification: Optional[VerificationResult] = None
        if self._verifier is not None and request.header_values("signature-input"):
            verification = await self._verifier.verify(request)
            if not verification.verified:
                high = verification.reason in _HIGH_RISK_SIGNATURE_FAILURES
                self._alert(
                    verdict,
                    "agent_signature_invalid",
                    "high" if high else "low",
                    "AI agent signature failed verification" + (" — possible impersonation" if high else ""),
                    f"reason: {verification.reason}",
                    action="treated as unverified",
                    dedupe=f"sig|{client_ip}|{verification.reason}",
                )
        verdict.identity = classify(user_agent, verification, cfg.declared_bot_tokens, cfg.automation_tokens)

        if cfg.ja4.enabled:
            verdict.ja4 = ja4_from_headers(request.header_values(cfg.ja4.header))
            if (
                verdict.ja4 is not None
                and cfg.ja4.alert_on_browser_mismatch
                and verdict.identity.kind == "unclassified"
            ):
                reason = browser_mismatch(user_agent, verdict.ja4)
                if reason is not None:
                    self._alert(
                        verdict,
                        "ja4_browser_mismatch",
                        cfg.ja4.mismatch_severity,
                        "Client pretends to be a browser — TLS fingerprint says otherwise",
                        f"{reason}; JA4 {verdict.ja4.value}",
                        action="observed",
                        dedupe=f"ja4mismatch|{client_ip}|{verdict.ja4.value}",
                    )

        decision = evaluate(cfg.rules, verdict.identity, request.method, request.match_path, verdict.ja4)
        if decision.action in ("block", "monitor") and decision.rule is not None:
            will_block = decision.action == "block" and self.enforcing
            if decision.action == "block":
                action = "blocked" if will_block else "would block (monitor mode)"
            else:
                action = "allowed (monitor rule)"
            self._alert(
                verdict,
                "policy_match",
                decision.rule.severity,
                f"Rule '{decision.rule.name}' matched {verdict.identity.label}",
                "; ".join(
                    part
                    for part in (verdict.identity.detail, f"JA4 {verdict.ja4.value}" if verdict.ja4 else "")
                    if part
                ),
                action=action,
                dedupe=f"rule|{decision.rule.name}|{client_ip}|{verdict.identity.label}",
            )
            if will_block:
                verdict.block_status = 403
                return verdict

        signal = await self._sessions.observe(
            request.header_values("cookie"),
            client_ip,
            user_agent,
            ", ".join(request.header_values("accept-language")),
        )
        if signal is not None:
            self._alert(
                verdict,
                f"session_{signal.kind}",
                signal.severity,
                "Session token used from a different device — possible session hijack"
                if signal.kind == "device_change"
                else "Session moved to a new network",
                f"{signal.detail} (session #{signal.session_hash})",
                action="allowed; review and revoke the session if unexpected",
                dedupe=f"session|{signal.kind}|{signal.session_hash}",
            )
        return verdict

    async def is_banned(self, client_ip: Optional[str]) -> bool:
        """True if ``client_ip`` is banned right now and bans are enforced.

        Used to cut off long-lived connections (WebSockets) whose IP was banned
        after they were opened.
        """
        if not self.enforcing or not client_ip or client_ip == UNKNOWN_IP:
            return False
        return await self.state.is_banned(client_ip)

    # -- response side -------------------------------------------------------

    async def on_response(self, *, client_ip: str, method: str, path: str, agent: str, status: int) -> None:
        """Record the app's response status for a request (failed-login monitoring).

        ``path`` is the raw request path. Safe to call for every response:
        anything that is not a failed response on a configured login path is ignored.
        """
        raw_path = path.partition("?")[0] or "/"
        if not self._login.is_login_path(normalize_match_path(raw_path)) or not self._login.is_failure(status):
            return
        for sig in await self._login.record_failure(client_ip if client_ip != UNKNOWN_IP else None):
            if sig.scope == "ip":
                title = "Repeated failed logins from one IP — likely brute force"
                detail = f"{sig.count} failures within {sig.window_seconds}s"
                alert_type, severity, dedupe = "login_bruteforce", "high", f"login|ip|{client_ip}"
            else:
                title = "Site-wide spike in failed logins — likely credential stuffing"
                detail = f"{sig.count} failures within {sig.window_seconds}s across all IPs"
                alert_type, severity, dedupe = "login_spike", "critical", "login|global"
            self.alerts.emit(
                Alert(
                    type=alert_type,
                    severity=severity,
                    title=title,
                    detail=detail,
                    client_ip=client_ip,
                    method=method.upper()[:_MAX_ALERT_METHOD],
                    path=raw_path[:_MAX_ALERT_PATH],
                    agent=agent,
                    action_taken="observed",
                    dedupe_key=dedupe,
                )
            )

    def _alert(
        self,
        verdict: Verdict,
        type_: str,
        severity: str,
        title: str,
        detail: str,
        *,
        action: str,
        dedupe: str,
    ) -> None:
        self.alerts.emit(
            Alert(
                type=type_,
                severity=severity,
                title=title,
                detail=detail,
                client_ip=verdict.client_ip,
                method=verdict.request.method[:_MAX_ALERT_METHOD],
                path=verdict.request.path[:_MAX_ALERT_PATH],
                agent=verdict.identity.label,
                action_taken=action,
                dedupe_key=dedupe,
            )
        )
