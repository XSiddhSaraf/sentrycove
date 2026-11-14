"""ASGI middleware: one line to add to any FastAPI/Starlette/ASGI app.

    app.add_middleware(AgentGate, config="agentgate.yaml")

Pipeline per HTTP request:
    banned IP? -> honeypot? -> identify agent (Web Bot Auth / UA) -> policy
    -> session hijack check -> app -> failed-login monitoring on the response

In ``monitor`` mode nothing is ever blocked; you only get alerts. Switch
to ``enforce`` once the alerts look right for your traffic.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from .alerts import Alert, AlertDispatcher
from .clientip import resolve_client_ip
from .config import Config, load_config
from .detectors import HoneypotDetector, LoginMonitor, SessionMonitor
from .identity import AgentIdentity, classify
from .policy import evaluate
from .store import TTLCache
from .webbotauth import (
    Fetcher,
    KeyDirectory,
    VerificationResult,
    WebBotAuthVerifier,
    _httpx_fetch,
    normalize_authority,
)

log = logging.getLogger("agentgate")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_HIGH_RISK_SIGNATURE_FAILURES = {"bad signature", "replayed nonce"}


@dataclass
class _ScopeMessage:
    """Adapts an ASGI scope to the SignedMessage protocol."""

    method: str
    scheme: str
    authority: str
    path: str
    query: str
    headers: list[tuple[str, str]]

    def header_values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]

    @classmethod
    def from_scope(cls, scope: Scope) -> _ScopeMessage:
        headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope.get("headers", [])]
        scheme = scope.get("scheme", "http")
        host = next((v for k, v in headers if k == "host"), "")
        if not host and scope.get("server"):
            server_host, server_port = scope["server"][0], scope["server"][1]
            host = f"{server_host}:{server_port}" if server_port else str(server_host)
        raw_path = scope.get("raw_path")
        path = raw_path.decode("latin-1") if raw_path else scope.get("path", "/")
        path = path.split("?", 1)[0] or "/"
        return cls(
            method=scope.get("method", "GET").upper(),
            scheme=scheme,
            authority=normalize_authority(host, scheme),
            path=path,
            query=scope.get("query_string", b"").decode("latin-1"),
            headers=headers,
        )


@dataclass
class _Context:
    msg: _ScopeMessage
    client_ip: str
    identity: AgentIdentity
    block_status: Optional[int] = None


class AgentGate:
    def __init__(
        self,
        app: ASGIApp,
        config: Union[Config, str, Path, dict, None] = None,
        *,
        dispatcher: Optional[AlertDispatcher] = None,
        key_fetcher: Fetcher = _httpx_fetch,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.app = app
        if isinstance(config, Config):
            self.config = config
        else:
            self.config = load_config(config if config is not None else {})
        cfg = self.config
        self.alerts = dispatcher or AlertDispatcher.from_config(cfg.alerts)
        self._verifier: Optional[WebBotAuthVerifier] = None
        if cfg.web_bot_auth.enabled and cfg.web_bot_auth.trusted_agents:
            directory = KeyDirectory(cfg.web_bot_auth, fetcher=key_fetcher, clock=clock)
            self._verifier = WebBotAuthVerifier(cfg.web_bot_auth, directory, clock=clock)
        self._honeypot = HoneypotDetector(cfg.honeypots)
        self._login = LoginMonitor(cfg.login, cfg.limits.max_tracked_keys)
        self._sessions = SessionMonitor(cfg.session, cfg.limits.max_tracked_keys)
        self._bans: TTLCache[str, bool] = TTLCache(cfg.limits.max_tracked_keys, max(1, cfg.honeypots.ban_seconds))

    @property
    def enforcing(self) -> bool:
        return self.config.mode == "enforce"

    async def aclose(self) -> None:
        """Flush pending alerts and close HTTP clients (call on app shutdown)."""
        await self.alerts.aclose()

    # -- ASGI entry point --------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            ctx = await self._inspect(scope)
        except Exception:
            log.exception("agentgate inspection failed")
            if self.config.fail_open:
                scope.setdefault("state", {})["agentgate"] = AgentIdentity("unclassified", None, "inspection failed")
                await self.app(scope, receive, send)
            else:
                await _respond(send, 503, {"error": "request could not be screened"})
            return

        if ctx.block_status is not None:
            await _respond(send, ctx.block_status, {"error": "request blocked"})
            return

        scope.setdefault("state", {})["agentgate"] = ctx.identity
        if not self._login.is_login_path(ctx.msg.path):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                try:
                    self._on_login_response(ctx, int(message["status"]))
                except Exception:
                    log.exception("agentgate login monitoring failed")
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # -- inspection ----------------------------------------------------------

    async def _inspect(self, scope: Scope) -> _Context:
        cfg = self.config
        msg = _ScopeMessage.from_scope(scope)
        peer = scope["client"][0] if scope.get("client") else None
        client_ip = resolve_client_ip(peer, msg.header_values("x-forwarded-for"), cfg.trusted_proxy_hops)
        user_agent = ", ".join(msg.header_values("user-agent"))
        # Preliminary (User-Agent only) classification so early alerts carry context;
        # refined below once any agent signature has been verified.
        ctx = _Context(msg, client_ip, classify(user_agent, None, cfg.declared_bot_tokens, cfg.automation_tokens))

        if self.enforcing and client_ip in self._bans:
            ctx.block_status = 403
            return ctx

        if self._honeypot.is_trap(msg.path):
            banned = self.enforcing and cfg.honeypots.ban_seconds > 0
            if banned:
                self._bans.set(client_ip, True, ttl_seconds=cfg.honeypots.ban_seconds)
            self._alert(
                ctx,
                "honeypot_hit",
                "critical",
                "Decoy path requested — someone is probing this app",
                f"User-Agent: {user_agent[:200] or '-'}",
                action=("blocked; IP banned" if banned else "blocked") if self.enforcing else "observed (monitor mode)",
                dedupe=f"honeypot|{client_ip}",
            )
            if self.enforcing:
                ctx.block_status = cfg.honeypots.response_status
                return ctx

        verification: Optional[VerificationResult] = None
        if self._verifier is not None and msg.header_values("signature-input"):
            verification = await self._verifier.verify(msg)
            if not verification.verified:
                high = verification.reason in _HIGH_RISK_SIGNATURE_FAILURES
                self._alert(
                    ctx,
                    "agent_signature_invalid",
                    "high" if high else "low",
                    "AI agent signature failed verification" + (" — possible impersonation" if high else ""),
                    f"reason: {verification.reason}",
                    action="treated as unverified",
                    dedupe=f"sig|{client_ip}|{verification.reason}",
                )
        ctx.identity = classify(user_agent, verification, cfg.declared_bot_tokens, cfg.automation_tokens)

        decision = evaluate(cfg.rules, ctx.identity, msg.method, msg.path)
        if decision.action in ("block", "monitor") and decision.rule is not None:
            will_block = decision.action == "block" and self.enforcing
            if decision.action == "block":
                action = "blocked" if will_block else "would block (monitor mode)"
            else:
                action = "allowed (monitor rule)"
            self._alert(
                ctx,
                "policy_match",
                decision.rule.severity,
                f"Rule '{decision.rule.name}' matched {ctx.identity.label}",
                ctx.identity.detail,
                action=action,
                dedupe=f"rule|{decision.rule.name}|{client_ip}|{ctx.identity.label}",
            )
            if will_block:
                ctx.block_status = 403
                return ctx

        signal = self._sessions.observe(
            msg.header_values("cookie"),
            client_ip,
            user_agent,
            ", ".join(msg.header_values("accept-language")),
        )
        if signal is not None:
            self._alert(
                ctx,
                f"session_{signal.kind}",
                signal.severity,
                "Session token used from a different device — possible session hijack"
                if signal.kind == "device_change"
                else "Session moved to a new network",
                f"{signal.detail} (session #{signal.session_hash})",
                action="allowed; review and revoke the session if unexpected",
                dedupe=f"session|{signal.kind}|{signal.session_hash}",
            )
        return ctx

    def _on_login_response(self, ctx: _Context, status: int) -> None:
        if not self._login.is_failure(status):
            return
        for sig in self._login.record_failure(ctx.client_ip):
            if sig.scope == "ip":
                self._alert(
                    ctx,
                    "login_bruteforce",
                    "high",
                    "Repeated failed logins from one IP — likely brute force",
                    f"{sig.count} failures within {sig.window_seconds}s",
                    action="observed",
                    dedupe=f"login|ip|{ctx.client_ip}",
                )
            else:
                self._alert(
                    ctx,
                    "login_spike",
                    "critical",
                    "Site-wide spike in failed logins — likely credential stuffing",
                    f"{sig.count} failures within {sig.window_seconds}s across all IPs",
                    action="observed",
                    dedupe="login|global",
                )

    def _alert(
        self,
        ctx: _Context,
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
                client_ip=ctx.client_ip,
                method=ctx.msg.method,
                path=ctx.msg.path,
                agent=ctx.identity.label,
                action_taken=action,
                dedupe_key=dedupe,
            )
        )


async def _respond(send: Send, status: int, body: dict) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})
