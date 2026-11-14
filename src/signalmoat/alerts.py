"""Early-warning alerts: de-duplicated, non-blocking, routed by severity."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Optional, Protocol

import httpx

from .config import AlertsConfig, SinkConfig
from .state import NS_ALERT, StateBackend
from .store import TTLCache
from .triage import Triage

log = logging.getLogger("signalmoat.alerts")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class Alert:
    type: str
    severity: str
    title: str
    detail: str = ""
    client_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    agent: Optional[str] = None
    action_taken: str = "none"
    dedupe_key: str = ""
    timestamp: float = field(default_factory=time.time)
    #: Advisory LLM note (what_happened / how_bad / what_to_do), when triage is enabled.
    triage: Optional[dict[str, str]] = None

    def to_dict(self) -> dict:
        return asdict(self)


class AlertSink(Protocol):
    async def send(self, alert: Alert) -> None: ...

    async def aclose(self) -> None: ...


class LogSink:
    def __init__(self, logger: logging.Logger = log) -> None:
        self._log = logger

    async def send(self, alert: Alert) -> None:
        level = logging.WARNING if SEVERITY_ORDER[alert.severity] >= 2 else logging.INFO
        self._log.log(level, "signalmoat alert %s", json.dumps(alert.to_dict(), sort_keys=True))

    async def aclose(self) -> None:
        return None


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class WebhookSink:
    """POSTs JSON. ``slack=True`` sends a Slack-compatible ``{"text": ...}`` body."""

    def __init__(self, url: str, timeout: float, slack: bool = False) -> None:
        self._url = url
        self._timeout = timeout
        self._slack = slack
        self._client: Optional[httpx.AsyncClient] = None

    def _payload(self, alert: Alert) -> dict:
        if not self._slack:
            return alert.to_dict()
        lines = [
            f"*[{alert.severity.upper()}] {_slack_escape(alert.title)}*",
            _slack_escape(alert.detail) if alert.detail else "",
            f"IP: `{_slack_escape(alert.client_ip or '-')}`  Agent: `{_slack_escape(alert.agent or '-')}`",
            f"Request: `{_slack_escape(alert.method or '-')} {_slack_escape(alert.path or '-')}`"
            f"  Action: `{alert.action_taken}`",
        ]
        if alert.triage:
            lines.append("_AI triage (advisory, may be wrong):_")
            for label, key in (
                ("What happened", "what_happened"),
                ("How bad", "how_bad"),
                ("What to do", "what_to_do"),
            ):
                if alert.triage.get(key):
                    lines.append(f"• *{label}:* {_slack_escape(alert.triage[key])}")
        return {"text": "\n".join(line for line in lines if line)}

    async def send(self, alert: Alert) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout, follow_redirects=False)
        resp = await self._client.post(self._url, json=self._payload(alert))
        if resp.status_code >= 400:
            log.warning("alert webhook returned HTTP %s", resp.status_code)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def build_sink(cfg: SinkConfig, timeout: float) -> Optional[AlertSink]:
    if cfg.type == "log":
        return LogSink()
    url = os.environ.get(cfg.url_env or "", "")
    if not url:
        log.warning("alert sink %s disabled: env var %s is not set", cfg.type, cfg.url_env)
        return None
    if not url.startswith("https://"):
        log.warning("alert sink %s disabled: URL must use https", cfg.type)
        return None
    return WebhookSink(url, timeout, slack=cfg.type == "slack")


class AlertDispatcher:
    def __init__(
        self,
        sinks: list[tuple[AlertSink, str]],
        cooldown_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        shared_state: Optional[StateBackend] = None,
        triage: Optional[Triage] = None,
    ) -> None:
        self._sinks = sinks
        self._triage = triage
        self._cooldown = cooldown_seconds
        #: With a shared backend, an alert raised by several workers is sent once.
        self._shared = shared_state if cooldown_seconds > 0 else None
        self._recent: Optional[TTLCache[str, bool]] = (
            TTLCache(50_000, cooldown_seconds, clock) if cooldown_seconds > 0 else None
        )
        self._tasks: set[asyncio.Task] = set()

    @classmethod
    def from_config(cls, cfg: AlertsConfig, shared_state: Optional[StateBackend] = None) -> AlertDispatcher:
        sinks: list[tuple[AlertSink, str]] = []
        for sink_cfg in cfg.sinks:
            sink = build_sink(sink_cfg, cfg.timeout_seconds)
            if sink is not None:
                sinks.append((sink, sink_cfg.min_severity))
        return cls(sinks, cfg.cooldown_seconds, shared_state=shared_state, triage=Triage.from_config(cfg.triage))

    def use_shared_state(self, state: StateBackend) -> None:
        """De-duplicate across processes through ``state`` (no-op when cooldown is 0)."""
        if self._cooldown > 0:
            self._shared = state

    def emit(self, alert: Alert) -> bool:
        """Queue an alert for delivery. Returns False if suppressed as a duplicate."""
        key = alert.dedupe_key or f"{alert.type}|{alert.client_ip}|{alert.path}"
        if self._recent is not None:
            if key in self._recent:
                return False
            self._recent.set(key, True)
        targets = [sink for sink, min_sev in self._sinks if SEVERITY_ORDER[alert.severity] >= SEVERITY_ORDER[min_sev]]
        if not targets:
            return True
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._dispatch(targets, alert, key))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    async def _dispatch(self, targets: list[AlertSink], alert: Alert, key: str) -> None:
        if self._shared is not None:
            try:
                if not await self._shared.claim(NS_ALERT, key, self._cooldown):
                    return  # another SignalMoat process already sent this alert
            except Exception as exc:  # shared store down: better a duplicate than a lost alert
                log.warning("shared alert de-duplication unavailable: %s", exc)
        if self._triage is not None:
            alert = await self._triage.enrich(alert)  # bounded by its timeout; never raises
        await asyncio.gather(*(self._deliver(sink, alert) for sink in targets))

    @staticmethod
    async def _deliver(sink: AlertSink, alert: Alert) -> None:
        try:
            await sink.send(alert)
        except Exception as exc:  # delivery problems must never affect traffic
            log.warning("alert delivery via %s failed: %s", type(sink).__name__, exc)

    async def drain(self, timeout: Optional[float] = None) -> None:
        """Wait for queued deliveries (useful in tests and on shutdown).

        With ``timeout``, deliveries still running after that many seconds are
        cancelled (and logged), so a stuck sink can never hang shutdown.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while self._tasks:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                stuck = list(self._tasks)
                log.warning("cancelling %d alert deliveries still running at shutdown", len(stuck))
                for task in stuck:
                    task.cancel()
                await asyncio.gather(*stuck, return_exceptions=True)
                self._tasks.difference_update(stuck)
                return
            await asyncio.wait(list(self._tasks), timeout=remaining)

    async def aclose(self, timeout: float = 15.0) -> None:
        await self.drain(timeout)
        for sink, _ in self._sinks:
            await sink.aclose()
        if self._triage is not None:
            await self._triage.aclose()
