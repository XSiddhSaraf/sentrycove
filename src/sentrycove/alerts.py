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
from .store import TTLCache

log = logging.getLogger("sentrycove.alerts")

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
        self._log.log(level, "sentrycove alert %s", json.dumps(alert.to_dict(), sort_keys=True))

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
    ) -> None:
        self._sinks = sinks
        self._cooldown = cooldown_seconds
        self._recent: Optional[TTLCache[str, bool]] = (
            TTLCache(50_000, cooldown_seconds, clock) if cooldown_seconds > 0 else None
        )
        self._tasks: set[asyncio.Task] = set()

    @classmethod
    def from_config(cls, cfg: AlertsConfig) -> AlertDispatcher:
        sinks: list[tuple[AlertSink, str]] = []
        for sink_cfg in cfg.sinks:
            sink = build_sink(sink_cfg, cfg.timeout_seconds)
            if sink is not None:
                sinks.append((sink, sink_cfg.min_severity))
        return cls(sinks, cfg.cooldown_seconds)

    def emit(self, alert: Alert) -> bool:
        """Queue an alert for delivery. Returns False if suppressed as a duplicate."""
        key = alert.dedupe_key or f"{alert.type}|{alert.client_ip}|{alert.path}"
        if self._recent is not None:
            if key in self._recent:
                return False
            self._recent.set(key, True)
        loop = asyncio.get_running_loop()
        for sink, min_sev in self._sinks:
            if SEVERITY_ORDER[alert.severity] < SEVERITY_ORDER[min_sev]:
                continue
            task = loop.create_task(self._deliver(sink, alert))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return True

    @staticmethod
    async def _deliver(sink: AlertSink, alert: Alert) -> None:
        try:
            await sink.send(alert)
        except Exception as exc:  # delivery problems must never affect traffic
            log.warning("alert delivery via %s failed: %s", type(sink).__name__, exc)

    async def drain(self) -> None:
        """Wait for queued deliveries (useful in tests and on shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def aclose(self) -> None:
        await self.drain()
        for sink, _ in self._sinks:
            await sink.aclose()
