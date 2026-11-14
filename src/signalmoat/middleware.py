"""ASGI middleware: one line to add to any FastAPI/Starlette/ASGI app.

    app.add_middleware(SignalMoat, config="signalmoat.yaml")

In ``monitor`` mode nothing is ever blocked; you only get alerts. Switch
to ``enforce`` once the alerts look right for your traffic.

Handlers can read the caller's classification from
``request.state.signalmoat`` (an :class:`~signalmoat.identity.AgentIdentity`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any, Optional, Union

from .alerts import AlertDispatcher
from .config import Config
from .engine import Engine, RequestInfo
from .identity import AgentIdentity
from .webbotauth import Fetcher, _httpx_fetch

log = logging.getLogger("signalmoat")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class SignalMoat:
    def __init__(
        self,
        app: ASGIApp,
        config: Union[Config, str, Path, dict, None] = None,
        *,
        dispatcher: Optional[AlertDispatcher] = None,
        key_fetcher: Fetcher = _httpx_fetch,
        clock: Callable[[], float] = time.time,
        engine: Optional[Engine] = None,
    ) -> None:
        self.app = app
        self.engine = engine or Engine(config, dispatcher=dispatcher, key_fetcher=key_fetcher, clock=clock)
        self.config = self.engine.config
        self.alerts = self.engine.alerts

    @property
    def enforcing(self) -> bool:
        return self.engine.enforcing

    async def aclose(self) -> None:
        """Flush pending alerts and close HTTP clients (call on app shutdown)."""
        await self.engine.aclose()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        peer = scope["client"][0] if scope.get("client") else None
        try:
            verdict = await self.engine.inspect(RequestInfo.from_scope(scope), peer)
        except Exception:
            log.exception("signalmoat inspection failed")
            if self.config.fail_open:
                state = scope.setdefault("state", {})
                state["signalmoat"] = AgentIdentity("unclassified", None, "inspection failed")
                state["signalmoat_client_ip"] = None
                await self.app(scope, receive, send)
            else:
                await respond_json(send, 503, {"error": "request could not be screened"})
            return

        if verdict.block_status is not None:
            await respond_json(send, verdict.block_status, {"error": "request blocked"})
            return

        state = scope.setdefault("state", {})
        state["signalmoat"] = verdict.identity
        state["signalmoat_client_ip"] = verdict.client_ip
        if not verdict.watch_response:
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                try:
                    await self.engine.on_response(
                        client_ip=verdict.client_ip,
                        method=verdict.request.method,
                        path=verdict.request.path,
                        agent=verdict.identity.label,
                        status=int(message["status"]),
                    )
                except Exception:
                    log.exception("signalmoat login monitoring failed")
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # -- WebSocket ----------------------------------------------------------

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Screen the opening handshake; while open, cut the connection if its IP gets banned."""
        ws_cfg = self.config.websocket
        if not ws_cfg.enabled:
            await _reject_websocket(receive, send, 403)
            return
        peer = scope["client"][0] if scope.get("client") else None
        state = scope.setdefault("state", {})
        try:
            verdict = await self.engine.inspect(RequestInfo.from_scope(scope), peer)
        except Exception:
            log.exception("signalmoat inspection failed (websocket)")
            if not self.config.fail_open:
                await _reject_websocket(receive, send, 503)
                return
            state["signalmoat"] = AgentIdentity("unclassified", None, "inspection failed")
            state["signalmoat_client_ip"] = None
            await self.app(scope, receive, send)
            return
        if verdict.block_status is not None:
            await _reject_websocket(receive, send, verdict.block_status)
            return
        state["signalmoat"] = verdict.identity
        state["signalmoat_client_ip"] = verdict.client_ip
        if not self.engine.enforcing or ws_cfg.ban_recheck_seconds <= 0:
            await self.app(scope, receive, send)
            return
        watch = _BanWatch(self.engine, verdict.client_ip, ws_cfg.ban_recheck_seconds, send)
        await watch.run(self.app, scope, receive)


async def _reject_websocket(receive: Receive, send: Send, status: int) -> None:
    """Refuse a WebSocket handshake. Servers answer a close-before-accept with HTTP 403."""
    message = await receive()
    if message["type"] != "websocket.connect":
        return
    await send({"type": "websocket.close", "code": 1008, "reason": f"refused ({status})"})


class _BanWatch:
    """Closes an open WebSocket (code 1008) once its client IP is banned.

    After the close, further messages from the app are dropped and the app's
    ``receive`` returns a disconnect, so the app winds down normally.
    """

    def __init__(self, engine: Engine, client_ip: str, interval: float, send: Send) -> None:
        self._engine = engine
        self._ip = client_ip
        self._interval = interval
        self._send = send
        self._closed = False
        self._cut = asyncio.Event()

    async def send(self, message: Message) -> None:
        if self._closed:
            return
        if message["type"] == "websocket.close":
            self._closed = True
        await self._send(message)

    def receiver(self, receive: Receive) -> Receive:
        async def guarded() -> Message:
            if self._cut.is_set():
                return {"type": "websocket.disconnect", "code": 1008}
            pending = asyncio.ensure_future(receive())
            cut = asyncio.ensure_future(self._cut.wait())
            done, _ = await asyncio.wait({pending, cut}, return_when=asyncio.FIRST_COMPLETED)
            if pending in done:
                cut.cancel()
                return pending.result()
            pending.cancel()
            return {"type": "websocket.disconnect", "code": 1008}

        return guarded

    async def _watch(self) -> None:
        while not self._closed:
            await asyncio.sleep(self._interval)
            try:
                banned = await self._engine.is_banned(self._ip)
            except Exception as exc:  # state store down: keep the connection (fail open)
                log.warning("signalmoat could not re-check websocket client %s: %s", self._ip, exc)
                continue
            if banned:
                log.info("closing websocket from banned address %s", self._ip)
                self._cut.set()
                if not self._closed:
                    self._closed = True
                    try:
                        await self._send({"type": "websocket.close", "code": 1008, "reason": "banned"})
                    except Exception:  # connection already gone
                        log.debug("websocket already closed", exc_info=True)
                return

    async def run(self, app: ASGIApp, scope: Scope, receive: Receive) -> None:
        watcher = asyncio.ensure_future(self._watch())
        try:
            await app(scope, self.receiver(receive), self.send)
        finally:
            watcher.cancel()


async def respond_json(send: Send, status: int, body: dict, extra_headers: Optional[list] = None) -> None:
    payload = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers + (extra_headers or [])})
    await send({"type": "http.response.body", "body": payload})
