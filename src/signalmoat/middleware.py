"""ASGI middleware: one line to add to any FastAPI/Starlette/ASGI app.

    app.add_middleware(SignalMoat, config="signalmoat.yaml")

In ``monitor`` mode nothing is ever blocked; you only get alerts. Switch
to ``enforce`` once the alerts look right for your traffic.

Handlers can read the caller's classification from
``request.state.signalmoat`` (an :class:`~signalmoat.identity.AgentIdentity`).
"""

from __future__ import annotations

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
                    self.engine.on_response(
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


async def respond_json(send: Send, status: int, body: dict, extra_headers: Optional[list] = None) -> None:
    payload = json.dumps(body).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers + (extra_headers or [])})
    await send({"type": "http.response.body", "body": payload})
