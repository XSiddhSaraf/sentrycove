"""Reverse-proxy mode: put SignalMoat in front of an app written in any language.

    client --> [TLS terminator] --> signalmoat proxy --> your app

No change to the app is needed. Requests are screened by the same engine
as the ASGI middleware, then streamed to the upstream app; responses are
streamed back. The upstream receives two extra headers it can trust
(client-supplied copies are always removed):

    X-SignalMoat-Agent:      e.g. "verified:example-agent", "automation:curl"
    X-SignalMoat-Client-IP:  the client address SignalMoat resolved

WebSocket connections are proxied too: the opening handshake is screened
like any request, then messages are relayed in both directions. A connection
is closed (code 1008) if its client IP is banned while it is open.

Limitations: HTTP/1.1 only towards the client and no TLS termination (run it
behind your load balancer / Caddy / nginx).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote, urlsplit

import httpx

from .config import Config
from .engine import Engine
from .middleware import ASGIApp, Message, Receive, Scope, Send, SignalMoat, respond_json

log = logging.getLogger("signalmoat.proxy")

HEALTH_PATH = "/_signalmoat/health"

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)
_FORWARDING_HEADERS = frozenset({"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded"})
_NO_STORE = [(b"cache-control", b"no-store")]


class _ClientDisconnected(Exception):
    pass


def _connection_tokens(headers: list[tuple[bytes, bytes]]) -> set[str]:
    """Header names listed in ``Connection`` are hop-by-hop too (RFC 9110 §7.6.1)."""
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            tokens.update(t.strip().lower() for t in value.decode("latin-1").split(",") if t.strip())
    return tokens


def _validate_upstream(upstream: str) -> str:
    parts = urlsplit(upstream)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("upstream must look like http://host:port")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("upstream must be an origin only (no path, query, fragment or credentials)")
    return f"{parts.scheme}://{parts.netloc}"


# Handshake headers the WebSocket client library writes itself.
_WS_OWN_HEADERS = frozenset(
    {"host", "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "sec-websocket-protocol"}
)
_WS_CLOSE_UNSENDABLE = {1005, 1006, 1015}  # reserved: may never appear in a close frame


def _ws_close_code(code: Optional[int]) -> int:
    if code is None or code == 1005:
        return 1000
    if code in _WS_CLOSE_UNSENDABLE or not (1000 <= code <= 4999):
        return 1011
    return code


class ReverseProxy:
    """ASGI app that forwards every HTTP request (and WebSocket) to one upstream origin."""

    def __init__(
        self,
        upstream: str,
        *,
        preserve_host: bool = True,
        trusted_proxy_hops: int = 0,
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
        websocket_max_message_bytes: int = 1_048_576,
    ) -> None:
        self._base = _validate_upstream(upstream)
        self._connect_timeout = connect_timeout
        self._ws_max_size = websocket_max_message_bytes
        self._preserve_host = preserve_host
        self._trusted_hops = trusted_proxy_hops
        self._timeout = httpx.Timeout(
            connect=connect_timeout, read=read_timeout, write=read_timeout, pool=connect_timeout
        )
        # trust_env=False: the upstream is reached directly, never via HTTP(S)_PROXY.
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=self._timeout,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- request construction ------------------------------------------------

    def _target_url(self, scope: Scope) -> str:
        raw = scope.get("raw_path")
        if raw:
            raw = raw.split(b"?", 1)[0]
            # Keep the client's own percent-encoding; escape any stray non-ASCII byte.
            path = "".join(chr(b) if 0x20 < b < 0x7F else f"%{b:02X}" for b in raw)
        else:
            path = quote(scope.get("path", "/"), safe="/%:@!$&'()*+,;=-._~")
        if not path.startswith("/"):
            path = "/" + path
        query = scope.get("query_string", b"")
        if query:
            path += "?" + "".join(chr(b) if 0x20 < b < 0x7F else f"%{b:02X}" for b in query)
        return self._base + path

    def _upstream_headers(self, scope: Scope) -> tuple[list[tuple[bytes, bytes]], bool]:
        incoming: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        skip = HOP_BY_HOP | _connection_tokens(incoming)
        state = scope.get("state") or {}
        peer = scope["client"][0] if scope.get("client") else None
        trusted = self._trusted_hops > 0

        headers: list[tuple[bytes, bytes]] = []
        host: Optional[bytes] = None
        forwarded_for: list[str] = []
        forwarded_proto: Optional[bytes] = None
        forwarded_host: Optional[bytes] = None
        has_body = False
        for raw_name, value in incoming:
            name = raw_name.decode("latin-1").lower()
            if name == "transfer-encoding":
                has_body = True
            if name in skip or name.startswith("x-signalmoat-"):
                continue
            if name == "host":
                host = value
                continue
            if name == "content-length":
                has_body = has_body or value.strip() not in (b"", b"0")
            if name in _FORWARDING_HEADERS:
                # Forwarding headers are only believed when they were written by
                # a proxy the operator declared; otherwise a client could forge them.
                if not trusted:
                    continue
                if name == "x-forwarded-for":
                    forwarded_for.append(value.decode("latin-1"))
                    continue
                if name == "x-forwarded-proto":
                    forwarded_proto = value
                    continue
                if name == "x-forwarded-host":
                    forwarded_host = value
                    continue
            headers.append((raw_name, value))

        if peer:
            forwarded_for.append(peer)
        if forwarded_for:
            headers.append((b"x-forwarded-for", ", ".join(forwarded_for).encode("latin-1")))
        headers.append((b"x-forwarded-proto", forwarded_proto or scope.get("scheme", "http").encode("ascii")))
        if forwarded_host or host:
            headers.append((b"x-forwarded-host", forwarded_host or host or b""))
        if host and self._preserve_host:
            headers.append((b"host", host))

        identity = state.get("signalmoat")
        if identity is not None:
            headers.append((b"x-signalmoat-agent", identity.label.encode("latin-1", "replace")))
        client_ip = state.get("signalmoat_client_ip")
        if client_ip:
            headers.append((b"x-signalmoat-client-ip", str(client_ip).encode("ascii", "replace")))
        return headers, has_body

    @staticmethod
    async def _request_body(receive: Receive) -> AsyncIterator[bytes]:
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise _ClientDisconnected()
            chunk = message.get("body", b"")
            if chunk:
                yield chunk
            if not message.get("more_body", False):
                return

    # -- ASGI ----------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            raise RuntimeError("ReverseProxy only handles HTTP and WebSocket scopes")
        headers, has_body = self._upstream_headers(scope)
        request = httpx.Request(
            scope["method"],
            self._target_url(scope),
            headers=headers,
            content=self._request_body(receive) if has_body else None,
            extensions={"timeout": self._timeout.as_dict()},
        )
        try:
            response = await self._client.send(request, stream=True)
        except _ClientDisconnected:
            return
        except httpx.TimeoutException:
            log.warning("upstream timed out: %s %s", scope["method"], scope.get("path"))
            await respond_json(send, 504, {"error": "upstream timed out"}, _NO_STORE)
            return
        except httpx.HTTPError as exc:
            log.warning("upstream unreachable: %s", exc)
            await respond_json(send, 502, {"error": "upstream unreachable"}, _NO_STORE)
            return

        try:
            raw_headers = list(response.headers.raw)
            skip = HOP_BY_HOP | _connection_tokens(raw_headers)
            out_headers = [(k.lower(), v) for k, v in raw_headers if k.decode("latin-1").lower() not in skip]
            await send({"type": "http.response.start", "status": response.status_code, "headers": out_headers})
            # aiter_raw: bytes exactly as the upstream sent them, so Content-Encoding
            # and Content-Length stay truthful.
            async for chunk in response.aiter_raw():
                if chunk:
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            await response.aclose()

    # -- WebSocket -----------------------------------------------------------

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Open the same WebSocket on the upstream, then relay messages both ways."""
        from websockets.asyncio.client import ClientConnection, connect
        from websockets.exceptions import ConnectionClosed, InvalidStatus, WebSocketException

        first = await receive()
        if first["type"] != "websocket.connect":
            return

        headers, _ = self._upstream_headers(scope)
        host: Optional[str] = None
        forward: list[tuple[str, str]] = []
        for raw_name, value in headers:
            name = raw_name.decode("latin-1").lower()
            if name == "host":
                host = value.decode("latin-1")
            elif name not in _WS_OWN_HEADERS:
                forward.append((name, value.decode("latin-1")))
        url = "ws" + self._target_url(scope)[len("http") :]  # http(s)://... -> ws(s)://...
        subprotocols = list(scope.get("subprotocols") or []) or None

        class _Upstream(ClientConnection):
            """Sends the client's Host header (when preserved) instead of the upstream's own."""

            async def handshake(self, *args: Any, **kwargs: Any) -> None:
                build = self.protocol.connect

                def connect_with_host() -> Any:
                    request = build()
                    if host:
                        del request.headers["Host"]
                        request.headers["Host"] = host
                    return request

                self.protocol.connect = connect_with_host  # type: ignore[method-assign]
                await super().handshake(*args, **kwargs)

        try:
            upstream = await connect(
                url,
                additional_headers=forward,
                subprotocols=subprotocols,
                user_agent_header=None,  # the client's own User-Agent is forwarded
                proxy=None,  # reach the upstream directly, never via HTTP(S)_PROXY
                open_timeout=self._connect_timeout,
                max_size=self._ws_max_size,
                create_connection=_Upstream,
            )
        except InvalidStatus as exc:
            log.info("upstream refused websocket %s: HTTP %s", scope.get("path"), exc.response.status_code)
            await send({"type": "websocket.close", "code": 1008})
            return
        except (OSError, asyncio.TimeoutError, WebSocketException) as exc:
            log.warning("upstream websocket unreachable: %s", exc)
            await send({"type": "websocket.close", "code": 1011})
            return

        async with upstream:
            await send({"type": "websocket.accept", "subprotocol": upstream.subprotocol})

            async def client_to_upstream() -> None:
                while True:
                    message = await receive()
                    if message["type"] == "websocket.disconnect":
                        await upstream.close(_ws_close_code(message.get("code")))
                        return
                    if message["type"] != "websocket.receive":
                        continue
                    if message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    elif message.get("text") is not None:
                        await upstream.send(message["text"])

            async def upstream_to_client() -> None:
                code, reason = 1000, ""
                try:
                    async for data in upstream:
                        if isinstance(data, bytes):
                            await send({"type": "websocket.send", "bytes": data})
                        else:
                            await send({"type": "websocket.send", "text": data})
                except ConnectionClosed:
                    pass
                if upstream.close_code is not None:
                    code, reason = upstream.close_code, upstream.close_reason or ""
                await send({"type": "websocket.close", "code": _ws_close_code(code), "reason": reason})

            tasks = {asyncio.ensure_future(client_to_upstream()), asyncio.ensure_future(upstream_to_client())}
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            for task in done:
                error = task.exception()
                if error is not None and not isinstance(error, ConnectionClosed):
                    log.warning("websocket relay ended with an error: %s", error)


class ProxyApp:
    """SignalMoat engine + reverse proxy + health endpoint + lifespan handling."""

    def __init__(self, gate: SignalMoat, proxy: ReverseProxy) -> None:
        self.gate = gate
        self.proxy = proxy

    async def aclose(self) -> None:
        await self.proxy.aclose()
        await self.gate.aclose()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await run_lifespan(receive, send, self.aclose)
        elif kind == "http" and scope.get("path") == HEALTH_PATH:
            await respond_json(send, 200, {"status": "ok", "mode": self.gate.config.mode})
        else:
            await self.gate(scope, receive, send)


async def run_lifespan(receive: Receive, send: Send, on_shutdown: Any) -> None:
    while True:
        message: Message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            try:
                await on_shutdown()
            finally:
                await send({"type": "lifespan.shutdown.complete"})
            return


def create_proxy_app(
    upstream: str,
    config: Union[Config, str, Path, dict, None] = None,
    *,
    preserve_host: bool = True,
    engine: Optional[Engine] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> ProxyApp:
    engine = engine or Engine(config)
    proxy = ReverseProxy(
        upstream,
        preserve_host=preserve_host,
        trusted_proxy_hops=engine.config.trusted_proxy_hops,
        client=client,
        websocket_max_message_bytes=engine.config.websocket.max_message_bytes,
    )
    inner: ASGIApp = proxy
    return ProxyApp(SignalMoat(inner, engine=engine), proxy)
