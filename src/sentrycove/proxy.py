"""Reverse-proxy mode: put SentryCove in front of an app written in any language.

    client --> [TLS terminator] --> sentrycove proxy --> your app

No change to the app is needed. Requests are screened by the same engine
as the ASGI middleware, then streamed to the upstream app; responses are
streamed back. The upstream receives two extra headers it can trust
(client-supplied copies are always removed):

    X-SentryCove-Agent:      e.g. "verified:example-agent", "automation:curl"
    X-SentryCove-Client-IP:  the client address SentryCove resolved

Limitations: HTTP/1.1 only towards the client, no TLS termination (run it
behind your load balancer / Caddy / nginx), and WebSocket connections are
refused rather than proxied.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import quote, urlsplit

import httpx

from .config import Config
from .engine import Engine
from .middleware import ASGIApp, Message, Receive, Scope, Send, SentryCove, respond_json

log = logging.getLogger("sentrycove.proxy")

HEALTH_PATH = "/_sentrycove/health"

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


class ReverseProxy:
    """ASGI app that forwards every HTTP request to one upstream origin."""

    def __init__(
        self,
        upstream: str,
        *,
        preserve_host: bool = True,
        trusted_proxy_hops: int = 0,
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._base = _validate_upstream(upstream)
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
            if name in skip or name.startswith("x-sentrycove-"):
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

        identity = state.get("sentrycove")
        if identity is not None:
            headers.append((b"x-sentrycove-agent", identity.label.encode("latin-1", "replace")))
        client_ip = state.get("sentrycove_client_ip")
        if client_ip:
            headers.append((b"x-sentrycove-client-ip", str(client_ip).encode("ascii", "replace")))
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
        if scope["type"] != "http":
            raise RuntimeError("ReverseProxy only handles HTTP scopes")
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


class ProxyApp:
    """SentryCove engine + reverse proxy + health endpoint + lifespan handling."""

    def __init__(self, gate: SentryCove, proxy: ReverseProxy) -> None:
        self.gate = gate
        self.proxy = proxy
        self._warned_websocket = False

    async def aclose(self) -> None:
        await self.proxy.aclose()
        await self.gate.aclose()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await run_lifespan(receive, send, self.aclose)
        elif kind == "websocket":
            if not self._warned_websocket:
                self._warned_websocket = True
                log.warning("WebSocket connections are not proxied yet; refusing %s", scope.get("path"))
            await receive()
            await send({"type": "websocket.close", "code": 1008})
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
    )
    inner: ASGIApp = proxy
    return ProxyApp(SentryCove(inner, engine=engine), proxy)
