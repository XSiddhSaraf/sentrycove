"""WebSockets: screened at the handshake, relayed by the proxy, cut off when banned."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from signalmoat import SignalMoat
from signalmoat.engine import Engine
from signalmoat.proxy import create_proxy_app

from ._servers import ServerThread
from .conftest import RecordingDispatcher

ws_sync = pytest.importorskip("websockets.sync.client")
from websockets.exceptions import ConnectionClosed, InvalidStatus  # noqa: E402

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"


class WsUpstream:
    """A stand-in app: tells the client what handshake it received, then echoes."""

    def __init__(self) -> None:
        self.handshakes: list[str] = []

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
            await send({"type": "http.response.body", "body": b"ok"})
            return
        if scope["type"] != "websocket":
            return
        self.handshakes.append(scope["path"])
        await receive()  # websocket.connect
        if scope["path"] == "/refuse":
            await send({"type": "websocket.close", "code": 1008})
            return
        offered = scope.get("subprotocols") or []
        await send({"type": "websocket.accept", "subprotocol": offered[0] if offered else None})
        headers: dict[str, list[str]] = {}
        for k, v in scope["headers"]:
            headers.setdefault(k.decode("latin-1"), []).append(v.decode("latin-1"))
        await send({"type": "websocket.send", "text": json.dumps({"headers": headers})})
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("text") == "close-4001":
                await send({"type": "websocket.close", "code": 4001, "reason": "bye"})
                return
            if message.get("bytes") is not None:
                await send({"type": "websocket.send", "bytes": message["bytes"][::-1]})
            else:
                await send({"type": "websocket.send", "text": "echo:" + message["text"]})


def policy(mode: str = "enforce", **extra) -> dict:
    cfg = {
        "mode": mode,
        "rules": [{"name": "no-scripted-ws", "paths": ["/feed"], "agents": ["automation"], "action": "block"}],
        "honeypots": {"paths": ["/.env"], "ban_seconds": 60},
        "websocket": {"ban_recheck_seconds": 0.1},
        "alerts": {"sinks": [], "cooldown_seconds": 0},
    }
    cfg.update(extra)
    return cfg


@pytest.fixture
def stack(request):
    cfg = getattr(request, "param", None) or policy()
    upstream, alerts = WsUpstream(), RecordingDispatcher()
    with ServerThread(upstream) as up:
        app = create_proxy_app(up.url, engine=Engine(cfg, dispatcher=alerts))
        with ServerThread(app) as px:
            yield up, px, upstream, alerts


def ws_connect(url: str, **kwargs):
    headers = {"User-Agent": BROWSER_UA, **kwargs.pop("headers", {})}
    return ws_sync.connect(url, additional_headers=headers, proxy=None, open_timeout=5, **kwargs)


def ws_url(server, path: str) -> str:
    return server.url.replace("http://", "ws://") + path


def test_messages_relayed_both_ways_with_trustworthy_headers(stack):
    up, px, _, _ = stack
    with ws_connect(
        ws_url(px, "/chat?room=1"),
        subprotocols=["chat.v2", "chat.v1"],
        headers={"X-SignalMoat-Agent": "verified:forged", "Origin": "https://app.example", "Cookie": "sid=abc"},
    ) as ws:
        assert ws.subprotocol == "chat.v2"
        hello = json.loads(ws.recv(timeout=5))["headers"]
        assert hello["x-signalmoat-agent"] == ["unclassified"]  # forged copy removed, real verdict added
        assert hello["x-signalmoat-client-ip"] == ["127.0.0.1"]
        assert hello["host"] == [px.url.removeprefix("http://")]  # client's Host preserved
        assert hello["origin"] == ["https://app.example"] and hello["cookie"] == ["sid=abc"]
        assert hello["user-agent"] == [BROWSER_UA]
        assert len(hello["sec-websocket-key"]) == 1
        ws.send("hi")
        assert ws.recv(timeout=5) == "echo:hi"
        ws.send(b"\x00\x01\x02")
        assert ws.recv(timeout=5) == b"\x02\x01\x00"


def test_upstream_close_code_reaches_client(stack):
    _, px, _, _ = stack
    with ws_connect(ws_url(px, "/chat")) as ws:
        ws.recv(timeout=5)
        ws.send("close-4001")
        with pytest.raises(ConnectionClosed) as info:
            ws.recv(timeout=5)
    assert info.value.rcvd is not None and info.value.rcvd.code == 4001


def test_blocked_handshake_never_reaches_the_app(stack):
    _, px, upstream, alerts = stack
    with pytest.raises(InvalidStatus) as info:
        ws_connect(ws_url(px, "/feed"), headers={"User-Agent": "python-requests/2.32"})
    assert info.value.response.status_code == 403
    assert upstream.handshakes == []
    assert alerts.types() == ["policy_match"]


def test_open_connection_cut_when_its_ip_is_banned(stack):
    _, px, _, alerts = stack
    with ws_connect(ws_url(px, "/chat")) as ws:
        ws.recv(timeout=5)
        ws.send("still here")
        assert ws.recv(timeout=5) == "echo:still here"
        # The same address now trips a honeypot over plain HTTP and is banned.
        assert httpx.get(px.url + "/.env", trust_env=False).status_code == 404
        with pytest.raises(ConnectionClosed) as info:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                ws.recv(timeout=1)
    assert info.value.rcvd is not None and info.value.rcvd.code == 1008
    assert "honeypot_hit" in alerts.types()


def test_upstream_refusal_and_outage_are_handled(stack):
    up, px, _, _ = stack
    with pytest.raises(InvalidStatus):
        ws_connect(ws_url(px, "/refuse"))
    app = create_proxy_app("http://127.0.0.1:9", engine=Engine(policy(), dispatcher=RecordingDispatcher()))
    with ServerThread(app) as dead, pytest.raises(InvalidStatus):
        ws_connect(ws_url(dead, "/chat"))


@pytest.mark.parametrize("stack", [policy(websocket={"enabled": False})], indirect=True)
def test_websockets_can_be_switched_off(stack):
    _, px, upstream, _ = stack
    with pytest.raises(InvalidStatus):
        ws_connect(ws_url(px, "/chat"))
    assert upstream.handshakes == []


# -- ASGI middleware (FastAPI WebSocket endpoints) ------------------------------


def fastapi_app(cfg: dict) -> tuple[FastAPI, RecordingDispatcher]:
    alerts = RecordingDispatcher()
    app = FastAPI()
    app.add_middleware(SignalMoat, engine=Engine(cfg, dispatcher=alerts))

    @app.websocket("/feed")
    async def feed(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text(websocket.state.signalmoat.label)
        await websocket.close()

    return app, alerts


def test_middleware_screens_websocket_endpoints():
    app, alerts = fastapi_app(policy())
    client = TestClient(app, client=("203.0.113.20", 5000))
    with client.websocket_connect("/feed", headers={"User-Agent": BROWSER_UA}) as ws:
        assert ws.receive_text() == "unclassified"
    with (
        pytest.raises(WebSocketDisconnect) as info,
        client.websocket_connect("/feed", headers={"User-Agent": "curl/8"}),
    ):
        pass
    assert info.value.code == 1008
    assert alerts.types() == ["policy_match"]


def test_middleware_websocket_monitor_mode_only_alerts():
    app, alerts = fastapi_app(policy("monitor"))
    client = TestClient(app, client=("203.0.113.21", 5000))
    with client.websocket_connect("/feed", headers={"User-Agent": "curl/8"}) as ws:
        assert ws.receive_text() == "automation:curl"
    assert alerts.records[0].action_taken == "would block (monitor mode)"
