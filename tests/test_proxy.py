from __future__ import annotations

import hashlib
import socket

import httpx
import pytest

from sentrycove.engine import Engine
from sentrycove.proxy import HEALTH_PATH, ReverseProxy, create_proxy_app

from ._servers import ServerThread, Upstream
from .conftest import RecordingDispatcher

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"


def policy(mode: str = "enforce", **extra) -> dict:
    cfg = {
        "mode": mode,
        "rules": [
            {
                "name": "no-bot-forms",
                "paths": ["/contact"],
                "methods": ["POST"],
                "agents": ["declared", "automation"],
                "action": "block",
                "severity": "high",
            },
        ],
        "honeypots": {"paths": ["/.env"], "ban_seconds": 0},
        "login": {"paths": ["/login"], "per_ip_threshold": 3, "global_threshold": 1000},
        "alerts": {"sinks": [], "cooldown_seconds": 0},
    }
    cfg.update(extra)
    return cfg


class Stack:
    def __init__(self, upstream, upstream_server, proxy_server, alerts) -> None:
        self.upstream, self.alerts = upstream, alerts
        self.upstream_url, self.url = upstream_server.url, proxy_server.url
        self.client = httpx.Client(base_url=proxy_server.url, trust_env=False, headers={"User-Agent": BROWSER_UA})

    def headers_seen(self, response: httpx.Response) -> dict[str, list[str]]:
        seen: dict[str, list[str]] = {}
        for name, value in response.json()["headers"]:
            seen.setdefault(name, []).append(value)
        return seen


@pytest.fixture
def stack(request):
    cfg = getattr(request, "param", None) or policy()
    upstream, alerts = Upstream(), RecordingDispatcher()
    with ServerThread(upstream, server_header=False) as up:
        app = create_proxy_app(up.url, engine=Engine(cfg, dispatcher=alerts))
        with ServerThread(app, server_header=False, date_header=False) as px:
            s = Stack(upstream, up, px, alerts)
            yield s
            s.client.close()


def test_request_is_forwarded_with_trustworthy_headers(stack):
    r = stack.client.get(
        "/echo/a%2Fb%20c?x=1&y=%C3%A9",
        headers={
            "X-Forwarded-For": "6.6.6.6",  # forged by the client
            "X-Real-IP": "6.6.6.6",
            "X-SentryCove-Agent": "verified:forged",
            "Connection": "keep-alive, X-Drop-Me",
            "X-Drop-Me": "1",
            "Accept-Encoding": "identity",
        },
    )
    assert r.status_code == 200
    body, seen = r.json(), stack.headers_seen(r)
    assert body["raw_path"] == "/echo/a%2Fb%20c"  # client's own encoding is preserved
    assert body["query"] == "x=1&y=%C3%A9"
    assert seen["host"] == [f"127.0.0.1:{stack.url.rsplit(':', 1)[1]}"]  # original Host kept
    assert seen["x-forwarded-for"] == ["127.0.0.1"]  # forged value dropped, real peer set
    assert "x-real-ip" not in seen
    assert seen["x-forwarded-proto"] == ["http"]
    assert seen["x-sentrycove-agent"] == ["unclassified"]  # forged value replaced
    assert seen["x-sentrycove-client-ip"] == ["127.0.0.1"]
    assert "x-drop-me" not in seen  # named in Connection => hop-by-hop
    assert seen["accept-encoding"] == ["identity"]  # nothing added on the client's behalf
    assert seen["user-agent"] == [BROWSER_UA]


@pytest.mark.parametrize("stack", [policy(trusted_proxy_hops=1)], indirect=True)
def test_forwarding_chain_is_extended_behind_a_trusted_proxy(stack):
    r = stack.client.get(
        "/echo", headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.9", "X-Forwarded-Proto": "https"}
    )
    seen = stack.headers_seen(r)
    assert seen["x-forwarded-for"] == ["198.51.100.1, 203.0.113.9, 127.0.0.1"]
    assert seen["x-forwarded-proto"] == ["https"]
    assert seen["x-sentrycove-client-ip"] == ["203.0.113.9"]


def test_large_and_chunked_bodies_arrive_intact(stack):
    payload = bytes(range(256)) * 8192  # 2 MiB
    r = stack.client.post("/echo", content=payload)
    assert r.json()["body_len"] == len(payload)
    assert r.json()["body_sha256"] == hashlib.sha256(payload).hexdigest()

    def chunks():
        for i in range(50):
            yield bytes([i]) * 10_000

    r = stack.client.post("/echo", content=chunks())  # no Content-Length: chunked upload
    assert r.json()["body_len"] == 500_000
    assert r.json()["body_sha256"] == hashlib.sha256(b"".join(chunks())).hexdigest()


def test_bodyless_requests_do_not_gain_a_body(stack):
    seen = stack.headers_seen(stack.client.get("/echo"))
    assert "transfer-encoding" not in seen and "content-length" not in seen
    assert stack.client.head("/echo").status_code == 200
    assert stack.client.delete("/echo").json()["method"] == "DELETE"


def test_streamed_compressed_and_multi_header_responses(stack):
    with stack.client.stream("GET", "/stream") as r:
        assert r.headers["content-type"] == "text/event-stream"
        assert b"".join(r.iter_raw()) == b"data: 0\n\ndata: 1\n\ndata: 2\n\n"
    r = stack.client.get("/gzip")
    assert r.headers["content-encoding"] == "gzip" and r.text == "hello " * 1000
    r = stack.client.get("/cookies")
    assert r.headers.get_list("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert r.headers["x-powered-by"] == "demo"
    assert "server" not in r.headers  # the proxy does not advertise itself
    assert len(r.headers.get_list("date")) == 1  # the app's Date header, not a second one
    r = stack.client.get("/redirect")
    assert r.status_code == 302 and r.headers["location"] == "https://elsewhere.example/next"


def test_blocked_requests_never_reach_the_app(stack):
    assert stack.client.get("/.env").status_code == 404
    assert stack.client.get("/%2Eenv").status_code == 404
    r = stack.client.post("/contact", headers={"User-Agent": "python-requests/2.32"}, json={"spam": True})
    assert r.status_code == 403 and r.json() == {"error": "request blocked"}
    assert stack.upstream.hits == []
    assert stack.alerts.types() == ["honeypot_hit", "honeypot_hit", "policy_match"]
    assert stack.client.post("/contact", json={"hello": 1}).status_code == 200  # a browser still gets through
    assert stack.upstream.hits == ["/contact"]


def test_failed_logins_at_the_app_raise_an_alert(stack):
    for _ in range(3):
        assert stack.client.post("/login", json={"u": "a", "p": "b"}).status_code == 401
    assert stack.alerts.types() == ["login_bruteforce"]
    assert stack.alerts.records[0].client_ip == "127.0.0.1"


def test_health_endpoint_is_answered_by_the_proxy(stack):
    r = stack.client.get(HEALTH_PATH)
    assert r.json() == {"status": "ok", "mode": "enforce"}
    assert stack.upstream.hits == []


def test_upstream_down_gives_502_and_slow_upstream_504():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]
    app = create_proxy_app(f"http://127.0.0.1:{dead_port}", engine=Engine(policy(), dispatcher=RecordingDispatcher()))
    with ServerThread(app) as px, httpx.Client(base_url=px.url, trust_env=False) as client:
        assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 502

    upstream = Upstream()
    with ServerThread(upstream) as up:
        engine = Engine(policy(), dispatcher=RecordingDispatcher())
        app = create_proxy_app(up.url, engine=engine)
        app.proxy._timeout = httpx.Timeout(0.3)
        with ServerThread(app) as px, httpx.Client(base_url=px.url, trust_env=False) as client:
            assert client.get("/slow", headers={"User-Agent": BROWSER_UA}).status_code == 504


@pytest.mark.parametrize("bad", ["app:3000", "ftp://app", "http://app/base", "http://user:pw@app", "http://app?x=1"])
def test_upstream_must_be_a_plain_origin(bad):
    with pytest.raises(ValueError):
        ReverseProxy(bad)
