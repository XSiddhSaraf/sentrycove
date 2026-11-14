"""State backends: the in-memory default and Redis, shared between processes.

The Redis tests run against a real server. They start a throw-away
``redis-server`` when one is installed, or use ``SIGNALMOAT_TEST_REDIS_URL``
(CI sets this to a Redis service container); otherwise they are skipped.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

from signalmoat.alerts import Alert, AlertDispatcher
from signalmoat.config import StateConfig
from signalmoat.engine import Engine, RequestInfo
from signalmoat.state import NS_NONCE, MemoryState, RedisState, StateUnavailable, build_state

from .conftest import AGENT_ORIGIN, FakeFetcher, RecordingDispatcher, make_key, sign_headers

redis_asyncio = pytest.importorskip("redis.asyncio")
from redis.backoff import NoBackoff  # noqa: E402
from redis.retry import Retry  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    url = os.environ.get("SIGNALMOAT_TEST_REDIS_URL")
    if url:
        yield url
        return
    binary = shutil.which("redis-server")
    if binary is None:
        pytest.skip("no redis-server installed and SIGNALMOAT_TEST_REDIS_URL not set")
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed arguments, test-only
        [binary, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.fail("redis-server did not start")
                time.sleep(0.05)
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def prefix() -> str:
    """A fresh key prefix per test, so tests never see each other's keys."""
    return f"t{uuid.uuid4().hex[:12]}:"


def redis_state(url: str, prefix: str) -> RedisState:
    return RedisState(redis_asyncio.Redis.from_url(url), prefix)


def run(coro):
    return asyncio.run(coro)


# -- the backend contract, checked for both implementations ---------------------


@pytest.fixture(params=["memory", "redis"])
def backend_factory(request, prefix):
    if request.param == "memory":
        return lambda: MemoryState(1000)
    url = request.getfixturevalue("redis_url")
    return lambda: redis_state(url, prefix)


def test_ban_expires(backend_factory):
    async def go():
        s = backend_factory()
        assert not await s.is_banned("198.51.100.7")
        await s.ban("198.51.100.7", 0.2)
        assert await s.is_banned("198.51.100.7")
        assert not await s.is_banned("198.51.100.8")
        await asyncio.sleep(0.35)
        assert not await s.is_banned("198.51.100.7")
        await s.aclose()

    run(go())


def test_hit_counts_within_window_and_saturates(backend_factory):
    async def go():
        s = backend_factory()
        assert [await s.hit("login:ip", "a", 0.3, 100) for _ in range(3)] == [1, 2, 3]
        assert await s.hit("login:ip", "b", 0.3, 100) == 1  # keys are independent
        assert [await s.hit("login:ip", "c", 10, 2) for _ in range(4)] == [1, 2, 2, 2]  # capped
        await asyncio.sleep(0.4)
        assert await s.hit("login:ip", "a", 0.3, 100) == 1  # old events left the window
        await s.aclose()

    run(go())


def test_claim_once_then_again_after_expiry(backend_factory):
    async def go():
        s = backend_factory()
        assert await s.claim("nonce", "n1", 0.2)
        assert not await s.claim("nonce", "n1", 0.2)
        assert await s.claim("alert", "n1", 0.2)  # namespaces are independent
        await asyncio.sleep(0.35)
        assert await s.claim("nonce", "n1", 0.2)
        await s.aclose()

    run(go())


def test_remember_first_never_overwrites(backend_factory):
    async def go():
        s = backend_factory()
        assert await s.remember_first("session", "h1", "first", 5) is None
        assert await s.remember_first("session", "h1", "attacker", 5) == "first"
        assert await s.remember_first("session", "h1", "again", 5) == "first"
        await s.aclose()

    run(go())


# -- Redis specifics -----------------------------------------------------------------


def test_concurrent_claims_succeed_exactly_once(redis_url, prefix):
    async def go():
        states = [redis_state(redis_url, prefix) for _ in range(4)]
        results = await asyncio.gather(*(states[i % 4].claim(NS_NONCE, "race", 5) for i in range(50)))
        assert results.count(True) == 1
        for s in states:
            await s.aclose()

    run(go())


def test_concurrent_hits_are_not_lost(redis_url, prefix):
    async def go():
        states = [redis_state(redis_url, prefix) for _ in range(4)]
        await asyncio.gather(*(states[i % 4].hit("login:ip", "ip", 10, 1000) for i in range(40)))
        assert await states[0].hit("login:ip", "ip", 10, 1000) == 41
        for s in states:
            await s.aclose()

    run(go())


def test_keys_are_prefixed_readable_or_hashed(redis_url, prefix):
    async def go():
        s = redis_state(redis_url, prefix)
        assert s.key("ban", "203.0.113.5") == f"{prefix}ban:203.0.113.5"
        assert s.key("ban", "2001:db8::1") == f"{prefix}ban:2001:db8::1"
        hashed = s.key("nonce", "x" * 500)  # attacker-sized input is bounded
        assert hashed.startswith(f"{prefix}nonce:h:") and len(hashed) < 80
        assert s.key("nonce", "a b") != s.key("nonce", "a_b")
        await s.ban("203.0.113.5", 60)
        ttl = await s._redis.pttl(f"{prefix}ban:203.0.113.5")
        assert 0 < ttl <= 60_000  # every key expires
        await s.hit("login:ip", "203.0.113.5", 30, 10)
        assert 0 < await s._redis.pttl(f"{prefix}login:ip:203.0.113.5") <= 30_000
        await s.aclose()

    run(go())


def test_build_state_from_config(redis_url, monkeypatch):
    assert isinstance(build_state(StateConfig(), 10), MemoryState)
    cfg = StateConfig(backend="redis", redis_url_env="SM_TEST_REDIS")
    monkeypatch.delenv("SM_TEST_REDIS", raising=False)
    with pytest.raises(ValueError, match="SM_TEST_REDIS is not set"):
        build_state(cfg, 10)
    monkeypatch.setenv("SM_TEST_REDIS", "http://not-redis")
    with pytest.raises(ValueError, match="must start with"):
        build_state(cfg, 10)
    monkeypatch.setenv("SM_TEST_REDIS", redis_url)
    state = build_state(cfg, 10)
    assert isinstance(state, RedisState)

    async def go():
        assert await state.ping()
        await state.aclose()

    run(go())


# -- several SignalMoat processes sharing one Redis -------------------------------

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"


def config(mode: str = "enforce") -> dict:
    return {
        "mode": mode,
        "honeypots": {"paths": ["/.env"], "ban_seconds": 60},
        "login": {"paths": ["/login"], "per_ip_threshold": 3, "global_threshold": 1000},
        "session": {"cookie_names": ["sid"]},
        "web_bot_auth": {"trusted_agents": [{"name": "test-agent", "signature_agent": AGENT_ORIGIN}]},
    }


def req(path: str = "/", headers: dict[str, str] | None = None, method: str = "GET") -> RequestInfo:
    return RequestInfo.from_parts(
        method=method, scheme="http", host="testserver", target=path, headers=list((headers or {}).items())
    )


def test_ban_by_one_worker_blocks_on_every_worker(redis_url, prefix):
    async def go():
        a = Engine(config(), dispatcher=RecordingDispatcher(), state=redis_state(redis_url, prefix))
        b = Engine(config(), dispatcher=RecordingDispatcher(), state=redis_state(redis_url, prefix))
        assert (await b.inspect(req(headers={"User-Agent": BROWSER_UA}), "203.0.113.1")).block_status is None
        assert (await a.inspect(req("/.env"), "203.0.113.1")).block_status == 404  # trap on worker A
        assert (await b.inspect(req(headers={"User-Agent": BROWSER_UA}), "203.0.113.1")).block_status == 403
        assert (await b.inspect(req(headers={"User-Agent": BROWSER_UA}), "203.0.113.2")).block_status is None
        await a.aclose()
        await b.aclose()

    run(go())


def test_bruteforce_counted_across_workers(redis_url, prefix):
    async def go():
        engines = [
            Engine(config("monitor"), dispatcher=RecordingDispatcher(), state=redis_state(redis_url, prefix))
            for _ in range(3)
        ]
        for e in engines:  # one failure per worker: none of them alone reaches the threshold of 3
            await e.on_response(client_ip="203.0.113.3", method="POST", path="/login", agent="-", status=401)
        alerts = [t for e in engines for t in e.alerts.types()]  # type: ignore[attr-defined]
        assert alerts == ["login_bruteforce"]
        for e in engines:
            await e.aclose()

    run(go())


def test_stolen_session_detected_on_another_worker(redis_url, prefix):
    async def go():
        a = Engine(config("monitor"), dispatcher=RecordingDispatcher(), state=redis_state(redis_url, prefix))
        b = Engine(config("monitor"), dispatcher=RecordingDispatcher(), state=redis_state(redis_url, prefix))
        await a.inspect(req(headers={"User-Agent": BROWSER_UA, "Cookie": "sid=s3cret"}), "203.0.113.4")
        await b.inspect(req(headers={"User-Agent": "curl/8.9", "Cookie": "sid=s3cret"}), "198.51.100.4")
        assert b.alerts.types() == ["session_device_change"]  # type: ignore[attr-defined]
        assert a.alerts.types() == []  # type: ignore[attr-defined]
        await a.aclose()
        await b.aclose()

    run(go())


def test_replayed_nonce_rejected_by_another_worker(redis_url, prefix):
    key = make_key()
    fetcher = FakeFetcher({AGENT_ORIGIN: [key.jwk]})

    async def go():
        a = Engine(
            config(), dispatcher=RecordingDispatcher(), key_fetcher=fetcher, state=redis_state(redis_url, prefix)
        )
        b = Engine(
            config(), dispatcher=RecordingDispatcher(), key_fetcher=fetcher, state=redis_state(redis_url, prefix)
        )
        headers = sign_headers(key, nonce="only-once")
        assert (await a.inspect(req(headers=headers), "203.0.113.5")).identity.kind == "verified"
        assert (await b.inspect(req(headers=headers), "203.0.113.5")).identity.kind != "verified"
        assert b.alerts.types() == ["agent_signature_invalid"]  # type: ignore[attr-defined]
        assert "replayed nonce" in b.alerts.records[0].detail  # type: ignore[attr-defined]
        await a.aclose()
        await b.aclose()

    run(go())


class ListSink:
    def __init__(self) -> None:
        self.sent: list[Alert] = []

    async def send(self, alert: Alert) -> None:
        self.sent.append(alert)

    async def aclose(self) -> None:
        pass


def test_alert_sent_once_across_workers(redis_url, prefix):
    async def go():
        sinks = [ListSink() for _ in range(3)]
        states = [redis_state(redis_url, prefix) for _ in range(3)]
        dispatchers = [AlertDispatcher([(s, "low")], 60, shared_state=st) for s, st in zip(sinks, states, strict=True)]
        for d in dispatchers:
            assert d.emit(Alert("honeypot_hit", "critical", "t", dedupe_key="honeypot|203.0.113.6"))
        for d in dispatchers:
            await d.aclose()
        assert sum(len(s.sent) for s in sinks) == 1
        for st in states:
            await st.aclose()

    run(go())


def test_redis_outage_follows_fail_open(prefix):
    """An unreachable Redis makes inspection fail; the middleware then applies fail_open."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from signalmoat import SignalMoat

    def make(fail_open: bool) -> TestClient:
        dead = RedisState(
            redis_asyncio.Redis(
                host="127.0.0.1", port=_free_port(), socket_connect_timeout=0.2, retry=Retry(NoBackoff(), 0)
            ),
            prefix,
        )
        engine = Engine({**config(), "fail_open": fail_open}, dispatcher=RecordingDispatcher(), state=dead)
        app = FastAPI()
        app.add_middleware(SignalMoat, engine=engine)
        app.get("/")(lambda: {"ok": True})
        return TestClient(app, client=("203.0.113.9", 40000))  # a known address -> ban lookup hits Redis

    assert make(True).get("/", headers={"User-Agent": BROWSER_UA}).status_code == 200
    assert make(False).get("/", headers={"User-Agent": BROWSER_UA}).status_code == 503


def test_outage_trips_breaker_and_fails_fast(prefix):
    async def go():
        now = [0.0]
        client = redis_asyncio.Redis(
            host="127.0.0.1", port=_free_port(), socket_connect_timeout=0.2, retry=Retry(NoBackoff(), 0)
        )
        dead = RedisState(client, prefix, breaker_seconds=5, clock=lambda: now[0])
        with pytest.raises(StateUnavailable):
            await dead.is_banned("203.0.113.1")
        started = time.monotonic()
        with pytest.raises(StateUnavailable, match="marked down"):
            await dead.claim("nonce", "n", 5)  # no network attempt while the breaker is open
        assert time.monotonic() - started < 0.05
        now[0] = 6  # breaker closes again: the next call reaches the network
        with pytest.raises(StateUnavailable) as info:
            await dead.ping()
        assert "marked down" not in str(info.value)
        await dead.aclose()

    run(go())


def test_alert_delivered_when_shared_dedupe_is_down(prefix):
    async def go():
        sink = ListSink()
        dead = RedisState(
            redis_asyncio.Redis(
                host="127.0.0.1", port=_free_port(), socket_connect_timeout=0.2, retry=Retry(NoBackoff(), 0)
            ),
            prefix,
        )
        d = AlertDispatcher([(sink, "low")], 60, shared_state=dead)
        d.emit(Alert("x", "high", "t", dedupe_key="k"))
        await d.aclose()
        assert len(sink.sent) == 1  # a duplicate is better than a lost alert

    run(go())
