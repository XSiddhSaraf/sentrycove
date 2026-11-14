from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from sentrycove.alerts import Alert, AlertDispatcher, WebhookSink, build_sink
from sentrycove.config import SinkConfig, load_config
from sentrycove.identity import AgentIdentity
from sentrycove.policy import evaluate
from sentrycove.store import SlidingWindowCounter, TTLCache


class ListSink:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[Alert] = []
        self.fail = fail

    async def send(self, alert: Alert) -> None:
        if self.fail:
            raise RuntimeError("sink down")
        self.sent.append(alert)

    async def aclose(self) -> None:
        pass


def test_dedupe_and_severity_routing():
    all_sink, high_sink, broken = ListSink(), ListSink(), ListSink(fail=True)

    async def go():
        d = AlertDispatcher([(all_sink, "low"), (high_sink, "high"), (broken, "low")], cooldown_seconds=60)
        assert d.emit(Alert("x", "medium", "t", dedupe_key="k1"))
        assert not d.emit(Alert("x", "medium", "t", dedupe_key="k1"))  # duplicate suppressed
        assert d.emit(Alert("y", "critical", "t", dedupe_key="k2"))
        await d.aclose()  # broken sink must not raise

    asyncio.run(go())
    assert [a.type for a in all_sink.sent] == ["x", "y"]
    assert [a.type for a in high_sink.sent] == ["y"]


def test_slack_payload_escapes_markup():
    sink = WebhookSink("https://hooks.example/x", 1.0, slack=True)
    payload = sink._payload(Alert("t", "high", "<script>&", path="/a<b>"))
    assert "<script>" not in payload["text"] and "&lt;script&gt;&amp;" in payload["text"]


def test_webhook_sink_requires_https_and_env(monkeypatch):
    cfg = SinkConfig(type="webhook", url_env="AG_TEST_URL")
    monkeypatch.delenv("AG_TEST_URL", raising=False)
    assert build_sink(cfg, 1.0) is None
    monkeypatch.setenv("AG_TEST_URL", "http://insecure.example/hook")
    assert build_sink(cfg, 1.0) is None
    monkeypatch.setenv("AG_TEST_URL", "https://hooks.example/hook")
    assert isinstance(build_sink(cfg, 1.0), WebhookSink)


def test_config_rejects_typos_and_bad_selectors():
    with pytest.raises(ValidationError):
        load_config({"mdoe": "enforce"})
    with pytest.raises(ValidationError):
        load_config({"rules": [{"name": "r", "agents": ["robots"], "action": "block"}]})
    with pytest.raises(ValidationError):
        load_config({"alerts": {"sinks": [{"type": "slack"}]}})
    with pytest.raises(ValidationError):
        load_config({"web_bot_auth": {"trusted_agents": [{"name": "a", "signature_agent": "http://x.example"}]}})


def test_example_policy_file_loads():
    from pathlib import Path

    cfg = load_config(Path(__file__).resolve().parent.parent / "examples" / "sentrycove.yaml")
    assert cfg.mode == "monitor"


def test_policy_first_match_wins_and_named_selectors():
    cfg = load_config(
        {
            "rules": [
                {"name": "a", "agents": ["declared:gptbot"], "paths": ["/docs/*"], "action": "allow"},
                {"name": "b", "agents": ["declared"], "action": "block"},
            ]
        }
    )
    gpt = AgentIdentity("declared", "GPTBot")
    other = AgentIdentity("declared", "CCBot")
    assert evaluate(cfg.rules, gpt, "GET", "/docs/x").rule.name == "a"
    assert evaluate(cfg.rules, other, "GET", "/docs/x").action == "block"
    assert evaluate(cfg.rules, AgentIdentity("unclassified"), "GET", "/").action == "allow"


def test_stores_are_bounded_and_expire():
    now = [0.0]
    cache: TTLCache[str, int] = TTLCache(2, 10, clock=lambda: now[0])
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None and len(cache) == 2
    now[0] = 11
    assert cache.get("b") is None

    counter: SlidingWindowCounter[str] = SlidingWindowCounter(10, 5, 100, clock=lambda: now[0])
    assert [counter.hit("ip") for _ in range(3)] == [1, 2, 3]
    now[0] += 11
    assert counter.hit("ip") == 1
