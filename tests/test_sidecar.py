from __future__ import annotations

import asyncio

import httpx
import pytest

from signalmoat.cli import main
from signalmoat.engine import Engine
from signalmoat.sidecar import DecisionAPI

from .conftest import RecordingDispatcher

TOKEN = "test-token-0123456789abcdef"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"

POLICY = {
    "mode": "enforce",
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
    "honeypots": {"paths": ["/.env"], "ban_seconds": 600},
    "login": {"paths": ["/login"], "per_ip_threshold": 2, "global_threshold": 1000},
    "alerts": {"sinks": [], "cooldown_seconds": 0},
}


def call(api: DecisionAPI, *requests):
    """Send (method, path, kwargs) requests to the API in one event loop; return responses."""

    async def go():
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(transport=transport, base_url="http://sidecar") as client:
            return [await client.request(m, p, **kw) for m, p, kw in requests]

    return asyncio.run(go())


def inspect_body(target="/", method="GET", ua=BROWSER_UA, peer="203.0.113.5", **extra):
    return {
        "method": method,
        "scheme": "https",
        "host": "shop.example",
        "target": target,
        "headers": [["Host", "shop.example"], ["User-Agent", ua]],
        "peer_ip": peer,
        **extra,
    }


@pytest.fixture
def api():
    alerts = RecordingDispatcher()
    api = DecisionAPI(Engine(POLICY, dispatcher=alerts), TOKEN)
    api.alerts = alerts
    return api


def test_token_is_required_and_must_be_long():
    with pytest.raises(ValueError):
        DecisionAPI(Engine(POLICY, dispatcher=RecordingDispatcher()), "short")


def test_calls_without_the_right_token_are_refused(api):
    body = inspect_body()
    missing, wrong, basic = call(
        api,
        ("POST", "/v1/inspect", {"json": body}),
        ("POST", "/v1/inspect", {"json": body, "headers": {"Authorization": "Bearer nope-nope-nope-nope"}}),
        ("POST", "/v1/inspect", {"json": body, "headers": {"Authorization": f"Basic {TOKEN}"}}),
    )
    assert [missing.status_code, wrong.status_code, basic.status_code] == [401, 401, 401]


def test_allow_block_and_ban(api):
    ok, bot, trap, banned, other_ip = call(
        api,
        ("POST", "/v1/inspect", {"json": inspect_body("/"), "headers": AUTH}),
        ("POST", "/v1/inspect", {"json": inspect_body("/contact?x=1", "POST", "curl/8.9"), "headers": AUTH}),
        ("POST", "/v1/inspect", {"json": inspect_body("/.ENV"), "headers": AUTH}),
        ("POST", "/v1/inspect", {"json": inspect_body("/"), "headers": AUTH}),
        ("POST", "/v1/inspect", {"json": inspect_body("/", peer="198.51.100.20"), "headers": AUTH}),
    )
    assert ok.json() == {
        "action": "allow",
        "status": None,
        "agent": {"kind": "unclassified", "name": None, "label": "unclassified"},
        "client_ip": "203.0.113.5",
        "report_response": False,
        "degraded": False,
    }
    assert bot.json()["action"] == "block" and bot.json()["status"] == 403
    assert bot.json()["agent"]["label"] == "automation:curl"
    assert trap.json()["action"] == "block" and trap.json()["status"] == 404
    assert banned.json()["action"] == "block"  # same IP is banned after the honeypot hit
    assert other_ip.json()["action"] == "allow"
    assert api.alerts.types() == ["policy_match", "honeypot_hit"]


def test_login_failures_reported_by_the_app_raise_an_alert(api):
    report = {
        "client_ip": "203.0.113.5",
        "method": "POST",
        "target": "/login?next=/",
        "agent": "unclassified",
        "status": 401,
    }
    inspected, r1, ignored, r2 = call(
        api,
        ("POST", "/v1/inspect", {"json": inspect_body("/login", "POST"), "headers": AUTH}),
        ("POST", "/v1/response", {"json": report, "headers": AUTH}),
        ("POST", "/v1/response", {"json": {**report, "target": "/other"}, "headers": AUTH}),
        ("POST", "/v1/response", {"json": report, "headers": AUTH}),
    )
    assert inspected.json()["report_response"] is True
    assert [r1.status_code, ignored.status_code, r2.status_code] == [204, 204, 204]
    assert api.alerts.types() == ["login_bruteforce"]


def test_bad_input_is_rejected_without_echoing_it(api):
    bad_target, not_json, too_big, wrong_method, unknown, health = call(
        api,
        ("POST", "/v1/inspect", {"json": inspect_body("no-leading-slash"), "headers": AUTH}),
        ("POST", "/v1/inspect", {"content": b"{not json", "headers": AUTH}),
        ("POST", "/v1/inspect", {"content": b"x" * (1100 * 1024), "headers": AUTH}),
        ("GET", "/v1/inspect", {"headers": AUTH}),
        ("POST", "/v1/nope", {"json": {}, "headers": AUTH}),
        ("GET", "/_signalmoat/health", {}),
    )
    assert bad_target.status_code == 422 and "no-leading-slash" not in bad_target.text
    assert [not_json.status_code, too_big.status_code] == [400, 400]
    assert wrong_method.status_code == 405 and unknown.status_code == 404
    assert health.json() == {"status": "ok", "mode": "enforce", "api": 1}


def test_fail_open_and_fail_closed_on_engine_errors(monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr("signalmoat.engine.classify", explode)
    open_api = DecisionAPI(Engine(POLICY, dispatcher=RecordingDispatcher()), TOKEN)
    closed_api = DecisionAPI(Engine({**POLICY, "fail_open": False}, dispatcher=RecordingDispatcher()), TOKEN)
    (opened,) = call(open_api, ("POST", "/v1/inspect", {"json": inspect_body(), "headers": AUTH}))
    (closed,) = call(closed_api, ("POST", "/v1/inspect", {"json": inspect_body(), "headers": AUTH}))
    assert opened.json()["action"] == "allow" and opened.json()["degraded"] is True
    assert closed.status_code == 503


def test_cli_validates_config_and_refuses_to_start_without_a_token(tmp_path, monkeypatch, capsys):
    good = tmp_path / "ok.yaml"
    good.write_text("mode: enforce\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("mdoe: enforce\n")
    assert main(["check-config", str(good)]) == 0
    assert main(["check-config", str(bad)]) == 1
    monkeypatch.delenv("SIGNALMOAT_API_TOKEN", raising=False)
    assert main(["sidecar"]) == 2
    monkeypatch.delenv("SIGNALMOAT_UPSTREAM", raising=False)
    assert main(["proxy"]) == 2
    assert main(["proxy", "--upstream", "not-a-url"]) == 2
    assert "SIGNALMOAT_API_TOKEN" in capsys.readouterr().err


def test_oversized_requests_are_still_judged_not_refused(api):
    """A refusal here would become a fail-open bypass in the calling middleware."""
    body = inspect_body("/contact?" + "q" * 50_000, "POST", "curl/8.9")
    body["headers"] += [[f"X-Pad-{i}", "v" * 100] for i in range(2000)]
    body["method"] = "POST"
    (r,) = call(api, ("POST", "/v1/inspect", {"json": body, "headers": AUTH}))
    assert r.status_code == 200 and r.json()["action"] == "block"
    assert len(api.alerts.records[0].path) <= 200  # alerts stay small
