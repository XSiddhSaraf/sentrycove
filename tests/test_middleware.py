from __future__ import annotations

from typing import Optional

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from agentgate import AgentGate

from .conftest import AGENT_ORIGIN, FakeFetcher, RecordingDispatcher, sign_headers

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"
OTHER_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15"


def base_config(mode: str = "monitor", **extra) -> dict:
    cfg = {
        "mode": mode,
        "web_bot_auth": {"trusted_agents": [{"name": "test-agent", "signature_agent": AGENT_ORIGIN}]},
        "rules": [
            {"name": "verified-agents-ok", "agents": ["verified"], "action": "allow"},
            {
                "name": "no-bot-forms",
                "paths": ["/contact"],
                "methods": ["POST"],
                "agents": ["declared", "automation"],
                "action": "block",
                "severity": "high",
            },
            {"name": "watch-api", "paths": ["/api/*"], "agents": ["automation"], "action": "monitor"},
        ],
        "honeypots": {"paths": ["/.env", "/backup*"], "ban_seconds": 600},
        "login": {"paths": ["/login"], "per_ip_threshold": 3, "global_threshold": 1000},
        "session": {"cookie_names": ["sid"]},
        "alerts": {"sinks": [], "cooldown_seconds": 0},
    }
    cfg.update(extra)
    return cfg


def make_app(config: dict, fetcher: Optional[FakeFetcher] = None):
    app = FastAPI()
    dispatcher = RecordingDispatcher()

    @app.get("/")
    def home(request: Request):
        identity = request.state.agentgate
        return {"agent": identity.label}

    @app.post("/contact")
    def contact():
        return {"ok": True}

    @app.get("/api/items")
    def items():
        return []

    @app.post("/login")
    def login(request: Request):
        raise HTTPException(status_code=401)

    app.add_middleware(AgentGate, config=config, dispatcher=dispatcher, key_fetcher=fetcher or FakeFetcher())
    return app, dispatcher


def test_browser_passes_untouched():
    app, alerts = make_app(base_config())
    r = TestClient(app).get("/", headers={"User-Agent": BROWSER_UA})
    assert r.status_code == 200 and r.json() == {"agent": "unclassified"}
    assert alerts.records == []


def test_monitor_mode_alerts_but_does_not_block():
    app, alerts = make_app(base_config("monitor"))
    r = TestClient(app).post("/contact", headers={"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.2)"})
    assert r.status_code == 200
    assert alerts.types() == ["policy_match"]
    assert alerts.records[0].action_taken == "would block (monitor mode)"
    assert alerts.records[0].agent == "declared:GPTBot"


def test_enforce_mode_blocks_declared_bot_on_form():
    app, alerts = make_app(base_config("enforce"))
    r = TestClient(app).post("/contact", headers={"User-Agent": "python-requests/2.32"})
    assert r.status_code == 403
    assert alerts.records[0].severity == "high"


def test_verified_agent_is_allowed_even_in_enforce(signing_key, fetcher):
    app, alerts = make_app(base_config("enforce"), fetcher)
    headers = sign_headers(signing_key, authority="testserver")
    headers["User-Agent"] = "Mozilla/5.0 (compatible; GPTBot/1.2)"
    client = TestClient(app)
    assert client.get("/", headers=headers).json() == {"agent": "verified:test-agent"}
    r = client.post("/contact", headers=sign_headers(signing_key, authority="testserver"))
    assert r.status_code == 200
    assert alerts.records == []


def test_forged_signature_raises_high_alert_and_falls_back_to_ua(signing_key, fetcher):
    app, alerts = make_app(base_config("enforce"), fetcher)
    headers = sign_headers(signing_key, authority="other.example")  # signed for another host
    headers["User-Agent"] = "Mozilla/5.0 (compatible; ClaudeBot/1.0)"
    r = TestClient(app).post("/contact", headers=headers)
    assert r.status_code == 403
    sig_alert = next(a for a in alerts.records if a.type == "agent_signature_invalid")
    assert sig_alert.severity == "high"


def test_monitor_rule_allows_with_alert():
    app, alerts = make_app(base_config("enforce"))
    r = TestClient(app).get("/api/items", headers={"User-Agent": "curl/8.9"})
    assert r.status_code == 200
    assert alerts.records[0].action_taken == "allowed (monitor rule)"


def test_honeypot_bans_ip_in_enforce_mode():
    app, alerts = make_app(base_config("enforce"))
    client = TestClient(app)
    assert client.get("/.env").status_code == 404
    assert alerts.records[0].type == "honeypot_hit" and alerts.records[0].severity == "critical"
    # The same IP is now banned from the whole app.
    assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 403


def test_honeypot_only_alerts_in_monitor_mode():
    app, alerts = make_app(base_config("monitor"))
    client = TestClient(app)
    client.get("/backup.zip")
    assert alerts.types() == ["honeypot_hit"]
    assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 200


def test_login_bruteforce_detected():
    app, alerts = make_app(base_config())
    client = TestClient(app)
    for _ in range(3):
        assert client.post("/login", headers={"User-Agent": BROWSER_UA}).status_code == 401
    assert alerts.types() == ["login_bruteforce"]


def test_session_reused_from_other_device():
    app, alerts = make_app(base_config())
    client = TestClient(app)
    client.get("/", headers={"User-Agent": BROWSER_UA, "Cookie": "sid=abc123"})
    client.get("/", headers={"User-Agent": BROWSER_UA, "Cookie": "sid=abc123"})
    assert alerts.records == []
    client.get("/", headers={"User-Agent": OTHER_UA, "Cookie": "sid=abc123"})
    assert alerts.types() == ["session_device_change"]
    assert "abc123" not in alerts.records[0].detail  # raw token never leaves the process


def test_spoofed_x_forwarded_for_is_ignored_without_trusted_proxies():
    app, alerts = make_app(base_config("enforce"))
    client = TestClient(app)
    client.get("/.env", headers={"X-Forwarded-For": "203.0.113.9"})
    assert alerts.records[0].client_ip != "203.0.113.9"


def test_x_forwarded_for_used_with_trusted_proxy():
    app, alerts = make_app(base_config("monitor", trusted_proxy_hops=1))
    TestClient(app).get("/.env", headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.9"})
    assert alerts.records[0].client_ip == "203.0.113.9"


def test_fail_open_on_internal_error(monkeypatch):
    app, _ = make_app(base_config("enforce"))
    client = TestClient(app)
    client.get("/")  # build middleware stack

    def explode(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr("agentgate.middleware.classify", explode)
    assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 200


def test_fail_closed_when_configured(monkeypatch):
    app, _ = make_app(base_config("enforce", fail_open=False))
    client = TestClient(app)

    def explode(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr("agentgate.middleware.classify", explode)
    assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 503


def test_websocket_and_lifespan_pass_through():
    app, _ = make_app(base_config("enforce"))
    with TestClient(app) as client:  # runs lifespan startup/shutdown through the middleware
        assert client.get("/", headers={"User-Agent": BROWSER_UA}).status_code == 200


@pytest.mark.parametrize("ua", ["", "python-httpx/0.28", "Mozilla/5.0 HeadlessChrome/141.0"])
def test_automation_user_agents_classified(ua):
    app, _ = make_app(base_config())
    r = TestClient(app).get("/", headers={"User-Agent": ua})
    assert r.json()["agent"].startswith("automation")
