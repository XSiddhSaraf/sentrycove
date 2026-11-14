"""JA4 TLS fingerprints passed in by the TLS terminator."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from signalmoat.config import load_config
from signalmoat.engine import Engine, RequestInfo
from signalmoat.ja4 import browser_mismatch, from_headers, matches, parse

from .conftest import RecordingDispatcher

CHROME = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
GO_CLIENT = "t13d190900_9dc949149365_97f8aa674fd9"  # Go TLS stack: no ALPN offered
LEGACY = "t11d070600_c50f5591e341_1a3805c3aa63"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0 Safari/537.36"
)


@pytest.mark.parametrize(
    "value",
    [CHROME, GO_CLIENT, "q13d0310h3_55b375c5d22e_cd85d2d88918", " T13D1516H2_8DAAF6152771_D8A2DA3F94CD "],
)
def test_parses_well_formed_fingerprints(value):
    ja4 = parse(value)
    assert ja4 is not None and ja4.value == value.strip().lower()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "t13d1516h2",  # only part a
        "t13d1516h2_8daaf6152771",
        "x13d1516h2_8daaf6152771_d8a2da3f94cd",  # unknown protocol
        "t13d1516h2_8daaf615277g_d8a2da3f94cd",  # not hex
        "t13d1516h2_8daaf6152771_d8a2da3f94cd_extra",
        "t13d1516h2_8daaf6152771_d8a2da3f94cd\nx-evil: 1",
        "<script>",
    ],
)
def test_rejects_anything_else(value):
    assert parse(value) is None


def test_rightmost_value_wins_and_padding_cannot_hide_it():
    assert from_headers([GO_CLIENT, CHROME]).value == CHROME  # proxy appended after a forged value
    assert from_headers([f"{GO_CLIENT}, {CHROME}"]).value == CHROME
    assert from_headers(["x" * 100_000 + "," + CHROME]).value == CHROME
    assert from_headers([CHROME + "," + "x" * 10_000]) is None  # malformed last value: ignored, not guessed
    assert from_headers([]) is None


def test_pattern_matching():
    chrome = parse(CHROME)
    assert matches(chrome, ["*"]) and matches(None, ["*"])
    assert matches(chrome, ["t13d1516h2_*"]) and matches(chrome, ["*_d8a2da3f94cd"])
    assert not matches(chrome, ["t13d1909*"])
    assert not matches(None, ["t13d1516h2_*"])  # no fingerprint never satisfies a specific pattern


def test_browser_mismatch_only_for_impossible_combinations():
    assert browser_mismatch(CHROME_UA, parse(CHROME)) is None
    assert "no ALPN" in browser_mismatch(CHROME_UA, parse(GO_CLIENT))
    assert "TLS 1.1" in browser_mismatch(CHROME_UA, parse(LEGACY))
    assert browser_mismatch("python-requests/2.32", parse(GO_CLIENT)) is None  # honest UA: nothing to flag
    assert browser_mismatch(CHROME_UA, parse("q13d0310h3_55b375c5d22e_cd85d2d88918")) is None  # QUIC


def test_config_requires_a_trusted_proxy_and_valid_patterns():
    with pytest.raises(ValidationError, match="trusted_proxy_hops"):
        load_config({"ja4": {"enabled": True}})
    with pytest.raises(ValidationError, match="ja4 section is not enabled"):
        load_config({"rules": [{"name": "r", "ja4": ["t13*"], "action": "block"}]})
    with pytest.raises(ValidationError, match="invalid ja4 pattern"):
        load_config(
            {
                "trusted_proxy_hops": 1,
                "ja4": {"enabled": True},
                "rules": [{"name": "r", "ja4": ["t[1]"], "action": "block"}],
            }
        )
    cfg = load_config({"trusted_proxy_hops": 1, "ja4": {"enabled": True, "header": "X-JA4"}})
    assert cfg.ja4.header == "x-ja4"


def policy(**ja4) -> dict:
    return {
        "mode": "enforce",
        "trusted_proxy_hops": 1,
        "ja4": {"enabled": True, **ja4},
        "rules": [
            {"name": "known-bad-tls", "ja4": ["t13d190900_9dc949149365_*"], "action": "block", "severity": "high"},
        ],
    }


def inspect(cfg: dict, headers: dict[str, str]):
    alerts = RecordingDispatcher()
    engine = Engine(cfg, dispatcher=alerts)
    request = RequestInfo.from_parts(
        method="GET", scheme="https", host="app.example", target="/", headers=list(headers.items())
    )

    async def go():
        verdict = await engine.inspect(request, "10.0.0.1")
        await engine.aclose()
        return verdict

    return asyncio.run(go()), alerts


def test_rule_blocks_by_fingerprint_and_reports_it():
    verdict, alerts = inspect(policy(), {"User-Agent": CHROME_UA, "cf-ja4": GO_CLIENT})
    assert verdict.block_status == 403 and verdict.ja4.value == GO_CLIENT
    assert alerts.types() == ["ja4_browser_mismatch", "policy_match"]
    assert GO_CLIENT in alerts.records[1].detail


def test_real_browser_passes_quietly():
    verdict, alerts = inspect(policy(), {"User-Agent": CHROME_UA, "cf-ja4": CHROME})
    assert verdict.block_status is None and alerts.records == []


def test_missing_or_garbage_fingerprint_is_ignored():
    for headers in ({"User-Agent": CHROME_UA}, {"User-Agent": CHROME_UA, "cf-ja4": "not-a-ja4"}):
        verdict, alerts = inspect(policy(), headers)
        assert verdict.ja4 is None and verdict.block_status is None and alerts.records == []


def test_header_is_not_read_when_disabled():
    cfg = {"mode": "enforce", "trusted_proxy_hops": 1}
    verdict, alerts = inspect(cfg, {"User-Agent": CHROME_UA, "cf-ja4": GO_CLIENT})
    assert verdict.ja4 is None and alerts.records == []


def test_custom_header_and_mismatch_alert_can_be_turned_off():
    verdict, alerts = inspect(
        policy(header="x-ja4", alert_on_browser_mismatch=False), {"User-Agent": CHROME_UA, "X-JA4": LEGACY}
    )
    assert verdict.ja4.value == LEGACY and alerts.records == []
