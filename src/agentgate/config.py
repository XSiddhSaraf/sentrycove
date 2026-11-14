"""Configuration model, loaded from YAML.

Unknown keys are rejected so that a typo in a policy file fails loudly
at startup instead of silently disabling a protection.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Action = Literal["allow", "monitor", "block"]
Severity = Literal["low", "medium", "high", "critical"]

AGENT_KINDS = ("verified", "declared", "automation", "unclassified")
_SELECTOR_RE = re.compile(r"^(\*|(verified|declared|automation|unclassified)(:[A-Za-z0-9_.\-]+)?)$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TrustedAgent(_Strict):
    """A signer whose key directory we are willing to fetch."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.\-]+$")
    signature_agent: str = Field(description="Origin, e.g. https://agent.example")

    @field_validator("signature_agent")
    @classmethod
    def _https_origin(cls, v: str) -> str:
        v = v.rstrip("/")
        if not re.fullmatch(r"https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?", v):
            raise ValueError("signature_agent must be an https origin with no path")
        return v.lower()


class WebBotAuthConfig(_Strict):
    enabled: bool = True
    trusted_agents: list[TrustedAgent] = Field(default_factory=list)
    max_signature_age_seconds: int = Field(default=300, gt=0)
    max_validity_seconds: int = Field(default=86400, gt=0)
    clock_skew_seconds: int = Field(default=30, ge=0)
    directory_cache_seconds: int = Field(default=3600, gt=0)
    directory_fetch_timeout_seconds: float = Field(default=2.0, gt=0)
    require_nonce: bool = False


class Rule(_Strict):
    name: str
    paths: list[str] = Field(default_factory=lambda: ["*"])
    methods: list[str] = Field(default_factory=lambda: ["*"])
    agents: list[str] = Field(default_factory=lambda: ["*"])
    action: Action
    severity: Severity = "medium"

    @field_validator("methods")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [m.upper() for m in v]

    @field_validator("agents")
    @classmethod
    def _selectors(cls, v: list[str]) -> list[str]:
        for sel in v:
            if not _SELECTOR_RE.match(sel):
                raise ValueError(
                    f"invalid agent selector {sel!r}; use '*', a kind ({', '.join(AGENT_KINDS)}) or 'kind:name'"
                )
        return v


class HoneypotConfig(_Strict):
    enabled: bool = True
    paths: list[str] = Field(default_factory=list)
    ban_seconds: int = Field(default=3600, ge=0)
    response_status: int = Field(default=404, ge=400, le=599)


class LoginConfig(_Strict):
    enabled: bool = True
    paths: list[str] = Field(default_factory=list)
    failure_statuses: list[int] = Field(default_factory=lambda: [401, 403])
    per_ip_threshold: int = Field(default=10, gt=0)
    global_threshold: int = Field(default=200, gt=0)
    window_seconds: int = Field(default=60, gt=0)


class SessionConfig(_Strict):
    enabled: bool = True
    cookie_names: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=86400, gt=0)
    alert_on_ip_change: bool = False


class SinkConfig(_Strict):
    type: Literal["log", "webhook", "slack"]
    url_env: Optional[str] = Field(
        default=None, description="Name of the env var holding the URL (never the URL itself)"
    )
    min_severity: Severity = "medium"

    @model_validator(mode="after")
    def _needs_url(self) -> SinkConfig:
        if self.type in ("webhook", "slack") and not self.url_env:
            raise ValueError(f"{self.type} sink requires url_env")
        return self


class AlertsConfig(_Strict):
    sinks: list[SinkConfig] = Field(default_factory=lambda: [SinkConfig(type="log", min_severity="low")])
    cooldown_seconds: int = Field(default=300, ge=0)
    timeout_seconds: float = Field(default=3.0, gt=0)


class LimitsConfig(_Strict):
    max_tracked_keys: int = Field(default=100_000, gt=0)


class Config(_Strict):
    version: Literal[1] = 1
    mode: Literal["monitor", "enforce"] = "monitor"
    fail_open: bool = True
    trusted_proxy_hops: int = Field(default=0, ge=0, le=10)
    declared_bot_tokens: list[str] = Field(
        default_factory=lambda: [
            "GPTBot",
            "ChatGPT-User",
            "OAI-SearchBot",
            "ClaudeBot",
            "Claude-User",
            "Claude-SearchBot",
            "PerplexityBot",
            "Perplexity-User",
            "Google-Extended",
            "Googlebot",
            "Bingbot",
            "Meta-ExternalAgent",
            "Meta-WebIndexer",
            "Bytespider",
            "CCBot",
            "Amazonbot",
            "Applebot",
        ]
    )
    automation_tokens: list[str] = Field(
        default_factory=lambda: [
            "python-requests",
            "python-httpx",
            "aiohttp",
            "curl/",
            "wget/",
            "go-http-client",
            "okhttp",
            "java/",
            "libwww-perl",
            "scrapy",
            "headlesschrome",
            "phantomjs",
            "puppeteer",
            "playwright",
            "selenium",
        ]
    )
    web_bot_auth: WebBotAuthConfig = Field(default_factory=WebBotAuthConfig)
    rules: list[Rule] = Field(default_factory=list)
    honeypots: HoneypotConfig = Field(default_factory=HoneypotConfig)
    login: LoginConfig = Field(default_factory=LoginConfig)
    session: SessionConfig = Field(default_factory=SessionConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)


def load_config(source: Union[str, Path, dict]) -> Config:
    """Load configuration from a YAML file path or an already-parsed dict."""
    if isinstance(source, dict):
        data = source
    else:
        with open(source, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("configuration root must be a mapping")
    return Config.model_validate(data)
