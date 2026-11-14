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
    #: JA4 TLS fingerprint patterns (``*`` wildcard), e.g. ``t13d191000_9dc949149365_*``.
    #: Anything other than ``*`` requires the ``ja4`` section to be enabled.
    ja4: list[str] = Field(default_factory=lambda: ["*"])
    action: Action
    severity: Severity = "medium"

    @field_validator("ja4")
    @classmethod
    def _ja4_patterns(cls, v: list[str]) -> list[str]:
        for pattern in v:
            if not re.fullmatch(r"[A-Za-z0-9_*]{1,64}", pattern):
                raise ValueError(f"invalid ja4 pattern {pattern!r}; use letters, digits, '_' and '*'")
        return [p.lower() for p in v]

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


_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


class TriageConfig(_Strict):
    """Optional LLM triage: adds a plain-language note to important alerts."""

    enabled: bool = False
    provider: Literal["anthropic", "openai"] = "anthropic"
    #: Model name, e.g. ``claude-haiku-5-5`` (anthropic) or the model your OpenAI-compatible server serves.
    model: str = Field(default="", max_length=128)
    #: Name of the env var holding the API key (never the key itself). Optional for a local server.
    api_key_env: Optional[str] = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    #: Override the API address, e.g. ``http://127.0.0.1:11434/v1`` for Ollama. https, or http on localhost only.
    base_url: Optional[str] = None
    api_version: str = Field(default="2026-10-21", pattern=r"^\d{4}-\d{2}-\d{2}$")
    min_severity: Severity = "high"
    timeout_seconds: float = Field(default=8.0, gt=0, le=60)
    #: Hard cap on the model's output. On newer Claude models it covers thinking AND the answer,
    #: so it must leave room for both.
    max_tokens: int = Field(default=2048, ge=256, le=16000)
    #: Anthropic only: how hard the model thinks (``output_config.effort``). ``low`` keeps triage
    #: fast and cheap; ``null`` omits it (for older models that do not accept the setting).
    effort: Optional[Literal["low", "medium", "high"]] = "low"
    #: Upper bound on LLM calls per hour (cost cap); alerts beyond it are sent without triage.
    max_per_hour: int = Field(default=60, gt=0, le=10_000)
    #: Send the full client IP to the model. Off: only its network (/24 or /48) is sent.
    include_client_ip: bool = False

    @field_validator("base_url")
    @classmethod
    def _safe_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~\-/]*)?", v):
            raise ValueError("base_url must be a plain http(s) URL without query or credentials")
        if v.startswith("http://"):
            host = v[len("http://") :].split("/", 1)[0]
            host = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]", 1)[0] + "]"
            if host not in _LOCAL_HOSTS:
                raise ValueError("base_url must use https (plain http is allowed only for localhost)")
        return v.rstrip("/")

    @model_validator(mode="after")
    def _complete(self) -> TriageConfig:
        if self.enabled:
            if not self.model:
                raise ValueError("alerts.triage.model is required when triage is enabled")
            if self.provider == "anthropic" and not self.api_key_env:
                raise ValueError("alerts.triage.api_key_env is required for the anthropic provider")
        return self


class AlertsConfig(_Strict):
    sinks: list[SinkConfig] = Field(default_factory=lambda: [SinkConfig(type="log", min_severity="low")])
    cooldown_seconds: int = Field(default=300, ge=0)
    timeout_seconds: float = Field(default=3.0, gt=0)
    triage: TriageConfig = Field(default_factory=TriageConfig)


class JA4Config(_Strict):
    """JA4 TLS fingerprints, read from a header set by your TLS terminator."""

    enabled: bool = False
    #: Header your TLS terminator writes, e.g. ``cf-ja4`` (Cloudflare) or ``x-ja4``.
    header: str = Field(default="cf-ja4", pattern=r"^[A-Za-z0-9\-]{1,64}$")
    #: Alert when the User-Agent claims a browser but the TLS handshake cannot be one.
    alert_on_browser_mismatch: bool = True
    mismatch_severity: Severity = "medium"

    @field_validator("header")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class WebSocketConfig(_Strict):
    """WebSocket connections: the opening handshake is screened like any request."""

    enabled: bool = True
    #: While a connection is open, how often to check whether its IP has been banned
    #: since (0 disables). Only applies in enforce mode.
    ban_recheck_seconds: float = Field(default=15.0, ge=0)
    #: Largest message accepted from the upstream app (reverse proxy only).
    max_message_bytes: int = Field(default=1_048_576, gt=0, le=64 * 1_048_576)


class StateConfig(_Strict):
    """Where counters, bans, nonces and session fingerprints live."""

    backend: Literal["memory", "redis"] = "memory"
    redis_url_env: str = Field(
        default="SIGNALMOAT_REDIS_URL",
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
        description="Name of the env var holding the Redis URL (never the URL itself: it may contain a password)",
    )
    key_prefix: str = Field(default="signalmoat:", pattern=r"^[A-Za-z0-9_.:\-]{1,64}$")
    timeout_seconds: float = Field(default=0.25, gt=0, le=10)


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
    state: StateConfig = Field(default_factory=StateConfig)
    websocket: WebSocketConfig = Field(default_factory=WebSocketConfig)
    ja4: JA4Config = Field(default_factory=JA4Config)

    @model_validator(mode="after")
    def _ja4_needs_trusted_proxy(self) -> Config:
        if self.ja4.enabled and self.trusted_proxy_hops < 1:
            raise ValueError(
                "ja4.enabled needs trusted_proxy_hops >= 1: the fingerprint header is written by your TLS "
                "terminator, and without a trusted proxy in front any client could forge it"
            )
        if not self.ja4.enabled:
            for rule in self.rules:
                if rule.ja4 != ["*"]:
                    raise ValueError(f"rule {rule.name!r} matches on ja4, but the ja4 section is not enabled")
        return self


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
