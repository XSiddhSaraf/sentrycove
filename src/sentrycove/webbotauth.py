"""Web Bot Auth verification (HTTP Message Signatures, RFC 9421, Ed25519).

An AI agent signs each request with a private key and publishes the
public keys at ``<origin>/.well-known/http-message-signatures-directory``.
We verify the signature and, if it checks out, know *which* agent sent the
request -- something a User-Agent string can never prove.

Security choices:
* Key directories are fetched only for origins listed in
  ``web_bot_auth.trusted_agents`` (prevents SSRF via the Signature-Agent
  header) and only over HTTPS, without following redirects.
* Signatures must carry ``tag="web-bot-auth"``, ``created``, ``expires`` and
  ``keyid``, and must cover ``@authority``.
* Anything unsupported or malformed results in "not verified", never in a
  best-effort guess.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Optional, Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import WebBotAuthConfig
from .sfv import InnerList, Item, SFVError, parse_dictionary, serialize_inner_list, serialize_item
from .store import TTLCache

log = logging.getLogger("sentrycove.webbotauth")

DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
WEB_BOT_AUTH_TAG = "web-bot-auth"
MAX_SIGNATURES_PER_REQUEST = 5
MAX_DIRECTORY_BYTES = 64 * 1024
NEGATIVE_CACHE_SECONDS = 60.0

SUPPORTED_DERIVED = {"@method", "@authority", "@scheme", "@path", "@query"}


# -- request abstraction ---------------------------------------------------


class SignedMessage(Protocol):
    method: str
    scheme: str
    authority: str
    path: str
    query: str

    def header_values(self, name: str) -> list[str]:
        """All values of a header (lower-case name), in order received."""
        ...


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    reason: str
    agent_name: Optional[str] = None
    signature_agent: Optional[str] = None
    keyid: Optional[str] = None


# -- helpers ----------------------------------------------------------------


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256) for an OKP key."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url_encode(hashlib.sha256(canonical.encode("utf-8")).digest())


def normalize_origin(url: str) -> Optional[str]:
    """Return ``https://host[:port]`` (lower-case) or None if not an https URL."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not parts.hostname:
        return None
    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError:
        return None
    if port and port != 443:
        return f"https://{host}:{port}"
    return f"https://{host}"


def normalize_authority(host_header: str, scheme: str) -> str:
    """RFC 9421 @authority: lower-case host, default port removed."""
    authority = host_header.strip().lower()
    default = ":443" if scheme == "https" else ":80"
    if authority.endswith(default):
        authority = authority[: -len(default)]
    return authority


# -- key directory -----------------------------------------------------------

Fetcher = Callable[[str, float], Awaitable[tuple[int, bytes]]]


async def _httpx_fetch(url: str, timeout: float) -> tuple[int, bytes]:
    import httpx  # imported lazily so the dependency is only needed when used

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        accept = "application/http-message-signatures-directory+json, application/json"
        async with client.stream("GET", url, headers={"Accept": accept}) as resp:
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_DIRECTORY_BYTES:
                    raise ValueError("key directory too large")
            return resp.status_code, bytes(body)


class KeyDirectory:
    """Fetches and caches signer key directories for trusted origins only."""

    def __init__(
        self,
        cfg: WebBotAuthConfig,
        fetcher: Fetcher = _httpx_fetch,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cfg = cfg
        self._fetch = fetcher
        self._clock = clock
        self._trusted = {a.signature_agent: a.name for a in cfg.trusted_agents}
        self._cache: TTLCache[str, dict[str, Ed25519PublicKey]] = TTLCache(
            max_items=max(1, len(self._trusted)),
            ttl_seconds=cfg.directory_cache_seconds,
        )
        self._locks: dict[str, asyncio.Lock] = {o: asyncio.Lock() for o in self._trusted}

    def trusted_name(self, origin: str) -> Optional[str]:
        return self._trusted.get(origin)

    @property
    def trusted_origins(self) -> list[str]:
        return list(self._trusted)

    async def keys_for(self, origin: str) -> dict[str, Ed25519PublicKey]:
        if origin not in self._trusted:
            return {}
        cached = self._cache.get(origin)
        if cached is not None:
            return cached
        async with self._locks[origin]:
            cached = self._cache.get(origin)
            if cached is not None:
                return cached
            keys = await self._load(origin)
            ttl = None if keys else NEGATIVE_CACHE_SECONDS
            self._cache.set(origin, keys, ttl_seconds=ttl)
            return keys

    async def _load(self, origin: str) -> dict[str, Ed25519PublicKey]:
        url = origin + DIRECTORY_PATH
        try:
            status, body = await self._fetch(url, self._cfg.directory_fetch_timeout_seconds)
        except Exception as exc:  # network errors must never break requests
            log.warning("key directory fetch failed for %s: %s", origin, exc)
            return {}
        if status != 200 or len(body) > MAX_DIRECTORY_BYTES:
            log.warning("key directory %s returned status %s", url, status)
            return {}
        try:
            doc = json.loads(body)
        except ValueError:
            log.warning("key directory %s is not valid JSON", url)
            return {}
        return self._parse_keys(doc)

    def _parse_keys(self, doc: object) -> dict[str, Ed25519PublicKey]:
        keys: dict[str, Ed25519PublicKey] = {}
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            return keys
        now = self._clock()
        for jwk in doc["keys"]:
            if not isinstance(jwk, dict):
                continue
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
                continue
            nbf, exp = jwk.get("nbf"), jwk.get("exp")
            if isinstance(nbf, (int, float)) and now < nbf:
                continue
            if isinstance(exp, (int, float)) and now >= exp:
                continue
            try:
                raw = b64url_decode(jwk["x"])
                if len(raw) != 32:
                    continue
                keys[jwk_thumbprint(jwk)] = Ed25519PublicKey.from_public_bytes(raw)
            except (ValueError, KeyError):
                continue
        return keys


# -- verifier ----------------------------------------------------------------


class _Unsupported(Exception):
    pass


class WebBotAuthVerifier:
    def __init__(
        self,
        cfg: WebBotAuthConfig,
        directory: KeyDirectory,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cfg = cfg
        self._dir = directory
        self._clock = clock
        nonce_ttl = cfg.max_signature_age_seconds + cfg.clock_skew_seconds
        self._nonces: TTLCache[tuple[str, str], bool] = TTLCache(100_000, nonce_ttl)

    async def verify(self, msg: SignedMessage) -> VerificationResult:
        sig_input_raw = ", ".join(msg.header_values("signature-input"))
        sig_raw = ", ".join(msg.header_values("signature"))
        if not sig_input_raw or not sig_raw:
            return VerificationResult(False, "no signature")
        try:
            sig_inputs = parse_dictionary(sig_input_raw)
            signatures = parse_dictionary(sig_raw)
        except SFVError as exc:
            return VerificationResult(False, f"malformed signature headers: {exc}")

        last_reason = "no web-bot-auth signature"
        candidates = [
            (label, member)
            for label, member in sig_inputs.items()
            if isinstance(member, InnerList) and member.params.get("tag") == WEB_BOT_AUTH_TAG
        ][:MAX_SIGNATURES_PER_REQUEST]
        for label, params in candidates:
            sig_item = signatures.get(label)
            if not isinstance(sig_item, Item) or not isinstance(sig_item.value, bytes):
                last_reason = f"signature {label!r} missing or not a byte sequence"
                continue
            result = await self._verify_one(msg, label, params, sig_item.value)
            if result.verified:
                return result
            last_reason = result.reason
        return VerificationResult(False, last_reason)

    async def _verify_one(
        self, msg: SignedMessage, label: str, params: InnerList, signature: bytes
    ) -> VerificationResult:
        p = params.params
        keyid, alg = p.get("keyid"), p.get("alg")
        created, expires, nonce = p.get("created"), p.get("expires"), p.get("nonce")

        if not isinstance(keyid, str):
            return VerificationResult(False, "keyid missing")
        if alg is not None and alg != "ed25519":
            return VerificationResult(False, f"unsupported alg {alg!r}")
        if isinstance(created, bool) or not isinstance(created, int):
            return VerificationResult(False, "created missing")
        if isinstance(expires, bool) or not isinstance(expires, int):
            return VerificationResult(False, "expires missing")

        now = self._clock()
        skew = self._cfg.clock_skew_seconds
        if created > now + skew:
            return VerificationResult(False, "created is in the future")
        if now - created > self._cfg.max_signature_age_seconds:
            return VerificationResult(False, "signature too old")
        if expires <= now - skew:
            return VerificationResult(False, "signature expired")
        if expires - created > self._cfg.max_validity_seconds:
            return VerificationResult(False, "validity window too long")
        if self._cfg.require_nonce and not isinstance(nonce, str):
            return VerificationResult(False, "nonce required")

        names = [i.value for i in params.items]
        if "@authority" not in names:
            return VerificationResult(False, "@authority not covered")
        serialized = [serialize_item(i) for i in params.items]
        if len(set(serialized)) != len(serialized):
            return VerificationResult(False, "duplicate covered component")

        # Which signer? Prefer the Signature-Agent header; otherwise try every
        # trusted origin (bounded by configuration).
        origins = self._signer_origins(msg, label)
        if origins is None:
            return VerificationResult(False, "signature-agent not a trusted https origin")

        try:
            base = self._signature_base(msg, params)
        except _Unsupported as exc:
            return VerificationResult(False, f"unsupported: {exc}")
        except (SFVError, KeyError) as exc:
            return VerificationResult(False, f"cannot build signature base: {exc}")

        for origin in origins:
            key = (await self._dir.keys_for(origin)).get(keyid)
            if key is None:
                continue
            try:
                key.verify(signature, base.encode("ascii"))
            except InvalidSignature:
                return VerificationResult(False, "bad signature", signature_agent=origin, keyid=keyid)
            if isinstance(nonce, str):
                nonce_key = (origin, nonce)
                if nonce_key in self._nonces:
                    return VerificationResult(False, "replayed nonce", signature_agent=origin, keyid=keyid)
                self._nonces.set(nonce_key, True)
            return VerificationResult(
                True,
                "ok",
                agent_name=self._dir.trusted_name(origin),
                signature_agent=origin,
                keyid=keyid,
            )
        return VerificationResult(False, "unknown keyid", keyid=keyid)

    def _signer_origins(self, msg: SignedMessage, label: str) -> Optional[list[str]]:
        raw = ", ".join(msg.header_values("signature-agent")).strip()
        if not raw:
            return self._dir.trusted_origins
        # Older drafts: a bare sf-string. Newer drafts: a dictionary keyed by label.
        try:
            member = parse_dictionary(f"x={raw}" if raw.startswith('"') else raw).get(
                "x" if raw.startswith('"') else label
            )
        except SFVError:
            return None
        url: Optional[str] = None
        if isinstance(member, Item) and type(member.value) is str:
            url = member.value
        origin = normalize_origin(url) if url else None
        if origin is None or self._dir.trusted_name(origin) is None:
            return None
        return [origin]

    def _component_value(self, msg: SignedMessage, item: Item) -> str:
        name = item.value
        if type(name) is not str:  # Tokens/bytes/numbers are not valid identifiers
            raise _Unsupported("component identifier must be a string")
        if name.startswith("@"):
            if item.params:
                raise _Unsupported(f"parameters on {name}")
            if name not in SUPPORTED_DERIVED:
                raise _Unsupported(name)
            if name == "@method":
                return msg.method.upper()
            if name == "@authority":
                return msg.authority
            if name == "@scheme":
                return msg.scheme.lower()
            if name == "@path":
                return msg.path or "/"
            return "?" + msg.query
        if name != name.lower():
            raise _Unsupported("header component names must be lower-case")
        values = msg.header_values(name)
        if not values:
            raise KeyError(f"header {name!r} not present")
        if not item.params:
            return ", ".join(v.strip(" \t") for v in values)
        if set(item.params) == {"key"} and isinstance(item.params["key"], str):
            member = parse_dictionary(", ".join(values)).get(item.params["key"])
            if member is None:
                raise KeyError(f"dictionary member {item.params['key']!r} missing")
            if isinstance(member, InnerList):
                return serialize_inner_list(member)
            return serialize_item(member)
        raise _Unsupported(f"component parameters {sorted(item.params)}")

    def _signature_base(self, msg: SignedMessage, params: InnerList) -> str:
        lines = []
        for item in params.items:
            lines.append(f"{serialize_item(Item(item.value, item.params))}: {self._component_value(msg, item)}")
        lines.append(f'"@signature-params": {serialize_inner_list(params)}')
        return "\n".join(lines)
