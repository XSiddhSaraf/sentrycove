from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sentrycove.alerts import Alert, AlertDispatcher
from sentrycove.webbotauth import jwk_thumbprint

AGENT_ORIGIN = "https://agent.example"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class SigningKey:
    private: Ed25519PrivateKey
    jwk: dict
    keyid: str


def make_key() -> SigningKey:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
    return SigningKey(private, jwk, jwk_thumbprint(jwk))


@dataclass
class FakeFetcher:
    """Serves key directories from memory and records fetched URLs."""

    directories: dict[str, list[dict]] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    fail: bool = False

    async def __call__(self, url: str, timeout: float) -> tuple[int, bytes]:
        self.calls.append(url)
        if self.fail:
            raise ConnectionError("network down")
        for origin, keys in self.directories.items():
            if url == origin + "/.well-known/http-message-signatures-directory":
                return 200, json.dumps({"keys": keys}).encode()
        return 404, b""


def sign_headers(
    key: SigningKey,
    *,
    authority: str = "testserver",
    method: str = "GET",
    path: str = "/",
    components: tuple[str, ...] = ("@authority", "signature-agent"),
    signature_agent: Optional[str] = f'"{AGENT_ORIGIN}"',
    created: Optional[int] = None,
    expires: Optional[int] = None,
    nonce: Optional[str] = None,
    tag: str = "web-bot-auth",
    label: str = "sig1",
    keyid: Optional[str] = None,
) -> dict[str, str]:
    """Independent minimal RFC 9421 signer used to build test requests."""
    created = int(time.time()) if created is None else created
    expires = created + 300 if expires is None else expires
    headers: dict[str, str] = {}
    if signature_agent is not None:
        headers["Signature-Agent"] = signature_agent
    values = {
        "@authority": authority,
        "@method": method,
        "@path": path,
        "signature-agent": signature_agent or "",
    }
    comp = " ".join(f'"{c}"' for c in components)
    params = f';created={created};keyid="{keyid or key.keyid}";alg="ed25519";expires={expires}'
    if nonce:
        params += f';nonce="{nonce}"'
    params += f';tag="{tag}"'
    sig_params = f"({comp}){params}"
    base = "\n".join([f'"{c}": {values[c]}' for c in components] + [f'"@signature-params": {sig_params}'])
    sig = key.private.sign(base.encode())
    headers["Signature-Input"] = f"{label}={sig_params}"
    headers["Signature"] = f"{label}=:{base64.b64encode(sig).decode()}:"
    return headers


class RecordingDispatcher(AlertDispatcher):
    """Records alerts synchronously (after de-duplication) instead of delivering."""

    def __init__(self, cooldown_seconds: float = 0) -> None:
        super().__init__([], cooldown_seconds)
        self.records: list[Alert] = []

    def emit(self, alert: Alert) -> bool:
        accepted = super().emit(alert)
        if accepted:
            self.records.append(alert)
        return accepted

    def types(self) -> list[str]:
        return [a.type for a in self.records]


@pytest.fixture
def signing_key() -> SigningKey:
    return make_key()


@pytest.fixture
def fetcher(signing_key: SigningKey) -> FakeFetcher:
    return FakeFetcher({AGENT_ORIGIN: [signing_key.jwk]})
