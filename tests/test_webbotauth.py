from __future__ import annotations

import asyncio
import datetime
import time

import pytest

from sentrycove.config import WebBotAuthConfig
from sentrycove.engine import RequestInfo
from sentrycove.webbotauth import (
    KeyDirectory,
    WebBotAuthVerifier,
    jwk_thumbprint,
    normalize_authority,
    normalize_origin,
)

from .conftest import AGENT_ORIGIN, FakeFetcher, make_key, sign_headers


def cfg(**overrides) -> WebBotAuthConfig:
    data = {"trusted_agents": [{"name": "test-agent", "signature_agent": AGENT_ORIGIN}]}
    data.update(overrides)
    return WebBotAuthConfig.model_validate(data)


def message(headers: dict[str, str], *, method="GET", path="/", query="", host="testserver", scheme="http"):
    raw = [(b"host", host.encode())] + [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return RequestInfo.from_scope(
        {
            "type": "http",
            "method": method,
            "scheme": scheme,
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "headers": raw,
        }
    )


def verifier(fetcher, **overrides) -> WebBotAuthVerifier:
    c = cfg(**overrides)
    return WebBotAuthVerifier(c, KeyDirectory(c, fetcher=fetcher))


def run(coro):
    return asyncio.run(coro)


def test_rfc8037_thumbprint_vector():
    # RFC 8037 Appendix A.3
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_valid_signature_is_verified(signing_key, fetcher):
    result = run(verifier(fetcher).verify(message(sign_headers(signing_key))))
    assert result.verified, result.reason
    assert result.agent_name == "test-agent"
    assert result.signature_agent == AGENT_ORIGIN


def test_interop_with_independent_library(signing_key, fetcher):
    """A signature produced by the http-message-signatures library must verify."""
    hms = pytest.importorskip("http_message_signatures")
    from http_message_signatures.resolvers import HTTPSignatureKeyResolver

    class Resolver(HTTPSignatureKeyResolver):
        def resolve_private_key(self, key_id):
            return signing_key.private

        def resolve_public_key(self, key_id):
            return signing_key.private.public_key()

    class Headers(dict):
        def _find(self, key):
            return next((k for k in self if k.lower() == key.lower()), None)

        def get(self, key, default=None):
            k = self._find(key)
            return default if k is None else dict.__getitem__(self, k)

        def __contains__(self, key):
            return self._find(key) is not None

        def __getitem__(self, key):
            k = self._find(key)
            if k is None:
                raise KeyError(key)
            return dict.__getitem__(self, k)

    class Msg:
        method = "POST"
        url = "https://shop.example/api/orders?id=7"
        headers = Headers({"Signature-Agent": f'"{AGENT_ORIGIN}"'})

    now = datetime.datetime.now(datetime.timezone.utc)
    signer = hms.HTTPMessageSigner(signature_algorithm=hms.algorithms.ED25519, key_resolver=Resolver())
    signer.sign(
        Msg,
        key_id=signing_key.keyid,
        created=now,
        expires=now + datetime.timedelta(minutes=5),
        nonce="abc123",
        label="sig1",
        tag="web-bot-auth",
        covered_component_ids=("@authority", "signature-agent", "@method", "@path", "@query"),
    )
    msg = message(
        dict(Msg.headers), method="POST", path="/api/orders", query="id=7", host="shop.example", scheme="https"
    )
    result = run(verifier(fetcher).verify(msg))
    assert result.verified, result.reason


def test_tampered_request_fails(signing_key, fetcher):
    headers = sign_headers(signing_key, authority="testserver")
    result = run(verifier(fetcher).verify(message(headers, host="evil.example")))
    assert not result.verified and result.reason == "bad signature"


def test_expired_signature_rejected(signing_key, fetcher):
    created = int(time.time()) - 200
    headers = sign_headers(signing_key, created=created, expires=created + 60)
    assert run(verifier(fetcher).verify(message(headers))).reason == "signature expired"


def test_old_signature_rejected(signing_key, fetcher):
    created = int(time.time()) - 1000
    headers = sign_headers(signing_key, created=created, expires=created + 5000)
    assert run(verifier(fetcher).verify(message(headers))).reason == "signature too old"


def test_future_signature_rejected(signing_key, fetcher):
    headers = sign_headers(signing_key, created=int(time.time()) + 3600)
    assert run(verifier(fetcher).verify(message(headers))).reason == "created is in the future"


def test_untrusted_signer_is_not_fetched(signing_key, fetcher):
    headers = sign_headers(signing_key, signature_agent='"https://attacker.example"')
    result = run(verifier(fetcher).verify(message(headers)))
    assert not result.verified
    assert fetcher.calls == []  # no SSRF: untrusted origins are never contacted


def test_non_https_signature_agent_rejected(signing_key, fetcher):
    headers = sign_headers(signing_key, signature_agent='"http://agent.example"')
    assert not run(verifier(fetcher).verify(message(headers))).verified


def test_unknown_keyid(fetcher):
    other = make_key()
    result = run(verifier(fetcher).verify(message(sign_headers(other))))
    assert result.reason == "unknown keyid"


def test_replayed_nonce_rejected(signing_key, fetcher):
    v = verifier(fetcher)
    headers = sign_headers(signing_key, nonce="once")

    async def twice():
        return await v.verify(message(headers)), await v.verify(message(headers))

    first, second = run(twice())
    assert first.verified and second.reason == "replayed nonce"


def test_nonce_required_when_configured(signing_key, fetcher):
    result = run(verifier(fetcher, require_nonce=True).verify(message(sign_headers(signing_key))))
    assert result.reason == "nonce required"


def test_authority_must_be_covered(signing_key, fetcher):
    headers = sign_headers(signing_key, components=("@method", "signature-agent"))
    assert run(verifier(fetcher).verify(message(headers))).reason == "@authority not covered"


def test_other_tags_are_ignored(signing_key, fetcher):
    headers = sign_headers(signing_key, tag="something-else")
    assert not run(verifier(fetcher).verify(message(headers))).verified


def test_dictionary_form_signature_agent(signing_key, fetcher):
    """Newer drafts send Signature-Agent as a dictionary keyed by signature label."""
    sa = f'sig1="{AGENT_ORIGIN}"'
    created = int(time.time())
    base_params = (
        f'("@authority" "signature-agent";key="sig1");created={created};'
        f'keyid="{signing_key.keyid}";alg="ed25519";expires={created + 300};tag="web-bot-auth"'
    )
    base = "\n".join(
        [
            '"@authority": testserver',
            f'"signature-agent";key="sig1": "{AGENT_ORIGIN}"',
            f'"@signature-params": {base_params}',
        ]
    )
    import base64

    sig = base64.b64encode(signing_key.private.sign(base.encode())).decode()
    headers = {"Signature-Agent": sa, "Signature-Input": f"sig1={base_params}", "Signature": f"sig1=:{sig}:"}
    result = run(verifier(fetcher).verify(message(headers)))
    assert result.verified, result.reason


def test_directory_fetch_failure_is_negative_cached(signing_key):
    failing = FakeFetcher({}, fail=True)
    v = verifier(failing)

    async def go():
        await v.verify(message(sign_headers(signing_key)))
        await v.verify(message(sign_headers(signing_key)))

    run(go())
    assert len(failing.calls) == 1


def test_directory_ignores_expired_and_non_ed25519_keys(signing_key):
    expired = dict(make_key().jwk, exp=1)
    rsa_like = {"kty": "RSA", "n": "x", "e": "AQAB"}
    fetcher = FakeFetcher({AGENT_ORIGIN: [expired, rsa_like, signing_key.jwk]})
    c = cfg()
    keys = run(KeyDirectory(c, fetcher=fetcher).keys_for(AGENT_ORIGIN))
    assert list(keys) == [signing_key.keyid]


def test_normalizers():
    assert normalize_origin("https://Agent.Example:443/path") == "https://agent.example"
    assert normalize_origin("https://agent.example:8443") == "https://agent.example:8443"
    assert normalize_origin("http://agent.example") is None
    assert normalize_authority("Example.COM:443", "https") == "example.com"
    assert normalize_authority("example.com:8080", "http") == "example.com:8080"
