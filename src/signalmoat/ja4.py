"""JA4 TLS client fingerprints, supplied by the proxy that terminates TLS.

SignalMoat does not terminate TLS, so it cannot compute JA4 itself. The
TLS terminator in front of it (Cloudflare, HAProxy, nginx with a JA4 module,
Caddy, ...) computes the fingerprint and passes it in a request header; this
module reads that header, but only when ``trusted_proxy_hops`` says a proxy
you control sits in front (otherwise any client could send the header).

A JA4 looks like ``t13d1516h2_8daaf6152771_b186095e22b6`` (format a_b_c):

* a: protocol (t=TCP, q=QUIC, d=DTLS), TLS version, SNI (d=domain, i=IP),
  cipher count, extension count, ALPN (first+last character, ``00`` = none)
* b: truncated SHA-256 of the sorted cipher suites
* c: truncated SHA-256 of the sorted extensions and signature algorithms

See https://github.com/FoxIO-LLC/ja4 for the specification.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Optional

_JA4 = re.compile(
    r"^(?P<proto>[tqd])(?P<version>1[0-3]|s[23]|d[123]|00)(?P<sni>[di])"
    r"(?P<ciphers>\d{2})(?P<extensions>\d{2})(?P<alpn>[0-9a-z]{2})"
    r"_[0-9a-f]{12}_[0-9a-f]{12}$"
)
_MAX_HEADER = 256
_BROWSER_MARKERS = ("chrome/", "firefox/", "safari/", "edg/", "opr/")
_LEGACY_VERSIONS = {"10", "11", "s3", "s2", "00"}


@dataclass(frozen=True)
class JA4:
    value: str
    protocol: str
    version: str
    sni: str
    alpn: str

    @property
    def tls_label(self) -> str:
        names = {"13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1", "10": "TLS 1.0", "s3": "SSL 3", "s2": "SSL 2"}
        return names.get(self.version, f"version {self.version}")


def parse(value: str) -> Optional[JA4]:
    """Parse a JA4 string; None if it is not a well-formed JA4."""
    value = value.strip().lower()
    match = _JA4.fullmatch(value)
    if match is None:
        return None
    return JA4(value, match["proto"], match["version"], match["sni"], match["alpn"])


def from_headers(values: list[str]) -> Optional[JA4]:
    """The fingerprint written by the nearest proxy.

    A proxy that *appends* puts its value last, after anything the client sent,
    so the right-most value is the trustworthy one (as with X-Forwarded-For).
    """
    if not values:
        return None
    # Only the right-most value matters, so client-sent padding in front of it
    # (however large) can neither hide it nor cost more than one split.
    last = values[-1].rstrip(" ,").rsplit(",", 1)[-1]
    if not last or len(last) > _MAX_HEADER:
        return None
    return parse(last)


def matches(ja4: Optional[JA4], patterns: list[str]) -> bool:
    """``*`` matches anything, including no fingerprint; other patterns need one."""
    if "*" in patterns:
        return True
    if ja4 is None:
        return False
    return any(fnmatch.fnmatchcase(ja4.value, p.lower()) for p in patterns)


def browser_mismatch(user_agent: str, ja4: JA4) -> Optional[str]:
    """Why a client claiming to be a mainstream browser cannot be one, or None.

    Only checks that current browsers never violate, to keep false positives
    near zero: they always offer ALPN over TCP and never use TLS below 1.2.
    """
    ua = user_agent.lower()
    if not ua.startswith("mozilla/5.0") or not any(m in ua for m in _BROWSER_MARKERS):
        return None
    if ja4.version in _LEGACY_VERSIONS:
        return f"User-Agent claims a modern browser, but the TLS handshake used {ja4.tls_label}"
    if ja4.protocol == "t" and ja4.alpn == "00":
        return "User-Agent claims a browser, but the TLS handshake offered no ALPN (typical of HTTP libraries)"
    return None
