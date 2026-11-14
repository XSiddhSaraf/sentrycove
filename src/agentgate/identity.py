"""Classify who is making a request.

Kinds, from most to least trustworthy:

* ``verified``     -- valid Web Bot Auth signature from a trusted signer.
* ``declared``     -- User-Agent names a known AI agent or crawler. Spoofable,
                      so treat it as a claim, never as proof.
* ``automation``   -- User-Agent reveals an HTTP library or headless browser.
* ``unclassified`` -- looks like an ordinary browser (may still be a bot).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from .webbotauth import VerificationResult

AgentKind = Literal["verified", "declared", "automation", "unclassified"]


@dataclass(frozen=True)
class AgentIdentity:
    kind: AgentKind
    name: Optional[str] = None
    detail: str = ""

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}" if self.name else self.kind

    def matches(self, selector: str) -> bool:
        """``*``, a bare kind (``declared``) or ``kind:name`` (case-insensitive name)."""
        if selector == "*":
            return True
        kind, _, name = selector.partition(":")
        if kind != self.kind:
            return False
        return not name or (self.name is not None and name.lower() == self.name.lower())


def classify(
    user_agent: str,
    verification: Optional[VerificationResult],
    declared_tokens: list[str],
    automation_tokens: list[str],
) -> AgentIdentity:
    if verification is not None and verification.verified:
        return AgentIdentity("verified", verification.agent_name, verification.signature_agent or "")

    ua = user_agent.lower()
    for token in declared_tokens:
        if token.lower() in ua:
            detail = ""
            if verification is not None and verification.reason not in ("no signature",):
                detail = f"signature rejected: {verification.reason}"
            return AgentIdentity("declared", token, detail)

    if not ua.strip():
        return AgentIdentity("automation", None, "empty user-agent")
    for token in automation_tokens:
        if token.lower() in ua:
            return AgentIdentity("automation", token.rstrip("/"), "")
    return AgentIdentity("unclassified")
