"""Per-agent access rules: first matching rule wins, default is allow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .config import Rule
from .identity import AgentIdentity
from .ja4 import JA4
from .ja4 import matches as ja4_matches
from .paths import path_matches


@dataclass(frozen=True)
class Decision:
    action: str  # allow | monitor | block
    rule: Optional[Rule] = None


ALLOW_DEFAULT = Decision("allow")


def evaluate(rules: list[Rule], identity: AgentIdentity, method: str, path: str, ja4: Optional[JA4] = None) -> Decision:
    """``path`` must be canonical (see :func:`signalmoat.paths.normalize_match_path`)."""
    method = method.upper()
    for rule in rules:
        if "*" not in rule.methods and method not in rule.methods:
            continue
        if not path_matches(path, rule.paths):
            continue
        if not any(identity.matches(sel) for sel in rule.agents):
            continue
        if not ja4_matches(ja4, rule.ja4):
            continue
        return Decision(rule.action, rule)
    return ALLOW_DEFAULT
