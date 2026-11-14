"""Per-agent access rules: first matching rule wins, default is allow."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Optional

from .config import Rule
from .identity import AgentIdentity


@dataclass(frozen=True)
class Decision:
    action: str  # allow | monitor | block
    rule: Optional[Rule] = None


ALLOW_DEFAULT = Decision("allow")


def _path_matches(path: str, patterns: list[str]) -> bool:
    # Note: in glob patterns '*' also matches '/', so '/api/*' covers nested paths.
    return any(fnmatchcase(path, p) for p in patterns)


def evaluate(rules: list[Rule], identity: AgentIdentity, method: str, path: str) -> Decision:
    method = method.upper()
    for rule in rules:
        if "*" not in rule.methods and method not in rule.methods:
            continue
        if not _path_matches(path, rule.paths):
            continue
        if not any(identity.matches(sel) for sel in rule.agents):
            continue
        return Decision(rule.action, rule)
    return ALLOW_DEFAULT
