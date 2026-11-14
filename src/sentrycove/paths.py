"""Path normalisation for rule matching.

Rules, honeypots and login paths are matched against a *canonical* form of
the request path so that an attacker cannot dodge a rule on ``/login`` by
requesting ``/lo%67in``, ``//login``, ``/LOGIN``, ``/login/`` or ``/x/../login``
-- all of which some web frameworks route to the same handler.

Canonical form: percent-decoded once, backslashes treated as slashes, empty
and ``.`` segments dropped, ``..`` resolved, no trailing slash, lower-case.
Normalising can only make a security rule match *more* requests, never fewer.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from urllib.parse import unquote


def normalize_decoded_path(path: str) -> str:
    """Canonicalise a path that has already been percent-decoded."""
    segments: list[str] = []
    for segment in path.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return ("/" + "/".join(segments)).lower()


def normalize_match_path(raw_path: str) -> str:
    """Canonicalise a raw (still percent-encoded) request path."""
    return normalize_decoded_path(unquote(raw_path, errors="replace"))


def _normalize_pattern(pattern: str) -> str:
    pattern = pattern.lower()
    if len(pattern) > 1 and pattern.endswith("/"):
        pattern = pattern.rstrip("/") or "/"
    return pattern


def path_matches(normalized_path: str, patterns: list[str]) -> bool:
    """Glob match against a canonical path.

    ``*`` also matches ``/``, so ``/api/*`` covers nested paths; it additionally
    covers the bare prefix ``/api`` (which is what ``/api/`` normalises to).
    """
    for raw_pattern in patterns:
        pattern = _normalize_pattern(raw_pattern)
        if fnmatchcase(normalized_path, pattern):
            return True
        if pattern.endswith("/*") and normalized_path == pattern[:-2]:
            return True
    return False
