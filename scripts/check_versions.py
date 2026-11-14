"""Check that every package in this repository carries the same version.

    python scripts/check_versions.py            # all four versions must agree
    python scripts/check_versions.py v0.2.0     # ...and must equal this release tag

Exits non-zero (with an explanation) on any mismatch, so a release can never
publish packages whose versions disagree with each other or with the tag.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _match(path: Path, pattern: str) -> str:
    found = re.search(pattern, path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    if not found:
        raise SystemExit(f"could not find a version in {path.relative_to(ROOT)}")
    return found.group(1)


def read_versions() -> dict[str, str]:
    return {
        "pyproject.toml": _match(ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
        "src/signalmoat/__init__.py": _match(ROOT / "src/signalmoat/__init__.py", r'^__version__\s*=\s*"([^"]+)"'),
        "clients/node/package.json": json.loads((ROOT / "clients/node/package.json").read_text(encoding="utf-8"))[
            "version"
        ],
        "clients/dotnet (csproj)": _match(
            ROOT / "clients/dotnet/src/SignalMoat.AspNetCore/SignalMoat.AspNetCore.csproj",
            r"<Version>([^<]+)</Version>",
        ),
    }


def check(tag: str | None = None) -> list[str]:
    """Return a list of problems (empty when everything is consistent)."""
    versions = read_versions()
    problems = []
    distinct = set(versions.values())
    if len(distinct) != 1:
        listing = ", ".join(f"{name}={value}" for name, value in versions.items())
        problems.append(f"versions disagree: {listing}")
    for name, value in versions.items():
        if not _VERSION_RE.match(value):
            problems.append(f"{name}: {value!r} is not a plain X.Y.Z version")
    if tag is not None and len(distinct) == 1:
        expected = "v" + next(iter(distinct))
        if tag != expected:
            problems.append(f"tag {tag!r} does not match the package version (expected {expected!r})")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(__doc__)
        return 2
    problems = check(argv[1] if len(argv) == 2 else None)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if not problems:
        print(f"ok: all packages are at version {next(iter(read_versions().values()))}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
