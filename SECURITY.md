# Security Policy

SentryCove is security software, so vulnerabilities in it matter more than usual.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability
reporting ("Report a vulnerability" under the repository's Security tab).

<!-- TODO(maintainer): add a security contact email before the first release. -->

We aim to acknowledge reports within 3 working days and to ship a fix or
mitigation for confirmed high-severity issues within 30 days, crediting the
reporter unless they prefer otherwise.

## Supported versions

Only the latest released minor version receives security fixes during the
0.x series.

## Project hygiene

- Maintainer and CI tokens are scoped to the minimum needed and rotated;
  access is revoked immediately when someone leaves the project.
- Releases are built and published by CI from tagged commits (see `RELEASING.md`). No registry
  passwords or API tokens are stored: PyPI, npm and NuGet trust the release workflow directly.
- Third-party GitHub Actions are pinned to full commit hashes.
