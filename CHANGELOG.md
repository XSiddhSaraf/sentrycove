# Changelog

All notable changes to SentryCove are recorded here. The Python package, the
Node package, the .NET package and the container image share one version
number and are released together.

## 0.2.1

No changes to how SentryCove behaves. This is the first version published by
the automated release pipeline.

### Added
- Release workflow that publishes to PyPI, npm and NuGet via trusted publishing
  (no stored tokens), builds a multi-arch container image, and creates a GitHub
  release — after checking that all versions match and the full test suite passes.
- `RELEASING.md` with step-by-step setup for each registry.

## 0.2.0

First public release under the name SentryCove (the 0.1 prototype was called AgentGate).

### Added
- **Reverse proxy** (`sentrycove proxy`, container image): protect an app in any
  language with no code change. Streams requests and responses, strips forged
  forwarding headers, and tells the app who is calling via `X-SentryCove-Agent`.
- **Decision API** (`sentrycove sidecar`): token-protected local service that
  lets middleware in other languages use the same engine.
- **Node package**: Express / Connect / `node:http` middleware and a guard for
  Next.js and other web-standard runtimes.
- **ASP.NET Core package** for .NET 8 and .NET 10.
- `sentrycove check-config` to validate a policy file.

### Security
- Rules, honeypots and login paths are matched on a canonical path, so they can
  no longer be dodged with upper-case, percent-encoding, extra slashes or
  dot segments (`/LOGIN`, `/lo%67in`, `//login`, `/x/../login`).
- An undeterminable client address is never banned or rate-counted (a ban
  would otherwise have applied to every such client at once).
- IPv4-mapped IPv6 peers (`::ffff:203.0.113.9`) are treated as the IPv4 address.

### Changed
- Renamed from AgentGate: package `sentrycove`, class `SentryCove`,
  `request.state.sentrycove`, `sentrycove.yaml`, `SENTRYCOVE_*` environment variables.

## 0.1.0

Prototype (unreleased): ASGI middleware with Web Bot Auth verification,
per-agent rules, honeypots, login and session monitoring, and alerts.
