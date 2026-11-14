# Changelog

All notable changes to SignalMoat (called SentryCove up to 0.2.1) are recorded here. The Python package, the
Node package, the .NET package and the container image share one version
number and are released together.

## 0.3.2

No changes to how SignalMoat behaves.

### Added
- SignalMoat icon: shown on the PyPI, npm and NuGet package pages, and as the
  NuGet package icon. Icon files are in `assets/`.
- Getting Started guide (`GETTING_STARTED.md`), linked from PyPI as the
  project's documentation.

## 0.3.1

No changes to how SignalMoat behaves. This release moves npm publishing to the
automated release pipeline (trusted publishing), as PyPI and NuGet already are.

## 0.3.0

### Changed (breaking: renamed)
SentryCove is now **SignalMoat**. nuget.org reserves package IDs beginning with
"Sentry" for another publisher, so the .NET package could never be published
under the old name, and the new name also avoids confusion with an existing brand.
Behaviour is unchanged; only names differ:

| Was | Now |
|---|---|
| `pip install sentrycove`, `import sentrycove`, class `SentryCove` | `pip install signalmoat`, `import signalmoat`, class `SignalMoat` |
| `npm install sentrycove`, `sentrycove/express` | `npm install signalmoat`, `signalmoat/express` |
| NuGet `SentryCove.AspNetCore`, `AddSentryCove`, `UseSentryCove`, `GetSentryCoveAgent` | `SignalMoat.AspNetCore`, `AddSignalMoat`, `UseSignalMoat`, `GetSignalMoatAgent` |
| `ghcr.io/xsiddhsaraf/sentrycove` | `ghcr.io/xsiddhsaraf/signalmoat` |
| `sentrycove` command, `sentrycove.yaml` | `signalmoat` command, `signalmoat.yaml` |
| `SENTRYCOVE_*` environment variables | `SIGNALMOAT_*` |
| `X-SentryCove-Agent`, `X-SentryCove-Client-IP` headers | `X-SignalMoat-Agent`, `X-SignalMoat-Client-IP` |
| `/_sentrycove/health`, `request.state.sentrycove`, `req.sentrycove` | `/_signalmoat/health`, `request.state.signalmoat`, `req.signalmoat` |

The old `sentrycove` packages on PyPI and npm (0.2.0, 0.2.1) remain available but
receive no further updates.

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
