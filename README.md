# SignalMoat

**An open-source agent firewall and early-warning layer for web apps.**
Know *which* AI agent is calling your app, decide what each one may do, and get
an alert within seconds when someone probes your app, brute-forces logins or
replays a stolen session.

> Status: **alpha (0.3)**. Start in `monitor` mode. APIs may change before 1.0.
> SignalMoat was called **SentryCove** up to version 0.2.1; see the [changelog](https://github.com/XSiddhSaraf/signalmoat/blob/main/CHANGELOG.md) for what to rename.

**New here? Follow the [Getting Started guide](https://github.com/XSiddhSaraf/signalmoat/blob/main/GETTING_STARTED.md)**
— install, write a policy, plug it in, get alerts — for Python, Node, ASP.NET Core or any app via the reverse proxy.

## Why

Bot traffic is no longer "bot vs human". AI agents browse with real browsers
from cloud infrastructure, antidetect browsers replay stolen session cookies,
and User-Agent strings prove nothing. SignalMoat answers three questions on
every request:

1. **Who is this?** A cryptographically verified AI agent (Web Bot Auth / RFC 9421),
   a self-declared bot, a script, or an ordinary browser.
2. **Is it allowed to do this?** Per-agent rules: e.g. verified agents may read
   docs; unverified bots may not submit forms.
3. **Is something attacking us right now?** Honeypot hits, credential stuffing,
   session hijacking, forged agent signatures → alert to Slack, a webhook or your logs.

## Pick your integration

One detection engine, four ways to put it in front of your app:

| Your app | Use | Code change |
|---|---|---|
| Anything (PHP, Java, Go, Ruby, Rails, WordPress, ...) | [Reverse proxy](#reverse-proxy-any-language) (Docker) | none |
| Python: FastAPI, Starlette, any ASGI app | [ASGI middleware](#python-fastapi--starlette--asgi) | one line |
| Node: Express, Next.js, Hono, plain `http` | [`clients/node`](https://github.com/XSiddhSaraf/signalmoat/tree/main/clients/node) | a few lines |
| ASP.NET Core (.NET 8 / 10) | [`clients/dotnet`](https://github.com/XSiddhSaraf/signalmoat/tree/main/clients/dotnet) | a few lines |

All four read the same policy file — copy [`examples/signalmoat.yaml`](https://github.com/XSiddhSaraf/signalmoat/blob/main/examples/signalmoat.yaml)
and adjust the paths.

### Reverse proxy (any language)

```
client ──> your TLS terminator ──> signalmoat proxy ──> your app
```

```bash
docker build -t signalmoat .
docker run -p 8080:8080 --add-host=host.docker.internal:host-gateway \
  -e SIGNALMOAT_UPSTREAM=http://host.docker.internal:3000 \
  -v "$PWD/signalmoat.yaml:/etc/signalmoat/signalmoat.yaml:ro" \
  signalmoat
```

or `docker compose -f deploy/docker-compose.yml up --build` for a complete
example. Without Docker: `pip install ".[server]"` then
`signalmoat proxy --upstream http://127.0.0.1:3000 --config signalmoat.yaml`.

Your app receives two extra headers it can trust (client-sent copies are
removed): `X-SignalMoat-Agent` (e.g. `verified:example-agent`,
`automation:curl`) and `X-SignalMoat-Client-IP`. Make sure the app is only
reachable through the proxy.

### Python (FastAPI / Starlette / ASGI)

```python
from fastapi import FastAPI, Request
from signalmoat import SignalMoat

app = FastAPI()
app.add_middleware(SignalMoat, config="signalmoat.yaml")

@app.get("/")
def home(request: Request):
    return {"caller": request.state.signalmoat.label}   # e.g. "declared:GPTBot"
```

### Node and ASP.NET Core

These use a thin middleware that asks a local SignalMoat service (the
"decision API") for a verdict — about 1 ms per request on localhost in our
measurement:

```bash
export SIGNALMOAT_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
signalmoat sidecar --config signalmoat.yaml      # or deploy/docker-compose.sidecar.yml
```

```js
// Express
import { signalmoat } from "signalmoat/express";
app.use(signalmoat({ url: "http://127.0.0.1:8787", token: process.env.SIGNALMOAT_API_TOKEN }));
```

```csharp
// ASP.NET Core
builder.Services.AddSignalMoat(o => { o.Url = new Uri("http://127.0.0.1:8787"); o.Token = token; });
app.UseSignalMoat();
```

See [`clients/node`](https://github.com/XSiddhSaraf/signalmoat/tree/main/clients/node) (including Next.js) and
[`clients/dotnet`](https://github.com/XSiddhSaraf/signalmoat/tree/main/clients/dotnet) for details.

## What it detects

| Detection | Signal | Default action |
|---|---|---|
| Verified AI agent | Valid Web Bot Auth signature from a trusted signer | Classified `verified`, rules decide |
| Forged / replayed agent signature | Signature fails or nonce reused | **High** alert |
| Bots on sensitive endpoints | Rule match (e.g. unverified bot POSTing a form) | Alert; block in `enforce` |
| Probing / scanning | Request to a honeypot path (`/.env`, `/.git/*`…) | **Critical** alert; IP ban in `enforce` |
| Brute force | N failed logins from one IP in a window | **High** alert |
| Credential stuffing | Site-wide spike of failed logins | **Critical** alert |
| Session hijack | Session cookie reused from a different browser/device | **High** alert |

## Rollout: monitor → enforce

1. Deploy with `mode: monitor`. Nothing is blocked; you only get alerts.
2. Tune rules and honeypot paths until alerts are meaningful.
3. Switch to `mode: enforce`. Blocking applies to `block` rules, honeypots and bans.

By default SignalMoat fails open: a bug or outage in SignalMoat never takes
your app down. Set `fail_open: false` (and `failOpen` / `FailOpen` in the Node
and .NET middleware) if you prefer requests to be refused instead.

## Security design

- **Rules cannot be dodged with path tricks.** Paths are matched in a canonical
  form, so `/LOGIN`, `/login/`, `//login`, `/lo%67in` and `/x/../login` all hit
  a rule on `/login`.
- **No SSRF**: key directories are fetched only from origins you list under
  `web_bot_auth.trusted_agents`, over HTTPS, without redirects, size-capped.
- **Spoof-resistant client IP**: `X-Forwarded-For` is ignored unless you set
  `trusted_proxy_hops`, and then only the proxy-written entry is used. The
  reverse proxy strips forged forwarding and `X-SignalMoat-*` headers.
- **Unknown addresses are never banned**: if the client address cannot be
  determined, IP bans and per-IP counters are skipped rather than applied to
  everyone at once.
- **Decision API is authenticated**: every call needs a bearer token, compared
  in constant time; it binds to localhost by default.
- **Bounded memory**: every tracker is size-capped and expires.
- **Privacy**: session tokens are stored only as truncated SHA-256 hashes; raw
  tokens never appear in alerts. Webhook URLs come from environment variables.
- **Strict config**: unknown keys are rejected so a typo cannot silently
  disable a protection.

## Limitations (honest list)

- State is **per process**. With several workers or hosts, counters and bans
  are not shared (a shared Redis backend is planned). Run one SignalMoat
  process per app for now.
- **Reverse proxy**: no WebSocket support yet (connections are refused), no
  TLS termination (run it behind your load balancer, Caddy or nginx), and it
  is a single Python process — fine for small and medium sites, not a CDN.
- **Next.js / edge runtimes** cannot see the response status, so failed-login
  monitoring needs the Express middleware or the reverse proxy; see
  [`clients/node`](https://github.com/XSiddhSaraf/signalmoat/tree/main/clients/node) for how the client address is determined.
- Session-hijack detection compares User-Agent and Accept-Language, so a
  browser auto-update can cause a false positive. It alerts; it never blocks.
- Web Bot Auth is an IETF **draft**; the verifier implements Ed25519 signatures
  with `@method`, `@authority`, `@scheme`, `@path`, `@query` and header
  components (including `;key=` dictionary members). Key-directory response
  signatures are not yet verified (HTTPS to a trusted origin is relied on).
- Behind a proxy that rewrites `Host`, signatures covering `@authority` will
  fail to verify — preserve the original Host header.

## Roadmap

- Publish to PyPI, npm, NuGet and a container registry
- Shared state via Redis; WebSocket proxying; JA4 TLS fingerprints
- LLM-assisted alert triage: plain-language "what happened, how bad, what to do"
- Optional hosted console: fleet view, shared threat intelligence, team alert routing

## Repository layout

```
src/signalmoat/     engine, ASGI middleware, reverse proxy, decision API, CLI   (Python)
clients/node/       Express middleware and Next.js / fetch guard                (TypeScript)
clients/dotnet/     ASP.NET Core middleware                                     (C#)
deploy/             Docker Compose examples
examples/           example policy and FastAPI app
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests && mypy --ignore-missing-imports src

(cd clients/node && npm ci && npm test)
dotnet run -c Release --project clients/dotnet/tests/SignalMoat.AspNetCore.Tests
```

Releases are described in [RELEASING.md](https://github.com/XSiddhSaraf/signalmoat/blob/main/RELEASING.md).

The Node and .NET suites start the real decision API and run the middleware
against it. The Python suite includes real-socket reverse-proxy tests, an
interoperability test that verifies signatures produced by the independent
`http-message-signatures` library, and the RFC 8037 JWK-thumbprint vector.

## License

Apache-2.0. Contributions require agreeing to the CLA — see
[CONTRIBUTING.md](https://github.com/XSiddhSaraf/signalmoat/blob/main/CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](https://github.com/XSiddhSaraf/signalmoat/blob/main/SECURITY.md).
