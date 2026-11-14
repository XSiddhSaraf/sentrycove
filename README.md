# AgentGate

**An open-source agent firewall and early-warning layer for web apps.**
Know *which* AI agent is calling your app, decide what each one may do, and get
an alert within seconds when someone probes your app, brute-forces logins or
replays a stolen session — with one line of code.

> Status: **alpha (0.1)**. Start in `monitor` mode. APIs may change before 1.0.

## Why

Bot traffic in 2026 is no longer "bot vs human". AI agents browse with real
browsers from cloud infrastructure, antidetect browsers replay stolen session
cookies, and User-Agent strings prove nothing. AgentGate answers three
questions on every request:

1. **Who is this?** Cryptographically verified AI agent (Web Bot Auth / RFC 9421),
   a self-declared bot, a script, or an ordinary browser.
2. **Is it allowed to do this?** Per-agent rules: e.g. verified agents may read
   docs; unverified bots may not submit forms.
3. **Is something attacking us right now?** Honeypot hits, credential stuffing,
   session hijacking, forged agent signatures → alert to Slack/webhook/logs.

## Quick start (FastAPI / Starlette / any ASGI app)

```bash
pip install agentgate            # from source for now: pip install -e .
```

```python
from fastapi import FastAPI
from agentgate import AgentGate

app = FastAPI()
app.add_middleware(AgentGate, config="agentgate.yaml")
```

Copy [`examples/agentgate.yaml`](examples/agentgate.yaml), adjust the paths,
and run. Your handlers can read the caller's classification:

```python
@app.get("/")
def home(request: Request):
    return {"caller": request.state.agentgate.label}   # e.g. "verified:example-agent"
```

## What it detects (v0.1)

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

`fail_open: true` (default) means a bug in AgentGate never takes your app down.

## Security design

- **No SSRF**: key directories are fetched only from origins you list under
  `web_bot_auth.trusted_agents`, over HTTPS, without redirects, size-capped.
- **Spoof-resistant client IP**: `X-Forwarded-For` is ignored unless you set
  `trusted_proxy_hops`, and then only the proxy-written entry is used.
- **Bounded memory**: every tracker is size-capped and expires.
- **Privacy**: session tokens are stored only as truncated SHA-256 hashes; raw
  tokens never appear in alerts. Webhook URLs come from environment variables.
- **Strict config**: unknown keys are rejected so a typo cannot silently
  disable a protection.

## Limitations (honest list)

- State is **per process**. With several workers/hosts, counters are not shared
  (shared Redis backend is planned).
- Session-hijack detection compares User-Agent and Accept-Language, so a
  browser auto-update can cause a false positive. It alerts; it never blocks.
- Web Bot Auth is an IETF **draft**; the verifier implements Ed25519 signatures
  with `@method`, `@authority`, `@scheme`, `@path`, `@query` and header
  components (including `;key=` dictionary members). Key-directory response
  signatures are not yet verified (HTTPS to a trusted origin is relied on).
- Behind a proxy that rewrites `Host`, signatures covering `@authority` will
  fail to verify — preserve the original Host header.

## Roadmap

- Shared state via Redis; reverse-proxy mode (Envoy/nginx) with JA4 TLS fingerprints
- ASP.NET Core and Express/Next.js middleware ports
- LLM-assisted alert triage: plain-language "what happened, how bad, what to do"
- Optional hosted console: fleet view, shared threat intelligence, team alert routing

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests && mypy --ignore-missing-imports src
```

The test suite includes an interoperability test that verifies signatures
produced by the independent `http-message-signatures` library, and the
RFC 8037 JWK-thumbprint test vector.

## License

Apache-2.0. Contributions require agreeing to the CLA — see
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).
