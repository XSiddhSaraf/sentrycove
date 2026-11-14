# Getting started with SignalMoat

SignalMoat sits in front of your web app or API. It tells you **which AI agent
or bot is calling**, lets you **decide what each one may do**, and **warns you
within seconds** when someone probes your app, brute-forces logins or replays a
stolen session.

Setup takes three steps, whatever your app is written in:

1. [Write a policy file](#step-1-write-a-policy-file)
2. [Plug SignalMoat in](#step-2-plug-signalmoat-in): pick the option that matches your app
3. [Get alerts, then turn on blocking](#step-3-get-alerts-then-turn-on-blocking)

You start in **monitor** mode: nothing is ever blocked, you only get alerts.
Your app keeps working exactly as before while you see what SignalMoat sees.

## Step 1: Write a policy file

Every option reads the same file. Save this as `signalmoat.yaml` and adjust the
paths to match your app:

```yaml
mode: monitor              # alert only; switch to "enforce" to block
rules:
  - name: no-bots-on-forms
    paths: ["/contact", "/login", "/signup"]
    methods: [POST]
    agents: [declared, automation]
    action: block
    severity: high
honeypots:
  paths: ["/.env", "/.git/*", "/wp-login.php"]   # paths your app never serves
login:
  paths: ["/login"]
  per_ip_threshold: 5
alerts:
  sinks:
    - type: log
      min_severity: low
```

What the sections mean:

| Section | What it does |
|---|---|
| `rules` | Who may do what. This one stops bots and scripts from submitting your forms. The first matching rule wins. |
| `honeypots` | Decoy paths no real visitor asks for. A request to one means someone is probing your app. |
| `login` | Raises an alert when one address fails to log in too many times in a minute. |
| `alerts` | Where warnings go. `log` prints them; Slack and webhooks are in [Step 3](#step-3-get-alerts-then-turn-on-blocking). |

Who a rule can match, from most to least trustworthy:

| Agent kind | Meaning |
|---|---|
| `verified` | An AI agent that proved its identity with a cryptographic signature (Web Bot Auth) |
| `declared` | Says it is a known bot, such as `GPTBot` or `ClaudeBot`. A claim, not proof. |
| `automation` | A script or tool: `curl`, `python-requests`, a headless browser |
| `unclassified` | Looks like an ordinary browser |

Target one agent by name with `kind:name`, for example `declared:GPTBot`.
[`examples/signalmoat.yaml`](examples/signalmoat.yaml) has a fuller example.

Check the file before you go live:

```bash
pip install signalmoat
signalmoat check-config signalmoat.yaml
```

## Step 2: Plug SignalMoat in

| Your app | Option | Code change |
|---|---|---|
| Python: FastAPI, Starlette, any ASGI app | [A. Python middleware](#a-python-fastapi-starlette) | one line |
| Anything: PHP, Java, Go, Ruby, WordPress… | [B. Reverse proxy](#b-any-language-no-code-change-reverse-proxy) | none |
| Node: Express, Next.js | [C. Node middleware](#c-node-express-or-nextjs) | a few lines |
| ASP.NET Core (.NET 8 or 10) | [D. ASP.NET Core middleware](#d-aspnet-core) | a few lines |

### A. Python (FastAPI, Starlette)

```bash
pip install signalmoat
```

```python
from fastapi import FastAPI, Request
from signalmoat import SignalMoat

app = FastAPI()
app.add_middleware(SignalMoat, config="signalmoat.yaml")

@app.get("/")
def home(request: Request):
    return {"caller": request.state.signalmoat.label}   # e.g. "declared:GPTBot"
```

That's all. Your handlers can read `request.state.signalmoat` to see who is calling.

### B. Any language, no code change (reverse proxy)

SignalMoat runs as its own small server in front of your app:

```
visitors ──> SignalMoat (port 8080) ──> your app (port 3000)
```

**With Docker:**

```bash
docker run -p 8080:8080 --add-host=host.docker.internal:host-gateway \
  -e SIGNALMOAT_UPSTREAM=http://host.docker.internal:3000 \
  -v "$PWD/signalmoat.yaml:/etc/signalmoat/signalmoat.yaml:ro" \
  ghcr.io/xsiddhsaraf/signalmoat:latest
```

**Without Docker:**

```bash
pip install "signalmoat[server]"
signalmoat proxy --upstream http://127.0.0.1:3000 --config signalmoat.yaml
```

Then:

- Send visitors to SignalMoat's port (8080 above) instead of your app's port,
  usually by pointing your load balancer, Caddy or nginx at it.
- Make sure your app can **only** be reached through SignalMoat; otherwise
  attackers simply go around it.
- SignalMoat does not handle HTTPS itself. Keep your existing HTTPS layer in front of it.
- Your app receives a header `X-SignalMoat-Agent` saying who is calling, and
  `X-SignalMoat-Client-IP` with the visitor's address.

A ready-made example is in [`deploy/docker-compose.yml`](deploy/docker-compose.yml).

### C. Node (Express or Next.js)

The Node and ASP.NET Core packages ask a small local SignalMoat service for a
decision on each request (about 1 ms on the same machine). Start it once, next
to your app:

```bash
pip install "signalmoat[server]"
export SIGNALMOAT_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
signalmoat sidecar --config signalmoat.yaml        # listens on 127.0.0.1:8787
```

Keep this service on the same machine or a private network. Never expose it to
the internet. With Docker, use [`deploy/docker-compose.sidecar.yml`](deploy/docker-compose.sidecar.yml).

**Express:**

```bash
npm install signalmoat
```

```js
import express from "express";
import { signalmoat } from "signalmoat/express";

const app = express();
app.use(signalmoat({ url: "http://127.0.0.1:8787", token: process.env.SIGNALMOAT_API_TOKEN }));

app.get("/", (req, res) => res.json({ caller: req.signalmoat.label }));
```

Add it before your routes.

**Next.js:** create `proxy.ts` (Next.js 16 or newer) or `middleware.ts`
(Next.js 15 or older, where the function is called `middleware`):

```ts
import { NextResponse, type NextRequest } from "next/server";
import { createFetchGuard } from "signalmoat";

const guard = createFetchGuard({
  url: process.env.SIGNALMOAT_URL!,          // e.g. http://127.0.0.1:8787
  token: process.env.SIGNALMOAT_API_TOKEN!,
});

export async function proxy(request: NextRequest) {
  const { blocked } = await guard(request);
  return blocked ?? NextResponse.next();
}
```

Two Next.js notes, explained in the [Node package guide](clients/node#2b-nextjs):
failed-login alerts need the Express middleware or option B, and the visitor's
address comes from your hosting platform's forwarding header.

### D. ASP.NET Core

Start the local SignalMoat service exactly as in [option C](#c-node-express-or-nextjs), then:

```bash
dotnet add package SignalMoat.AspNetCore
```

```csharp
using SignalMoat.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalMoat(options =>
{
    options.Url = new Uri("http://127.0.0.1:8787");
    options.Token = builder.Configuration["SignalMoat:Token"];   // keep it in secrets, not in code
});

var app = builder.Build();
app.UseSignalMoat();   // early: before routing, authentication and your endpoints

app.MapGet("/", (HttpContext context) => $"Hello {context.GetSignalMoatAgent()?.Label}");
app.Run();
```

## Step 3: Get alerts, then turn on blocking

**1. Send alerts where you will see them.** Add Slack (or any webhook) to
`signalmoat.yaml`. The URL is read from an environment variable, so it never
sits in the file:

```yaml
alerts:
  sinks:
    - type: log
      min_severity: low
    - type: slack
      url_env: SIGNALMOAT_SLACK_WEBHOOK      # export SIGNALMOAT_SLACK_WEBHOOK=https://hooks.slack.com/...
      min_severity: high
    - type: webhook
      url_env: SIGNALMOAT_WEBHOOK_URL        # receives each alert as JSON
      min_severity: medium
```

Webhook and Slack URLs must start with `https://`; a sink whose variable is
missing is skipped with a warning at startup. The same alert is sent at most once every five minutes, so an attack does not
flood your channel.

**2. Watch in monitor mode for a few days.** Each alert says what happened and
what SignalMoat *would* have done, for example `would block (monitor mode)`.
Tune your rules and honeypot paths until the alerts are ones you care about.

**3. Turn on blocking.** Change one line and restart:

```yaml
mode: enforce
```

Blocked requests get `403`; honeypot visitors get `404` and their address is
banned for an hour.

## Good to know

- **Behind a load balancer or CDN?** Set `trusted_proxy_hops` in the policy to
  the number of proxies in front of SignalMoat, so it sees the real visitor
  address. Leave it at `0` otherwise; a visitor could fake the address.
- **If SignalMoat itself fails, your app keeps working** (`fail_open: true`, the
  default). Set `fail_open: false` if you would rather refuse requests that
  could not be checked.
- **Health check:** the proxy and the local service answer `GET /_signalmoat/health`.
- **More than one server or worker?** Each keeps its own counters unless you
  share them through Redis: add `state: {backend: redis}` to the policy and
  set `SIGNALMOAT_REDIS_URL` (see the README).
- **WebSockets** going through the reverse proxy or the Python middleware are
  checked when they open, and cut off if their address is banned later.
- **Want alerts explained in plain language?** Turn on `alerts.triage` (see
  the README); it is optional and never blocks anything.

## Help

- What SignalMoat detects and how it is built: [README](README.md)
- Every option for Node and ASP.NET Core: [Node guide](clients/node), [.NET guide](clients/dotnet)
- Questions and bugs: [open an issue](https://github.com/XSiddhSaraf/signalmoat/issues).
  Security problems: see [SECURITY.md](SECURITY.md); please don't report them in public issues.
