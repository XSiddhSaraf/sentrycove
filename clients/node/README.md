<img src="https://raw.githubusercontent.com/XSiddhSaraf/signalmoat/main/assets/signalmoat-icon-256.png" alt="SignalMoat" width="96" height="96" align="right">

# signalmoat (Node.js)

SignalMoat middleware for **Express**, **Next.js** and any Node server.
Know which AI agent is calling your app, decide what each one may do, and get
an alert within seconds when someone probes your app or brute-forces logins.

This package is a thin, dependency-free client. The detection engine runs
next to your app as a small service (the "decision API"), so every language
gets exactly the same behaviour.

> Status: alpha (0.2). Start with `mode: monitor` in your policy.

## 1. Start the decision API

```bash
export SIGNALMOAT_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# with Docker (from the repository root)
docker compose -f deploy/docker-compose.sidecar.yml up --build

# or with Python
pip install "signalmoat[server]"
signalmoat sidecar --config signalmoat.yaml        # listens on 127.0.0.1:8787
```

Keep it on localhost or a private network: it must never be reachable from
the internet.

## 2a. Express (also Connect and plain `node:http`)

```js
import express from "express";
import { signalmoat } from "signalmoat/express";

const app = express();
app.use(signalmoat({ url: "http://127.0.0.1:8787", token: process.env.SIGNALMOAT_API_TOKEN }));

app.get("/", (req, res) => res.json({ caller: req.signalmoat.label })); // e.g. "declared:GPTBot"
```

Register it before your routes and body parsers.

## 2b. Next.js

`proxy.ts` (Next.js 16+) or `middleware.ts` (Next.js 15 and earlier):

```ts
import { NextResponse, type NextRequest } from "next/server";
import { createFetchGuard } from "signalmoat";

const guard = createFetchGuard({
  url: process.env.SIGNALMOAT_URL!,
  token: process.env.SIGNALMOAT_API_TOKEN!,
});

export async function proxy(request: NextRequest) {   // name it `middleware` on Next.js 15
  const { blocked } = await guard(request);
  return blocked ?? NextResponse.next();
}
```

`createFetchGuard` works anywhere the web `Request`/`Response` API exists
(Hono, Bun, Deno, edge runtimes).

Two things to know for Next.js and other web-standard runtimes:

- **Client address.** These runtimes do not expose the connection's address,
  so SignalMoat can only learn it from `X-Forwarded-For`. That header is
  trustworthy only when a proxy you control (nginx, Caddy, a load balancer,
  your hosting platform) writes it — then set `trusted_proxy_hops` in the
  policy to the number of such proxies. If `next start` is exposed directly to
  the internet, leave `trusted_proxy_hops: 0`: clients could otherwise forge
  the header. Rules, honeypot alerts and agent verification work either way;
  only IP bans and per-IP login counting need the address.
- **Failed-login monitoring** needs the final response status, which
  Next.js middleware cannot see. Use the Express middleware or SignalMoat's
  reverse-proxy mode if you need it.

## Options

| Option | Default | Meaning |
|---|---|---|
| `url` | required | Base URL of the decision API |
| `token` | required | The `SIGNALMOAT_API_TOKEN` the decision API was started with |
| `timeoutMs` | `500` | How long to wait for a decision |
| `failOpen` | `true` | If the decision API is down: `true` lets requests through, `false` answers 503 |
| `onError` | throttled `console.warn` | Called when the decision API is unreachable or errors |

## Requirements

Node.js 20.19 or newer. ESM package; `require("signalmoat")` also works on
supported Node versions.

## Development

```bash
pip install -e "../..[server]"   # the tests start the real decision API
npm install
npm test
```

Licensed under Apache-2.0. See the [main repository](https://github.com/XSiddhSaraf/signalmoat).
