<img src="https://raw.githubusercontent.com/XSiddhSaraf/signalmoat/main/assets/signalmoat-icon-256.png" alt="SignalMoat" width="96" height="96" align="right">

# SignalMoat.AspNetCore

SignalMoat middleware for **ASP.NET Core** (.NET 8 and .NET 10).
Know which AI agent is calling your app, decide what each one may do, and get
an alert within seconds when someone probes your app or brute-forces logins.

This package is a thin client with no dependencies beyond ASP.NET Core. The
detection engine runs next to your app as a small service (the "decision
API"), so every language gets exactly the same behaviour.

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

## 2. Add the middleware

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

app.MapGet("/", (HttpContext context) =>
    $"Hello {context.GetSignalMoatAgent()?.Label}");   // e.g. "declared:GPTBot"

app.Run();
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `Url` | required | Base URL of the decision API |
| `Token` | required | The `SIGNALMOAT_API_TOKEN` the decision API was started with |
| `Timeout` | 500 ms | How long to wait for a decision |
| `FailOpen` | `true` | If the decision API is down: `true` lets requests through, `false` answers 503 |

Options are validated when the app starts, so a missing URL or token fails
fast instead of silently disabling protection.

## Behind a load balancer

SignalMoat needs the real client address for IP bans and per-IP login
counting. Pick one:

- Leave ASP.NET Core's forwarded-headers handling off and set
  `trusted_proxy_hops` in the SignalMoat policy to the number of proxies in
  front of your app; or
- call `app.UseForwardedHeaders()` **before** `app.UseSignalMoat()` and keep
  `trusted_proxy_hops: 0`.

Do not do both.

## Development

The test runner starts the real decision API and needs no test-framework
packages:

```bash
pip install -e "../..[server]"
dotnet run -c Release --project tests/SignalMoat.AspNetCore.Tests
```

Licensed under Apache-2.0. See the [main repository](https://github.com/XSiddhSaraf/signalmoat).
