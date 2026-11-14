import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { createRequire } from "node:module";
import { after, before, describe, test } from "node:test";

import express from "express";

import { SignalMoatClient, createFetchGuard } from "../dist/index.js";
import { signalmoat } from "../dist/express.js";
import { BROWSER_UA, TOKEN, freePort, listen, startSidecar } from "./helpers.mjs";

let sidecar;
const servers = [];

before(async () => {
  sidecar = await startSidecar();
});

after(async () => {
  await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
  await sidecar.stop();
});

async function serve(handler) {
  const server = createServer(handler);
  servers.push(server);
  server.on("connection", (socket) => socket.unref());
  return listen(server);
}

function expressApp(options = {}) {
  const app = express();
  app.use(signalmoat({ url: sidecar.url, token: TOKEN, ...options }));
  app.get("/", (req, res) => res.json({ caller: req.signalmoat.label }));
  app.post("/contact", (req, res) => res.json({ received: true }));
  app.post("/login", (req, res) => res.status(401).json({ error: "bad credentials" }));
  app.get("/.env", (req, res) => res.send("SECRET=should-never-be-served"));
  return app;
}

describe("Express middleware against the real decision API", () => {
  test("browsers pass and handlers can see who is calling", async () => {
    const base = await serve(expressApp());
    const r = await fetch(`${base}/`, { headers: { "user-agent": BROWSER_UA } });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { caller: "unclassified" });

    const bot = await fetch(`${base}/`, { headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)" } });
    assert.deepEqual(await bot.json(), { caller: "declared:GPTBot" });
  });

  test("rule and honeypot blocks stop the request before the route runs", async () => {
    const base = await serve(expressApp());
    const script = { "user-agent": "python-requests/2.32", "content-type": "application/json" };

    const blocked = await fetch(`${base}/contact`, { method: "POST", headers: script, body: "{}" });
    assert.equal(blocked.status, 403);
    assert.deepEqual(await blocked.json(), { error: "request blocked" });
    assert.equal(blocked.headers.get("cache-control"), "no-store");

    // Express routes /CONTACT and /contact/ to the same handler; so must the rule.
    for (const path of ["/CONTACT", "/contact/", "/c%6fntact"]) {
      const r = await fetch(`${base}${path}`, { method: "POST", headers: script, body: "{}" });
      assert.equal(r.status, 403, path);
    }

    const human = await fetch(`${base}/contact`, { method: "POST", headers: { "user-agent": BROWSER_UA } });
    assert.deepEqual(await human.json(), { received: true });

    const trap = await fetch(`${base}/.env`, { headers: { "user-agent": BROWSER_UA } });
    assert.equal(trap.status, 404);
    assert.ok(!(await trap.text()).includes("SECRET"));
    await sidecar.waitForLog('"type": "honeypot_hit"');
  });

  test("absolute-form request targets are judged by the path inside them", async () => {
    const base = await serve(expressApp());
    const { hostname, port } = new URL(base);
    const status = await new Promise((resolve, reject) => {
      const req = httpRequest(
        { hostname, port, method: "GET", path: `http://${hostname}:${port}/.env`, headers: { "user-agent": BROWSER_UA } },
        (res) => {
          res.resume();
          resolve(res.statusCode);
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(status, 404);
  });

  test("failed logins are reported and raise a brute-force alert", async () => {
    const base = await serve(expressApp());
    for (let i = 0; i < 3; i++) {
      const r = await fetch(`${base}/login`, { method: "POST", headers: { "user-agent": BROWSER_UA } });
      assert.equal(r.status, 401);
    }
    await sidecar.waitForLog('"type": "login_bruteforce"');
  });

  test("works as plain node:http middleware without Express", async () => {
    const guard = signalmoat({ url: sidecar.url, token: TOKEN });
    const base = await serve((req, res) =>
      guard(req, res, (error) => {
        if (error) {
          res.statusCode = 500;
          res.end();
          return;
        }
        res.end(`hello ${req.signalmoat.label}`);
      }),
    );
    const ok = await fetch(`${base}/anything`, { headers: { "user-agent": BROWSER_UA } });
    assert.equal(await ok.text(), "hello unclassified");
    const blocked = await fetch(`${base}/contact`, { method: "POST", headers: { "user-agent": "curl/8.9" } });
    assert.equal(blocked.status, 403);
  });
});

describe("when the decision API is unavailable", () => {
  test("fail-open lets requests through and reports the error", async () => {
    const errors = [];
    const deadUrl = `http://127.0.0.1:${await freePort()}`;
    const base = await serve(expressApp({ url: deadUrl, onError: (e) => errors.push(e) }));
    const r = await fetch(`${base}/contact`, { method: "POST", headers: { "user-agent": "curl/8.9" } });
    assert.equal(r.status, 200);
    assert.equal(errors.length, 1);
  });

  test("fail-closed answers 503", async () => {
    const deadUrl = `http://127.0.0.1:${await freePort()}`;
    const base = await serve(expressApp({ url: deadUrl, failOpen: false, onError: () => {} }));
    const r = await fetch(`${base}/`, { headers: { "user-agent": BROWSER_UA } });
    assert.equal(r.status, 503);
    assert.deepEqual(await r.json(), { error: "request could not be screened" });
  });

  test("a wrong token is an error, not a silent allow", async () => {
    const errors = [];
    const client = new SignalMoatClient({
      url: sidecar.url,
      token: "wrong-token-wrong-token-wrong",
      failOpen: false,
      onError: (e) => errors.push(e),
    });
    const decision = await client.inspect({ method: "GET", scheme: "http", host: "x", target: "/", headers: [], peerIp: null });
    assert.equal(decision.action, "block");
    assert.equal(decision.degraded, true);
    assert.match(String(errors[0]), /HTTP 401/);
  });

  test("a slow decision API times out", async () => {
    const slow = await serve(() => {
      /* never answers */
    });
    const errors = [];
    const client = new SignalMoatClient({ url: slow, token: TOKEN, timeoutMs: 100, onError: (e) => errors.push(e) });
    const started = Date.now();
    const decision = await client.inspect({ method: "GET", scheme: "http", host: "x", target: "/", headers: [], peerIp: null });
    assert.ok(Date.now() - started < 2000);
    assert.deepEqual([decision.action, decision.degraded], ["allow", true]);
    assert.equal(errors.length, 1);
  });
});

describe("fetch guard (Next.js and other web-standard runtimes)", () => {
  test("allows browsers and returns a ready-made response for blocked requests", async () => {
    const guard = createFetchGuard({ url: sidecar.url, token: TOKEN });

    const allowed = await guard(new Request("https://shop.example/pricing?x=1", { headers: { "user-agent": BROWSER_UA } }));
    assert.equal(allowed.blocked, null);
    assert.equal(allowed.decision.agent.label, "unclassified");
    // No peer address in these runtimes and no trusted proxy configured in this policy.
    assert.equal(allowed.decision.clientIp, "unknown");

    const bot = await guard(
      new Request("https://shop.example/contact", { method: "POST", headers: { "user-agent": "python-httpx/0.28" } }),
      { peerIp: "203.0.113.50" },
    );
    assert.ok(bot.blocked instanceof Response);
    assert.equal(bot.blocked.status, 403);
    assert.deepEqual(await bot.blocked.json(), { error: "request blocked" });
    assert.equal(bot.decision.clientIp, "203.0.113.50");
    assert.equal(bot.decision.agent.label, "automation:python-httpx");
  });
});

describe("configuration", () => {
  test("bad options fail fast at startup", () => {
    assert.throws(() => signalmoat({ url: sidecar.url, token: "short" }), /token/);
    assert.throws(() => signalmoat({ url: "127.0.0.1:8787", token: TOKEN }), /url/);
    assert.throws(() => signalmoat({ url: sidecar.url, token: TOKEN, timeoutMs: 0 }), /timeoutMs/);
  });

  test("the package can also be loaded with require()", () => {
    const require = createRequire(import.meta.url);
    assert.equal(typeof require("../dist/express.js").signalmoat, "function");
    assert.equal(typeof require("../dist/index.js").createFetchGuard, "function");
  });
});
