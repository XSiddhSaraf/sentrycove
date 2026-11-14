// Starts the real SignalMoat decision API (Python) so the middleware is tested
// against the actual engine rather than a mock.
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const TOKEN = "node-test-token-0123456789abcdef";
export const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36";

export const POLICY = {
  mode: "enforce",
  rules: [
    {
      name: "no-bot-forms",
      paths: ["/contact"],
      methods: ["POST"],
      agents: ["declared", "automation"],
      action: "block",
      severity: "high",
    },
  ],
  honeypots: { paths: ["/.env"], ban_seconds: 0 },
  login: { paths: ["/login"], per_ip_threshold: 3, global_threshold: 1000 },
  alerts: { sinks: [{ type: "log", min_severity: "low" }], cooldown_seconds: 0 },
};

export function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}

export async function startSidecar(policy = POLICY) {
  const dir = mkdtempSync(join(tmpdir(), "signalmoat-"));
  const configPath = join(dir, "policy.yaml");
  writeFileSync(configPath, JSON.stringify(policy)); // JSON is valid YAML
  const port = await freePort();
  const python = process.env.SIGNALMOAT_PYTHON ?? "python3";
  const child = spawn(python, ["-m", "signalmoat", "sidecar", "--config", configPath, "--port", String(port)], {
    env: { ...process.env, SIGNALMOAT_API_TOKEN: TOKEN },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (chunk) => (log += chunk));
  child.stderr.on("data", (chunk) => (log += chunk));
  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`sidecar exited early:\n${log}`);
    try {
      const r = await fetch(`${url}/_signalmoat/health`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) {
      child.kill();
      throw new Error(`sidecar did not start:\n${log}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    url,
    log: () => log,
    /** Wait until the sidecar has logged `text` (alerts are written as log lines). */
    async waitForLog(text, timeoutMs = 5000) {
      const until = Date.now() + timeoutMs;
      while (!log.includes(text)) {
        if (Date.now() > until) throw new Error(`"${text}" never appeared in sidecar log:\n${log}`);
        await new Promise((r) => setTimeout(r, 25));
      }
    },
    stop: () =>
      new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill("SIGINT");
      }),
  };
}
