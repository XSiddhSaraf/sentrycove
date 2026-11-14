/**
 * Client for the SentryCove decision API (`sentrycove sidecar`).
 *
 * The detection logic lives in one place -- the SentryCove engine -- and this
 * package asks it for a verdict on each request. Zero runtime dependencies:
 * it uses the `fetch` built into Node 20+ and edge runtimes.
 */

export type AgentKind = "verified" | "declared" | "automation" | "unclassified";

export interface AgentIdentity {
  /** How the caller was classified. `verified` means a cryptographically proven AI agent. */
  kind: AgentKind;
  /** Agent name when known, e.g. "GPTBot" or the name of a trusted signer. */
  name: string | null;
  /** `kind` or `kind:name`, convenient for logs and rules. */
  label: string;
}

export interface Decision {
  action: "allow" | "block";
  /** HTTP status to answer with when `action` is "block". */
  status: number | null;
  agent: AgentIdentity;
  /** Client address as resolved by SentryCove, or null if the decision is a fallback. */
  clientIp: string | null;
  /** True when SentryCove wants the response status reported (login monitoring). */
  reportResponse: boolean;
  /** True when no real decision was made (decision API unreachable or errored). */
  degraded: boolean;
}

export interface InspectInput {
  method: string;
  scheme: "http" | "https";
  host: string;
  /** Raw request target exactly as received: "/path?query". */
  target: string;
  headers: Array<[string, string]>;
  /** Address of the TCP peer, if the runtime exposes it. */
  peerIp: string | null;
}

export interface ReportInput {
  clientIp: string;
  method: string;
  target: string;
  agent: string;
  status: number;
}

export interface SentryCoveOptions {
  /** Base URL of the decision API, e.g. "http://127.0.0.1:8787". */
  url: string;
  /** The shared secret the decision API was started with (SENTRYCOVE_API_TOKEN). */
  token: string;
  /** How long to wait for a decision, in milliseconds. Default 500. */
  timeoutMs?: number;
  /**
   * What to do when the decision API cannot be reached or errors.
   * `true` (default): let the request through, so SentryCove can never take your app down.
   * `false`: answer 503.
   */
  failOpen?: boolean;
  /** Called whenever the decision API cannot be reached or errors. Default: a throttled console.warn. */
  onError?: (error: unknown) => void;
  /** Custom fetch implementation (mainly for tests). */
  fetch?: typeof fetch;
}

const MIN_TOKEN_LENGTH = 16;
const UNCLASSIFIED: AgentIdentity = Object.freeze({ kind: "unclassified", name: null, label: "unclassified" });
const AGENT_KINDS: ReadonlySet<string> = new Set(["verified", "declared", "automation", "unclassified"]);

function defaultOnError(): (error: unknown) => void {
  let lastLogged = 0;
  return (error) => {
    const now = Date.now();
    if (now - lastLogged < 30_000) return;
    lastLogged = now;
    const reason = error instanceof Error ? error.message : String(error);
    console.warn(`[sentrycove] decision API unavailable: ${reason}`);
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseDecision(body: unknown): Decision {
  if (!isRecord(body) || (body.action !== "allow" && body.action !== "block")) {
    throw new Error("decision API returned an unexpected body");
  }
  const rawAgent = isRecord(body.agent) ? body.agent : {};
  const kind = typeof rawAgent.kind === "string" && AGENT_KINDS.has(rawAgent.kind) ? (rawAgent.kind as AgentKind) : "unclassified";
  const name = typeof rawAgent.name === "string" ? rawAgent.name : null;
  const label = typeof rawAgent.label === "string" ? rawAgent.label : name ? `${kind}:${name}` : kind;
  const status = typeof body.status === "number" && body.status >= 400 && body.status <= 599 ? body.status : null;
  return {
    action: body.action,
    status: body.action === "block" ? (status ?? 403) : null,
    agent: { kind, name, label },
    clientIp: typeof body.client_ip === "string" ? body.client_ip : null,
    reportResponse: body.report_response === true,
    degraded: body.degraded === true,
  };
}

export class SentryCoveClient {
  readonly failOpen: boolean;
  private readonly baseUrl: string;
  private readonly authorization: string;
  private readonly timeoutMs: number;
  private readonly onError: (error: unknown) => void;
  private readonly fetchImpl: typeof fetch;

  constructor(options: SentryCoveOptions) {
    if (!options || typeof options.url !== "string" || !/^https?:\/\//i.test(options.url)) {
      throw new TypeError('sentrycove: "url" must be the http(s) URL of the decision API, e.g. "http://127.0.0.1:8787"');
    }
    if (typeof options.token !== "string" || options.token.length < MIN_TOKEN_LENGTH) {
      throw new TypeError(`sentrycove: "token" must be the decision API secret (at least ${MIN_TOKEN_LENGTH} characters)`);
    }
    const timeoutMs = options.timeoutMs ?? 500;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('sentrycove: "timeoutMs" must be a positive number');
    }
    this.baseUrl = options.url.replace(/\/+$/, "");
    this.authorization = `Bearer ${options.token}`;
    this.timeoutMs = timeoutMs;
    this.failOpen = options.failOpen ?? true;
    this.onError = options.onError ?? defaultOnError();
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (typeof this.fetchImpl !== "function") {
      throw new TypeError("sentrycove: no fetch implementation available (Node 20+ is required)");
    }
  }

  private async post(path: string, body: unknown): Promise<Response> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { authorization: this.authorization, "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
      redirect: "error",
    });
    if (!response.ok) {
      // Drain so the connection can be reused; the body is never needed.
      await response.arrayBuffer().catch(() => undefined);
      throw new Error(`decision API answered HTTP ${response.status} for ${path}`);
    }
    return response;
  }

  /**
   * Ask SentryCove for a verdict. Never rejects: if the decision API is
   * unavailable the result is a `degraded` decision chosen by `failOpen`.
   */
  async inspect(input: InspectInput): Promise<Decision> {
    try {
      const response = await this.post("/v1/inspect", {
        method: input.method,
        scheme: input.scheme,
        host: input.host,
        target: input.target,
        headers: input.headers,
        peer_ip: input.peerIp,
      });
      return parseDecision(await response.json());
    } catch (error) {
      this.reportError(error);
      return {
        action: this.failOpen ? "allow" : "block",
        status: this.failOpen ? null : 503,
        agent: UNCLASSIFIED,
        clientIp: null,
        reportResponse: false,
        degraded: true,
      };
    }
  }

  /** Report the app's response status (fire-and-forget; used for failed-login monitoring). */
  report(input: ReportInput): void {
    this.post("/v1/response", {
      client_ip: input.clientIp,
      method: input.method,
      target: input.target,
      agent: input.agent,
      status: input.status,
    }).then(
      (response) => void response.arrayBuffer().catch(() => undefined),
      (error: unknown) => this.reportError(error),
    );
  }

  private reportError(error: unknown): void {
    try {
      this.onError(error);
    } catch {
      // An error handler must never break request handling.
    }
  }
}

export const BLOCKED_BODY = JSON.stringify({ error: "request blocked" });
export const UNAVAILABLE_BODY = JSON.stringify({ error: "request could not be screened" });

export function blockedBody(decision: Decision): string {
  return decision.degraded ? UNAVAILABLE_BODY : BLOCKED_BODY;
}
