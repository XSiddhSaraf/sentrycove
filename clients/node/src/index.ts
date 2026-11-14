/**
 * SentryCove for JavaScript runtimes.
 *
 *   import { createFetchGuard } from "sentrycove";          // Next.js, Hono, Bun, Deno, edge
 *   import { sentrycove } from "sentrycove/express";        // Express, Connect, plain node:http
 */

import { SentryCoveClient, blockedBody } from "./client.js";
import type { Decision, SentryCoveOptions } from "./client.js";

export { SentryCoveClient } from "./client.js";
export type { AgentIdentity, AgentKind, Decision, InspectInput, ReportInput, SentryCoveOptions } from "./client.js";

export interface GuardInfo {
  /** Address of the TCP peer, when your runtime exposes it. */
  peerIp?: string | null;
}

export interface GuardResult {
  /** A ready-made response to return when the request must be stopped; otherwise null. */
  blocked: Response | null;
  decision: Decision;
}

export type FetchGuard = (request: Request, info?: GuardInfo) => Promise<GuardResult>;

/**
 * Guard for runtimes built on the web `Request`/`Response` API.
 *
 * Next.js (`middleware.ts`, or `proxy.ts` on Next.js 16+):
 *
 *   const guard = createFetchGuard({ url: process.env.SENTRYCOVE_URL!, token: process.env.SENTRYCOVE_API_TOKEN! });
 *   export async function middleware(request: NextRequest) {
 *     const { blocked } = await guard(request);
 *     return blocked ?? NextResponse.next();
 *   }
 *
 * These runtimes do not expose the TCP peer address, so SentryCove relies on
 * `X-Forwarded-For`: set `trusted_proxy_hops` in the policy to the number of
 * proxies in front of your app. They also cannot see the final response, so
 * failed-login monitoring needs the Express middleware or the reverse proxy.
 */
export function createFetchGuard(options: SentryCoveOptions): FetchGuard {
  const client = new SentryCoveClient(options);
  return async (request, info) => {
    const url = new URL(request.url);
    const decision = await client.inspect({
      method: request.method,
      scheme: url.protocol === "https:" ? "https" : "http",
      host: request.headers.get("host") ?? url.host,
      target: `${url.pathname}${url.search}`,
      headers: Array.from(request.headers.entries()),
      peerIp: info?.peerIp ?? null,
    });
    if (decision.action !== "block") {
      return { blocked: null, decision };
    }
    const blocked = new Response(blockedBody(decision), {
      status: decision.status ?? 403,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
    return { blocked, decision };
  };
}
