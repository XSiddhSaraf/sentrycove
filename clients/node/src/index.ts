/**
 * SignalMoat for JavaScript runtimes.
 *
 *   import { createFetchGuard } from "signalmoat";          // Next.js, Hono, Bun, Deno, edge
 *   import { signalmoat } from "signalmoat/express";        // Express, Connect, plain node:http
 */

import { SignalMoatClient, blockedBody } from "./client.js";
import type { Decision, SignalMoatOptions } from "./client.js";

export { SignalMoatClient } from "./client.js";
export type { AgentIdentity, AgentKind, Decision, InspectInput, ReportInput, SignalMoatOptions } from "./client.js";

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
 *   const guard = createFetchGuard({ url: process.env.SIGNALMOAT_URL!, token: process.env.SIGNALMOAT_API_TOKEN! });
 *   export async function middleware(request: NextRequest) {
 *     const { blocked } = await guard(request);
 *     return blocked ?? NextResponse.next();
 *   }
 *
 * These runtimes do not expose the TCP peer address, so SignalMoat relies on
 * `X-Forwarded-For`: set `trusted_proxy_hops` in the policy to the number of
 * proxies in front of your app. They also cannot see the final response, so
 * failed-login monitoring needs the Express middleware or the reverse proxy.
 */
export function createFetchGuard(options: SignalMoatOptions): FetchGuard {
  const client = new SignalMoatClient(options);
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
