/**
 * SignalMoat middleware for Express 4/5, Connect and plain `node:http` servers.
 *
 *   import express from "express";
 *   import { signalmoat } from "signalmoat/express";
 *
 *   const app = express();
 *   app.use(signalmoat({ url: "http://127.0.0.1:8787", token: process.env.SIGNALMOAT_API_TOKEN }));
 *
 * Register it before your routes and body parsers. Afterwards
 * `req.signalmoat` tells your handlers who is calling.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import { SignalMoatClient, blockedBody } from "./client.js";
import type { AgentIdentity, SignalMoatOptions } from "./client.js";

export type { AgentIdentity, SignalMoatOptions } from "./client.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Who SignalMoat thinks is calling. Set by the `signalmoat()` middleware. */
      signalmoat?: AgentIdentity;
    }
  }
}

export type SignalMoatRequest = IncomingMessage & { signalmoat?: AgentIdentity; originalUrl?: string };
export type NextFunction = (error?: unknown) => void;
export type SignalMoatMiddleware = (req: SignalMoatRequest, res: ServerResponse, next: NextFunction) => void;

function headerPairs(req: IncomingMessage): Array<[string, string]> {
  // rawHeaders keeps duplicates and order: [name, value, name, value, ...]
  const raw = req.rawHeaders;
  const pairs: Array<[string, string]> = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    pairs.push([raw[i] as string, raw[i + 1] as string]);
  }
  return pairs;
}

/**
 * Reduce a request target to origin form ("/path?query").
 *
 * HTTP also allows absolute-form targets ("GET http://host/admin HTTP/1.1"), which
 * routers resolve to the path inside them; SignalMoat must judge that same path.
 */
function originForm(target: string): string {
  if (target.startsWith("/")) return target;
  try {
    const url = new URL(target);
    return `${url.pathname}${url.search}`;
  } catch {
    return "/";
  }
}

export function signalmoat(options: SignalMoatOptions): SignalMoatMiddleware {
  const client = new SignalMoatClient(options);

  return (req, res, next) => {
    const method = req.method ?? "GET";
    // originalUrl survives Express router mounting; url is the fallback for plain node:http.
    const target = req.originalUrl ?? req.url ?? "/";
    const encrypted = (req.socket as { encrypted?: boolean }).encrypted === true;

    client
      .inspect({
        method,
        scheme: encrypted ? "https" : "http",
        host: req.headers.host ?? "",
        target: originForm(target),
        headers: headerPairs(req),
        peerIp: req.socket.remoteAddress ?? null,
      })
      .then((decision) => {
        req.signalmoat = decision.agent;
        if (decision.action === "block") {
          const body = blockedBody(decision);
          res.statusCode = decision.status ?? 403;
          res.setHeader("content-type", "application/json");
          res.setHeader("cache-control", "no-store");
          res.setHeader("content-length", Buffer.byteLength(body));
          res.end(body);
          return;
        }
        if (decision.reportResponse && decision.clientIp !== null) {
          const clientIp = decision.clientIp;
          res.once("finish", () => {
            client.report({ clientIp, method, target: originForm(target), agent: decision.agent.label, status: res.statusCode });
          });
        }
        next();
      })
      .catch(next);
  };
}
