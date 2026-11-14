"""Decision API ("sidecar"): lets middleware written in other languages use the engine.

The Node/Next.js and ASP.NET Core packages call this small HTTP API on
every request and act on the answer. Run it next to your app and keep it
off the public internet -- bind it to localhost or a private network.

    POST /v1/inspect    -> {"action": "allow" | "block", ...}
    POST /v1/response   -> 204 (reports the app's response status, for login monitoring)
    GET  /_signalmoat/health

Every /v1 call must carry ``Authorization: Bearer <SIGNALMOAT_API_TOKEN>``.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .engine import Engine, RequestInfo
from .middleware import Receive, Scope, Send, respond_json
from .proxy import HEALTH_PATH, run_lifespan

log = logging.getLogger("signalmoat.sidecar")

MIN_TOKEN_LENGTH = 16
MAX_BODY_BYTES = 1024 * 1024
API_VERSION = 1


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class InspectRequest(_Model):
    # Deliberately no per-field length limits: a request this API refuses to parse
    # would be treated by the calling middleware as "decision unavailable" and, with
    # fail-open, let through -- so an attacker must not be able to trigger a refusal
    # with an oversized header or URL. Only the total body size is capped.
    method: str = Field(min_length=1)
    scheme: str = Field(default="http", pattern=r"^(?i:https?)$")
    host: str = ""
    #: Raw request target exactly as received: "/path?query".
    target: str = Field(pattern=r"^/")
    headers: list[tuple[str, str]] = Field(default_factory=list)
    #: Address of the TCP peer as seen by the app server (may be a load balancer).
    peer_ip: Optional[str] = None


class ResponseReport(_Model):
    client_ip: str = Field(min_length=1)
    method: str = Field(min_length=1)
    target: str = Field(pattern=r"^/")
    agent: str = "unclassified"
    status: int = Field(ge=100, le=599)


class DecisionAPI:
    """ASGI app exposing the engine over HTTP."""

    def __init__(self, engine: Engine, token: str) -> None:
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"API token must be at least {MIN_TOKEN_LENGTH} characters")
        self.engine = engine
        self._expected = b"Bearer " + token.encode("utf-8")

    async def aclose(self) -> None:
        await self.engine.aclose()

    def _authorized(self, scope: Scope) -> bool:
        supplied = next((v for k, v in scope.get("headers", []) if k.lower() == b"authorization"), b"")
        return hmac.compare_digest(supplied, self._expected)

    @staticmethod
    async def _read_json(receive: Receive) -> Optional[object]:
        """Return the parsed JSON body, or None if it is too large or not JSON."""
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            body.extend(message.get("body", b""))
            if len(body) > MAX_BODY_BYTES:
                return None
            if not message.get("more_body", False):
                break
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await run_lifespan(receive, send, self.aclose)
            return
        if scope["type"] != "http":
            return
        path, method = scope.get("path", ""), scope.get("method", "GET")
        if path == HEALTH_PATH:
            await respond_json(send, 200, {"status": "ok", "mode": self.engine.config.mode, "api": API_VERSION})
            return
        if path not in ("/v1/inspect", "/v1/response"):
            await respond_json(send, 404, {"error": "not found"})
            return
        if method != "POST":
            await respond_json(send, 405, {"error": "use POST"}, [(b"allow", b"POST")])
            return
        if not self._authorized(scope):
            await respond_json(send, 401, {"error": "missing or wrong bearer token"})
            return
        payload = await self._read_json(receive)
        if payload is None:
            await respond_json(send, 400, {"error": "body must be JSON under 1 MiB"})
            return
        try:
            if path == "/v1/inspect":
                await self._inspect(InspectRequest.model_validate(payload), send)
            else:
                await self._report(ResponseReport.model_validate(payload), send)
        except ValidationError as exc:
            await respond_json(
                send, 422, {"error": "invalid request", "detail": exc.errors(include_url=False, include_input=False)}
            )

    async def _inspect(self, req: InspectRequest, send: Send) -> None:
        request = RequestInfo.from_parts(
            method=req.method, scheme=req.scheme, host=req.host, target=req.target, headers=req.headers
        )
        try:
            verdict = await self.engine.inspect(request, req.peer_ip)
        except Exception:
            log.exception("signalmoat inspection failed")
            if not self.engine.config.fail_open:
                await respond_json(send, 503, {"error": "request could not be screened"})
                return
            await respond_json(
                send,
                200,
                {
                    "action": "allow",
                    "status": None,
                    "agent": {"kind": "unclassified", "name": None, "label": "unclassified"},
                    "client_ip": None,
                    "report_response": False,
                    "degraded": True,
                },
            )
            return
        identity = verdict.identity
        await respond_json(
            send,
            200,
            {
                "action": "block" if verdict.blocked else "allow",
                "status": verdict.block_status,
                "agent": {"kind": identity.kind, "name": identity.name, "label": identity.label},
                "client_ip": verdict.client_ip,
                "report_response": verdict.watch_response and not verdict.blocked,
                "degraded": False,
            },
        )

    async def _report(self, report: ResponseReport, send: Send) -> None:
        try:
            await self.engine.on_response(
                client_ip=report.client_ip,
                method=report.method,
                path=report.target,
                agent=report.agent,
                status=report.status,
            )
        except Exception:
            log.exception("signalmoat login monitoring failed")
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})
