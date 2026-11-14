"""Real-socket helpers: run ASGI apps on 127.0.0.1 in background threads."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import threading
import time

import uvicorn


class ServerThread:
    def __init__(self, app, **uvicorn_kwargs) -> None:
        config = uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="warning", proxy_headers=False, lifespan="on", **uvicorn_kwargs
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> ServerThread:
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline or not self.thread.is_alive():
                raise RuntimeError("server did not start")
            time.sleep(0.01)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        return self

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


class Upstream:
    """A stand-in for 'your app': records what it received."""

    def __init__(self) -> None:
        self.hits: list[str] = []

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        path = scope["path"]
        self.hits.append(path)
        body = bytearray()
        chunks = 0
        while True:
            message = await receive()
            body.extend(message.get("body", b""))
            chunks += 1
            if not message.get("more_body", False):
                break

        async def reply(status, headers, payload=b""):
            headers = [*headers, (b"content-length", str(len(payload)).encode())]
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": b"" if scope["method"] == "HEAD" else payload})

        if path.startswith("/echo"):
            info = {
                "method": scope["method"],
                "raw_path": scope["raw_path"].decode("latin-1"),
                "query": scope["query_string"].decode("latin-1"),
                "headers": [[k.decode("latin-1"), v.decode("latin-1")] for k, v in scope["headers"]],
                "body_len": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }
            await reply(200, [(b"content-type", b"application/json")], json.dumps(info).encode())
        elif path == "/stream":
            await send(
                {"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]}
            )
            for i in range(3):
                await send({"type": "http.response.body", "body": f"data: {i}\n\n".encode(), "more_body": True})
                await asyncio.sleep(0.05)
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        elif path == "/gzip":
            payload = gzip.compress(b"hello " * 1000)
            await reply(200, [(b"content-encoding", b"gzip"), (b"content-type", b"text/plain")], payload)
        elif path == "/cookies":
            await reply(
                200, [(b"set-cookie", b"a=1; Path=/"), (b"set-cookie", b"b=2; Path=/"), (b"x-powered-by", b"demo")]
            )
        elif path == "/redirect":
            await reply(302, [(b"location", b"https://elsewhere.example/next")])
        elif path == "/login":
            await reply(401, [(b"content-type", b"application/json")], b'{"error":"bad credentials"}')
        elif path == "/slow":
            await asyncio.sleep(2)
            await reply(200, [], b"late")
        else:
            await reply(200, [(b"content-type", b"text/plain")], b"ok")
