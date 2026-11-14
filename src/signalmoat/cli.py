"""Command line entry point: ``signalmoat proxy | sidecar | check-config``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from typing import Optional

from . import __version__
from .config import load_config
from .engine import Engine

log = logging.getLogger("signalmoat")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signalmoat", description="Agent firewall and early-warning layer.")
    parser.add_argument("--version", action="version", version=f"signalmoat {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, default_port: int) -> None:
        p.add_argument("--config", default=os.environ.get("SIGNALMOAT_CONFIG"), help="policy YAML file")
        p.add_argument("--host", default=os.environ.get("SIGNALMOAT_HOST", "127.0.0.1"), help="address to listen on")
        p.add_argument("--port", type=int, default=_env_int("SIGNALMOAT_PORT", default_port))

    proxy = sub.add_parser("proxy", help="reverse proxy in front of an app in any language")
    common(proxy, 8080)
    proxy.add_argument(
        "--upstream", default=os.environ.get("SIGNALMOAT_UPSTREAM"), help="the app to protect, e.g. http://app:3000"
    )
    proxy.add_argument(
        "--rewrite-host", action="store_true", help="send the upstream's own host name instead of the client's Host"
    )

    sidecar = sub.add_parser("sidecar", help="decision API for the Node and ASP.NET Core middleware")
    common(sidecar, 8787)

    check = sub.add_parser("check-config", help="validate a policy file and exit")
    check.add_argument("path")
    return parser


def _load_engine(config_path: Optional[str]) -> Engine:
    if not config_path:
        log.warning("no --config given: running with defaults (monitor mode, no rules, honeypots or login paths)")
    engine = Engine(config_path or {})
    log.info("policy loaded: mode=%s rules=%d", engine.config.mode, len(engine.config.rules))
    return engine


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.command == "check-config":
        try:
            cfg = load_config(args.path)
        except Exception as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return 1
        print(f"ok: mode={cfg.mode}, {len(cfg.rules)} rules, {len(cfg.honeypots.paths)} honeypot paths")
        return 0

    try:
        import uvicorn
    except ImportError:
        print('this command needs the server extra: pip install "signalmoat[server]"', file=sys.stderr)
        return 1

    if args.command == "proxy":
        if not args.upstream:
            print("--upstream (or SIGNALMOAT_UPSTREAM) is required, e.g. http://127.0.0.1:3000", file=sys.stderr)
            return 2
        from .proxy import create_proxy_app

        try:
            app = create_proxy_app(args.upstream, engine=_load_engine(args.config), preserve_host=not args.rewrite_host)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        log.info("proxying %s:%d -> %s", args.host, args.port, args.upstream)
        # proxy_headers=False: SignalMoat resolves the client address itself (trusted_proxy_hops).
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            proxy_headers=False,
            server_header=False,
            date_header=False,
            access_log=False,
            log_config=None,
        )
        return 0

    token = os.environ.get("SIGNALMOAT_API_TOKEN", "")
    from .sidecar import MIN_TOKEN_LENGTH, DecisionAPI

    if len(token) < MIN_TOKEN_LENGTH:
        print(
            f"SIGNALMOAT_API_TOKEN must be set to a secret of at least {MIN_TOKEN_LENGTH} characters "
            '(generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))")',
            file=sys.stderr,
        )
        return 2
    api = DecisionAPI(_load_engine(args.config), token)
    log.info("decision API listening on %s:%d", args.host, args.port)
    uvicorn.run(
        api, host=args.host, port=args.port, proxy_headers=False, server_header=False, access_log=False, log_config=None
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
