"""Where SignalMoat keeps the state it needs between requests.

Bans, failed-login counters, session fingerprints, Web Bot Auth nonces and
alert de-duplication all go through one small interface with two backends:

* :class:`MemoryState` (default) -- bounded, per-process. Each worker or host
  keeps its own view.
* :class:`RedisState` -- shared by every SignalMoat process that points at the
  same Redis (or Valkey) server, so a ban, a brute-force counter or a used
  nonce is seen by all of them. Install with ``pip install "signalmoat[redis]"``.

Every Redis operation is a single server-side script, so concurrent workers
cannot interleave a read and a write (no lost updates, no double claims).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import secrets
import time
from collections.abc import Callable
from typing import Any, NoReturn, Optional, Protocol

from .config import StateConfig
from .store import SlidingWindowCounter, TTLCache

Clock = Callable[[], float]

log = logging.getLogger("signalmoat.state")

#: Namespaces used by SignalMoat. Kept short: they are part of every Redis key.
NS_BAN = "ban"
NS_LOGIN_IP = "login:ip"
NS_LOGIN_GLOBAL = "login:all"
NS_SESSION = "session"
NS_NONCE = "nonce"
NS_ALERT = "alert"

_READABLE_KEY = re.compile(r"^[A-Za-z0-9.:_\-\[\]|]{1,128}$")


class StateBackend(Protocol):
    """Operations the engine needs. Each one is atomic."""

    async def ban(self, key: str, ttl_seconds: float) -> None:
        """Mark ``key`` (an IP address) as banned for ``ttl_seconds``."""

    async def is_banned(self, key: str) -> bool: ...

    async def hit(self, namespace: str, key: str, window_seconds: float, max_events: int) -> int:
        """Record one event and return how many happened in the trailing window.

        At most ``max_events`` are remembered per key, so the count saturates there.
        """

    async def claim(self, namespace: str, key: str, ttl_seconds: float) -> bool:
        """Set ``key`` if it is not set yet. True if this call set it (first claim)."""

    async def remember_first(self, namespace: str, key: str, value: str, ttl_seconds: float) -> Optional[str]:
        """Store ``value`` unless a value is already stored.

        Returns the value that was already stored, or None if ``value`` was just stored.
        The first value always wins: a later caller can never overwrite it.
        """

    async def aclose(self) -> None: ...


class MemoryState:
    """Per-process state, bounded so unique keys cannot exhaust memory."""

    def __init__(self, max_keys: int, clock: Clock = time.monotonic) -> None:
        self._max_keys = max_keys
        self._clock = clock
        self._caches: dict[str, TTLCache[str, Any]] = {}
        self._counters: dict[tuple[str, float, int], SlidingWindowCounter[str]] = {}

    def _cache(self, namespace: str, ttl_seconds: float) -> TTLCache[str, Any]:
        cache = self._caches.get(namespace)
        if cache is None:
            cache = TTLCache(self._max_keys, max(ttl_seconds, 1e-3), self._clock)
            self._caches[namespace] = cache
        return cache

    async def ban(self, key: str, ttl_seconds: float) -> None:
        self._cache(NS_BAN, ttl_seconds).set(key, True, ttl_seconds=ttl_seconds)

    async def is_banned(self, key: str) -> bool:
        cache = self._caches.get(NS_BAN)
        return cache is not None and key in cache

    async def hit(self, namespace: str, key: str, window_seconds: float, max_events: int) -> int:
        slot = (namespace, float(window_seconds), max_events)
        counter = self._counters.get(slot)
        if counter is None:
            counter = SlidingWindowCounter(window_seconds, self._max_keys, max_events, self._clock)
            self._counters[slot] = counter
        return counter.hit(key)

    async def claim(self, namespace: str, key: str, ttl_seconds: float) -> bool:
        cache = self._cache(namespace, ttl_seconds)
        if key in cache:
            return False
        cache.set(key, True, ttl_seconds=ttl_seconds)
        return True

    async def remember_first(self, namespace: str, key: str, value: str, ttl_seconds: float) -> Optional[str]:
        cache = self._cache(namespace, ttl_seconds)
        known = cache.get(key)
        if known is not None:
            return str(known)
        cache.set(key, value, ttl_seconds=ttl_seconds)
        return None

    async def aclose(self) -> None:
        return None


# --- Redis -------------------------------------------------------------------

# Sliding window on a sorted set scored by the Redis server's own clock, so
# hosts with skewed clocks still agree. Members carry a random suffix so two
# events in the same microsecond are both counted.
_HIT_SCRIPT = """
local t = redis.call('TIME')
local now_us = tonumber(t[1]) * 1000000 + tonumber(t[2])
local window_us = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_us - window_us)
redis.call('ZADD', KEYS[1], now_us, now_us .. ':' .. ARGV[3])
redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -(cap + 1))
redis.call('PEXPIRE', KEYS[1], math.ceil(window_us / 1000))
return redis.call('ZCARD', KEYS[1])
"""

_REMEMBER_FIRST_SCRIPT = """
local known = redis.call('GET', KEYS[1])
if known then return known end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return false
"""


def _ms(seconds: float) -> int:
    return max(1, int(seconds * 1000))


class StateUnavailable(RuntimeError):
    """The shared state server cannot be reached; the caller applies ``fail_open``."""


class RedisState:
    """State shared through Redis (or a Redis-compatible server such as Valkey).

    ``client`` is a ``redis.asyncio.Redis`` instance; normally built from
    configuration with :func:`build_state`.
    """

    def __init__(
        self,
        client: Any,
        key_prefix: str = "signalmoat:",
        *,
        breaker_seconds: float = 5.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self._redis = client
        self._prefix = key_prefix
        self._hit = client.register_script(_HIT_SCRIPT)
        self._remember_first = client.register_script(_REMEMBER_FIRST_SCRIPT)
        # Circuit breaker: after a connection failure, fail immediately for a few
        # seconds instead of making every request wait for a timeout.
        self._breaker_seconds = breaker_seconds
        self._down_until = 0.0
        self._clock = clock
        from redis.exceptions import ConnectionError as RedisConnectionError
        from redis.exceptions import TimeoutError as RedisTimeoutError

        self._outage_errors: tuple[type[BaseException], ...] = (
            RedisConnectionError,  # includes BusyLoadingError
            RedisTimeoutError,
            OSError,
            asyncio.TimeoutError,
        )

    async def _call(self, coro: Any) -> Any:
        if self._clock() < self._down_until:
            coro.close()
            raise StateUnavailable("shared state server marked down; retrying shortly")
        try:
            return await coro
        except self._outage_errors as exc:
            self._trip(exc)

    def _trip(self, exc: BaseException) -> NoReturn:
        if self._clock() >= self._down_until:
            log.warning("shared state server unreachable (%s); failing fast for %ss", exc, self._breaker_seconds)
        self._down_until = self._clock() + self._breaker_seconds
        raise StateUnavailable(str(exc)) from exc

    def key(self, namespace: str, key: str) -> str:
        """The Redis key used for ``key``.

        Short, printable keys (IP addresses, hashes) are kept readable so an
        operator can inspect or delete them with ``redis-cli``; anything else
        (attacker-controlled nonces, for example) is hashed to bound its size.
        """
        if not _READABLE_KEY.match(key):
            key = "h:" + hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:32]
        return f"{self._prefix}{namespace}:{key}"

    async def ban(self, key: str, ttl_seconds: float) -> None:
        await self._call(self._redis.set(self.key(NS_BAN, key), b"1", px=_ms(ttl_seconds)))

    async def is_banned(self, key: str) -> bool:
        return bool(await self._call(self._redis.exists(self.key(NS_BAN, key))))

    async def hit(self, namespace: str, key: str, window_seconds: float, max_events: int) -> int:
        window_us = max(1, int(window_seconds * 1_000_000))
        count = await self._call(
            self._hit(keys=[self.key(namespace, key)], args=[window_us, max(1, max_events), secrets.token_hex(4)])
        )
        return int(count)

    async def claim(self, namespace: str, key: str, ttl_seconds: float) -> bool:
        return bool(await self._call(self._redis.set(self.key(namespace, key), b"1", nx=True, px=_ms(ttl_seconds))))

    async def remember_first(self, namespace: str, key: str, value: str, ttl_seconds: float) -> Optional[str]:
        known = await self._call(self._remember_first(keys=[self.key(namespace, key)], args=[value, _ms(ttl_seconds)]))
        if known is None:
            return None
        return known.decode("utf-8") if isinstance(known, bytes) else str(known)

    async def ping(self) -> bool:
        return bool(await self._call(self._redis.ping()))

    async def aclose(self) -> None:
        await self._redis.aclose()


def build_state(cfg: StateConfig, max_keys: int) -> StateBackend:
    """Create the backend selected in the ``state`` section of the configuration."""
    if cfg.backend == "memory":
        return MemoryState(max_keys)
    url = os.environ.get(cfg.redis_url_env, "")
    if not url:
        raise ValueError(f"state.backend is redis but the environment variable {cfg.redis_url_env} is not set")
    if not url.startswith(("redis://", "rediss://", "unix://")):
        raise ValueError(f"{cfg.redis_url_env} must start with redis://, rediss:// or unix://")
    try:
        import redis.asyncio as redis_asyncio
        from redis.backoff import NoBackoff
        from redis.retry import Retry
    except ImportError:
        raise ValueError(
            'state.backend is redis but the redis package is missing: pip install "signalmoat[redis]"'
        ) from None
    client = redis_asyncio.Redis.from_url(
        url,
        socket_timeout=cfg.timeout_seconds,
        socket_connect_timeout=cfg.timeout_seconds,
        health_check_interval=30,
        # No client-side retries: a request must never wait seconds for Redis.
        # The circuit breaker in RedisState handles outages instead.
        retry=Retry(NoBackoff(), 0),
    )
    return RedisState(client, cfg.key_prefix)
