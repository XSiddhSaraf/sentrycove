"""Bounded in-memory state stores.

Everything is size-capped so an attacker cannot exhaust memory by
sending unique keys. These are the building blocks of the per-process
:class:`signalmoat.state.MemoryState`; for state shared between workers or
hosts, see :class:`signalmoat.state.RedisState`.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable
from typing import Generic, Optional, TypeVar

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")

Clock = Callable[[], float]


class TTLCache(Generic[K, V]):
    """LRU cache with per-entry expiry and a hard size cap."""

    def __init__(
        self,
        max_items: int,
        ttl_seconds: float,
        clock: Clock = time.monotonic,
    ) -> None:
        if max_items <= 0:
            raise ValueError("max_items must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._data: OrderedDict[K, tuple[float, V]] = OrderedDict()
        self._max = max_items
        self._ttl = ttl_seconds
        self._clock = clock

    def get(self, key: K) -> Optional[V]:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= self._clock():
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: K, value: V, ttl_seconds: Optional[float] = None) -> None:
        ttl = self._ttl if ttl_seconds is None else ttl_seconds
        self._data[key] = (self._clock() + ttl, value)
        self._data.move_to_end(key)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def __contains__(self, key: object) -> bool:
        return self.get(key) is not None  # type: ignore[arg-type]

    def __len__(self) -> int:
        return len(self._data)


class SlidingWindowCounter(Generic[K]):
    """Counts events per key within a trailing time window."""

    def __init__(
        self,
        window_seconds: float,
        max_keys: int,
        max_events_per_key: int,
        clock: Clock = time.monotonic,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._window = window_seconds
        self._clock = clock
        self._maxlen = max(1, max_events_per_key)
        self._events: TTLCache[K, deque[float]] = TTLCache(max_keys, window_seconds, clock)

    def hit(self, key: K) -> int:
        """Record one event for ``key`` and return the count in the window."""
        now = self._clock()
        events = self._events.get(key)
        if events is None:
            events = deque(maxlen=self._maxlen)
        cutoff = now - self._window
        while events and events[0] <= cutoff:
            events.popleft()
        events.append(now)
        self._events.set(key, events)
        return len(events)
