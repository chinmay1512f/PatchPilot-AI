"""Usage limits for public demo deployments.

Caps how many analyses can start per hour and per day, and how many may run at once, so a public
link cannot run up an unbounded Claude bill. Counters live in memory (they reset when the server
restarts); deleting a job does not give its slot back. A limit of 0 disables that check.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque

HOUR, DAY = 3600, 86400


class LimitExceeded(Exception):
    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.message = message
        self.retry_after = max(1, int(retry_after))


def _minutes(seconds: float) -> str:
    m = max(1, math.ceil(seconds / 60))
    return "1 minute" if m == 1 else f"{m} minutes"


class JobLimiter:
    def __init__(self, per_hour: int = 0, per_day: int = 0, concurrent: int = 0, clock=time.time):
        self.per_hour, self.per_day, self.concurrent = max(0, per_hour), max(0, per_day), max(0, concurrent)
        self._clock = clock
        self._starts: deque[float] = deque()  # start times of accepted analyses, last 24 h
        self._reserved = 0  # requests between reserve() and commit()/release()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.per_hour or self.per_day or self.concurrent)

    def _prune(self, now: float) -> None:
        while self._starts and now - self._starts[0] >= DAY:
            self._starts.popleft()

    def _last_hour(self, now: float) -> list[float]:
        return [t for t in self._starts if now - t < HOUR]

    def reserve(self, active: int) -> None:
        """Claim a slot for a new analysis or raise LimitExceeded. ``active`` = analyses running now."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if self.concurrent and active + self._reserved >= self.concurrent:
                raise LimitExceeded(
                    "Another analysis is already running on this demo server. Please wait for it to finish "
                    "(you can follow it on the dashboard), then try again.", 60)
            hour = self._last_hour(now)
            if self.per_hour and len(hour) + self._reserved >= self.per_hour:
                wait = HOUR - (now - hour[0]) if hour else 60
                raise LimitExceeded(
                    f"Demo limit reached: at most {self.per_hour} analyses per hour on this public demo. "
                    f"Please try again in about {_minutes(wait)}.", wait)
            if self.per_day and len(self._starts) + self._reserved >= self.per_day:
                wait = DAY - (now - self._starts[0]) if self._starts else 60
                raise LimitExceeded(
                    f"Demo limit reached: at most {self.per_day} analyses per day on this public demo. "
                    f"Please try again in about {_minutes(wait)}.", wait)
            self._reserved += 1

    def commit(self) -> None:
        """The reserved analysis was accepted: count it."""
        with self._lock:
            self._reserved = max(0, self._reserved - 1)
            self._starts.append(self._clock())

    def release(self) -> None:
        """The reserved analysis was rejected (bad upload, bad URL…): give the slot back."""
        with self._lock:
            self._reserved = max(0, self._reserved - 1)

    def status(self) -> dict | None:
        if not self.enabled:
            return None
        with self._lock:
            now = self._clock()
            self._prune(now)
            return {"per_hour": self.per_hour, "per_day": self.per_day, "concurrent": self.concurrent,
                    "used_hour": len(self._last_hour(now)), "used_day": len(self._starts)}
