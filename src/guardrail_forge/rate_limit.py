from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import monotonic


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60, clock: Callable[[], float] = monotonic) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> RateLimitDecision:
        now = self.clock()
        with self._lock:
            events = self._events[key]
            cutoff = now - self.window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - events[0])) + 1)
                return RateLimitDecision(False, self.limit, 0, retry_after)
            events.append(now)
            return RateLimitDecision(True, self.limit, self.limit - len(events), 0)

