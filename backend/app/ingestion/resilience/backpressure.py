"""Backpressure, rate limiting, and bounded concurrency safeguards for the ingestion layer."""

import asyncio
import time
from collections import deque

from backend.app.core.exceptions import CyberAIError
from backend.app.core.logging import get_logger

logger = get_logger("cyber_ai.ingestion.backpressure")


class BackpressureExceededError(CyberAIError):
    """Exception raised when telemetry ingestion exceeds buffer capacity or rate limits."""

    def __init__(
        self,
        message: str = "Ingestion backpressure capacity exceeded",
        current_load: int = 0,
        limit: int = 0,
    ) -> None:
        super().__init__(
            message=message,
            details={"current_load": current_load, "limit": limit, "retry_after_sec": 1.0},
        )


class RateLimiter:
    """Sliding-window rate limiter calculating current events per second and enforcing limits."""

    def __init__(self, max_rate_per_sec: int = 5000, window_sec: float = 1.0) -> None:
        self.max_rate_per_sec = max_rate_per_sec
        self.window_sec = window_sec
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, count: int = 1) -> bool:
        """Check if `count` items can be processed within rate limit.

        Returns True if allowed, False if rate limit exceeded.
        """
        async with self._lock:
            now = time.perf_counter()
            cutoff = now - self.window_sec

            # Purge timestamps outside the sliding window
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            if len(self._timestamps) + count > self.max_rate_per_sec:
                return False

            for _ in range(count):
                self._timestamps.append(now)
            return True

    @property
    def current_rate(self) -> float:
        """Return current events per second estimated over recent window."""
        now = time.perf_counter()
        cutoff = now - self.window_sec
        recent_count = sum(1 for ts in self._timestamps if ts >= cutoff)
        return recent_count / max(self.window_sec, 0.001)


class BackpressureController:
    """Bounded concurrency semaphore and buffer queue manager for ingestion safety."""

    def __init__(
        self,
        max_concurrent_tasks: int = 500,
        max_queue_size: int = 10000,
        rate_limit_eps: int = 5000,
    ) -> None:
        self.max_concurrent_tasks = max_concurrent_tasks
        self.max_queue_size = max_queue_size
        self._semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self._rate_limiter = RateLimiter(max_rate_per_sec=rate_limit_eps)
        self._active_tasks: int = 0
        self._lock = asyncio.Lock()

    @property
    def active_tasks(self) -> int:
        """Return current active concurrent task count."""
        return self._active_tasks

    async def try_acquire(self, batch_size: int = 1) -> None:
        """Try to acquire execution slot under concurrency and rate limits.

        Raises:
            BackpressureExceededError if concurrency capacity or rate limit is saturated.
        """
        async with self._lock:
            if self._active_tasks + batch_size > self.max_queue_size:
                logger.warning(
                    "Ingestion buffer saturated: active=%d, requested=%d, max=%d",
                    self._active_tasks,
                    batch_size,
                    self.max_queue_size,
                )
                raise BackpressureExceededError(
                    message="Ingestion buffer saturated. Server is experiencing high load.",
                    current_load=self._active_tasks,
                    limit=self.max_queue_size,
                )

            rate_ok = await self._rate_limiter.acquire(count=batch_size)
            if not rate_ok:
                logger.warning(
                    "Ingestion rate limit exceeded: current_eps=%.1f, max_eps=%d",
                    self._rate_limiter.current_rate,
                    self._rate_limiter.max_rate_per_sec,
                )
                raise BackpressureExceededError(
                    message="Ingestion rate limit exceeded. Please backoff and retry.",
                    current_load=int(self._rate_limiter.current_rate),
                    limit=self._rate_limiter.max_rate_per_sec,
                )

            self._active_tasks += batch_size

    def release(self, batch_size: int = 1) -> None:
        """Release previously acquired execution slot."""
        self._active_tasks = max(0, self._active_tasks - batch_size)

    def get_metrics(self) -> dict[str, int | float]:
        """Return snapshot of current backpressure metrics."""
        return {
            "active_tasks": self._active_tasks,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "max_queue_size": self.max_queue_size,
            "current_eps": round(self._rate_limiter.current_rate, 2),
            "max_rate_per_sec": self._rate_limiter.max_rate_per_sec,
        }
