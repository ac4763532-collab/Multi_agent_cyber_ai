"""Performance Engineering Module."""

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from backend.app.utils.datetime import utc_now


class ResourceType(StrEnum):
    """Types of system resources."""

    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"


class ThrottleStrategy(StrEnum):
    """Rate limiting strategies."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


class CircuitState(StrEnum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class ResourceMetrics:
    """Real-time resource metrics."""

    timestamp: datetime = field(default_factory=utc_now)
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    disk_read_mb_s: float = 0.0
    disk_write_mb_s: float = 0.0
    network_recv_mb_s: float = 0.0
    network_sent_mb_s: float = 0.0
    active_connections: int = 0
    queue_depth: int = 0
    cache_hit_rate: float = 0.0


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(
        self,
        rate: float,  # tokens per second
        capacity: int,  # max tokens
        strategy: ThrottleStrategy = ThrottleStrategy.TOKEN_BUCKET,
    ):
        self.rate = rate
        self.capacity = capacity
        self.strategy = strategy
        self.tokens = float(capacity)
        self.last_update = time.monotonic()
        self._request_count = 0
        self._rejected_count = 0

    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens. Returns True if successful."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now

        # Refill tokens
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        self._request_count += 1

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True

        self._rejected_count += 1
        return False

    async def acquire_async(self, tokens: int = 1, timeout: float = 5.0) -> bool:
        """Async acquire with wait."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.acquire(tokens):
                return True
            await asyncio.sleep(0.01)
        return False

    def get_metrics(self) -> dict[str, Any]:
        """Get rate limiter metrics."""
        return {
            "rate": self.rate,
            "capacity": self.capacity,
            "current_tokens": self.tokens,
            "total_requests": self._request_count,
            "rejected_requests": self._rejected_count,
            "rejection_rate": (
                self._rejected_count / self._request_count
                if self._request_count > 0
                else 0.0
            ),
        }


class CircuitBreaker:
    """Circuit breaker for fault tolerance."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_requests: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_requests = half_open_requests

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float | None = None
        self.half_open_successes = 0

        self._total_calls = 0
        self._successful_calls = 0
        self._failed_calls = 0

    def can_execute(self) -> bool:
        """Check if request can proceed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.last_failure_time:
                elapsed = time.monotonic() - self.last_failure_time
                if elapsed >= self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_successes = 0
                    return True
            return False

        # HALF_OPEN state
        return True

    def record_success(self) -> None:
        """Record successful execution."""
        self._total_calls += 1
        self._successful_calls += 1

        if self.state == CircuitState.HALF_OPEN:
            self.half_open_successes += 1
            if self.half_open_successes >= self.half_open_requests:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitState.CLOSED:
            self.success_count += 1
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed execution."""
        self._total_calls += 1
        self._failed_calls += 1
        self.failure_count += 1
        self.last_failure_time = time.monotonic()

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
        elif self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN

    def get_state(self) -> dict[str, Any]:
        """Get circuit breaker state."""
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "total_calls": self._total_calls,
            "successful_calls": self._successful_calls,
            "failed_calls": self._failed_calls,
            "failure_rate": (
                self._failed_calls / self._total_calls if self._total_calls > 0 else 0.0
            ),
        }


class ConnectionPool:
    """Generic connection pool."""

    def __init__(
        self,
        min_size: int = 5,
        max_size: int = 20,
        timeout: float = 30.0,
    ):
        self.min_size = min_size
        self.max_size = max_size
        self.timeout = timeout
        self._available: deque[Any] = deque()
        self._in_use: set[int] = set()
        self._created = 0

    def _create_connection(self) -> Any:
        """Create new connection (override in subclass)."""
        self._created += 1
        return {"id": self._created, "created_at": utc_now()}

    def acquire(self) -> Any | None:
        """Acquire connection from pool."""
        if self._available:
            conn = self._available.popleft()
            self._in_use.add(id(conn))
            return conn

        if len(self._in_use) < self.max_size:
            conn = self._create_connection()
            self._in_use.add(id(conn))
            return conn

        return None

    def release(self, conn: Any) -> None:
        """Return connection to pool."""
        conn_id = id(conn)
        if conn_id in self._in_use:
            self._in_use.remove(conn_id)
            self._available.append(conn)

    def get_metrics(self) -> dict[str, Any]:
        """Get pool metrics."""
        return {
            "min_size": self.min_size,
            "max_size": self.max_size,
            "available": len(self._available),
            "in_use": len(self._in_use),
            "total_created": self._created,
            "utilization": len(self._in_use) / self.max_size if self.max_size > 0 else 0,
        }


class CacheManager:
    """LRU cache manager with TTL."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: dict[str, tuple[Any, datetime]] = {}
        self._access_order: deque[str] = deque()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        """Get value from cache."""
        if key not in self._cache:
            self._misses += 1
            return None

        value, expires_at = self._cache[key]
        if utc_now() > expires_at:
            del self._cache[key]
            self._misses += 1
            return None

        self._hits += 1
        # Update access order
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache."""
        ttl = ttl or self.default_ttl
        expires_at = utc_now() + timedelta(seconds=ttl)

        # Evict if at capacity
        while len(self._cache) >= self.max_size and self._access_order:
            oldest = self._access_order.popleft()
            self._cache.pop(oldest, None)

        self._cache[key] = (value, expires_at)
        self._access_order.append(key)

    def delete(self, key: str) -> bool:
        """Delete from cache."""
        if key in self._cache:
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            return True
        return False

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()
        self._access_order.clear()

    def get_metrics(self) -> dict[str, Any]:
        """Get cache metrics."""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / total if total > 0 else 0.0,
        }


class PerformanceMonitor:
    """Monitors system performance metrics."""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._latencies: deque[float] = deque(maxlen=window_size)
        self._throughput_samples: deque[tuple[datetime, int]] = deque(maxlen=window_size)
        self._error_counts: deque[tuple[datetime, bool]] = deque(maxlen=window_size)
        self._resource_samples: deque[ResourceMetrics] = deque(maxlen=window_size)

    def record_latency(self, latency_ms: float) -> None:
        """Record operation latency."""
        self._latencies.append(latency_ms)

    def record_throughput(self, count: int) -> None:
        """Record throughput sample."""
        self._throughput_samples.append((utc_now(), count))

    def record_operation(self, success: bool) -> None:
        """Record operation success/failure."""
        self._error_counts.append((utc_now(), not success))

    def record_resources(self, metrics: ResourceMetrics) -> None:
        """Record resource metrics."""
        self._resource_samples.append(metrics)

    def get_latency_stats(self) -> dict[str, float]:
        """Get latency statistics."""
        if not self._latencies:
            return {"avg": 0, "p50": 0, "p95": 0, "p99": 0, "max": 0}

        sorted_latencies = sorted(self._latencies)
        n = len(sorted_latencies)

        return {
            "avg": sum(sorted_latencies) / n,
            "p50": sorted_latencies[n // 2],
            "p95": sorted_latencies[int(n * 0.95)],
            "p99": sorted_latencies[int(n * 0.99)],
            "max": sorted_latencies[-1],
        }

    def get_error_rate(self, window_seconds: int = 60) -> float:
        """Get error rate over time window."""
        cutoff = utc_now() - timedelta(seconds=window_seconds)
        recent = [(ts, err) for ts, err in self._error_counts if ts > cutoff]

        if not recent:
            return 0.0

        errors = sum(1 for _, err in recent if err)
        return errors / len(recent)

    def get_throughput(self) -> float:
        """Get current throughput (ops/sec)."""
        if len(self._throughput_samples) < 2:
            return 0.0

        first_ts, _ = self._throughput_samples[0]
        last_ts, _ = self._throughput_samples[-1]
        duration = (last_ts - first_ts).total_seconds()

        if duration <= 0:
            return 0.0

        total = sum(count for _, count in self._throughput_samples)
        return total / duration

    def get_summary(self) -> dict[str, Any]:
        """Get performance summary."""
        latency_stats = self.get_latency_stats()
        return {
            "latency": latency_stats,
            "throughput_ops_sec": self.get_throughput(),
            "error_rate": self.get_error_rate(),
            "samples_collected": len(self._latencies),
        }


class PerformanceOptimizer:
    """Optimizes system performance based on metrics."""

    def __init__(self):
        self.rate_limiters: dict[str, RateLimiter] = {}
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.caches: dict[str, CacheManager] = {}
        self.monitor = PerformanceMonitor()

    def create_rate_limiter(
        self,
        name: str,
        rate: float,
        capacity: int,
    ) -> RateLimiter:
        """Create named rate limiter."""
        limiter = RateLimiter(rate=rate, capacity=capacity)
        self.rate_limiters[name] = limiter
        return limiter

    def create_circuit_breaker(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> CircuitBreaker:
        """Create named circuit breaker."""
        breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )
        self.circuit_breakers[name] = breaker
        return breaker

    def create_cache(
        self,
        name: str,
        max_size: int = 1000,
        default_ttl: int = 300,
    ) -> CacheManager:
        """Create named cache."""
        cache = CacheManager(max_size=max_size, default_ttl=default_ttl)
        self.caches[name] = cache
        return cache

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all performance metrics."""
        return {
            "monitor": self.monitor.get_summary(),
            "rate_limiters": {
                name: rl.get_metrics() for name, rl in self.rate_limiters.items()
            },
            "circuit_breakers": {
                name: cb.get_state() for name, cb in self.circuit_breakers.items()
            },
            "caches": {
                name: cache.get_metrics() for name, cache in self.caches.items()
            },
        }


# Singleton
_optimizer: PerformanceOptimizer | None = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get performance optimizer singleton."""
    global _optimizer
    if _optimizer is None:
        _optimizer = PerformanceOptimizer()
    return _optimizer
