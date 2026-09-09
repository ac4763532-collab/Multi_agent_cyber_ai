"""Real-time metrics tracking and performance counters for telemetry ingestion."""

import asyncio
import time
from collections import deque
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.observability.metrics import (
    DEAD_LETTER_EVENTS_TOTAL,
    EVENT_PROCESSING_LATENCY,
    EVENTS_INGESTED_TOTAL,
    EVENTS_NORMALIZED_TOTAL,
    EVENTS_REJECTED_TOTAL,
    INGESTION_EPS_GAUGE,
)

logger = get_logger("cyber_ai.ingestion.metrics")


class IngestionMetricsTracker:
    """In-memory high-performance metrics collector for telemetry ingestion rates."""

    def __init__(self, window_sec: float = 5.0, max_latency_samples: int = 2000) -> None:
        self.window_sec = window_sec
        self.max_latency_samples = max_latency_samples

        self._events_received: int = 0
        self._events_accepted: int = 0
        self._events_rejected: int = 0

        self._by_source: dict[str, int] = {}
        self._by_severity: dict[str, int] = {}

        # Deque of timestamps for sliding-window EPS calculation
        self._timestamps: deque[float] = deque()
        # Deque of (timestamp, latency_ms) samples
        self._latencies_ms: deque[float] = deque(maxlen=max_latency_samples)

        self._lock = asyncio.Lock()
        self._start_time = time.time()

    def record_received(self, source_type: str = "unknown", count: int = 1) -> None:
        """Record incoming raw telemetry event(s)."""
        self._events_received += count
        now = time.perf_counter()
        for _ in range(count):
            self._timestamps.append(now)

        try:
            EVENTS_INGESTED_TOTAL.labels(source_type=source_type).inc(count)
        except Exception as exc:
            logger.debug("Prometheus metric update skipped: %s", str(exc))

    def record_accepted(
        self,
        source_type: str,
        severity: str,
        latency_ms: float,
    ) -> None:
        """Record successfully validated and normalized telemetry event."""
        self._events_accepted += 1
        self._by_source[source_type] = self._by_source.get(source_type, 0) + 1
        self._by_severity[severity] = self._by_severity.get(severity, 0) + 1
        self._latencies_ms.append(latency_ms)

        try:
            EVENTS_NORMALIZED_TOTAL.labels(domain=source_type).inc(1)
            EVENT_PROCESSING_LATENCY.labels(pipeline_stage="ingestion_normalization").observe(
                latency_ms / 1000.0
            )
        except Exception as exc:
            logger.debug("Prometheus metric update skipped: %s", str(exc))

    def record_rejected(
        self,
        source_type: str = "unknown",
        latency_ms: float = 0.0,
        error_type: str = "validation_error",
    ) -> None:
        """Record rejected / invalid telemetry event."""
        self._events_rejected += 1
        if latency_ms > 0:
            self._latencies_ms.append(latency_ms)

        try:
            EVENTS_REJECTED_TOTAL.labels(source_type=source_type, error_type=error_type).inc()
            DEAD_LETTER_EVENTS_TOTAL.labels(error_type=error_type).inc()
        except Exception as exc:
            logger.debug("Prometheus metric update skipped: %s", str(exc))

    def calculate_eps(self) -> float:
        """Calculate events per second over current sliding window."""
        now = time.perf_counter()
        cutoff = now - self.window_sec

        # Purge stale timestamps
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

        return round(len(self._timestamps) / max(self.window_sec, 0.001), 2)

    def get_latency_stats(self) -> dict[str, float]:
        """Calculate latency distribution statistics in milliseconds."""
        if not self._latencies_ms:
            return {"avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0}

        samples = sorted(self._latencies_ms)
        n = len(samples)
        avg_val = sum(samples) / n
        min_val = samples[0]
        max_val = samples[-1]
        p95_idx = min(int(n * 0.95), n - 1)
        p99_idx = min(int(n * 0.99), n - 1)

        return {
            "avg_ms": round(avg_val, 3),
            "min_ms": round(min_val, 3),
            "max_ms": round(max_val, 3),
            "p95_ms": round(samples[p95_idx], 3),
            "p99_ms": round(samples[p99_idx], 3),
        }

    def get_snapshot(self) -> dict[str, Any]:
        """Return comprehensive metrics snapshot."""
        eps = self.calculate_eps()
        latencies = self.get_latency_stats()
        uptime_sec = time.time() - self._start_time
        try:
            INGESTION_EPS_GAUGE.set(eps)
        except Exception as exc:
            logger.debug("Prometheus EPS gauge update skipped: %s", str(exc))

        return {
            "events_received": self._events_received,
            "events_accepted": self._events_accepted,
            "events_rejected": self._events_rejected,
            "acceptance_rate_pct": round(
                (self._events_accepted / max(self._events_received, 1)) * 100, 2
            ),
            "events_per_second": eps,
            "latency_ms": latencies,
            "processing_latency": latencies,
            "by_source": dict(self._by_source),
            "by_severity": dict(self._by_severity),
            "uptime_seconds": round(uptime_sec, 1),
        }

    def reset(self) -> None:
        """Reset internal metric counters (useful for isolated benchmark runs)."""
        self._events_received = 0
        self._events_accepted = 0
        self._events_rejected = 0
        self._by_source.clear()
        self._by_severity.clear()
        self._timestamps.clear()
        self._latencies_ms.clear()
        self._start_time = time.time()


_metrics_tracker: IngestionMetricsTracker | None = None


def get_metrics_tracker() -> IngestionMetricsTracker:
    """Return singleton IngestionMetricsTracker instance."""
    global _metrics_tracker
    if _metrics_tracker is None:
        _metrics_tracker = IngestionMetricsTracker()
    return _metrics_tracker
