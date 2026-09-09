"""Observability and telemetry package."""

from backend.app.observability.metrics import (
    AGENT_EXECUTION_TOTAL,
    EVENT_PROCESSING_LATENCY,
    EVENTS_INGESTED_TOTAL,
    EVENTS_NORMALIZED_TOTAL,
    SYSTEM_UPTIME_SECONDS,
    get_uptime_seconds,
)

__all__ = [
    "AGENT_EXECUTION_TOTAL",
    "EVENT_PROCESSING_LATENCY",
    "EVENTS_INGESTED_TOTAL",
    "EVENTS_NORMALIZED_TOTAL",
    "SYSTEM_UPTIME_SECONDS",
    "get_uptime_seconds",
]
