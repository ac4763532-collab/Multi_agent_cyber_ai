"""Platform Prometheus metrics and telemetry telemetry collectors."""

import time

from prometheus_client import Counter, Gauge, Histogram

# Ingestion metrics
EVENTS_INGESTED_TOTAL = Counter(
    "cyber_ai_events_ingested_total",
    "Total raw security events ingested across all endpoints",
    ["source_type"],
)

EVENTS_NORMALIZED_TOTAL = Counter(
    "cyber_ai_events_normalized_total",
    "Total security events normalized into ECS/OCSF schema",
    ["domain"],
)

EVENTS_REJECTED_TOTAL = Counter(
    "cyber_ai_events_rejected_total",
    "Total security events rejected due to validation or parsing errors",
    ["source_type", "error_type"],
)

DEAD_LETTER_EVENTS_TOTAL = Counter(
    "cyber_ai_dead_letter_events_total",
    "Total events routed to dead-letter queue topic",
    ["error_type"],
)

INGESTION_EPS_GAUGE = Gauge(
    "cyber_ai_ingestion_eps_gauge",
    "Current real-time telemetry ingestion events per second",
)

# Latency metrics
EVENT_PROCESSING_LATENCY = Histogram(
    "cyber_ai_event_processing_latency_seconds",
    "End-to-end event processing latency in seconds",
    ["pipeline_stage"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Agent performance metrics
AGENT_EXECUTION_TOTAL = Counter(
    "cyber_ai_agent_execution_total",
    "Total executions per autonomous agent",
    ["agent_name", "status"],
)

# System health gauges
SYSTEM_UPTIME_SECONDS = Gauge(
    "cyber_ai_system_uptime_seconds",
    "Time since platform startup in seconds",
)

_START_TIME = time.time()


def get_uptime_seconds() -> float:
    """Return process uptime in seconds."""
    return time.time() - _START_TIME
