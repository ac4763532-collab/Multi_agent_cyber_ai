"""Real-time Security Telemetry Ingestion Layer."""

from backend.app.ingestion.collectors import (
    ApplicationLogCollector,
    AuthenticationLogCollector,
    BaseCollector,
    EmailSecurityCollector,
    HttpTelemetryCollector,
    JsonEventCollector,
    SuricataCollector,
    SyslogCollector,
)
from backend.app.ingestion.interfaces import (
    DeadLetterHandler,
    EventNormalizer,
    EventParser,
    ParsedEvent,
    TelemetryCollector,
    TelemetrySourceType,
)
from backend.app.ingestion.metrics import IngestionMetricsTracker, get_metrics_tracker
from backend.app.ingestion.pipeline import IngestionPipeline, get_ingestion_pipeline
from backend.app.ingestion.registry import IngestionRegistry, get_ingestion_registry
from backend.app.ingestion.resilience import (
    BackpressureController,
    BackpressureExceededError,
    DeadLetterQueueManager,
    RateLimiter,
    get_dlq_manager,
    retry_async,
    with_retry,
)

__all__ = [
    "BackpressureController",
    "BackpressureExceededError",
    "ApplicationLogCollector",
    "AuthenticationLogCollector",
    "BaseCollector",
    "EmailSecurityCollector",
    "HttpTelemetryCollector",
    "JsonEventCollector",
    "SuricataCollector",
    "SyslogCollector",
    "DeadLetterHandler",
    "DeadLetterQueueManager",
    "EventNormalizer",
    "EventParser",
    "HttpTelemetryCollector",
    "IngestionMetricsTracker",
    "IngestionPipeline",
    "IngestionRegistry",
    "ParsedEvent",
    "RateLimiter",
    "TelemetryCollector",
    "TelemetrySourceType",
    "get_dlq_manager",
    "get_ingestion_pipeline",
    "get_ingestion_registry",
    "get_metrics_tracker",
    "retry_async",
    "with_retry",
]
