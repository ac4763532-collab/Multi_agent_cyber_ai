"""HTTP REST & Webhook Telemetry Collector Adapter."""

from backend.app.ingestion.collectors.base import BaseCollector
from backend.app.ingestion.pipeline import IngestionPipeline


class HttpTelemetryCollector(BaseCollector):
    """Collector receiving security events via HTTP REST and Webhook endpoints."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(pipeline=pipeline)

    @property
    def collector_name(self) -> str:
        return "http_telemetry_collector"


_http_collector: HttpTelemetryCollector | None = None


def get_http_collector() -> HttpTelemetryCollector:
    """Return singleton HTTP telemetry collector."""
    global _http_collector
    if _http_collector is None:
        _http_collector = HttpTelemetryCollector()
    return _http_collector
