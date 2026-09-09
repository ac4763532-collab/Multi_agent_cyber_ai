"""Base telemetry collector implementation."""

from typing import Any

from backend.app.ingestion.interfaces import TelemetryCollector, TelemetrySourceType
from backend.app.ingestion.pipeline import IngestionPipeline, get_ingestion_pipeline


class BaseCollector(TelemetryCollector):
    """Base collector delegating to IngestionPipeline with uniform diagnostics."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        self.pipeline = pipeline or get_ingestion_pipeline()

    async def collect(
        self,
        raw_payload: Any,
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest single telemetry payload."""
        return await self.pipeline.ingest_single(
            raw_payload=raw_payload,
            source_type=source_type,
            source_identifier=source_identifier or self.collector_name,
        )

    async def collect_batch(
        self,
        raw_payloads: list[Any],
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest batch of telemetry payloads."""
        return await self.pipeline.ingest_batch(
            raw_payloads=raw_payloads,
            source_type=source_type,
            source_identifier=source_identifier or self.collector_name,
        )
