"""Source-bound collector adapters.

Collectors only ingest and hand off to the pipeline. They must not import
or call detection agents, correlation, or ML modules.
"""

from typing import Any

from backend.app.ingestion.collectors.base import BaseCollector
from backend.app.ingestion.interfaces import TelemetrySourceType
from backend.app.ingestion.pipeline import IngestionPipeline


class SourceBoundCollector(BaseCollector):
    """Collector that pins payloads to a single telemetry source type."""

    def __init__(
        self,
        source_type: TelemetrySourceType,
        name: str,
        pipeline: IngestionPipeline | None = None,
    ) -> None:
        super().__init__(pipeline=pipeline)
        self._bound_source_type = source_type
        self._name = name

    @property
    def collector_name(self) -> str:
        return self._name

    @property
    def source_type(self) -> TelemetrySourceType:
        return self._bound_source_type

    async def collect(
        self,
        raw_payload: Any,
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest a single payload using the bound source type unless overridden."""
        return await super().collect(
            raw_payload=raw_payload,
            source_type=source_type or self._bound_source_type,
            source_identifier=source_identifier or self.collector_name,
        )

    async def collect_batch(
        self,
        raw_payloads: list[Any],
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest a batch using the bound source type unless overridden."""
        return await super().collect_batch(
            raw_payloads=raw_payloads,
            source_type=source_type or self._bound_source_type,
            source_identifier=source_identifier or self.collector_name,
        )


class SyslogCollector(SourceBoundCollector):
    """Adapter for syslog-style security and authentication events."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(TelemetrySourceType.SYSLOG, "syslog_collector", pipeline)


class JsonEventCollector(SourceBoundCollector):
    """Adapter for structured JSON security events."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(TelemetrySourceType.JSON, "json_event_collector", pipeline)


class SuricataCollector(SourceBoundCollector):
    """Adapter for Suricata EVE JSON telemetry."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(TelemetrySourceType.SURICATA, "suricata_collector", pipeline)


class ApplicationLogCollector(SourceBoundCollector):
    """Adapter for application and web access logs."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(TelemetrySourceType.APPLICATION, "application_log_collector", pipeline)


class AuthenticationLogCollector(SourceBoundCollector):
    """Adapter for authentication / IAM / Windows security logs."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(
            TelemetrySourceType.AUTHENTICATION, "authentication_log_collector", pipeline
        )


class EmailSecurityCollector(SourceBoundCollector):
    """Adapter for email security gateway events."""

    def __init__(self, pipeline: IngestionPipeline | None = None) -> None:
        super().__init__(TelemetrySourceType.EMAIL, "email_security_collector", pipeline)
