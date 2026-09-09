"""End-to-end Real-Time Security Telemetry Ingestion Pipeline."""

import asyncio
import time
from typing import Any

from backend.app.core.broker import KafkaTopic, get_broker_manager
from backend.app.core.logging import get_logger
from backend.app.ingestion.interfaces import (
    DeadLetterHandler,
    EventNormalizer,
    EventParser,
    ParsedEvent,
    TelemetrySourceType,
)
from backend.app.ingestion.metrics import IngestionMetricsTracker, get_metrics_tracker
from backend.app.ingestion.registry import IngestionRegistry, get_ingestion_registry
from backend.app.ingestion.resilience.backpressure import (
    BackpressureController,
    BackpressureExceededError,
)
from backend.app.ingestion.resilience.dead_letter import (
    DeadLetterQueueManager,
    get_dlq_manager,
)
from backend.app.ingestion.resilience.retry import retry_async
from backend.app.schemas.events import SecurityEvent, validate_security_event_safely

logger = get_logger("cyber_ai.ingestion.pipeline")


class IngestionPipeline:
    """Master telemetry ingestion pipeline: Collector -> Validation -> Normalization -> Kafka -> Workers."""

    def __init__(
        self,
        registry: IngestionRegistry | None = None,
        dlq_manager: DeadLetterHandler | None = None,
        metrics_tracker: IngestionMetricsTracker | None = None,
        backpressure: BackpressureController | None = None,
        publish_to_broker: bool = True,
    ) -> None:
        self.registry = registry or get_ingestion_registry()
        self.dlq_manager = dlq_manager or get_dlq_manager()
        self.metrics = metrics_tracker or get_metrics_tracker()
        self.backpressure = backpressure or BackpressureController()
        self.publish_to_broker = publish_to_broker

    async def _handle_rejection(
        self,
        raw_payload: Any,
        error_msg: str,
        error_type: str,
        source_identifier: str | None,
        source_label: str,
        start_time: float,
        validation_errors: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Record rejected telemetry to metrics and dead-letter queue."""
        latency_ms = (time.perf_counter() - start_time) * 1000
        self.metrics.record_rejected(
            source_type=source_label,
            latency_ms=latency_ms,
            error_type=error_type,
        )
        dlq_record = await self.dlq_manager.handle_invalid_event(
            raw_payload=raw_payload,
            error_message=error_msg,
            error_type=error_type,
            source=source_identifier or source_label,
            source_type=source_label,
            validation_errors=validation_errors,
        )
        return {
            "status": "rejected",
            "error": error_msg,
            "error_type": error_type,
            "validation_errors": validation_errors or [],
            "dead_letter_id": dlq_record.get("dead_letter_id"),
            "is_valid": False,
            "latency_ms": round(latency_ms, 3),
        }

    async def _publish_safely(self, security_event: SecurityEvent) -> None:
        """Publish canonical event to Kafka topic with retry; never crash the pipeline."""
        if not self.publish_to_broker:
            return

        async def _publish() -> None:
            broker = get_broker_manager()
            await broker.publish_event(
                topic=KafkaTopic.SECURITY_EVENTS,
                payload=security_event.model_dump(mode="json"),
                key=security_event.event_id,
            )

        try:
            await retry_async(_publish, max_retries=3, initial_delay=0.05)
        except Exception as exc:
            logger.warning(
                "Broker publish failed after retries [%s]: %s (pipeline continues)",
                security_event.event_id,
                str(exc),
            )

    async def ingest_single(
        self,
        raw_payload: Any,
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Process a single raw telemetry payload through full validation and normalization."""
        if isinstance(raw_payload, (bytes, bytearray)):
            try:
                raw_payload = raw_payload.decode("utf-8")
            except UnicodeDecodeError:
                pass

        start_time = time.perf_counter()
        st_resolved = (
            source_type
            if isinstance(source_type, TelemetrySourceType)
            else (TelemetrySourceType.from_str(source_type) if source_type else None)
        )
        source_label = st_resolved.value if st_resolved else "unknown"
        self.metrics.record_received(source_type=source_label, count=1)

        # 1. Backpressure guard
        try:
            await self.backpressure.try_acquire(batch_size=1)
        except BackpressureExceededError as exc:
            return await self._handle_rejection(
                raw_payload,
                exc.message,
                "backpressure_exceeded",
                source_identifier,
                source_label,
                start_time,
            )

        try:
            # 2. Source resolution
            if st_resolved is None or st_resolved == TelemetrySourceType.UNKNOWN:
                st_resolved = self.registry.detect_source_type(raw_payload)

            if st_resolved == TelemetrySourceType.UNKNOWN:
                return await self._handle_rejection(
                    raw_payload,
                    "Could not auto-detect telemetry source format",
                    "unknown_source_format",
                    source_identifier,
                    "unknown",
                    start_time,
                )

            # 3. Parsing
            parser: EventParser | None = self.registry.get_parser(st_resolved)
            if not parser:
                return await self._handle_rejection(
                    raw_payload,
                    f"No parser registered for source '{st_resolved.value}'",
                    "parser_not_found",
                    source_identifier,
                    st_resolved.value,
                    start_time,
                )

            try:
                parsed_event: ParsedEvent = parser.parse(raw_payload)
            except Exception as parse_exc:
                return await self._handle_rejection(
                    raw_payload,
                    f"Parsing exception: {parse_exc}",
                    "parsing_exception",
                    source_identifier,
                    st_resolved.value,
                    start_time,
                )

            # 4. Normalization
            normalizer: EventNormalizer | None = self.registry.get_normalizer(st_resolved)
            if not normalizer:
                return await self._handle_rejection(
                    raw_payload,
                    f"No normalizer registered for source '{st_resolved.value}'",
                    "normalizer_not_found",
                    source_identifier,
                    st_resolved.value,
                    start_time,
                )

            try:
                security_event: SecurityEvent = normalizer.normalize(parsed_event)
            except Exception as norm_exc:
                return await self._handle_rejection(
                    raw_payload,
                    f"Normalization exception: {norm_exc}",
                    "normalization_exception",
                    source_identifier,
                    st_resolved.value,
                    start_time,
                )

            # 5. Safe validation check
            val_result = validate_security_event_safely(security_event.model_dump(mode="json"))
            if not val_result.is_valid:
                return await self._handle_rejection(
                    raw_payload,
                    val_result.error_message or "Validation failed",
                    "schema_validation_error",
                    source_identifier,
                    security_event.source_type,
                    start_time,
                    val_result.validation_errors,
                )

            # 6. Publish to Kafka
            await self._publish_safely(security_event)

            # 7. Record success metrics
            latency_ms = (time.perf_counter() - start_time) * 1000
            sev_str = (
                security_event.severity.value
                if hasattr(security_event.severity, "value")
                else str(security_event.severity)
            )
            self.metrics.record_accepted(
                source_type=security_event.source_type,
                severity=sev_str,
                latency_ms=latency_ms,
            )

            return {
                "status": "accepted",
                "is_valid": True,
                "event_id": security_event.event_id,
                "source": security_event.source,
                "source_type": security_event.source_type,
                "event_type": security_event.event_type,
                "severity": sev_str,
                "timestamp": security_event.timestamp.isoformat(),
                "latency_ms": round(latency_ms, 3),
                "event": security_event,
            }

        finally:
            self.backpressure.release(batch_size=1)

    async def ingest_batch(
        self,
        raw_payloads: list[Any],
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
        max_concurrency: int = 50,
    ) -> dict[str, Any]:
        """Process a batch of telemetry events with concurrent worker tasks."""
        start_time = time.perf_counter()
        total = len(raw_payloads)
        if total == 0:
            return {
                "total": 0,
                "accepted": 0,
                "rejected": 0,
                "duration_ms": 0.0,
                "events_per_second": 0.0,
                "results": [],
            }

        semaphore = asyncio.Semaphore(max_concurrency)

        async def _process_item(item: Any) -> dict[str, Any]:
            async with semaphore:
                return await self.ingest_single(
                    raw_payload=item,
                    source_type=source_type,
                    source_identifier=source_identifier,
                )

        results = await asyncio.gather(*[_process_item(p) for p in raw_payloads])

        accepted_count = sum(1 for r in results if r.get("status") == "accepted")
        rejected_count = total - accepted_count
        duration_ms = (time.perf_counter() - start_time) * 1000
        batch_eps = round(total / (max(duration_ms, 1) / 1000.0), 2)

        return {
            "total": total,
            "accepted": accepted_count,
            "rejected": rejected_count,
            "duration_ms": round(duration_ms, 2),
            "events_per_second": batch_eps,
            "results": results,
        }


_ingestion_pipeline: IngestionPipeline | None = None


def get_ingestion_pipeline() -> IngestionPipeline:
    """Return singleton IngestionPipeline instance."""
    global _ingestion_pipeline
    if _ingestion_pipeline is None:
        _ingestion_pipeline = IngestionPipeline()
    return _ingestion_pipeline
