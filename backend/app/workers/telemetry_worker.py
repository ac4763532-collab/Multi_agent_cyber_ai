"""Background Telemetry Processing Worker consuming from Kafka / Redpanda and persisting events."""

import asyncio
import json
from typing import Any

from aiokafka import AIOKafkaConsumer  # type: ignore[import-untyped]
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.broker import KafkaTopic, get_broker_manager
from backend.app.core.logging import get_logger
from backend.app.core.redis import get_redis_manager
from backend.app.database.session import get_session_maker
from backend.app.ingestion.resilience.dead_letter import get_dlq_manager
from backend.app.ingestion.resilience.retry import retry_async
from backend.app.models.event import SecurityEventModel
from backend.app.schemas.events import SecurityEvent, validate_security_event_safely

logger = get_logger("cyber_ai.workers.telemetry")


class TelemetryProcessingWorker:
    """Consumes normalized security events from Kafka/Redpanda, persists to DB and caches in Redis."""

    def __init__(
        self,
        group_id: str = "cyber-ai-telemetry-workers",
        batch_size: int = 50,
        poll_timeout_ms: int = 1000,
    ) -> None:
        self.group_id = group_id
        self.batch_size = batch_size
        self.poll_timeout_ms = poll_timeout_ms
        self._consumer: AIOKafkaConsumer | None = None
        self._is_running: bool = False
        self._task: asyncio.Task[None] | None = None
        self._processed_count: int = 0
        self._error_count: int = 0

    @property
    def is_running(self) -> bool:
        """Return worker running status."""
        return self._is_running

    @property
    def processed_count(self) -> int:
        """Return total count of processed events."""
        return self._processed_count

    @property
    def error_count(self) -> int:
        """Return total count of failed events."""
        return self._error_count

    async def process_event(
        self, event_data: dict[str, Any], session: AsyncSession | None = None
    ) -> bool:
        """Process a single event: validate, persist to PostgreSQL and cache in Redis."""
        # 1. Validation
        val_result = validate_security_event_safely(event_data)
        if not val_result.is_valid or val_result.event is None:
            logger.warning("Worker received invalid event payload: %s", val_result.error_message)
            dlq = get_dlq_manager()
            await dlq.handle_invalid_event(
                raw_payload=event_data,
                error_message=val_result.error_message or "Worker validation failure",
                error_type="worker_validation_error",
                source="telemetry_worker",
                validation_errors=val_result.validation_errors,
            )
            self._error_count += 1
            return False

        sec_event: SecurityEvent = val_result.event

        # 2. Database Persistence
        try:

            async def _persist() -> None:
                if session is not None:
                    db_model = SecurityEventModel(**sec_event.to_db_dict())
                    session.add(db_model)
                    await session.flush()
                else:
                    session_maker = get_session_maker()
                    async with session_maker() as db_session:
                        async with db_session.begin():
                            db_model = SecurityEventModel(**sec_event.to_db_dict())
                            db_session.add(db_model)

            await retry_async(_persist, max_retries=3, initial_delay=0.05)
        except Exception as db_exc:
            logger.error(
                "Failed to persist event %s to database: %s", sec_event.event_id, str(db_exc)
            )
            dlq = get_dlq_manager()
            await dlq.handle_invalid_event(
                raw_payload=event_data,
                error_message=f"Database persistence failure: {str(db_exc)}",
                error_type="database_persistence_error",
                source=sec_event.source,
                source_type=sec_event.source_type,
            )
            self._error_count += 1
            return False

        # 3. Publish Redis Notification / Cache
        try:
            redis_mgr = get_redis_manager()
            sev_str = (
                sec_event.severity.value
                if hasattr(sec_event.severity, "value")
                else str(sec_event.severity)
            )
            await redis_mgr.set(
                key=f"event:latest:{sec_event.event_id}",
                value=json.dumps(
                    {
                        "event_id": sec_event.event_id,
                        "timestamp": sec_event.timestamp.isoformat(),
                        "source": sec_event.source,
                        "source_type": sec_event.source_type,
                        "event_type": sec_event.event_type,
                        "severity": sev_str,
                    }
                ),
                expire_seconds=3600,
            )
        except Exception as redis_exc:
            logger.debug("Redis cache notification skipped: %s", str(redis_exc))

        self._processed_count += 1
        return True

    async def start(self) -> None:
        """Start async Kafka consumer loop."""
        if self._is_running:
            return

        self._is_running = True
        try:
            broker = get_broker_manager()
            self._consumer = broker.create_consumer(
                topics=[KafkaTopic.SECURITY_EVENTS],
                group_id=self.group_id,
            )
            await self._consumer.start()
            logger.info(
                "TelemetryProcessingWorker started on topic '%s'",
                KafkaTopic.SECURITY_EVENTS.value,
            )
            self._task = asyncio.create_task(self._consume_loop())
        except Exception as exc:
            logger.warning(
                "Could not start Kafka consumer in TelemetryProcessingWorker: %s (running in passive mode)",
                str(exc),
            )
            self._is_running = False

    async def _consume_loop(self) -> None:
        """Internal message consumption loop."""
        if not self._consumer:
            return

        try:
            while self._is_running:
                data = await self._consumer.getmany(
                    timeout_ms=self.poll_timeout_ms,
                    max_records=self.batch_size,
                )
                for _tp, messages in data.items():
                    for msg in messages:
                        if not self._is_running:
                            break
                        try:
                            payload = msg.value
                            await self.process_event(payload)
                        except Exception as e:
                            logger.error("Error processing consumed message: %s", str(e))
                            self._error_count += 1

                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Telemetry worker consume loop error: %s", str(exc))
        finally:
            self._is_running = False

    async def stop(self) -> None:
        """Stop worker and close consumer connection."""
        self._is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception as e:
                logger.warning("Error stopping worker consumer: %s", str(e))
            finally:
                self._consumer = None

        logger.info(
            "TelemetryProcessingWorker stopped (processed=%d, errors=%d)",
            self._processed_count,
            self._error_count,
        )
