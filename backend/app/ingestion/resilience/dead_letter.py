"""Dead-Letter Queue (DLQ) manager and topic publisher for rejected/malformed telemetry."""

import uuid
from collections import deque
from typing import Any

from backend.app.core.broker import KafkaTopic, get_broker_manager
from backend.app.core.logging import get_logger
from backend.app.ingestion.interfaces import DeadLetterHandler
from backend.app.utils.datetime import utc_now

logger = get_logger("cyber_ai.ingestion.dead_letter")


class DeadLetterQueueManager(DeadLetterHandler):
    """Manages rejection diagnostics, publishes to DLQ topic, and maintains buffer."""

    def __init__(self, max_buffer_size: int = 1000) -> None:
        self.max_buffer_size = max_buffer_size
        self._dlq_buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer_size)
        self._total_dead_letters: int = 0

    @property
    def total_count(self) -> int:
        """Return total count of dead letter events recorded since startup."""
        return self._total_dead_letters

    async def handle_invalid_event(
        self,
        raw_payload: Any,
        error_message: str,
        error_type: str = "validation_error",
        source: str = "unknown",
        source_type: str = "unknown",
        validation_errors: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Construct dead-letter diagnostic record, store in buffer, and publish to DLQ."""
        self._total_dead_letters += 1
        dead_letter_id = f"dlq-{uuid.uuid4()}"
        now = utc_now()

        # Sanitize / serialize raw payload
        sanitized_payload = (
            raw_payload
            if isinstance(raw_payload, (dict, list, str, int, float, bool)) or raw_payload is None
            else str(raw_payload)
        )

        dlq_record: dict[str, Any] = {
            "dead_letter_id": dead_letter_id,
            "timestamp": now.isoformat(),
            "source": source,
            "source_type": source_type,
            "error_type": error_type,
            "error_message": error_message,
            "validation_errors": validation_errors or [],
            "raw_payload": sanitized_payload,
            "context": context or {},
        }

        # Store in circular buffer
        self._dlq_buffer.append(dlq_record)

        logger.warning(
            "Telemetry rejected [%s]: error_type=%s, source=%s, reason=%s",
            dead_letter_id,
            error_type,
            source,
            error_message,
        )

        # Attempt to publish to broker dead-letter topic (non-blocking failure)
        try:
            broker = get_broker_manager()
            await broker.publish_event(
                topic=KafkaTopic.DEAD_LETTER,
                payload=dlq_record,
                key=dead_letter_id,
            )
        except Exception as exc:
            logger.debug(
                "DLQ broker publish skipped [%s]: %s (buffered locally)",
                dead_letter_id,
                str(exc),
            )

        return dlq_record

    def get_recent(self, limit: int = 50, error_type: str | None = None) -> list[dict[str, Any]]:
        """Retrieve recent dead-letter events from circular buffer."""
        items = list(self._dlq_buffer)
        if error_type:
            items = [item for item in items if item.get("error_type") == error_type]
        # Return most recent first
        return list(reversed(items))[:limit]

    def clear(self) -> None:
        """Clear local dead-letter buffer."""
        self._dlq_buffer.clear()


_dlq_manager: DeadLetterQueueManager | None = None


def get_dlq_manager() -> DeadLetterQueueManager:
    """Return singleton DeadLetterQueueManager instance."""
    global _dlq_manager
    if _dlq_manager is None:
        _dlq_manager = DeadLetterQueueManager()
    return _dlq_manager
