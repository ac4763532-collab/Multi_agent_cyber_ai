"""Message Broker Manager for Kafka / Redpanda event streaming."""

import asyncio
import json
import socket
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from enum import StrEnum
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore[import-untyped]
from aiokafka.errors import KafkaError  # type: ignore[import-untyped]

from backend.app.config.settings import Settings, get_settings
from backend.app.core.exceptions import BrokerError
from backend.app.core.logging import get_logger

logger = get_logger("cyber_ai.broker")


class KafkaTopic(StrEnum):
    """Standardized event stream topic registry for the multi-agent SOC platform."""

    SECURITY_EVENTS = "security-events"
    AGENT_TASKS = "agent-tasks"
    AGENT_RESULTS = "agent-results"
    CORRELATIONS = "correlations"
    INCIDENTS = "incidents"
    ALERTS = "alerts"
    DEAD_LETTER = "dead-letter"

    @classmethod
    def list_all(cls) -> list[str]:
        """Return list of all registered topic names."""
        return [t.value for t in cls]


class BrokerManager:
    """Asynchronous Kafka / Redpanda message broker connection & lifecycle manager."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._producer: AIOKafkaProducer | None = None
        self._is_started: bool = False
        self._lock = asyncio.Lock()

    async def get_producer(self) -> AIOKafkaProducer:
        """Return initialized and started AIOKafkaProducer singleton with retry logic."""
        if self._producer is not None and self._is_started:
            return self._producer

        async with self._lock:
            if self._producer is not None and self._is_started:
                return self._producer

            retries = self.settings.kafka_retries
            delay = self.settings.kafka_retry_backoff_ms / 1000.0

            for attempt in range(1, retries + 1):
                try:
                    logger.info(
                        "Connecting to Kafka/Redpanda broker at %s (Attempt %d/%d)",
                        self.settings.kafka_bootstrap_servers,
                        attempt,
                        retries,
                    )
                    producer = AIOKafkaProducer(
                        bootstrap_servers=self.settings.kafka_bootstrap_servers,
                        client_id=self.settings.kafka_client_id,
                        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                        key_serializer=lambda k: k.encode("utf-8") if isinstance(k, str) else k,
                        request_timeout_ms=self.settings.kafka_request_timeout_ms,
                        retry_backoff_ms=self.settings.kafka_retry_backoff_ms,
                    )
                    await producer.start()
                    self._producer = producer
                    self._is_started = True
                    logger.info("Kafka/Redpanda producer successfully started")
                    return self._producer
                except KafkaError as e:
                    logger.warning(
                        "Broker connection attempt %d failed: %s. Retrying in %.2fs",
                        attempt,
                        str(e),
                        delay,
                    )
                    if attempt == retries:
                        raise BrokerError(
                            f"Failed to connect to message broker after {retries} attempts: {e}"
                        ) from e
                    await asyncio.sleep(delay)
                except Exception as e:
                    logger.error("Unexpected error connecting to broker: %s", str(e))
                    raise BrokerError(f"Unexpected broker error: {e}") from e

            raise BrokerError("Broker connection could not be established")

    async def publish_event(
        self,
        topic: KafkaTopic | str,
        payload: dict[str, Any],
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Publish event message to the designated Kafka/Redpanda topic."""
        topic_name = topic.value if isinstance(topic, KafkaTopic) else topic
        raw_headers = [(k, v.encode("utf-8")) for k, v in headers.items()] if headers else None

        try:
            producer = await self.get_producer()
            record_metadata = await producer.send_and_wait(
                topic=topic_name,
                value=payload,
                key=key,
                headers=raw_headers,
            )
            return record_metadata
        except Exception as e:
            logger.error("Failed to publish event to topic %s: %s", topic_name, str(e))
            raise BrokerError(f"Publish failed for topic {topic_name}: {e}") from e

    def create_consumer(
        self,
        topics: list[KafkaTopic | str],
        group_id: str,
        auto_offset_reset: str | None = None,
    ) -> AIOKafkaConsumer:
        """Create configured AIOKafkaConsumer instance for subscriber workers."""
        topic_names = [t.value if isinstance(t, KafkaTopic) else t for t in topics]
        return AIOKafkaConsumer(
            *topic_names,
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            group_id=group_id,
            auto_offset_reset=auto_offset_reset or self.settings.kafka_auto_offset_reset,
            enable_auto_commit=self.settings.kafka_enable_auto_commit,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            request_timeout_ms=self.settings.kafka_request_timeout_ms,
        )

    async def check_broker_health(self) -> tuple[bool, float, dict[str, Any]]:
        """Probe message broker connectivity and return (is_healthy, latency_ms, details)."""
        start_time = time.perf_counter()
        bootstrap = self.settings.kafka_bootstrap_servers

        try:
            # First perform socket ping to verify host and port are accepting TCP
            host, port_str = bootstrap.split(":", 1)
            port = int(port_str)

            # Test TCP connection with short timeout
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: socket.create_connection((host, port), timeout=1.5).close(),
            )

            latency = (time.perf_counter() - start_time) * 1000
            return (
                True,
                round(latency, 2),
                {
                    "bootstrap_servers": bootstrap,
                    "topics_registered": KafkaTopic.list_all(),
                    "client_id": self.settings.kafka_client_id,
                    "connected": True,
                },
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000
            return (
                False,
                round(latency, 2),
                {
                    "bootstrap_servers": bootstrap,
                    "topics_registered": KafkaTopic.list_all(),
                    "error": str(e),
                    "connected": False,
                },
            )

    async def close(self) -> None:
        """Gracefully terminate producer connections."""
        async with self._lock:
            if self._producer and self._is_started:
                try:
                    await self._producer.stop()
                    logger.info("Kafka/Redpanda producer closed gracefully")
                except Exception as e:
                    logger.warning("Error stopping broker producer: %s", str(e))
                finally:
                    self._producer = None
                    self._is_started = False


_broker_manager: BrokerManager | None = None


def get_broker_manager() -> BrokerManager:
    """Return singleton BrokerManager instance."""
    global _broker_manager
    if _broker_manager is None:
        _broker_manager = BrokerManager()
    return _broker_manager


@asynccontextmanager
async def lifespan_broker() -> AsyncGenerator[BrokerManager, None]:
    """Context manager for broker lifecycle management."""
    manager = get_broker_manager()
    try:
        yield manager
    finally:
        await manager.close()
