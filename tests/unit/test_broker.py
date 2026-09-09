"""Unit tests for Message Broker (Kafka / Redpanda) and topic management."""

import pytest

from backend.app.config.settings import Settings
from backend.app.core.broker import BrokerManager, KafkaTopic


def test_kafka_topics_enumeration() -> None:
    """Verify all 7 required Kafka topics are defined with exact naming."""
    topics = KafkaTopic.list_all()
    required_topics = [
        "security-events",
        "agent-tasks",
        "agent-results",
        "correlations",
        "incidents",
        "alerts",
        "dead-letter",
    ]
    for req in required_topics:
        assert req in topics

    assert KafkaTopic.SECURITY_EVENTS == "security-events"
    assert KafkaTopic.AGENT_TASKS == "agent-tasks"
    assert KafkaTopic.AGENT_RESULTS == "agent-results"
    assert KafkaTopic.CORRELATIONS == "correlations"
    assert KafkaTopic.INCIDENTS == "incidents"
    assert KafkaTopic.ALERTS == "alerts"
    assert KafkaTopic.DEAD_LETTER == "dead-letter"


@pytest.mark.asyncio
async def test_broker_manager_health_offline() -> None:
    """Verify BrokerManager returns structured diagnostic details when broker is unreachable."""
    test_settings = Settings(
        app_env="test",
        kafka_bootstrap_servers="127.0.0.1:59999",  # Non-existent port
    )
    manager = BrokerManager(settings=test_settings)
    is_healthy, latency_ms, details = await manager.check_broker_health()

    assert not is_healthy
    assert latency_ms >= 0
    assert "bootstrap_servers" in details
    assert details["bootstrap_servers"] == "127.0.0.1:59999"
    assert "topics_registered" in details
    assert len(details["topics_registered"]) == 7
