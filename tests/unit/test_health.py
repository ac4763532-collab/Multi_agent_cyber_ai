"""Unit tests for health schemas and status logic."""

from datetime import UTC, datetime

from backend.app.schemas.health import HealthResponse, SubsystemStatus


def test_subsystem_status_schema() -> None:
    """Verify SubsystemStatus validation with various status states."""
    subsystem = SubsystemStatus(
        status="healthy",
        latency_ms=1.23,
        details={"info": "operational"},
    )
    assert subsystem.status == "healthy"
    assert subsystem.latency_ms == 1.23
    assert subsystem.details["info"] == "operational"


def test_health_response_schema() -> None:
    """Verify HealthResponse model serializes correctly."""
    now = datetime.now(UTC)
    response = HealthResponse(
        status="healthy",
        app_name="Multi-Agent Cyber AI",
        version="0.1.0",
        environment="test",
        timestamp=now,
        uptime_seconds=42.5,
        services={
            "database": SubsystemStatus(status="healthy", latency_ms=0.5),
            "event_broker": SubsystemStatus(status="healthy", latency_ms=0.8),
        },
    )

    data = response.model_dump()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert data["services"]["database"]["status"] == "healthy"
    assert data["services"]["event_broker"]["latency_ms"] == 0.8
