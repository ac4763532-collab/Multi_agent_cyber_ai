"""Integration test for health endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_api_health_endpoint(async_client: AsyncClient) -> None:
    """Verify GET /api/health returns 200 OK with expected JSON structure and all subsystems."""
    response = await async_client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert "status" in data
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
    assert data["app_name"] == "Multi-Agent Cyber AI"
    assert data["version"] == "0.1.0"
    assert "services" in data

    # Verify all 5 core subsystems exist in health payload
    assert "database" in data["services"]
    assert "redis" in data["services"]
    assert "message_broker" in data["services"]
    assert "gemini_ai" in data["services"]
    assert "vector_store" in data["services"]

    # Verify message broker details
    broker = data["services"]["message_broker"]
    assert "status" in broker
    assert "details" in broker
    assert "topics_registered" in broker["details"]
    assert len(broker["details"]["topics_registered"]) == 7

    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))

    # Verify custom headers injected by timing/trace middleware
    assert "x-trace-id" in response.headers
    assert "x-response-time-ms" in response.headers


@pytest.mark.asyncio
async def test_get_api_v1_health_endpoint(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/health returns 200 OK with identical schema."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "0.1.0"
    assert "services" in data
    assert "message_broker" in data["services"]
