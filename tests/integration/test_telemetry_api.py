"""Integration tests for telemetry ingestion API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_telemetry_sources(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/telemetry/sources returns list of supported sources."""
    response = await async_client.get("/api/v1/telemetry/sources")
    assert response.status_code == 200

    data = response.json()
    assert "supported_sources" in data
    assert "total_sources" in data
    assert data["total_sources"] >= 6
    assert "suricata" in data["supported_sources"]
    assert "syslog" in data["supported_sources"]
    assert "json" in data["supported_sources"]
    assert "application" in data["supported_sources"]
    assert "authentication" in data["supported_sources"]
    assert "email" in data["supported_sources"]


@pytest.mark.asyncio
async def test_ingest_suricata_event(async_client: AsyncClient) -> None:
    """Verify POST /api/v1/telemetry/ingest with Suricata EVE JSON."""
    payload = {
        "timestamp": "2026-09-09T16:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.99",
        "dest_ip": "10.0.1.100",
        "src_port": 49999,
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "drop",
            "signature": "ET MALWARE Suspicious Inbound Beacon",
            "category": "Trojan Activity",
            "severity": 1,
        },
    }

    response = await async_client.post("/api/v1/telemetry/ingest", json=payload)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["is_valid"] is True
    assert data["source"] == "suricata"
    assert data["source_type"] == "network_ids"
    assert data["severity"] == "critical"
    assert data["event_id"].startswith("evt_")
    assert data["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_ingest_syslog_line(async_client: AsyncClient) -> None:
    """Verify POST /api/v1/telemetry/ingest with Syslog string payload."""
    line = "<85>Sep  9 16:05:00 soc-workstation sshd[9999]: Failed password for invalid user malicious from 203.0.113.44 port 54321 ssh2"

    response = await async_client.post(
        "/api/v1/telemetry/ingest",
        content=line,
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["source"] == "syslog.sshd"
    assert data["event_type"] == "auth_failed"


@pytest.mark.asyncio
async def test_ingest_invalid_payload_triggers_rejection(
    async_client: AsyncClient,
) -> None:
    """Verify POST /api/v1/telemetry/ingest with invalid data returns 400 Bad Request."""
    bad_payload = "random_unparseable_noise_@@@"

    response = await async_client.post(
        "/api/v1/telemetry/ingest",
        content=bad_payload,
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 400

    data = response.json()
    assert data["status"] == "rejected"
    assert data["is_valid"] is False
    assert "dead_letter_id" in data


@pytest.mark.asyncio
async def test_batch_ingestion_endpoint(async_client: AsyncClient) -> None:
    """Verify POST /api/v1/telemetry/batch accepts bulk telemetry."""
    batch_payload = {
        "events": [
            {
                "timestamp": "2026-09-09T16:10:00Z",
                "event_type": "alert",
                "src_ip": "198.51.100.1",
                "dest_ip": "10.0.0.1",
                "alert": {"signature": "ET SCAN", "severity": 2},
            },
            {
                "EventID": 4624,
                "TargetUserName": "admin",
                "IpAddress": "10.0.0.5",
            },
            {
                "sender": "spammer@bad.org",
                "recipient": "user@corp.local",
                "spf_result": "fail",
                "threat_verdict": "phishing",
            },
        ]
    }

    response = await async_client.post("/api/v1/telemetry/batch", json=batch_payload)
    assert response.status_code == 202

    data = response.json()
    assert data["total"] == 3
    assert data["accepted"] == 3
    assert data["rejected"] == 0
    assert len(data["results"]) == 3


@pytest.mark.asyncio
async def test_get_metrics_endpoint(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/telemetry/metrics returns performance snapshot."""
    response = await async_client.get("/api/v1/telemetry/metrics")
    assert response.status_code == 200

    data = response.json()
    assert "events_received" in data
    assert "events_accepted" in data
    assert "events_rejected" in data
    assert "events_per_second" in data
    assert "latency_ms" in data
    assert "uptime_seconds" in data


@pytest.mark.asyncio
async def test_get_dead_letter_endpoint(async_client: AsyncClient) -> None:
    """Verify GET /api/v1/telemetry/dead-letter returns rejected items."""
    # First post an invalid event to ensure DLQ has data
    await async_client.post(
        "/api/v1/telemetry/ingest",
        content="bad_corrupt_test_data",
        headers={"Content-Type": "text/plain"},
    )

    response = await async_client.get("/api/v1/telemetry/dead-letter?limit=10")
    assert response.status_code == 200

    data = response.json()
    assert "total_recorded" in data
    assert "dead_letters" in data
    assert len(data["dead_letters"]) > 0
