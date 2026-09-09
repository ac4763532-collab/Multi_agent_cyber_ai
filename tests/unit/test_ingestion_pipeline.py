"""Unit tests for the end-to-end IngestionPipeline and metrics tracking."""

import pytest

from backend.app.ingestion.metrics import IngestionMetricsTracker
from backend.app.ingestion.pipeline import IngestionPipeline
from backend.app.ingestion.registry import IngestionRegistry
from backend.app.ingestion.resilience.dead_letter import DeadLetterQueueManager


@pytest.fixture
def pipeline() -> IngestionPipeline:
    registry = IngestionRegistry()
    dlq = DeadLetterQueueManager(max_buffer_size=100)
    metrics = IngestionMetricsTracker()
    return IngestionPipeline(
        registry=registry,
        dlq_manager=dlq,
        metrics_tracker=metrics,
        publish_to_broker=False,  # Isolated unit test mode
    )


@pytest.mark.asyncio
async def test_pipeline_ingest_suricata(pipeline: IngestionPipeline) -> None:
    suricata_raw = {
        "timestamp": "2026-09-09T15:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.15",
        "dest_ip": "10.0.1.10",
        "src_port": 50123,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Cobalt Strike",
            "category": "Trojan",
            "action": "drop",
            "severity": 1,
        },
    }

    result = await pipeline.ingest_single(suricata_raw)
    assert result["status"] == "accepted"
    assert result["is_valid"] is True
    assert result["source"] == "suricata"
    assert result["source_type"] == "network_ids"
    assert result["severity"] == "critical"
    assert "event_id" in result
    assert result["latency_ms"] > 0


@pytest.mark.asyncio
async def test_pipeline_ingest_syslog(pipeline: IngestionPipeline) -> None:
    syslog_line = "<85>Sep  9 15:05:00 auth-server sshd[1234]: Failed password for invalid user root from 203.0.113.5 port 2222 ssh2"
    result = await pipeline.ingest_single(syslog_line)

    assert result["status"] == "accepted"
    assert result["is_valid"] is True
    assert result["source"] == "syslog.sshd"
    assert result["event_type"] == "auth_failed"


@pytest.mark.asyncio
async def test_pipeline_ingest_corrupted_payload(pipeline: IngestionPipeline) -> None:
    bad_payload = "totally unrecognized gibberish ?&$#@"
    result = await pipeline.ingest_single(bad_payload)

    assert result["status"] == "rejected"
    assert result["is_valid"] is False
    assert "dead_letter_id" in result


@pytest.mark.asyncio
async def test_pipeline_batch_ingest(pipeline: IngestionPipeline) -> None:
    batch = [
        {
            "timestamp": "2026-09-09T15:10:00Z",
            "event_type": "alert",
            "src_ip": "198.51.100.1",
            "dest_ip": "10.0.0.2",
            "alert": {"signature": "ET SCAN", "severity": 2},
        },
        "<85>Sep  9 15:10:01 srv sshd[11]: Accepted password for admin from 10.0.0.5 port 123 ssh2",
        {
            "EventID": 4624,
            "TargetUserName": "admin",
            "IpAddress": "10.0.0.5",
        },
        "corrupted_bad_item_!!",
    ]

    batch_result = await pipeline.ingest_batch(batch)
    assert batch_result["total"] == 4
    assert batch_result["accepted"] == 3
    assert batch_result["rejected"] == 1
    assert batch_result["events_per_second"] > 0

    # Verify metrics snapshot
    snapshot = pipeline.metrics.get_snapshot()
    assert snapshot["events_received"] >= 4
    assert snapshot["events_accepted"] >= 3
    assert snapshot["events_rejected"] >= 1
