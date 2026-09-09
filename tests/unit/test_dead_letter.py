"""Unit tests for Dead-Letter Queue (DLQ) manager and failure resilience."""

import pytest

from backend.app.ingestion.resilience.dead_letter import DeadLetterQueueManager


@pytest.mark.asyncio
async def test_dead_letter_queue_recording() -> None:
    dlq = DeadLetterQueueManager(max_buffer_size=10)
    assert dlq.total_count == 0

    record = await dlq.handle_invalid_event(
        raw_payload={"corrupt": "data"},
        error_message="Missing timestamp and source",
        error_type="validation_error",
        source="unit_test",
        source_type="syslog",
        validation_errors=[{"loc": ["timestamp"], "msg": "Field required"}],
    )

    assert dlq.total_count == 1
    assert record["dead_letter_id"].startswith("dlq-")
    assert record["error_type"] == "validation_error"
    assert record["error_message"] == "Missing timestamp and source"
    assert record["source"] == "unit_test"
    assert len(record["validation_errors"]) == 1

    recent = dlq.get_recent(limit=5)
    assert len(recent) == 1
    assert recent[0]["dead_letter_id"] == record["dead_letter_id"]


@pytest.mark.asyncio
async def test_dead_letter_buffer_overflow() -> None:
    dlq = DeadLetterQueueManager(max_buffer_size=3)

    for i in range(5):
        await dlq.handle_invalid_event(
            raw_payload=f"bad_event_{i}",
            error_message=f"Error {i}",
            error_type="syntax_error",
        )

    assert dlq.total_count == 5
    recent = dlq.get_recent(limit=10)
    assert len(recent) == 3  # Buffer capped at 3
    # Most recent first
    assert recent[0]["raw_payload"] == "bad_event_4"


@pytest.mark.asyncio
async def test_dead_letter_filter_by_error_type() -> None:
    dlq = DeadLetterQueueManager(max_buffer_size=10)

    await dlq.handle_invalid_event(
        raw_payload="1", error_message="msg1", error_type="type_a"
    )
    await dlq.handle_invalid_event(
        raw_payload="2", error_message="msg2", error_type="type_b"
    )
    await dlq.handle_invalid_event(
        raw_payload="3", error_message="msg3", error_type="type_a"
    )

    filtered_a = dlq.get_recent(error_type="type_a")
    assert len(filtered_a) == 2

    filtered_b = dlq.get_recent(error_type="type_b")
    assert len(filtered_b) == 1
