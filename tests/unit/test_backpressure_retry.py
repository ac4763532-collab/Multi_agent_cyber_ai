"""Unit tests for backpressure, rate limiting, and retry policies."""

import asyncio

import pytest

from backend.app.ingestion.resilience.backpressure import (
    BackpressureController,
    BackpressureExceededError,
    RateLimiter,
)
from backend.app.ingestion.resilience.retry import retry_async


@pytest.mark.asyncio
async def test_rate_limiter() -> None:
    limiter = RateLimiter(max_rate_per_sec=10, window_sec=0.5)

    # Acquire 10 slots
    assert await limiter.acquire(count=5) is True
    assert await limiter.acquire(count=5) is True
    # 11th should fail
    assert await limiter.acquire(count=1) is False

    # Wait for window to expire
    await asyncio.sleep(0.55)
    assert await limiter.acquire(count=5) is True


@pytest.mark.asyncio
async def test_backpressure_controller_concurrency_limit() -> None:
    controller = BackpressureController(
        max_concurrent_tasks=10,
        max_queue_size=20,
        rate_limit_eps=1000,
    )

    await controller.try_acquire(batch_size=15)
    assert controller.active_tasks == 15

    # Should fail if exceeding max_queue_size
    with pytest.raises(BackpressureExceededError):
        await controller.try_acquire(batch_size=10)

    controller.release(batch_size=15)
    assert controller.active_tasks == 0


@pytest.mark.asyncio
async def test_retry_async_success_after_failure() -> None:
    attempts = 0

    async def flaky_operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionError("Transient network failure")
        return "success"

    result = await retry_async(
        flaky_operation,
        max_retries=4,
        initial_delay=0.01,
        backoff_factor=1.5,
    )
    assert result == "success"
    assert attempts == 3


@pytest.mark.asyncio
async def test_retry_async_permanent_failure() -> None:
    attempts = 0

    async def doomed_operation() -> str:
        nonlocal attempts
        attempts += 1
        raise ValueError("Permanent fatal error")

    with pytest.raises(ValueError):
        await retry_async(
            doomed_operation,
            max_retries=2,
            initial_delay=0.01,
        )
    assert attempts == 2
