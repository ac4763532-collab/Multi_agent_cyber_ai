"""Unit tests for Redis Manager, cache, and rate limiter."""

import pytest

from backend.app.config.settings import Settings
from backend.app.core.redis import RedisManager


@pytest.mark.asyncio
async def test_redis_manager_offline_health() -> None:
    """Verify RedisManager returns structured status when Redis is unreachable."""
    test_settings = Settings(
        app_env="test",
        redis_host="127.0.0.1",
        redis_port=59998,
        redis_url="redis://127.0.0.1:59998/0",
        redis_timeout_sec=0.5,
    )
    manager = RedisManager(settings=test_settings)
    is_healthy, latency_ms, details = await manager.check_redis_health()

    assert not is_healthy
    assert latency_ms >= 0
    assert "host" in details
    assert "error" in details
    assert not details["connected"]


@pytest.mark.asyncio
async def test_redis_rate_limit_fallback() -> None:
    """Verify rate limiter fails open on connection failure without raising exceptions."""
    test_settings = Settings(
        app_env="test",
        redis_url="redis://127.0.0.1:59998/0",
        redis_timeout_sec=0.2,
    )
    manager = RedisManager(settings=test_settings)
    is_allowed, _count, remaining = await manager.check_rate_limit("test-ip", limit=10)

    assert is_allowed is True
    assert remaining == 10
