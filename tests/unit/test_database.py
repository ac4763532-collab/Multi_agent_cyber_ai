"""Unit tests for Database engine configuration and retries."""

import pytest

from backend.app.config.settings import Settings
from backend.app.database.session import check_db_health


@pytest.mark.asyncio
async def test_database_health_probe() -> None:
    """Verify check_db_health returns structured status and handles offline instances gracefully."""
    is_healthy, latency_ms, details = await check_db_health(max_retries=1)
    assert isinstance(is_healthy, bool)
    assert isinstance(latency_ms, (int, float))
    assert "host" in details
    assert "database" in details


def test_database_settings_parameters() -> None:
    """Verify database retry and timeout parameters."""
    settings = Settings(app_env="test")
    assert settings.db_pool_size >= 10
    assert settings.db_max_retries == 3
    assert settings.db_connect_timeout > 0
