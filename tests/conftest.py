"""Pytest fixtures for unit and integration testing."""

import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Set test environment
os.environ["APP_ENV"] = "test"
os.environ["DEBUG"] = "true"

from backend.app.config.settings import Settings, get_settings
from backend.app.main import app


@pytest.fixture
def test_settings() -> Settings:
    """Return test settings instance."""
    return get_settings()


@pytest_asyncio.fixture(loop_scope="function")
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Provide async HTTP client for API testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
