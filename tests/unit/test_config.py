"""Unit tests for settings and configuration management."""

from backend.app.config.settings import Settings


def test_default_settings() -> None:
    """Verify default settings values match security and architectural baselines."""
    settings = Settings(app_env="test")
    assert settings.app_name == "Multi-Agent Cyber AI"
    assert settings.app_version == "0.1.0"
    assert settings.api_prefix == "/api"
    assert settings.max_agent_concurrency == 12
    assert "127.0.0.1/32" in settings.allowed_scan_ranges
    assert "10.0.0.0/8" in settings.allowed_scan_ranges
