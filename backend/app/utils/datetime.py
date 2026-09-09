"""Datetime and timestamp utility functions."""

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(UTC)


def format_iso8601(dt: datetime | None = None) -> str:
    """Format datetime as ISO 8601 string with UTC indicator."""
    target_dt = dt or utc_now()
    return target_dt.isoformat()
