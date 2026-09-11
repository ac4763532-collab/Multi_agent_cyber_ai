"""Shared base utilities for detection rule implementations."""

import re
from typing import Any

from backend.app.schemas.events import EventSeverity, SecurityEvent


def get_event_field(event: SecurityEvent, field_path: str) -> Any:
    """Extract a field value from SecurityEvent using dot notation.

    Supports nested paths like 'normalized_data.network.source.ip'.

    Args:
        event: SecurityEvent to extract from.
        field_path: Dot-separated field path.

    Returns:
        Field value or None if not found.
    """
    # Handle direct attributes first
    parts = field_path.split(".")
    current: Any = event

    for part in parts:
        if current is None:
            return None

        # Try attribute access for Pydantic models
        if hasattr(current, part):
            current = getattr(current, part)
        # Try dict access
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None

    return current


def get_searchable_fields(event: SecurityEvent) -> dict[str, Any]:
    """Extract all searchable fields from a SecurityEvent into a flat dict.

    Args:
        event: SecurityEvent to extract fields from.

    Returns:
        Dict mapping field names to their values (flattened).
    """
    fields: dict[str, Any] = {
        "event_id": event.event_id,
        "source": event.source,
        "source_type": event.source_type,
        "event_type": event.event_type,
        "severity": (
            event.severity.value
            if isinstance(event.severity, EventSeverity)
            else event.severity
        ),
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "username": event.username,
        "hostname": event.hostname,
        "domain": event.domain,
        "url": event.url,
        "hash": event.hash,
        "protocol": event.protocol,
        "action": event.action,
        "status": event.status,
        "asset_id": event.asset_id,
    }

    # Flatten raw_data if dict
    if isinstance(event.raw_data, dict):
        for key, value in event.raw_data.items():
            fields[f"raw_data.{key}"] = value
            if isinstance(value, str):
                fields[f"raw_{key}"] = value

    # Flatten normalized_data
    if isinstance(event.normalized_data, dict):
        _flatten_dict(event.normalized_data, "normalized_data", fields)

    # Flatten metadata
    if event.metadata:
        for key, value in event.metadata.items():
            fields[f"metadata.{key}"] = value

    # Add full raw string for pattern matching
    if isinstance(event.raw_data, str):
        fields["raw_string"] = event.raw_data
    elif isinstance(event.raw_data, dict):
        fields["raw_string"] = str(event.raw_data)

    return fields


def _flatten_dict(d: dict[str, Any], prefix: str, result: dict[str, Any]) -> None:
    """Recursively flatten a nested dict with dot-notation keys."""
    for key, value in d.items():
        full_key = f"{prefix}.{key}"
        if isinstance(value, dict):
            _flatten_dict(value, full_key, result)
        elif isinstance(value, list):
            result[full_key] = value
            # Also store as joined string for pattern matching
            if all(isinstance(v, str) for v in value):
                result[f"{full_key}_str"] = " ".join(value)
        else:
            result[full_key] = value


def normalize_field_name(field: str) -> str:
    """Normalize field name for case-insensitive matching.

    Args:
        field: Field name to normalize.

    Returns:
        Lowercase field name with consistent separators.
    """
    return field.lower().replace("-", "_").replace(" ", "_")


def safe_str(value: Any) -> str:
    """Safely convert any value to string for pattern matching.

    Args:
        value: Any value to convert.

    Returns:
        String representation, empty string for None.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


def compile_regex_safe(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str] | None:
    """Safely compile a regex pattern, returning None on error.

    Args:
        pattern: Regex pattern string.
        flags: Regex flags (default: case insensitive).

    Returns:
        Compiled Pattern or None if invalid.
    """
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def severity_from_string(
    value: str | int | None, default: EventSeverity = EventSeverity.MEDIUM
) -> EventSeverity:
    """Convert string/int to EventSeverity enum.

    Args:
        value: Severity value to convert.
        default: Default severity if conversion fails.

    Returns:
        EventSeverity enum value.
    """
    if value is None:
        return default

    if isinstance(value, EventSeverity):
        return value

    if isinstance(value, int):
        int_mapping: dict[int, EventSeverity] = {
            1: EventSeverity.CRITICAL,
            2: EventSeverity.HIGH,
            3: EventSeverity.MEDIUM,
            4: EventSeverity.LOW,
            5: EventSeverity.INFORMATIONAL,
        }
        return int_mapping.get(value, default)

    if isinstance(value, str):
        val = value.strip().lower()
        str_mapping: dict[str, EventSeverity] = {
            "critical": EventSeverity.CRITICAL,
            "crit": EventSeverity.CRITICAL,
            "high": EventSeverity.HIGH,
            "medium": EventSeverity.MEDIUM,
            "med": EventSeverity.MEDIUM,
            "low": EventSeverity.LOW,
            "informational": EventSeverity.INFORMATIONAL,
            "info": EventSeverity.INFORMATIONAL,
        }
        return str_mapping.get(val, default)

    return default
