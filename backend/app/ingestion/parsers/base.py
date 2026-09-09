"""Shared base utilities and parsing helpers for telemetry parsers."""

import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

from backend.app.schemas.events import EventSeverity
from backend.app.utils.datetime import utc_now


def parse_json_safe(raw_data: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Attempt to parse input into a dictionary.

    Returns (dict, None) on success or (None, error_str) on failure.
    """
    if isinstance(raw_data, dict):
        return raw_data, None
    if isinstance(raw_data, (bytes, bytearray)):
        try:
            raw_data = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            return None, f"UTF-8 decoding failed: {exc}"
    if isinstance(raw_data, str):
        cleaned = raw_data.strip()
        if not cleaned:
            return None, "Empty payload string"
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed, None
            return None, f"Expected JSON object/dict, got {type(parsed).__name__}"
        except json.JSONDecodeError as exc:
            return None, f"Invalid JSON syntax: {exc}"
    return None, f"Unsupported payload type: {type(raw_data).__name__}"


def extract_ip(value: Any) -> str | None:
    """Validate and return normalized IP string (IPv4/IPv6), or None."""
    if not value or not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return None
    val_str = str(value).strip()
    if not val_str or val_str in ("-", "none", "null", "unknown", "127.0.0.1/32"):
        return None
    if ":" in val_str and val_str.count(":") == 1 and not val_str.startswith("["):
        val_str = val_str.split(":")[0]
    try:
        ip = ipaddress.ip_address(val_str)
        return str(ip)
    except ValueError:
        return None


def extract_port(value: Any) -> int | None:
    """Validate and return integer port (0-65535), or None."""
    if value is None:
        return None
    try:
        port = int(str(value).strip())
        return port if 0 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def _parse_custom_datetime_str(v: str) -> datetime | None:
    """Parse custom syslog and apache date formats."""
    current_year = datetime.now(UTC).year
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            return datetime.strptime(f"{current_year} {v}", f"%Y {fmt}").replace(tzinfo=UTC)
        except ValueError:
            continue

    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(v, fmt)
            return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
        except ValueError:
            continue
    return None


def parse_datetime_safe(value: Any) -> datetime:
    """Parse various timestamp formats into a UTC datetime object."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return utc_now()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        if re.search(r"[+-]\d{4}$", v):
            v = v[:-2] + ":" + v[-2:]
        try:
            dt = datetime.fromisoformat(v)
            return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
        except ValueError:
            pass

        parsed_custom = _parse_custom_datetime_str(v)
        if parsed_custom:
            return parsed_custom

    return utc_now()


_SEVERITY_MAPPINGS: dict[str, EventSeverity] = {
    "critical": EventSeverity.CRITICAL,
    "fatal": EventSeverity.CRITICAL,
    "emerg": EventSeverity.CRITICAL,
    "emergency": EventSeverity.CRITICAL,
    "alert": EventSeverity.CRITICAL,
    "crit": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "err": EventSeverity.HIGH,
    "error": EventSeverity.HIGH,
    "sev1": EventSeverity.HIGH,
    "p1": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "med": EventSeverity.MEDIUM,
    "warn": EventSeverity.MEDIUM,
    "warning": EventSeverity.MEDIUM,
    "sev2": EventSeverity.MEDIUM,
    "p2": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
    "notice": EventSeverity.LOW,
    "info": EventSeverity.LOW,
    "informational": EventSeverity.LOW,
    "sev3": EventSeverity.LOW,
    "p3": EventSeverity.LOW,
    "debug": EventSeverity.INFORMATIONAL,
    "trace": EventSeverity.INFORMATIONAL,
}


def map_severity_str(value: Any, default: EventSeverity = EventSeverity.LOW) -> EventSeverity:
    """Map string, integer, or enum value to canonical EventSeverity."""
    if isinstance(value, EventSeverity):
        return value
    if isinstance(value, int):
        if value <= 1:
            return EventSeverity.CRITICAL
        if value == 2:
            return EventSeverity.HIGH
        if value == 3:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW

    if isinstance(value, str):
        val = value.strip().lower()
        return _SEVERITY_MAPPINGS.get(val, default)

    return default
