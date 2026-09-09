"""Telemetry event parsers for supported security sources."""

from backend.app.ingestion.parsers.application import ApplicationLogParser
from backend.app.ingestion.parsers.authentication import AuthenticationLogParser
from backend.app.ingestion.parsers.base import (
    extract_ip,
    extract_port,
    map_severity_str,
    parse_datetime_safe,
    parse_json_safe,
)
from backend.app.ingestion.parsers.email_security import EmailSecurityParser
from backend.app.ingestion.parsers.json_event import JsonEventParser
from backend.app.ingestion.parsers.suricata import SuricataEveParser
from backend.app.ingestion.parsers.syslog import SyslogParser

__all__ = [
    "ApplicationLogParser",
    "AuthenticationLogParser",
    "EmailSecurityParser",
    "JsonEventParser",
    "SuricataEveParser",
    "SyslogParser",
    "extract_ip",
    "extract_port",
    "map_severity_str",
    "parse_datetime_safe",
    "parse_json_safe",
]
