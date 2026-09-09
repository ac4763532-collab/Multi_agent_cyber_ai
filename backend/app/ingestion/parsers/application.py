"""Application log parser supporting Nginx/Apache CLF, JSON app logs, and errors."""

import re
from typing import Any

from backend.app.ingestion.interfaces import EventParser, ParsedEvent, TelemetrySourceType
from backend.app.ingestion.parsers.base import (
    extract_ip,
    map_severity_str,
    parse_datetime_safe,
    parse_json_safe,
)
from backend.app.schemas.events import EventSeverity

# Nginx/Apache Combined Log Format pattern
COMBINED_LOG_PATTERN = re.compile(
    r"^(?P<client_ip>\S+)\s+(?P<ident>\S+)\s+(?P<auth_user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status_code>\d{3})\s+'
    r'(?P<bytes_sent>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Application text error log pattern
APP_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)\s+"
    r"(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\s+"
    r"(?:\[(?P<logger>[\w\.\-]+)\]\s+)?(?P<message>.*)$",
    re.IGNORECASE,
)

# SQLi and XSS heuristic signatures in URI
SQLI_PATTERN = re.compile(
    r"(\b(select|union|insert|update|delete|drop|alter|exec|declare)\b|"
    r"--|\'|\%27|\%22|information_schema)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(
    r"(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)",
    re.IGNORECASE,
)


class ApplicationLogParser(EventParser):
    """Parser for web application access logs, JSON application events, and errors."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.APPLICATION

    @property
    def parser_name(self) -> str:
        return "application_log_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Check if payload matches application web access logs or error format."""
        if isinstance(raw_data, str):
            clean = raw_data.strip()
            return bool(
                COMBINED_LOG_PATTERN.match(clean)
                or APP_LOG_PATTERN.match(clean)
                or "HTTP/1." in clean
                or "HTTP/2." in clean
            )
        if isinstance(raw_data, dict):
            src = raw_data.get("source")
            return bool(
                raw_data.get("source_type") == "application"
                or src in ("nginx", "apache", "webapp", "api_gateway", "fastapi")
                or ("status_code" in raw_data and "uri" in raw_data)
                or ("http_method" in raw_data and "url" in raw_data)
            )
        return False

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse application log into canonical ParsedEvent."""
        # 1. Handle JSON structured application log
        if isinstance(raw_data, dict) or (
            isinstance(raw_data, str) and raw_data.strip().startswith("{")
        ):
            data, err = parse_json_safe(raw_data)
            if not err and isinstance(data, dict):
                return self._parse_json_app_log(data, raw_data)

        # 2. Handle Text Log Line (Combined / CLF / Standard App Log)
        raw_str = raw_data if isinstance(raw_data, str) else str(raw_data)
        clean_str = raw_str.strip()

        m_web = COMBINED_LOG_PATTERN.match(clean_str)
        if m_web:
            return self._parse_combined_access_log(m_web, clean_str, raw_data)

        m_app = APP_LOG_PATTERN.match(clean_str)
        if m_app:
            return self._parse_text_app_log(m_app, clean_str, raw_data)

        # Fallback generic text parse
        return ParsedEvent(
            source_type=TelemetrySourceType.APPLICATION,
            raw_payload=raw_data,
            extracted_fields={"raw_line": clean_str},
            timestamp=parse_datetime_safe(None),
            event_type="app_log_generic",
            severity=EventSeverity.LOW,
            metadata={"message": clean_str},
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

    def _parse_combined_access_log(
        self, match: re.Match[str], raw_line: str, raw_payload: Any
    ) -> ParsedEvent:
        """Parse Nginx/Apache combined access log line."""
        client_ip = extract_ip(match.group("client_ip"))
        auth_user = match.group("auth_user")
        user = auth_user if auth_user and auth_user != "-" else None
        ts_str = match.group("timestamp")
        event_time = parse_datetime_safe(ts_str)

        method = match.group("method")
        uri = match.group("uri")
        protocol = match.group("protocol")
        status_code = int(match.group("status_code"))
        referrer = match.group("referrer")
        user_agent = match.group("user_agent")

        event_type = "web_access"
        severity = EventSeverity.LOW
        status = "success" if status_code < 400 else "failure"
        action = "allowed"

        if status_code == 401:
            event_type = "web_unauthorized"
            severity = EventSeverity.MEDIUM
            action = "denied"
        elif status_code == 403:
            event_type = "web_forbidden"
            severity = EventSeverity.MEDIUM
            action = "blocked"
        elif status_code == 404:
            event_type = "web_not_found"
            severity = EventSeverity.LOW
        elif status_code >= 500:
            event_type = "web_server_error"
            severity = EventSeverity.HIGH

        is_sqli = bool(SQLI_PATTERN.search(uri))
        is_xss = bool(XSS_PATTERN.search(uri))

        if is_sqli:
            event_type = "web_sqli_attempt"
            severity = EventSeverity.HIGH
        elif is_xss:
            event_type = "web_xss_attempt"
            severity = EventSeverity.HIGH

        metadata = {
            "http_method": method,
            "status_code": status_code,
            "uri": uri,
            "protocol": protocol,
            "referrer": referrer if referrer != "-" else None,
            "user_agent": user_agent if user_agent != "-" else None,
            "is_sqli_pattern": is_sqli,
            "is_xss_pattern": is_xss,
        }

        return ParsedEvent(
            source_type=TelemetrySourceType.APPLICATION,
            raw_payload=raw_payload,
            extracted_fields=metadata,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=client_ip,
            username=user,
            url=uri,
            action=action,
            status=status,
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

    def _parse_text_app_log(
        self, match: re.Match[str], raw_line: str, raw_payload: Any
    ) -> ParsedEvent:
        """Parse standard application logger text format."""
        ts_str = match.group("timestamp")
        event_time = parse_datetime_safe(ts_str)
        level_str = match.group("level")
        severity = map_severity_str(level_str)
        logger_name = match.group("logger") or "root"
        message = match.group("message")

        is_high = severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
        event_type = "app_error" if is_high else "app_log"

        metadata = {
            "logger": logger_name,
            "level": level_str,
            "message": message,
        }

        return ParsedEvent(
            source_type=TelemetrySourceType.APPLICATION,
            raw_payload=raw_payload,
            extracted_fields=metadata,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            status="error" if is_high else "info",
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

    def _parse_json_app_log(self, data: dict[str, Any], raw_payload: Any) -> ParsedEvent:
        """Parse structured application JSON log."""
        raw_ts = data.get("timestamp") or data.get("time") or data.get("@timestamp")
        event_time = parse_datetime_safe(raw_ts)

        src_ip = extract_ip(data.get("client_ip") or data.get("ip") or data.get("source_ip"))
        status_code = data.get("status_code") or data.get("status")
        method = data.get("method") or data.get("http_method")
        uri = data.get("url") or data.get("uri") or data.get("path")
        level = data.get("level") or data.get("severity") or "info"
        severity = map_severity_str(level)
        user = data.get("user") or data.get("username")

        event_type = str(data.get("event_type") or ("web_access" if method else "app_log")).lower()

        return ParsedEvent(
            source_type=TelemetrySourceType.APPLICATION,
            raw_payload=raw_payload,
            extracted_fields=data,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            username=str(user) if user else None,
            url=str(uri) if uri else None,
            action=data.get("action", "allowed"),
            status=str(status_code) if status_code else "info",
            metadata=data,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
