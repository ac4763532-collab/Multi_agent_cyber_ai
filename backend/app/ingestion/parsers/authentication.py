"""Authentication log parser for Windows Event Logs, Linux PAM, and Cloud IAM."""

import re
from typing import Any

from backend.app.ingestion.interfaces import EventParser, ParsedEvent, TelemetrySourceType
from backend.app.ingestion.parsers.base import (
    extract_ip,
    extract_port,
    parse_datetime_safe,
    parse_json_safe,
)
from backend.app.schemas.events import EventSeverity

# Windows Logon Types lookup map
WINDOWS_LOGON_TYPES = {
    "2": "Interactive (Console)",
    "3": "Network (SMB/RPC)",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

# Windows Event ID Descriptions
WIN_EVENT_DESCRIPTIONS = {
    4624: ("user_logon_success", EventSeverity.LOW, "allowed", "success"),
    4625: ("user_logon_failed", EventSeverity.HIGH, "denied", "failure"),
    4648: ("user_logon_explicit_creds", EventSeverity.MEDIUM, "allowed", "success"),
    4672: ("special_privileges_assigned", EventSeverity.MEDIUM, "assigned", "success"),
    4720: ("user_account_created", EventSeverity.MEDIUM, "created", "success"),
    4726: ("user_account_deleted", EventSeverity.MEDIUM, "deleted", "success"),
    4728: ("user_added_to_security_group", EventSeverity.MEDIUM, "added", "success"),
    4738: ("user_account_modified", EventSeverity.LOW, "modified", "success"),
    4740: ("user_account_locked_out", EventSeverity.HIGH, "locked", "failure"),
}

AUTH_SOURCES = (
    "windows_security",
    "auth_log",
    "active_directory",
    "okta",
    "azure_ad",
    "iam",
)


class AuthenticationLogParser(EventParser):
    """Parser for authentication telemetry across Windows, Linux, and Cloud providers."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.AUTHENTICATION

    @property
    def parser_name(self) -> str:
        return "authentication_log_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Check if payload matches authentication event signatures."""
        if isinstance(raw_data, dict):
            src = raw_data.get("source")
            return bool(
                raw_data.get("source_type") == "authentication"
                or src in AUTH_SOURCES
                or "EventID" in raw_data
                or "event_id" in raw_data
                and str(raw_data.get("event_id")).isdigit()
                or "TargetUserName" in raw_data
                or "ConsoleLogin" in str(raw_data)
            )
        if isinstance(raw_data, str):
            clean = raw_data.strip()
            if clean.startswith("<"):
                return False
            return bool(
                "EventID" in clean
                or "pam_unix" in clean
                or "Failed password" in clean
                or "Accepted password" in clean
                or "ConsoleLogin" in clean
            )
        return False

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse authentication telemetry into canonical ParsedEvent."""
        data, err = parse_json_safe(raw_data)
        if not err and isinstance(data, dict):
            return self._parse_structured_auth(data, raw_data)

        return self._parse_text_auth(str(raw_data), raw_data)

    def _extract_username(self, data: dict[str, Any]) -> str | None:
        user_id_obj = data.get("userIdentity") if isinstance(data.get("userIdentity"), dict) else {}
        username = (
            data.get("TargetUserName")
            or data.get("username")
            or data.get("user")
            or data.get("SubjectUserName")
            or data.get("userName")
            or user_id_obj.get("userName")
        )
        return str(username) if username else None

    def _parse_structured_auth(self, data: dict[str, Any], raw_payload: Any) -> ParsedEvent:
        """Parse structured dictionary (Windows Event, Cloud IAM, Okta, Azure AD)."""
        raw_event_id = data.get("EventID") or data.get("event_id") or data.get("EventId")
        win_eid = None
        if raw_event_id is not None:
            try:
                win_eid = int(str(raw_event_id).strip())
            except ValueError:
                pass

        raw_ts = (
            data.get("TimeCreated")
            or data.get("timestamp")
            or data.get("@timestamp")
            or data.get("eventTime")
        )
        event_time = parse_datetime_safe(raw_ts)
        username = self._extract_username(data)
        domain = data.get("TargetDomainName") or data.get("domain") or data.get("SubjectDomainName")
        hostname = data.get("WorkstationName") or data.get("Computer") or data.get("hostname")

        src_ip = extract_ip(
            data.get("IpAddress")
            or data.get("src_ip")
            or data.get("source_ip")
            or data.get("sourceIPAddress")
            or data.get("client_ip")
        )
        src_port = extract_port(data.get("IpPort") or data.get("src_port"))

        if win_eid in WIN_EVENT_DESCRIPTIONS:
            event_type, severity, action, status = WIN_EVENT_DESCRIPTIONS[win_eid]
        else:
            event_name = str(
                data.get("eventName") or data.get("event_type") or "auth_event"
            ).lower()
            if "fail" in event_name or data.get("status") in ("failure", "failed", "denied"):
                event_type, severity, action, status = (
                    "auth_failed",
                    EventSeverity.HIGH,
                    "denied",
                    "failure",
                )
            else:
                event_type, severity, action, status = (
                    "auth_success",
                    EventSeverity.LOW,
                    "allowed",
                    "success",
                )

        logon_code = str(data.get("LogonType") or data.get("logon_type") or "")
        metadata = dict(data)
        if win_eid:
            metadata["windows_event_id"] = win_eid
        if logon_code in WINDOWS_LOGON_TYPES:
            metadata["logon_type_desc"] = WINDOWS_LOGON_TYPES[logon_code]

        return ParsedEvent(
            source_type=TelemetrySourceType.AUTHENTICATION,
            raw_payload=raw_payload,
            extracted_fields=data,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            source_port=src_port,
            username=username,
            hostname=str(hostname) if hostname else None,
            domain=str(domain) if domain else None,
            action=action,
            status=status,
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

    def _parse_text_auth(self, text: str, raw_payload: Any) -> ParsedEvent:
        """Parse unstructured text authentication line."""
        clean = text.strip()
        event_time = parse_datetime_safe(None)
        severity = EventSeverity.LOW
        event_type = "auth_event"
        action = "logged"
        status = "success"
        username, src_ip = None, None

        m_fail = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", clean, re.I)
        m_ok = re.search(r"Accepted password for (\S+) from (\S+)", clean, re.I)

        if m_fail:
            username = m_fail.group(1)
            src_ip = extract_ip(m_fail.group(2))
            event_type = "auth_failed"
            severity = EventSeverity.HIGH
            action = "denied"
            status = "failure"
        elif m_ok:
            username = m_ok.group(1)
            src_ip = extract_ip(m_ok.group(2))
            event_type = "auth_success"
            severity = EventSeverity.LOW
            action = "allowed"
            status = "success"

        return ParsedEvent(
            source_type=TelemetrySourceType.AUTHENTICATION,
            raw_payload=raw_payload,
            extracted_fields={"raw_line": clean},
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            username=username,
            action=action,
            status=status,
            metadata={"raw_message": clean},
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
