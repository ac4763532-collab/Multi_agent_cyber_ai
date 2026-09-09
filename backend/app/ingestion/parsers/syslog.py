"""Syslog parser supporting RFC 3164, RFC 5424, and common Linux security subsystems."""

import re
from typing import Any

from backend.app.ingestion.interfaces import EventParser, ParsedEvent, TelemetrySourceType
from backend.app.ingestion.parsers.base import (
    extract_ip,
    extract_port,
    map_severity_str,
    parse_datetime_safe,
)
from backend.app.schemas.events import EventSeverity

# Regex Patterns for Syslog Formats
RFC3164_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[\w\.\-]+)\s+(?P<app>[\w\.\-\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)(?:\s+(?P<sd>\[.*?\]|-))?\s+(?P<message>.*)$"
)

SSHD_FAILED_PATTERN = re.compile(
    r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
SSHD_ACCEPTED_PATTERN = re.compile(
    r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)",
    re.IGNORECASE,
)
SSHD_INVALID_USER_PATTERN = re.compile(
    r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>\S+)",
    re.IGNORECASE,
)
SUDO_PATTERN = re.compile(
    r"(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?(?:PWD=\S+\s*;\s*)?USER=(?P<target_user>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.*)",
    re.IGNORECASE,
)
SUDO_AUTH_FAIL_PATTERN = re.compile(
    r"pam_unix\(sudo:auth\):\s*authentication failure;.*rhost=(?P<rhost>\S*)\s+user=(?P<user>\S+)",
    re.IGNORECASE,
)
UFW_BLOCK_PATTERN = re.compile(
    r"\[UFW\s+(?P<action>BLOCK|AUDIT|ALLOW)\]\s+IN=(?P<in_iface>\S*)\s+OUT=(?P<out_iface>\S*).*?"
    r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dest_ip>\S+).*?PROTO=(?P<proto>\S+)"
    r"(?:\s+SPT=(?P<src_port>\d+)\s+DPT=(?P<dest_port>\d+))?",
    re.IGNORECASE,
)
PAM_AUTH_FAIL_PATTERN = re.compile(
    r"pam_unix\((?P<service>\S+):auth\):\s*authentication failure;.*?"
    r"(?:rhost=(?P<src_ip>\S+))?.*?(?:user=(?P<user>\S+))?",
    re.IGNORECASE,
)


class SyslogParser(EventParser):
    """Parser for standard RFC 3164 / RFC 5424 and Linux security auth/firewall syslog streams."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.SYSLOG

    @property
    def parser_name(self) -> str:
        return "syslog_security_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Check if payload matches syslog text structure or syslog dictionary."""
        if isinstance(raw_data, str):
            clean = raw_data.strip()
            return bool(
                RFC3164_PATTERN.match(clean)
                or RFC5424_PATTERN.match(clean)
                or "sshd[" in clean
                or "sudo:" in clean
                or "[UFW " in clean
                or clean.startswith("<")
            )
        if isinstance(raw_data, dict):
            return bool(
                raw_data.get("source_type") == "syslog"
                or raw_data.get("source") == "syslog"
                or "syslog" in str(raw_data.get("tags", "")).lower()
                or ("message" in raw_data and "hostname" in raw_data)
            )
        return False

    def _parse_sshd(
        self, msg: str
    ) -> tuple[str, EventSeverity, str | None, str | None, int | None, str, str]:
        """Extract SSHD subsystem fields."""
        m_fail = SSHD_FAILED_PATTERN.search(msg)
        if m_fail:
            return (
                "auth_failed",
                EventSeverity.MEDIUM,
                m_fail.group("user"),
                extract_ip(m_fail.group("src_ip")),
                extract_port(m_fail.group("src_port")),
                "denied",
                "failure",
            )
        m_acc = SSHD_ACCEPTED_PATTERN.search(msg)
        if m_acc:
            return (
                "auth_success",
                EventSeverity.LOW,
                m_acc.group("user"),
                extract_ip(m_acc.group("src_ip")),
                extract_port(m_acc.group("src_port")),
                "allowed",
                "success",
            )
        m_inv = SSHD_INVALID_USER_PATTERN.search(msg)
        if m_inv:
            return (
                "auth_invalid_user",
                EventSeverity.MEDIUM,
                m_inv.group("user"),
                extract_ip(m_inv.group("src_ip")),
                None,
                "denied",
                "failure",
            )
        return ("syslog_generic", EventSeverity.LOW, None, None, None, "logged", "info")

    def _parse_ufw(
        self, msg: str
    ) -> tuple[
        str, EventSeverity, str | None, str | None, int | None, int | None, str | None, str, str
    ]:
        """Extract UFW firewall fields."""
        m_ufw = UFW_BLOCK_PATTERN.search(msg)
        if m_ufw:
            ufw_act = m_ufw.group("action").lower()
            action = "blocked" if ufw_act == "block" else "allowed"
            sev = EventSeverity.MEDIUM if ufw_act == "block" else EventSeverity.LOW
            src_ip = extract_ip(m_ufw.group("src_ip"))
            dest_ip = extract_ip(m_ufw.group("dest_ip"))
            protocol = (m_ufw.group("proto") or "TCP").upper()
            src_port = extract_port(m_ufw.group("src_port"))
            dest_port = extract_port(m_ufw.group("dest_port"))
            return (
                "firewall_drop",
                sev,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                protocol,
                action,
                action,
            )
        return ("syslog_generic", EventSeverity.LOW, None, None, None, None, None, "logged", "info")

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse raw syslog line or dict into canonical ParsedEvent."""
        raw_str = raw_data if isinstance(raw_data, str) else str(raw_data.get("message", raw_data))
        clean_str = raw_str.strip()
        extracted: dict[str, Any] = {}
        ts_str, hostname, app_name, pid, pri, message = None, None, "syslog", None, None, clean_str

        m5424 = RFC5424_PATTERN.match(clean_str)
        m3164 = RFC3164_PATTERN.match(clean_str)
        if m5424:
            pri, ts_str, hostname, app_name, pid, message = (
                m5424.group("pri"),
                m5424.group("timestamp"),
                m5424.group("hostname"),
                m5424.group("app"),
                m5424.group("procid"),
                m5424.group("message"),
            )
        elif m3164:
            pri, ts_str, hostname, app_name, pid, message = (
                m3164.group("pri"),
                m3164.group("timestamp"),
                m3164.group("hostname"),
                m3164.group("app"),
                m3164.group("pid"),
                m3164.group("message"),
            )

        event_time = parse_datetime_safe(ts_str) if ts_str else parse_datetime_safe(None)
        severity = (
            map_severity_str(int(pri) & 0x07) if pri and str(pri).isdigit() else EventSeverity.LOW
        )

        event_type, action, status = "syslog_generic", "logged", "informational"
        username, src_ip, dest_ip, src_port, dest_port, protocol = (
            None,
            None,
            None,
            None,
            None,
            None,
        )

        if "sshd" in app_name.lower() or "sshd" in message.lower():
            event_type, severity, username, src_ip, src_port, action, status = self._parse_sshd(
                message
            )
        elif "ufw" in app_name.lower() or "[UFW " in message:
            event_type, severity, src_ip, dest_ip, src_port, dest_port, protocol, action, status = (
                self._parse_ufw(message)
            )
        elif "sudo" in app_name.lower() or "sudo:" in message.lower():
            m_sudo_fail = SUDO_AUTH_FAIL_PATTERN.search(message)
            m_sudo = SUDO_PATTERN.search(message)
            if m_sudo_fail:
                event_type, severity, username, action, status = (
                    "auth_failed",
                    EventSeverity.HIGH,
                    m_sudo_fail.group("user"),
                    "denied",
                    "failure",
                )
                src_ip = extract_ip(m_sudo_fail.group("rhost")) or src_ip
            elif m_sudo:
                event_type, severity, username, action, status = (
                    "privilege_escalation",
                    EventSeverity.LOW,
                    m_sudo.group("user"),
                    "executed",
                    "success",
                )
                extracted["target_user"] = m_sudo.group("target_user")
                extracted["command"] = m_sudo.group("command")
        else:
            m_pam = PAM_AUTH_FAIL_PATTERN.search(message)
            if m_pam:
                event_type, severity, username, action, status = (
                    "auth_failed",
                    EventSeverity.HIGH,
                    m_pam.group("user"),
                    "denied",
                    "failure",
                )
                src_ip = extract_ip(m_pam.group("src_ip")) or src_ip

        extracted.update(
            {"hostname": hostname, "app_name": app_name, "pid": pid, "pri": pri, "message": message}
        )
        return ParsedEvent(
            source_type=TelemetrySourceType.SYSLOG,
            raw_payload=raw_data,
            extracted_fields=extracted,
            timestamp=event_time,
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dest_ip,
            source_port=src_port,
            destination_port=dest_port,
            protocol=protocol,
            username=username,
            hostname=hostname,
            action=action,
            status=status,
            metadata=extracted,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
