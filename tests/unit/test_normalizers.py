"""Unit tests for telemetry normalizers across all 6 supported sources."""

from datetime import UTC, datetime

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers import (
    AuthenticationLogNormalizer,
    EmailSecurityNormalizer,
    SuricataNormalizer,
    SyslogNormalizer,
)
from backend.app.schemas.events import EventSeverity, SecurityEvent


class TestNormalizers:
    """Test suite verifying canonical SecurityEvent production across all normalizers."""

    def test_suricata_normalizer(self) -> None:
        normalizer = SuricataNormalizer()
        parsed = ParsedEvent(
            source_type=TelemetrySourceType.SURICATA,
            raw_payload={"alert": "test"},
            extracted_fields={"proto": "TCP"},
            timestamp=datetime(2026, 9, 9, 10, 0, 0, tzinfo=UTC),
            event_type="network_ids_alert",
            severity=EventSeverity.CRITICAL,
            source_ip="198.51.100.5",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=443,
            protocol="TCP",
            action="blocked",
            status="triggered",
            metadata={"signature": "ET TROJAN C2"},
        )

        event = normalizer.normalize(parsed)
        assert isinstance(event, SecurityEvent)
        assert event.source == "suricata"
        assert event.source_type == "network_ids"
        assert event.event_type == "network_ids_alert"
        assert event.severity == EventSeverity.CRITICAL
        assert event.source_ip == "198.51.100.5"
        assert event.destination_ip == "10.0.0.1"
        assert event.source_port == 54321
        assert event.destination_port == 443
        assert event.normalized_data["network"]["source"]["ip"] == "198.51.100.5"

    def test_syslog_normalizer(self) -> None:
        normalizer = SyslogNormalizer()
        parsed = ParsedEvent(
            source_type=TelemetrySourceType.SYSLOG,
            raw_payload="Sep 9 10:00:00 srv sshd: Failed password",
            extracted_fields={"app_name": "sshd"},
            timestamp=datetime(2026, 9, 9, 10, 0, 0, tzinfo=UTC),
            event_type="auth_failed",
            severity=EventSeverity.MEDIUM,
            source_ip="203.0.113.88",
            username="admin",
            hostname="srv",
            action="denied",
            status="failure",
            metadata={"app_name": "sshd"},
        )

        event = normalizer.normalize(parsed)
        assert isinstance(event, SecurityEvent)
        assert event.source == "syslog.sshd"
        assert event.source_type == "syslog"
        assert event.username == "admin"
        assert event.hostname == "srv"
        assert event.normalized_data["user"]["name"] == "admin"
        assert event.normalized_data["host"]["hostname"] == "srv"

    def test_authentication_normalizer(self) -> None:
        normalizer = AuthenticationLogNormalizer()
        parsed = ParsedEvent(
            source_type=TelemetrySourceType.AUTHENTICATION,
            raw_payload={"EventID": 4624},
            extracted_fields={},
            timestamp=datetime(2026, 9, 9, 10, 0, 0, tzinfo=UTC),
            event_type="user_logon_success",
            severity=EventSeverity.LOW,
            username="analyst_1",
            domain="CORP",
            source_ip="10.0.1.25",
            metadata={"windows_event_id": 4624},
        )

        event = normalizer.normalize(parsed)
        assert isinstance(event, SecurityEvent)
        assert event.source == "windows_security_event_4624"
        assert event.source_type == "authentication"
        assert event.username == "analyst_1"
        assert event.domain == "CORP"

    def test_email_security_normalizer(self) -> None:
        normalizer = EmailSecurityNormalizer()
        parsed = ParsedEvent(
            source_type=TelemetrySourceType.EMAIL,
            raw_payload={"sender": "evil@phish.xyz"},
            extracted_fields={"source": "proofpoint"},
            timestamp=datetime(2026, 9, 9, 10, 0, 0, tzinfo=UTC),
            event_type="email_phishing_detected",
            severity=EventSeverity.HIGH,
            username="evil@phish.xyz",
            domain="phish.xyz",
            url="http://phish.xyz/login",
            hash="abc123sha256",
            action="quarantined",
            status="detected",
        )

        event = normalizer.normalize(parsed)
        assert isinstance(event, SecurityEvent)
        assert event.source == "proofpoint"
        assert event.source_type == "email_security"
        assert event.url == "http://phish.xyz/login"
        assert event.hash == "abc123sha256"
        assert event.normalized_data["url"]["original"] == "http://phish.xyz/login"
