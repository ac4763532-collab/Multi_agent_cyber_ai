"""Unit tests for Canonical SecurityEvent Pydantic schema and safe validation pipeline."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.app.schemas.events import (
    EventLineage,
    EventSeverity,
    SecurityEvent,
    validate_security_event_safely,
)


@pytest.fixture
def valid_event_dict() -> dict:
    """Fixture providing a standard valid security event dictionary."""
    return {
        "event_id": "evt-sec-98214-uuid",
        "timestamp": "2026-09-08T22:00:00Z",
        "source": "suricata-sensor-01",
        "source_type": "network_ids",
        "event_type": "c2_beacon",
        "severity": "high",
        "raw_data": {
            "timestamp": "2026-09-08T22:00:00.123456+0000",
            "flow_id": 123456789,
            "alert": {"signature": "ET MALWARE Suspicious Beaconing"},
        },
        "normalized_data": {
            "category": "network",
            "action": "blocked",
            "protocol": "TCP",
        },
        "source_ip": "192.168.1.105",
        "destination_ip": "198.51.100.42",
        "source_port": 49152,
        "destination_port": 443,
        "username": "svc-backup",
        "hostname": "srv-prod-db01",
        "domain": "corp.internal",
        "url": "https://evil-c2.example.com/gate.php",
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "protocol": "TCP",
        "action": "blocked",
        "status": "failure",
        "asset_id": "asset-server-0092",
        "metadata": {
            "env": "production",
            "zone": "dmz",
            "vlan": 20,
        },
        "parser_version": "1.0.0",
    }


def test_valid_security_event_instantiation_full(valid_event_dict: dict) -> None:
    """Verify instantiation with all canonical required and optional fields."""
    event = SecurityEvent.model_validate(valid_event_dict)

    assert event.event_id == "evt-sec-98214-uuid"
    assert event.source == "suricata-sensor-01"
    assert event.source_type == "network_ids"
    assert event.event_type == "c2_beacon"
    assert event.severity == EventSeverity.HIGH
    assert event.source_ip == "192.168.1.105"
    assert event.destination_ip == "198.51.100.42"
    assert event.source_port == 49152
    assert event.destination_port == 443
    assert event.username == "svc-backup"
    assert event.hostname == "srv-prod-db01"
    assert event.domain == "corp.internal"
    assert event.url == "https://evil-c2.example.com/gate.php"
    assert (
        event.hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert event.protocol == "TCP"
    assert event.action == "blocked"
    assert event.status == "failure"
    assert event.asset_id == "asset-server-0092"
    assert event.metadata["zone"] == "dmz"
    assert event.parser_version == "1.0.0"
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None
    assert isinstance(event.ingestion_timestamp, datetime)


def test_valid_security_event_minimal_required_fields() -> None:
    """Verify instantiation with only mandatory canonical fields."""
    minimal_event = {
        "event_id": "evt-min-001",
        "timestamp": datetime.now(UTC),
        "source": "syslog",
        "source_type": "os_syslog",
        "event_type": "auth_login",
        "severity": EventSeverity.INFORMATIONAL,
        "raw_data": "Sep  8 22:00:00 localhost sshd[1234]: Accepted publickey",
        "normalized_data": {"action": "allowed"},
    }

    event = SecurityEvent.model_validate(minimal_event)
    assert event.event_id == "evt-min-001"
    assert event.source_ip is None
    assert event.destination_ip is None
    assert event.source_port is None
    assert event.destination_port is None
    assert event.username is None
    assert event.metadata == {}
    assert event.parser_version == "1.0.0"
    assert isinstance(event.ingestion_timestamp, datetime)


@pytest.mark.parametrize(
    "missing_field",
    [
        "event_id",
        "timestamp",
        "source",
        "source_type",
        "event_type",
        "severity",
        "raw_data",
        "normalized_data",
    ],
)
def test_missing_required_fields(valid_event_dict: dict, missing_field: str) -> None:
    """Verify rejection when any required canonical field is missing."""
    invalid_data = valid_event_dict.copy()
    del invalid_data[missing_field]

    # Direct Pydantic validation should raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent.model_validate(invalid_data)

    errors = exc_info.value.errors()
    assert any(missing_field in str(err["loc"]) for err in errors)

    # Safe validation wrapper should reject safely without throwing
    res = validate_security_event_safely(invalid_data)
    assert not res.is_valid
    assert res.event is None
    assert res.error_message is not None
    assert len(res.validation_errors) > 0


@pytest.mark.parametrize(
    "invalid_ts",
    [
        "not-a-timestamp",
        "2026-99-99T99:99:99Z",
        "2026/09/08 25:00:00",
        "",
        None,
        {"time": "now"},
    ],
)
def test_invalid_timestamp(valid_event_dict: dict, invalid_ts: object) -> None:
    """Verify rejection of malformed, invalid, or unparseable timestamps."""
    invalid_data = valid_event_dict.copy()
    invalid_data["timestamp"] = invalid_ts

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(invalid_data)

    res = validate_security_event_safely(invalid_data)
    assert not res.is_valid
    assert res.event is None


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.999.999.999",
        "256.1.1.1",
        "192.168.1.1.1",
        "not_an_ip",
        "1234::gggg",
        "192.168.1.1:8080",
    ],
)
def test_invalid_ip_addresses(valid_event_dict: dict, invalid_ip: str) -> None:
    """Verify rejection of malformed IPv4 and IPv6 addresses."""
    # Test source_ip
    invalid_src = valid_event_dict.copy()
    invalid_src["source_ip"] = invalid_ip
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(invalid_src)

    res_src = validate_security_event_safely(invalid_src)
    assert not res_src.is_valid

    # Test destination_ip
    invalid_dst = valid_event_dict.copy()
    invalid_dst["destination_ip"] = invalid_ip
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(invalid_dst)

    res_dst = validate_security_event_safely(invalid_dst)
    assert not res_dst.is_valid


@pytest.mark.parametrize(
    "valid_ip",
    [
        "127.0.0.1",
        "192.168.1.100",
        "10.0.0.1",
        "172.16.254.1",
        "8.8.8.8",
        "::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1",
    ],
)
def test_valid_ip_addresses(valid_event_dict: dict, valid_ip: str) -> None:
    """Verify valid IPv4 and IPv6 addresses are accepted and normalized."""
    data = valid_event_dict.copy()
    data["source_ip"] = valid_ip
    data["destination_ip"] = valid_ip

    event = SecurityEvent.model_validate(data)
    assert event.source_ip is not None
    assert event.destination_ip is not None


def test_oversized_event_rejection(valid_event_dict: dict) -> None:
    """Verify safe rejection of oversized payloads exceeding size thresholds."""
    oversized_data = valid_event_dict.copy()
    # Create large payload chunk (2 MB payload)
    oversized_data["raw_data"] = {"huge_blob": "A" * (2 * 1024 * 1024)}

    # Safe validation wrapper with 1MB ceiling
    res = validate_security_event_safely(oversized_data, max_size_bytes=1_048_576)
    assert not res.is_valid
    assert res.event is None
    assert "exceeds maximum limit" in (res.error_message or "")
    assert res.validation_errors[0]["type"] == "oversized_payload"


@pytest.mark.parametrize(
    "malformed_meta",
    [
        "invalid_string_metadata",
        ["item1", "item2"],
        12345,
        True,
    ],
)
def test_malformed_metadata(valid_event_dict: dict, malformed_meta: object) -> None:
    """Verify rejection when metadata is not a key-value dictionary."""
    invalid_data = valid_event_dict.copy()
    invalid_data["metadata"] = malformed_meta

    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(invalid_data)

    res = validate_security_event_safely(invalid_data)
    assert not res.is_valid
    assert res.event is None


def test_event_lineage_preservation(valid_event_dict: dict) -> None:
    """Verify lineage preserves raw input, normalized representation, parser, and timestamp."""
    event = SecurityEvent.model_validate(valid_event_dict)
    lineage = event.get_lineage()

    assert isinstance(lineage, EventLineage)
    assert lineage.raw_input == valid_event_dict["raw_data"]
    assert lineage.normalized_representation == valid_event_dict["normalized_data"]
    assert lineage.parser_version == "1.0.0"
    assert lineage.source == "suricata-sensor-01"
    assert isinstance(lineage.ingestion_timestamp, datetime)
    assert lineage.ingestion_timestamp.tzinfo is not None

    # Verify property accessors
    assert event.lineage == lineage
    assert event.raw_input == valid_event_dict["raw_data"]
    assert event.normalized_representation == valid_event_dict["normalized_data"]
    assert event.parser_version == "1.0.0"
    assert event.source == "suricata-sensor-01"
    assert isinstance(event.ingestion_timestamp, datetime)


def test_safe_validation_pipeline_resilience() -> None:
    """Verify safe validator never throws exceptions on corrupted or unexpected inputs."""
    # Test None
    res_none = validate_security_event_safely(None)
    assert not res_none.is_valid
    assert "cannot be None" in (res_none.error_message or "")

    # Test empty string
    res_empty = validate_security_event_safely("")
    assert not res_empty.is_valid

    # Test corrupted JSON string
    res_corrupt_json = validate_security_event_safely("{invalid json::: 123")
    assert not res_corrupt_json.is_valid
    assert "Malformed JSON" in (res_corrupt_json.error_message or "")

    # Test non-dict JSON array
    res_array = validate_security_event_safely(json.dumps([1, 2, 3, "test"]))
    assert not res_array.is_valid
    assert "Expected JSON object dict, got list" in (res_array.error_message or "")

    # Test non-dict non-string object (e.g. integer or list)
    res_int = validate_security_event_safely(12345)
    assert not res_int.is_valid
    assert "must be a dict or JSON string" in (res_int.error_message or "")

    # Test valid JSON string
    valid_json_str = json.dumps(
        {
            "event_id": "evt-json-01",
            "timestamp": "2026-09-08T22:30:00Z",
            "source": "auth-log",
            "source_type": "syslog",
            "event_type": "user_login",
            "severity": "low",
            "raw_data": {"msg": "login success"},
            "normalized_data": {"action": "allow"},
        }
    )
    res_valid = validate_security_event_safely(valid_json_str)
    assert res_valid.is_valid
    assert res_valid.event is not None
    assert res_valid.event.event_id == "evt-json-01"


def test_to_db_dict_serialization(valid_event_dict: dict) -> None:
    """Verify conversion of SecurityEvent to database entity dictionary."""
    event = SecurityEvent.model_validate(valid_event_dict)
    db_dict = event.to_db_dict()

    assert db_dict["event_id"] == "evt-sec-98214-uuid"
    assert db_dict["severity"] == "high"
    assert db_dict["source_ip"] == "192.168.1.105"
    assert db_dict["metadata_payload"] == valid_event_dict["metadata"]
    assert "metadata" not in db_dict  # Key renamed to metadata_payload for DB
    assert db_dict["parser_version"] == "1.0.0"
