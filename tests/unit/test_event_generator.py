"""Unit tests for the synthetic event generator."""

from scripts.event_generator import (
    DEMO_ENVIRONMENT_TAG,
    generate_application_event,
    generate_authentication_event,
    generate_email_event,
    generate_event,
    generate_json_event,
    generate_suricata_event,
    generate_syslog_event,
)


def test_suricata_event_generator() -> None:
    event = generate_suricata_event()
    assert isinstance(event, dict)
    assert event["environment"] == DEMO_ENVIRONMENT_TAG
    assert event["synthetic"] is True
    assert event["event_type"] == "alert"
    assert "src_ip" in event
    assert "dest_ip" in event
    assert "alert" in event
    assert "[DEMO]" in event["alert"]["signature"]


def test_syslog_event_generator() -> None:
    line = generate_syslog_event()
    assert isinstance(line, str)
    assert DEMO_ENVIRONMENT_TAG in line
    assert "sshd" in line or "sudo" in line or "UFW" in line


def test_json_event_generator() -> None:
    event = generate_json_event()
    assert isinstance(event, dict)
    assert event["environment"] == DEMO_ENVIRONMENT_TAG
    assert event["synthetic"] is True
    assert "event_type" in event
    assert "source_ip" in event


def test_application_event_generator() -> None:
    line = generate_application_event()
    assert isinstance(line, str)
    assert DEMO_ENVIRONMENT_TAG in line
    assert "HTTP/1.1" in line


def test_authentication_event_generator() -> None:
    event = generate_authentication_event()
    assert isinstance(event, dict)
    assert event["environment"] == DEMO_ENVIRONMENT_TAG
    assert event["synthetic"] is True
    assert event["EventID"] in (4624, 4625)
    assert "TargetUserName" in event


def test_email_event_generator() -> None:
    event = generate_email_event()
    assert isinstance(event, dict)
    assert event["environment"] == DEMO_ENVIRONMENT_TAG
    assert event["synthetic"] is True
    assert "sender" in event
    assert "recipient" in event
    assert "spf_result" in event


def test_generate_all_sources() -> None:
    for source in [
        "suricata",
        "syslog",
        "json",
        "application",
        "authentication",
        "email",
        "all",
    ]:
        payload, _st = generate_event(source)
        assert payload is not None
        if isinstance(payload, dict):
            assert payload.get("environment") == DEMO_ENVIRONMENT_TAG
            assert payload.get("synthetic") is True
        else:
            assert DEMO_ENVIRONMENT_TAG in str(payload)
