"""Unit tests for SecurityEventModel database entity and index definitions."""

from datetime import UTC, datetime

from sqlalchemy import inspect

from backend.app.models.event import SecurityEventModel
from backend.app.schemas.events import EventSeverity, SecurityEvent


def test_security_event_model_table_name() -> None:
    """Verify table name is security_events."""
    assert SecurityEventModel.__tablename__ == "security_events"


def test_security_event_model_column_attributes() -> None:
    """Verify all canonical and lineage columns exist with correct nullable and index configs."""
    mapper = inspect(SecurityEventModel)
    columns = {col.key: col for col in mapper.columns}

    # Verify primary key
    assert "id" in columns
    assert columns["id"].primary_key

    # Verify required canonical fields
    assert "event_id" in columns
    assert not columns["event_id"].nullable
    assert columns["event_id"].unique

    assert "timestamp" in columns
    assert not columns["timestamp"].nullable

    assert "source" in columns
    assert not columns["source"].nullable

    assert "source_type" in columns
    assert not columns["source_type"].nullable

    assert "event_type" in columns
    assert not columns["event_type"].nullable

    assert "severity" in columns
    assert not columns["severity"].nullable

    assert "raw_data" in columns
    assert not columns["raw_data"].nullable

    assert "normalized_data" in columns
    assert not columns["normalized_data"].nullable

    # Verify optional canonical fields
    assert "source_ip" in columns
    assert columns["source_ip"].nullable

    assert "destination_ip" in columns
    assert columns["destination_ip"].nullable

    assert "source_port" in columns
    assert columns["source_port"].nullable

    assert "destination_port" in columns
    assert columns["destination_port"].nullable

    assert "username" in columns
    assert "hostname" in columns
    assert "domain" in columns
    assert "url" in columns
    assert "hash" in columns
    assert "protocol" in columns
    assert "action" in columns
    assert "status" in columns
    assert "asset_id" in columns
    assert "metadata_payload" in columns

    # Verify lineage metadata fields
    assert "parser_version" in columns
    assert not columns["parser_version"].nullable

    assert "ingestion_timestamp" in columns
    assert not columns["ingestion_timestamp"].nullable


def test_security_event_model_indexes() -> None:
    """Verify required indexes exist on timestamp, source, event_type, IP fields, and severity."""
    table = SecurityEventModel.__table__
    indexed_column_sets = {
        tuple(col.name for col in idx.columns) for idx in table.indexes
    }

    # Required single-column indexes
    assert ("timestamp",) in indexed_column_sets
    assert ("source",) in indexed_column_sets
    assert ("event_type",) in indexed_column_sets
    assert ("source_ip",) in indexed_column_sets
    assert ("destination_ip",) in indexed_column_sets
    assert ("severity",) in indexed_column_sets

    # Composite query acceleration indexes
    assert ("timestamp", "severity") in indexed_column_sets
    assert ("source", "event_type") in indexed_column_sets


def test_security_event_schema_to_model_instantiation() -> None:
    """Verify instantiating SecurityEventModel from SecurityEvent schema to_db_dict()."""
    schema_event = SecurityEvent(
        event_id="evt-db-test-01",
        timestamp=datetime.now(UTC),
        source="suricata-ids",
        source_type="network_ids",
        event_type="port_scan",
        severity=EventSeverity.CRITICAL,
        raw_data={"alert": "ET SCAN Nmap"},
        normalized_data={"category": "reconnaissance"},
        source_ip="10.0.0.99",
        destination_ip="10.0.0.1",
        source_port=55123,
        destination_port=80,
        username="attacker",
        metadata={"scanner": "nmap-syn"},
    )

    db_dict = schema_event.to_db_dict()
    db_model = SecurityEventModel(**db_dict)

    assert db_model.event_id == "evt-db-test-01"
    assert db_model.source == "suricata-ids"
    assert db_model.event_type == "port_scan"
    assert db_model.severity == "critical"
    assert db_model.source_ip == "10.0.0.99"
    assert db_model.destination_ip == "10.0.0.1"
    assert db_model.source_port == 55123
    assert db_model.destination_port == 80
    assert db_model.metadata_payload == {"scanner": "nmap-syn"}
    assert "evt-db-test-01" in repr(db_model)
