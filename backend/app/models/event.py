"""SQLAlchemy database model for Canonical Security Events."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import Base, TimestampMixin


class SecurityEventModel(Base, TimestampMixin):
    """Database model for storing canonical security telemetry and incident events."""

    __tablename__ = "security_events"

    # Primary key
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # Required canonical fields
    event_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(128),
        index=True,
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(128),
        index=True,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )
    raw_data: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )
    normalized_data: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )

    # Optional canonical fields
    source_ip: Mapped[str | None] = mapped_column(
        String(45),
        index=True,
        nullable=True,
    )
    destination_ip: Mapped[str | None] = mapped_column(
        String(45),
        index=True,
        nullable=True,
    )
    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    destination_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    url: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    protocol: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    action: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    status: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    # Lineage metadata fields
    parser_version: Mapped[str] = mapped_column(
        String(32),
        default="1.0.0",
        nullable=False,
    )
    ingestion_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Composite indexes.
    # Individual indexes are already created by index=True above.
    __table_args__ = (
        Index(
            "ix_security_events_timestamp_severity",
            "timestamp",
            "severity",
        ),
        Index(
            "ix_security_events_source_event_type",
            "source",
            "event_type",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEventModel(id={self.id}, event_id='{self.event_id}', "
            f"source='{self.source}', event_type='{self.event_type}', "
            f"severity='{self.severity}')>"
        )
