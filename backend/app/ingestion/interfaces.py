"""Abstract interfaces and protocol definitions for the telemetry ingestion layer."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from backend.app.schemas.events import EventSeverity, SecurityEvent


class TelemetrySourceType(StrEnum):
    """Supported telemetry source categories."""

    SURICATA = "suricata"
    SYSLOG = "syslog"
    JSON = "json"
    APPLICATION = "application"
    AUTHENTICATION = "authentication"
    EMAIL = "email"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str | None) -> "TelemetrySourceType":
        """Safe parser from string value."""
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        for member in cls:
            if member.value == val:
                return member
        return cls.UNKNOWN


@dataclass(frozen=True)
class ParsedEvent:
    """Intermediate parsed event data container before normalization."""

    source_type: TelemetrySourceType
    raw_payload: Any
    extracted_fields: dict[str, Any]
    timestamp: datetime | None = None
    event_type: str = "generic_event"
    severity: EventSeverity | str = EventSeverity.LOW
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    hostname: str | None = None
    domain: str | None = None
    action: str | None = None
    status: str | None = None
    url: str | None = None
    hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    parser_name: str = "base"
    parser_version: str = "1.0.0"


class EventParser(ABC):
    """Abstract Base Class for raw telemetry syntax parsing."""

    @property
    @abstractmethod
    def source_type(self) -> TelemetrySourceType:
        """Return the telemetry source type handled by this parser."""
        ...

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Return identifier name for this parser."""
        ...

    @property
    def parser_version(self) -> str:
        """Return version string for this parser implementation."""
        return "1.0.0"

    @abstractmethod
    def can_parse(self, raw_data: Any) -> bool:
        """Determine if this parser can handle the given raw payload."""
        ...

    @abstractmethod
    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse raw payload into intermediate ParsedEvent representation.

        Raises:
            ValueError or ParsingError if raw_data cannot be parsed.
        """
        ...


class EventNormalizer(ABC):
    """Abstract Base Class for transforming parsed data into canonical SecurityEvent."""

    @property
    @abstractmethod
    def source_type(self) -> TelemetrySourceType:
        """Return the telemetry source type handled by this normalizer."""
        ...

    @abstractmethod
    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform ParsedEvent into canonical ECS/OCSF compliant SecurityEvent."""
        ...


class DeadLetterHandler(ABC):
    """Abstract Base Class for Dead-Letter Queue (DLQ) processing."""

    @abstractmethod
    async def handle_invalid_event(
        self,
        raw_payload: Any,
        error_message: str,
        error_type: str = "validation_error",
        source: str = "unknown",
        source_type: str = "unknown",
        validation_errors: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record and route invalid event to dead-letter storage and broker topic."""
        ...


class TelemetryCollector(ABC):
    """Abstract Base Class for telemetry collectors receiving events from sources."""

    @property
    @abstractmethod
    def collector_name(self) -> str:
        """Return identifier name of this collector."""
        ...

    @abstractmethod
    async def collect(
        self,
        raw_payload: Any,
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest, validate, and process single telemetry payload."""
        ...

    @abstractmethod
    async def collect_batch(
        self,
        raw_payloads: list[Any],
        source_type: str | TelemetrySourceType | None = None,
        source_identifier: str | None = None,
    ) -> dict[str, Any]:
        """Ingest, validate, and process batch of telemetry payloads."""
        ...
