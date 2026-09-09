"""Canonical Security Event schema, lineage tracking, and safe validation pipeline."""

import ipaddress
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from backend.app.utils.datetime import utc_now


class EventSeverity(StrEnum):
    """Standardized severity classification for security telemetry."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object) -> "EventSeverity | None":
        if isinstance(value, str):
            val_lower = value.strip().lower()
            for member in cls:
                if member.value == val_lower:
                    return member
        return None


class EventLineage(BaseModel):
    """Data lineage tracking the origin, raw input, parser, and ingestion timestamp."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_input: dict[str, Any] | str = Field(
        ..., description="Original unaltered raw telemetry input"
    )
    normalized_representation: dict[str, Any] = Field(
        ..., description="Standardized ECS/OCSF normalized representation"
    )
    parser_version: str = Field(
        default="1.0.0", description="Version of the parsing and normalization engine"
    )
    source: str = Field(..., description="Telemetry source identifier")
    ingestion_timestamp: datetime = Field(
        default_factory=utc_now, description="UTC timestamp of pipeline ingestion"
    )


def _parse_timestamp_str(v_str: str) -> datetime:
    """Helper to parse and validate ISO 8601 timestamp string."""
    v_clean = v_str.strip()
    if not v_clean:
        raise ValueError("Timestamp string cannot be empty")
    if v_clean.endswith("Z"):
        v_clean = v_clean[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v_clean)
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt
    except ValueError as err:
        raise ValueError(f"Invalid timestamp format: '{v_str}' (expected ISO 8601)") from err


def _parse_timestamp_numeric(v_num: int | float) -> datetime:
    """Helper to parse epoch timestamp in seconds or milliseconds."""
    seconds = v_num / 1000.0 if v_num > 1e11 else float(v_num)
    return datetime.fromtimestamp(seconds, tz=UTC)


class SecurityEvent(BaseModel):
    """Canonical Unified Security Event Model conforming to ECS/OCSF standards."""

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Required Canonical Fields
    event_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique canonical event identifier",
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp of the security event occurrence",
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Telemetry origin source (e.g. suricata, zeek, auth_log)",
    )
    source_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Domain category of telemetry (e.g. syslog, network_ids, host_edr)",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Specific classification of event (e.g. auth_failed, c2_beacon)",
    )
    severity: EventSeverity = Field(
        ...,
        description="Normalized severity rating (informational, low, medium, high, critical)",
    )
    raw_data: dict[str, Any] | str = Field(
        ...,
        description="Raw immutable input payload as received before normalization",
    )
    normalized_data: dict[str, Any] = Field(
        ...,
        description="Normalized structured representation conforming to canonical taxonomy",
    )

    # Optional Canonical Fields
    source_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Source IPv4 or IPv6 address",
    )
    destination_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Destination IPv4 or IPv6 address",
    )
    source_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source network transport port (0-65535)",
    )
    destination_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination network transport port (0-65535)",
    )
    username: str | None = Field(
        default=None,
        max_length=128,
        description="Associated user account or principal name",
    )
    hostname: str | None = Field(
        default=None,
        max_length=255,
        description="Associated endpoint, server, or host device name",
    )
    domain: str | None = Field(
        default=None,
        max_length=255,
        description="Network domain or Kerberos realm",
    )
    url: str | None = Field(
        default=None,
        description="Uniform Resource Locator involved in event",
    )
    hash: str | None = Field(
        default=None,
        max_length=128,
        description="Cryptographic file hash (MD5, SHA1, SHA256)",
    )
    protocol: str | None = Field(
        default=None,
        max_length=32,
        description="Network protocol (e.g. TCP, UDP, ICMP, DNS, HTTP, TLS)",
    )
    action: str | None = Field(
        default=None,
        max_length=64,
        description="Enforced or observed security action (e.g. allowed, blocked)",
    )
    status: str | None = Field(
        default=None,
        max_length=64,
        description="Outcome status of the activity (e.g. success, failure)",
    )
    asset_id: str | None = Field(
        default=None,
        max_length=128,
        description="Unique inventory asset identifier from CMDB or asset registry",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary contextual metadata and custom vendor tags",
    )

    # Lineage Metadata Fields
    parser_version: str = Field(
        default="1.0.0",
        max_length=32,
        description="Version string of parser/normalization engine",
    )
    ingestion_timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when the event was ingested by the pipeline",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, v: Any) -> datetime:
        """Validate and normalize timestamp into timezone-aware datetime."""
        if v is None:
            raise ValueError("Timestamp cannot be None")
        if isinstance(v, datetime):
            return v.replace(tzinfo=UTC) if v.tzinfo is None else v
        if isinstance(v, (int, float)):
            return _parse_timestamp_numeric(v)
        if isinstance(v, str):
            return _parse_timestamp_str(v)
        raise ValueError(f"Invalid timestamp type: {type(v).__name__}")

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ip_address(cls, v: Any) -> str | None:
        """Validate IPv4 and IPv6 addresses."""
        if v is None:
            return None
        if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return str(v)
        if isinstance(v, str):
            v_str = v.strip()
            if not v_str:
                return None
            try:
                ip = ipaddress.ip_address(v_str)
                return str(ip)
            except ValueError as err:
                raise ValueError(f"Invalid IP address: '{v_str}'") from err
        raise ValueError(
            f"IP address must be a string or IPAddress instance, got {type(v).__name__}"
        )

    @field_validator("metadata", mode="before")
    @classmethod
    def validate_metadata(cls, v: Any) -> dict[str, Any]:
        """Validate metadata is a dictionary."""
        if v is None:
            return {}
        if isinstance(v, dict):
            return v
        raise ValueError(f"metadata must be a dictionary, got {type(v).__name__}")

    @field_validator("normalized_data", mode="before")
    @classmethod
    def validate_normalized_data(cls, v: Any) -> dict[str, Any]:
        """Validate normalized_data is a dictionary."""
        if isinstance(v, dict):
            return v
        raise ValueError(f"normalized_data must be a dictionary, got {type(v).__name__}")

    def get_lineage(self) -> EventLineage:
        """Extract the full lineage provenance record for this security event."""
        return EventLineage(
            raw_input=self.raw_data,
            normalized_representation=self.normalized_data,
            parser_version=self.parser_version,
            source=self.source,
            ingestion_timestamp=self.ingestion_timestamp,
        )

    def to_db_dict(self) -> dict[str, Any]:
        """Convert to dictionary matching the SQLAlchemy SecurityEventModel attributes."""
        sev = (
            self.severity.value if isinstance(self.severity, EventSeverity) else str(self.severity)
        )
        raw = self.raw_data if isinstance(self.raw_data, dict) else {"raw": str(self.raw_data)}
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "severity": sev,
            "raw_data": raw,
            "normalized_data": self.normalized_data,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "hostname": self.hostname,
            "domain": self.domain,
            "url": self.url,
            "hash": self.hash,
            "protocol": self.protocol,
            "action": self.action,
            "status": self.status,
            "asset_id": self.asset_id,
            "metadata_payload": self.metadata,
            "parser_version": self.parser_version,
            "ingestion_timestamp": self.ingestion_timestamp,
        }


class EventValidationResult(BaseModel):
    """Result object encapsulating safe event validation status and diagnostics."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_valid: bool = Field(..., description="Whether event passed validation")
    event: SecurityEvent | None = Field(default=None, description="Parsed canonical SecurityEvent")
    error_message: str | None = Field(default=None, description="Human-readable error summary")
    validation_errors: list[dict[str, Any]] = Field(
        default_factory=list, description="Structured field validation errors"
    )
    raw_payload: Any = Field(default=None, description="Original unparsed payload")


def _calc_payload_size(raw_input: Any) -> int:
    """Calculate byte size of raw input."""
    if isinstance(raw_input, (str, bytes)):
        return len(raw_input)
    if isinstance(raw_input, dict):
        return len(json.dumps(raw_input))
    return 0


def _parse_raw_payload_dict(raw_input: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Extract or parse dictionary payload from raw input."""
    if isinstance(raw_input, str):
        try:
            parsed = json.loads(raw_input)
            if not isinstance(parsed, dict):
                return None, f"Expected JSON object dict, got {type(parsed).__name__}"
            return parsed, None
        except Exception as exc:
            return None, f"Malformed JSON payload: {str(exc)}"
    if isinstance(raw_input, dict):
        return raw_input, None
    return None, f"Event payload must be a dict or JSON string, got {type(raw_input).__name__}"


def validate_security_event_safely(
    raw_input: Any,
    max_size_bytes: int = 1_048_576,  # 1 MB maximum payload safeguard
    default_parser_version: str = "1.0.0",
) -> EventValidationResult:
    """Safely validate raw telemetry into a canonical SecurityEvent without throwing exceptions."""
    if raw_input is None:
        return EventValidationResult(
            is_valid=False,
            event=None,
            error_message="Event payload cannot be None",
            validation_errors=[
                {"loc": ["payload"], "msg": "Payload is None", "type": "value_error"}
            ],
            raw_payload=None,
        )

    # 1. Check payload size against maximum threshold
    try:
        size = _calc_payload_size(raw_input)
        if size > max_size_bytes:
            msg = (
                f"Payload size {size} bytes exceeds maximum allowed limit of {max_size_bytes} bytes"
            )
            return EventValidationResult(
                is_valid=False,
                event=None,
                error_message=(
                    f"Payload size {size} bytes exceeds maximum limit of {max_size_bytes} bytes"
                ),
                validation_errors=[{"loc": ["payload"], "msg": msg, "type": "oversized_payload"}],
                raw_payload=str(raw_input)[:256] + "... [truncated]",
            )
    except Exception as exc:
        return EventValidationResult(
            is_valid=False,
            event=None,
            error_message=f"Failed to check payload size: {str(exc)}",
            validation_errors=[{"loc": ["payload"], "msg": str(exc), "type": "size_check_error"}],
            raw_payload=None,
        )

    # 2. Parse dictionary structure
    parsed_dict, parse_err = _parse_raw_payload_dict(raw_input)
    if parse_err is not None or parsed_dict is None:
        return EventValidationResult(
            is_valid=False,
            event=None,
            error_message=parse_err,
            validation_errors=[
                {"loc": ["payload"], "msg": parse_err or "Invalid payload", "type": "type_error"}
            ],
            raw_payload=raw_input,
        )

    # 3. Inject parser version if omitted
    if "parser_version" not in parsed_dict:
        parsed_dict["parser_version"] = default_parser_version

    # 4. Pydantic canonical validation
    try:
        event = SecurityEvent.model_validate(parsed_dict)
        return EventValidationResult(
            is_valid=True,
            event=event,
            error_message=None,
            validation_errors=[],
            raw_payload=raw_input,
        )
    except ValidationError as val_err:
        errors = [
            {
                "loc": [str(loc) for loc in err.get("loc", [])],
                "msg": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in val_err.errors()
        ]
        return EventValidationResult(
            is_valid=False,
            event=None,
            error_message=f"Validation failed: {len(errors)} error(s) found",
            validation_errors=errors,
            raw_payload=raw_input,
        )
    except Exception as exc:
        return EventValidationResult(
            is_valid=False,
            event=None,
            error_message=f"Unexpected validation exception: {str(exc)}",
            validation_errors=[
                {"loc": ["__all__"], "msg": str(exc), "type": "unexpected_exception"}
            ],
            raw_payload=raw_input,
        )
