"""Generic structured JSON security event parser with flexible schema alias matching."""

from typing import Any

from backend.app.ingestion.interfaces import EventParser, ParsedEvent, TelemetrySourceType
from backend.app.ingestion.parsers.base import (
    extract_ip,
    extract_port,
    map_severity_str,
    parse_datetime_safe,
    parse_json_safe,
)
from backend.app.schemas.events import EventSeverity


class JsonEventParser(EventParser):
    """Parser for arbitrary structured JSON security events and SIEM/Cloud alerts."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.JSON

    @property
    def parser_name(self) -> str:
        return "generic_json_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Check if payload is valid JSON dictionary."""
        data, err = parse_json_safe(raw_data)
        return err is None and isinstance(data, dict)

    def _get_first(self, data: dict[str, Any], keys: tuple[str, ...]) -> Any:
        """Return the first non-None value matching candidate keys or nested paths."""
        for key in keys:
            if key in data and data[key] is not None:
                return data[key]
            # Check nested dotted key like 'source.ip'
            if "." in key:
                parts = key.split(".")
                curr: Any = data
                for p in parts:
                    if isinstance(curr, dict) and p in curr:
                        curr = curr[p]
                    else:
                        curr = None
                        break
                if curr is not None:
                    return curr
        return None

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Extract canonical security fields from structured JSON object."""
        data, err = parse_json_safe(raw_data)
        if err or data is None:
            raise ValueError(f"Failed to parse JSON telemetry: {err}")

        # 1. Timestamp extraction with alias candidates
        raw_ts = self._get_first(
            data,
            (
                "timestamp",
                "@timestamp",
                "time",
                "event_time",
                "created_at",
                "dateTime",
                "EventTime",
                "TimeCreated",
            ),
        )
        event_time = parse_datetime_safe(raw_ts)

        # 2. Network 5-tuple
        src_ip_val = self._get_first(
            data,
            (
                "source_ip",
                "src_ip",
                "src",
                "source.ip",
                "client_ip",
                "srcAddress",
                "sourceIPAddress",
                "clientIp",
                "IpAddress",
            ),
        )
        dest_ip_val = self._get_first(
            data,
            (
                "destination_ip",
                "dest_ip",
                "dst",
                "destination.ip",
                "server_ip",
                "destAddress",
                "destinationIPAddress",
                "target_ip",
            ),
        )
        src_port_val = self._get_first(
            data,
            (
                "source_port",
                "src_port",
                "src_pt",
                "source.port",
                "srcPort",
                "sourcePort",
                "IpPort",
            ),
        )
        dest_port_val = self._get_first(
            data,
            (
                "destination_port",
                "dest_port",
                "dst_port",
                "destination.port",
                "destPort",
                "destinationPort",
                "target_port",
            ),
        )
        proto_val = self._get_first(
            data,
            ("protocol", "proto", "network.protocol", "transport", "network_protocol"),
        )

        src_ip = extract_ip(src_ip_val)
        dest_ip = extract_ip(dest_ip_val)
        src_port = extract_port(src_port_val)
        dest_port = extract_port(dest_port_val)
        protocol = str(proto_val).upper() if proto_val else None

        # 3. Identity and Host
        username_val = self._get_first(
            data,
            (
                "username",
                "user",
                "user_name",
                "user.name",
                "principal",
                "TargetUserName",
                "actor",
                "userIdentity.userName",
            ),
        )
        hostname_val = self._get_first(
            data,
            (
                "hostname",
                "host",
                "host.name",
                "computer_name",
                "Computer",
                "node_name",
                "WorkstationName",
            ),
        )
        domain_val = self._get_first(
            data,
            ("domain", "realm", "domain_name", "user.domain", "TargetDomainName"),
        )

        # 4. Classification, Severity & Action
        event_type_val = (
            self._get_first(
                data,
                (
                    "event_type",
                    "type",
                    "name",
                    "event_name",
                    "eventName",
                    "action_type",
                    "activity",
                ),
            )
            or "json_security_event"
        )

        sev_val = self._get_first(
            data,
            ("severity", "level", "priority", "threat_level", "risk_level", "Severity"),
        )
        severity = map_severity_str(sev_val, default=EventSeverity.LOW)

        action_val = self._get_first(
            data,
            ("action", "event_action", "disposition", "decision", "rule_action"),
        )
        status_val = self._get_first(
            data,
            ("status", "result", "outcome", "event_status", "response_status"),
        )
        url_val = self._get_first(data, ("url", "uri", "request_url", "http.url"))
        hash_val = self._get_first(
            data,
            ("hash", "sha256", "md5", "file.hash.sha256", "file_hash", "checksum"),
        )

        # 5. Metadata
        metadata = dict(data)
        # Avoid redundant nesting of huge fields if already pulled
        metadata["parsed_as"] = "generic_json"

        return ParsedEvent(
            source_type=TelemetrySourceType.JSON,
            raw_payload=raw_data,
            extracted_fields=data,
            timestamp=event_time,
            event_type=str(event_type_val).lower(),
            severity=severity,
            source_ip=src_ip,
            destination_ip=dest_ip,
            source_port=src_port,
            destination_port=dest_port,
            protocol=protocol,
            username=str(username_val) if username_val else None,
            hostname=str(hostname_val) if hostname_val else None,
            domain=str(domain_val) if domain_val else None,
            action=str(action_val).lower() if action_val else None,
            status=str(status_val).lower() if status_val else None,
            url=str(url_val) if url_val else None,
            hash=str(hash_val) if hash_val else None,
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
