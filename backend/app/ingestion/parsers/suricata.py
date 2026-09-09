"""Suricata EVE JSON parser for Network Intrusion Detection & Flow telemetry."""

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


class SuricataEveParser(EventParser):
    """Parser for Suricata EVE JSON format logs (alerts, dns, http, tls, flow, etc.)."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.SURICATA

    @property
    def parser_name(self) -> str:
        return "suricata_eve_json_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, raw_data: Any) -> bool:
        """Heuristic check for Suricata EVE JSON format."""
        data, err = parse_json_safe(raw_data)
        if err or data is None:
            return False

        # Check characteristic Suricata fields
        has_suricata_fields = "event_type" in data and (
            "src_ip" in data or "dest_ip" in data or "flow_id" in data or "alert" in data
        )
        has_suricata_tag = (
            data.get("source") == "suricata"
            or data.get("app") == "suricata"
            or "suricata" in str(data.get("tags", "")).lower()
        )
        return bool(has_suricata_fields or has_suricata_tag)

    def parse(self, raw_data: Any) -> ParsedEvent:
        """Parse Suricata EVE JSON payload into canonical ParsedEvent."""
        data, err = parse_json_safe(raw_data)
        if err or data is None:
            raise ValueError(f"Failed to parse Suricata EVE JSON: {err}")

        # 1. Timestamp
        raw_ts = data.get("timestamp") or data.get("@timestamp")
        event_time = parse_datetime_safe(raw_ts)

        # 2. Network 5-tuple
        src_ip = extract_ip(data.get("src_ip"))
        dest_ip = extract_ip(data.get("dest_ip"))
        src_port = extract_port(data.get("src_port"))
        dest_port = extract_port(data.get("dest_port"))
        protocol = str(data.get("proto") or "TCP").upper()

        # 3. Event Classification and Action
        suricata_event_type = str(data.get("event_type", "alert")).lower()
        raw_alert = data.get("alert")
        alert_info: dict[str, Any] = raw_alert if isinstance(raw_alert, dict) else {}

        signature = (
            alert_info.get("signature") or alert_info.get("signature_id") or data.get("signature")
        )
        category = alert_info.get("category") or data.get("category") or "Network Security Event"
        action = alert_info.get("action") or data.get("action") or "alert"

        # Severity mapping from Suricata 1-4 scale (1 = critical, 4 = info)
        raw_sev = alert_info.get("severity") or data.get("severity")
        severity = map_severity_str(raw_sev, default=EventSeverity.MEDIUM)

        # Canonical event_type
        if suricata_event_type == "alert":
            canonical_event_type = "network_ids_alert"
        else:
            canonical_event_type = f"network_{suricata_event_type}"

        # 4. Context Metadata
        metadata: dict[str, Any] = {
            "suricata_event_type": suricata_event_type,
            "signature": signature,
            "category": category,
            "action": action,
            "flow_id": data.get("flow_id"),
            "in_iface": data.get("in_iface"),
            "app_proto": data.get("app_proto"),
            "pcap_cnt": data.get("pcap_cnt"),
            "community_id": data.get("community_id"),
        }

        # Include protocol-specific nested blocks if present
        for proto_block in ("http", "dns", "tls", "smtp", "flow", "payload"):
            if proto_block in data and isinstance(data[proto_block], (dict, list, str)):
                metadata[proto_block] = data[proto_block]

        # Extract URL if HTTP metadata present
        url = None
        if isinstance(data.get("http"), dict):
            http_meta = data["http"]
            hostname = http_meta.get("hostname", "")
            http_url = http_meta.get("url", "")
            if hostname or http_url:
                url = f"http://{hostname}{http_url}" if hostname else http_url
        elif "url" in data:
            url = str(data["url"])

        # Extract Hostname
        http_data: dict[str, Any] = data["http"] if isinstance(data.get("http"), dict) else {}
        tls_data: dict[str, Any] = data["tls"] if isinstance(data.get("tls"), dict) else {}
        hostname = data.get("hostname") or http_data.get("hostname") or tls_data.get("sni")

        return ParsedEvent(
            source_type=TelemetrySourceType.SURICATA,
            raw_payload=raw_data,
            extracted_fields=data,
            timestamp=event_time,
            event_type=canonical_event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dest_ip,
            source_port=src_port,
            destination_port=dest_port,
            protocol=protocol,
            hostname=hostname,
            action=str(action).lower(),
            status="triggered" if suricata_event_type == "alert" else "success",
            url=url,
            metadata=metadata,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
