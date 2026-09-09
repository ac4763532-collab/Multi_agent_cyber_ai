"""Base normalizer utilities for producing canonical ECS/OCSF SecurityEvent models."""

import uuid
from typing import Any

from backend.app.ingestion.interfaces import EventNormalizer, ParsedEvent
from backend.app.schemas.events import EventSeverity, SecurityEvent
from backend.app.utils.datetime import utc_now


class BaseNormalizer(EventNormalizer):
    """Base normalizer implementation with shared canonical transformation helpers."""

    @staticmethod
    def _stamp_demonstration_tags(metadata: dict[str, Any], raw_payload: Any) -> None:
        """
        Preserve synthetic/demo markers so generated events are never
        treated as live telemetry.
        """
        if isinstance(raw_payload, dict):
            environment = raw_payload.get("environment")
            synthetic = raw_payload.get("synthetic")
            if environment:
                metadata.setdefault("environment", environment)
            if synthetic is True or str(synthetic).lower() == "true":
                metadata.setdefault("synthetic", True)
            return
        if isinstance(raw_payload, str) and "DEMONSTRATION" in raw_payload:
            metadata.setdefault("environment", "DEMONSTRATION")
            metadata.setdefault("synthetic", True)

    def _build_network_block(self, parsed_event: ParsedEvent) -> dict[str, Any] | None:
        """Build ECS network object."""
        if not (
            parsed_event.source_ip
            or parsed_event.destination_ip
            or parsed_event.source_port
            or parsed_event.destination_port
            or parsed_event.protocol
        ):
            return None

        network_block: dict[str, Any] = {}
        if parsed_event.protocol:
            network_block["transport"] = parsed_event.protocol.lower()
            network_block["protocol"] = parsed_event.protocol.lower()
        if parsed_event.source_ip or parsed_event.source_port:
            network_block["source"] = {
                "ip": parsed_event.source_ip,
                "port": parsed_event.source_port,
            }
        if parsed_event.destination_ip or parsed_event.destination_port:
            network_block["destination"] = {
                "ip": parsed_event.destination_ip,
                "port": parsed_event.destination_port,
            }
        return network_block

    def _build_normalized_data_dict(self, parsed_event: ParsedEvent) -> dict[str, Any]:
        """Build ECS/OCSF aligned normalized dictionary representation."""
        normalized: dict[str, Any] = {
            "ecs_version": "8.11.0",
            "event": {
                "kind": "event",
                "category": [str(parsed_event.source_type.value)],
                "type": [parsed_event.event_type],
                "action": parsed_event.action or "unknown",
                "outcome": parsed_event.status or "unknown",
            },
        }

        network_block = self._build_network_block(parsed_event)
        if network_block:
            normalized["network"] = network_block

        if parsed_event.hostname:
            normalized["host"] = {"hostname": parsed_event.hostname, "name": parsed_event.hostname}

        if parsed_event.username or parsed_event.domain:
            user_block: dict[str, Any] = {}
            if parsed_event.username:
                user_block["name"] = parsed_event.username
            if parsed_event.domain:
                user_block["domain"] = parsed_event.domain
            normalized["user"] = user_block

        if parsed_event.url:
            normalized["url"] = {"original": parsed_event.url}

        if parsed_event.hash:
            normalized["file"] = {"hash": {"sha256": parsed_event.hash}}

        return normalized

    def _create_security_event(
        self,
        parsed_event: ParsedEvent,
        source: str,
        source_type: str,
        asset_id: str | None = None,
    ) -> SecurityEvent:
        """Construct validated canonical SecurityEvent instance."""
        event_id = f"evt_{uuid.uuid4().hex}"
        event_time = parsed_event.timestamp or utc_now()
        ingestion_time = utc_now()

        severity = (
            parsed_event.severity
            if isinstance(parsed_event.severity, EventSeverity)
            else EventSeverity(str(parsed_event.severity))
        )

        normalized_data = self._build_normalized_data_dict(parsed_event)

        raw_payload = parsed_event.raw_payload
        if not isinstance(raw_payload, (dict, str)):
            raw_payload = str(raw_payload)

        metadata = dict(parsed_event.metadata)
        metadata["parser_name"] = parsed_event.parser_name
        self._stamp_demonstration_tags(metadata, parsed_event.raw_payload)

        return SecurityEvent(
            event_id=event_id,
            timestamp=event_time,
            source=source,
            source_type=source_type,
            event_type=parsed_event.event_type,
            severity=severity,
            raw_data=raw_payload,
            normalized_data=normalized_data,
            source_ip=parsed_event.source_ip,
            destination_ip=parsed_event.destination_ip,
            source_port=parsed_event.source_port,
            destination_port=parsed_event.destination_port,
            username=parsed_event.username,
            hostname=parsed_event.hostname,
            domain=parsed_event.domain,
            url=parsed_event.url,
            hash=parsed_event.hash,
            protocol=parsed_event.protocol,
            action=parsed_event.action,
            status=parsed_event.status,
            asset_id=asset_id,
            metadata=metadata,
            parser_version=parsed_event.parser_version,
            ingestion_timestamp=ingestion_time,
        )
