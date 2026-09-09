"""Suricata normalizer for network threat telemetry."""

from typing import Any

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class SuricataNormalizer(BaseNormalizer):
    """Normalizes Suricata EVE JSON parsed events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.SURICATA

    def _build_normalized_data_dict(self, parsed_event: ParsedEvent) -> dict[str, Any]:
        """Include Suricata signature, category, protocol, and action in normalized data."""
        normalized = super()._build_normalized_data_dict(parsed_event)
        normalized["suricata"] = {
            "signature": parsed_event.metadata.get("signature"),
            "category": parsed_event.metadata.get("category"),
            "action": parsed_event.action,
            "protocol": parsed_event.protocol,
        }
        return normalized

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform Suricata parsed event into canonical SecurityEvent."""
        return self._create_security_event(
            parsed_event=parsed_event,
            source="suricata",
            source_type="network_ids",
        )
