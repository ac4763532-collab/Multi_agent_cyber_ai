"""Generic JSON security event normalizer."""

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class JsonEventNormalizer(BaseNormalizer):
    """Normalizes structured JSON events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.JSON

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform JSON parsed event into canonical SecurityEvent."""
        raw_source = (
            parsed_event.extracted_fields.get("source")
            or parsed_event.extracted_fields.get("vendor")
            or "json_stream"
        )
        source_type = parsed_event.extracted_fields.get("source_type") or "generic_json"
        return self._create_security_event(
            parsed_event=parsed_event,
            source=str(raw_source),
            source_type=str(source_type),
        )
