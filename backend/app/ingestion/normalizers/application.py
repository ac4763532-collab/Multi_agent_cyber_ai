"""Application log normalizer for web server, API, and internal app logs."""

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class ApplicationLogNormalizer(BaseNormalizer):
    """Normalizes application log parsed events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.APPLICATION

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform application log parsed event into canonical SecurityEvent."""
        source_name = (
            parsed_event.extracted_fields.get("logger")
            or parsed_event.extracted_fields.get("source")
            or "webapp"
        )
        return self._create_security_event(
            parsed_event=parsed_event,
            source=f"application.{source_name}",
            source_type="application_log",
        )
