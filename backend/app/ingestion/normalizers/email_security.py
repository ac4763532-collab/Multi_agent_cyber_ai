"""Email security normalizer for gateway logs, SPF/DKIM/DMARC events, and phishing telemetry."""

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class EmailSecurityNormalizer(BaseNormalizer):
    """Normalizes email security parsed events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.EMAIL

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform email security parsed event into canonical SecurityEvent."""
        raw_source = parsed_event.extracted_fields.get("source") or "email_gateway"
        return self._create_security_event(
            parsed_event=parsed_event,
            source=str(raw_source),
            source_type="email_security",
        )
