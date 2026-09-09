"""Authentication log normalizer for Windows Event Logs, Linux PAM, and Cloud IAM telemetry."""

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class AuthenticationLogNormalizer(BaseNormalizer):
    """Normalizes authentication parsed events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.AUTHENTICATION

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform authentication parsed event into canonical SecurityEvent."""
        win_eid = parsed_event.metadata.get("windows_event_id")
        source = (
            f"windows_security_event_{win_eid}"
            if win_eid
            else str(parsed_event.extracted_fields.get("source", "authentication_service"))
        )
        return self._create_security_event(
            parsed_event=parsed_event,
            source=source,
            source_type="authentication",
        )
