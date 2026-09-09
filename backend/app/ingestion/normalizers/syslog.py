"""Syslog normalizer for system, auth, and firewall syslog events."""

from backend.app.ingestion.interfaces import ParsedEvent, TelemetrySourceType
from backend.app.ingestion.normalizers.base import BaseNormalizer
from backend.app.schemas.events import SecurityEvent


class SyslogNormalizer(BaseNormalizer):
    """Normalizes Syslog parsed events into canonical SecurityEvent instances."""

    @property
    def source_type(self) -> TelemetrySourceType:
        return TelemetrySourceType.SYSLOG

    def normalize(self, parsed_event: ParsedEvent) -> SecurityEvent:
        """Transform Syslog parsed event into canonical SecurityEvent."""
        app_name = parsed_event.metadata.get("app_name", "syslog")
        return self._create_security_event(
            parsed_event=parsed_event,
            source=f"syslog.{app_name}" if app_name else "syslog",
            source_type="syslog",
        )
