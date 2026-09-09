"""Central registry for telemetry parsers, normalizers, and source auto-detection."""

from typing import Any

from backend.app.ingestion.interfaces import (
    EventNormalizer,
    EventParser,
    TelemetrySourceType,
)
from backend.app.ingestion.normalizers import (
    ApplicationLogNormalizer,
    AuthenticationLogNormalizer,
    EmailSecurityNormalizer,
    JsonEventNormalizer,
    SuricataNormalizer,
    SyslogNormalizer,
)
from backend.app.ingestion.parsers import (
    ApplicationLogParser,
    AuthenticationLogParser,
    EmailSecurityParser,
    JsonEventParser,
    SuricataEveParser,
    SyslogParser,
)


class IngestionRegistry:
    """Registry managing telemetry parsers, normalizers, and source auto-detection heuristics."""

    def __init__(self) -> None:
        self._parsers: dict[TelemetrySourceType, EventParser] = {}
        self._normalizers: dict[TelemetrySourceType, EventNormalizer] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the 6 default supported telemetry adapters."""
        self.register(SuricataEveParser(), SuricataNormalizer())
        self.register(SyslogParser(), SyslogNormalizer())
        self.register(ApplicationLogParser(), ApplicationLogNormalizer())
        self.register(AuthenticationLogParser(), AuthenticationLogNormalizer())
        self.register(EmailSecurityParser(), EmailSecurityNormalizer())
        self.register(JsonEventParser(), JsonEventNormalizer())

    def register(self, parser: EventParser, normalizer: EventNormalizer) -> None:
        """Register a parser and normalizer pair for a source type."""
        self._parsers[parser.source_type] = parser
        self._normalizers[normalizer.source_type] = normalizer

    def get_parser(self, source_type: TelemetrySourceType | str) -> EventParser | None:
        """Retrieve registered parser for the specified source type."""
        st = (
            source_type
            if isinstance(source_type, TelemetrySourceType)
            else TelemetrySourceType.from_str(source_type)
        )
        return self._parsers.get(st)

    def get_normalizer(self, source_type: TelemetrySourceType | str) -> EventNormalizer | None:
        """Retrieve registered normalizer for the specified source type."""
        st = (
            source_type
            if isinstance(source_type, TelemetrySourceType)
            else TelemetrySourceType.from_str(source_type)
        )
        return self._normalizers.get(st)

    def detect_source_type(self, raw_data: Any) -> TelemetrySourceType:
        """Auto-detect telemetry source type based on registered parser capability heuristics."""
        # Priority order for detection:
        # 1. Suricata (specific signature and event_type structure)
        # 2. Email (email headers / DMARC / SPF / recipient)
        # 3. Authentication (Windows EventID / PAM)
        # 4. Application (HTTP access logs / status_code / error traces)
        # 5. Syslog (RFC 3164 / 5424 formats)
        # 6. Generic JSON
        detection_order = [
            TelemetrySourceType.SURICATA,
            TelemetrySourceType.EMAIL,
            TelemetrySourceType.SYSLOG,
            TelemetrySourceType.APPLICATION,
            TelemetrySourceType.AUTHENTICATION,
            TelemetrySourceType.JSON,
        ]

        for st in detection_order:
            parser = self._parsers.get(st)
            if parser and parser.can_parse(raw_data):
                return st

        return TelemetrySourceType.UNKNOWN

    def list_supported_sources(self) -> list[str]:
        """Return list of supported source type identifiers."""
        return [st.value for st in self._parsers.keys()]


_registry: IngestionRegistry | None = None


def get_ingestion_registry() -> IngestionRegistry:
    """Return singleton IngestionRegistry instance."""
    global _registry
    if _registry is None:
        _registry = IngestionRegistry()
    return _registry
