"""Main detection orchestrator for Layer 1 deterministic detection.

Coordinates all rule engines (Sigma, Regex, IoC) and produces unified
DetectionFinding objects for the correlation layer.
"""

import time
import uuid

from backend.app.core.logging import get_logger
from backend.app.detection.interfaces import (
    DetectionEngineInterface,
    DetectionLayer,
    RuleEngine,
    RuleType,
)
from backend.app.detection.models import (
    DetectionFinding,
    DetectionMatch,
    DetectionStats,
    MatchConfidence,
)
from backend.app.detection.registry import DetectionRegistry, get_detection_registry
from backend.app.schemas.events import EventSeverity, SecurityEvent
from backend.app.utils.datetime import utc_now

logger = get_logger("cyber_ai.detection.engine")


class DetectionEngine(DetectionEngineInterface):
    """Main Layer 1 detection orchestrator.

    Coordinates parallel evaluation across Sigma, Regex, and IoC engines,
    aggregates results into DetectionFinding objects, and tracks performance
    metrics to ensure < 5ms latency target.
    """

    def __init__(
        self,
        registry: DetectionRegistry | None = None,
        timeout_ms: float = 5.0,
        enabled: bool = True,
    ) -> None:
        """Initialize the detection engine.

        Args:
            registry: Detection registry with loaded engines
            timeout_ms: Maximum processing time in milliseconds
            enabled: Whether detection is active
        """
        self._registry = registry or get_detection_registry()
        self._timeout_ms = timeout_ms
        self._enabled = enabled

        # Performance tracking
        self._latencies: list[float] = []
        self._max_latency_samples = 1000

    @property
    def enabled(self) -> bool:
        """Check if detection is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable detection."""
        self._enabled = value

    @property
    def timeout_ms(self) -> float:
        """Get timeout threshold in milliseconds."""
        return self._timeout_ms

    def _ensure_initialized(self) -> None:
        """Ensure the registry is initialized."""
        if not self._registry.is_initialized:
            self._registry.initialize()

    async def evaluate(
        self,
        event: SecurityEvent,
        engines: list[RuleType] | None = None,
    ) -> list[DetectionMatch]:
        """Evaluate event against all or specified rule engines.

        Args:
            event: SecurityEvent to evaluate
            engines: Optional list of specific engine types to use

        Returns:
            List of DetectionMatch from all engines

        Raises:
            DetectionTimeoutError: If processing exceeds timeout
        """
        if not self._enabled:
            return []

        self._ensure_initialized()
        start_time = time.perf_counter()

        # Determine which engines to use
        target_engines: list[RuleEngine] = []
        if engines:
            for rule_type in engines:
                engine = self._registry.get_engine(rule_type)
                if engine:
                    target_engines.append(engine)
        else:
            target_engines = self._registry.list_engines()

        if not target_engines:
            return []

        # Run evaluation (engines are synchronous but fast)
        all_matches: list[DetectionMatch] = []

        for engine in target_engines:
            try:
                matches = engine.evaluate(event)
                all_matches.extend(matches)
            except Exception as e:
                logger.warning(
                    "Engine %s failed for event %s: %s",
                    engine.engine_name,
                    event.event_id,
                    e,
                )

        # Track latency
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self._record_latency(elapsed_ms)

        # Check timeout (log warning but don't fail)
        if elapsed_ms > self._timeout_ms:
            logger.warning(
                "Detection exceeded timeout: %.2fms > %.2fms for event %s",
                elapsed_ms,
                self._timeout_ms,
                event.event_id,
            )

        # Update registry stats
        self._registry.update_stats(
            events_processed=self._registry.get_stats().events_processed + 1,
            matches_found=self._registry.get_stats().matches_found + len(all_matches),
            last_evaluation_at=utc_now(),
        )

        return all_matches

    def evaluate_sync(
        self,
        event: SecurityEvent,
        engines: list[RuleType] | None = None,
    ) -> list[DetectionMatch]:
        """Synchronous evaluation for non-async contexts.

        Args:
            event: SecurityEvent to evaluate
            engines: Optional list of specific engine types

        Returns:
            List of DetectionMatch from all engines
        """
        if not self._enabled:
            return []

        self._ensure_initialized()
        start_time = time.perf_counter()

        # Determine engines
        target_engines: list[RuleEngine] = []
        if engines:
            for rule_type in engines:
                engine = self._registry.get_engine(rule_type)
                if engine:
                    target_engines.append(engine)
        else:
            target_engines = self._registry.list_engines()

        # Evaluate
        all_matches: list[DetectionMatch] = []
        for engine in target_engines:
            try:
                matches = engine.evaluate(event)
                all_matches.extend(matches)
            except Exception as e:
                logger.warning("Engine %s failed: %s", engine.engine_name, e)

        # Track latency
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        self._record_latency(elapsed_ms)

        return all_matches

    async def evaluate_to_finding(
        self,
        event: SecurityEvent,
        engines: list[RuleType] | None = None,
    ) -> DetectionFinding | None:
        """Evaluate event and produce aggregated DetectionFinding.

        Args:
            event: SecurityEvent to evaluate
            engines: Optional list of specific engine types

        Returns:
            DetectionFinding if any rules matched, None otherwise
        """
        start_time = time.perf_counter()

        matches = await self.evaluate(event, engines)

        if not matches:
            return None

        # Create finding
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        finding = DetectionFinding(
            finding_id=f"finding_{uuid.uuid4().hex}",
            event_id=event.event_id,
            finding_type=self._determine_finding_type(matches),
            severity=EventSeverity.INFORMATIONAL,  # Will be updated by add_match
            confidence=MatchConfidence.HIGH,
            detection_layer=DetectionLayer.L1_DETERMINISTIC,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            username=event.username,
            hostname=event.hostname,
            domain=event.domain,
            event_timestamp=event.timestamp,
            processing_time_ms=elapsed_ms,
        )

        # Add all matches (this updates severity and MITRE mappings)
        for match in matches:
            finding.add_match(match)

        # Update stats
        self._registry.update_stats(
            findings_generated=self._registry.get_stats().findings_generated + 1,
        )

        return finding

    def _determine_finding_type(self, matches: list[DetectionMatch]) -> str:  # noqa: C901
        """Determine finding type from matches based on tags and rules."""
        # Collect all tags
        all_tags: set[str] = set()
        for match in matches:
            all_tags.update(match.tags)

        # Priority-based type determination
        if "sqli" in all_tags or "sql-injection" in all_tags:
            return "sql_injection_attempt"
        if "xss" in all_tags:
            return "xss_attempt"
        if "command-injection" in all_tags or "rce" in all_tags:
            return "command_injection_attempt"
        if "log4shell" in all_tags or "jndi" in all_tags:
            return "log4shell_exploitation"
        if "path-traversal" in all_tags or "lfi" in all_tags:
            return "path_traversal_attempt"
        if "ssrf" in all_tags:
            return "ssrf_attempt"
        if "brute-force" in all_tags:
            return "brute_force_indicator"
        if "phishing" in all_tags:
            return "phishing_indicator"
        if "scanner" in all_tags or "recon" in all_tags:
            return "reconnaissance_activity"

        # Check IoC matches
        for match in matches:
            if match.rule_type == RuleType.IOC:
                ioc_type = match.match_details.get("ioc_type", "")
                if ioc_type == "ip":
                    return "malicious_ip_communication"
                if ioc_type == "domain":
                    return "malicious_domain_access"
                if ioc_type == "hash":
                    return "malicious_file_detected"
                if ioc_type == "url":
                    return "malicious_url_access"

        # Default based on rule type
        rule_types = {m.rule_type for m in matches}
        if RuleType.SIGMA in rule_types:
            return "sigma_rule_match"
        if RuleType.REGEX in rule_types:
            return "pattern_match"
        if RuleType.IOC in rule_types:
            return "ioc_match"

        return "security_detection"

    def _record_latency(self, latency_ms: float) -> None:
        """Record latency sample and update stats."""
        self._latencies.append(latency_ms)

        # Keep bounded samples
        if len(self._latencies) > self._max_latency_samples:
            self._latencies = self._latencies[-self._max_latency_samples:]

        # Update stats
        if self._latencies:
            sorted_latencies = sorted(self._latencies)
            n = len(sorted_latencies)

            self._registry.update_stats(
                avg_latency_ms=sum(sorted_latencies) / n,
                p50_latency_ms=sorted_latencies[n // 2],
                p95_latency_ms=(
                    sorted_latencies[int(n * 0.95)] if n >= 20 else sorted_latencies[-1]
                ),
                p99_latency_ms=(
                    sorted_latencies[int(n * 0.99)] if n >= 100 else sorted_latencies[-1]
                ),
                max_latency_ms=max(sorted_latencies),
            )

    def register_engine(self, engine: RuleEngine) -> None:
        """Register a rule engine with the orchestrator."""
        self._registry.register_engine(engine)

    def get_engine(self, rule_type: RuleType) -> RuleEngine | None:
        """Retrieve a registered engine by type."""
        return self._registry.get_engine(rule_type)

    def reload_rules(self) -> dict[str, int]:
        """Reload rules for all registered engines."""
        return self._registry.reload_rules()

    def get_stats(self) -> DetectionStats:
        """Get detection performance statistics."""
        stats = self._registry.get_stats()
        return stats


# Singleton instance
_detection_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    """Get the singleton detection engine instance."""
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine


async def evaluate_event(
    event: SecurityEvent,
    engines: list[RuleType] | None = None,
) -> list[DetectionMatch]:
    """Convenience function to evaluate an event.

    Args:
        event: SecurityEvent to evaluate
        engines: Optional list of specific engine types

    Returns:
        List of DetectionMatch
    """
    engine = get_detection_engine()
    return await engine.evaluate(event, engines)


async def evaluate_event_to_finding(
    event: SecurityEvent,
    engines: list[RuleType] | None = None,
) -> DetectionFinding | None:
    """Convenience function to evaluate and produce finding.

    Args:
        event: SecurityEvent to evaluate
        engines: Optional list of specific engine types

    Returns:
        DetectionFinding if matches found, None otherwise
    """
    engine = get_detection_engine()
    return await engine.evaluate_to_finding(event, engines)
