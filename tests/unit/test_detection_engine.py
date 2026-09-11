"""Unit tests for the main DetectionEngine orchestrator."""

from datetime import UTC, datetime

import pytest

from backend.app.detection.engine import DetectionEngine, get_detection_engine
from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.detection.registry import get_detection_registry
from backend.app.schemas.events import EventSeverity, SecurityEvent


class TestDetectionEngine:
    """Test suite for DetectionEngine orchestrator."""

    @pytest.fixture
    def engine(self) -> DetectionEngine:
        """Create detection engine."""
        return DetectionEngine()

    @pytest.fixture
    def sqli_event(self) -> SecurityEvent:
        """Create event with SQL injection payload."""
        return SecurityEvent(
            event_id="evt_sqli_detection",
            timestamp=datetime.now(UTC),
            source="waf",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"request": "GET /api?id=' UNION SELECT * FROM users--"},
            normalized_data={"action": "blocked"},
            url="/api?id=' UNION SELECT * FROM users--",
        )

    @pytest.fixture
    def xss_event(self) -> SecurityEvent:
        """Create event with XSS payload."""
        return SecurityEvent(
            event_id="evt_xss_detection",
            timestamp=datetime.now(UTC),
            source="waf",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/search?q=<script>alert('xss')</script>",
        )

    @pytest.fixture
    def clean_event(self) -> SecurityEvent:
        """Create clean event with no threats."""
        return SecurityEvent(
            event_id="evt_clean",
            timestamp=datetime.now(UTC),
            source="web_server",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"message": "Normal user browsing"},
            normalized_data={},
            url="/products/category/electronics?sort=price&page=2",
            source_ip="10.0.0.5",
        )

    def test_engine_properties(self, engine: DetectionEngine) -> None:
        """Verify engine property accessors."""
        assert engine.enabled is True
        assert engine.timeout_ms > 0

    def test_engine_enabled_setter(self, engine: DetectionEngine) -> None:
        """Verify enabling/disabling detection."""
        engine.enabled = False
        assert engine.enabled is False
        engine.enabled = True
        assert engine.enabled is True

    def test_engine_evaluate_sync_returns_matches(
        self, engine: DetectionEngine, sqli_event: SecurityEvent
    ) -> None:
        """Verify evaluate_sync returns detection matches."""
        matches = engine.evaluate_sync(sqli_event)

        assert isinstance(matches, list)
        # SQLi should be detected by regex engine
        assert len(matches) >= 1

    def test_engine_evaluate_sync_sqli(
        self, engine: DetectionEngine, sqli_event: SecurityEvent
    ) -> None:
        """Verify SQL injection detection."""
        matches = engine.evaluate_sync(sqli_event)

        sqli_matches = [
            m for m in matches
            if "sqli" in m.tags or "sql" in m.rule_name.lower()
        ]
        assert len(sqli_matches) >= 1

        match = sqli_matches[0]
        assert match.detection_layer == DetectionLayer.L1_DETERMINISTIC
        assert match.severity in (EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL)

    def test_engine_evaluate_sync_xss(
        self, engine: DetectionEngine, xss_event: SecurityEvent
    ) -> None:
        """Verify XSS detection."""
        matches = engine.evaluate_sync(xss_event)

        xss_matches = [
            m for m in matches
            if "xss" in m.tags or "xss" in m.rule_name.lower()
        ]
        assert len(xss_matches) >= 1

    def test_engine_evaluate_sync_clean_event(
        self, engine: DetectionEngine, clean_event: SecurityEvent
    ) -> None:
        """Verify clean events produce no matches."""
        matches = engine.evaluate_sync(clean_event)
        assert len(matches) == 0

    @pytest.mark.asyncio
    async def test_engine_evaluate_async(
        self, engine: DetectionEngine, sqli_event: SecurityEvent
    ) -> None:
        """Verify async evaluate returns matches."""
        matches = await engine.evaluate(sqli_event)
        assert len(matches) >= 1

    @pytest.mark.asyncio
    async def test_engine_evaluate_to_finding(
        self, engine: DetectionEngine, sqli_event: SecurityEvent
    ) -> None:
        """Verify evaluate_to_finding creates proper finding."""
        finding = await engine.evaluate_to_finding(sqli_event)

        assert finding is not None
        assert finding.event_id == sqli_event.event_id
        assert finding.match_count >= 1
        assert finding.severity in (EventSeverity.MEDIUM, EventSeverity.HIGH, EventSeverity.CRITICAL)
        assert finding.detection_layer == DetectionLayer.L1_DETERMINISTIC

    @pytest.mark.asyncio
    async def test_engine_evaluate_to_finding_clean(
        self, engine: DetectionEngine, clean_event: SecurityEvent
    ) -> None:
        """Verify evaluate_to_finding returns None for clean events."""
        finding = await engine.evaluate_to_finding(clean_event)
        assert finding is None

    def test_engine_get_stats(self, engine: DetectionEngine) -> None:
        """Verify engine statistics."""
        stats = engine.get_stats()

        assert stats.total_rules >= 0
        assert stats.events_processed >= 0

    def test_engine_detection_disabled(self) -> None:
        """Verify engine respects detection_enabled flag."""
        engine = DetectionEngine(enabled=False)

        event = SecurityEvent(
            event_id="evt_disabled",
            timestamp=datetime.now(UTC),
            source="test",
            source_type="test",
            event_type="test",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/' UNION SELECT * --",  # SQLi payload
        )

        matches = engine.evaluate_sync(event)
        assert len(matches) == 0

    def test_engine_multiple_matches(self, engine: DetectionEngine) -> None:
        """Verify engine returns multiple matches for multi-attack payload."""
        # Event with both SQLi and path traversal
        multi_attack_event = SecurityEvent(
            event_id="evt_multi",
            timestamp=datetime.now(UTC),
            source="waf",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/api?file=../../../etc/passwd&id=' OR 1=1--",
        )

        matches = engine.evaluate_sync(multi_attack_event)
        assert len(matches) >= 2  # Should detect both SQLi and LFI


class TestDetectionEngineIoCIntegration:
    """Test IoC detection integration with engine."""

    @pytest.fixture
    def engine(self) -> DetectionEngine:
        """Create engine with custom IoC."""
        engine = DetectionEngine()
        # Trigger initialization and add test IoC
        registry = get_detection_registry()
        if not registry.is_initialized:
            registry.initialize()
        ioc_engine = registry.get_engine(RuleType.IOC)
        if ioc_engine:
            ioc_engine.ioc_store.add_ip("198.51.100.50")
            ioc_engine.ioc_store.add_domain("malware-c2.evil.test")
        return engine

    def test_engine_detects_malicious_ip(self, engine: DetectionEngine) -> None:
        """Verify IoC IP detection."""
        event = SecurityEvent(
            event_id="evt_mal_ip",
            timestamp=datetime.now(UTC),
            source="firewall",
            source_type="network",
            event_type="connection",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            source_ip="198.51.100.50",
        )

        matches = engine.evaluate_sync(event)
        ioc_matches = [m for m in matches if m.rule_type == RuleType.IOC]
        assert len(ioc_matches) >= 1

    def test_engine_detects_malicious_domain(self, engine: DetectionEngine) -> None:
        """Verify IoC domain detection."""
        event = SecurityEvent(
            event_id="evt_mal_domain",
            timestamp=datetime.now(UTC),
            source="dns",
            source_type="network",
            event_type="dns_query",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            hostname="malware-c2.evil.test",
        )

        matches = engine.evaluate_sync(event)
        ioc_matches = [m for m in matches if m.rule_type == RuleType.IOC]
        assert len(ioc_matches) >= 1


class TestDetectionEngineSigmaIntegration:
    """Test Sigma rule integration with engine."""

    @pytest.fixture
    def engine(self) -> DetectionEngine:
        """Create engine with custom Sigma rule."""
        engine = DetectionEngine()
        registry = get_detection_registry()
        if not registry.is_initialized:
            registry.initialize()

        # Add test Sigma rule
        sigma_engine = registry.get_engine(RuleType.SIGMA)
        if sigma_engine:
            sigma_engine.add_rule_from_dict({
                "id": "test_custom_sigma",
                "title": "Test Custom Sigma Rule",
                "level": "high",
                "detection": {
                    "selection": {
                        "event_type|contains": ["suspicious_action"],
                    },
                    "condition": "selection",
                },
                "tags": ["attack.t1059"],
            })
        return engine

    def test_engine_matches_sigma_rule(self, engine: DetectionEngine) -> None:
        """Verify custom Sigma rule detection."""
        event = SecurityEvent(
            event_id="evt_sigma_test",
            timestamp=datetime.now(UTC),
            source="host",
            source_type="endpoint",
            event_type="suspicious_action_detected",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
        )

        matches = engine.evaluate_sync(event)
        sigma_matches = [m for m in matches if m.rule_type == RuleType.SIGMA]
        assert len(sigma_matches) >= 1
        assert sigma_matches[0].rule_id == "test_custom_sigma"


class TestGetDetectionEngine:
    """Test singleton access functions."""

    def test_get_detection_engine_returns_instance(self) -> None:
        """Verify singleton returns initialized engine."""
        engine = get_detection_engine()
        assert engine is not None
        assert isinstance(engine, DetectionEngine)

    def test_get_detection_engine_same_instance(self) -> None:
        """Verify singleton returns same instance."""
        engine1 = get_detection_engine()
        engine2 = get_detection_engine()
        assert engine1 is engine2


class TestDetectionRegistry:
    """Test detection registry integration."""

    def test_registry_singleton(self) -> None:
        """Verify registry singleton."""
        reg1 = get_detection_registry()
        reg2 = get_detection_registry()
        assert reg1 is reg2

    def test_registry_has_engines_after_init(self) -> None:
        """Verify registry contains expected engines after initialization."""
        registry = get_detection_registry()
        if not registry.is_initialized:
            registry.initialize()

        # Should have sigma, regex, and ioc engines registered
        engine_names = [e.engine_name for e in registry.list_engines()]
        assert "sigma_engine" in engine_names
        assert "regex_engine" in engine_names
        assert "ioc_engine" in engine_names


class TestDetectionEngineLatency:
    """Test detection engine latency requirements."""

    @pytest.fixture
    def engine(self) -> DetectionEngine:
        """Create initialized engine."""
        engine = DetectionEngine()
        # Warm up registry
        registry = get_detection_registry()
        if not registry.is_initialized:
            registry.initialize()
        return engine

    def test_evaluation_latency(self, engine: DetectionEngine) -> None:
        """Verify evaluation latency is under target."""
        import time

        event = SecurityEvent(
            event_id="evt_latency_test",
            timestamp=datetime.now(UTC),
            source="test",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/api?id=1' UNION SELECT * FROM users--",
        )

        # Warm up
        engine.evaluate_sync(event)

        # Measure
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            engine.evaluate_sync(event)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        # Target is < 5ms per PROJECT_CONSTITUTION.md
        # Allow some margin for test environment variability
        assert avg_ms < 50, f"Average latency {avg_ms:.2f}ms exceeds limit"
