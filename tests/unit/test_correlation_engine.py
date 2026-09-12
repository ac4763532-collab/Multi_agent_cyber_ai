"""Tests for Cross-Domain Correlation Engine."""

from datetime import timedelta

import pytest

from backend.app.correlation import (
    AttackChainStage,
    CorrelationSignal,
    CrossDomainCorrelationEngine,
    Finding,
    get_correlation_engine,
)
from backend.app.utils.datetime import utc_now


class TestCrossDomainCorrelationEngine:
    """Tests for CrossDomainCorrelationEngine."""

    @pytest.fixture
    def engine(self) -> CrossDomainCorrelationEngine:
        return CrossDomainCorrelationEngine(
            time_window_minutes=60,
            min_correlation_score=0.1,
        )

    @pytest.fixture
    def sample_findings(self) -> list[Finding]:
        """Create sample findings for testing."""
        now = utc_now()
        return [
            Finding(
                finding_id="f1",
                finding_type="phishing",
                source="email",
                timestamp=now,
                severity="high",
                confidence=0.9,
                indicators={"source_ip": "192.168.1.100", "domain": "evil.com"},
            ),
            Finding(
                finding_id="f2",
                finding_type="credential_theft",
                source="authentication",
                timestamp=now + timedelta(minutes=5),
                severity="high",
                confidence=0.85,
                indicators={
                    "source_ip": "192.168.1.100",
                    "username": "victim@corp.com",
                },
            ),
        ]

    def test_engine_initialization(self, engine: CrossDomainCorrelationEngine) -> None:
        """Test engine initializes correctly."""
        assert engine.time_window == timedelta(minutes=60)
        assert engine.min_score == 0.1

    def test_correlate_single_finding(
        self, engine: CrossDomainCorrelationEngine
    ) -> None:
        """Single finding should not produce correlation."""
        findings = [
            Finding(
                finding_id="f1",
                finding_type="test",
                source="test",
                timestamp=utc_now(),
            )
        ]
        results = engine.correlate(findings)
        assert len(results) == 0

    def test_correlate_with_shared_ip(
        self, engine: CrossDomainCorrelationEngine, sample_findings: list[Finding]
    ) -> None:
        """Findings with shared IP should correlate."""
        results = engine.correlate(sample_findings)
        assert len(results) >= 1

        result = results[0]
        assert "192.168.1.100" in result.shared_indicators.get("ip", [])
        assert result.correlation_score > 0

    def test_correlate_temporal_proximity(
        self, engine: CrossDomainCorrelationEngine
    ) -> None:
        """Findings close in time should get temporal proximity score."""
        now = utc_now()
        findings = [
            Finding(
                finding_id="f1",
                finding_type="type_a",
                source="source_a",
                timestamp=now,
                indicators={"source_ip": "10.0.0.1"},
            ),
            Finding(
                finding_id="f2",
                finding_type="type_b",
                source="source_b",
                timestamp=now + timedelta(seconds=30),
                indicators={"source_ip": "10.0.0.1"},
            ),
        ]

        results = engine.correlate(findings)
        assert len(results) >= 1

        # Check for temporal proximity component
        temporal_components = [
            c
            for c in results[0].score_components
            if c.signal == CorrelationSignal.TEMPORAL_PROXIMITY
        ]
        assert len(temporal_components) > 0

    def test_attack_chain_detection(self, engine: CrossDomainCorrelationEngine) -> None:
        """Test attack chain stage detection."""
        now = utc_now()
        # Use multiple shared indicators to ensure correlation score meets threshold
        findings = [
            Finding(
                finding_id="f1",
                finding_type="phishing_email",
                source="email",
                timestamp=now,
                indicators={
                    "source_ip": "1.2.3.4",
                    "domain": "evil.com",
                    "user": "victim",
                },
            ),
            Finding(
                finding_id="f2",
                finding_type="brute_force_login",
                source="auth",
                timestamp=now + timedelta(minutes=2),
                indicators={
                    "source_ip": "1.2.3.4",
                    "domain": "evil.com",
                    "user": "victim",
                },
            ),
        ]

        results = engine.correlate(findings)
        assert len(results) >= 1

        attack_chain = results[0].attack_chain
        # Should detect initial access and credential activity stages
        assert (
            AttackChainStage.INITIAL_ACCESS in attack_chain
            or AttackChainStage.CREDENTIAL_ACTIVITY in attack_chain
        )

    def test_severity_aggregation(self, engine: CrossDomainCorrelationEngine) -> None:
        """Correlation severity should be highest of findings."""
        now = utc_now()
        findings = [
            Finding(
                finding_id="f1",
                finding_type="test",
                source="a",
                timestamp=now,
                severity="medium",
                indicators={"ip": "1.1.1.1"},
            ),
            Finding(
                finding_id="f2",
                finding_type="test",
                source="b",
                timestamp=now,
                severity="critical",
                indicators={"ip": "1.1.1.1"},
            ),
        ]

        results = engine.correlate(findings)
        assert len(results) >= 1
        assert results[0].severity == "critical"

    def test_get_correlation_by_id(
        self, engine: CrossDomainCorrelationEngine, sample_findings: list[Finding]
    ) -> None:
        """Test retrieving correlation by ID."""
        results = engine.correlate(sample_findings)
        assert len(results) >= 1

        correlation_id = results[0].correlation_id
        retrieved = engine.get_correlation(correlation_id)
        assert retrieved is not None
        assert retrieved.correlation_id == correlation_id

    def test_get_recent_correlations(
        self, engine: CrossDomainCorrelationEngine, sample_findings: list[Finding]
    ) -> None:
        """Test getting recent correlations."""
        engine.correlate(sample_findings)

        recent = engine.get_recent_correlations(limit=10)
        assert len(recent) >= 1

    def test_get_metrics(
        self, engine: CrossDomainCorrelationEngine, sample_findings: list[Finding]
    ) -> None:
        """Test getting engine metrics."""
        engine.correlate(sample_findings)

        metrics = engine.get_metrics()
        assert "total_correlations" in metrics
        assert metrics["total_correlations"] >= 1

    def test_classification(self, engine: CrossDomainCorrelationEngine) -> None:
        """Test correlation classification."""
        now = utc_now()
        findings = [
            Finding(
                finding_id="f1",
                finding_type="ransomware_detected",
                source="endpoint",
                timestamp=now,
                indicators={"ip": "5.5.5.5"},
            ),
            Finding(
                finding_id="f2",
                finding_type="data_exfiltration",
                source="network",
                timestamp=now,
                indicators={"ip": "5.5.5.5"},
            ),
        ]

        results = engine.correlate(findings)
        assert len(results) >= 1
        assert results[0].classification == "ransomware_attack"


class TestCorrelationEngineSingleton:
    """Test singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """Singleton should return same instance."""
        import backend.app.correlation as correlation_module

        correlation_module._engine = None

        e1 = get_correlation_engine()
        e2 = get_correlation_engine()
        assert e1 is e2
