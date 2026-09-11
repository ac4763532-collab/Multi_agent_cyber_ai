"""Unit tests for detection models (DetectionMatch, DetectionFinding, etc.)."""

from datetime import UTC, datetime

import pytest

from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.detection.models import (
    DetectionFinding,
    DetectionMatch,
    DetectionStats,
    MatchConfidence,
    RuleDefinition,
)
from backend.app.schemas.events import EventSeverity


class TestDetectionMatch:
    """Test suite for DetectionMatch model."""

    def test_valid_detection_match_instantiation(self) -> None:
        """Verify instantiation with all required fields."""
        match = DetectionMatch(
            rule_id="test_rule_001",
            rule_name="Test SQL Injection Detection",
            rule_type=RuleType.REGEX,
            severity=EventSeverity.HIGH,
            matched_field="url",
            matched_value="' OR 1=1 --",
        )

        assert match.rule_id == "test_rule_001"
        assert match.rule_name == "Test SQL Injection Detection"
        assert match.rule_type == RuleType.REGEX
        assert match.severity == EventSeverity.HIGH
        assert match.confidence == MatchConfidence.HIGH  # default
        assert match.matched_field == "url"
        assert match.matched_value == "' OR 1=1 --"
        assert match.detection_layer == DetectionLayer.L1_DETERMINISTIC
        assert isinstance(match.detection_timestamp, datetime)

    def test_detection_match_with_mitre_mapping(self) -> None:
        """Verify MITRE ATT&CK technique and tactic mapping."""
        match = DetectionMatch(
            rule_id="mitre_test",
            rule_name="MITRE Test Rule",
            rule_type=RuleType.SIGMA,
            severity=EventSeverity.CRITICAL,
            matched_field="event_type",
            matched_value="brute_force",
            mitre_techniques=["T1110", "T1110.001"],
            mitre_tactics=["credential-access"],
        )

        assert "T1110" in match.mitre_techniques
        assert "T1110.001" in match.mitre_techniques
        assert "credential-access" in match.mitre_tactics

    def test_detection_match_with_details(self) -> None:
        """Verify match details dictionary."""
        match = DetectionMatch(
            rule_id="detail_test",
            rule_name="Detail Test",
            rule_type=RuleType.IOC,
            severity=EventSeverity.HIGH,
            matched_field="source_ip",
            matched_value="203.0.113.100",
            match_details={
                "ioc_type": "ip",
                "context": {"category": "c2_server"},
            },
        )

        assert match.match_details["ioc_type"] == "ip"
        assert match.match_details["context"]["category"] == "c2_server"


class TestDetectionFinding:
    """Test suite for DetectionFinding model."""

    @pytest.fixture
    def sample_match(self) -> DetectionMatch:
        """Create a sample detection match."""
        return DetectionMatch(
            rule_id="sample_rule",
            rule_name="Sample Rule",
            rule_type=RuleType.REGEX,
            severity=EventSeverity.MEDIUM,
            matched_field="url",
            matched_value="test_value",
            mitre_techniques=["T1190"],
            mitre_tactics=["initial-access"],
        )

    def test_valid_finding_instantiation(self) -> None:
        """Verify instantiation with required fields."""
        finding = DetectionFinding(
            finding_id="finding_001",
            event_id="evt_12345",
            finding_type="sql_injection_attempt",
            severity=EventSeverity.LOW,
            event_timestamp=datetime.now(UTC),
        )

        assert finding.finding_id == "finding_001"
        assert finding.event_id == "evt_12345"
        assert finding.finding_type == "sql_injection_attempt"
        assert finding.severity == EventSeverity.LOW
        assert finding.match_count == 0
        assert finding.matches == []

    def test_add_match_updates_severity(self, sample_match: DetectionMatch) -> None:
        """Verify that adding a match updates severity to highest."""
        finding = DetectionFinding(
            finding_id="finding_002",
            event_id="evt_test",
            finding_type="test_type",
            severity=EventSeverity.LOW,
            event_timestamp=datetime.now(UTC),
        )

        # Add match with MEDIUM severity
        finding.add_match(sample_match)

        assert finding.severity == EventSeverity.MEDIUM
        assert finding.match_count == 1

        # Add match with HIGH severity
        high_match = DetectionMatch(
            rule_id="high_rule",
            rule_name="High Rule",
            rule_type=RuleType.SIGMA,
            severity=EventSeverity.HIGH,
            matched_field="test",
            matched_value="test",
        )
        finding.add_match(high_match)

        assert finding.severity == EventSeverity.HIGH
        assert finding.match_count == 2

    def test_add_match_aggregates_mitre(self, sample_match: DetectionMatch) -> None:
        """Verify MITRE mappings are aggregated without duplicates."""
        finding = DetectionFinding(
            finding_id="finding_003",
            event_id="evt_mitre",
            finding_type="test_type",
            severity=EventSeverity.LOW,
            event_timestamp=datetime.now(UTC),
        )

        finding.add_match(sample_match)
        assert "T1190" in finding.mitre_techniques
        assert "initial-access" in finding.mitre_tactics

        # Add another match with same technique
        another_match = DetectionMatch(
            rule_id="another_rule",
            rule_name="Another Rule",
            rule_type=RuleType.REGEX,
            severity=EventSeverity.MEDIUM,
            matched_field="test",
            matched_value="test",
            mitre_techniques=["T1190", "T1059"],  # T1190 duplicate
            mitre_tactics=["initial-access", "execution"],
        )
        finding.add_match(another_match)

        # Check no duplicates
        assert finding.mitre_techniques.count("T1190") == 1
        assert finding.mitre_tactics.count("initial-access") == 1
        assert "T1059" in finding.mitre_techniques
        assert "execution" in finding.mitre_tactics


class TestMatchConfidence:
    """Test suite for MatchConfidence enum."""

    def test_confidence_levels(self) -> None:
        """Verify all confidence levels exist."""
        assert MatchConfidence.DEFINITIVE == "definitive"
        assert MatchConfidence.HIGH == "high"
        assert MatchConfidence.MEDIUM == "medium"
        assert MatchConfidence.LOW == "low"


class TestRuleDefinition:
    """Test suite for RuleDefinition schema."""

    def test_rule_definition_minimal(self) -> None:
        """Verify minimal rule definition."""
        rule_def = RuleDefinition(
            id="test_rule",
            name="Test Rule",
        )

        assert rule_def.id == "test_rule"
        assert rule_def.name == "Test Rule"
        assert rule_def.enabled is True
        assert rule_def.rule_type == RuleType.CUSTOM

    def test_rule_definition_full(self) -> None:
        """Verify full rule definition with all fields."""
        rule_def = RuleDefinition(
            id="full_rule",
            name="Full Rule",
            rule_type=RuleType.SIGMA,
            severity="critical",
            description="A full test rule",
            author="Test Author",
            mitre_attack=["T1110"],
            tactics=["credential-access"],
            tags=["test", "brute-force"],
            detection={"selection": {"event_type": "auth_failed"}},
            condition="all",
        )

        assert rule_def.id == "full_rule"
        assert rule_def.rule_type == RuleType.SIGMA
        assert rule_def.description == "A full test rule"
        assert "T1110" in rule_def.mitre_attack
        assert "test" in rule_def.tags


class TestDetectionStats:
    """Test suite for DetectionStats model."""

    def test_stats_defaults(self) -> None:
        """Verify default statistics values."""
        stats = DetectionStats()

        assert stats.total_rules == 0
        assert stats.sigma_rules == 0
        assert stats.regex_rules == 0
        assert stats.ioc_rules == 0
        assert stats.events_processed == 0
        assert stats.matches_found == 0
        assert stats.avg_latency_ms == 0.0
        assert stats.errors == 0

    def test_stats_with_values(self) -> None:
        """Verify statistics with custom values."""
        stats = DetectionStats(
            total_rules=100,
            sigma_rules=50,
            regex_rules=30,
            ioc_rules=20,
            events_processed=10000,
            matches_found=150,
            avg_latency_ms=2.5,
        )

        assert stats.total_rules == 100
        assert stats.events_processed == 10000
        assert stats.avg_latency_ms == 2.5
