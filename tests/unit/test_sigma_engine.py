"""Unit tests for Sigma rule engine."""

from datetime import UTC, datetime

import pytest

from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.detection.models import MatchConfidence
from backend.app.detection.rules.sigma_engine import (
    CompiledCondition,
    SigmaEngine,
    SigmaModifier,
    SigmaRule,
)
from backend.app.schemas.events import EventSeverity, SecurityEvent


class TestSigmaModifier:
    """Test suite for Sigma field modifiers."""

    def test_contains_modifier(self) -> None:
        """Verify contains modifier with case insensitivity."""
        assert SigmaModifier.contains("Hello World", "world") is True
        assert SigmaModifier.contains("Hello World", "HELLO") is True
        assert SigmaModifier.contains("Hello World", "xyz") is False

    def test_startswith_modifier(self) -> None:
        """Verify startswith modifier."""
        assert SigmaModifier.startswith("Hello World", "hello") is True
        assert SigmaModifier.startswith("Hello World", "world") is False

    def test_endswith_modifier(self) -> None:
        """Verify endswith modifier."""
        assert SigmaModifier.endswith("Hello World", "world") is True
        assert SigmaModifier.endswith("Hello World", "hello") is False

    def test_regex_modifier(self) -> None:
        """Verify regex modifier."""
        assert SigmaModifier.regex("user123", r"user\d+") is True
        assert SigmaModifier.regex("admin", r"user\d+") is False

    def test_equals_modifier(self) -> None:
        """Verify case-insensitive equals."""
        assert SigmaModifier.equals("Test", "test") is True
        assert SigmaModifier.equals("Test", "TEST") is True
        assert SigmaModifier.equals("Test", "Other") is False

    def test_equals_exact_modifier(self) -> None:
        """Verify case-sensitive exact equals."""
        assert SigmaModifier.equals_exact("Test", "Test") is True
        assert SigmaModifier.equals_exact("Test", "test") is False


class TestCompiledCondition:
    """Test suite for compiled Sigma conditions."""

    def test_condition_contains_match(self) -> None:
        """Verify condition with contains modifier."""
        condition = CompiledCondition(
            field="event_type",
            patterns=["auth_failed", "login_failed"],
            modifier="contains",
        )

        fields = {"event_type": "user_auth_failed_event"}
        matched, value = condition.evaluate(fields)
        assert matched is True
        assert value == "auth_failed"

    def test_condition_no_match(self) -> None:
        """Verify condition with no match."""
        condition = CompiledCondition(
            field="event_type",
            patterns=["brute_force"],
            modifier="contains",
        )

        fields = {"event_type": "user_login_success"}
        matched, value = condition.evaluate(fields)
        assert matched is False
        assert value is None

    def test_condition_negate(self) -> None:
        """Verify negated condition."""
        condition = CompiledCondition(
            field="status",
            patterns=["success"],
            modifier="contains",
            negate=True,
        )

        fields = {"status": "failure"}
        matched, _value = condition.evaluate(fields)
        assert matched is True

    def test_condition_match_all(self) -> None:
        """Verify match_all requires all patterns to match."""
        condition = CompiledCondition(
            field="message",
            patterns=["error", "critical"],
            modifier="contains",
            match_all=True,
        )

        # Only one pattern matches
        fields1 = {"message": "An error occurred"}
        matched1, _ = condition.evaluate(fields1)
        assert matched1 is False

        # Both patterns match
        fields2 = {"message": "A critical error occurred"}
        matched2, _ = condition.evaluate(fields2)
        assert matched2 is True


class TestSigmaRule:
    """Test suite for SigmaRule class."""

    @pytest.fixture
    def brute_force_rule(self) -> SigmaRule:
        """Create a sample brute force detection rule."""
        conditions = [
            CompiledCondition(
                field="event_type",
                patterns=["auth_failed", "login_failed"],
                modifier="contains",
            ),
            CompiledCondition(
                field="action",
                patterns=["denied", "blocked"],
                modifier="contains",
            ),
        ]
        return SigmaRule(
            rule_id="sigma_brute_force_test",
            rule_name="Test Brute Force Detection",
            severity=EventSeverity.HIGH,
            conditions=conditions,
            condition_logic="any",
            mitre_techniques=["T1110"],
            mitre_tactics=["credential-access"],
            tags=["brute-force", "authentication"],
        )

    @pytest.fixture
    def sample_auth_failed_event(self) -> SecurityEvent:
        """Create sample authentication failure event."""
        return SecurityEvent(
            event_id="evt_auth_test_001",
            timestamp=datetime.now(UTC),
            source="sshd",
            source_type="syslog",
            event_type="auth_failed",
            severity=EventSeverity.MEDIUM,
            raw_data={"message": "Failed password for user admin"},
            normalized_data={"action": "denied"},
            source_ip="192.168.1.100",
            username="admin",
            action="denied",
            status="failure",
        )

    def test_sigma_rule_properties(self, brute_force_rule: SigmaRule) -> None:
        """Verify SigmaRule property accessors."""
        assert brute_force_rule.rule_id == "sigma_brute_force_test"
        assert brute_force_rule.rule_name == "Test Brute Force Detection"
        assert brute_force_rule.rule_type == RuleType.SIGMA
        assert brute_force_rule.severity == EventSeverity.HIGH
        assert "T1110" in brute_force_rule.mitre_techniques
        assert brute_force_rule.enabled is True

    def test_sigma_rule_matches_event(
        self, brute_force_rule: SigmaRule, sample_auth_failed_event: SecurityEvent
    ) -> None:
        """Verify rule matches against qualifying event."""
        match = brute_force_rule.matches(sample_auth_failed_event)

        assert match is not None
        assert match.rule_id == "sigma_brute_force_test"
        assert match.rule_type == RuleType.SIGMA
        assert match.severity == EventSeverity.HIGH
        assert match.confidence == MatchConfidence.HIGH
        assert "T1110" in match.mitre_techniques

    def test_sigma_rule_no_match(self, brute_force_rule: SigmaRule) -> None:
        """Verify rule does not match non-qualifying event."""
        success_event = SecurityEvent(
            event_id="evt_success_001",
            timestamp=datetime.now(UTC),
            source="sshd",
            source_type="syslog",
            event_type="auth_success",
            severity=EventSeverity.LOW,
            raw_data={"message": "Accepted publickey"},
            normalized_data={"action": "allowed"},
            action="allowed",
            status="success",
        )

        match = brute_force_rule.matches(success_event)
        assert match is None


class TestSigmaEngine:
    """Test suite for SigmaEngine class."""

    @pytest.fixture
    def engine(self) -> SigmaEngine:
        """Create SigmaEngine instance."""
        return SigmaEngine()

    def test_engine_properties(self, engine: SigmaEngine) -> None:
        """Verify engine property accessors."""
        assert engine.engine_name == "sigma_engine"
        assert engine.rule_type == RuleType.SIGMA
        assert engine.detection_layer == DetectionLayer.L1_DETERMINISTIC
        assert engine.rule_count == 0

    def test_add_rule_from_dict(self, engine: SigmaEngine) -> None:
        """Verify adding rule from dictionary."""
        rule_dict = {
            "id": "test_dict_rule",
            "title": "Test Rule from Dict",
            "level": "high",
            "detection": {
                "selection": {
                    "event_type|contains": ["malware", "suspicious"],
                },
                "condition": "selection",
            },
            "tags": ["attack.t1059"],
        }

        rule = engine.add_rule_from_dict(rule_dict)

        assert rule.rule_id == "test_dict_rule"
        assert rule.rule_name == "Test Rule from Dict"
        assert rule.severity == EventSeverity.HIGH
        assert engine.rule_count == 1

    def test_add_rule_from_yaml(self, engine: SigmaEngine) -> None:
        """Verify adding rule from YAML string."""
        yaml_str = """
id: yaml_test_rule
title: YAML Test Rule
level: medium
detection:
    selection:
        source_ip|startswith:
            - "10."
            - "192.168."
    condition: selection
tags:
    - attack.t1046
"""
        rule = engine.add_rule_from_yaml(yaml_str)

        assert rule.rule_id == "yaml_test_rule"
        assert rule.severity == EventSeverity.MEDIUM
        assert engine.rule_count == 1

    def test_evaluate_with_match(self, engine: SigmaEngine) -> None:
        """Verify evaluation produces matches."""
        # Add a rule
        engine.add_rule_from_dict(
            {
                "id": "eval_test_rule",
                "title": "Eval Test Rule",
                "level": "high",
                "detection": {
                    "selection": {
                        "event_type|contains": ["auth_failed"],
                    },
                    "condition": "selection",
                },
            }
        )

        event = SecurityEvent(
            event_id="evt_eval_001",
            timestamp=datetime.now(UTC),
            source="auth_log",
            source_type="authentication",
            event_type="auth_failed",
            severity=EventSeverity.MEDIUM,
            raw_data={},
            normalized_data={},
        )

        matches = engine.evaluate(event)
        assert len(matches) == 1
        assert matches[0].rule_id == "eval_test_rule"

    def test_evaluate_no_match(self, engine: SigmaEngine) -> None:
        """Verify evaluation with no matches."""
        engine.add_rule_from_dict(
            {
                "id": "no_match_rule",
                "title": "No Match Rule",
                "level": "low",
                "detection": {
                    "selection": {
                        "event_type": ["very_specific_event"],
                    },
                    "condition": "selection",
                },
            }
        )

        event = SecurityEvent(
            event_id="evt_no_match",
            timestamp=datetime.now(UTC),
            source="generic",
            source_type="generic",
            event_type="generic_event",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
        )

        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_get_rule(self, engine: SigmaEngine) -> None:
        """Verify rule retrieval by ID."""
        engine.add_rule_from_dict(
            {
                "id": "retrieve_test",
                "title": "Retrieve Test",
                "level": "medium",
                "detection": {"selection": {"event_type": ["test"]}},
            }
        )

        rule = engine.get_rule("retrieve_test")
        assert rule is not None
        assert rule.rule_name == "Retrieve Test"

        missing = engine.get_rule("nonexistent")
        assert missing is None

    def test_list_rules(self, engine: SigmaEngine) -> None:
        """Verify listing all rules."""
        engine.add_rule_from_dict(
            {
                "id": "list_rule_1",
                "title": "List Rule 1",
                "level": "low",
                "detection": {"selection": {"event_type": ["a"]}},
            }
        )
        engine.add_rule_from_dict(
            {
                "id": "list_rule_2",
                "title": "List Rule 2",
                "level": "high",
                "detection": {"selection": {"event_type": ["b"]}},
            }
        )

        rules = engine.list_rules()
        assert len(rules) == 2

    def test_clear_rules(self, engine: SigmaEngine) -> None:
        """Verify clearing all rules."""
        engine.add_rule_from_dict(
            {
                "id": "clear_test",
                "title": "Clear Test",
                "level": "low",
                "detection": {"selection": {"event_type": ["x"]}},
            }
        )

        assert engine.rule_count == 1
        engine.clear_rules()
        assert engine.rule_count == 0
