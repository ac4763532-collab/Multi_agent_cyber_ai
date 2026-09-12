"""Unit tests for IoC (Indicator of Compromise) matching engine."""

from datetime import UTC, datetime

import pytest

from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.detection.models import MatchConfidence
from backend.app.detection.rules.ioc_engine import (
    SAMPLE_MALICIOUS_DOMAINS,
    SAMPLE_MALICIOUS_HASHES,
    SAMPLE_MALICIOUS_IPS,
    IoCEngine,
    IoCRule,
    IoCStore,
)
from backend.app.schemas.events import EventSeverity, SecurityEvent


class TestIoCStore:
    """Test suite for IoCStore class."""

    @pytest.fixture
    def store(self) -> IoCStore:
        """Create empty IoC store."""
        return IoCStore()

    @pytest.fixture
    def loaded_store(self) -> IoCStore:
        """Create IoC store with sample data loaded."""
        store = IoCStore()
        store.load()
        return store

    def test_add_ip(self, store: IoCStore) -> None:
        """Verify adding IP to blocklist."""
        store.add_ip("10.0.0.1")
        assert store.contains_ip("10.0.0.1") is True
        assert store.contains_ip("10.0.0.2") is False

    def test_add_ip_with_context(self, store: IoCStore) -> None:
        """Verify adding IP with context metadata."""
        store.add_ip("192.168.1.1", context={"category": "c2", "source": "threat_feed"})

        assert store.contains_ip("192.168.1.1") is True
        context = store.get_indicator_context("192.168.1.1")
        assert context is not None
        assert context["category"] == "c2"

    def test_add_domain(self, store: IoCStore) -> None:
        """Verify adding domain to blocklist."""
        store.add_domain("malicious.example.com")
        assert store.contains_domain("malicious.example.com") is True
        assert store.contains_domain("safe.example.com") is False

    def test_domain_subdomain_matching(self, store: IoCStore) -> None:
        """Verify subdomain matching against parent domain."""
        store.add_domain("evil.com")

        # Subdomains should match
        assert store.contains_domain("www.evil.com") is True
        assert store.contains_domain("sub.domain.evil.com") is True

        # Different domains should not match
        assert store.contains_domain("notevil.com") is False

    def test_add_hash(self, store: IoCStore) -> None:
        """Verify adding hash to blocklist."""
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"  # MD5
        store.add_hash(test_hash)

        assert store.contains_hash(test_hash) is True
        assert store.contains_hash(test_hash.upper()) is True  # Case insensitive
        assert store.contains_hash("0" * 32) is False

    def test_contains_url(self, store: IoCStore) -> None:
        """Verify URL checking extracts domain."""
        store.add_domain("phishing.example.com")

        assert store.contains_url("http://phishing.example.com/login") is True
        assert store.contains_url("https://phishing.example.com:8443/steal") is True
        assert store.contains_url("safe.example.com/page") is False

    def test_load_sample_data(self, loaded_store: IoCStore) -> None:
        """Verify sample data is loaded."""
        assert loaded_store.total_indicators > 0

        # Check sample IPs
        for ip in list(SAMPLE_MALICIOUS_IPS)[:2]:
            assert loaded_store.contains_ip(ip) is True

        # Check sample domains
        for domain in list(SAMPLE_MALICIOUS_DOMAINS)[:2]:
            assert loaded_store.contains_domain(domain) is True

        # Check sample hashes
        for h in list(SAMPLE_MALICIOUS_HASHES)[:2]:
            assert loaded_store.contains_hash(h) is True

    def test_invalid_ip_ignored(self, store: IoCStore) -> None:
        """Verify invalid IPs are ignored."""
        store.add_ip("not-an-ip")
        store.add_ip("256.256.256.256")

        assert store.contains_ip("not-an-ip") is False


class TestIoCRule:
    """Test suite for IoCRule class."""

    @pytest.fixture
    def store(self) -> IoCStore:
        """Create store with test data."""
        store = IoCStore()
        store.add_ip("203.0.113.100", context={"category": "c2"})
        store.add_domain("evil-c2.example.com")
        store.add_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        return store

    @pytest.fixture
    def ip_rule(self, store: IoCStore) -> IoCRule:
        """Create IP blocklist rule."""
        return IoCRule(
            rule_id="test_ip_blocklist",
            rule_name="Test IP Blocklist",
            ioc_type="ip",
            ioc_store=store,
            target_fields=["source_ip", "destination_ip"],
            severity=EventSeverity.HIGH,
        )

    def test_ioc_rule_properties(self, ip_rule: IoCRule) -> None:
        """Verify IoCRule property accessors."""
        assert ip_rule.rule_id == "test_ip_blocklist"
        assert ip_rule.rule_type == RuleType.IOC
        assert ip_rule.severity == EventSeverity.HIGH

    def test_ip_rule_matches(self, ip_rule: IoCRule) -> None:
        """Verify IP rule matches blocked IP."""
        event = SecurityEvent(
            event_id="evt_ioc_ip_test",
            timestamp=datetime.now(UTC),
            source="firewall",
            source_type="network",
            event_type="connection",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            source_ip="203.0.113.100",  # Blocked IP
        )

        match = ip_rule.matches(event)

        assert match is not None
        assert match.rule_type == RuleType.IOC
        assert match.confidence == MatchConfidence.DEFINITIVE  # IoC = definitive
        assert match.matched_field == "source_ip"
        assert match.matched_value == "203.0.113.100"
        assert match.match_details["ioc_type"] == "ip"

    def test_ip_rule_no_match(self, ip_rule: IoCRule) -> None:
        """Verify IP rule does not match clean IPs."""
        event = SecurityEvent(
            event_id="evt_clean_ip",
            timestamp=datetime.now(UTC),
            source="firewall",
            source_type="network",
            event_type="connection",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            source_ip="8.8.8.8",  # Clean IP
        )

        match = ip_rule.matches(event)
        assert match is None

    def test_domain_rule_matches(self, store: IoCStore) -> None:
        """Verify domain rule matches blocked domain."""
        domain_rule = IoCRule(
            rule_id="test_domain_blocklist",
            rule_name="Test Domain Blocklist",
            ioc_type="domain",
            ioc_store=store,
            target_fields=["domain", "hostname"],
            severity=EventSeverity.HIGH,
        )

        event = SecurityEvent(
            event_id="evt_ioc_domain_test",
            timestamp=datetime.now(UTC),
            source="dns",
            source_type="network",
            event_type="dns_query",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            domain="evil-c2.example.com",
        )

        match = domain_rule.matches(event)
        assert match is not None
        assert match.matched_value == "evil-c2.example.com"

    def test_hash_rule_matches(self, store: IoCStore) -> None:
        """Verify hash rule matches blocked hash."""
        hash_rule = IoCRule(
            rule_id="test_hash_blocklist",
            rule_name="Test Hash Blocklist",
            ioc_type="hash",
            ioc_store=store,
            target_fields=["hash"],
            severity=EventSeverity.CRITICAL,
        )

        event = SecurityEvent(
            event_id="evt_ioc_hash_test",
            timestamp=datetime.now(UTC),
            source="edr",
            source_type="endpoint",
            event_type="file_created",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

        match = hash_rule.matches(event)
        assert match is not None
        assert match.severity == EventSeverity.CRITICAL


class TestIoCEngine:
    """Test suite for IoCEngine class."""

    @pytest.fixture
    def engine(self) -> IoCEngine:
        """Create initialized IoC engine."""
        engine = IoCEngine()
        engine.load_rules()
        return engine

    def test_engine_properties(self, engine: IoCEngine) -> None:
        """Verify engine property accessors."""
        assert engine.engine_name == "ioc_engine"
        assert engine.rule_type == RuleType.IOC
        assert engine.detection_layer == DetectionLayer.L1_DETERMINISTIC
        assert engine.rule_count >= 4  # Default IP, domain, hash, URL rules

    def test_engine_evaluates_malicious_ip(self, engine: IoCEngine) -> None:
        """Verify engine detects malicious IP."""
        # Add a test IP to the store
        engine.ioc_store.add_ip("10.99.99.99")

        event = SecurityEvent(
            event_id="evt_engine_ip",
            timestamp=datetime.now(UTC),
            source="ids",
            source_type="network",
            event_type="network_traffic",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            source_ip="10.99.99.99",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

        ip_matches = [m for m in matches if m.match_details.get("ioc_type") == "ip"]
        assert len(ip_matches) >= 1

    def test_engine_evaluates_malicious_domain(self, engine: IoCEngine) -> None:
        """Verify engine detects malicious domain."""
        engine.ioc_store.add_domain("test-malware.xyz")

        event = SecurityEvent(
            event_id="evt_engine_domain",
            timestamp=datetime.now(UTC),
            source="dns",
            source_type="network",
            event_type="dns_query",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            hostname="test-malware.xyz",
        )

        matches = engine.evaluate(event)
        assert len(matches) >= 1

    def test_engine_clean_event(self, engine: IoCEngine) -> None:
        """Verify engine produces no matches for clean events."""
        event = SecurityEvent(
            event_id="evt_clean_ioc",
            timestamp=datetime.now(UTC),
            source="web",
            source_type="application",
            event_type="web_request",
            severity=EventSeverity.LOW,
            raw_data={},
            normalized_data={},
            source_ip="1.1.1.1",  # Cloudflare DNS - not in blocklist
            hostname="google.com",
        )

        matches = engine.evaluate(event)
        assert len(matches) == 0

    def test_add_custom_ioc_rule(self, engine: IoCEngine) -> None:
        """Verify adding custom IoC rule."""
        rule = engine.add_ioc_rule(
            ioc_type="ip",
            target_fields=["source_ip"],
            name="Custom IP Rule",
            severity=EventSeverity.MEDIUM,
        )

        assert rule.rule_name == "Custom IP Rule"
        assert engine.get_rule(rule.rule_id) is not None

    def test_list_rules(self, engine: IoCEngine) -> None:
        """Verify listing all rules."""
        rules = engine.list_rules()
        assert len(rules) >= 4
