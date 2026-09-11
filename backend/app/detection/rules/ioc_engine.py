"""Indicator of Compromise (IoC) matching engine for Layer 1 detection.

Provides fast O(1) lookup for known malicious indicators including:
- IP addresses (blocklists)
- Domain names (reputation lists)
- File hashes (MD5, SHA1, SHA256)
- URL patterns
"""

import ipaddress
import uuid
from pathlib import Path
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.detection.exceptions import IoCSouceLoadError
from backend.app.detection.interfaces import (
    DetectionLayer,
    DetectionRule,
    IoCSources,
    RuleEngine,
    RuleType,
)
from backend.app.detection.models import DetectionMatch, MatchConfidence
from backend.app.detection.rules.base import get_searchable_fields
from backend.app.schemas.events import EventSeverity, SecurityEvent

logger = get_logger("cyber_ai.detection.ioc")


# =============================================================================
# Sample IoC Data (Test/Demo Only - Replace with real threat intel in production)
# =============================================================================

SAMPLE_MALICIOUS_IPS: set[str] = {
    # Known test/demo malicious IPs (not real threats)
    "203.0.113.100",  # TEST-NET-3 - Documented as example
    "203.0.113.200",
    "198.51.100.100",  # TEST-NET-2
    "198.51.100.200",
    "192.0.2.100",  # TEST-NET-1
    "192.0.2.200",
    # Common honeypot/scanner IPs (examples)
    "45.33.32.156",  # scanme.nmap.org
}

SAMPLE_MALICIOUS_DOMAINS: set[str] = {
    # Test/demo malicious domains (not real threats)
    "malware-test.example.com",
    "phishing-demo.example.org",
    "c2-beacon.example.net",
    "evil-download.test.local",
    "fake-bank-login.xyz",
    "credential-harvest.test",
}

SAMPLE_MALICIOUS_HASHES: set[str] = {
    # Test hashes - EICAR test file and common test patterns
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR MD5
    "3395856ce81f2b7382dee72602f798b642f14140",  # EICAR SHA1
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR SHA256
    # Empty file hash (sometimes used in tests)
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty
}


class IoCStore(IoCSources):
    """In-memory IoC storage with efficient lookup."""

    def __init__(self) -> None:
        self._ips: set[str] = set()
        self._ip_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: set[str] = set()
        self._hashes: set[str] = set()
        self._urls: set[str] = set()
        self._url_patterns: list[str] = []

        # Context/metadata for indicators
        self._ip_context: dict[str, dict[str, Any]] = {}
        self._domain_context: dict[str, dict[str, Any]] = {}
        self._hash_context: dict[str, dict[str, Any]] = {}

    def load(self, source_path: str | None = None) -> int:
        """Load IoCs from files or use sample data."""
        loaded = 0

        if source_path:
            path = Path(source_path)
            if path.is_dir():
                # Load from directory structure
                loaded += self._load_ip_file(path / "ip_blocklist.txt")
                loaded += self._load_domain_file(path / "domain_blocklist.txt")
                loaded += self._load_hash_file(path / "hash_blocklist.txt")
            elif path.is_file():
                # Load single file based on name
                name_lower = path.name.lower()
                if "ip" in name_lower:
                    loaded += self._load_ip_file(path)
                elif "domain" in name_lower:
                    loaded += self._load_domain_file(path)
                elif "hash" in name_lower:
                    loaded += self._load_hash_file(path)

        # Load sample data if nothing loaded
        if loaded == 0:
            self._ips.update(SAMPLE_MALICIOUS_IPS)
            self._domains.update(SAMPLE_MALICIOUS_DOMAINS)
            self._hashes.update(h.lower() for h in SAMPLE_MALICIOUS_HASHES)
            loaded = (
                len(SAMPLE_MALICIOUS_IPS)
                + len(SAMPLE_MALICIOUS_DOMAINS)
                + len(SAMPLE_MALICIOUS_HASHES)
            )
            logger.info("Loaded %d sample IoCs (demo mode)", loaded)

        return loaded

    def _load_ip_file(self, file_path: Path) -> int:
        """Load IP addresses from file (one per line)."""
        if not file_path.exists():
            return 0

        loaded = 0
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Parse optional context (IP,category,source)
                    parts = line.split(",")
                    ip_str = parts[0].strip()

                    try:
                        # Check if it's a CIDR range
                        if "/" in ip_str:
                            network = ipaddress.ip_network(ip_str, strict=False)
                            self._ip_ranges.append(network)
                        else:
                            ip = ipaddress.ip_address(ip_str)
                            self._ips.add(str(ip))

                        if len(parts) > 1:
                            self._ip_context[ip_str] = {
                                "category": parts[1].strip() if len(parts) > 1 else "malicious",
                                "source": parts[2].strip() if len(parts) > 2 else "blocklist",
                            }
                        loaded += 1
                    except ValueError:
                        logger.debug("Invalid IP in blocklist: %s", ip_str)

        except OSError as e:
            raise IoCSouceLoadError(
                f"Failed to load IP blocklist: {e}",
                source_path=str(file_path),
                ioc_type="ip",
            ) from e

        logger.info("Loaded %d IPs from %s", loaded, file_path)
        return loaded

    def _load_domain_file(self, file_path: Path) -> int:
        """Load domains from file (one per line)."""
        if not file_path.exists():
            return 0

        loaded = 0
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(",")
                    domain = parts[0].strip().lower()

                    if domain:
                        self._domains.add(domain)
                        if len(parts) > 1:
                            self._domain_context[domain] = {
                                "category": parts[1].strip() if len(parts) > 1 else "malicious",
                                "source": parts[2].strip() if len(parts) > 2 else "blocklist",
                            }
                        loaded += 1

        except OSError as e:
            raise IoCSouceLoadError(
                f"Failed to load domain blocklist: {e}",
                source_path=str(file_path),
                ioc_type="domain",
            ) from e

        logger.info("Loaded %d domains from %s", loaded, file_path)
        return loaded

    def _load_hash_file(self, file_path: Path) -> int:
        """Load file hashes from file (one per line)."""
        if not file_path.exists():
            return 0

        loaded = 0
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(",")
                    file_hash = parts[0].strip().lower()

                    # Validate hash format (MD5: 32, SHA1: 40, SHA256: 64)
                    valid_len = len(file_hash) in (32, 40, 64)
                    valid_hex = all(c in "0123456789abcdef" for c in file_hash)
                    if valid_len and valid_hex:
                        self._hashes.add(file_hash)
                        if len(parts) > 1:
                            self._hash_context[file_hash] = {
                                "malware_family": parts[1].strip() if len(parts) > 1 else "unknown",
                                "source": parts[2].strip() if len(parts) > 2 else "blocklist",
                            }
                        loaded += 1

        except OSError as e:
            raise IoCSouceLoadError(
                f"Failed to load hash blocklist: {e}",
                source_path=str(file_path),
                ioc_type="hash",
            ) from e

        logger.info("Loaded %d hashes from %s", loaded, file_path)
        return loaded

    def add_ip(self, ip: str, context: dict[str, Any] | None = None) -> None:
        """Add an IP to the blocklist."""
        try:
            parsed = ipaddress.ip_address(ip)
            self._ips.add(str(parsed))
            if context:
                self._ip_context[str(parsed)] = context
        except ValueError:
            logger.warning("Invalid IP address: %s", ip)

    def add_domain(self, domain: str, context: dict[str, Any] | None = None) -> None:
        """Add a domain to the blocklist."""
        domain_lower = domain.lower().strip()
        self._domains.add(domain_lower)
        if context:
            self._domain_context[domain_lower] = context

    def add_hash(self, file_hash: str, context: dict[str, Any] | None = None) -> None:
        """Add a hash to the blocklist."""
        hash_lower = file_hash.lower().strip()
        self._hashes.add(hash_lower)
        if context:
            self._hash_context[hash_lower] = context

    def contains_ip(self, ip: str) -> bool:
        """Check if IP is in blocklist."""
        if not ip:
            return False

        try:
            parsed = ipaddress.ip_address(ip)
            ip_str = str(parsed)

            # Check exact match
            if ip_str in self._ips:
                return True

            # Check CIDR ranges
            for network in self._ip_ranges:
                if parsed in network:
                    return True

            return False
        except ValueError:
            return False

    def contains_domain(self, domain: str) -> bool:
        """Check if domain is in blocklist (supports subdomain matching)."""
        if not domain:
            return False

        domain_lower = domain.lower().strip()

        # Exact match
        if domain_lower in self._domains:
            return True

        # Check if any parent domain is blocked
        parts = domain_lower.split(".")
        for i in range(len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._domains:
                return True

        return False

    def contains_hash(self, file_hash: str) -> bool:
        """Check if hash is in blocklist."""
        if not file_hash:
            return False
        return file_hash.lower().strip() in self._hashes

    def contains_url(self, url: str) -> bool:
        """Check if URL matches blocklist (domain extraction)."""
        if not url:
            return False

        # Extract domain from URL
        url_lower = url.lower()
        domain = None

        # Simple domain extraction
        if "://" in url_lower:
            domain = url_lower.split("://")[1].split("/")[0].split(":")[0]
        else:
            domain = url_lower.split("/")[0].split(":")[0]

        if domain:
            return self.contains_domain(domain)

        return False

    def get_indicator_context(self, indicator: str) -> dict[str, Any] | None:
        """Get context/metadata for a matched indicator."""
        indicator_lower = indicator.lower().strip()

        # Check IP context
        if indicator in self._ip_context:
            return self._ip_context[indicator]

        # Check domain context
        if indicator_lower in self._domain_context:
            return self._domain_context[indicator_lower]

        # Check hash context
        if indicator_lower in self._hash_context:
            return self._hash_context[indicator_lower]

        return None

    @property
    def total_indicators(self) -> int:
        """Total number of loaded indicators."""
        return len(self._ips) + len(self._ip_ranges) + len(self._domains) + len(self._hashes)


class IoCRule(DetectionRule):
    """IoC matching rule that checks event fields against blocklists."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        ioc_type: str,  # ip, domain, hash, url
        ioc_store: IoCStore,
        target_fields: list[str],
        severity: EventSeverity = EventSeverity.HIGH,
        description: str = "",
        mitre_techniques: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        self._rule_id = rule_id
        self._rule_name = rule_name
        self._ioc_type = ioc_type
        self._ioc_store = ioc_store
        self._target_fields = target_fields
        self._severity = severity
        self._description = description
        self._mitre_techniques = mitre_techniques or []
        self._mitre_tactics = mitre_tactics or []
        self._enabled = enabled

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def rule_name(self) -> str:
        return self._rule_name

    @property
    def rule_type(self) -> RuleType:
        return RuleType.IOC

    @property
    def severity(self) -> EventSeverity:
        return self._severity

    @property
    def description(self) -> str:
        return self._description

    @property
    def mitre_techniques(self) -> list[str]:
        return self._mitre_techniques

    @property
    def mitre_tactics(self) -> list[str]:
        return self._mitre_tactics

    @property
    def enabled(self) -> bool:
        return self._enabled

    def matches(self, event: SecurityEvent) -> DetectionMatch | None:  # noqa: C901
        """Check if event contains any blocked indicators."""
        if not self._enabled:
            return None

        fields = get_searchable_fields(event)

        for target_field in self._target_fields:
            value = fields.get(target_field)
            if value is None:
                # Case-insensitive lookup
                target_lower = target_field.lower()
                for key, val in fields.items():
                    if key.lower() == target_lower:
                        value = val
                        break

            if value is None:
                continue

            value_str = str(value).strip()
            if not value_str:
                continue

            # Check based on IoC type
            matched = False
            if self._ioc_type == "ip":
                matched = self._ioc_store.contains_ip(value_str)
            elif self._ioc_type == "domain":
                matched = self._ioc_store.contains_domain(value_str)
            elif self._ioc_type == "hash":
                matched = self._ioc_store.contains_hash(value_str)
            elif self._ioc_type == "url":
                matched = self._ioc_store.contains_url(value_str)

            if matched:
                context = self._ioc_store.get_indicator_context(value_str)
                match_details: dict[str, Any] = {
                    "ioc_type": self._ioc_type,
                    "indicator": value_str,
                    "context": context,
                }

                return DetectionMatch(
                    rule_id=self._rule_id,
                    rule_name=self._rule_name,
                    rule_type=RuleType.IOC,
                    rule_version="1.0.0",
                    detection_layer=DetectionLayer.L1_DETERMINISTIC,
                    severity=self._severity,
                    confidence=MatchConfidence.DEFINITIVE,  # IoC matches are definitive
                    matched_field=target_field,
                    matched_value=value_str,
                    match_details=match_details,
                    mitre_techniques=self._mitre_techniques,
                    mitre_tactics=self._mitre_tactics,
                    description=self._description,
                )

        return None


class IoCEngine(RuleEngine):
    """IoC matching engine with efficient blocklist lookups."""

    def __init__(self) -> None:
        self._ioc_store = IoCStore()
        self._rules: dict[str, IoCRule] = {}
        self._initialized = False

    def _initialize_default_rules(self) -> None:
        """Create default IoC matching rules."""
        # IP blocklist rule
        ip_rule = IoCRule(
            rule_id="ioc_ip_blocklist",
            rule_name="Malicious IP Address Detected",
            ioc_type="ip",
            ioc_store=self._ioc_store,
            target_fields=["source_ip", "destination_ip"],
            severity=EventSeverity.HIGH,
            description="Source or destination IP matches known malicious IP blocklist",
            mitre_techniques=["T1071"],
            mitre_tactics=["command-and-control"],
        )
        self._rules[ip_rule.rule_id] = ip_rule

        # Domain blocklist rule
        domain_rule = IoCRule(
            rule_id="ioc_domain_blocklist",
            rule_name="Malicious Domain Detected",
            ioc_type="domain",
            ioc_store=self._ioc_store,
            target_fields=["domain", "hostname", "url"],
            severity=EventSeverity.HIGH,
            description="Domain matches known malicious domain blocklist",
            mitre_techniques=["T1071.001"],
            mitre_tactics=["command-and-control"],
        )
        self._rules[domain_rule.rule_id] = domain_rule

        # Hash blocklist rule
        hash_rule = IoCRule(
            rule_id="ioc_hash_blocklist",
            rule_name="Malicious File Hash Detected",
            ioc_type="hash",
            ioc_store=self._ioc_store,
            target_fields=["hash", "metadata.file_hash", "raw_data.sha256"],
            severity=EventSeverity.CRITICAL,
            description="File hash matches known malware signature",
            mitre_techniques=["T1204"],
            mitre_tactics=["execution"],
        )
        self._rules[hash_rule.rule_id] = hash_rule

        # URL blocklist rule
        url_rule = IoCRule(
            rule_id="ioc_url_blocklist",
            rule_name="Malicious URL Detected",
            ioc_type="url",
            ioc_store=self._ioc_store,
            target_fields=["url", "raw_data.url", "metadata.url"],
            severity=EventSeverity.HIGH,
            description="URL matches known malicious URL patterns",
            mitre_techniques=["T1566.002"],
            mitre_tactics=["initial-access"],
        )
        self._rules[url_rule.rule_id] = url_rule

        self._initialized = True

    @property
    def engine_name(self) -> str:
        return "ioc_engine"

    @property
    def rule_type(self) -> RuleType:
        return RuleType.IOC

    @property
    def detection_layer(self) -> DetectionLayer:
        return DetectionLayer.L1_DETERMINISTIC

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def ioc_store(self) -> IoCStore:
        """Access the underlying IoC store."""
        return self._ioc_store

    def load_rules(self, rules_path: str | None = None) -> int:
        """Load IoC blocklists from files."""
        loaded = self._ioc_store.load(rules_path)

        if not self._initialized:
            self._initialize_default_rules()

        logger.info("IoC engine loaded %d indicators, %d rules", loaded, len(self._rules))
        return loaded

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a custom IoC rule."""
        if isinstance(rule, IoCRule):
            self._rules[rule.rule_id] = rule
        else:
            logger.warning("Attempted to add non-IoC rule to IoCEngine: %s", type(rule))

    def add_ioc_rule(
        self,
        ioc_type: str,
        target_fields: list[str],
        name: str | None = None,
        severity: EventSeverity = EventSeverity.HIGH,
        rule_id: str | None = None,
    ) -> IoCRule:
        """Create and add a new IoC matching rule.

        Args:
            ioc_type: Type of indicator (ip, domain, hash, url)
            target_fields: Event fields to check
            name: Optional rule name
            severity: Detection severity
            rule_id: Optional custom rule ID

        Returns:
            The created IoCRule
        """
        rid = rule_id or f"ioc_custom_{uuid.uuid4().hex[:8]}"
        rname = name or f"Custom {ioc_type.upper()} IoC Match"

        rule = IoCRule(
            rule_id=rid,
            rule_name=rname,
            ioc_type=ioc_type,
            ioc_store=self._ioc_store,
            target_fields=target_fields,
            severity=severity,
        )
        self._rules[rule.rule_id] = rule
        return rule

    def evaluate(self, event: SecurityEvent) -> list[DetectionMatch]:
        """Evaluate all IoC rules against an event."""
        if not self._initialized:
            self.load_rules()

        matches: list[DetectionMatch] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                match = rule.matches(event)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.warning("Error evaluating IoC rule %s: %s", rule.rule_id, e)

        return matches

    def get_rule(self, rule_id: str) -> IoCRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[DetectionRule]:
        """List all loaded rules."""
        return list(self._rules.values())

    def clear_rules(self) -> None:
        """Remove all rules (but keep IoC store)."""
        self._rules.clear()
        self._initialized = False
