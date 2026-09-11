"""Regex pattern matching engine for Layer 1 deterministic detection.

Provides fast precompiled regex-based detection for common attack patterns
including SQL injection, XSS, command injection, path traversal, and more.
"""

import re
import uuid
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.detection.exceptions import RuleCompilationError
from backend.app.detection.interfaces import DetectionLayer, DetectionRule, RuleEngine, RuleType
from backend.app.detection.models import DetectionMatch, MatchConfidence
from backend.app.detection.rules.base import get_searchable_fields, safe_str, severity_from_string
from backend.app.schemas.events import EventSeverity, SecurityEvent

logger = get_logger("cyber_ai.detection.regex")


# =============================================================================
# Built-in Attack Pattern Definitions
# =============================================================================

BUILTIN_PATTERNS: list[dict[str, Any]] = [
    # SQL Injection Patterns
    {
        "id": "regex_sqli_union",
        "name": "SQL Injection - UNION SELECT",
        "pattern": r"(?i)union\s+(all\s+)?select\s+",
        "severity": "high",
        "fields": ["url", "raw_string", "raw_data.query", "normalized_data.url.original"],
        "mitre_techniques": ["T1190"],
        "mitre_tactics": ["initial-access"],
        "tags": ["sqli", "web-attack", "injection"],
        "description": "Detects SQL injection attempts using UNION SELECT statements",
    },
    {
        "id": "regex_sqli_or_bypass",
        "name": "SQL Injection - OR Boolean Bypass",
        "pattern": r"(?i)['\"]?\s*or\s+['\"]?[\d]+['\"]?\s*=\s*['\"]?[\d]+",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1190"],
        "mitre_tactics": ["initial-access"],
        "tags": ["sqli", "web-attack", "injection"],
        "description": "Detects SQL injection using OR 1=1 style bypasses",
    },
    {
        "id": "regex_sqli_comment",
        "name": "SQL Injection - Comment Termination",
        "pattern": r"(?i)(['\"]\s*;\s*--)|(['\"]\s*#)|(\*/\s*;)",
        "severity": "medium",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1190"],
        "tags": ["sqli", "web-attack"],
        "description": "Detects SQL injection using comment-based query termination",
    },
    {
        "id": "regex_sqli_stacked",
        "name": "SQL Injection - Stacked Queries",
        "pattern": r"(?i);\s*(drop|delete|truncate|update|insert|alter)\s+",
        "severity": "critical",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1190"],
        "tags": ["sqli", "web-attack", "destructive"],
        "description": "Detects SQL injection with stacked destructive queries",
    },
    # XSS Patterns
    {
        "id": "regex_xss_script_tag",
        "name": "XSS - Script Tag Injection",
        "pattern": r"(?i)<\s*script[^>]*>",
        "severity": "high",
        "fields": ["url", "raw_string", "raw_data.body"],
        "mitre_techniques": ["T1059.007"],
        "mitre_tactics": ["execution"],
        "tags": ["xss", "web-attack", "injection"],
        "description": "Detects XSS attempts using script tag injection",
    },
    {
        "id": "regex_xss_event_handler",
        "name": "XSS - Event Handler Injection",
        "pattern": r"(?i)\bon\w+\s*=\s*['\"]?[^'\"]*['\"]?",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1059.007"],
        "tags": ["xss", "web-attack"],
        "description": "Detects XSS attempts using event handlers (onclick, onerror, etc.)",
    },
    {
        "id": "regex_xss_javascript_uri",
        "name": "XSS - JavaScript URI",
        "pattern": r"(?i)javascript\s*:",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1059.007"],
        "tags": ["xss", "web-attack"],
        "description": "Detects XSS attempts using javascript: URI scheme",
    },
    {
        "id": "regex_xss_data_uri",
        "name": "XSS - Data URI with Script",
        "pattern": r"(?i)data\s*:\s*text/html",
        "severity": "medium",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1059.007"],
        "tags": ["xss", "web-attack"],
        "description": "Detects XSS attempts using data: URI with HTML content",
    },
    # Command Injection Patterns
    {
        "id": "regex_cmdi_shell_metachar",
        "name": "Command Injection - Shell Metacharacters",
        "pattern": r"(?i)[;&|`$]\s*(cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby)\s",  # noqa: E501
        "severity": "critical",
        "fields": ["url", "raw_string", "raw_data.command"],
        "mitre_techniques": ["T1059.004"],
        "mitre_tactics": ["execution"],
        "tags": ["command-injection", "rce"],
        "description": "Detects command injection using shell metacharacters",
    },
    {
        "id": "regex_cmdi_etc_passwd",
        "name": "Command Injection - /etc/passwd Access",
        "pattern": r"(?i)(cat|head|tail|less|more|type)\s+[^\s]*(/etc/passwd|/etc/shadow)",
        "severity": "critical",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1003.008"],
        "mitre_tactics": ["credential-access"],
        "tags": ["command-injection", "credential-theft"],
        "description": "Detects attempts to read Unix password files",
    },
    {
        "id": "regex_cmdi_reverse_shell",
        "name": "Command Injection - Reverse Shell",
        "pattern": r"(?i)(bash\s+-i|nc\s+-[elp]|/dev/tcp/|mkfifo|python\s+-c\s+['\"]import\s+socket)",  # noqa: E501
        "severity": "critical",
        "fields": ["raw_string", "raw_data.command"],
        "mitre_techniques": ["T1059.004"],
        "tags": ["command-injection", "reverse-shell", "rce"],
        "description": "Detects reverse shell command patterns",
    },
    # Path Traversal Patterns
    {
        "id": "regex_lfi_dotdot",
        "name": "Path Traversal - Directory Traversal",
        "pattern": r"(?i)(\.\.[\\/]){2,}",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1083"],
        "tags": ["lfi", "path-traversal"],
        "description": "Detects directory traversal using ../ sequences",
    },
    {
        "id": "regex_lfi_encoded",
        "name": "Path Traversal - URL Encoded",
        "pattern": r"(?i)(%2e%2e[%2f%5c]|%252e%252e%252f|\.\.%c0%af|\.\.%c1%9c)",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1083"],
        "tags": ["lfi", "path-traversal", "evasion"],
        "description": "Detects URL-encoded path traversal attempts",
    },
    # Log4Shell / JNDI Injection
    {
        "id": "regex_log4shell_jndi",
        "name": "Log4Shell - JNDI Injection",
        "pattern": r"(?i)\$\{(jndi|lower|upper|env|sys|date|java):[^}]+\}",
        "severity": "critical",
        "fields": ["url", "raw_string", "username", "hostname", "raw_data.user_agent"],
        "mitre_techniques": ["T1190", "T1059"],
        "mitre_tactics": ["initial-access", "execution"],
        "tags": ["log4shell", "jndi", "rce", "cve-2021-44228"],
        "description": "Detects Log4Shell JNDI injection attempts (CVE-2021-44228)",
    },
    {
        "id": "regex_log4shell_obfuscated",
        "name": "Log4Shell - Obfuscated JNDI",
        "pattern": r"(?i)\$\{[^}]*\$\{[^}]*\}[^}]*\}",
        "severity": "critical",
        "fields": ["url", "raw_string", "raw_data.user_agent"],
        "mitre_techniques": ["T1190", "T1027"],
        "tags": ["log4shell", "jndi", "obfuscation"],
        "description": "Detects obfuscated Log4Shell attempts with nested expressions",
    },
    # SSRF Patterns
    {
        "id": "regex_ssrf_internal",
        "name": "SSRF - Internal IP Access",
        "pattern": r"(?i)(https?://)(localhost|127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0)",
        "severity": "high",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1090"],
        "tags": ["ssrf", "web-attack"],
        "description": "Detects SSRF attempts targeting internal/private IP addresses",
    },
    {
        "id": "regex_ssrf_cloud_metadata",
        "name": "SSRF - Cloud Metadata Endpoint",
        "pattern": r"(?i)(169\.254\.169\.254|metadata\.google|100\.100\.100\.200)",
        "severity": "critical",
        "fields": ["url", "raw_string"],
        "mitre_techniques": ["T1552.005"],
        "mitre_tactics": ["credential-access"],
        "tags": ["ssrf", "cloud", "metadata"],
        "description": "Detects SSRF attempts targeting cloud metadata endpoints",
    },
    # Authentication Attack Patterns
    {
        "id": "regex_auth_brute_indicator",
        "name": "Authentication - Brute Force Indicator",
        "pattern": r"(?i)(failed\s+(password|login|auth)|invalid\s+(user|credentials)|authentication\s+fail)",  # noqa: E501
        "severity": "medium",
        "fields": ["raw_string", "status", "raw_data.message"],
        "mitre_techniques": ["T1110"],
        "mitre_tactics": ["credential-access"],
        "tags": ["brute-force", "authentication"],
        "description": "Detects authentication failure indicators",
    },
    # Suspicious User-Agent Patterns
    {
        "id": "regex_ua_scanner",
        "name": "Suspicious User-Agent - Security Scanner",
        "pattern": r"(?i)(nikto|nmap|sqlmap|burp|acunetix|nessus|openvas|masscan|zgrab|gobuster|dirbuster)",  # noqa: E501
        "severity": "medium",
        "fields": ["raw_string", "raw_data.user_agent", "metadata.user_agent"],
        "mitre_techniques": ["T1595"],
        "mitre_tactics": ["reconnaissance"],
        "tags": ["scanner", "recon"],
        "description": "Detects known security scanner user-agent strings",
    },
]


class RegexRule(DetectionRule):
    """Compiled regex detection rule."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        pattern: re.Pattern[str],
        severity: EventSeverity,
        target_fields: list[str],
        description: str = "",
        mitre_techniques: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        references: list[str] | None = None,
        tags: list[str] | None = None,
        enabled: bool = True,
        version: str = "1.0.0",
    ) -> None:
        self._rule_id = rule_id
        self._rule_name = rule_name
        self._pattern = pattern
        self._severity = severity
        self._target_fields = target_fields
        self._description = description
        self._mitre_techniques = mitre_techniques or []
        self._mitre_tactics = mitre_tactics or []
        self._references = references or []
        self._tags = tags or []
        self._enabled = enabled
        self._version = version

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def rule_name(self) -> str:
        return self._rule_name

    @property
    def rule_type(self) -> RuleType:
        return RuleType.REGEX

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
    def references(self) -> list[str]:
        return self._references

    @property
    def tags(self) -> list[str]:
        return self._tags

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def version(self) -> str:
        return self._version

    @property
    def pattern_str(self) -> str:
        """Return the raw pattern string."""
        return self._pattern.pattern

    def matches(self, event: SecurityEvent) -> DetectionMatch | None:
        """Evaluate regex pattern against event fields."""
        if not self._enabled:
            return None

        fields = get_searchable_fields(event)

        for target_field in self._target_fields:
            # Try exact field match
            value = fields.get(target_field)
            if value is None:
                # Try case-insensitive lookup
                target_lower = target_field.lower()
                for key, val in fields.items():
                    if key.lower() == target_lower:
                        value = val
                        break

            if value is None:
                continue

            value_str = safe_str(value)
            if not value_str:
                continue

            # Check pattern match
            match = self._pattern.search(value_str)
            if match:
                matched_value = match.group(0)
                match_details = {
                    "pattern": self._pattern.pattern,
                    "matched_text": matched_value,
                    "match_start": match.start(),
                    "match_end": match.end(),
                    "field_value_length": len(value_str),
                }

                return DetectionMatch(
                    rule_id=self._rule_id,
                    rule_name=self._rule_name,
                    rule_type=RuleType.REGEX,
                    rule_version=self._version,
                    detection_layer=DetectionLayer.L1_DETERMINISTIC,
                    severity=self._severity,
                    confidence=MatchConfidence.HIGH,
                    matched_field=target_field,
                    matched_value=matched_value[:256],  # Truncate long matches
                    match_details=match_details,
                    mitre_techniques=self._mitre_techniques,
                    mitre_tactics=self._mitre_tactics,
                    description=self._description,
                    references=self._references,
                    tags=self._tags,
                )

        return None


class RegexEngine(RuleEngine):
    """Regex pattern matching engine with precompiled patterns."""

    def __init__(self, load_builtin: bool = True) -> None:
        self._rules: dict[str, RegexRule] = {}
        if load_builtin:
            self._load_builtin_patterns()

    def _load_builtin_patterns(self) -> None:
        """Load built-in attack pattern definitions."""
        for pattern_def in BUILTIN_PATTERNS:
            try:
                rule = self._compile_pattern(pattern_def)
                self._rules[rule.rule_id] = rule
            except Exception as e:
                logger.warning("Failed to compile builtin pattern %s: %s", pattern_def.get("id"), e)

        logger.info("Loaded %d built-in regex patterns", len(self._rules))

    def _compile_pattern(self, pattern_def: dict[str, Any]) -> RegexRule:
        """Compile a pattern definition into a RegexRule."""
        rule_id = pattern_def.get("id", f"regex_{uuid.uuid4().hex[:8]}")
        pattern_str = pattern_def.get("pattern")

        if not pattern_str:
            raise RuleCompilationError("Missing pattern string", rule_id=rule_id, rule_type="regex")

        try:
            compiled = re.compile(pattern_str)
        except re.error as e:
            raise RuleCompilationError(
                f"Invalid regex: {e}", rule_id=rule_id, rule_type="regex"
            ) from e

        severity = severity_from_string(pattern_def.get("severity", "medium"))
        target_fields = pattern_def.get("fields", ["raw_string", "url"])

        return RegexRule(
            rule_id=rule_id,
            rule_name=pattern_def.get("name", rule_id),
            pattern=compiled,
            severity=severity,
            target_fields=target_fields,
            description=pattern_def.get("description", ""),
            mitre_techniques=pattern_def.get("mitre_techniques", []),
            mitre_tactics=pattern_def.get("mitre_tactics", []),
            references=pattern_def.get("references", []),
            tags=pattern_def.get("tags", []),
            enabled=pattern_def.get("enabled", True),
            version=pattern_def.get("version", "1.0.0"),
        )

    @property
    def engine_name(self) -> str:
        return "regex_engine"

    @property
    def rule_type(self) -> RuleType:
        return RuleType.REGEX

    @property
    def detection_layer(self) -> DetectionLayer:
        return DetectionLayer.L1_DETERMINISTIC

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def load_rules(self, rules_path: str | None = None) -> int:
        """Load additional regex rules from JSON/YAML file."""
        # Built-in patterns are loaded in __init__
        # This method can load additional custom patterns
        if rules_path is None:
            return len(self._rules)

        # TODO: Implement loading from file
        logger.info("Custom regex rules loading not yet implemented")
        return len(self._rules)

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a compiled rule to the engine."""
        if isinstance(rule, RegexRule):
            self._rules[rule.rule_id] = rule
        else:
            logger.warning("Attempted to add non-Regex rule to RegexEngine: %s", type(rule))

    def add_pattern(
        self,
        pattern: str,
        name: str,
        severity: EventSeverity | str = EventSeverity.MEDIUM,
        target_fields: list[str] | None = None,
        rule_id: str | None = None,
        **kwargs: Any,
    ) -> RegexRule:
        """Add a new pattern to the engine.

        Args:
            pattern: Regex pattern string
            name: Human-readable rule name
            severity: Detection severity
            target_fields: Fields to match against
            rule_id: Optional custom rule ID
            **kwargs: Additional rule metadata

        Returns:
            The compiled RegexRule
        """
        pattern_def = {
            "id": rule_id or f"regex_custom_{uuid.uuid4().hex[:8]}",
            "name": name,
            "pattern": pattern,
            "severity": severity if isinstance(severity, str) else severity.value,
            "fields": target_fields or ["raw_string", "url"],
            **kwargs,
        }

        rule = self._compile_pattern(pattern_def)
        self._rules[rule.rule_id] = rule
        return rule

    def evaluate(self, event: SecurityEvent) -> list[DetectionMatch]:
        """Evaluate all patterns against an event."""
        matches: list[DetectionMatch] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                match = rule.matches(event)
                if match:
                    matches.append(match)
            except Exception as e:
                logger.warning("Error evaluating regex rule %s: %s", rule.rule_id, e)

        return matches

    def get_rule(self, rule_id: str) -> RegexRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[DetectionRule]:
        """List all loaded rules."""
        return list(self._rules.values())

    def clear_rules(self) -> None:
        """Remove all loaded rules."""
        self._rules.clear()

    def get_patterns_by_tag(self, tag: str) -> list[RegexRule]:
        """Get all rules with a specific tag."""
        return [r for r in self._rules.values() if tag in r.tags]
