"""Abstract interfaces and protocol definitions for the detection engine layer."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.app.detection.models import DetectionMatch
    from backend.app.schemas.events import EventSeverity, SecurityEvent


class RuleType(StrEnum):
    """Classification of detection rule types."""

    SIGMA = "sigma"
    REGEX = "regex"
    IOC = "ioc"
    YARA = "yara"
    CUSTOM = "custom"


class DetectionLayer(StrEnum):
    """Detection layer classification per defense-in-depth architecture."""

    L1_DETERMINISTIC = "L1_deterministic"
    L2_STATISTICAL = "L2_statistical"
    L3_ML = "L3_ml"
    L4_LLM = "L4_llm"
    L5_THREAT_INTEL = "L5_threat_intel"
    L6_CORRELATION = "L6_correlation"


class DetectionRule(ABC):
    """Abstract base class for all detection rules.

    Each rule encapsulates a single detection pattern that can be evaluated
    against SecurityEvent instances. Rules are stateless and thread-safe.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this detection rule."""
        ...

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name describing the detection."""
        ...

    @property
    @abstractmethod
    def rule_type(self) -> RuleType:
        """Type classification of this rule (sigma, regex, ioc, etc.)."""
        ...

    @property
    @abstractmethod
    def severity(self) -> "EventSeverity":
        """Default severity level when this rule triggers."""
        ...

    @property
    def description(self) -> str:
        """Optional detailed description of what this rule detects."""
        return ""

    @property
    def mitre_techniques(self) -> list[str]:
        """MITRE ATT&CK technique IDs associated with this detection."""
        return []

    @property
    def mitre_tactics(self) -> list[str]:
        """MITRE ATT&CK tactic IDs associated with this detection."""
        return []

    @property
    def references(self) -> list[str]:
        """External reference URLs for this detection."""
        return []

    @property
    def tags(self) -> list[str]:
        """Classification tags for rule categorization."""
        return []

    @property
    def enabled(self) -> bool:
        """Whether this rule is active for detection."""
        return True

    @property
    def version(self) -> str:
        """Version string of this rule definition."""
        return "1.0.0"

    @abstractmethod
    def matches(self, event: "SecurityEvent") -> "DetectionMatch | None":
        """Evaluate this rule against a security event.

        Args:
            event: Normalized SecurityEvent to evaluate.

        Returns:
            DetectionMatch if the rule triggers, None otherwise.
        """
        ...


class RuleEngine(ABC):
    """Abstract base class for rule evaluation engines.

    Each engine handles a specific rule type (Sigma, Regex, IoC) and
    manages a collection of rules for batch evaluation.
    """

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Identifier name for this engine."""
        ...

    @property
    @abstractmethod
    def rule_type(self) -> RuleType:
        """Type of rules this engine handles."""
        ...

    @property
    @abstractmethod
    def detection_layer(self) -> DetectionLayer:
        """Detection layer this engine operates at."""
        ...

    @property
    def rule_count(self) -> int:
        """Number of active rules loaded in this engine."""
        return 0

    @abstractmethod
    def load_rules(self, rules_path: str | None = None) -> int:
        """Load rules from filesystem or default bundle.

        Args:
            rules_path: Optional path to rules directory or file.

        Returns:
            Number of rules successfully loaded.
        """
        ...

    @abstractmethod
    def add_rule(self, rule: DetectionRule) -> None:
        """Add a single rule to the engine.

        Args:
            rule: DetectionRule instance to register.
        """
        ...

    @abstractmethod
    def evaluate(self, event: "SecurityEvent") -> list["DetectionMatch"]:
        """Evaluate all loaded rules against a security event.

        Args:
            event: SecurityEvent to evaluate.

        Returns:
            List of DetectionMatch objects for all triggered rules.
        """
        ...

    @abstractmethod
    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Retrieve a specific rule by ID.

        Args:
            rule_id: Unique identifier of the rule.

        Returns:
            DetectionRule if found, None otherwise.
        """
        ...

    @abstractmethod
    def list_rules(self) -> list[DetectionRule]:
        """Return all loaded rules.

        Returns:
            List of all DetectionRule instances.
        """
        ...


class DetectionEngineInterface(ABC):
    """Abstract interface for the main detection orchestrator.

    The orchestrator coordinates multiple rule engines (Sigma, Regex, IoC)
    and aggregates their results into unified DetectionFinding objects.
    """

    @abstractmethod
    async def evaluate(
        self,
        event: "SecurityEvent",
        engines: list[RuleType] | None = None,
    ) -> list["DetectionMatch"]:
        """Evaluate event against all or specified rule engines.

        Args:
            event: SecurityEvent to evaluate.
            engines: Optional list of specific engine types to use.
                     If None, all enabled engines are used.

        Returns:
            Aggregated list of DetectionMatch from all engines.
        """
        ...

    @abstractmethod
    def register_engine(self, engine: RuleEngine) -> None:
        """Register a rule engine with the orchestrator.

        Args:
            engine: RuleEngine instance to register.
        """
        ...

    @abstractmethod
    def get_engine(self, rule_type: RuleType) -> RuleEngine | None:
        """Retrieve a registered engine by type.

        Args:
            rule_type: Type of engine to retrieve.

        Returns:
            RuleEngine if registered, None otherwise.
        """
        ...

    @abstractmethod
    def reload_rules(self) -> dict[str, int]:
        """Reload rules for all registered engines.

        Returns:
            Dict mapping engine name to count of rules loaded.
        """
        ...


class IoCSources(ABC):
    """Abstract interface for IoC data sources (blocklists, feeds)."""

    @abstractmethod
    def load(self, source_path: str | None = None) -> int:
        """Load indicators from source.

        Args:
            source_path: Path to indicator file or directory.

        Returns:
            Number of indicators loaded.
        """
        ...

    @abstractmethod
    def contains_ip(self, ip: str) -> bool:
        """Check if IP address is in blocklist."""
        ...

    @abstractmethod
    def contains_domain(self, domain: str) -> bool:
        """Check if domain is in blocklist."""
        ...

    @abstractmethod
    def contains_hash(self, file_hash: str) -> bool:
        """Check if file hash is in blocklist."""
        ...

    @abstractmethod
    def contains_url(self, url: str) -> bool:
        """Check if URL matches blocklist patterns."""
        ...

    @abstractmethod
    def get_indicator_context(self, indicator: str) -> dict[str, Any] | None:
        """Get enrichment context for a matched indicator.

        Args:
            indicator: The matched indicator value.

        Returns:
            Dict with threat context (category, source, etc.) or None.
        """
        ...
