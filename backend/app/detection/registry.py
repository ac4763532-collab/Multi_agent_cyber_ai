"""Detection registry for managing rule engines and configurations."""

from typing import Any

from backend.app.core.logging import get_logger
from backend.app.detection.interfaces import DetectionLayer, RuleEngine, RuleType
from backend.app.detection.models import DetectionStats
from backend.app.detection.rules.ioc_engine import IoCEngine
from backend.app.detection.rules.regex_engine import RegexEngine
from backend.app.detection.rules.sigma_engine import SigmaEngine

logger = get_logger("cyber_ai.detection.registry")


class DetectionRegistry:
    """Central registry for detection rule engines.

    Manages engine lifecycle, rule loading, and provides unified access
    to all Layer 1 detection capabilities.
    """

    def __init__(self) -> None:
        self._engines: dict[RuleType, RuleEngine] = {}
        self._stats = DetectionStats()
        self._initialized = False

    def initialize(
        self,
        sigma_rules_path: str | None = None,
        ioc_path: str | None = None,
        load_builtin_regex: bool = True,
    ) -> None:
        """Initialize all detection engines with rule loading.

        Args:
            sigma_rules_path: Path to Sigma YAML rules directory
            ioc_path: Path to IoC blocklist files directory
            load_builtin_regex: Whether to load built-in regex patterns
        """
        # Initialize Sigma engine
        sigma_engine = SigmaEngine()
        sigma_rules_loaded = sigma_engine.load_rules(sigma_rules_path)
        self._engines[RuleType.SIGMA] = sigma_engine
        self._stats.sigma_rules = sigma_rules_loaded

        # Initialize Regex engine
        regex_engine = RegexEngine(load_builtin=load_builtin_regex)
        self._engines[RuleType.REGEX] = regex_engine
        self._stats.regex_rules = regex_engine.rule_count

        # Initialize IoC engine
        ioc_engine = IoCEngine()
        ioc_engine.load_rules(ioc_path)
        self._engines[RuleType.IOC] = ioc_engine
        self._stats.ioc_rules = ioc_engine.rule_count

        # Update total count
        self._stats.total_rules = (
            self._stats.sigma_rules + self._stats.regex_rules + self._stats.ioc_rules
        )

        self._initialized = True
        logger.info(
            "Detection registry initialized: %d Sigma, %d Regex, %d IoC rules",
            self._stats.sigma_rules,
            self._stats.regex_rules,
            self._stats.ioc_rules,
        )

    @property
    def is_initialized(self) -> bool:
        """Check if registry has been initialized."""
        return self._initialized

    def register_engine(self, engine: RuleEngine) -> None:
        """Register a rule engine.

        Args:
            engine: RuleEngine instance to register
        """
        self._engines[engine.rule_type] = engine
        logger.info("Registered engine: %s (%s)", engine.engine_name, engine.rule_type)

    def get_engine(self, rule_type: RuleType) -> RuleEngine | None:
        """Get a registered engine by type.

        Args:
            rule_type: Type of engine to retrieve

        Returns:
            RuleEngine if registered, None otherwise
        """
        return self._engines.get(rule_type)

    def get_sigma_engine(self) -> SigmaEngine | None:
        """Get the Sigma rule engine."""
        engine = self._engines.get(RuleType.SIGMA)
        return engine if isinstance(engine, SigmaEngine) else None

    def get_regex_engine(self) -> RegexEngine | None:
        """Get the Regex pattern engine."""
        engine = self._engines.get(RuleType.REGEX)
        return engine if isinstance(engine, RegexEngine) else None

    def get_ioc_engine(self) -> IoCEngine | None:
        """Get the IoC matching engine."""
        engine = self._engines.get(RuleType.IOC)
        return engine if isinstance(engine, IoCEngine) else None

    def list_engines(self) -> list[RuleEngine]:
        """List all registered engines."""
        return list(self._engines.values())

    def get_layer_engines(self, layer: DetectionLayer) -> list[RuleEngine]:
        """Get all engines for a specific detection layer."""
        return [e for e in self._engines.values() if e.detection_layer == layer]

    def reload_rules(self) -> dict[str, int]:
        """Reload rules for all engines.

        Returns:
            Dict mapping engine name to count of rules loaded
        """
        results: dict[str, int] = {}

        for engine in self._engines.values():
            try:
                count = engine.load_rules()
                results[engine.engine_name] = count
            except Exception as e:
                logger.error("Failed to reload rules for %s: %s", engine.engine_name, e)
                results[engine.engine_name] = 0

        # Update stats
        sigma = self.get_sigma_engine()
        regex = self.get_regex_engine()
        ioc = self.get_ioc_engine()

        self._stats.sigma_rules = sigma.rule_count if sigma else 0
        self._stats.regex_rules = regex.rule_count if regex else 0
        self._stats.ioc_rules = ioc.rule_count if ioc else 0
        self._stats.total_rules = (
            self._stats.sigma_rules + self._stats.regex_rules + self._stats.ioc_rules
        )

        return results

    def get_stats(self) -> DetectionStats:
        """Get current detection statistics."""
        return self._stats

    def update_stats(self, **kwargs: Any) -> None:
        """Update detection statistics."""
        for key, value in kwargs.items():
            if hasattr(self._stats, key):
                setattr(self._stats, key, value)

    def get_all_rules_info(self) -> list[dict[str, Any]]:
        """Get summary information for all loaded rules."""
        rules_info: list[dict[str, Any]] = []

        for engine in self._engines.values():
            for rule in engine.list_rules():
                rules_info.append(
                    {
                        "rule_id": rule.rule_id,
                        "rule_name": rule.rule_name,
                        "rule_type": rule.rule_type.value,
                        "severity": rule.severity.value,
                        "enabled": rule.enabled,
                        "mitre_techniques": rule.mitre_techniques,
                        "tags": rule.tags,
                        "engine": engine.engine_name,
                    }
                )

        return rules_info


# Singleton instance
_detection_registry: DetectionRegistry | None = None


def get_detection_registry() -> DetectionRegistry:
    """Get the singleton detection registry instance.

    Returns:
        Initialized DetectionRegistry
    """
    global _detection_registry
    if _detection_registry is None:
        _detection_registry = DetectionRegistry()
    return _detection_registry


def initialize_detection_registry(
    sigma_rules_path: str | None = None,
    ioc_path: str | None = None,
    load_builtin_regex: bool = True,
) -> DetectionRegistry:
    """Initialize the global detection registry.

    Args:
        sigma_rules_path: Path to Sigma rules
        ioc_path: Path to IoC blocklists
        load_builtin_regex: Load built-in regex patterns

    Returns:
        Initialized DetectionRegistry
    """
    registry = get_detection_registry()
    if not registry.is_initialized:
        registry.initialize(
            sigma_rules_path=sigma_rules_path,
            ioc_path=ioc_path,
            load_builtin_regex=load_builtin_regex,
        )
    return registry
