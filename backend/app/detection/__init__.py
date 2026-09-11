"""Multi-layer threat detection engine package.

Layer 1 (Deterministic): Sigma rules, Regex patterns, IoC matching
- Target latency: < 5ms
- Confidence: High (definitive matches)

Public API:
    - DetectionEngine: Main orchestrator
    - evaluate_event(): Async event evaluation
    - evaluate_event_to_finding(): Evaluation with finding generation
    - get_detection_engine(): Singleton access
    - get_detection_registry(): Registry access
"""

from backend.app.detection.engine import (
    DetectionEngine,
    evaluate_event,
    evaluate_event_to_finding,
    get_detection_engine,
)
from backend.app.detection.exceptions import (
    DetectionError,
    DetectionTimeoutError,
    EngineNotFoundError,
    InvalidRuleDefinition,
    IoCSouceLoadError,
    RuleCompilationError,
    RuleEvaluationError,
    RuleLoadError,
)
from backend.app.detection.interfaces import (
    DetectionEngineInterface,
    DetectionLayer,
    DetectionRule,
    IoCSources,
    RuleEngine,
    RuleType,
)
from backend.app.detection.models import (
    DetectionFinding,
    DetectionMatch,
    DetectionStats,
    MatchConfidence,
    RuleDefinition,
)
from backend.app.detection.registry import (
    DetectionRegistry,
    get_detection_registry,
    initialize_detection_registry,
)

__all__ = [
    # Engine
    "DetectionEngine",
    "evaluate_event",
    "evaluate_event_to_finding",
    "get_detection_engine",
    # Registry
    "DetectionRegistry",
    "get_detection_registry",
    "initialize_detection_registry",
    # Interfaces
    "DetectionEngineInterface",
    "DetectionRule",
    "RuleEngine",
    "IoCSources",
    "RuleType",
    "DetectionLayer",
    # Models
    "DetectionMatch",
    "DetectionFinding",
    "DetectionStats",
    "MatchConfidence",
    "RuleDefinition",
    # Exceptions
    "DetectionError",
    "RuleLoadError",
    "RuleCompilationError",
    "RuleEvaluationError",
    "InvalidRuleDefinition",
    "IoCSouceLoadError",
    "DetectionTimeoutError",
    "EngineNotFoundError",
]
