"""Detection engine specific exceptions."""

from typing import Any

from backend.app.core.exceptions import CyberAIError


class DetectionError(CyberAIError):
    """Base exception for all detection engine errors."""


class RuleLoadError(DetectionError):
    """Raised when a detection rule fails to load or parse."""

    def __init__(
        self,
        message: str,
        rule_path: str | None = None,
        rule_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.rule_path = rule_path
        self.rule_id = rule_id


class RuleCompilationError(DetectionError):
    """Raised when a rule fails to compile (e.g., invalid regex, Sigma syntax)."""

    def __init__(
        self,
        message: str,
        rule_id: str | None = None,
        rule_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.rule_id = rule_id
        self.rule_type = rule_type


class RuleEvaluationError(DetectionError):
    """Raised when rule evaluation fails unexpectedly."""

    def __init__(
        self,
        message: str,
        rule_id: str | None = None,
        event_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.rule_id = rule_id
        self.event_id = event_id


class InvalidRuleDefinition(DetectionError):
    """Raised when a rule definition is malformed or missing required fields."""

    def __init__(
        self,
        message: str,
        rule_id: str | None = None,
        missing_fields: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.rule_id = rule_id
        self.missing_fields = missing_fields or []


class IoCSouceLoadError(DetectionError):
    """Raised when IoC source files fail to load."""

    def __init__(
        self,
        message: str,
        source_path: str | None = None,
        ioc_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.source_path = source_path
        self.ioc_type = ioc_type


class DetectionTimeoutError(DetectionError):
    """Raised when detection processing exceeds the configured timeout."""

    def __init__(
        self,
        message: str,
        timeout_ms: float | None = None,
        actual_ms: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.timeout_ms = timeout_ms
        self.actual_ms = actual_ms


class EngineNotFoundError(DetectionError):
    """Raised when a requested detection engine is not registered."""

    def __init__(
        self,
        message: str,
        engine_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.engine_type = engine_type
