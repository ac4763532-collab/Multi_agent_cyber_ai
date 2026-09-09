"""Core exceptions and error handling hierarchy."""

from typing import Any


class CyberAIError(Exception):
    """Base exception for all Multi-Agent Cyber AI errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(CyberAIError):
    """Raised when application configuration is invalid or missing."""


class SecurityBoundaryViolation(CyberAIError):
    """Raised when an operation violates strict security rules (e.g. untrusted IP scan)."""


class IngestionError(CyberAIError):
    """Raised when telemetry ingestion fails or payload is malformed."""


class BrokerError(CyberAIError):
    """Raised when interaction with message broker fails."""


class AgentExecutionError(CyberAIError):
    """Raised when an autonomous agent encounters an unrecoverable failure."""


class DatabaseError(CyberAIError):
    """Raised when database operations encounter errors."""


class ExternalServiceError(CyberAIError):
    """Raised when an upstream threat feed or LLM API call fails."""
