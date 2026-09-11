"""Agent-specific exceptions for the multi-agent framework."""

from typing import Any

from backend.app.core.exceptions import CyberAIError


class AgentError(CyberAIError):
    """Base exception for all agent-related errors."""

    def __init__(
        self,
        message: str,
        agent_id: str | None = None,
        agent_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details)
        self.agent_id = agent_id
        self.agent_type = agent_type


class AgentValidationError(AgentError):
    """Raised when task validation fails for an agent."""

    def __init__(
        self,
        message: str,
        agent_id: str | None = None,
        task_id: str | None = None,
        validation_errors: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, agent_id=agent_id, details=details)
        self.task_id = task_id
        self.validation_errors = validation_errors or []


class AgentTimeoutError(AgentError):
    """Raised when agent processing exceeds timeout threshold."""

    def __init__(
        self,
        message: str,
        agent_id: str | None = None,
        task_id: str | None = None,
        timeout_sec: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, agent_id=agent_id, details=details)
        self.task_id = task_id
        self.timeout_sec = timeout_sec


class AgentNotFoundError(AgentError):
    """Raised when a requested agent is not registered."""

    def __init__(
        self,
        message: str,
        agent_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, agent_type=agent_type, details=details)


class TaskRoutingError(AgentError):
    """Raised when event cannot be routed to an appropriate agent."""

    def __init__(
        self,
        message: str,
        event_id: str | None = None,
        event_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.event_id = event_id
        self.event_type = event_type


class TaskExecutionError(AgentError):
    """Raised when task execution fails."""

    def __init__(
        self,
        message: str,
        agent_id: str | None = None,
        task_id: str | None = None,
        original_error: Exception | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, agent_id=agent_id, details=details)
        self.task_id = task_id
        self.original_error = original_error


class TaskDeadLetterError(AgentError):
    """Raised when a task is moved to dead-letter queue after max retries."""

    def __init__(
        self,
        message: str,
        task_id: str | None = None,
        retry_count: int = 0,
        last_error: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.task_id = task_id
        self.retry_count = retry_count
        self.last_error = last_error


class AgentRegistrationError(AgentError):
    """Raised when agent registration fails."""

    def __init__(
        self,
        message: str,
        agent_id: str | None = None,
        agent_type: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, agent_id=agent_id, agent_type=agent_type, details=details)
