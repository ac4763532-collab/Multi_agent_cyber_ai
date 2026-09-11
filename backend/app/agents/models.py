"""Pydantic models and enums for the multi-agent framework."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.detection.models import MatchConfidence
from backend.app.schemas.events import EventSeverity
from backend.app.utils.datetime import utc_now


class TaskStatus(StrEnum):
    """Lifecycle states for agent tasks."""

    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"


class TaskPriority(StrEnum):
    """Priority levels for task scheduling."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_severity(cls, severity: EventSeverity) -> "TaskPriority":
        """Map EventSeverity to TaskPriority."""
        mapping = {
            EventSeverity.CRITICAL: cls.CRITICAL,
            EventSeverity.HIGH: cls.HIGH,
            EventSeverity.MEDIUM: cls.MEDIUM,
            EventSeverity.LOW: cls.LOW,
            EventSeverity.INFORMATIONAL: cls.LOW,
        }
        return mapping.get(severity, cls.MEDIUM)


class AgentType(StrEnum):
    """Enumeration of all 12 specialized security agents."""

    TASK_DISPATCHER = "task_dispatcher"
    EMAIL_VERIFICATION = "email_verification"
    LOG_ANALYZER = "log_analyzer"
    NETWORK_THREAT = "network_threat"
    IP_RANGE_ANALYZER = "ip_range_analyzer"
    VULNERABILITY = "vulnerability"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CORRELATION = "correlation"
    INVESTIGATION = "investigation"
    INCIDENT_PRIORITIZATION = "incident_prioritization"
    RESPONSE_RECOMMENDATION = "response_recommendation"
    REPORT_GENERATION = "report_generation"


class AgentStatus(StrEnum):
    """Runtime status of an agent instance."""

    IDLE = "idle"
    PROCESSING = "processing"
    ERROR = "error"
    STOPPED = "stopped"


class ResultStatus(StrEnum):
    """Outcome status for agent processing results."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ExecutionStatus(StrEnum):
    """Status of an execution record."""

    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class AgentTask(BaseModel):
    """Task dispatched to a specialized agent for processing.

    Represents a unit of work derived from a SecurityEvent or DetectionFinding
    that requires agent analysis.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Task identification
    task_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique task identifier",
    )
    event_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Source event that triggered this task",
    )

    # Routing
    agent_type: AgentType = Field(
        ...,
        description="Target agent type for processing",
    )
    priority: TaskPriority = Field(
        default=TaskPriority.MEDIUM,
        description="Task priority for scheduling",
    )

    # Lifecycle timestamps
    created_at: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when task was created",
    )
    started_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when processing started",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when processing completed",
    )

    # Status tracking
    status: TaskStatus = Field(
        default=TaskStatus.QUEUED,
        description="Current task lifecycle state",
    )
    retry_count: int = Field(
        default=0,
        ge=0,
        description="Number of retry attempts",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        description="Maximum allowed retry attempts",
    )
    error: str | None = Field(
        default=None,
        max_length=2048,
        description="Error message if task failed",
    )

    # Payload and context
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Task payload data (event, finding, etc.)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional task metadata",
    )

    def mark_started(self) -> None:
        """Mark task as started."""
        self.status = TaskStatus.RUNNING
        self.started_at = utc_now()

    def mark_completed(self) -> None:
        """Mark task as successfully completed."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = utc_now()

    def mark_failed(self, error: str) -> None:
        """Mark task as failed with error message."""
        self.status = TaskStatus.FAILED
        self.error = error
        self.completed_at = utc_now()

    def can_retry(self) -> bool:
        """Check if task can be retried."""
        return self.retry_count < self.max_retries

    def mark_retry(self) -> None:
        """Mark task for retry."""
        self.retry_count += 1
        self.status = TaskStatus.RETRYING
        self.error = None


class BaseFinding(BaseModel):
    """Base model for all agent-generated findings.

    Specialized agents extend this with domain-specific fields.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",  # Allow subclasses to add fields
        str_strip_whitespace=True,
    )

    # Finding identification
    finding_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique finding identifier",
    )
    finding_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Type/category of finding",
    )

    # Source references
    event_id: str = Field(
        ...,
        description="Source event ID",
    )
    task_id: str = Field(
        ...,
        description="Task that produced this finding",
    )
    agent_id: str = Field(
        ...,
        description="Agent that generated this finding",
    )

    # Classification
    severity: EventSeverity = Field(
        default=EventSeverity.MEDIUM,
        description="Severity classification",
    )
    confidence: MatchConfidence = Field(
        default=MatchConfidence.MEDIUM,
        description="Confidence level of the finding",
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when finding was created",
    )

    # Evidence and explanation
    evidence: list[str] = Field(
        default_factory=list,
        description="List of evidence IDs supporting this finding",
    )
    explanation: str = Field(
        default="",
        max_length=4096,
        description="Human-readable explanation of the finding",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Recommended actions",
    )

    # MITRE ATT&CK mapping
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic names",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional finding metadata",
    )


class AgentResult(BaseModel):
    """Result produced by an agent after processing a task.

    Contains the finding (if any), timing, and status information.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Result identification
    result_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique result identifier",
    )
    task_id: str = Field(
        ...,
        description="Task that was processed",
    )

    # Agent information
    agent_id: str = Field(
        ...,
        description="Agent that produced this result",
    )
    agent_type: AgentType = Field(
        ...,
        description="Type of agent",
    )
    agent_version: str = Field(
        default="1.0.0",
        max_length=32,
        description="Agent version string",
    )

    # Outcome
    status: ResultStatus = Field(
        ...,
        description="Processing outcome status",
    )
    finding: BaseFinding | None = Field(
        default=None,
        description="Generated finding, if any",
    )

    # Timing
    start_time: datetime = Field(
        ...,
        description="Processing start timestamp",
    )
    end_time: datetime = Field(
        ...,
        description="Processing end timestamp",
    )
    processing_time_ms: float = Field(
        ...,
        ge=0,
        description="Processing duration in milliseconds",
    )

    # Errors
    errors: list[str] = Field(
        default_factory=list,
        description="Error messages if any",
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional result metadata",
    )


class ExecutionRecord(BaseModel):
    """Audit record of an agent execution.

    Tracks agent invocations for observability and debugging.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Execution identification
    execution_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique execution identifier",
    )

    # Agent information
    agent_id: str = Field(
        ...,
        description="Agent that was executed",
    )
    agent_type: AgentType = Field(
        ...,
        description="Type of agent",
    )
    agent_version: str = Field(
        default="1.0.0",
        max_length=32,
        description="Agent version at execution time",
    )

    # Task reference
    task_id: str = Field(
        ...,
        description="Task that was processed",
    )

    # Timing
    start_time: datetime = Field(
        ...,
        description="Execution start timestamp",
    )
    end_time: datetime | None = Field(
        default=None,
        description="Execution end timestamp",
    )

    # Status
    status: ExecutionStatus = Field(
        default=ExecutionStatus.STARTED,
        description="Execution status",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered during execution",
    )

    # Result reference
    result_id: str | None = Field(
        default=None,
        description="ID of generated result, if any",
    )

    def complete(self, result_id: str | None = None) -> None:
        """Mark execution as completed."""
        self.status = ExecutionStatus.COMPLETED
        self.end_time = utc_now()
        self.result_id = result_id

    def fail(self, error: str) -> None:
        """Mark execution as failed."""
        self.status = ExecutionStatus.FAILED
        self.end_time = utc_now()
        self.errors.append(error)
