"""Abstract base class for all autonomous security agents."""

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

from backend.app.agents.exceptions import AgentValidationError
from backend.app.agents.models import (
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentType,
    BaseFinding,
    ExecutionRecord,
    ExecutionStatus,
    ResultStatus,
    TaskStatus,
)
from backend.app.core.broker import KafkaTopic, get_broker_manager
from backend.app.core.logging import get_logger
from backend.app.utils.datetime import utc_now

logger = get_logger("cyber_ai.agents.base")


class BaseAgent(ABC):
    """Abstract base class for all autonomous security agents.

    Provides consistent lifecycle management, error handling, and result
    publishing for all 12 specialized agents in the SOC platform.

    Subclasses must implement:
    - agent_id: Unique identifier
    - name: Human-readable name
    - agent_type: AgentType enum value
    - capabilities: List of capabilities
    - validate_task: Task validation logic
    - process_task: Core processing logic
    - create_finding: Finding generation logic
    """

    def __init__(self) -> None:
        """Initialize base agent state."""
        self._status: AgentStatus = AgentStatus.IDLE
        self._tasks_processed: int = 0
        self._tasks_failed: int = 0
        self._total_processing_time_ms: float = 0.0

    # -------------------------------------------------------------------------
    # Abstract Properties (must be implemented by subclasses)
    # -------------------------------------------------------------------------

    @property
    @abstractmethod
    def agent_id(self) -> str:
        """Unique identifier for this agent instance."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this agent."""
        ...

    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """Type classification of this agent."""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> list[str]:
        """List of capabilities this agent provides."""
        ...

    # -------------------------------------------------------------------------
    # Optional Properties (can be overridden)
    # -------------------------------------------------------------------------

    @property
    def version(self) -> str:
        """Version string for this agent implementation."""
        return "1.0.0"

    @property
    def description(self) -> str:
        """Description of what this agent does."""
        return f"{self.name} agent"

    @property
    def status(self) -> AgentStatus:
        """Current runtime status of the agent."""
        return self._status

    @property
    def tasks_processed(self) -> int:
        """Total number of tasks processed."""
        return self._tasks_processed

    @property
    def tasks_failed(self) -> int:
        """Total number of tasks that failed."""
        return self._tasks_failed

    @property
    def avg_processing_time_ms(self) -> float:
        """Average processing time in milliseconds."""
        if self._tasks_processed == 0:
            return 0.0
        return self._total_processing_time_ms / self._tasks_processed

    # -------------------------------------------------------------------------
    # Abstract Methods (must be implemented by subclasses)
    # -------------------------------------------------------------------------

    @abstractmethod
    async def validate_task(self, task: AgentTask) -> bool:
        """Validate that a task can be processed by this agent.

        Args:
            task: AgentTask to validate.

        Returns:
            True if task is valid, False otherwise.

        Raises:
            AgentValidationError: If validation fails with specific errors.
        """
        ...

    @abstractmethod
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process a task and produce a result.

        This is the core processing logic that subclasses must implement.

        Args:
            task: Validated AgentTask to process.

        Returns:
            AgentResult containing the processing outcome.

        Raises:
            TaskExecutionError: If processing fails.
        """
        ...

    @abstractmethod
    def create_finding(
        self,
        task: AgentTask,
        analysis: dict[str, Any],
    ) -> BaseFinding:
        """Create a finding from analysis results.

        Args:
            task: The processed task.
            analysis: Analysis results from processing.

        Returns:
            BaseFinding or subclass with finding details.
        """
        ...

    # -------------------------------------------------------------------------
    # Concrete Methods (shared implementation)
    # -------------------------------------------------------------------------

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute the full agent workflow for a task.

        Orchestrates validation, processing, error handling, and result
        publishing. This is the main entry point for task execution.

        Args:
            task: AgentTask to execute.

        Returns:
            AgentResult with processing outcome.
        """
        start_time = utc_now()
        start_perf = time.perf_counter()
        execution_id = f"exec_{uuid.uuid4().hex}"

        # Create execution record
        execution = ExecutionRecord(
            execution_id=execution_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            agent_version=self.version,
            task_id=task.task_id,
            start_time=start_time,
            status=ExecutionStatus.STARTED,
        )

        self._status = AgentStatus.PROCESSING
        task.mark_started()

        try:
            # Validate task
            task.status = TaskStatus.VALIDATING
            is_valid = await self.validate_task(task)

            if not is_valid:
                raise AgentValidationError(
                    message=f"Task validation failed for {task.task_id}",
                    agent_id=self.agent_id,
                    task_id=task.task_id,
                )

            # Process task
            task.status = TaskStatus.RUNNING
            result = await self.process_task(task)

            # Update metrics
            elapsed_ms = (time.perf_counter() - start_perf) * 1000
            self._tasks_processed += 1
            self._total_processing_time_ms += elapsed_ms

            # Complete execution
            execution.complete(result_id=result.result_id)
            task.mark_completed()

            logger.info(
                "Agent %s completed task %s in %.2fms",
                self.agent_id,
                task.task_id,
                elapsed_ms,
            )

            # Publish result
            await self.publish_result(result)

            return result

        except AgentValidationError as e:
            return await self._handle_validation_error(task, e, execution, start_perf)

        except Exception as e:
            return await self._handle_execution_error(task, e, execution, start_perf)

        finally:
            self._status = AgentStatus.IDLE

    async def _handle_validation_error(
        self,
        task: AgentTask,
        error: AgentValidationError,
        execution: ExecutionRecord,
        start_perf: float,
    ) -> AgentResult:
        """Handle validation errors."""
        elapsed_ms = (time.perf_counter() - start_perf) * 1000
        self._tasks_failed += 1

        logger.warning(
            "Validation failed for task %s: %s",
            task.task_id,
            str(error),
        )

        execution.fail(str(error))
        task.mark_failed(str(error))

        return AgentResult(
            result_id=f"result_{uuid.uuid4().hex}",
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            agent_version=self.version,
            status=ResultStatus.FAILED,
            finding=None,
            start_time=execution.start_time,
            end_time=utc_now(),
            processing_time_ms=elapsed_ms,
            errors=[str(error)],
        )

    async def _handle_execution_error(
        self,
        task: AgentTask,
        error: Exception,
        execution: ExecutionRecord,
        start_perf: float,
    ) -> AgentResult:
        """Handle execution errors with optional retry."""
        elapsed_ms = (time.perf_counter() - start_perf) * 1000
        self._tasks_failed += 1

        logger.error(
            "Agent %s failed to process task %s: %s",
            self.agent_id,
            task.task_id,
            str(error),
            exc_info=True,
        )

        # Call error handler hook
        await self.handle_error(task, error)

        execution.fail(str(error))
        task.mark_failed(str(error))

        return AgentResult(
            result_id=f"result_{uuid.uuid4().hex}",
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            agent_version=self.version,
            status=ResultStatus.FAILED,
            finding=None,
            start_time=execution.start_time,
            end_time=utc_now(),
            processing_time_ms=elapsed_ms,
            errors=[str(error)],
        )

    async def handle_error(self, task: AgentTask, error: Exception) -> None:  # noqa: B027
        """Hook for custom error handling logic.

        Subclasses can override to implement agent-specific error handling,
        such as alerting, custom logging, or cleanup.

        Args:
            task: The task that failed.
            error: The exception that occurred.
        """
        # Default implementation does nothing - subclasses may override
        pass

    async def publish_result(self, result: AgentResult) -> None:
        """Publish agent result to the results topic.

        Args:
            result: AgentResult to publish.
        """
        try:
            broker = get_broker_manager()
            await broker.publish_event(
                topic=KafkaTopic.AGENT_RESULTS,
                payload=result.model_dump(mode="json"),
                key=result.task_id,
                headers={
                    "agent_id": self.agent_id,
                    "agent_type": self.agent_type.value,
                    "status": result.status.value,
                },
            )
            logger.debug(
                "Published result %s for task %s",
                result.result_id,
                result.task_id,
            )
        except Exception as e:
            # Log but don't fail - result is already computed
            logger.warning(
                "Failed to publish result %s: %s (result computed successfully)",
                result.result_id,
                str(e),
            )

    def get_stats(self) -> dict[str, Any]:
        """Get agent runtime statistics.

        Returns:
            Dict with agent metrics.
        """
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "version": self.version,
            "status": self.status.value,
            "tasks_processed": self._tasks_processed,
            "tasks_failed": self._tasks_failed,
            "success_rate": (
                (self._tasks_processed - self._tasks_failed) / self._tasks_processed
                if self._tasks_processed > 0
                else 0.0
            ),
            "avg_processing_time_ms": round(self.avg_processing_time_ms, 2),
        }

    def __repr__(self) -> str:
        """String representation."""
        return f"<{self.__class__.__name__} id={self.agent_id} status={self.status.value}>"
