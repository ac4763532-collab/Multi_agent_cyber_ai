"""Task Dispatcher Agent - central coordinator for routing events to specialized agents."""

import uuid
from typing import Any

from backend.app.agents.base import BaseAgent
from backend.app.agents.dispatcher.router import TaskRouter, get_task_router
from backend.app.agents.dispatcher.tracker import TaskTracker, get_task_tracker
from backend.app.agents.exceptions import TaskRoutingError
from backend.app.agents.models import (
    AgentResult,
    AgentTask,
    AgentType,
    BaseFinding,
    ResultStatus,
    TaskPriority,
    TaskStatus,
)
from backend.app.core.broker import KafkaTopic, get_broker_manager
from backend.app.core.logging import get_logger
from backend.app.detection.models import DetectionFinding
from backend.app.ingestion.resilience.retry import retry_async
from backend.app.schemas.events import SecurityEvent
from backend.app.utils.datetime import utc_now

logger = get_logger("cyber_ai.agents.dispatcher")


class TaskDispatcherAgent(BaseAgent):
    """Central coordinator that routes security events to specialized agents.

    Responsibilities:
    1. Receive normalized events from ingestion pipeline
    2. Determine event type and appropriate agent
    3. Validate required fields
    4. Create AgentTask with priority
    5. Publish task to correct queue/topic
    6. Track task status
    7. Handle retries and failures
    """

    def __init__(
        self,
        router: TaskRouter | None = None,
        tracker: TaskTracker | None = None,
        max_retries: int = 3,
    ) -> None:
        """Initialize the task dispatcher.

        Args:
            router: TaskRouter for event routing decisions.
            tracker: TaskTracker for task state management.
            max_retries: Maximum retry attempts for failed dispatches.
        """
        super().__init__()
        self._router = router or get_task_router()
        self._tracker = tracker or get_task_tracker()
        self._max_retries = max_retries

        # Dispatcher-specific metrics
        self._events_dispatched = 0
        self._routing_failures = 0

    @property
    def agent_id(self) -> str:
        return "task_dispatcher_001"

    @property
    def name(self) -> str:
        return "Task Dispatcher"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.TASK_DISPATCHER

    @property
    def capabilities(self) -> list[str]:
        return [
            "event_routing",
            "task_creation",
            "priority_assignment",
            "status_tracking",
            "retry_management",
        ]

    @property
    def description(self) -> str:
        return "Central coordinator that routes security events to specialized analysis agents"

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate that task has required payload for dispatching.

        Args:
            task: AgentTask to validate.

        Returns:
            True if valid, False otherwise.
        """
        # Dispatcher receives events to dispatch, not tasks to process
        payload = task.payload or {}

        # Must have either a security event or detection finding
        has_event = "event" in payload or "event_id" in payload
        has_finding = "finding" in payload or "finding_id" in payload

        if not (has_event or has_finding):
            logger.warning("Task %s missing event or finding in payload", task.task_id)
            return False

        return True

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process a dispatch request - route event to appropriate agent.

        Args:
            task: AgentTask containing event/finding to dispatch.

        Returns:
            AgentResult with dispatch outcome.
        """
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract event from payload
            event_data = payload.get("event")
            if event_data:
                event = SecurityEvent(**event_data) if isinstance(event_data, dict) else event_data
                target_agent = self._router.route(event)
                priority = self._router.get_priority(event)
                event_id = event.event_id
            else:
                # Handle detection finding
                finding_data = payload.get("finding", {})
                event_id = finding_data.get("event_id", task.event_id)
                target_agent = self._determine_agent_for_finding(finding_data)
                priority = TaskPriority.HIGH  # Findings are pre-prioritized

            # Create task for target agent
            agent_task = await self.dispatch_to_agent(
                event_id=event_id,
                agent_type=target_agent,
                priority=priority,
                payload=payload,
            )

            self._events_dispatched += 1

            # Create finding for successful dispatch
            finding = self.create_finding(
                task=task,
                analysis={
                    "dispatched_to": target_agent.value,
                    "dispatched_task_id": agent_task.task_id,
                    "priority": priority.value,
                },
            )

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.SUCCESS,
                finding=finding,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                metadata={
                    "dispatched_to": target_agent.value,
                    "dispatched_task_id": agent_task.task_id,
                },
            )

        except TaskRoutingError as e:
            self._routing_failures += 1
            logger.warning("Routing failed for task %s: %s", task.task_id, e)

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.FAILED,
                finding=None,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                errors=[str(e)],
            )

    def create_finding(
        self,
        task: AgentTask,
        analysis: dict[str, Any],
    ) -> BaseFinding:
        """Create a dispatch finding.

        Args:
            task: The processed task.
            analysis: Dispatch analysis results.

        Returns:
            BaseFinding with dispatch details.
        """
        return BaseFinding(
            finding_id=f"dispatch_{uuid.uuid4().hex}",
            finding_type="task_dispatch",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            explanation=f"Event dispatched to {analysis.get('dispatched_to', 'unknown')} agent",
            metadata=analysis,
        )

    def _determine_agent_for_finding(self, finding_data: dict[str, Any]) -> AgentType:
        """Determine target agent for a detection finding.

        Args:
            finding_data: Detection finding data.

        Returns:
            Target AgentType.
        """
        finding_type = finding_data.get("finding_type", "")

        # Map finding types to agents
        type_mapping = {
            "sql_injection": AgentType.LOG_ANALYZER,
            "xss": AgentType.LOG_ANALYZER,
            "brute_force": AgentType.LOG_ANALYZER,
            "malicious_ip": AgentType.THREAT_INTELLIGENCE,
            "malicious_domain": AgentType.THREAT_INTELLIGENCE,
            "malicious_hash": AgentType.THREAT_INTELLIGENCE,
            "ioc_match": AgentType.THREAT_INTELLIGENCE,
            "network_alert": AgentType.NETWORK_THREAT,
            "ids_alert": AgentType.NETWORK_THREAT,
            "vulnerability": AgentType.VULNERABILITY,
            "phishing": AgentType.EMAIL_VERIFICATION,
            "email": AgentType.EMAIL_VERIFICATION,
        }

        for key, agent in type_mapping.items():
            if key in finding_type.lower():
                return agent

        # Default to correlation for multi-indicator findings
        if finding_data.get("match_count", 0) > 1:
            return AgentType.CORRELATION

        return AgentType.LOG_ANALYZER

    async def dispatch_to_agent(
        self,
        event_id: str,
        agent_type: AgentType,
        priority: TaskPriority,
        payload: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> AgentTask:
        """Create and dispatch a task to a specific agent.

        Args:
            event_id: Source event ID.
            agent_type: Target agent type.
            priority: Task priority.
            payload: Task payload data.
            metadata: Optional metadata.

        Returns:
            Created AgentTask.
        """
        task = AgentTask(
            task_id=f"task_{uuid.uuid4().hex}",
            event_id=event_id,
            agent_type=agent_type,
            priority=priority,
            status=TaskStatus.QUEUED,
            max_retries=self._max_retries,
            payload=payload,
            metadata=metadata or {},
        )

        # Track task
        await self._tracker.create_task(
            event_id=task.event_id,
            agent_type=task.agent_type,
            priority=task.priority,
            max_retries=task.max_retries,
            payload=task.payload,
            metadata=task.metadata,
        )

        # Publish to broker
        await self._publish_task(task)

        logger.info(
            "Dispatched task %s to %s (priority=%s)",
            task.task_id,
            agent_type.value,
            priority.value,
        )

        return task

    async def _publish_task(self, task: AgentTask) -> None:
        """Publish task to agent tasks topic with retry.

        Args:
            task: AgentTask to publish.
        """

        async def _do_publish() -> None:
            broker = get_broker_manager()
            await broker.publish_event(
                topic=KafkaTopic.AGENT_TASKS,
                payload=task.model_dump(mode="json"),
                key=task.task_id,
                headers={
                    "agent_type": task.agent_type.value,
                    "priority": task.priority.value,
                    "event_id": task.event_id,
                },
            )

        try:
            await retry_async(_do_publish, max_retries=3, initial_delay=0.1)
        except Exception as e:
            logger.error("Failed to publish task %s: %s", task.task_id, e)
            # Task is still tracked locally even if publish fails
            raise

    async def dispatch_event(self, event: SecurityEvent) -> AgentTask:
        """Convenience method to dispatch a SecurityEvent directly.

        Args:
            event: SecurityEvent to dispatch.

        Returns:
            Created AgentTask.
        """
        target_agent = self._router.route(event)
        priority = self._router.get_priority(event)

        return await self.dispatch_to_agent(
            event_id=event.event_id,
            agent_type=target_agent,
            priority=priority,
            payload={"event": event.model_dump(mode="json")},
            metadata={"source": event.source, "source_type": event.source_type},
        )

    async def dispatch_finding(self, finding: DetectionFinding) -> AgentTask:
        """Convenience method to dispatch a DetectionFinding directly.

        Args:
            finding: DetectionFinding to dispatch.

        Returns:
            Created AgentTask.
        """
        target_agent = self._determine_agent_for_finding(finding.model_dump())

        return await self.dispatch_to_agent(
            event_id=finding.event_id,
            agent_type=target_agent,
            priority=TaskPriority.from_severity(finding.severity),
            payload={"finding": finding.model_dump(mode="json")},
            metadata={"finding_type": finding.finding_type},
        )

    async def handle_task_failure(
        self,
        task_id: str,
        error: str,
    ) -> AgentTask | None:
        """Handle a failed task - retry or dead-letter.

        Args:
            task_id: ID of failed task.
            error: Error message.

        Returns:
            Updated AgentTask or None.
        """
        task = await self._tracker.get_task(task_id)
        if not task:
            logger.warning("Task %s not found for failure handling", task_id)
            return None

        if task.can_retry():
            # Mark for retry
            task = await self._tracker.mark_retry(task_id)
            if task:
                logger.info(
                    "Task %s marked for retry (attempt %d/%d)",
                    task_id,
                    task.retry_count,
                    task.max_retries,
                )
                # Re-publish for retry
                await self._publish_task(task)
            return task
        else:
            # Move to dead letter
            task = await self._tracker.mark_dead_letter(task_id, error)
            if task:
                logger.warning(
                    "Task %s moved to dead letter after %d retries: %s",
                    task_id,
                    task.retry_count,
                    error,
                )
            return task

    def get_stats(self) -> dict[str, Any]:
        """Get dispatcher statistics.

        Returns:
            Dict with dispatcher metrics.
        """
        base_stats = super().get_stats()
        base_stats.update(
            {
                "events_dispatched": self._events_dispatched,
                "routing_failures": self._routing_failures,
                "routing_rules_count": len(self._router.list_rules()),
            }
        )
        return base_stats


# Singleton instance
_dispatcher: TaskDispatcherAgent | None = None


def get_task_dispatcher() -> TaskDispatcherAgent:
    """Return singleton TaskDispatcherAgent instance."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = TaskDispatcherAgent()
    return _dispatcher
