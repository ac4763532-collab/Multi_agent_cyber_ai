"""Unit tests for TaskDispatcher and routing."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app.agents.dispatcher.router import TaskRouter, get_task_router
from backend.app.agents.dispatcher.tracker import TaskTracker, get_task_tracker
from backend.app.agents.dispatcher.dispatcher import TaskDispatcherAgent
from backend.app.agents.models import AgentTask, AgentType, TaskStatus, TaskPriority
from backend.app.agents.exceptions import TaskRoutingError
from backend.app.schemas.events import SecurityEvent, EventSeverity


def _make_event(
    event_id: str = "evt_001",
    source_type: str = "test",
    event_type: str = "test_event",
    severity: EventSeverity = EventSeverity.MEDIUM,
    **kwargs,
) -> SecurityEvent:
    """Helper to create SecurityEvent for tests."""
    return SecurityEvent(
        event_id=event_id,
        timestamp=kwargs.get("timestamp", datetime.now(timezone.utc)),
        source=kwargs.get("source", "test_source"),
        source_type=source_type,
        event_type=event_type,
        severity=severity,
        source_ip=kwargs.get("source_ip", "192.168.1.1"),
        raw_data=kwargs.get("raw_data", {}),
        normalized_data=kwargs.get("normalized_data", {}),
        metadata=kwargs.get("metadata", {}),
    )


class TestTaskRouter:
    """Tests for TaskRouter."""

    def test_default_rules_loaded(self):
        """Router loads default routing rules."""
        router = TaskRouter()
        assert len(router._rules) > 0

    def test_route_email_event(self):
        """Email events route to EmailVerificationAgent."""
        router = TaskRouter()
        event = _make_event(source_type="email_gateway", event_type="email_received")
        agent_type = router.route(event)
        assert agent_type == AgentType.EMAIL_VERIFICATION

    def test_route_auth_log(self):
        """Auth logs route to LogAnalyzerAgent."""
        router = TaskRouter()
        event = _make_event(source_type="authentication", event_type="auth_failed")
        agent_type = router.route(event)
        assert agent_type == AgentType.LOG_ANALYZER

    def test_route_network_ids(self):
        """IDS events route to NetworkThreatAgent."""
        router = TaskRouter()
        event = _make_event(source_type="suricata", event_type="alert")
        agent_type = router.route(event)
        assert agent_type == AgentType.NETWORK_THREAT

    def test_route_vulnerability(self):
        """Vulnerability events route to VulnerabilityAgent."""
        router = TaskRouter()
        event = _make_event(source_type="vulnerability_scanner", event_type="vulnerability_found")
        agent_type = router.route(event)
        assert agent_type == AgentType.VULNERABILITY

    def test_route_no_match_raises(self):
        """No matching rule raises error."""
        router = TaskRouter()
        event = _make_event(source_type="unknown_source", event_type="unknown_event")
        with pytest.raises(TaskRoutingError):
            router.route(event)

    def test_list_rules(self):
        """List all routing rules."""
        router = TaskRouter()
        rules = router.list_rules()
        assert len(rules) > 0
        assert all("name" in r and "agent_type" in r for r in rules)

    def test_get_priority_from_severity(self):
        """Priority is derived from event severity."""
        router = TaskRouter()

        critical_event = _make_event(severity=EventSeverity.CRITICAL)
        assert router.get_priority(critical_event) == TaskPriority.CRITICAL

        high_event = _make_event(severity=EventSeverity.HIGH)
        assert router.get_priority(high_event) == TaskPriority.HIGH

        medium_event = _make_event(severity=EventSeverity.MEDIUM)
        assert router.get_priority(medium_event) == TaskPriority.MEDIUM


class TestTaskTracker:
    """Tests for TaskTracker."""

    @pytest.fixture
    def tracker(self):
        """Create tracker with mocked Redis."""
        with patch("backend.app.agents.dispatcher.tracker._get_redis_client") as mock_fn:
            mock_fn.return_value = None  # Use local cache only
            return TaskTracker()

    @pytest.mark.asyncio
    async def test_create_task(self, tracker):
        """Create task and track it."""
        task = await tracker.create_task(
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
        )
        assert task.task_id.startswith("task_")
        assert task.event_id == "evt_001"
        assert task.agent_type == AgentType.EMAIL_VERIFICATION
        assert task.status == TaskStatus.QUEUED

    @pytest.mark.asyncio
    async def test_update_status(self, tracker):
        """Update task status."""
        task = await tracker.create_task(
            event_id="evt_002",
            agent_type=AgentType.LOG_ANALYZER,
        )
        updated = await tracker.update_status(task.task_id, TaskStatus.RUNNING)
        assert updated.status == TaskStatus.RUNNING

    @pytest.mark.asyncio
    async def test_mark_started(self, tracker):
        """Mark task as started."""
        task = await tracker.create_task(
            event_id="evt_003",
            agent_type=AgentType.NETWORK_THREAT,
        )
        updated = await tracker.mark_started(task.task_id)
        assert updated.status == TaskStatus.RUNNING
        assert updated.started_at is not None

    @pytest.mark.asyncio
    async def test_mark_completed(self, tracker):
        """Mark task as completed."""
        task = await tracker.create_task(
            event_id="evt_004",
            agent_type=AgentType.THREAT_INTELLIGENCE,
        )
        await tracker.mark_started(task.task_id)
        updated = await tracker.mark_completed(task.task_id, result_id="res_001")
        assert updated.status == TaskStatus.COMPLETED
        assert updated.completed_at is not None

    @pytest.mark.asyncio
    async def test_mark_failed(self, tracker):
        """Mark task as failed."""
        task = await tracker.create_task(
            event_id="evt_005",
            agent_type=AgentType.CORRELATION,
        )
        updated = await tracker.mark_failed(task.task_id, error="Connection timeout")
        assert updated.status == TaskStatus.FAILED
        assert updated.error == "Connection timeout"

    @pytest.mark.asyncio
    async def test_mark_retry(self, tracker):
        """Mark task for retry."""
        task = await tracker.create_task(
            event_id="evt_006",
            agent_type=AgentType.INVESTIGATION,
        )
        updated = await tracker.mark_retry(task.task_id, error="Temporary failure")
        assert updated.status == TaskStatus.RETRYING
        assert updated.retry_count == 1

    @pytest.mark.asyncio
    async def test_mark_dead_letter(self, tracker):
        """Mark task as dead letter."""
        task = await tracker.create_task(
            event_id="evt_007",
            agent_type=AgentType.VULNERABILITY,
            max_retries=3,
        )
        # Exhaust retries
        task.retry_count = 3
        tracker._tasks[task.task_id] = task

        updated = await tracker.mark_dead_letter(task.task_id, error="Max retries exceeded")
        assert updated.status == TaskStatus.DEAD_LETTER

    @pytest.mark.asyncio
    async def test_get_task(self, tracker):
        """Retrieve task by ID."""
        task = await tracker.create_task(
            event_id="evt_008",
            agent_type=AgentType.INCIDENT_PRIORITIZATION,
        )
        retrieved = await tracker.get_task(task.task_id)
        assert retrieved is not None
        assert retrieved.task_id == task.task_id

    @pytest.mark.asyncio
    async def test_get_task_not_found(self, tracker):
        """Get non-existent task returns None."""
        result = await tracker.get_task("nonexistent_task")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_metrics(self, tracker):
        """Get tracker metrics."""
        # Get initial count
        initial_metrics = await tracker.get_metrics()
        initial_count = initial_metrics.get("tasks_created", 0)

        await tracker.create_task(event_id="evt_009", agent_type=AgentType.EMAIL_VERIFICATION)
        await tracker.create_task(event_id="evt_010", agent_type=AgentType.LOG_ANALYZER)

        metrics = await tracker.get_metrics()
        assert metrics["tasks_created"] == initial_count + 2


class TestTaskDispatcherAgent:
    """Tests for TaskDispatcherAgent."""

    @pytest.fixture
    def dispatcher(self):
        """Create dispatcher with mocked dependencies."""
        with patch("backend.app.agents.dispatcher.dispatcher.get_task_router") as mock_router, \
             patch("backend.app.agents.dispatcher.dispatcher.get_task_tracker") as mock_tracker:
            mock_router_instance = MagicMock()
            mock_router_instance.route = MagicMock(return_value=AgentType.EMAIL_VERIFICATION)
            mock_router_instance.get_priority = MagicMock(return_value=TaskPriority.MEDIUM)
            mock_router.return_value = mock_router_instance

            mock_tracker_instance = MagicMock()
            mock_tracker_instance.create_task = AsyncMock(
                return_value=AgentTask(
                    task_id="task_001",
                    event_id="evt_001",
                    agent_type=AgentType.EMAIL_VERIFICATION,
                )
            )
            mock_tracker.return_value = mock_tracker_instance

            return TaskDispatcherAgent()

    def test_dispatcher_properties(self, dispatcher):
        """Dispatcher has correct properties."""
        assert dispatcher.agent_type == AgentType.TASK_DISPATCHER
        assert "event_routing" in dispatcher.capabilities
        assert "task_creation" in dispatcher.capabilities

    @pytest.mark.asyncio
    async def test_validate_task(self, dispatcher):
        """Dispatcher validates task correctly."""
        valid_task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.TASK_DISPATCHER,
            payload={"event": {"source_type": "email"}},
        )
        assert await dispatcher.validate_task(valid_task) is True

        invalid_task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.TASK_DISPATCHER,
            payload={},
        )
        assert await dispatcher.validate_task(invalid_task) is False

    @pytest.mark.asyncio
    async def test_dispatch_event(self, dispatcher):
        """Dispatcher routes and creates task for event."""
        event = _make_event(
            event_id="evt_001",
            source_type="email_gateway",
            event_type="email_received",
        )
        # Mock the broker publish to avoid Kafka connection
        with patch("backend.app.agents.dispatcher.dispatcher.get_broker_manager") as mock_broker:
            mock_broker_instance = MagicMock()
            mock_broker_instance.publish_event = AsyncMock(return_value=True)
            mock_broker.return_value = mock_broker_instance

            task = await dispatcher.dispatch_event(event)
            assert task is not None
            assert task.event_id == "evt_001"


class TestGetTaskRouter:
    """Tests for get_task_router singleton."""

    def test_returns_same_instance(self):
        """Singleton returns same instance."""
        import backend.app.agents.dispatcher.router as router_module
        router_module._router = None

        r1 = get_task_router()
        r2 = get_task_router()
        assert r1 is r2


class TestGetTaskTracker:
    """Tests for get_task_tracker singleton."""

    def test_returns_same_instance(self):
        """Singleton returns same instance."""
        import backend.app.agents.dispatcher.tracker as tracker_module
        tracker_module._tracker = None

        t1 = get_task_tracker()
        t2 = get_task_tracker()
        assert t1 is t2
