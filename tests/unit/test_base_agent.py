"""Unit tests for BaseAgent abstract class."""


import pytest

from backend.app.agents.base import BaseAgent
from backend.app.agents.models import (
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentType,
    BaseFinding,
    ResultStatus,
)


class ConcreteAgent(BaseAgent):
    """Concrete implementation of BaseAgent for testing."""

    def __init__(self, should_fail: bool = False, should_timeout: bool = False):
        super().__init__()
        self._should_fail = should_fail
        self._should_timeout = should_timeout

    @property
    def agent_id(self) -> str:
        return "test_agent_001"

    @property
    def name(self) -> str:
        return "Test Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.EMAIL_VERIFICATION

    @property
    def capabilities(self) -> list[str]:
        return ["testing", "validation"]

    async def validate_task(self, task: AgentTask) -> bool:
        return task.payload is not None and "data" in task.payload

    async def process_task(self, task: AgentTask) -> AgentResult:
        if self._should_fail:
            raise ValueError("Intentional failure")
        if self._should_timeout:
            raise TimeoutError("Task timeout")

        finding = self.create_finding(task, {"processed": True})
        from backend.app.utils.datetime import utc_now
        now = utc_now()
        return AgentResult(
            result_id=f"result_{task.task_id}",
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            agent_version=self.version,
            status=ResultStatus.SUCCESS,
            finding=finding,
            start_time=now,
            end_time=now,
            processing_time_ms=10.0,
        )

    def create_finding(self, task: AgentTask, analysis: dict) -> BaseFinding:
        return BaseFinding(
            finding_id=f"finding_{task.task_id}",
            finding_type="test_finding",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )


class TestBaseAgentProperties:
    """Tests for BaseAgent properties."""

    def test_agent_id(self):
        """Agent has correct ID."""
        agent = ConcreteAgent()
        assert agent.agent_id == "test_agent_001"

    def test_agent_name(self):
        """Agent has correct name."""
        agent = ConcreteAgent()
        assert agent.name == "Test Agent"

    def test_agent_type(self):
        """Agent has correct type."""
        agent = ConcreteAgent()
        assert agent.agent_type == AgentType.EMAIL_VERIFICATION

    def test_agent_version(self):
        """Agent has default version."""
        agent = ConcreteAgent()
        assert agent.version == "1.0.0"

    def test_agent_capabilities(self):
        """Agent has correct capabilities."""
        agent = ConcreteAgent()
        assert "testing" in agent.capabilities
        assert "validation" in agent.capabilities

    def test_agent_status_default(self):
        """Agent starts in idle status."""
        agent = ConcreteAgent()
        assert agent.status == AgentStatus.IDLE


class TestBaseAgentValidation:
    """Tests for task validation."""

    @pytest.mark.asyncio
    async def test_validate_valid_task(self):
        """Valid task passes validation."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        assert await agent.validate_task(task) is True

    @pytest.mark.asyncio
    async def test_validate_invalid_task_no_payload(self):
        """Task without payload fails validation."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.EMAIL_VERIFICATION,
        )
        assert await agent.validate_task(task) is False

    @pytest.mark.asyncio
    async def test_validate_invalid_task_missing_key(self):
        """Task with wrong payload fails validation."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_003",
            event_id="evt_003",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"wrong_key": "value"},
        )
        assert await agent.validate_task(task) is False


class TestBaseAgentExecution:
    """Tests for task execution."""

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Successful execution returns success result."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        result = await agent.execute(task)

        assert result.status == ResultStatus.SUCCESS
        assert result.task_id == "task_001"
        assert result.agent_id == "test_agent_001"
        assert result.finding is not None

    @pytest.mark.asyncio
    async def test_execute_validation_failure(self):
        """Execution with invalid task returns failed result."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={},  # Missing required "data" key
        )
        result = await agent.execute(task)

        assert result.status == ResultStatus.FAILED
        assert "validation failed" in result.errors[0].lower()

    @pytest.mark.asyncio
    async def test_execute_processing_failure(self):
        """Execution handles processing errors."""
        agent = ConcreteAgent(should_fail=True)
        task = AgentTask(
            task_id="task_003",
            event_id="evt_003",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        result = await agent.execute(task)

        assert result.status == ResultStatus.FAILED
        assert "Intentional failure" in result.errors[0]

    @pytest.mark.asyncio
    async def test_execute_tracks_time(self):
        """Execution tracks processing time."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_004",
            event_id="evt_004",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        result = await agent.execute(task)

        assert result.processing_time_ms >= 0
        assert result.start_time is not None
        assert result.end_time is not None
        assert result.end_time >= result.start_time


class TestBaseAgentFinding:
    """Tests for finding creation."""

    def test_create_finding(self):
        """Agent creates finding correctly."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        finding = agent.create_finding(task, {"key": "value"})

        assert finding.finding_id == "finding_task_001"
        assert finding.event_id == "evt_001"
        assert finding.task_id == "task_001"
        assert finding.agent_id == "test_agent_001"
        assert finding.metadata == {"key": "value"}


class TestBaseAgentStats:
    """Tests for agent statistics."""

    def test_get_stats_initial(self):
        """Agent starts with zero stats."""
        agent = ConcreteAgent()
        stats = agent.get_stats()

        assert stats["tasks_processed"] == 0
        assert stats["tasks_failed"] == 0
        assert stats["avg_processing_time_ms"] == 0.0

    @pytest.mark.asyncio
    async def test_get_stats_after_execution(self):
        """Stats update after execution."""
        agent = ConcreteAgent()
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        await agent.execute(task)
        stats = agent.get_stats()

        assert stats["tasks_processed"] == 1
        assert stats["tasks_failed"] == 0

    @pytest.mark.asyncio
    async def test_get_stats_after_failure(self):
        """Stats track failures."""
        agent = ConcreteAgent(should_fail=True)
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={"data": "test"},
        )
        await agent.execute(task)
        stats = agent.get_stats()

        # Note: failed tasks still increment tasks_processed before failure
        assert stats["tasks_failed"] == 1
