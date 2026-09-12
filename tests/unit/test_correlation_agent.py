"""Unit tests for Correlation Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.correlation import (
    AttackStage,
    CorrelatedEvent,
    CorrelationAgent,
    CorrelationType,
)
from backend.app.utils.datetime import utc_now


class TestCorrelationAgent:
    """Tests for CorrelationAgent."""

    @pytest.fixture
    def agent(self) -> CorrelationAgent:
        return CorrelationAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_corr_001",
            event_id="evt_corr_001",
            agent_type=AgentType.CORRELATION,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: CorrelationAgent) -> None:
        """Test agent properties."""
        assert agent.agent_id == "correlation_001"
        assert agent.name == "Correlation Agent"
        assert agent.agent_type == AgentType.CORRELATION
        assert len(agent.capabilities) > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_events(
        self, agent: CorrelationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with events."""
        base_task.payload = {
            "events": [
                {"event_id": "e1", "source_ip": "192.168.1.1"},
                {"event_id": "e2", "source_ip": "192.168.1.1"},
            ]
        }
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_findings(
        self, agent: CorrelationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with findings."""
        base_task.payload = {"findings": [{"finding_id": "f1"}, {"finding_id": "f2"}]}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: CorrelationAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "events": [
                {
                    "event_id": "e1",
                    "source_ip": "192.168.1.100",
                    "event_type": "login_failure",
                    "timestamp": utc_now().isoformat(),
                },
                {
                    "event_id": "e2",
                    "source_ip": "192.168.1.100",
                    "event_type": "port_scan",
                    "timestamp": utc_now().isoformat(),
                },
            ]
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id

    def test_attack_stage_enum(self) -> None:
        """Test AttackStage enum values."""
        assert AttackStage.RECONNAISSANCE == "reconnaissance"
        assert AttackStage.INITIAL_ACCESS == "initial_access"
        assert AttackStage.EXECUTION == "execution"

    def test_correlation_type_enum(self) -> None:
        """Test CorrelationType enum values."""
        assert CorrelationType.SAME_SOURCE == "same_source"
        assert CorrelationType.SAME_TARGET == "same_target"
        assert CorrelationType.TEMPORAL == "temporal"

    def test_correlated_event_model(self) -> None:
        """Test CorrelatedEvent model."""
        event = CorrelatedEvent(
            event_id="evt_001",
            event_type="login_failure",
            timestamp=utc_now(),
            source_ip="192.168.1.1",
        )
        assert event.event_id == "evt_001"
        assert event.source_ip == "192.168.1.1"

    def test_create_finding(
        self, agent: CorrelationAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"events": [{"event_id": "e1"}, {"event_id": "e2"}]}
        finding = agent.create_finding(base_task, {"correlation_type": "test"})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
