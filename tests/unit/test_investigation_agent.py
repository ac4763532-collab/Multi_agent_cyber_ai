"""Unit tests for Investigation Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.investigation import (
    InvestigationAgent,
    TimelineEntry,
)
from backend.app.schemas.events import EventSeverity
from backend.app.utils.datetime import utc_now


class TestInvestigationAgent:
    """Tests for InvestigationAgent."""

    @pytest.fixture
    def agent(self) -> InvestigationAgent:
        return InvestigationAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_inv_001",
            event_id="evt_inv_001",
            agent_type=AgentType.INVESTIGATION,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: InvestigationAgent) -> None:
        """Test agent properties."""
        assert agent.agent_id == "investigation_001"
        assert agent.name == "Investigation Agent"
        assert agent.agent_type == AgentType.INVESTIGATION
        assert len(agent.capabilities) > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_incident(
        self, agent: InvestigationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with incident."""
        base_task.payload = {"incident": {"incident_id": "inc_001"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_events(
        self, agent: InvestigationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with events."""
        base_task.payload = {"events": [{"event_id": "e1"}, {"event_id": "e2"}]}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: InvestigationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: InvestigationAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "incident": {"incident_id": "inc_001", "severity": "high"},
            "events": [
                {
                    "event_id": "e1",
                    "event_type": "login_failure",
                    "timestamp": utc_now().isoformat(),
                    "source_ip": "192.168.1.100",
                },
            ],
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id
        assert result.agent_id == agent.agent_id

    def test_timeline_entry_model(self) -> None:
        """Test TimelineEntry model."""
        entry = TimelineEntry(
            timestamp=utc_now(),
            event_id="evt_001",
            event_type="login_failure",
            description="Failed login attempt",
            source="auth_log",
            severity=EventSeverity.MEDIUM,
        )
        assert entry.event_id == "evt_001"
        assert entry.severity == EventSeverity.MEDIUM

    def test_create_finding(
        self, agent: InvestigationAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"incident": {"incident_id": "inc_001"}}
        finding = agent.create_finding(base_task, {"summary": "test"})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
