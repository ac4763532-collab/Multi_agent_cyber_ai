"""Unit tests for Response Recommendation Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.response_recommendation import (
    AutomationLevel,
    ResponseAction,
    ResponseRecommendationAgent,
    ResponseType,
    ResponseUrgency,
)
from backend.app.utils.datetime import utc_now


class TestResponseRecommendationAgent:
    """Tests for ResponseRecommendationAgent."""

    @pytest.fixture
    def agent(self) -> ResponseRecommendationAgent:
        return ResponseRecommendationAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_resp_001",
            event_id="evt_resp_001",
            agent_type=AgentType.RESPONSE_RECOMMENDATION,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: ResponseRecommendationAgent) -> None:
        """Test agent properties."""
        assert "response" in agent.agent_id
        assert agent.name == "Response Recommendation Agent"
        assert agent.agent_type == AgentType.RESPONSE_RECOMMENDATION
        assert len(agent.capabilities) > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_incident(
        self, agent: ResponseRecommendationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with incident."""
        base_task.payload = {"incident": {"incident_id": "inc_001", "severity": "high"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_finding(
        self, agent: ResponseRecommendationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with finding."""
        base_task.payload = {"finding": {"finding_id": "f1", "finding_type": "malware"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: ResponseRecommendationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: ResponseRecommendationAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "incident": {
                "incident_id": "inc_001",
                "severity": "critical",
                "classification": "malware",
                "affected_hosts": ["host1", "host2"],
            }
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id
        assert result.agent_id == agent.agent_id

    def test_response_urgency_enum(self) -> None:
        """Test ResponseUrgency enum values."""
        assert ResponseUrgency.IMMEDIATE == "immediate"
        assert ResponseUrgency.URGENT == "urgent"
        assert ResponseUrgency.STANDARD == "standard"

    def test_response_type_enum(self) -> None:
        """Test ResponseType enum values."""
        assert ResponseType.CONTAINMENT == "containment"
        assert ResponseType.ERADICATION == "eradication"
        assert ResponseType.RECOVERY == "recovery"

    def test_automation_level_enum(self) -> None:
        """Test AutomationLevel enum values."""
        assert AutomationLevel.FULLY_AUTOMATED == "fully_automated"
        assert AutomationLevel.SEMI_AUTOMATED == "semi_automated"
        assert AutomationLevel.MANUAL == "manual"

    def test_response_action_model(self) -> None:
        """Test ResponseAction model."""
        action = ResponseAction(
            action_id="act_001",
            action_type=ResponseType.CONTAINMENT,
            title="Isolate Host",
            description="Isolate compromised host from network",
        )
        assert action.action_id == "act_001"
        assert action.action_type == ResponseType.CONTAINMENT

    def test_create_finding(
        self, agent: ResponseRecommendationAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"incident": {"incident_id": "inc_001"}}
        finding = agent.create_finding(base_task, {"actions": []})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
