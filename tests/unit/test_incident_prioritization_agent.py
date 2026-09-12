"""Unit tests for Incident Prioritization Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.incident_prioritization import (
    AssetCriticality,
    IncidentPrioritizationAgent,
    RiskFactor,
)
from backend.app.utils.datetime import utc_now


class TestIncidentPrioritizationAgent:
    """Tests for IncidentPrioritizationAgent."""

    @pytest.fixture
    def agent(self) -> IncidentPrioritizationAgent:
        return IncidentPrioritizationAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_pri_001",
            event_id="evt_pri_001",
            agent_type=AgentType.INCIDENT_PRIORITIZATION,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: IncidentPrioritizationAgent) -> None:
        """Test agent properties."""
        assert (
            "incident_prioritization" in agent.agent_id
            or "prioritization" in agent.agent_id
        )
        assert agent.name == "Incident Prioritization Agent"
        assert agent.agent_type == AgentType.INCIDENT_PRIORITIZATION
        assert len(agent.capabilities) > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_incident(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with incident."""
        base_task.payload = {"incident": {"incident_id": "inc_001", "severity": "high"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_finding(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with finding."""
        base_task.payload = {"finding": {"finding_id": "f1", "severity": "critical"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_event(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with event."""
        base_task.payload = {"event": {"event_id": "e1", "severity": "medium"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "incident": {
                "incident_id": "inc_001",
                "severity": "critical",
                "affected_assets": 10,
            }
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id
        assert result.agent_id == agent.agent_id

    def test_asset_criticality_enum(self) -> None:
        """Test AssetCriticality enum values."""
        assert AssetCriticality.CRITICAL == "critical"
        assert AssetCriticality.HIGH == "high"
        assert AssetCriticality.MEDIUM == "medium"
        assert AssetCriticality.LOW == "low"

    def test_risk_factor_model(self) -> None:
        """Test RiskFactor model."""
        factor = RiskFactor(
            factor_name="severity",
            description="Event severity level",
            weight=0.3,
            score=0.9,
            weighted_score=0.27,
            evidence="Severity: CRITICAL",
        )
        assert factor.factor_name == "severity"
        assert factor.weighted_score == 0.27

    def test_create_finding(
        self, agent: IncidentPrioritizationAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"incident": {"incident_id": "inc_001"}}
        finding = agent.create_finding(base_task, {"priority": "P1"})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
