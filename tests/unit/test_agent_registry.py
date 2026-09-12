"""Unit tests for AgentRegistry."""

import pytest

from backend.app.agents.base import BaseAgent
from backend.app.agents.exceptions import AgentNotFoundError, AgentRegistrationError
from backend.app.agents.models import (
    AgentResult,
    AgentTask,
    AgentType,
    BaseFinding,
    ResultStatus,
)
from backend.app.agents.registry import AgentRegistry, get_agent_registry


class MockAgent(BaseAgent):
    """Mock agent for testing registry."""

    def __init__(self, agent_id: str, agent_type: AgentType, caps: list[str] | None = None):
        super().__init__()
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._caps = caps or ["default"]

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def name(self) -> str:
        return f"Mock {self._agent_type.value}"

    @property
    def agent_type(self) -> AgentType:
        return self._agent_type

    @property
    def capabilities(self) -> list[str]:
        return self._caps

    async def validate_task(self, task: AgentTask) -> bool:
        return True

    async def process_task(self, task: AgentTask) -> AgentResult:
        from backend.app.utils.datetime import utc_now
        now = utc_now()
        return AgentResult(
            result_id="mock_result",
            task_id=task.task_id,
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            agent_version=self.version,
            status=ResultStatus.SUCCESS,
            start_time=now,
            end_time=now,
            processing_time_ms=1.0,
        )

    def create_finding(self, task: AgentTask, analysis: dict) -> BaseFinding:
        return BaseFinding(
            finding_id="mock_finding",
            finding_type="mock",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
        )


class TestAgentRegistry:
    """Tests for AgentRegistry."""

    def test_register_agent(self):
        """Register an agent successfully."""
        registry = AgentRegistry()
        agent = MockAgent("agent_001", AgentType.EMAIL_VERIFICATION)

        registry.register(agent)

        assert AgentType.EMAIL_VERIFICATION in registry._agents

    def test_register_duplicate_raises(self):
        """Registering duplicate agent type raises error."""
        registry = AgentRegistry()
        agent1 = MockAgent("agent_001", AgentType.EMAIL_VERIFICATION)
        agent2 = MockAgent("agent_002", AgentType.EMAIL_VERIFICATION)

        registry.register(agent1)
        with pytest.raises(AgentRegistrationError):
            registry.register(agent2)

    def test_get_agent(self):
        """Get registered agent by type."""
        registry = AgentRegistry()
        agent = MockAgent("agent_001", AgentType.LOG_ANALYZER)
        registry.register(agent)

        retrieved = registry.get_agent(AgentType.LOG_ANALYZER)
        assert retrieved.agent_id == "agent_001"

    def test_get_agent_not_found(self):
        """Get non-existent agent raises error."""
        registry = AgentRegistry()

        with pytest.raises(AgentNotFoundError):
            registry.get_agent(AgentType.VULNERABILITY)

    def test_list_agents(self):
        """List all registered agents."""
        registry = AgentRegistry()
        registry.register(MockAgent("a1", AgentType.EMAIL_VERIFICATION))
        registry.register(MockAgent("a2", AgentType.LOG_ANALYZER))
        registry.register(MockAgent("a3", AgentType.NETWORK_THREAT))

        agents = registry.list_agents()
        assert len(agents) == 3
        agent_types = [a.agent_type for a in agents]
        assert AgentType.EMAIL_VERIFICATION in agent_types
        assert AgentType.LOG_ANALYZER in agent_types
        assert AgentType.NETWORK_THREAT in agent_types

    def test_get_by_capability(self):
        """Get agents by capability."""
        registry = AgentRegistry()
        registry.register(MockAgent("a1", AgentType.EMAIL_VERIFICATION, ["email", "phishing"]))
        registry.register(MockAgent("a2", AgentType.LOG_ANALYZER, ["logs", "brute_force"]))
        registry.register(MockAgent("a3", AgentType.NETWORK_THREAT, ["network", "phishing"]))

        phishing_agents = registry.get_by_capability("phishing")
        assert len(phishing_agents) == 2

        log_agents = registry.get_by_capability("logs")
        assert len(log_agents) == 1
        assert log_agents[0].agent_type == AgentType.LOG_ANALYZER

    def test_get_by_capability_none_found(self):
        """Get by capability returns empty list if none match."""
        registry = AgentRegistry()
        registry.register(MockAgent("a1", AgentType.EMAIL_VERIFICATION, ["email"]))

        result = registry.get_by_capability("nonexistent")
        assert result == []

    def test_unregister_agent(self):
        """Unregister an agent."""
        registry = AgentRegistry()
        agent = MockAgent("a1", AgentType.EMAIL_VERIFICATION)
        registry.register(agent)

        result = registry.unregister(AgentType.EMAIL_VERIFICATION)
        assert result is True
        agent_types = [a.agent_type for a in registry.list_agents()]
        assert AgentType.EMAIL_VERIFICATION not in agent_types

    def test_unregister_not_found(self):
        """Unregister non-existent agent returns False."""
        registry = AgentRegistry()

        result = registry.unregister(AgentType.VULNERABILITY)
        assert result is False


class TestGetAgentRegistry:
    """Tests for get_agent_registry singleton."""

    def test_returns_same_instance(self):
        """Singleton returns same instance."""
        # Clear existing singleton for test isolation
        import backend.app.agents.registry as registry_module
        registry_module._registry = None

        r1 = get_agent_registry()
        r2 = get_agent_registry()
        assert r1 is r2

    def test_registry_persists_state(self):
        """Singleton maintains state."""
        import backend.app.agents.registry as registry_module
        registry_module._registry = None

        registry = get_agent_registry()
        # Use a type that's unlikely to be already registered
        agent_types = [a.agent_type for a in registry.list_agents()]
        if AgentType.REPORT_GENERATION not in agent_types:
            registry.register(MockAgent("singleton_test", AgentType.REPORT_GENERATION))

        registry2 = get_agent_registry()
        agent_types2 = [a.agent_type for a in registry2.list_agents()]
        assert AgentType.REPORT_GENERATION in agent_types2

        # Cleanup
        registry.unregister(AgentType.REPORT_GENERATION)
