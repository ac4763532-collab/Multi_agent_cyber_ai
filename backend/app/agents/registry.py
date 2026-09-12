"""Agent registry for managing all specialized security agents."""

from typing import Any

from backend.app.agents.base import BaseAgent
from backend.app.agents.exceptions import AgentNotFoundError, AgentRegistrationError
from backend.app.agents.models import AgentType
from backend.app.core.logging import get_logger

logger = get_logger("cyber_ai.agents.registry")


class AgentRegistry:
    """Registry for managing and accessing specialized security agents.

    Provides singleton access to all 12 agents with lookup by type,
    capability, and ID.
    """

    def __init__(self) -> None:
        """Initialize empty registry."""
        self._agents: dict[AgentType, BaseAgent] = {}
        self._agents_by_id: dict[str, BaseAgent] = {}
        self._capabilities_index: dict[str, list[AgentType]] = {}

    def register(self, agent: BaseAgent) -> None:
        """Register an agent with the registry.

        Args:
            agent: BaseAgent instance to register.

        Raises:
            AgentRegistrationError: If agent type is already registered.
        """
        if agent.agent_type in self._agents:
            raise AgentRegistrationError(
                message=f"Agent type {agent.agent_type.value} already registered",
                agent_id=agent.agent_id,
                agent_type=agent.agent_type.value,
            )

        self._agents[agent.agent_type] = agent
        self._agents_by_id[agent.agent_id] = agent

        # Index capabilities
        for capability in agent.capabilities:
            if capability not in self._capabilities_index:
                self._capabilities_index[capability] = []
            self._capabilities_index[capability].append(agent.agent_type)

        logger.info(
            "Registered agent %s (type=%s, version=%s)",
            agent.agent_id,
            agent.agent_type.value,
            agent.version,
        )

    def unregister(self, agent_type: AgentType) -> bool:
        """Unregister an agent by type.

        Args:
            agent_type: Type of agent to unregister.

        Returns:
            True if agent was unregistered, False if not found.
        """
        agent = self._agents.pop(agent_type, None)
        if not agent:
            return False

        self._agents_by_id.pop(agent.agent_id, None)

        # Remove from capabilities index
        for capability in agent.capabilities:
            if capability in self._capabilities_index:
                self._capabilities_index[capability] = [
                    t for t in self._capabilities_index[capability] if t != agent_type
                ]
                if not self._capabilities_index[capability]:
                    del self._capabilities_index[capability]

        logger.info("Unregistered agent %s", agent.agent_id)
        return True

    def get_agent(self, agent_type: AgentType) -> BaseAgent:
        """Get an agent by type.

        Args:
            agent_type: Type of agent to retrieve.

        Returns:
            BaseAgent instance.

        Raises:
            AgentNotFoundError: If agent type is not registered.
        """
        agent = self._agents.get(agent_type)
        if not agent:
            raise AgentNotFoundError(
                message=f"Agent type {agent_type.value} not registered",
                agent_type=agent_type.value,
            )
        return agent

    def get_agent_by_id(self, agent_id: str) -> BaseAgent:
        """Get an agent by ID.

        Args:
            agent_id: Agent identifier.

        Returns:
            BaseAgent instance.

        Raises:
            AgentNotFoundError: If agent ID is not found.
        """
        agent = self._agents_by_id.get(agent_id)
        if not agent:
            raise AgentNotFoundError(
                message=f"Agent {agent_id} not found",
                agent_type=None,
            )
        return agent

    def get_by_capability(self, capability: str) -> list[BaseAgent]:
        """Get agents that have a specific capability.

        Args:
            capability: Capability to search for.

        Returns:
            List of agents with the capability.
        """
        agent_types = self._capabilities_index.get(capability, [])
        return [self._agents[t] for t in agent_types if t in self._agents]

    def has_agent(self, agent_type: AgentType) -> bool:
        """Check if an agent type is registered.

        Args:
            agent_type: Type to check.

        Returns:
            True if registered, False otherwise.
        """
        return agent_type in self._agents

    def list_agents(self) -> list[BaseAgent]:
        """List all registered agents.

        Returns:
            List of all BaseAgent instances.
        """
        return list(self._agents.values())

    def list_agent_types(self) -> list[AgentType]:
        """List all registered agent types.

        Returns:
            List of registered AgentType values.
        """
        return list(self._agents.keys())

    def list_capabilities(self) -> list[str]:
        """List all available capabilities.

        Returns:
            List of capability strings.
        """
        return list(self._capabilities_index.keys())

    def get_stats(self) -> dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dict with registry metrics.
        """
        return {
            "total_agents": len(self._agents),
            "agent_types": [t.value for t in self._agents.keys()],
            "total_capabilities": len(self._capabilities_index),
            "agents": {t.value: self._agents[t].get_stats() for t in self._agents},
        }

    def clear(self) -> None:
        """Clear all registered agents."""
        self._agents.clear()
        self._agents_by_id.clear()
        self._capabilities_index.clear()
        logger.info("Agent registry cleared")


# Singleton instance
_registry: AgentRegistry | None = None


def get_agent_registry() -> AgentRegistry:
    """Return singleton AgentRegistry instance."""
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
    return _registry


def register_agent(agent: BaseAgent) -> None:
    """Convenience function to register an agent."""
    get_agent_registry().register(agent)


def get_agent(agent_type: AgentType) -> BaseAgent:
    """Convenience function to get an agent by type."""
    return get_agent_registry().get_agent(agent_type)
