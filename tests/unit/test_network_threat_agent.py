"""Unit tests for Phase 10-15 Agents - Network Threat Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.network_threat import (
    NetworkThreatAgent,
    NetworkThreatConfig,
    NetworkThreatType,
)
from backend.app.utils.datetime import utc_now


class TestNetworkThreatAgent:
    """Tests for NetworkThreatAgent."""

    @pytest.fixture
    def agent(self) -> NetworkThreatAgent:
        return NetworkThreatAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_net_001",
            event_id="evt_net_001",
            agent_type=AgentType.NETWORK_THREAT,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: NetworkThreatAgent) -> None:
        """Test agent properties."""
        assert agent.agent_id == "network_threat_001"
        assert agent.name == "Network Threat Agent"
        assert agent.agent_type == AgentType.NETWORK_THREAT
        assert len(agent.capabilities) > 0

    def test_config_model(self) -> None:
        """Test config can be instantiated."""
        config = NetworkThreatConfig()
        assert config.port_scan_threshold > 0
        assert config.port_scan_window_sec > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_event(
        self, agent: NetworkThreatAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with event payload."""
        base_task.payload = {"event": {"source_ip": "192.168.1.100"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: NetworkThreatAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: NetworkThreatAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "event": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "bytes_out": 500 * 1024 * 1024,
            }
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id
        assert result.agent_id == agent.agent_id

    def test_network_threat_type_enum(self) -> None:
        """Test NetworkThreatType enum exists."""
        assert NetworkThreatType.C2_COMMUNICATION == "c2_communication"
        assert NetworkThreatType.PORT_SCAN == "port_scan"
        assert NetworkThreatType.DATA_EXFILTRATION == "data_exfiltration"

    def test_create_finding(
        self, agent: NetworkThreatAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"event": {"source_ip": "192.168.1.1"}}
        finding = agent.create_finding(base_task, {"threat_type": "test"})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
