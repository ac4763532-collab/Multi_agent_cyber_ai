"""Unit tests for Threat Intelligence Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.threat_intelligence import (
    IoC_Enrichment,
    IoC_Type,
    MitreTechnique,
    ThreatIntelligenceAgent,
)
from backend.app.utils.datetime import utc_now


class TestThreatIntelligenceAgent:
    """Tests for ThreatIntelligenceAgent."""

    @pytest.fixture
    def agent(self) -> ThreatIntelligenceAgent:
        return ThreatIntelligenceAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        return AgentTask(
            task_id="task_ti_001",
            event_id="evt_ti_001",
            agent_type=AgentType.THREAT_INTELLIGENCE,
            priority=TaskPriority.HIGH,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: ThreatIntelligenceAgent) -> None:
        """Test agent properties."""
        assert agent.agent_id == "threat_intel_001"
        assert agent.name == "Threat Intelligence Agent"
        assert agent.agent_type == AgentType.THREAT_INTELLIGENCE
        assert len(agent.capabilities) > 0

    @pytest.mark.asyncio
    async def test_validate_task_with_iocs(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with IoCs."""
        base_task.payload = {"iocs": ["192.168.1.1", "malware.com"]}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_ip(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with IP."""
        base_task.payload = {"ip": "192.168.1.1"}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_domain(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with domain."""
        base_task.payload = {"domain": "suspicious.com"}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_returns_result(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test process_task returns a result."""
        base_task.payload = {
            "ip": "185.220.101.1",
            "event_type": "network_connection",
        }
        result = await agent.process_task(base_task)
        assert result is not None
        assert result.task_id == base_task.task_id
        assert result.agent_id == agent.agent_id

    def test_ioc_type_enum(self) -> None:
        """Test IoC_Type enum values."""
        assert IoC_Type.IP_ADDRESS == "ip_address"
        assert IoC_Type.DOMAIN == "domain"
        assert IoC_Type.URL == "url"

    def test_ioc_enrichment_model(self) -> None:
        """Test IoC_Enrichment model."""
        enrichment = IoC_Enrichment(
            ioc_value="192.168.1.1",
            ioc_type=IoC_Type.IP_ADDRESS,
            is_known_malicious=True,
            confidence_score=0.85,
        )
        assert enrichment.ioc_value == "192.168.1.1"
        assert enrichment.is_known_malicious is True

    def test_mitre_technique_model(self) -> None:
        """Test MitreTechnique model."""
        technique = MitreTechnique(
            technique_id="T1566",
            technique_name="Phishing",
            tactic="Initial Access",
            description="Adversaries may send phishing messages",
        )
        assert technique.technique_id == "T1566"
        assert technique.tactic == "Initial Access"

    def test_create_finding(
        self, agent: ThreatIntelligenceAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"ip": "192.168.1.1"}
        finding = agent.create_finding(base_task, {"enrichment": "test"})
        assert finding is not None
        assert finding.agent_id == agent.agent_id
