"""Unit tests for Report Generation Agent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.agents.specialized.report_generation import (
    GeneratedReport,
    ReportFormat,
    ReportGenerationAgent,
    ReportMetadata,
    ReportSection,
    ReportType,
)
from backend.app.utils.datetime import utc_now


class TestReportGenerationAgent:
    """Tests for ReportGenerationAgent."""

    @pytest.fixture
    def agent(self) -> ReportGenerationAgent:
        """Create agent instance."""
        return ReportGenerationAgent()

    @pytest.fixture
    def base_task(self) -> AgentTask:
        """Create base task for testing."""
        return AgentTask(
            task_id="task_rpt_001",
            event_id="evt_rpt_001",
            agent_type=AgentType.REPORT_GENERATION,
            priority=TaskPriority.MEDIUM,
            status=TaskStatus.QUEUED,
            created_at=utc_now(),
            payload={},
        )

    def test_agent_properties(self, agent: ReportGenerationAgent) -> None:
        """Test agent properties."""
        assert agent.agent_id == "report_gen_001"
        assert agent.name == "Report Generation Agent"
        assert agent.agent_type == AgentType.REPORT_GENERATION
        assert "incident_report_generation" in agent.capabilities
        assert "executive_summary_generation" in agent.capabilities
        assert "multi_format_output" in agent.capabilities

    @pytest.mark.asyncio
    async def test_validate_task_with_incident(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with incident."""
        base_task.payload = {
            "incident": {"incident_id": "inc_001", "severity": "high"}
        }
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_findings(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with findings."""
        base_task.payload = {"findings": [{"finding_id": "f1"}]}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_investigation(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with investigation."""
        base_task.payload = {"investigation": {"investigation_id": "inv_001"}}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_events(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with events."""
        base_task.payload = {"events": [{"event_id": "e1"}]}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_report_type(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with report_type."""
        base_task.payload = {"report_type": "incident_report"}
        assert await agent.validate_task(base_task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test task validation with empty payload."""
        base_task.payload = {}
        assert await agent.validate_task(base_task) is False

    @pytest.mark.asyncio
    async def test_process_task_incident_report_markdown(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test incident report generation in Markdown format."""
        base_task.payload = {
            "incident": {
                "incident_id": "inc_001",
                "severity": "high",
                "affected_assets": ["host1", "host2"],
                "affected_users": ["user1"],
                "mitre_techniques": ["T1566", "T1059"],
            },
            "format": "markdown",
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"
        assert result.finding is not None

    @pytest.mark.asyncio
    async def test_process_task_incident_report_html(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test incident report generation in HTML format."""
        base_task.payload = {
            "incident": {
                "incident_id": "inc_002",
                "severity": "critical",
            },
            "format": "html",
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_process_task_incident_report_json(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test incident report generation in JSON format."""
        base_task.payload = {
            "incident": {"incident_id": "inc_003"},
            "format": "json",
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_process_task_executive_summary(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test executive summary generation."""
        base_task.payload = {
            "report_type": "executive_summary",
            "incident": {
                "incident_id": "inc_004",
                "severity": "high",
                "affected_assets": ["server1"],
            },
            "executive": True,
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_process_task_technical_analysis(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test technical analysis report generation."""
        base_task.payload = {
            "report_type": "technical_analysis",
            "findings": [
                {"finding_id": "f1", "finding_type": "malware", "severity": "critical"},
                {"finding_id": "f2", "finding_type": "c2", "severity": "high"},
            ],
            "technical": True,
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_process_task_investigation_report(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test investigation report generation."""
        base_task.payload = {
            "investigation": {
                "investigation_id": "inv_001",
                "timeline": [
                    {"timestamp": utc_now().isoformat(), "event": "Initial access"},
                    {"timestamp": utc_now().isoformat(), "event": "Lateral movement"},
                ],
                "findings": [{"finding_id": "f1", "explanation": "Malware detected"}],
            },
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    def test_report_format_enum(self) -> None:
        """Test ReportFormat enum values."""
        assert ReportFormat.JSON == "json"
        assert ReportFormat.HTML == "html"
        assert ReportFormat.MARKDOWN == "markdown"
        assert ReportFormat.PDF == "pdf"
        assert ReportFormat.TEXT == "text"

    def test_report_type_enum(self) -> None:
        """Test ReportType enum values."""
        assert ReportType.INCIDENT_REPORT == "incident_report"
        assert ReportType.EXECUTIVE_SUMMARY == "executive_summary"
        assert ReportType.TECHNICAL_ANALYSIS == "technical_analysis"
        assert ReportType.INVESTIGATION_REPORT == "investigation_report"
        assert ReportType.COMPLIANCE_REPORT == "compliance_report"

    def test_report_section_model(self) -> None:
        """Test ReportSection model."""
        section = ReportSection(
            section_id="sec_001",
            title="Executive Summary",
            content="This is the summary content.",
            order=1,
        )
        assert section.section_id == "sec_001"
        assert section.title == "Executive Summary"
        assert section.order == 1

    def test_report_metadata_model(self) -> None:
        """Test ReportMetadata model."""
        metadata = ReportMetadata(
            report_id="rpt_001",
            report_type=ReportType.INCIDENT_REPORT,
            title="Security Incident Report",
            generated_at=utc_now(),
            generated_by="report_gen_001",
            classification="CONFIDENTIAL",
            incident_id="inc_001",
        )
        assert metadata.report_id == "rpt_001"
        assert metadata.report_type == ReportType.INCIDENT_REPORT
        assert metadata.classification == "CONFIDENTIAL"

    def test_generated_report_model(self) -> None:
        """Test GeneratedReport model."""
        metadata = ReportMetadata(
            report_id="rpt_002",
            report_type=ReportType.EXECUTIVE_SUMMARY,
            title="Executive Summary",
            generated_at=utc_now(),
            generated_by="report_gen_001",
        )
        report = GeneratedReport(
            metadata=metadata,
            format=ReportFormat.MARKDOWN,
            content="# Report\n\nContent here.",
            summary="Brief summary",
            key_findings=["Finding 1", "Finding 2"],
            recommendations=["Recommendation 1"],
        )
        assert report.format == ReportFormat.MARKDOWN
        assert len(report.key_findings) == 2
        assert len(report.recommendations) == 1

    @pytest.mark.asyncio
    async def test_create_finding(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test finding creation."""
        base_task.payload = {"incident": {"incident_id": "inc_001"}}
        finding = agent.create_finding(base_task, {"report_type": "incident"})
        assert finding.finding_type == "report_generation"
        assert finding.agent_id == agent.agent_id

    @pytest.mark.asyncio
    async def test_report_with_timeline(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test report generation with timeline data."""
        base_task.payload = {
            "incident": {"incident_id": "inc_005"},
            "events": [
                {
                    "event_id": "e1",
                    "event_type": "login_failure",
                    "timestamp": utc_now().isoformat(),
                },
                {
                    "event_id": "e2",
                    "event_type": "privilege_escalation",
                    "timestamp": utc_now().isoformat(),
                },
            ],
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_report_text_format(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test report generation in plain text format."""
        base_task.payload = {
            "incident": {"incident_id": "inc_006", "severity": "medium"},
            "format": "text",
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"

    @pytest.mark.asyncio
    async def test_report_metadata_in_result(
        self, agent: ReportGenerationAgent, base_task: AgentTask
    ) -> None:
        """Test that report metadata is included in result."""
        base_task.payload = {
            "incident": {"incident_id": "inc_007"},
        }
        result = await agent.process_task(base_task)
        assert result.status.value == "success"
        assert "report_id" in result.metadata
        assert "report_type" in result.metadata
        assert "word_count" in result.metadata
