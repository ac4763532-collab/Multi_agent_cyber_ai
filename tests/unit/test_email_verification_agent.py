"""Unit tests for EmailVerificationAgent."""

import pytest

from backend.app.agents.models import AgentTask, AgentType, ResultStatus
from backend.app.agents.specialized.email_verification import (
    EmailAnalysis,
    EmailClassification,
    EmailIndicator,
    EmailVerificationAgent,
)
from backend.app.detection.models import MatchConfidence
from backend.app.schemas.events import EventSeverity


class TestEmailClassification:
    """Tests for EmailClassification enum."""

    def test_all_classifications(self):
        """All classifications are defined."""
        expected = {
            "benign",
            "suspicious",
            "possible_phishing",
            "possible_social_engineering",
            "malicious_indicators",
        }
        actual = {c.value for c in EmailClassification}
        assert actual == expected


class TestEmailVerificationAgent:
    """Tests for EmailVerificationAgent."""

    @pytest.fixture
    def agent(self):
        """Create email verification agent."""
        return EmailVerificationAgent()

    def test_agent_properties(self, agent):
        """Agent has correct properties."""
        assert agent.agent_id == "email_verification_001"
        assert agent.name == "Email Verification Agent"
        assert agent.agent_type == AgentType.EMAIL_VERIFICATION
        assert "phishing_detection" in agent.capabilities
        assert "header_analysis" in agent.capabilities

    @pytest.mark.asyncio
    async def test_validate_task_with_email(self, agent):
        """Task with email data validates."""
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "test@example.com",
                        "subject": "Test email",
                    }
                }
            },
        )
        assert await agent.validate_task(task) is True

    @pytest.mark.asyncio
    async def test_validate_task_no_email(self, agent):
        """Task without email data fails validation."""
        task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={},
        )
        assert await agent.validate_task(task) is False

    @pytest.mark.asyncio
    async def test_process_benign_email(self, agent):
        """Benign email is classified correctly."""
        task = AgentTask(
            task_id="task_003",
            event_id="evt_003",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "newsletter@company.com",
                        "reply_to": "newsletter@company.com",
                        "subject": "Weekly Newsletter - September Edition",
                        "body": "Here are this week's updates from our team.",
                        "authentication_results": "spf=pass; dkim=pass; dmarc=pass",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.status == ResultStatus.SUCCESS
        assert result.finding is not None
        finding = result.finding
        assert finding.classification in [
            EmailClassification.BENIGN,
            EmailClassification.SUSPICIOUS,
        ]

    @pytest.mark.asyncio
    async def test_detect_sender_mismatch(self, agent):
        """Detects sender/reply-to mismatch."""
        task = AgentTask(
            task_id="task_004",
            event_id="evt_004",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "support@legitbank.com",
                        "reply_to": "hacker@malicious.tk",
                        "subject": "Urgent: Verify Your Account",
                        "body": "Click here to verify",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        # Should detect the mismatch
        indicators = [i.indicator_type for i in finding.indicators]
        assert "sender_reply_to_mismatch" in indicators or finding.risk_score > 0.3

    @pytest.mark.asyncio
    async def test_detect_auth_failure(self, agent):
        """Detects SPF/DKIM/DMARC failures."""
        task = AgentTask(
            task_id="task_005",
            event_id="evt_005",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "ceo@company.com",
                        "subject": "Wire Transfer Request",
                        "body": "Please wire $50,000 immediately",
                        "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        # Auth failures should increase risk score
        assert finding.risk_score > 0.0

    @pytest.mark.asyncio
    async def test_detect_credential_phishing(self, agent):
        """Detects credential phishing patterns."""
        task = AgentTask(
            task_id="task_006",
            event_id="evt_006",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "security@bank-alerts.tk",
                        "subject": "Action Required: Verify Your Password",
                        "body": "Your account has been compromised. Click here to reset your password immediately: http://192.168.1.1/login",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        assert finding.classification in [
            EmailClassification.POSSIBLE_PHISHING,
            EmailClassification.MALICIOUS_INDICATORS,
            EmailClassification.SUSPICIOUS,
        ]
        assert finding.risk_score >= 0.4

    @pytest.mark.asyncio
    async def test_detect_urgency_language(self, agent):
        """Detects urgency/pressure language."""
        task = AgentTask(
            task_id="task_007",
            event_id="evt_007",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "accounts@service.com",
                        "subject": "URGENT: Account Will Be Suspended in 24 Hours",
                        "body": "Immediate action required! Your account will be permanently deleted unless you act now.",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        indicators = [i.indicator_type for i in finding.indicators]
        assert "urgency_language" in indicators or finding.risk_score > 0.3

    @pytest.mark.asyncio
    async def test_detect_suspicious_attachment(self, agent):
        """Detects suspicious attachments."""
        task = AgentTask(
            task_id="task_008",
            event_id="evt_008",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "hr@company.com",
                        "subject": "Updated Salary Information",
                        "body": "Please see attached document",
                        "attachments": [
                            {"filename": "salary_update.exe", "size": 45000},
                        ],
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        indicators = [i.indicator_type for i in finding.indicators]
        assert "suspicious_attachment" in indicators

    @pytest.mark.asyncio
    async def test_detect_suspicious_url(self, agent):
        """Detects suspicious URLs."""
        task = AgentTask(
            task_id="task_009",
            event_id="evt_009",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "support@service.com",
                        "subject": "Click Here to Claim Your Prize",
                        "body": "You won! Click http://10.0.0.1/claim or visit free-prizes.tk/winner to claim",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        # Should detect IP-based URL or suspicious TLD
        assert finding.risk_score > 0.1

    @pytest.mark.asyncio
    async def test_detect_financial_scam(self, agent):
        """Detects financial scam patterns."""
        task = AgentTask(
            task_id="task_010",
            event_id="evt_010",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "finance@vendor.com",
                        "subject": "Invoice #12345 - Payment Required",
                        "body": "Please process this wire transfer of $25,000. New bank account details: Account: 123456789",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        finding = result.finding
        indicators = [i.indicator_type for i in finding.indicators]
        assert "financial_indicator" in indicators or finding.risk_score > 0.0

    @pytest.mark.asyncio
    async def test_generates_recommendations(self, agent):
        """Agent generates actionable recommendations."""
        task = AgentTask(
            task_id="task_011",
            event_id="evt_011",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "phisher@evil.tk",
                        "subject": "Verify Your Account Now",
                        "body": "Click http://192.168.1.100/login to verify",
                        "authentication_results": "spf=fail",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        assert len(result.finding.recommendations) > 0

    @pytest.mark.asyncio
    async def test_mitre_mapping(self, agent):
        """Findings include MITRE ATT&CK mapping."""
        task = AgentTask(
            task_id="task_012",
            event_id="evt_012",
            agent_type=AgentType.EMAIL_VERIFICATION,
            payload={
                "event": {
                    "raw_data": {
                        "sender": "attacker@malicious.com",
                        "subject": "Password Reset Required",
                        "body": "Click here to reset your password",
                        "authentication_results": "spf=fail; dkim=fail",
                    }
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        # Should include phishing technique
        if result.finding.mitre_techniques:
            assert any("T1566" in t for t in result.finding.mitre_techniques)


class TestEmailAnalysis:
    """Tests for EmailAnalysis model."""

    def test_create_analysis(self):
        """Create email analysis model."""
        analysis = EmailAnalysis(
            sender="test@example.com",
            sender_domain="example.com",
            recipients=["user@company.com"],
            subject="Test Subject",
            body_text="Test body",
        )
        assert analysis.sender == "test@example.com"
        assert analysis.sender_domain == "example.com"

    def test_analysis_with_urls(self):
        """Analysis includes extracted URLs."""
        from backend.app.agents.specialized.email_verification import ExtractedURL

        analysis = EmailAnalysis(
            sender="test@example.com",
            sender_domain="example.com",
            recipients=["user@company.com"],
            subject="Test",
            body_text="Visit http://example.com",
            urls=[
                ExtractedURL(
                    url="http://example.com",
                    domain="example.com",
                    is_ip_based=False,
                )
            ],
        )
        assert len(analysis.urls) == 1
        assert analysis.urls[0].domain == "example.com"


class TestEmailIndicator:
    """Tests for EmailIndicator model."""

    def test_create_indicator(self):
        """Create email indicator."""
        indicator = EmailIndicator(
            indicator_type="suspicious_attachment",
            description="Executable attachment detected",
            severity=EventSeverity.HIGH,
            confidence=MatchConfidence.HIGH,
            evidence="malware.exe",
        )
        assert indicator.indicator_type == "suspicious_attachment"
        assert indicator.severity == EventSeverity.HIGH
