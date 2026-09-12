"""Tests for AI Investigation Engine."""

import pytest

from backend.app.investigation import (
    AIInvestigationEngine,
    EvidenceType,
    HypothesisStatus,
    InvestigationPriority,
    InvestigationStatus,
    get_investigation_engine,
)


class TestAIInvestigationEngine:
    """Tests for AIInvestigationEngine."""

    @pytest.fixture
    def engine(self) -> AIInvestigationEngine:
        return AIInvestigationEngine()

    def test_create_investigation(self, engine: AIInvestigationEngine) -> None:
        """Test investigation creation."""
        investigation = engine.create_investigation(
            title="Phishing Investigation",
            description="Investigating reported phishing emails",
            priority=InvestigationPriority.HIGH,
        )

        assert investigation.investigation_id.startswith("inv_")
        assert investigation.title == "Phishing Investigation"
        assert investigation.status == InvestigationStatus.PENDING
        assert investigation.priority == InvestigationPriority.HIGH

    def test_create_investigation_from_template(
        self, engine: AIInvestigationEngine
    ) -> None:
        """Test creating investigation from template."""
        investigation = engine.create_investigation(
            title="Test",
            template="phishing",
        )

        assert investigation.title == "Phishing Investigation"
        assert len(investigation.steps) > 0
        assert len(investigation.hypotheses) > 0

    def test_add_evidence(self, engine: AIInvestigationEngine) -> None:
        """Test adding evidence."""
        investigation = engine.create_investigation(title="Test")

        evidence = engine.add_evidence(
            investigation.investigation_id,
            evidence_type=EvidenceType.LOG_ENTRY,
            source="email_gateway",
            content={"message": "Blocked suspicious email"},
            relevance_score=0.9,
        )

        assert evidence.evidence_id.startswith("evd_")
        assert evidence.evidence_type == EvidenceType.LOG_ENTRY
        assert len(investigation.evidence) == 1

    def test_add_hypothesis(self, engine: AIInvestigationEngine) -> None:
        """Test adding hypothesis."""
        investigation = engine.create_investigation(title="Test")

        hypothesis = engine.add_hypothesis(
            investigation.investigation_id,
            statement="Credentials were compromised via fake login page",
            reasoning="Users reported entering credentials on linked page",
        )

        assert hypothesis.hypothesis_id.startswith("hyp_")
        assert hypothesis.status == HypothesisStatus.PROPOSED
        assert len(investigation.hypotheses) == 1

    def test_update_hypothesis(self, engine: AIInvestigationEngine) -> None:
        """Test updating hypothesis."""
        investigation = engine.create_investigation(title="Test")

        hypothesis = engine.add_hypothesis(
            investigation.investigation_id,
            statement="Test hypothesis",
        )

        updated = engine.update_hypothesis(
            investigation.investigation_id,
            hypothesis.hypothesis_id,
            status=HypothesisStatus.SUPPORTED,
            confidence=0.85,
        )

        assert updated is not None
        assert updated.status == HypothesisStatus.SUPPORTED
        assert updated.confidence == 0.85

    def test_complete_step(self, engine: AIInvestigationEngine) -> None:
        """Test completing investigation step."""
        investigation = engine.create_investigation(
            title="Test",
            template="phishing",
        )

        step = investigation.steps[0]
        completed = engine.complete_step(
            investigation.investigation_id,
            step.step_id,
            findings="Identified 10 recipients of phishing email",
        )

        assert completed is not None
        assert completed.status == "completed"
        assert completed.completed_at is not None

    def test_generate_timeline(self, engine: AIInvestigationEngine) -> None:
        """Test timeline generation."""
        investigation = engine.create_investigation(title="Test")

        # Add some evidence
        engine.add_evidence(
            investigation.investigation_id,
            evidence_type=EvidenceType.ALERT,
            source="siem",
            content={"alert_name": "Suspicious login"},
        )

        engine.add_evidence(
            investigation.investigation_id,
            evidence_type=EvidenceType.LOG_ENTRY,
            source="auth_logs",
            content={"message": "Failed login attempt"},
        )

        timeline = engine.generate_timeline(investigation.investigation_id)

        assert len(timeline) == 2
        assert all("timestamp" in entry for entry in timeline)

    def test_analyze_investigation(self, engine: AIInvestigationEngine) -> None:
        """Test investigation analysis."""
        investigation = engine.create_investigation(
            title="Test",
            template="phishing",
        )

        # Add evidence
        engine.add_evidence(
            investigation.investigation_id,
            evidence_type=EvidenceType.LOG_ENTRY,
            source="test",
            content={},
        )

        analysis = engine.analyze_investigation(investigation.investigation_id)

        assert "investigation_id" in analysis
        assert "evidence_count" in analysis
        assert "progress_pct" in analysis

    def test_generate_summary(self, engine: AIInvestigationEngine) -> None:
        """Test summary generation."""
        investigation = engine.create_investigation(
            title="Test Investigation",
            template="phishing",
        )

        summary = engine.generate_summary(investigation.investigation_id)

        assert "Test Investigation" in summary or "Phishing" in summary
        assert "Status:" in summary

    def test_close_investigation(self, engine: AIInvestigationEngine) -> None:
        """Test closing investigation."""
        investigation = engine.create_investigation(title="Test")

        closed = engine.close_investigation(
            investigation.investigation_id,
            findings_summary="Confirmed phishing attack targeting 5 users",
            root_cause="Compromised vendor email account",
            recommendations=["Implement MFA", "Block sender domain"],
        )

        assert closed is not None
        assert closed.status == InvestigationStatus.CLOSED
        assert closed.closed_at is not None
        assert len(closed.recommendations) == 2

    def test_list_investigations(self, engine: AIInvestigationEngine) -> None:
        """Test listing investigations."""
        engine.create_investigation(title="Inv 1", priority=InvestigationPriority.HIGH)
        engine.create_investigation(title="Inv 2", priority=InvestigationPriority.MEDIUM)

        investigations = engine.list_investigations()
        assert len(investigations) == 2

    def test_list_investigations_filtered(self, engine: AIInvestigationEngine) -> None:
        """Test filtering investigations."""
        engine.create_investigation(title="High", priority=InvestigationPriority.HIGH)
        engine.create_investigation(title="Low", priority=InvestigationPriority.LOW)

        high_priority = engine.list_investigations(priority=InvestigationPriority.HIGH)
        assert len(high_priority) == 1

    def test_get_metrics(self, engine: AIInvestigationEngine) -> None:
        """Test getting metrics."""
        engine.create_investigation(title="Test")

        metrics = engine.get_metrics()

        assert "total_investigations" in metrics
        assert metrics["total_investigations"] >= 1


class TestInvestigationEngineSingleton:
    """Test singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """Singleton should return same instance."""
        import backend.app.investigation as investigation_module
        investigation_module._engine = None

        e1 = get_investigation_engine()
        e2 = get_investigation_engine()
        assert e1 is e2
