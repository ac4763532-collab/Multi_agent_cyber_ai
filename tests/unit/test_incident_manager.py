"""Tests for Incident Management System."""

import pytest

from backend.app.incidents import (
    IncidentManager,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    get_incident_manager,
)


class TestIncidentManager:
    """Tests for IncidentManager."""

    @pytest.fixture
    def manager(self) -> IncidentManager:
        return IncidentManager()

    def test_create_incident(self, manager: IncidentManager) -> None:
        """Test incident creation."""
        incident = manager.create_incident(
            title="Phishing Campaign",
            severity=IncidentSeverity.HIGH,
            incident_type=IncidentType.PHISHING,
            description="Multiple phishing emails detected",
        )

        assert incident.incident_id.startswith("INC-")
        assert incident.title == "Phishing Campaign"
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.status == IncidentStatus.NEW
        assert len(incident.timeline) == 1  # Creation event

    def test_get_incident(self, manager: IncidentManager) -> None:
        """Test getting incident by ID."""
        incident = manager.create_incident(
            title="Test Incident",
            severity=IncidentSeverity.MEDIUM,
        )

        retrieved = manager.get_incident(incident.incident_id)
        assert retrieved is not None
        assert retrieved.incident_id == incident.incident_id

    def test_update_status(self, manager: IncidentManager) -> None:
        """Test updating incident status."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
        )

        updated = manager.update_status(
            incident.incident_id,
            IncidentStatus.INVESTIGATING,
            actor="analyst@test.com",
        )

        assert updated is not None
        assert updated.status == IncidentStatus.INVESTIGATING
        assert len(updated.timeline) == 2  # Creation + status change

    def test_assign_incident(self, manager: IncidentManager) -> None:
        """Test assigning incident."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.MEDIUM,
        )

        assigned = manager.assign_incident(
            incident.incident_id,
            owner="ir-lead@test.com",
            team="SOC Team",
        )

        assert assigned is not None
        assert assigned.owner == "ir-lead@test.com"
        assert assigned.assigned_team == "SOC Team"

    def test_add_comment(self, manager: IncidentManager) -> None:
        """Test adding comment to incident."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.MEDIUM,
        )

        comment = manager.add_comment(
            incident.incident_id,
            author="analyst@test.com",
            content="Investigation started",
        )

        assert comment is not None
        assert comment.author == "analyst@test.com"
        assert len(incident.comments) == 1

    def test_add_task(self, manager: IncidentManager) -> None:
        """Test adding task to incident."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.HIGH,
        )

        task = manager.add_task(
            incident.incident_id,
            title="Block malicious IP",
            assigned_to="admin@test.com",
        )

        assert task is not None
        assert task.title == "Block malicious IP"
        assert len(incident.tasks) == 1

    def test_complete_task(self, manager: IncidentManager) -> None:
        """Test completing a task."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.MEDIUM,
        )

        task = manager.add_task(
            incident.incident_id,
            title="Test Task",
        )

        completed = manager.complete_task(incident.incident_id, task.task_id)

        assert completed is not None
        assert completed.status == "completed"
        assert completed.completed_at is not None

    def test_add_artifact(self, manager: IncidentManager) -> None:
        """Test adding artifact to incident."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.MEDIUM,
        )

        artifact = manager.add_artifact(
            incident.incident_id,
            name="email_sample.eml",
            artifact_type="email",
            uploaded_by="analyst@test.com",
        )

        assert artifact is not None
        assert artifact.name == "email_sample.eml"
        assert len(incident.artifacts) == 1

    def test_close_incident(self, manager: IncidentManager) -> None:
        """Test closing incident."""
        incident = manager.create_incident(
            title="Test",
            severity=IncidentSeverity.MEDIUM,
        )

        closed = manager.close_incident(
            incident.incident_id,
            root_cause="Compromised vendor account",
            lessons_learned="Implement additional email filters",
        )

        assert closed is not None
        assert closed.status == IncidentStatus.CLOSED
        assert closed.root_cause == "Compromised vendor account"
        assert closed.closed_at is not None
        assert closed.time_to_resolve_minutes is not None

    def test_list_incidents(self, manager: IncidentManager) -> None:
        """Test listing incidents."""
        manager.create_incident(title="Incident 1", severity=IncidentSeverity.HIGH)
        manager.create_incident(title="Incident 2", severity=IncidentSeverity.MEDIUM)
        manager.create_incident(title="Incident 3", severity=IncidentSeverity.LOW)

        incidents = manager.list_incidents()
        assert len(incidents) == 3

    def test_list_incidents_filtered(self, manager: IncidentManager) -> None:
        """Test filtering incidents."""
        manager.create_incident(title="High 1", severity=IncidentSeverity.HIGH)
        manager.create_incident(title="High 2", severity=IncidentSeverity.HIGH)
        manager.create_incident(title="Medium", severity=IncidentSeverity.MEDIUM)

        high_incidents = manager.list_incidents(severity=IncidentSeverity.HIGH)
        assert len(high_incidents) == 2

    def test_get_metrics(self, manager: IncidentManager) -> None:
        """Test getting metrics."""
        manager.create_incident(title="Test 1", severity=IncidentSeverity.HIGH)
        manager.create_incident(title="Test 2", severity=IncidentSeverity.MEDIUM)

        metrics = manager.get_metrics()

        assert metrics.total_incidents == 2
        assert metrics.open_incidents == 2
        assert "high" in metrics.by_severity


class TestIncidentManagerSingleton:
    """Test singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """Singleton should return same instance."""
        import backend.app.incidents as incidents_module

        incidents_module._incident_manager = None

        m1 = get_incident_manager()
        m2 = get_incident_manager()
        assert m1 is m2
