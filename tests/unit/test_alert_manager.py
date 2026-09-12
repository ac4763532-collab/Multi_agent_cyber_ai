"""Tests for Alert Manager."""

import pytest

from backend.app.alerting import (
    Alert,
    AlertCategory,
    AlertManager,
    AlertPrioritizer,
    AlertSeverity,
    AlertStatus,
    get_alert_manager,
)


class TestAlertManager:
    """Tests for AlertManager."""

    @pytest.fixture
    def manager(self) -> AlertManager:
        return AlertManager()

    def test_create_alert(self, manager: AlertManager) -> None:
        """Test alert creation."""
        alert = manager.create_alert(
            title="Test Alert",
            severity=AlertSeverity.HIGH,
            category=AlertCategory.MALWARE,
            description="Test description",
        )

        assert alert.alert_id.startswith("alert_")
        assert alert.title == "Test Alert"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.status == AlertStatus.NEW

    def test_get_alert(self, manager: AlertManager) -> None:
        """Test getting alert by ID."""
        alert = manager.create_alert(title="Test", severity=AlertSeverity.MEDIUM)

        retrieved = manager.get_alert(alert.alert_id)
        assert retrieved is not None
        assert retrieved.alert_id == alert.alert_id

    def test_get_nonexistent_alert(self, manager: AlertManager) -> None:
        """Test getting non-existent alert."""
        result = manager.get_alert("nonexistent")
        assert result is None

    def test_update_alert(self, manager: AlertManager) -> None:
        """Test updating alert."""
        alert = manager.create_alert(title="Test", severity=AlertSeverity.MEDIUM)

        updated = manager.update_alert(
            alert.alert_id,
            status=AlertStatus.IN_PROGRESS,
            assigned_to="analyst@test.com",
        )

        assert updated is not None
        assert updated.status == AlertStatus.IN_PROGRESS
        assert updated.assigned_to == "analyst@test.com"

    def test_acknowledge_alert(self, manager: AlertManager) -> None:
        """Test acknowledging alert."""
        alert = manager.create_alert(title="Test", severity=AlertSeverity.HIGH)

        acked = manager.acknowledge_alert(alert.alert_id, "analyst@test.com")

        assert acked is not None
        assert acked.status == AlertStatus.ACKNOWLEDGED
        assert acked.acknowledged_by == "analyst@test.com"
        assert acked.acknowledged_at is not None

    def test_resolve_alert(self, manager: AlertManager) -> None:
        """Test resolving alert."""
        alert = manager.create_alert(title="Test", severity=AlertSeverity.MEDIUM)

        resolved = manager.resolve_alert(
            alert.alert_id,
            resolved_by="analyst@test.com",
            resolution_notes="Issue fixed",
        )

        assert resolved is not None
        assert resolved.status == AlertStatus.RESOLVED
        assert resolved.resolved_by == "analyst@test.com"
        assert resolved.resolved_at is not None

    def test_resolve_alert_as_false_positive(self, manager: AlertManager) -> None:
        """Test marking alert as false positive."""
        alert = manager.create_alert(title="Test", severity=AlertSeverity.LOW)

        resolved = manager.resolve_alert(
            alert.alert_id,
            resolved_by="analyst@test.com",
            is_false_positive=True,
        )

        assert resolved is not None
        assert resolved.status == AlertStatus.FALSE_POSITIVE

    def test_list_alerts(self, manager: AlertManager) -> None:
        """Test listing alerts."""
        manager.create_alert(title="Alert 1", severity=AlertSeverity.HIGH)
        manager.create_alert(title="Alert 2", severity=AlertSeverity.MEDIUM)
        manager.create_alert(title="Alert 3", severity=AlertSeverity.LOW)

        alerts = manager.list_alerts()
        assert len(alerts) == 3

    def test_list_alerts_filtered_by_severity(self, manager: AlertManager) -> None:
        """Test filtering alerts by severity."""
        manager.create_alert(title="High 1", severity=AlertSeverity.HIGH)
        manager.create_alert(title="High 2", severity=AlertSeverity.HIGH)
        manager.create_alert(title="Medium", severity=AlertSeverity.MEDIUM)

        high_alerts = manager.list_alerts(severity=AlertSeverity.HIGH)
        assert len(high_alerts) == 2

    def test_list_alerts_filtered_by_status(self, manager: AlertManager) -> None:
        """Test filtering alerts by status."""
        alert1 = manager.create_alert(title="Alert 1", severity=AlertSeverity.HIGH)
        manager.create_alert(title="Alert 2", severity=AlertSeverity.HIGH)

        manager.acknowledge_alert(alert1.alert_id, "analyst")

        new_alerts = manager.list_alerts(status=AlertStatus.NEW)
        assert len(new_alerts) == 1

    def test_get_alert_counts(self, manager: AlertManager) -> None:
        """Test getting alert counts."""
        manager.create_alert(title="High", severity=AlertSeverity.HIGH)
        manager.create_alert(title="High", severity=AlertSeverity.HIGH)
        manager.create_alert(title="Medium", severity=AlertSeverity.MEDIUM)

        counts = manager.get_alert_counts()

        assert counts["total"] == 3
        assert counts["by_severity"]["high"] == 2
        assert counts["by_severity"]["medium"] == 1

    def test_get_metrics(self, manager: AlertManager) -> None:
        """Test getting metrics."""
        manager.create_alert(title="Test", severity=AlertSeverity.MEDIUM)

        metrics = manager.get_metrics()

        assert "total_alerts" in metrics
        assert "total_created" in metrics
        assert metrics["total_alerts"] >= 1


class TestAlertPrioritizer:
    """Tests for AlertPrioritizer."""

    @pytest.fixture
    def prioritizer(self) -> AlertPrioritizer:
        return AlertPrioritizer()

    def test_calculate_priority_score(self, prioritizer: AlertPrioritizer) -> None:
        """Test priority score calculation."""
        alert = Alert(
            title="Critical Alert",
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.MALWARE,
            risk_score=0.9,
            confidence=0.95,
        )

        score = prioritizer.calculate_priority_score(alert)
        assert 0 <= score <= 1
        assert score > 0.5  # Critical should have high score

    def test_prioritize_alerts(self, prioritizer: AlertPrioritizer) -> None:
        """Test alert prioritization."""
        alerts = [
            Alert(
                title="Low", severity=AlertSeverity.LOW, category=AlertCategory.ANOMALY
            ),
            Alert(
                title="Critical",
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.MALWARE,
            ),
            Alert(
                title="Medium",
                severity=AlertSeverity.MEDIUM,
                category=AlertCategory.PHISHING,
            ),
        ]

        prioritized = prioritizer.prioritize_alerts(alerts)

        assert len(prioritized) == 3
        assert prioritized[0].title == "Critical"  # Critical should be first


class TestAlertManagerSingleton:
    """Test singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """Singleton should return same instance."""
        import backend.app.alerting as alerting_module

        alerting_module._alert_manager = None

        m1 = get_alert_manager()
        m2 = get_alert_manager()
        assert m1 is m2
