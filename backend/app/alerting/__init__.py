"""Real-Time Alerting System with WebSocket Support."""

import asyncio
import uuid
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(StrEnum):
    """Alert status values."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class AlertCategory(StrEnum):
    """Alert categories."""

    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    ANOMALY = "anomaly"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY = "vulnerability"
    SYSTEM = "system"


class Alert(BaseModel):
    """Security alert model."""

    alert_id: str = Field(default_factory=lambda: f"alert_{uuid.uuid4().hex[:12]}")
    title: str
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    category: AlertCategory = AlertCategory.ANOMALY
    source: str = ""
    source_type: str = ""
    event_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    investigation_id: str | None = None
    indicators: dict[str, Any] = Field(default_factory=dict)
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 0.0
    assigned_to: str | None = None
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_notes: str = ""
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlertRule(BaseModel):
    """Rule for generating alerts."""

    rule_id: str = Field(default_factory=lambda: f"rule_{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    enabled: bool = True
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: AlertCategory = AlertCategory.ANOMALY
    conditions: dict[str, Any] = Field(default_factory=dict)
    throttle_seconds: int = 300
    last_triggered: datetime | None = None
    trigger_count: int = 0


class AlertNotification(BaseModel):
    """Notification for alert delivery."""

    notification_id: str = Field(default_factory=lambda: f"notif_{uuid.uuid4().hex[:8]}")
    alert_id: str
    channel: str  # websocket, email, slack, webhook
    recipient: str
    status: str = "pending"
    sent_at: datetime | None = None
    error: str | None = None


class WebSocketMessage(BaseModel):
    """WebSocket message format."""

    message_type: str  # alert, update, ack, heartbeat
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)


# Alert handlers type
AlertHandler = Callable[[Alert], None]


class AlertManager:
    """Manages alerts and notifications."""

    def __init__(self):
        self._alerts: dict[str, Alert] = {}
        self._rules: dict[str, AlertRule] = {}
        self._handlers: list[AlertHandler] = []
        self._websocket_clients: set[str] = set()
        self._notification_queue: asyncio.Queue[AlertNotification] = asyncio.Queue()
        self._alert_count = 0

    def create_alert(
        self,
        title: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        category: AlertCategory = AlertCategory.ANOMALY,
        description: str = "",
        source: str = "",
        event_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
        indicators: dict[str, Any] | None = None,
        affected_assets: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
        risk_score: float = 0.0,
        confidence: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> Alert:
        """Create a new alert."""
        alert = Alert(
            title=title,
            description=description,
            severity=severity,
            category=category,
            source=source,
            event_ids=event_ids or [],
            finding_ids=finding_ids or [],
            indicators=indicators or {},
            affected_assets=affected_assets or [],
            mitre_techniques=mitre_techniques or [],
            risk_score=risk_score,
            confidence=confidence,
            metadata=metadata or {},
        )

        self._alerts[alert.alert_id] = alert
        self._alert_count += 1

        # Notify handlers
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception:  # noqa: S110
                pass  # Log error in production

        return alert

    def get_alert(self, alert_id: str) -> Alert | None:
        """Get alert by ID."""
        return self._alerts.get(alert_id)

    def update_alert(
        self,
        alert_id: str,
        status: AlertStatus | None = None,
        assigned_to: str | None = None,
        tags: list[str] | None = None,
        resolution_notes: str | None = None,
    ) -> Alert | None:
        """Update an alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        if status is not None:
            alert.status = status
        if assigned_to is not None:
            alert.assigned_to = assigned_to
        if tags is not None:
            alert.tags = tags
        if resolution_notes is not None:
            alert.resolution_notes = resolution_notes

        alert.updated_at = utc_now()
        return alert

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> Alert | None:
        """Acknowledge an alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = utc_now()
        alert.updated_at = utc_now()

        return alert

    def resolve_alert(
        self,
        alert_id: str,
        resolved_by: str,
        resolution_notes: str = "",
        is_false_positive: bool = False,
    ) -> Alert | None:
        """Resolve an alert."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None

        alert.status = AlertStatus.FALSE_POSITIVE if is_false_positive else AlertStatus.RESOLVED
        alert.resolved_by = resolved_by
        alert.resolved_at = utc_now()
        alert.resolution_notes = resolution_notes
        alert.updated_at = utc_now()

        return alert

    def list_alerts(
        self,
        status: AlertStatus | None = None,
        severity: AlertSeverity | None = None,
        category: AlertCategory | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Alert]:
        """List alerts with filtering."""
        alerts = list(self._alerts.values())

        if status:
            alerts = [a for a in alerts if a.status == status]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if category:
            alerts = [a for a in alerts if a.category == category]

        # Sort by severity then creation time
        severity_order = {
            AlertSeverity.CRITICAL: 0,
            AlertSeverity.HIGH: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.LOW: 3,
            AlertSeverity.INFO: 4,
        }
        alerts.sort(key=lambda a: (severity_order.get(a.severity, 5), -a.created_at.timestamp()))

        return alerts[offset : offset + limit]

    def get_alert_counts(self) -> dict[str, int | dict[str, int]]:
        """Get alert counts by severity and status."""
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for alert in self._alerts.values():
            sev = alert.severity.value
            stat = alert.status.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_status[stat] = by_status.get(stat, 0) + 1

        return {
            "total": len(self._alerts),
            "by_severity": by_severity,
            "by_status": by_status,
        }

    def register_handler(self, handler: AlertHandler) -> None:
        """Register alert handler."""
        self._handlers.append(handler)

    def add_rule(self, rule: AlertRule) -> None:
        """Add alert rule."""
        self._rules[rule.rule_id] = rule

    def get_rules(self) -> list[AlertRule]:
        """Get all alert rules."""
        return list(self._rules.values())

    def register_websocket_client(self, client_id: str) -> None:
        """Register WebSocket client."""
        self._websocket_clients.add(client_id)

    def unregister_websocket_client(self, client_id: str) -> None:
        """Unregister WebSocket client."""
        self._websocket_clients.discard(client_id)

    def get_websocket_clients(self) -> set[str]:
        """Get registered WebSocket clients."""
        return self._websocket_clients.copy()

    async def queue_notification(self, notification: AlertNotification) -> None:
        """Queue notification for delivery."""
        await self._notification_queue.put(notification)

    def get_metrics(self) -> dict[str, Any]:
        """Get alerting metrics."""
        counts = self.get_alert_counts()
        return {
            "total_alerts": counts["total"],
            "alerts_by_severity": counts["by_severity"],
            "alerts_by_status": counts["by_status"],
            "active_rules": len([r for r in self._rules.values() if r.enabled]),
            "websocket_clients": len(self._websocket_clients),
            "total_created": self._alert_count,
        }


class AlertPrioritizer:
    """Prioritizes alerts based on risk and context."""

    # Severity weights
    SEVERITY_WEIGHTS = {
        AlertSeverity.CRITICAL: 1.0,
        AlertSeverity.HIGH: 0.8,
        AlertSeverity.MEDIUM: 0.5,
        AlertSeverity.LOW: 0.3,
        AlertSeverity.INFO: 0.1,
    }

    # Category risk multipliers
    CATEGORY_MULTIPLIERS = {
        AlertCategory.MALWARE: 1.2,
        AlertCategory.DATA_EXFILTRATION: 1.3,
        AlertCategory.INTRUSION: 1.2,
        AlertCategory.PHISHING: 1.0,
        AlertCategory.BRUTE_FORCE: 0.9,
        AlertCategory.ANOMALY: 0.8,
        AlertCategory.VULNERABILITY: 0.9,
        AlertCategory.POLICY_VIOLATION: 0.7,
        AlertCategory.SYSTEM: 0.6,
    }

    def calculate_priority_score(self, alert: Alert) -> float:
        """Calculate priority score for an alert."""
        # Base score from severity
        base_score = self.SEVERITY_WEIGHTS.get(alert.severity, 0.5)

        # Category multiplier
        category_mult = self.CATEGORY_MULTIPLIERS.get(alert.category, 1.0)

        # Risk score contribution
        risk_contribution = alert.risk_score * 0.3

        # Confidence adjustment
        confidence_adj = alert.confidence * 0.2

        # Asset criticality (simplified)
        asset_factor = min(len(alert.affected_assets) * 0.1, 0.3)

        # Calculate final score
        score = (base_score * category_mult) + risk_contribution + confidence_adj + asset_factor

        return min(score, 1.0)

    def prioritize_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """Sort alerts by priority score."""
        scored = [(alert, self.calculate_priority_score(alert)) for alert in alerts]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [alert for alert, _ in scored]


# Singleton instances
_alert_manager: AlertManager | None = None
_prioritizer: AlertPrioritizer | None = None


def get_alert_manager() -> AlertManager:
    """Get alert manager singleton."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


def get_alert_prioritizer() -> AlertPrioritizer:
    """Get alert prioritizer singleton."""
    global _prioritizer
    if _prioritizer is None:
        _prioritizer = AlertPrioritizer()
    return _prioritizer
