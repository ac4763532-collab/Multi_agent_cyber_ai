"""Task routing logic for dispatching events to appropriate agents."""

from collections.abc import Callable
from typing import Any

from backend.app.agents.exceptions import TaskRoutingError
from backend.app.agents.models import AgentType, TaskPriority
from backend.app.core.logging import get_logger
from backend.app.schemas.events import EventSeverity, SecurityEvent

logger = get_logger("cyber_ai.agents.dispatcher.router")


class RoutingRule:
    """Single routing rule that maps event characteristics to an agent type."""

    def __init__(
        self,
        name: str,
        agent_type: AgentType,
        priority: int = 0,
        source_types: list[str] | None = None,
        event_types: list[str] | None = None,
        required_fields: list[str] | None = None,
        condition: Callable[[SecurityEvent], bool] | None = None,
    ) -> None:
        """Initialize routing rule.

        Args:
            name: Human-readable rule name.
            agent_type: Target agent type for matching events.
            priority: Rule priority (higher = checked first).
            source_types: List of matching source_type values.
            event_types: List of matching event_type values.
            required_fields: Fields that must be present.
            condition: Optional callable for custom matching logic.
        """
        self.name = name
        self.agent_type = agent_type
        self.priority = priority
        self.source_types = set(source_types or [])
        self.event_types = set(event_types or [])
        self.required_fields = set(required_fields or [])
        self.condition = condition

    def matches(self, event: SecurityEvent) -> bool:
        """Check if this rule matches the given event.

        Args:
            event: SecurityEvent to evaluate.

        Returns:
            True if rule matches, False otherwise.
        """
        # Check source_type match
        if self.source_types and event.source_type not in self.source_types:
            return False

        # Check event_type match
        if self.event_types and event.event_type not in self.event_types:
            return False

        # Check required fields
        for field in self.required_fields:
            value = getattr(event, field, None)
            if value is None:
                # Also check in metadata
                if field not in event.metadata:
                    return False

        # Check custom condition
        if self.condition and not self.condition(event):
            return False

        return True


class TaskRouter:
    """Routes security events to appropriate agents based on event characteristics.

    Implements the routing table defined in the project architecture:
    - Email events → EmailVerificationAgent
    - Authentication logs → LogAnalyzerAgent
    - Network IDS events → NetworkThreatAgent
    - CIDR requests → IPRangeAnalyzerAgent
    - Vulnerability findings → VulnerabilityAgent
    - IoC matches → ThreatIntelligenceAgent
    - Multiple findings → CorrelationAgent
    - Strong incidents → InvestigationAgent
    """

    def __init__(self) -> None:
        """Initialize router with default routing rules."""
        self._rules: list[RoutingRule] = []
        self._register_default_rules()

    def _register_default_rules(self) -> None:
        """Register the default routing rules."""
        # Email events → EmailVerificationAgent
        self.add_rule(
            RoutingRule(
                name="email_events",
                agent_type=AgentType.EMAIL_VERIFICATION,
                priority=100,
                source_types=["email", "email_gateway", "email_security"],
                event_types=[
                    "email_received",
                    "email_scan",
                    "phishing_alert",
                    "spam_detected",
                    "email_security_event",
                ],
            )
        )

        # Authentication/security logs → LogAnalyzerAgent
        self.add_rule(
            RoutingRule(
                name="auth_logs",
                agent_type=AgentType.LOG_ANALYZER,
                priority=90,
                source_types=["authentication", "syslog", "windows_security"],
                event_types=[
                    "auth_failed",
                    "auth_success",
                    "login_attempt",
                    "logout",
                    "session_created",
                    "session_terminated",
                    "privilege_escalation",
                    "sudo_command",
                    "account_lockout",
                ],
            )
        )

        # Network IDS events (Suricata) → NetworkThreatAgent
        self.add_rule(
            RoutingRule(
                name="network_ids",
                agent_type=AgentType.NETWORK_THREAT,
                priority=95,
                source_types=["suricata", "ids", "nids", "network_security"],
                event_types=[
                    "alert",
                    "ids_alert",
                    "intrusion_detected",
                    "network_anomaly",
                    "port_scan",
                    "c2_communication",
                ],
            )
        )

        # IP/CIDR analysis requests → IPRangeAnalyzerAgent
        self.add_rule(
            RoutingRule(
                name="ip_analysis",
                agent_type=AgentType.IP_RANGE_ANALYZER,
                priority=70,
                event_types=["cidr_request", "ip_analysis_request", "network_scan"],
                required_fields=["source_ip"],
                condition=lambda e: _has_cidr_context(e),
            )
        )

        # Vulnerability findings → VulnerabilityAgent
        self.add_rule(
            RoutingRule(
                name="vulnerability",
                agent_type=AgentType.VULNERABILITY,
                priority=85,
                source_types=["vulnerability_scanner", "cve_feed", "nessus", "qualys"],
                event_types=[
                    "vulnerability_found",
                    "cve_detected",
                    "vulnerability_scan_result",
                    "security_advisory",
                ],
            )
        )

        # IoC matches → ThreatIntelligenceAgent
        self.add_rule(
            RoutingRule(
                name="ioc_match",
                agent_type=AgentType.THREAT_INTELLIGENCE,
                priority=92,
                event_types=[
                    "ioc_match",
                    "threat_indicator",
                    "malware_detected",
                    "hash_match",
                    "domain_blocklist_hit",
                    "ip_blocklist_hit",
                ],
                condition=lambda e: _has_ioc_indicators(e),
            )
        )

        # Multiple related findings → CorrelationAgent
        self.add_rule(
            RoutingRule(
                name="correlation",
                agent_type=AgentType.CORRELATION,
                priority=60,
                event_types=[
                    "correlated_events",
                    "attack_chain",
                    "multi_stage_attack",
                ],
                condition=lambda e: _has_correlation_context(e),
            )
        )

        # Strong incidents → InvestigationAgent
        self.add_rule(
            RoutingRule(
                name="investigation",
                agent_type=AgentType.INVESTIGATION,
                priority=50,
                event_types=[
                    "incident_created",
                    "high_severity_alert",
                    "confirmed_breach",
                    "data_exfiltration",
                ],
                condition=lambda e: _is_high_severity_incident(e),
            )
        )

        # Application logs → LogAnalyzerAgent (lower priority fallback)
        self.add_rule(
            RoutingRule(
                name="application_logs",
                agent_type=AgentType.LOG_ANALYZER,
                priority=40,
                source_types=["application", "json"],
                event_types=[
                    "error",
                    "warning",
                    "access_log",
                    "application_event",
                ],
            )
        )

        # Sort rules by priority (highest first)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def add_rule(self, rule: RoutingRule) -> None:
        """Add a routing rule and re-sort by priority.

        Args:
            rule: RoutingRule to add.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, name: str) -> bool:
        """Remove a routing rule by name.

        Args:
            name: Name of rule to remove.

        Returns:
            True if rule was removed, False if not found.
        """
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                del self._rules[i]
                return True
        return False

    def route(self, event: SecurityEvent) -> AgentType:
        """Determine the appropriate agent type for an event.

        Args:
            event: SecurityEvent to route.

        Returns:
            AgentType that should handle the event.

        Raises:
            TaskRoutingError: If no matching rule is found.
        """
        for rule in self._rules:
            if rule.matches(event):
                logger.debug(
                    "Event %s matched rule '%s' → %s",
                    event.event_id,
                    rule.name,
                    rule.agent_type.value,
                )
                return rule.agent_type

        # No matching rule - use default based on source_type
        default_agent = self._get_default_agent(event)
        if default_agent:
            logger.debug(
                "Event %s using default agent for source_type '%s' → %s",
                event.event_id,
                event.source_type,
                default_agent.value,
            )
            return default_agent

        raise TaskRoutingError(
            message=f"No routing rule matches event {event.event_id}",
            event_id=event.event_id,
            event_type=event.event_type,
        )

    def _get_default_agent(self, event: SecurityEvent) -> AgentType | None:
        """Get default agent based on source_type when no rule matches.

        Args:
            event: SecurityEvent to analyze.

        Returns:
            Default AgentType or None if no default applies.
        """
        source_defaults: dict[str, AgentType] = {
            "email": AgentType.EMAIL_VERIFICATION,
            "authentication": AgentType.LOG_ANALYZER,
            "syslog": AgentType.LOG_ANALYZER,
            "suricata": AgentType.NETWORK_THREAT,
            "application": AgentType.LOG_ANALYZER,
            "json": AgentType.LOG_ANALYZER,
        }
        return source_defaults.get(event.source_type)

    def get_priority(self, event: SecurityEvent) -> TaskPriority:
        """Determine task priority based on event characteristics.

        Args:
            event: SecurityEvent to analyze.

        Returns:
            TaskPriority for the event.
        """
        # Map severity to priority
        priority = TaskPriority.from_severity(event.severity)

        # Boost priority for certain event types
        high_priority_types = {
            "malware_detected",
            "data_exfiltration",
            "confirmed_breach",
            "ransomware",
            "c2_communication",
        }

        if event.event_type in high_priority_types:
            if priority == TaskPriority.MEDIUM:
                priority = TaskPriority.HIGH
            elif priority == TaskPriority.LOW:
                priority = TaskPriority.MEDIUM

        return priority

    def list_rules(self) -> list[dict[str, Any]]:
        """List all registered routing rules.

        Returns:
            List of rule summaries.
        """
        return [
            {
                "name": rule.name,
                "agent_type": rule.agent_type.value,
                "priority": rule.priority,
                "source_types": list(rule.source_types),
                "event_types": list(rule.event_types),
            }
            for rule in self._rules
        ]


# Helper functions for conditional routing
def _has_cidr_context(event: SecurityEvent) -> bool:
    """Check if event has CIDR/IP range analysis context."""
    metadata = event.metadata or {}
    return (
        "cidr" in metadata
        or "ip_range" in metadata
        or event.event_type in ("cidr_request", "network_scan")
    )


def _has_ioc_indicators(event: SecurityEvent) -> bool:
    """Check if event contains IoC match indicators."""
    metadata = event.metadata or {}
    return (
        "ioc_type" in metadata
        or "threat_indicator" in metadata
        or "matched_ioc" in metadata
        or event.hash is not None
    )


def _has_correlation_context(event: SecurityEvent) -> bool:
    """Check if event should be sent to correlation engine."""
    metadata = event.metadata or {}
    return (
        "related_events" in metadata
        or "correlation_id" in metadata
        or metadata.get("finding_count", 0) > 1
    )


def _is_high_severity_incident(event: SecurityEvent) -> bool:
    """Check if event represents a high-severity incident."""
    return event.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)


# Singleton instance
_router: TaskRouter | None = None


def get_task_router() -> TaskRouter:
    """Return singleton TaskRouter instance."""
    global _router
    if _router is None:
        _router = TaskRouter()
    return _router
