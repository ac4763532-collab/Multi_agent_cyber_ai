"""Response Recommendation Agent - automated response suggestions."""

import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.agents.base import BaseAgent
from backend.app.agents.models import (
    AgentResult,
    AgentTask,
    AgentType,
    BaseFinding,
    ResultStatus,
)
from backend.app.detection.models import MatchConfidence
from backend.app.schemas.events import EventSeverity
from backend.app.utils.datetime import utc_now


class ResponseType(StrEnum):
    """Types of response actions."""

    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    MONITORING = "monitoring"
    COMMUNICATION = "communication"
    EVIDENCE_PRESERVATION = "evidence_preservation"


class ResponseUrgency(StrEnum):
    """Urgency levels for response actions."""

    IMMEDIATE = "immediate"
    URGENT = "urgent"
    STANDARD = "standard"
    DEFERRED = "deferred"


class AutomationLevel(StrEnum):
    """Level of automation for response action."""

    FULLY_AUTOMATED = "fully_automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL = "manual"
    APPROVAL_REQUIRED = "approval_required"


class ResponseAction(BaseModel):
    """A recommended response action."""

    action_id: str
    action_type: ResponseType
    title: str
    description: str
    urgency: ResponseUrgency = ResponseUrgency.STANDARD
    automation_level: AutomationLevel = AutomationLevel.MANUAL
    target_type: str = ""  # host, user, network, application
    target_identifier: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    estimated_duration_minutes: int = 30
    potential_impact: str = ""
    rollback_procedure: str = ""
    soar_playbook_id: str | None = None
    execution_order: int = 0


class ResponsePlaybook(BaseModel):
    """Collection of response actions for an incident type."""

    playbook_id: str
    playbook_name: str
    incident_type: str
    actions: list[ResponseAction]
    total_estimated_duration: int  # minutes
    required_approvals: list[str] = Field(default_factory=list)


class ResponseFinding(BaseFinding):
    """Finding from response recommendation analysis."""

    recommended_actions: list[ResponseAction] = Field(default_factory=list)
    playbook: ResponsePlaybook | None = None
    containment_actions: list[ResponseAction] = Field(default_factory=list)
    eradication_actions: list[ResponseAction] = Field(default_factory=list)
    recovery_actions: list[ResponseAction] = Field(default_factory=list)
    total_actions: int = 0
    immediate_actions_count: int = 0
    automation_possible: bool = False
    estimated_response_time_minutes: int = 0


# Response action templates
CONTAINMENT_ACTIONS = {
    "isolate_host": ResponseAction(
        action_id="contain_001",
        action_type=ResponseType.CONTAINMENT,
        title="Isolate Affected Host",
        description="Isolate the compromised host from the network to prevent lateral movement",
        urgency=ResponseUrgency.IMMEDIATE,
        automation_level=AutomationLevel.SEMI_AUTOMATED,
        target_type="host",
        estimated_duration_minutes=5,
        potential_impact="Host will be offline and users cannot access it",
        rollback_procedure="Remove host from isolation VLAN and restore network access",
    ),
    "disable_user": ResponseAction(
        action_id="contain_002",
        action_type=ResponseType.CONTAINMENT,
        title="Disable Compromised User Account",
        description="Disable the user account to prevent further unauthorized access",
        urgency=ResponseUrgency.IMMEDIATE,
        automation_level=AutomationLevel.APPROVAL_REQUIRED,
        target_type="user",
        estimated_duration_minutes=2,
        potential_impact="User will be locked out of all systems",
        rollback_procedure="Re-enable account after credential reset and MFA enrollment",
    ),
    "block_ip": ResponseAction(
        action_id="contain_003",
        action_type=ResponseType.CONTAINMENT,
        title="Block Malicious IP Address",
        description="Add IP to firewall blocklist to prevent C2 communications",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.FULLY_AUTOMATED,
        target_type="network",
        estimated_duration_minutes=1,
        potential_impact="May affect legitimate traffic if IP is shared",
        rollback_procedure="Remove IP from firewall blocklist",
    ),
    "block_domain": ResponseAction(
        action_id="contain_004",
        action_type=ResponseType.CONTAINMENT,
        title="Block Malicious Domain",
        description="Block domain at DNS/proxy level",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.FULLY_AUTOMATED,
        target_type="network",
        estimated_duration_minutes=2,
        potential_impact="Traffic to domain will be blocked",
        rollback_procedure="Remove domain from blocklist",
    ),
    "quarantine_email": ResponseAction(
        action_id="contain_005",
        action_type=ResponseType.CONTAINMENT,
        title="Quarantine Phishing Emails",
        description="Remove phishing emails from all mailboxes",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.SEMI_AUTOMATED,
        target_type="application",
        estimated_duration_minutes=15,
        potential_impact="Users may lose access to legitimate emails if incorrectly identified",
        rollback_procedure="Restore emails from quarantine",
    ),
}

ERADICATION_ACTIONS = {
    "remove_malware": ResponseAction(
        action_id="erad_001",
        action_type=ResponseType.ERADICATION,
        title="Remove Malware",
        description="Run AV/EDR scan and remove identified malware",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.SEMI_AUTOMATED,
        target_type="host",
        estimated_duration_minutes=30,
        potential_impact="May require system restart",
        rollback_procedure="Restore from backup if removal causes issues",
    ),
    "reset_credentials": ResponseAction(
        action_id="erad_002",
        action_type=ResponseType.ERADICATION,
        title="Reset User Credentials",
        description="Force password reset and revoke active sessions",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.APPROVAL_REQUIRED,
        target_type="user",
        estimated_duration_minutes=10,
        potential_impact="User will need to set new password",
        rollback_procedure="N/A - credential reset is permanent",
    ),
    "patch_vulnerability": ResponseAction(
        action_id="erad_003",
        action_type=ResponseType.ERADICATION,
        title="Apply Security Patch",
        description="Apply patches to fix exploited vulnerability",
        urgency=ResponseUrgency.STANDARD,
        automation_level=AutomationLevel.MANUAL,
        target_type="host",
        estimated_duration_minutes=60,
        potential_impact="May require system restart and testing",
        rollback_procedure="Uninstall patch if compatibility issues arise",
    ),
    "remove_persistence": ResponseAction(
        action_id="erad_004",
        action_type=ResponseType.ERADICATION,
        title="Remove Persistence Mechanisms",
        description="Remove scheduled tasks, registry keys, and startup items",
        urgency=ResponseUrgency.URGENT,
        automation_level=AutomationLevel.MANUAL,
        target_type="host",
        estimated_duration_minutes=45,
        potential_impact="May affect legitimate scheduled tasks",
        rollback_procedure="Restore from documented baseline",
    ),
}

RECOVERY_ACTIONS = {
    "restore_backup": ResponseAction(
        action_id="recov_001",
        action_type=ResponseType.RECOVERY,
        title="Restore from Backup",
        description="Restore affected systems from clean backup",
        urgency=ResponseUrgency.STANDARD,
        automation_level=AutomationLevel.MANUAL,
        target_type="host",
        estimated_duration_minutes=120,
        potential_impact="Data created after backup will be lost",
        rollback_procedure="Re-image if restoration fails",
    ),
    "reimage_host": ResponseAction(
        action_id="recov_002",
        action_type=ResponseType.RECOVERY,
        title="Reimage Affected Host",
        description="Completely reimage the compromised host",
        urgency=ResponseUrgency.STANDARD,
        automation_level=AutomationLevel.MANUAL,
        target_type="host",
        estimated_duration_minutes=180,
        potential_impact="All data on host will be lost",
        rollback_procedure="N/A - full reimage",
    ),
    "restore_service": ResponseAction(
        action_id="recov_003",
        action_type=ResponseType.RECOVERY,
        title="Restore Network Access",
        description="Remove containment measures and restore normal access",
        urgency=ResponseUrgency.DEFERRED,
        automation_level=AutomationLevel.APPROVAL_REQUIRED,
        target_type="network",
        estimated_duration_minutes=15,
        potential_impact="Exposure if threat not fully eradicated",
        rollback_procedure="Re-isolate if suspicious activity resumes",
    ),
}


class ResponseRecommendationAgent(BaseAgent):
    """Generates automated response recommendations for security incidents.

    Capabilities:
    - Containment action recommendations
    - Eradication procedure suggestions
    - Recovery planning
    - Playbook generation
    - SOAR integration preparation
    """

    @property
    def agent_id(self) -> str:
        return "response_rec_001"

    @property
    def name(self) -> str:
        return "Response Recommendation Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RESPONSE_RECOMMENDATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "containment_recommendations",
            "eradication_recommendations",
            "recovery_planning",
            "playbook_generation",
            "automation_assessment",
            "impact_analysis",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has incident data."""
        payload = task.payload or {}
        return any(
            k in payload
            for k in ["incident", "finding", "event", "threat_type", "classification"]
        )

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process response recommendation task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract incident context
            context = self._extract_context(payload)

            # Generate containment actions
            containment = self._generate_containment_actions(context)

            # Generate eradication actions
            eradication = self._generate_eradication_actions(context)

            # Generate recovery actions
            recovery = self._generate_recovery_actions(context)

            # Combine all actions
            all_actions = containment + eradication + recovery

            # Set execution order
            for i, action in enumerate(all_actions):
                action.execution_order = i + 1

            # Generate playbook
            playbook = self._generate_playbook(context, all_actions)

            # Calculate metrics
            immediate_count = sum(
                1 for a in all_actions if a.urgency == ResponseUrgency.IMMEDIATE
            )
            total_time = sum(a.estimated_duration_minutes for a in all_actions)
            automatable_levels = (
                AutomationLevel.FULLY_AUTOMATED,
                AutomationLevel.SEMI_AUTOMATED,
            )
            can_automate = any(
                a.automation_level in automatable_levels
                for a in all_actions
            )

            # Determine severity
            severity = EventSeverity.HIGH if immediate_count > 2 else EventSeverity.MEDIUM

            # Create finding
            finding = ResponseFinding(
                finding_id=f"resp_{uuid.uuid4().hex}",
                finding_type="response_recommendation",
                event_id=task.event_id,
                task_id=task.task_id,
                agent_id=self.agent_id,
                severity=severity,
                confidence=MatchConfidence.HIGH,
                recommended_actions=all_actions,
                playbook=playbook,
                containment_actions=containment,
                eradication_actions=eradication,
                recovery_actions=recovery,
                total_actions=len(all_actions),
                immediate_actions_count=immediate_count,
                automation_possible=can_automate,
                estimated_response_time_minutes=total_time,
                explanation=(
                    f"Generated {len(all_actions)} response actions "
                    f"({immediate_count} immediate). "
                    f"Estimated response time: {total_time} minutes."
                ),
                recommendations=[a.title for a in all_actions[:5]],
            )

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.SUCCESS,
                finding=finding,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                metadata={
                    "total_actions": len(all_actions),
                    "immediate_actions": immediate_count,
                    "estimated_time_minutes": total_time,
                    "automation_possible": can_automate,
                },
            )

        except Exception as e:
            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.FAILED,
                finding=None,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                errors=[str(e)],
            )

    def create_finding(
        self,
        task: AgentTask,
        analysis: dict[str, Any],
    ) -> BaseFinding:
        """Create a basic finding."""
        return BaseFinding(
            finding_id=f"resp_{uuid.uuid4().hex}",
            finding_type="response_recommendation",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_context(  # noqa: C901
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract incident context for response planning."""
        context: dict[str, Any] = {
            "threat_type": "unknown",
            "classification": "other",
            "severity": "medium",
            "affected_hosts": [],
            "affected_users": [],
            "malicious_ips": [],
            "malicious_domains": [],
            "has_malware": False,
            "has_c2": False,
            "has_lateral_movement": False,
            "has_data_exfil": False,
            "has_credential_theft": False,
        }

        # From finding
        if "finding" in payload:
            finding = payload["finding"]
            if isinstance(finding, dict):
                context["threat_type"] = finding.get("finding_type", "unknown")
                context["severity"] = finding.get("severity", "medium")

                # Extract indicators
                if "source_ips" in finding:
                    context["malicious_ips"].extend(finding["source_ips"])
                if "destination_ips" in finding:
                    context["malicious_ips"].extend(finding["destination_ips"])

        # From incident
        if "incident" in payload:
            incident = payload["incident"]
            if isinstance(incident, dict):
                context["classification"] = incident.get("classification", "other")
                context["affected_hosts"] = incident.get("affected_hosts", [])
                context["affected_users"] = incident.get("affected_users", [])

        # From event
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                if event.get("source_ip"):
                    context["affected_hosts"].append(event["source_ip"])
                if event.get("destination_ip"):
                    context["malicious_ips"].append(event["destination_ip"])
                if event.get("username"):
                    context["affected_users"].append(event["username"])

        # Check for specific threat indicators
        threat_type = context["threat_type"].lower()
        classification = context["classification"].lower()

        context["has_malware"] = "malware" in threat_type or "malware" in classification
        context["has_c2"] = "c2" in threat_type or "command" in classification
        context["has_lateral_movement"] = "lateral" in threat_type
        context["has_data_exfil"] = "exfil" in threat_type or "breach" in classification
        context["has_credential_theft"] = (
            "credential" in threat_type or "phishing" in classification
        )

        return context

    def _generate_containment_actions(
        self, context: dict[str, Any]
    ) -> list[ResponseAction]:
        """Generate containment actions based on context."""
        actions: list[ResponseAction] = []

        # Host isolation for compromised hosts
        for host in context.get("affected_hosts", [])[:5]:  # Limit to 5
            action = CONTAINMENT_ACTIONS["isolate_host"].model_copy()
            action.action_id = f"contain_host_{uuid.uuid4().hex[:8]}"
            action.target_identifier = host
            actions.append(action)

        # User account disable for compromised users
        if context.get("has_credential_theft"):
            for user in context.get("affected_users", [])[:5]:
                action = CONTAINMENT_ACTIONS["disable_user"].model_copy()
                action.action_id = f"contain_user_{uuid.uuid4().hex[:8]}"
                action.target_identifier = user
                actions.append(action)

        # IP blocking for C2
        if context.get("has_c2"):
            for ip in context.get("malicious_ips", [])[:10]:
                action = CONTAINMENT_ACTIONS["block_ip"].model_copy()
                action.action_id = f"contain_ip_{uuid.uuid4().hex[:8]}"
                action.target_identifier = ip
                actions.append(action)

        # Domain blocking
        for domain in context.get("malicious_domains", [])[:10]:
            action = CONTAINMENT_ACTIONS["block_domain"].model_copy()
            action.action_id = f"contain_domain_{uuid.uuid4().hex[:8]}"
            action.target_identifier = domain
            actions.append(action)

        # Email quarantine for phishing
        if "phishing" in context.get("classification", "").lower():
            action = CONTAINMENT_ACTIONS["quarantine_email"].model_copy()
            action.action_id = f"contain_email_{uuid.uuid4().hex[:8]}"
            actions.append(action)

        return actions

    def _generate_eradication_actions(
        self, context: dict[str, Any]
    ) -> list[ResponseAction]:
        """Generate eradication actions based on context."""
        actions: list[ResponseAction] = []

        # Malware removal
        if context.get("has_malware"):
            for host in context.get("affected_hosts", [])[:5]:
                action = ERADICATION_ACTIONS["remove_malware"].model_copy()
                action.action_id = f"erad_malware_{uuid.uuid4().hex[:8]}"
                action.target_identifier = host
                actions.append(action)

        # Credential reset for compromised users
        if context.get("has_credential_theft") or context.get("affected_users"):
            for user in context.get("affected_users", [])[:10]:
                action = ERADICATION_ACTIONS["reset_credentials"].model_copy()
                action.action_id = f"erad_creds_{uuid.uuid4().hex[:8]}"
                action.target_identifier = user
                actions.append(action)

        # Persistence removal for APT/malware
        if context.get("has_malware") or context.get("has_c2"):
            action = ERADICATION_ACTIONS["remove_persistence"].model_copy()
            action.action_id = f"erad_persist_{uuid.uuid4().hex[:8]}"
            actions.append(action)

        # Patching for vulnerability exploits
        if "exploit" in context.get("threat_type", "").lower():
            action = ERADICATION_ACTIONS["patch_vulnerability"].model_copy()
            action.action_id = f"erad_patch_{uuid.uuid4().hex[:8]}"
            actions.append(action)

        return actions

    def _generate_recovery_actions(
        self, context: dict[str, Any]
    ) -> list[ResponseAction]:
        """Generate recovery actions based on context."""
        actions: list[ResponseAction] = []

        severity = context.get("severity", "medium")
        if isinstance(severity, str):
            severity = severity.lower()

        # Restore from backup for severe incidents
        if severity in ("critical", "high") or context.get("has_malware"):
            action = RECOVERY_ACTIONS["restore_backup"].model_copy()
            action.action_id = f"recov_backup_{uuid.uuid4().hex[:8]}"
            actions.append(action)

        # Reimage for ransomware/APT
        if "ransomware" in context.get("classification", "").lower():
            action = RECOVERY_ACTIONS["reimage_host"].model_copy()
            action.action_id = f"recov_reimage_{uuid.uuid4().hex[:8]}"
            actions.append(action)

        # Restore network access (always last)
        action = RECOVERY_ACTIONS["restore_service"].model_copy()
        action.action_id = f"recov_restore_{uuid.uuid4().hex[:8]}"
        action.prerequisites = ["All eradication steps complete", "Security team approval"]
        actions.append(action)

        return actions

    def _generate_playbook(
        self, context: dict[str, Any], actions: list[ResponseAction]
    ) -> ResponsePlaybook:
        """Generate a response playbook."""
        classification = context.get("classification", "other")
        total_time = sum(a.estimated_duration_minutes for a in actions)

        # Determine required approvals
        approvals = []
        if any(a.automation_level == AutomationLevel.APPROVAL_REQUIRED for a in actions):
            approvals.append("Security Manager")
        if any(a.target_type == "user" for a in actions):
            approvals.append("HR Representative")
        if total_time > 120:
            approvals.append("IT Operations Lead")

        return ResponsePlaybook(
            playbook_id=f"playbook_{uuid.uuid4().hex}",
            playbook_name=f"Response Playbook - {classification.replace('_', ' ').title()}",
            incident_type=classification,
            actions=actions,
            total_estimated_duration=total_time,
            required_approvals=approvals,
        )
