"""Incident Prioritization Agent - risk scoring and priority assignment."""

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


class IncidentPriority(StrEnum):
    """Incident priority levels."""

    P1_CRITICAL = "P1"
    P2_HIGH = "P2"
    P3_MEDIUM = "P3"
    P4_LOW = "P4"
    P5_INFORMATIONAL = "P5"


class RiskFactor(BaseModel):
    """Individual risk factor contributing to overall score."""

    factor_name: str
    description: str
    weight: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=1.0)
    weighted_score: float = Field(ge=0.0, le=1.0)
    evidence: str = ""


class AssetCriticality(StrEnum):
    """Asset criticality levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentClassification(StrEnum):
    """Incident classification types."""

    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    RANSOMWARE = "ransomware"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    OTHER = "other"


class SLARequirements(BaseModel):
    """SLA requirements based on priority."""

    priority: IncidentPriority
    initial_response_minutes: int
    containment_hours: int
    resolution_hours: int
    escalation_after_minutes: int


class PrioritizationFinding(BaseFinding):
    """Finding from incident prioritization."""

    priority: IncidentPriority
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    classification: IncidentClassification = IncidentClassification.OTHER
    affected_asset_count: int = 0
    affected_user_count: int = 0
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM
    business_impact: str = ""
    sla_requirements: SLARequirements | None = None
    escalation_required: bool = False
    escalation_reason: str = ""


# SLA definitions by priority
SLA_DEFINITIONS = {
    IncidentPriority.P1_CRITICAL: SLARequirements(
        priority=IncidentPriority.P1_CRITICAL,
        initial_response_minutes=15,
        containment_hours=1,
        resolution_hours=4,
        escalation_after_minutes=30,
    ),
    IncidentPriority.P2_HIGH: SLARequirements(
        priority=IncidentPriority.P2_HIGH,
        initial_response_minutes=30,
        containment_hours=4,
        resolution_hours=24,
        escalation_after_minutes=60,
    ),
    IncidentPriority.P3_MEDIUM: SLARequirements(
        priority=IncidentPriority.P3_MEDIUM,
        initial_response_minutes=60,
        containment_hours=8,
        resolution_hours=72,
        escalation_after_minutes=120,
    ),
    IncidentPriority.P4_LOW: SLARequirements(
        priority=IncidentPriority.P4_LOW,
        initial_response_minutes=240,
        containment_hours=24,
        resolution_hours=168,
        escalation_after_minutes=480,
    ),
    IncidentPriority.P5_INFORMATIONAL: SLARequirements(
        priority=IncidentPriority.P5_INFORMATIONAL,
        initial_response_minutes=1440,
        containment_hours=72,
        resolution_hours=336,
        escalation_after_minutes=2880,
    ),
}

# Risk factor weights
RISK_WEIGHTS = {
    "severity": 0.25,
    "asset_criticality": 0.20,
    "data_sensitivity": 0.15,
    "threat_actor_sophistication": 0.10,
    "attack_stage": 0.10,
    "affected_scope": 0.10,
    "confidence": 0.05,
    "recurrence": 0.05,
}


class IncidentPrioritizationAgent(BaseAgent):
    """Calculates risk scores and assigns incident priorities.

    Capabilities:
    - Multi-factor risk scoring
    - Priority assignment with SLAs
    - Asset criticality assessment
    - Business impact analysis
    - Escalation determination
    """

    @property
    def agent_id(self) -> str:
        return "prioritization_001"

    @property
    def name(self) -> str:
        return "Incident Prioritization Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.INCIDENT_PRIORITIZATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "risk_scoring",
            "priority_assignment",
            "sla_calculation",
            "asset_criticality_assessment",
            "business_impact_analysis",
            "escalation_determination",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has incident data."""
        payload = task.payload or {}
        return any(k in payload for k in ["incident", "finding", "event", "alert", "findings"])

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process prioritization task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract incident data
            incident_data = self._extract_incident_data(payload)

            # Calculate risk factors
            risk_factors = self._calculate_risk_factors(incident_data)

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(risk_factors)

            # Determine priority
            priority = self._determine_priority(risk_score)

            # Get SLA requirements
            sla = SLA_DEFINITIONS.get(priority)

            # Classify incident
            classification = self._classify_incident(incident_data)

            # Assess asset criticality
            asset_criticality = self._assess_asset_criticality(incident_data)

            # Determine business impact
            business_impact = self._assess_business_impact(
                incident_data, asset_criticality, classification
            )

            # Check if escalation needed
            escalation_required, escalation_reason = self._check_escalation(
                risk_score, asset_criticality, classification, incident_data
            )

            # Create finding
            finding = PrioritizationFinding(
                finding_id=f"prio_{uuid.uuid4().hex}",
                finding_type="incident_prioritization",
                event_id=task.event_id,
                task_id=task.task_id,
                agent_id=self.agent_id,
                severity=self._priority_to_severity(priority),
                confidence=MatchConfidence.HIGH,
                priority=priority,
                risk_score=risk_score,
                risk_factors=risk_factors,
                classification=classification,
                affected_asset_count=incident_data.get("affected_assets", 1),
                affected_user_count=incident_data.get("affected_users", 0),
                asset_criticality=asset_criticality,
                business_impact=business_impact,
                sla_requirements=sla,
                escalation_required=escalation_required,
                escalation_reason=escalation_reason,
                explanation=(
                    f"Incident classified as {priority.value} priority with risk score "
                    f"{risk_score:.1f}/100. {business_impact}"
                ),
                recommendations=self._generate_recommendations(
                    priority, classification, escalation_required
                ),
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
                    "priority": priority.value,
                    "risk_score": risk_score,
                    "classification": classification.value,
                    "escalation_required": escalation_required,
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
            finding_id=f"prio_{uuid.uuid4().hex}",
            finding_type="incident_prioritization",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_incident_data(  # noqa: C901
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract and normalize incident data."""
        data: dict[str, Any] = {
            "severity": EventSeverity.MEDIUM,
            "affected_assets": 1,
            "affected_users": 0,
            "confidence": 0.5,
            "event_types": [],
            "mitre_techniques": [],
            "mitre_tactics": [],
        }

        # From incident object
        if "incident" in payload:
            incident = payload["incident"]
            if isinstance(incident, dict):
                data.update(
                    {
                        "severity": self._parse_severity(incident.get("severity")),
                        "affected_assets": incident.get("affected_assets", 1),
                        "affected_users": incident.get("affected_users", 0),
                        "event_types": incident.get("event_types", []),
                        "mitre_techniques": incident.get("mitre_techniques", []),
                        "mitre_tactics": incident.get("mitre_tactics", []),
                    }
                )

        # From finding
        if "finding" in payload:
            finding = payload["finding"]
            if isinstance(finding, dict):
                data["severity"] = self._parse_severity(finding.get("severity"))
                data["confidence"] = finding.get("confidence", 0.5)
                if "mitre_techniques" in finding:
                    data["mitre_techniques"] = finding["mitre_techniques"]
                if "finding_type" in finding:
                    data["event_types"].append(finding["finding_type"])

        # From event
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                data["severity"] = self._parse_severity(event.get("severity"))
                if event.get("event_type"):
                    data["event_types"].append(event["event_type"])

        # From multiple findings
        if "findings" in payload:
            for finding in payload["findings"]:
                if isinstance(finding, dict):
                    sev = self._parse_severity(finding.get("severity"))
                    if self._severity_to_score(sev) > self._severity_to_score(data["severity"]):
                        data["severity"] = sev
                    if finding.get("finding_type"):
                        data["event_types"].append(finding["finding_type"])

        return data

    def _calculate_risk_factors(self, data: dict[str, Any]) -> list[RiskFactor]:
        """Calculate individual risk factors."""
        factors: list[RiskFactor] = []

        # Severity factor
        severity_score = self._severity_to_score(data["severity"])
        factors.append(
            RiskFactor(
                factor_name="severity",
                description="Event/finding severity level",
                weight=RISK_WEIGHTS["severity"],
                score=severity_score,
                weighted_score=severity_score * RISK_WEIGHTS["severity"],
                evidence=f"Severity: {data['severity'].value}",
            )
        )

        # Asset criticality factor
        asset_score = min(data["affected_assets"] / 10, 1.0)
        factors.append(
            RiskFactor(
                factor_name="affected_scope",
                description="Number of affected assets",
                weight=RISK_WEIGHTS["affected_scope"],
                score=asset_score,
                weighted_score=asset_score * RISK_WEIGHTS["affected_scope"],
                evidence=f"Affected assets: {data['affected_assets']}",
            )
        )

        # Attack stage factor (based on MITRE tactics)
        stage_score = self._calculate_attack_stage_score(data.get("mitre_tactics", []))
        factors.append(
            RiskFactor(
                factor_name="attack_stage",
                description="Stage in attack lifecycle",
                weight=RISK_WEIGHTS["attack_stage"],
                score=stage_score,
                weighted_score=stage_score * RISK_WEIGHTS["attack_stage"],
                evidence=f"Tactics: {', '.join(data.get('mitre_tactics', [])[:3])}",
            )
        )

        # Confidence factor
        conf_score = data.get("confidence", 0.5)
        if isinstance(conf_score, str):
            conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
            conf_score = conf_map.get(conf_score.lower(), 0.5)
        factors.append(
            RiskFactor(
                factor_name="confidence",
                description="Detection confidence level",
                weight=RISK_WEIGHTS["confidence"],
                score=conf_score,
                weighted_score=conf_score * RISK_WEIGHTS["confidence"],
                evidence=f"Confidence: {conf_score:.0%}",
            )
        )

        # Data sensitivity (simplified)
        data_score = 0.5  # Default medium
        if any("exfil" in t.lower() for t in data.get("mitre_tactics", [])):
            data_score = 0.9
        elif any("credential" in t.lower() for t in data.get("event_types", [])):
            data_score = 0.8
        factors.append(
            RiskFactor(
                factor_name="data_sensitivity",
                description="Sensitivity of data at risk",
                weight=RISK_WEIGHTS["data_sensitivity"],
                score=data_score,
                weighted_score=data_score * RISK_WEIGHTS["data_sensitivity"],
                evidence="Data sensitivity assessment",
            )
        )

        return factors

    def _calculate_risk_score(self, factors: list[RiskFactor]) -> float:
        """Calculate overall risk score (0-100)."""
        if not factors:
            return 50.0

        total_weighted = sum(f.weighted_score for f in factors)
        total_weight = sum(f.weight for f in factors)

        if total_weight == 0:
            return 50.0

        normalized = total_weighted / total_weight
        return round(normalized * 100, 1)

    def _determine_priority(self, risk_score: float) -> IncidentPriority:
        """Determine priority from risk score."""
        if risk_score >= 85:
            return IncidentPriority.P1_CRITICAL
        elif risk_score >= 70:
            return IncidentPriority.P2_HIGH
        elif risk_score >= 50:
            return IncidentPriority.P3_MEDIUM
        elif risk_score >= 30:
            return IncidentPriority.P4_LOW
        else:
            return IncidentPriority.P5_INFORMATIONAL

    def _classify_incident(self, data: dict[str, Any]) -> IncidentClassification:
        """Classify the incident type."""
        event_types = [t.lower() for t in data.get("event_types", [])]
        tactics = [t.lower() for t in data.get("mitre_tactics", [])]

        # Check for specific incident types
        if any("ransomware" in t or "encrypt" in t for t in event_types):
            return IncidentClassification.RANSOMWARE

        if any("phishing" in t for t in event_types):
            return IncidentClassification.PHISHING

        if any("malware" in t for t in event_types):
            return IncidentClassification.MALWARE

        if any("exfil" in t for t in tactics) or any("breach" in t for t in event_types):
            return IncidentClassification.DATA_BREACH

        if any("brute" in t or "unauthorized" in t for t in event_types):
            return IncidentClassification.UNAUTHORIZED_ACCESS

        if any("dos" in t or "denial" in t for t in event_types):
            return IncidentClassification.DOS

        if any("insider" in t for t in event_types):
            return IncidentClassification.INSIDER_THREAT

        if any("recon" in t for t in tactics):
            return IncidentClassification.RECONNAISSANCE

        if "command-and-control" in tactics or "lateral-movement" in tactics:
            return IncidentClassification.APT

        return IncidentClassification.OTHER

    def _assess_asset_criticality(self, data: dict[str, Any]) -> AssetCriticality:
        """Assess overall asset criticality."""
        affected = data.get("affected_assets", 1)

        # Simplified logic - in production, look up asset inventory
        if affected >= 10:
            return AssetCriticality.CRITICAL
        elif affected >= 5:
            return AssetCriticality.HIGH
        elif affected >= 2:
            return AssetCriticality.MEDIUM
        else:
            return AssetCriticality.LOW

    def _assess_business_impact(
        self,
        data: dict[str, Any],
        asset_criticality: AssetCriticality,
        classification: IncidentClassification,
    ) -> str:
        """Generate business impact assessment."""
        impacts = []

        # Based on classification
        classification_impacts = {
            IncidentClassification.RANSOMWARE: "Critical business disruption risk",
            IncidentClassification.DATA_BREACH: (
                "Potential data exposure and compliance implications"
            ),
            IncidentClassification.PHISHING: "Risk of credential compromise",
            IncidentClassification.MALWARE: "System integrity at risk",
            IncidentClassification.UNAUTHORIZED_ACCESS: "Security boundary violation",
            IncidentClassification.APT: "Sophisticated threat actor with persistence",
        }

        if classification in classification_impacts:
            impacts.append(classification_impacts[classification])

        # Based on asset criticality
        if asset_criticality == AssetCriticality.CRITICAL:
            impacts.append("Critical assets affected")
        elif asset_criticality == AssetCriticality.HIGH:
            impacts.append("High-value assets involved")

        # Based on scope
        if data.get("affected_assets", 0) > 5:
            impacts.append(f"{data['affected_assets']} assets affected")

        if data.get("affected_users", 0) > 0:
            impacts.append(f"{data['affected_users']} users potentially impacted")

        return ". ".join(impacts) if impacts else "Business impact assessment pending"

    def _check_escalation(
        self,
        risk_score: float,
        asset_criticality: AssetCriticality,
        classification: IncidentClassification,
        data: dict[str, Any],
    ) -> tuple[bool, str]:
        """Determine if escalation is required."""
        reasons = []

        # Automatic escalation triggers
        if risk_score >= 90:
            reasons.append("Risk score exceeds critical threshold")

        if asset_criticality == AssetCriticality.CRITICAL:
            reasons.append("Critical assets affected")

        if classification in (
            IncidentClassification.RANSOMWARE,
            IncidentClassification.APT,
            IncidentClassification.DATA_BREACH,
        ):
            reasons.append(f"Incident type: {classification.value}")

        if data.get("affected_assets", 0) >= 10:
            reasons.append("Wide-spread impact detected")

        if reasons:
            return True, "; ".join(reasons)

        return False, ""

    def _generate_recommendations(
        self,
        priority: IncidentPriority,
        classification: IncidentClassification,
        escalation_required: bool,
    ) -> list[str]:
        """Generate response recommendations."""
        recommendations = []

        if escalation_required:
            recommendations.append("Immediately escalate to security leadership")

        if priority in (IncidentPriority.P1_CRITICAL, IncidentPriority.P2_HIGH):
            recommendations.append("Activate incident response team")
            recommendations.append("Begin containment procedures")

        # Classification-specific recommendations
        class_recommendations = {
            IncidentClassification.RANSOMWARE: [
                "Isolate affected systems immediately",
                "Do not pay ransom",
                "Preserve evidence for forensics",
            ],
            IncidentClassification.DATA_BREACH: [
                "Identify scope of exposed data",
                "Notify legal and compliance teams",
                "Prepare breach notification if required",
            ],
            IncidentClassification.PHISHING: [
                "Reset credentials for affected users",
                "Block malicious domains/IPs",
                "Send user awareness notification",
            ],
            IncidentClassification.UNAUTHORIZED_ACCESS: [
                "Disable compromised accounts",
                "Review access logs",
                "Strengthen authentication controls",
            ],
        }

        if classification in class_recommendations:
            recommendations.extend(class_recommendations[classification])

        # SLA reminder
        sla = SLA_DEFINITIONS.get(priority)
        if sla:
            recommendations.append(
                f"Initial response required within {sla.initial_response_minutes} minutes"
            )

        return recommendations

    def _severity_to_score(self, severity: EventSeverity) -> float:
        """Convert severity to numeric score (0-1)."""
        scores = {
            EventSeverity.CRITICAL: 1.0,
            EventSeverity.HIGH: 0.8,
            EventSeverity.MEDIUM: 0.5,
            EventSeverity.LOW: 0.3,
            EventSeverity.INFORMATIONAL: 0.1,
        }
        return scores.get(severity, 0.5)

    def _priority_to_severity(self, priority: IncidentPriority) -> EventSeverity:
        """Convert priority to severity."""
        mapping = {
            IncidentPriority.P1_CRITICAL: EventSeverity.CRITICAL,
            IncidentPriority.P2_HIGH: EventSeverity.HIGH,
            IncidentPriority.P3_MEDIUM: EventSeverity.MEDIUM,
            IncidentPriority.P4_LOW: EventSeverity.LOW,
            IncidentPriority.P5_INFORMATIONAL: EventSeverity.INFORMATIONAL,
        }
        return mapping.get(priority, EventSeverity.MEDIUM)

    def _calculate_attack_stage_score(self, tactics: list[str]) -> float:
        """Score based on attack stage (later stages = higher risk)."""
        if not tactics:
            return 0.3

        # Later kill chain stages are more critical
        stage_scores = {
            "reconnaissance": 0.2,
            "initial-access": 0.4,
            "execution": 0.5,
            "persistence": 0.6,
            "privilege-escalation": 0.7,
            "defense-evasion": 0.6,
            "credential-access": 0.7,
            "discovery": 0.5,
            "lateral-movement": 0.8,
            "collection": 0.8,
            "command-and-control": 0.8,
            "exfiltration": 0.95,
            "impact": 1.0,
        }

        scores = [stage_scores.get(t.lower(), 0.5) for t in tactics]
        return max(scores) if scores else 0.3

    def _parse_severity(self, sev: Any) -> EventSeverity:
        """Parse severity from various formats."""
        if isinstance(sev, EventSeverity):
            return sev
        if isinstance(sev, str):
            try:
                return EventSeverity(sev.lower())
            except ValueError:
                pass
        return EventSeverity.MEDIUM
