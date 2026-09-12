"""AI Investigation Agent - LLM-powered incident investigation."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class InvestigationStatus(StrEnum):
    """Status of an investigation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_INPUT = "awaiting_input"
    COMPLETED = "completed"
    ESCALATED = "escalated"
    CLOSED = "closed"


class InvestigationPriority(StrEnum):
    """Investigation priority levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceType(StrEnum):
    """Types of evidence in investigation."""

    LOG_ENTRY = "log_entry"
    NETWORK_FLOW = "network_flow"
    FILE_ARTIFACT = "file_artifact"
    PROCESS_INFO = "process_info"
    USER_ACTIVITY = "user_activity"
    ALERT = "alert"
    CORRELATION = "correlation"
    THREAT_INTEL = "threat_intel"


class Evidence(BaseModel):
    """Evidence item in an investigation."""

    evidence_id: str = Field(default_factory=lambda: f"evd_{uuid.uuid4().hex[:12]}")
    evidence_type: EvidenceType
    source: str
    timestamp: datetime
    content: dict[str, Any] = Field(default_factory=dict)
    relevance_score: float = 0.5
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class InvestigationStep(BaseModel):
    """A step in the investigation process."""

    step_id: str = Field(default_factory=lambda: f"step_{uuid.uuid4().hex[:8]}")
    step_number: int
    action: str
    reasoning: str
    evidence_collected: list[str] = Field(default_factory=list)
    findings: str = ""
    status: str = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None


class HypothesisStatus(StrEnum):
    """Status of investigation hypothesis."""

    PROPOSED = "proposed"
    INVESTIGATING = "investigating"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class Hypothesis(BaseModel):
    """Investigation hypothesis."""

    hypothesis_id: str = Field(default_factory=lambda: f"hyp_{uuid.uuid4().hex[:8]}")
    statement: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.0
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    reasoning: str = ""


class Investigation(BaseModel):
    """Full investigation record."""

    investigation_id: str = Field(default_factory=lambda: f"inv_{uuid.uuid4().hex[:12]}")
    title: str
    description: str = ""
    status: InvestigationStatus = InvestigationStatus.PENDING
    priority: InvestigationPriority = InvestigationPriority.MEDIUM
    incident_id: str | None = None
    correlation_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    steps: list[InvestigationStep] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    findings_summary: str = ""
    recommendations: list[str] = Field(default_factory=list)
    root_cause: str = ""
    impact_assessment: str = ""
    assigned_to: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationQuery(BaseModel):
    """Query for the AI investigator."""

    query: str
    context: dict[str, Any] = Field(default_factory=dict)
    investigation_id: str | None = None


class InvestigationResponse(BaseModel):
    """Response from AI investigator."""

    response: str
    suggested_actions: list[str] = Field(default_factory=list)
    relevant_evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""


# Investigation templates for common scenarios
INVESTIGATION_TEMPLATES = {
    "phishing": {
        "title": "Phishing Investigation",
        "steps": [
            "Identify all recipients of the phishing email",
            "Check if any users clicked malicious links",
            "Review credential usage for affected users",
            "Scan endpoints for malware indicators",
            "Block sender and malicious URLs",
            "Reset credentials if compromise suspected",
        ],
        "hypotheses": [
            "Credentials were harvested via fake login page",
            "Malware was delivered via attachment",
            "No users interacted with the phishing email",
        ],
    },
    "brute_force": {
        "title": "Brute Force Attack Investigation",
        "steps": [
            "Identify source IPs of authentication attempts",
            "Check for successful authentications from those IPs",
            "Review targeted accounts for signs of compromise",
            "Analyze timing patterns and automation indicators",
            "Block attacking IPs at perimeter",
            "Enforce password reset for targeted accounts",
        ],
        "hypotheses": [
            "Attack was automated credential stuffing",
            "Attacker gained access to one or more accounts",
            "Attack was unsuccessful and contained",
        ],
    },
    "data_exfiltration": {
        "title": "Data Exfiltration Investigation",
        "steps": [
            "Identify unusual outbound data transfers",
            "Map source systems and user accounts involved",
            "Categorize types of data potentially exposed",
            "Review access logs for unauthorized access",
            "Check for C2 communication patterns",
            "Assess regulatory notification requirements",
        ],
        "hypotheses": [
            "Insider threat exfiltrated sensitive data",
            "Malware established C2 and exfiltrated data",
            "Legitimate business activity misclassified",
        ],
    },
    "ransomware": {
        "title": "Ransomware Investigation",
        "steps": [
            "Isolate affected systems immediately",
            "Identify ransomware variant and IoCs",
            "Determine initial access vector",
            "Map lateral movement and impact scope",
            "Check for data exfiltration before encryption",
            "Assess backup availability and integrity",
        ],
        "hypotheses": [
            "Initial access via phishing email",
            "Initial access via exposed RDP/VPN",
            "Initial access via supply chain compromise",
        ],
    },
}


class AIInvestigationEngine:
    """AI-powered investigation engine."""

    def __init__(self):
        self._investigations: dict[str, Investigation] = {}
        self._evidence_store: dict[str, Evidence] = {}

    def create_investigation(
        self,
        title: str,
        description: str = "",
        template: str | None = None,
        priority: InvestigationPriority = InvestigationPriority.MEDIUM,
        incident_id: str | None = None,
        correlation_ids: list[str] | None = None,
        alert_ids: list[str] | None = None,
    ) -> Investigation:
        """Create a new investigation."""
        investigation = Investigation(
            title=title,
            description=description,
            priority=priority,
            incident_id=incident_id,
            correlation_ids=correlation_ids or [],
            alert_ids=alert_ids or [],
        )

        # Apply template if specified
        if template and template in INVESTIGATION_TEMPLATES:
            tmpl = INVESTIGATION_TEMPLATES[template]
            investigation.title = tmpl["title"]
            for i, step_desc in enumerate(tmpl["steps"], 1):
                investigation.steps.append(
                    InvestigationStep(
                        step_number=i,
                        action=step_desc,
                        reasoning=f"Standard step for {template} investigation",
                    )
                )
            for hyp_stmt in tmpl["hypotheses"]:
                investigation.hypotheses.append(Hypothesis(statement=hyp_stmt))

        self._investigations[investigation.investigation_id] = investigation
        return investigation

    def add_evidence(
        self,
        investigation_id: str,
        evidence_type: EvidenceType,
        source: str,
        content: dict[str, Any],
        timestamp: datetime | None = None,
        relevance_score: float = 0.5,
        tags: list[str] | None = None,
    ) -> Evidence:
        """Add evidence to an investigation."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")

        evidence = Evidence(
            evidence_type=evidence_type,
            source=source,
            timestamp=timestamp or utc_now(),
            content=content,
            relevance_score=relevance_score,
            tags=tags or [],
        )

        investigation.evidence.append(evidence)
        investigation.updated_at = utc_now()
        self._evidence_store[evidence.evidence_id] = evidence

        return evidence

    def add_hypothesis(
        self,
        investigation_id: str,
        statement: str,
        reasoning: str = "",
    ) -> Hypothesis:
        """Add a hypothesis to an investigation."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")

        hypothesis = Hypothesis(statement=statement, reasoning=reasoning)
        investigation.hypotheses.append(hypothesis)
        investigation.updated_at = utc_now()

        return hypothesis

    def update_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        status: HypothesisStatus | None = None,
        confidence: float | None = None,
        supporting_evidence: list[str] | None = None,
        contradicting_evidence: list[str] | None = None,
        reasoning: str | None = None,
    ) -> Hypothesis | None:
        """Update a hypothesis."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return None

        for hyp in investigation.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                if status is not None:
                    hyp.status = status
                if confidence is not None:
                    hyp.confidence = confidence
                if supporting_evidence is not None:
                    hyp.supporting_evidence.extend(supporting_evidence)
                if contradicting_evidence is not None:
                    hyp.contradicting_evidence.extend(contradicting_evidence)
                if reasoning is not None:
                    hyp.reasoning = reasoning
                investigation.updated_at = utc_now()
                return hyp

        return None

    def complete_step(
        self,
        investigation_id: str,
        step_id: str,
        findings: str,
        evidence_ids: list[str] | None = None,
    ) -> InvestigationStep | None:
        """Mark an investigation step as complete."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return None

        for step in investigation.steps:
            if step.step_id == step_id:
                step.status = "completed"
                step.findings = findings
                step.completed_at = utc_now()
                if evidence_ids:
                    step.evidence_collected.extend(evidence_ids)
                investigation.updated_at = utc_now()
                return step

        return None

    def generate_timeline(self, investigation_id: str) -> list[dict[str, Any]]:
        """Generate investigation timeline from evidence."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return []

        timeline = []
        for evidence in sorted(investigation.evidence, key=lambda e: e.timestamp):
            timeline.append(
                {
                    "timestamp": evidence.timestamp.isoformat(),
                    "type": evidence.evidence_type.value,
                    "source": evidence.source,
                    "summary": self._summarize_evidence(evidence),
                    "evidence_id": evidence.evidence_id,
                }
            )

        investigation.timeline = timeline
        return timeline

    def _summarize_evidence(self, evidence: Evidence) -> str:
        """Generate brief summary of evidence."""
        content = evidence.content
        if evidence.evidence_type == EvidenceType.LOG_ENTRY:
            return content.get("message", "Log entry")[:100]
        elif evidence.evidence_type == EvidenceType.ALERT:
            return content.get("alert_name", "Security alert")
        elif evidence.evidence_type == EvidenceType.NETWORK_FLOW:
            src = content.get("source_ip", "?")
            dst = content.get("dest_ip", "?")
            return f"Network flow {src} → {dst}"
        elif evidence.evidence_type == EvidenceType.THREAT_INTEL:
            return content.get("indicator", "Threat intel match")
        else:
            return f"{evidence.evidence_type.value} evidence"

    def analyze_investigation(self, investigation_id: str) -> dict[str, Any]:
        """Analyze investigation and generate insights."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return {"error": "Investigation not found"}

        # Count evidence by type
        evidence_by_type: dict[str, int] = {}
        for e in investigation.evidence:
            t = e.evidence_type.value
            evidence_by_type[t] = evidence_by_type.get(t, 0) + 1

        # Analyze hypotheses
        supported = [h for h in investigation.hypotheses if h.status == HypothesisStatus.SUPPORTED]
        refuted = [h for h in investigation.hypotheses if h.status == HypothesisStatus.REFUTED]

        # Calculate progress
        completed_steps = [s for s in investigation.steps if s.status == "completed"]
        progress = len(completed_steps) / len(investigation.steps) if investigation.steps else 0

        return {
            "investigation_id": investigation_id,
            "status": investigation.status.value,
            "priority": investigation.priority.value,
            "evidence_count": len(investigation.evidence),
            "evidence_by_type": evidence_by_type,
            "hypothesis_count": len(investigation.hypotheses),
            "supported_hypotheses": len(supported),
            "refuted_hypotheses": len(refuted),
            "steps_total": len(investigation.steps),
            "steps_completed": len(completed_steps),
            "progress_pct": round(progress * 100, 1),
            "timeline_events": len(investigation.timeline),
        }

    def generate_summary(self, investigation_id: str) -> str:
        """Generate investigation summary."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return "Investigation not found"

        analysis = self.analyze_investigation(investigation_id)
        supported_hyps = [
            h for h in investigation.hypotheses if h.status == HypothesisStatus.SUPPORTED
        ]

        parts = [
            f"## Investigation: {investigation.title}",
            f"**Status:** {investigation.status.value}",
            f"**Priority:** {investigation.priority.value}",
            f"**Progress:** {analysis['progress_pct']}%",
            "",
            "### Evidence Summary",
            f"Total evidence items: {analysis['evidence_count']}",
        ]

        for etype, count in analysis.get("evidence_by_type", {}).items():
            parts.append(f"- {etype}: {count}")

        if supported_hyps:
            parts.append("")
            parts.append("### Supported Hypotheses")
            for h in supported_hyps:
                parts.append(f"- {h.statement} (confidence: {h.confidence:.0%})")

        if investigation.findings_summary:
            parts.append("")
            parts.append("### Findings")
            parts.append(investigation.findings_summary)

        if investigation.recommendations:
            parts.append("")
            parts.append("### Recommendations")
            for rec in investigation.recommendations:
                parts.append(f"- {rec}")

        return "\n".join(parts)

    def close_investigation(
        self,
        investigation_id: str,
        findings_summary: str,
        root_cause: str = "",
        impact_assessment: str = "",
        recommendations: list[str] | None = None,
    ) -> Investigation | None:
        """Close an investigation with findings."""
        investigation = self._investigations.get(investigation_id)
        if not investigation:
            return None

        investigation.status = InvestigationStatus.CLOSED
        investigation.findings_summary = findings_summary
        investigation.root_cause = root_cause
        investigation.impact_assessment = impact_assessment
        investigation.recommendations = recommendations or []
        investigation.closed_at = utc_now()
        investigation.updated_at = utc_now()

        return investigation

    def get_investigation(self, investigation_id: str) -> Investigation | None:
        """Get investigation by ID."""
        return self._investigations.get(investigation_id)

    def list_investigations(
        self,
        status: InvestigationStatus | None = None,
        priority: InvestigationPriority | None = None,
        limit: int = 100,
    ) -> list[Investigation]:
        """List investigations with optional filters."""
        investigations = list(self._investigations.values())

        if status:
            investigations = [i for i in investigations if i.status == status]
        if priority:
            investigations = [i for i in investigations if i.priority == priority]

        return sorted(investigations, key=lambda i: i.created_at, reverse=True)[:limit]

    def get_metrics(self) -> dict[str, Any]:
        """Get engine metrics."""
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}

        for inv in self._investigations.values():
            s = inv.status.value
            p = inv.priority.value
            by_status[s] = by_status.get(s, 0) + 1
            by_priority[p] = by_priority.get(p, 0) + 1

        return {
            "total_investigations": len(self._investigations),
            "total_evidence": len(self._evidence_store),
            "by_status": by_status,
            "by_priority": by_priority,
        }


# Singleton
_engine: AIInvestigationEngine | None = None


def get_investigation_engine() -> AIInvestigationEngine:
    """Get investigation engine singleton."""
    global _engine
    if _engine is None:
        _engine = AIInvestigationEngine()
    return _engine
