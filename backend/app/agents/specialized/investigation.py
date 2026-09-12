"""Investigation Agent - deep-dive analysis and forensic timeline construction."""

import uuid
from collections import defaultdict
from datetime import datetime
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


class InvestigationStatus(StrEnum):
    """Status of an investigation."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_INFO = "pending_info"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EvidenceType(StrEnum):
    """Types of evidence collected."""

    LOG_ENTRY = "log_entry"
    NETWORK_FLOW = "network_flow"
    FILE_ARTIFACT = "file_artifact"
    PROCESS_INFO = "process_info"
    REGISTRY_KEY = "registry_key"
    USER_ACTIVITY = "user_activity"
    ALERT = "alert"
    FINDING = "finding"


class TimelineEntry(BaseModel):
    """Single entry in forensic timeline."""

    timestamp: datetime
    event_id: str
    event_type: str
    description: str
    source: str = ""
    actor: str = ""  # User or process
    target: str = ""  # Target system/file/resource
    evidence_type: EvidenceType = EvidenceType.LOG_ENTRY
    severity: EventSeverity = EventSeverity.INFORMATIONAL
    raw_data: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Collected evidence piece."""

    evidence_id: str
    evidence_type: EvidenceType
    source: str
    collected_at: datetime
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    related_events: list[str] = Field(default_factory=list)
    chain_of_custody: list[str] = Field(default_factory=list)
    integrity_hash: str = ""


class AffectedAsset(BaseModel):
    """Asset affected by the incident."""

    asset_id: str
    asset_type: str  # host, user, service, data
    name: str
    ip_address: str | None = None
    hostname: str | None = None
    criticality: str = "medium"  # low, medium, high, critical
    impact: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class InvestigationSummary(BaseModel):
    """Summary of investigation findings."""

    hypothesis: str = ""
    confirmed_findings: list[str] = Field(default_factory=list)
    unconfirmed_findings: list[str] = Field(default_factory=list)
    attack_vector: str = ""
    root_cause: str = ""
    scope_assessment: str = ""
    data_at_risk: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class InvestigationFinding(BaseFinding):
    """Finding from investigation analysis."""

    investigation_id: str
    status: InvestigationStatus = InvestigationStatus.OPEN
    timeline: list[TimelineEntry] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    summary: InvestigationSummary = Field(default_factory=InvestigationSummary)
    related_findings: list[str] = Field(default_factory=list)
    time_span_hours: float = 0.0
    event_count: int = 0


class InvestigationAgent(BaseAgent):
    """Performs deep-dive analysis and constructs forensic timelines.

    Capabilities:
    - Evidence collection and correlation
    - Forensic timeline construction
    - Affected asset identification
    - Root cause analysis
    - Attack vector determination
    - Scope assessment
    """

    def __init__(self) -> None:
        """Initialize investigation agent."""
        super().__init__()
        self._active_investigations: dict[str, InvestigationFinding] = {}

    @property
    def agent_id(self) -> str:
        return "investigation_001"

    @property
    def name(self) -> str:
        return "Investigation Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.INVESTIGATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "evidence_collection",
            "timeline_construction",
            "root_cause_analysis",
            "scope_assessment",
            "asset_impact_analysis",
            "attack_vector_determination",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has investigation data."""
        payload = task.payload or {}
        return any(
            k in payload for k in ["incident", "finding", "events", "alert", "investigation_id"]
        )

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process investigation task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Create or retrieve investigation
            investigation_id = payload.get("investigation_id", f"inv_{uuid.uuid4().hex}")

            # Extract events and findings
            events = self._extract_events(payload)
            findings = self._extract_findings(payload)

            # Build timeline
            timeline = self._build_timeline(events, findings)

            # Collect evidence
            evidence = self._collect_evidence(events, findings)

            # Identify affected assets
            affected_assets = self._identify_affected_assets(events, findings)

            # Analyze and summarize
            summary = self._analyze_investigation(timeline, evidence, affected_assets)

            # Calculate time span
            time_span = 0.0
            if timeline:
                sorted_timeline = sorted(timeline, key=lambda t: t.timestamp)
                time_span = (
                    sorted_timeline[-1].timestamp - sorted_timeline[0].timestamp
                ).total_seconds() / 3600

            # Determine severity
            severity = self._determine_severity(timeline, affected_assets)

            # Create finding
            finding = InvestigationFinding(
                finding_id=f"inv_finding_{uuid.uuid4().hex}",
                finding_type="investigation",
                event_id=task.event_id,
                task_id=task.task_id,
                agent_id=self.agent_id,
                severity=severity,
                confidence=MatchConfidence.HIGH if len(evidence) > 3 else MatchConfidence.MEDIUM,
                investigation_id=investigation_id,
                status=InvestigationStatus.IN_PROGRESS,
                timeline=timeline,
                evidence=evidence,
                affected_assets=affected_assets,
                summary=summary,
                related_findings=[f.get("finding_id", "") for f in findings if isinstance(f, dict)],
                time_span_hours=time_span,
                event_count=len(timeline),
                explanation=summary.hypothesis or "Investigation in progress",
                recommendations=summary.recommended_actions,
            )

            # Store active investigation
            self._active_investigations[investigation_id] = finding

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
                    "investigation_id": investigation_id,
                    "timeline_entries": len(timeline),
                    "evidence_count": len(evidence),
                    "affected_assets": len(affected_assets),
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
            finding_id=f"inv_{uuid.uuid4().hex}",
            finding_type="investigation",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_events(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract events from payload."""
        events = []

        if "events" in payload:
            for evt in payload["events"]:
                if isinstance(evt, dict):
                    events.append(evt)

        if "event" in payload:
            evt = payload["event"]
            if isinstance(evt, dict):
                events.append(evt)

        if "incident" in payload:
            incident = payload["incident"]
            if isinstance(incident, dict) and "events" in incident:
                for evt in incident["events"]:
                    if isinstance(evt, dict):
                        events.append(evt)

        return events

    def _extract_findings(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract findings from payload."""
        findings = []

        if "findings" in payload:
            for f in payload["findings"]:
                if isinstance(f, dict):
                    findings.append(f)

        if "finding" in payload:
            f = payload["finding"]
            if isinstance(f, dict):
                findings.append(f)

        if "alert" in payload:
            alert = payload["alert"]
            if isinstance(alert, dict):
                findings.append(alert)

        return findings

    def _build_timeline(
        self,
        events: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> list[TimelineEntry]:
        """Build forensic timeline from events and findings."""
        timeline: list[TimelineEntry] = []

        # Add events to timeline
        for evt in events:
            timestamp = self._parse_timestamp(evt.get("timestamp"))
            entry = TimelineEntry(
                timestamp=timestamp,
                event_id=evt.get("event_id", f"evt_{uuid.uuid4().hex[:8]}"),
                event_type=evt.get("event_type", "unknown"),
                description=self._generate_event_description(evt),
                source=evt.get("source", evt.get("source_ip", "")),
                actor=evt.get("username", evt.get("user", "")),
                target=evt.get("destination_ip", evt.get("hostname", "")),
                evidence_type=self._determine_evidence_type(evt),
                severity=self._parse_severity(evt.get("severity")),
                raw_data=evt,
            )
            timeline.append(entry)

        # Add findings to timeline
        for finding in findings:
            timestamp = self._parse_timestamp(finding.get("timestamp", finding.get("created_at")))
            finding_desc = finding.get(
                "explanation", finding.get("description", "Finding detected")
            )
            entry = TimelineEntry(
                timestamp=timestamp,
                event_id=finding.get("finding_id", f"finding_{uuid.uuid4().hex[:8]}"),
                event_type=finding.get("finding_type", "finding"),
                description=finding_desc,
                source=finding.get("agent_id", "detection"),
                actor="",
                target="",
                evidence_type=EvidenceType.FINDING,
                severity=self._parse_severity(finding.get("severity")),
                raw_data=finding,
            )
            timeline.append(entry)

        # Sort by timestamp
        timeline.sort(key=lambda t: t.timestamp)

        return timeline

    def _collect_evidence(
        self,
        events: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> list[Evidence]:
        """Collect evidence from events and findings."""
        evidence_list: list[Evidence] = []
        now = utc_now()

        # Collect from events
        for evt in events:
            evidence = Evidence(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                evidence_type=self._determine_evidence_type(evt),
                source=evt.get("source", "unknown"),
                collected_at=now,
                description=self._generate_event_description(evt),
                data={
                    "event_id": evt.get("event_id"),
                    "event_type": evt.get("event_type"),
                    "source_ip": evt.get("source_ip"),
                    "destination_ip": evt.get("destination_ip"),
                    "username": evt.get("username"),
                    "raw_data": evt.get("raw_data", {}),
                },
                related_events=[evt.get("event_id", "")],
                chain_of_custody=[f"Collected by {self.agent_id} at {now.isoformat()}"],
            )
            evidence_list.append(evidence)

        # Collect from findings
        for finding in findings:
            evidence = Evidence(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                evidence_type=EvidenceType.FINDING,
                source=finding.get("agent_id", "unknown"),
                collected_at=now,
                description=finding.get("explanation", "Finding evidence"),
                data=finding,
                related_events=[finding.get("event_id", "")],
                chain_of_custody=[f"Collected by {self.agent_id} at {now.isoformat()}"],
            )
            evidence_list.append(evidence)

        return evidence_list

    def _identify_affected_assets(
        self,
        events: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> list[AffectedAsset]:
        """Identify assets affected by the incident."""
        assets: dict[str, AffectedAsset] = {}

        for evt in events:
            # Source host
            src_ip = evt.get("source_ip")
            if src_ip and src_ip not in assets:
                assets[src_ip] = AffectedAsset(
                    asset_id=f"asset_{src_ip.replace('.', '_')}",
                    asset_type="host",
                    name=evt.get("source_hostname", src_ip),
                    ip_address=src_ip,
                    hostname=evt.get("source_hostname"),
                    criticality=self._assess_asset_criticality(src_ip),
                    impact="Source of suspicious activity",
                    first_seen=self._parse_timestamp(evt.get("timestamp")),
                )
            elif src_ip:
                assets[src_ip].last_seen = self._parse_timestamp(evt.get("timestamp"))

            # Destination host
            dst_ip = evt.get("destination_ip")
            if dst_ip and dst_ip not in assets:
                assets[dst_ip] = AffectedAsset(
                    asset_id=f"asset_{dst_ip.replace('.', '_')}",
                    asset_type="host",
                    name=evt.get("destination_hostname", dst_ip),
                    ip_address=dst_ip,
                    hostname=evt.get("destination_hostname"),
                    criticality=self._assess_asset_criticality(dst_ip),
                    impact="Target of suspicious activity",
                    first_seen=self._parse_timestamp(evt.get("timestamp")),
                )
            elif dst_ip:
                assets[dst_ip].last_seen = self._parse_timestamp(evt.get("timestamp"))

            # User
            username = evt.get("username")
            if username and username not in assets:
                assets[username] = AffectedAsset(
                    asset_id=f"asset_user_{username}",
                    asset_type="user",
                    name=username,
                    criticality="medium",
                    impact="User account involved in activity",
                    first_seen=self._parse_timestamp(evt.get("timestamp")),
                )

        return list(assets.values())

    def _analyze_investigation(
        self,
        timeline: list[TimelineEntry],
        evidence: list[Evidence],
        affected_assets: list[AffectedAsset],
    ) -> InvestigationSummary:
        """Analyze collected data and generate summary."""
        summary = InvestigationSummary()

        if not timeline:
            summary.hypothesis = "Insufficient data for analysis"
            return summary

        # Analyze event types
        event_types = [t.event_type for t in timeline]
        type_counts = defaultdict(int)
        for et in event_types:
            type_counts[et] += 1

        # Determine attack vector
        if any("phishing" in et.lower() for et in event_types):
            summary.attack_vector = "Email phishing"
        elif any("brute" in et.lower() for et in event_types):
            summary.attack_vector = "Brute force authentication"
        elif any("exploit" in et.lower() for et in event_types):
            summary.attack_vector = "Vulnerability exploitation"
        elif any("lateral" in et.lower() for et in event_types):
            summary.attack_vector = "Lateral movement from compromised host"
        else:
            summary.attack_vector = "Under investigation"

        # Generate hypothesis
        high_sev_events = [
            t for t in timeline if t.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
        ]
        high_severity = len(high_sev_events)
        if high_severity > 3:
            summary.hypothesis = (
                f"Active security incident detected with {high_severity} high-severity events. "
                f"Attack vector appears to be {summary.attack_vector.lower()}."
            )
        else:
            summary.hypothesis = (
                f"Suspicious activity detected involving {len(affected_assets)} assets. "
                "Further investigation recommended."
            )

        # Confirmed findings
        summary.confirmed_findings = [
            f"{len(timeline)} security events collected",
            f"{len(affected_assets)} assets affected",
            f"{len(evidence)} pieces of evidence collected",
        ]

        # Scope assessment
        unique_actors = {t.actor for t in timeline if t.actor}
        summary.scope_assessment = (
            f"Incident scope: {len(affected_assets)} assets, "
            f"{len(unique_actors)} users, "
            f"spanning {len(timeline)} events"
        )

        # Recommended actions
        summary.recommended_actions = [
            "Review affected user accounts for compromise indicators",
            "Analyze network traffic for additional C2 communications",
            "Check endpoint logs for persistence mechanisms",
            "Consider isolating affected systems",
            "Preserve evidence for potential forensic analysis",
        ]

        return summary

    def _determine_evidence_type(self, evt: dict[str, Any]) -> EvidenceType:
        """Determine evidence type from event."""
        event_type = evt.get("event_type", "").lower()

        if "network" in event_type or "flow" in event_type:
            return EvidenceType.NETWORK_FLOW
        elif "process" in event_type:
            return EvidenceType.PROCESS_INFO
        elif "file" in event_type:
            return EvidenceType.FILE_ARTIFACT
        elif "registry" in event_type:
            return EvidenceType.REGISTRY_KEY
        elif "user" in event_type or "auth" in event_type:
            return EvidenceType.USER_ACTIVITY
        elif "alert" in event_type:
            return EvidenceType.ALERT
        else:
            return EvidenceType.LOG_ENTRY

    def _generate_event_description(self, evt: dict[str, Any]) -> str:
        """Generate human-readable event description."""
        event_type = evt.get("event_type", "Unknown event")
        source = evt.get("source_ip", evt.get("source", "unknown"))
        dest = evt.get("destination_ip", "")
        user = evt.get("username", "")

        parts = [event_type]
        if source:
            parts.append(f"from {source}")
        if dest:
            parts.append(f"to {dest}")
        if user:
            parts.append(f"by user {user}")

        return " ".join(parts)

    def _assess_asset_criticality(self, ip: str) -> str:
        """Assess asset criticality (simplified)."""
        # In production, look up asset inventory
        if ip.startswith("10.0.0.") or ip.startswith("192.168.1."):
            return "high"  # Assume internal critical range
        return "medium"

    def _parse_timestamp(self, ts: Any) -> datetime:
        """Parse timestamp from various formats."""
        if ts is None:
            return utc_now()
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return utc_now()
        return utc_now()

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

    def _determine_severity(
        self,
        timeline: list[TimelineEntry],
        affected_assets: list[AffectedAsset],
    ) -> EventSeverity:
        """Determine overall investigation severity."""
        if not timeline:
            return EventSeverity.LOW

        # Check for critical events
        if any(t.severity == EventSeverity.CRITICAL for t in timeline):
            return EventSeverity.CRITICAL

        # High severity if multiple high events or critical assets
        high_count = sum(1 for t in timeline if t.severity == EventSeverity.HIGH)
        critical_assets = sum(1 for a in affected_assets if a.criticality == "critical")

        if high_count > 3 or critical_assets > 0:
            return EventSeverity.HIGH

        if high_count > 0 or len(affected_assets) > 5:
            return EventSeverity.MEDIUM

        return EventSeverity.LOW
