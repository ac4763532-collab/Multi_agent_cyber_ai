"""Incident Management System."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class IncidentSeverity(StrEnum):
    """Incident severity levels."""

    CRITICAL = "critical"  # P1 - Immediate response required
    HIGH = "high"  # P2 - Response within 1 hour
    MEDIUM = "medium"  # P3 - Response within 4 hours
    LOW = "low"  # P4 - Response within 24 hours


class IncidentStatus(StrEnum):
    """Incident lifecycle status."""

    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    LESSONS_LEARNED = "lessons_learned"
    CLOSED = "closed"


class IncidentType(StrEnum):
    """Types of security incidents."""

    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class IncidentComment(BaseModel):
    """Comment on an incident."""

    comment_id: str = Field(default_factory=lambda: f"cmt_{uuid.uuid4().hex[:8]}")
    author: str
    content: str
    created_at: datetime = Field(default_factory=utc_now)
    is_internal: bool = True


class IncidentTask(BaseModel):
    """Task within an incident."""

    task_id: str = Field(default_factory=lambda: f"itask_{uuid.uuid4().hex[:8]}")
    title: str
    description: str = ""
    status: str = "pending"  # pending, in_progress, completed, blocked
    assigned_to: str | None = None
    due_date: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class IncidentArtifact(BaseModel):
    """Artifact/evidence attached to incident."""

    artifact_id: str = Field(default_factory=lambda: f"art_{uuid.uuid4().hex[:8]}")
    name: str
    artifact_type: str  # log, screenshot, packet_capture, memory_dump, etc.
    description: str = ""
    file_path: str | None = None
    hash_sha256: str | None = None
    size_bytes: int = 0
    uploaded_by: str = ""
    uploaded_at: datetime = Field(default_factory=utc_now)


class IncidentTimeline(BaseModel):
    """Timeline entry for incident."""

    entry_id: str = Field(default_factory=lambda: f"tl_{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    event_type: str
    description: str
    source: str = ""
    actor: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Security incident model."""

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str = ""
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    incident_type: IncidentType = IncidentType.OTHER

    # Related entities
    alert_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    investigation_id: str | None = None

    # Affected scope
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    affected_data_types: list[str] = Field(default_factory=list)

    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Assignment
    owner: str | None = None
    assigned_team: str | None = None
    escalated_to: str | None = None

    # Incident details
    root_cause: str = ""
    impact_assessment: str = ""
    containment_actions: list[str] = Field(default_factory=list)
    eradication_actions: list[str] = Field(default_factory=list)
    recovery_actions: list[str] = Field(default_factory=list)
    lessons_learned: str = ""

    # Related content
    comments: list[IncidentComment] = Field(default_factory=list)
    tasks: list[IncidentTask] = Field(default_factory=list)
    artifacts: list[IncidentArtifact] = Field(default_factory=list)
    timeline: list[IncidentTimeline] = Field(default_factory=list)

    # Timestamps
    detected_at: datetime = Field(default_factory=utc_now)
    reported_at: datetime | None = None
    contained_at: datetime | None = None
    eradicated_at: datetime | None = None
    recovered_at: datetime | None = None
    closed_at: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    # Metrics
    time_to_detect_minutes: int | None = None
    time_to_contain_minutes: int | None = None
    time_to_resolve_minutes: int | None = None

    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentMetrics(BaseModel):
    """Incident response metrics."""

    total_incidents: int = 0
    open_incidents: int = 0
    closed_incidents: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    avg_time_to_detect_min: float = 0.0
    avg_time_to_contain_min: float = 0.0
    avg_time_to_resolve_min: float = 0.0
    mttr_minutes: float = 0.0  # Mean Time To Resolve


class IncidentManager:
    """Manages security incidents."""

    def __init__(self):
        self._incidents: dict[str, Incident] = {}
        self._incident_count = 0

    def create_incident(
        self,
        title: str,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        incident_type: IncidentType = IncidentType.OTHER,
        description: str = "",
        alert_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
        affected_assets: list[str] | None = None,
        affected_users: list[str] | None = None,
        owner: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident:
        """Create a new incident."""
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            incident_type=incident_type,
            alert_ids=alert_ids or [],
            finding_ids=finding_ids or [],
            affected_assets=affected_assets or [],
            affected_users=affected_users or [],
            owner=owner,
            metadata=metadata or {},
        )

        # Add creation to timeline
        incident.timeline.append(
            IncidentTimeline(
                timestamp=utc_now(),
                event_type="incident_created",
                description=f"Incident created: {title}",
                source="system",
            )
        )

        self._incidents[incident.incident_id] = incident
        self._incident_count += 1

        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    def update_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        actor: str = "system",
        notes: str = "",
    ) -> Incident | None:
        """Update incident status."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        old_status = incident.status
        incident.status = new_status
        incident.updated_at = utc_now()

        # Update timestamps based on status
        now = utc_now()
        if new_status == IncidentStatus.CONTAINING:
            incident.contained_at = now
            if incident.detected_at:
                delta = (now - incident.detected_at).total_seconds() / 60
                incident.time_to_contain_minutes = int(delta)
        elif new_status == IncidentStatus.CLOSED:
            incident.closed_at = now
            if incident.detected_at:
                delta = (now - incident.detected_at).total_seconds() / 60
                incident.time_to_resolve_minutes = int(delta)

        # Add to timeline
        incident.timeline.append(
            IncidentTimeline(
                timestamp=now,
                event_type="status_change",
                description=f"Status changed from {old_status.value} to {new_status.value}",
                source="system",
                actor=actor,
                metadata={"notes": notes} if notes else {},
            )
        )

        return incident

    def assign_incident(
        self,
        incident_id: str,
        owner: str,
        team: str | None = None,
    ) -> Incident | None:
        """Assign incident to owner/team."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.owner = owner
        if team:
            incident.assigned_team = team
        incident.updated_at = utc_now()

        incident.timeline.append(
            IncidentTimeline(
                timestamp=utc_now(),
                event_type="assignment",
                description=f"Assigned to {owner}" + (f" ({team})" if team else ""),
                source="system",
            )
        )

        return incident

    def add_comment(
        self,
        incident_id: str,
        author: str,
        content: str,
        is_internal: bool = True,
    ) -> IncidentComment | None:
        """Add comment to incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        comment = IncidentComment(
            author=author,
            content=content,
            is_internal=is_internal,
        )
        incident.comments.append(comment)
        incident.updated_at = utc_now()

        return comment

    def add_task(
        self,
        incident_id: str,
        title: str,
        description: str = "",
        assigned_to: str | None = None,
        due_date: datetime | None = None,
    ) -> IncidentTask | None:
        """Add task to incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        task = IncidentTask(
            title=title,
            description=description,
            assigned_to=assigned_to,
            due_date=due_date,
        )
        incident.tasks.append(task)
        incident.updated_at = utc_now()

        return task

    def complete_task(
        self,
        incident_id: str,
        task_id: str,
    ) -> IncidentTask | None:
        """Mark task as completed."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        for task in incident.tasks:
            if task.task_id == task_id:
                task.status = "completed"
                task.completed_at = utc_now()
                incident.updated_at = utc_now()
                return task

        return None

    def add_artifact(
        self,
        incident_id: str,
        name: str,
        artifact_type: str,
        uploaded_by: str,
        description: str = "",
        file_path: str | None = None,
        hash_sha256: str | None = None,
        size_bytes: int = 0,
    ) -> IncidentArtifact | None:
        """Add artifact to incident."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        artifact = IncidentArtifact(
            name=name,
            artifact_type=artifact_type,
            description=description,
            file_path=file_path,
            hash_sha256=hash_sha256,
            size_bytes=size_bytes,
            uploaded_by=uploaded_by,
        )
        incident.artifacts.append(artifact)
        incident.updated_at = utc_now()

        return artifact

    def add_timeline_entry(
        self,
        incident_id: str,
        timestamp: datetime,
        event_type: str,
        description: str,
        source: str = "",
        actor: str | None = None,
    ) -> IncidentTimeline | None:
        """Add entry to incident timeline."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        entry = IncidentTimeline(
            timestamp=timestamp,
            event_type=event_type,
            description=description,
            source=source,
            actor=actor,
        )
        incident.timeline.append(entry)
        incident.timeline.sort(key=lambda e: e.timestamp)
        incident.updated_at = utc_now()

        return entry

    def close_incident(
        self,
        incident_id: str,
        root_cause: str,
        lessons_learned: str = "",
        closed_by: str = "system",
    ) -> Incident | None:
        """Close an incident with resolution details."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.status = IncidentStatus.CLOSED
        incident.root_cause = root_cause
        incident.lessons_learned = lessons_learned
        incident.closed_at = utc_now()
        incident.updated_at = utc_now()

        if incident.detected_at:
            delta = (incident.closed_at - incident.detected_at).total_seconds() / 60
            incident.time_to_resolve_minutes = int(delta)

        incident.timeline.append(
            IncidentTimeline(
                timestamp=utc_now(),
                event_type="incident_closed",
                description=f"Incident closed by {closed_by}",
                source="system",
                actor=closed_by,
            )
        )

        return incident

    def list_incidents(
        self,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        incident_type: IncidentType | None = None,
        owner: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Incident]:
        """List incidents with filters."""
        incidents = list(self._incidents.values())

        if status:
            incidents = [i for i in incidents if i.status == status]
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        if incident_type:
            incidents = [i for i in incidents if i.incident_type == incident_type]
        if owner:
            incidents = [i for i in incidents if i.owner == owner]

        # Sort by severity then creation time
        severity_order = {
            IncidentSeverity.CRITICAL: 0,
            IncidentSeverity.HIGH: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 3,
        }
        incidents.sort(key=lambda i: (severity_order.get(i.severity, 4), -i.created_at.timestamp()))

        return incidents[offset : offset + limit]

    def get_metrics(self) -> IncidentMetrics:
        """Calculate incident metrics."""
        metrics = IncidentMetrics()
        metrics.total_incidents = len(self._incidents)

        ttd_values = []
        ttc_values = []
        ttr_values = []

        for incident in self._incidents.values():
            # Count by status
            status = incident.status.value
            metrics.by_status[status] = metrics.by_status.get(status, 0) + 1

            if incident.status != IncidentStatus.CLOSED:
                metrics.open_incidents += 1
            else:
                metrics.closed_incidents += 1

            # Count by severity
            sev = incident.severity.value
            metrics.by_severity[sev] = metrics.by_severity.get(sev, 0) + 1

            # Count by type
            itype = incident.incident_type.value
            metrics.by_type[itype] = metrics.by_type.get(itype, 0) + 1

            # Collect timing metrics
            if incident.time_to_detect_minutes:
                ttd_values.append(incident.time_to_detect_minutes)
            if incident.time_to_contain_minutes:
                ttc_values.append(incident.time_to_contain_minutes)
            if incident.time_to_resolve_minutes:
                ttr_values.append(incident.time_to_resolve_minutes)

        # Calculate averages
        if ttd_values:
            metrics.avg_time_to_detect_min = sum(ttd_values) / len(ttd_values)
        if ttc_values:
            metrics.avg_time_to_contain_min = sum(ttc_values) / len(ttc_values)
        if ttr_values:
            metrics.avg_time_to_resolve_min = sum(ttr_values) / len(ttr_values)
            metrics.mttr_minutes = metrics.avg_time_to_resolve_min

        return metrics


# Singleton
_incident_manager: IncidentManager | None = None


def get_incident_manager() -> IncidentManager:
    """Get incident manager singleton."""
    global _incident_manager
    if _incident_manager is None:
        _incident_manager = IncidentManager()
    return _incident_manager
