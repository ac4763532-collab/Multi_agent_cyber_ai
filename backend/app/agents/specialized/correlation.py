"""Correlation Agent - cross-event correlation and attack chain detection."""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
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


class CorrelationType(StrEnum):
    """Types of event correlations."""

    SAME_SOURCE = "same_source"
    SAME_TARGET = "same_target"
    SAME_USER = "same_user"
    TEMPORAL = "temporal"
    ATTACK_CHAIN = "attack_chain"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


class AttackStage(StrEnum):
    """Kill chain / attack stages."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class CorrelationConfig(BaseModel):
    """Configuration for correlation engine."""

    # Time-based correlation
    temporal_window_sec: int = Field(
        default=3600, ge=60, description="Time window for temporal correlation"
    )

    # Attack chain detection
    min_chain_events: int = Field(
        default=3, ge=2, description="Minimum events for attack chain"
    )
    chain_timeout_sec: int = Field(
        default=86400, ge=3600, description="Max time span for attack chain"
    )

    # Correlation thresholds
    same_source_threshold: int = Field(
        default=5, ge=2, description="Events from same source to correlate"
    )
    same_target_threshold: int = Field(
        default=5, ge=2, description="Events to same target to correlate"
    )


class CorrelatedEvent(BaseModel):
    """An event that is part of a correlation."""

    event_id: str
    event_type: str
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    severity: EventSeverity = EventSeverity.MEDIUM
    attack_stage: AttackStage | None = None
    finding_id: str | None = None


class AttackChain(BaseModel):
    """Detected attack chain / kill chain progression."""

    chain_id: str
    stages: list[AttackStage]
    events: list[CorrelatedEvent]
    start_time: datetime
    end_time: datetime
    duration_sec: float
    source_ips: list[str]
    target_ips: list[str]
    users: list[str]
    completeness: float = Field(ge=0.0, le=1.0, description="Chain completeness ratio")


class CorrelationFinding(BaseFinding):
    """Finding from correlation analysis."""

    correlation_type: CorrelationType
    correlated_events: list[CorrelatedEvent] = Field(default_factory=list)
    attack_chain: AttackChain | None = None
    common_source_ip: str | None = None
    common_target_ip: str | None = None
    common_user: str | None = None
    time_span_sec: float = 0.0
    event_count: int = 0
    unique_sources: int = 0
    unique_targets: int = 0


# Event type to attack stage mapping
EVENT_TO_STAGE: dict[str, AttackStage] = {
    # Reconnaissance
    "port_scan": AttackStage.RECONNAISSANCE,
    "network_scan": AttackStage.RECONNAISSANCE,
    "dns_query": AttackStage.RECONNAISSANCE,
    "service_discovery": AttackStage.RECONNAISSANCE,
    # Initial Access
    "phishing": AttackStage.INITIAL_ACCESS,
    "exploit_attempt": AttackStage.INITIAL_ACCESS,
    "brute_force": AttackStage.INITIAL_ACCESS,
    "auth_success_after_failures": AttackStage.INITIAL_ACCESS,
    # Execution
    "process_creation": AttackStage.EXECUTION,
    "script_execution": AttackStage.EXECUTION,
    "command_execution": AttackStage.EXECUTION,
    # Persistence
    "scheduled_task": AttackStage.PERSISTENCE,
    "registry_modification": AttackStage.PERSISTENCE,
    "service_installation": AttackStage.PERSISTENCE,
    # Privilege Escalation
    "privilege_escalation": AttackStage.PRIVILEGE_ESCALATION,
    "sudo_command": AttackStage.PRIVILEGE_ESCALATION,
    "admin_login": AttackStage.PRIVILEGE_ESCALATION,
    # Credential Access
    "credential_dump": AttackStage.CREDENTIAL_ACCESS,
    "password_spray": AttackStage.CREDENTIAL_ACCESS,
    "kerberoasting": AttackStage.CREDENTIAL_ACCESS,
    # Discovery
    "ad_enumeration": AttackStage.DISCOVERY,
    "file_enumeration": AttackStage.DISCOVERY,
    "network_enumeration": AttackStage.DISCOVERY,
    # Lateral Movement
    "lateral_movement": AttackStage.LATERAL_MOVEMENT,
    "rdp_connection": AttackStage.LATERAL_MOVEMENT,
    "smb_connection": AttackStage.LATERAL_MOVEMENT,
    "ssh_connection": AttackStage.LATERAL_MOVEMENT,
    # C2
    "c2_communication": AttackStage.COMMAND_AND_CONTROL,
    "beaconing": AttackStage.COMMAND_AND_CONTROL,
    "dns_tunneling": AttackStage.COMMAND_AND_CONTROL,
    # Exfiltration
    "data_exfiltration": AttackStage.EXFILTRATION,
    "large_upload": AttackStage.EXFILTRATION,
    "dns_exfil": AttackStage.EXFILTRATION,
    # Impact
    "ransomware": AttackStage.IMPACT,
    "data_destruction": AttackStage.IMPACT,
    "service_disruption": AttackStage.IMPACT,
}


class CorrelationAgent(BaseAgent):
    """Correlates multiple events to detect attack patterns and chains.

    Capabilities:
    - Same-source event correlation
    - Same-target event correlation
    - User activity correlation
    - Temporal correlation
    - Attack chain / kill chain detection
    - Lateral movement detection
    """

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        """Initialize correlation agent."""
        super().__init__()
        self.config = config or CorrelationConfig()

        # Event stores for correlation (in production, use Redis/DB)
        self._events_by_source: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        self._events_by_target: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        self._events_by_user: dict[str, list[CorrelatedEvent]] = defaultdict(list)
        self._all_events: list[CorrelatedEvent] = []

    @property
    def agent_id(self) -> str:
        return "correlation_001"

    @property
    def name(self) -> str:
        return "Correlation Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CORRELATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "event_correlation",
            "attack_chain_detection",
            "lateral_movement_detection",
            "temporal_correlation",
            "user_activity_correlation",
            "multi_stage_attack_detection",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has events to correlate."""
        payload = task.payload or {}
        return "events" in payload or "findings" in payload or "event" in payload

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process correlation analysis task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract events
            events = self._extract_events(payload)

            # Add to correlation stores
            for event in events:
                self._index_event(event)

            # Perform correlations
            correlations: list[CorrelationFinding] = []

            # Same-source correlation
            source_corr = self._correlate_by_source(events)
            if source_corr:
                correlations.append(source_corr)

            # Same-target correlation
            target_corr = self._correlate_by_target(events)
            if target_corr:
                correlations.append(target_corr)

            # User correlation
            user_corr = self._correlate_by_user(events)
            if user_corr:
                correlations.append(user_corr)

            # Attack chain detection
            chain = self._detect_attack_chain(events)
            if chain:
                chain_finding = self._create_chain_finding(task, chain)
                correlations.append(chain_finding)

            # Select primary finding
            primary = self._select_primary_correlation(correlations)

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.SUCCESS if primary else ResultStatus.PARTIAL,
                finding=primary,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                metadata={
                    "events_processed": len(events),
                    "correlations_found": len(correlations),
                    "attack_chain_detected": chain is not None,
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
            finding_id=f"corr_{uuid.uuid4().hex}",
            finding_type="correlation",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_events(self, payload: dict[str, Any]) -> list[CorrelatedEvent]:
        """Extract events from payload."""
        events: list[CorrelatedEvent] = []

        # Single event
        if "event" in payload:
            event = self._parse_event(payload["event"])
            if event:
                events.append(event)

        # Multiple events
        if "events" in payload:
            for evt in payload["events"]:
                event = self._parse_event(evt)
                if event:
                    events.append(event)

        # From findings
        if "findings" in payload:
            for finding in payload["findings"]:
                if isinstance(finding, dict):
                    event = CorrelatedEvent(
                        event_id=finding.get("event_id", f"finding_{uuid.uuid4().hex}"),
                        event_type=finding.get("finding_type", "unknown"),
                        timestamp=self._parse_timestamp(finding.get("timestamp")),
                        source_ip=finding.get("source_ip"),
                        destination_ip=finding.get("destination_ip"),
                        username=finding.get("username"),
                        severity=self._parse_severity(finding.get("severity")),
                        finding_id=finding.get("finding_id"),
                    )
                    event.attack_stage = self._determine_attack_stage(event.event_type)
                    events.append(event)

        return events

    def _parse_event(self, evt: Any) -> CorrelatedEvent | None:
        """Parse a single event into CorrelatedEvent."""
        if isinstance(evt, dict):
            event = CorrelatedEvent(
                event_id=evt.get("event_id", f"evt_{uuid.uuid4().hex}"),
                event_type=evt.get("event_type", "unknown"),
                timestamp=self._parse_timestamp(evt.get("timestamp")),
                source_ip=evt.get("source_ip"),
                destination_ip=evt.get("destination_ip"),
                username=evt.get("username"),
                severity=self._parse_severity(evt.get("severity")),
            )
            event.attack_stage = self._determine_attack_stage(event.event_type)
            return event
        return None

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

    def _determine_attack_stage(self, event_type: str) -> AttackStage | None:
        """Determine attack stage from event type."""
        event_type_lower = event_type.lower()
        for pattern, stage in EVENT_TO_STAGE.items():
            if pattern in event_type_lower:
                return stage
        return None

    def _index_event(self, event: CorrelatedEvent) -> None:
        """Index event for correlation lookups."""
        self._all_events.append(event)

        if event.source_ip:
            self._events_by_source[event.source_ip].append(event)

        if event.destination_ip:
            self._events_by_target[event.destination_ip].append(event)

        if event.username:
            self._events_by_user[event.username].append(event)

    def _correlate_by_source(
        self, new_events: list[CorrelatedEvent]
    ) -> CorrelationFinding | None:
        """Correlate events from the same source."""
        for event in new_events:
            if not event.source_ip:
                continue

            related = self._events_by_source.get(event.source_ip, [])
            if len(related) >= self.config.same_source_threshold:
                # Filter to temporal window
                cutoff = utc_now() - timedelta(seconds=self.config.temporal_window_sec)
                recent = [e for e in related if e.timestamp >= cutoff]

                if len(recent) >= self.config.same_source_threshold:
                    return self._create_source_correlation(event.source_ip, recent)

        return None

    def _correlate_by_target(
        self, new_events: list[CorrelatedEvent]
    ) -> CorrelationFinding | None:
        """Correlate events targeting the same destination."""
        for event in new_events:
            if not event.destination_ip:
                continue

            related = self._events_by_target.get(event.destination_ip, [])
            if len(related) >= self.config.same_target_threshold:
                cutoff = utc_now() - timedelta(seconds=self.config.temporal_window_sec)
                recent = [e for e in related if e.timestamp >= cutoff]

                if len(recent) >= self.config.same_target_threshold:
                    return self._create_target_correlation(event.destination_ip, recent)

        return None

    def _correlate_by_user(
        self, new_events: list[CorrelatedEvent]
    ) -> CorrelationFinding | None:
        """Correlate events for the same user."""
        for event in new_events:
            if not event.username:
                continue

            related = self._events_by_user.get(event.username, [])
            if len(related) >= self.config.same_source_threshold:
                cutoff = utc_now() - timedelta(seconds=self.config.temporal_window_sec)
                recent = [e for e in related if e.timestamp >= cutoff]

                if len(recent) >= self.config.same_source_threshold:
                    return self._create_user_correlation(event.username, recent)

        return None

    def _detect_attack_chain(
        self, events: list[CorrelatedEvent]
    ) -> AttackChain | None:
        """Detect attack chain from events."""
        # Need minimum events with attack stages
        staged_events = [e for e in events if e.attack_stage]
        if len(staged_events) < self.config.min_chain_events:
            return None

        # Sort by timestamp
        staged_events.sort(key=lambda e: e.timestamp)

        # Check for progression through stages
        stages_seen: list[AttackStage] = []
        chain_events: list[CorrelatedEvent] = []

        stage_order = list(AttackStage)
        for event in staged_events:
            if event.attack_stage and event.attack_stage not in stages_seen:
                # Check if this is a logical progression
                current_idx = stage_order.index(event.attack_stage)
                last_idx = stage_order.index(stages_seen[-1]) if stages_seen else -1
                if not stages_seen or current_idx >= last_idx:
                    stages_seen.append(event.attack_stage)
                    chain_events.append(event)

        if len(stages_seen) >= self.config.min_chain_events:
            # Calculate chain completeness (how many kill chain stages covered)
            completeness = len(stages_seen) / len(stage_order)

            return AttackChain(
                chain_id=f"chain_{uuid.uuid4().hex}",
                stages=stages_seen,
                events=chain_events,
                start_time=chain_events[0].timestamp,
                end_time=chain_events[-1].timestamp,
                duration_sec=(
                    chain_events[-1].timestamp - chain_events[0].timestamp
                ).total_seconds(),
                source_ips=list({e.source_ip for e in chain_events if e.source_ip}),
                target_ips=list({e.destination_ip for e in chain_events if e.destination_ip}),
                users=list({e.username for e in chain_events if e.username}),
                completeness=completeness,
            )

        return None

    def _create_source_correlation(
        self, source_ip: str, events: list[CorrelatedEvent]
    ) -> CorrelationFinding:
        """Create finding for same-source correlation."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

        return CorrelationFinding(
            finding_id=f"corr_src_{uuid.uuid4().hex}",
            finding_type="source_correlation",
            event_id=events[0].event_id,
            task_id="",
            agent_id=self.agent_id,
            severity=self._determine_correlation_severity(events),
            confidence=MatchConfidence.HIGH,
            correlation_type=CorrelationType.SAME_SOURCE,
            correlated_events=events,
            common_source_ip=source_ip,
            time_span_sec=time_span,
            event_count=len(events),
            unique_targets=len({e.destination_ip for e in events if e.destination_ip}),
            explanation=f"Correlated {len(events)} events from source {source_ip}",
            mitre_techniques=["T1595"],
            mitre_tactics=["reconnaissance"],
        )

    def _create_target_correlation(
        self, target_ip: str, events: list[CorrelatedEvent]
    ) -> CorrelationFinding:
        """Create finding for same-target correlation."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

        return CorrelationFinding(
            finding_id=f"corr_tgt_{uuid.uuid4().hex}",
            finding_type="target_correlation",
            event_id=events[0].event_id,
            task_id="",
            agent_id=self.agent_id,
            severity=self._determine_correlation_severity(events),
            confidence=MatchConfidence.HIGH,
            correlation_type=CorrelationType.SAME_TARGET,
            correlated_events=events,
            common_target_ip=target_ip,
            time_span_sec=time_span,
            event_count=len(events),
            unique_sources=len({e.source_ip for e in events if e.source_ip}),
            explanation=f"Correlated {len(events)} events targeting {target_ip}",
        )

    def _create_user_correlation(
        self, username: str, events: list[CorrelatedEvent]
    ) -> CorrelationFinding:
        """Create finding for same-user correlation."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        time_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()

        return CorrelationFinding(
            finding_id=f"corr_user_{uuid.uuid4().hex}",
            finding_type="user_correlation",
            event_id=events[0].event_id,
            task_id="",
            agent_id=self.agent_id,
            severity=self._determine_correlation_severity(events),
            confidence=MatchConfidence.HIGH,
            correlation_type=CorrelationType.SAME_USER,
            correlated_events=events,
            common_user=username,
            time_span_sec=time_span,
            event_count=len(events),
            explanation=f"Correlated {len(events)} events for user {username}",
            mitre_techniques=["T1078"],
            mitre_tactics=["defense-evasion", "persistence"],
        )

    def _create_chain_finding(
        self, task: AgentTask, chain: AttackChain
    ) -> CorrelationFinding:
        """Create finding for attack chain detection."""
        return CorrelationFinding(
            finding_id=f"corr_chain_{uuid.uuid4().hex}",
            finding_type="attack_chain",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            severity=EventSeverity.CRITICAL if chain.completeness > 0.5 else EventSeverity.HIGH,
            confidence=MatchConfidence.HIGH,
            correlation_type=CorrelationType.ATTACK_CHAIN,
            correlated_events=chain.events,
            attack_chain=chain,
            time_span_sec=chain.duration_sec,
            event_count=len(chain.events),
            explanation=(
                f"Attack chain detected: {len(chain.stages)} stages over "
                f"{chain.duration_sec:.0f}s ({chain.completeness:.0%} complete)"
            ),
            mitre_tactics=[s.value.replace("_", "-") for s in chain.stages],
        )

    def _determine_correlation_severity(
        self, events: list[CorrelatedEvent]
    ) -> EventSeverity:
        """Determine severity based on correlated events."""
        if any(e.severity == EventSeverity.CRITICAL for e in events):
            return EventSeverity.CRITICAL
        if any(e.severity == EventSeverity.HIGH for e in events):
            return EventSeverity.HIGH
        if len(events) > 10:
            return EventSeverity.HIGH
        if len(events) > 5:
            return EventSeverity.MEDIUM
        return EventSeverity.LOW

    def _select_primary_correlation(
        self, correlations: list[CorrelationFinding]
    ) -> CorrelationFinding | None:
        """Select the most significant correlation as primary."""
        if not correlations:
            return None

        # Prioritize attack chains
        chains = [c for c in correlations if c.correlation_type == CorrelationType.ATTACK_CHAIN]
        if chains:
            return chains[0]

        # Then by severity and event count
        correlations.sort(
            key=lambda c: (
                -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(c.severity.value, 0),
                -c.event_count,
            )
        )
        return correlations[0]
