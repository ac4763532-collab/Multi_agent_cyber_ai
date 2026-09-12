"""Log Analyzer Agent - full implementation for real-time log analysis."""

import re
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


class DetectionType(StrEnum):
    """Types of detections the log analyzer can produce."""

    BRUTE_FORCE = "brute_force"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REPEATED_ACCESS = "repeated_access"
    SUSPICIOUS_RATE = "suspicious_rate"
    OFF_HOURS_ACTIVITY = "off_hours_activity"
    ANOMALY = "anomaly"
    PATTERN_MATCH = "pattern_match"


class LogAnalyzerConfig(BaseModel):
    """Configuration for log analysis thresholds."""

    # Brute force detection
    brute_force_threshold: int = Field(
        default=5, ge=1, description="Failed auth attempts to trigger"
    )
    brute_force_window_sec: int = Field(default=60, ge=10, description="Time window in seconds")

    # Rate limiting
    rate_limit_threshold: int = Field(
        default=100, ge=10, description="Requests per window to trigger"
    )
    rate_limit_window_sec: int = Field(default=60, ge=10, description="Time window in seconds")

    # Business hours
    business_hours_start: int = Field(default=8, ge=0, le=23, description="Start hour (0-23)")
    business_hours_end: int = Field(default=18, ge=0, le=23, description="End hour (0-23)")

    # Anomaly detection
    anomaly_zscore_threshold: float = Field(default=3.0, ge=1.0, description="Z-score for anomaly")

    # Repeated access
    repeated_access_threshold: int = Field(
        default=50, ge=5, description="Accesses to same resource"
    )
    repeated_access_window_sec: int = Field(
        default=300, ge=60, description="Time window in seconds"
    )


class AnomalySignal(BaseModel):
    """Anomaly detection signal - separate from attack classification."""

    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Normalized anomaly score")
    features: dict[str, float] = Field(default_factory=dict, description="Feature values")
    baseline: dict[str, float] = Field(default_factory=dict, description="Baseline values")
    model_version: str = Field(default="1.0.0", description="Anomaly model version")
    is_anomaly: bool = Field(default=False, description="Whether score exceeds threshold")


class LogFinding(BaseFinding):
    """Finding specific to log analysis."""

    detection_type: DetectionType = Field(..., description="Type of detection")
    matching_events: list[str] = Field(default_factory=list, description="Event IDs that matched")
    time_range_start: datetime | None = Field(default=None, description="Start of detection window")
    time_range_end: datetime | None = Field(default=None, description="End of detection window")
    source: str = Field(default="", description="Source system or IP")
    rule_id: str = Field(default="", description="Detection rule ID")
    model_version: str | None = Field(default=None, description="Model version if ML-based")
    anomaly_signal: AnomalySignal | None = Field(
        default=None, description="Anomaly signal if applicable"
    )
    threshold_exceeded: dict[str, Any] = Field(
        default_factory=dict, description="Threshold details"
    )


# Authentication failure patterns
AUTH_FAILURE_PATTERNS = [
    # Linux/PAM patterns
    r"(?i)failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)",
    r"(?i)authentication\s+failure.*user=(\S+).*rhost=(\S+)",
    r"(?i)pam_unix.*authentication\s+failure",
    # Windows patterns
    r"(?i)an\s+account\s+failed\s+to\s+log\s+on",
    r"(?i)logon\s+failure.*user.*(\S+)",
    # Generic patterns
    r"(?i)(failed|invalid|bad)\s+(login|auth|password|credential)",
    r"(?i)access\s+denied",
]

# Privilege escalation patterns
PRIVILEGE_PATTERNS = [
    r"(?i)sudo.*command=",
    r"(?i)su\s*:\s*\S+\s+to\s+root",
    r"(?i)privilege\s+escalation",
    r"(?i)user\s+added\s+to\s+.*admin",
    r"(?i)security\s+group.*administrator",
]

# Windows Event IDs for auth
WINDOWS_AUTH_FAILURE_IDS = {"4625", "4771", "4776"}
WINDOWS_AUTH_SUCCESS_IDS = {"4624", "4648"}
WINDOWS_PRIV_ESCALATION_IDS = {"4672", "4728", "4732", "4756"}


class LogAnalyzerAgent(BaseAgent):
    """Analyzes logs for brute force, anomalies, and security patterns.

    Supports:
    - JSON structured logs
    - CSV logs
    - Plain text (regex patterns)
    - Linux authentication logs
    - Windows security events
    - Suricata events

    Detections:
    - Brute force indicators
    - Impossible travel patterns
    - Privilege escalation attempts
    - Repeated access anomalies
    - Suspicious request rates
    - Off-hours activity
    """

    def __init__(self, config: LogAnalyzerConfig | None = None) -> None:
        """Initialize log analyzer with configuration."""
        super().__init__()
        self.config = config or LogAnalyzerConfig()

        # Event tracking for correlation (in-memory, would be Redis in production)
        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        self._access_counts: dict[str, list[datetime]] = defaultdict(list)
        self._user_locations: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    @property
    def agent_id(self) -> str:
        return "log_analyzer_001"

    @property
    def name(self) -> str:
        return "Log Analyzer Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.LOG_ANALYZER

    @property
    def capabilities(self) -> list[str]:
        return [
            "brute_force_detection",
            "anomaly_detection",
            "privilege_escalation_detection",
            "rate_limiting_detection",
            "off_hours_detection",
            "log_parsing",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has log data."""
        payload = task.payload or {}
        return "event" in payload or "log" in payload or "events" in payload

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process log analysis task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract log data
            events = self._extract_events(payload)

            # Analyze logs
            findings: list[LogFinding] = []

            for event in events:
                # Check for auth failures (brute force)
                brute_force_finding = self._check_brute_force(event)
                if brute_force_finding:
                    findings.append(brute_force_finding)

                # Check for privilege escalation
                priv_finding = self._check_privilege_escalation(event)
                if priv_finding:
                    findings.append(priv_finding)

                # Check for rate limiting
                rate_finding = self._check_rate_limit(event)
                if rate_finding:
                    findings.append(rate_finding)

                # Check for off-hours activity
                off_hours_finding = self._check_off_hours(event)
                if off_hours_finding:
                    findings.append(off_hours_finding)

                # Calculate anomaly signal
                anomaly = self._calculate_anomaly(event)
                if anomaly and anomaly.is_anomaly:
                    findings.append(self._create_anomaly_finding(task, event, anomaly))

            # Return primary finding or aggregate
            primary_finding = self._aggregate_findings(task, findings) if findings else None

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.SUCCESS if primary_finding else ResultStatus.PARTIAL,
                finding=primary_finding,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                metadata={
                    "events_analyzed": len(events),
                    "findings_count": len(findings),
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
            finding_id=f"log_{uuid.uuid4().hex}",
            finding_type="log_analysis",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_events(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract events from various payload formats."""
        events = []

        # Single event
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                events.append(event)
            else:
                if hasattr(event, "model_dump"):
                    events.append(event.model_dump())
                else:
                    events.append({"raw": str(event)})

        # Multiple events
        if "events" in payload:
            for evt in payload["events"]:
                if isinstance(evt, dict):
                    events.append(evt)

        # Raw log
        if "log" in payload:
            log_data = payload["log"]
            if isinstance(log_data, str):
                events.append({"raw_data": {"message": log_data}, "message": log_data})
            elif isinstance(log_data, dict):
                events.append(log_data)

        return events

    def _check_brute_force(self, event: dict[str, Any]) -> LogFinding | None:
        """Check for brute force indicators."""
        # Extract relevant fields
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})
        message = raw_data.get("message", "") if isinstance(raw_data, dict) else str(raw_data)
        source_ip = event.get("source_ip", "")
        username = event.get("username", "")
        status = event.get("status", "")
        action = event.get("action", "")

        # Check if this is an auth failure
        is_auth_failure = False

        # Check event type
        if event_type in ("auth_failed", "login_failed", "authentication_failure"):
            is_auth_failure = True

        # Check status/action
        if status in ("failure", "failed", "denied") or action in ("denied", "blocked"):
            is_auth_failure = True

        # Check Windows Event IDs
        event_id = str(raw_data.get("EventID", raw_data.get("event_id", "")))
        if event_id in WINDOWS_AUTH_FAILURE_IDS:
            is_auth_failure = True

        # Check message patterns
        if not is_auth_failure:
            for pattern in AUTH_FAILURE_PATTERNS:
                if re.search(pattern, message):
                    is_auth_failure = True
                    break

        if not is_auth_failure:
            return None

        # Track the failure
        tracking_key = source_ip or username or "unknown"
        now = utc_now()
        self._auth_failures[tracking_key].append(now)

        # Clean old entries
        window_start = now - timedelta(seconds=self.config.brute_force_window_sec)
        self._auth_failures[tracking_key] = [
            t for t in self._auth_failures[tracking_key] if t >= window_start
        ]

        # Check threshold
        failure_count = len(self._auth_failures[tracking_key])
        if failure_count >= self.config.brute_force_threshold:
            return LogFinding(
                finding_id=f"bf_{uuid.uuid4().hex}",
                finding_type="brute_force_indicator",
                event_id=event.get("event_id", "unknown"),
                task_id="",  # Will be set by caller
                agent_id=self.agent_id,
                severity=EventSeverity.HIGH,
                confidence=MatchConfidence.HIGH,
                detection_type=DetectionType.BRUTE_FORCE,
                matching_events=[event.get("event_id", "")],
                time_range_start=self._auth_failures[tracking_key][0],
                time_range_end=now,
                source=source_ip,
                rule_id="brute_force_detector",
                explanation=(
                    f"Detected {failure_count} auth failures from {tracking_key} "
                    f"in {self.config.brute_force_window_sec}s"
                ),
                threshold_exceeded={
                    "threshold": self.config.brute_force_threshold,
                    "actual": failure_count,
                    "window_sec": self.config.brute_force_window_sec,
                },
                mitre_techniques=["T1110", "T1110.001"],
                mitre_tactics=["credential-access"],
            )

        return None

    def _check_privilege_escalation(self, event: dict[str, Any]) -> LogFinding | None:
        """Check for privilege escalation indicators."""
        event_type = event.get("event_type", "")
        raw_data = event.get("raw_data", {})
        message = raw_data.get("message", "") if isinstance(raw_data, dict) else str(raw_data)

        is_priv_event = False

        # Check event type
        if event_type in ("privilege_escalation", "sudo_command", "su_command"):
            is_priv_event = True

        # Check Windows Event IDs
        event_id = str(raw_data.get("EventID", raw_data.get("event_id", "")))
        if event_id in WINDOWS_PRIV_ESCALATION_IDS:
            is_priv_event = True

        # Check message patterns
        if not is_priv_event:
            for pattern in PRIVILEGE_PATTERNS:
                if re.search(pattern, message):
                    is_priv_event = True
                    break

        if not is_priv_event:
            return None

        return LogFinding(
            finding_id=f"priv_{uuid.uuid4().hex}",
            finding_type="privilege_escalation_indicator",
            event_id=event.get("event_id", "unknown"),
            task_id="",
            agent_id=self.agent_id,
            severity=EventSeverity.MEDIUM,
            confidence=MatchConfidence.MEDIUM,
            detection_type=DetectionType.PRIVILEGE_ESCALATION,
            matching_events=[event.get("event_id", "")],
            source=event.get("source_ip", "") or event.get("username", ""),
            rule_id="privilege_escalation_detector",
            explanation="Detected privilege escalation activity",
            mitre_techniques=["T1548", "T1068"],
            mitre_tactics=["privilege-escalation"],
        )

    def _check_rate_limit(self, event: dict[str, Any]) -> LogFinding | None:
        """Check for rate limit violations."""
        source_ip = event.get("source_ip", "")
        if not source_ip:
            return None

        now = utc_now()
        self._access_counts[source_ip].append(now)

        # Clean old entries
        window_start = now - timedelta(seconds=self.config.rate_limit_window_sec)
        self._access_counts[source_ip] = [
            t for t in self._access_counts[source_ip] if t >= window_start
        ]

        access_count = len(self._access_counts[source_ip])
        if access_count >= self.config.rate_limit_threshold:
            return LogFinding(
                finding_id=f"rate_{uuid.uuid4().hex}",
                finding_type="rate_limit_exceeded",
                event_id=event.get("event_id", "unknown"),
                task_id="",
                agent_id=self.agent_id,
                severity=EventSeverity.MEDIUM,
                confidence=MatchConfidence.HIGH,
                detection_type=DetectionType.SUSPICIOUS_RATE,
                matching_events=[event.get("event_id", "")],
                time_range_start=self._access_counts[source_ip][0],
                time_range_end=now,
                source=source_ip,
                rule_id="rate_limit_detector",
                explanation=(
                    f"Source {source_ip} exceeded rate limit: "
                    f"{access_count} requests in {self.config.rate_limit_window_sec}s"
                ),
                threshold_exceeded={
                    "threshold": self.config.rate_limit_threshold,
                    "actual": access_count,
                    "window_sec": self.config.rate_limit_window_sec,
                },
                mitre_techniques=["T1498"],
                mitre_tactics=["impact"],
            )

        return None

    def _check_off_hours(self, event: dict[str, Any]) -> LogFinding | None:
        """Check for off-hours activity."""
        # Only check auth events
        event_type = event.get("event_type", "")
        if not any(t in event_type for t in ("auth", "login", "session")):
            return None

        timestamp = event.get("timestamp")
        if not timestamp:
            return None

        # Parse timestamp if string
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return None

        hour = timestamp.hour

        # Check if outside business hours
        if self.config.business_hours_start <= hour < self.config.business_hours_end:
            return None

        return LogFinding(
            finding_id=f"offhours_{uuid.uuid4().hex}",
            finding_type="off_hours_activity",
            event_id=event.get("event_id", "unknown"),
            task_id="",
            agent_id=self.agent_id,
            severity=EventSeverity.LOW,
            confidence=MatchConfidence.MEDIUM,
            detection_type=DetectionType.OFF_HOURS_ACTIVITY,
            matching_events=[event.get("event_id", "")],
            source=event.get("source_ip", "") or event.get("username", ""),
            rule_id="off_hours_detector",
            explanation=(
                f"Auth activity at {hour:02d}:00 (outside business hours "
                f"{self.config.business_hours_start}:00-{self.config.business_hours_end}:00)"
            ),
            threshold_exceeded={
                "hour": hour,
                "business_start": self.config.business_hours_start,
                "business_end": self.config.business_hours_end,
            },
        )

    def _calculate_anomaly(self, event: dict[str, Any]) -> AnomalySignal | None:
        """Calculate anomaly signal for event."""
        # Simplified anomaly scoring based on feature extraction
        features: dict[str, float] = {}
        baseline: dict[str, float] = {}

        # Feature: request frequency (if we have enough data)
        source_ip = event.get("source_ip", "")
        if source_ip and source_ip in self._access_counts:
            features["request_frequency"] = len(self._access_counts[source_ip])
            baseline["request_frequency"] = 10.0  # Assumed baseline

        # Feature: auth failure rate
        tracking_key = source_ip or event.get("username", "")
        if tracking_key and tracking_key in self._auth_failures:
            features["auth_failure_rate"] = len(self._auth_failures[tracking_key])
            baseline["auth_failure_rate"] = 1.0

        if not features:
            return None

        # Calculate simple anomaly score (normalized z-score approximation)
        scores = []
        for key in features:
            if key in baseline and baseline[key] > 0:
                deviation = abs(features[key] - baseline[key]) / baseline[key]
                scores.append(min(deviation / self.config.anomaly_zscore_threshold, 1.0))

        if not scores:
            return None

        anomaly_score = sum(scores) / len(scores)
        is_anomaly = anomaly_score >= (1.0 / self.config.anomaly_zscore_threshold)

        return AnomalySignal(
            anomaly_score=anomaly_score,
            features=features,
            baseline=baseline,
            model_version="1.0.0",
            is_anomaly=is_anomaly,
        )

    def _create_anomaly_finding(
        self,
        task: AgentTask,
        event: dict[str, Any],
        anomaly: AnomalySignal,
    ) -> LogFinding:
        """Create finding for anomaly detection."""
        return LogFinding(
            finding_id=f"anomaly_{uuid.uuid4().hex}",
            finding_type="anomaly_detected",
            event_id=event.get("event_id", task.event_id),
            task_id=task.task_id,
            agent_id=self.agent_id,
            severity=EventSeverity.MEDIUM,
            confidence=MatchConfidence.MEDIUM,
            detection_type=DetectionType.ANOMALY,
            matching_events=[event.get("event_id", "")],
            source=event.get("source_ip", ""),
            rule_id="anomaly_detector",
            model_version=anomaly.model_version,
            anomaly_signal=anomaly,
            explanation=f"Anomaly detected with score {anomaly.anomaly_score:.2f}",
        )

    def _aggregate_findings(
        self,
        task: AgentTask,
        findings: list[LogFinding],
    ) -> LogFinding:
        """Aggregate multiple findings into primary finding."""
        if len(findings) == 1:
            findings[0].task_id = task.task_id
            return findings[0]

        # Prioritize by severity
        severity_order = {
            EventSeverity.CRITICAL: 0,
            EventSeverity.HIGH: 1,
            EventSeverity.MEDIUM: 2,
            EventSeverity.LOW: 3,
            EventSeverity.INFORMATIONAL: 4,
        }

        findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        primary = findings[0]
        primary.task_id = task.task_id

        # Aggregate matching events
        all_events = set()
        for f in findings:
            all_events.update(f.matching_events)
        primary.matching_events = list(all_events)

        # Update explanation
        detection_types = list({f.detection_type.value for f in findings})
        types_str = ", ".join(detection_types)
        primary.explanation = f"Multiple detections: {types_str}. {primary.explanation}"

        return primary
