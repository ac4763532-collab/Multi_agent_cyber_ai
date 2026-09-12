"""Pydantic models for detection results, matches, and findings."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.detection.interfaces import DetectionLayer, RuleType
from backend.app.schemas.events import EventSeverity
from backend.app.utils.datetime import utc_now


class MatchConfidence(StrEnum):
    """Confidence level classification for detection matches.

    Per PROJECT_CONSTITUTION.md §2.2 Epistemic Humility Standards.
    """

    DEFINITIVE = "definitive"  # Exact signature/hash match
    HIGH = "high"  # Strong pattern match with multiple indicators
    MEDIUM = "medium"  # Single indicator or heuristic match
    LOW = "low"  # Weak signal, requires correlation


class DetectionMatch(BaseModel):
    """Single detection rule match result.

    Represents a triggered detection rule with full evidence provenance.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Rule identification
    rule_id: str = Field(..., min_length=1, max_length=128, description="Unique rule identifier")
    rule_name: str = Field(
        ..., min_length=1, max_length=256, description="Human-readable rule name"
    )
    rule_type: RuleType = Field(..., description="Type of detection rule")
    rule_version: str = Field(default="1.0.0", max_length=32, description="Rule version string")

    # Detection metadata
    detection_layer: DetectionLayer = Field(
        default=DetectionLayer.L1_DETERMINISTIC,
        description="Layer in defense-in-depth architecture",
    )
    severity: EventSeverity = Field(..., description="Severity classification of the match")
    confidence: MatchConfidence = Field(
        default=MatchConfidence.HIGH,
        description="Confidence level of the detection",
    )

    # Evidence and context
    matched_field: str = Field(..., description="Event field that triggered the match")
    matched_value: str = Field(..., description="Actual value that matched the rule")
    match_details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional match context (pattern, threshold, etc.)",
    )

    # MITRE ATT&CK mapping
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs (e.g., T1110.001)",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic names (e.g., Credential Access)",
    )

    # Timestamps
    detection_timestamp: datetime = Field(
        default_factory=utc_now,
        description="UTC timestamp when detection occurred",
    )

    # Optional enrichment
    description: str | None = Field(default=None, description="Rule description")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    tags: list[str] = Field(default_factory=list, description="Classification tags")


class DetectionFinding(BaseModel):
    """Aggregated detection finding for correlation layer.

    A finding combines one or more matches with the source event context,
    ready for emission to the correlation engine.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    # Finding identification
    finding_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique finding identifier",
    )
    event_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Source event that triggered this finding",
    )

    # Classification
    finding_type: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Category of finding (e.g., brute_force, sql_injection)",
    )
    severity: EventSeverity = Field(
        ...,
        description="Highest severity among all matches",
    )
    confidence: MatchConfidence = Field(
        default=MatchConfidence.HIGH,
        description="Overall confidence level",
    )
    detection_layer: DetectionLayer = Field(
        default=DetectionLayer.L1_DETERMINISTIC,
        description="Detection layer that produced this finding",
    )

    # Detection results
    matches: list[DetectionMatch] = Field(
        default_factory=list,
        description="List of individual rule matches",
    )
    match_count: int = Field(default=0, description="Number of rules that matched")

    # Event context (for correlation)
    source_ip: str | None = Field(default=None, description="Source IP from event")
    destination_ip: str | None = Field(default=None, description="Destination IP from event")
    username: str | None = Field(default=None, description="Username from event")
    hostname: str | None = Field(default=None, description="Hostname from event")
    domain: str | None = Field(default=None, description="Domain from event")

    # MITRE aggregation (union of all matches)
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Aggregated MITRE technique IDs",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="Aggregated MITRE tactic names",
    )

    # Timestamps
    event_timestamp: datetime = Field(..., description="Original event timestamp")
    detection_timestamp: datetime = Field(
        default_factory=utc_now,
        description="When detection processing completed",
    )

    # Performance tracking
    processing_time_ms: float = Field(
        default=0.0,
        ge=0,
        description="Detection processing time in milliseconds",
    )

    # Metadata
    agent_name: str = Field(
        default="detection_engine",
        description="Agent that produced this finding",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context and enrichment data",
    )

    def add_match(self, match: DetectionMatch) -> None:
        """Add a detection match and update aggregated fields."""
        self.matches.append(match)
        self.match_count = len(self.matches)

        # Update severity to highest
        severity_order = [
            EventSeverity.INFORMATIONAL,
            EventSeverity.LOW,
            EventSeverity.MEDIUM,
            EventSeverity.HIGH,
            EventSeverity.CRITICAL,
        ]
        if severity_order.index(match.severity) > severity_order.index(self.severity):
            self.severity = match.severity

        # Aggregate MITRE mappings (deduplicated)
        for tech in match.mitre_techniques:
            if tech not in self.mitre_techniques:
                self.mitre_techniques.append(tech)
        for tactic in match.mitre_tactics:
            if tactic not in self.mitre_tactics:
                self.mitre_tactics.append(tactic)


class RuleDefinition(BaseModel):
    """Schema for loading rule definitions from YAML/JSON files."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="allow",  # Allow extra fields for rule-specific config
    )

    # Required fields
    id: str = Field(..., alias="rule_id", description="Unique rule identifier")
    name: str = Field(..., alias="rule_name", description="Rule display name")
    rule_type: RuleType = Field(default=RuleType.CUSTOM, description="Rule type")
    severity: EventSeverity | str = Field(
        default=EventSeverity.MEDIUM,
        description="Default severity",
    )

    # Optional metadata
    description: str = Field(default="", description="Rule description")
    author: str = Field(default="", description="Rule author")
    version: str = Field(default="1.0.0", description="Rule version")
    enabled: bool = Field(default=True, description="Whether rule is active")

    # MITRE mapping
    mitre_attack: list[str] = Field(
        default_factory=list,
        alias="mitre_techniques",
        description="MITRE ATT&CK technique IDs",
    )
    tactics: list[str] = Field(
        default_factory=list,
        alias="mitre_tactics",
        description="MITRE tactic names",
    )

    # Classification
    tags: list[str] = Field(default_factory=list, description="Rule tags")
    references: list[str] = Field(default_factory=list, description="Reference URLs")

    # Detection logic (rule-type specific)
    detection: dict[str, Any] = Field(
        default_factory=dict,
        description="Detection conditions (Sigma-style)",
    )
    pattern: str | None = Field(default=None, description="Regex pattern")
    indicators: list[str] = Field(
        default_factory=list,
        description="IoC values",
    )
    condition: str = Field(
        default="any",
        description="Logic condition (all, any, expression)",
    )


class DetectionStats(BaseModel):
    """Statistics and metrics for detection engine performance."""

    model_config = ConfigDict(extra="forbid")

    # Rule counts
    total_rules: int = Field(default=0, description="Total rules loaded")
    sigma_rules: int = Field(default=0, description="Sigma rules loaded")
    regex_rules: int = Field(default=0, description="Regex rules loaded")
    ioc_rules: int = Field(default=0, description="IoC rules loaded")

    # Processing metrics
    events_processed: int = Field(default=0, description="Total events evaluated")
    matches_found: int = Field(default=0, description="Total matches triggered")
    findings_generated: int = Field(default=0, description="Findings emitted")

    # Latency tracking (milliseconds)
    avg_latency_ms: float = Field(default=0.0, description="Average processing latency")
    p50_latency_ms: float = Field(default=0.0, description="50th percentile latency")
    p95_latency_ms: float = Field(default=0.0, description="95th percentile latency")
    p99_latency_ms: float = Field(default=0.0, description="99th percentile latency")
    max_latency_ms: float = Field(default=0.0, description="Maximum latency observed")

    # Error tracking
    errors: int = Field(default=0, description="Processing errors")
    last_error: str | None = Field(default=None, description="Last error message")

    # Timestamps
    started_at: datetime | None = Field(default=None, description="Engine start time")
    last_evaluation_at: datetime | None = Field(default=None, description="Last evaluation time")
