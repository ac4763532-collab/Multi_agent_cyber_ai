"""Cross-Domain Correlation Engine - Combines findings from multiple sources."""

import uuid
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class CorrelationSignal(StrEnum):
    """Types of correlation signals."""

    TEMPORAL_PROXIMITY = "temporal_proximity"
    SHARED_IP = "shared_ip"
    SHARED_DOMAIN = "shared_domain"
    SHARED_URL = "shared_url"
    SHARED_USER = "shared_user"
    SHARED_HOSTNAME = "shared_hostname"
    SHARED_ASSET = "shared_asset"
    SHARED_INDICATOR = "shared_indicator"
    COMPATIBLE_THREAT = "compatible_threat"
    EVENT_SEQUENCE = "event_sequence"


class AttackChainStage(StrEnum):
    """Attack chain stages."""

    INITIAL_ACCESS = "initial_access"
    CREDENTIAL_ACTIVITY = "credential_activity"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    NETWORK_ACTIVITY = "network_activity"
    POTENTIAL_IMPACT = "potential_impact"


class CorrelationScoreComponent(BaseModel):
    """Component of correlation score."""

    signal: CorrelationSignal
    weight: float
    score: float
    evidence: str
    weighted_score: float = 0.0

    def __init__(self, **data: Any):
        super().__init__(**data)
        self.weighted_score = self.weight * self.score


class CorrelationResult(BaseModel):
    """Result of cross-domain correlation."""

    correlation_id: str = Field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}")
    finding_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    shared_indicators: dict[str, list[str]] = Field(default_factory=dict)
    time_window_start: datetime | None = None
    time_window_end: datetime | None = None
    correlation_score: float = 0.0
    score_components: list[CorrelationScoreComponent] = Field(default_factory=list)
    confidence: float = 0.0
    severity: str = "medium"
    attack_chain: list[AttackChainStage] = Field(default_factory=list)
    reasoning: str = ""
    classification: str = ""
    sources: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class Finding(BaseModel):
    """Generic finding from any agent."""

    finding_id: str
    finding_type: str
    source: str  # email, auth, network, suricata, etc.
    timestamp: datetime
    severity: str = "medium"
    confidence: float = 0.5
    indicators: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


# Correlation weights
SIGNAL_WEIGHTS = {
    CorrelationSignal.SHARED_IP: 0.15,
    CorrelationSignal.SHARED_DOMAIN: 0.12,
    CorrelationSignal.SHARED_URL: 0.12,
    CorrelationSignal.SHARED_USER: 0.15,
    CorrelationSignal.SHARED_HOSTNAME: 0.12,
    CorrelationSignal.SHARED_ASSET: 0.10,
    CorrelationSignal.SHARED_INDICATOR: 0.08,
    CorrelationSignal.TEMPORAL_PROXIMITY: 0.08,
    CorrelationSignal.COMPATIBLE_THREAT: 0.05,
    CorrelationSignal.EVENT_SEQUENCE: 0.03,
}

# Compatible threat categories
COMPATIBLE_THREATS = {
    "phishing": ["credential_theft", "malware", "social_engineering"],
    "brute_force": ["credential_theft", "unauthorized_access"],
    "c2_communication": ["malware", "data_exfiltration", "apt"],
    "data_exfiltration": ["c2_communication", "insider_threat"],
    "ransomware": ["malware", "data_exfiltration"],
    "lateral_movement": ["credential_theft", "privilege_escalation"],
}


class CrossDomainCorrelationEngine:
    """Engine for correlating findings across security domains."""

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_correlation_score: float = 0.3,
    ):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_score = min_correlation_score
        self._correlations: list[CorrelationResult] = []

    def correlate(self, findings: list[Finding]) -> list[CorrelationResult]:
        """Correlate a list of findings."""
        if len(findings) < 2:
            return []

        correlations: list[CorrelationResult] = []

        # Group findings by time windows
        time_groups = self._group_by_time(findings)

        for group in time_groups:
            if len(group) < 2:
                continue

            # Calculate correlation for this group
            result = self._correlate_group(group)
            if result and result.correlation_score >= self.min_score:
                correlations.append(result)
                self._correlations.append(result)

        return correlations

    def _group_by_time(self, findings: list[Finding]) -> list[list[Finding]]:
        """Group findings by time windows."""
        if not findings:
            return []

        # Sort by timestamp
        sorted_findings = sorted(findings, key=lambda f: f.timestamp)
        groups: list[list[Finding]] = []
        current_group: list[Finding] = [sorted_findings[0]]

        for finding in sorted_findings[1:]:
            if finding.timestamp - current_group[0].timestamp <= self.time_window:
                current_group.append(finding)
            else:
                if len(current_group) >= 2:
                    groups.append(current_group)
                current_group = [finding]

        if len(current_group) >= 2:
            groups.append(current_group)

        return groups

    def _correlate_group(self, findings: list[Finding]) -> CorrelationResult | None:
        """Correlate a group of findings."""
        result = CorrelationResult(
            finding_ids=[f.finding_id for f in findings],
            sources=list({f.source for f in findings}),
            time_window_start=min(f.timestamp for f in findings),
            time_window_end=max(f.timestamp for f in findings),
        )

        # Calculate score components
        components: list[CorrelationScoreComponent] = []

        # Check shared IPs
        shared_ips = self._find_shared_values(findings, ["source_ip", "dest_ip", "ip"])
        if shared_ips:
            result.shared_indicators["ip"] = shared_ips
            components.append(
                CorrelationScoreComponent(
                    signal=CorrelationSignal.SHARED_IP,
                    weight=SIGNAL_WEIGHTS[CorrelationSignal.SHARED_IP],
                    score=min(len(shared_ips) / 2, 1.0),
                    evidence=f"Shared IPs: {', '.join(shared_ips[:3])}",
                )
            )

        # Check shared domains
        shared_domains = self._find_shared_values(findings, ["domain", "hostname"])
        if shared_domains:
            result.shared_indicators["domain"] = shared_domains
            components.append(
                CorrelationScoreComponent(
                    signal=CorrelationSignal.SHARED_DOMAIN,
                    weight=SIGNAL_WEIGHTS[CorrelationSignal.SHARED_DOMAIN],
                    score=min(len(shared_domains) / 2, 1.0),
                    evidence=f"Shared domains: {', '.join(shared_domains[:3])}",
                )
            )

        # Check shared users
        shared_users = self._find_shared_values(findings, ["username", "user", "email"])
        if shared_users:
            result.shared_indicators["user"] = shared_users
            components.append(
                CorrelationScoreComponent(
                    signal=CorrelationSignal.SHARED_USER,
                    weight=SIGNAL_WEIGHTS[CorrelationSignal.SHARED_USER],
                    score=min(len(shared_users) / 2, 1.0),
                    evidence=f"Shared users: {', '.join(shared_users[:3])}",
                )
            )

        # Check temporal proximity
        time_diff = (result.time_window_end - result.time_window_start).total_seconds()
        if time_diff < 300:  # 5 minutes
            proximity_score = 1.0 - (time_diff / 300)
            components.append(
                CorrelationScoreComponent(
                    signal=CorrelationSignal.TEMPORAL_PROXIMITY,
                    weight=SIGNAL_WEIGHTS[CorrelationSignal.TEMPORAL_PROXIMITY],
                    score=proximity_score,
                    evidence=f"Events within {int(time_diff)} seconds",
                )
            )

        # Check compatible threats
        threat_types = [f.finding_type for f in findings]
        compatible = self._check_compatible_threats(threat_types)
        if compatible:
            components.append(
                CorrelationScoreComponent(
                    signal=CorrelationSignal.COMPATIBLE_THREAT,
                    weight=SIGNAL_WEIGHTS[CorrelationSignal.COMPATIBLE_THREAT],
                    score=0.8,
                    evidence=f"Compatible threat types: {', '.join(threat_types[:3])}",
                )
            )

        # Calculate total score
        if components:
            result.score_components = components
            result.correlation_score = sum(c.weighted_score for c in components)
            result.confidence = min(result.correlation_score * 1.2, 1.0)

        # Determine severity
        severities = [f.severity for f in findings]
        if "critical" in severities:
            result.severity = "critical"
        elif "high" in severities:
            result.severity = "high"
        elif "medium" in severities:
            result.severity = "medium"
        else:
            result.severity = "low"

        # Build attack chain
        result.attack_chain = self._build_attack_chain(findings)

        # Generate reasoning
        result.reasoning = self._generate_reasoning(result, findings)

        # Classify correlation
        result.classification = self._classify_correlation(findings)

        return result

    def _find_shared_values(self, findings: list[Finding], fields: list[str]) -> list[str]:
        """Find values shared across findings."""
        values_by_finding: list[set[str]] = []

        for finding in findings:
            values: set[str] = set()
            for field in fields:
                if field in finding.indicators:
                    v = finding.indicators[field]
                    if isinstance(v, list):
                        values.update(str(x) for x in v if x)
                    elif v:
                        values.add(str(v))
            values_by_finding.append(values)

        # Find intersection
        if not values_by_finding:
            return []

        shared = values_by_finding[0]
        for values in values_by_finding[1:]:
            shared = shared.intersection(values)

        return list(shared)

    def _check_compatible_threats(self, threat_types: list[str]) -> bool:
        """Check if threat types are compatible."""
        for t1 in threat_types:
            t1_lower = t1.lower()
            if t1_lower in COMPATIBLE_THREATS:
                for t2 in threat_types:
                    if t2.lower() in COMPATIBLE_THREATS[t1_lower]:
                        return True
        return False

    def _build_attack_chain(self, findings: list[Finding]) -> list[AttackChainStage]:
        """Build attack chain from findings."""
        stages: list[AttackChainStage] = []
        finding_types = {f.finding_type.lower() for f in findings}

        # Map finding types to attack chain stages
        stage_mapping = {
            AttackChainStage.INITIAL_ACCESS: ["phishing", "exploit", "initial_access", "email"],
            AttackChainStage.CREDENTIAL_ACTIVITY: [
                "brute_force",
                "credential",
                "authentication",
                "login",
            ],
            AttackChainStage.SUSPICIOUS_ACTIVITY: ["malware", "suspicious", "anomaly", "threat"],
            AttackChainStage.NETWORK_ACTIVITY: ["c2", "network", "lateral", "scan", "exfiltration"],
            AttackChainStage.POTENTIAL_IMPACT: [
                "ransomware",
                "impact",
                "data_breach",
                "destruction",
            ],
        }

        for stage, keywords in stage_mapping.items():
            for ft in finding_types:
                if any(kw in ft for kw in keywords):
                    if stage not in stages:
                        stages.append(stage)
                    break

        return stages

    def _generate_reasoning(self, result: CorrelationResult, findings: list[Finding]) -> str:
        """Generate reasoning for correlation."""
        parts = []

        parts.append(f"Correlated {len(findings)} findings from {len(result.sources)} sources.")

        if result.shared_indicators:
            indicators = []
            for ind_type, values in result.shared_indicators.items():
                indicators.append(f"{len(values)} shared {ind_type}(s)")
            parts.append(f"Shared indicators: {', '.join(indicators)}.")

        if result.attack_chain:
            stages = [s.value.replace("_", " ") for s in result.attack_chain]
            parts.append(f"Attack chain stages: {' → '.join(stages)}.")

        parts.append(
            f"Correlation score: {result.correlation_score:.2f}, "
            f"confidence: {result.confidence:.2f}."
        )

        return " ".join(parts)

    def _classify_correlation(self, findings: list[Finding]) -> str:
        """Classify the type of correlated incident."""
        finding_types = [f.finding_type.lower() for f in findings]

        if any("ransomware" in ft for ft in finding_types):
            return "ransomware_attack"
        if any("phishing" in ft for ft in finding_types):
            if any("credential" in ft or "login" in ft for ft in finding_types):
                return "credential_phishing"
            return "phishing_campaign"
        if any("c2" in ft or "beacon" in ft for ft in finding_types):
            return "c2_activity"
        if any("exfil" in ft or "breach" in ft for ft in finding_types):
            return "data_exfiltration"
        if any("brute" in ft for ft in finding_types):
            return "brute_force_attack"
        if any("lateral" in ft for ft in finding_types):
            return "lateral_movement"

        return "suspicious_activity"

    def get_correlation(self, correlation_id: str) -> CorrelationResult | None:
        """Get a correlation by ID."""
        for c in self._correlations:
            if c.correlation_id == correlation_id:
                return c
        return None

    def get_recent_correlations(self, limit: int = 100) -> list[CorrelationResult]:
        """Get recent correlations."""
        return sorted(self._correlations, key=lambda c: c.created_at, reverse=True)[:limit]

    def get_metrics(self) -> dict[str, Any]:
        """Get engine metrics."""
        return {
            "total_correlations": len(self._correlations),
            "time_window_minutes": self.time_window.total_seconds() / 60,
            "min_correlation_score": self.min_score,
        }


# Singleton
_engine: CrossDomainCorrelationEngine | None = None


def get_correlation_engine() -> CrossDomainCorrelationEngine:
    """Get correlation engine singleton."""
    global _engine
    if _engine is None:
        _engine = CrossDomainCorrelationEngine()
    return _engine
