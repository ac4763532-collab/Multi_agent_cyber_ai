"""Threat Intelligence Agent - IoC enrichment and MITRE ATT&CK mapping."""

import re
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


class IoC_Type(StrEnum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre_technique"


class ThreatCategory(StrEnum):
    """Categories of threats."""

    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "command_and_control"
    RANSOMWARE = "ransomware"
    APT = "apt"
    BOTNET = "botnet"
    EXPLOIT = "exploit"
    SPAM = "spam"
    UNKNOWN = "unknown"


class IoC_Enrichment(BaseModel):
    """Enrichment data for an IoC."""

    ioc_value: str
    ioc_type: IoC_Type
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    first_seen: str | None = None
    last_seen: str | None = None
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    related_iocs: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    geolocation: dict[str, str] = Field(default_factory=dict)
    asn_info: dict[str, str] = Field(default_factory=dict)
    is_known_malicious: bool = False


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique mapping."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    detection_methods: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


class ThreatIntelFinding(BaseFinding):
    """Finding from threat intelligence analysis."""

    enrichments: list[IoC_Enrichment] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    technique_details: list[MitreTechnique] = Field(default_factory=list)
    threat_categories: list[ThreatCategory] = Field(default_factory=list)
    overall_threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    known_malicious_count: int = 0
    total_iocs_analyzed: int = 0


# Sample threat intelligence database (in production, use real feeds)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.1": {"category": ThreatCategory.C2, "confidence": 0.95},
    "45.33.32.156": {"category": ThreatCategory.MALWARE, "confidence": 0.8},
    "198.51.100.1": {"category": ThreatCategory.BOTNET, "confidence": 0.9},
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-c2.com": {"category": ThreatCategory.C2, "confidence": 0.95},
    "phishing-site.net": {"category": ThreatCategory.PHISHING, "confidence": 0.9},
    "ransomware-payment.org": {"category": ThreatCategory.RANSOMWARE, "confidence": 0.95},
}

KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": {  # EICAR test file
        "category": ThreatCategory.MALWARE,
        "malware_family": "EICAR-Test",
        "confidence": 1.0,
    },
}

# MITRE ATT&CK technique database (subset)
MITRE_TECHNIQUES = {
    "T1566": MitreTechnique(
        technique_id="T1566",
        technique_name="Phishing",
        tactic="initial-access",
        description="Adversaries may send phishing messages to gain access",
        platforms=["Windows", "macOS", "Linux"],
        data_sources=["Email gateway", "File monitoring"],
    ),
    "T1566.001": MitreTechnique(
        technique_id="T1566.001",
        technique_name="Spearphishing Attachment",
        tactic="initial-access",
        description="Adversaries may send spearphishing emails with malicious attachments",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1071": MitreTechnique(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic="command-and-control",
        description="Adversaries may communicate using application layer protocols",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1110": MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="credential-access",
        description="Adversaries may use brute force techniques to gain access",
        platforms=["Windows", "macOS", "Linux", "Azure AD"],
    ),
    "T1046": MitreTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="discovery",
        description="Adversaries may attempt to get a listing of services",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1048": MitreTechnique(
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactic="exfiltration",
        description="Adversaries may steal data by exfiltrating it over different protocols",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1059": MitreTechnique(
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="execution",
        description="Adversaries may abuse command and script interpreters",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="defense-evasion",
        description="Adversaries may obtain and abuse credentials of existing accounts",
        platforms=["Windows", "macOS", "Linux", "Azure AD", "AWS", "GCP"],
    ),
    "T1021": MitreTechnique(
        technique_id="T1021",
        technique_name="Remote Services",
        tactic="lateral-movement",
        description="Adversaries may use remote services to move within a network",
        platforms=["Windows", "macOS", "Linux"],
    ),
    "T1486": MitreTechnique(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="impact",
        description="Adversaries may encrypt data on target systems",
        platforms=["Windows", "macOS", "Linux"],
    ),
}


class ThreatIntelligenceAgent(BaseAgent):
    """Enriches IoCs with threat intelligence and maps to MITRE ATT&CK.

    Capabilities:
    - IoC type detection (IP, domain, hash, URL, email, CVE)
    - Threat intelligence enrichment
    - MITRE ATT&CK technique mapping
    - Threat categorization
    - Related IoC correlation
    """

    @property
    def agent_id(self) -> str:
        return "threat_intel_001"

    @property
    def name(self) -> str:
        return "Threat Intelligence Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.THREAT_INTELLIGENCE

    @property
    def capabilities(self) -> list[str]:
        return [
            "ioc_enrichment",
            "mitre_mapping",
            "threat_categorization",
            "ioc_correlation",
            "threat_scoring",
            "geolocation_lookup",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has IoC data."""
        payload = task.payload or {}
        return any(
            k in payload
            for k in ["iocs", "indicators", "event", "finding", "ip", "domain", "hash"]
        )

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process threat intelligence enrichment task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract IoCs from payload
            iocs = self._extract_iocs(payload)

            # Enrich each IoC
            enrichments: list[IoC_Enrichment] = []
            for ioc_value, ioc_type in iocs:
                enrichment = self._enrich_ioc(ioc_value, ioc_type)
                if enrichment:
                    enrichments.append(enrichment)

            # Map to MITRE techniques
            techniques = self._map_mitre_techniques(payload, enrichments)

            # Calculate threat score
            threat_score = self._calculate_threat_score(enrichments)

            # Get unique threat categories
            categories = list({e.threat_category for e in enrichments if e.is_known_malicious})

            # Create finding
            finding = ThreatIntelFinding(
                finding_id=f"ti_{uuid.uuid4().hex}",
                finding_type="threat_intelligence",
                event_id=task.event_id,
                task_id=task.task_id,
                agent_id=self.agent_id,
                severity=self._score_to_severity(threat_score),
                confidence=MatchConfidence.HIGH if enrichments else MatchConfidence.LOW,
                enrichments=enrichments,
                mitre_techniques=[t.technique_id for t in techniques],
                mitre_tactics=list({t.tactic for t in techniques}),
                technique_details=techniques,
                threat_categories=categories,
                overall_threat_score=threat_score,
                known_malicious_count=sum(1 for e in enrichments if e.is_known_malicious),
                total_iocs_analyzed=len(iocs),
                explanation=self._generate_explanation(enrichments, techniques),
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
                    "iocs_analyzed": len(iocs),
                    "enrichments_found": len(enrichments),
                    "techniques_mapped": len(techniques),
                    "threat_score": threat_score,
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
            finding_id=f"ti_{uuid.uuid4().hex}",
            finding_type="threat_intelligence",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_iocs(  # noqa: C901
        self, payload: dict[str, Any]
    ) -> list[tuple[str, IoC_Type]]:
        """Extract IoCs from payload with type detection."""
        iocs: list[tuple[str, IoC_Type]] = []
        seen = set()

        # Direct IoC lists
        if "iocs" in payload:
            for ioc in payload["iocs"]:
                if isinstance(ioc, dict):
                    value = ioc.get("value", "")
                    ioc_type = self._detect_ioc_type(value)
                elif isinstance(ioc, str):
                    value = ioc
                    ioc_type = self._detect_ioc_type(value)
                else:
                    continue

                if value and value not in seen:
                    seen.add(value)
                    iocs.append((value, ioc_type))

        # Direct fields
        for field in ["ip", "source_ip", "destination_ip"]:
            if field in payload and payload[field]:
                value = payload[field]
                if value not in seen:
                    seen.add(value)
                    iocs.append((value, IoC_Type.IP_ADDRESS))

        for field in ["domain", "hostname"]:
            if field in payload and payload[field]:
                value = payload[field]
                if value not in seen:
                    seen.add(value)
                    iocs.append((value, IoC_Type.DOMAIN))

        if "hash" in payload and payload["hash"]:
            value = payload["hash"]
            if value not in seen:
                seen.add(value)
                iocs.append((value, self._detect_hash_type(value)))

        if "url" in payload and payload["url"]:
            value = payload["url"]
            if value not in seen:
                seen.add(value)
                iocs.append((value, IoC_Type.URL))

        # Extract from event
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                for field, ioc_type in [
                    ("source_ip", IoC_Type.IP_ADDRESS),
                    ("destination_ip", IoC_Type.IP_ADDRESS),
                    ("domain", IoC_Type.DOMAIN),
                    ("url", IoC_Type.URL),
                    ("hash", None),
                ]:
                    if field in event and event[field] and event[field] not in seen:
                        value = event[field]
                        seen.add(value)
                        if ioc_type is None:
                            ioc_type = self._detect_hash_type(value)
                        iocs.append((value, ioc_type))

        return iocs

    def _detect_ioc_type(self, value: str) -> IoC_Type:
        """Detect IoC type from value."""
        # IP address
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, value):
            return IoC_Type.IP_ADDRESS

        # Hash detection
        hash_type = self._detect_hash_type(value)
        if hash_type != IoC_Type.DOMAIN:
            return hash_type

        # URL
        if value.startswith(("http://", "https://", "ftp://")):
            return IoC_Type.URL

        # Email
        if "@" in value and "." in value.split("@")[-1]:
            return IoC_Type.EMAIL

        # CVE
        if re.match(r"^CVE-\d{4}-\d+$", value, re.IGNORECASE):
            return IoC_Type.CVE

        # MITRE technique
        if re.match(r"^T\d{4}(\.\d{3})?$", value):
            return IoC_Type.MITRE_TECHNIQUE

        # Default to domain
        return IoC_Type.DOMAIN

    def _detect_hash_type(self, value: str) -> IoC_Type:
        """Detect hash type from length."""
        clean = value.lower().strip()
        if len(clean) == 32 and all(c in "0123456789abcdef" for c in clean):
            return IoC_Type.FILE_HASH_MD5
        elif len(clean) == 40 and all(c in "0123456789abcdef" for c in clean):
            return IoC_Type.FILE_HASH_SHA1
        elif len(clean) == 64 and all(c in "0123456789abcdef" for c in clean):
            return IoC_Type.FILE_HASH_SHA256
        return IoC_Type.DOMAIN  # Default

    def _enrich_ioc(self, value: str, ioc_type: IoC_Type) -> IoC_Enrichment | None:
        """Enrich an IoC with threat intelligence."""
        enrichment = IoC_Enrichment(
            ioc_value=value,
            ioc_type=ioc_type,
        )

        # Check against known malicious indicators
        if ioc_type == IoC_Type.IP_ADDRESS:
            if value in KNOWN_MALICIOUS_IPS:
                info = KNOWN_MALICIOUS_IPS[value]
                enrichment.is_known_malicious = True
                enrichment.threat_category = info["category"]
                enrichment.confidence_score = info["confidence"]
                enrichment.sources = ["internal_threat_feed"]
                enrichment.tags = ["malicious", info["category"].value]

        elif ioc_type == IoC_Type.DOMAIN:
            domain_lower = value.lower()
            if domain_lower in KNOWN_MALICIOUS_DOMAINS:
                info = KNOWN_MALICIOUS_DOMAINS[domain_lower]
                enrichment.is_known_malicious = True
                enrichment.threat_category = info["category"]
                enrichment.confidence_score = info["confidence"]
                enrichment.sources = ["internal_threat_feed"]
                enrichment.tags = ["malicious", info["category"].value]

        elif ioc_type in (
            IoC_Type.FILE_HASH_MD5,
            IoC_Type.FILE_HASH_SHA1,
            IoC_Type.FILE_HASH_SHA256,
        ):
            hash_lower = value.lower()
            if hash_lower in KNOWN_MALICIOUS_HASHES:
                info = KNOWN_MALICIOUS_HASHES[hash_lower]
                enrichment.is_known_malicious = True
                enrichment.threat_category = info["category"]
                enrichment.confidence_score = info["confidence"]
                enrichment.malware_families = [info.get("malware_family", "unknown")]
                enrichment.sources = ["internal_threat_feed"]

        return enrichment

    def _map_mitre_techniques(  # noqa: C901
        self,
        payload: dict[str, Any],
        enrichments: list[IoC_Enrichment],
    ) -> list[MitreTechnique]:
        """Map findings to MITRE ATT&CK techniques."""
        techniques: list[MitreTechnique] = []
        technique_ids: set[str] = set()

        # From payload
        if "mitre_techniques" in payload:
            for tech_id in payload["mitre_techniques"]:
                if tech_id in MITRE_TECHNIQUES and tech_id not in technique_ids:
                    technique_ids.add(tech_id)
                    techniques.append(MITRE_TECHNIQUES[tech_id])

        # From enrichments
        for enrichment in enrichments:
            if enrichment.is_known_malicious:
                # Map threat categories to techniques
                category_techniques = {
                    ThreatCategory.PHISHING: ["T1566", "T1566.001"],
                    ThreatCategory.C2: ["T1071"],
                    ThreatCategory.MALWARE: ["T1059"],
                    ThreatCategory.RANSOMWARE: ["T1486"],
                    ThreatCategory.BOTNET: ["T1071"],
                }

                for tech_id in category_techniques.get(enrichment.threat_category, []):
                    if tech_id in MITRE_TECHNIQUES and tech_id not in technique_ids:
                        technique_ids.add(tech_id)
                        techniques.append(MITRE_TECHNIQUES[tech_id])

        # From event type hints
        event = payload.get("event", {})
        if isinstance(event, dict):
            event_type = event.get("event_type", "")
            type_techniques = {
                "auth_failed": ["T1110"],
                "brute_force": ["T1110"],
                "port_scan": ["T1046"],
                "lateral_movement": ["T1021"],
                "data_exfil": ["T1048"],
            }

            for hint, tech_ids in type_techniques.items():
                if hint in event_type.lower():
                    for tech_id in tech_ids:
                        if tech_id in MITRE_TECHNIQUES and tech_id not in technique_ids:
                            technique_ids.add(tech_id)
                            techniques.append(MITRE_TECHNIQUES[tech_id])

        return techniques

    def _calculate_threat_score(self, enrichments: list[IoC_Enrichment]) -> float:
        """Calculate overall threat score from enrichments."""
        if not enrichments:
            return 0.0

        # Weight malicious indicators heavily
        malicious_scores = [
            e.confidence_score for e in enrichments if e.is_known_malicious
        ]

        if not malicious_scores:
            return 0.1  # Low score if no known malicious

        # Average of malicious confidence scores
        return sum(malicious_scores) / len(malicious_scores)

    def _score_to_severity(self, score: float) -> EventSeverity:
        """Convert threat score to severity level."""
        if score >= 0.9:
            return EventSeverity.CRITICAL
        elif score >= 0.7:
            return EventSeverity.HIGH
        elif score >= 0.4:
            return EventSeverity.MEDIUM
        elif score >= 0.2:
            return EventSeverity.LOW
        return EventSeverity.INFORMATIONAL

    def _generate_explanation(
        self,
        enrichments: list[IoC_Enrichment],
        techniques: list[MitreTechnique],
    ) -> str:
        """Generate human-readable explanation."""
        parts = []

        malicious_count = sum(1 for e in enrichments if e.is_known_malicious)
        if malicious_count > 0:
            parts.append(f"Found {malicious_count} known malicious indicator(s)")

        if techniques:
            tactic_names = list({t.tactic for t in techniques})
            parts.append(f"Mapped to MITRE tactics: {', '.join(tactic_names)}")

        categories = list({e.threat_category.value for e in enrichments if e.is_known_malicious})
        if categories:
            parts.append(f"Threat categories: {', '.join(categories)}")

        if not parts:
            return "No significant threat intelligence findings"

        return ". ".join(parts) + "."
