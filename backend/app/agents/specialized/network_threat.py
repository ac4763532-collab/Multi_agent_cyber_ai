"""Network Threat Agent - analyzes network traffic for malicious patterns."""

import uuid
from collections import defaultdict
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
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


class NetworkThreatType(StrEnum):
    """Types of network threats detected."""

    C2_COMMUNICATION = "c2_communication"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    DNS_TUNNELING = "dns_tunneling"
    BEACONING = "beaconing"
    SUSPICIOUS_PROTOCOL = "suspicious_protocol"
    ANOMALOUS_TRAFFIC = "anomalous_traffic"


class NetworkThreatConfig(BaseModel):
    """Configuration for network threat detection."""

    # Port scan detection
    port_scan_threshold: int = Field(
        default=10, ge=3, description="Unique ports to trigger scan detection"
    )
    port_scan_window_sec: int = Field(
        default=60, ge=10, description="Time window for port scan detection"
    )

    # Beaconing detection
    beacon_interval_tolerance: float = Field(
        default=0.1, ge=0.01, le=0.5, description="Tolerance for beacon interval variance"
    )
    beacon_min_connections: int = Field(
        default=5, ge=3, description="Minimum connections to detect beaconing"
    )

    # Data exfiltration
    exfil_threshold_bytes: int = Field(
        default=10_000_000, ge=1_000_000, description="Bytes threshold for exfil alert"
    )
    exfil_window_sec: int = Field(default=300, ge=60, description="Time window for exfil detection")

    # DNS tunneling
    dns_query_length_threshold: int = Field(
        default=50, ge=30, description="Subdomain length threshold for DNS tunneling"
    )
    dns_entropy_threshold: float = Field(
        default=3.5, ge=2.0, le=5.0, description="Entropy threshold for DNS tunneling"
    )


class NetworkIndicator(BaseModel):
    """Single network threat indicator."""

    indicator_type: NetworkThreatType
    description: str
    severity: EventSeverity = EventSeverity.MEDIUM
    confidence: MatchConfidence = MatchConfidence.MEDIUM
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int | None = None
    protocol: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    risk_contribution: float = Field(default=0.2, ge=0.0, le=1.0)


class NetworkFinding(BaseFinding):
    """Finding specific to network threat analysis."""

    threat_type: NetworkThreatType = Field(..., description="Type of network threat")
    indicators: list[NetworkIndicator] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    bytes_transferred: int = Field(default=0)
    connection_count: int = Field(default=0)


# Known C2 indicators
C2_PORTS = {443, 8443, 4443, 8080, 8888, 1337, 31337, 6667, 6697}
C2_USER_AGENTS = {
    "mozilla/4.0",
    "python-requests",
    "curl",
    "wget",
    "powershell",
}

# Suspicious TLDs for C2
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}

# Private IP ranges
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]


class NetworkThreatAgent(BaseAgent):
    """Analyzes network traffic for malicious patterns and threats.

    Detects:
    - Command & Control (C2) communications
    - Port scanning activity
    - Data exfiltration attempts
    - Lateral movement patterns
    - DNS tunneling
    - Beaconing behavior
    - Protocol anomalies
    """

    def __init__(self, config: NetworkThreatConfig | None = None) -> None:
        """Initialize network threat agent."""
        super().__init__()
        self.config = config or NetworkThreatConfig()

        # Connection tracking
        self._port_scan_tracker: dict[str, dict[str, set]] = defaultdict(
            lambda: {"ports": set(), "timestamps": set()}
        )
        self._connection_intervals: dict[str, list[datetime]] = defaultdict(list)
        self._data_transfer: dict[str, int] = defaultdict(int)

    @property
    def agent_id(self) -> str:
        return "network_threat_001"

    @property
    def name(self) -> str:
        return "Network Threat Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.NETWORK_THREAT

    @property
    def capabilities(self) -> list[str]:
        return [
            "c2_detection",
            "port_scan_detection",
            "data_exfiltration_detection",
            "lateral_movement_detection",
            "dns_tunneling_detection",
            "beaconing_detection",
            "protocol_analysis",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has network data."""
        payload = task.payload or {}
        return "event" in payload or "flow" in payload or "connection" in payload

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process network threat analysis task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract network data
            network_data = self._extract_network_data(payload)

            # Detect threats
            indicators: list[NetworkIndicator] = []

            # Check for C2 communication
            c2_indicators = self._detect_c2(network_data)
            indicators.extend(c2_indicators)

            # Check for port scanning
            scan_indicators = self._detect_port_scan(network_data)
            indicators.extend(scan_indicators)

            # Check for data exfiltration
            exfil_indicators = self._detect_exfiltration(network_data)
            indicators.extend(exfil_indicators)

            # Check for DNS tunneling
            dns_indicators = self._detect_dns_tunneling(network_data)
            indicators.extend(dns_indicators)

            # Check for beaconing
            beacon_indicators = self._detect_beaconing(network_data)
            indicators.extend(beacon_indicators)

            # Check for lateral movement
            lateral_indicators = self._detect_lateral_movement(network_data)
            indicators.extend(lateral_indicators)

            # Calculate risk and create finding
            risk_score = self._calculate_risk_score(indicators)
            threat_type = self._determine_primary_threat(indicators)

            finding = None
            if indicators:
                finding = self._create_network_finding(
                    task, threat_type, indicators, risk_score, network_data
                )

            return AgentResult(
                result_id=f"result_{uuid.uuid4().hex}",
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                agent_version=self.version,
                status=ResultStatus.SUCCESS if finding else ResultStatus.PARTIAL,
                finding=finding,
                start_time=start_time,
                end_time=utc_now(),
                processing_time_ms=(utc_now() - start_time).total_seconds() * 1000,
                metadata={
                    "threat_type": threat_type.value if threat_type else None,
                    "risk_score": risk_score,
                    "indicator_count": len(indicators),
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
            finding_id=f"network_{uuid.uuid4().hex}",
            finding_type="network_analysis",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _extract_network_data(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract network data from payload."""
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                return event
            elif hasattr(event, "model_dump"):
                return event.model_dump()

        if "flow" in payload:
            return payload["flow"]

        if "connection" in payload:
            return payload["connection"]

        return payload

    def _detect_c2(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect Command & Control communication patterns."""
        indicators = []

        dest_ip = data.get("destination_ip", "")
        dest_port = data.get("destination_port")
        protocol = data.get("protocol", "").lower()
        user_agent = data.get("user_agent", "").lower()
        domain = data.get("domain", "").lower()

        # Check for known C2 ports with encrypted traffic
        if dest_port in C2_PORTS and protocol in ("tcp", "https", "ssl"):
            indicators.append(
                NetworkIndicator(
                    indicator_type=NetworkThreatType.C2_COMMUNICATION,
                    description=f"Connection to known C2 port {dest_port}",
                    severity=EventSeverity.HIGH,
                    confidence=MatchConfidence.MEDIUM,
                    destination_ip=dest_ip,
                    destination_port=dest_port,
                    protocol=protocol,
                    evidence={"port": dest_port, "reason": "known_c2_port"},
                    risk_contribution=0.3,
                )
            )

        # Check for suspicious user agents
        if user_agent and any(ua in user_agent for ua in C2_USER_AGENTS):
            indicators.append(
                NetworkIndicator(
                    indicator_type=NetworkThreatType.C2_COMMUNICATION,
                    description="Suspicious user agent detected",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.MEDIUM,
                    destination_ip=dest_ip,
                    evidence={"user_agent": user_agent[:100]},
                    risk_contribution=0.2,
                )
            )

        # Check for suspicious TLDs
        if domain and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            indicators.append(
                NetworkIndicator(
                    indicator_type=NetworkThreatType.C2_COMMUNICATION,
                    description="Connection to suspicious TLD",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.MEDIUM,
                    destination_ip=dest_ip,
                    evidence={"domain": domain},
                    risk_contribution=0.25,
                )
            )

        return indicators

    def _detect_port_scan(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect port scanning activity."""
        indicators = []

        source_ip = data.get("source_ip", "")
        dest_ip = data.get("destination_ip", "")
        dest_port = data.get("destination_port")

        if not source_ip or not dest_port:
            return indicators

        # Track ports per source->dest pair
        key = f"{source_ip}:{dest_ip}"
        now = utc_now()

        self._port_scan_tracker[key]["ports"].add(dest_port)
        self._port_scan_tracker[key]["timestamps"].add(now.isoformat())

        # Check threshold
        unique_ports = len(self._port_scan_tracker[key]["ports"])
        if unique_ports >= self.config.port_scan_threshold:
            indicators.append(
                NetworkIndicator(
                    indicator_type=NetworkThreatType.PORT_SCAN,
                    description=f"Port scan detected: {unique_ports} unique ports",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.HIGH,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    evidence={
                        "unique_ports": unique_ports,
                        "threshold": self.config.port_scan_threshold,
                        "ports_sample": list(self._port_scan_tracker[key]["ports"])[:10],
                    },
                    risk_contribution=0.25,
                )
            )

        return indicators

    def _detect_exfiltration(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect data exfiltration attempts."""
        indicators = []

        source_ip = data.get("source_ip", "")
        dest_ip = data.get("destination_ip", "")
        bytes_out = data.get("bytes_out", data.get("bytes_sent", 0))

        if not source_ip or not bytes_out:
            return indicators

        # Check if destination is external
        is_external = True
        try:
            dest = ip_address(dest_ip)
            for network in PRIVATE_NETWORKS:
                if dest in network:
                    is_external = False
                    break
        except ValueError:
            pass

        if is_external:
            key = f"{source_ip}:{dest_ip}"
            self._data_transfer[key] += bytes_out

            if self._data_transfer[key] >= self.config.exfil_threshold_bytes:
                indicators.append(
                    NetworkIndicator(
                        indicator_type=NetworkThreatType.DATA_EXFILTRATION,
                        description="Large data transfer to external destination",
                        severity=EventSeverity.HIGH,
                        confidence=MatchConfidence.MEDIUM,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        evidence={
                            "bytes_transferred": self._data_transfer[key],
                            "threshold": self.config.exfil_threshold_bytes,
                        },
                        risk_contribution=0.35,
                    )
                )

        return indicators

    def _detect_dns_tunneling(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect DNS tunneling attempts."""
        indicators = []

        query = data.get("dns_query", data.get("query", ""))
        if not query:
            return indicators

        # Check subdomain length
        parts = query.split(".")
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            if len(subdomain) > self.config.dns_query_length_threshold:
                indicators.append(
                    NetworkIndicator(
                        indicator_type=NetworkThreatType.DNS_TUNNELING,
                        description="Unusually long DNS subdomain (possible tunneling)",
                        severity=EventSeverity.HIGH,
                        confidence=MatchConfidence.MEDIUM,
                        evidence={
                            "query": query[:100],
                            "subdomain_length": len(subdomain),
                            "threshold": self.config.dns_query_length_threshold,
                        },
                        risk_contribution=0.3,
                    )
                )

        # Check entropy
        entropy = self._calculate_entropy(query)
        if entropy > self.config.dns_entropy_threshold:
            indicators.append(
                NetworkIndicator(
                    indicator_type=NetworkThreatType.DNS_TUNNELING,
                    description="High entropy DNS query (possible tunneling)",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.MEDIUM,
                    evidence={
                        "query": query[:100],
                        "entropy": round(entropy, 2),
                        "threshold": self.config.dns_entropy_threshold,
                    },
                    risk_contribution=0.25,
                )
            )

        return indicators

    def _detect_beaconing(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect beaconing behavior (regular interval connections)."""
        indicators = []

        source_ip = data.get("source_ip", "")
        dest_ip = data.get("destination_ip", "")
        timestamp = data.get("timestamp")

        if not source_ip or not dest_ip or not timestamp:
            return indicators

        key = f"{source_ip}:{dest_ip}"

        # Parse timestamp
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return indicators

        self._connection_intervals[key].append(timestamp)

        # Need minimum connections to detect beaconing
        intervals = self._connection_intervals[key]
        if len(intervals) < self.config.beacon_min_connections:
            return indicators

        # Calculate intervals between connections
        intervals_sorted = sorted(intervals)
        deltas = []
        for i in range(1, len(intervals_sorted)):
            delta = (intervals_sorted[i] - intervals_sorted[i - 1]).total_seconds()
            if delta > 0:
                deltas.append(delta)

        if len(deltas) < 3:
            return indicators

        # Check for regularity (low variance)
        avg_interval = sum(deltas) / len(deltas)
        if avg_interval > 0:
            variance = sum((d - avg_interval) ** 2 for d in deltas) / len(deltas)
            std_dev = variance**0.5
            coefficient_of_variation = std_dev / avg_interval

            if coefficient_of_variation < self.config.beacon_interval_tolerance:
                indicators.append(
                    NetworkIndicator(
                        indicator_type=NetworkThreatType.BEACONING,
                        description="Regular interval connections detected (beaconing)",
                        severity=EventSeverity.HIGH,
                        confidence=MatchConfidence.HIGH,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        evidence={
                            "avg_interval_sec": round(avg_interval, 2),
                            "connection_count": len(intervals),
                            "variance_coefficient": round(coefficient_of_variation, 3),
                        },
                        risk_contribution=0.4,
                    )
                )

        return indicators

    def _detect_lateral_movement(self, data: dict[str, Any]) -> list[NetworkIndicator]:
        """Detect lateral movement within internal network."""
        indicators = []

        source_ip = data.get("source_ip", "")
        dest_ip = data.get("destination_ip", "")
        dest_port = data.get("destination_port")
        protocol = data.get("protocol", "").lower()

        # Check if both IPs are internal
        try:
            src = ip_address(source_ip)
            dst = ip_address(dest_ip)

            src_internal = any(src in net for net in PRIVATE_NETWORKS)
            dst_internal = any(dst in net for net in PRIVATE_NETWORKS)

            if src_internal and dst_internal:
                # Suspicious internal protocols
                lateral_ports = {22, 23, 135, 139, 445, 3389, 5985, 5986}
                if dest_port in lateral_ports:
                    indicators.append(
                        NetworkIndicator(
                            indicator_type=NetworkThreatType.LATERAL_MOVEMENT,
                            description=f"Internal connection on administrative port {dest_port}",
                            severity=EventSeverity.MEDIUM,
                            confidence=MatchConfidence.MEDIUM,
                            source_ip=source_ip,
                            destination_ip=dest_ip,
                            destination_port=dest_port,
                            protocol=protocol,
                            evidence={
                                "port": dest_port,
                                "service": self._port_to_service(dest_port),
                            },
                            risk_contribution=0.2,
                        )
                    )

        except ValueError:
            pass

        return indicators

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        import math
        from collections import Counter

        if not text:
            return 0.0

        counter = Counter(text.lower())
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            if count > 0:
                freq = count / length
                entropy -= freq * math.log2(freq)

        return entropy

    def _port_to_service(self, port: int) -> str:
        """Map port number to service name."""
        services = {
            22: "SSH",
            23: "Telnet",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            3389: "RDP",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
        }
        return services.get(port, f"port-{port}")

    def _calculate_risk_score(self, indicators: list[NetworkIndicator]) -> float:
        """Calculate aggregate risk score."""
        if not indicators:
            return 0.0
        total = sum(ind.risk_contribution for ind in indicators)
        return min(total, 1.0)

    def _determine_primary_threat(
        self, indicators: list[NetworkIndicator]
    ) -> NetworkThreatType | None:
        """Determine the primary threat type from indicators."""
        if not indicators:
            return None

        # Prioritize by severity and risk
        severity_order = {
            EventSeverity.CRITICAL: 0,
            EventSeverity.HIGH: 1,
            EventSeverity.MEDIUM: 2,
            EventSeverity.LOW: 3,
        }

        indicators.sort(key=lambda x: (severity_order.get(x.severity, 4), -x.risk_contribution))
        return indicators[0].indicator_type

    def _create_network_finding(
        self,
        task: AgentTask,
        threat_type: NetworkThreatType | None,
        indicators: list[NetworkIndicator],
        risk_score: float,
        data: dict[str, Any],
    ) -> NetworkFinding:
        """Create network threat finding."""
        # Collect unique IPs and ports
        source_ips = list({ind.source_ip for ind in indicators if ind.source_ip})
        dest_ips = list({ind.destination_ip for ind in indicators if ind.destination_ip})
        ports = list({ind.destination_port for ind in indicators if ind.destination_port})
        protocols = list({ind.protocol for ind in indicators if ind.protocol})

        # Determine severity
        max_severity = EventSeverity.LOW
        for ind in indicators:
            if ind.severity == EventSeverity.CRITICAL:
                max_severity = EventSeverity.CRITICAL
                break
            elif ind.severity == EventSeverity.HIGH:
                max_severity = EventSeverity.HIGH
            elif ind.severity == EventSeverity.MEDIUM and max_severity == EventSeverity.LOW:
                max_severity = EventSeverity.MEDIUM

        # MITRE mappings
        mitre_map = {
            NetworkThreatType.C2_COMMUNICATION: (["T1071", "T1573"], ["command-and-control"]),
            NetworkThreatType.PORT_SCAN: (["T1046"], ["discovery"]),
            NetworkThreatType.DATA_EXFILTRATION: (["T1048"], ["exfiltration"]),
            NetworkThreatType.LATERAL_MOVEMENT: (["T1021"], ["lateral-movement"]),
            NetworkThreatType.DNS_TUNNELING: (["T1071.004"], ["command-and-control"]),
            NetworkThreatType.BEACONING: (["T1071"], ["command-and-control"]),
        }

        techniques, tactics = [], []
        if threat_type and threat_type in mitre_map:
            techniques, tactics = mitre_map[threat_type]

        return NetworkFinding(
            finding_id=f"network_{uuid.uuid4().hex}",
            finding_type="network_threat_analysis",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            severity=max_severity,
            confidence=MatchConfidence.HIGH if len(indicators) > 2 else MatchConfidence.MEDIUM,
            threat_type=threat_type or NetworkThreatType.ANOMALOUS_TRAFFIC,
            indicators=indicators,
            risk_score=risk_score,
            source_ips=source_ips,
            destination_ips=dest_ips,
            ports=ports,
            protocols=protocols,
            bytes_transferred=data.get("bytes_out", 0) + data.get("bytes_in", 0),
            connection_count=1,
            explanation=(
                f"Network threat detected: {threat_type.value if threat_type else 'anomaly'}"
            ),
            mitre_techniques=techniques,
            mitre_tactics=tactics,
        )
