"""Specialized agents package - 12 autonomous security analysis agents."""

from backend.app.agents.specialized.correlation import CorrelationAgent
from backend.app.agents.specialized.email_verification import EmailVerificationAgent
from backend.app.agents.specialized.incident_prioritization import IncidentPrioritizationAgent
from backend.app.agents.specialized.investigation import InvestigationAgent
from backend.app.agents.specialized.ip_range_analyzer import IPRangeAnalyzerAgent
from backend.app.agents.specialized.log_analyzer import LogAnalyzerAgent
from backend.app.agents.specialized.network_threat import NetworkThreatAgent
from backend.app.agents.specialized.report_generation import ReportGenerationAgent
from backend.app.agents.specialized.response_recommendation import ResponseRecommendationAgent
from backend.app.agents.specialized.threat_intelligence import ThreatIntelligenceAgent
from backend.app.agents.specialized.vulnerability import VulnerabilityAgent

__all__ = [
    "EmailVerificationAgent",
    "LogAnalyzerAgent",
    "NetworkThreatAgent",
    "IPRangeAnalyzerAgent",
    "VulnerabilityAgent",
    "ThreatIntelligenceAgent",
    "CorrelationAgent",
    "InvestigationAgent",
    "IncidentPrioritizationAgent",
    "ResponseRecommendationAgent",
    "ReportGenerationAgent",
]
