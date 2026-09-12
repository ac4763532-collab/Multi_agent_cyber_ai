"""Report Generation Agent - automated security report generation."""

import json
import uuid
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


class ReportFormat(StrEnum):
    """Available report formats."""

    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"  # Generates HTML that can be converted to PDF
    TEXT = "text"


class ReportType(StrEnum):
    """Types of security reports."""

    INCIDENT_REPORT = "incident_report"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    THREAT_ASSESSMENT = "threat_assessment"
    COMPLIANCE_REPORT = "compliance_report"
    DAILY_SUMMARY = "daily_summary"
    INVESTIGATION_REPORT = "investigation_report"


class ReportSection(BaseModel):
    """A section within a report."""

    section_id: str
    title: str
    content: str
    order: int = 0
    subsections: list["ReportSection"] = Field(default_factory=list)


class ReportMetadata(BaseModel):
    """Metadata for generated report."""

    report_id: str
    report_type: ReportType
    title: str
    generated_at: datetime
    generated_by: str
    classification: str = "INTERNAL"
    version: str = "1.0"
    incident_id: str | None = None
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None


class GeneratedReport(BaseModel):
    """A generated report."""

    metadata: ReportMetadata
    format: ReportFormat
    sections: list[ReportSection] = Field(default_factory=list)
    content: str = ""  # Full rendered content
    summary: str = ""
    key_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    appendices: list[dict[str, Any]] = Field(default_factory=list)


class ReportFinding(BaseFinding):
    """Finding containing generated report."""

    report: GeneratedReport
    formats_generated: list[ReportFormat] = Field(default_factory=list)
    word_count: int = 0
    section_count: int = 0


class ReportGenerationAgent(BaseAgent):
    """Generates automated security reports in multiple formats.

    Capabilities:
    - Incident report generation
    - Executive summary creation
    - Technical analysis reports
    - Multiple output formats (JSON, HTML, Markdown, PDF-ready)
    - Customizable report templates
    """

    @property
    def agent_id(self) -> str:
        return "report_gen_001"

    @property
    def name(self) -> str:
        return "Report Generation Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.REPORT_GENERATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "incident_report_generation",
            "executive_summary_generation",
            "technical_analysis_reports",
            "multi_format_output",
            "template_customization",
            "compliance_reporting",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has report data."""
        payload = task.payload or {}
        return any(
            k in payload
            for k in [
                "incident",
                "findings",
                "investigation",
                "events",
                "report_type",
            ]
        )

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process report generation task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Determine report type and format
            report_type = self._determine_report_type(payload)
            report_format = ReportFormat(payload.get("format", "markdown").lower())

            # Extract data for report
            report_data = self._extract_report_data(payload)

            # Generate report sections
            sections = self._generate_sections(report_type, report_data)

            # Generate key findings and recommendations
            key_findings = self._extract_key_findings(report_data)
            recommendations = self._generate_recommendations(report_data)

            # Create report metadata
            metadata = ReportMetadata(
                report_id=f"report_{uuid.uuid4().hex}",
                report_type=report_type,
                title=self._generate_title(report_type, report_data),
                generated_at=utc_now(),
                generated_by=self.agent_id,
                incident_id=report_data.get("incident_id"),
                time_range_start=report_data.get("time_start"),
                time_range_end=report_data.get("time_end"),
            )

            # Render content in requested format
            content = self._render_report(
                metadata, sections, key_findings, recommendations, report_format
            )

            # Create report object
            report = GeneratedReport(
                metadata=metadata,
                format=report_format,
                sections=sections,
                content=content,
                summary=self._generate_summary(report_data),
                key_findings=key_findings,
                recommendations=recommendations,
            )

            # Calculate metrics
            word_count = len(content.split())

            # Create finding
            finding = ReportFinding(
                finding_id=f"rpt_{uuid.uuid4().hex}",
                finding_type="report_generation",
                event_id=task.event_id,
                task_id=task.task_id,
                agent_id=self.agent_id,
                severity=EventSeverity.INFORMATIONAL,
                confidence=MatchConfidence.HIGH,
                report=report,
                formats_generated=[report_format],
                word_count=word_count,
                section_count=len(sections),
                explanation=f"Generated {report_type.value} report with {len(sections)} sections",
                recommendations=recommendations[:5],
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
                    "report_id": metadata.report_id,
                    "report_type": report_type.value,
                    "format": report_format.value,
                    "word_count": word_count,
                    "section_count": len(sections),
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
            finding_id=f"rpt_{uuid.uuid4().hex}",
            finding_type="report_generation",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _determine_report_type(self, payload: dict[str, Any]) -> ReportType:
        """Determine report type from payload."""
        if "report_type" in payload:
            try:
                return ReportType(payload["report_type"])
            except ValueError:
                pass

        # Infer from content
        if "investigation" in payload:
            return ReportType.INVESTIGATION_REPORT
        if "incident" in payload:
            return ReportType.INCIDENT_REPORT
        if payload.get("executive", False):
            return ReportType.EXECUTIVE_SUMMARY
        if payload.get("technical", False):
            return ReportType.TECHNICAL_ANALYSIS

        return ReportType.INCIDENT_REPORT

    def _extract_report_data(  # noqa: C901
        self, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Extract and normalize data for report."""
        data: dict[str, Any] = {
            "incident_id": None,
            "severity": "medium",
            "findings": [],
            "events": [],
            "affected_assets": [],
            "affected_users": [],
            "timeline": [],
            "mitre_techniques": [],
            "recommendations": [],
            "time_start": None,
            "time_end": None,
        }

        # From incident
        if "incident" in payload:
            incident = payload["incident"]
            if isinstance(incident, dict):
                data["incident_id"] = incident.get("incident_id")
                data["severity"] = incident.get("severity", "medium")
                data["affected_assets"] = incident.get("affected_assets", [])
                data["affected_users"] = incident.get("affected_users", [])
                data["mitre_techniques"] = incident.get("mitre_techniques", [])

        # From investigation
        if "investigation" in payload:
            inv = payload["investigation"]
            if isinstance(inv, dict):
                data["incident_id"] = inv.get("investigation_id")
                data["timeline"] = inv.get("timeline", [])
                data["findings"] = inv.get("findings", [])

        # From findings list
        if "findings" in payload:
            for finding in payload["findings"]:
                if isinstance(finding, dict):
                    data["findings"].append(finding)

        # From events list
        if "events" in payload:
            for event in payload["events"]:
                if isinstance(event, dict):
                    data["events"].append(event)

        return data

    def _generate_sections(
        self, report_type: ReportType, data: dict[str, Any]
    ) -> list[ReportSection]:
        """Generate report sections based on type."""
        sections: list[ReportSection] = []

        if report_type == ReportType.INCIDENT_REPORT:
            sections = self._generate_incident_sections(data)
        elif report_type == ReportType.EXECUTIVE_SUMMARY:
            sections = self._generate_executive_sections(data)
        elif report_type == ReportType.TECHNICAL_ANALYSIS:
            sections = self._generate_technical_sections(data)
        elif report_type == ReportType.INVESTIGATION_REPORT:
            sections = self._generate_investigation_sections(data)
        else:
            sections = self._generate_incident_sections(data)

        return sections

    def _generate_incident_sections(self, data: dict[str, Any]) -> list[ReportSection]:
        """Generate sections for incident report."""
        sections = []

        # Executive Summary
        sections.append(
            ReportSection(
                section_id="exec_summary",
                title="Executive Summary",
                content=self._generate_summary(data),
                order=1,
            )
        )

        # Incident Overview
        overview_content = self._format_incident_overview(data)
        sections.append(
            ReportSection(
                section_id="overview",
                title="Incident Overview",
                content=overview_content,
                order=2,
            )
        )

        # Timeline
        if data.get("timeline") or data.get("events"):
            timeline_content = self._format_timeline(data)
            sections.append(
                ReportSection(
                    section_id="timeline",
                    title="Timeline of Events",
                    content=timeline_content,
                    order=3,
                )
            )

        # Technical Findings
        if data.get("findings"):
            findings_content = self._format_findings(data["findings"])
            sections.append(
                ReportSection(
                    section_id="findings",
                    title="Technical Findings",
                    content=findings_content,
                    order=4,
                )
            )

        # Affected Assets
        if data.get("affected_assets"):
            assets_content = self._format_affected_assets(data["affected_assets"])
            sections.append(
                ReportSection(
                    section_id="assets",
                    title="Affected Assets",
                    content=assets_content,
                    order=5,
                )
            )

        # MITRE ATT&CK Mapping
        if data.get("mitre_techniques"):
            mitre_content = self._format_mitre_mapping(data["mitre_techniques"])
            sections.append(
                ReportSection(
                    section_id="mitre",
                    title="MITRE ATT&CK Mapping",
                    content=mitre_content,
                    order=6,
                )
            )

        # Recommendations
        recommendations = self._generate_recommendations(data)
        if recommendations:
            rec_content = self._format_recommendations(recommendations)
            sections.append(
                ReportSection(
                    section_id="recommendations",
                    title="Recommendations",
                    content=rec_content,
                    order=7,
                )
            )

        return sections

    def _generate_executive_sections(self, data: dict[str, Any]) -> list[ReportSection]:
        """Generate sections for executive summary."""
        sections = []

        # Key Points
        sections.append(
            ReportSection(
                section_id="key_points",
                title="Key Points",
                content=self._format_key_points(data),
                order=1,
            )
        )

        # Impact Summary
        sections.append(
            ReportSection(
                section_id="impact",
                title="Business Impact",
                content=self._format_business_impact(data),
                order=2,
            )
        )

        # Risk Assessment
        sections.append(
            ReportSection(
                section_id="risk",
                title="Risk Assessment",
                content=self._format_risk_assessment(data),
                order=3,
            )
        )

        # Recommended Actions
        sections.append(
            ReportSection(
                section_id="actions",
                title="Recommended Actions",
                content=self._format_recommendations(self._generate_recommendations(data)),
                order=4,
            )
        )

        return sections

    def _generate_technical_sections(self, data: dict[str, Any]) -> list[ReportSection]:
        """Generate sections for technical analysis."""
        sections = []

        # Technical Overview
        sections.append(
            ReportSection(
                section_id="tech_overview",
                title="Technical Overview",
                content=self._format_incident_overview(data),
                order=1,
            )
        )

        # Detailed Findings
        if data.get("findings"):
            sections.append(
                ReportSection(
                    section_id="detailed_findings",
                    title="Detailed Technical Findings",
                    content=self._format_detailed_findings(data["findings"]),
                    order=2,
                )
            )

        # Indicators of Compromise
        sections.append(
            ReportSection(
                section_id="iocs",
                title="Indicators of Compromise",
                content=self._format_iocs(data),
                order=3,
            )
        )

        # Attack Chain Analysis
        sections.append(
            ReportSection(
                section_id="attack_chain",
                title="Attack Chain Analysis",
                content=self._format_attack_chain(data),
                order=4,
            )
        )

        # Remediation Steps
        sections.append(
            ReportSection(
                section_id="remediation",
                title="Technical Remediation Steps",
                content=self._format_remediation(data),
                order=5,
            )
        )

        return sections

    def _generate_investigation_sections(self, data: dict[str, Any]) -> list[ReportSection]:
        """Generate sections for investigation report."""
        sections = []

        # Investigation Summary
        sections.append(
            ReportSection(
                section_id="inv_summary",
                title="Investigation Summary",
                content=self._generate_summary(data),
                order=1,
            )
        )

        # Scope and Methodology
        sections.append(
            ReportSection(
                section_id="methodology",
                title="Scope and Methodology",
                content=self._format_methodology(),
                order=2,
            )
        )

        # Forensic Timeline
        sections.append(
            ReportSection(
                section_id="forensic_timeline",
                title="Forensic Timeline",
                content=self._format_timeline(data),
                order=3,
            )
        )

        # Evidence Analysis
        sections.append(
            ReportSection(
                section_id="evidence",
                title="Evidence Analysis",
                content=self._format_evidence(data),
                order=4,
            )
        )

        # Conclusions
        sections.append(
            ReportSection(
                section_id="conclusions",
                title="Conclusions",
                content=self._format_conclusions(data),
                order=5,
            )
        )

        return sections

    def _generate_title(self, report_type: ReportType, data: dict[str, Any]) -> str:
        """Generate report title."""
        incident_id = data.get("incident_id", "")

        titles = {
            ReportType.INCIDENT_REPORT: "Security Incident Report",
            ReportType.EXECUTIVE_SUMMARY: "Executive Security Summary",
            ReportType.TECHNICAL_ANALYSIS: "Technical Security Analysis",
            ReportType.INVESTIGATION_REPORT: "Security Investigation Report",
            ReportType.THREAT_ASSESSMENT: "Threat Assessment Report",
            ReportType.COMPLIANCE_REPORT: "Security Compliance Report",
            ReportType.DAILY_SUMMARY: "Daily Security Summary",
        }

        title = titles.get(report_type, "Security Report")
        if incident_id:
            title += f" - {incident_id}"

        return title

    def _generate_summary(self, data: dict[str, Any]) -> str:
        """Generate executive summary content."""
        severity = data.get("severity", "medium")
        finding_count = len(data.get("findings", []))
        asset_count = len(data.get("affected_assets", []))
        event_count = len(data.get("events", []))

        summary_parts = []

        summary_parts.append(
            f"This report documents a security incident classified as {severity} severity."
        )

        if finding_count:
            summary_parts.append(f"Analysis identified {finding_count} security findings.")

        if asset_count:
            summary_parts.append(f"{asset_count} assets were affected by this incident.")

        if event_count:
            summary_parts.append(f"The incident involved {event_count} security events.")

        if data.get("mitre_techniques"):
            techniques = data["mitre_techniques"][:3]
            summary_parts.append(f"MITRE ATT&CK techniques observed: {', '.join(techniques)}.")

        summary_parts.append("Immediate remediation actions are recommended based on the findings.")

        return " ".join(summary_parts)

    def _extract_key_findings(self, data: dict[str, Any]) -> list[str]:
        """Extract key findings from data."""
        key_findings = []

        severity = data.get("severity", "medium")
        key_findings.append(f"Incident severity: {severity.upper()}")

        if data.get("affected_assets"):
            key_findings.append(f"{len(data['affected_assets'])} assets identified as affected")

        if data.get("mitre_techniques"):
            key_findings.append("Attack techniques mapped to MITRE ATT&CK framework")

        for finding in data.get("findings", [])[:5]:
            if isinstance(finding, dict):
                explanation = finding.get("explanation", finding.get("description", ""))
                if explanation:
                    key_findings.append(explanation[:100])

        return key_findings

    def _generate_recommendations(self, data: dict[str, Any]) -> list[str]:
        """Generate recommendations based on data."""
        recommendations = []

        severity = data.get("severity", "medium")
        if isinstance(severity, str):
            severity = severity.lower()

        # Severity-based recommendations
        if severity in ("critical", "high"):
            recommendations.extend(
                [
                    "Activate incident response team immediately",
                    "Isolate affected systems from the network",
                    "Preserve all evidence for forensic analysis",
                ]
            )
        else:
            recommendations.extend(
                [
                    "Review affected systems for compromise indicators",
                    "Update security monitoring rules",
                ]
            )

        # Asset-based recommendations
        if data.get("affected_assets"):
            recommendations.append("Conduct thorough review of all affected assets")

        # User-based recommendations
        if data.get("affected_users"):
            recommendations.append("Reset credentials for affected user accounts")

        # MITRE-based recommendations
        if data.get("mitre_techniques"):
            recommendations.append("Implement mitigations for identified MITRE ATT&CK techniques")

        # General recommendations
        recommendations.extend(
            [
                "Update security policies based on lessons learned",
                "Conduct security awareness training for affected teams",
                "Review and update incident response procedures",
            ]
        )

        return recommendations[:10]

    def _render_report(
        self,
        metadata: ReportMetadata,
        sections: list[ReportSection],
        key_findings: list[str],
        recommendations: list[str],
        format: ReportFormat,
    ) -> str:
        """Render report in requested format."""
        if format == ReportFormat.JSON:
            return self._render_json(metadata, sections, key_findings, recommendations)
        elif format == ReportFormat.HTML:
            return self._render_html(metadata, sections, key_findings, recommendations)
        elif format == ReportFormat.MARKDOWN:
            return self._render_markdown(metadata, sections, key_findings, recommendations)
        elif format == ReportFormat.TEXT:
            return self._render_text(metadata, sections, key_findings, recommendations)
        elif format == ReportFormat.PDF:
            # Return HTML that can be converted to PDF
            return self._render_html(metadata, sections, key_findings, recommendations)
        else:
            return self._render_markdown(metadata, sections, key_findings, recommendations)

    def _render_markdown(
        self,
        metadata: ReportMetadata,
        sections: list[ReportSection],
        key_findings: list[str],
        recommendations: list[str],
    ) -> str:
        """Render report as Markdown."""
        lines = []

        # Title
        lines.append(f"# {metadata.title}")
        lines.append("")

        # Metadata
        lines.append("---")
        lines.append(f"**Report ID:** {metadata.report_id}")
        lines.append(f"**Generated:** {metadata.generated_at.isoformat()}")
        lines.append(f"**Classification:** {metadata.classification}")
        if metadata.incident_id:
            lines.append(f"**Incident ID:** {metadata.incident_id}")
        lines.append("---")
        lines.append("")

        # Key Findings
        if key_findings:
            lines.append("## Key Findings")
            lines.append("")
            for finding in key_findings:
                lines.append(f"- {finding}")
            lines.append("")

        # Sections
        for section in sorted(sections, key=lambda s: s.order):
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")

        # Recommendations
        if recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    def _render_html(
        self,
        metadata: ReportMetadata,
        sections: list[ReportSection],
        key_findings: list[str],
        recommendations: list[str],
    ) -> str:
        """Render report as HTML."""
        html_parts = []

        # CSS styles - split for readability
        css_body = "font-family: Arial, sans-serif; margin: 40px; line-height: 1.6;"
        css_h1 = "color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px;"
        css_h2 = "color: #555; margin-top: 30px;"
        css_box = "padding: 15px; border-radius: 5px; margin: 20px 0;"

        html_parts.append(f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{metadata.title}</title>
    <style>
        body {{ {css_body} }}
        h1 {{ {css_h1} }}
        h2 {{ {css_h2} }}
        .metadata {{ background: #f5f5f5; {css_box} }}
        .key-findings {{ background: #fff3cd; {css_box} }}
        .recommendations {{ background: #d4edda; {css_box} }}
        ul, ol {{ margin: 10px 0; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
""")

        # Title
        html_parts.append(f"<h1>{metadata.title}</h1>")

        # Metadata
        html_parts.append('<div class="metadata">')
        html_parts.append(f"<p><strong>Report ID:</strong> {metadata.report_id}</p>")
        html_parts.append(f"<p><strong>Generated:</strong> {metadata.generated_at.isoformat()}</p>")
        html_parts.append(f"<p><strong>Classification:</strong> {metadata.classification}</p>")
        if metadata.incident_id:
            html_parts.append(f"<p><strong>Incident ID:</strong> {metadata.incident_id}</p>")
        html_parts.append("</div>")

        # Key Findings
        if key_findings:
            html_parts.append('<div class="key-findings">')
            html_parts.append("<h2>Key Findings</h2>")
            html_parts.append("<ul>")
            for finding in key_findings:
                html_parts.append(f"<li>{finding}</li>")
            html_parts.append("</ul>")
            html_parts.append("</div>")

        # Sections
        for section in sorted(sections, key=lambda s: s.order):
            html_parts.append(f"<h2>{section.title}</h2>")
            # Convert newlines to <br> for HTML
            content = section.content.replace("\n", "<br>")
            html_parts.append(f"<p>{content}</p>")

        # Recommendations
        if recommendations:
            html_parts.append('<div class="recommendations">')
            html_parts.append("<h2>Recommendations</h2>")
            html_parts.append("<ol>")
            for rec in recommendations:
                html_parts.append(f"<li>{rec}</li>")
            html_parts.append("</ol>")
            html_parts.append("</div>")

        html_parts.append("</body></html>")

        return "\n".join(html_parts)

    def _render_json(
        self,
        metadata: ReportMetadata,
        sections: list[ReportSection],
        key_findings: list[str],
        recommendations: list[str],
    ) -> str:
        """Render report as JSON."""
        report_dict = {
            "metadata": {
                "report_id": metadata.report_id,
                "report_type": metadata.report_type.value,
                "title": metadata.title,
                "generated_at": metadata.generated_at.isoformat(),
                "generated_by": metadata.generated_by,
                "classification": metadata.classification,
                "incident_id": metadata.incident_id,
            },
            "key_findings": key_findings,
            "sections": [
                {
                    "id": s.section_id,
                    "title": s.title,
                    "content": s.content,
                    "order": s.order,
                }
                for s in sorted(sections, key=lambda s: s.order)
            ],
            "recommendations": recommendations,
        }

        return json.dumps(report_dict, indent=2)

    def _render_text(
        self,
        metadata: ReportMetadata,
        sections: list[ReportSection],
        key_findings: list[str],
        recommendations: list[str],
    ) -> str:
        """Render report as plain text."""
        lines = []

        # Title
        lines.append("=" * 60)
        lines.append(metadata.title.upper())
        lines.append("=" * 60)
        lines.append("")

        # Metadata
        lines.append(f"Report ID: {metadata.report_id}")
        lines.append(f"Generated: {metadata.generated_at.isoformat()}")
        lines.append(f"Classification: {metadata.classification}")
        if metadata.incident_id:
            lines.append(f"Incident ID: {metadata.incident_id}")
        lines.append("")

        # Key Findings
        if key_findings:
            lines.append("-" * 40)
            lines.append("KEY FINDINGS")
            lines.append("-" * 40)
            for finding in key_findings:
                lines.append(f"* {finding}")
            lines.append("")

        # Sections
        for section in sorted(sections, key=lambda s: s.order):
            lines.append("-" * 40)
            lines.append(section.title.upper())
            lines.append("-" * 40)
            lines.append(section.content)
            lines.append("")

        # Recommendations
        if recommendations:
            lines.append("-" * 40)
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    # Helper methods for formatting sections

    def _format_incident_overview(self, data: dict[str, Any]) -> str:
        """Format incident overview section."""
        lines = []
        lines.append(f"Severity: {data.get('severity', 'Unknown').upper()}")
        lines.append(f"Affected Assets: {len(data.get('affected_assets', []))}")
        lines.append(f"Affected Users: {len(data.get('affected_users', []))}")
        lines.append(f"Total Events: {len(data.get('events', []))}")
        return "\n".join(lines)

    def _format_timeline(self, data: dict[str, Any]) -> str:
        """Format timeline section."""
        timeline = data.get("timeline", [])
        events = data.get("events", [])

        lines = []
        items = timeline if timeline else events

        for item in items[:20]:  # Limit to 20 entries
            if isinstance(item, dict):
                ts = item.get("timestamp", "Unknown time")
                event_type = item.get("event_type", item.get("type", "Event"))
                desc = item.get("description", item.get("event_id", ""))
                lines.append(f"[{ts}] {event_type}: {desc}")

        return "\n".join(lines) if lines else "No timeline data available."

    def _format_findings(self, findings: list[Any]) -> str:
        """Format findings section."""
        lines = []
        for i, finding in enumerate(findings[:10], 1):
            if isinstance(finding, dict):
                severity = finding.get("severity", "medium")
                finding_type = finding.get("finding_type", "finding")
                explanation = finding.get("explanation", "No details available")
                lines.append(f"{i}. [{severity.upper()}] {finding_type}")
                lines.append(f"   {explanation}")
                lines.append("")
        return "\n".join(lines) if lines else "No findings to report."

    def _format_detailed_findings(self, findings: list[Any]) -> str:
        """Format detailed findings for technical report."""
        return self._format_findings(findings)

    def _format_affected_assets(self, assets: list[Any]) -> str:
        """Format affected assets section."""
        lines = []
        for asset in assets[:20]:
            if isinstance(asset, str):
                lines.append(f"- {asset}")
            elif isinstance(asset, dict):
                name = asset.get("name", asset.get("ip", asset.get("hostname", "Unknown")))
                asset_type = asset.get("type", "host")
                lines.append(f"- {name} ({asset_type})")
        return "\n".join(lines) if lines else "No affected assets identified."

    def _format_mitre_mapping(self, techniques: list[str]) -> str:
        """Format MITRE ATT&CK mapping section."""
        lines = []
        for tech in techniques:
            lines.append(f"- {tech}")
        return "\n".join(lines) if lines else "No MITRE techniques mapped."

    def _format_recommendations(self, recommendations: list[str]) -> str:
        """Format recommendations section."""
        lines = []
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        return "\n".join(lines) if lines else "No recommendations at this time."

    def _format_key_points(self, data: dict[str, Any]) -> str:
        """Format key points for executive summary."""
        points = self._extract_key_findings(data)
        return "\n".join(f"• {p}" for p in points)

    def _format_business_impact(self, data: dict[str, Any]) -> str:
        """Format business impact section."""
        lines = []
        lines.append(f"Assets Affected: {len(data.get('affected_assets', []))}")
        lines.append(f"Users Affected: {len(data.get('affected_users', []))}")
        lines.append("Business continuity assessment: Under evaluation")
        return "\n".join(lines)

    def _format_risk_assessment(self, data: dict[str, Any]) -> str:
        """Format risk assessment section."""
        severity = data.get("severity", "medium")
        lines = []
        lines.append(f"Current Risk Level: {severity.upper()}")
        lines.append(
            "Risk factors considered: Asset criticality, data sensitivity, threat actor capability"
        )
        return "\n".join(lines)

    def _format_iocs(self, data: dict[str, Any]) -> str:
        """Format IoCs section."""
        lines = []
        lines.append("Indicators of Compromise identified during analysis:")
        # Would extract actual IoCs from findings
        lines.append("- See technical findings for detailed IoC list")
        return "\n".join(lines)

    def _format_attack_chain(self, data: dict[str, Any]) -> str:
        """Format attack chain section."""
        techniques = data.get("mitre_techniques", [])
        if techniques:
            return f"Attack chain involved the following techniques: {', '.join(techniques)}"
        return "Attack chain analysis in progress."

    def _format_remediation(self, data: dict[str, Any]) -> str:
        """Format remediation section."""
        return self._format_recommendations(self._generate_recommendations(data))

    def _format_methodology(self) -> str:
        """Format methodology section."""
        return """Investigation methodology included:
1. Evidence collection and preservation
2. Timeline reconstruction
3. Malware analysis (if applicable)
4. Network traffic analysis
5. Log correlation and analysis
6. Affected asset identification
7. Root cause determination"""

    def _format_evidence(self, data: dict[str, Any]) -> str:
        """Format evidence section."""
        event_count = len(data.get("events", []))
        finding_count = len(data.get("findings", []))
        return f"Evidence analyzed: {event_count} events, {finding_count} findings"

    def _format_conclusions(self, data: dict[str, Any]) -> str:
        """Format conclusions section."""
        return """Based on the investigation:
1. The incident has been characterized and documented
2. Affected assets have been identified
3. Remediation recommendations have been provided
4. Follow-up actions are recommended as outlined above"""
