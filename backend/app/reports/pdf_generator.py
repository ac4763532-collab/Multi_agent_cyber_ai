"""PDF Report Generation for Security Reports."""

import uuid
from datetime import datetime
from enum import StrEnum
from io import BytesIO
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class PDFReportType(StrEnum):
    """Types of PDF reports."""

    INCIDENT_REPORT = "incident_report"
    INVESTIGATION_REPORT = "investigation_report"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    COMPLIANCE_REPORT = "compliance_report"
    THREAT_BRIEF = "threat_brief"
    DAILY_SUMMARY = "daily_summary"
    WEEKLY_SUMMARY = "weekly_summary"


class PDFSection(BaseModel):
    """Section in a PDF report."""

    section_id: str = Field(default_factory=lambda: f"sec_{uuid.uuid4().hex[:8]}")
    title: str
    content: str
    order: int = 0
    include_page_break: bool = False


class PDFTable(BaseModel):
    """Table for PDF report."""

    table_id: str = Field(default_factory=lambda: f"tbl_{uuid.uuid4().hex[:8]}")
    title: str
    headers: list[str]
    rows: list[list[str]]
    caption: str = ""


class PDFChart(BaseModel):
    """Chart placeholder for PDF report."""

    chart_id: str = Field(default_factory=lambda: f"chart_{uuid.uuid4().hex[:8]}")
    chart_type: str  # bar, pie, line, timeline
    title: str
    data: dict[str, Any] = Field(default_factory=dict)
    width: int = 500
    height: int = 300


class PDFReportConfig(BaseModel):
    """Configuration for PDF report."""

    include_header: bool = True
    include_footer: bool = True
    include_toc: bool = True
    include_page_numbers: bool = True
    company_name: str = "Security Operations Center"
    logo_path: str | None = None
    classification: str = "CONFIDENTIAL"
    page_size: str = "A4"
    orientation: str = "portrait"


class PDFReport(BaseModel):
    """PDF report model."""

    report_id: str = Field(default_factory=lambda: f"rpt_{uuid.uuid4().hex[:12]}")
    report_type: PDFReportType
    title: str
    subtitle: str = ""
    author: str = "SOC Team"
    classification: str = "CONFIDENTIAL"
    sections: list[PDFSection] = Field(default_factory=list)
    tables: list[PDFTable] = Field(default_factory=list)
    charts: list[PDFChart] = Field(default_factory=list)
    config: PDFReportConfig = Field(default_factory=PDFReportConfig)
    created_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PDFGenerator:
    """Generates PDF reports."""

    def __init__(self, config: PDFReportConfig | None = None):
        self.config = config or PDFReportConfig()
        self._reports_generated = 0

    def create_report(
        self,
        report_type: PDFReportType,
        title: str,
        subtitle: str = "",
        author: str = "SOC Team",
    ) -> PDFReport:
        """Create a new PDF report."""
        return PDFReport(
            report_type=report_type,
            title=title,
            subtitle=subtitle,
            author=author,
            config=self.config,
        )

    def add_section(
        self,
        report: PDFReport,
        title: str,
        content: str,
        include_page_break: bool = False,
    ) -> PDFSection:
        """Add section to report."""
        section = PDFSection(
            title=title,
            content=content,
            order=len(report.sections),
            include_page_break=include_page_break,
        )
        report.sections.append(section)
        return section

    def add_table(
        self,
        report: PDFReport,
        title: str,
        headers: list[str],
        rows: list[list[str]],
        caption: str = "",
    ) -> PDFTable:
        """Add table to report."""
        table = PDFTable(
            title=title,
            headers=headers,
            rows=rows,
            caption=caption,
        )
        report.tables.append(table)
        return table

    def add_chart(
        self,
        report: PDFReport,
        chart_type: str,
        title: str,
        data: dict[str, Any],
    ) -> PDFChart:
        """Add chart to report."""
        chart = PDFChart(
            chart_type=chart_type,
            title=title,
            data=data,
        )
        report.charts.append(chart)
        return chart

    def generate_pdf(self, report: PDFReport) -> bytes:  # noqa: C901
        """Generate PDF bytes from report.

        Note: In production, this would use a library like reportlab or weasyprint.
        This implementation creates a simple text-based representation.
        """
        output = BytesIO()

        # Build content
        lines = []

        # Header
        if report.config.include_header:
            lines.append("=" * 60)
            lines.append(report.config.company_name.center(60))
            lines.append(report.config.classification.center(60))
            lines.append("=" * 60)
            lines.append("")

        # Title
        lines.append(report.title.upper().center(60))
        if report.subtitle:
            lines.append(report.subtitle.center(60))
        lines.append("")
        lines.append(f"Author: {report.author}")
        lines.append(f"Date: {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Report ID: {report.report_id}")
        lines.append("")

        # Table of Contents
        if report.config.include_toc and report.sections:
            lines.append("-" * 40)
            lines.append("TABLE OF CONTENTS")
            lines.append("-" * 40)
            for i, section in enumerate(report.sections, 1):
                lines.append(f"  {i}. {section.title}")
            lines.append("")

        # Sections
        for i, section in enumerate(report.sections, 1):
            lines.append("=" * 60)
            lines.append(f"{i}. {section.title.upper()}")
            lines.append("=" * 60)
            lines.append("")
            lines.append(section.content)
            lines.append("")

            if section.include_page_break:
                lines.append("\n--- PAGE BREAK ---\n")

        # Tables
        if report.tables:
            lines.append("=" * 60)
            lines.append("TABLES")
            lines.append("=" * 60)
            for table in report.tables:
                lines.append("")
                lines.append(f"Table: {table.title}")
                lines.append("-" * 40)

                # Header row
                lines.append(" | ".join(table.headers))
                lines.append("-" * 40)

                # Data rows
                for row in table.rows:
                    lines.append(" | ".join(row))

                if table.caption:
                    lines.append(f"Caption: {table.caption}")
                lines.append("")

        # Footer
        if report.config.include_footer:
            lines.append("")
            lines.append("=" * 60)
            lines.append(f"Generated by {report.config.company_name}")
            lines.append(report.config.classification.center(60))
            lines.append("=" * 60)

        content = "\n".join(lines)
        output.write(content.encode("utf-8"))
        self._reports_generated += 1

        return output.getvalue()

    def generate_incident_report(
        self,
        incident: dict[str, Any],
        include_timeline: bool = True,
        include_evidence: bool = True,
    ) -> PDFReport:
        """Generate incident report from incident data."""
        report = self.create_report(
            report_type=PDFReportType.INCIDENT_REPORT,
            title=f"Incident Report: {incident.get('incident_id', 'Unknown')}",
            subtitle=incident.get("title", ""),
        )

        # Executive Summary
        self.add_section(
            report,
            "Executive Summary",
            f"""
Incident ID: {incident.get('incident_id')}
Severity: {incident.get('severity', 'Unknown')}
Status: {incident.get('status', 'Unknown')}
Type: {incident.get('incident_type', 'Unknown')}

Description:
{incident.get('description', 'No description available.')}
            """.strip(),
        )

        # Affected Assets
        assets = incident.get("affected_assets", [])
        users = incident.get("affected_users", [])
        self.add_section(
            report,
            "Impact Assessment",
            f"""
Affected Assets: {len(assets)}
{chr(10).join(f'  - {a}' for a in assets) if assets else '  None identified'}

Affected Users: {len(users)}
{chr(10).join(f'  - {u}' for u in users) if users else '  None identified'}

Impact Assessment:
{incident.get('impact_assessment', 'Not yet assessed.')}
            """.strip(),
        )

        # Timeline
        if include_timeline and incident.get("timeline"):
            timeline_text = "Event Timeline:\n\n"
            for entry in incident.get("timeline", []):
                ts = entry.get("timestamp", "Unknown")
                desc = entry.get("description", "")
                timeline_text += f"[{ts}] {desc}\n"

            self.add_section(report, "Timeline", timeline_text.strip())

        # Root Cause
        if incident.get("root_cause"):
            self.add_section(
                report,
                "Root Cause Analysis",
                incident.get("root_cause", "Investigation ongoing."),
            )

        # Recommendations
        recommendations = incident.get("containment_actions", [])
        if recommendations:
            self.add_section(
                report,
                "Containment Actions",
                "\n".join(f"• {r}" for r in recommendations),
            )

        # Lessons Learned
        if incident.get("lessons_learned"):
            self.add_section(
                report,
                "Lessons Learned",
                incident.get("lessons_learned", ""),
            )

        return report

    def generate_executive_summary(
        self,
        metrics: dict[str, Any],
        period: str = "Daily",
    ) -> PDFReport:
        """Generate executive summary report."""
        report = self.create_report(
            report_type=PDFReportType.EXECUTIVE_SUMMARY,
            title=f"{period} Security Executive Summary",
        )

        # Overview
        self.add_section(
            report,
            "Security Overview",
            f"""
Report Period: {period}
Total Incidents: {metrics.get('total_incidents', 0)}
Open Incidents: {metrics.get('open_incidents', 0)}
Closed Incidents: {metrics.get('closed_incidents', 0)}
Mean Time to Resolve: {metrics.get('mttr_minutes', 0):.0f} minutes
            """.strip(),
        )

        # Severity breakdown
        by_severity = metrics.get("by_severity", {})
        severity_text = "Incidents by Severity:\n\n"
        for sev, count in sorted(by_severity.items()):
            severity_text += f"  {sev.upper()}: {count}\n"

        self.add_section(report, "Severity Distribution", severity_text.strip())

        # Add severity table
        if by_severity:
            self.add_table(
                report,
                "Incidents by Severity",
                ["Severity", "Count", "Percentage"],
                [
                    [
                        sev,
                        str(count),
                        f"{count / max(metrics.get('total_incidents', 1), 1) * 100:.1f}%",
                    ]
                    for sev, count in sorted(by_severity.items())
                ],
            )

        return report

    def get_metrics(self) -> dict[str, Any]:
        """Get generator metrics."""
        return {
            "reports_generated": self._reports_generated,
        }


# Singleton
_generator: PDFGenerator | None = None


def get_pdf_generator() -> PDFGenerator:
    """Get PDF generator singleton."""
    global _generator
    if _generator is None:
        _generator = PDFGenerator()
    return _generator
