"""Email Verification Agent - full implementation for phishing detection."""

import re
import uuid
from email.utils import parseaddr
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

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

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".link"}

# Suspicious file extensions for attachments
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".msi",
    ".jar", ".hta", ".wsf", ".lnk", ".pif", ".reg", ".com",
}

# Password-protected archive indicators
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

# Urgency keywords
URGENCY_PATTERNS = [
    r"(?i)\b(urgent|immediate|action\s+required|act\s+now|limited\s+time)\b",
    r"(?i)\b(within\s+\d+\s+hours?|expires?\s+today|deadline)\b",
    r"(?i)\b(account\s+(suspended|locked|compromised|disabled))\b",
    r"(?i)\b(verify\s+(your\s+)?(account|identity|email))\b",
]

# Credential request patterns
CREDENTIAL_PATTERNS = [
    r"(?i)\b(password|login|credential|sign\s*in)\b.*\b(update|verify|confirm|reset)\b",
    r"(?i)\b(update|verify|confirm)\b.*\b(password|login|credential)\b",
    r"(?i)\bclick\s+(here|below|link)\s+to\s+(verify|confirm|login|sign\s*in)\b",
    r"(?i)\benter\s+(your\s+)?(password|credentials)\b",
]

# Financial/scam indicators
FINANCIAL_PATTERNS = [
    r"(?i)\b(invoice|payment|wire\s+transfer|bank\s+account)\b",
    r"(?i)\b(tax\s+refund|lottery|prize|winner|inheritance)\b",
    r"(?i)\b(bitcoin|crypto|investment\s+opportunity)\b",
    r"(?i)\b(\$\d+[,\d]*|\d+\s*dollars?)\b",
]


class EmailClassification(StrEnum):
    """Classification levels for email security analysis."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    POSSIBLE_PHISHING = "possible_phishing"
    POSSIBLE_SOCIAL_ENGINEERING = "possible_social_engineering"
    MALICIOUS_INDICATORS = "malicious_indicators"


class EmailIndicator(BaseModel):
    """Single indicator found in email analysis."""

    indicator_type: str = Field(..., description="Type of indicator")
    description: str = Field(..., description="Description of the finding")
    severity: EventSeverity = Field(default=EventSeverity.LOW)
    confidence: MatchConfidence = Field(default=MatchConfidence.MEDIUM)
    evidence: str = Field(default="", description="Supporting evidence")
    risk_contribution: float = Field(default=0.1, ge=0.0, le=1.0)


class ExtractedURL(BaseModel):
    """URL extracted from email with analysis."""

    url: str
    domain: str
    is_ip_based: bool = False
    has_suspicious_tld: bool = False
    subdomain_count: int = 0
    is_shortened: bool = False


class AttachmentMetadata(BaseModel):
    """Metadata about email attachment (never executed)."""

    filename: str
    extension: str
    size_bytes: int = 0
    content_type: str = ""
    is_suspicious_type: bool = False
    is_archive: bool = False


class EmailAnalysis(BaseModel):
    """Extracted and analyzed email components."""

    sender: str = ""
    sender_domain: str = ""
    reply_to: str | None = None
    reply_to_domain: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_text: str = ""
    body_html: str | None = None
    urls: list[ExtractedURL] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMetadata] = Field(default_factory=list)

    # Authentication results
    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None


class EmailFinding(BaseFinding):
    """Finding specific to email security analysis."""

    classification: EmailClassification = Field(
        default=EmailClassification.BENIGN,
        description="Overall email classification",
    )
    indicators: list[EmailIndicator] = Field(
        default_factory=list,
        description="List of detected indicators",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Aggregate risk score",
    )
    analysis: EmailAnalysis | None = Field(
        default=None,
        description="Extracted email analysis",
    )


class EmailVerificationAgent(BaseAgent):
    """Analyzes emails for phishing, social engineering, and malicious indicators.

    Performs deterministic analysis without executing attachments or visiting URLs.

    Analysis includes:
    - Sender/domain mismatch detection
    - Suspicious URL structure analysis
    - Credential request pattern detection
    - Urgency language indicators
    - Financial/social-engineering markers
    - Header inconsistency checks
    - Attachment metadata analysis
    - Domain anomaly detection
    """

    @property
    def agent_id(self) -> str:
        return "email_verification_001"

    @property
    def name(self) -> str:
        return "Email Verification Agent"

    @property
    def agent_type(self) -> AgentType:
        return AgentType.EMAIL_VERIFICATION

    @property
    def capabilities(self) -> list[str]:
        return [
            "phishing_detection",
            "social_engineering_detection",
            "header_analysis",
            "url_analysis",
            "attachment_analysis",
            "sender_verification",
        ]

    async def validate_task(self, task: AgentTask) -> bool:
        """Validate task has email data."""
        payload = task.payload or {}

        # Must have email content or event with email data
        has_email = (
            "email" in payload
            or "eml" in payload
            or "raw_email" in payload
            or "event" in payload
        )

        return has_email

    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process email security analysis task."""
        start_time = utc_now()
        payload = task.payload or {}

        try:
            # Extract email data
            email_data = self._extract_email_data(payload)

            # Perform analysis
            analysis = self._analyze_email(email_data)

            # Detect indicators
            indicators = self._detect_indicators(analysis)

            # Calculate risk score and classification
            risk_score = self._calculate_risk_score(indicators)
            classification = self._determine_classification(indicators, risk_score)

            # Create finding
            finding = self._create_email_finding(
                task=task,
                classification=classification,
                indicators=indicators,
                risk_score=risk_score,
                analysis=analysis,
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
                    "classification": classification.value,
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
        """Create a basic finding (used by base class)."""
        return BaseFinding(
            finding_id=f"email_{uuid.uuid4().hex}",
            finding_type="email_analysis",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            metadata=analysis,
        )

    def _create_email_finding(
        self,
        task: AgentTask,
        classification: EmailClassification,
        indicators: list[EmailIndicator],
        risk_score: float,
        analysis: EmailAnalysis,
    ) -> EmailFinding:
        """Create detailed email finding."""
        # Determine severity based on classification
        severity_map = {
            EmailClassification.BENIGN: EventSeverity.INFORMATIONAL,
            EmailClassification.SUSPICIOUS: EventSeverity.LOW,
            EmailClassification.POSSIBLE_PHISHING: EventSeverity.MEDIUM,
            EmailClassification.POSSIBLE_SOCIAL_ENGINEERING: EventSeverity.MEDIUM,
            EmailClassification.MALICIOUS_INDICATORS: EventSeverity.HIGH,
        }

        # Generate explanation
        explanation = self._generate_explanation(classification, indicators)

        # Generate recommendations
        recommendations = self._generate_recommendations(classification, indicators)

        return EmailFinding(
            finding_id=f"email_{uuid.uuid4().hex}",
            finding_type="email_security_analysis",
            event_id=task.event_id,
            task_id=task.task_id,
            agent_id=self.agent_id,
            severity=severity_map.get(classification, EventSeverity.LOW),
            confidence=MatchConfidence.HIGH if indicators else MatchConfidence.MEDIUM,
            explanation=explanation,
            recommendations=recommendations,
            classification=classification,
            indicators=indicators,
            risk_score=risk_score,
            analysis=analysis,
            mitre_techniques=(
                ["T1566", "T1566.001"] if classification != EmailClassification.BENIGN else []
            ),
            mitre_tactics=(
                ["initial-access"] if classification != EmailClassification.BENIGN else []
            ),
        )

    def _extract_email_data(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract email data from various payload formats."""
        # Direct email object
        if "email" in payload:
            return payload["email"]

        # Raw EML content
        if "eml" in payload or "raw_email" in payload:
            return self._parse_eml(payload.get("eml") or payload.get("raw_email"))

        # Event with email data
        if "event" in payload:
            event = payload["event"]
            if isinstance(event, dict):
                return event.get("raw_data", {})

        return {}

    def _parse_eml(self, eml_content: str) -> dict[str, Any]:
        """Parse raw EML content into structured data."""
        # Basic EML parsing (simplified)
        result: dict[str, Any] = {
            "headers": {},
            "body": "",
            "subject": "",
            "from": "",
            "to": [],
        }

        lines = eml_content.split("\n")
        in_body = False
        body_lines = []

        for line in lines:
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                in_body = True
            elif ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                result["headers"][key] = value

                if key == "subject":
                    result["subject"] = value
                elif key == "from":
                    result["from"] = value
                elif key == "to":
                    result["to"] = [v.strip() for v in value.split(",")]

        result["body"] = "\n".join(body_lines)
        return result

    def _analyze_email(self, email_data: dict[str, Any]) -> EmailAnalysis:
        """Analyze email components."""
        headers = email_data.get("headers", {})

        # Extract sender info
        sender_raw = email_data.get("from") or headers.get("from", "")
        _, sender = parseaddr(sender_raw)
        sender_domain = sender.split("@")[1] if "@" in sender else ""

        # Extract reply-to
        reply_to_raw = headers.get("reply-to", "")
        _, reply_to = parseaddr(reply_to_raw) if reply_to_raw else ("", None)
        reply_to_domain = reply_to.split("@")[1] if reply_to and "@" in reply_to else None

        # Extract body
        body_text = email_data.get("body", "") or email_data.get("body_text", "")
        body_html = email_data.get("body_html")

        # Extract URLs
        urls = self._extract_urls(body_text + (body_html or ""))

        # Extract attachments
        attachments = self._extract_attachments(email_data.get("attachments", []))

        # Check authentication headers
        spf_result = self._extract_auth_result(headers, "received-spf")
        dkim_result = self._extract_auth_result(headers, "dkim-signature")
        dmarc_result = self._extract_auth_result(headers, "authentication-results")

        return EmailAnalysis(
            sender=sender,
            sender_domain=sender_domain,
            reply_to=reply_to,
            reply_to_domain=reply_to_domain,
            recipients=email_data.get("to", []),
            subject=email_data.get("subject", ""),
            headers=headers,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            domains=list({u.domain for u in urls}),
            attachments=attachments,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
        )

    def _extract_urls(self, text: str) -> list[ExtractedURL]:
        """Extract and analyze URLs from text."""
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        matches = re.findall(url_pattern, text, re.IGNORECASE)

        urls = []
        seen = set()

        for match in matches:
            if match in seen:
                continue
            seen.add(match)

            try:
                parsed = urlparse(match if match.startswith("http") else f"http://{match}")
                domain = parsed.netloc.lower()

                # Check if IP-based
                is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))

                # Check TLD
                has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

                # Count subdomains
                subdomain_count = domain.count(".") - 1 if "." in domain else 0

                # Check for URL shorteners
                shorteners = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "is.gd"}
                is_shortened = any(s in domain for s in shorteners)

                urls.append(ExtractedURL(
                    url=match,
                    domain=domain,
                    is_ip_based=is_ip,
                    has_suspicious_tld=has_suspicious_tld,
                    subdomain_count=subdomain_count,
                    is_shortened=is_shortened,
                ))
            except Exception:  # noqa: S112
                # Skip malformed URLs - parsing failures are expected for invalid input
                continue

        return urls

    def _extract_attachments(self, attachments_data: list[Any]) -> list[AttachmentMetadata]:
        """Extract attachment metadata."""
        attachments = []

        for att in attachments_data:
            if isinstance(att, dict):
                filename = att.get("filename", att.get("name", ""))
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

                attachments.append(AttachmentMetadata(
                    filename=filename,
                    extension=ext,
                    size_bytes=att.get("size", 0),
                    content_type=att.get("content_type", ""),
                    is_suspicious_type=ext in SUSPICIOUS_EXTENSIONS,
                    is_archive=ext in ARCHIVE_EXTENSIONS,
                ))

        return attachments

    def _extract_auth_result(self, headers: dict[str, str], header_name: str) -> str | None:
        """Extract authentication result from headers."""
        value = headers.get(header_name, "")
        if "pass" in value.lower():
            return "pass"
        elif "fail" in value.lower():
            return "fail"
        elif "none" in value.lower():
            return "none"
        return None

    def _detect_indicators(  # noqa: C901
        self, analysis: EmailAnalysis
    ) -> list[EmailIndicator]:
        """Detect all indicators from email analysis."""
        indicators: list[EmailIndicator] = []

        # Check sender/reply-to mismatch
        if analysis.reply_to_domain and analysis.sender_domain:
            if analysis.reply_to_domain != analysis.sender_domain:
                indicators.append(EmailIndicator(
                    indicator_type="sender_mismatch",
                    description="Reply-To domain differs from sender domain",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.HIGH,
                    evidence=(
                        f"From: {analysis.sender_domain}, "
                        f"Reply-To: {analysis.reply_to_domain}"
                    ),
                    risk_contribution=0.25,
                ))

        # Check authentication failures
        if analysis.spf_result == "fail":
            indicators.append(EmailIndicator(
                indicator_type="spf_fail",
                description="SPF authentication failed",
                severity=EventSeverity.MEDIUM,
                confidence=MatchConfidence.HIGH,
                evidence="SPF: fail",
                risk_contribution=0.2,
            ))

        if analysis.dkim_result == "fail":
            indicators.append(EmailIndicator(
                indicator_type="dkim_fail",
                description="DKIM signature verification failed",
                severity=EventSeverity.MEDIUM,
                confidence=MatchConfidence.HIGH,
                evidence="DKIM: fail",
                risk_contribution=0.2,
            ))

        # Check URLs
        for url in analysis.urls:
            if url.is_ip_based:
                indicators.append(EmailIndicator(
                    indicator_type="ip_based_url",
                    description="URL uses IP address instead of domain",
                    severity=EventSeverity.MEDIUM,
                    confidence=MatchConfidence.HIGH,
                    evidence=url.url[:100],
                    risk_contribution=0.15,
                ))

            if url.has_suspicious_tld:
                indicators.append(EmailIndicator(
                    indicator_type="suspicious_tld",
                    description="URL uses suspicious top-level domain",
                    severity=EventSeverity.LOW,
                    confidence=MatchConfidence.MEDIUM,
                    evidence=url.domain,
                    risk_contribution=0.1,
                ))

            if url.subdomain_count > 3:
                indicators.append(EmailIndicator(
                    indicator_type="excessive_subdomains",
                    description="URL has excessive subdomains",
                    severity=EventSeverity.LOW,
                    confidence=MatchConfidence.MEDIUM,
                    evidence=url.domain,
                    risk_contribution=0.1,
                ))

        # Check attachments
        for att in analysis.attachments:
            if att.is_suspicious_type:
                indicators.append(EmailIndicator(
                    indicator_type="suspicious_attachment",
                    description=f"Suspicious attachment type: {att.extension}",
                    severity=EventSeverity.HIGH,
                    confidence=MatchConfidence.HIGH,
                    evidence=att.filename,
                    risk_contribution=0.3,
                ))

        # Check for urgency language
        combined_text = f"{analysis.subject} {analysis.body_text}"
        self._check_pattern_indicators(
            indicators, combined_text, URGENCY_PATTERNS,
            "urgency_language", "Email contains urgency language",
            EventSeverity.LOW, 0.1,
        )

        # Check for credential requests
        self._check_pattern_indicators(
            indicators, combined_text, CREDENTIAL_PATTERNS,
            "credential_request", "Email requests credentials or login",
            EventSeverity.MEDIUM, 0.2,
        )

        # Check for financial indicators
        self._check_pattern_indicators(
            indicators, combined_text, FINANCIAL_PATTERNS,
            "financial_indicator", "Email contains financial/scam indicators",
            EventSeverity.LOW, 0.1,
        )

        return indicators

    def _check_pattern_indicators(
        self,
        indicators: list[EmailIndicator],
        text: str,
        patterns: list[str],
        indicator_type: str,
        description: str,
        severity: EventSeverity,
        risk_contribution: float,
    ) -> None:
        """Check text against patterns and add indicator if matched."""
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                indicators.append(EmailIndicator(
                    indicator_type=indicator_type,
                    description=description,
                    severity=severity,
                    confidence=MatchConfidence.MEDIUM,
                    evidence=match.group(0)[:80],
                    risk_contribution=risk_contribution,
                ))
                break  # Only count once per category

    def _calculate_risk_score(self, indicators: list[EmailIndicator]) -> float:
        """Calculate aggregate risk score from indicators."""
        if not indicators:
            return 0.0

        # Sum risk contributions, cap at 1.0
        total = sum(ind.risk_contribution for ind in indicators)
        return min(total, 1.0)

    def _determine_classification(
        self,
        indicators: list[EmailIndicator],
        risk_score: float,
    ) -> EmailClassification:
        """Determine overall classification based on indicators."""
        if not indicators:
            return EmailClassification.BENIGN

        # Check for malicious indicators
        high_severity_count = sum(1 for ind in indicators if ind.severity == EventSeverity.HIGH)
        if high_severity_count > 0 or risk_score >= 0.7:
            return EmailClassification.MALICIOUS_INDICATORS

        # Check for phishing indicators
        phishing_types = {"credential_request", "sender_mismatch", "ip_based_url"}
        phishing_count = sum(1 for ind in indicators if ind.indicator_type in phishing_types)
        if phishing_count >= 2 or risk_score >= 0.5:
            return EmailClassification.POSSIBLE_PHISHING

        # Check for social engineering
        social_types = {"urgency_language", "financial_indicator"}
        social_count = sum(1 for ind in indicators if ind.indicator_type in social_types)
        if social_count >= 2 or risk_score >= 0.3:
            return EmailClassification.POSSIBLE_SOCIAL_ENGINEERING

        # Default to suspicious if any indicators
        if risk_score >= 0.1:
            return EmailClassification.SUSPICIOUS

        return EmailClassification.BENIGN

    def _generate_explanation(
        self,
        classification: EmailClassification,
        indicators: list[EmailIndicator],
    ) -> str:
        """Generate human-readable explanation."""
        if classification == EmailClassification.BENIGN:
            return "No significant security indicators detected in this email."

        explanations = {
            EmailClassification.SUSPICIOUS: (
                "This email contains minor suspicious indicators that warrant attention."
            ),
            EmailClassification.POSSIBLE_PHISHING: (
                "This email exhibits characteristics consistent with phishing attempts."
            ),
            EmailClassification.POSSIBLE_SOCIAL_ENGINEERING: (
                "This email contains social engineering tactics to manipulate the recipient."
            ),
            EmailClassification.MALICIOUS_INDICATORS: (
                "This email contains strong indicators of malicious intent."
            ),
        }

        base = explanations.get(classification, "Security analysis completed.")
        indicator_types = [ind.indicator_type.replace("_", " ") for ind in indicators[:3]]
        indicator_summary = ", ".join(indicator_types)

        return f"{base} Detected indicators: {indicator_summary}."

    def _generate_recommendations(
        self,
        classification: EmailClassification,
        indicators: list[EmailIndicator],
    ) -> list[str]:
        """Generate security recommendations."""
        if classification == EmailClassification.BENIGN:
            return []

        recommendations = ["Do not click any links in this email."]

        if classification == EmailClassification.MALICIOUS_INDICATORS:
            recommendations.extend([
                "Report this email to your security team immediately.",
                "Delete this email from your inbox.",
                "Do not download or open any attachments.",
            ])
        elif classification == EmailClassification.POSSIBLE_PHISHING:
            recommendations.extend([
                "Verify the sender through an alternative channel.",
                "Do not enter any credentials on linked pages.",
                "Forward to your security team for review.",
            ])
        elif classification == EmailClassification.POSSIBLE_SOCIAL_ENGINEERING:
            recommendations.extend([
                "Be skeptical of urgent requests.",
                "Verify any financial requests through official channels.",
            ])
        else:
            recommendations.append("Exercise caution before taking any action.")

        return recommendations
