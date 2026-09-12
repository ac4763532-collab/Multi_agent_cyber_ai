"""Security Audit and Hardening Module."""

import hashlib
import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.utils.datetime import utc_now


class AuditSeverity(StrEnum):
    """Audit finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditCategory(StrEnum):
    """Audit finding categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    DATA_PROTECTION = "data_protection"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    NETWORK = "network"
    COMPLIANCE = "compliance"


class ComplianceFramework(StrEnum):
    """Compliance frameworks."""

    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CIS = "cis_benchmarks"


class AuditFinding(BaseModel):
    """Security audit finding."""

    finding_id: str = Field(default_factory=lambda: f"audit_{uuid.uuid4().hex[:12]}")
    title: str
    description: str
    severity: AuditSeverity
    category: AuditCategory
    affected_component: str = ""
    evidence: str = ""
    recommendation: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    compliance_refs: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    cvss_score: float | None = None
    status: str = "open"  # open, in_progress, resolved, accepted_risk
    created_at: datetime = Field(default_factory=utc_now)
    resolved_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditCheck(BaseModel):
    """Individual audit check."""

    check_id: str
    name: str
    description: str
    category: AuditCategory
    severity: AuditSeverity
    check_function: str  # Name of check function
    enabled: bool = True
    compliance_mappings: dict[str, list[str]] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Security audit report."""

    report_id: str = Field(default_factory=lambda: f"audrpt_{uuid.uuid4().hex[:12]}")
    title: str = "Security Audit Report"
    scope: str = ""
    findings: list[AuditFinding] = Field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0
    checks_skipped: int = 0
    overall_score: float = 0.0  # 0-100
    risk_rating: str = "unknown"
    compliance_status: dict[str, dict[str, Any]] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    auditor: str = "automated"


class SecurityAuditor:
    """Performs security audits on the platform."""

    def __init__(self):
        self._checks: list[AuditCheck] = []
        self._findings: list[AuditFinding] = []
        self._reports: list[AuditReport] = []
        self._load_default_checks()

    def _load_default_checks(self) -> None:
        """Load default security checks."""
        default_checks = [
            AuditCheck(
                check_id="AUTH001",
                name="Password Policy",
                description="Verify password complexity requirements",
                category=AuditCategory.AUTHENTICATION,
                severity=AuditSeverity.HIGH,
                check_function="check_password_policy",
                compliance_mappings={
                    "nist_csf": ["PR.AC-1"],
                    "soc2": ["CC6.1"],
                    "pci_dss": ["8.2.3"],
                },
            ),
            AuditCheck(
                check_id="AUTH002",
                name="MFA Enforcement",
                description="Check multi-factor authentication is required",
                category=AuditCategory.AUTHENTICATION,
                severity=AuditSeverity.HIGH,
                check_function="check_mfa_enforcement",
                compliance_mappings={
                    "nist_csf": ["PR.AC-7"],
                    "soc2": ["CC6.1"],
                },
            ),
            AuditCheck(
                check_id="AUTH003",
                name="Session Management",
                description="Verify secure session handling",
                category=AuditCategory.AUTHENTICATION,
                severity=AuditSeverity.MEDIUM,
                check_function="check_session_management",
            ),
            AuditCheck(
                check_id="AUTHZ001",
                name="Role-Based Access Control",
                description="Verify RBAC implementation",
                category=AuditCategory.AUTHORIZATION,
                severity=AuditSeverity.HIGH,
                check_function="check_rbac",
                compliance_mappings={
                    "nist_csf": ["PR.AC-4"],
                    "soc2": ["CC6.3"],
                },
            ),
            AuditCheck(
                check_id="INPUT001",
                name="SQL Injection Prevention",
                description="Check for SQL injection vulnerabilities",
                category=AuditCategory.INPUT_VALIDATION,
                severity=AuditSeverity.CRITICAL,
                check_function="check_sql_injection",
                compliance_mappings={
                    "pci_dss": ["6.5.1"],
                },
            ),
            AuditCheck(
                check_id="INPUT002",
                name="XSS Prevention",
                description="Check for cross-site scripting vulnerabilities",
                category=AuditCategory.INPUT_VALIDATION,
                severity=AuditSeverity.HIGH,
                check_function="check_xss",
                compliance_mappings={
                    "pci_dss": ["6.5.7"],
                },
            ),
            AuditCheck(
                check_id="DATA001",
                name="Encryption at Rest",
                description="Verify sensitive data encryption",
                category=AuditCategory.DATA_PROTECTION,
                severity=AuditSeverity.HIGH,
                check_function="check_encryption_at_rest",
                compliance_mappings={
                    "pci_dss": ["3.4"],
                    "hipaa": ["164.312(a)(2)(iv)"],
                },
            ),
            AuditCheck(
                check_id="DATA002",
                name="Encryption in Transit",
                description="Verify TLS/SSL configuration",
                category=AuditCategory.DATA_PROTECTION,
                severity=AuditSeverity.HIGH,
                check_function="check_encryption_in_transit",
                compliance_mappings={
                    "pci_dss": ["4.1"],
                },
            ),
            AuditCheck(
                check_id="LOG001",
                name="Audit Logging",
                description="Verify comprehensive audit logging",
                category=AuditCategory.LOGGING,
                severity=AuditSeverity.MEDIUM,
                check_function="check_audit_logging",
                compliance_mappings={
                    "nist_csf": ["DE.AE-3"],
                    "soc2": ["CC7.2"],
                },
            ),
            AuditCheck(
                check_id="LOG002",
                name="Log Integrity",
                description="Verify log tampering protection",
                category=AuditCategory.LOGGING,
                severity=AuditSeverity.MEDIUM,
                check_function="check_log_integrity",
            ),
            AuditCheck(
                check_id="CFG001",
                name="Secure Defaults",
                description="Check for secure default configurations",
                category=AuditCategory.CONFIGURATION,
                severity=AuditSeverity.MEDIUM,
                check_function="check_secure_defaults",
            ),
            AuditCheck(
                check_id="CFG002",
                name="Debug Mode Disabled",
                description="Verify debug mode is disabled in production",
                category=AuditCategory.CONFIGURATION,
                severity=AuditSeverity.HIGH,
                check_function="check_debug_disabled",
            ),
            AuditCheck(
                check_id="DEP001",
                name="Dependency Vulnerabilities",
                description="Check for known vulnerable dependencies",
                category=AuditCategory.DEPENDENCY,
                severity=AuditSeverity.HIGH,
                check_function="check_dependency_vulnerabilities",
            ),
            AuditCheck(
                check_id="SEC001",
                name="Hardcoded Secrets",
                description="Check for hardcoded secrets in code",
                category=AuditCategory.SECRETS,
                severity=AuditSeverity.CRITICAL,
                check_function="check_hardcoded_secrets",
            ),
            AuditCheck(
                check_id="SEC002",
                name="Secret Management",
                description="Verify proper secret management practices",
                category=AuditCategory.SECRETS,
                severity=AuditSeverity.HIGH,
                check_function="check_secret_management",
            ),
        ]
        self._checks = default_checks

    def run_audit(self, scope: str = "full") -> AuditReport:
        """Run security audit."""
        report = AuditReport(scope=scope)

        enabled_checks = [c for c in self._checks if c.enabled]

        for check in enabled_checks:
            try:
                # Run check (simulated)
                finding = self._run_check(check)
                if finding:
                    report.findings.append(finding)
                    report.checks_failed += 1
                else:
                    report.checks_passed += 1
            except Exception as e:
                report.checks_skipped += 1
                report.findings.append(
                    AuditFinding(
                        title=f"Check failed: {check.name}",
                        description=str(e),
                        severity=AuditSeverity.INFO,
                        category=check.category,
                    )
                )

        # Calculate score
        total_checks = report.checks_passed + report.checks_failed
        if total_checks > 0:
            report.overall_score = (report.checks_passed / total_checks) * 100

        # Determine risk rating
        critical_count = len([f for f in report.findings if f.severity == AuditSeverity.CRITICAL])
        high_count = len([f for f in report.findings if f.severity == AuditSeverity.HIGH])

        if critical_count > 0:
            report.risk_rating = "critical"
        elif high_count > 2:
            report.risk_rating = "high"
        elif high_count > 0 or report.overall_score < 70:
            report.risk_rating = "medium"
        elif report.overall_score < 90:
            report.risk_rating = "low"
        else:
            report.risk_rating = "minimal"

        # Generate compliance status
        report.compliance_status = self._generate_compliance_status(report.findings)

        report.completed_at = utc_now()
        self._reports.append(report)
        self._findings.extend(report.findings)

        return report

    def _run_check(self, check: AuditCheck) -> AuditFinding | None:
        """Run individual security check (simulated)."""
        # In production, these would be actual security checks
        # For now, simulate with some checks passing and some failing

        # Simulate checks - most pass
        check_hash = int(hashlib.md5(check.check_id.encode()).hexdigest(), 16)  # noqa: S324
        if check_hash % 5 == 0:  # ~20% fail rate for simulation
            return AuditFinding(
                title=f"Failed: {check.name}",
                description=check.description,
                severity=check.severity,
                category=check.category,
                recommendation=f"Review and remediate {check.name.lower()} issues",
                compliance_refs=[
                    f"{fw}:{ctrl}"
                    for fw, ctrls in check.compliance_mappings.items()
                    for ctrl in ctrls
                ],
            )
        return None

    def _generate_compliance_status(
        self, findings: list[AuditFinding]
    ) -> dict[str, dict[str, Any]]:
        """Generate compliance status from findings."""
        status: dict[str, dict[str, Any]] = {}

        for framework in ComplianceFramework:
            fw_name = framework.value
            status[fw_name] = {
                "controls_checked": 0,
                "controls_passed": 0,
                "controls_failed": 0,
                "compliance_pct": 0.0,
            }

        # Count compliance violations
        for finding in findings:
            for ref in finding.compliance_refs:
                if ":" in ref:
                    fw, _ = ref.split(":", 1)
                    if fw in status:
                        status[fw]["controls_failed"] += 1

        # Calculate compliance percentage (simplified)
        for fw in status:
            failed = status[fw]["controls_failed"]
            # Assume 10 controls per framework for simulation
            total = max(10, failed)
            passed = total - failed
            status[fw]["controls_checked"] = total
            status[fw]["controls_passed"] = passed
            status[fw]["compliance_pct"] = (passed / total) * 100 if total > 0 else 100

        return status

    def check_secrets_in_code(self, code: str) -> list[AuditFinding]:
        """Check for hardcoded secrets in code."""
        findings = []

        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
            (r'token\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']', "Hardcoded token"),
            (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "Private key in code"),
        ]

        for pattern, description in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                findings.append(
                    AuditFinding(
                        title=description,
                        description=f"Found {len(matches)} instance(s) of {description.lower()}",
                        severity=AuditSeverity.CRITICAL,
                        category=AuditCategory.SECRETS,
                        recommendation="Use environment variables or a secrets manager",
                        cwe_id="CWE-798",
                    )
                )

        return findings

    def check_sql_injection_patterns(self, code: str) -> list[AuditFinding]:
        """Check for SQL injection vulnerabilities."""
        findings = []

        # Patterns that might indicate SQL injection vulnerability
        patterns = [
            (r'execute\([^)]*\%s', "String formatting in SQL execute"),
            (r'f"SELECT.*{', "F-string in SQL query"),
            (r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', "Format string in SQL"),
            (r'\+\s*(?:request|user_input|data)', "String concatenation with user input"),
        ]

        for pattern, description in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(
                    AuditFinding(
                        title="Potential SQL Injection",
                        description=description,
                        severity=AuditSeverity.CRITICAL,
                        category=AuditCategory.INPUT_VALIDATION,
                        recommendation="Use parameterized queries",
                        cwe_id="CWE-89",
                    )
                )

        return findings

    def get_finding(self, finding_id: str) -> AuditFinding | None:
        """Get finding by ID."""
        for f in self._findings:
            if f.finding_id == finding_id:
                return f
        return None

    def resolve_finding(
        self, finding_id: str, resolution_notes: str = ""
    ) -> AuditFinding | None:
        """Mark finding as resolved."""
        finding = self.get_finding(finding_id)
        if finding:
            finding.status = "resolved"
            finding.resolved_at = utc_now()
            if resolution_notes:
                finding.metadata["resolution_notes"] = resolution_notes
        return finding

    def get_reports(self) -> list[AuditReport]:
        """Get all audit reports."""
        return self._reports

    def get_findings_by_severity(
        self, severity: AuditSeverity
    ) -> list[AuditFinding]:
        """Get findings filtered by severity."""
        return [f for f in self._findings if f.severity == severity]

    def get_metrics(self) -> dict[str, Any]:
        """Get audit metrics."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for f in self._findings:
            sev = f.severity.value
            cat = f.category.value
            stat = f.status
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
            by_status[stat] = by_status.get(stat, 0) + 1

        return {
            "total_checks": len(self._checks),
            "total_findings": len(self._findings),
            "total_reports": len(self._reports),
            "findings_by_severity": by_severity,
            "findings_by_category": by_category,
            "findings_by_status": by_status,
            "open_findings": by_status.get("open", 0),
        }


# Singleton
_auditor: SecurityAuditor | None = None


def get_security_auditor() -> SecurityAuditor:
    """Get security auditor singleton."""
    global _auditor
    if _auditor is None:
        _auditor = SecurityAuditor()
    return _auditor
