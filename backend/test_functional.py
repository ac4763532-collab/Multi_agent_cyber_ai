"""Functional tests for detection engines and specialized agents."""

import uuid
from datetime import UTC, datetime

import pytest

from backend.app.agents.models import AgentTask, AgentType, TaskPriority
from backend.app.agents.registry import AgentRegistry
from backend.app.agents.specialized.email_verification import (
    EmailVerificationAgent,
)
from backend.app.agents.specialized.log_analyzer import LogAnalyzerAgent
from backend.app.detection.rules.ioc_engine import IoCEngine, IoCStore
from backend.app.detection.rules.regex_engine import RegexEngine
from backend.app.detection.rules.sigma_engine import SigmaEngine
from backend.app.schemas.events import EventSeverity, SecurityEvent

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------


def make_security_event(
    *,
    source: str,
    source_type: str,
    event_type: str,
    severity: EventSeverity,
    raw_data: dict,
    normalized_data: dict,
    **kwargs,
) -> SecurityEvent:
    """Create a valid SecurityEvent for functional testing."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        source=source,
        source_type=source_type,
        event_type=event_type,
        severity=severity,
        raw_data=raw_data,
        normalized_data=normalized_data,
        **kwargs,
    )


def make_email_task() -> AgentTask:
    """Create a suspicious email verification task."""
    return AgentTask(
        task_id=str(uuid.uuid4()),
        event_id=str(uuid.uuid4()),
        agent_type=AgentType.EMAIL_VERIFICATION,
        priority=TaskPriority.HIGH,
        payload={
            "email": {
                "from": "security@bank-secure-login.xyz",
                "to": "user@company.com",
                "subject": ("URGENT: Your account has been compromised! Act now!"),
                "body": (
                    "Dear Customer, Your account security is at risk. "
                    "Click here immediately: "
                    "http://bank-secure-login.xyz/verify?token=abc123 "
                    "to verify your identity. Failure to act within "
                    "24 hours will result in account suspension."
                ),
                "headers": {
                    "Reply-To": "support@different-domain.com",
                    "X-Mailer": "PHPMailer",
                },
            }
        },
    )


def make_log_task() -> AgentTask:
    """Create a brute-force authentication log task."""
    log_events = []

    for _ in range(6):
        log_events.append(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "source_ip": "10.0.0.50",
                "event_type": "authentication",
                "status": "failed",
                "username": "admin",
                "message": ("Failed password for admin from 10.0.0.50"),
            }
        )

    return AgentTask(
        task_id=str(uuid.uuid4()),
        event_id=str(uuid.uuid4()),
        agent_type=AgentType.LOG_ANALYZER,
        priority=TaskPriority.MEDIUM,
        payload={
            "events": log_events,
        },
    )


# -----------------------------------------------------------------------------
# DETECTION ENGINE TESTS
# -----------------------------------------------------------------------------


def test_regex_engine_loads_builtin_rules():
    """Regex engine should load builtin detection rules."""
    engine = RegexEngine(load_builtin=True)

    assert engine.rule_count > 0


def test_regex_engine_detects_or_sql_injection():
    """Regex engine should detect OR-based SQL injection."""
    engine = RegexEngine(load_builtin=True)

    event = make_security_event(
        source="test",
        source_type="network_ids",
        event_type="http_request",
        severity=EventSeverity.HIGH,
        raw_data={
            "method": "GET",
            "url": "/search?q=1' OR '1'='1",
            "raw_string": "GET /search?q=1' OR '1'='1 HTTP/1.1",
        },
        normalized_data={
            "event.category": "web",
            "event.type": "http_request",
            "http.request.method": "GET",
            "url.original": "/search?q=1' OR '1'='1",
        },
        url="/search?q=1' OR '1'='1",
    )

    matches = engine.evaluate(event)

    assert matches, "OR-based SQL injection was not detected"


def test_regex_engine_detects_union_sql_injection():
    """Regex engine should detect UNION SELECT SQL injection."""
    engine = RegexEngine(load_builtin=True)

    event = make_security_event(
        source="test",
        source_type="network_ids",
        event_type="http_request",
        severity=EventSeverity.HIGH,
        raw_data={
            "method": "GET",
            "url": ("/api?id=1 UNION SELECT username,password FROM users--"),
            "raw_string": ("GET /api?id=1 UNION SELECT username,password FROM users-- HTTP/1.1"),
        },
        normalized_data={
            "event.category": "web",
            "event.type": "http_request",
            "http.request.method": "GET",
            "url.original": ("/api?id=1 UNION SELECT username,password FROM users--"),
        },
        url=("/api?id=1 UNION SELECT username,password FROM users--"),
    )

    matches = engine.evaluate(event)

    assert matches, "UNION SELECT SQL injection was not detected"


def test_ioc_store_loads_indicators():
    """IoC store should load IP, domain, and hash indicators."""
    store = IoCStore()
    store.load()

    assert len(store._ips) > 0
    assert len(store._domains) > 0
    assert len(store._hashes) > 0


def test_ioc_engine_detects_malicious_ip():
    """IoC engine should detect a known malicious IP."""
    engine = IoCEngine()

    event = make_security_event(
        source="test",
        source_type="firewall",
        event_type="connection",
        severity=EventSeverity.HIGH,
        raw_data={
            "message": ("Connection from 203.0.113.100 to internal server"),
            "source_ip": "203.0.113.100",
        },
        normalized_data={
            "event.category": "network",
            "event.type": "connection",
            "source.ip": "203.0.113.100",
        },
        source_ip="203.0.113.100",
    )

    matches = engine.evaluate(event)

    assert matches, "Malicious IP 203.0.113.100 was not detected"

    assert any(match.matched_value == "203.0.113.100" for match in matches)


def test_sigma_engine_initializes():
    """Sigma engine should initialize successfully."""
    engine = SigmaEngine()

    assert engine is not None


# -----------------------------------------------------------------------------
# EMAIL AGENT TEST
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_email_verification_agent():
    """Email verification agent should process a suspicious email."""
    agent = EmailVerificationAgent()
    task = make_email_task()

    result = await agent.execute(task)

    assert result.status.value == "success", (
        f"EmailVerificationAgent failed with status {result.status.value}"
    )

    assert result.finding is not None, "EmailVerificationAgent produced no finding"


# -----------------------------------------------------------------------------
# LOG ANALYZER TEST
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_analyzer_agent():
    """Log analyzer should detect brute-force authentication activity."""
    agent = LogAnalyzerAgent()
    task = make_log_task()

    result = await agent.execute(task)

    assert result.status.value == "success", (
        f"LogAnalyzerAgent failed with status {result.status.value}"
    )

    assert result.finding is not None, "LogAnalyzerAgent produced no finding"

    assert result.finding.detection_type.value == "brute_force"


# -----------------------------------------------------------------------------
# AGENT REGISTRY TEST
# -----------------------------------------------------------------------------


def test_agent_registry_registers_agents():
    """Agent registry should register both specialized agents."""
    registry = AgentRegistry()

    email_agent = EmailVerificationAgent()
    log_agent = LogAnalyzerAgent()

    registry.register(email_agent)
    registry.register(log_agent)

    registered_agents = registry.list_agents()

    assert len(registered_agents) == 2
    assert email_agent in registry.get_by_type(AgentType.EMAIL_VERIFICATION)
    assert log_agent in registry.get_by_type(AgentType.LOG_ANALYZER)
