"""Unit tests for agent models."""

import pytest
from datetime import datetime, timezone

from backend.app.agents.models import (
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentType,
    BaseFinding,
    ExecutionRecord,
    ExecutionStatus,
    ResultStatus,
    TaskPriority,
    TaskStatus,
)
from backend.app.schemas.events import EventSeverity


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_all_statuses_defined(self):
        """Verify all expected statuses exist."""
        expected = {"queued", "validating", "running", "completed", "failed", "retrying", "dead_letter"}
        actual = {s.value for s in TaskStatus}
        assert actual == expected

    def test_status_values(self):
        """Test individual status values."""
        assert TaskStatus.QUEUED == "queued"
        assert TaskStatus.RUNNING == "running"
        assert TaskStatus.COMPLETED == "completed"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.DEAD_LETTER == "dead_letter"


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_all_priorities_defined(self):
        """Verify all expected priorities exist."""
        expected = {"critical", "high", "medium", "low"}
        actual = {p.value for p in TaskPriority}
        assert actual == expected

    def test_from_severity_critical(self):
        """Critical severity maps to critical priority."""
        assert TaskPriority.from_severity(EventSeverity.CRITICAL) == TaskPriority.CRITICAL

    def test_from_severity_high(self):
        """High severity maps to high priority."""
        assert TaskPriority.from_severity(EventSeverity.HIGH) == TaskPriority.HIGH

    def test_from_severity_medium(self):
        """Medium severity maps to medium priority."""
        assert TaskPriority.from_severity(EventSeverity.MEDIUM) == TaskPriority.MEDIUM

    def test_from_severity_low(self):
        """Low severity maps to low priority."""
        assert TaskPriority.from_severity(EventSeverity.LOW) == TaskPriority.LOW

    def test_from_severity_informational(self):
        """Informational severity maps to low priority."""
        assert TaskPriority.from_severity(EventSeverity.INFORMATIONAL) == TaskPriority.LOW


class TestAgentType:
    """Tests for AgentType enum."""

    def test_all_agent_types_defined(self):
        """Verify all 12 agent types exist."""
        expected = {
            "task_dispatcher",
            "email_verification",
            "log_analyzer",
            "network_threat",
            "ip_range_analyzer",
            "vulnerability",
            "threat_intelligence",
            "correlation",
            "investigation",
            "incident_prioritization",
            "response_recommendation",
            "report_generation",
        }
        actual = {t.value for t in AgentType}
        assert actual == expected

    def test_agent_count(self):
        """Ensure exactly 12 agents."""
        assert len(AgentType) == 12


class TestAgentTask:
    """Tests for AgentTask model."""

    def test_create_minimal_task(self):
        """Create task with minimal fields."""
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
        )
        assert task.task_id == "task_001"
        assert task.event_id == "evt_001"
        assert task.agent_type == AgentType.EMAIL_VERIFICATION
        assert task.status == TaskStatus.QUEUED
        assert task.priority == TaskPriority.MEDIUM
        assert task.retry_count == 0
        assert task.max_retries == 3

    def test_create_full_task(self):
        """Create task with all fields."""
        now = datetime.now(timezone.utc)
        task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.LOG_ANALYZER,
            priority=TaskPriority.HIGH,
            status=TaskStatus.RUNNING,
            created_at=now,
            started_at=now,
            retry_count=1,
            max_retries=5,
            payload={"key": "value"},
            metadata={"source": "test"},
        )
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.RUNNING
        assert task.retry_count == 1
        assert task.max_retries == 5
        assert task.payload == {"key": "value"}

    def test_task_serialization(self):
        """Task can be serialized and deserialized."""
        task = AgentTask(
            task_id="task_003",
            event_id="evt_003",
            agent_type=AgentType.NETWORK_THREAT,
        )
        data = task.model_dump()
        restored = AgentTask(**data)
        assert restored.task_id == task.task_id
        assert restored.agent_type == task.agent_type


class TestBaseFinding:
    """Tests for BaseFinding model."""

    def test_create_minimal_finding(self):
        """Create finding with minimal fields."""
        finding = BaseFinding(
            finding_id="find_001",
            finding_type="test",
            event_id="evt_001",
            task_id="task_001",
            agent_id="agent_001",
        )
        assert finding.finding_id == "find_001"
        assert finding.finding_type == "test"
        assert finding.severity == EventSeverity.MEDIUM

    def test_create_finding_with_severity(self):
        """Create finding with custom severity."""
        finding = BaseFinding(
            finding_id="find_002",
            finding_type="critical_test",
            event_id="evt_002",
            task_id="task_002",
            agent_id="agent_002",
            severity=EventSeverity.CRITICAL,
            explanation="Critical issue found",
            recommendations=["Fix immediately"],
        )
        assert finding.severity == EventSeverity.CRITICAL
        assert finding.explanation == "Critical issue found"
        assert "Fix immediately" in finding.recommendations


class TestAgentResult:
    """Tests for AgentResult model."""

    def test_create_success_result(self):
        """Create successful result."""
        now = datetime.now(timezone.utc)
        result = AgentResult(
            result_id="res_001",
            task_id="task_001",
            agent_id="agent_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            agent_version="1.0.0",
            status=ResultStatus.SUCCESS,
            start_time=now,
            end_time=now,
            processing_time_ms=100.5,
        )
        assert result.status == ResultStatus.SUCCESS
        assert result.finding is None
        assert result.errors == []

    def test_create_failed_result(self):
        """Create failed result with errors."""
        now = datetime.now(timezone.utc)
        result = AgentResult(
            result_id="res_002",
            task_id="task_002",
            agent_id="agent_002",
            agent_type=AgentType.LOG_ANALYZER,
            agent_version="1.0.0",
            status=ResultStatus.FAILED,
            start_time=now,
            end_time=now,
            processing_time_ms=50.0,
            errors=["Timeout", "Connection failed"],
        )
        assert result.status == ResultStatus.FAILED
        assert len(result.errors) == 2

    def test_result_with_finding(self):
        """Create result with attached finding."""
        now = datetime.now(timezone.utc)
        finding = BaseFinding(
            finding_id="find_003",
            finding_type="test",
            event_id="evt_003",
            task_id="task_003",
            agent_id="agent_003",
        )
        result = AgentResult(
            result_id="res_003",
            task_id="task_003",
            agent_id="agent_003",
            agent_type=AgentType.THREAT_INTELLIGENCE,
            agent_version="1.0.0",
            status=ResultStatus.SUCCESS,
            finding=finding,
            start_time=now,
            end_time=now,
            processing_time_ms=200.0,
        )
        assert result.finding is not None
        assert result.finding.finding_id == "find_003"


class TestExecutionRecord:
    """Tests for ExecutionRecord model."""

    def test_create_execution_record(self):
        """Create execution record."""
        now = datetime.now(timezone.utc)
        record = ExecutionRecord(
            execution_id="exec_001",
            agent_id="agent_001",
            agent_type=AgentType.EMAIL_VERIFICATION,
            agent_version="1.0.0",
            task_id="task_001",
            start_time=now,
            end_time=now,
            status=ExecutionStatus.COMPLETED,
        )
        assert record.execution_id == "exec_001"
        assert record.status == ExecutionStatus.COMPLETED
        assert record.errors == []

    def test_execution_record_with_errors(self):
        """Create execution record with errors."""
        now = datetime.now(timezone.utc)
        record = ExecutionRecord(
            execution_id="exec_002",
            agent_id="agent_002",
            agent_type=AgentType.LOG_ANALYZER,
            agent_version="1.0.0",
            task_id="task_002",
            start_time=now,
            end_time=now,
            status=ExecutionStatus.FAILED,
            errors=["Error 1", "Error 2"],
        )
        assert record.status == ExecutionStatus.FAILED
        assert len(record.errors) == 2


class TestAgentStatus:
    """Tests for AgentStatus enum."""

    def test_all_statuses(self):
        """Verify all agent statuses exist."""
        expected = {"idle", "processing", "error", "stopped"}
        actual = {s.value for s in AgentStatus}
        assert actual == expected


class TestResultStatus:
    """Tests for ResultStatus enum."""

    def test_all_statuses(self):
        """Verify all result statuses exist."""
        expected = {"success", "partial", "failed", "timeout"}
        actual = {s.value for s in ResultStatus}
        assert actual == expected
