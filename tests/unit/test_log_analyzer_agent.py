"""Unit tests for LogAnalyzerAgent."""

from datetime import datetime, timezone

import pytest

from backend.app.agents.models import AgentTask, AgentType, ResultStatus
from backend.app.agents.specialized.log_analyzer import (
    AnomalySignal,
    DetectionType,
    LogAnalyzerAgent,
    LogAnalyzerConfig,
    LogFinding,
)


class TestLogAnalyzerConfig:
    """Tests for LogAnalyzerConfig."""

    def test_default_config(self):
        """Default configuration values."""
        config = LogAnalyzerConfig()
        assert config.brute_force_threshold == 5
        assert config.brute_force_window_sec == 60
        assert config.rate_limit_threshold == 100
        assert config.business_hours_start == 8
        assert config.business_hours_end == 18
        assert config.anomaly_zscore_threshold == 3.0

    def test_custom_config(self):
        """Custom configuration values."""
        config = LogAnalyzerConfig(
            brute_force_threshold=10,
            brute_force_window_sec=120,
            rate_limit_threshold=200,
        )
        assert config.brute_force_threshold == 10
        assert config.brute_force_window_sec == 120
        assert config.rate_limit_threshold == 200


class TestLogAnalyzerAgent:
    """Tests for LogAnalyzerAgent."""

    @pytest.fixture
    def agent(self):
        """Create log analyzer agent."""
        return LogAnalyzerAgent()

    @pytest.fixture
    def agent_low_threshold(self):
        """Create agent with low thresholds for testing."""
        config = LogAnalyzerConfig(
            brute_force_threshold=3,
            brute_force_window_sec=300,
            rate_limit_threshold=10,  # Minimum allowed value
        )
        return LogAnalyzerAgent(config=config)

    def test_agent_properties(self, agent):
        """Agent has correct properties."""
        assert agent.agent_id == "log_analyzer_001"
        assert agent.name == "Log Analyzer Agent"
        assert agent.agent_type == AgentType.LOG_ANALYZER
        assert "brute_force_detection" in agent.capabilities
        assert "anomaly_detection" in agent.capabilities

    @pytest.mark.asyncio
    async def test_validate_task_with_event(self, agent):
        """Task with event data validates."""
        task = AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.LOG_ANALYZER,
            payload={"event": {"source_ip": "192.168.1.1"}},
        )
        assert await agent.validate_task(task) is True

    @pytest.mark.asyncio
    async def test_validate_task_with_log(self, agent):
        """Task with log data validates."""
        task = AgentTask(
            task_id="task_002",
            event_id="evt_002",
            agent_type=AgentType.LOG_ANALYZER,
            payload={"log": "Failed password for user admin"},
        )
        assert await agent.validate_task(task) is True

    @pytest.mark.asyncio
    async def test_validate_task_empty(self, agent):
        """Task without data fails validation."""
        task = AgentTask(
            task_id="task_003",
            event_id="evt_003",
            agent_type=AgentType.LOG_ANALYZER,
            payload={},
        )
        assert await agent.validate_task(task) is False

    @pytest.mark.asyncio
    async def test_detect_brute_force_from_event_type(self, agent_low_threshold):
        """Detects brute force from event type."""
        # Send multiple failed auth events from same IP
        for i in range(3):
            task = AgentTask(
                task_id=f"task_bf_{i}",
                event_id=f"evt_bf_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_bf_{i}",
                        "event_type": "auth_failed",
                        "source_ip": "10.0.0.100",
                        "username": "admin",
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        # Last event should trigger brute force detection
        assert result.finding is not None
        finding = result.finding
        assert finding.detection_type == DetectionType.BRUTE_FORCE

    @pytest.mark.asyncio
    async def test_detect_brute_force_from_log_message(self, agent_low_threshold):
        """Detects brute force from log messages."""
        for i in range(3):
            task = AgentTask(
                task_id=f"task_log_{i}",
                event_id=f"evt_log_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_log_{i}",
                        "source_ip": "10.0.0.200",
                        "raw_data": {
                            "message": "Failed password for invalid user test from 10.0.0.200"
                        },
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.BRUTE_FORCE

    @pytest.mark.asyncio
    async def test_detect_windows_auth_failure(self, agent_low_threshold):
        """Detects Windows auth failures by Event ID."""
        for i in range(3):
            task = AgentTask(
                task_id=f"task_win_{i}",
                event_id=f"evt_win_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_win_{i}",
                        "source_ip": "10.0.0.150",
                        "raw_data": {
                            "EventID": "4625",
                            "message": "An account failed to log on",
                        },
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.BRUTE_FORCE

    @pytest.mark.asyncio
    async def test_detect_privilege_escalation(self, agent):
        """Detects privilege escalation."""
        task = AgentTask(
            task_id="task_priv_001",
            event_id="evt_priv_001",
            agent_type=AgentType.LOG_ANALYZER,
            payload={
                "event": {
                    "event_id": "evt_priv_001",
                    "event_type": "sudo_command",
                    "raw_data": {
                        "message": "sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
                    },
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.PRIVILEGE_ESCALATION

    @pytest.mark.asyncio
    async def test_detect_windows_privilege_escalation(self, agent):
        """Detects Windows privilege escalation events."""
        task = AgentTask(
            task_id="task_win_priv",
            event_id="evt_win_priv",
            agent_type=AgentType.LOG_ANALYZER,
            payload={
                "event": {
                    "event_id": "evt_win_priv",
                    "raw_data": {
                        "EventID": "4672",
                        "message": "Special privileges assigned to new logon",
                    },
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.PRIVILEGE_ESCALATION

    @pytest.mark.asyncio
    async def test_detect_rate_limit(self, agent_low_threshold):
        """Detects rate limit violations."""
        # Need 10 events to exceed threshold (rate_limit_threshold=10)
        for i in range(10):
            task = AgentTask(
                task_id=f"task_rate_{i}",
                event_id=f"evt_rate_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_rate_{i}",
                        "source_ip": "10.0.0.50",
                        "event_type": "http_request",
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.SUSPICIOUS_RATE

    @pytest.mark.asyncio
    async def test_detect_off_hours_activity(self, agent):
        """Detects off-hours authentication."""
        # Create timestamp at 3 AM
        off_hours_time = datetime.now(timezone.utc).replace(hour=3, minute=0)

        task = AgentTask(
            task_id="task_offhours",
            event_id="evt_offhours",
            agent_type=AgentType.LOG_ANALYZER,
            payload={
                "event": {
                    "event_id": "evt_offhours",
                    "event_type": "authentication",
                    "timestamp": off_hours_time.isoformat(),
                    "source_ip": "192.168.1.50",
                }
            },
        )
        result = await agent.process_task(task)

        assert result.finding is not None
        assert result.finding.detection_type == DetectionType.OFF_HOURS_ACTIVITY

    @pytest.mark.asyncio
    async def test_no_detection_normal_activity(self, agent):
        """Normal activity produces no critical findings."""
        task = AgentTask(
            task_id="task_normal",
            event_id="evt_normal",
            agent_type=AgentType.LOG_ANALYZER,
            payload={
                "event": {
                    "event_id": "evt_normal",
                    "event_type": "file_access",
                    "source_ip": "192.168.1.10",
                }
            },
        )
        result = await agent.process_task(task)

        # Should complete but without critical detection
        assert result.status in [ResultStatus.SUCCESS, ResultStatus.PARTIAL]

    @pytest.mark.asyncio
    async def test_mitre_mapping_brute_force(self, agent_low_threshold):
        """Brute force findings include MITRE mapping."""
        for i in range(3):
            task = AgentTask(
                task_id=f"task_mitre_{i}",
                event_id=f"evt_mitre_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_mitre_{i}",
                        "event_type": "auth_failed",
                        "source_ip": "10.0.0.99",
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        assert result.finding is not None
        assert "T1110" in result.finding.mitre_techniques

    @pytest.mark.asyncio
    async def test_threshold_exceeded_details(self, agent_low_threshold):
        """Finding includes threshold details."""
        for i in range(3):
            task = AgentTask(
                task_id=f"task_thresh_{i}",
                event_id=f"evt_thresh_{i}",
                agent_type=AgentType.LOG_ANALYZER,
                payload={
                    "event": {
                        "event_id": f"evt_thresh_{i}",
                        "event_type": "auth_failed",
                        "source_ip": "10.0.0.77",
                    }
                },
            )
            result = await agent_low_threshold.process_task(task)

        assert result.finding is not None
        assert "threshold" in result.finding.threshold_exceeded
        assert "actual" in result.finding.threshold_exceeded

    @pytest.mark.asyncio
    async def test_process_multiple_events(self, agent):
        """Process batch of events."""
        task = AgentTask(
            task_id="task_batch",
            event_id="evt_batch",
            agent_type=AgentType.LOG_ANALYZER,
            payload={
                "events": [
                    {
                        "event_id": "evt_1",
                        "event_type": "auth_failed",
                        "source_ip": "1.1.1.1",
                    },
                    {
                        "event_id": "evt_2",
                        "event_type": "file_access",
                        "source_ip": "1.1.1.2",
                    },
                    {
                        "event_id": "evt_3",
                        "event_type": "process_start",
                        "source_ip": "1.1.1.3",
                    },
                ]
            },
        )
        result = await agent.process_task(task)

        assert result.status in [ResultStatus.SUCCESS, ResultStatus.PARTIAL]
        assert result.metadata.get("events_analyzed") == 3


class TestAnomalySignal:
    """Tests for AnomalySignal model."""

    def test_create_anomaly_signal(self):
        """Create anomaly signal."""
        signal = AnomalySignal(
            anomaly_score=0.85,
            features={"request_rate": 150.0},
            baseline={"request_rate": 10.0},
            model_version="1.0.0",
            is_anomaly=True,
        )
        assert signal.anomaly_score == 0.85
        assert signal.is_anomaly is True

    def test_anomaly_signal_below_threshold(self):
        """Signal below threshold is not anomaly."""
        signal = AnomalySignal(
            anomaly_score=0.2,
            features={"request_rate": 15.0},
            baseline={"request_rate": 10.0},
            model_version="1.0.0",
            is_anomaly=False,
        )
        assert signal.is_anomaly is False


class TestLogFinding:
    """Tests for LogFinding model."""

    def test_create_log_finding(self):
        """Create log finding."""
        finding = LogFinding(
            finding_id="log_001",
            finding_type="brute_force",
            event_id="evt_001",
            task_id="task_001",
            agent_id="log_analyzer_001",
            detection_type=DetectionType.BRUTE_FORCE,
            matching_events=["evt_1", "evt_2", "evt_3"],
            source="192.168.1.100",
            rule_id="brute_force_detector",
        )
        assert finding.detection_type == DetectionType.BRUTE_FORCE
        assert len(finding.matching_events) == 3

    def test_finding_with_anomaly(self):
        """Finding with anomaly signal."""
        anomaly = AnomalySignal(
            anomaly_score=0.9,
            features={"rate": 100.0},
            baseline={"rate": 5.0},
            model_version="1.0.0",
            is_anomaly=True,
        )
        finding = LogFinding(
            finding_id="log_002",
            finding_type="anomaly",
            event_id="evt_002",
            task_id="task_002",
            agent_id="log_analyzer_001",
            detection_type=DetectionType.ANOMALY,
            anomaly_signal=anomaly,
        )
        assert finding.anomaly_signal is not None
        assert finding.anomaly_signal.is_anomaly is True


class TestDetectionType:
    """Tests for DetectionType enum."""

    def test_all_detection_types(self):
        """All detection types are defined."""
        expected = {
            "brute_force",
            "impossible_travel",
            "privilege_escalation",
            "repeated_access",
            "suspicious_rate",
            "off_hours_activity",
            "anomaly",
            "pattern_match",
        }
        actual = {d.value for d in DetectionType}
        assert actual == expected
