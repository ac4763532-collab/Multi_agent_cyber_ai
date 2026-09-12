# Agent Development Guide

This guide explains how to develop new specialized agents for the Multi-Agent Cybersecurity AI Platform.

## Overview

The platform uses an abstract agent framework where each agent specializes in a specific security domain. All agents inherit from `BaseAgent` and follow a consistent lifecycle for task processing.

## Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       BaseAgent (ABC)                       │
├─────────────────────────────────────────────────────────────┤
│ Properties:                                                  │
│   - agent_id: str                                           │
│   - name: str                                                │
│   - agent_type: AgentType                                   │
│   - version: str                                             │
│   - capabilities: list[str]                                 │
│   - status: AgentStatus                                     │
├─────────────────────────────────────────────────────────────┤
│ Abstract Methods:                                            │
│   - validate_task(task) -> bool                             │
│   - process_task(task) -> AgentResult                       │
│   - create_finding(task, analysis) -> BaseFinding           │
├─────────────────────────────────────────────────────────────┤
│ Concrete Methods:                                            │
│   - handle_error(task, error) -> None                       │
│   - publish_result(result) -> None                          │
│   - get_health() -> HealthStatus                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              YourSpecializedAgent(BaseAgent)                │
└─────────────────────────────────────────────────────────────┘
```

## Task Lifecycle

```
  QUEUED → VALIDATING → RUNNING → COMPLETED
                │           │
                ▼           ▼
             FAILED    RETRYING → DEAD_LETTER
```

## Creating a New Agent

### Step 1: Define Agent Type

Add your agent type to the `AgentType` enum in `backend/app/agents/models.py`:

```python
class AgentType(StrEnum):
    # Existing agents...
    YOUR_NEW_AGENT = "your_new_agent"
```

### Step 2: Create Finding Model

Define your agent's finding model in `backend/app/agents/specialized/your_agent.py`:

```python
from pydantic import BaseModel, Field
from backend.app.agents.base import BaseFinding
from backend.app.schemas.events import EventSeverity, MatchConfidence

class YourFindingType(StrEnum):
    """Types of findings your agent produces."""
    TYPE_A = "type_a"
    TYPE_B = "type_b"

class YourFinding(BaseFinding):
    """Finding model for your agent."""
    
    finding_type: YourFindingType
    detection_details: dict[str, Any] = Field(default_factory=dict)
    indicators: list[str] = Field(default_factory=list)
    confidence: MatchConfidence = MatchConfidence.MEDIUM
    severity: EventSeverity = EventSeverity.MEDIUM
    risk_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
```

### Step 3: Implement the Agent

```python
from backend.app.agents.base import BaseAgent
from backend.app.agents.models import (
    AgentTask, AgentResult, AgentType, ResultStatus
)
from backend.app.utils.datetime import utc_now

class YourNewAgent(BaseAgent):
    """Your specialized security agent."""
    
    def __init__(self):
        super().__init__()
        self._tasks_processed = 0
        self._config = YourAgentConfig()
    
    @property
    def agent_id(self) -> str:
        return "your_agent_001"
    
    @property
    def name(self) -> str:
        return "Your New Agent"
    
    @property
    def agent_type(self) -> AgentType:
        return AgentType.YOUR_NEW_AGENT
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def capabilities(self) -> list[str]:
        return [
            "capability_one",
            "capability_two",
            "capability_three",
        ]
    
    async def validate_task(self, task: AgentTask) -> bool:
        """Validate that task has required data."""
        payload = task.payload or {}
        
        # Check for required fields
        required_fields = ["data_field_1", "data_field_2"]
        for field in required_fields:
            if field not in payload:
                return False
        
        return True
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process the task and generate findings."""
        start_time = utc_now()
        
        try:
            # Extract data from task
            payload = task.payload or {}
            data = payload.get("data_field_1")
            
            # Perform analysis
            analysis = await self._analyze(data)
            
            # Create finding if detection
            finding = None
            if analysis.get("detected"):
                finding = self.create_finding(task, analysis)
            
            # Build result
            end_time = utc_now()
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_version=self.version,
                status=ResultStatus.SUCCESS,
                finding=finding,
                start_time=start_time,
                end_time=end_time,
                processing_time_ms=(end_time - start_time).total_seconds() * 1000,
            )
            
        except Exception as e:
            end_time = utc_now()
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                agent_version=self.version,
                status=ResultStatus.FAILED,
                start_time=start_time,
                end_time=end_time,
                errors=[str(e)],
            )
    
    def create_finding(self, task: AgentTask, analysis: dict) -> YourFinding:
        """Create a finding from analysis results."""
        return YourFinding(
            finding_id=f"finding_{task.task_id}",
            event_id=task.event_id,
            agent_id=self.agent_id,
            finding_type=YourFindingType.TYPE_A,
            detection_details=analysis,
            confidence=MatchConfidence.HIGH,
            severity=EventSeverity.MEDIUM,
            risk_score=analysis.get("risk_score", 0.5),
            recommendations=self._generate_recommendations(analysis),
        )
    
    async def _analyze(self, data: Any) -> dict:
        """Perform your specialized analysis."""
        # Your detection logic here
        result = {
            "detected": False,
            "indicators": [],
            "risk_score": 0.0,
        }
        
        # Example detection logic
        if self._check_condition(data):
            result["detected"] = True
            result["indicators"].append("suspicious_indicator")
            result["risk_score"] = 0.75
        
        return result
    
    def _check_condition(self, data: Any) -> bool:
        """Check your detection conditions."""
        # Implement your detection logic
        return False
    
    def _generate_recommendations(self, analysis: dict) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if analysis.get("risk_score", 0) > 0.7:
            recommendations.append("Immediate investigation recommended")
        
        return recommendations
```

### Step 4: Register the Agent

Add your agent to the registry in `backend/app/agents/registry.py`:

```python
from backend.app.agents.specialized.your_agent import YourNewAgent

# In AgentRegistry.__init__ or initialization
def _register_default_agents(self):
    # ... existing agents ...
    self.register(YourNewAgent())
```

### Step 5: Add Routing Rules

Update the task router in `backend/app/agents/dispatcher/router.py`:

```python
# Add routing rule for your agent
RoutingRule(
    name="your_agent_rule",
    description="Route events to YourNewAgent",
    source_types=["your_source"],
    event_types=["your_event_type"],
    agent_type=AgentType.YOUR_NEW_AGENT,
    priority=50,
)
```

## Agent Best Practices

### 1. Deterministic Detection

Use clear, deterministic rules rather than relying on ambiguous heuristics:

```python
# Good: Clear, testable rule
def detect_brute_force(events: list[Event]) -> bool:
    failed_logins = [e for e in events if e.event_type == "login_failed"]
    return len(failed_logins) >= self.config.threshold

# Avoid: Vague heuristic
def detect_suspicious(events: list[Event]) -> bool:
    return some_magic_score(events) > 0.5  # Hard to test/debug
```

### 2. Confidence Scoring

Provide meaningful confidence scores:

```python
def calculate_confidence(indicators: list[str]) -> MatchConfidence:
    """Calculate confidence based on evidence strength."""
    if len(indicators) >= 5:
        return MatchConfidence.CONFIRMED
    elif len(indicators) >= 3:
        return MatchConfidence.HIGH
    elif len(indicators) >= 1:
        return MatchConfidence.MEDIUM
    else:
        return MatchConfidence.LOW
```

### 3. Error Handling

Handle errors gracefully and provide useful context:

```python
async def process_task(self, task: AgentTask) -> AgentResult:
    try:
        # Processing logic
        pass
    except ValidationError as e:
        # Return partial result with error details
        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            status=ResultStatus.PARTIAL,
            errors=[f"Validation failed: {e}"],
        )
    except ExternalServiceError as e:
        # May be retryable
        raise  # Let framework handle retry
```

### 4. Logging

Use structured logging for observability:

```python
import structlog

logger = structlog.get_logger(__name__)

async def process_task(self, task: AgentTask) -> AgentResult:
    logger.info(
        "processing_task",
        task_id=task.task_id,
        event_id=task.event_id,
        agent_id=self.agent_id,
    )
    
    # Processing...
    
    logger.info(
        "task_completed",
        task_id=task.task_id,
        detection=finding is not None,
        processing_time_ms=processing_time,
    )
```

### 5. Configuration

Make thresholds and parameters configurable:

```python
class YourAgentConfig(BaseModel):
    """Configuration for YourNewAgent."""
    
    detection_threshold: int = 5
    time_window_seconds: int = 60
    risk_score_multiplier: float = 1.0
    enabled_checks: list[str] = Field(
        default_factory=lambda: ["check_a", "check_b"]
    )
```

## Testing Your Agent

### Unit Tests

```python
# tests/unit/test_your_agent.py
import pytest
from backend.app.agents.specialized.your_agent import YourNewAgent
from backend.app.agents.models import AgentTask, AgentType

class TestYourNewAgent:
    
    @pytest.fixture
    def agent(self):
        return YourNewAgent()
    
    @pytest.fixture
    def sample_task(self):
        return AgentTask(
            task_id="task_001",
            event_id="evt_001",
            agent_type=AgentType.YOUR_NEW_AGENT,
            payload={"data_field_1": "test_data"},
        )
    
    def test_agent_properties(self, agent):
        assert agent.agent_id == "your_agent_001"
        assert agent.agent_type == AgentType.YOUR_NEW_AGENT
        assert len(agent.capabilities) > 0
    
    @pytest.mark.asyncio
    async def test_validate_task_valid(self, agent, sample_task):
        assert await agent.validate_task(sample_task) is True
    
    @pytest.mark.asyncio
    async def test_validate_task_missing_field(self, agent, sample_task):
        sample_task.payload = {}
        assert await agent.validate_task(sample_task) is False
    
    @pytest.mark.asyncio
    async def test_process_task_no_detection(self, agent, sample_task):
        result = await agent.process_task(sample_task)
        assert result.status == ResultStatus.SUCCESS
        assert result.finding is None
    
    @pytest.mark.asyncio
    async def test_process_task_with_detection(self, agent, sample_task):
        sample_task.payload = {"data_field_1": "malicious_pattern"}
        result = await agent.process_task(sample_task)
        assert result.status == ResultStatus.SUCCESS
        assert result.finding is not None
```

### Integration Tests

```python
# tests/integration/test_your_agent_integration.py
import pytest
from backend.app.agents.registry import get_agent_registry

class TestYourAgentIntegration:
    
    @pytest.mark.asyncio
    async def test_agent_registered(self):
        registry = get_agent_registry()
        agent = registry.get_agent("your_agent_001")
        assert agent is not None
    
    @pytest.mark.asyncio
    async def test_end_to_end_flow(self):
        # Test full flow from event to finding
        pass
```

## Agent Checklist

Before deploying your agent, verify:

- [ ] Agent implements all abstract methods
- [ ] Agent is registered in the registry
- [ ] Routing rules are configured
- [ ] Finding model is properly defined
- [ ] Unit tests cover all detection paths
- [ ] Integration tests verify end-to-end flow
- [ ] Configuration is externalized
- [ ] Logging is implemented
- [ ] Error handling is comprehensive
- [ ] Documentation is complete
