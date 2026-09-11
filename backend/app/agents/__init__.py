"""Autonomous domain agents package.

Encapsulates 12 specialized SOC intelligence agents:
1. Task Dispatcher Agent
2. Email Verification Agent
3. Log Analyzer Agent
4. Network Threat Analysis Agent
5. IP Range Analyzer Agent
6. Vulnerability Analysis Agent
7. Threat Intelligence Agent
8. Correlation Agent
9. Investigation Agent
10. Incident Prioritization Agent
11. Response Recommendation Agent
12. Report Generation Agent
"""

from backend.app.agents.base import BaseAgent
from backend.app.agents.exceptions import (
    AgentError,
    AgentNotFoundError,
    AgentRegistrationError,
    AgentTimeoutError,
    AgentValidationError,
    TaskDeadLetterError,
    TaskExecutionError,
    TaskRoutingError,
)
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
from backend.app.agents.registry import AgentRegistry, get_agent_registry

__all__ = [
    # Base
    "BaseAgent",
    # Models
    "AgentTask",
    "AgentResult",
    "BaseFinding",
    "ExecutionRecord",
    # Enums
    "TaskStatus",
    "TaskPriority",
    "AgentType",
    "AgentStatus",
    "ResultStatus",
    "ExecutionStatus",
    # Registry
    "AgentRegistry",
    "get_agent_registry",
    # Exceptions
    "AgentError",
    "AgentValidationError",
    "AgentTimeoutError",
    "AgentNotFoundError",
    "TaskRoutingError",
    "TaskExecutionError",
    "TaskDeadLetterError",
    "AgentRegistrationError",
]
