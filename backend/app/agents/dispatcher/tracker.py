"""Redis-backed task state tracking for the agent dispatcher."""

import json
import uuid
from typing import Any

from backend.app.agents.models import AgentTask, AgentType, TaskPriority, TaskStatus
from backend.app.core.logging import get_logger
from backend.app.core.redis import get_redis_manager
from backend.app.utils.datetime import utc_now

logger = get_logger("cyber_ai.agents.dispatcher.tracker")


async def _get_redis_client():
    """Get Redis client from manager."""
    try:
        manager = get_redis_manager()
        return await manager.get_client()
    except Exception:
        return None


class TaskTracker:
    """Redis-backed task lifecycle state machine.

    Tracks task creation, status transitions, retries, and completion.
    Provides metrics and query capabilities for monitoring.
    """

    # Redis key prefixes
    TASK_KEY_PREFIX = "agent:task:"
    TASK_INDEX_PREFIX = "agent:tasks:"
    METRICS_KEY = "agent:metrics"

    # Default TTL for task records (24 hours)
    DEFAULT_TTL_SEC = 86400

    def __init__(self, ttl_sec: int = DEFAULT_TTL_SEC) -> None:
        """Initialize task tracker.

        Args:
            ttl_sec: TTL for task records in Redis.
        """
        self._ttl_sec = ttl_sec
        self._tasks: dict[str, AgentTask] = {}
        self._use_redis = True

        # Metrics counters (local fallback)
        self._tasks_created = 0
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._total_latency_ms = 0.0

    def _task_key(self, task_id: str) -> str:
        """Generate Redis key for a task."""
        return f"{self.TASK_KEY_PREFIX}{task_id}"

    def _index_key(self, agent_type: AgentType, status: TaskStatus) -> str:
        """Generate Redis index key for agent+status queries."""
        return f"{self.TASK_INDEX_PREFIX}{agent_type.value}:{status.value}"

    async def create_task(
        self,
        event_id: str,
        agent_type: AgentType,
        priority: TaskPriority = TaskPriority.MEDIUM,
        max_retries: int = 3,
        payload: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentTask:
        """Create and store a new task.

        Args:
            event_id: Source event ID.
            agent_type: Target agent type.
            priority: Task priority.
            max_retries: Maximum retry attempts.
            payload: Task payload data.
            metadata: Additional metadata.

        Returns:
            The created AgentTask.
        """
        task = AgentTask(
            task_id=f"task_{uuid.uuid4().hex}",
            event_id=event_id,
            agent_type=agent_type,
            priority=priority,
            max_retries=max_retries,
            payload=payload or {},
            metadata=metadata or {},
        )

        task_data = task.model_dump(mode="json")

        try:
            redis = await _get_redis_client()
            if redis:
                # Store task
                await redis.setex(
                    self._task_key(task.task_id),
                    self._ttl_sec,
                    json.dumps(task_data),
                )

                # Add to status index
                await redis.sadd(
                    self._index_key(task.agent_type, task.status),
                    task.task_id,
                )

                # Increment metrics
                await redis.hincrby(self.METRICS_KEY, "tasks_created", 1)

                logger.debug("Created task %s in Redis", task.task_id)
        except Exception as e:
            logger.warning("Redis unavailable, using local cache: %s", e)
            self._use_redis = False

        # Always store in local cache as fallback
        self._tasks[task.task_id] = task
        self._tasks_created += 1

        return task

    async def get_task(self, task_id: str) -> AgentTask | None:
        """Retrieve a task by ID.

        Args:
            task_id: Task identifier.

        Returns:
            AgentTask if found, None otherwise.
        """
        # Try Redis first
        try:
            redis = await _get_redis_client()
            if redis:
                data = await redis.get(self._task_key(task_id))
                if data:
                    task_dict = json.loads(data)
                    return AgentTask(**task_dict)
        except Exception as e:
            logger.debug("Redis get failed: %s", e)

        # Fall back to local cache
        return self._tasks.get(task_id)

    async def update_status(
        self,
        task_id: str,
        new_status: TaskStatus,
        error: str | None = None,
    ) -> AgentTask | None:
        """Update task status.

        Args:
            task_id: Task identifier.
            new_status: New status value.
            error: Optional error message for failed tasks.

        Returns:
            Updated AgentTask or None if not found.
        """
        task = await self.get_task(task_id)
        if not task:
            logger.warning("Task %s not found for status update", task_id)
            return None

        old_status = task.status
        task.status = new_status

        if error:
            task.error = error

        if new_status == TaskStatus.RUNNING and not task.started_at:
            task.started_at = utc_now()
        elif new_status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.DEAD_LETTER):
            task.completed_at = utc_now()

        # Update in storage
        await self._update_task(task, old_status)

        return task

    async def _update_task(self, task: AgentTask, old_status: TaskStatus | None = None) -> None:
        """Update task in storage."""
        task_data = task.model_dump(mode="json")

        try:
            redis = await _get_redis_client()
            if redis:
                # Update task data
                await redis.setex(
                    self._task_key(task.task_id),
                    self._ttl_sec,
                    json.dumps(task_data),
                )

                # Update indexes
                if old_status and old_status != task.status:
                    await redis.srem(
                        self._index_key(task.agent_type, old_status),
                        task.task_id,
                    )
                    await redis.sadd(
                        self._index_key(task.agent_type, task.status),
                        task.task_id,
                    )

                # Update metrics
                if task.status == TaskStatus.COMPLETED:
                    await redis.hincrby(self.METRICS_KEY, "tasks_completed", 1)
                elif task.status == TaskStatus.FAILED:
                    await redis.hincrby(self.METRICS_KEY, "tasks_failed", 1)

        except Exception as e:
            logger.debug("Redis update failed: %s", e)

        # Always update local cache
        self._tasks[task.task_id] = task

        # Update local metrics
        if task.status == TaskStatus.COMPLETED:
            self._tasks_completed += 1
        elif task.status == TaskStatus.FAILED:
            self._tasks_failed += 1

    async def mark_started(self, task_id: str) -> AgentTask | None:
        """Mark task as started/running.

        Args:
            task_id: Task identifier.

        Returns:
            Updated AgentTask or None.
        """
        return await self.update_status(task_id, TaskStatus.RUNNING)

    async def mark_completed(self, task_id: str, result_id: str | None = None) -> AgentTask | None:
        """Mark task as completed.

        Args:
            task_id: Task identifier.
            result_id: Optional result identifier.

        Returns:
            Updated AgentTask or None.
        """
        task = await self.update_status(task_id, TaskStatus.COMPLETED)

        # Record latency if task has timing info
        if task and task.started_at and task.completed_at:
            latency_ms = (task.completed_at - task.started_at).total_seconds() * 1000
            self._total_latency_ms += latency_ms

        return task

    async def mark_failed(self, task_id: str, error: str) -> AgentTask | None:
        """Mark task as failed.

        Args:
            task_id: Task identifier.
            error: Error message.

        Returns:
            Updated AgentTask or None.
        """
        return await self.update_status(task_id, TaskStatus.FAILED, error=error)

    async def mark_retry(self, task_id: str, error: str | None = None) -> AgentTask | None:
        """Increment retry count and mark for retry.

        Args:
            task_id: Task identifier.
            error: Optional error message.

        Returns:
            Updated AgentTask or None.
        """
        task = await self.get_task(task_id)
        if not task:
            return None

        task.retry_count += 1
        task.status = TaskStatus.RETRYING
        task.error = error

        await self._update_task(task, TaskStatus.FAILED)
        return task

    async def mark_dead_letter(self, task_id: str, error: str) -> AgentTask | None:
        """Move task to dead-letter state after max retries.

        Args:
            task_id: Task identifier.
            error: Final error message.

        Returns:
            Updated AgentTask or None.
        """
        return await self.update_status(task_id, TaskStatus.DEAD_LETTER, error=error)

    async def get_tasks_by_status(
        self,
        agent_type: AgentType,
        status: TaskStatus,
        limit: int = 100,
    ) -> list[AgentTask]:
        """Get tasks by agent type and status.

        Args:
            agent_type: Agent type filter.
            status: Status filter.
            limit: Maximum tasks to return.

        Returns:
            List of matching AgentTasks.
        """
        tasks: list[AgentTask] = []

        try:
            redis = await _get_redis_client()
            if redis:
                task_ids = await redis.smembers(self._index_key(agent_type, status))
                for task_id in list(task_ids)[:limit]:
                    decoded_id = task_id.decode() if isinstance(task_id, bytes) else task_id
                    task = await self.get_task(decoded_id)
                    if task:
                        tasks.append(task)
                return tasks
        except Exception as e:
            logger.debug("Redis query failed: %s", e)

        # Fall back to local cache
        for task in list(self._tasks.values())[:limit]:
            if task.agent_type == agent_type and task.status == status:
                tasks.append(task)

        return tasks

    async def get_pending_tasks(self, agent_type: AgentType, limit: int = 100) -> list[AgentTask]:
        """Get pending (queued) tasks for an agent type.

        Args:
            agent_type: Agent type filter.
            limit: Maximum tasks to return.

        Returns:
            List of pending AgentTasks.
        """
        return await self.get_tasks_by_status(agent_type, TaskStatus.QUEUED, limit)

    async def get_metrics(self) -> dict[str, Any]:
        """Get task tracking metrics.

        Returns:
            Dict with metric values.
        """
        metrics = {
            "tasks_created": self._tasks_created,
            "tasks_completed": self._tasks_completed,
            "tasks_failed": self._tasks_failed,
            "avg_latency_ms": (
                self._total_latency_ms / self._tasks_completed
                if self._tasks_completed > 0
                else 0.0
            ),
        }

        try:
            redis = await _get_redis_client()
            if redis:
                redis_metrics = await redis.hgetall(self.METRICS_KEY)
                if redis_metrics:
                    for key, value in redis_metrics.items():
                        key_str = key.decode() if isinstance(key, bytes) else key
                        value_str = value.decode() if isinstance(value, bytes) else value
                        metrics[key_str] = int(value_str)
        except Exception as e:
            logger.debug("Redis metrics fetch failed: %s", e)

        return metrics

    async def clear_completed(self, older_than_sec: int = 3600) -> int:
        """Clear completed tasks older than threshold.

        Args:
            older_than_sec: Age threshold in seconds.

        Returns:
            Number of tasks cleared.
        """
        # For now, just clear from local cache
        # Redis entries will expire via TTL
        cleared = 0
        cutoff = utc_now()

        to_remove = []
        for task_id, task in self._tasks.items():
            if task.status == TaskStatus.COMPLETED and task.completed_at:
                age_sec = (cutoff - task.completed_at).total_seconds()
                if age_sec > older_than_sec:
                    to_remove.append(task_id)

        for task_id in to_remove:
            del self._tasks[task_id]
            cleared += 1

        return cleared


# Singleton instance
_tracker: TaskTracker | None = None


def get_task_tracker() -> TaskTracker:
    """Return singleton TaskTracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = TaskTracker()
    return _tracker
