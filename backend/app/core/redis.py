"""Redis connection manager for cache, temporary state, rate limiting, and coordination."""

import asyncio
import time
import uuid
from typing import Any

import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool

from backend.app.config.settings import Settings, get_settings
from backend.app.core.logging import get_logger

logger = get_logger("cyber_ai.redis")


class RedisManager:
    """Async Redis client manager supporting caching, rate limiting, and coordination."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._pool: ConnectionPool | None = None
        self._client: aioredis.Redis | None = None
        self._lock = asyncio.Lock()

    def get_pool(self) -> ConnectionPool:
        """Return initialized connection pool."""
        if self._pool is None:
            self._pool = ConnectionPool.from_url(
                self.settings.redis_url,
                max_connections=self.settings.redis_max_connections,
                socket_timeout=self.settings.redis_timeout_sec,
                socket_connect_timeout=self.settings.redis_timeout_sec,
                retry_on_timeout=self.settings.redis_retry_on_timeout,
                decode_responses=True,
            )
        return self._pool

    async def get_client(self) -> aioredis.Redis:
        """Return active Redis client singleton."""
        if self._client is not None:
            return self._client

        async with self._lock:
            if self._client is not None:
                return self._client
            pool = self.get_pool()
            self._client = aioredis.Redis(connection_pool=pool)
            return self._client

    # --------------------------------------------------------------------------
    # Caching Primitives
    # --------------------------------------------------------------------------
    async def get(self, key: str) -> str | None:
        """Retrieve value from cache by key."""
        try:
            client = await self.get_client()
            return await client.get(key)
        except Exception as e:
            logger.warning("Redis GET failed for key %s: %s", key, str(e))
            return None

    async def set(self, key: str, value: str, expire_seconds: int | None = None) -> bool:
        """Set value in cache with optional TTL."""
        try:
            client = await self.get_client()
            if expire_seconds:
                await client.setex(key, expire_seconds, value)
            else:
                await client.set(key, value)
            return True
        except Exception as e:
            logger.warning("Redis SET failed for key %s: %s", key, str(e))
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        try:
            client = await self.get_client()
            await client.delete(key)
            return True
        except Exception as e:
            logger.warning("Redis DELETE failed for key %s: %s", key, str(e))
            return False

    # --------------------------------------------------------------------------
    # Rate Limiting Primitive (Sliding Window Counter)
    # --------------------------------------------------------------------------
    async def check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int, int]:
        """Check sliding-window rate limit. Returns (is_allowed, current_count, remaining_quota)."""
        key = f"rate_limit:{identifier}"
        now = time.time()
        window_start = now - window_seconds

        try:
            client = await self.get_client()
            pipe = client.pipeline()
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            # Add current timestamp
            pipe.zadd(key, {f"{now}-{uuid.uuid4().hex[:6]}": now})
            # Count elements in window
            pipe.zcard(key)
            # Set key expiration
            pipe.expire(key, window_seconds + 5)
            results = await pipe.execute()

            current_count = int(results[2])
            is_allowed = current_count <= limit
            remaining = max(0, limit - current_count)

            return is_allowed, current_count, remaining
        except Exception as e:
            logger.warning("Rate limit evaluation fallback for %s: %s", identifier, str(e))
            # Fail open in development/errors
            return True, 0, limit

    # --------------------------------------------------------------------------
    # Distributed Coordination (Mutex Lock)
    # --------------------------------------------------------------------------
    async def acquire_lock(self, lock_name: str, timeout_seconds: int = 10) -> str | None:
        """Acquire distributed lock. Returns token string if acquired, None otherwise."""
        token = str(uuid.uuid4())
        key = f"lock:{lock_name}"
        try:
            client = await self.get_client()
            acquired = await client.set(key, token, ex=timeout_seconds, nx=True)
            return token if acquired else None
        except Exception as e:
            logger.warning("Lock acquisition failed for %s: %s", lock_name, str(e))
            return None

    async def release_lock(self, lock_name: str, token: str) -> bool:
        """Release distributed lock only if token matches."""
        key = f"lock:{lock_name}"
        lua_script = """
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
        """
        try:
            client = await self.get_client()
            result = await client.eval(lua_script, 1, key, token)  # type: ignore[no-untyped-call]
            return bool(result == 1)
        except Exception as e:
            logger.warning("Lock release failed for %s: %s", lock_name, str(e))
            return False

    # --------------------------------------------------------------------------
    # Health Probe
    # --------------------------------------------------------------------------
    async def check_redis_health(self) -> tuple[bool, float, dict[str, Any]]:
        """Probe Redis server and return (is_healthy, latency_ms, details)."""
        start = time.perf_counter()
        try:
            client = await self.get_client()
            await client.ping()
            info = await client.info("memory")
            latency = (time.perf_counter() - start) * 1000
            return (
                True,
                round(latency, 2),
                {
                    "host": self.settings.redis_host,
                    "port": self.settings.redis_port,
                    "db": self.settings.redis_db,
                    "used_memory_human": info.get("used_memory_human", "unknown"),
                    "connected": True,
                },
            )
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return (
                False,
                round(latency, 2),
                {
                    "host": self.settings.redis_host,
                    "port": self.settings.redis_port,
                    "db": self.settings.redis_db,
                    "error": str(e),
                    "connected": False,
                },
            )

    async def close(self) -> None:
        """Close client and connection pool."""
        async with self._lock:
            if self._client:
                await self._client.close()
                self._client = None
            if self._pool:
                await self._pool.disconnect()
                self._pool = None
            logger.info("Redis manager closed gracefully")


_redis_manager: RedisManager | None = None


def get_redis_manager() -> RedisManager:
    """Return singleton RedisManager instance."""
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisManager()
    return _redis_manager
