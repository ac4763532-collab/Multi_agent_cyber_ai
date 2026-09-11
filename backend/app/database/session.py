"""Async SQLAlchemy database engine and session dependency."""

import asyncio
import time
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.config.settings import get_settings
from backend.app.core.logging import get_logger
from backend.app.database.base import Base

logger = get_logger("cyber_ai.database")

_engine: AsyncEngine | None = None
_session_maker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Return initialized async SQLAlchemy engine singleton with resilience configuration."""
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args: dict[str, Any] = {
            "timeout": settings.db_connect_timeout,
        }
        # Only pass server_settings if not sqlite in testing
        if "sqlite" not in settings.database_url:
            connect_args["server_settings"] = {
                "application_name": settings.app_name,
            }

        _engine = create_async_engine(
            settings.database_url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle,
            pool_pre_ping=True,
            connect_args=connect_args,
            future=True,
        )
    return _engine


def get_session_maker() -> async_sessionmaker[AsyncSession]:
    """Return initialized async session maker."""
    global _session_maker
    if _session_maker is None:
        _session_maker = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_maker
async def init_db() -> None:
    """Create database tables that do not already exist."""
    engine = get_engine()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database tables initialized successfully")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for obtaining an isolated async database session."""
    session_factory = get_session_maker()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_health(max_retries: int = 1) -> tuple[bool, float, dict[str, Any]]:
    """Check database connectivity with retry backoff and return health diagnostics."""
    settings = get_settings()
    start_time = time.perf_counter()

    for attempt in range(1, max_retries + 1):
        try:
            engine = get_engine()
            async with engine.connect() as conn:
                result = await conn.execute(text("SELECT 1"))
                result.fetchone()

            latency = (time.perf_counter() - start_time) * 1000
            return (
                True,
                round(latency, 2),
                {
                    "host": settings.postgres_host,
                    "port": settings.postgres_port,
                    "database": settings.postgres_db,
                    "connected": True,
                },
            )
        except Exception as e:
            if attempt < max_retries:
                await asyncio.sleep(settings.db_retry_delay_sec)
                continue
            latency = (time.perf_counter() - start_time) * 1000
            return (
                False,
                round(latency, 2),
                {
                    "host": settings.postgres_host,
                    "port": settings.postgres_port,
                    "database": settings.postgres_db,
                    "error": str(e),
                    "connected": False,
                },
            )

    return False, 0.0, {"error": "Connection attempt exhausted"}


async def close_db() -> None:
    """Dispose of engine connections."""
    global _engine, _session_maker
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_maker = None
        logger.info("Database engine disposed gracefully")
