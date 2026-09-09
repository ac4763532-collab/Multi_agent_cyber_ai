"""Retry utilities with exponential backoff and jitter for transient pipeline operations."""

import asyncio
import functools
import secrets
from collections.abc import Callable
from typing import Any, TypeVar

from backend.app.core.logging import get_logger

logger = get_logger("cyber_ai.ingestion.retry")

T = TypeVar("T")


async def retry_async(
    func: Callable[..., Any],
    *args: Any,
    max_retries: int = 3,
    initial_delay: float = 0.1,
    max_delay: float = 2.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    **kwargs: Any,
) -> Any:
    """Execute an asynchronous function with exponential backoff and jitter."""
    attempt = 0
    delay = initial_delay

    while True:
        attempt += 1
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as exc:
            if attempt >= max_retries:
                logger.error(
                    "Operation %s failed permanently after %d attempts: %s",
                    getattr(func, "__name__", str(func)),
                    attempt,
                    str(exc),
                )
                raise

            sleep_time = delay
            if jitter:
                # Use secrets generator for safe jitter calculation
                jitter_val = secrets.randbelow(1000) / 1000.0
                sleep_time = delay * (0.5 + jitter_val * 0.5)

            logger.warning(
                "Operation %s failed on attempt %d/%d: %s. Retrying in %.3fs",
                getattr(func, "__name__", str(func)),
                attempt,
                max_retries,
                str(exc),
                sleep_time,
            )
            await asyncio.sleep(sleep_time)
            delay = min(delay * backoff_factor, max_delay)


def with_retry(
    max_retries: int = 3,
    initial_delay: float = 0.1,
    max_delay: float = 2.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for retrying async functions with exponential backoff."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await retry_async(
                func,
                *args,
                max_retries=max_retries,
                initial_delay=initial_delay,
                max_delay=max_delay,
                backoff_factor=backoff_factor,
                jitter=jitter,
                retryable_exceptions=retryable_exceptions,
                **kwargs,
            )

        return wrapper

    return decorator
