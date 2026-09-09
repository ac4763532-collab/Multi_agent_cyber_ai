"""Health check endpoint definitions."""

from datetime import UTC, datetime
from typing import Literal

import anyio
from fastapi import APIRouter, status

from backend.app.config.settings import get_settings
from backend.app.core.broker import get_broker_manager
from backend.app.core.redis import get_redis_manager
from backend.app.database.session import check_db_health
from backend.app.observability.metrics import get_uptime_seconds
from backend.app.schemas.health import HealthResponse, SubsystemStatus

router = APIRouter(tags=["Health & Status"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Platform Health Status",
    description="Returns aggregate health and status breakdown for all infrastructure services.",
)
async def get_health() -> HealthResponse:
    """Evaluate and return real-time system and dependency status."""
    settings = get_settings()

    # 1. PostgreSQL Database check
    db_ok, db_lat, db_details = await check_db_health(max_retries=1)

    # 2. Redis Cache & Ephemeral State check
    redis_mgr = get_redis_manager()
    redis_ok, redis_lat, redis_details = await redis_mgr.check_redis_health()

    # 3. Message Broker (Kafka / Redpanda) check
    broker_mgr = get_broker_manager()
    broker_ok, broker_lat, broker_details = await broker_mgr.check_broker_health()

    # 4. AI / LLM status
    has_custom_key = settings.gemini_api_key != "your_gemini_api_key_here"
    gemini_configured = bool(settings.gemini_api_key and has_custom_key)

    # 5. Vector Store status
    index_exists = await anyio.Path(settings.faiss_index_path).exists()

    services: dict[str, SubsystemStatus] = {
        "database": SubsystemStatus(
            status="healthy" if db_ok else "unhealthy",
            latency_ms=db_lat,
            details=db_details,
        ),
        "redis": SubsystemStatus(
            status="healthy" if redis_ok else "unhealthy",
            latency_ms=redis_lat,
            details=redis_details,
        ),
        "message_broker": SubsystemStatus(
            status="healthy" if broker_ok else "unhealthy",
            latency_ms=broker_lat,
            details=broker_details,
        ),
        "gemini_ai": SubsystemStatus(
            status="healthy" if gemini_configured else "degraded",
            details={
                "configured": gemini_configured,
                "model_reasoning": settings.gemini_model_reasoning,
                "model_fast": settings.gemini_model_fast,
            },
        ),
        "vector_store": SubsystemStatus(
            status="healthy" if index_exists else "degraded",
            details={"path": settings.faiss_index_path, "index_exists": index_exists},
        ),
    }

    # Determine overall status
    core_healthy = db_ok and redis_ok and broker_ok
    core_partial = db_ok or redis_ok or broker_ok

    overall_status: Literal["healthy", "degraded", "unhealthy"]
    if core_healthy:
        overall_status = "healthy"
    elif core_partial or settings.app_env in ["development", "test"]:
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    return HealthResponse(
        status=overall_status,
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        timestamp=datetime.now(UTC),
        uptime_seconds=round(get_uptime_seconds(), 2),
        services=services,
    )
