"""FastAPI application entry point."""

import asyncio
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.router import root_api_router
from backend.app.config.settings import get_settings
from backend.app.core.broker import get_broker_manager
from backend.app.core.exceptions import CyberAIError, SecurityBoundaryViolation
from backend.app.core.logging import get_logger, setup_logging
from backend.app.schemas.common import ErrorResponse
from backend.app.workers.telemetry_worker import TelemetryProcessingWorker

logger = get_logger("cyber_ai.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown orchestration."""
    settings = get_settings()
    setup_logging(log_level=settings.log_level, log_format=settings.log_format)
    logger.info(
        "Starting %s v%s in %s mode",
        settings.app_name,
        settings.app_version,
        settings.app_env,
    )
    worker: TelemetryProcessingWorker | None = None
    # Kafka worker is skipped in unit/integration tests so they do not wait on a broker.
    if settings.app_env != "test":
        worker = TelemetryProcessingWorker()
        try:
            await asyncio.wait_for(
                worker.start(),
                timeout=(settings.kafka_request_timeout_ms / 1000.0) * 2,
            )
        except TimeoutError:
            logger.warning(
                "Telemetry worker start exceeded timeout; API will continue without live consumption"
            )
        app.state.telemetry_worker = worker
    yield
    if worker is not None:
        await worker.stop()
        await get_broker_manager().close()
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "AI-Driven Multi-Agent System for Real-Time Cybersecurity "
            "Threat Detection and Correlation API Gateway"
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware: Request Timing & Trace ID Injection
    @app.middleware("http")
    async def trace_and_timing_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
        start_time = time.perf_counter()

        response = await call_next(request)

        process_time = (time.perf_counter() - start_time) * 1000
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Response-Time-Ms"] = f"{process_time:.2f}"
        return response

    # Exception Handlers
    @app.exception_handler(SecurityBoundaryViolation)
    async def security_violation_handler(
        request: Request, exc: SecurityBoundaryViolation
    ) -> JSONResponse:
        logger.warning("Security boundary violation: %s", exc.message)
        payload = ErrorResponse(
            error_code="SECURITY_BOUNDARY_VIOLATION",
            message=exc.message,
            details=exc.details,
            trace_id=request.headers.get("X-Trace-ID"),
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=payload.model_dump(mode="json"),
        )

    @app.exception_handler(CyberAIError)
    async def cyber_ai_error_handler(request: Request, exc: CyberAIError) -> JSONResponse:
        logger.error("Domain exception: %s", exc.message)
        payload = ErrorResponse(
            error_code="APPLICATION_ERROR",
            message=exc.message,
            details=exc.details,
            trace_id=request.headers.get("X-Trace-ID"),
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=payload.model_dump(mode="json"),
        )

    # Mount Root API Routers at /api
    app.include_router(root_api_router, prefix=settings.api_prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "message": f"{settings.app_name} API is operational",
            "docs": "/docs",
            "health": f"{settings.api_prefix}/health",
        }

    return app


app = create_app()
