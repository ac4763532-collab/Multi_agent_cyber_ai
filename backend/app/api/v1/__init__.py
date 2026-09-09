"""API version 1 route collection."""

from fastapi import APIRouter

from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.telemetry import router as telemetry_router

api_v1_router = APIRouter(prefix="/v1")
api_v1_router.include_router(health_router)
api_v1_router.include_router(telemetry_router)

__all__ = ["api_v1_router"]
