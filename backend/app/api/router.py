"""Root API Router definitions."""

from fastapi import APIRouter

from backend.app.api.v1 import api_v1_router
from backend.app.api.v1.health import router as health_router

root_api_router = APIRouter()

# Mount top-level health endpoint at /api/health as requested
root_api_router.include_router(health_router)

# Mount versioned sub-routers at /api/v1/...
root_api_router.include_router(api_v1_router)

__all__ = ["root_api_router"]
