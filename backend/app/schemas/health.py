"""Pydantic schemas for health and system status endpoints."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class SubsystemStatus(BaseModel):
    """Health status details of an individual subsystem component."""

    status: Literal["healthy", "degraded", "unhealthy", "disabled"] = Field(
        ..., description="Current operational status of subsystem"
    )
    latency_ms: float | None = Field(
        default=None, description="Round-trip ping/check latency in milliseconds"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional subsystem diagnostics"
    )


class HealthResponse(BaseModel):
    """Standardized API health status payload."""

    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ..., description="Overall platform health state"
    )
    app_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Platform version")
    environment: str = Field(..., description="Active runtime environment")
    timestamp: datetime = Field(..., description="Timestamp of health check in UTC")
    uptime_seconds: float = Field(..., description="Process uptime in seconds")
    services: dict[str, SubsystemStatus] = Field(
        default_factory=dict, description="Status breakdown of interconnected services"
    )
