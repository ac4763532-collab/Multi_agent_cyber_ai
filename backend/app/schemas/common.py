"""Common reusable Pydantic schemas."""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class APIResponse(BaseModel, Generic[T]):
    """Standard generic API envelope."""

    success: bool = Field(default=True, description="Indicates operation success")
    message: str = Field(default="Operation completed successfully", description="Status message")
    data: T | None = Field(default=None, description="Payload data")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="UTC timestamp of response generation"
    )
    trace_id: str | None = Field(default=None, description="Distributed correlation trace ID")


class ErrorResponse(BaseModel):
    """Standard error response payload."""

    success: bool = Field(default=False)
    error_code: str = Field(..., description="Machine-readable error identifier")
    message: str = Field(..., description="Human-readable error explanation")
    details: dict[str, str] = Field(default_factory=dict, description="Diagnostic error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    trace_id: str | None = None
