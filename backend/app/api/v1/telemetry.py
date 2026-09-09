"""Telemetry Ingestion REST API Endpoints."""

import json
from typing import Any

from fastapi import APIRouter, Body, Query, Request, Response, status
from pydantic import BaseModel, Field

from backend.app.core.logging import get_logger
from backend.app.ingestion.collectors.http import get_http_collector
from backend.app.ingestion.metrics import get_metrics_tracker
from backend.app.ingestion.registry import get_ingestion_registry
from backend.app.ingestion.resilience.dead_letter import get_dlq_manager

logger = get_logger("cyber_ai.api.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Real-Time Telemetry Ingestion"])


class BatchIngestRequest(BaseModel):
    """Batch ingestion request envelope."""

    events: list[Any] = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="List of raw or structured security event payloads",
    )
    source_type: str | None = Field(
        default=None,
        description="Optional override source type for all events in batch",
    )
    source_identifier: str | None = Field(
        default=None,
        description="Optional telemetry collector source identifier",
    )


class IngestionResultResponse(BaseModel):
    """Individual event ingestion result response."""

    status: str = Field(..., description="Ingestion status: 'accepted' or 'rejected'")
    is_valid: bool = Field(..., description="Whether event passed validation")
    event_id: str | None = Field(default=None, description="Unique event ID if accepted")
    source: str | None = Field(default=None, description="Telemetry source identifier")
    source_type: str | None = Field(default=None, description="Source classification")
    event_type: str | None = Field(default=None, description="Event classification")
    severity: str | None = Field(default=None, description="Normalized severity rating")
    timestamp: str | None = Field(default=None, description="Event occurrence timestamp")
    latency_ms: float = Field(..., description="Processing latency in milliseconds")
    error: str | None = Field(default=None, description="Error reason if rejected")
    dead_letter_id: str | None = Field(default=None, description="Dead letter record ID if rejected")


@router.post(
    "/ingest",
    summary="Ingest Single Telemetry Event",
    response_model=dict[str, Any],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_single_event(
    request: Request,
    response: Response,
    payload: Any = Body(None, description="Raw telemetry payload (JSON or string)"),
    source_type: str | None = Query(
        default=None,
        description="Source type (suricata, syslog, json, application, authentication, email)",
    ),
    source_identifier: str | None = Query(
        default=None,
        description="Optional collector origin identifier",
    ),
) -> dict[str, Any]:
    """Ingest, validate, normalize, and publish a real-time security event."""
    content_type = request.headers.get("content-type", "")
    if payload is None or (isinstance(payload, (bytes, str)) and not payload):
        body_bytes = await request.body()
        if "json" in content_type:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                payload = body_bytes.decode("utf-8", errors="replace")
        else:
            payload = body_bytes.decode("utf-8", errors="replace")
    elif isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", errors="replace")

    collector = get_http_collector()
    result = await collector.collect(
        raw_payload=payload,
        source_type=source_type,
        source_identifier=source_identifier,
    )

    if result.get("status") == "rejected":
        if result.get("error_type") == "backpressure_exceeded":
            response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
        else:
            response.status_code = status.HTTP_400_BAD_REQUEST

    result_clean = {k: v for k, v in result.items() if k != "event"}
    return result_clean


@router.post(
    "/batch",
    summary="Ingest Telemetry Batch",
    response_model=dict[str, Any],
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_batch_events(
    request: BatchIngestRequest,
) -> dict[str, Any]:
    """Ingest a batch of security events concurrently with throughput summary."""
    collector = get_http_collector()
    result = await collector.collect_batch(
        raw_payloads=request.events,
        source_type=request.source_type,
        source_identifier=request.source_identifier,
    )

    cleaned_items = []
    for item in result.get("results", []):
        cleaned_items.append({k: v for k, v in item.items() if k != "event"})
    result["results"] = cleaned_items

    return result


@router.get(
    "/metrics",
    summary="Get Ingestion Performance Metrics",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def get_ingestion_metrics() -> dict[str, Any]:
    """Retrieve telemetry metrics: events received, accepted, rejected, EPS, latency."""
    metrics_tracker = get_metrics_tracker()
    return metrics_tracker.get_snapshot()


@router.get(
    "/dead-letter",
    summary="Query Dead-Letter Queue (DLQ)",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def get_dead_letter_events(
    limit: int = Query(default=50, ge=1, le=500, description="Max items to return"),
    error_type: str | None = Query(default=None, description="Filter by error classification"),
) -> dict[str, Any]:
    """Query recent rejected and malformed security events from the Dead-Letter Queue."""
    dlq = get_dlq_manager()
    items = dlq.get_recent(limit=limit, error_type=error_type)
    return {
        "total_recorded": dlq.total_count,
        "returned_count": len(items),
        "dead_letters": items,
    }


@router.get(
    "/sources",
    summary="List Supported Telemetry Sources",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
)
async def list_supported_sources() -> dict[str, Any]:
    """List all supported telemetry adapters, parser versions, and mappings."""
    registry = get_ingestion_registry()
    sources = registry.list_supported_sources()
    return {
        "supported_sources": sources,
        "total_sources": len(sources),
        "parser_details": [
            {
                "source_type": src,
                "parser_name": getattr(registry.get_parser(src), "parser_name", "unknown"),
                "parser_version": getattr(registry.get_parser(src), "parser_version", "1.0.0"),
            }
            for src in sources
        ],
    }
