"""
ThreatLens - Remote Windows Collector API Router

Endpoints:
  POST /collector/enrol          — Admin: register a new Windows endpoint
  GET  /collector/collectors     — Admin: list all enrolled collectors
  GET  /collector/collectors/{id} — Admin: single collector status
  POST /collector/collectors/{id}/revoke — Admin: revoke collector token
  POST /collector/ingest/events  — Collector: authenticated event ingestion

Design decisions:
  - Collector authentication uses X-Collector-ID + X-Collector-Token headers
    (separate from the admin X-API-Key path to avoid confusion).
  - Admin enrolment/listing operations reuse verify_admin_access().
  - The ingestion path does NOT expose Kafka or Neo4j directly; it normalises
    Windows events into SecurityEventEnvelope and publishes via the existing
    GraphOpsKafkaProducer.
  - Request size is capped at COLLECTOR_MAX_REQUEST_SIZE_BYTES.
  - Rate limiting is enforced per collector_id.
  - Duplicate event IDs are rejected early via the in-memory dedup cache
    before the durable Neo4j MERGE check.
  - Credentials and token values are never logged.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator

from backend.collector.dedup import is_duplicate, mark_seen
from backend.collector.normalizer import normalize_windows_events
from backend.collector.rate_limiter import check_rate_limit
from backend.collector.registry import (
    authenticate_collector,
    enrol_collector,
    get_collector,
    get_collector_overview,
    list_collectors,
    record_auth_failure,
    record_event_delivery,
    record_ingestion_activity,
    revoke_collector,
)
from backend.core import config
from backend.core.security import verify_admin_access
from backend.api.graphops_routes import get_kafka_producer_dep

logger = logging.getLogger("threatlens.collector.routes")

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------

class EnrolRequest(BaseModel):
    """Admin request to register a new Windows collector endpoint."""
    hostname: str = Field(
        description="Windows hostname of the endpoint being enrolled (e.g. DESKTOP-ABC123)",
        min_length=1,
        max_length=255,
    )
    ip_address: str = Field(
        default="",
        description="Current IP address of the endpoint (informational)",
        max_length=45,
    )
    os_version: str = Field(
        default="Windows",
        description="Windows OS version string",
        max_length=200,
    )


class EnrolResponse(BaseModel):
    """
    Response to a successful enrolment.
    Returns the raw token ONCE. Store it securely — it cannot be retrieved again.
    """
    collector_id: str
    token: str
    hostname: str
    device_node_id: str
    message: str


class CollectorStatusResponse(BaseModel):
    """Public view of a collector's operational status."""
    collector_id: str
    hostname: str
    ip_address: str
    os_version: str
    enrolled_at: str
    last_seen: Optional[str]
    event_count: int
    error_count: int
    status: str
    device_node_id: str
    recent_errors: List[str]
    pending_spool_events: int = 0
    auth_failures: int = 0
    online_status: str = "ENROLLED"
    is_online: bool = False


class CollectorOverviewResponse(BaseModel):
    """Consolidated security overview of fleet collectors, telemetry throughput, and infrastructure."""
    total_registered_devices: int
    online_collectors: int
    offline_collectors: int
    revoked_collectors: int
    total_events_received: int
    total_accepted_events: int
    total_rejected_events: int
    total_ingestion_errors: int
    authentication_failures_count: int
    recent_auth_failures: List[Dict[str, Any]]
    recent_ingestion_activity: List[Dict[str, Any]]
    connectivity: Dict[str, Any]
    collectors: List[CollectorStatusResponse]
    timestamp: str


class WindowsEventRecord(BaseModel):
    """
    A single raw Windows Security Event Log record forwarded by the collector.
    Field names follow both snake_case (preferred) and PascalCase for compatibility.
    """
    event_id_number: int = Field(description="Windows Event ID number (e.g. 4624)")
    source_computer: str = Field(description="Originating Windows hostname")
    time_created: str = Field(description="Event timestamp (ISO 8601 or epoch)")
    source_event_record_id: Optional[Any] = Field(
        default=None,
        description="Windows EventRecordID for deduplication",
    )
    channel: str = Field(default="Security", description="Log channel (Security, System, etc.)")
    event_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="EventData key-value pairs from the Windows event",
    )

    @model_validator(mode="before")
    @classmethod
    def populate_record_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("event_id_number") and data.get("event_id"):
                data["event_id_number"] = data["event_id"]
            elif not data.get("event_id_number") and data.get("EventID"):
                data["event_id_number"] = data["EventID"]
            if not data.get("source_computer") and data.get("computer"):
                data["source_computer"] = data["computer"]
            elif not data.get("source_computer") and data.get("Computer"):
                data["source_computer"] = data["Computer"]
            elif not data.get("source_computer") and data.get("hostname"):
                data["source_computer"] = data["hostname"]
            if not data.get("time_created") and data.get("timestamp"):
                data["time_created"] = data["timestamp"]
            elif not data.get("time_created") and data.get("TimeCreated"):
                data["time_created"] = data["TimeCreated"]
        return data


class CollectorIngestRequest(BaseModel):
    """Batch of Windows event records submitted by a collector agent."""
    events: List[WindowsEventRecord] = Field(
        min_length=1,
        max_length=500,  # soft max; hard cap enforced below
        description="Batch of Windows event records",
    )
    checkpoint_offset: Optional[int] = Field(
        default=None,
        description="Agent checkpoint offset for acknowledgement (informational)",
    )
    pending_spool_events: Optional[int] = Field(
        default=None,
        description="Current number of events queued locally in endpoint offline spool",
    )


class CollectorIngestResponse(BaseModel):
    """Summary of a completed ingestion batch."""
    accepted: int
    rejected: int
    duplicate: int
    published: int
    errors: List[str]
    collector_id: Optional[str] = None


# ---------------------------------------------------------------------------
# System Connectivity Helper
# ---------------------------------------------------------------------------

def get_connectivity_status(client=None, producer=None, worker=None) -> Dict[str, Any]:
    """Inspects live or mock connectivity for Neo4j and Kafka without throwing exceptions."""
    if client is None:
        try:
            from backend.graphops.client import get_graphops_client
            client = get_graphops_client()
        except Exception:
            client = None
    if producer is None:
        try:
            from backend.graphops.kafka import get_graphops_producer
            producer = get_graphops_producer()
        except Exception:
            producer = None
    if worker is None:
        try:
            from backend.graphops.kafka_worker import get_kafka_worker
            worker = get_kafka_worker()
        except Exception:
            worker = None

    neo4j_info = {"status": "offline", "connected": False, "mock_mode": False, "database": "none"}
    if client is not None:
        try:
            health = client.health_check()
            is_mock = getattr(client, "mock_mode", False) or "in-memory" in str(health.get("database", "")).lower()
            connected = bool(health.get("connected", False))
            neo4j_info = {
                "status": "online" if connected and not is_mock else ("mock" if is_mock else "offline"),
                "connected": connected,
                "mock_mode": is_mock,
                "database": health.get("database", "neo4j"),
                "active_nodes": health.get("active_nodes", 0),
                "active_relationships": health.get("active_relationships", 0),
            }
        except Exception as exc:
            neo4j_info["error"] = str(exc)

    kafka_info = {"status": "offline", "connected": False, "mock_mode": False}
    if producer is not None or worker is not None:
        try:
            p_health = producer.health_check() if producer else {}
            w_status = worker.get_status() if worker else {}
            is_mock = bool(p_health.get("mock_mode") or w_status.get("mock_mode"))
            is_online = (p_health.get("status") == "healthy") or bool(w_status.get("is_running"))
            kafka_info = {
                "status": "online" if is_online and not is_mock else ("mock" if is_mock else "offline"),
                "connected": is_online,
                "mock_mode": is_mock,
                "bootstrap_servers": p_health.get("bootstrap_servers", "localhost:9092"),
                "consumer_running": bool(w_status.get("is_running", False)),
            }
        except Exception as exc:
            kafka_info["error"] = str(exc)

    return {"neo4j": neo4j_info, "kafka": kafka_info}


# ---------------------------------------------------------------------------
# Collector authentication dependency
# ---------------------------------------------------------------------------

def _get_collector_credentials(
    request: Request,
    x_collector_id: Optional[str] = Header(None, alias="X-Collector-ID"),
    x_collector_token: Optional[str] = Header(None, alias="X-Collector-Token"),
    x_threatlens_collector_id: Optional[str] = Header(None, alias="X-ThreatLens-Collector-ID"),
    x_threatlens_token: Optional[str] = Header(None, alias="X-ThreatLens-Token"),
):
    """
    FastAPI dependency that authenticates the collector from headers.
    Supports both X-Collector-ID/Token and X-ThreatLens-Collector-ID/Token headers.
    Raises HTTP 401 on missing/invalid credentials.
    Records authentication failures to registry and governance audit ledger.
    Never logs the raw token.
    """
    cid = x_collector_id or x_threatlens_collector_id
    token = x_collector_token or x_threatlens_token
    client_ip = request.client.host if request.client else ""
    if not cid or not token:
        record_auth_failure(
            collector_id=cid or "MISSING_ID",
            ip_address=client_ip,
            reason="MISSING_AUTHENTICATION_HEADERS",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing collector authentication headers (X-Collector-ID, X-Collector-Token).",
            headers={"WWW-Authenticate": "CollectorToken"},
        )
    collector = authenticate_collector(cid.strip(), token.strip(), ip_address=client_ip)
    if collector is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked collector credentials.",
            headers={"WWW-Authenticate": "CollectorToken"},
        )
    return collector


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/enrol",
    response_model=EnrolResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enrol a new Windows Collector",
    description=(
        "Registers a Windows endpoint as an authorised log collector. "
        "Returns a one-time secret token that must be stored in the collector's configuration. "
        "The token is shown only once; subsequent calls re-issue a new token for the same hostname."
    ),
)
async def enrol_collector_endpoint(
    payload: EnrolRequest,
    actor: str = Depends(verify_admin_access),
) -> EnrolResponse:
    """Admin-only: registers a new collector and returns its one-time token."""
    result = enrol_collector(
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        os_version=payload.os_version,
        enrolled_by=actor,
    )
    collector = get_collector(result["collector_id"])
    device_node_id = collector.device_node_id if collector else f"device:{payload.hostname.lower()}"
    logger.info(
        "Collector enrolled: id=%s hostname=%s actor=%s",
        result["collector_id"], payload.hostname, actor,
    )
    return EnrolResponse(
        collector_id=result["collector_id"],
        token=result["token"],
        hostname=payload.hostname,
        device_node_id=device_node_id,
        message=(
            f"Collector '{payload.hostname}' enrolled successfully. "
            "Save the token now — it cannot be retrieved again."
        ),
    )


@router.get(
    "/overview",
    response_model=CollectorOverviewResponse,
    summary="Security Overview & Telemetry Dashboard",
    description="Returns centralized security overview: registered computers, online/offline collectors, event totals, auth failures, and infrastructure connectivity.",
)
async def get_overview_endpoint(
    actor: str = Depends(verify_admin_access),
    producer: Any = Depends(get_kafka_producer_dep),
) -> CollectorOverviewResponse:
    """Admin-only / Dashboard: returns high-level security overview and fleet telemetry status."""
    data = get_collector_overview()
    data["connectivity"] = get_connectivity_status(producer=producer)
    return CollectorOverviewResponse(**data)


@router.get(
    "/collectors",
    response_model=List[CollectorStatusResponse],
    summary="List Enrolled Collectors",
    description="Returns operational status of all registered collector endpoints.",
)
async def list_collectors_endpoint(
    actor: str = Depends(verify_admin_access),
) -> List[CollectorStatusResponse]:
    """Admin-only: lists all registered collectors."""
    return [
        CollectorStatusResponse(**c.to_dict())
        for c in list_collectors()
    ]


@router.get(
    "/collectors/{collector_id}",
    response_model=CollectorStatusResponse,
    summary="Get Collector Status",
    description="Returns operational status for a single collector endpoint.",
)
async def get_collector_endpoint(
    collector_id: str,
    actor: str = Depends(verify_admin_access),
) -> CollectorStatusResponse:
    """Admin-only: retrieves a single collector's operational status."""
    collector = get_collector(collector_id)
    if collector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{collector_id}' not found.",
        )
    return CollectorStatusResponse(**collector.to_dict())


@router.post(
    "/collectors/{collector_id}/revoke",
    summary="Revoke Collector Token",
    description="Permanently revokes a collector's authentication token. The device will no longer be able to submit events.",
)
async def revoke_collector_endpoint(
    collector_id: str,
    actor: str = Depends(verify_admin_access),
) -> Dict[str, str]:
    """Admin-only: revokes a collector's token."""
    found = revoke_collector(collector_id, actor)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Collector '{collector_id}' not found.",
        )
    logger.info("Collector %s revoked by actor %s", collector_id, actor)
    return {"message": f"Collector '{collector_id}' has been revoked.", "collector_id": collector_id, "status": "REVOKED"}


# ---------------------------------------------------------------------------
# Collector ingestion endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/ingest/events",
    response_model=CollectorIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit Windows Security Events",
    description=(
        "Authenticated endpoint for enrolled Windows collector agents to submit "
        "batches of Windows Security Event Log records. Events are normalised into "
        "SecurityEventEnvelope format and published to the existing Kafka pipeline. "
        "Requires X-Collector-ID and X-Collector-Token headers."
    ),
)
async def ingest_collector_events(
    request: Request,
    payload: CollectorIngestRequest,
    collector=Depends(_get_collector_credentials),
    producer: Any = Depends(get_kafka_producer_dep),
) -> CollectorIngestResponse:
    """
    Ingestion endpoint for enrolled Windows collector agents.

    Processing order:
    1. Rate limit check
    2. Batch size hard cap
    3. Normalise raw Windows events -> SecurityEventEnvelope
    4. Dedup: skip event IDs already seen in this process
    5. Publish valid envelopes to Kafka (existing producer)
    6. Update collector last-seen and event counter
    """
    collector_id = collector.collector_id
    device_node_id = collector.device_node_id

    # 1. Rate limit
    if not check_rate_limit(collector_id):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please reduce the submission frequency.",
            headers={"Retry-After": "60"},
        )

    # 2. Request body size check & Hard batch-size cap
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > config.COLLECTOR_MAX_REQUEST_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request body exceeds maximum allowed size ({config.COLLECTOR_MAX_REQUEST_SIZE_BYTES} bytes).",
        )

    max_batch = config.COLLECTOR_MAX_EVENTS_PER_BATCH
    if len(payload.events) > max_batch:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch size {len(payload.events)} exceeds maximum {max_batch} events per request.",
        )

    # 3. Convert to dicts and enforce source computer anti-spoofing
    auth_host_norm = collector.hostname.lower().split(".")[0].strip()
    raw_records = []
    for e in payload.events:
        d = e.model_dump()
        raw_source = (d.get("source_computer") or "").strip()
        raw_source_norm = raw_source.lower().split(".")[0].strip()
        if raw_source_norm and raw_source_norm != auth_host_norm:
            logger.warning(
                "Collector %s (%s) attempted source impersonation: claimed source_computer='%s'. Binding to authentic host.",
                collector_id, collector.hostname, raw_source
            )
            d["claimed_source_computer"] = raw_source
            d["impersonation_prevented"] = True
            d["source_computer"] = collector.hostname  # Bound to authenticated identity!
        elif not raw_source:
            d["source_computer"] = collector.hostname
        raw_records.append(d)

    # 4. Normalise
    envelopes, rejected = normalize_windows_events(raw_records, collector_id, device_node_id)

    rejected_count = len(rejected)
    accepted_count = len(envelopes)
    duplicate_count = 0
    published_count = 0
    errors: List[str] = [r.get("reason", "unknown") for r in rejected]

    # 5. Dedup + publish
    for envelope in envelopes:
        if is_duplicate(envelope.event_id):
            duplicate_count += 1
            continue

        try:
            producer.publish_security_event(envelope)
            mark_seen(envelope.event_id)
            published_count += 1
        except Exception as exc:
            errors.append(f"Publish failed for {envelope.event_id}: {type(exc).__name__}")
            logger.error(
                "Failed to publish event %s from collector %s: %s",
                envelope.event_id, collector_id, exc,
            )

    # 6. Update collector telemetry and stream activity
    last_err = errors[-1] if errors else None
    record_event_delivery(
        collector_id,
        count=published_count,
        error=last_err,
        accepted=accepted_count,
        rejected=rejected_count,
        pending_spool_events=payload.pending_spool_events,
    )

    is_synthetic = any(
        getattr(e, "payload", {}).get("is_synthetic", False)
        for e in envelopes
    )
    record_ingestion_activity(
        collector_id=collector_id,
        hostname=collector.hostname,
        accepted=accepted_count,
        rejected=rejected_count,
        duplicate=duplicate_count,
        published=published_count,
        is_synthetic=is_synthetic,
        errors=errors[:10],
        pending_spool_events=payload.pending_spool_events,
    )

    logger.info(
        "Collector %s (%s): accepted=%d rejected=%d duplicate=%d published=%d pending_spool=%s",
        collector_id, collector.hostname,
        accepted_count, rejected_count, duplicate_count, published_count,
        payload.pending_spool_events,
    )

    return CollectorIngestResponse(
        accepted=accepted_count,
        rejected=rejected_count,
        duplicate=duplicate_count,
        published=published_count,
        errors=errors[:20],  # cap error list in response
        collector_id=collector_id,
    )

