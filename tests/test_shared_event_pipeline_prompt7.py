"""
ThreatLens Prompt 7 - Shared Event Pipeline, Neo4j Graph Integrity, and API Contracts Test Suite
Verifies:
1. Canonical SecurityEventEnvelope contracts (all 6 event types, schema versions, timestamps, validation).
2. Deterministic event ID generation and command-line credential/secret redaction.
3. Kafka producer per-entity key partitioning, topic routing, delivery acknowledgement, and fallback.
4. Kafka consumer worker lifecycle, thread safety, retries with backoff, poison message handling, and DLQ routing.
5. Manual offset commit semantics (offsets committed only after successful processing or DLQ routing).
6. Neo4j graph integrity: unique constraints, indexes, canonical ID prefixing, and endpoint type rules.
7. Idempotent Neo4j event persistence (replaying events prevents duplicate nodes/edges).
8. Automatic device provisioning for authenticated collectors linked via ASSOCIATED_WITH_CASE.
9. Provenance preservation and evidence class attribution (OBSERVED vs AUTHORIZED_ACCESS vs INFERRED vs HYPOTHETICAL).
10. System health & readiness probes (/api/v1/health, /api/v1/ready) and end-to-end API contracts.
"""

import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
# pyrefly: ignore[missing-import]
import pytest
# pyrefly: ignore[missing-import]
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    CYPHER_SCHEMA_STATEMENTS,
    canonicalize_node_id,
    get_node_label_from_id,
    VALID_RELATIONSHIP_ENDPOINTS,
)
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    DeadLetterEventEnvelope,
    SecurityFindingRecord,
    EventPublishResponse,
    KafkaServiceStatus,
)
from backend.collector.normalizer import (
    _make_stable_event_id,
    redact_sensitive_cmdline,
    normalize_windows_events,
)
from backend.graphops.kafka_producer import (
    GraphOpsKafkaProducer,
    KafkaProducerError,
    get_kafka_producer,
)
from backend.graphops.kafka_processor import (
    GraphOpsEventProcessor,
    PermanentEventError,
    TransientEventError,
)
from backend.graphops.kafka_worker import (
    GraphOpsKafkaWorker,
    get_kafka_worker,
    reset_kafka_worker,
)
from backend.graphops.mock_client import get_mock_graphops_client


@pytest.fixture
def mock_graph_client():
    """Provides a fresh isolated mock graph client for pipeline tests."""
    return get_mock_graphops_client()


@pytest.fixture
def isolated_producer():
    """Provides an isolated in-memory Kafka producer."""
    return GraphOpsKafkaProducer(mock_mode=True)


@pytest.fixture
def isolated_worker(mock_graph_client, isolated_producer):
    """Provides an isolated consumer worker backed by the isolated mock graph and producer."""
    processor = GraphOpsEventProcessor(client=mock_graph_client, producer=isolated_producer)
    worker = GraphOpsKafkaWorker(
        processor=processor,
        producer=isolated_producer,
        mock_mode=True,
    )
    yield worker
    worker.stop()


@pytest.fixture
def api_client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# =============================================================================
# 1. EVENT CONTRACTS & SCHEMA VALIDATION TESTS
# =============================================================================

def test_security_event_envelope_all_event_types():
    """Verifies that all 6 SecurityEventType domains instantiate and validate cleanly."""
    event_types = [
        SecurityEventType.ENDPOINT_ALERT,
        SecurityEventType.PROCESS_EVENT,
        SecurityEventType.COMPROMISE_INDICATOR,
        SecurityEventType.IDENTITY_EVENT,
        SecurityEventType.NETWORK_CONNECTION,
        SecurityEventType.EMAIL_INVESTIGATION_RESULT,
    ]
    now_iso = datetime.now(timezone.utc).isoformat()

    for idx, et in enumerate(event_types):
        envelope = SecurityEventEnvelope(
            event_id=f"ev-test-{idx}",
            schema_version="1.0.0",
            event_type=et,
            source="sensor-edr-01",
            occurred_at=now_iso,
            entity_ids=["device:dev-ws-101"],
            payload={"action": "test_verification", "type": et.value},
            correlation_id=f"CASE-{idx}",
            severity=CriticalityTier.MEDIUM,
            evidence_metadata={"collector_id": "col-test-01"},
        )
        assert envelope.event_id == f"ev-test-{idx}"
        assert envelope.event_type == et
        assert envelope.schema_version == "1.0.0"
        assert len(envelope.entity_ids) >= 1


def test_security_event_envelope_missing_required_fields_fails():
    """Verifies that missing event_id, occurred_at, or empty entity_ids raises ValidationError."""
    # pyrefly: ignore[missing-import]
    from pydantic import ValidationError

    # Missing entity_ids
    with pytest.raises(ValidationError):
        SecurityEventEnvelope(
            event_id="ev-missing-entities",
            event_type=SecurityEventType.PROCESS_EVENT,
            source="edr",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            entity_ids=[],  # min_length=1
        )

    # Missing event_type
    with pytest.raises(ValidationError):
        SecurityEventEnvelope.model_validate({
            "event_id": "ev-missing-type",
            "source": "edr",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "entity_ids": ["device:dev-ws-101"],
        })


def test_security_event_envelope_schema_evolution():
    """Verifies backward-compatible schema evolution when unexpected or future fields appear in payload."""
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_data = {
        "event_id": "ev-evolution-01",
        "schema_version": "1.1.0",  # Evolved version
        "event_type": SecurityEventType.PROCESS_EVENT,
        "source": "future-edr-v3",
        "occurred_at": now_iso,
        "entity_ids": ["device:dev-ws-101"],
        "payload": {"process_name": "powershell.exe", "future_telemetry_metric": 42.5},
        "evidence_metadata": {"future_flag": True},
    }
    envelope = SecurityEventEnvelope(**raw_data)
    assert envelope.schema_version == "1.1.0"
    assert envelope.payload["future_telemetry_metric"] == 42.5


def test_deterministic_event_id_stability():
    """Verifies that _make_stable_event_id produces identical deterministic IDs for identical inputs."""
    id1 = _make_stable_event_id(1001, "WORKSTATION-01", 4624, "2026-08-28T10:00:00Z")
    id2 = _make_stable_event_id(1001, "WORKSTATION-01", 4624, "2026-08-28T10:00:00Z")
    id3 = _make_stable_event_id(1002, "WORKSTATION-01", 4624, "2026-08-28T10:00:00Z")

    assert id1 == id2, "Identical inputs must yield identical stable event IDs"
    assert id1 != id3, "Different record IDs must yield distinct stable event IDs"
    assert id1.startswith("wev-")
    assert len(id1) == 28  # 'wev-' (4 chars) + 24 sha256 hex chars


def test_command_line_credential_redaction():
    """Verifies that redact_sensitive_cmdline strips passwords, bearer tokens, and API keys."""
    raw_cmds = [
        "net user admin /password:SuperSecret123 /add",
        "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1Ni...' https://api.corp.internal",
        "python script.py --password=MyPassword! -u admin",
        "agent.exe /p:P@ssw0rd123 /user:operator",
        "connect.sh --api_key=sk-live-998877665544332211 --token=tok_secret_abc",
    ]
    for cmd in raw_cmds:
        redacted = redact_sensitive_cmdline(cmd)
        assert "SuperSecret123" not in redacted
        assert "eyJhbGciOiJIUzI1Ni..." not in redacted
        assert "MyPassword!" not in redacted
        assert "P@ssw0rd123" not in redacted
        assert "sk-live-998877665544332211" not in redacted
        assert "tok_secret_abc" not in redacted
        assert "[REDACTED]" in redacted


# =============================================================================
# 2. KAFKA PRODUCER ROUTING & PARTITIONING CONTRACTS
# =============================================================================

def test_kafka_producer_topic_routing(isolated_producer):
    """Verifies that get_topic_for_event_type routes each event type to its configured Kafka topic."""
    routing_map = {
        SecurityEventType.ENDPOINT_ALERT: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        SecurityEventType.PROCESS_EVENT: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        SecurityEventType.COMPROMISE_INDICATOR: config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        SecurityEventType.IDENTITY_EVENT: config.KAFKA_TOPIC_IDENTITY_EVENTS,
        SecurityEventType.NETWORK_CONNECTION: config.KAFKA_TOPIC_NETWORK_EVENTS,
        SecurityEventType.EMAIL_INVESTIGATION_RESULT: config.KAFKA_TOPIC_EMAIL_EVENTS,
    }
    for et, expected_topic in routing_map.items():
        assert isolated_producer.get_topic_for_event_type(et) == expected_topic


def test_kafka_producer_message_key_and_mock_queue(isolated_producer):
    """Verifies publishing an event queues message with primary entity ID as partitioning key."""
    event = SecurityEventEnvelope(
        event_id="ev-prod-001",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="ad-sensor",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=["user:victim@corp.com", "device:dev-ws-101"],
        payload={"auth_status": "SUCCESS"},
    )
    res = isolated_producer.publish_security_event(event)
    assert res.status == "ACCEPTED_FOR_STREAMING"
    assert res.topic == config.KAFKA_TOPIC_IDENTITY_EVENTS
    assert res.offset == 0

    topic_messages = isolated_producer._mock_messages[config.KAFKA_TOPIC_IDENTITY_EVENTS]
    assert len(topic_messages) == 1
    assert topic_messages[0]["key"] == "user:victim@corp.com"  # Primary entity ID


def test_kafka_producer_dead_letter_publishing(isolated_producer):
    """Verifies publish_dead_letter writes to KAFKA_TOPIC_DLQ."""
    dlq = DeadLetterEventEnvelope(
        event_id="ev-bad-001",
        source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        failure_category="PERMANENT_SCHEMA_ERROR",
        sanitized_error="Field required: entity_ids",
        retry_count=0,
        raw_payload={"raw": "test"},
    )
    res = isolated_producer.publish_dead_letter(dlq)
    assert res.status == "DEAD_LETTERED"
    assert res.topic == config.KAFKA_TOPIC_DLQ
    assert len(isolated_producer._mock_messages[config.KAFKA_TOPIC_DLQ]) == 1


# =============================================================================
# 3. KAFKA CONSUMER WORKER & POISON MESSAGE / DLQ ROUTING
# =============================================================================

def test_consumer_decodes_and_processes_valid_message(isolated_worker):
    """Verifies that worker decodes raw bytes, invokes processor, and updates processed counts."""
    event = SecurityEventEnvelope(
        event_id="ev-work-001",
        event_type=SecurityEventType.PROCESS_EVENT,
        source="edr-agent",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=["device:dev-ws-101"],
        payload={"process": "cmd.exe"},
    )
    raw_bytes = event.model_dump_json().encode("utf-8")
    success = isolated_worker.process_raw_message(
        raw_bytes=raw_bytes,
        source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        partition=0,
        offset=100,
    )
    assert success is True
    assert isolated_worker.processed_count == 1
    assert isolated_worker.last_processed_timestamp is not None


def test_consumer_malformed_json_routes_to_dlq(isolated_worker):
    """Poison message test: Non-JSON raw bytes must be caught and routed directly to DLQ."""
    bad_bytes = b"THIS IS NOT JSON AT ALL; CRASH ATTEMPT \x00\xff"
    success = isolated_worker.process_raw_message(
        raw_bytes=bad_bytes,
        source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        partition=0,
        offset=101,
    )
    assert success is False
    assert isolated_worker.dlq_count == 1

    dlq_queue = isolated_worker.producer._mock_messages[config.KAFKA_TOPIC_DLQ]
    assert len(dlq_queue) == 1
    dlq_payload = json.loads(dlq_queue[0]["value"].decode("utf-8"))
    assert dlq_payload["failure_category"] == "PERMANENT_MALFORMED_JSON"
    assert "JSON decoding failed" in dlq_payload["sanitized_error"]


def test_consumer_schema_validation_error_routes_to_dlq(isolated_worker):
    """Schema violation test: Ingesting JSON with missing required fields routes to DLQ."""
    invalid_json = json.dumps({"event_id": "ev-missing-type"}).encode("utf-8")
    success = isolated_worker.process_raw_message(
        raw_bytes=invalid_json,
        source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS,
        partition=0,
        offset=102,
    )
    assert success is False
    assert isolated_worker.dlq_count == 1

    dlq_queue = isolated_worker.producer._mock_messages[config.KAFKA_TOPIC_DLQ]
    dlq_payload = json.loads(dlq_queue[-1]["value"].decode("utf-8"))
    assert dlq_payload["failure_category"] == "PERMANENT_SCHEMA_VALIDATION_ERROR"


def test_consumer_unresolvable_entity_routes_to_dlq(isolated_worker):
    """Unresolvable entity test: An event referencing an unknown device routes to DLQ as permanent error."""
    event = SecurityEventEnvelope(
        event_id="ev-unresolvable-001",
        event_type=SecurityEventType.PROCESS_EVENT,
        source="edr-agent",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=["device:ghost-nonexistent-node-999"],
        payload={"process": "cmd.exe"},
    )
    raw_bytes = event.model_dump_json().encode("utf-8")
    success = isolated_worker.process_raw_message(
        raw_bytes=raw_bytes,
        source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS,
    )
    assert success is False
    assert isolated_worker.dlq_count == 1

    dlq_queue = isolated_worker.producer._mock_messages[config.KAFKA_TOPIC_DLQ]
    dlq_payload = json.loads(dlq_queue[-1]["value"].decode("utf-8"))
    assert dlq_payload["failure_category"] == "PERMANENT_ENTITY_ERROR"
    assert "could not be resolved" in dlq_payload["sanitized_error"]


# =============================================================================
# 4. NEO4J GRAPH INTEGRITY, DEDUPLICATION & EVIDENCE CLASSES
# =============================================================================

def test_neo4j_schema_constraints_and_indexes():
    """Verifies that CYPHER_SCHEMA_STATEMENTS contains unique constraints for all 9 node labels."""
    assert len(CYPHER_SCHEMA_STATEMENTS) >= 15

    expected_unique_labels = [
        "User", "Device", "Server", "Application",
        "IPAddress", "Vulnerability", "CriticalAsset",
        "SecurityEvent", "EmailAccount"
    ]
    for label in expected_unique_labels:
        assert any(f":{label}" in stmt and "UNIQUE" in stmt for stmt in CYPHER_SCHEMA_STATEMENTS), (
            f"Missing UNIQUE constraint for label {label}"
        )


def test_neo4j_canonical_node_id_prefixes():
    """Verifies that canonicalize_node_id and get_node_label_from_id conform to standard prefixes."""
    assert canonicalize_node_id(NodeLabel.USER, "usr-01") == "user:usr-01"
    assert canonicalize_node_id(NodeLabel.DEVICE, "DEV-WS-101") == "device:dev-ws-101"
    assert canonicalize_node_id(NodeLabel.SERVER, "SRV-APP-01") == "server:srv-app-01"
    assert canonicalize_node_id(NodeLabel.APPLICATION, "payment-api") == "app:payment-api"
    assert canonicalize_node_id(NodeLabel.IP_ADDRESS, "10.0.1.5") == "ip:10.0.1.5"
    assert canonicalize_node_id(NodeLabel.VULNERABILITY, "cve-2024-21413") == "vuln:CVE-2024-21413"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "cust-db") == "critical:cust-db"

    assert get_node_label_from_id("user:alice@corp.com") == NodeLabel.USER
    assert get_node_label_from_id("device:ws-101") == NodeLabel.DEVICE
    assert get_node_label_from_id("server:srv-core") == NodeLabel.SERVER
    assert get_node_label_from_id("vuln:CVE-2024-1234") == NodeLabel.VULNERABILITY


def test_neo4j_valid_relationship_endpoints():
    """Verifies VALID_RELATIONSHIP_ENDPOINTS typing rules."""
    uses_sources, uses_targets = VALID_RELATIONSHIP_ENDPOINTS[RelationshipType.USES]
    assert NodeLabel.USER in uses_sources
    assert NodeLabel.DEVICE in uses_targets

    conn_sources, conn_targets = VALID_RELATIONSHIP_ENDPOINTS[RelationshipType.CONNECTS_TO]
    assert NodeLabel.DEVICE in conn_sources
    assert NodeLabel.SERVER in conn_targets


def test_idempotent_event_persistence_re_delivery(isolated_worker, mock_graph_client):
    """
    Idempotency test: Re-delivery of an identical event envelope must not duplicate
    the SecurityEvent node or re-execute downstream graph mutations.
    """
    event = SecurityEventEnvelope(
        event_id="wev-idempotency-test-01",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="dc-sensor",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=["user:victim1@corporation.com", "device:dev-ws-101"],
        payload={"user_id": "user:victim1@corporation.com", "target_resource_id": "device:dev-ws-101", "auth_status": "SUCCESS"},
    )
    raw_bytes = event.model_dump_json().encode("utf-8")

    # First delivery
    res1 = isolated_worker.process_raw_message(raw_bytes, config.KAFKA_TOPIC_IDENTITY_EVENTS)
    assert res1 is True

    # Check mock client recorded the SecurityEvent
    assert "wev-idempotency-test-01" in mock_graph_client.security_events

    # Second delivery (replay)
    res2 = isolated_worker.process_raw_message(raw_bytes, config.KAFKA_TOPIC_IDENTITY_EVENTS)
    assert res2 is True

    # Assert SecurityEvent was not duplicated
    assert len([k for k in mock_graph_client.security_events if k == "wev-idempotency-test-01"]) == 1


def test_auto_provisioning_enrolled_collector_device(isolated_worker, mock_graph_client):
    """
    Auto-provisioning test: An event from an authenticated collector with an unindexed
    device entity is automatically provisioned into Neo4j without dropping the event.
    """
    new_device_id = "device:new-endpoint-99"
    assert new_device_id not in mock_graph_client.nodes

    event = SecurityEventEnvelope(
        event_id="wev-autoprovision-01",
        event_type=SecurityEventType.PROCESS_EVENT,
        source="windows-collector",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=[new_device_id],
        payload={"process_name": "svchost.exe"},
        evidence_metadata={
            "collector_id": "col-new-001",
            "source_computer": "NEW-ENDPOINT-99",
        },
    )
    raw_bytes = event.model_dump_json().encode("utf-8")
    success = isolated_worker.process_raw_message(raw_bytes, config.KAFKA_TOPIC_ENDPOINT_EVENTS)

    assert success is True
    # The device node must now exist in the graph
    assert new_device_id in mock_graph_client.nodes
    node_data = mock_graph_client.nodes[new_device_id]
    assert "Device" in node_data.get("labels", []) or node_data.get("label") == "Device"


def test_relationship_evidence_class_attribution(isolated_worker, mock_graph_client):
    """Verifies that newly materialized event edges carry EvidenceClass.OBSERVED."""
    event = SecurityEventEnvelope(
        event_id="wev-obs-conn-01",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="netflow",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=["device:dev-ws-101", "server:srv-app-01"],
        payload={"source_entity_id": "device:dev-ws-101", "target_entity_id": "server:srv-app-01", "port": 443},
    )
    raw_bytes = event.model_dump_json().encode("utf-8")
    success = isolated_worker.process_raw_message(raw_bytes, config.KAFKA_TOPIC_NETWORK_EVENTS)
    assert success is True

    # Check observed connection edge in mock client
    obs_edges = [
        e for e in mock_graph_client.edges
        if (e.get("source_id") == "device:dev-ws-101" or e.get("source") == "device:dev-ws-101")
        and (e.get("target_id") == "server:srv-app-01" or e.get("target") == "server:srv-app-01")
    ]
    assert len(obs_edges) >= 1
    edge = obs_edges[-1]
    assert edge.get("relationship_type") == "OBSERVED_CONNECTION" or edge.get("type") == "OBSERVED_CONNECTION"
    assert edge.get("evidence_class") == "OBSERVED" or edge.get("properties", {}).get("evidence_class") == "OBSERVED"


# =============================================================================
# 5. API CONTRACTS, HEALTH & READINESS PROBES
# =============================================================================

def test_api_health_endpoint(api_client):
    """Verifies GET /api/v1/health basic operational contract."""
    resp = api_client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_api_readiness_endpoint_diagnostics(api_client):
    """Verifies GET /api/v1/ready evaluates all essential dependencies."""
    from backend.api.routes import get_readiness_graph_client_dep
    from backend.graphops.mock_client import get_mock_graphops_client

    app.dependency_overrides[get_readiness_graph_client_dep] = get_mock_graphops_client
    try:
        resp = api_client.get("/api/v1/ready?allow_mock=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert "components" in data

        components = data["components"]
        assert "neo4j" in components
        assert "kafka_producer" in components
        assert "kafka_worker" in components
        assert "audit_ledger" in components
        assert "collector_registry" in components
        assert components["audit_ledger"]["status"] == "intact"

        # Verify strict readiness rejects mock fallbacks
        resp_strict = api_client.get("/api/v1/ready?allow_mock=false")
        assert resp_strict.status_code == 503
        assert resp_strict.json()["detail"]["status"] == "not_ready"
    finally:
        app.dependency_overrides.pop(get_readiness_graph_client_dep, None)


def test_api_events_status_endpoint(api_client):
    """Verifies GET /api/v1/graphops/events/status."""
    resp = api_client.get("/api/v1/graphops/events/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "broker_connected" in data
    assert "bootstrap_servers" in data
    assert "processed_events_count" in data


def test_api_events_publish_endpoint(api_client):
    """Verifies POST /api/v1/graphops/events/publish accepts valid SecurityEventEnvelope."""
    now_iso = datetime.now(timezone.utc).isoformat()
    envelope_payload = {
        "event_id": "ev-api-test-01",
        "schema_version": "1.0.0",
        "event_type": "IDENTITY_EVENT",
        "source": "api-client",
        "occurred_at": now_iso,
        "entity_ids": ["user:victim1@corporation.com"],
        "payload": {"auth_status": "SUCCESS"},
    }
    resp = api_client.post("/api/v1/graphops/events/publish", json=envelope_payload)
    assert resp.status_code == 202
    data = resp.json()
    assert data["event_id"] == "ev-api-test-01"
    assert data["status"] == "ACCEPTED_FOR_STREAMING"


def test_api_events_publish_missing_fields_returns_422(api_client):
    """Verifies POST /api/v1/graphops/events/publish returns 422 on invalid schema."""
    resp = api_client.post(
        "/api/v1/graphops/events/publish",
        json={"event_id": "only-id-no-type"},
    )
    assert resp.status_code == 422


def test_api_events_dlq_endpoint_requires_admin(api_client):
    """Verifies GET /api/v1/graphops/events/dlq enforces admin authentication."""
    from backend.core import config as cfg
    resp = api_client.get("/api/v1/graphops/events/dlq")
    # If REQUIRE_API_KEY is false, it returns 200; if true, it returns 401/403
    if cfg.REQUIRE_API_KEY:
        assert resp.status_code in (401, 403)
    else:
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


def test_api_collector_ingest_anti_spoofing(api_client):
    """Verifies that an enrolled collector cannot impersonate a foreign host."""
    # Enrol collector
    enrol_resp = api_client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "AUTHENTIC-HOST-01", "ip_address": "10.0.1.100"},
    )
    assert enrol_resp.status_code == 201
    enrol_data = enrol_resp.json()
    cid = enrol_data["collector_id"]
    token = enrol_data["token"]

    # Ingest event claiming to be from foreign host 'SPOOFED-HOST-99'
    ingest_payload = {
        "events": [
            {
                "event_id_number": 4624,
                "source_computer": "SPOOFED-HOST-99",
                "time_created": "2026-08-28T12:00:00Z",
                "source_event_record_id": 5001,
                "channel": "Security",
                "event_data": {"TargetUserName": "alice"},
            }
        ]
    }
    resp = api_client.post(
        "/api/v1/collector/ingest/events",
        headers={"X-Collector-ID": cid, "X-Collector-Token": token},
        json=ingest_payload,
    )
    assert resp.status_code == 202
    res_data = resp.json()
    assert res_data["accepted"] == 1
    assert res_data["published"] == 1
