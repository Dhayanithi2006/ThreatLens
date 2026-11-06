"""
ThreatLens - Module 0: Overview & Remote Telemetry Verification Test Suite
========================================================================

Comprehensive validation for all 8 submodules:
1. Security Overview Dashboard (API metrics, Neo4j, Kafka status, live activity stream)
2. Remote Windows Computer Management (enrollment, details inspection, revocation)
3. Collector Device Registry (unique IDs, HMAC token digests, persistence, status machine)
4. Endpoint Enrollment & Authentication (token digests, 401 rejection, auth failure tracking, DPAPI)
5. Collector Health & Event Monitoring (accepted/rejected counters, pending spool tracking)
6. Windows Event Collection (IDs 4624, 4625, 4688, 5140, checkpointing)
7. Event Normalization & Deduplication (schema, UTC timestamps, sensitive redaction, synthetic vs genuine)
8. Offline Spool Queue (offline persistence, FIFO drainage, unacknowledged preservation)
"""

import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.collector.registry import (
    CollectorRecord,
    enrol_collector,
    authenticate_collector,
    revoke_collector,
    record_auth_failure,
    record_ingestion_activity,
    record_event_delivery,
    get_collector_overview,
    list_collectors,
    get_collector,
)
from backend.collector.normalizer import (
    WindowsEventNormalizer,
    normalize_windows_events,
    redact_sensitive_cmdline,
)
from backend.models.graphops import SecurityEventType, SecurityEventEnvelope
from backend.collector.dedup import is_duplicate, mark_seen, _cache
from backend.collector.rate_limiter import _request_windows
from collector.threatlens_collector import (
    SpoolManager,
    CheckpointManager,
    protect_token_dpapi,
    unprotect_token_dpapi,
)


@pytest.fixture(autouse=True)
def setup_module0_env(tmp_path, monkeypatch):
    """Isolate registry and stats paths in a temporary test directory."""
    test_reg = tmp_path / "mod0_registry.json"
    test_stats = tmp_path / "mod0_registry_telemetry_stats.json"
    monkeypatch.setattr("backend.collector.registry._REGISTRY_PATH", test_reg)
    monkeypatch.setattr(config, "COLLECTOR_REGISTRY_PATH", str(test_reg))
    monkeypatch.setattr(config, "REQUIRE_API_KEY", False)
    _cache.clear()
    _request_windows.clear()
    yield
    _cache.clear()
    _request_windows.clear()


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# SUBMODULE 1: SECURITY OVERVIEW DASHBOARD
# =============================================================================
def test_submodule1_security_overview_dashboard(client):
    """
    Verify centralized overview dashboard:
    - Total registered devices
    - Online and offline collectors
    - Total events received
    - Auth failures count
    - Ingestion errors count
    - Neo4j and Kafka connectivity status
    - Recent ingestion activity stream
    """
    # Enrol two computers
    resp1 = client.post("/api/v1/collector/enrol", json={"hostname": "CORP-WIN11-01", "ip_address": "10.0.1.10"})
    assert resp1.status_code == 201
    col1 = resp1.json()

    resp2 = client.post("/api/v1/collector/enrol", json={"hostname": "CORP-WIN11-02", "ip_address": "10.0.1.11"})
    assert resp2.status_code == 201
    col2 = resp2.json()

    # Submit an event from col1 so it becomes online ("ACTIVELY SENDING")
    event_payload = {
        "events": [
            {
                "event_id_number": 4624,
                "channel": "Security",
                "source_computer": "CORP-WIN11-01",
                "time_created": datetime.now(timezone.utc).isoformat(),
                "source_event_record_id": 1001,
                "event_data": {
                    "TargetUserName": "admin_jdoe",
                    "TargetDomainName": "CORP",
                    "LogonType": "2",
                    "IpAddress": "127.0.0.1",
                },
            }
        ],
        "pending_spool_events": 0,
    }
    ingest_resp = client.post(
        "/api/v1/collector/ingest/events",
        json=event_payload,
        headers={
            "X-Collector-ID": col1["collector_id"],
            "X-Collector-Token": col1["token"],
        },
    )
    assert ingest_resp.status_code == 202

    # Query the dedicated collector overview endpoint
    ov_resp = client.get("/api/v1/collector/overview")
    assert ov_resp.status_code == 200
    ov = ov_resp.json()

    assert ov["total_registered_devices"] == 2
    assert ov["online_collectors"] == 1
    assert ov["offline_collectors"] == 1  # col2 has not sent events yet
    assert ov["total_events_received"] >= 1
    assert "connectivity" in ov
    assert "neo4j" in ov["connectivity"]
    assert "kafka" in ov["connectivity"]
    assert len(ov["recent_ingestion_activity"]) >= 1
    act = ov["recent_ingestion_activity"][0]
    assert act["collector_id"] == col1["collector_id"]
    assert act["hostname"] == "CORP-WIN11-01"
    assert act["accepted"] == 1
    assert act["is_synthetic"] is False

    # Also query the unified /api/v1/overview endpoint
    main_ov_resp = client.get("/api/v1/overview")
    assert main_ov_resp.status_code == 200
    main_ov = main_ov_resp.json()
    assert "telemetry_fleet" in main_ov
    assert main_ov["telemetry_fleet"]["total_registered_devices"] == 2
    assert main_ov["telemetry_fleet"]["online_collectors"] == 1
    assert main_ov["telemetry_fleet"]["offline_collectors"] == 1
    assert "neo4j_status" in main_ov
    assert main_ov["neo4j_status"] in ("CONNECTED", "MOCK_CONNECTED", "DISCONNECTED")
    assert "kafka_status" in main_ov
    assert main_ov["kafka_status"] in ("CONNECTED", "MOCK_CONNECTED", "DISCONNECTED")


# =============================================================================
# SUBMODULE 2: REMOTE WINDOWS COMPUTER MANAGEMENT
# =============================================================================
def test_submodule2_remote_windows_computer_management(client):
    """
    Verify remote Windows endpoint management:
    - Device registration & identification
    - Computer details inspection
    - Status management and tracking
    - Credential revocation
    """
    # Enrol computer
    enrol_resp = client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "DESKTOP-FINANCE-04", "ip_address": "192.168.10.45", "os_version": "Windows 11 Pro"},
    )
    assert enrol_resp.status_code == 201
    data = enrol_resp.json()
    cid = data["collector_id"]

    # Retrieve individual details
    detail_resp = client.get(f"/api/v1/collector/collectors/{cid}")
    assert detail_resp.status_code == 200
    details = detail_resp.json()
    assert details["hostname"] == "DESKTOP-FINANCE-04"
    assert details["device_node_id"] == "device:desktop-finance-04"
    assert details["os_version"] == "Windows 11 Pro"
    assert details["ip_address"] == "192.168.10.45"
    assert details["online_status"] == "ENROLLED (PENDING)"
    assert details["is_online"] is False
    assert details["pending_spool_events"] == 0

    # Revoke computer credentials
    revoke_resp = client.post(f"/api/v1/collector/collectors/{cid}/revoke")
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"

    # Verify status is now REVOKED
    revoked_detail = client.get(f"/api/v1/collector/collectors/{cid}").json()
    assert revoked_detail["status"] == "REVOKED"
    assert revoked_detail["online_status"] == "REVOKED"
    assert revoked_detail["is_online"] is False


# =============================================================================
# SUBMODULE 3: COLLECTOR DEVICE REGISTRY
# =============================================================================
def test_submodule3_device_registry():
    """
    Verify device registry internals:
    - Unique device and collector IDs
    - Secure token generation and HMAC-SHA256 validation
    - Multi-process persistence
    - Status lifecycle management
    """
    # Create registry and enrol device
    res = enrol_collector("SERVER-DC-01", "10.0.0.1", "Windows 11", "admin")
    cid = res["collector_id"]
    token = res["token"]
    rec = get_collector(cid)
    assert rec.collector_id.startswith("col-")
    assert rec.device_node_id == "device:server-dc-01"
    assert rec.status == "ENROLLED"
    assert rec.online_status() == "ENROLLED (PENDING)"
    assert rec.is_online() is False

    # Authenticate with valid token
    authed_rec = authenticate_collector(rec.collector_id, token)
    assert authed_rec is not None
    assert authed_rec.collector_id == rec.collector_id

    # Check persistence: load fresh registry from disk
    fresh_list = list_collectors()
    assert any(c.collector_id == rec.collector_id for c in fresh_list)

    # Test status transitions:
    # 1. Update last_seen to now -> ACTIVELY SENDING
    now = datetime.now(timezone.utc)
    rec.last_seen = now.isoformat()
    rec.event_count = 5
    rec.status = "ACTIVE"
    assert rec.online_status() == "ACTIVELY SENDING"
    assert rec.is_online() is True

    # 2. Update last_seen to 20 minutes ago -> CONNECTED (IDLE)
    rec.last_seen = (now - timedelta(minutes=20)).isoformat()
    assert rec.online_status() == "CONNECTED (IDLE)"
    assert rec.is_online() is False

    # 3. Add errors -> DEGRADED
    rec.error_count = 5
    rec.recent_errors = ["SocketTimeout"]
    assert rec.online_status() == "DEGRADED"
    assert rec.is_online() is False

    # 4. Revocation -> REVOKED
    revoke_collector(rec.collector_id)
    revoked_rec = get_collector(rec.collector_id)
    assert revoked_rec.status == "REVOKED"
    assert revoked_rec.online_status() == "REVOKED"
    assert revoked_rec.is_online() is False


# =============================================================================
# SUBMODULE 4: ENDPOINT ENROLLMENT & AUTHENTICATION
# =============================================================================
def test_submodule4_endpoint_enrollment_and_authentication(client):
    """
    Verify enrollment security:
    - Token digests stored, plaintext NEVER stored
    - Rejection of missing, invalid and revoked credentials
    - Audit logging of authentication failures
    - DPAPI secret protection compatibility
    """
    # Enrol a collector
    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "HR-DESKTOP-09"})
    assert enrol_resp.status_code == 201
    creds = enrol_resp.json()
    cid = creds["collector_id"]
    token = creds["token"]

    # Check registry file on disk: verify token is NOT stored in plaintext
    with open(config.COLLECTOR_REGISTRY_PATH, "r", encoding="utf-8") as f:
        disk_data = json.load(f)
    stored_record = disk_data[cid]
    assert "token" not in stored_record
    assert "token_digest" in stored_record
    assert stored_record["token_digest"] != token
    assert len(stored_record["token_digest"]) == 64  # SHA-256 hex digest

    sample_event = {
        "event_id_number": 4624,
        "source_computer": "HR-DESKTOP-09",
        "time_created": "2026-11-05T12:00:00Z",
        "source_event_record_id": 1,
    }

    # Reject missing credentials
    bad_req1 = client.post("/api/v1/collector/ingest/events", json={"events": [sample_event]})
    assert bad_req1.status_code == 401

    # Reject incorrect token
    bad_req2 = client.post(
        "/api/v1/collector/ingest/events",
        json={"events": [sample_event]},
        headers={"X-Collector-ID": cid, "X-Collector-Token": "invalid_wrong_secret"},
    )
    assert bad_req2.status_code == 401
    assert "Invalid or revoked collector credentials" in bad_req2.json()["detail"]

    # Verify auth failure count was recorded
    detail = client.get(f"/api/v1/collector/collectors/{cid}").json()
    assert detail["auth_failures"] >= 1

    # Revoke credentials and verify revocation rejection
    client.post(f"/api/v1/collector/collectors/{cid}/revoke")
    bad_req3 = client.post(
        "/api/v1/collector/ingest/events",
        json={"events": [sample_event]},
        headers={"X-Collector-ID": cid, "X-Collector-Token": token},
    )
    assert bad_req3.status_code == 401
    assert "revoked" in bad_req3.json()["detail"].lower()

    # Verify DPAPI helper
    secret = "TopSecretThreatLensToken_12345"
    protected = protect_token_dpapi(secret)
    unprotected = unprotect_token_dpapi(protected)
    assert unprotected == secret


# =============================================================================
# SUBMODULE 5: COLLECTOR HEALTH & EVENT MONITORING
# =============================================================================
def test_submodule5_collector_health_and_monitoring(client):
    """
    Verify collector health monitoring:
    - Accepted and rejected event tracking
    - Pending offline spool queue monitoring
    - Error tracking and last-seen updating
    """
    res = enrol_collector("ENG-BUILD-SERVER", "10.0.0.2", "Windows 11", "admin")
    cid = res["collector_id"]

    # Record delivery with accepted=10, rejected=2, pending_spool=15
    record_event_delivery(
        collector_id=cid,
        count=10,
        accepted=10,
        rejected=2,
        error="Invalid XML event header",
        pending_spool_events=15,
    )

    detail = client.get(f"/api/v1/collector/collectors/{cid}").json()
    assert detail["event_count"] == 10
    assert detail["error_count"] == 1
    assert detail["pending_spool_events"] == 15
    assert len(detail["recent_errors"]) == 1
    assert "Invalid XML event header" in detail["recent_errors"][0]
    assert detail["last_seen"] is not None


# =============================================================================
# SUBMODULE 6: WINDOWS EVENT COLLECTION (IDs 4624, 4625, 4688, 5140)
# =============================================================================
def test_submodule6_windows_event_collection_and_checkpointing(tmp_path):
    """
    Verify collection support for required Windows Event IDs:
    - ID 4624: Successful Logon
    - ID 4625: Failed Logon
    - ID 4688: Process Creation
    - ID 5140: Network Share Access
    And verify incremental CheckpointManager.
    """
    events = [
        # 4624
        {
            "event_id_number": 4624,
            "channel": "Security",
            "source_computer": "WS-EXEC-01",
            "time_created": "2026-11-05T12:00:00Z",
            "source_event_record_id": 501,
            "event_data": {"TargetUserName": "alice", "LogonType": "10", "IpAddress": "192.168.1.50"},
        },
        # 4625
        {
            "event_id_number": 4625,
            "channel": "Security",
            "source_computer": "WS-EXEC-01",
            "time_created": "2026-11-05T12:01:00Z",
            "source_event_record_id": 502,
            "event_data": {"TargetUserName": "root", "FailureReason": "UnknownUser", "IpAddress": "192.168.1.99"},
        },
        # 4688
        {
            "event_id_number": 4688,
            "channel": "Security",
            "source_computer": "WS-EXEC-01",
            "time_created": "2026-11-05T12:02:00Z",
            "source_event_record_id": 503,
            "event_data": {
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
            },
        },
        # 5140
        {
            "event_id_number": 5140,
            "channel": "Security",
            "source_computer": "WS-EXEC-01",
            "time_created": "2026-11-05T12:03:00Z",
            "source_event_record_id": 504,
            "event_data": {"ShareName": "\\\\*\\C$", "IpAddress": "192.168.1.80", "SubjectUserName": "svc_backup"},
        },
    ]

    envelopes, errors = normalize_windows_events(events, collector_id="col-test01", device_node_id="device:ws-exec-01")
    assert len(errors) == 0
    assert len(envelopes) == 4

    types = [e.event_type for e in envelopes]
    assert SecurityEventType.IDENTITY_EVENT in types
    assert SecurityEventType.PROCESS_EVENT in types
    assert SecurityEventType.NETWORK_CONNECTION in types

    # Test incremental CheckpointManager
    ckpt_file = str(tmp_path / "checkpoint.json")
    logger = logging.getLogger("test_submodule6")
    mgr = CheckpointManager(ckpt_file, logger=logger)
    assert mgr.get("Security") == 0

    mgr.update("Security", 504)
    assert mgr.get("Security") == 504

    # Reload from disk
    mgr2 = CheckpointManager(ckpt_file, logger=logger)
    assert mgr2.get("Security") == 504


# =============================================================================
# SUBMODULE 7: EVENT NORMALIZATION, DEDUPLICATION & PROVENANCE
# =============================================================================
def test_submodule7_normalization_dedup_and_provenance():
    """
    Verify:
    - Normalization of timestamps and identifiers
    - Sensitive password / secret redaction
    - Deduplication
    - Distinguishing synthetic vs genuine Windows telemetry
    """
    normalizer = WindowsEventNormalizer()
    raw_event = {
        "event_id_number": 4688,
        "channel": "Security",
        "source_computer": "DC-PROD-01",
        "time_created": "2026-11-05T14:30:00Z",
        "source_event_record_id": 8801,
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\net.exe",
            "CommandLine": "net user admin SuperSecretP@ssword123 /add",
        },
    }

    env = normalizer.normalize(raw_event, collector_id="col-corp01", device_node_id="device:dc-prod-01")
    assert env is not None

    # Redaction test
    assert "SuperSecretP@ssword123" not in env.payload["command_line"]
    assert "[REDACTED]" in env.payload["command_line"]

    # Provenance preservation
    assert env.evidence_metadata["windows_event_id"] == 4688
    assert env.evidence_metadata["channel"] == "Security"
    assert env.evidence_metadata["collector_id"] == "col-corp01"
    assert env.evidence_metadata["device_node_id"] == "device:dc-prod-01"

    # Distinguish genuine vs synthetic:
    # 1. Genuine security event from corp collector
    assert env.payload["is_synthetic"] is False
    assert env.evidence_metadata["telemetry_source"] == "GENUINE_WINDOWS_TELEMETRY"

    # 2. Synthetic event simulation
    synth_event = dict(raw_event)
    synth_event["channel"] = "Simulation/Tests"
    synth_env = normalizer.normalize(synth_event, collector_id="synth-col-01", device_node_id="device:dc-prod-01")
    assert synth_env.payload["is_synthetic"] is True
    assert synth_env.evidence_metadata["telemetry_source"] == "SYNTHETIC_SIMULATION"

    # Deduplication test
    assert not is_duplicate(env.event_id)
    mark_seen(env.event_id)
    assert is_duplicate(env.event_id)


# =============================================================================
# SUBMODULE 8: OFFLINE SPOOL QUEUE
# =============================================================================
def test_submodule8_offline_spool_queue(tmp_path):
    """
    Verify offline spool resilience:
    - Enqueue events when offline
    - Track pending spool count
    - Drain in FIFO order upon recovery
    - Preserve unacknowledged events
    """
    spool_dir = str(tmp_path / "spool")
    logger = logging.getLogger("test_submodule8")
    spool = SpoolManager(spool_dir=spool_dir, logger=logger)

    events_batch1 = [{"event_id": 4624, "event_record_id": 1}]
    events_batch2 = [{"event_id": 4688, "event_record_id": 2}]

    assert spool.get_pending_count() == 0

    # Write two offline batches
    spool.spool_batch(events_batch1, checkpoint_offset=1)
    time.sleep(0.01)
    spool.spool_batch(events_batch2, checkpoint_offset=2)

    assert spool.get_pending_count() == 2
    assert len(spool.get_spooled_files()) == 2

    # Drain spool: simulate network failure on batch 2
    submitted = []

    def mock_submit(events, offset):
        submitted.append(offset)
        return len(submitted) == 1  # 1st batch succeeds, 2nd batch fails

    drained_count = spool.drain(mock_submit)
    assert drained_count == 1
    assert submitted == [1, 2]
    assert spool.get_pending_count() == 1
    assert len(spool.get_spooled_files()) == 1  # 2nd batch is preserved!

    # On reconnection, retry drainage of the unacknowledged batch
    drained_count2 = spool.drain(lambda ev, off: True)
    assert drained_count2 == 1
    assert spool.get_pending_count() == 0
    assert len(spool.get_spooled_files()) == 0
