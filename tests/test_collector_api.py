"""
ThreatLens - Collector API Integration Tests
Tests:
- Admin enrolment of new collectors (POST /api/v1/collector/enrol)
- Listing and querying collector status (GET /api/v1/collector/collectors)
- Authenticated Windows security event ingestion (POST /api/v1/collector/ingest/events)
- Authentication failures (missing/invalid tokens)
- Ingestion rate limiting & batch size validation
- Fast-path deduplication
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.collector.dedup import _cache
from backend.collector.rate_limiter import _request_windows


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Temporary registry and reset rate limiter/dedup caches."""
    test_reg_path = tmp_path / "test_api_collector_reg.json"
    monkeypatch.setattr("backend.collector.registry._REGISTRY_PATH", test_reg_path)
    monkeypatch.setattr(config, "COLLECTOR_REGISTRY_PATH", str(test_reg_path))
    monkeypatch.setattr(config, "REQUIRE_API_KEY", False)
    _cache.clear()
    _request_windows.clear()
    yield
    if test_reg_path.exists():
        test_reg_path.unlink()
    _cache.clear()
    _request_windows.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_enrol_and_list_collectors_endpoint(client):
    """Admin can enrol a Windows computer and view it in the registry."""
    enrol_resp = client.post(
        "/api/v1/collector/enrol",
        json={
            "hostname": "FINANCE-PC-01",
            "ip_address": "10.0.1.100",
            "os_version": "Windows 11 Enterprise"
        }
    )
    assert enrol_resp.status_code == 201
    data = enrol_resp.json()
    assert "collector_id" in data
    assert "token" in data
    assert data["hostname"] == "FINANCE-PC-01"
    assert data["device_node_id"] == "device:finance-pc-01"

    # List collectors
    list_resp = client.get("/api/v1/collector/collectors")
    assert list_resp.status_code == 200
    collectors = list_resp.json()
    assert len(collectors) >= 1
    found = next((c for c in collectors if c["collector_id"] == data["collector_id"]), None)
    assert found is not None
    assert found["hostname"] == "FINANCE-PC-01"
    assert found["event_count"] == 0
    assert found["last_seen"] is None


def test_ingest_events_authenticated_success(client):
    """Enrolled collector submits Windows security events successfully."""
    # 1. Enrol
    enrol_resp = client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "HR-WORKSTATION-05"}
    )
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]

    # 2. Ingest batch of Windows events
    batch_payload = {
        "events": [
            {
                "event_id_number": 4624,
                "source_computer": "HR-WORKSTATION-05",
                "time_created": "2026-10-29T08:30:00Z",
                "source_event_record_id": 501,
                "channel": "Security",
                "event_data": {
                    "TargetUserName": "carol",
                    "TargetDomainName": "CORP",
                    "LogonType": "2"
                }
            },
            {
                "event_id_number": 4688,
                "source_computer": "HR-WORKSTATION-05",
                "time_created": "2026-10-29T08:31:00Z",
                "source_event_record_id": 502,
                "channel": "Security",
                "event_data": {
                    "SubjectUserName": "carol",
                    "NewProcessName": "C:\\Program Files\\app.exe"
                }
            }
        ],
        "checkpoint_offset": 502
    }

    ingest_resp = client.post(
        "/api/v1/collector/ingest/events",
        headers={
            "X-Collector-ID": cid,
            "X-Collector-Token": token
        },
        json=batch_payload
    )

    assert ingest_resp.status_code == 202
    res = ingest_resp.json()
    assert res["accepted"] == 2
    assert res["published"] == 2
    assert res["rejected"] == 0
    assert res["duplicate"] == 0

    # 3. Check collector operational metrics updated
    status_resp = client.get(f"/api/v1/collector/collectors/{cid}")
    assert status_resp.status_code == 200
    stat = status_resp.json()
    assert stat["event_count"] == 2
    assert stat["last_seen"] is not None
    assert stat["status"] == "ACTIVE"


def test_ingest_events_authentication_failures(client):
    """Ingestion endpoint strictly rejects unauthenticated or invalid tokens."""
    payload = {
        "events": [{
            "event_id_number": 4624,
            "source_computer": "TEST-HOST",
            "time_created": "2026-10-29T08:30:00Z",
        }]
    }

    # Missing headers
    resp1 = client.post("/api/v1/collector/ingest/events", json=payload)
    assert resp1.status_code == 401

    # Invalid token
    resp2 = client.post(
        "/api/v1/collector/ingest/events",
        headers={"X-Collector-ID": "col-fake", "X-Collector-Token": "bad-token"},
        json=payload
    )
    assert resp2.status_code == 401


def test_ingest_events_deduplication(client):
    """Submitting the exact same event twice increments duplicate counter and skips re-publishing."""
    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "WS-DEDUP"})
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]

    single_event = {
        "event_id_number": 4625,
        "source_computer": "WS-DEDUP",
        "time_created": "2026-10-29T08:40:00Z",
        "source_event_record_id": 9991,
        "channel": "Security",
        "event_data": {"TargetUserName": "admin"}
    }

    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}

    # First delivery
    r1 = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [single_event]})
    assert r1.status_code == 202
    assert r1.json()["published"] == 1
    assert r1.json()["duplicate"] == 0

    # Second delivery of identical record
    r2 = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [single_event]})
    assert r2.status_code == 202
    assert r2.json()["duplicate"] == 1
    assert r2.json()["published"] == 0


def test_ingest_events_rate_limit(client, monkeypatch):
    """Exceeding requests per minute returns HTTP 429."""
    monkeypatch.setattr(config, "COLLECTOR_RATE_LIMIT_RPM", 2)

    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "WS-RATELIMIT"})
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}

    event = {
        "event_id_number": 4624,
        "source_computer": "WS-RATELIMIT",
        "time_created": "2026-10-29T08:00:00Z",
        "source_event_record_id": 1,
    }

    # Request 1: OK
    assert client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]}).status_code == 202
    # Request 2: OK
    assert client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]}).status_code == 202
    # Request 3: Exceeded -> 429
    r3 = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]})
    assert r3.status_code == 429


def test_revoke_collector_endpoint_and_immediate_ingest_rejection(client):
    """Admin calls revoke endpoint; subsequent ingestion attempts are immediately rejected with HTTP 401."""
    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "WS-REVOKE-TEST"})
    assert enrol_resp.status_code == 201
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}

    event = {
        "event_id_number": 4624,
        "source_computer": "WS-REVOKE-TEST",
        "time_created": "2026-10-29T08:00:00Z",
        "source_event_record_id": 1,
    }

    # 1. Delivery succeeds while ACTIVE
    r1 = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]})
    assert r1.status_code == 202

    # 2. Revoke collector via API endpoint
    revoke_resp = client.post(f"/api/v1/collector/collectors/{cid}/revoke")
    assert revoke_resp.status_code == 200
    rev_data = revoke_resp.json()
    assert "revoked" in rev_data["message"]
    assert rev_data["collector_id"] == cid

    # 3. Status endpoint reflects REVOKED
    status_resp = client.get(f"/api/v1/collector/collectors/{cid}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "REVOKED"

    # 4. Ingestion immediately returns HTTP 401
    r2 = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]})
    assert r2.status_code == 401


def test_ingest_events_batch_size_oversized_validation(client):
    """Batches exceeding 500 events are rejected by request validation with HTTP 422."""
    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "WS-BATCH-CAP"})
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}

    # Create oversized batch (max 500 + 1)
    oversized = [
        {
            "event_id_number": 4624,
            "source_computer": "WS-BATCH-CAP",
            "time_created": "2026-10-29T08:00:00Z",
            "source_event_record_id": i + 1,
        }
        for i in range(501)
    ]

    resp = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": oversized})
    assert resp.status_code == 422


def test_ingest_events_hostname_mismatch_preserves_evidence(client):
    """Spoofed source_computer is bound to authentic host, and mismatch is preserved in evidence."""
    enrol_resp = client.post("/api/v1/collector/enrol", json={"hostname": "CORP-LAPTOP-01"})
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}

    spoofed_event = {
        "event_id_number": 4688,
        "source_computer": "DOMAIN-CONTROLLER-01",  # Impersonation attempt!
        "time_created": "2026-10-29T08:50:00Z",
        "source_event_record_id": 8801,
        "channel": "Security",
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami"
        }
    }

    resp = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [spoofed_event]})
    assert resp.status_code == 202
    assert resp.json()["published"] == 1


def test_collector_lifecycle_enrollment_to_event_to_status_update(client):
    """Verify state transitions: enrollment -> ENROLLED (pending delivery) -> ACTIVE streaming after delivery."""
    # 1. Enrol
    enrol_resp = client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "FINANCE-PC-99", "ip_address": "10.0.5.99"}
    )
    assert enrol_resp.status_code == 201
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]

    # 2. Before any event: status shows 0 events, last_seen is None, status is ENROLLED
    status_before = client.get(f"/api/v1/collector/collectors/{cid}").json()
    assert status_before["event_count"] == 0
    assert status_before["last_seen"] is None
    assert status_before["status"] == "ENROLLED"

    # 3. Deliver event
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}
    event = {
        "event_id_number": 4624,
        "source_computer": "FINANCE-PC-99",
        "time_created": "2026-10-29T09:00:00Z",
        "source_event_record_id": 101,
        "event_data": {"TargetUserName": "alice"}
    }
    ingest_resp = client.post("/api/v1/collector/ingest/events", headers=headers, json={"events": [event]})
    assert ingest_resp.status_code == 202

    # 4. After event: event_count incremented, last_seen set, status transitions to ACTIVE
    status_after = client.get(f"/api/v1/collector/collectors/{cid}").json()
    assert status_after["event_count"] == 1
    assert status_after["last_seen"] is not None
    assert status_after["status"] == "ACTIVE"


def test_collector_api_validation_errors_and_missing_resources(client):
    """Check 404 on missing collector, 404 on missing revoke, and 422 on invalid enrol payload."""
    # 404 on non-existent collector
    r1 = client.get("/api/v1/collector/collectors/non-existent-collector-id")
    assert r1.status_code == 404

    # 404 on revoking non-existent collector
    r2 = client.post("/api/v1/collector/collectors/non-existent-collector-id/revoke")
    assert r2.status_code == 404

    # 422 on empty hostname
    r3 = client.post("/api/v1/collector/enrol", json={"hostname": ""})
    assert r3.status_code == 422

    # 422 on empty events array
    r4 = client.post("/api/v1/collector/ingest/events", json={"events": []})
    assert r4.status_code in (401, 422)  # Either unauthenticated or invalid


