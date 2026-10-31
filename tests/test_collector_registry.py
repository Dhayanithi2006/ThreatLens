"""
ThreatLens - Collector Registry Unit Tests
Verifies collector enrolment, HMAC token generation, credential verification,
constant-time authentication, event metrics recording, and revocation.
"""

import os
import json
import pytest
from pathlib import Path

from backend.collector.registry import (
    enrol_collector,
    authenticate_collector,
    record_event_delivery,
    list_collectors,
    get_collector,
    revoke_collector,
    _digest_token,
    _verify_token,
)
from backend.core import config


@pytest.fixture(autouse=True)
def clean_registry(tmp_path, monkeypatch):
    """Use a temporary path for collector registry during testing."""
    test_reg_path = tmp_path / "test_collector_registry.json"
    monkeypatch.setattr("backend.collector.registry._REGISTRY_PATH", test_reg_path)
    monkeypatch.setattr(config, "COLLECTOR_REGISTRY_PATH", str(test_reg_path))
    yield
    if test_reg_path.exists():
        test_reg_path.unlink()


def test_enrol_collector_generates_unique_token_and_hmac_digest():
    """Verify enrolment returns a one-time token and stores only HMAC-SHA256 digest."""
    result = enrol_collector(
        hostname="DESKTOP-WIN11-01",
        ip_address="192.168.1.101",
        os_version="Windows 11 Pro",
        enrolled_by="admin-test",
    )

    assert "collector_id" in result
    assert result["collector_id"].startswith("col-")
    assert "token" in result
    assert len(result["token"]) >= 32

    # Check that plain-text token is NOT in registry on disk
    reg_file = Path(config.COLLECTOR_REGISTRY_PATH)
    assert reg_file.exists()
    disk_data = json.loads(reg_file.read_text(encoding="utf-8"))
    stored_rec = disk_data[result["collector_id"]]
    assert "token" not in stored_rec
    assert "token_digest" in stored_rec
    assert stored_rec["token_digest"] != result["token"]
    assert _verify_token(result["token"], stored_rec["token_digest"])


def test_authenticate_collector_valid_and_invalid():
    """Verify authentication succeeds with valid token and fails with incorrect token."""
    enrol = enrol_collector(
        hostname="SERVER-AD-01",
        ip_address="10.0.0.10",
        os_version="Windows Server 2022",
        enrolled_by="secops",
    )
    cid = enrol["collector_id"]
    token = enrol["token"]

    # Valid auth
    rec = authenticate_collector(cid, token)
    assert rec is not None
    assert rec.collector_id == cid
    assert rec.hostname == "SERVER-AD-01"
    assert rec.device_node_id == "device:server-ad-01"
    assert rec.status == "ENROLLED"

    # Invalid token
    assert authenticate_collector(cid, "wrong-token-abc-123") is None

    # Unknown collector ID
    assert authenticate_collector("col-nonexistent", token) is None


def test_re_enrol_updates_token_and_resets_counters():
    """Re-enrolling an existing hostname issues a new token and resets counters."""
    first = enrol_collector("WORKSTATION-42", "10.0.1.42", "Windows 10", "admin")
    record_event_delivery(first["collector_id"], count=10)

    # Re-enrol same hostname
    second = enrol_collector("WORKSTATION-42", "10.0.1.42", "Windows 10", "admin")
    assert second["collector_id"] == first["collector_id"]
    assert second["token"] != first["token"]

    # Old token fails
    assert authenticate_collector(first["collector_id"], first["token"]) is None
    # New token succeeds
    rec = authenticate_collector(second["collector_id"], second["token"])
    assert rec is not None
    assert rec.event_count == 0


def test_record_event_delivery_and_error_tracking():
    """Verify last-seen timestamp, event counter, and error logging."""
    enrol = enrol_collector("LAPTOP-DEV", "192.168.1.55", "Windows 11", "admin")
    cid = enrol["collector_id"]

    # Record delivery of 25 events
    record_event_delivery(cid, count=25)
    rec = get_collector(cid)
    assert rec.event_count == 25
    assert rec.status == "ACTIVE"
    assert rec.last_seen is not None
    assert rec.error_count == 0

    # Record an ingestion error
    record_event_delivery(cid, count=0, error="Kafka broker timeout")
    rec2 = get_collector(cid)
    assert rec2.error_count == 1
    assert len(rec2.recent_errors) == 1
    assert "Kafka broker timeout" in rec2.recent_errors[0]


def test_revoke_collector():
    """Verify revoking permanently blocks collector access."""
    enrol = enrol_collector("COMPROMISED-PC", "192.168.1.99", "Windows 10", "admin")
    cid = enrol["collector_id"]
    token = enrol["token"]

    assert authenticate_collector(cid, token) is not None

    # Revoke
    revoked = revoke_collector(cid, actor="soc-lead")
    assert revoked is True

    # Immediate rejection
    assert authenticate_collector(cid, token) is None
    rec = get_collector(cid)
    assert rec.status == "REVOKED"

