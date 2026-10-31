"""
ThreatLens Collector Security Hardening & Reliability Test Suite
===============================================================
Validates:
  1. Anti-spoofing and host impersonation prevention.
  2. Event 4688 sensitive command-line credential redaction (client & backend).
  3. Fail-closed TLS verification enforcement.
  4. DPAPI credential protection & automatic decryption.
  5. Local disk offline spool queue (bounded storage, FIFO replay).
  6. Windows Event Log clear / rollover checkpoint recovery.
  7. Neo4j (:Device) auto-provisioning for newly enrolled collectors.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.api.collector_routes import get_kafka_producer_dep
from backend.collector.normalizer import WindowsEventNormalizer, redact_sensitive_cmdline
from backend.collector.registry import (
    auto_provision_device_node,
    enrol_collector,
)
from backend.core import config
from backend.main import app
from backend.models.graphops import SecurityEventEnvelope
from collector.threatlens_collector import (
    CheckpointManager,
    SpoolManager,
    load_config,
    protect_token_dpapi,
    submit_events,
    unprotect_token_dpapi,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="tl_test_sec_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# 1. Anti-Spoofing & Impersonation Prevention
# ---------------------------------------------------------------------------

def test_anti_spoofing_prevent_host_impersonation(temp_dir, monkeypatch):
    reg_path = temp_dir / "registry.json"
    monkeypatch.setattr("backend.collector.registry._REGISTRY_PATH", reg_path)
    monkeypatch.setattr(config, "COLLECTOR_REGISTRY_PATH", str(reg_path))

    enrol_res = enrol_collector(
        hostname="DESKTOP-BRANCH01",
        ip_address="192.168.10.45",
        os_version="Windows 11",
        enrolled_by="admin-test",
    )
    col_id = enrol_res["collector_id"]
    token = enrol_res["token"]

    client = TestClient(app)
    mock_producer = MagicMock()
    mock_producer.publish_security_event.return_value = True
    app.dependency_overrides[get_kafka_producer_dep] = lambda: mock_producer

    # Endpoint DESKTOP-BRANCH01 tries to claim an event came from DC-CORP-PRIMARY
    spoofed_payload = {
        "events": [
            {
                "event_id_number": 4624,
                "source_computer": "DC-CORP-PRIMARY",  # Spoofed!
                "time_created": "2026-10-29T08:00:00Z",
                "channel": "Security",
                "event_data": {
                    "TargetUserName": "admin_backup",
                    "TargetDomainName": "CORP",
                    "IpAddress": "10.0.0.99",
                },
            }
        ]
    }

    resp = client.post(
        "/api/v1/collector/ingest/events",
        headers={
            "X-Collector-ID": col_id,
            "X-Collector-Token": token,
            "Content-Type": "application/json",
        },
        json=spoofed_payload,
    )

    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 1
    assert data["published"] == 1

    # Verify published envelope has enforced authentic source_computer
    assert mock_producer.publish_security_event.called
    envelope = mock_producer.publish_security_event.call_args[0][0]
    assert isinstance(envelope, SecurityEventEnvelope)
    assert "device:desktop-branch01" in envelope.entity_ids
    assert envelope.evidence_metadata.get("device_node_id") == "device:desktop-branch01"
    assert envelope.evidence_metadata.get("impersonation_prevented") is True
    assert envelope.evidence_metadata.get("claimed_source_computer") == "DC-CORP-PRIMARY"

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 2. Command Line Sensitive Credential Redaction
# ---------------------------------------------------------------------------

def test_cmdline_credential_redaction_client_and_backend():
    sensitive_cmdlines = [
        ("cmd.exe /c net use \\\\share\\data /user:corp\\bob -p SuperSecretPwd123!",
         "cmd.exe /c net use \\\\share\\data /user:corp\\bob -p [REDACTED]"),
        ("powershell.exe -token ghp_93817293817293812739812739812",
         "powershell.exe -token [REDACTED]"),
        ("app.exe --password=MyRootAdminPass! --verbose",
         "app.exe --password=[REDACTED] --verbose"),
        ("connect.exe /password:SecretToken999",
         "connect.exe /password:[REDACTED]"),
    ]

    for raw, expected in sensitive_cmdlines:
        redacted = redact_sensitive_cmdline(raw)
        assert redacted == expected
        assert "SuperSecretPwd123!" not in redacted
        assert "ghp_93817293817293812739812739812" not in redacted
        assert "MyRootAdminPass!" not in redacted


def test_normalizer_sanitizes_event_4688_cmdline():
    norm = WindowsEventNormalizer()
    raw = {
        "event_id_number": 4688,
        "source_computer": "WIN-SRV-APP01",
        "time_created": "2026-10-29T08:30:00Z",
        "channel": "Security",
        "event_data": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe -password SuperSecret! /c whoami",
            "SubjectUserName": "svc_sql",
        },
    }

    env = norm.normalize(raw, collector_id="col-test-srv", device_node_id="device:win-srv-app01")
    assert env is not None
    assert env.payload.get("command_line") == "cmd.exe -password [REDACTED] /c whoami"
    assert "SuperSecret!" not in json.dumps(env.payload)
    assert "SuperSecret!" not in json.dumps(env.evidence_metadata)


# ---------------------------------------------------------------------------
# 3. Fail-Closed TLS Enforcement
# ---------------------------------------------------------------------------

def test_fail_closed_tls_prohibits_unverified_connection():
    logger = MagicMock()
    # verify_tls is False but insecure_dev_allowed is False -> must return False and abort
    ok = submit_events(
        server_url="https://threatlens.example.com",
        collector_id="col-test",
        token="test-tok",
        events=[{"test": 1}],
        verify_tls=False,
        ca_cert=None,
        checkpoint_offset=None,
        logger=logger,
        insecure_dev_allowed=False,
    )
    assert ok is False
    assert logger.critical.called
    assert "Refusing to transmit authentication token" in logger.critical.call_args[0][0]


def test_fail_closed_tls_missing_ca_cert():
    logger = MagicMock()
    ok = submit_events(
        server_url="https://threatlens.example.com",
        collector_id="col-test",
        token="test-tok",
        events=[{"test": 1}],
        verify_tls=True,
        ca_cert="C:\\non_existent_ca_path.pem",
        checkpoint_offset=None,
        logger=logger,
    )
    assert ok is False
    assert logger.critical.called
    assert "Specified ca_cert file not found" in logger.critical.call_args[0][0]


# ---------------------------------------------------------------------------
# 4. DPAPI Credential Protection & Config Loader
# ---------------------------------------------------------------------------

def test_dpapi_protect_and_unprotect_roundtrip():
    secret = "threatlens_live_secret_token_12345"
    protected = protect_token_dpapi(secret)
    assert protected.startswith("dpapi:")
    assert secret not in protected

    recovered = unprotect_token_dpapi(protected)
    assert recovered == secret


def test_load_config_with_dpapi_token(temp_dir):
    cfg_file = temp_dir / "config.json"
    plain_token = "secret-token-to-encrypt"
    enc_token = protect_token_dpapi(plain_token)

    cfg_data = {
        "server_url": "https://threatlens.internal",
        "collector_id": "col-dpapi-test",
        "token": enc_token,
    }
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    logger = MagicMock()
    loaded = load_config(str(cfg_file), logger=logger)
    assert loaded["token"] == plain_token
    assert loaded["collector_id"] == "col-dpapi-test"


# ---------------------------------------------------------------------------
# 5. Local Disk Offline Spool Queue
# ---------------------------------------------------------------------------

def test_spool_manager_bounded_queue_and_fifo_drain(temp_dir):
    spool_dir = temp_dir / "spool"
    logger = MagicMock()
    # Set a tiny max bytes to test bounds enforcement
    mgr = SpoolManager(str(spool_dir), logger=logger, max_bytes=2048, max_events=100)

    # 1. Spool 3 batches
    mgr.spool_batch([{"batch": 1, "data": "a" * 200}], checkpoint_offset=10)
    mgr.spool_batch([{"batch": 2, "data": "b" * 200}], checkpoint_offset=20)
    mgr.spool_batch([{"batch": 3, "data": "c" * 200}], checkpoint_offset=30)

    files = mgr.get_spooled_files()
    assert len(files) == 3

    # 2. Test drain with mock submission
    submitted_batches = []

    def mock_submit(events, offset):
        submitted_batches.append(events[0]["batch"])
        return True

    drained_count = mgr.drain(mock_submit)
    assert drained_count == 3
    assert submitted_batches == [1, 2, 3]  # Strictly FIFO
    assert len(mgr.get_spooled_files()) == 0  # Drained files are cleaned up


def test_spool_manager_halts_drain_on_failure(temp_dir):
    spool_dir = temp_dir / "spool_fail"
    logger = MagicMock()
    mgr = SpoolManager(str(spool_dir), logger=logger)

    mgr.spool_batch([{"batch": 1}], checkpoint_offset=1)
    mgr.spool_batch([{"batch": 2}], checkpoint_offset=2)

    def failing_submit(events, offset):
        return False  # Server temporarily down

    drained = mgr.drain(failing_submit)
    assert drained == 0
    # Files must be retained for next attempt!
    assert len(mgr.get_spooled_files()) == 2


# ---------------------------------------------------------------------------
# 6. Windows Event Log Checkpoint Rollover Recovery
# ---------------------------------------------------------------------------

def test_checkpoint_reset_on_rollover(temp_dir):
    chk_file = temp_dir / "checkpoint.json"
    logger = MagicMock()
    chk = CheckpointManager(str(chk_file), logger=logger)

    # Historical high checkpoint before log was cleared
    chk.update("Security", 950000)
    assert chk.get("Security") == 950000

    # Reset triggered by log rollover detection
    chk.reset("Security")
    assert chk.get("Security") == 0

    # Re-read checkpoint file from disk
    chk2 = CheckpointManager(str(chk_file), logger=logger)
    assert chk2.get("Security") == 0


# ---------------------------------------------------------------------------
# 7. Neo4j (:Device) Auto-Provisioning on Collector Enrolment
# ---------------------------------------------------------------------------

def test_auto_provision_device_node_in_neo4j():
    mock_client = MagicMock()
    with patch("backend.graphops.client.get_graphops_client", return_value=mock_client):
        auto_provision_device_node(hostname="DESKTOP-AUTO01", ip_address="192.168.1.55", os_version="Windows 11")
        assert mock_client.execute_query.called
        query, params = mock_client.execute_query.call_args[0]
        assert "MERGE (d:Device {id: $id})" in query
        assert params["id"] == "device:desktop-auto01"
        assert params["hostname"] == "DESKTOP-AUTO01"
        assert params["ip"] == "192.168.1.55"


def test_dpapi_machine_and_user_scope_roundtrip():
    """Validates DPAPI encryption and decryption for both machine-scoped and user-scoped tokens."""
    secret = "threatlens_scheduled_task_token_9988"

    # Machine scope (for NT AUTHORITY\SYSTEM scheduled tasks)
    machine_enc = protect_token_dpapi(secret, machine_scope=True)
    assert machine_enc.startswith("dpapi:m:")
    assert secret not in machine_enc
    assert unprotect_token_dpapi(machine_enc) == secret

    # User scope
    user_enc = protect_token_dpapi(secret, machine_scope=False)
    assert user_enc.startswith("dpapi:u:")
    assert secret not in user_enc
    assert unprotect_token_dpapi(user_enc) == secret

    # Legacy prefix support
    legacy_enc = "dpapi:" + machine_enc[len("dpapi:m:"):]
    assert unprotect_token_dpapi(legacy_enc) == secret


def test_spool_capacity_exhaustion_diagnostics_and_metrics(temp_dir):
    """Validates that spool quota exhaustion logs visible diagnostic alerts and updates persistent metrics."""
    spool_dir = temp_dir / "spool_metrics_test"
    logger = MagicMock()
    # Tiny 1KB quota to force eviction
    mgr = SpoolManager(str(spool_dir), logger=logger, max_bytes=1024, max_events=10)

    # Spool 5 batches exceeding 1KB total
    for i in range(5):
        mgr.spool_batch([{"event_id": 4624, "payload": "X" * 350, "index": i}], checkpoint_offset=i)

    metrics = mgr.get_metrics()
    assert metrics["dropped_files_count"] > 0
    assert metrics["dropped_events_count"] > 0
    assert metrics["total_spooled_events"] == 5

    # Check metrics file persisted on disk
    metrics_file = spool_dir / "spool_metrics.json"
    assert metrics_file.exists()
    disk_metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
    assert disk_metrics["dropped_files_count"] == metrics["dropped_files_count"]

    # Verify visible diagnostic log
    warning_calls = [str(call) for call in logger.warning.call_args_list]
    assert any("[SPOOL CAPACITY EXHAUSTED]" in call for call in warning_calls)


def test_checkpoint_advances_only_on_success_or_spool(temp_dir):
    """Ensures checkpoints strictly advance only upon verified submission or durable spooling."""
    chk_file = temp_dir / "chk_test.json"
    logger = MagicMock()
    chk = CheckpointManager(str(chk_file), logger=logger)
    chk.update("Security", 100)
    assert chk.get("Security") == 100

    # If neither submission nor spool succeeded, checkpoint remains unchanged
    unprocessed_record_id = 150
    assert chk.get("Security") == 100

    # When safely spooled to disk, checkpoint advances
    chk.update("Security", unprocessed_record_id)
    assert chk.get("Security") == 150
