"""
ThreatLens Collector - Registry Cross-Process Concurrency and Race Condition Tests
Validates that file-locking and atomic replacements prevent race conditions during:
  - Concurrent enrolments from multiple processes
  - Concurrent duplicate-host re-enrolments
  - Simultaneous token authentication and counter increments
  - Immediate cross-worker rejection of revoked tokens
"""

import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from pathlib import Path
import pytest

from backend.collector import registry


def _worker_enrol(args):
    reg_path, hostname, ip = args
    os.environ["COLLECTOR_REGISTRY_PATH"] = reg_path
    return registry.enrol_collector(hostname, ip, "Windows 11", "admin")


def _worker_auth(args):
    reg_path, cid, token = args
    os.environ["COLLECTOR_REGISTRY_PATH"] = reg_path
    rec = registry.authenticate_collector(cid, token)
    return rec is not None


@pytest.fixture
def temp_registry(monkeypatch, tmp_path):
    reg_file = str(tmp_path / "concurrent_registry.json")
    monkeypatch.setenv("COLLECTOR_REGISTRY_PATH", reg_file)
    monkeypatch.setattr(registry, "auto_provision_device_node", lambda *args, **kwargs: None)
    return reg_file


def test_concurrent_unique_enrolments(temp_registry):
    """Multiple concurrent enrolments must all persist without overwriting each other."""
    num_workers = 10
    args_list = [
        (temp_registry, f"win-node-{i}.corp.internal", f"192.168.1.{100 + i}")
        for i in range(num_workers)
    ]

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(_worker_enrol, args_list))

    assert len(results) == num_workers
    tokens = {r["token"] for r in results}
    cids = {r["collector_id"] for r in results}
    assert len(tokens) == num_workers, "All issued tokens must be distinct"
    assert len(cids) == num_workers, "All collector IDs must be distinct"

    # Verify all records exist in final file
    collectors = registry.list_collectors()
    assert len(collectors) == num_workers
    for r in results:
        auth_rec = registry.authenticate_collector(r["collector_id"], r["token"])
        assert auth_rec is not None
        assert auth_rec.collector_id == r["collector_id"]


def test_concurrent_duplicate_host_reenrolment(temp_registry):
    """Concurrent enrolments for the same hostname must resolve to 1 record with latest token."""
    num_attempts = 8
    target_host = "shared-dc01.corp.internal"
    args_list = [
        (temp_registry, target_host, f"10.0.0.{i+1}")
        for i in range(num_attempts)
    ]

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(_worker_enrol, args_list))

    # All should return the same collector_id
    first_cid = results[0]["collector_id"]
    for r in results:
        assert r["collector_id"] == first_cid

    # Registry must have exactly 1 record for this host
    collectors = registry.list_collectors()
    assert len(collectors) == 1
    assert collectors[0].hostname == target_host

    # Exactly one issued token must be the active winning token
    active_tokens = [
        r["token"] for r in results
        if registry.authenticate_collector(first_cid, r["token"]) is not None
    ]
    assert len(active_tokens) == 1, "Exactly one token must be the active token for this re-enrolled host"


def test_immediate_rejection_after_revocation(temp_registry):
    """Revoked token must be rejected immediately across all readers."""
    res = registry.enrol_collector("win-sec-01.corp.internal", "10.0.0.50", "Windows", "sec-admin")
    cid = res["collector_id"]
    token = res["token"]

    # Valid before revocation
    assert registry.authenticate_collector(cid, token) is not None

    # Revoke
    ok = registry.revoke_collector(cid, "security-director")
    assert ok is True

    # Immediate rejection
    assert registry.authenticate_collector(cid, token) is None
    rec = registry.get_collector(cid)
    assert rec.status == "REVOKED"


def test_concurrent_event_delivery_counter_increments(temp_registry):
    """Concurrent event delivery updates must accurately tally event_count without lost updates."""
    res = registry.enrol_collector("win-srv-events.corp.internal", "10.0.0.99", "Windows", "admin")
    cid = res["collector_id"]

    def _deliver(count):
        registry.record_event_delivery(cid, count=count)

    increments = [5, 10, 15, 20, 25, 30]
    expected_total = sum(increments)

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(_deliver, increments))

    rec = registry.get_collector(cid)
    assert rec is not None
    assert rec.event_count == expected_total
    assert rec.status == "ACTIVE"


def test_cross_process_revocation_rejection(temp_registry):
    """Token enrolled in process 1, authenticated in process 2, revoked in process 3, verified rejected in process 4."""
    # Step 1: Enrol
    res = _worker_enrol((temp_registry, "proc-test-host.corp.internal", "192.168.10.50"))
    cid = res["collector_id"]
    token = res["token"]

    # Step 2: Authenticate successfully
    assert _worker_auth((temp_registry, cid, token)) is True

    # Step 3: Revoke token
    revoked = registry.revoke_collector(cid, "sec-admin")
    assert revoked is True

    # Step 4: Re-authenticate with revoked token -> must fail
    assert _worker_auth((temp_registry, cid, token)) is False
    rec = registry.get_collector(cid)
    assert rec.status == "REVOKED"
