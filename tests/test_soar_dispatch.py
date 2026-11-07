"""
ThreatLens SOAR — Closed-Loop Containment & Reversible Rollback Tests
Validates active containment enforcement, pre-state preservation,
adapter dispatch, 1-click reversible rollback, and cryptographic SHA-256 audit ledger integrity.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.soar import (
    EnforcementAction,
    EnforcementState,
    EnforceContainmentRequest,
    RollbackRequest,
    get_soar_dispatcher,
)
from backend.governance.audit import verify_audit_integrity, list_audit_records
from backend.graphops.mock_client import get_mock_graphops_client


@pytest.fixture
def client():
    return TestClient(app)


def test_soar_firewall_containment_and_rollback():
    """Validates host firewall isolation adapter and reversible rollback."""
    dispatcher = get_soar_dispatcher()
    target_node = "server:srv-app-01"

    # Step 1: Enforce containment
    req = EnforceContainmentRequest(
        target_node_id=target_node,
        action=EnforcementAction.ISOLATE_NODE,
        reason="Automated containment test on jump server",
    )
    enf_res = dispatcher.enforce_containment(req, actor="tester_soc")
    
    assert enf_res.enforcement_id.startswith("ENF-")
    assert enf_res.target_node_id == target_node
    assert enf_res.state == EnforcementState.ENFORCED
    assert enf_res.adapter_name == "WindowsHostFirewallAdapter"
    assert enf_res.rollback_token.startswith("rbk_")
    assert "telemetry_whitelisted_ports" in enf_res.pre_state_snapshot.get("primary_state", {})
    
    # Verify Knowledge Graph reflects containment
    mock_c = get_mock_graphops_client()
    if target_node in mock_c.nodes:
        assert mock_c.nodes[target_node].get("contained") is True
        assert mock_c.nodes[target_node].get("containment_state") == "ISOLATED"

    # Verify audit ledger integrity
    is_valid, err = verify_audit_integrity()
    assert is_valid is True, f"Audit trail broken after enforcement: {err}"

    # Step 2: Query active enforcements list
    active = dispatcher.list_active_enforcements()
    matched = next((a for a in active if a.enforcement_id == enf_res.enforcement_id), None)
    assert matched is not None
    assert matched.state == EnforcementState.ENFORCED

    # Step 3: Rollback containment
    rbk_req = RollbackRequest(
        remediation_id=enf_res.remediation_id,
        rollback_token=enf_res.rollback_token,
        reason="Test completed / Threat cleared",
    )
    rbk_res = dispatcher.rollback_containment(rbk_req, actor="tester_soc")
    
    assert rbk_res.state == EnforcementState.ROLLED_BACK
    assert rbk_res.target_node_id == target_node
    
    # Verify Knowledge Graph reflects restoration
    if target_node in mock_c.nodes:
        assert mock_c.nodes[target_node].get("contained") is False

    # Verify audit ledger integrity post-rollback
    is_valid, err = verify_audit_integrity()
    assert is_valid is True, f"Audit trail broken after rollback: {err}"


def test_soar_active_directory_account_suspension():
    """Validates user account suspension adapter and rollback."""
    dispatcher = get_soar_dispatcher()
    target_user = "user:usr-101"

    req = EnforceContainmentRequest(
        target_node_id=target_user,
        action=EnforcementAction.SUSPEND_ACCOUNT,
        reason="Compromised credentials detected",
    )
    enf_res = dispatcher.enforce_containment(req, actor="tester_soc")
    
    assert enf_res.adapter_name == "ActiveDirectoryAccountAdapter"
    assert enf_res.state == EnforcementState.ENFORCED
    assert enf_res.pre_state_snapshot.get("primary_state", {}).get("account_suspended") is True

    # Rollback
    rbk_req = RollbackRequest(
        remediation_id=enf_res.remediation_id,
        rollback_token=enf_res.rollback_token,
        reason="False positive cleared by SOC manager",
    )
    rbk_res = dispatcher.rollback_containment(rbk_req, actor="tester_soc")
    assert rbk_res.state == EnforcementState.ROLLED_BACK


def test_soar_http_api_endpoints(client):
    """Validates HTTP REST API endpoints for enforcement and rollback."""
    target_node = "device:dev-ws-101"

    # 1. Enforce via HTTP POST
    payload = {
        "target_node_id": target_node,
        "action": "ISOLATE_NODE",
        "reason": "Lateral movement detected from workstation",
    }
    resp = client.post("/api/v1/governance/remediations/enforce", json=payload)
    assert resp.status_code == 201, f"Enforce failed: {resp.text}"
    data = resp.json()
    rem_id = data["remediation_id"]
    enf_id = data["enforcement_id"]
    token = data["rollback_token"]
    assert data["state"] == "ENFORCED"

    # 2. Query active enforcements
    list_resp = client.get("/api/v1/governance/soar/enforcements")
    assert list_resp.status_code == 200
    active_items = list_resp.json()
    assert any(item["enforcement_id"] == enf_id for item in active_items)

    # 3. Query enforcement detail
    detail_resp = client.get(f"/api/v1/governance/soar/enforcements/{enf_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["enforcement_id"] == enf_id

    # 4. Rollback via HTTP POST
    rbk_payload = {
        "remediation_id": rem_id,
        "rollback_token": token,
        "reason": "Host sanitized and verified by EDR scan",
    }
    rbk_resp = client.post(f"/api/v1/governance/remediations/{rem_id}/rollback", json=rbk_payload)
    assert rbk_resp.status_code == 200, f"Rollback failed: {rbk_resp.text}"
    rbk_data = rbk_resp.json()
    assert rbk_data["state"] == "ROLLED_BACK"

    # 5. Verify cryptographic audit integrity via HTTP
    audit_verify_resp = client.get("/api/v1/governance/audit/verify")
    assert audit_verify_resp.status_code == 200
    assert audit_verify_resp.json()["ledger_intact"] is True

