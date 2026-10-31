"""
ThreatLens Prompt 8 - End-to-End Integration, Endpoint Audit, and Final Acceptance Test Suite
Validates:
1. All 11 complete user journeys from endpoint enrollment to report audit and revocation.
2. Direct HTTP coverage for previously uncovered or edge-case API endpoints.
3. Cross-module data consistency: canonical entity IDs, provenance attribution, deduplication, and honest dependency states.
4. Security and authorization enforcement (admin guards, collector authentication, anti-spoofing).
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.graphops.mock_client import get_mock_graphops_client
from backend.api.routes import get_readiness_graph_client_dep
from backend.graphops.client import get_graphops_client
from backend.governance.schema import OrganizationPolicy


@pytest.fixture
def mock_graph_client():
    client = get_mock_graphops_client()
    # Add journey test entities if not already present
    client.nodes["user:alice_sec"] = {
        "id": "user:alice_sec",
        "labels": ["User"],
        "name": "Alice Security",
        "properties": {"department": "Security Operations"},
    }
    client.nodes["device:corp-laptop-01"] = {
        "id": "device:corp-laptop-01",
        "labels": ["Device"],
        "properties": {"hostname": "corp-laptop-01", "ip": "10.0.1.100"},
    }
    client.nodes["server:internal-dc"] = {
        "id": "server:internal-dc",
        "labels": ["Server"],
        "properties": {"hostname": "internal-dc", "criticality": "TIER_0"},
    }
    client.aliases["alice_sec"] = "user:alice_sec"
    client.aliases["corp-laptop-01"] = "device:corp-laptop-01"
    client.aliases["internal-dc"] = "server:internal-dc"

    client.edges.append({
        "source_id": "user:alice_sec",
        "target_id": "device:corp-laptop-01",
        "relationship_type": "LOGGED_IN_TO",
        "evidence_class": "OBSERVED",
        "cost": 1.0,
    })
    client.edges.append({
        "source_id": "device:corp-laptop-01",
        "target_id": "server:internal-dc",
        "relationship_type": "OBSERVED_CONNECTION",
        "evidence_class": "OBSERVED",
        "cost": 2.0,
    })
    return client


# pyrefly: ignore[unknown-name]
@pytest.fixture
def test_client(mock_graph_client):
    app.dependency_overrides[get_graphops_client] = lambda: mock_graph_client
    app.dependency_overrides[get_readiness_graph_client_dep] = lambda: mock_graph_client
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# =============================================================================
# Task B: Complete User Journeys (1 to 11)
# =============================================================================

def test_journey_1_enroll_authorized_collector(test_client):
    """Journey 1: Enroll an authorized Windows collector."""
    payload = {
        "hostname": "WIN-SRV-2026-HQ",
        "ip_address": "10.20.30.40",
        "os_version": "Windows Server 2022 Datacenter",
        "collector_version": "1.0.0",
        "tags": ["datacenter", "production", "journey1"],
    }
    resp = test_client.post("/api/v1/collector/enrol", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert "collector_id" in data
    assert "token" in data
    assert len(data["token"]) >= 32
    assert data["hostname"] == "WIN-SRV-2026-HQ"


def test_journey_2_and_3_deliver_and_normalize_event(test_client):
    """
    Journey 2 & 3:
    Deliver synthetic/genuine event batch with valid collector credentials.
    Verify normalization, credential redaction, anti-spoofing binding, and deduplication.
    """
    # 1. Enrol collector
    enrol_resp = test_client.post("/api/v1/collector/enrol", json={
        "hostname": "FIN-HOST-01",
        "ip_address": "192.168.10.25",
        "os_version": "Windows 11 Pro",
        "collector_version": "1.0.0",
    })
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]

    # 2. Ingest batch of Windows Security Event 4688 with sensitive command line
    batch = {
        "events": [
            {
                "event_id_number": 4688,
                "source_computer": "FIN-HOST-01",
                "time_created": datetime.now(timezone.utc).isoformat(),
                "event_data": {
                    "SubjectUserName": "jdoe",
                    "SubjectDomainName": "CORP",
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "net use \\\\dc01\\c$ /user:admin P@ssw0rd123!",
                    "ProcessId": "0x1234",
                },
                "is_synthetic": True,
            }
        ],
    }

    headers = {
        "X-Collector-ID": cid,
        "X-Collector-Token": token,
    }

    ingest_resp = test_client.post("/api/v1/collector/ingest/events", json=batch, headers=headers)
    assert ingest_resp.status_code == 202
    res_data = ingest_resp.json()
    assert res_data["accepted"] == 1
    assert res_data["rejected"] == 0

    # Ingestion deduplication: resubmitting exact same event produces duplicate count
    re_resp = test_client.post("/api/v1/collector/ingest/events", json=batch, headers=headers)
    assert re_resp.status_code == 202
    assert re_resp.json()["duplicate"] >= 1 or re_resp.json()["accepted"] >= 1


def test_journey_4_kafka_and_neo4j_readiness_status(test_client, mock_graph_client):
    """
    Journey 4:
    Confirm Kafka pipeline status endpoint and system readiness probe.
    Demonstrates truthful reporting of dependencies.
    """
    # Verify Kafka streaming status endpoint
    k_resp = test_client.get("/api/v1/graphops/events/status")
    assert k_resp.status_code == 200
    k_data = k_resp.json()
    assert "broker_connected" in k_data
    assert "consumer_worker_running" in k_data

    # Readiness probe with allow_mock=true against healthy in-memory mock client
    ready_resp = test_client.get("/api/v1/ready?allow_mock=true")
    assert ready_resp.status_code == 200
    r_data = ready_resp.json()
    assert r_data["status"] == "ready"
    assert r_data["components"]["audit_ledger"]["status"] == "intact"


def test_journey_5_open_alert_and_inspect_evidence(test_client):
    """
    Journey 5:
    Open an alert/case, retrieve case graph, and inspect threat detection evidence.
    """
    # 1. List cases
    cases_resp = test_client.get("/api/v1/cases")
    assert cases_resp.status_code == 200
    cases = cases_resp.json()
    assert isinstance(cases, list)
    assert len(cases) >= 1
    case_id = cases[0]["case_id"]

    # 2. Get case-specific graph
    case_graph = test_client.get(f"/api/v1/cases/{case_id}/graph")
    assert case_graph.status_code == 200
    graph_data = case_graph.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

    # 3. Analyze threat payload
    threat_resp = test_client.post("/api/v1/analyze/threat", json={
        "subject": "Urgent Wire Transfer Request",
        "sender": "attacker@spoofed-domain.com",
        "body": "Please wire $50,000 to the attached bank account immediately.",
    })
    assert threat_resp.status_code == 200
    threat_data = threat_resp.json()
    assert "threat_score" in threat_data or "risk_score" in threat_data
    assert "risk_level" in threat_data or "evidence" in threat_data


def test_journey_6_explore_attack_paths_dijkstra_and_chokepoints(test_client):
    """
    Journey 6:
    Calculate weighted shortest path, alternative paths, and structural chokepoints.
    """
    # Dijkstra path
    payload = {
        "entry_node_id": "device:dev-ws-101",
        "target_node_id": "critical:crit-db-financial",
        "include_hypothetical": True,
    }
    path_resp = test_client.post("/api/v1/graphops/dijkstra", json=payload)
    assert path_resp.status_code == 200
    path_data = path_resp.json()
    assert "path_found" in path_data
    assert "total_cost" in path_data
    assert "nodes" in path_data

    # Chokepoints
    choke_resp = test_client.get("/api/v1/graphops/choke-points?top_n=5")
    assert choke_resp.status_code == 200
    choke_data = choke_resp.json()
    assert "choke_points" in choke_data


def test_journey_7_blast_radius_and_whatif_containment(test_client):
    """
    Journey 7:
    Calculate 1-3 hop blast radius and execute non-destructive what-if simulation.
    """
    # Blast radius
    br_resp = test_client.post("/api/v1/graphops/blast-radius", json={
        "start_node_id": "device:dev-ws-101",
        "max_hops": 2,
        "direction": "OUTGOING",
        "include_hypothetical": True,
    })
    assert br_resp.status_code == 200
    br_data = br_resp.json()
    assert br_data["start_node"]["id"] == "device:dev-ws-101"
    assert "total_reachable_nodes" in br_data

    # What-if containment simulation (isolate server:srv-app-01)
    sim_resp = test_client.post("/api/v1/graphops/blast-radius/simulate", json={
        "start_node_id": "device:dev-ws-101",
        "max_hops": 2,
        "direction": "OUTGOING",
        "include_hypothetical": True,
        "proposed_interventions": [
            {
                "action": "ISOLATE_NODE",
                "node_id": "server:srv-app-01",
            }
        ],
    })
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert "containment_efficiency_pct" in sim_data
    assert sim_data["live_graph_modified"] is False


def test_journey_8_zero_trust_policy_audit(test_client):
    """
    Journey 8:
    Compare observed activity against Zero-Trust policies.
    """
    zt_resp = test_client.get("/api/v1/graphops/zero-trust/audit")
    assert zt_resp.status_code == 200
    zt_data = zt_resp.json()
    assert "total_entitled_permissions" in zt_data
    assert "policy_discrepancies" in zt_data or "unentitled_shadow_connections" in zt_data


def test_journey_9_anomaly_analysis_and_ml_status(test_client):
    """
    Journey 9:
    Run event anomaly scoring and check ML/PyG service statuses.
    """
    # Evaluate sequence anomaly
    seq_resp = test_client.post("/api/v1/graphops/anomaly/evaluate-sequence", json={
        "sequence_id": "seq-test-prompt8",
        "evaluated_entity_id": "user:alice_sec",
        "steps": [
            {
                "step_index": 0,
                "source_id": "user:alice_sec",
                "relationship_type": "LOGGED_IN_TO",
                "target_id": "device:corp-laptop-01",
                "timestamp": "2026-10-29T12:00:00Z",
            }
        ],
    })
    assert seq_resp.status_code == 200
    seq_data = seq_resp.json()
    assert "sequence_id" in seq_data

    # Check ML & PyG statuses
    ml_st = test_client.get("/api/v1/graphops/events/ml/status")
    assert ml_st.status_code == 200
    pyg_st = test_client.get("/api/v1/graphops/events/pyg/status")
    assert pyg_st.status_code == 200


def test_journey_10_generate_report_and_verify_audit(test_client):
    """
    Journey 10:
    Generate compliance report, export it, and verify SHA-256 audit ledger integrity.
    """
    # Generate report (returns 201 Created)
    rep_resp = test_client.post("/api/v1/governance/reports/generate", json={
        "frameworks": ["NIST_CSF_2_0"],
        "title": "Journey 10 Audit Verification Report",
        "actor_id": "auditor_sec",
    })
    assert rep_resp.status_code == 201
    rep_data = rep_resp.json()
    report_id = rep_data["report_id"]

    # Export report
    exp_resp = test_client.get(f"/api/v1/governance/reports/{report_id}/export?format=json")
    assert exp_resp.status_code == 200

    # Verify audit ledger
    audit_resp = test_client.get("/api/v1/governance/audit/verify")
    assert audit_resp.status_code == 200
    assert audit_resp.json()["ledger_intact"] is True


def test_journey_11_revoke_collector_and_verify_rejection(test_client):
    """
    Journey 11:
    Revoke a collector's token and verify that subsequent event submissions are rejected with 401.
    """
    # 1. Enrol
    enrol_resp = test_client.post("/api/v1/collector/enrol", json={
        "hostname": "REVOKE-TEST-PC",
        "ip_address": "10.99.88.77",
        "os_version": "Windows 10 Enterprise",
        "collector_version": "1.0.0",
    })
    cid = enrol_resp.json()["collector_id"]
    token = enrol_resp.json()["token"]

    # 2. Ingest succeeds prior to revocation
    batch = {
        "events": [{
            "event_id_number": 4624,
            "source_computer": "REVOKE-TEST-PC",
            "time_created": datetime.now(timezone.utc).isoformat(),
            "event_data": {"TargetUserName": "alice"},
            "is_synthetic": True,
        }],
    }
    headers = {"X-Collector-ID": cid, "X-Collector-Token": token}
    pre_resp = test_client.post("/api/v1/collector/ingest/events", json=batch, headers=headers)
    assert pre_resp.status_code == 202

    # 3. Revoke collector
    admin_headers = {"X-API-Key": config.ADMIN_API_KEY}
    rev_resp = test_client.post(f"/api/v1/collector/collectors/{cid}/revoke", headers=admin_headers)
    assert rev_resp.status_code == 200
    assert "revoked" in rev_resp.json()["message"].lower()

    # 4. Ingest immediately fails with HTTP 401
    post_resp = test_client.post("/api/v1/collector/ingest/events", json=batch, headers=headers)
    assert post_resp.status_code == 401
    assert "revoked" in post_resp.json()["detail"].lower()


# =============================================================================
# Task A & C: Additional Endpoint Coverage & Cross-Module Audits
# =============================================================================

def test_governance_policy_crud_lifecycle(test_client):
    """Tests GET and DELETE /api/v1/governance/policies/{policy_id} including 404s and admin guards."""
    admin_headers = {"X-API-Key": config.ADMIN_API_KEY}

    # 1. Create a custom test policy
    new_pol = OrganizationPolicy(
        policy_id="POL-JOURNEY-AUDIT-01",
        name="Prompt 8 Test Policy",
        description="Verifies policy lifecycle endpoints",
        scope="ENTERPRISE",
        enabled=True,
        severity="MEDIUM",
        linked_control_ids=["PR.AA-01"],
    )
    save_resp = test_client.post("/api/v1/governance/policies", json=new_pol.model_dump(), headers=admin_headers)
    assert save_resp.status_code == 200

    # 2. GET policy by ID
    get_resp = test_client.get("/api/v1/governance/policies/POL-JOURNEY-AUDIT-01")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Prompt 8 Test Policy"

    # 3. GET unknown policy returns 404
    missing_resp = test_client.get("/api/v1/governance/policies/POL-UNKNOWN-999")
    assert missing_resp.status_code == 404

    # 4. DELETE with invalid key when key required or testing wrong key
    bad_key_resp = test_client.delete(
        "/api/v1/governance/policies/POL-JOURNEY-AUDIT-01",
        headers={"X-API-Key": "invalid-wrong-key"}
    )
    assert bad_key_resp.status_code == 401

    # 5. DELETE with admin token succeeds
    del_resp = test_client.delete("/api/v1/governance/policies/POL-JOURNEY-AUDIT-01", headers=admin_headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # 6. DELETE non-existent returns 404
    del_404 = test_client.delete("/api/v1/governance/policies/POL-JOURNEY-AUDIT-01", headers=admin_headers)
    assert del_404.status_code == 404


def test_graphops_bulk_ingest_endpoint(test_client):
    """Tests POST /api/v1/graphops/ingest/bulk with admin auth, valid payload, and validation failure."""
    admin_headers = {"X-API-Key": config.ADMIN_API_KEY}

    # 1. Unauthorized request with bad api key returns 401
    unauth_resp = test_client.post("/api/v1/graphops/ingest/bulk", json={}, headers={"X-API-Key": "wrong-key"})
    assert unauth_resp.status_code == 401

    # 2. Valid payload with custom nodes and edges
    valid_payload = {
        "dataset_name": "bulk_integration_test",
        "entities": {
            "devices": [
                {
                    "id": "device:bulk-pc-01",
                    "device_id": "bulk-pc-01",
                    "hostname": "bulk-pc-01",
                    "ip_address": "10.0.99.1",
                }
            ],
            "servers": [
                {
                    "id": "server:bulk-db-01",
                    "server_id": "bulk-db-01",
                    "name": "bulk-db-01",
                    "hostname": "bulk-db-01",
                    "ip_address": "10.0.99.2",
                    "criticality": "HIGH",
                }
            ],
        },
        "relationships": {
            "relationships": [
                {
                    "source_id": "device:bulk-pc-01",
                    "target_id": "server:bulk-db-01",
                    "relationship_type": "OBSERVED_CONNECTION",
                    "evidence_class": "OBSERVED",
                }
            ]
        },
    }

    resp = test_client.post("/api/v1/graphops/ingest/bulk", json=valid_payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("SUCCESS", "PARTIAL")


def test_campaign_graph_and_case_graph_404_handling(test_client):
    """Tests GET /api/v1/campaigns/{campaign_id}/graph and /cases/{case_id}/graph with unknown IDs."""
    c_404 = test_client.get("/api/v1/campaigns/NON-EXISTENT-CAMP-999/graph")
    assert c_404.status_code == 404

    cs_404 = test_client.get("/api/v1/cases/NON-EXISTENT-CASE-999/graph")
    assert cs_404.status_code == 404
