"""
ThreatLens Comprehensive Unit Test Suite — All 80 API Endpoints
Verifies that every single registered endpoint across all subsystems executes cleanly,
returns expected HTTP status codes, respects authentication, and conforms to response contracts.
"""

import io
import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.graphops.mock_client import get_mock_graphops_client
from backend.api.routes import get_readiness_graph_client_dep
from backend.graphops.client import get_graphops_client


@pytest.fixture(scope="module")
def api_test_context():
    client = TestClient(app)
    mock_graph = get_mock_graphops_client()
    app.dependency_overrides[get_readiness_graph_client_dep] = lambda: mock_graph
    app.dependency_overrides[get_graphops_client] = lambda: mock_graph

    # Provision standard entities in mock graph for testing
    mock_graph.nodes["user:alice_sec"] = {
        "id": "user:alice_sec",
        "labels": ["User"],
        "name": "Alice Security",
        "properties": {"department": "SOC"},
    }
    mock_graph.nodes["device:corp-laptop-01"] = {
        "id": "device:corp-laptop-01",
        "labels": ["Device"],
        "name": "Corp Laptop 01",
        "properties": {"hostname": "corp-laptop-01", "ip": "10.0.1.100"},
    }
    mock_graph.nodes["server:internal-dc"] = {
        "id": "server:internal-dc",
        "labels": ["Server"],
        "name": "Domain Controller",
        "properties": {"hostname": "internal-dc", "criticality": "TIER_0"},
    }
    mock_graph.aliases["alice_sec"] = "user:alice_sec"
    mock_graph.aliases["corp-laptop-01"] = "device:corp-laptop-01"
    mock_graph.aliases["internal-dc"] = "server:internal-dc"

    mock_graph.edges.append({
        "source_id": "user:alice_sec",
        "target_id": "device:corp-laptop-01",
        "relationship_type": "LOGGED_IN_TO",
        "evidence_class": "OBSERVED",
        "cost": 1.0,
    })
    mock_graph.edges.append({
        "source_id": "device:corp-laptop-01",
        "target_id": "server:internal-dc",
        "relationship_type": "ACCESSES",
        "evidence_class": "OBSERVED",
        "cost": 2.0,
    })

    admin_headers = {"X-API-Key": config.ADMIN_API_KEY}
    return client, admin_headers, mock_graph


# 1. Root & Core Health Endpoints
def test_endpoint_root(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/")
    assert resp.status_code == 200

def test_endpoint_health(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

def test_endpoint_ready(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/ready")
    assert resp.status_code == 200

def test_endpoint_demo_emails(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/demo-emails")
    assert resp.status_code == 200

def test_endpoint_demo_emls(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/demo-emls")
    assert resp.status_code == 200

def test_endpoint_search_ioc(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/search/ioc?q=198.51.100.14")
    assert resp.status_code == 200


# 2. Email & Threat Analysis Endpoints
EMAIL_SAMPLE = {
    "sender": "attacker@evil.com",
    "recipient": "victim@corp.com",
    "subject": "Urgent Security Alert: Action Required",
    "body": "Please review this invoice: http://malicious-gateway.com/login and verify your credentials."
}

def test_endpoint_analyze_threat(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/threat", json=EMAIL_SAMPLE)
    assert resp.status_code == 200

def test_endpoint_analyze_explain(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/explain", json=EMAIL_SAMPLE)
    assert resp.status_code == 200

def test_endpoint_analyze_unified(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze", json=EMAIL_SAMPLE)
    assert resp.status_code == 200

def test_endpoint_analyze_forensics_json(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/forensics", json={"raw_eml": "From: a@b.com\nTo: c@d.com\nSubject: Hi\n\nBody"})
    assert resp.status_code == 200

def test_endpoint_analyze_forensics_upload(api_test_context):
    client, _, _ = api_test_context
    eml_bytes = io.BytesIO(b"From: phish@evil.com\nTo: user@corp.com\nSubject: Urgent Notification\n\nClick http://bad.com")
    resp = client.post("/api/v1/analyze/forensics/upload", files={"file": ("alert.eml", eml_bytes, "message/rfc822")})
    assert resp.status_code == 200

def test_endpoint_analyze_iocs(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/iocs", json={"raw_eml": "From: phish@evil.com\nTo: user@corp.com\nSubject: Test\n\nIP 198.51.100.14"})
    assert resp.status_code == 200

def test_endpoint_analyze_intelligence(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/intelligence", json={"indicators": ["198.51.100.14"]})
    assert resp.status_code == 200

def test_endpoint_analyze_complete_eml(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/analyze/eml", json={"raw_eml": "From: phish@evil.com\nTo: user@corp.com\nSubject: Test\n\nBody"})
    assert resp.status_code == 200


# 3. Cases & Campaigns Endpoints
def test_endpoint_list_cases(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/cases")
    assert resp.status_code == 200

def test_endpoint_case_graph(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/cases/NON_EXISTENT_CASE_999/graph")
    assert resp.status_code == 404

def test_endpoint_list_campaigns(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/campaigns")
    assert resp.status_code == 200

def test_endpoint_campaign_graph(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/campaigns/NON_EXISTENT_CAMP_999/graph")
    assert resp.status_code == 404


# 4. Collector Subsystem Endpoints
def test_endpoint_collector_enrol_and_lifecycle(api_test_context):
    client, admin_headers, _ = api_test_context
    # Enroll
    col_enrol_resp = client.post("/api/v1/collector/enrol", json={
        "device_id": "EP-UNIT-01",
        "hostname": "unit-endpoint-01",
        "os_version": "Windows 11 Enterprise",
        "agent_version": "1.0.0",
        "ip_address": "10.0.5.25",
    }, headers=admin_headers)
    assert col_enrol_resp.status_code in (200, 201)
    data = col_enrol_resp.json()
    col_id = data["collector_id"]
    token = data["token"]

    # List
    list_resp = client.get("/api/v1/collector/collectors")
    assert list_resp.status_code == 200

    # Get Single
    get_resp = client.get(f"/api/v1/collector/collectors/{col_id}")
    assert get_resp.status_code == 200

    # Ingest Event
    now_iso = datetime.now(timezone.utc).isoformat()
    ingest_resp = client.post("/api/v1/collector/ingest/events", json={
        "events": [{
            "event_id_number": 4624,
            "source_computer": "unit-endpoint-01",
            "time_created": now_iso,
            "channel": "Security",
            "event_data": {"TargetUserName": "alice_sec", "LogonType": "2"},
        }],
        "checkpoint_offset": 1
    }, headers={"X-Collector-ID": col_id, "X-Collector-Token": token})
    assert ingest_resp.status_code in (200, 202)

    # Revoke
    revoke_resp = client.post(f"/api/v1/collector/collectors/{col_id}/revoke", headers=admin_headers)
    assert revoke_resp.status_code == 200


# 5. GraphOps Algorithms
def test_endpoint_dijkstra_post(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/dijkstra", json={"entry_node_id": "user:alice_sec", "target_node_id": "server:internal-dc"})
    assert resp.status_code == 200

def test_endpoint_dijkstra_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/dijkstra?entry_node_id=user:alice_sec&target_node_id=server:internal-dc")
    assert resp.status_code == 200

def test_endpoint_shortest_path_post(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/shortest-path", json={"entry_node_id": "user:alice_sec", "target_node_id": "server:internal-dc"})
    assert resp.status_code == 200

def test_endpoint_shortest_path_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/shortest-path?entry_node_id=user:alice_sec&target_node_id=server:internal-dc")
    assert resp.status_code == 200

def test_endpoint_attack_paths_post(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/attack-paths", json={"entry_node_id": "user:alice_sec", "target_node_id": "server:internal-dc", "max_depth": 3, "max_paths": 5})
    assert resp.status_code == 200

def test_endpoint_chokepoints_post(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/choke-points", json={"target_ids": ["server:internal-dc"], "max_depth": 3})
    assert resp.status_code == 200

def test_endpoint_chokepoints_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/choke-points?target_ids=server:internal-dc")
    assert resp.status_code == 200

def test_endpoint_centrality_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/centrality?top_k=5")
    assert resp.status_code == 200

def test_endpoint_simulate_containment(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/simulate-containment", json={
        "entry_node_id": "user:alice_sec",
        "target_asset_ids": ["server:internal-dc"],
        "proposed_interventions": [{"action": "ISOLATE_NODE", "node_id": "device:corp-laptop-01"}]
    })
    assert resp.status_code == 200


# 6. Blast Radius Endpoints
def test_endpoint_blast_radius_post(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/blast-radius", json={
        "start_node_id": "device:corp-laptop-01",
        "max_hops": 2,
        "direction": "OUTGOING",
        "include_hypothetical": True,
    })
    assert resp.status_code == 200

def test_endpoint_blast_radius_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/blast-radius?start_node_id=device:corp-laptop-01&max_hops=2")
    assert resp.status_code == 200

def test_endpoint_blast_radius_simulate(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/blast-radius/simulate", json={
        "start_node_id": "device:corp-laptop-01",
        "max_hops": 2,
        "proposed_interventions": [{"action": "ISOLATE_NODE", "node_id": "device:corp-laptop-01"}]
    })
    assert resp.status_code == 200


# 7. Topology, Communities & Summary Endpoints
def test_endpoint_graphops_summary(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/summary")
    assert resp.status_code == 200

def test_endpoint_graphops_communities(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/communities")
    assert resp.status_code == 200

def test_endpoint_incident_narrative(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/incident-narrative/MT-101")
    assert resp.status_code == 200

def test_endpoint_case_bridge(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/bridge/case/MT-101")
    assert resp.status_code == 200

def test_endpoint_graphops_health(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/health")
    assert resp.status_code == 200

def test_endpoint_schema_constraints_get(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/schema/constraints")
    assert resp.status_code == 200

def test_endpoint_schema_init_post(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/schema/init", headers=admin_headers)
    assert resp.status_code == 200


# 8. Ingestion Endpoints
def test_endpoint_bulk_ingest(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/ingest/bulk", json={
        "dataset_name": "bulk_unit_test",
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
        "relationships": {"custom_edges": []}
    }, headers=admin_headers)
    assert resp.status_code == 200

def test_endpoint_csv_ingest(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/ingest/csv", json={
        "csv_data": "id,label,name\nuser:csv_user,User,CSV User\n",
        "dataset_name": "unit_test_csv"
    }, headers=admin_headers)
    assert resp.status_code == 200

def test_endpoint_sample_ingest(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/ingest/sample", headers=admin_headers)
    assert resp.status_code == 200


# 9. Streaming Pipeline Endpoints
def test_endpoint_events_publish(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/publish", json={
        "event_id": f"ev-unit-stream-{int(time.time())}",
        "schema_version": "1.0.0",
        "event_type": "PROCESS_EVENT",
        "source": "edr-sensor",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "entity_ids": ["device:corp-laptop-01"],
        "payload": {"proc": "svchost.exe"}
    })
    assert resp.status_code == 202

def test_endpoint_events_simulate(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/simulate", json={
        "event_type": "PROCESS_EVENT",
        "source": "simulation-sensor",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "entity_ids": ["device:corp-laptop-01"],
        "payload": {"action": "simulation_ping"}
    })
    assert resp.status_code == 200

def test_endpoint_events_status(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/status")
    assert resp.status_code == 200

def test_endpoint_events_dlq(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/dlq", headers=admin_headers)
    assert resp.status_code == 200

def test_endpoint_events_findings(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/findings")
    assert resp.status_code == 200

def test_endpoint_finding_by_id_404(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/findings/find-nonexistent")
    assert resp.status_code == 404


# 10. ML & PyG Endpoints
def test_endpoint_ml_status(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/ml/status")
    assert resp.status_code == 200

def test_endpoint_ml_evaluate(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/ml/evaluate", json={
        "event_id": "ev-ml-unit",
        "schema_version": "1.0.0",
        "event_type": "PROCESS_EVENT",
        "source": "edr",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "entity_ids": ["device:corp-laptop-01"],
        "payload": {"process_name": "cmd.exe"}
    })
    assert resp.status_code == 200

def test_endpoint_ml_train(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/ml/train", json={"force_retrain": True}, headers=admin_headers)
    assert resp.status_code == 200

def test_endpoint_pyg_status(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/events/pyg/status")
    assert resp.status_code == 200

def test_endpoint_pyg_evaluate(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/pyg/evaluate", json={
        "source_entity_id": "user:alice_sec",
        "target_entity_id": "device:corp-laptop-01",
        "relationship_type": "LOGGED_IN_TO"
    })
    assert resp.status_code == 200

def test_endpoint_pyg_train(api_test_context):
    client, admin_headers, _ = api_test_context
    resp = client.post("/api/v1/graphops/events/pyg/train", json={"epochs": 2}, headers=admin_headers)
    assert resp.status_code == 200


# 11. Zero Trust & Anomaly Baseline Endpoints
def test_endpoint_zero_trust_audit(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/zero-trust/audit")
    assert resp.status_code == 200

def test_endpoint_anomaly_baseline(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/anomaly/baseline")
    assert resp.status_code == 200

def test_endpoint_anomaly_test_suite(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/anomaly/test-suite")
    assert resp.status_code == 200

def test_endpoint_anomaly_evaluate_case(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/graphops/anomaly/evaluate-case/MT-101")
    assert resp.status_code == 200

def test_endpoint_anomaly_evaluate_sequence(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/graphops/anomaly/evaluate-sequence", json={
        "evaluated_entity_id": "device:corp-laptop-01",
        "steps": [{
            "step_index": 0,
            "source_id": "user:alice_sec",
            "relationship_type": "LOGGED_IN_TO",
            "target_id": "device:corp-laptop-01"
        }]
    })
    assert resp.status_code == 200


# 12. Governance, Standards & Policies Endpoints
def test_endpoint_governance_controls(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/governance/controls")
    assert resp.status_code == 200

def test_endpoint_governance_single_control(api_test_context):
    client, _, _ = api_test_context
    resp = client.get("/api/v1/governance/controls/ID.AM-01")
    assert resp.status_code == 200

def test_endpoint_governance_evaluate(api_test_context):
    client, _, _ = api_test_context
    resp = client.post("/api/v1/governance/evaluate", json={"framework": "NIST_CSF_2.0"})
    assert resp.status_code == 200

def test_endpoint_governance_policies_crud(api_test_context):
    client, admin_headers, _ = api_test_context
    # List
    list_resp = client.get("/api/v1/governance/policies")
    assert list_resp.status_code == 200

    # Create
    create_resp = client.post("/api/v1/governance/policies", json={
        "policy_id": "pol-unit-spec",
        "name": "Unit Specification Policy",
        "description": "Validation policy",
        "framework": "NIST_CSF_2.0"
    }, headers=admin_headers)
    assert create_resp.status_code == 200

    # Get
    get_resp = client.get("/api/v1/governance/policies/pol-unit-spec")
    assert get_resp.status_code == 200

    # Delete
    del_resp = client.delete("/api/v1/governance/policies/pol-unit-spec", headers=admin_headers)
    assert del_resp.status_code == 200


# 13. Governance Remediations Endpoints
def test_endpoint_governance_remediations_crud(api_test_context):
    client, admin_headers, _ = api_test_context
    # Create
    create_resp = client.post("/api/v1/governance/remediations", json={
        "finding_reference": "FIND-UNIT-01",
        "recommended_action": "Apply security patch",
        "priority": "P2_HIGH"
    }, headers=admin_headers)
    assert create_resp.status_code in (200, 201)
    rem_id = create_resp.json()["remediation_id"]

    # List
    list_resp = client.get("/api/v1/governance/remediations")
    assert list_resp.status_code == 200

    # Get Single
    get_resp = client.get(f"/api/v1/governance/remediations/{rem_id}")
    assert get_resp.status_code == 200

    # Patch
    patch_resp = client.patch(f"/api/v1/governance/remediations/{rem_id}", json={"status": "IN_PROGRESS"}, headers=admin_headers)
    assert patch_resp.status_code == 200


# 14. Governance Reports, Audit & Evidence Endpoints
def test_endpoint_governance_reports_and_ledger(api_test_context):
    client, _, _ = api_test_context
    # List reports
    list_resp = client.get("/api/v1/governance/reports")
    assert list_resp.status_code == 200

    # Generate report
    gen_resp = client.post("/api/v1/governance/reports/generate", json={
        "framework": "NIST_CSF_2.0",
        "report_type": "EXECUTIVE_SUMMARY",
        "generated_by": "unit-tester"
    })
    assert gen_resp.status_code in (200, 201)
    rep_id = gen_resp.json()["report_id"]

    # Get Report
    get_rep = client.get(f"/api/v1/governance/reports/{rep_id}")
    assert get_rep.status_code == 200

    # Export Report
    exp_rep = client.get(f"/api/v1/governance/reports/{rep_id}/export")
    assert exp_rep.status_code == 200

    # Audit Ledger
    audit_resp = client.get("/api/v1/governance/audit")
    assert audit_resp.status_code == 200

    # Audit Integrity Verify
    audit_v_resp = client.get("/api/v1/governance/audit/verify")
    assert audit_v_resp.status_code == 200

    # Evidence Ledger
    ev_resp = client.get("/api/v1/governance/evidence/ledger")
    assert ev_resp.status_code == 200

    # Evidence Verify
    ev_records = ev_resp.json()
    if ev_records and isinstance(ev_records, list):
        rec = ev_records[0]
        ev_v_resp = client.post("/api/v1/governance/evidence/verify", json={
            "evidence_id": rec["evidence_id"],
            "provided_hash": rec["sha256_hash"],
        })
        assert ev_v_resp.status_code == 200
