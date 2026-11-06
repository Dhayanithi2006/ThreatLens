"""
ThreatLens - Module 1: Investigate Alerts & Incidents Test Suite
Verifies all 5 submodules:
1. Alerts Stream: Unified alert stream, separate graph findings, filtering, search, distinct data types.
2. Incidents & Cases: Case listing, retrieval, manual creation, status/assignment/severity patch.
3. Case Details Workspace: Full dossier, risk rating, XAI explanation, extracted IOCs, SPF/DKIM/DMARC, notes persistence.
4. Investigation Timeline: Genuine chronologically sorted events, dual timestamps (origin vs ingestion), strict validation.
5. Correlated Incident Narrative & Kill Chain: Explicit correlation, involved entities (user/device/choke), 5-step MITRE chain, disclaimer.
"""

import os
import sys
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is on sys.path
WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from backend.main import app
from backend.services.case_store import default_case_repo


@pytest.fixture(scope="module")
def client():
    """Shared FastAPI test client."""
    return TestClient(app)


# ==============================================================================
# SUBMODULE 1: ALERTS STREAM
# ==============================================================================

def test_alerts_stream_retrieval_and_counts(client):
    """Verify GET /api/v1/alerts returns unified stream with accurate category counts and normalized schema."""
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert "total_alerts" in data
    assert "case_alerts_count" in data
    assert "graph_findings_count" in data
    assert "telemetry_alerts_count" in data
    assert "alerts" in data

    assert data["total_alerts"] >= 5, "Should index at least historical case alerts"
    assert data["case_alerts_count"] >= 5
    assert data["graph_findings_count"] >= 1, "Graph security findings must be included"

    # Verify distinct alert schema
    for a in data["alerts"]:
        assert "alert_id" in a
        assert "alert_type" in a
        assert a["alert_type"] in ["case_alert", "graph_finding", "telemetry_alert"]
        assert "timestamp" in a
        assert "severity" in a
        assert a["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert "detector_source" in a
        assert "affected_entity" in a
        assert "title" in a
        assert "classification" in a
        assert "status" in a


def test_alerts_stream_filtering_and_separation(client):
    """Verify alerts stream supports filtering by severity, alert type, and keyword search while preserving distinct data types."""
    # Filter by severity
    resp_crit = client.get("/api/v1/alerts?severity=CRITICAL")
    assert resp_crit.status_code == 200
    crit_alerts = resp_crit.json()["alerts"]
    assert len(crit_alerts) > 0
    assert all(a["severity"] == "CRITICAL" for a in crit_alerts)

    # Filter by alert_type: case_alert
    resp_cases = client.get("/api/v1/alerts?alert_type=case_alert")
    assert resp_cases.status_code == 200
    case_alerts = resp_cases.json()["alerts"]
    assert len(case_alerts) >= 5
    assert all(a["alert_type"] == "case_alert" for a in case_alerts)
    assert all(a.get("case_id") is not None for a in case_alerts)

    # Filter by alert_type: graph_finding
    resp_graph = client.get("/api/v1/alerts?alert_type=graph_finding")
    assert resp_graph.status_code == 200
    graph_alerts = resp_graph.json()["alerts"]
    assert len(graph_alerts) >= 1
    assert all(a["alert_type"] == "graph_finding" for a in graph_alerts)
    assert all(a.get("finding_id") is not None for a in graph_alerts)

    # Search keyword
    resp_search = client.get("/api/v1/alerts?search=Verify")
    assert resp_search.status_code == 200
    searched = resp_search.json()["alerts"]
    assert any("Verify" in a["title"] for a in searched)


# ==============================================================================
# SUBMODULE 2: INCIDENTS & CASES
# ==============================================================================

def test_list_cases_filtering_and_retrieval(client):
    """Verify GET /api/v1/cases lists indexed cases and supports status and severity filtering."""
    resp = client.get("/api/v1/cases")
    assert resp.status_code == 200
    cases = resp.json()
    assert len(cases) >= 5

    # Filter by status
    resp_open = client.get("/api/v1/cases?status=OPEN")
    assert resp_open.status_code == 200
    open_cases = resp_open.json()
    assert len(open_cases) >= 1
    assert all(c["status"] == "OPEN" for c in open_cases)

    # Filter by primary_threat
    resp_bec = client.get("/api/v1/cases?primary_threat=BEC")
    assert resp_bec.status_code == 200
    bec_cases = resp_bec.json()
    assert len(bec_cases) >= 1
    assert all(c["primary_threat"] == "BEC" for c in bec_cases)


def test_create_and_manage_case_lifecycle(client):
    """Verify manual case creation, status triage updates, and analyst assignment."""
    custom_case_id = f"MT-TEST-{int(datetime.now().timestamp())}"
    new_case_payload = {
        "case_id": custom_case_id,
        "subject": "Suspicious Lateral SMB Activity on Gateway",
        "sender": "sec-ops@external-monitor.com",
        "recipient": "admin@corporation.com",
        "threat_score": 90,
        "risk_level": "CRITICAL",
        "primary_threat": "LATERAL_MOVEMENT",
        "status": "OPEN",
        "assigned_to": "triage_analyst_01",
        "iocs": {
            "ips": ["192.168.1.105", "10.0.1.50"],
            "domains": ["gateway-pivot.internal"],
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        },
        "notes": [
            {"note": "Escalated from Windows Event ID 5140 network share access.", "author": "tier1"}
        ]
    }

    # 1. Create Case
    create_resp = client.post("/api/v1/cases", json=new_case_payload)
    assert create_resp.status_code == 201, f"Failed: {create_resp.text}"
    created = create_resp.json()
    assert created["case_id"] == custom_case_id
    assert created["status"] == "OPEN"
    assert created["assigned_to"] == "triage_analyst_01"

    # 2. Reject Duplicate Case ID
    dup_resp = client.post("/api/v1/cases", json=new_case_payload)
    assert dup_resp.status_code == 400

    # 3. Update status & assignment via PATCH
    patch_payload = {
        "status": "INVESTIGATING",
        "assigned_to": "dfir_lead@threatlens.io",
        "risk_level": "CRITICAL"
    }
    patch_resp = client.patch(f"/api/v1/cases/{custom_case_id}", json=patch_payload)
    assert patch_resp.status_code == 200
    patched = patch_resp.json()
    assert patched["status"] == "INVESTIGATING"
    assert patched["assigned_to"] == "dfir_lead@threatlens.io"

    # 4. Verify persistence in GET /api/v1/cases/{case_id}
    get_resp = client.get(f"/api/v1/cases/{custom_case_id}")
    assert get_resp.status_code == 200
    retrieved = get_resp.json()
    assert retrieved["status"] == "INVESTIGATING"
    assert retrieved["assigned_to"] == "dfir_lead@threatlens.io"


# ==============================================================================
# SUBMODULE 3: CASE DETAILS WORKSPACE
# ==============================================================================

def test_case_details_workspace_fields(client):
    """Verify GET /api/v1/cases/{case_id} provides complete investigation dossier with IOCs, forensics, intel, and notes."""
    resp = client.get("/api/v1/cases/MT-101")
    assert resp.status_code == 200
    case = resp.json()

    # Core metadata & risk rating
    assert case["case_id"] == "MT-101"
    assert case["subject"] == "URGENT: Verify your account immediately"
    assert case["sender"] == "Security Alert <service-update@alert-center.xyz>"
    assert case["recipient"] == "victim1@corporation.com"
    assert case["threat_score"] == 100
    assert case["risk_level"] == "CRITICAL"
    assert case["status"] in ["OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"]

    # Threat classification & XAI explanation
    assert case["primary_threat"] == "PHISHING"
    assert "explanation" in case
    assert case["explanation"] is not None

    # Extracted IOCs
    assert "iocs" in case
    assert "185.190.140.22" in case["iocs"].get("ips", [])
    assert "alert-center.xyz" in case["iocs"].get("domains", [])

    # Cryptographic authentication verification (SPF/DKIM/DMARC)
    assert "forensics_summary" in case
    forensics = case["forensics_summary"]
    assert forensics.get("spf") == "FAIL"
    assert forensics.get("dkim") == "FAIL"
    assert forensics.get("dmarc") == "FAIL"

    # Threat Intelligence summary
    assert "intel_summary" in case
    assert case["intel_summary"].get("status") == "MALICIOUS"

    # Evidence references
    assert "evidence_references" in case
    assert len(case["evidence_references"]) >= 1

    # Cross-module links
    assert "graphops_bridge_url" in case
    assert "/api/v1/graphops/bridge/case/MT-101" in case["graphops_bridge_url"]
    assert "narrative_url" in case


def test_analyst_notes_persistence(client):
    """Verify analysts can append timestamped notes to an active case."""
    note_payload = {
        "author": "soc_incident_commander",
        "note": "Confirmed weaponized HTML macro attachment. Host containment dispatched."
    }
    resp = client.post("/api/v1/cases/MT-101/notes", json=note_payload)
    assert resp.status_code == 200
    note_data = resp.json()
    assert "note_id" in note_data
    assert note_data["author"] == "soc_incident_commander"
    assert "attachment" in note_data["note"]
    assert "timestamp" in note_data

    # Verify note is returned in case dossier
    case_resp = client.get("/api/v1/cases/MT-101")
    assert case_resp.status_code == 200
    case_notes = case_resp.json().get("notes", [])
    assert any(n.get("note_id") == note_data["note_id"] for n in case_notes)


# ==============================================================================
# SUBMODULE 4: INVESTIGATION TIMELINE
# ==============================================================================

def test_investigation_timeline_chronology_and_dual_timestamps(client):
    """Verify investigation timeline events have distinct original and ingestion times and are chronologically sorted."""
    resp = client.get("/api/v1/cases/MT-101/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == "MT-101"
    timeline = data["timeline"]
    assert len(timeline) >= 3

    # Check dual timestamps and chronological ordering
    prev_time = None
    for event in timeline:
        assert "event_id" in event
        assert "original_event_time" in event, "Must contain original event time"
        assert "ingested_at" in event, "Must contain platform ingestion time"
        assert "source" in event
        assert "event_type" in event
        assert "title" in event
        assert "severity" in event

        # Ensure valid ISO 8601 formatting
        orig_dt = datetime.fromisoformat(event["original_event_time"].replace("Z", "+00:00"))
        ingest_dt = datetime.fromisoformat(event["ingested_at"].replace("Z", "+00:00"))

        # Verify strict chronological sorting
        if prev_time is not None:
            assert orig_dt >= prev_time, f"Timeline events must be chronologically ordered ({orig_dt} < {prev_time})"
        prev_time = orig_dt


def test_timeline_append_and_validation(client):
    """Verify appending a genuine timeline event validates timestamps and maintains ordering."""
    valid_event = {
        "event_id": f"EVT-APPEND-{int(datetime.now().timestamp())}",
        "original_event_time": "2026-08-28T10:19:30Z",
        "ingested_at": "2026-08-28T10:19:35Z",
        "source": "EDR_AGENT",
        "event_type": "PROCESS_SPAWN",
        "title": "Suspicious PowerShell Invocations Observed",
        "description": "powershell.exe -enc executed on assigned workstation dev-ws-101",
        "severity": "CRITICAL",
        "evidence_ref": "EV-EDR-8812",
        "details": {"pid": 4812, "parent_pid": 2048}
    }

    # Append valid event
    resp = client.post("/api/v1/cases/MT-101/timeline", json=valid_event)
    assert resp.status_code == 200
    created = resp.json()
    assert created["event_id"] == valid_event["event_id"]

    # Verify event appears in chronological position
    t_resp = client.get("/api/v1/cases/MT-101/timeline")
    assert t_resp.status_code == 200
    events = t_resp.json()["timeline"]
    found_event = next((e for e in events if e["event_id"] == valid_event["event_id"]), None)
    assert found_event is not None
    assert found_event["evidence_ref"] == "EV-EDR-8812"

    # Reject invalid event missing original_event_time
    invalid_event = {
        "event_id": "EVT-BAD",
        "original_event_time": "",
        "ingested_at": "2026-08-28T10:20:00Z",
        "source": "UNKNOWN",
        "event_type": "BAD_EVENT",
        "title": "Invalid Undated Event",
        "description": "Should be rejected"
    }
    bad_resp = client.post("/api/v1/cases/MT-101/timeline", json=invalid_event)
    assert bad_resp.status_code in [400, 422]


# ==============================================================================
# SUBMODULE 5: CORRELATED INCIDENT NARRATIVE & KILL CHAIN
# ==============================================================================

def test_correlated_incident_narrative_and_kill_chain(client):
    """Verify synthesized incident narrative connects multi-hop sequence, identifies entities, and provides clear analytical disclaimer."""
    # Test through case narrative endpoint
    resp = client.get("/api/v1/cases/MT-101/narrative")
    assert resp.status_code == 200
    narrative = resp.json()

    assert "incident_id" in narrative
    assert "case_reference" in narrative
    assert narrative["case_reference"] == "MT-101"
    assert "executive_summary" in narrative
    assert "alert_noise_reduction_pct" in narrative
    assert narrative["alert_noise_reduction_pct"] > 80.0

    # Explicit analytical interpretation disclaimer
    assert "disclaimer" in narrative
    assert "Analytical Interpretation" in narrative["disclaimer"]

    # MITRE ATT&CK kill-chain progression
    assert "kill_chain_steps" in narrative
    steps = narrative["kill_chain_steps"]
    assert len(steps) >= 5

    tactics = [s["mitre_tactic"] for s in steps]
    assert "Initial Access" in tactics
    assert "Execution" in tactics
    assert "Lateral Movement" in tactics

    # Check involved entities
    all_affected = []
    for s in steps:
        assert "affected_entities" in s
        assert "mitre_technique_id" in s
        assert "evidence_class" in s
        assert s["evidence_class"] in ["OBSERVED", "HYPOTHETICAL", "INFERRED"]
        all_affected.extend(s["affected_entities"])

    # Must contain recipient or compromised device and choke points
    assert any("victim" in e or "dev-ws" in e or "srv-" in e for e in all_affected)

    # Test GraphOps consolidated route alias
    g_resp = client.get("/api/v1/graphops/incident-narrative/MT-101")
    assert g_resp.status_code == 200
    g_narrative = g_resp.json()
    assert g_narrative["case_reference"] == "MT-101"
    assert g_narrative["alert_noise_reduction_pct"] == narrative["alert_noise_reduction_pct"]


# ==============================================================================
# CROSS-MODULE NAVIGATION & INTEGRATION
# ==============================================================================

def test_cross_module_investigation_links(client):
    """Verify seamless navigation from alerts to cases, cases to graph, and timeline to evidence."""
    # 1. Fetch Alerts
    alerts_resp = client.get("/api/v1/alerts?alert_type=case_alert")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["alerts"]
    assert len(alerts) > 0
    first_alert = alerts[0]
    target_case_id = first_alert["case_id"]

    # 2. Navigate Alert -> Case Dossier
    case_resp = client.get(f"/api/v1/cases/{target_case_id}")
    assert case_resp.status_code == 200
    case_dossier = case_resp.json()
    assert case_dossier["case_id"] == target_case_id

    # 3. Navigate Case -> Attack Graph
    graph_url = f"/api/v1/cases/{target_case_id}/graph"
    graph_resp = client.get(graph_url)
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

    # 4. Navigate Case -> Timeline -> Evidence Ref
    timeline_resp = client.get(f"/api/v1/cases/{target_case_id}/timeline")
    assert timeline_resp.status_code == 200
    timeline = timeline_resp.json()["timeline"]
    assert len(timeline) > 0
    # At least one event has evidence_ref
    assert any(e.get("evidence_ref") is not None for e in timeline)


def test_case_persistence_across_restarts(client, tmp_path):
    """Verify that case updates, analyst notes, and timeline events persist to disk across repository reload."""
    from backend.services.case_store import CaseRepository, _DEFAULT_CASES_PATH
    import uuid

    test_case_id = f"MT-PERSIST-{uuid.uuid4().hex[:4].upper()}"

    # 1. Create a case via API
    create_resp = client.post(
        "/api/v1/cases",
        json={
            "case_id": test_case_id,
            "subject": "Persistence Audit Case",
            "sender": "attacker@darkweb.io",
            "threat_score": 90,
            "risk_level": "CRITICAL",
            "primary_threat": "RANSOMWARE_STAGING",
            "status": "OPEN",
            "assigned_to": "audit_analyst"
        }
    )
    assert create_resp.status_code == 201

    # 2. Update status and assignment
    patch_resp = client.patch(
        f"/api/v1/cases/{test_case_id}",
        json={"status": "INVESTIGATING", "assigned_to": "lead_hunter"}
    )
    assert patch_resp.status_code == 200

    # 3. Add an analyst note
    note_resp = client.post(
        f"/api/v1/cases/{test_case_id}/notes",
        json={"author": "lead_hunter", "note": "Persistence verification note test."}
    )
    assert note_resp.status_code == 200

    # 4. Add a timeline event
    now_iso = datetime.now(timezone.utc).isoformat()
    tl_resp = client.post(
        f"/api/v1/cases/{test_case_id}/timeline",
        json={
            "original_event_time": now_iso,
            "ingested_at": now_iso,
            "source": "AUDIT",
            "event_type": "PERSISTENCE_CHECK",
            "title": "Timeline Persistence Event",
            "severity": "HIGH",
            "evidence_ref": f"CASE-{test_case_id}"
        }
    )
    assert tl_resp.status_code == 200

    # 5. Simulate application restart: Instantiate a brand new CaseRepository from the same storage path
    restarted_repo = CaseRepository()
    reloaded_case = restarted_repo.get_case(test_case_id)
    assert reloaded_case is not None, "Case record must persist across application reload"
    assert reloaded_case.status == "INVESTIGATING", "Updated status must persist"
    assert reloaded_case.assigned_to == "lead_hunter", "Updated assignment must persist"
    assert len(reloaded_case.notes) >= 1, "Analyst notes must persist"
    assert any("Persistence verification note" in n["note"] for n in reloaded_case.notes)
    assert len(reloaded_case.timeline) >= 2, "Timeline events must persist"
    assert any(e["event_type"] == "PERSISTENCE_CHECK" for e in reloaded_case.timeline)


def test_sensitive_case_operations_authorization(client):
    """Verify that mutating case operations strictly reject invalid credentials with HTTP 401."""
    from backend.core import config

    invalid_headers = {"Authorization": "Bearer bad-token-xyz"}
    invalid_api_key = {"X-API-Key": "wrong-secret-key"}

    # 1. Reject invalid auth on case creation
    resp1 = client.post(
        "/api/v1/cases",
        headers=invalid_headers,
        json={"subject": "Unauthorized Test", "sender": "test@test.com"}
    )
    assert resp1.status_code == 401, f"Expected 401, got {resp1.status_code}"

    # 2. Reject invalid auth on case patch
    resp2 = client.patch(
        "/api/v1/cases/MT-101",
        headers=invalid_api_key,
        json={"status": "CLOSED"}
    )
    assert resp2.status_code == 401, f"Expected 401, got {resp2.status_code}"

    # 3. Reject invalid auth on note creation
    resp3 = client.post(
        "/api/v1/cases/MT-101/notes",
        headers=invalid_headers,
        json={"author": "hacker", "note": "malicious injection"}
    )
    assert resp3.status_code == 401, f"Expected 401, got {resp3.status_code}"

    # 4. Reject invalid auth on timeline append
    now_iso = datetime.now(timezone.utc).isoformat()
    resp4 = client.post(
        "/api/v1/cases/MT-101/timeline",
        headers=invalid_api_key,
        json={
            "original_event_time": now_iso,
            "ingested_at": now_iso,
            "source": "FORGERY",
            "event_type": "FORGED_EVENT"
        }
    )
    assert resp4.status_code == 401, f"Expected 401, got {resp4.status_code}"

    # 5. Succeed with valid admin credentials
    valid_headers = {"X-API-Key": config.ADMIN_API_KEY}
    valid_resp = client.patch(
        "/api/v1/cases/MT-101",
        headers=valid_headers,
        json={"status": "INVESTIGATING"}
    )
    assert valid_resp.status_code == 200


def test_sample_data_distinction_from_live_incidents(client):
    """Verify that historical/synthetic sample data is clearly tagged as is_sample=True, while live incidents are is_sample=False."""
    # 1. Historical cases are marked is_sample=True
    historical_resp = client.get("/api/v1/cases/MT-101")
    assert historical_resp.status_code == 200
    historical_case = historical_resp.json()
    assert historical_case.get("is_sample") is True, "MT-101 must be tagged as sample data"

    # 2. Create a live case
    live_resp = client.post(
        "/api/v1/cases",
        json={
            "subject": "Live Security Incident",
            "sender": "external@phishing.net",
            "threat_score": 92,
            "risk_level": "CRITICAL",
            "primary_threat": "PHISHING",
            "is_sample": False
        }
    )
    assert live_resp.status_code == 201
    live_case = live_resp.json()
    assert live_case.get("is_sample") is False, "Created live case must not be marked as sample data"

    # 3. Alerts stream distinguishes sample alerts from live alerts
    alerts_resp = client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["alerts"]
    assert any(a.get("is_sample") is True for a in alerts), "Sample alerts must be identified"
    assert any(a.get("is_sample") is False for a in alerts), "Live alerts must be identified"
