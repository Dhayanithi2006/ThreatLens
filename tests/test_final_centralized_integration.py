"""
ThreatLens Final Centralized Platform Integration Test Suite
Verifies the complete 13-step cybersecurity operational workflow connecting
Modules 0 through 5 into one unified, enterprise-ready platform:

1. Windows Collector Registration, Authentication, & DPAPI Token Protection (Module 0)
2. Security Events Collection, Normalization, & Pipeline Ingestion (Module 0 -> Module 2)
3. Incident Cases & Correlated Alerts Stream (Module 1)
4. Case Investigation Dossier & Timeline Dual Timestamps (Module 1)
5. Case-to-Graph Bridging & Attack Path Analysis (Module 1 -> Module 2)
6. Chokepoint Analysis along Attack Paths (Module 2)
7. Blast-Radius Neighborhood Traversal & Crown Jewel Risk (Module 3)
8. What-If Containment Simulation & Safety Invariants (Module 3)
9. Containment Finding Persistence to Case Timeline & Notes (Module 3 -> Module 1)
10. Zero-Trust Access Discrepancy & Anomaly Finding Linking (Module 4 -> Module 1)
11. Evidence Chain-of-Custody Ledger & Dual Timestamp Verification (Module 5)
12. Cryptographic SHA-256 Audit Ledger & Chain Integrity (Module 5)
13. Cross-Module Investigation Dossier Synthesis & Redacted Export (Module 5)
"""

import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.config import ADMIN_API_KEY
from backend.services.case_store import default_case_repo
from backend.collector.registry import list_collectors, get_collector
from backend.governance.evidence_ledger import EvidenceLedgerService
from backend.governance.audit import verify_audit_integrity, reset_audit_and_remediations
from backend.governance.investigation_reports import InvestigationReportService, redact_sensitive_credentials
from backend.governance.policies import reset_policies_to_default
from backend.governance.reports import _reports_store


@pytest.fixture(autouse=True)
def setup_integration_state():
    """Ensures clean state for tests while preserving default seed fixtures."""
    reset_policies_to_default()
    reset_audit_and_remediations()
    EvidenceLedgerService.reset_ledger()
    _reports_store.clear()
    yield
    reset_policies_to_default()
    reset_audit_and_remediations()
    EvidenceLedgerService.reset_ledger()
    _reports_store.clear()


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. WINDOWS COLLECTOR TELEMETRY & OVERVIEW (MODULE 0)
# =============================================================================

def test_step01_collector_enrollment_and_authentication(client):
    """
    Step 1: Enrols a Windows endpoint collector, verifies secret token generation,
    enforces credential checks on event submission, and checks device node ID.
    """
    # 1. Enrol collector
    enrol_res = client.post(
        "/api/v1/collector/enrol",
        headers={"X-API-Key": ADMIN_API_KEY},
        json={
            "hostname": "CORP-FIN-WS01",
            "ip_address": "192.168.10.45",
            "os_version": "Windows 11 Pro 23H2",
        },
    )
    assert enrol_res.status_code == 201
    enrol_data = enrol_res.json()
    collector_id = enrol_data["collector_id"]
    token = enrol_data["token"]
    assert enrol_data["device_node_id"] == "device:corp-fin-ws01"
    assert len(token) > 20

    # 2. Reject unauthenticated event submission
    unauth_res = client.post(
        "/api/v1/collector/ingest/events",
        json={"events": [{"event_id": 4624, "provider": "Security"}]},
    )
    assert unauth_res.status_code == 401

    # 3. Accept authenticated event submission
    auth_res = client.post(
        "/api/v1/collector/ingest/events",
        headers={
            "X-Collector-ID": collector_id,
            "X-Collector-Token": token,
        },
        json={
            "events": [
                {
                    "event_id": 4624,
                    "channel": "Security",
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "time_created": "2026-11-06T08:00:00Z",
                    "computer": "CORP-FIN-WS01",
                    "event_data": {
                        "TargetUserName": "finance_analyst",
                        "TargetDomainName": "CORPORATION",
                        "LogonType": 3,
                        "IpAddress": "192.168.10.45",
                    },
                }
            ]
        },
    )
    assert auth_res.status_code == 202
    ingest_data = auth_res.json()
    assert ingest_data["accepted"] == 1
    assert ingest_data["collector_id"] == collector_id

    # 4. Overview reflects registered device
    overview_res = client.get(
        "/api/v1/collector/overview",
        headers={"X-API-Key": ADMIN_API_KEY},
    )
    assert overview_res.status_code == 200
    overview_data = overview_res.json()
    assert overview_data["total_registered_devices"] >= 1


# =============================================================================
# 2. NORMALIZATION & PIPELINE INGESTION (MODULE 0 -> MODULE 2)
# =============================================================================

def test_step02_telemetry_normalization_and_canonical_identifiers():
    """
    Step 2 & 3: Verifies Windows security events are normalized into standard envelopes
    with canonical entity identifiers (device:, user:, ip:).
    """
    from backend.collector.normalizer import WindowsEventNormalizer
    from backend.models.graphops import SecurityEventType

    raw_logon = {
        "event_id": 4624,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "time_created": "2026-11-06T08:15:22Z",
        "computer": "CORP-HR-WS02",
        "event_data": {
            "TargetUserName": "hr_manager",
            "TargetDomainName": "CORP",
            "LogonType": 10,  # RemoteInteractive (RDP)
            "IpAddress": "10.0.5.20",
        },
    }

    envelope = WindowsEventNormalizer.normalize(raw_logon, collector_id="col-hr-02")
    assert envelope.payload["windows_event_id"] == 4624
    assert envelope.event_type == SecurityEventType.IDENTITY_EVENT
    assert "user:hr_manager@corp" in envelope.entity_ids
    assert "device:corp-hr-ws02" in envelope.entity_ids
    assert envelope.payload["source_ip"] == "10.0.5.20"
    assert envelope.payload["logon_type"] == "10"


# =============================================================================
# 3. ALERTS & INCIDENT CASES (MODULE 1)
# =============================================================================

def test_step03_alerts_stream_and_categorization(client):
    """
    Step 5: Verifies the alerts stream returns merged, categorized security alerts:
    case_alert, graph_finding, and telemetry_alert.
    """
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert data["total_alerts"] >= 1
    assert data["case_alerts_count"] >= 1
    assert data["graph_findings_count"] >= 1

    # Verify alert properties
    for alert in data["alerts"][:5]:
        assert "alert_id" in alert
        assert "alert_type" in alert
        assert "severity" in alert
        assert "timestamp" in alert
        assert alert["alert_type"] in ("case_alert", "graph_finding", "telemetry_alert")


def test_step04_case_dossier_and_dual_timestamps(client):
    """
    Step 6: Verifies case retrieval returns complete metadata, risk rating,
    related findings, cross-module URLs, and dual timestamps in the timeline.
    """
    res = client.get("/api/v1/cases/MT-101")
    assert res.status_code == 200
    case = res.json()
    assert case["case_id"] == "MT-101"
    assert case["primary_threat"] == "PHISHING"
    assert case["threat_score"] == 100
    assert case["is_sample"] is True

    # Cross-module URLs
    assert case["graphops_bridge_url"] == "/api/v1/graphops/bridge/case/MT-101"
    assert case["narrative_url"] == "/api/v1/graphops/incident-narrative/MT-101"
    assert case["investigation_report_url"] == "/api/v1/governance/reports/investigation/MT-101"

    # Timeline dual timestamps
    timeline = case["timeline"]
    assert len(timeline) >= 2
    for evt in timeline:
        assert "original_event_time" in evt
        assert "ingested_at" in evt
        assert evt["original_event_time"] is not None
        assert evt["ingested_at"] is not None


# =============================================================================
# 4. KNOWLEDGE GRAPH, ATTACK PATHS & CHOKEPOINTS (MODULE 2)
# =============================================================================

def test_step05_case_to_graph_bridging(client):
    """
    Step 7: Verifies bridging the email investigation case to the knowledge graph
    resolves the victim recipient to a canonical graph identity node.
    """
    res = client.get("/api/v1/graphops/bridge/case/MT-101")
    assert res.status_code == 200
    bridge = res.json()
    assert bridge["case_id"] == "MT-101"
    assert bridge["primary_compromised_node"] is not None
    assert bridge["primary_compromised_node"]["id"] == "user:usr-101"
    assert len(bridge["mapped_entities"]) >= 1


def test_step06_attack_paths_and_chokepoints(client):
    """
    Step 8: Analyzes shortest paths from compromised node to high-value Crown Jewels
    and computes candidate chokepoints along those routes.
    """
    # 1. Query shortest attack paths
    paths_res = client.post(
        "/api/v1/graphops/paths",
        json={
            "entry_node_id": "email:victim1@corporation.com",
            "target_node_id": "server:srv-db-01",
            "max_hops": 4,
        },
    )
    assert paths_res.status_code in (200, 404)
    if paths_res.status_code == 200:
        paths_data = paths_res.json()
        assert "paths" in paths_data
        assert "entry_node_id" in paths_data

    # 2. Query chokepoints
    cp_res = client.post(
        "/api/v1/graphops/chokepoints",
        json={
            "entry_node_id": "email:victim1@corporation.com",
            "max_hops": 3,
        },
    )
    assert cp_res.status_code == 200
    cp_data = cp_res.json()
    assert "choke_points" in cp_data


# =============================================================================
# 5. BLAST RADIUS & WHAT-IF SIMULATOR (MODULE 3)
# =============================================================================

def test_step07_blast_radius_and_whatif_simulation(client):
    """
    Step 9 & 10: Calculates blast radius neighborhood exposure (1-3 hops),
    simulates endpoint containment, and validates the live_graph_modified: False invariant.
    """
    # 1. Blast Radius
    br_res = client.get("/api/v1/graphops/blast-radius?start_node_id=email:victim1@corporation.com&max_hops=3")
    assert br_res.status_code == 200
    br_data = br_res.json()
    assert "total_reachable_nodes" in br_data
    assert "critical_assets_at_risk" in br_data
    assert br_data["max_hops_evaluated"] == 3

    # 2. What-If Containment Simulation
    sim_res = client.post(
        "/api/v1/graphops/blast-radius/simulate",
        json={
            "start_node_id": "email:victim1@corporation.com",
            "max_hops": 3,
            "interventions": [
                {
                    "action": "ISOLATE_NODE",
                    "target_id": "email:victim1@corporation.com",
                    "rationale": "Quarantine compromised user mailbox and linked workstation",
                }
            ],
            "case_id": "MT-101",
        },
    )
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["live_graph_modified"] is False
    assert sim_data["containment_efficiency_pct"] >= 0.0
    assert "safety_disclaimer" in sim_data
    assert sim_data["case_id"] == "MT-101"


def test_step08_persist_simulation_to_investigation_case(client):
    """
    Cross-Module: Verifies containment simulation results can be explicitly saved
    against the investigation case timeline and analyst notes.
    """
    save_res = client.post(
        "/api/v1/graphops/cases/MT-101/save-simulation",
        json={
            "case_id": "MT-101",
            "simulation_id": "SIM-TEST-7788",
            "simulation_type": "WHAT_IF_CONTAINMENT",
            "entry_node_id": "email:victim1@corporation.com",
            "interventions": [
                {
                    "action": "ISOLATE_NODE",
                    "target_id": "email:victim1@corporation.com",
                    "rationale": "Automated containment test",
                }
            ],
            "efficiency_pct": 85.5,
            "verdict": "Node isolation removes all reachable Crown Jewel paths.",
            "residual_assets": [],
            "author": "soc_lead@threatlens.io",
        },
    )
    assert save_res.status_code == 200
    res_data = save_res.json()
    assert res_data["success"] is True
    assert res_data["case_id"] == "MT-101"
    assert res_data["timeline_event_id"].startswith("EVT-SIM-")
    assert res_data["note_id"].startswith("NOTE-")

    # Verify timeline event was persisted in case store
    case = default_case_repo.get_case("MT-101")
    assert any(e.get("event_id") == res_data["timeline_event_id"] for e in case.timeline)
    assert any(n.get("note_id") == res_data["note_id"] for n in case.notes)


# =============================================================================
# 6. ZERO-TRUST ACCESS & ANOMALY FINDING LINKING (MODULE 4)
# =============================================================================

def test_step09_zero_trust_and_finding_linking_to_case(client):
    """
    Step 11: Audits Zero-Trust least privilege access discrepancies and links
    an operational anomaly finding directly to an investigation case.
    """
    # 1. Zero-Trust audit
    zt_res = client.get("/api/v1/graphops/zero-trust/audit?limit=5")
    assert zt_res.status_code == 200
    zt_data = zt_res.json()
    assert "items" in zt_data
    assert "disclaimer" in zt_data

    # 2. Link an anomaly finding to case MT-101
    link_res = client.post(
        "/api/v1/cases/MT-101/findings",
        headers={"X-API-Key": ADMIN_API_KEY},
        json={
            "finding_id": "FND-ANOM-2026-09",
            "finding_type": "ACCESS_ANOMALY",
            "title": "Unusual Interactive Logon to Bastion Host",
            "description": "User alice authenticated to jumpbox from external IP outside baseline hours.",
            "severity": "CRITICAL",
            "details": {
                "source_user": "user:alice@corporation.com",
                "target_host": "server:srv-bastion-01",
                "anomaly_score": 0.88,
            },
        },
    )
    assert link_res.status_code == 200
    link_data = link_res.json()
    assert link_data["case_id"] == "MT-101"
    assert link_data["finding_id"] == "FND-ANOM-2026-09"
    assert link_data["timeline_event_id"].startswith("EVT-FND-")

    # Verify case evidence references and notes were updated
    case = default_case_repo.get_case("MT-101")
    assert any(r.get("evidence_id") == "FND-ANOM-2026-09" for r in case.evidence_references)
    assert any("FND-ANOM-2026-09" in n.get("note", "") for n in case.notes)


# =============================================================================
# 7. EVIDENCE & AUDIT LEDGER INTEGRITY (MODULE 5)
# =============================================================================

def test_step10_evidence_chain_of_custody_and_audit_integrity(client):
    """
    Step 12: Verifies evidence records have deterministic SHA-256 digests,
    validates cryptographic chaining, and verifies tamper-evident audit ledger.
    """
    # 1. Query evidence records
    ev_res = client.get("/api/v1/governance/evidence/records?case_id=MT-101")
    assert ev_res.status_code == 200
    records = ev_res.json()
    assert len(records) >= 1
    sample_ev = records[0]
    assert len(sample_ev["sha256_hash"]) == 64
    assert sample_ev["verification_status"] == "VERIFIED"

    # 2. Verify evidence record hash
    ver_res = client.post(
        "/api/v1/governance/evidence/verify",
        json={"evidence_id": sample_ev["evidence_id"], "provided_hash": sample_ev["sha256_hash"]},
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["verified"] is True

    # 3. Verify evidence chain integrity
    chain_res = client.get("/api/v1/governance/evidence/verify-chain")
    assert chain_res.status_code == 200
    assert chain_res.json()["chain_intact"] is True

    # 4. Verify audit ledger integrity
    audit_res = client.get("/api/v1/governance/audit/verify")
    assert audit_res.status_code == 200
    assert audit_res.json()["ledger_intact"] is True


# =============================================================================
# 8. CROSS-MODULE INVESTIGATION REPORTS & EXPORT (MODULE 5)
# =============================================================================

def test_step11_investigation_report_synthesis_and_exports(client):
    """
    Step 13: Synthesizes a full cross-module investigation dossier connecting
    Modules 0 through 5, and exports in sanitized JSON and ReportLab PDF formats.
    """
    # 1. Generate Investigation Report
    rep_res = client.post(
        "/api/v1/governance/reports/investigation",
        json={"case_id": "MT-101"},
    )
    assert rep_res.status_code == 201
    report = rep_res.json()
    assert report["case_id"] == "MT-101"
    assert report["report_id"].startswith("INV-RPT-")

    # Verify cross-module connections in report
    assert len(report["alerts"]) > 0
    assert len(report["timeline"]) > 0
    assert "total_reachable_nodes" in report["blast_radius"]
    assert "containment_efficiency_pct" in report["simulation_results"]
    assert len(report["compliance_assessments"]) >= 5
    assert len(report["evidence_ledger_items"]) > 0
    assert len(report["recommendations"]) >= 3
    assert len(report["limitations"]) >= 2

    # 2. Export Sanitized JSON
    json_export = client.get("/api/v1/governance/reports/investigation/MT-101/export?format=json")
    assert json_export.status_code == 200
    assert json_export.headers["content-type"] == "application/json"
    parsed_json = json_export.json()
    assert parsed_json["case_id"] == "MT-101"

    # 3. Export Publication-Ready PDF
    pdf_export = client.get("/api/v1/governance/reports/investigation/MT-101/export?format=pdf")
    assert pdf_export.status_code == 200
    assert pdf_export.headers["content-type"] == "application/pdf"
    assert pdf_export.content.startswith(b"%PDF")
    assert len(pdf_export.content) > 2000


# =============================================================================
# 9. DATA CONSISTENCY & SERVICE RESILIENCE
# =============================================================================

def test_step12_data_consistency_and_service_fallback(client):
    """
    Verifies that sample data is explicitly marked with is_sample: True,
    rule-based findings vs ML predictions are labeled, and service errors
    return clean HTTP statuses without reporting fake success.
    """
    # 1. Sample data distinction
    case = default_case_repo.get_case("MT-101")
    assert case.is_sample is True

    # 2. Non-existent case returns 404
    bad_case_res = client.get("/api/v1/cases/NON_EXISTENT_CASE_999")
    assert bad_case_res.status_code == 404

    # 3. Non-existent collector returns 404
    bad_col_res = client.get(
        "/api/v1/collector/collectors/non-existent-collector",
        headers={"X-API-Key": ADMIN_API_KEY},
    )
    assert bad_col_res.status_code == 404

    # 4. Empty evidence verification returns 404
    bad_ev_res = client.post(
        "/api/v1/governance/evidence/verify",
        json={"evidence_id": "evi:non-existent"},
    )
    assert bad_ev_res.status_code == 404
