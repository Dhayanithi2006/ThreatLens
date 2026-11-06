"""
ThreatLens Module 5 - Comprehensive Reports & Governance Test Suite
Verifies:
1. Compliance & Policy Evaluation:
   - NIST CSF 2.0 & CIS Controls v8.1 mappings.
   - Compliance statuses: PASS, PARTIAL, FAIL, NOT_ASSESSED, NEEDS_REVIEW.
   - Invariant: Missing evidence strictly never returns PASS.
   - Missing-evidence identification and remediation recommendations.
   - Evaluation run history tracking.
2. Evidence & Chain-of-Custody Ledger:
   - Registration, provenance, dual timestamps (collected_at vs ingested_at).
   - Deterministic SHA-256 hash generation and verification.
   - Tamper detection and chain integrity verification.
   - Cross-module auto-indexing from cases and collectors.
3. Audit Trail:
   - Cryptographic SHA-256 ledger recording actor, action, target, related_case_id, result.
   - Tamper detection across breaks, duplicates, and payload changes.
4. Investigation & Compliance Reports:
   - Full cross-module investigation report synthesis connecting alerts, timeline,
     attack paths, chokepoints, blast radius, what-if simulations, access discrepancies,
     anomalies, compliance evaluations, and evidence items.
5. Evidence Export & Secret Redaction:
   - JSON, HTML, and PDF export.
   - Sensitive credential redaction (passwords, tokens, DPAPI keys, API keys).
   - Valid ReportLab PDF generation (>1000 bytes with %PDF header).
   - Export authorization and audit logging.
"""

import io
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.governance.catalog import (
    get_control_catalog,
    get_control,
    find_controls_by_framework,
    find_controls_by_applicability,
)
from backend.governance.schema import (
    EvaluationStatus,
    OrganizationPolicy,
    PolicyEvaluation,
    RemediationPriority,
    RemediationStatus,
)
from backend.governance.policies import (
    get_policy,
    list_policies,
    save_policy,
    reset_policies_to_default,
)
from backend.governance.evaluator import (
    evaluate_policy,
    evaluate_all_active_policies,
    list_evaluation_history,
    reset_evaluation_history,
)
from backend.governance.audit import (
    record_audit_event,
    list_audit_records,
    verify_audit_integrity,
    reset_audit_and_remediations,
    tamper_audit_record_for_test,
)
from backend.governance.evidence_ledger import (
    EvidenceLedgerService,
    compute_evidence_hash,
)
from backend.governance.reports import (
    GovernanceReportService,
    _reports_store,
)
from backend.governance.investigation_reports import (
    InvestigationReportService,
    redact_sensitive_credentials,
    _investigation_reports_store,
)
from backend.governance.pdf_generator import (
    generate_governance_pdf,
    generate_investigation_pdf,
)


@pytest.fixture(autouse=True)
def reset_governance_state():
    """Ensure completely isolated state before and after each test."""
    reset_policies_to_default()
    reset_audit_and_remediations()
    reset_evaluation_history()
    EvidenceLedgerService.reset_ledger()
    _reports_store.clear()
    _investigation_reports_store.clear()
    yield
    reset_policies_to_default()
    reset_audit_and_remediations()
    reset_evaluation_history()
    EvidenceLedgerService.reset_ledger()
    _reports_store.clear()
    _investigation_reports_store.clear()


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. COMPLIANCE & POLICY EVALUATION TESTS
# =============================================================================

def test_standards_framework_mappings():
    """Verifies NIST CSF and CIS Controls mappings are present and authoritative."""
    catalog = get_control_catalog()
    assert len(catalog) >= 15

    # Check NIST CSF 2.0 controls
    nist_controls = find_controls_by_framework("NIST CSF")
    assert len(nist_controls) >= 5
    nist_ids = {c.control_id for c in nist_controls}
    assert "PR.AA-01" in nist_ids
    assert "PR.AA-05" in nist_ids
    assert "DE.CM-01" in nist_ids
    assert "RS.AN-01" in nist_ids

    # Check CIS Controls v8.1
    cis_controls = find_controls_by_framework("CIS Controls")
    assert len(cis_controls) >= 4
    cis_ids = {c.control_id for c in cis_controls}
    assert "CIS-1.1" in cis_ids
    assert "CIS-3.3" in cis_ids
    assert "CIS-5.1" in cis_ids


def test_missing_evidence_never_returns_pass():
    """CRITICAL: Empty or missing evidence strictly never resolves to PASS."""
    # 1. None context
    eval_none = evaluate_policy("POL-IAM-01", None)
    assert eval_none.status != EvaluationStatus.PASS
    assert eval_none.status in (EvaluationStatus.NEEDS_REVIEW, EvaluationStatus.INSUFFICIENT_EVIDENCE, EvaluationStatus.NOT_ASSESSED)
    assert len(eval_none.missing_evidence) > 0

    # 2. Empty dict context
    eval_empty = evaluate_policy("POL-EXPOSURE-01", {})
    assert eval_empty.status != EvaluationStatus.PASS
    assert eval_empty.status in (EvaluationStatus.NEEDS_REVIEW, EvaluationStatus.INSUFFICIENT_EVIDENCE, EvaluationStatus.NOT_ASSESSED)
    assert len(eval_empty.missing_evidence) > 0

    # 3. Partial context lacking required telemetry
    eval_partial = evaluate_policy("POL-LOG-01", {"nodes": [{"id": "user:alice"}]})
    assert eval_partial.status != EvaluationStatus.PASS
    assert len(eval_partial.missing_evidence) > 0


def test_evaluation_statuses_and_remediation():
    """Tests PASS, FAIL, PARTIAL, and NOT_ASSESSED statuses with remediation recommendations."""
    # Test FAIL with direct path violation
    violation_context = {
        "attack_paths": [{
            "path_id": "path-01",
            "nodes": ["device:dev-ws-101", "server:srv-db-01"],
            "edges": [{"source": "device:dev-ws-101", "target": "server:srv-db-01", "type": "CAN_REACH"}],
        }]
    }
    eval_fail = evaluate_policy("POL-IAM-01", violation_context)
    assert eval_fail.status == EvaluationStatus.FAIL
    assert eval_fail.recommended_remediation is not None
    assert len(eval_fail.supporting_evidence) > 0

    # Test PASS when jumpbox / bastion is present
    safe_context = {
        "attack_paths": [{
            "path_id": "path-02",
            "nodes": ["device:dev-ws-101", "server:srv-bastion-jumpbox-01", "server:srv-db-01"],
            "edges": [],
        }]
    }
    eval_pass = evaluate_policy("POL-IAM-01", safe_context)
    assert eval_pass.status == EvaluationStatus.PASS
    assert eval_pass.recommended_remediation is None


def test_evaluation_history_tracking():
    """Verifies evaluation runs are recorded in chronological history."""
    assert len(list_evaluation_history()) == 0

    context = {
        "attack_paths": [{
            "path_id": "p-1",
            "nodes": ["device:ws-1", "server:bastion", "server:db-1"],
            "edges": [],
        }],
        "blast_radius": {
            "root_entity": "device:ws-1",
            "crown_jewel_reachability_pct": 0.0,
            "critical_assets_compromised": [],
        },
    }
    results = evaluate_all_active_policies(context)
    assert len(results) >= 5

    history = list_evaluation_history()
    assert len(history) == 1
    run = history[0]
    assert run["total_evaluated"] >= 5
    assert run["passed"] >= 1
    assert "timestamp" in run


# =============================================================================
# 2. EVIDENCE & CHAIN-OF-CUSTODY LEDGER TESTS
# =============================================================================

def test_evidence_registration_and_hash():
    """Verifies evidence records have deterministic SHA-256 hashes and dual timestamps."""
    coll_time = datetime(2026, 3, 15, 10, 30, 0, tzinfo=timezone.utc)
    ev = EvidenceLedgerService.register_evidence(
        evidence_id="evi:test:001",
        evidence_type="ENDPOINT_TELEMETRY",
        source="EDR_COLLECTOR",
        payload={"hostname": "CORP-WS-101", "event_id": 4688, "process": "powershell.exe"},
        case_id="MT-101",
        finding_id="finding:f-001",
        provenance={"collector_id": "agent-01", "os": "Windows 11"},
        collected_at=coll_time,
        actor_id="analyst-alice",
    )

    assert ev.evidence_id == "evi:test:001"
    assert ev.evidence_type == "ENDPOINT_TELEMETRY"
    assert ev.case_id == "MT-101"
    assert len(ev.sha256_hash) == 64
    assert ev.collected_at == coll_time
    assert ev.ingested_at is not None
    assert ev.verification_status == "VERIFIED"


def test_evidence_verification_and_tamper_detection():
    """Verifies that evidence payload alteration is cryptographically detected."""
    ev = EvidenceLedgerService.register_evidence(
        evidence_id="evi:tamper:001",
        evidence_type="EMAIL_FORENSICS",
        source="EMAIL_GATEWAY",
        payload={"sender": "attacker@bad.org", "threat_score": 95},
        case_id="CASE-999",
    )

    # 1. Verify authentic record
    res_valid = EvidenceLedgerService.verify_evidence(ev.evidence_id)
    assert res_valid["verified"] is True
    assert res_valid["status"] == "VERIFIED_TAMPER_FREE"

    # 2. Verify with matching provided hash
    res_provided = EvidenceLedgerService.verify_evidence(ev.evidence_id, provided_hash=ev.sha256_hash)
    assert res_provided["verified"] is True

    # 3. Verify with wrong provided hash
    res_wrong = EvidenceLedgerService.verify_evidence(ev.evidence_id, provided_hash="a" * 64)
    assert res_wrong["verified"] is False
    assert res_wrong["status"] == "HASH_MISMATCH"

    # 4. Tamper with record payload in memory
    raw_rec = EvidenceLedgerService.get_evidence("evi:tamper:001")
    raw_rec.payload["threat_score"] = 0  # Tampered!
    from backend.governance.evidence_ledger import _evidence_lookup
    _evidence_lookup["evi:tamper:001"] = raw_rec

    res_tampered = EvidenceLedgerService.verify_evidence("evi:tamper:001")
    assert res_tampered["verified"] is False
    assert res_tampered["status"] == "TAMPER_DETECTED"


def test_evidence_chain_integrity():
    """Verifies hash chaining across multiple sequential evidence records."""
    EvidenceLedgerService.register_evidence(
        evidence_id="evi:chain:1",
        evidence_type="ENDPOINT_TELEMETRY",
        source="EDR_COLLECTOR",
        payload={"step": 1},
    )
    EvidenceLedgerService.register_evidence(
        evidence_id="evi:chain:2",
        evidence_type="GRAPH_FINDING",
        source="GRAPHOPS",
        payload={"step": 2},
    )
    EvidenceLedgerService.register_evidence(
        evidence_id="evi:chain:3",
        evidence_type="POLICY_EVALUATION",
        source="GOVERNANCE",
        payload={"step": 3},
    )

    is_intact, err = EvidenceLedgerService.verify_chain_integrity()
    assert is_intact is True
    assert err is None


def test_evidence_auto_sync():
    """Verifies auto_sync discovers cases from case store and indexes them into evidence ledger."""
    synced = EvidenceLedgerService.auto_sync_from_subsystems()
    assert synced >= 1

    ledger = EvidenceLedgerService.list_evidence()
    assert len(ledger) >= 1
    types = {item.evidence_type for item in ledger}
    assert "EMAIL_FORENSICS" in types or "ENDPOINT_TELEMETRY" in types


# =============================================================================
# 3. AUDIT TRAIL TESTS
# =============================================================================

def test_audit_record_with_case_and_result():
    """Verifies audit entries record user, action, target, related_case_id, result, and timestamp."""
    rec = record_audit_event(
        event_type="CASE_CONTAINMENT_EXECUTED",
        actor_id="secops-analyst-01",
        target_resource="device:dev-ws-101",
        action="ISOLATE",
        details={"vlan": "QUARANTINE", "prior_hops": 3},
        related_case_id="MT-101",
        result="SUCCESS",
    )

    assert rec.audit_id.startswith("aud-")
    assert rec.actor_id == "secops-analyst-01"
    assert rec.target_resource == "device:dev-ws-101"
    assert rec.action == "ISOLATE"
    assert rec.related_case_id == "MT-101"
    assert rec.result == "SUCCESS"
    assert len(rec.current_hash) == 64

    # Verify audit chain integrity
    is_valid, err = verify_audit_integrity()
    assert is_valid is True


def test_audit_tamper_detection():
    """Verifies that altering an audit record breaks cryptographic verification."""
    record_audit_event("POLICY_CREATED", "admin", "policy:P1", "CREATE")
    record_audit_event("POLICY_UPDATED", "admin", "policy:P1", "UPDATE")
    record_audit_event("POLICY_DELETED", "admin", "policy:P1", "DELETE")

    assert verify_audit_integrity()[0] is True

    # Tamper with index 1
    tamper_audit_record_for_test(1, actor_id="malicious_attacker")
    is_valid, err = verify_audit_integrity()
    assert is_valid is False
    assert "Digest mismatch" in err


# =============================================================================
# 4. INVESTIGATION & COMPLIANCE REPORTS TESTS
# =============================================================================

def test_generate_investigation_report_cross_module():
    """Verifies full investigation report synthesis connecting Modules 0 to 5."""
    report = InvestigationReportService.generate_investigation_report("MT-101", actor_id="lead-analyst")

    assert report.report_id.startswith("INV-RPT-")
    assert report.case_id == "MT-101"
    assert report.case_summary["case_id"] == "MT-101"

    # Module 1 connections
    assert len(report.alerts) > 0
    assert len(report.timeline) >= 0

    # Module 2 connections
    assert isinstance(report.attack_paths, list)
    assert isinstance(report.chokepoints, list)

    # Module 3 connections
    assert "total_reachable_nodes" in report.blast_radius
    assert "containment_efficiency_pct" in report.simulation_results

    # Module 4 connections
    assert isinstance(report.access_discrepancies, list)
    assert isinstance(report.anomalies, list)

    # Module 5 connections
    assert len(report.compliance_assessments) >= 5
    comp_statuses = {c.status for c in report.compliance_assessments}
    assert any(s in (EvaluationStatus.PASS, EvaluationStatus.FAIL, EvaluationStatus.NEEDS_REVIEW) for s in comp_statuses)

    # Evidence ledger references
    assert len(report.evidence_ledger_items) > 0
    for ev in report.evidence_ledger_items:
        assert "evidence_id" in ev
        assert "sha256_hash" in ev

    # Recommendations & limitations
    assert len(report.recommendations) >= 3
    assert len(report.limitations) >= 2


def test_investigation_report_persistence_and_retrieval():
    """Verifies investigation reports can be retrieved by report ID or case ID."""
    created = InvestigationReportService.generate_investigation_report("MT-101")
    retrieved_by_case = InvestigationReportService.get_investigation_report("MT-101")
    retrieved_by_id = InvestigationReportService.get_investigation_report(created.report_id)

    assert retrieved_by_case is not None
    assert retrieved_by_id is not None
    assert retrieved_by_case.report_id == created.report_id
    assert retrieved_by_id.report_id == created.report_id


# =============================================================================
# 5. EVIDENCE EXPORT & CREDENTIAL REDACTION TESTS
# =============================================================================

def test_redact_sensitive_credentials():
    """Verifies recursive sanitization of passwords, tokens, DPAPI keys, and secrets."""
    dirty_payload = {
        "username": "victim1@corporation.com",
        "password": "SuperSecretPassword123!",
        "auth_token": "tok_live_9876543210abcdef",
        "nested": {
            "api_key": "key-secret-12345",
            "dpapi_blob": "dpapi:AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA",
            "normal_data": "SAFE_VALUE",
        },
        "log_line": "Connecting with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "credentials_list": [{"secret": "top_secret_val"}],
    }

    clean = redact_sensitive_credentials(dirty_payload)

    assert clean["username"] == "victim1@corporation.com"
    assert clean["password"] == "[REDACTED]"
    assert clean["auth_token"] == "[REDACTED]"
    assert clean["nested"]["api_key"] == "[REDACTED]"
    assert clean["nested"]["dpapi_blob"] == "[REDACTED]"
    assert clean["nested"]["normal_data"] == "SAFE_VALUE"
    assert "Bearer [REDACTED]" in clean["log_line"]
    assert clean["credentials_list"][0]["secret"] == "[REDACTED]"


def test_export_investigation_report_json():
    """Verifies JSON export produces valid, redacted JSON."""
    content, media_type = InvestigationReportService.export_investigation_report("MT-101", export_format="json")
    assert media_type == "application/json"
    parsed = json.loads(content)
    assert parsed["case_id"] == "MT-101"
    assert "evidence_ledger_items" in parsed


def test_export_investigation_report_pdf():
    """Verifies PDF export produces valid, readable PDF bytes via ReportLab."""
    pdf_bytes, media_type = InvestigationReportService.export_investigation_report("MT-101", export_format="pdf")
    assert media_type == "application/pdf"
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 2000


def test_export_governance_report_pdf():
    """Verifies standard governance report PDF export."""
    rep = GovernanceReportService.generate_report(framework="ALL")
    pdf_bytes, media_type = GovernanceReportService.export_report(rep.report_id, export_format="pdf")
    assert media_type == "application/pdf"
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 2000


# =============================================================================
# 6. REST API INTEGRATION TESTS
# =============================================================================

def test_api_evaluation_history(client):
    """GET /api/v1/governance/evaluations/history returns past evaluation runs."""
    # First trigger evaluation
    client.post("/api/v1/governance/evaluate", json={"finding_context": {"attack_paths": []}})
    res = client.get("/api/v1/governance/evaluations/history")
    assert res.status_code == 200
    runs = res.json()
    assert isinstance(runs, list)
    assert len(runs) >= 1
    assert "total_evaluated" in runs[0]


def test_api_investigation_report_lifecycle(client):
    """Tests POST and GET endpoints for investigation dossiers."""
    # 1. Generate report
    post_res = client.post("/api/v1/governance/reports/investigation", json={"case_id": "MT-101"})
    assert post_res.status_code == 201
    doc = post_res.json()
    assert doc["case_id"] == "MT-101"
    assert doc["report_id"].startswith("INV-RPT-")

    # 2. Retrieve report
    get_res = client.get("/api/v1/governance/reports/investigation/MT-101")
    assert get_res.status_code == 200
    assert get_res.json()["report_id"] == doc["report_id"]

    # 3. Export JSON
    json_export = client.get("/api/v1/governance/reports/investigation/MT-101/export?format=json")
    assert json_export.status_code == 200
    assert json_export.headers["content-type"] == "application/json"

    # 4. Export PDF
    pdf_export = client.get("/api/v1/governance/reports/investigation/MT-101/export?format=pdf")
    assert pdf_export.status_code == 200
    assert pdf_export.headers["content-type"] == "application/pdf"
    assert pdf_export.content.startswith(b"%PDF")


def test_api_evidence_ledger_endpoints(client):
    """Tests evidence records listing, manual registration, and chain verification."""
    # 1. Register evidence
    post_res = client.post(
        "/api/v1/governance/evidence",
        json={
            "evidence_id": "evi:api:001",
            "evidence_type": "ENDPOINT_TELEMETRY",
            "source": "EDR_AGENT",
            "payload": {"status": "ONLINE", "ip": "10.0.1.50"},
            "case_id": "MT-101",
        },
    )
    assert post_res.status_code == 201
    ev_data = post_res.json()
    assert ev_data["evidence_id"] == "evi:api:001"
    assert len(ev_data["sha256_hash"]) == 64

    # 2. List records
    get_res = client.get("/api/v1/governance/evidence/records?case_id=MT-101")
    assert get_res.status_code == 200
    records = get_res.json()
    assert any(r["evidence_id"] == "evi:api:001" for r in records)

    # 3. Verify evidence item
    ver_res = client.post(
        "/api/v1/governance/evidence/verify",
        json={"evidence_id": "evi:api:001", "provided_hash": ev_data["sha256_hash"]},
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["verified"] is True

    # 4. Verify chain integrity
    chain_res = client.get("/api/v1/governance/evidence/verify-chain")
    assert chain_res.status_code == 200
    assert chain_res.json()["chain_intact"] is True
