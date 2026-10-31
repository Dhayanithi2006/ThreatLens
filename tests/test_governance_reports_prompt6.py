"""
ThreatLens Prompt 6 - Governance, Reports, Policy Evaluation, and Audit Integrity Test Suite
Verifies:
1. Supported standards frameworks: NIST CSF 2.0 (PR.AA, DE.CM, RS.AN), CIS Controls v8.1,
   NIST SP 800-53 Rev. 5, MITRE ATT&CK v14.1, ISO/IEC 27001:2022.
2. Comprehensive evaluation statuses: PASS, FAIL, PARTIAL, NOT_APPLICABLE, INSUFFICIENT_EVIDENCE.
3. Strict invariant: Missing telemetry or empty evidence strictly never returns PASS.
4. Tamper-evident SHA-256 audit ledger:
   - Valid chain verification
   - Payload content alteration detection
   - Prior hash break detection
   - Record deletion detection
   - Record reordering / chronological anomaly detection
   - Duplicate audit ID detection
   - Empty ledger handling
5. Trustworthy Governance Report Generation:
   - Real context evaluation
   - Date range validation (valid vs start_time > end_time)
   - Provenance, audit integrity status, data limitations, and normative disclaimer
6. Evidence chain-of-custody ledger and constant-time SHA-256 verification.
7. Safe exports (JSON, CSV, HTML) with strict XSS sanitization (html.escape).
8. Read and export immutability: read/export operations do not mutate the audit ledger.
9. Full REST API integration via FastAPI TestClient for all report and evidence endpoints.
"""

import copy
from datetime import datetime, timezone, timedelta
import html
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.governance.catalog import (
    find_controls_by_applicability,
    find_controls_by_framework,
    get_control,
    get_control_catalog,
)
from backend.governance.evaluator import (
    evaluate_all_active_policies,
    evaluate_policy,
)
from backend.governance.policies import (
    delete_policy,
    get_policy,
    list_policies,
    reset_policies_to_default,
    save_policy,
)
from backend.governance.reports import (
    EvidenceLedgerItem,
    GovernanceReport,
    GovernanceReportService,
    _reports_store,
)
from backend.governance.schema import (
    AuditRecord,
    ControlRecord,
    EvaluationStatus,
    OrganizationPolicy,
    PolicyEvaluation,
)
from backend.governance.audit import (
    _audit_ledger,
    _audit_lock,
    list_audit_records,
    record_audit_event,
    reset_audit_and_remediations,
    tamper_audit_record_for_test,
    verify_audit_integrity,
)


@pytest.fixture(autouse=True)
def reset_governance_state():
    """Ensure clean policy, audit ledger, and reports store state before each test."""
    reset_policies_to_default()
    reset_audit_and_remediations()
    _reports_store.clear()
    yield
    reset_policies_to_default()
    reset_audit_and_remediations()
    _reports_store.clear()


@pytest.fixture
def api_client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# =============================================================================
# 1. STANDARDS FRAMEWORK & CATEGORY MAPPINGS TESTS
# =============================================================================

def test_standards_frameworks_coverage():
    """Verifies that all 5 authoritative frameworks are populated with normative controls."""
    catalog = get_control_catalog()
    assert len(catalog) >= 15

    frameworks = {c.framework_name for c in catalog}
    assert "NIST CSF" in frameworks
    assert "NIST SP 800-53" in frameworks
    assert "CIS Controls" in frameworks
    assert "MITRE ATT&CK" in frameworks
    assert "ISO/IEC 27001" in frameworks


def test_nist_csf_2_pr_aa_identity_mappings():
    """
    Verifies that NIST CSF 2.0 controls properly reference PR.AA
    for Identity Management, Authentication, and Access Control.
    """
    nist_controls = find_controls_by_framework("NIST CSF")
    assert len(nist_controls) >= 3

    # Check for PR.AA (Protect: Identity Management, Authentication and Access Control)
    pr_aa_controls = [c for c in nist_controls if "PR.AA" in c.control_id]
    assert len(pr_aa_controls) >= 1, "NIST CSF 2.0 must include PR.AA category mappings"

    for c in pr_aa_controls:
        assert c.title
        assert "Identity" in c.applicability or "Access" in c.applicability
        assert "2.0" in c.title or "NIST CSF" in c.framework_name


def test_nist_csf_2_de_cm_and_rs_an_mappings():
    """Verifies NIST CSF 2.0 DE.CM (Continuous Monitoring) and RS.AN (Incident Analysis) controls."""
    nist_controls = find_controls_by_framework("NIST CSF")
    ctrl_ids = {c.control_id for c in nist_controls}

    assert any("DE.CM" in cid for cid in ctrl_ids), "Expected DE.CM continuous monitoring mapping"
    assert any("RS.AN" in cid for cid in ctrl_ids), "Expected RS.AN incident analysis mapping"


# =============================================================================
# 2. POLICY EVALUATION STATUS GRANULARITY TESTS
# =============================================================================

def test_evaluation_status_pass_with_clean_context():
    """Verifies PASS evaluation when context satisfies policy requirements cleanly."""
    clean_context = {
        "nodes": [
            {"id": "user:u1", "role": "ANALYST", "mfa_active": True, "failed_logins": 0},
            {"id": "device:d1", "isolated": False, "patch_level": "CURRENT"},
        ],
        "edges": [],
        "blast_radius": {
            "root_entity": "device:d1",
            "hop_depth": 3,
            "crown_jewel_reachability_pct": 0.0,
            "critical_assets_compromised": [],
        },
    }
    result = evaluate_policy("POL-EXPOSURE-01", clean_context)
    assert result.status == EvaluationStatus.PASS
    assert "remains within organization isolation tolerance" in result.reasoning


def test_evaluation_status_fail_with_violating_context():
    """Verifies FAIL evaluation when context has high-risk reachability to crown jewels."""
    violating_context = {
        "nodes": [],
        "blast_radius": {
            "root_entity": "device:compromised-host",
            "hop_depth": 3,
            "crown_jewel_reachability_pct": 85.0,
            "critical_assets_compromised": ["database:prod-customer-pii"],
        },
    }
    result = evaluate_policy("POL-EXPOSURE-01", violating_context)
    assert result.status == EvaluationStatus.FAIL
    assert "Crown Jewel(s) exposed" in result.reasoning and "85.0%" in result.reasoning
    assert result.recommended_remediation is not None


def test_evaluation_status_partial_coverage():
    """Verifies PARTIAL status when reachability is non-zero but below critical threshold."""
    partial_context = {
        "nodes": [],
        "blast_radius": {
            "root_entity": "device:ws-dev",
            "hop_depth": 2,
            "crown_jewel_reachability_pct": 15.0,
            "critical_assets_compromised": [],
        },
    }
    result = evaluate_policy("POL-EXPOSURE-01", partial_context)
    assert result.status == EvaluationStatus.PARTIAL
    assert "partial reachability evidence" in result.reasoning


def test_missing_telemetry_never_returns_pass():
    """
    CRITICAL INVARIANT: Missing telemetry, empty finding context, or absent evidence
    must NEVER evaluate to PASS. It must return INSUFFICIENT_EVIDENCE or NEEDS_REVIEW.
    """
    empty_contexts = [None, {}, {"nodes": []}, {"blast_radius": None}]
    for ctx in empty_contexts:
        res = evaluate_policy("POL-EXPOSURE-01", ctx)
        assert res.status != EvaluationStatus.PASS, f"Context {ctx} incorrectly evaluated to PASS!"
        assert res.status in (EvaluationStatus.INSUFFICIENT_EVIDENCE, EvaluationStatus.NEEDS_REVIEW)
        assert len(res.data_limitations) > 0


def test_disabled_policy_returns_not_applicable():
    """Verifies that an administratively disabled policy evaluates to NOT_APPLICABLE."""
    pol = get_policy("POL-EXPOSURE-01")
    assert pol is not None
    disabled_pol = pol.model_copy(update={"enabled": False})
    save_policy(disabled_pol)

    result = evaluate_policy("POL-EXPOSURE-01", {"blast_radius": {"crown_jewel_reachability_pct": 0.0}})
    assert result.status == EvaluationStatus.NOT_APPLICABLE
    assert "Policy is administratively disabled" in result.reasoning or "currently disabled" in result.reasoning


# =============================================================================
# 3. SHA-256 AUDIT LEDGER INTEGRITY & TAMPER DETECTION TESTS
# =============================================================================

def test_audit_ledger_valid_chain():
    """Verifies that normal append operations maintain cryptographic SHA-256 integrity."""
    record_audit_event("POLICY_CREATED", "admin-1", "policy:POL-01", "CREATE", {"name": "Test 1"})
    record_audit_event("POLICY_EVALUATED", "system", "policy:POL-01", "EVALUATE", {"status": "PASS"})
    record_audit_event("REMEDIATION_CREATED", "analyst-2", "rem:REM-01", "CREATE", {"urgency": "HIGH"})

    is_intact, err = verify_audit_integrity()
    assert is_intact is True
    assert err is None


def test_audit_ledger_detects_payload_tampering():
    """Verifies that altering the payload of any ledger entry triggers a digest mismatch."""
    record_audit_event("POLICY_CREATED", "admin-1", "policy:POL-01", "CREATE", {"name": "Original"})
    record_audit_event("POLICY_EVALUATED", "system", "policy:POL-01", "EVALUATE", {"status": "PASS"})

    # Tamper with the details payload of the first record
    tamper_audit_record_for_test(0, details={"name": "TAMPERED_IN_STORAGE"})

    is_intact, err = verify_audit_integrity()
    assert is_intact is False
    assert "Digest mismatch" in err


def test_audit_ledger_detects_prior_hash_tampering():
    """Verifies that modifying previous_hash triggers a chain break error."""
    record_audit_event("POLICY_CREATED", "admin-1", "policy:POL-01", "CREATE", {})
    record_audit_event("POLICY_EVALUATED", "system", "policy:POL-01", "EVALUATE", {})

    # Modify previous_hash on record 1
    tamper_audit_record_for_test(1, previous_hash="badf00d" * 9 + "1")

    is_intact, err = verify_audit_integrity()
    assert is_intact is False
    assert "Chain break" in err


def test_audit_ledger_detects_record_deletion():
    """Verifies that deleting an intermediate ledger entry breaks hash linkage."""
    record_audit_event("EVENT_1", "actor-1", "res-1", "ACT_1", {})
    record_audit_event("EVENT_2", "actor-2", "res-2", "ACT_2", {})
    record_audit_event("EVENT_3", "actor-3", "res-3", "ACT_3", {})

    with _audit_lock:
        # Delete middle entry (index 1)
        del _audit_ledger[1]

    is_intact, err = verify_audit_integrity()
    assert is_intact is False
    assert "Chain break" in err


def test_audit_ledger_detects_duplicate_audit_id():
    """Verifies that injecting an entry with a duplicate audit_id is flagged as tampering."""
    r1 = record_audit_event("EVENT_1", "actor-1", "res-1", "ACT_1", {})
    record_audit_event("EVENT_2", "actor-2", "res-2", "ACT_2", {})

    # Overwrite record 1's audit_id to duplicate record 0's ID
    tamper_audit_record_for_test(1, audit_id=r1.audit_id)

    is_intact, err = verify_audit_integrity()
    assert is_intact is False
    assert "Duplicate audit_id" in err


def test_audit_ledger_detects_chronological_anomaly():
    """Verifies that out-of-order timestamps are detected as integrity violations."""
    r1 = record_audit_event("EVENT_1", "actor-1", "res-1", "ACT_1", {})
    record_audit_event("EVENT_2", "actor-2", "res-2", "ACT_2", {})

    # Set record 1's timestamp earlier than record 0
    tamper_audit_record_for_test(1, timestamp=r1.timestamp - timedelta(hours=2))

    is_intact, err = verify_audit_integrity()
    assert is_intact is False
    assert "Chronological anomaly" in err or "Digest mismatch" in err


def test_audit_ledger_empty_is_valid():
    """Verifies that an empty audit ledger evaluates as intact."""
    is_intact, err = verify_audit_integrity()
    assert is_intact is True
    assert err is None


def test_read_operations_do_not_mutate_ledger():
    """Verifies that read/query operations are strictly non-mutating."""
    record_audit_event("EVENT_1", "actor-1", "res-1", "ACT_1", {})
    record_audit_event("EVENT_2", "actor-2", "res-2", "ACT_2", {})

    len_before = len(_audit_ledger)

    # Perform multiple read and verification queries
    _ = list_audit_records(limit=10)
    _ = verify_audit_integrity()
    _ = GovernanceReportService.get_evidence_ledger()

    len_after = len(_audit_ledger)
    assert len_before == len_after, "Read operations must not append or mutate audit records"


# =============================================================================
# 4. GOVERNANCE REPORT GENERATION & VALIDATION TESTS
# =============================================================================

def test_generate_report_basic():
    """Verifies generating an evidence-grounded report with accurate summary counts."""
    report = GovernanceReportService.generate_report(framework="ALL", scope="ENTERPRISE")
    assert report.report_id.startswith("RPT-2026-")
    assert report.title
    assert report.summary.total_controls_assessed > 0
    assert 0.0 <= report.summary.overall_compliance_pct <= 100.0
    assert report.provenance.get("audit_ledger_status") == "INTACT"
    assert len(report.data_limitations) >= 2
    assert "do not constitute formal regulatory compliance certification" in report.disclaimer


def test_generate_report_valid_date_range():
    """Verifies report generation with valid ISO-8601 UTC date range filter."""
    start = "2026-01-01T00:00:00Z"
    end = "2026-12-31T23:59:59Z"
    report = GovernanceReportService.generate_report(start_time=start, end_time=end)
    assert report.date_range_start == start
    assert report.date_range_end == end


def test_generate_report_invalid_date_range_raises_value_error():
    """Verifies that start_time > end_time raises ValueError with informative message."""
    start = "2026-12-31T23:59:59Z"
    end = "2026-01-01T00:00:00Z"
    with pytest.raises(ValueError) as exc:
        GovernanceReportService.generate_report(start_time=start, end_time=end)
    assert "must precede or equal end_time" in str(exc.value)


def test_generate_report_framework_filter():
    """Verifies filtering report evaluations by standards framework."""
    report_nist = GovernanceReportService.generate_report(framework="NIST CSF")
    assert report_nist.framework_scope == "NIST CSF"
    assert len(report_nist.evaluations) > 0


# =============================================================================
# 5. EVIDENCE LEDGER & EXPORT INTEGRITY TESTS
# =============================================================================

def test_evidence_ledger_sha256_verification():
    """Verifies evidence ledger retrieval and constant-time SHA-256 hash verification."""
    # Ensure at least one audit record is present
    record_audit_event("TEST_AUDIT", "tester", "res:test", "ACTION", {})

    ledger = GovernanceReportService.get_evidence_ledger()
    assert len(ledger) > 0

    first_item = ledger[0]
    assert first_item.evidence_id
    assert len(first_item.sha256_hash) == 64

    # Verify against correct hash
    ver_clean = GovernanceReportService.verify_evidence_hash(
        evidence_id=first_item.evidence_id,
        provided_hash=first_item.sha256_hash,
    )
    assert ver_clean["verified"] is True
    assert ver_clean["status"] == "VERIFIED_TAMPER_FREE"

    # Verify against tampered hash
    ver_bad = GovernanceReportService.verify_evidence_hash(
        evidence_id=first_item.evidence_id,
        provided_hash="00" * 32,
    )
    assert ver_bad["verified"] is False
    assert ver_bad["status"] == "HASH_MISMATCH"

    # Verify non-existent evidence ID
    ver_missing = GovernanceReportService.verify_evidence_hash("non-existent-id-999")
    assert ver_missing["verified"] is False
    assert ver_missing["status"] == "EVIDENCE_NOT_FOUND"


def test_export_report_json():
    """Verifies exporting report as valid JSON."""
    report = GovernanceReportService.generate_report()
    content, media_type = GovernanceReportService.export_report(report.report_id, "json")
    assert media_type == "application/json"
    parsed = json.loads(content)
    assert parsed["report_id"] == report.report_id
    assert "summary" in parsed


def test_export_report_csv():
    """Verifies exporting report as well-formed CSV."""
    report = GovernanceReportService.generate_report()
    content, media_type = GovernanceReportService.export_report(report.report_id, "csv")
    assert media_type == "text/csv"
    assert "Report ID,Evaluation ID,Policy ID" in content
    assert report.report_id in content


def test_export_report_html_xss_protection():
    """
    CRITICAL SECURITY TEST: Verifies that HTML exports strictly escape
    all dynamic strings to prevent XSS script injection.
    """
    report = GovernanceReportService.generate_report()

    # Artificially inject an XSS script string into one evaluation reasoning
    xss_payload = "<script>alert('XSS_VULNERABILITY')</script>"
    report.evaluations[0].reasoning = f"Compromised host detected: {xss_payload}"
    _reports_store[report.report_id] = report

    content, media_type = GovernanceReportService.export_report(report.report_id, "html")
    assert media_type == "text/html"
    assert "<!DOCTYPE html>" in content
    # Ensure raw tag does NOT appear in HTML
    assert xss_payload not in content
    # Ensure escaped HTML entity appears instead
    assert html.escape(xss_payload) in content


def test_export_report_does_not_mutate_ledger_by_default():
    """Verifies that calling export_report without record_audit does not mutate the audit ledger."""
    report = GovernanceReportService.generate_report()
    len_before = len(_audit_ledger)

    _ = GovernanceReportService.export_report(report.report_id, "json")
    _ = GovernanceReportService.export_report(report.report_id, "csv")
    _ = GovernanceReportService.export_report(report.report_id, "html")

    len_after = len(_audit_ledger)
    assert len_before == len_after, "Default export_report must be read-only and non-mutating"


# =============================================================================
# 6. REST API INTEGRATION TESTS
# =============================================================================

def test_api_generate_and_get_report(api_client):
    """Verifies POST /api/v1/governance/reports/generate and GET /api/v1/governance/reports/{id}."""
    resp = api_client.post(
        "/api/v1/governance/reports/generate",
        json={"framework": "ALL", "scope": "ENTERPRISE"},
    )
    assert resp.status_code == 201
    data = resp.json()
    report_id = data["report_id"]
    assert report_id.startswith("RPT-2026-")

    # Get by ID
    get_resp = api_client.get(f"/api/v1/governance/reports/{report_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["report_id"] == report_id

    # List reports
    list_resp = api_client.get("/api/v1/governance/reports")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1


def test_api_generate_report_invalid_date_range_returns_400(api_client):
    """Verifies that submitting start_time > end_time returns 400 Bad Request."""
    resp = api_client.post(
        "/api/v1/governance/reports/generate",
        json={
            "start_time": "2026-12-31T00:00:00Z",
            "end_time": "2026-01-01T00:00:00Z",
        },
    )
    assert resp.status_code == 400
    assert "must precede or equal end_time" in resp.json()["detail"]


def test_api_export_report_endpoints(api_client):
    """Verifies GET /api/v1/governance/reports/{id}/export for json, csv, and html."""
    gen_resp = api_client.post(
        "/api/v1/governance/reports/generate",
        json={"framework": "ALL"},
    )
    report_id = gen_resp.json()["report_id"]

    for fmt, expected_mime in [
        ("json", "application/json"),
        ("csv", "text/csv"),
        ("html", "text/html"),
    ]:
        exp_resp = api_client.get(f"/api/v1/governance/reports/{report_id}/export?format={fmt}")
        assert exp_resp.status_code == 200
        assert expected_mime in exp_resp.headers["content-type"]

    # Unsupported format returns 400
    bad_resp = api_client.get(f"/api/v1/governance/reports/{report_id}/export?format=xml")
    assert bad_resp.status_code == 400


def test_api_evidence_ledger_and_verification(api_client):
    """Verifies GET /evidence/ledger and POST /evidence/verify endpoints."""
    # Seed an audit record
    api_client.post(
        "/api/v1/governance/reports/generate",
        json={"framework": "ALL"},
    )

    ledger_resp = api_client.get("/api/v1/governance/evidence/ledger")
    assert ledger_resp.status_code == 200
    ledger = ledger_resp.json()
    assert len(ledger) > 0

    first = ledger[0]
    verify_resp = api_client.post(
        "/api/v1/governance/evidence/verify",
        json={"evidence_id": first["evidence_id"], "provided_hash": first["sha256_hash"]},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["verified"] is True


def test_api_audit_ledger_verify(api_client):
    """Verifies GET /api/v1/governance/audit/verify returns tamper-free status on fresh ledger."""
    resp = api_client.get("/api/v1/governance/audit/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ledger_intact"] is True
    assert data["status"] == "VERIFIED_TAMPER_FREE"
