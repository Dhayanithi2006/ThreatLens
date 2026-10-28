"""
ThreatLens Phase 6 - Comprehensive Governance, Security, and MVP Readiness Test Suite
Verifies:
1. Policy evaluation with valid evidence (Pass and Fail paths).
2. Policy evaluation without evidence (Deterministic NEEDS_REVIEW / NOT_EVALUATED; NEVER Pass).
3. Invalid policy handling and disabled policy states.
4. Standards reference validation across NIST CSF 2.0, NIST SP 800-53, CIS v8.1, MITRE, ISO 27001.
5. Remediation lifecycle and status transitions.
6. Tamper-evident cryptographic audit chain integrity and break detection.
7. Role-based administrative authentication, API key enforcement, and timing-safe checks.
8. CORS configuration and origin validation.
9. File upload boundary checks (disallowed extensions, payload size limits).
10. Full end-to-end API integration via FastAPI TestClient.
"""

import hmac
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.core.config import (
    ADMIN_API_KEY,
    ALLOWED_UPLOAD_EXTENSIONS,
    CORS_ORIGINS,
    MAX_UPLOAD_SIZE_BYTES,
)
import backend.core.config as config_mod
from backend.core.security import verify_admin_access, extract_api_key
from backend.governance.catalog import (
    get_control,
    get_control_catalog,
    find_controls_by_framework,
    find_controls_by_applicability,
)
from backend.governance.policies import (
    get_policy,
    list_policies,
    save_policy,
    reset_policies_to_default,
)
from backend.governance.schema import (
    EvaluationStatus,
    OrganizationPolicy,
    RemediationPriority,
    RemediationStatus,
)
from backend.governance.evaluator import (
    evaluate_policy,
    evaluate_all_active_policies,
)
from backend.governance.audit import (
    create_remediation,
    get_remediation,
    list_remediations,
    update_remediation_status,
    record_audit_event,
    list_audit_records,
    verify_audit_integrity,
    reset_audit_and_remediations,
    tamper_audit_record_for_test,
)


@pytest.fixture(autouse=True)
def setup_governance_test():
    """Reset policy and audit ledger states between test cases."""
    reset_policies_to_default()
    reset_audit_and_remediations()
    yield
    reset_policies_to_default()
    reset_audit_and_remediations()


# =============================================================================
# 1. STANDARDS CONTROL CATALOG TESTS
# =============================================================================

def test_standards_catalog_integrity():
    """Asserts authoritative standards catalog contains verified controls from all 5 frameworks."""
    catalog = get_control_catalog()
    assert len(catalog) >= 15

    frameworks = {c.framework_name for c in catalog}
    assert "NIST CSF" in frameworks
    assert "NIST SP 800-53" in frameworks
    assert "CIS Controls" in frameworks
    assert "MITRE ATT&CK" in frameworks
    assert "ISO/IEC 27001" in frameworks

    # Verify each control has complete normative fields and official references
    for ctrl in catalog:
        assert ctrl.control_id
        assert ctrl.title
        assert ctrl.description
        assert ctrl.mapping_rationale
        assert ctrl.official_reference.startswith("http") or ctrl.official_reference.startswith("https")
        assert ctrl.applicability


def test_standards_catalog_queries():
    """Tests control lookup by ID, framework, and applicability."""
    ctrl_ac3 = get_control("AC-3")
    assert ctrl_ac3 is not None
    assert ctrl_ac3.framework_name == "NIST SP 800-53"
    assert "Access Enforcement" in ctrl_ac3.title

    ctrl_csf = get_control("pr.aa-01")  # Case insensitive
    assert ctrl_csf is not None
    assert ctrl_csf.framework_version == "2.0"

    # Framework filtering
    cis_controls = find_controls_by_framework("CIS Controls")
    assert len(cis_controls) >= 3
    for c in cis_controls:
        assert "CIS" in c.framework_name

    # Applicability filtering
    iam_controls = find_controls_by_applicability("Identity")
    assert len(iam_controls) >= 2


# =============================================================================
# 2. POLICY EVALUATION TESTS: EVIDENCE vs. MISSING EVIDENCE
# =============================================================================

def test_policy_evaluation_missing_evidence_never_passes():
    """
    CRITICAL GOVERNANCE RULE:
    Missing evidence must NEVER automatically be treated as compliance.
    Empty finding context must return NEEDS_REVIEW or NOT_EVALUATED with data limitations.
    """
    # 1. None context
    eval_none = evaluate_policy("POL-IAM-01", None)
    assert eval_none.status in (EvaluationStatus.NEEDS_REVIEW, EvaluationStatus.NOT_EVALUATED)
    assert eval_none.status != EvaluationStatus.PASS
    assert len(eval_none.data_limitations) > 0

    # 2. Empty dict context
    eval_empty = evaluate_policy("POL-EXPOSURE-01", {})
    assert eval_empty.status in (EvaluationStatus.NEEDS_REVIEW, EvaluationStatus.NOT_EVALUATED)
    assert eval_empty.status != EvaluationStatus.PASS
    assert len(eval_empty.data_limitations) > 0

    # 3. Evaluate all active policies with empty context: none must pass
    all_evals = evaluate_all_active_policies({})
    for ev in all_evals:
        assert ev.status != EvaluationStatus.PASS, f"Policy {ev.policy_id} incorrectly passed with empty evidence!"
        assert len(ev.data_limitations) > 0


def test_policy_evaluation_valid_evidence_fail_and_pass():
    """Tests policy evaluations against concrete graph attack path findings."""
    # Scenario A: Direct workstation to database bypass without jumpbox -> FAILS POL-IAM-01
    bypass_context = {
        "attack_paths": [
            {
                "path_id": "path-001",
                "nodes": ["ws-hr-01", "db-prod-core"],
                "path_nodes": ["ws-hr-01", "db-prod-core"],
            }
        ]
    }
    eval_fail = evaluate_policy("POL-IAM-01", bypass_context)
    assert eval_fail.status == EvaluationStatus.FAIL
    assert len(eval_fail.supporting_evidence) > 0
    assert eval_fail.recommended_remediation is not None
    assert "bastion" in eval_fail.recommended_remediation.lower() or "isolate" in eval_fail.recommended_remediation.lower()

    # Scenario B: Path traverses jumpbox/bastion -> PASSES POL-IAM-01
    bastion_context = {
        "attack_paths": [
            {
                "path_id": "path-002",
                "nodes": ["ws-hr-01", "bastion-jumpbox-01", "db-prod-core"],
                "path_nodes": ["ws-hr-01", "bastion-jumpbox-01", "db-prod-core"],
            }
        ]
    }
    eval_pass = evaluate_policy("POL-IAM-01", bastion_context)
    assert eval_pass.status == EvaluationStatus.PASS
    assert len(eval_pass.supporting_evidence) > 0


def test_blast_radius_exposure_policy_evaluation():
    """Tests POL-EXPOSURE-01 against blast radius simulation findings."""
    # Excessive blast radius reaching Crown Jewels -> FAILS
    excessive_blast = {
        "blast_radius": {
            "root_entity": "ws-finance-02",
            "reachable_nodes_count": 45,
            "crown_jewels_compromised": ["db-customer-pii", "db-financial-ledger"],
            "crown_jewel_reachability_pct": 50.0,
        }
    }
    eval_res = evaluate_policy("POL-EXPOSURE-01", excessive_blast)
    assert eval_res.status == EvaluationStatus.FAIL
    assert "exceeding" in eval_res.reasoning.lower() or "exposed" in eval_res.reasoning.lower()

    # Contained blast radius with 0 Crown Jewels -> PASSES
    contained_blast = {
        "blast_radius": {
            "root_entity": "ws-guest-01",
            "reachable_nodes_count": 2,
            "crown_jewels_compromised": [],
            "crown_jewel_reachability_pct": 0.0,
        }
    }
    eval_ok = evaluate_policy("POL-EXPOSURE-01", contained_blast)
    assert eval_ok.status == EvaluationStatus.PASS


def test_vulnerability_and_incident_policies():
    """Tests POL-VULN-01 and POL-INC-01 evaluations."""
    # Critical unpatched CVE on lateral path -> FAILS POL-VULN-01
    vuln_context = {
        "attack_paths": [
            {
                "path_id": "path-vuln-01",
                "edges": [
                    {"type": "EXPLOITS", "cve": "CVE-2024-3400", "cvss": 9.8}
                ]
            }
        ]
    }
    eval_vuln = evaluate_policy("POL-VULN-01", vuln_context)
    assert eval_vuln.status == EvaluationStatus.FAIL
    assert len(eval_vuln.supporting_evidence) > 0

    # Uncontained phishing IOC -> FAILS POL-INC-01
    inc_context = {
        "email_verdict": "PHISHING",
        "iocs": [{"value": "198.51.100.25", "verdict": "MALICIOUS", "threat_score": 90}],
        "contained": False,
    }
    eval_inc = evaluate_policy("POL-INC-01", inc_context)
    assert eval_inc.status == EvaluationStatus.FAIL

    # Contained phishing incident -> PASSES POL-INC-01
    inc_contained = {
        "email_verdict": "PHISHING",
        "iocs": [{"value": "198.51.100.25", "verdict": "MALICIOUS", "threat_score": 90}],
        "contained": True,
    }
    eval_inc_ok = evaluate_policy("POL-INC-01", inc_contained)
    assert eval_inc_ok.status == EvaluationStatus.PASS


def test_invalid_and_disabled_policy_handling():
    """Tests unknown policy ID and administratively disabled policies."""
    unknown = evaluate_policy("POL-NONEXISTENT", {"nodes": []})
    assert unknown.status == EvaluationStatus.NOT_EVALUATED
    assert "not found" in unknown.reasoning.lower()

    # Disable a policy and assert it resolves to NOT_APPLICABLE
    pol = get_policy("POL-LOG-01")
    assert pol is not None
    disabled_pol = OrganizationPolicy(
        policy_id=pol.policy_id,
        name=pol.name,
        description=pol.description,
        rule_conditions=pol.rule_conditions,
        severity=pol.severity,
        scope=pol.scope,
        version=pol.version,
        enabled=False,
        linked_control_ids=pol.linked_control_ids,
    )
    save_policy(disabled_pol)

    eval_disabled = evaluate_policy("POL-LOG-01", {"edges": []})
    assert eval_disabled.status == EvaluationStatus.NOT_APPLICABLE
    assert "disabled" in eval_disabled.reasoning.lower()


# =============================================================================
# 3. REMEDIATION LIFECYCLE & AUDIT TRAIL TESTS
# =============================================================================

def test_remediation_lifecycle_and_audit():
    """Tests creation, status transitions, and audit generation for remediation records."""
    # 1. Create remediation
    rem = create_remediation(
        finding_reference="eval-test-001",
        recommended_action="Deploy bastion host proxy on subnet 10.0.1.0/24",
        priority=RemediationPriority.P1_CRITICAL,
        owner="secops-neteng",
        actor_id="analyst-carter",
    )
    assert rem.remediation_id.startswith("REM-")
    assert rem.status == RemediationStatus.OPEN
    assert rem.priority == RemediationPriority.P1_CRITICAL

    # 2. Update status to IN_PROGRESS
    updated1 = update_remediation_status(
        rem.remediation_id,
        new_status=RemediationStatus.IN_PROGRESS,
        resolution_evidence="Jira ticket SEC-9401 assigned to NetEng",
        actor_id="analyst-carter",
    )
    assert updated1 is not None
    assert updated1.status == RemediationStatus.IN_PROGRESS

    # 3. Resolve remediation
    updated2 = update_remediation_status(
        rem.remediation_id,
        new_status=RemediationStatus.RESOLVED,
        resolution_evidence="Bastion configured; verified zero direct routing from workstations.",
        actor_id="analyst-lead",
    )
    assert updated2 is not None
    assert updated2.status == RemediationStatus.RESOLVED

    # 4. Verify audit ledger captured each mutation
    audits = list_audit_records()
    assert len(audits) >= 3
    event_types = [a.event_type for a in audits]
    assert "REMEDIATION_CREATED" in event_types
    assert "REMEDIATION_STATUS_CHANGED" in event_types

    # 5. Verify cryptographic chain integrity
    is_valid, err = verify_audit_integrity()
    assert is_valid is True
    assert err is None


def test_audit_integrity_detects_tampering():
    """Verifies that unauthorized modifications to audit records cause cryptographic verification to fail."""
    record_audit_event("TEST_EVENT_1", "actor-1", "res-1", "CREATE", {"key": "val1"})
    record_audit_event("TEST_EVENT_2", "actor-2", "res-2", "UPDATE", {"key": "val2"})
    record_audit_event("TEST_EVENT_3", "actor-3", "res-3", "FINALIZE", {"key": "val3"})

    is_valid, _ = verify_audit_integrity()
    assert is_valid is True

    # Intentionally corrupt the payload of the second entry in the ledger
    tamper_audit_record_for_test(1, action="UNAUTHORIZED_MODIFICATION")

    # Cryptographic integrity check MUST detect the discrepancy
    tampered_valid, err = verify_audit_integrity()
    assert tampered_valid is False
    assert err is not None
    assert "Digest mismatch" in err or "Chain break" in err


# =============================================================================
# 4. ADMINISTRATIVE AUTHENTICATION & SECURITY CONTROLS TESTS
# =============================================================================

def test_api_key_extraction_and_timing_safe_check():
    """Validates API key extraction and constant-time string comparison."""
    # Direct X-API-Key
    assert extract_api_key(x_api_key="secret123") == "secret123"
    # Bearer header
    assert extract_api_key(authorization="Bearer token456") == "token456"
    # Raw token
    assert extract_api_key(authorization="token789") == "token789"
    # None
    assert extract_api_key(None, None) is None

    # Constant-time comparison
    assert hmac.compare_digest(ADMIN_API_KEY, ADMIN_API_KEY) is True
    assert hmac.compare_digest("wrong_key", ADMIN_API_KEY) is False


def test_admin_authorization_enforcement_with_flag():
    """
    Tests administrative protection when REQUIRE_API_KEY is enabled.
    Simulates production deployment setting.
    """
    client = TestClient(app)

    try:
        # Temporarily enable strict API key requirement
        config_mod.REQUIRE_API_KEY = True

        # Mutating governance route without key -> 401 Unauthorized
        res_no_auth = client.post("/api/v1/governance/policies", json={
            "policy_id": "POL-TEST-01",
            "name": "Test Policy",
            "description": "Test",
        })
        assert res_no_auth.status_code == 401
        assert "Unauthorized" in res_no_auth.json()["detail"]

        # Mutating governance route with invalid key -> 401 Unauthorized
        res_bad_auth = client.post(
            "/api/v1/governance/policies",
            json={"policy_id": "POL-TEST-01", "name": "Test", "description": "Test"},
            headers={"X-API-Key": "invalid_super_secret"},
        )
        assert res_bad_auth.status_code == 401

        # Mutating governance route with valid key -> 200 OK
        res_good_auth = client.post(
            "/api/v1/governance/policies",
            json={
                "policy_id": "POL-TEST-01",
                "name": "Test Policy",
                "description": "Test description",
                "rule_conditions": {},
                "severity": "LOW",
                "scope": "ENTERPRISE",
                "version": "1.0",
                "enabled": True,
                "linked_control_ids": [],
            },
            headers={"X-API-Key": ADMIN_API_KEY},
        )
        assert res_good_auth.status_code == 200
        assert res_good_auth.json()["policy_id"] == "POL-TEST-01"

    finally:
        # Restore dev mode setting
        config_mod.REQUIRE_API_KEY = False


# =============================================================================
# 5. CORS AND FILE UPLOAD SECURITY TESTS
# =============================================================================

def test_cors_configuration():
    """Asserts CORS origins are explicit and no wildcard is used with credentials."""
    client = TestClient(app)

    # Valid origin from explicit list
    valid_origin = "http://localhost:3000"
    assert valid_origin in CORS_ORIGINS

    res = client.options(
        "/api/v1/governance/controls",
        headers={
            "Origin": valid_origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") == valid_origin
    assert res.headers.get("access-control-allow-credentials") == "true"

    # Wildcard origin MUST NOT be configured when allow_credentials is True
    assert "*" not in CORS_ORIGINS


def test_file_upload_security_boundaries():
    """Validates file upload extension whitelisting and payload size limits."""
    client = TestClient(app)

    # 1. Invalid file extension (.exe) -> 400 Bad Request
    res_bad_ext = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("malware.exe", b"MZexecutabledata", "application/octet-stream")},
    )
    assert res_bad_ext.status_code == 400
    assert "Invalid file format" in res_bad_ext.json()["detail"]

    # 2. Empty file upload -> 400 Bad Request
    res_empty = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )
    assert res_empty.status_code == 400
    assert "empty" in res_empty.json()["detail"].lower()

    # 3. Oversized file exceeding MAX_UPLOAD_SIZE_BYTES -> 413 Payload Too Large
    oversized_bytes = b"X" * (MAX_UPLOAD_SIZE_BYTES + 1024)
    res_large = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("huge.eml", oversized_bytes, "message/rfc822")},
    )
    assert res_large.status_code == 413
    assert "Payload Too Large" in res_large.json()["detail"]


# =============================================================================
# 6. END-TO-END GOVERNANCE REST API TESTS
# =============================================================================

def test_governance_api_end_to_end():
    """Tests full API flow: catalog -> policies -> evaluate -> remediation -> audit verify."""
    client = TestClient(app)

    # 1. GET /api/v1/governance/controls
    res_controls = client.get("/api/v1/governance/controls")
    assert res_controls.status_code == 200
    controls_data = res_controls.json()
    assert len(controls_data) >= 15

    # 2. GET /api/v1/governance/controls/{id}
    res_ctrl = client.get("/api/v1/governance/controls/AC-3")
    assert res_ctrl.status_code == 200
    assert res_ctrl.json()["control_id"] == "AC-3"

    # 3. GET /api/v1/governance/policies
    res_policies = client.get("/api/v1/governance/policies")
    assert res_policies.status_code == 200
    policies_data = res_policies.json()
    assert len(policies_data) >= 6

    # 4. POST /api/v1/governance/evaluate with attack path evidence
    eval_payload = {
        "policy_id": "POL-IAM-01",
        "finding_context": {
            "attack_paths": [
                {
                    "path_id": "api-path-1",
                    "nodes": ["ws-01", "bastion-01", "db-01"],
                    "path_nodes": ["ws-01", "bastion-01", "db-01"],
                }
            ]
        }
    }
    res_eval = client.post("/api/v1/governance/evaluate", json=eval_payload)
    assert res_eval.status_code == 200
    eval_list = res_eval.json()
    assert len(eval_list) == 1
    assert eval_list[0]["status"] == "PASS"

    # 5. POST /api/v1/governance/remediations
    rem_payload = {
        "finding_reference": "finding-api-01",
        "recommended_action": "Enable multi-factor authentication on database bastion",
        "priority": "P2_HIGH",
        "owner": "cloud-sec",
    }
    res_rem = client.post("/api/v1/governance/remediations", json=rem_payload)
    assert res_rem.status_code == 201
    created_rem = res_rem.json()
    rem_id = created_rem["remediation_id"]
    assert rem_id.startswith("REM-")

    # 6. PATCH /api/v1/governance/remediations/{id}
    patch_payload = {
        "status": "RESOLVED",
        "resolution_evidence": "Enforced Okta MFA conditional access rule on bastion.",
    }
    res_patch = client.patch(f"/api/v1/governance/remediations/{rem_id}", json=patch_payload)
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "RESOLVED"

    # 7. GET /api/v1/governance/audit
    res_audit = client.get("/api/v1/governance/audit")
    assert res_audit.status_code == 200
    audits = res_audit.json()
    assert len(audits) >= 2

    # 8. GET /api/v1/governance/audit/verify
    res_verify = client.get("/api/v1/governance/audit/verify")
    assert res_verify.status_code == 200
    verify_data = res_verify.json()
    assert verify_data["ledger_intact"] is True
    assert verify_data["status"] == "VERIFIED_TAMPER_FREE"
