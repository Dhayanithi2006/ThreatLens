"""
ThreatLens - Prompt 2: Investigate Alerts Workflow Test Suite
Verifies alert triage, case indexing, attack graph retrieval, campaign correlation,
cross-investigation IOC search, RFC 822 email forensics (missing vs failed auth),
malformed/oversized MIME safety, threat intel provenance (mock tracking),
explainable AI scoring consistency, and end-to-end case lifecycle.
"""

import os
import sys
import asyncio
import pytest
from fastapi.testclient import TestClient

# Ensure workspace root is on sys.path
WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

from backend.main import app
from backend.services.case_store import default_case_repo
from backend.services.campaign_correlation import default_correlation_engine
from backend.services.email_forensics import analyze_email_forensics
from backend.services.ioc_extractor import default_ioc_service
from backend.services.threat_intelligence.virustotal import VirusTotalProvider
from backend.services.threat_intelligence.abuseipdb import AbuseIPDBProvider
from backend.services.threat_intelligence.aggregator import ThreatIntelligenceService
from backend.services.threat_detection import detect_threat
from backend.services.explainable_ai import generate_explanation
from backend.models.threat import EmailAnalysisInput
from backend.data.demo_emails import DEMO_EMAILS
from backend.data.eml_samples import EML_SAMPLES
from backend.core.config import MAX_UPLOAD_SIZE_BYTES


@pytest.fixture(scope="module")
def client():
    """Shared FastAPI test client."""
    return TestClient(app)


# ==============================================================================
# 1. ALERT & CASE MANAGEMENT ENDPOINTS (Task A)
# ==============================================================================

def test_cases_listing_and_schema(client):
    """Verify GET /api/v1/cases returns indexed cases with accurate fields."""
    response = client.get("/api/v1/cases")
    assert response.status_code == 200
    cases = response.json()
    assert isinstance(cases, list)
    assert len(cases) >= 5, "Should include preloaded historical cases"

    # Verify case schema fields
    for case in cases:
        assert "case_id" in case
        assert "subject" in case
        assert "sender" in case
        assert "threat_score" in case
        assert "risk_level" in case
        assert "iocs" in case
        assert 0 <= case["threat_score"] <= 100
        assert case["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_case_graph_retrieval(client):
    """Verify GET /api/v1/cases/{case_id}/graph generates attack graph or returns 404."""
    # Existing case
    response = client.get("/api/v1/cases/MT-101/graph")
    assert response.status_code == 200
    graph = response.json()
    assert "nodes" in graph
    assert "edges" in graph
    assert "case_id" in graph
    assert graph["case_id"] == "MT-101"
    assert len(graph["nodes"]) > 0

    # Nonexistent case
    missing_resp = client.get("/api/v1/cases/NONEXISTENT-CASE-999/graph")
    assert missing_resp.status_code == 404
    assert "not found" in missing_resp.json()["detail"].lower()


def test_campaign_endpoints(client):
    """Verify GET /api/v1/campaigns and campaign graph retrieval."""
    response = client.get("/api/v1/campaigns")
    assert response.status_code == 200
    campaigns = response.json()
    assert isinstance(campaigns, list)
    assert len(campaigns) >= 1, "Preloaded cases should yield at least one campaign cluster"

    camp = campaigns[0]
    camp_id = camp["campaign_id"]
    assert "status" in camp
    assert "shared_indicators" in camp
    assert "case_ids" in camp
    assert len(camp["case_ids"]) >= 2

    # Campaign graph
    graph_resp = client.get(f"/api/v1/campaigns/{camp_id}/graph")
    assert graph_resp.status_code == 200
    camp_graph = graph_resp.json()
    assert "nodes" in camp_graph
    assert "edges" in camp_graph

    # Nonexistent campaign
    missing_camp = client.get("/api/v1/campaigns/CMP-NONEXISTENT/graph")
    assert missing_camp.status_code == 404


def test_cross_investigation_ioc_search(client):
    """Verify GET /api/v1/search/ioc accurately queries cases and campaigns."""
    # Search by IP present in MT-101, MT-102, MT-103
    resp = client.get("/api/v1/search/ioc?q=185.190.140.22")
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "185.190.140.22"
    assert data["total_matches"] >= 3
    matched_ids = [c["case_id"] for c in data["matching_cases"]]
    assert "MT-101" in matched_ids
    assert "MT-102" in matched_ids
    assert len(data["matching_campaigns"]) >= 1

    # Search by domain
    resp_dom = client.get("/api/v1/search/ioc?q=alert-center.xyz")
    assert resp_dom.status_code == 200
    assert resp_dom.json()["total_matches"] >= 2

    # Search for nonexistent IOC
    resp_clean = client.get("/api/v1/search/ioc?q=clean-never-seen-998877.org")
    assert resp_clean.status_code == 200
    assert resp_clean.json()["total_matches"] == 0
    assert len(resp_clean.json()["matching_cases"]) == 0

    # Missing query parameter returns 422
    resp_empty = client.get("/api/v1/search/ioc")
    assert resp_empty.status_code == 422


# ==============================================================================
# 2. EMAIL FORENSICS & AUTHENTICATION INTEGRITY (Task B)
# ==============================================================================

def test_missing_vs_failed_authentication_distinction():
    """Verify that missing authentication headers are labeled 'unknown' and never trigger false positive failure penalties."""
    # Synthetic email with NO authentication headers
    raw_no_auth = (
        "From: colleague@partner.org\r\n"
        "To: employee@corporation.com\r\n"
        "Subject: Project Kickoff Notes\r\n"
        "Date: Wed, 29 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <notes-123@partner.org>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Hi, here are the project kickoff notes from our call.\r\n"
    )
    result = analyze_email_forensics(raw_no_auth)
    # Auth status should be UNKNOWN, not FAIL
    assert result.authentication.spf.result == "unknown"
    assert result.authentication.dkim.result == "unknown"
    assert result.authentication.dmarc.result == "unknown"
    assert result.authentication.overall_status in ["UNKNOWN", "NEUTRAL", "UNVERIFIED"]

    # Verify no authentication fail anomalies were added
    auth_anomalies = [a for a in result.anomalies if "SPF" in a.description or "DKIM" in a.description or "DMARC" in a.description]
    assert len(auth_anomalies) == 0, "Missing headers must not be classified as explicit authentication failures"

    # Synthetic email with EXPLICIT authentication failure
    raw_failed_auth = (
        "From: boss@corporation.com\r\n"
        "To: employee@corporation.com\r\n"
        "Subject: Urgent Wire Transfer\r\n"
        "Authentication-Results: mx.corporation.com; spf=fail (sender IP not authorized); dkim=fail\r\n"
        "Date: Wed, 29 Oct 2026 10:05:00 +0000\r\n"
        "Message-ID: <wire-999@attacker.net>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Please transfer funds immediately.\r\n"
    )
    fail_result = analyze_email_forensics(raw_failed_auth)
    assert fail_result.authentication.spf.result == "fail"
    assert fail_result.authentication.dkim.result == "fail"
    assert fail_result.authentication.overall_status in ["FAIL", "FAILED", "SUSPICIOUS"]
    fail_anomalies = [a for a in fail_result.anomalies if "SPF" in a.description or "DKIM" in a.description]
    assert len(fail_anomalies) > 0, "Explicit failures must be recorded in anomalies"


def test_malformed_and_edge_case_mime_handling():
    """Verify parser robustness against truncated boundaries, nested encoding, and empty input."""
    # Truncated MIME boundary
    raw_truncated_mime = (
        "From: sender@example.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Broken Boundary\r\n"
        "Content-Type: multipart/mixed; boundary=\"====BOUNDARY====\"\r\n"
        "\r\n"
        "--====BOUNDARY====\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Partial text without closing boundary..."
    )
    result = analyze_email_forensics(raw_truncated_mime)
    assert result.subject == "Broken Boundary"
    assert result.raw_evidence_hash is not None

    # Mixed character sets and encoded words
    raw_encoded_words = (
        "From: =?utf-8?B?U2VjdXJpdHkgVGVhbQ==?= <security@test.org>\r\n"
        "To: user@corporation.com\r\n"
        "Subject: =?iso-8859-1?Q?Compromise_=E9tude?=\r\n"
        "\r\n"
        "Testing character decoding safety."
    )
    enc_result = analyze_email_forensics(raw_encoded_words)
    assert "Security Team" in enc_result.sender_identity.display_name or "security@test.org" in enc_result.sender_identity.from_address
    assert enc_result.raw_evidence_hash is not None


def test_forensics_upload_validations(client):
    """Verify /api/v1/analyze/forensics/upload security boundary validations."""
    # Rejection of wrong extension
    bad_ext_resp = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("malicious.exe", b"MZexecutabledata", "application/octet-stream")}
    )
    assert bad_ext_resp.status_code == 400
    assert "extension" in bad_ext_resp.json()["detail"].lower()

    # Rejection of empty file
    empty_resp = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("empty.eml", b"", "message/rfc822")}
    )
    assert empty_resp.status_code == 400
    assert "empty" in empty_resp.json()["detail"].lower()

    # Rejection of oversized file exceeding MAX_UPLOAD_SIZE_BYTES
    oversized_data = b"X" * (MAX_UPLOAD_SIZE_BYTES + 1024)
    oversized_resp = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("large.eml", oversized_data, "message/rfc822")}
    )
    assert oversized_resp.status_code == 413
    assert "exceeds" in oversized_resp.json()["detail"].lower()

    # Successful valid EML upload
    valid_eml_bytes = EML_SAMPLES["benign"].encode("utf-8")
    valid_resp = client.post(
        "/api/v1/analyze/forensics/upload",
        files={"file": ("benign.eml", valid_eml_bytes, "message/rfc822")}
    )
    assert valid_resp.status_code == 200
    v_data = valid_resp.json()
    assert v_data["subject"] is not None
    assert v_data["sender_identity"]["from_address"] == "alice@corporation.com"


# ==============================================================================
# 3. IOC EXTRACTION & THREAT INTEL PROVENANCE (Task C)
# ==============================================================================

def test_ioc_extraction_coverage():
    """Verify IOC extraction covers domains, IPs, URLs, hashes, and emails safely."""
    raw_eml = EML_SAMPLES["phishing"]
    forensics = analyze_email_forensics(raw_eml)
    iocs = default_ioc_service.extract_from_forensics(forensics, raw_eml)

    # Validate domains
    assert len(iocs.domains) > 0
    domain_vals = [d.value for d in iocs.domains]
    assert any("alert-center.xyz" in d for d in domain_vals)

    # Validate IPs (including public/private scope tagging)
    assert len(iocs.ips) > 0
    for ip in iocs.ips:
        assert ip.scope in ["public", "private", "loopback", "unknown"]

    # Validate URLs
    assert len(iocs.urls) > 0
    for u in iocs.urls:
        assert u.normalized is not None
        assert u.scheme in ["http", "https"]

    # Total counts
    assert (iocs.summary.urls + iocs.summary.domains + iocs.summary.ips) > 0


def test_threat_intel_provenance_and_private_ip_safety():
    """Verify external intel query safety: private IPs skipped and mock fallback explicitly tagged."""
    async def _run_async_checks():
        vt = VirusTotalProvider(mode="mock")
        abuse = AbuseIPDBProvider(mode="mock")
        service = ThreatIntelligenceService(vt_provider=vt, abuse_provider=abuse)

        # RFC 1918 Private IP lookup must be skipped without hitting external services
        priv_res = await abuse.lookup_ip("192.168.1.100", scope="private")
        assert priv_res.status == "SKIPPED"
        assert priv_res.abuse_confidence == 0

        loopback_res = await abuse.lookup_ip("127.0.0.1", scope="loopback")
        assert loopback_res.status == "SKIPPED"

        # Public IP lookup in mock mode must preserve mock provenance
        pub_res = await abuse.lookup_ip("185.190.140.22", scope="public")
        assert pub_res.status in ["FOUND", "MOCK"]

        # Verify aggregator tags is_mock=True on enriched item
        from backend.models.ioc import IocExtractionResult, IpIoc
        ioc_container = IocExtractionResult(ips=[IpIoc(value="185.190.140.22", scope="public")])
        enriched = await service.enrich_iocs(ioc_container)
        assert len(enriched.results) > 0
        intel_item = enriched.results[0]
        assert intel_item.is_mock is True, "Mock threat intelligence must explicitly flag is_mock=True"
        assert intel_item.checked_at is not None

    asyncio.run(_run_async_checks())


# ==============================================================================
# 4. RISK SCORING & EXPLAINABLE AI CONSISTENCY (Task D)
# ==============================================================================

def test_risk_scoring_and_xai_explainability():
    """Verify threat scoring normalization, correlation capping, and explainable AI evidence output."""
    # Benign email input
    benign_input = EmailAnalysisInput(**DEMO_EMAILS["benign"])
    b_result = detect_threat(benign_input)
    assert b_result.threat_score <= 20
    assert b_result.risk_level == "LOW"
    assert b_result.primary_threat == "BENIGN"

    b_xai = generate_explanation(b_result, benign_input)
    assert b_xai.is_benign is True
    assert b_xai.primary_threat == "BENIGN"
    assert b_xai.risk_level == "LOW"
    assert len(b_xai.benign_assurances) > 0

    # Phishing email with multiple correlated fear signals and auth failures
    phish_input = EmailAnalysisInput(**DEMO_EMAILS["phishing"])
    p_result = detect_threat(phish_input)
    assert 70 <= p_result.threat_score <= 100, "Correlated phishing must score HIGH/CRITICAL and remain capped at 100"
    assert p_result.risk_level in ["HIGH", "CRITICAL"]

    p_xai = generate_explanation(p_result, phish_input)
    assert len(p_xai.top_reasons) >= 2
    # Verify ranked factors
    assert len(p_xai.risk_factors) > 0

    # Determinism: exact same input produces exact same score
    p_result2 = detect_threat(phish_input)
    assert p_result.threat_score == p_result2.threat_score
    assert p_result.primary_threat == p_result2.primary_threat

    # Determinism: exact same input produces exact same score
    p_result2 = detect_threat(phish_input)
    assert p_result.threat_score == p_result2.threat_score
    assert p_result.primary_threat == p_result2.primary_threat


# ==============================================================================
# 5. END-TO-END PIPELINE & CASE INDEXING (Tasks A, B, C, D, E)
# ==============================================================================

def test_full_pipeline_eml_analysis_and_case_lifecycle(client):
    """
    Verify complete POST /api/v1/analyze/eml pipeline:
    1. Parses forensics
    2. Extracts IOCs
    3. Queries threat intelligence
    4. Detects threat and explains factors
    5. Indexes new case into CaseRepository
    6. Enables cross-investigation search for newly created case
    """
    phish_eml = EML_SAMPLES["phishing"]
    resp = client.post("/api/v1/analyze/eml", json={"raw_eml": phish_eml})
    assert resp.status_code == 200
    data = resp.json()

    # Check all 8 pipeline components
    expected_keys = [
        "case_id",
        "forensics",
        "iocs",
        "threat_intelligence",
        "attack_graph",
        "campaign_correlation",
        "threat_analysis",
        "explanation",
        "graphops_bridge_url"
    ]
    for key in expected_keys:
        assert key in data, f"Missing key in pipeline response: {key}"

    new_case_id = data["case_id"]
    assert new_case_id.startswith("MT-")

    # Verify newly created case is indexed in repository
    retrieved_case = default_case_repo.get_case(new_case_id)
    assert retrieved_case is not None
    assert retrieved_case.case_id == new_case_id
    assert retrieved_case.threat_score >= 70

    # Verify case appears in GET /api/v1/cases
    all_cases_resp = client.get("/api/v1/cases")
    assert all_cases_resp.status_code == 200
    all_case_ids = [c["case_id"] for c in all_cases_resp.json()]
    assert new_case_id in all_case_ids

    # Verify graph can be retrieved for new case
    case_graph_resp = client.get(f"/api/v1/cases/{new_case_id}/graph")
    assert case_graph_resp.status_code == 200
    assert case_graph_resp.json()["case_id"] == new_case_id

    # Verify cross-investigation search finds this new case via extracted IOC
    extracted_domains = [d["value"] for d in data["iocs"]["domains"]]
    if extracted_domains:
        test_domain = extracted_domains[0]
        search_resp = client.get(f"/api/v1/search/ioc?q={test_domain}")
        assert search_resp.status_code == 200
        found_ids = [c["case_id"] for c in search_resp.json()["matching_cases"]]
        assert new_case_id in found_ids
