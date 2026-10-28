"""
ThreatLens MVP - Phase 4 Integration Test Suite
Verifies the complete end-to-end integration between ThreatLens Email Threat Investigation
and GraphOps Enterprise Graph Investigation.

Key checks:
1. End-to-end workflow: Email/.eml -> IOC extraction -> Case creation -> GraphOps Bridge -> Blast Radius / Attack Paths.
2. Evidence-backed identity correlation (recipient email -> Active Directory User -> Assigned Device).
3. Critical rule: Phishing email receipt DOES NOT mark recipient endpoint as compromised.
4. Quarantining of external attacker IOCs (IPs/domains) from internal enterprise graph.
5. Error handling and HTTP 404 responses for non-existent case IDs and unindexed entities.
6. Anomaly detection validation with structured finding schema (finding_id, rule_id, severity, etc.).
7. Cold start and incomplete baseline handling (new legitimate user not flagged as malicious).
8. External threat-intelligence provider failure tolerance.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.case_store import default_case_repo, CaseRecord
from backend.data.eml_samples import EML_SAMPLES
from backend.graphops.client import get_graphops_client
from backend.graphops.attack_paths import AttackPathService, CaseNotFoundError
from backend.graphops.anomaly_detection import AccessAnomalyDetector
from backend.models.graphops import (
    AnomalyClassification,
    DeviationType,
    HistoryCompleteness,
    BaselineConfidence,
    AccessSequenceStep,
    AccessSequenceRequest,
)
from backend.graphops.schema import RelationshipType
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from test_graphops_phase7 import build_phase7_fixture_mock


@pytest.fixture
def mock_graph_client():
    return build_phase7_fixture_mock()


@pytest.fixture
def client(mock_graph_client):
    app.dependency_overrides[get_graphops_client] = lambda: mock_graph_client
    c = TestClient(app)
    yield c
    app.dependency_overrides.pop(get_graphops_client, None)


@pytest.fixture
def anomaly_detector():
    return AccessAnomalyDetector()


# =====================================================================
# 1. END-TO-END INVESTIGATION FLOW & CASE BRIDGE
# =====================================================================

class TestEmailToGraphOpsWorkflow:

    def test_complete_eml_analysis_to_graphops_bridge(self, client):
        """
        Verify: EML upload/analysis -> Case creation with recipient -> Bridge to GraphOps.
        """
        phishing_eml = EML_SAMPLES["phishing"].replace("victim@corporation.com", "victim1@corporation.com")
        
        # 1. Analyze EML via API
        resp = client.post(
            "/api/v1/analyze/eml",
            json={"raw_eml": phishing_eml}
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        
        assert "case_id" in data
        assert "graphops_bridge_url" in data
        case_id = data["case_id"]
        bridge_url = data["graphops_bridge_url"]
        assert f"/api/v1/graphops/bridge/case/{case_id}" == bridge_url
        
        # Verify case record in default_case_repo has recipient populated
        case_rec = default_case_repo.get(case_id)
        assert case_rec is not None
        assert case_rec.recipient is not None
        assert "victim1@corporation.com" in case_rec.recipient.lower()

        # 2. Query Case Bridge Endpoint
        bridge_resp = client.get(bridge_url)
        assert bridge_resp.status_code == 200, bridge_resp.text
        bridge_data = bridge_resp.json()

        assert bridge_data["case_id"] == case_id
        assert bridge_data["primary_compromised_node"] is not None
        assert bridge_data["primary_compromised_node"]["id"] == "user:usr-101"
        
        # 3. Verify Investigation Disclaimer: Receipt is NOT compromise
        assert "investigation_disclaimer" in bridge_data
        assert "RECEIPT IS NOT COMPROMISE" in bridge_data["investigation_disclaimer"]
        assert "not confirmed compromised infrastructure" in bridge_data["investigation_disclaimer"]

        # 4. Verify External IOCs Quarantined
        assert "185.190.140.22" in bridge_data["unmapped_external_iocs"]
        assert "alert-center.xyz" in bridge_data["unmapped_external_iocs"]

        # 5. Verify GraphOps Blast Radius navigation
        blast_url = bridge_data["recommended_blast_radius_url"]
        assert "/api/v1/graphops/blast-radius" in blast_url
        assert "user:usr-101" in blast_url

        # Execute blast radius on bridged node
        blast_resp = client.get(blast_url)
        assert blast_resp.status_code == 200
        blast_res = blast_resp.json()
        assert blast_res["start_node"]["id"] == "user:usr-101"

    def test_phishing_receipt_does_not_mark_device_as_compromised(self, mock_graph_client):
        """
        Critical rule verification:
        Receiving a phishing email must NOT automatically mark the recipient's device as compromised.
        """
        service = AttackPathService(mock_graph_client)
        res = service.bridge_case_to_graph("MT-101")
        
        # Check mapped device rationale
        device_mapping = next((m for m in res.mapped_entities if m.evidence_type == "ASSIGNED_DEVICE"), None)
        assert device_mapping is not None
        assert "exposure" in device_mapping.match_rationale.lower()
        assert "not confirmed device compromise" in device_mapping.match_rationale.lower()

        # Check disclaimer
        assert "RECEIPT IS NOT COMPROMISE" in res.investigation_disclaimer

    def test_bridge_nonexistent_case_returns_404(self, client):
        """Unknown case ID must return a clean HTTP 404 without silent failure or fallback fake data."""
        resp = client.get("/api/v1/graphops/bridge/case/NON_EXISTENT_CASE_99999")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_unindexed_recipient_email_graceful_handling(self, mock_graph_client):
        """Recipient with no matching Active Directory node should be handled safely."""
        service = AttackPathService(mock_graph_client)
        
        # Seed a case with an unknown external recipient
        unknown_case = CaseRecord(
            case_id="MT-EXT-999",
            subject="External Phishing Test",
            sender="attacker@evil.com",
            recipient="external_consultant@unindexed-contractor.net",
            threat_score=80,
            risk_level="HIGH",
            primary_threat="PHISHING",
            timestamp="2026-08-28T10:15:00Z",
            iocs={"domains": [], "ips": ["1.2.3.4"], "urls": [], "emails": [], "hashes": []},
        )
        default_case_repo.save(unknown_case)

        # Bridge should succeed with unmapped list and fallback node
        bridge_res = service.bridge_case_to_graph("MT-EXT-999")
        assert bridge_res.case_id == "MT-EXT-999"
        assert any("external_consultant" in u for u in bridge_res.unmapped_external_iocs)


# =====================================================================
# 2. ANOMALY DETECTION STRUCTURED FINDINGS & ACCURACY
# =====================================================================

class TestAnomalyDetectionFidelity:

    def test_anomaly_findings_contain_all_required_fields(self, anomaly_detector):
        """
        Verify that every unexpected relationship / anomaly finding contains:
        - finding_id
        - rule_id
        - severity
        - affected_entity
        - supporting_event_sequence
        - detection_rationale
        - timestamp
        - recommended_investigation
        - relevant_graph_context
        """
        # Exploit precondition step that triggers anomaly finding
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="device:dev-ws-101",
                relationship_type=RelationshipType.POTENTIAL_EXPLOIT,
                target_id="server:srv-app-01",
                properties={"via_cve": "CVE-2024-21413"},
            )
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="device:dev-ws-101",
            steps=steps,
        )
        res = anomaly_detector.evaluate_sequence(req)
        assert res.is_anomalous
        assert len(res.unexpected_relationships) >= 1

        finding = res.unexpected_relationships[0]
        assert finding.finding_id.startswith("ANOM-")
        assert finding.rule_id == "RULE-EXPLOIT-PRECONDITION-01"
        assert finding.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert finding.affected_entity == "server:srv-app-01"
        assert len(finding.supporting_event_sequence) >= 1
        assert finding.detection_rationale != ""
        assert finding.timestamp != ""
        assert "investigat" in finding.recommended_investigation.lower() or "inspect" in finding.recommended_investigation.lower() or "quarantine" in finding.recommended_investigation.lower()
        assert finding.relevant_graph_context is not None
        assert finding.relevant_graph_context.get("source_id") == "device:dev-ws-101"

    def test_benign_access_has_zero_false_positive_anomalies(self, anomaly_detector):
        """Legitimate workstation accessing internal application server produces zero anomalies."""
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="user:usr-101",
                relationship_type=RelationshipType.USES,
                target_id="device:dev-ws-101",
            ),
            AccessSequenceStep(
                step_index=1,
                source_id="device:dev-ws-101",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-app-01",
                properties={"port": 443},
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="user:usr-101",
            steps=steps,
        )
        res = anomaly_detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.BENIGN_EXPECTED
        assert res.anomaly_score < 20
        assert not res.is_anomalous
        assert len(res.unexpected_relationships) == 0

    def test_cold_start_new_employee_not_classified_as_attacker(self, anomaly_detector):
        """
        New employee with incomplete historical baseline must be classified as
        UNOBSERVED_NEW_LEGITIMATE rather than flagged as malicious or anomalous.
        """
        steps = [
            AccessSequenceStep(
                step_index=0,
                source_id="user:usr-104",  # New employee
                relationship_type=RelationshipType.USES,
                target_id="device:dev-ws-104",
            ),
            AccessSequenceStep(
                step_index=1,
                source_id="device:dev-ws-104",
                relationship_type=RelationshipType.OBSERVED_CONNECTION,
                target_id="server:srv-app-01",
                properties={"port": 443},
            ),
        ]
        req = AccessSequenceRequest(
            evaluated_entity_id="user:usr-104",
            steps=steps,
        )
        res = anomaly_detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE
        assert res.history_completeness == HistoryCompleteness.INCOMPLETE
        assert res.baseline_confidence == BaselineConfidence.LOW
        assert not res.is_anomalous  # Strictly not an attack

    def test_evaluate_case_anomalies_preserves_uncompromised_state(self, anomaly_detector):
        """
        When evaluating anomaly risk for an email investigation case,
        the client context must specify that receiving a phishing email does NOT
        equate to confirmed endpoint compromise.
        """
        res = anomaly_detector.evaluate_case("MT-101")
        assert res.evaluated_entity_id in ["case:MT-101", "device:dev-ws-101"]
        assert "mt-101" in res.sequence_id.lower()
        # Workstation dev-ws-101 accessing app-01 is not marked critical compromise
        # because has_confirmed_compromise is False
        assert res.classification in [AnomalyClassification.BENIGN_EXPECTED, AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE]


# =====================================================================
# 3. ERROR HANDLING AND PROVIDER FAULT TOLERANCE
# =====================================================================

class TestErrorHandlingAndResilience:

    def test_threat_intel_provider_fallback_graceful(self, client):
        """
        Simulated threat intelligence provider unconfigured/offline must not crash
        IOC enrichment or case endpoints.
        """
        # Testing the enrichment API for an IOC with provider mock/fallback
        resp = client.post(
            "/api/v1/analyze/intelligence",
            json={"indicators": ["185.190.140.22"]}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert data["summary"]["total_analyzed"] >= 1
        assert "results" in data
        assert len(data["results"]) >= 1
        assert data["results"][0]["normalized_status"] in ["MALICIOUS", "SUSPICIOUS", "CLEAN_REPORTED", "UNKNOWN", "NOT_CONFIGURED"]
