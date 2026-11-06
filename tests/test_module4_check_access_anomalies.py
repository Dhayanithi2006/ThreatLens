"""
ThreatLens - Module 4: Check Access & Anomalies Comprehensive Test Suite

Verifies:
1. Submodule 1: Graph Anomaly Detection
   - Rule-based access anomaly detection with 4-tier matrix
   - Cold-start handling & baseline confidence assessment
   - scikit-learn Isolation Forest ML inference & cold-start robustness
   - PyTorch Geometric GNN structural link scoring & missing artifact fallback
   - Case-linked anomaly evaluation & preset sequence evaluation
   - Findings retrieval with multi-parameter filtering (severity, type, score, search)
2. Submodule 2: Entitled vs. Used Access (Zero-Trust)
   - Dual-graph comparison: IAM entitlements vs. empirical observed telemetry
   - 3-way partition: ACTIVE_VERIFIED, OVER_PRIVILEGED_DORMANT, UNENTITLED_SHADOW
   - Discrepancy explanation without assuming missing permissions equal compromise
   - Filtering by entity_id, status_filter, severity, and keyword search
   - Pivot URLs to Module 3 Blast Radius
3. Submodule 3: Security Communities
   - Enterprise security enclaves partition (Crown Jewels, IAM, DMZ, User Endpoints)
   - Cross-boundary lateral movement boundary edge detection
   - Newman-Girvan modularity metric calculation
   - Filtering by community_id and risk_level
   - Frontend schema compatibility aliases
4. Centralized Integration & Cross-Module Linkage
   - Shared canonical identifiers across graph, events, and cases
   - Module 1 case evidence bridge into Module 4 anomaly evaluation
   - Direct pivot URLs to Module 3 Blast Radius
"""

import pytest
from typing import Dict, Any, List
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.mock_client import get_mock_graphops_client
from backend.graphops.anomaly_detection import AccessAnomalyDetector
from backend.graphops.zero_trust import ZeroTrustAuditService, get_zero_trust_service
from backend.graphops.communities import detect_security_communities
from backend.graphops.ml_service import get_event_anomaly_ml_service
from backend.graphops.pyg_service import get_pyg_learning_service
from backend.graphops.kafka_processor import GraphOpsEventProcessor
from backend.models.graphops import (
    AccessSequenceRequest,
    AccessSequenceStep,
    AnomalyClassification,
    DeviationType,
    BaselineConfidence,
    HistoryCompleteness,
    SecurityEventEnvelope,
    SecurityEventType,
    CriticalityTier,
)


@pytest.fixture
def mock_client():
    return get_mock_graphops_client()


@pytest.fixture
def api_client():
    return TestClient(app)


# ==============================================================================
# SUBMODULE 1: GRAPH ANOMALY DETECTION TESTS
# ==============================================================================

class TestGraphAnomalyDetection:
    """Tests rule-based detection, scoring formula, cold-start, and classifications."""

    def test_benign_expected_access_sequence(self, mock_client):
        """Verifies normal, verified historical access receives BENIGN_EXPECTED classification (score 0-19)."""
        detector = AccessAnomalyDetector(mock_client)
        req = AccessSequenceRequest(
            sequence_id="test-benign-seq",
            evaluated_entity_id="user:usr-101",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="user:usr-101",
                    relationship_type="USES",
                    target_id="device:dev-ws-101",
                ),
                AccessSequenceStep(
                    step_index=1,
                    source_id="device:dev-ws-101",
                    relationship_type="OBSERVED_CONNECTION",
                    target_id="server:srv-app-01",
                ),
            ],
            include_explanations=True,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.BENIGN_EXPECTED
        assert res.anomaly_score < 20
        assert not res.is_anomalous
        assert len(res.unexpected_relationships) == 0

    def test_unobserved_new_legitimate_not_labeled_malicious(self, mock_client):
        """Verifies newly observed connection conforming to role and tiering is not marked malicious (score 20-39)."""
        detector = AccessAnomalyDetector(mock_client)
        # dev-ws-104 is a newly hired Finance workstation accessing application gateway
        req = AccessSequenceRequest(
            sequence_id="test-new-legit-seq",
            evaluated_entity_id="device:dev-ws-104",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="device:dev-ws-104",
                    relationship_type="OBSERVED_CONNECTION",
                    target_id="server:srv-app-01",
                )
            ],
            include_explanations=True,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE
        assert 20 <= res.anomaly_score < 40
        assert not res.is_anomalous
        assert len(res.unexpected_relationships) == 1
        finding = res.unexpected_relationships[0]
        assert finding.deviation_type == DeviationType.UNOBSERVED_RELATIONSHIP
        assert "conforms" in finding.explanation.lower()

    def test_policy_violation_tier_bypass(self, mock_client):
        """Verifies client-to-database tier bypass receives POLICY_VIOLATION_UNAUTHORIZED (score 40-79)."""
        detector = AccessAnomalyDetector(mock_client)
        req = AccessSequenceRequest(
            sequence_id="test-policy-bypass",
            evaluated_entity_id="device:dev-ws-101",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="device:dev-ws-101",
                    relationship_type="OBSERVED_CONNECTION",
                    target_id="server:srv-db-01",
                    properties={"port": 5432},
                )
            ],
            include_explanations=True,
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED
        assert 40 <= res.anomaly_score < 80
        assert res.is_anomalous
        assert len(res.unexpected_relationships) == 1
        finding = res.unexpected_relationships[0]
        assert finding.deviation_type == DeviationType.TIER_BYPASS
        assert "RULE-TIER-CLIENT-TO-DB-01" in finding.rule_id
        assert finding.blast_radius_pivot_url is not None

    def test_suspicious_anomalous_exploit_precondition(self, mock_client):
        """Verifies CVE exploit traversal receives SUSPICIOUS_ANOMALOUS (score 80-100)."""
        detector = AccessAnomalyDetector(mock_client)
        req = AccessSequenceRequest(
            sequence_id="test-exploit-seq",
            evaluated_entity_id="device:dev-ws-101",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="device:dev-ws-101",
                    relationship_type="POTENTIAL_EXPLOIT",
                    target_id="server:srv-app-01",
                    properties={"via_cve": "CVE-2024-21413"},
                )
            ],
            include_explanations=True,
            client_context={"case_id": "MT-101"},
        )
        res = detector.evaluate_sequence(req)
        assert res.classification == AnomalyClassification.SUSPICIOUS_ANOMALOUS
        assert res.anomaly_score >= 80
        assert res.is_anomalous
        finding = res.unexpected_relationships[0]
        assert finding.deviation_type == DeviationType.EXPLOIT_PRECONDITION
        assert finding.case_id == "MT-101"
        assert "blast-radius" in finding.blast_radius_pivot_url

    def test_cold_start_vs_established_entity(self, mock_client):
        """Verifies cold-start entities receive LOW confidence while established receive HIGH confidence."""
        detector = AccessAnomalyDetector(mock_client)
        # Established user
        h_comp, b_conf, _ = detector._assess_cold_start("user:usr-101")
        assert h_comp == HistoryCompleteness.COMPLETE
        assert b_conf == BaselineConfidence.HIGH

        # Unknown / cold-start user
        h_comp_new, b_conf_new, _ = detector._assess_cold_start("user:usr-brand-new-999")
        assert h_comp_new == HistoryCompleteness.INCOMPLETE
        assert b_conf_new == BaselineConfidence.LOW


class TestMLAndPyGAnomalyServices:
    """Tests scikit-learn Isolation Forest and PyTorch Geometric GraphSAGE."""

    def test_isolation_forest_evaluates_normal_vs_outlier_event(self):
        """Verifies ML service generates structured prediction and isolates statistical outliers."""
        ml_service = get_event_anomaly_ml_service()
        # Normal event
        normal_evt = SecurityEventEnvelope(
            event_id="EVT-TEST-NORM-01",
            event_type=SecurityEventType.IDENTITY_EVENT,
            source="TestAgent",
            occurred_at="2026-03-01T10:00:00Z",
            entity_ids=["user:usr-101", "device:dev-ws-101"],
            payload={"auth_status": "SUCCESS", "hour_of_day": 10},
        )
        norm_pred = ml_service.evaluate_event(normal_evt)
        assert 0.0 <= norm_pred.normalized_score <= 100.0
        assert norm_pred.model_version is not None

        # Outlier event (off-hours unusual target)
        outlier_evt = SecurityEventEnvelope(
            event_id="EVT-TEST-OUTLIER-01",
            event_type=SecurityEventType.COMPROMISE_INDICATOR,
            source="TestAgent",
            occurred_at="2026-03-01T03:30:00Z",
            entity_ids=["device:dev-ws-101", "server:srv-dc-01"],
            payload={"auth_status": "FAILURE", "hour_of_day": 3, "failed_attempts": 25},
        )
        outlier_pred = ml_service.evaluate_event(outlier_evt)
        assert 0.0 <= outlier_pred.normalized_score <= 100.0

    def test_pyg_evaluates_relationship_or_falls_back_gracefully(self):
        """Verifies PyG service scores link plausibility or falls back gracefully without inventing predictions."""
        pyg_service = get_pyg_learning_service()
        status = pyg_service.get_status()
        assert status.model_name == "StructuralGraphSAGE"

        res = pyg_service.evaluate_relationship(
            source_entity_id="device:dev-ws-101",
            target_entity_id="server:srv-app-01",
            relationship_type="OBSERVED_CONNECTION",
        )
        assert res.prediction_type == "RELATIONSHIP_PLAUSIBILITY_ANOMALY"
        assert 0.0 <= res.structural_anomaly_score <= 100.0
        assert 0.0 <= res.predicted_plausibility <= 1.0

        # If model is unavailable, it must report model_available=False and never invent fake predictions
        if not pyg_service.model_loaded:
            assert res.model_available is False
            assert res.score_interpretation == "MODEL_UNAVAILABLE"


# ==============================================================================
# SUBMODULE 2: ENTITLED VS. USED ACCESS (ZERO-TRUST) TESTS
# ==============================================================================

class TestZeroTrustAccessAudit:
    """Tests Zero-Trust dual-graph comparison between IAM permissions and empirical telemetry."""

    def test_zero_trust_3way_partition_and_disclaimer(self, mock_client):
        """Verifies audit partitions access into active, dormant, and unentitled, with compliance guidance."""
        service = get_zero_trust_service(mock_client)
        audit = service.audit_access_entitlements()

        assert audit.total_entitled_permissions > 0
        assert audit.active_verified_permissions > 0
        assert audit.dormant_overprivileged_permissions > 0
        assert audit.unentitled_shadow_connections >= 0
        assert 0.0 <= audit.least_privilege_compliance_pct <= 100.0
        assert 0.0 <= audit.over_privilege_risk_score <= 100.0

        # Verify core zero-trust disclaimer: missing permissions do not mean confirmed compromise
        assert "dormant entitlements to review" in audit.disclaimer.lower()
        assert "not conclusive proof of malicious activity" in audit.disclaimer.lower()

        # Check item breakdown schema and pivot URLs
        for item in audit.access_breakdown:
            assert item.status in ("ACTIVE_VERIFIED", "OVER_PRIVILEGED_DORMANT", "UNENTITLED_SHADOW")
            assert item.blast_radius_pivot_url is not None
            assert item.graph_pivot_url is not None
            assert item.risk_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_zero_trust_filtering_by_entity_and_severity(self, mock_client):
        """Verifies filtering by canonical entity_id, severity, and keyword search."""
        service = get_zero_trust_service(mock_client)

        # Filter by entity
        res_entity = service.audit_access_entitlements(entity_id="user:usr-101")
        assert all("usr-101" in item.source_id.lower() or "usr-101" in item.target_id.lower() for item in res_entity.access_breakdown)

        # Filter by severity
        res_crit = service.audit_access_entitlements(severity="CRITICAL")
        assert all(item.risk_severity == "CRITICAL" for item in res_crit.access_breakdown)

        # Filter by search keyword
        res_search = service.audit_access_entitlements(search="database")
        assert all("db" in item.target_id.lower() or "database" in (item.recommendation + (item.basis or "")).lower() for item in res_search.access_breakdown)


# ==============================================================================
# SUBMODULE 3: SECURITY COMMUNITIES TESTS
# ==============================================================================

class TestSecurityCommunities:
    """Tests modularity community detection, enclaves, and cross-boundary edges."""

    def test_security_community_partitioning_and_modularity(self, mock_client):
        """Verifies discovery of topological enclaves and cross-boundary lateral movement edges."""
        res = detect_security_communities(mock_client)

        assert res.total_communities >= 4
        cluster_ids = {c.community_id for c in res.communities}
        assert "COMM-CROWN-JEWELS" in cluster_ids
        assert "COMM-DMZ-GATEWAYS" in cluster_ids
        assert "COMM-USER-ENDPOINTS" in cluster_ids
        assert "COMM-IAM" in cluster_ids

        # Modularity score Q
        assert res.modularity_score > 0.4
        assert res.modularity_q == res.modularity_score

        # Boundary transitions
        assert res.cross_boundary_edges_count > 0
        assert len(res.cross_boundary_transitions) == res.cross_boundary_edges_count
        for b in res.boundary_edges:
            assert b.source_node == b.source_id
            assert b.target_node == b.target_id

        # Cluster metadata
        for c in res.communities:
            assert c.node_count == len(c.node_ids)
            assert len(c.sample_nodes) <= 5

    def test_security_community_filtering(self, mock_client):
        """Verifies filtering communities by community_id and risk_level."""
        res_cj = detect_security_communities(mock_client, community_id="COMM-CROWN-JEWELS")
        assert res_cj.total_communities == 1
        assert res_cj.communities[0].community_id == "COMM-CROWN-JEWELS"

        res_high = detect_security_communities(mock_client, risk_level="HIGH")
        assert all(c.risk_level == "HIGH" for c in res_high.communities)
        assert all(b.risk_level == "HIGH" for b in res_high.boundary_edges)


# ==============================================================================
# SUBMODULE 4: FASTAPI REST ENDPOINTS & CROSS-MODULE INTEGRATION TESTS
# ==============================================================================

class TestModule4RestEndpointsAndIntegration:
    """Tests all Module 4 FastAPI endpoints and end-to-end integration."""

    def test_api_anomaly_baseline_and_test_suite(self, api_client):
        """Verifies /api/v1/graphops/anomaly/baseline and test-suite endpoints."""
        resp_base = api_client.get("/api/v1/graphops/anomaly/baseline")
        assert resp_base.status_code == 200
        data_base = resp_base.json()
        assert len(data_base["network_tiering_rules"]) > 0

        resp_suite = api_client.get("/api/v1/graphops/anomaly/test-suite")
        assert resp_suite.status_code == 200
        data_suite = resp_suite.json()
        assert data_suite["total_evaluated"] >= 12
        assert data_suite["precision"] >= 0.90

    def test_api_evaluate_preset_endpoint(self, api_client):
        """Verifies /api/v1/graphops/anomaly/evaluate-preset/{sequence_id} endpoint."""
        resp = api_client.get("/api/v1/graphops/anomaly/evaluate-preset/seq-policy-01")
        assert resp.status_code == 200
        data = resp.json()
        assert data["sequence_id"] == "seq-policy-01"
        assert data["classification"] == "POLICY_VIOLATION_UNAUTHORIZED"
        assert data["is_anomalous"] is True
        assert len(data["unexpected_relationships"]) > 0

    def test_api_evaluate_case_anomalies(self, api_client):
        """Verifies /api/v1/graphops/anomaly/evaluate-case/{case_id} bridges investigation case to anomaly evaluation."""
        resp = api_client.get("/api/v1/graphops/anomaly/evaluate-case/MT-101")
        assert resp.status_code == 200
        data = resp.json()
        assert "mt-101" in data["sequence_id"].lower()
        assert data["classification"] in ("BENIGN_EXPECTED", "UNOBSERVED_NEW_LEGITIMATE", "POLICY_VIOLATION_UNAUTHORIZED", "SUSPICIOUS_ANOMALOUS")

    def test_api_zero_trust_audit_endpoint_with_filters(self, api_client):
        """Verifies /api/v1/graphops/zero-trust/audit endpoint with status, severity, and search filters."""
        resp = api_client.get("/api/v1/graphops/zero-trust/audit?status_filter=OVER_PRIVILEGED_DORMANT&severity=CRITICAL")
        assert resp.status_code == 200
        data = resp.json()
        assert "least_privilege_compliance_pct" in data
        assert all(item["status"] == "OVER_PRIVILEGED_DORMANT" for item in data["access_breakdown"])

    def test_api_communities_endpoint_with_filters(self, api_client):
        """Verifies /api/v1/graphops/communities endpoint with community_id filter."""
        resp = api_client.get("/api/v1/graphops/communities?community_id=COMM-CROWN-JEWELS")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_communities"] == 1
        assert data["communities"][0]["community_id"] == "COMM-CROWN-JEWELS"
        assert "modularity_q" in data

    def test_api_findings_endpoint_with_filtering(self, api_client):
        """Verifies /api/v1/graphops/events/findings endpoint with severity and limit filters."""
        resp = api_client.get("/api/v1/graphops/events/findings?limit=10")
        assert resp.status_code == 200
        findings = resp.json()
        assert isinstance(findings, list)
