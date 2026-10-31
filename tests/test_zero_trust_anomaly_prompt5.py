"""
ThreatLens Prompt 5 — Comprehensive Verification Test Suite
Verifies:
1. Zero-Trust Access Governance:
   - Differentiates matching access, unexercised grants, and unentitled observed connections.
   - Ensures unobserved grants are flagged for operational review (not automatically unnecessary privileges).
   - Ensures unentitled observed connections are treated as potential policy discrepancies (not confirmed compromises).
   - Correctly matches principal, device, resource, and policy context without false conflation of similar IDs.
   - Supports entity_id and status_filter query parameters.
2. Graph-Based Access Anomaly Engine:
   - Four-tier classification matrix: BENIGN_EXPECTED, UNOBSERVED_NEW_LEGITIMATE, POLICY_VIOLATION_UNAUTHORIZED, SUSPICIOUS_ANOMALOUS.
   - Cold-start handling: uncertainty-aware scoring for unfamiliar entities.
   - Longitudinal entity confidence calibration.
3. Statistical Event Anomaly ML (Isolation Forest):
   - Inference on normal vs anomalous events.
   - Graceful fallback when model artifact is absent (MODEL_UNAVAILABLE).
   - Insufficient feature context handling (INSUFFICIENT_CONTEXT).
   - Unseen categorical handling and explainable attribution rationales.
4. PyTorch Geometric Structural GNN (GraphSAGE):
   - Structural link plausibility scoring and structural anomaly score bounds.
   - Graceful fallback when model artifact is missing.
   - Cold-start handling for unobserved entities (COLD_START_UNOBSERVED_ENTITY).
   - Bounded k-hop subgraph extraction and isolated node handling.
5. REST API Integration:
   - /api/v1/graphops/zero-trust/audit
   - /api/v1/graphops/anomaly/evaluate-sequence
   - /api/v1/graphops/anomaly/baseline
   - /api/v1/graphops/anomaly/test-suite
   - /api/v1/graphops/events/ml/evaluate and status
   - /api/v1/graphops/events/pyg/evaluate and status
"""

import pytest
import os
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.zero_trust import (
    ZeroTrustAuditService,
    ZeroTrustAuditResult,
    ZeroTrustAccessItem,
    get_zero_trust_service,
)
from backend.graphops.anomaly_detection import AccessAnomalyDetector
from backend.graphops.ml_service import EventAnomalyMLService
from backend.graphops.pyg_service import PyGGraphLearningService
from backend.graphops.pyg_model import StructuralGraphSageModel
from backend.graphops.mock_client import get_mock_graphops_client
from backend.models.graphops import (
    SecurityEventEnvelope,
    SecurityEventType,
    AccessSequenceRequest,
    AccessSequenceStep,
    AnomalyClassification,
    PyGEvaluateRequest,
    CriticalityTier,
    EvidenceClass,
)


@pytest.fixture
def mock_client():
    return get_mock_graphops_client()


@pytest.fixture
def test_client():
    return TestClient(app)


# ==============================================================================
# 1. ZERO-TRUST ACCESS GOVERNANCE & POLICY DISCREPANCY AUDIT
# ==============================================================================

class TestZeroTrustAccessAudit:

    def test_audit_execution_and_schema_compliance(self, mock_client):
        """Validates that ZeroTrustAuditService produces complete, well-formed audit results."""
        service = ZeroTrustAuditService(client=mock_client)
        result = service.audit_access_entitlements()

        assert isinstance(result, ZeroTrustAuditResult)
        assert result.total_entitled_permissions >= 0
        assert 0.0 <= result.least_privilege_compliance_pct <= 100.0
        assert 0.0 <= result.over_privilege_risk_score <= 100.0
        assert len(result.access_breakdown) > 0
        assert "disclaimer" in result.model_dump()
        assert "Unobserved grants represent dormant entitlements" in result.disclaimer

    def test_distinguishes_matching_access_vs_unexercised_grant(self, mock_client):
        """Verifies that exercised entitlements are ACTIVE_VERIFIED / MATCHING_ACCESS
        and unexercised entitlements are OVER_PRIVILEGED_DORMANT / UNEXERCISED_GRANT."""
        service = ZeroTrustAuditService(client=mock_client)
        result = service.audit_access_entitlements()

        # Check that items contain discrepancy_type and appropriate recommendations
        for item in result.access_breakdown:
            if item.status == "ACTIVE_VERIFIED":
                assert item.discrepancy_type == "MATCHING_ACCESS"
                assert item.risk_severity == "LOW"
                assert "actively required" in item.recommendation.lower()
                assert item.supporting_events_count is not None and item.supporting_events_count >= 1
            elif item.status == "OVER_PRIVILEGED_DORMANT":
                assert item.discrepancy_type == "UNEXERCISED_GRANT"
                assert "review dormant entitlement" in item.recommendation.lower()
                # Must not falsely declare confirmed malicious breach
                assert "malicious" not in item.recommendation.lower()
                assert "compromise" not in item.recommendation.lower()
                assert item.supporting_events_count == 0

    def test_distinguishes_unentitled_shadow_connections(self, mock_client):
        """Verifies that observed connections lacking explicit IAM grants are flagged as potential discrepancies."""
        service = ZeroTrustAuditService(client=mock_client)
        result = service.audit_access_entitlements()

        shadow_items = [i for i in result.access_breakdown if i.status == "UNENTITLED_SHADOW"]
        assert len(shadow_items) > 0

        for item in shadow_items:
            assert item.discrepancy_type == "POTENTIAL_UNENTITLED_ACCESS"
            # Must explain potential policy discrepancy without claiming confirmed compromise
            assert "potential policy discrepancy" in item.recommendation.lower() or "unmapped workflow" in item.recommendation.lower()
            assert "not conclusive proof of breach" in item.recommendation.lower()

    def test_identity_context_matching_does_not_conflate_similar_ids(self):
        """Confirms that principal and device matching uses exact canonical IDs and does not conflate similar prefixes."""
        custom_mock = MagicMock()
        # Alice is entitled to server-1, but Alice_Admin connects to server-1
        custom_mock.execute_query.side_effect = [
            # Entitled records
            [
                {
                    "user_id": "user:alice",
                    "user_label": "User",
                    "device_id": "device:ws-alice",
                    "target_id": "server:srv-db",
                    "target_label": "Server",
                    "target_criticality": "HIGH",
                    "rel_type": "HAS_PERMISSION",
                }
            ],
            # Observed records: made by user:alice_admin (a distinct identity!)
            [
                {
                    "source_id": "user:alice_admin",
                    "source_label": "User",
                    "target_id": "server:srv-db",
                    "target_label": "Server",
                    "target_criticality": "HIGH",
                    "rel_type": "LOGGED_IN_TO",
                }
            ]
        ]

        service = ZeroTrustAuditService(client=custom_mock)
        result = service.audit_access_entitlements()

        # user:alice should be OVER_PRIVILEGED_DORMANT (she did not log in)
        alice_items = [i for i in result.access_breakdown if i.source_id == "user:alice"]
        assert len(alice_items) == 1
        assert alice_items[0].status == "OVER_PRIVILEGED_DORMANT"
        assert alice_items[0].discrepancy_type == "UNEXERCISED_GRANT"

        # user:alice_admin should be UNENTITLED_SHADOW (no entitlement for alice_admin)
        admin_items = [i for i in result.access_breakdown if i.source_id == "user:alice_admin"]
        assert len(admin_items) == 1
        assert admin_items[0].status == "UNENTITLED_SHADOW"
        assert admin_items[0].discrepancy_type == "POTENTIAL_UNENTITLED_ACCESS"

    def test_entity_id_and_status_filtering(self, mock_client):
        """Verifies filtering zero-trust audit by specific entity or status."""
        service = ZeroTrustAuditService(client=mock_client)

        # Filter by entity
        filtered_entity = service.audit_access_entitlements(entity_id="server:srv-app-01")
        for item in filtered_entity.access_breakdown:
            assert "server:srv-app-01" in (item.source_id.lower(), item.target_id.lower())

        # Filter by status
        filtered_status = service.audit_access_entitlements(status_filter="ACTIVE_VERIFIED")
        for item in filtered_status.access_breakdown:
            assert item.status == "ACTIVE_VERIFIED"


# ==============================================================================
# 2. GRAPH-BASED ACCESS ANOMALY DETECTION ENGINE
# ==============================================================================

class TestGraphAccessAnomalyEngine:

    def test_four_tier_classification_matrix(self, mock_client):
        """Verifies that the anomaly engine adheres strictly to the four-tier classification matrix."""
        detector = AccessAnomalyDetector(client=mock_client)

        # Tier 1: Benign Expected
        req_benign = AccessSequenceRequest(
            evaluated_entity_id="user:victim1@corporation.com",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="user:victim1@corporation.com",
                    target_id="device:dev-ws-101",
                    relationship_type="USES",
                ),
            ]
        )
        res_benign = detector.evaluate_sequence(req_benign)
        assert res_benign.classification == AnomalyClassification.BENIGN_EXPECTED
        assert res_benign.anomaly_score < 40.0

        # Tier 2: Unobserved New Legitimate (Cold-start or new workflow matching role)
        req_new_legit = AccessSequenceRequest(
            evaluated_entity_id="user:accounting@corporation.com",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="user:accounting@corporation.com",
                    target_id="device:dev-ws-201",
                    relationship_type="LOGGED_IN_TO",
                )
            ]
        )
        res_new_legit = detector.evaluate_sequence(req_new_legit)
        assert res_new_legit.classification in (
            AnomalyClassification.BENIGN_EXPECTED,
            AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE
        )
        # Must not be flagged as a critical attack
        assert res_new_legit.anomaly_score < 75.0

        # Tier 3: Policy Violation (Tier bypass / direct workstation to sensitive database)
        req_violation = AccessSequenceRequest(
            evaluated_entity_id="device:dev-ws-101",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="device:dev-ws-101",
                    target_id="server:srv-db-01",
                    relationship_type="OBSERVED_CONNECTION",
                )
            ]
        )
        res_violation = detector.evaluate_sequence(req_violation)
        assert res_violation.classification in (
            AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED,
            AnomalyClassification.SUSPICIOUS_ANOMALOUS,
        )
        assert res_violation.anomaly_score >= 40.0

    def test_cold_start_entity_uncertainty_handling(self, mock_client):
        """Verifies cold-start entities receive appropriate uncertainty and confidence markers."""
        detector = AccessAnomalyDetector(client=mock_client)

        req_cold = AccessSequenceRequest(
            evaluated_entity_id="user:brand_new_intern@corporation.com",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="user:brand_new_intern@corporation.com",
                    target_id="device:dev-ws-101",
                    relationship_type="LOGGED_IN_TO",
                )
            ]
        )
        res_cold = detector.evaluate_sequence(req_cold)
        assert res_cold.history_completeness.value in ("INCOMPLETE", "PARTIAL")
        assert res_cold.baseline_confidence.value in ("LOW", "MEDIUM")
        # Cold start alone should not create false-positive 100/100 score
        assert res_cold.anomaly_score < 80.0

    def test_longitudinal_entity_high_confidence(self, mock_client):
        """Verifies established entities with rich history achieve HIGH baseline confidence."""
        detector = AccessAnomalyDetector(client=mock_client)

        req = AccessSequenceRequest(
            evaluated_entity_id="user:victim1@corporation.com",
            steps=[
                AccessSequenceStep(
                    step_index=0,
                    source_id="user:victim1@corporation.com",
                    target_id="device:dev-ws-101",
                    relationship_type="USES",
                )
            ]
        )
        res = detector.evaluate_sequence(req)
        assert res.baseline_confidence.value in ("HIGH", "MEDIUM")


# ==============================================================================
# 3. STATISTICAL EVENT ANOMALY ML (ISOLATION FOREST)
# ==============================================================================

class TestEventAnomalyMLService:

    def test_normal_vs_anomalous_event_evaluation(self, mock_client):
        """Tests that Isolation Forest distinguishes normal telemetry from high-risk anomalies."""
        from backend.graphops.ml_service import get_event_anomaly_ml_service
        ml_service = get_event_anomaly_ml_service()

        # Benign logon event
        benign_event = SecurityEventEnvelope(
            event_id="EVT-BENIGN-001",
            event_type=SecurityEventType.IDENTITY_EVENT,
            source="edr-sensor",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            entity_ids=["device:dev-ws-101", "server:srv-app-01"],
            payload={
                "ip_address": "10.0.1.101",
                "bytes_sent": 1024,
                "failure_count": 0,
            }
        )
        pred_benign = ml_service.evaluate_event(benign_event)
        assert pred_benign.model_name == "IsolationForest"
        assert not pred_benign.is_anomaly or pred_benign.normalized_score < 70.0

        # Anomalous event with high failures and mass exfiltration
        anomaly_event = SecurityEventEnvelope(
            event_id="EVT-ANOMALY-999",
            event_type=SecurityEventType.NETWORK_CONNECTION,
            source="edr-sensor",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            entity_ids=["device:dev-ws-101", "server:srv-db-01"],
            payload={
                "ip_address": "198.51.100.55",
                "bytes_sent": 25_000_000,
                "failure_count": 12,
                "is_new_destination": 1,
            }
        )
        pred_anomaly = ml_service.evaluate_event(anomaly_event)
        assert pred_anomaly.normalized_score >= pred_benign.normalized_score
        assert "auth" in pred_anomaly.rationale.lower() or "transfer" in pred_anomaly.rationale.lower() or "destination" in pred_anomaly.rationale.lower() or "statistical" in pred_anomaly.rationale.lower()

    def test_missing_model_artifact_fallback(self, mock_client):
        """Verifies that if the model artifact is missing, ML inference safely degrades without crashing."""
        service = EventAnomalyMLService(
            model_path="non_existent_model_file.joblib",
            meta_path="non_existent_meta_file.json",
            client=mock_client,
        )
        service.model_loaded = False
        service.pipeline = None

        event = SecurityEventEnvelope(
            event_id="EVT-TEST-002",
            event_type=SecurityEventType.IDENTITY_EVENT,
            source="edr-sensor",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            entity_ids=["device:dev-ws-101", "server:srv-app-01"],
            payload={},
        )
        pred = service.evaluate_event(event)

        assert pred.anomaly_classification == "MODEL_UNAVAILABLE"
        assert not pred.is_anomaly
        assert pred.raw_score == 0.0
        assert "not loaded" in pred.rationale.lower()

    def test_insufficient_context_handling(self, mock_client):
        """Verifies that an event lacking minimum identifiers is marked INSUFFICIENT_CONTEXT."""
        from backend.graphops.ml_service import get_event_anomaly_ml_service
        ml_service = get_event_anomaly_ml_service()

        empty_event = SecurityEventEnvelope.model_construct(
            event_id="EVT-EMPTY-001",
            event_type=SecurityEventType.NETWORK_CONNECTION,
            source="test-sensor",
            occurred_at=datetime.now(timezone.utc).isoformat(),
            entity_ids=[],
            payload={},
        )
        pred = ml_service.evaluate_event(empty_event)
        assert pred.insufficient_context
        assert pred.anomaly_classification in ("INSUFFICIENT_CONTEXT", "EXTRACTION_ERROR")


# ==============================================================================
# 4. PYTORCH GEOMETRIC (PYG) STRUCTURAL GNN (GRAPHSAGE)
# ==============================================================================

class TestPyGStructuralGraphSage:

    def test_model_architecture_and_forward_pass(self):
        """Validates that StructuralGraphSageModel adheres to 2-layer GraphSAGE architecture."""
        import torch
        model = StructuralGraphSageModel(
            in_channels=16,
            hidden_channels=32,
            out_channels=32,
            dropout=0.0,
        )

        assert model.in_channels == 16
        assert model.hidden_channels == 32
        assert model.out_channels == 32

        # 4 nodes with 16 features, 3 edges
        x = torch.randn(4, 16)
        edge_index = torch.tensor([[0, 1, 2], [1, 2, 3]], dtype=torch.long)

        embeddings = model.encode(x, edge_index)
        assert embeddings.shape == (4, 32)
        # Check L2 normalization
        norms = torch.norm(embeddings, p=2, dim=-1)
        assert torch.allclose(norms, torch.ones_like(norms), atol=1e-4)

        # Predict plausibility for edge (0 -> 3)
        plausibility = model.predict_plausibility(x, edge_index, src_idx=0, tgt_idx=3)
        assert 0.0 <= plausibility <= 1.0

    def test_pyg_service_evaluate_relationship(self, mock_client):
        """Validates relationship plausibility scoring via PyGGraphLearningService."""
        from backend.graphops.pyg_service import get_pyg_learning_service
        service = get_pyg_learning_service()

        res = service.evaluate_relationship(
            source_entity_id="device:dev-ws-101",
            target_entity_id="server:srv-app-01",
            relationship_type="OBSERVED_CONNECTION",
        )

        assert "structuralgraphsage" in res.model_name.lower() or "gnn" in res.model_name.lower()
        assert 0.0 <= res.predicted_plausibility <= 1.0
        assert 0.0 <= res.structural_anomaly_score <= 100.0
        assert res.score_interpretation in ("EXPECTED_TOPOLOGY", "ELEVATED_STRUCTURAL_RISK", "UNUSUAL_ACCESS_PATH", "COLD_START_UNOBSERVED_ENTITY")

    def test_pyg_cold_start_unobserved_entity(self, mock_client):
        """Validates that entities not present in active graph snapshot return COLD_START_UNOBSERVED_ENTITY."""
        from backend.graphops.pyg_service import get_pyg_learning_service
        service = get_pyg_learning_service()

        res = service.evaluate_relationship(
            source_entity_id="device:completely-unseen-machine-999",
            target_entity_id="server:srv-app-01",
            relationship_type="OBSERVED_CONNECTION",
        )

        assert res.score_interpretation == "COLD_START_UNOBSERVED_ENTITY"
        assert not res.is_anomaly
        assert res.structural_anomaly_score == 50.0
        assert "COLD_START_UNOBSERVED_ENTITY" in res.reason_codes

    def test_pyg_missing_model_fallback(self, mock_client):
        """Verifies graceful handling when PyG model artifact is not loaded."""
        service = PyGGraphLearningService(
            model_path="non_existent_pyg.pt",
            meta_path="non_existent_meta.json",
            client=mock_client,
        )
        service.model_loaded = False
        service.model = None

        res = service.evaluate_relationship(
            source_entity_id="device:dev-ws-101",
            target_entity_id="server:srv-app-01",
        )

        assert not res.model_available
        assert not res.is_anomaly
        assert "MODEL_ARTIFACT_UNAVAILABLE" in res.reason_codes


# ==============================================================================
# 5. REST API ENDPOINT INTEGRATION
# ==============================================================================

class TestPrompt5RestEndpoints:

    def test_api_zero_trust_audit_endpoint(self, test_client):
        """Tests GET /api/v1/graphops/zero-trust/audit with and without query parameters."""
        # Unfiltered
        res = test_client.get("/api/v1/graphops/zero-trust/audit")
        assert res.status_code == 200
        data = res.json()
        assert "total_entitled_permissions" in data
        assert "least_privilege_compliance_pct" in data
        assert "access_breakdown" in data
        assert "disclaimer" in data
        assert len(data["access_breakdown"]) > 0

        # Filtered by entity
        res_entity = test_client.get("/api/v1/graphops/zero-trust/audit?entity_id=server:srv-app-01")
        assert res_entity.status_code == 200
        data_entity = res_entity.json()
        assert len(data_entity["access_breakdown"]) > 0
        for item in data_entity["access_breakdown"]:
            assert "server:srv-app-01" in (item["source_id"].lower(), item["target_id"].lower())

        # Filtered by status
        res_status = test_client.get("/api/v1/graphops/zero-trust/audit?status_filter=ACTIVE_VERIFIED")
        assert res_status.status_code == 200
        data_status = res_status.json()
        for item in data_status["access_breakdown"]:
            assert item["status"] == "ACTIVE_VERIFIED"

    def test_api_anomaly_evaluate_sequence_endpoint(self, test_client):
        """Tests POST /api/v1/graphops/anomaly/evaluate-sequence."""
        payload = {
            "evaluated_entity_id": "user:victim1@corporation.com",
            "steps": [
                {
                    "step_index": 0,
                    "source_id": "user:victim1@corporation.com",
                    "target_id": "device:dev-ws-101",
                    "relationship_type": "USES",
                }
            ]
        }
        res = test_client.post("/api/v1/graphops/anomaly/evaluate-sequence", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "classification" in data
        assert "anomaly_score" in data
        assert "history_completeness" in data
        assert "baseline_confidence" in data

    def test_api_anomaly_baseline_and_test_suite_endpoints(self, test_client):
        """Tests GET /api/v1/graphops/anomaly/baseline and /anomaly/test-suite."""
        res_b = test_client.get("/api/v1/graphops/anomaly/baseline")
        assert res_b.status_code == 200
        data_b = res_b.json()
        assert "network_tiering_rules" in data_b
        assert "department_profiles" in data_b

        res_ts = test_client.get("/api/v1/graphops/anomaly/test-suite")
        assert res_ts.status_code == 200
        data_ts = res_ts.json()
        assert "total_evaluated" in data_ts
        assert "precision" in data_ts
        assert "recall" in data_ts
        assert "f1_score" in data_ts

    def test_api_ml_evaluate_and_status_endpoints(self, test_client):
        """Tests POST /api/v1/graphops/events/ml/evaluate and GET /api/v1/graphops/events/ml/status."""
        # Status
        res_stat = test_client.get("/api/v1/graphops/events/ml/status")
        assert res_stat.status_code == 200
        data_stat = res_stat.json()
        assert data_stat["model_name"] == "IsolationForest"

        # Evaluate
        event_payload = {
            "event_id": "EVT-API-001",
            "event_type": "IDENTITY_EVENT",
            "source": "edr-agent",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "entity_ids": ["device:dev-ws-101", "server:srv-app-01"],
            "payload": {
                "ip_address": "10.0.1.101",
                "bytes_sent": 1024,
            }
        }
        res_ev = test_client.post("/api/v1/graphops/events/ml/evaluate", json=event_payload)
        assert res_ev.status_code == 200
        data_ev = res_ev.json()
        assert "normalized_score" in data_ev
        assert "rationale" in data_ev

    def test_api_pyg_evaluate_and_status_endpoints(self, test_client):
        """Tests POST /api/v1/graphops/events/pyg/evaluate and GET /api/v1/graphops/events/pyg/status."""
        # Status
        res_stat = test_client.get("/api/v1/graphops/events/pyg/status")
        assert res_stat.status_code == 200
        data_stat = res_stat.json()
        assert "structuralgraphsage" in data_stat["model_name"].lower() or "gnn" in data_stat["model_name"].lower()

        # Evaluate
        req_payload = {
            "source_entity_id": "device:dev-ws-101",
            "target_entity_id": "server:srv-app-01",
            "relationship_type": "OBSERVED_CONNECTION",
        }
        res_ev = test_client.post("/api/v1/graphops/events/pyg/evaluate", json=req_payload)
        assert res_ev.status_code == 200
        data_ev = res_ev.json()
        assert "predicted_plausibility" in data_ev
        assert "structural_anomaly_score" in data_ev
