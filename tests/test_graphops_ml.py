"""
ThreatLens GraphOps - scikit-learn Event Anomaly Detection Test Suite
Phase 5 Verification:
1. Feature extraction contracts, type safety, and topological enrichment.
2. Training pipeline, ColumnTransformer preprocessing, reproducibility, and held-out evaluation.
3. Model inference, calibrated scoring, decision threshold semantics, and cold-start handling.
4. Kafka consumer integration: ML finding generation, source traceability, and deduplication.
5. FastAPI ML endpoints: /events/ml/evaluate, /events/ml/status, /events/ml/train.
"""

import json
import pytest
import os
import tempfile
from typing import Dict, Any, List
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    SecurityFindingRecord,
    EventFeatureRecord,
    EventAnomalyPrediction,
    MLModelStatus,
    MLTrainResponse,
)
from backend.graphops.feature_extractor import (
    EventFeatureExtractor,
    NUMERICAL_FEATURE_COLUMNS,
    CATEGORICAL_FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
)
from backend.graphops.ml_training import (
    train_event_anomaly_pipeline,
    generate_synthetic_training_dataset,
)
from backend.graphops.ml_service import (
    EventAnomalyMLService,
    get_event_anomaly_ml_service,
)
from backend.graphops.kafka_producer import GraphOpsKafkaProducer
from backend.graphops.kafka_processor import GraphOpsEventProcessor
from backend.graphops.kafka_worker import GraphOpsKafkaWorker
from backend.graphops.kafka_simulator import (
    create_synthetic_compromise_indicator,
    create_synthetic_identity_event,
    create_synthetic_network_event,
)
from backend.api.graphops_routes import get_ml_service_dep, get_graphops_client
import sys
sys.path.insert(0, os.path.dirname(__file__))
from test_graphops_kafka import enterprise_graph_fixture, kafka_pipeline



# =====================================================================
# 1. FEATURE EXTRACTION & SCHEMA CONTRACT TESTS
# =====================================================================

def test_feature_extractor_numerical_and_categorical_columns():
    """Verifies that extracted features match documented column definitions and types."""
    extractor = EventFeatureExtractor()

    event = create_synthetic_identity_event(
        user_id="user:victim1@corporation.com",
        target_resource_id="server:srv-app-01",
    )
    record = extractor.extract_features(event)

    assert isinstance(record, EventFeatureRecord)
    assert record.feature_schema_version == "1.0.0"
    assert record.source_entity_id == "user:victim1@corporation.com"
    assert record.target_entity_id == "server:srv-app-01"
    assert record.source_label == "USER"
    assert record.target_label == "SERVER"
    assert record.insufficient_context is False

    feat_dict = EventFeatureExtractor.record_to_feature_dict(record)
    for col in NUMERICAL_FEATURE_COLUMNS:
        assert col in feat_dict, f"Missing numerical column {col}"
        assert isinstance(feat_dict[col], (int, float)), f"Column {col} is not numeric"

    for col in CATEGORICAL_FEATURE_COLUMNS:
        assert col in feat_dict, f"Missing categorical column {col}"
        assert isinstance(feat_dict[col], str), f"Column {col} is not string"


def test_feature_extractor_handles_empty_entity_ids():
    """Events without entity IDs return an explicit insufficient_context record."""
    extractor = EventFeatureExtractor()

    event = SecurityEventEnvelope.model_construct(
        event_id="EVT-TEST-EMPTY",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="test-sensor",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=[],
        payload={"bytes_sent": 1000},
    )

    record = extractor.extract_features(event)

    assert record.insufficient_context is True
    assert record.source_entity_id == "UNKNOWN"
    assert len(record.extraction_warnings) >= 1


def test_feature_extractor_network_payload_mapping():
    """Network connection telemetry correctly populates outbound bytes and port."""
    extractor = EventFeatureExtractor()

    event = SecurityEventEnvelope(
        event_id="EVT-NET-99",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="network-monitor",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["device:dev-ws-101", "server:srv-app-02"],
        payload={
            "bytes_sent": 2500000,
            "port": 8080,
            "protocol": "TCP",
            "traversal_cost": 2.0,
        },
    )
    record = extractor.extract_features(event)

    assert record.outbound_bytes == 2500000.0
    assert record.port == 8080.0
    assert record.protocol == "TCP"
    assert record.traversal_cost == 2.0


# =====================================================================
# 2. MODEL TRAINING & ARTIFACT LIFECYCLE TESTS
# =====================================================================

def test_model_training_reproducibility_and_metrics():
    """Verifies that model training generates artifact, metadata, and documented evaluation metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        model_path = os.path.join(tmpdir, "test_iso_forest.joblib")
        meta_path = os.path.join(tmpdir, "test_iso_forest_meta.json")

        resp = train_event_anomaly_pipeline(
            model_path=model_path,
            meta_path=meta_path,
            contamination=0.08,
            random_seed=42,
        )

        assert resp.status == "SUCCESS"
        assert resp.training_samples > 500
        assert resp.validation_samples > 100
        assert resp.test_samples > 100
        assert resp.threshold == 0.0

        # Verify artifacts exist on filesystem
        assert os.path.exists(model_path)
        assert os.path.exists(meta_path)

        # Verify evaluation metrics
        metrics = resp.metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "false_positive_rate" in metrics
        assert "confusion_matrix" in metrics
        assert metrics["recall"] > 0.85
        assert metrics["f1_score"] > 0.70


def test_synthetic_dataset_generation_distributions():
    """Verifies class distribution and schema consistency of the training dataset."""
    X, y = generate_synthetic_training_dataset(normal_count=100, anomaly_count=20, random_seed=42)

    assert len(X) == 120
    assert len(y) == 120
    assert (y == 0).sum() == 100
    assert (y == 1).sum() == 20

    for col in NUMERICAL_FEATURE_COLUMNS + CATEGORICAL_FEATURE_COLUMNS:
        assert col in X.columns


# =====================================================================
# 3. INFERENCE & ATTRIBUTION RATIONALE TESTS
# =====================================================================

def test_inference_scores_normal_vs_anomalous_events():
    """Normal routine events score below threshold, while extreme attacks score above threshold."""
    service = get_event_anomaly_ml_service()

    # 1. Routine Normal Event (User Logon with 0 failures, known destination)
    normal_event = create_synthetic_identity_event(
        user_id="user:victim1@corporation.com",
        target_resource_id="device:dev-ws-101",
    )
    normal_pred = service.evaluate_event(normal_event)

    assert normal_pred.is_anomaly is False
    assert normal_pred.raw_score >= normal_pred.threshold
    assert normal_pred.normalized_score < 50.0
    assert "Consistent with enterprise baseline" in normal_pred.rationale or "Normal" in normal_pred.anomaly_classification

    # 2. Deliberate Severe Anomaly (High failed logins, exfiltration volume, new destination)
    attack_event = SecurityEventEnvelope(
        event_id="EVT-ATTACK-EXFIL-01",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="edr-sensor",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["device:dev-ws-101", "critical:crit-db-financial"],
        payload={
            "failure_count": 25,
            "bytes_sent": 850_000_000,  # 850 MB exfiltration
            "port": 4444,
            "destinations_count": 12,
            "protocol": "TCP",
        },
    )
    attack_pred = service.evaluate_event(attack_event)

    assert attack_pred.is_anomaly is True
    assert attack_pred.raw_score < attack_pred.threshold
    assert attack_pred.normalized_score >= 50.0
    assert "High outbound transfer volume" in attack_pred.rationale or "Elevated authentication failures" in attack_pred.rationale


def test_inference_handles_unseen_categorical_gracefully():
    """OneHotEncoder handle_unknown='ignore' allows previously unseen categories without crashing."""
    service = get_event_anomaly_ml_service()

    event = SecurityEventEnvelope(
        event_id="EVT-UNSEEN-CAT-01",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="custom-probe",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["device:dev-ws-101", "server:srv-unknown-99"],
        payload={
            "protocol": "WEBSOCKET_CUSTOM_PROTOCOL",  # Unseen category
            "bytes_sent": 5000,
        },
    )
    pred = service.evaluate_event(event)

    assert isinstance(pred, EventAnomalyPrediction)
    assert pred.anomaly_classification in ("NORMAL", "ANOMALY")
    assert pred.insufficient_context is False


def test_cold_start_entity_not_falsely_marked_critical_attack():
    """An unfamiliar user with benign characteristics is not labeled an attack purely due to cold start."""
    service = get_event_anomaly_ml_service()

    cold_start_event = SecurityEventEnvelope(
        event_id="EVT-COLD-START-01",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="sso-gateway",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["user:newbie.intern@corporation.com", "server:srv-app-01"],
        payload={
            "auth_success": True,
            "failure_count": 0,
            "bytes_sent": 1200,
            "port": 443,
        },
    )
    pred = service.evaluate_event(cold_start_event)

    assert pred.historical_context_status == "COLD_START_INSUFFICIENT"
    assert pred.is_anomaly is False
    assert pred.normalized_score < 50.0


# =====================================================================
# 4. KAFKA PIPELINE & FINDING GENERATION TESTS
# =====================================================================

def test_kafka_event_processing_triggers_ml_finding(kafka_pipeline):
    """Processing a severe security event via Kafka worker generates an explainable ML SecurityFindingRecord."""
    producer, processor, worker, graph = kafka_pipeline

    attack_event = SecurityEventEnvelope(
        event_id="EVT-KAFKA-ML-TEST-01",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="edr-agent",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["device:dev-ws-101", "server:srv-app-01"],
        payload={
            "failure_count": 30,
            "bytes_sent": 50_000_000,
            "port": 3389,
            "protocol": "SMB",
        },
    )
    producer.publish_security_event(attack_event)
    processed_count = worker.run_once()
    assert processed_count == 1

    findings = processor.get_findings(source_event_id=attack_event.event_id)
    assert len(findings) >= 1

    ml_findings = [f for f in findings if f.analysis_type == "SKLEARN_ISOLATION_FOREST"]
    assert len(ml_findings) == 1

    ml_f = ml_findings[0]
    assert ml_f.source_event_id == attack_event.event_id
    assert ml_f.affected_entity_id == "device:dev-ws-101"
    assert "Isolation Forest flagged" in ml_f.summary
    assert "raw_score" in ml_f.details
    assert "normalized_score" in ml_f.details
    assert ml_f.details["normalized_score"] >= 50.0


def test_ml_findings_idempotency_under_duplicate_delivery(kafka_pipeline):
    """Re-delivering the exact same event does not multiply ML findings."""
    producer, processor, worker, graph = kafka_pipeline

    attack_event = SecurityEventEnvelope(
        event_id="EVT-KAFKA-ML-IDEMP-01",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="edr-agent",
        occurred_at="2026-10-22T10:00:00Z",
        entity_ids=["device:dev-ws-101", "server:srv-app-01"],
        payload={"failure_count": 40, "bytes_sent": 200_000_000},
    )

    producer.publish_security_event(attack_event)
    worker.run_once()
    first_findings = processor.get_findings(source_event_id=attack_event.event_id)

    # Re-delivery
    producer.publish_security_event(attack_event)
    worker.run_once()
    second_findings = processor.get_findings(source_event_id=attack_event.event_id)

    assert len(first_findings) == len(second_findings)


# =====================================================================
# 5. FASTAPI ML ENDPOINTS TESTS
# =====================================================================

def test_fastapi_ml_evaluate_and_status_endpoints():
    """Verifies POST /events/ml/evaluate and GET /events/ml/status."""
    client = TestClient(app)

    # 1. Check ML Status
    status_resp = client.get("/api/v1/graphops/events/ml/status")
    assert status_resp.status_code == 200, status_resp.text
    status_data = status_resp.json()
    assert status_data["model_loaded"] is True
    assert status_data["model_name"] == "IsolationForest"
    assert "evaluation_metrics" in status_data

    # 2. Evaluate Event via API
    event = create_synthetic_identity_event(
        user_id="user:victim1@corporation.com",
        target_resource_id="server:srv-app-01",
    )
    eval_resp = client.post(
        "/api/v1/graphops/events/ml/evaluate",
        json=event.model_dump(),
    )
    assert eval_resp.status_code == 200, eval_resp.text
    eval_data = eval_resp.json()
    assert eval_data["event_id"] == event.event_id
    assert "raw_score" in eval_data
    assert "normalized_score" in eval_data
    assert "rationale" in eval_data


def test_fastapi_ml_train_endpoint():
    """Tests admin-only controlled retraining endpoint POST /events/ml/train."""
    client = TestClient(app)

    resp = client.post(
        "/api/v1/graphops/events/ml/train",
        params={"contamination": 0.08, "random_seed": 42},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["status"] == "SUCCESS"
    assert data["training_samples"] > 500
    assert "metrics" in data
    assert data["metrics"]["f1_score"] > 0.70
