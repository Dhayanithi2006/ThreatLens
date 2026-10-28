"""
ThreatLens GraphOps - scikit-learn Event Anomaly Detection Inference Service
Loads versioned Isolation Forest pipeline artifacts, validates feature schemas,
performs real-time inference on security events, calculates normalized threat scores,
and generates explainable attribution rationales.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import pandas as pd
import joblib

from backend.core import config
from backend.models.graphops import (
    SecurityEventEnvelope,
    EventFeatureRecord,
    EventAnomalyPrediction,
    MLModelStatus,
)
from backend.graphops.feature_extractor import (
    EventFeatureExtractor,
    NUMERICAL_FEATURE_COLUMNS,
    CATEGORICAL_FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
)
from backend.graphops.client import Neo4jClient, get_graphops_client

logger = logging.getLogger("threatlens.graphops.ml_service")


class EventAnomalyMLService:
    """
    Dedicated inference service for scikit-learn event anomaly detection.
    Evaluates individual security events, handles cold-start gracefully,
    and isolates ML inference from deterministic graph algorithms.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        meta_path: Optional[str] = None,
        client: Optional[Neo4jClient] = None,
    ):
        self.model_path = model_path or config.SKLEARN_MODEL_PATH
        self.meta_path = meta_path or config.SKLEARN_META_PATH
        self.client = client or get_graphops_client()
        self.feature_extractor = EventFeatureExtractor(self.client)

        self.pipeline: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.model_loaded: bool = False
        self.threshold: float = config.SKLEARN_ANOMALY_THRESHOLD

        self._load_or_initialize_model()

    def _load_or_initialize_model(self):
        """Loads model artifact from disk; trains baseline model if missing."""
        if os.path.exists(self.model_path) and os.path.exists(self.meta_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("threshold", config.SKLEARN_ANOMALY_THRESHOLD))
                self.model_loaded = True
                logger.info(f"Loaded scikit-learn model v{self.metadata.get('model_version')} from {self.model_path}")
                return
            except Exception as e:
                logger.error(f"Failed to load existing model artifact from {self.model_path}: {e}")

        # If model does not exist, trigger controlled baseline training
        try:
            from backend.graphops.ml_training import train_event_anomaly_pipeline
            logger.info("No persisted scikit-learn model found; generating initial baseline model...")
            train_event_anomaly_pipeline(
                model_path=self.model_path,
                meta_path=self.meta_path,
                contamination=config.SKLEARN_CONTAMINATION,
                random_seed=config.SKLEARN_RANDOM_SEED,
            )
            self.pipeline = joblib.load(self.model_path)
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
            self.threshold = float(self.metadata.get("threshold", config.SKLEARN_ANOMALY_THRESHOLD))
            self.model_loaded = True
            logger.info(f"Initial model successfully trained and loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not automatically train baseline model: {e}")
            self.model_loaded = False

    def evaluate_event(
        self,
        event: SecurityEventEnvelope,
        custom_graph_context: Optional[Dict[str, Any]] = None,
    ) -> EventAnomalyPrediction:
        """
        Executes feature extraction and model inference for a single security event.
        Returns a structured EventAnomalyPrediction without throwing unhandled exceptions.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        model_version = self.metadata.get("model_version", "1.0.0")

        # 1. Feature Extraction
        try:
            record: EventFeatureRecord = self.feature_extractor.extract_features(event, custom_graph_context)
        except Exception as e:
            logger.error(f"Feature extraction failed for event {event.event_id}: {e}")
            return EventAnomalyPrediction(
                event_id=event.event_id,
                is_anomaly=False,
                anomaly_classification="EXTRACTION_ERROR",
                raw_score=0.0,
                normalized_score=0.0,
                threshold=self.threshold,
                model_version=model_version,
                insufficient_context=True,
                historical_context_status="ERROR",
                rationale=f"Feature extraction error: {str(e)}",
                feature_vector={},
                timestamp=now_iso,
            )

        feat_dict = EventFeatureExtractor.record_to_feature_dict(record)

        # 2. Insufficient Context / Missing Fields Handling
        if record.insufficient_context:
            return EventAnomalyPrediction(
                event_id=event.event_id,
                is_anomaly=False,
                anomaly_classification="INSUFFICIENT_CONTEXT",
                raw_score=0.0,
                normalized_score=0.0,
                threshold=self.threshold,
                model_version=model_version,
                insufficient_context=True,
                historical_context_status="INSUFFICIENT",
                rationale="Event lacks minimum entity identifiers or telemetry properties for ML scoring.",
                feature_vector=feat_dict,
                timestamp=now_iso,
            )

        # 3. Model Availability Verification
        if not self.model_loaded or self.pipeline is None:
            return EventAnomalyPrediction(
                event_id=event.event_id,
                is_anomaly=False,
                anomaly_classification="MODEL_UNAVAILABLE",
                raw_score=0.0,
                normalized_score=0.0,
                threshold=self.threshold,
                model_version="UNAVAILABLE",
                insufficient_context=False,
                historical_context_status="SKIPPED",
                rationale="scikit-learn anomaly detection model is not loaded; skipping ML scoring safely.",
                feature_vector=feat_dict,
                timestamp=now_iso,
            )

        # 4. Execute Inference
        all_cols = NUMERICAL_FEATURE_COLUMNS + CATEGORICAL_FEATURE_COLUMNS
        df = pd.DataFrame([feat_dict])[all_cols]

        try:
            raw_scores = self.pipeline.decision_function(df)
            raw_score = float(raw_scores[0])
        except Exception as e:
            logger.error(f"Inference execution failed on event {event.event_id}: {e}")
            return EventAnomalyPrediction(
                event_id=event.event_id,
                is_anomaly=False,
                anomaly_classification="INFERENCE_ERROR",
                raw_score=0.0,
                normalized_score=0.0,
                threshold=self.threshold,
                model_version=model_version,
                insufficient_context=False,
                historical_context_status="ERROR",
                rationale=f"Model inference failed: {str(e)}",
                feature_vector=feat_dict,
                timestamp=now_iso,
            )

        # 5. Calibrate Normalized Score (0.0 to 100.0)
        # In scikit-learn IsolationForest, lower decision_function score indicates higher anomaly.
        # raw_score >= threshold (0.0): Normal (0.0 to 49.9)
        # raw_score < threshold (0.0): Anomaly (50.0 to 100.0)
        if raw_score >= self.threshold:
            normalized_score = max(0.0, 50.0 - (raw_score * 125.0))
            is_anomaly = False
            classification = "NORMAL"
        else:
            normalized_score = min(100.0, 50.0 + (abs(raw_score) * 250.0))
            is_anomaly = True
            classification = "ANOMALY"

        # 6. Cold-Start Historical Context Assessment
        hist_status = "SUFFICIENT"
        if not record.historical_context_available:
            hist_status = "COLD_START_INSUFFICIENT"
            # Unfamiliar entities should not be automatically classified as critical attacks
            # if the only reason was missing history
            if is_anomaly and record.auth_failure_count == 0 and record.outbound_bytes < 100_000:
                is_anomaly = False
                classification = "UNOBSERVED_LEGITIMATE"
                normalized_score = min(normalized_score, 45.0)

        # 7. Generate Explainable Attribution Rationale
        rationale_parts = []
        if record.auth_failure_count > 3:
            rationale_parts.append(f"Elevated authentication failures ({int(record.auth_failure_count)} attempts)")
        if record.outbound_bytes > 500_000:
            bytes_mb = record.outbound_bytes / (1024 * 1024)
            rationale_parts.append(f"High outbound transfer volume ({bytes_mb:.1f} MB)")
        if record.is_new_destination == 1.0:
            rationale_parts.append(f"Access to previously unobserved destination '{record.target_entity_id}'")
        if record.distinct_destinations > 5:
            rationale_parts.append(f"Broad fan-out to {int(record.distinct_destinations)} distinct destinations")
        if record.asset_criticality_score >= 70.0:
            rationale_parts.append(f"Interaction with high-value Crown Jewel asset ({int(record.asset_criticality_score)} impact)")

        if not rationale_parts:
            if is_anomaly:
                rationale_parts.append("Statistical outlier across joint feature distributions")
            else:
                rationale_parts.append("Consistent with enterprise baseline operational distributions")

        rationale = "; ".join(rationale_parts) + "."

        return EventAnomalyPrediction(
            event_id=event.event_id,
            is_anomaly=is_anomaly,
            anomaly_classification=classification,
            raw_score=round(raw_score, 4),
            normalized_score=round(normalized_score, 2),
            threshold=self.threshold,
            model_name="IsolationForest",
            model_version=model_version,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            insufficient_context=False,
            historical_context_status=hist_status,
            rationale=rationale,
            feature_vector=feat_dict,
            timestamp=now_iso,
        )

    def get_status(self) -> MLModelStatus:
        """Returns diagnostic health and metadata for the scikit-learn model service."""
        return MLModelStatus(
            model_loaded=self.model_loaded,
            model_name="IsolationForest",
            model_version=self.metadata.get("model_version", "UNKNOWN"),
            feature_schema_version=self.metadata.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
            model_path=self.model_path,
            contamination=float(self.metadata.get("contamination", config.SKLEARN_CONTAMINATION)),
            threshold=self.threshold,
            training_timestamp=self.metadata.get("training_timestamp"),
            training_sample_count=self.metadata.get("training_sample_count"),
            evaluation_metrics=self.metadata.get("evaluation_metrics"),
        )


_ml_service_instance: Optional[EventAnomalyMLService] = None


def get_event_anomaly_ml_service() -> EventAnomalyMLService:
    """Singleton factory for EventAnomalyMLService."""
    global _ml_service_instance
    if _ml_service_instance is None:
        _ml_service_instance = EventAnomalyMLService()
    return _ml_service_instance
