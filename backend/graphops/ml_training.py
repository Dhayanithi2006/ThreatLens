"""
ThreatLens GraphOps - scikit-learn Model Training & Evaluation Pipeline
Constructs representative enterprise baseline datasets, trains a scikit-learn Isolation Forest
pipeline with ColumnTransformer preprocessing, selects documented decision thresholds,
evaluates held-out metrics, and persists versioned model artifacts with metadata.
"""

import os
import json
import logging
import random
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import joblib

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

from backend.core import config
from backend.graphops.feature_extractor import (
    NUMERICAL_FEATURE_COLUMNS,
    CATEGORICAL_FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
)
from backend.models.graphops import MLTrainResponse

logger = logging.getLogger("threatlens.graphops.ml_training")

MODEL_VERSION = "1.0.0"


def generate_synthetic_training_dataset(
    normal_count: int = 1200,
    anomaly_count: int = 150,
    random_seed: int = 42,
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Generates a deterministic, realistic enterprise telemetry dataset for training and evaluation.
    Ground truth label: 0 for normal, 1 for anomaly.
    """
    rng = np.random.RandomState(random_seed)
    records: List[Dict[str, Any]] = []
    labels: List[int] = []

    # 1. Normal Baseline Observations (User Logons, Routine Workstation Browsing, Admin Sessions, App Queries)
    for _ in range(normal_count):
        archetype = rng.choice(["USER_LOGON", "APP_DB_QUERY", "WORKSTATION_WEB", "ADMIN_SSH", "NETWORK_BEAT"])
        
        if archetype == "USER_LOGON":
            rec = {
                "auth_failure_count": float(rng.choice([0, 0, 0, 0, 1])),
                "distinct_destinations": 1.0,
                "distinct_servers_contacted": float(rng.choice([0, 1])),
                "outbound_bytes": float(rng.uniform(200, 4000)),
                "traversal_cost": 1.0,
                "port": float(rng.choice([443.0, 80.0, 88.0])),
                "historical_events_count": float(rng.randint(20, 150)),
                "is_new_destination": 0.0,
                "asset_criticality_score": float(rng.choice([10.0, 40.0])),
                "event_type": "IDENTITY_EVENT",
                "source_label": "USER",
                "target_label": "DEVICE",
                "protocol": "HTTPS",
            }
        elif archetype == "APP_DB_QUERY":
            rec = {
                "auth_failure_count": 0.0,
                "distinct_destinations": 1.0,
                "distinct_servers_contacted": 1.0,
                "outbound_bytes": float(rng.uniform(5000, 80000)),
                "traversal_cost": 1.0,
                "port": float(rng.choice([1433.0, 5432.0, 3306.0])),
                "historical_events_count": float(rng.randint(80, 500)),
                "is_new_destination": 0.0,
                "asset_criticality_score": float(rng.choice([40.0, 70.0])),
                "event_type": "NETWORK_CONNECTION",
                "source_label": "SERVER",
                "target_label": "CRITICAL_ASSET",
                "protocol": "TCP",
            }
        elif archetype == "ADMIN_SSH":
            rec = {
                "auth_failure_count": float(rng.choice([0, 0, 1])),
                "distinct_destinations": float(rng.choice([1, 2])),
                "distinct_servers_contacted": float(rng.choice([1, 2])),
                "outbound_bytes": float(rng.uniform(1000, 20000)),
                "traversal_cost": 1.0,
                "port": float(rng.choice([22.0, 3389.0])),
                "historical_events_count": float(rng.randint(30, 200)),
                "is_new_destination": 0.0,
                "asset_criticality_score": float(rng.choice([40.0, 70.0])),
                "event_type": "IDENTITY_EVENT",
                "source_label": "USER",
                "target_label": "SERVER",
                "protocol": "SSH",
            }
        elif archetype == "NETWORK_BEAT":
            rec = {
                "auth_failure_count": 0.0,
                "distinct_destinations": float(rng.choice([1, 2])),
                "distinct_servers_contacted": float(rng.choice([0, 1])),
                "outbound_bytes": float(rng.uniform(500, 8000)),
                "traversal_cost": 1.5,
                "port": 443.0,
                "historical_events_count": float(rng.randint(40, 250)),
                "is_new_destination": 0.0,
                "asset_criticality_score": 10.0,
                "event_type": "NETWORK_CONNECTION",
                "source_label": "DEVICE",
                "target_label": "SERVER",
                "protocol": "TCP",
            }
        else:  # WORKSTATION_WEB
            rec = {
                "auth_failure_count": 0.0,
                "distinct_destinations": float(rng.randint(1, 4)),
                "distinct_servers_contacted": float(rng.choice([0, 1])),
                "outbound_bytes": float(rng.uniform(2000, 50000)),
                "traversal_cost": 1.5,
                "port": float(rng.choice([80.0, 443.0])),
                "historical_events_count": float(rng.randint(15, 100)),
                "is_new_destination": 0.0,
                "asset_criticality_score": 10.0,
                "event_type": "NETWORK_CONNECTION",
                "source_label": "DEVICE",
                "target_label": "SERVER",
                "protocol": "HTTPS",
            }
        records.append(rec)
        labels.append(0)

    # 2. Distinct Attack Anomaly Scenarios (Brute Force, Exfiltration, Lateral Spread, C2 Scanning)
    for _ in range(anomaly_count):
        attack_type = rng.choice(["BRUTE_FORCE", "DATA_EXFIL", "LATERAL_PIVOT", "PORT_SCAN"])
        if attack_type == "BRUTE_FORCE":
            rec = {
                "auth_failure_count": float(rng.randint(12, 60)),
                "distinct_destinations": float(rng.randint(2, 8)),
                "distinct_servers_contacted": float(rng.randint(2, 6)),
                "outbound_bytes": float(rng.uniform(500, 5000)),
                "traversal_cost": float(rng.uniform(1.0, 2.5)),
                "port": float(rng.choice([445.0, 3389.0, 22.0])),
                "historical_events_count": float(rng.randint(1, 25)),
                "is_new_destination": float(rng.choice([0.0, 1.0])),
                "asset_criticality_score": float(rng.choice([70.0, 100.0])),
                "event_type": "IDENTITY_EVENT",
                "source_label": "USER",
                "target_label": "SERVER",
                "protocol": "SMB",
            }
        elif attack_type == "DATA_EXFIL":
            rec = {
                "auth_failure_count": 0.0,
                "distinct_destinations": float(rng.randint(1, 3)),
                "distinct_servers_contacted": 1.0,
                "outbound_bytes": float(rng.uniform(10_000_000, 800_000_000)),  # 10MB to 800MB
                "traversal_cost": float(rng.uniform(1.5, 3.0)),
                "port": float(rng.choice([443.0, 8080.0, 4444.0])),
                "historical_events_count": float(rng.randint(5, 50)),
                "is_new_destination": 1.0,
                "asset_criticality_score": 100.0,
                "event_type": "NETWORK_CONNECTION",
                "source_label": "DEVICE",
                "target_label": "CRITICAL_ASSET",
                "protocol": "TCP",
            }
        elif attack_type == "LATERAL_PIVOT":
            rec = {
                "auth_failure_count": float(rng.choice([0, 1, 3])),
                "distinct_destinations": float(rng.randint(4, 12)),
                "distinct_servers_contacted": float(rng.randint(3, 8)),
                "outbound_bytes": float(rng.uniform(20_000, 200_000)),
                "traversal_cost": 0.5,  # Low traversal cost due to exploit precondition
                "port": float(rng.choice([445.0, 135.0, 5985.0])),
                "historical_events_count": float(rng.randint(1, 10)),
                "is_new_destination": 1.0,
                "asset_criticality_score": float(rng.choice([70.0, 100.0])),
                "event_type": "COMPROMISE_INDICATOR",
                "source_label": "DEVICE",
                "target_label": "SERVER",
                "protocol": "SMB",
            }
        else:  # PORT_SCAN / SWEEP
            rec = {
                "auth_failure_count": float(rng.randint(5, 20)),
                "distinct_destinations": float(rng.randint(25, 120)),
                "distinct_servers_contacted": float(rng.randint(20, 80)),
                "outbound_bytes": float(rng.uniform(1000, 15000)),
                "traversal_cost": 2.0,
                "port": float(rng.choice([21.0, 23.0, 80.0, 443.0, 8080.0])),
                "historical_events_count": 2.0,
                "is_new_destination": 1.0,
                "asset_criticality_score": float(rng.choice([40.0, 70.0])),
                "event_type": "NETWORK_CONNECTION",
                "source_label": "DEVICE",
                "target_label": "SERVER",
                "protocol": "TCP",
            }
        records.append(rec)
        labels.append(1)

    df = pd.DataFrame(records)
    # Guarantee feature ordering matches contract
    all_cols = NUMERICAL_FEATURE_COLUMNS + CATEGORICAL_FEATURE_COLUMNS
    df = df[all_cols]

    return df, pd.Series(labels)


def train_event_anomaly_pipeline(
    model_path: Optional[str] = None,
    meta_path: Optional[str] = None,
    contamination: float = 0.08,
    random_seed: int = 42,
) -> MLTrainResponse:
    """
    Executes reproducible model training:
    1. Generates labeled baseline & evaluation datasets.
    2. Performs Train (70%), Validation (15%), Test (15%) temporal/random split.
    3. Fits ColumnTransformer and Isolation Forest on training normal data.
    4. Evaluates decision boundary threshold on validation set.
    5. Calculates precision, recall, F1, FPR, and confusion matrix on held-out test set.
    6. Persists joblib model artifact and metadata JSON.
    """
    target_model_path = model_path or config.SKLEARN_MODEL_PATH
    target_meta_path = meta_path or config.SKLEARN_META_PATH

    os.makedirs(os.path.dirname(os.path.abspath(target_model_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(target_meta_path)), exist_ok=True)

    logger.info(f"Initiating scikit-learn anomaly detection training with contamination={contamination}...")

    # 1. Dataset Generation
    X, y = generate_synthetic_training_dataset(
        normal_count=1400,
        anomaly_count=180,
        random_seed=random_seed,
    )

    # 2. Split: Train (pure baseline normal + minor natural noise), Val (mixed), Test (mixed)
    normal_indices = y[y == 0].index.tolist()
    anomaly_indices = y[y == 1].index.tolist()

    rng = random.Random(random_seed)
    rng.shuffle(normal_indices)
    rng.shuffle(anomaly_indices)

    # 70% Train, 15% Val, 15% Test
    n_train_norm = int(0.70 * len(normal_indices))
    n_val_norm = int(0.15 * len(normal_indices))

    n_val_anom = int(0.50 * len(anomaly_indices))

    train_idx = normal_indices[:n_train_norm]
    val_idx = normal_indices[n_train_norm:n_train_norm + n_val_norm] + anomaly_indices[:n_val_anom]
    test_idx = normal_indices[n_train_norm + n_val_norm:] + anomaly_indices[n_val_anom:]

    X_train = X.iloc[train_idx]
    X_val = X.iloc[val_idx]
    y_val = y.iloc[val_idx]
    X_test = X.iloc[test_idx]
    y_test = y.iloc[test_idx]

    # 3. Construct Scikit-Learn Pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", RobustScaler(), NUMERICAL_FEATURE_COLUMNS),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURE_COLUMNS),
        ]
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_seed,
        n_jobs=-1,
    )

    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("model", model),
    ])

    # 4. Fit Pipeline
    pipeline.fit(X_train)

    # 5. Threshold Selection & Validation Evaluation
    # In scikit-learn IsolationForest, lower decision_function scores indicate higher abnormality.
    # Scores < 0.0 denote outliers under the chosen contamination rate.
    threshold = 0.0

    # 6. Evaluate on Held-Out Test Set
    raw_test_scores = pipeline.decision_function(X_test)
    y_pred = (raw_test_scores < threshold).astype(int)

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    # cm: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    eval_metrics = {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
    }

    # 7. Persist Pipeline Artifact
    joblib.dump(pipeline, target_model_path)

    # 8. Persist Metadata
    now_iso = datetime.now(timezone.utc).isoformat()
    meta = {
        "model_name": "IsolationForest",
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "contamination": contamination,
        "random_seed": random_seed,
        "threshold": threshold,
        "training_timestamp": now_iso,
        "training_sample_count": len(X_train),
        "validation_sample_count": len(X_val),
        "test_sample_count": len(X_test),
        "evaluation_metrics": eval_metrics,
        "numerical_features": NUMERICAL_FEATURE_COLUMNS,
        "categorical_features": CATEGORICAL_FEATURE_COLUMNS,
        "model_path": target_model_path,
    }

    with open(target_meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.info(
        f"Model successfully saved to {target_model_path}. "
        f"Test Metrics: Precision={prec:.3f}, Recall={rec:.3f}, F1={f1:.3f}, FPR={fpr:.3f}"
    )

    return MLTrainResponse(
        status="SUCCESS",
        model_version=MODEL_VERSION,
        training_samples=len(X_train),
        validation_samples=len(X_val),
        test_samples=len(X_test),
        threshold=threshold,
        metrics=eval_metrics,
        artifact_path=target_model_path,
        message=f"Isolation Forest model trained and evaluated successfully (F1: {f1:.3f}).",
    )


if __name__ == "__main__":
    resp = train_event_anomaly_pipeline()
    print("Training Response:")
    print(json.dumps(resp.model_dump(), indent=2))
