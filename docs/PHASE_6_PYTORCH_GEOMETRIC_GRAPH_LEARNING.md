# ThreatLens GraphOps — Phase 6: PyTorch Geometric (PyG) Graph Learning & Structural Anomaly Detection

## 1. Overview & Problem Definition

In enterprise security environments, sophisticated adversaries rarely execute isolated, high-volume anomalous actions that trigger classical perimeter alerts. Instead, modern lateral movement and privilege escalation rely on living-off-the-land techniques: individually ordinary network connections, legitimate authentication sessions, or valid credential usage that nonetheless form **structurally unusual access paths** within the enterprise knowledge graph.

### The Security Problem Addressed
Standard event-level machine learning models (such as the scikit-learn Isolation Forest implemented in Phase 5) analyze tabular, event-level attributes in isolation (e.g., bytes transferred, port number, failed logon count). However, event-level models cannot determine whether an edge:
1. Crosses architectural security tiers that are topologically separated (e.g., standard workstation connecting to an isolated payment processing server).
2. Connects entities that share zero common organizational or administrative neighbors.
3. Violates learned community clustering patterns across organizational identities.
4. Introduces a rare or topologically unexpected route toward high-value Crown Jewels.

**Phase 6 implements a genuine PyTorch Geometric (PyG) Graph Neural Network (GNN)** that learns directly from the enterprise knowledge graph topology and node properties to identify structurally anomalous relationships.

---

## 2. Model Architecture & Selection Justification

### Architecture: `StructuralGraphSageModel`
We selected a 2-layer **GraphSAGE** (`SAGEConv`) GNN encoder paired with a non-linear Multi-Layer Perceptron (MLP) link prediction decoder:

```
Enterprise Knowledge Graph
         │
         ▼
[PyG Graph Converter] ──> Node Feature Matrix X [N x 14] & Edge Index [2 x E]
                                   │
                                   ▼
                   [Layer 1: SAGEConv(14 -> 64) + LayerNorm + ReLU + Dropout]
                                   │
                                   ▼
                   [Layer 2: SAGEConv(64 -> 64) + LayerNorm + L2 Normalize]
                                   │
                                   ▼
                       Node Embeddings H [N x 64]
                                   │
                                   ▼
          Candidate Edge (u -> v): Concatenation [h_u || h_v] [128]
                                   │
                                   ▼
               [MLP Decoder: Linear(128 -> 64) -> ReLU -> Dropout -> Linear(64 -> 1)]
                                   │
                                   ▼
                       Sigmoid Link Plausibility P(u -> v) in [0.0, 1.0]
                                   │
                                   ▼
            Structural Anomaly Score S(u, v) = (1.0 - P(u -> v)) * 100.0
```

### Why GraphSAGE & Link Prediction Decoder?
- **Neighborhood Aggregation**: GraphSAGE aggregates information from local multi-hop neighborhoods, allowing nodes to incorporate both their own attributes (criticality, administrative status, entity label) and the topological roles of their neighbors.
- **Asymmetric Link Prediction**: Unlike symmetric inner-product decoders, the concatenated MLP decoder allows learning directed access semantics (e.g., User $u$ logging into Workstation $w$ has different plausibility from Workstation $w$ initiating a session into User $u$).
- **CPU Compatibility & Bounded Latency**: GraphSAGE operates with fast sparse matrix multiplication and does not require GPU extensions or CUDA acceleration, running efficiently on standard host hardware.

---

## 3. Reusable Graph-Data Conversion Layer

The conversion layer ([`backend/graphops/pyg_converter.py`](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/pyg_converter.py)) transforms the canonical ThreatLens knowledge graph into a PyTorch Geometric representation.

### Supported Node Types (9 Labels, One-Hot Encoded)
1. `USER`
2. `DEVICE`
3. `SERVER`
4. `APPLICATION`
5. `IP_ADDRESS`
6. `VULNERABILITY`
7. `CRITICAL_ASSET`
8. `SECURITY_EVENT`
9. `EMAIL_ACCOUNT`

### Total Node Feature Dimension: 14 Features
- **Features 0–8**: One-hot indicator for canonical node label.
- **Feature 9**: Asset criticality tier scalar (`LOW`=0.25, `MEDIUM`=0.50, `HIGH`=0.75, `CRITICAL`=1.0).
- **Feature 10**: Binary administrative privilege flag (`is_admin`: 1.0 or 0.0).
- **Feature 11**: Binary network isolation flag (`is_isolated`: 1.0 or 0.0).
- **Feature 12**: Normalized in-degree centrality (`in_degree / max_degree`).
- **Feature 13**: Normalized out-degree centrality (`out_degree / max_degree`).

### Total Edge Feature Dimension: 20 Features
- **Feature 0**: Edge traversal friction cost (float, default 1.0).
- **Feature 1**: Relationship confidence score (float, default 1.0).
- **Feature 2**: Epistemological evidence class scalar (`OBSERVED`=1.0, `AUTHORIZED_ACCESS`=0.8, `INFERRED`=0.5, `HYPOTHETICAL`=0.2).
- **Features 3–19**: One-hot indicator for canonical relationship type (`LOGGED_IN_TO`, `OBSERVED_CONNECTION`, `HAS_PERMISSION`, `CAN_REACH`, `USES`, `HOSTS`, etc.).

### Robustness & Bounded Ego-Networks
- **Deterministic Node Ordering**: Node canonical IDs are sorted before indexing to guarantee strictly identical tensor mappings across runs.
- **Empty & Disconnected Graphs**: Empty graphs produce zero-dimensional tensors without crashing; disconnected nodes are preserved with valid zero-degree features.
- **Bounded Ego-Network Subgraphs**: During real-time inference, the converter extracts a bounded $k$-hop ego-network around the candidate pair (`k=2`, max 200 nodes) to prevent loading unbounded enterprise graphs into memory.

---

## 4. Leakage-Aware Training & Evaluation Protocol

Data leakage is a critical vulnerability in graph link prediction. If positive candidate edges are present in the message-passing graph while predicting their existence, the model merely learns to check if an edge already exists.

### Leakage Prevention Guarantees
1. **Split Isolation**: The observed graph relationships are split into **Train (70%)**, **Validation (15%)**, and **Test (15%)**.
2. **Held-Out Edge Exclusion**:
   - During training, message passing uses **strictly `train_pos_edges`**.
   - During validation evaluation, target validation edges are **strictly excluded** from the message-passing graph.
   - During final test evaluation, test target edges are **strictly excluded** from the message-passing graph.
3. **Structured Negative Sampling**: Non-edges $(u, v)$ are sampled such that $u \neq v$ and $(u, v) \notin \mathcal{E}_{observed}$, pairing each positive edge with a plausible negative counter-example to evaluate link discernment.
4. **No Test-Set Threshold Leakage**: The decision boundary threshold is selected by optimizing the F1 score on the **validation set** alone, then evaluated on the untouched held-out test split.

---

## 5. Structural Anomaly Score Semantics & Provenance

When evaluating a candidate relationship $(u, r, v)$, the model returns a [`GraphStructureAnomalyResult`](file:///d:/Desktop/Hackathon/ThreatLens/backend/models/graphops.py):

| Field | Type | Description |
| :--- | :--- | :--- |
| `model_name` | string | `"StructuralGraphSAGE"` |
| `model_version` | string | Active model version (e.g. `"1.0.0"`) |
| `model_available` | boolean | `true` if loaded and operational; `false` on fallback |
| `prediction_type` | string | `"RELATIONSHIP_PLAUSIBILITY_ANOMALY"` |
| `is_anomaly` | boolean | `true` if `structural_anomaly_score >= threshold` |
| `structural_anomaly_score` | float | Calibrated anomaly score from `0.0` (expected) to `100.0` (anomalous) |
| `predicted_plausibility` | float | Raw GNN link probability $\in [0.0, 1.0]$ |
| `threshold` | float | Active decision boundary (e.g. `60.0` or tuned on validation) |
| `score_interpretation` | string | `EXPECTED_TOPOLOGY`, `ELEVATED_STRUCTURAL_RISK`, `UNUSUAL_ACCESS_PATH`, `COLD_START_UNOBSERVED_ENTITY`, or `MODEL_UNAVAILABLE` |
| `source_entity_id` | string | Canonical source node ID (e.g. `"device:dev-ws-101"`) |
| `target_entity_id` | string | Canonical target node ID (e.g. `"server:srv-db-01"`) |
| `relationship_type` | string | Evaluated relationship type (e.g. `"OBSERVED_CONNECTION"`) |
| `graph_snapshot_id` | string | Cryptographic provenance ID of graph snapshot |
| `supporting_context` | dict | Source/target degrees, common neighbors count, common neighbor IDs |
| `reason_codes` | list[str] | `["ZERO_COMMON_NEIGHBORS", "LOW_TOPOLOGICAL_PLAUSIBILITY", "UNUSUAL_CRITICAL_DESTINATION"]` |
| `limitations` | list[str] | Explicit caveats (e.g., structural anomaly $\neq$ confirmed attack) |
| `scored_at` | string | ISO 8601 UTC timestamp |

### Distinction from Phase 5 Event-Level Anomaly Scoring
- **Phase 5 (`SKLEARN_ISOLATION_FOREST`)**: Evaluates statistical event telemetry (bytes transferred, port frequency, failed logons). An alert indicates: *"This event transferred an unusual volume of bytes or occurred on an unusual port."*
- **Phase 6 (`PYG_GRAPH_LEARNING`)**: Evaluates knowledge graph topological affinity and neighborhood structure. An alert indicates: *"Regardless of packet size or port, this workstation has never topologically connected to this database cluster and shares zero intermediate access groups with it."*

---

## 6. Kafka Event-Streaming Pipeline Integration

In [`backend/graphops/kafka_processor.py`](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/kafka_processor.py), incoming security events are evaluated sequentially across all analytical engines:

1. **scikit-learn Isolation Forest**: Scores event telemetry attributes $\to$ emits `SKLEARN_ISOLATION_FOREST` finding if anomalous.
2. **PyG Graph-Structure Anomaly Detection**:
   - Inspects candidate source and target entities referenced by the event.
   - Evaluates relationship plausibility via `pyg_service.evaluate_relationship(src, tgt, rel_type)`.
   - If `pyg_res.is_anomaly` and `pyg_res.model_available`, emits a distinct finding:
     - `analysis_type`: `"PYG_GRAPH_LEARNING"`
     - `finding_id`: `"FIND-PYG-<HASH>"`
     - `evidence_class`: `EvidenceClass.INFERRED`
     - Retains separate attribution evidence without overwriting other findings.
3. **Deterministic Graph Analytics**: BFS blast radius, Dijkstra shortest paths, and choke-point analysis remain fully intact and independent.

---

## 7. FastAPI Service Endpoints

The API router in [`backend/api/graphops_routes.py`](file:///d:/Desktop/Hackathon/ThreatLens/backend/api/graphops_routes.py) provides three typed endpoints:

### 1. `POST /api/v1/graphops/events/pyg/evaluate`
Scores an arbitrary candidate relationship on demand.
```json
// Request
{
  "source_entity_id": "user:victim1@corporation.com",
  "target_entity_id": "server:srv-db-01",
  "relationship_type": "OBSERVED_CONNECTION"
}

// Response: HTTP 200 OK
{
  "model_name": "StructuralGraphSAGE",
  "model_version": "1.0.0",
  "model_available": true,
  "prediction_type": "RELATIONSHIP_PLAUSIBILITY_ANOMALY",
  "is_anomaly": false,
  "structural_anomaly_score": 0.0,
  "predicted_plausibility": 1.0,
  "threshold": 30.0,
  "score_interpretation": "EXPECTED_TOPOLOGY",
  "source_entity_id": "user:victim1@corporation.com",
  "target_entity_id": "server:srv-db-01",
  "relationship_type": "OBSERVED_CONNECTION",
  "graph_snapshot_id": "snap-0d117bb48c4b",
  "supporting_context": {
    "source_type": "USER",
    "target_type": "SERVER",
    "source_degree": 2,
    "target_degree": 6,
    "common_neighbors_count": 0,
    "common_neighbors": []
  },
  "reason_codes": [
    "ZERO_COMMON_NEIGHBORS",
    "CONSISTENT_WITH_COMMUNITY_STRUCTURE"
  ],
  "limitations": [
    "Structural anomaly indicates unusual graph topology, not confirmed attack.",
    "Scored on active graph snapshot without out-of-band enterprise permissions."
  ],
  "scored_at": "2026-10-23T05:35:50.983153+00:00"
}
```

### 2. `GET /api/v1/graphops/events/pyg/status`
Returns active model configuration, snapshot size, threshold, and validation metrics.
```json
// Response: HTTP 200 OK
{
  "model_loaded": true,
  "model_name": "StructuralGraphSAGE",
  "model_version": "1.0.0",
  "device": "cpu",
  "model_path": "backend/data/models/pyg_structural_gnn.pt",
  "meta_path": "backend/data/models/pyg_structural_gnn_meta.json",
  "num_nodes": 29,
  "num_edges": 13,
  "embedding_dim": 64,
  "hidden_dim": 64,
  "threshold": 30.0,
  "training_timestamp": "2026-10-23T05:33:19.504293+00:00",
  "evaluation_metrics": {
    "test_roc_auc": 1.0,
    "test_average_precision": 1.0,
    "test_f1": 0.6667,
    "test_precision": 0.5,
    "test_recall": 1.0,
    "confusion_matrix": {
      "true_negatives": 0,
      "false_positives": 3,
      "false_negatives": 0,
      "true_positives": 3
    },
    "validation_best_f1": 1.0,
    "selected_threshold": 30.0
  },
  "limitations": [
    "Evaluated on enterprise baseline graph with negative non-edge sampling.",
    "Dynamic temporal edge timestamps are aggregated into unified message-passing snapshot.",
    "Higher anomaly score indicates low structural plausibility in current topological context."
  ]
}
```

### 3. `POST /api/v1/graphops/events/pyg/train`
Admin-protected endpoint to trigger controlled GNN retraining and artifact persistence.
- Parameters: `num_epochs` (int, default 50), `learning_rate` (float, default 0.01), `random_seed` (int, default 42).
- Returns: `PyGTrainResponse` with complete split counts and held-out evaluation metrics.

---

## 8. Verification & Test Evidence

The Phase 6 test suite in [`tests/test_graphops_pyg.py`](file:///d:/Desktop/Hackathon/ThreatLens/tests/test_graphops_pyg.py) verifies all capabilities:

| Test Name | Verification Focus | Result |
| :--- | :--- | :--- |
| `test_pyg_converter_deterministic_node_mapping` | Conversion reproducibility & ID order | **PASSED** |
| `test_pyg_converter_feature_dimensions_and_bounds` | Shape contracts ($14$ node features, bounds) | **PASSED** |
| `test_pyg_converter_handles_empty_graph` | Empty graph zero-tensor handling | **PASSED** |
| `test_pyg_converter_handles_disconnected_and_unknown_entities` | Missing labels & isolated nodes | **PASSED** |
| `test_pyg_converter_bounded_subgraph_extraction` | $k$-hop ego-network relabeling & bounds | **PASSED** |
| `test_pyg_model_initialization_and_forward` | GraphSAGE convolution & MLP decoder | **PASSED** |
| `test_pyg_model_predict_plausibility_bounds` | Sigmoid output bounds in $[0.0, 1.0]$ | **PASSED** |
| `test_pyg_model_handles_isolated_zero_edge_graph` | Isolated graph message-passing | **PASSED** |
| `test_pyg_model_save_and_load_roundtrip` | Weights serialization & deserialization | **PASSED** |
| `test_leakage_prevention_held_out_edges_excluded` | **Held-out target edge exclusion from message passing** | **PASSED** |
| `test_structured_negative_sampling_avoids_existing_edges` | Negative non-edge sampling validity | **PASSED** |
| `test_pyg_service_evaluate_relationship` | Real-time candidate relationship evaluation | **PASSED** |
| `test_pyg_service_handles_cold_start_entity` | Unobserved entity safe cold-start fallback | **PASSED** |
| `test_pyg_service_fallback_when_model_missing` | Missing `.pt` artifact safe degradation | **PASSED** |
| `test_kafka_event_processor_generates_pyg_finding` | Kafka pipeline PyG finding generation | **PASSED** |
| `test_kafka_event_processor_pyg_failure_does_not_abort_processing` | Event loop fault isolation on GNN error | **PASSED** |
| `test_fastapi_pyg_evaluate_endpoint` | `POST /events/pyg/evaluate` API contract | **PASSED** |
| `test_fastapi_pyg_status_endpoint` | `GET /events/pyg/status` health contract | **PASSED** |
| `test_fastapi_pyg_train_endpoint_admin_protected` | `POST /events/pyg/train` admin protection | **PASSED** |

### Test Suite Execution Summary
- **Phase 6 Test Suite**: **19 passed / 19 passed (100%)** in 56.71s
- **Complete Project Regression Suite (Phases 1–6)**: **228 passed / 228 passed (100%)** in 106.76s
- **Zero regressions across prior phases.**
