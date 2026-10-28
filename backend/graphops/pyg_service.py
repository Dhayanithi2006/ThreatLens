"""
ThreatLens GraphOps - PyTorch Geometric (PyG) Inference Service
Provides real-time structural anomaly scoring for candidate relationships and graph mutations.
Computes link plausibility using GraphSAGE node embeddings, checks topological context,
calculates calibrated anomaly scores, and generates explainable security rationales.
"""

from ast import Set
import os
import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import torch

from backend.core import config
from backend.models.graphops import (
    GraphStructureAnomalyResult,
    PyGModelStatus,
    PyGEvaluateRequest,
)
from backend.graphops.pyg_converter import PyGGraphConverter, PyGGraphSnapshot, NODE_FEATURE_DIM
from backend.graphops.pyg_model import StructuralGraphSageModel
from backend.graphops.client import Neo4jClient, get_graphops_client

logger = logging.getLogger("threatlens.graphops.pyg_service")


class PyGGraphLearningService:
    """
    Dedicated inference service for PyTorch Geometric graph learning.
    Scores relationship plausibility, detects structurally unusual access paths,
    and isolates GNN execution from deterministic graph algorithms and event loops.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        meta_path: Optional[str] = None,
        client: Optional[Neo4jClient] = None,
    ):
        self.model_path = model_path or config.PYG_MODEL_PATH
        self.meta_path = meta_path or config.PYG_META_PATH
        self.client = client or get_graphops_client()
        self.converter = PyGGraphConverter(self.client)

        self.model: Optional[StructuralGraphSageModel] = None
        self.metadata: Dict[str, Any] = {}
        self.model_loaded: bool = False
        self.threshold: float = config.PYG_ANOMALY_THRESHOLD
        self.device = config.PYG_DEVICE

        # Cached active graph snapshot for real-time inference
        self._active_snapshot: Optional[PyGGraphSnapshot] = None

        self._load_or_initialize_model()

    def _load_or_initialize_model(self):
        """Loads model weights from disk or triggers baseline training if missing."""
        if os.path.exists(self.model_path) and os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

                in_channels = NODE_FEATURE_DIM
                hidden_channels = int(self.metadata.get("hidden_dim", config.PYG_HIDDEN_DIM))
                out_channels = int(self.metadata.get("embedding_dim", config.PYG_EMBEDDING_DIM))

                self.model = StructuralGraphSageModel(
                    in_channels=in_channels,
                    hidden_channels=hidden_channels,
                    out_channels=out_channels,
                )
                self.model.load_weights(self.model_path, device=self.device)
                self.threshold = float(self.metadata.get("threshold", config.PYG_ANOMALY_THRESHOLD))
                self.model_loaded = True
                logger.info(f"Loaded PyG StructuralGraphSageModel v{self.metadata.get('model_version')} from {self.model_path}")
                return
            except Exception as e:
                logger.error(f"Failed to load PyG model artifact from {self.model_path}: {e}")

        # If model does not exist or failed to load, train baseline model
        try:
            from backend.graphops.pyg_training import train_pyg_structural_gnn
            logger.info("No persisted PyG model artifact found; training initial baseline model...")
            train_pyg_structural_gnn(
                model_path=self.model_path,
                meta_path=self.meta_path,
                embedding_dim=config.PYG_EMBEDDING_DIM,
                hidden_dim=config.PYG_HIDDEN_DIM,
                num_epochs=config.PYG_NUM_EPOCHS,
                learning_rate=config.PYG_LEARNING_RATE,
                device=self.device,
            )
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

            self.model = StructuralGraphSageModel(
                in_channels=NODE_FEATURE_DIM,
                hidden_channels=config.PYG_HIDDEN_DIM,
                out_channels=config.PYG_EMBEDDING_DIM,
            )
            self.model.load_weights(self.model_path, device=self.device)
            self.threshold = float(self.metadata.get("threshold", config.PYG_ANOMALY_THRESHOLD))
            self.model_loaded = True
            logger.info(f"Initial PyG model trained and loaded from {self.model_path}")
        except Exception as e:
            logger.warning(f"Could not automatically train baseline PyG model: {e}")
            self.model_loaded = False

    def get_snapshot(self, refresh: bool = False) -> PyGGraphSnapshot:
        """Retrieves or refreshes the active graph snapshot."""
        if self._active_snapshot is None or refresh:
            self._active_snapshot = self.converter.extract_and_convert()
        return self._active_snapshot

    def set_snapshot(self, snapshot: PyGGraphSnapshot):
        """Allows injecting a custom graph snapshot (useful for testing and simulation)."""
        self._active_snapshot = snapshot

    def evaluate_relationship(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str = "OBSERVED_CONNECTION",
        traversal_cost: float = 1.0,
        evidence_class: str = "OBSERVED",
        custom_snapshot: Optional[PyGGraphSnapshot] = None,
    ) -> GraphStructureAnomalyResult:
        """
        Evaluates the structural plausibility of a candidate relationship (source -> target).
        Returns a structured GraphStructureAnomalyResult.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        snapshot = custom_snapshot or self.get_snapshot()
        model_version = self.metadata.get("model_version", "1.0.0")

        # 1. Model Availability Guard
        if not self.model_loaded or self.model is None:
            return GraphStructureAnomalyResult(
                model_name="StructuralGraphSAGE",
                model_version=model_version,
                model_available=False,
                prediction_type="RELATIONSHIP_PLAUSIBILITY_ANOMALY",
                is_anomaly=False,
                structural_anomaly_score=0.0,
                predicted_plausibility=0.5,
                threshold=self.threshold,
                score_interpretation="MODEL_UNAVAILABLE",
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                relationship_type=relationship_type,
                graph_snapshot_id=snapshot.snapshot_id,
                supporting_context={"error": "PyG model weights not loaded or unavailable on host"},
                reason_codes=["MODEL_ARTIFACT_UNAVAILABLE"],
                limitations=["Inference disabled due to missing model artifact."],
                scored_at=now_iso,
            )

        # 2. Entity Resolution in Active Graph Snapshot
        node_to_idx = snapshot.node_to_idx
        src_norm = source_entity_id.strip()
        tgt_norm = target_entity_id.strip()

        # Check if source or target exists in the graph snapshot
        src_exists = src_norm in node_to_idx
        tgt_exists = tgt_norm in node_to_idx

        # If either entity is completely unobserved in the snapshot (Cold Start)
        if not src_exists or not tgt_exists:
            missing_entities = []
            if not src_exists:
                missing_entities.append(f"source:{src_norm}")
            if not tgt_exists:
                missing_entities.append(f"target:{tgt_norm}")

            # Cold start: moderate uncertainty score, not an automatic alert
            return GraphStructureAnomalyResult(
                model_name="StructuralGraphSAGE",
                model_version=model_version,
                model_available=True,
                prediction_type="RELATIONSHIP_PLAUSIBILITY_ANOMALY",
                is_anomaly=False,
                structural_anomaly_score=50.0,
                predicted_plausibility=0.50,
                threshold=self.threshold,
                score_interpretation="COLD_START_UNOBSERVED_ENTITY",
                source_entity_id=src_norm,
                target_entity_id=tgt_norm,
                relationship_type=relationship_type,
                graph_snapshot_id=snapshot.snapshot_id,
                supporting_context={
                    "missing_entities": missing_entities,
                    "active_graph_nodes": snapshot.num_nodes,
                },
                reason_codes=["COLD_START_UNOBSERVED_ENTITY", "INSUFFICIENT_HISTORICAL_TOPOLOGY"],
                limitations=["Entity has not yet been observed in enterprise baseline graph."],
                scored_at=now_iso,
            )

        src_idx = node_to_idx[src_norm]
        tgt_idx = node_to_idx[tgt_norm]

        # 3. Extract Local k-Hop Subgraph for Bounded Computation
        sub_snapshot = self.converter.extract_subgraph_around_nodes(
            target_node_ids=[src_norm, tgt_norm],
            full_snapshot=snapshot,
            num_hops=config.PYG_MAX_SUBGRAPH_HOPS,
            max_subgraph_nodes=config.PYG_MAX_SUBGRAPH_NODES,
        )

        sub_src_idx = sub_snapshot.node_to_idx.get(src_norm, 0)
        sub_tgt_idx = sub_snapshot.node_to_idx.get(tgt_norm, 0)

        # 4. GNN Inference (predict link plausibility)
        try:
            plausibility = self.model.predict_plausibility(
                x=sub_snapshot.data.x,
                edge_index=sub_snapshot.data.edge_index,
                src_idx=sub_src_idx,
                tgt_idx=sub_tgt_idx,
            )
        except Exception as e:
            logger.error(f"GNN forward pass error for {src_norm} -> {tgt_norm}: {e}")
            plausibility = 0.50

        # Structural Anomaly Score: 0.0 to 100.0 (lower plausibility => higher anomaly score)
        anomaly_score = round(float(max(0.0, min(100.0, (1.0 - plausibility) * 100.0))), 2)
        is_anomaly = anomaly_score >= self.threshold

        # 5. Compute Topological Supporting Context & Reason Codes
        supporting_context, reason_codes = self._build_supporting_context(
            snapshot=snapshot,
            src_norm=src_norm,
            tgt_norm=tgt_norm,
            plausibility=plausibility,
            anomaly_score=anomaly_score,
            relationship_type=relationship_type,
        )

        # Determine Interpretation Category
        if anomaly_score >= 75.0:
            interpretation = "UNUSUAL_ACCESS_PATH"
        elif anomaly_score >= self.threshold:
            interpretation = "ELEVATED_STRUCTURAL_RISK"
        else:
            interpretation = "EXPECTED_TOPOLOGY"

        return GraphStructureAnomalyResult(
            model_name="StructuralGraphSAGE",
            model_version=model_version,
            model_available=True,
            prediction_type="RELATIONSHIP_PLAUSIBILITY_ANOMALY",
            is_anomaly=is_anomaly,
            structural_anomaly_score=anomaly_score,
            predicted_plausibility=round(plausibility, 4),
            threshold=self.threshold,
            score_interpretation=interpretation,
            source_entity_id=src_norm,
            target_entity_id=tgt_norm,
            relationship_type=relationship_type,
            graph_snapshot_id=snapshot.snapshot_id,
            supporting_context=supporting_context,
            reason_codes=reason_codes,
            limitations=[
                "Structural anomaly indicates unusual graph topology, not confirmed attack.",
                "Scored on active graph snapshot without out-of-band enterprise permissions.",
            ],
            scored_at=now_iso,
        )

    def _build_supporting_context(
        self,
        snapshot: PyGGraphSnapshot,
        src_norm: str,
        tgt_norm: str,
        plausibility: float,
        anomaly_score: float,
        relationship_type: str,
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Analyzes graph topology around source and target to generate interpretable evidence."""
        edge_index = snapshot.data.edge_index
        src_idx = snapshot.node_to_idx.get(src_norm)
        tgt_idx = snapshot.node_to_idx.get(tgt_norm)

        src_neighbors: Set[int] = set()
        tgt_neighbors: Set[int] = set()

        if edge_index.size(1) > 0 and src_idx is not None and tgt_idx is not None:
            # Find neighbors of source
            src_mask = (edge_index[0] == src_idx) | (edge_index[1] == src_idx)
            for i in range(edge_index.size(1)):
                if src_mask[i]:
                    n = edge_index[1, i].item() if edge_index[0, i].item() == src_idx else edge_index[0, i].item()
                    src_neighbors.add(n)

            # Find neighbors of target
            tgt_mask = (edge_index[0] == tgt_idx) | (edge_index[1] == tgt_idx)
            for i in range(edge_index.size(1)):
                if tgt_mask[i]:
                    n = edge_index[1, i].item() if edge_index[0, i].item() == tgt_idx else edge_index[0, i].item()
                    tgt_neighbors.add(n)

        common_neighbor_indices = src_neighbors.intersection(tgt_neighbors)
        common_neighbors = [snapshot.idx_to_node.get(i, f"node:{i}") for i in common_neighbor_indices]

        # Extract node label types
        src_prefix = src_norm.split(":")[0].upper() if ":" in src_norm else "ENTITY"
        tgt_prefix = tgt_norm.split(":")[0].upper() if ":" in tgt_norm else "ENTITY"

        context = {
            "source_type": src_prefix,
            "target_type": tgt_prefix,
            "source_degree": len(src_neighbors),
            "target_degree": len(tgt_neighbors),
            "common_neighbors_count": len(common_neighbors),
            "common_neighbors": common_neighbors[:5],
            "relationship_type": relationship_type,
            "predicted_plausibility": round(plausibility, 4),
            "anomaly_score": anomaly_score,
        }

        reasons: List[str] = []
        if len(common_neighbors) == 0:
            reasons.append("ZERO_COMMON_NEIGHBORS")
        else:
            reasons.append(f"SHARED_NEIGHBORHOOD_DEGREE_{len(common_neighbors)}")

        if anomaly_score >= self.threshold:
            reasons.append("LOW_TOPOLOGICAL_PLAUSIBILITY")
            if tgt_prefix in ("CRITICAL", "SERVER"):
                reasons.append("UNUSUAL_CRITICAL_DESTINATION")
        else:
            reasons.append("CONSISTENT_WITH_COMMUNITY_STRUCTURE")

        return context, reasons

    def get_status(self) -> PyGModelStatus:
        """Returns health, configuration, and evaluation metadata for the PyG model."""
        snapshot = self.get_snapshot()
        metrics = self.metadata.get("metrics", {})
        return PyGModelStatus(
            model_loaded=self.model_loaded,
            model_name=self.metadata.get("model_name", "StructuralGraphSAGE"),
            model_version=self.metadata.get("model_version", "1.0.0"),
            device=self.device,
            model_path=self.model_path,
            meta_path=self.meta_path,
            num_nodes=snapshot.num_nodes,
            num_edges=snapshot.num_edges,
            embedding_dim=int(self.metadata.get("embedding_dim", config.PYG_EMBEDDING_DIM)),
            hidden_dim=int(self.metadata.get("hidden_dim", config.PYG_HIDDEN_DIM)),
            threshold=self.threshold,
            training_timestamp=self.metadata.get("training_timestamp"),
            evaluation_metrics=metrics,
            limitations=self.metadata.get("limitations", []),
        )


# Singleton instance
_GLOBAL_PYG_SERVICE: Optional[PyGGraphLearningService] = None


def get_pyg_learning_service() -> PyGGraphLearningService:
    """Returns the singleton instance of the PyG Graph Learning Service."""
    global _GLOBAL_PYG_SERVICE
    if _GLOBAL_PYG_SERVICE is None:
        _GLOBAL_PYG_SERVICE = PyGGraphLearningService()
    return _GLOBAL_PYG_SERVICE
