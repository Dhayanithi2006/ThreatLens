"""
ThreatLens GraphOps - Security Event Feature Extraction Pipeline
Transforms validated security event envelopes and organizational graph context into
reproducible, type-safe numerical and categorical feature vectors for scikit-learn anomaly detection.
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timezone

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    CriticalityTier,
)
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    EventFeatureRecord,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture

logger = logging.getLogger("threatlens.graphops.feature_extractor")

# Defined feature columns for scikit-learn Pipeline
NUMERICAL_FEATURE_COLUMNS = [
    "auth_failure_count",
    "distinct_destinations",
    "distinct_servers_contacted",
    "outbound_bytes",
    "traversal_cost",
    "port",
    "historical_events_count",
    "is_new_destination",
    "asset_criticality_score",
]

CATEGORICAL_FEATURE_COLUMNS = [
    "event_type",
    "source_label",
    "target_label",
    "protocol",
]

FEATURE_SCHEMA_VERSION = "1.0.0"


class EventFeatureExtractor:
    """
    Extracts structured, standardized features from SecurityEventEnvelopes
    and enriches them with topological graph context from Neo4j / enterprise baseline.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()
        self._baseline_known_edges: Set[Tuple[str, str]] = set()
        self._entity_historical_counts: Dict[str, int] = {}
        self._entity_criticality_map: Dict[str, float] = {}
        self._initialize_baseline_cache()

    def _initialize_baseline_cache(self):
        """Pre-indexes enterprise fixture topology for fast, low-latency feature lookup."""
        try:
            fixture = load_sample_enterprise_fixture()
            entities = fixture.get("entities", {})
            relationships = fixture.get("relationships", {}).get("relationships", [])

            # Index historical edges
            for r in relationships:
                s = str(r.get("source_id", "")).lower()
                t = str(r.get("target_id", "")).lower()
                if s and t:
                    self._baseline_known_edges.add((s, t))
                    self._entity_historical_counts[s] = self._entity_historical_counts.get(s, 0) + 1
                    self._entity_historical_counts[t] = self._entity_historical_counts.get(t, 0) + 1

            # Index criticality scores
            for server in entities.get("servers", []):
                sid = f"server:{server['server_id'].lower()}"
                crit = str(server.get("criticality", "MEDIUM")).upper()
                self._entity_criticality_map[sid] = self._score_criticality(crit)

            for ca in entities.get("critical_assets", []):
                cid = f"critical:{ca['asset_id'].lower()}"
                self._entity_criticality_map[cid] = 100.0

        except Exception as e:
            logger.warning(f"Could not initialize feature extraction baseline cache: {e}")

    @staticmethod
    def _score_criticality(crit_str: str) -> float:
        """Maps criticality tiers to normalized numerical friction/impact values."""
        crit = crit_str.upper()
        if crit == "CRITICAL":
            return 100.0
        elif crit == "HIGH":
            return 70.0
        elif crit == "MEDIUM":
            return 40.0
        elif crit == "LOW":
            return 10.0
        return 0.0

    def extract_features(
        self,
        event: SecurityEventEnvelope,
        custom_graph_context: Optional[Dict[str, Any]] = None,
    ) -> EventFeatureRecord:
        """
        Converts a SecurityEventEnvelope into an EventFeatureRecord.
        Guarantees deterministic feature ordering and missingness safety.
        """
        warnings: List[str] = []
        payload = event.payload or {}
        event_type_str = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)

        # 1. Resolve Primary & Target Entities
        if not event.entity_ids:
            return EventFeatureRecord(
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                event_id=event.event_id,
                event_type=event_type_str,
                source_entity_id="UNKNOWN",
                insufficient_context=True,
                extraction_warnings=["Event entity_ids list is empty; cannot extract features."],
            )

        src_id = event.entity_ids[0].strip().lower()
        tgt_id = event.entity_ids[1].strip().lower() if len(event.entity_ids) > 1 else None

        if not tgt_id:
            tgt_id = str(payload.get("target_entity_id") or payload.get("target_resource_id") or payload.get("destination") or "").lower() or None

        # 2. Extract Event-Specific Telemetry
        auth_failures = float(payload.get("failure_count") or (1.0 if payload.get("auth_success") is False else 0.0))
        distinct_dest = float(payload.get("distinct_destinations") or payload.get("destinations_count") or (1.0 if tgt_id else 0.0))
        distinct_srv = float(payload.get("distinct_servers") or (1.0 if tgt_id and "server:" in tgt_id else 0.0))
        outbound_bytes = float(payload.get("bytes_sent") or payload.get("bytes_transferred") or payload.get("outbound_bytes") or 0.0)
        traversal_cost = float(payload.get("traversal_cost", 1.0))
        port = float(payload.get("port", 443.0))
        protocol = str(payload.get("protocol", "TCP")).upper()

        # 3. Derive Node Labels
        source_label = "USER" if src_id.startswith("user:") else ("DEVICE" if src_id.startswith("device:") else "SERVER")
        if tgt_id:
            if tgt_id.startswith("server:"):
                target_label = "SERVER"
            elif tgt_id.startswith("critical:") or "financial" in tgt_id or "crown" in tgt_id:
                target_label = "CRITICAL_ASSET"
            elif tgt_id.startswith("device:"):
                target_label = "DEVICE"
            elif tgt_id.startswith("user:"):
                target_label = "USER"
            else:
                target_label = "APPLICATION"
        else:
            target_label = "NONE"

        # 4. Topological & Contextual Enrichment from Graph
        hist_count = float(self._entity_historical_counts.get(src_id, 0))
        is_known_edge = (src_id, tgt_id) in self._baseline_known_edges if tgt_id else True
        is_new_dest = 0.0 if is_known_edge else 1.0

        asset_crit = self._entity_criticality_map.get(tgt_id, 0.0) if tgt_id else 0.0
        if asset_crit == 0.0 and event.severity:
            sev_str = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
            asset_crit = self._score_criticality(sev_str)

        # 5. Cold-Start / Insufficient History Check
        historical_available = hist_count > 0 or is_known_edge
        if not historical_available:
            warnings.append(f"Entity '{src_id}' has no historical graph activity (Cold-Start).")

        return EventFeatureRecord(
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            event_id=event.event_id,
            event_type=event_type_str,
            source_entity_id=src_id,
            target_entity_id=tgt_id,
            auth_failure_count=auth_failures,
            distinct_destinations=distinct_dest,
            distinct_servers_contacted=distinct_srv,
            outbound_bytes=outbound_bytes,
            traversal_cost=traversal_cost,
            port=port,
            historical_events_count=hist_count,
            is_new_destination=is_new_dest,
            asset_criticality_score=asset_crit,
            source_label=source_label,
            target_label=target_label,
            protocol=protocol,
            historical_context_available=historical_available,
            insufficient_context=False,
            extraction_warnings=warnings,
        )

    @classmethod
    def record_to_feature_dict(cls, record: EventFeatureRecord) -> Dict[str, Any]:
        """Flattens an EventFeatureRecord into a pure dictionary of model input features."""
        return {
            # Numerical
            "auth_failure_count": record.auth_failure_count,
            "distinct_destinations": record.distinct_destinations,
            "distinct_servers_contacted": record.distinct_servers_contacted,
            "outbound_bytes": record.outbound_bytes,
            "traversal_cost": record.traversal_cost,
            "port": record.port,
            "historical_events_count": record.historical_events_count,
            "is_new_destination": record.is_new_destination,
            "asset_criticality_score": record.asset_criticality_score,
            # Categorical
            "event_type": record.event_type,
            "source_label": record.source_label,
            "target_label": record.target_label,
            "protocol": record.protocol,
        }
