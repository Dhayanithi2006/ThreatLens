"""
ThreatLens GraphOps - Kafka Security Event Processor & Graph Analytics Orchestrator
Normalizes security events, enforces idempotent Neo4j graph updates, resolves entities,
and triggers existing deterministic GraphOps analytics (BFS, Dijkstra, Attack Paths, Choke Points).
"""

import logging
import uuid
import time
import hashlib
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
)
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    SecurityFindingRecord,
    BlastRadiusRequest,
    DijkstraShortestPathRequest,
    AttackPathRequest,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError
from backend.graphops.dijkstra import DijkstraShortestPathEngine
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.anomaly_detection import AccessAnomalyDetector
from backend.graphops.ml_service import EventAnomalyMLService, get_event_anomaly_ml_service
from backend.graphops.pyg_service import PyGGraphLearningService, get_pyg_learning_service
from backend.graphops.kafka_producer import GraphOpsKafkaProducer, get_kafka_producer

logger = logging.getLogger("threatlens.graphops.kafka_processor")


class EventProcessingError(Exception):
    """Base exception for Kafka event processing failures."""
    pass


class PermanentEventError(EventProcessingError):
    """Unrecoverable error (e.g. malformed schema, invalid entity ID) - send to DLQ."""
    pass


class TransientEventError(EventProcessingError):
    """Recoverable error (e.g. Neo4j connectivity glitch) - retry."""
    pass


class GraphOpsEventProcessor:
    """
    Core security event processor.
    Handles entity resolution, idempotent persistence, and analytics triggering.
    """

    def __init__(
        self,
        client: Optional[Neo4jClient] = None,
        producer: Optional[GraphOpsKafkaProducer] = None,
        ml_service: Optional[EventAnomalyMLService] = None,
        pyg_service: Optional[PyGGraphLearningService] = None,
    ):
        self._client = client or get_graphops_client()
        self.producer = producer or get_kafka_producer()

        self.blast_service = BlastRadiusService(self._client)
        self.dijkstra_engine = DijkstraShortestPathEngine(self._client)
        self.attack_path_service = AttackPathService(self._client)
        self.anomaly_detector = AccessAnomalyDetector()
        self.ml_service = ml_service or get_event_anomaly_ml_service()
        self.pyg_service = pyg_service or get_pyg_learning_service()

        # In-memory finding cache for fast retrieval & query endpoints
        self._processed_events: Set[str] = set()
        self._findings_store: Dict[str, SecurityFindingRecord] = {}

    @property
    def client(self) -> Neo4jClient:
        return self._client

    @client.setter
    def client(self, client: Neo4jClient):
        self._client = client
        self.blast_service = BlastRadiusService(client)
        self.dijkstra_engine = DijkstraShortestPathEngine(client)
        self.attack_path_service = AttackPathService(client)
        if hasattr(self, "ml_service") and self.ml_service:
            self.ml_service.client = client
            if hasattr(self.ml_service, "feature_extractor"):
                self.ml_service.feature_extractor.client = client
        if hasattr(self, "pyg_service") and self.pyg_service:
            self.pyg_service.client = client
            if hasattr(self.pyg_service, "converter"):
                self.pyg_service.converter.client = client


    def is_event_processed(self, event_id: str) -> bool:
        """Checks if event has already been processed to guarantee idempotency."""
        if event_id in self._processed_events:
            return True

        # Check durable Neo4j marker
        cypher = "MATCH (e:SecurityEvent {id: $event_id}) RETURN e.id AS id"
        try:
            records = self.client.execute_query(cypher, {"event_id": event_id})
            if records:
                self._processed_events.add(event_id)
                return True
        except Exception as e:
            logger.warning(f"Failed to query event marker for {event_id}: {e}")

        return False

    def process_event(self, event: SecurityEventEnvelope) -> List[SecurityFindingRecord]:
        """
        Main execution workflow for an ingested security event envelope:
        1. Validates and resolves referenced entities.
        2. Idempotently writes the SecurityEvent node and graph relationships.
        3. Invokes appropriate GraphOps analytics based on event type.
        4. Publishes and caches explainable SecurityFindingRecords.
        """
        logger.info(f"Processing {event.event_type.value} event: {event.event_id}")

        if not event.entity_ids:
            raise PermanentEventError(f"Event {event.event_id} contains no entity_ids.")

        # 1. Resolve Primary Entity
        primary_entity_id = event.entity_ids[0]
        try:
            resolved_primary = self.blast_service.resolve_start_node(primary_entity_id)
        except NodeNotFoundError:
            # If entity is an enrolled collector device, auto-provision it into Neo4j so legitimate endpoint logs are never dropped
            collector_id = (event.evidence_metadata or {}).get("collector_id")
            if collector_id and primary_entity_id.startswith("device:"):
                clean_host = primary_entity_id.split(":", 1)[1]
                src_comp = (event.evidence_metadata or {}).get("source_computer") or clean_host
                cypher_dev = """
                MERGE (d:Device {id: $id})
                ON CREATE SET
                    d.device_id = $device_id,
                    d.hostname = $hostname,
                    d.criticality = 'MEDIUM',
                    d.created_at = $timestamp
                """
                try:
                    self.client.execute_query(cypher_dev, {
                        "id": primary_entity_id,
                        "device_id": clean_host.upper(),
                        "hostname": src_comp,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    resolved_primary = self.blast_service.resolve_start_node(primary_entity_id)
                except Exception as auto_exc:
                    logger.error("Auto-provisioning failed for %s: %s", primary_entity_id, auto_exc)
                    raise PermanentEventError(f"Referenced primary entity '{primary_entity_id}' could not be resolved in the enterprise graph.")
            else:
                # If entity is completely unknown, we cannot safely analyze graph propagation
                raise PermanentEventError(
                    f"Referenced primary entity '{primary_entity_id}' could not be resolved in the enterprise graph."
                )

        # 2. Idempotent Graph Persistence & Deduplication
        already_processed = self.is_event_processed(event.event_id)
        if not already_processed:
            self._persist_event_to_graph(event, resolved_primary.id)
            self._apply_event_graph_topology(event)
            self._processed_events.add(event.event_id)
        else:
            logger.info(f"Event {event.event_id} already marked processed. Checking existing findings.")
            existing_findings = self.get_findings(source_event_id=event.event_id)
            if existing_findings:
                return existing_findings

        # 3. Trigger Analytics & Generate Findings
        findings = self._trigger_graphops_analytics(event, resolved_primary.id)

        # 4. Store and Publish Findings
        for finding in findings:
            self._findings_store[finding.finding_id] = finding
            try:
                self.producer.publish_finding(finding)
            except Exception as e:
                logger.error(f"Failed to stream finding {finding.finding_id} to Kafka: {e}")

        return findings

    def _persist_event_to_graph(self, event: SecurityEventEnvelope, resolved_id: str):
        """Creates a durable SecurityEvent node linked to the primary entity."""
        cypher = """
        MERGE (e:SecurityEvent {id: $event_id})
        ON CREATE SET
            e.event_type = $event_type,
            e.source = $source,
            e.occurred_at = $occurred_at,
            e.ingested_at = $ingested_at,
            e.correlation_id = $correlation_id,
            e.processed_at = $processed_at
        WITH e
        MATCH (target {id: $resolved_id})
        MERGE (target)-[:ASSOCIATED_WITH_CASE]->(e)
        """
        params = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "source": event.source,
            "occurred_at": event.occurred_at,
            "ingested_at": event.ingested_at,
            "correlation_id": event.correlation_id or "",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "resolved_id": resolved_id,
        }
        try:
            self.client.execute_query(cypher, params)
        except Exception as e:
            raise TransientEventError(f"Database write failure while persisting SecurityEvent: {e}")

    def _apply_event_graph_topology(self, event: SecurityEventEnvelope):
        """Updates relationships in Neo4j if event represents verified network/identity activity."""
        payload = event.payload or {}

        # 1. Identity Event -> LOGGED_IN_TO
        if event.event_type == SecurityEventType.IDENTITY_EVENT:
            user_id = payload.get("user_id") or (event.entity_ids[0] if event.entity_ids else None)
            target_res = payload.get("target_resource_id") or (event.entity_ids[1] if len(event.entity_ids) > 1 else None)
            auth_status = str(payload.get("auth_status", "SUCCESS")).upper()

            if user_id and target_res and auth_status == "SUCCESS":
                cypher = """
                MATCH (u {id: $user_id}), (t {id: $target_id})
                MERGE (u)-[r:LOGGED_IN_TO]->(t)
                ON CREATE SET r.evidence_class = 'OBSERVED', r.traversal_cost = 1.0, r.last_observed = $timestamp
                ON MATCH SET r.last_observed = $timestamp
                """
                try:
                    self.client.execute_query(cypher, {
                        "user_id": user_id,
                        "target_id": target_res,
                        "timestamp": event.occurred_at,
                    })
                except Exception as e:
                    logger.warning(f"Could not link LOGGED_IN_TO relationship: {e}")

        # 2. Network Connection -> OBSERVED_CONNECTION
        elif event.event_type == SecurityEventType.NETWORK_CONNECTION:
            src_id = payload.get("source_entity_id") or (event.entity_ids[0] if event.entity_ids else None)
            tgt_id = payload.get("target_entity_id") or (event.entity_ids[1] if len(event.entity_ids) > 1 else None)
            port = payload.get("port", 443)

            if src_id and tgt_id:
                cypher = """
                MATCH (s {id: $src_id}), (t {id: $tgt_id})
                MERGE (s)-[r:OBSERVED_CONNECTION]->(t)
                ON CREATE SET r.evidence_class = 'OBSERVED', r.port = $port, r.traversal_cost = 1.5, r.last_observed = $timestamp
                ON MATCH SET r.last_observed = $timestamp
                """
                try:
                    self.client.execute_query(cypher, {
                        "src_id": src_id,
                        "tgt_id": tgt_id,
                        "port": port,
                        "timestamp": event.occurred_at,
                    })
                except Exception as e:
                    logger.warning(f"Could not link OBSERVED_CONNECTION relationship: {e}")

    def _trigger_graphops_analytics(
        self,
        event: SecurityEventEnvelope,
        resolved_primary_id: str,
    ) -> List[SecurityFindingRecord]:
        """
        Executes deterministic graph analytics:
        - BFS 3-hop blast radius
        - Dijkstra minimum-cost path to exposed critical assets
        - Bounded alternative attack paths and choke-point ranking
        """
        findings: List[SecurityFindingRecord] = []
        now_str = datetime.now(timezone.utc).isoformat()

        # 1. Execute scikit-learn Machine-Learning Anomaly Detection across all incoming events
        try:
            ml_pred = self.ml_service.evaluate_event(event)
            if ml_pred.is_anomaly and not ml_pred.insufficient_context:
                ml_hash = hashlib.sha256(f"{event.event_id}:SKLEARN".encode("utf-8")).hexdigest()[:8].upper()
                sev = CriticalityTier.CRITICAL if ml_pred.normalized_score >= 80 else (
                    CriticalityTier.HIGH if ml_pred.normalized_score >= 60 else CriticalityTier.MEDIUM
                )
                tgt_ent = ml_pred.feature_vector.get("target_entity_id")
                ml_finding = SecurityFindingRecord(
                    finding_id=f"FIND-ML-{ml_hash}",
                    source_event_id=event.event_id,
                    analysis_type="SKLEARN_ISOLATION_FOREST",
                    affected_entity_id=resolved_primary_id,
                    critical_asset_impacted=tgt_ent if ml_pred.feature_vector.get("asset_criticality_score", 0) >= 70 else None,
                    severity=sev,
                    title=f"Statistical Event Anomaly: {event.event_type.value}",
                    summary=(
                        f"scikit-learn Isolation Forest flagged event {event.event_id} with anomaly score "
                        f"{ml_pred.normalized_score:.1f}/100 (raw decision score: {ml_pred.raw_score:.3f}, "
                        f"threshold: {ml_pred.threshold:.3f}). {ml_pred.rationale}"
                    ),
                    details={
                        "raw_score": ml_pred.raw_score,
                        "normalized_score": ml_pred.normalized_score,
                        "threshold": ml_pred.threshold,
                        "model_name": ml_pred.model_name,
                        "model_version": ml_pred.model_version,
                        "feature_schema_version": ml_pred.feature_schema_version,
                        "historical_context_status": ml_pred.historical_context_status,
                        "features": ml_pred.feature_vector,
                    },
                    evidence_class=EvidenceClass.INFERRED,
                    timestamp=now_str,
                )
                findings.append(ml_finding)
        except Exception as e:
            logger.warning(f"scikit-learn ML anomaly detection skipped for {event.event_id}: {e}")

        # 2. Execute PyTorch Geometric Graph-Structure Anomaly Detection on Candidate Relationships
        try:
            # Check if event involves a candidate relationship (source -> target)
            src_ent = resolved_primary_id
            tgt_ent = None
            if len(event.entity_ids) > 1:
                tgt_ent = event.entity_ids[1]
            elif "target_entity_id" in event.payload:
                tgt_ent = str(event.payload["target_entity_id"])
            elif "target_resource" in event.payload:
                tgt_ent = str(event.payload["target_resource"])
            elif "destination_ip" in event.payload:
                tgt_ent = f"ip:{event.payload['destination_ip']}"
            elif "server_id" in event.payload:
                tgt_ent = str(event.payload["server_id"])

            if tgt_ent:
                rel_type = "OBSERVED_CONNECTION"
                if event.event_type == SecurityEventType.IDENTITY_EVENT:
                    rel_type = "LOGGED_IN_TO"
                elif event.event_type == SecurityEventType.PROCESS_EVENT:
                    rel_type = "USES"
                elif event.event_type == SecurityEventType.NETWORK_CONNECTION:
                    rel_type = "OBSERVED_CONNECTION"

                pyg_res = self.pyg_service.evaluate_relationship(
                    source_entity_id=src_ent,
                    target_entity_id=tgt_ent,
                    relationship_type=rel_type,
                )

                if pyg_res.is_anomaly and pyg_res.model_available:
                    pyg_hash = hashlib.sha256(f"{event.event_id}:PYG:{src_ent}:{tgt_ent}".encode("utf-8")).hexdigest()[:8].upper()
                    sev = CriticalityTier.CRITICAL if pyg_res.structural_anomaly_score >= 80 else (
                        CriticalityTier.HIGH if pyg_res.structural_anomaly_score >= 60 else CriticalityTier.MEDIUM
                    )
                    pyg_finding = SecurityFindingRecord(
                        finding_id=f"FIND-PYG-{pyg_hash}",
                        source_event_id=event.event_id,
                        analysis_type="PYG_GRAPH_LEARNING",
                        affected_entity_id=src_ent,
                        critical_asset_impacted=tgt_ent if "CRITICAL" in str(tgt_ent).upper() or "SERVER" in str(tgt_ent).upper() else None,
                        severity=sev,
                        title=f"Graph Structure Anomaly: {pyg_res.score_interpretation}",
                        summary=(
                            f"PyG {pyg_res.model_name} flagged candidate relationship {src_ent} -> {tgt_ent} "
                            f"({rel_type}) with structural anomaly score {pyg_res.structural_anomaly_score:.1f}/100 "
                            f"(predicted plausibility: {pyg_res.predicted_plausibility:.3f}, threshold: {pyg_res.threshold:.1f}). "
                            f"Reasons: {', '.join(pyg_res.reason_codes)}."
                        ),
                        details={
                            "structural_anomaly_score": pyg_res.structural_anomaly_score,
                            "predicted_plausibility": pyg_res.predicted_plausibility,
                            "threshold": pyg_res.threshold,
                            "model_name": pyg_res.model_name,
                            "model_version": pyg_res.model_version,
                            "prediction_type": pyg_res.prediction_type,
                            "score_interpretation": pyg_res.score_interpretation,
                            "supporting_context": pyg_res.supporting_context,
                            "reason_codes": pyg_res.reason_codes,
                            "limitations": pyg_res.limitations,
                        },
                        evidence_class=EvidenceClass.INFERRED,
                        timestamp=now_str,
                    )
                    findings.append(pyg_finding)
        except Exception as e:
            logger.warning(f"PyG graph anomaly detection skipped for {event.event_id}: {e}")

        # 3. GraphOps Deterministic Analytics (BFS, Dijkstra, Attack Paths, Choke Points)
        if event.event_type in (
            SecurityEventType.COMPROMISE_INDICATOR,
            SecurityEventType.ENDPOINT_ALERT,
        ):
            # A. Execute BFS Blast Radius
            try:
                blast_req = BlastRadiusRequest(
                    start_node_id=resolved_primary_id,
                    max_hops=3,
                    include_hypothetical=True,
                )
                blast_res = self.blast_service.calculate_blast_radius(blast_req)

                exposed_critical_assets = [c.asset_id for c in blast_res.critical_assets_at_risk]
                blast_hash = hashlib.sha256(event.event_id.encode("utf-8")).hexdigest()[:8].upper()
                blast_finding = SecurityFindingRecord(
                    finding_id=f"FIND-BLAST-{blast_hash}",
                    source_event_id=event.event_id,
                    analysis_type="BFS_BLAST_RADIUS",
                    affected_entity_id=resolved_primary_id,
                    critical_asset_impacted=exposed_critical_assets[0] if exposed_critical_assets else None,
                    severity=CriticalityTier.HIGH if exposed_critical_assets else CriticalityTier.MEDIUM,
                    title=f"3-Hop Blast Radius: {blast_res.total_reachable_nodes} Entities Exposed",
                    summary=(
                        f"Potentially compromised node {resolved_primary_id} can reach "
                        f"{blast_res.total_reachable_nodes} entities within 3 hops, "
                        f"including {len(exposed_critical_assets)} Crown Jewels: {exposed_critical_assets}."
                    ),
                    details={
                        "hop_1_count": blast_res.hop_1.node_count,
                        "hop_2_count": blast_res.hop_2.node_count,
                        "hop_3_count": blast_res.hop_3.node_count,
                        "reachable_critical_assets": exposed_critical_assets,
                        "calculation_time_ms": blast_res.calculation_time_ms,
                    },
                    evidence_class=EvidenceClass.OBSERVED,
                    timestamp=now_str,
                )
                findings.append(blast_finding)

                # B. Execute Dijkstra Minimum-Cost Route if Crown Jewels are reachable
                if exposed_critical_assets:
                    dijkstra_req = DijkstraShortestPathRequest(
                        entry_node_id=resolved_primary_id,
                        target_node_ids=exposed_critical_assets,
                        include_hypothetical=True,
                    )
                    dijkstra_res = self.dijkstra_engine.find_shortest_path(dijkstra_req)

                    if dijkstra_res.path_found and dijkstra_res.target_node:
                        dijkstra_hash = hashlib.sha256(f"{event.event_id}:{dijkstra_res.target_node.id}".encode("utf-8")).hexdigest()[:8].upper()
                        dijkstra_finding = SecurityFindingRecord(
                            finding_id=f"FIND-DIJKSTRA-{dijkstra_hash}",
                            source_event_id=event.event_id,
                            analysis_type="DIJKSTRA_SHORTEST_PATH",
                            affected_entity_id=resolved_primary_id,
                            critical_asset_impacted=dijkstra_res.target_node.id,
                            severity=CriticalityTier.CRITICAL,
                            title=f"Minimum-Cost Attack Route to Crown Jewel ({dijkstra_res.target_node.id})",
                            summary=(
                                f"Minimum accumulated traversal friction is {dijkstra_res.total_cost} "
                                f"across {dijkstra_res.hop_count} hops to {dijkstra_res.target_node.id}. "
                                f"Route: {' -> '.join(n.id for n in dijkstra_res.nodes)}."
                            ),
                            details={
                                "total_cost": dijkstra_res.total_cost,
                                "hop_count": dijkstra_res.hop_count,
                                "path_node_ids": [n.id for n in dijkstra_res.nodes],
                                "steps": [s.model_dump() for s in dijkstra_res.steps],
                                "calculation_time_ms": dijkstra_res.calculation_time_ms,
                            },
                            evidence_class=EvidenceClass.OBSERVED,
                            timestamp=now_str,
                        )
                        findings.append(dijkstra_finding)

                        # C. Execute Bounded Alternative Attack Paths & Choke Points
                        try:
                            path_req = AttackPathRequest(
                                entry_node_id=resolved_primary_id,
                                target_node_id=dijkstra_res.target_node.id,
                                max_depth=5,
                                include_hypothetical=True,
                            )
                            path_res = self.attack_path_service.find_attack_paths(path_req)
                            if path_res.paths:
                                choke_res = self.attack_path_service.analyze_choke_points(
                                    paths=path_res.paths,
                                    top_n=3,
                                )
                                if choke_res.choke_points:
                                    top_choke = choke_res.top_recommendation or choke_res.choke_points[0]
                                    choke_hash = hashlib.sha256(f"{event.event_id}:{top_choke.entity_id}".encode("utf-8")).hexdigest()[:8].upper()
                                    choke_finding = SecurityFindingRecord(
                                        finding_id=f"FIND-CHOKE-{choke_hash}",
                                        source_event_id=event.event_id,
                                        analysis_type="CHOKE_POINT",
                                        affected_entity_id=top_choke.entity_id,
                                        critical_asset_impacted=dijkstra_res.target_node.id,
                                        severity=CriticalityTier.HIGH,
                                        title=f"Intervention Choke Point: {top_choke.entity_label} ({top_choke.traversal_percentage}% Impact)",
                                        summary=(
                                            f"Severing choke point {top_choke.entity_label} ({top_choke.entity_id}) "
                                            f"eliminates {top_choke.traversal_percentage}% of candidate attack paths to "
                                            f"{dijkstra_res.target_node.id}."
                                        ),
                                        details={
                                            "choke_entity_id": top_choke.entity_id,
                                            "traversal_percentage": top_choke.traversal_percentage,
                                            "paths_eliminated": top_choke.paths_traversed_count,
                                            "recommended_action": top_choke.recommended_action.value,
                                            "intervention_details": top_choke.intervention_details,
                                        },
                                        evidence_class=EvidenceClass.INFERRED,
                                        timestamp=now_str,
                                    )
                                    findings.append(choke_finding)
                        except Exception as e:
                            logger.warning(f"Alternative paths/choke points analysis skipped: {e}")

            except Exception as e:
                logger.error(f"Error during graph analytics execution for {resolved_primary_id}: {e}")
                raise TransientEventError(f"Analytics execution failed: {e}")

        return findings

    def get_findings(
        self,
        source_event_id: Optional[str] = None,
        entity_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[SecurityFindingRecord]:
        """Retrieves cached findings, optionally filtered by event or entity."""
        results = list(self._findings_store.values())
        if source_event_id:
            results = [f for f in results if f.source_event_id == source_event_id]
        if entity_id:
            results = [f for f in results if f.affected_entity_id.lower() == entity_id.lower()]
        return results[:limit]

    def get_finding_by_id(self, finding_id: str) -> Optional[SecurityFindingRecord]:
        """Retrieves a single finding record by its unique ID."""
        return self._findings_store.get(finding_id)
