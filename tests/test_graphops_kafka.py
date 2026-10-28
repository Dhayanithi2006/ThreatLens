"""
ThreatLens GraphOps - Apache Kafka Event Streaming & Analytics Integration Test Suite
Phase 4 Verification:
1. Canonical security-event envelope validation (Pydantic models, schema versions, timestamps).
2. Kafka producer topic routing, partitioning key assignment, and delivery confirmation.
3. Dedicated consumer worker lifecycle, polling, retry with backoff, and dead-letter queue (DLQ) routing.
4. Idempotent Neo4j event persistence (re-delivery does not duplicate relationships).
5. Event-triggered deterministic GraphOps analytics:
   - BFS 3-hop blast radius
   - Dijkstra minimum-cost path discovery
   - Bounded attack-path discovery & choke-point ranking
6. Generation and publication of explainable SecurityFindingRecords.
7. FastAPI streaming endpoints: /events/publish, /events/simulate, /events/findings, /events/status, /events/dlq.
"""

import json
import pytest
from typing import Dict, List, Any, Optional, Set
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
)
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    DeadLetterEventEnvelope,
    SecurityFindingRecord,
    EventPublishResponse,
    KafkaServiceStatus,
)
from backend.graphops.kafka_producer import GraphOpsKafkaProducer
from backend.graphops.kafka_processor import (
    GraphOpsEventProcessor,
    PermanentEventError,
    TransientEventError,
)
from backend.graphops.kafka_worker import GraphOpsKafkaWorker
from backend.graphops.kafka_simulator import (
    create_synthetic_compromise_indicator,
    create_synthetic_identity_event,
    create_synthetic_network_event,
)
from backend.graphops.client import get_graphops_client
from backend.api.graphops_routes import get_kafka_producer_dep, get_kafka_worker_dep


# =====================================================================
# IN-MEMORY GRAPH MOCK FOR KAFKA INTEGRATION
# =====================================================================

class MockNeo4jClientForKafka:
    """Mock Neo4j client supporting node resolution, SecurityEvent persistence, and path queries."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.edges = edges
        self.security_events: Dict[str, Dict[str, Any]] = {}
        self.executed_queries: List[str] = []
        self.aliases: Dict[str, str] = {}

        for n in nodes:
            nid = n["id"].lower()
            props = n.get("properties", {})
            for key in ["email", "hostname", "user_id", "device_id", "server_id", "asset_id"]:
                val = props.get(key)
                if val:
                    self.aliases[str(val).lower()] = nid
                    if ":" in str(val):
                        self.aliases[str(val).split(":", 1)[1].lower()] = nid
            if ":" in nid:
                self.aliases[nid.split(":", 1)[1].lower()] = nid

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.executed_queries.append(query)
        params = params or {}
        q = query.strip()

        # 1. SecurityEvent Marker Query (Deduplication Check)
        if "MATCH (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid and eid in self.security_events:
                return [{"id": eid}]
            return []

        # 2. SecurityEvent Persist / Merge Query
        if "MERGE (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid:
                self.security_events[eid] = params
            return []

        # 3. Dynamic Relationship Merges (LOGGED_IN_TO, OBSERVED_CONNECTION)
        if "MERGE (u)-[r:LOGGED_IN_TO]->(t)" in q:
            uid = str(params.get("user_id", "")).lower()
            tid = str(params.get("target_id", "")).lower()
            self.edges.append({
                "source": uid,
                "target": tid,
                "type": "LOGGED_IN_TO",
                "evidence_class": "OBSERVED",
                "properties": {"traversal_cost": 1.0, "last_observed": params.get("timestamp")},
            })
            return []

        if "MERGE (s)-[r:OBSERVED_CONNECTION]->(t)" in q:
            sid = str(params.get("src_id", "")).lower()
            tid = str(params.get("tgt_id", "")).lower()
            self.edges.append({
                "source": sid,
                "target": tid,
                "type": "OBSERVED_CONNECTION",
                "evidence_class": "OBSERVED",
                "properties": {"port": params.get("port", 445), "traversal_cost": 1.5},
            })
            return []

        # 4. Node resolution query
        if "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q:
            target_id = str(params.get("id", "")).lower()
            id_without_prefix = str(params.get("id_without_prefix", "")).lower()
            resolved = (
                self.nodes.get(target_id)
                or self.nodes.get(id_without_prefix)
                or self.aliases.get(target_id)
                or self.aliases.get(id_without_prefix)
            )
            if resolved:
                node = resolved if isinstance(resolved, dict) else self.nodes[resolved]
                return [{
                    "id": node["id"],
                    "labels": node.get("labels", []),
                    "properties": node.get("properties", {}),
                }]
            return []

        # 5. Crown Jewels query
        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # 5b. BFS Frontier Edges Query
        if "frontier_ids" in params:
            frontier = [fid.lower() for fid in params.get("frontier_ids", [])]
            allowed_types = params.get("allowed_types", [])
            include_hypothetical = params.get("include_hypothetical", False)

            if "(s)<-[r]-(t)" in q:
                direction = "INCOMING"
            elif "(s)-[r]-(t)" in q:
                direction = "BOTH"
            else:
                direction = "OUTGOING"

            results = []
            for e in self.edges:
                src = (e.get("source_id") or e.get("source", "")).lower()
                tgt = (e.get("target_id") or e.get("target", "")).lower()
                rel_type = e.get("relationship_type") or e.get("type", "")
                ev_class = e.get("evidence_class", "OBSERVED")

                if allowed_types and rel_type not in allowed_types:
                    continue

                if not include_hypothetical:
                    if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                        continue

                matches = []
                if direction == "OUTGOING" and src in frontier:
                    matches.append((src, tgt))
                elif direction == "INCOMING" and tgt in frontier:
                    matches.append((tgt, src))
                elif direction == "BOTH":
                    if src in frontier:
                        matches.append((src, tgt))
                    if tgt in frontier and tgt != src:
                        matches.append((tgt, src))

                for f_id, n_id in matches:
                    neighbor_node = self.nodes.get(n_id)
                    if neighbor_node:
                        results.append({
                            "frontier_id": f_id,
                            "neighbor_id": n_id,
                            "neighbor_labels": neighbor_node.get("labels", []),
                            "neighbor_props": neighbor_node.get("properties", {}),
                            "rel_type": rel_type,
                            "rel_source_id": e.get("source_id") or e.get("source"),
                            "rel_target_id": e.get("target_id") or e.get("target"),
                            "rel_props": e.get("properties", {}),
                        })

            return results

        # 6. Path Search Query: MATCH p = (start)-[r*1..N]->(target)
        if "MATCH p = (start)-[r*" in q:
            entry_id = str(params.get("entry_id", "")).lower()
            target_ids = {str(t).lower() for t in params.get("target_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            limit = params.get("limit", 50)

            found_paths = []

            def dfs(current_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]], visited_ids: Set[str]):
                if len(found_paths) >= limit or len(path_edges) >= 6:
                    return

                for e in self.edges:
                    src = (e.get("source_id") or e.get("source", "")).lower()
                    if src != current_id:
                        continue

                    rel_type = e.get("relationship_type") or e.get("type", "")
                    ev_class = e.get("evidence_class", "OBSERVED")

                    if allowed_types and rel_type not in allowed_types:
                        continue
                    if not include_hypothetical:
                        if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                            continue

                    tgt = (e.get("target_id") or e.get("target", "")).lower()
                    if tgt in visited_ids:
                        continue

                    tgt_node = self.nodes.get(tgt)
                    if not tgt_node:
                        continue

                    new_nodes = path_nodes + [tgt_node]
                    edge_dict = {
                        "type": rel_type,
                        "source_id": e.get("source_id") or e.get("source"),
                        "target_id": e.get("target_id") or e.get("target"),
                        "evidence_class": ev_class,
                        "properties": e.get("properties", {}),
                    }
                    new_edges = path_edges + [edge_dict]

                    if tgt in target_ids:
                        found_paths.append({
                            "path_nodes": [
                                {"id": n["id"], "labels": n.get("labels", []), "properties": n.get("properties", {})}
                                for n in new_nodes
                            ],
                            "path_relationships": new_edges,
                        })

                    dfs(tgt, new_nodes, new_edges, visited_ids | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})

            return found_paths

        return []


@pytest.fixture
def enterprise_graph_fixture() -> MockNeo4jClientForKafka:
    """Standard enterprise graph fixture for Kafka event streaming tests."""
    nodes = [
        {
            "id": "device:dev-ws-101",
            "labels": ["Device"],
            "properties": {"name": "Finance Workstation 101", "hostname": "ws-fin-101.corp", "criticality": "LOW"},
        },
        {
            "id": "user:victim1@corporation.com",
            "labels": ["User"],
            "properties": {"name": "Alice Vance", "email": "victim1@corporation.com", "criticality": "LOW"},
        },
        {
            "id": "server:srv-app-01",
            "labels": ["Server"],
            "properties": {"name": "App Server 01", "server_type": "APP_SERVER", "criticality": "MEDIUM"},
        },
        {
            "id": "server:srv-app-02",
            "labels": ["Server"],
            "properties": {"name": "App Server 02", "server_type": "APP_SERVER", "criticality": "MEDIUM"},
        },
        {
            "id": "critical:crit-db-financial",
            "labels": ["CriticalAsset", "Database"],
            "properties": {"name": "Financial DB", "criticality": "CRITICAL", "data_classification": "RESTRICTED"},
        },
    ]

    edges = [
        # ws-101 -> srv-app-01 (cost 1.0)
        {
            "source": "device:dev-ws-101",
            "target": "server:srv-app-01",
            "type": "CONNECTS_TO",
            "evidence_class": "OBSERVED",
            "properties": {"weight": 1.0, "traversal_cost": 1.0},
        },
        # srv-app-01 -> crit-db-financial (cost 2.5)
        {
            "source": "server:srv-app-01",
            "target": "critical:crit-db-financial",
            "type": "CAN_REACH",
            "evidence_class": "AUTHORIZED_ACCESS",
            "properties": {"weight": 2.5, "traversal_cost": 2.5},
        },
    ]

    return MockNeo4jClientForKafka(nodes, edges)


@pytest.fixture
def kafka_pipeline(enterprise_graph_fixture):
    """Sets up producer, processor, and consumer worker in mock streaming mode."""
    producer = GraphOpsKafkaProducer(mock_mode=True)
    processor = GraphOpsEventProcessor(client=enterprise_graph_fixture, producer=producer)
    worker = GraphOpsKafkaWorker(producer=producer, processor=processor, mock_mode=True)
    return producer, processor, worker, enterprise_graph_fixture


# =====================================================================
# 1. EVENT CONTRACT VALIDATION TESTS
# =====================================================================

def test_security_event_envelope_valid():
    """Verifies valid canonical security event envelope initialization."""
    event = create_synthetic_compromise_indicator(device_id="device:dev-ws-101")
    assert event.event_id.startswith("EVT-COMPROMISE-")
    assert event.schema_version == "1.0.0"
    assert event.event_type == SecurityEventType.COMPROMISE_INDICATOR
    assert event.entity_ids == ["device:dev-ws-101"]
    assert event.payload["indicator_type"] == "REMOTE_CODE_EXECUTION"


def test_security_event_envelope_validation_rejects_missing_fields():
    """Rejects event envelope missing mandatory fields."""
    with pytest.raises(Exception):
        SecurityEventEnvelope(
            # Missing event_id, source, occurred_at
            event_type=SecurityEventType.ENDPOINT_ALERT,
            entity_ids=[],
        )


def test_security_event_envelope_rejects_empty_entity_ids():
    """Envelope requires at least one referenced entity ID."""
    with pytest.raises(Exception):
        SecurityEventEnvelope(
            event_id="EVT-001",
            event_type=SecurityEventType.ENDPOINT_ALERT,
            source="TEST",
            occurred_at="2026-10-22T00:00:00Z",
            entity_ids=[],  # min_length=1 constraint
        )


# =====================================================================
# 2. PRODUCER TESTS
# =====================================================================

def test_producer_topic_routing_and_partitioning_key(kafka_pipeline):
    """Producer correctly routes events to respective topic and uses entity ID as key."""
    producer, _, _, _ = kafka_pipeline

    # 1. Compromise indicator -> endpoint events topic
    evt_comp = create_synthetic_compromise_indicator(device_id="device:dev-ws-101")
    res1 = producer.publish_security_event(evt_comp)
    assert res1.status == "ACCEPTED_FOR_STREAMING"
    assert res1.topic == config.KAFKA_TOPIC_ENDPOINT_EVENTS

    # 2. Identity logon -> identity events topic
    evt_ident = create_synthetic_identity_event(user_id="user:victim1@corporation.com")
    res2 = producer.publish_security_event(evt_ident)
    assert res2.status == "ACCEPTED_FOR_STREAMING"
    assert res2.topic == config.KAFKA_TOPIC_IDENTITY_EVENTS

    # 3. Network connection -> network events topic
    evt_net = create_synthetic_network_event(source_entity_id="device:dev-ws-101")
    res3 = producer.publish_security_event(evt_net)
    assert res3.status == "ACCEPTED_FOR_STREAMING"
    assert res3.topic == config.KAFKA_TOPIC_NETWORK_EVENTS


def test_producer_health_check(kafka_pipeline):
    """Verifies producer readiness reporting."""
    producer, _, _, _ = kafka_pipeline
    health = producer.health_check()
    assert health["status"] == "online"
    assert health["mock_mode"] is True
    assert "bootstrap_servers" in health


# =====================================================================
# 3. CONSUMER WORKER & ERROR CLASSIFICATION TESTS
# =====================================================================

def test_consumer_worker_malformed_json_routes_to_dlq(kafka_pipeline):
    """Malformed non-JSON bytes are safely dead-lettered without crashing worker."""
    producer, _, worker, _ = kafka_pipeline

    raw_garbage = b"THIS IS NOT VALID JSON AT ALL"
    success = worker.process_raw_message(raw_garbage, source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS)

    assert success is False
    assert worker.dlq_count == 1
    dlq_msgs = producer._mock_messages.get(config.KAFKA_TOPIC_DLQ, [])
    assert len(dlq_msgs) == 1
    envelope = json.loads(dlq_msgs[0]["value"].decode("utf-8"))
    assert envelope["failure_category"] == "PERMANENT_MALFORMED_JSON"


def test_consumer_worker_unknown_entity_routes_to_dlq(kafka_pipeline):
    """Event referencing nonexistent entity ID is routed to DLQ."""
    producer, _, worker, _ = kafka_pipeline

    ghost_event = create_synthetic_compromise_indicator(device_id="device:ghost-nonexistent-device")
    raw_bytes = ghost_event.model_dump_json().encode("utf-8")

    success = worker.process_raw_message(raw_bytes, source_topic=config.KAFKA_TOPIC_ENDPOINT_EVENTS)

    assert success is False
    assert worker.dlq_count == 1
    dlq_msgs = producer._mock_messages.get(config.KAFKA_TOPIC_DLQ, [])
    assert len(dlq_msgs) == 1
    envelope = json.loads(dlq_msgs[0]["value"].decode("utf-8"))
    assert envelope["failure_category"] == "PERMANENT_ENTITY_ERROR"
    assert "could not be resolved" in envelope["sanitized_error"]


# =====================================================================
# 4. GRAPH PERSISTENCE & EVENT-TRIGGERED ANALYTICS TESTS
# =====================================================================

def test_compromise_indicator_triggers_bfs_and_dijkstra(kafka_pipeline):
    """
    Ingesting a COMPROMISE_INDICATOR event on device:dev-ws-101:
    1. Persists SecurityEvent in graph.
    2. Runs BFS blast radius (discovering critical:crit-db-financial at 2 hops).
    3. Runs Dijkstra shortest path (finding ws-101 -> srv-app-01 -> crit-db-financial, total cost 3.5).
    4. Generates traceable SecurityFindingRecords.
    """
    producer, processor, worker, graph = kafka_pipeline

    event = create_synthetic_compromise_indicator(device_id="device:dev-ws-101")
    producer.publish_security_event(event)

    # Worker consumes and processes
    processed_count = worker.run_once()
    assert processed_count == 1
    assert worker.processed_count == 1

    # Verify SecurityEvent was persisted
    assert event.event_id in graph.security_events

    # Verify Findings were generated
    findings = processor.get_findings(source_event_id=event.event_id)
    assert len(findings) >= 2  # BFS blast radius + Dijkstra shortest path

    types = {f.analysis_type for f in findings}
    assert "BFS_BLAST_RADIUS" in types
    assert "DIJKSTRA_SHORTEST_PATH" in types

    dijkstra_finding = next(f for f in findings if f.analysis_type == "DIJKSTRA_SHORTEST_PATH")
    assert dijkstra_finding.critical_asset_impacted == "critical:crit-db-financial"
    assert dijkstra_finding.severity == CriticalityTier.CRITICAL
    assert dijkstra_finding.details["total_cost"] == 3.5
    assert dijkstra_finding.details["hop_count"] == 2
    assert dijkstra_finding.details["path_node_ids"] == [
        "device:dev-ws-101",
        "server:srv-app-01",
        "critical:crit-db-financial",
    ]


def test_idempotent_event_processing(kafka_pipeline):
    """Re-delivering the exact same event ID does not duplicate findings or graph entities."""
    producer, processor, worker, graph = kafka_pipeline

    event = create_synthetic_compromise_indicator(device_id="device:dev-ws-101")

    # 1. First execution
    producer.publish_security_event(event)
    worker.run_once()
    first_findings_count = len(processor.get_findings(source_event_id=event.event_id))

    # 2. Duplicate re-delivery
    producer.publish_security_event(event)
    worker.run_once()
    second_findings_count = len(processor.get_findings(source_event_id=event.event_id))

    # Idempotent guarantee: Finding count is identical
    assert first_findings_count == second_findings_count


def test_identity_event_updates_graph_topology(kafka_pipeline):
    """Identity logon event updates (user)-[:LOGGED_IN_TO]->(server) relationship."""
    producer, _, worker, graph = kafka_pipeline

    event = create_synthetic_identity_event(
        user_id="user:victim1@corporation.com",
        target_resource_id="server:srv-app-01",
    )
    producer.publish_security_event(event)
    worker.run_once()

    # Verify edge was merged in mock graph
    logon_edges = [
        e for e in graph.edges
        if e.get("type") == "LOGGED_IN_TO"
        and e.get("source") == "user:victim1@corporation.com"
        and e.get("target") == "server:srv-app-01"
    ]
    assert len(logon_edges) == 1
    assert logon_edges[0]["properties"]["traversal_cost"] == 1.0


# =====================================================================
# 5. FASTAPI STREAMING & SIMULATION ENDPOINTS
# =====================================================================

def test_fastapi_publish_and_status_endpoints(kafka_pipeline):
    """Tests POST /events/publish and GET /events/status."""
    producer, processor, worker, graph = kafka_pipeline

    app.dependency_overrides[get_graphops_client] = lambda: graph
    app.dependency_overrides[get_kafka_producer_dep] = lambda: producer
    app.dependency_overrides[get_kafka_worker_dep] = lambda: worker
    client = TestClient(app)

    try:
        # 1. Publish Event via API
        event = create_synthetic_compromise_indicator(device_id="device:dev-ws-101")
        resp = client.post(
            "/api/v1/graphops/events/publish",
            json=event.model_dump(),
        )
        assert resp.status_code == 202, resp.text
        data = resp.json()
        assert data["status"] == "ACCEPTED_FOR_STREAMING"
        assert data["event_id"] == event.event_id

        # 2. Check Status via API
        status_resp = client.get("/api/v1/graphops/events/status")
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert "bootstrap_servers" in status_data
        assert "consumer_worker_running" in status_data

    finally:
        app.dependency_overrides.clear()


def test_fastapi_simulate_end_to_end_demonstration(kafka_pipeline):
    """
    Tests POST /events/simulate endpoint which executes full pipeline:
    publish -> worker consume -> Neo4j write -> BFS & Dijkstra -> return findings.
    """
    producer, processor, worker, graph = kafka_pipeline

    app.dependency_overrides[get_graphops_client] = lambda: graph
    app.dependency_overrides[get_kafka_producer_dep] = lambda: producer
    app.dependency_overrides[get_kafka_worker_dep] = lambda: worker
    client = TestClient(app)

    try:
        resp = client.post(
            "/api/v1/graphops/events/simulate",
            params={
                "device_id": "device:dev-ws-101",
                "scenario": "COMPROMISE_INDICATOR",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["status"] == "COMPLETED"
        assert data["scenario"] == "COMPROMISE_INDICATOR"
        assert data["messages_consumed_count"] >= 1
        assert data["findings_generated_count"] >= 2
        assert len(data["findings"]) >= 2

        # Verify findings list endpoint
        findings_resp = client.get(
            "/api/v1/graphops/events/findings",
            params={"entity_id": "device:dev-ws-101"},
        )
        assert findings_resp.status_code == 200
        findings_list = findings_resp.json()
        assert len(findings_list) >= 2

        # Verify individual finding retrieval
        first_fid = data["findings"][0]["finding_id"]
        single_resp = client.get(f"/api/v1/graphops/events/findings/{first_fid}")
        assert single_resp.status_code == 200
        assert single_resp.json()["finding_id"] == first_fid

    finally:
        app.dependency_overrides.clear()

