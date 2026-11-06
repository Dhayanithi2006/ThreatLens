"""
ThreatLens GraphOps — Module 2: Explore Attack Paths Comprehensive Test Suite
Validates:
1. Graph Ingestion & Topology:
   - Canonical identifiers and entity schemas
   - Evidence classification, timestamps, and provenance preservation
   - Duplicate prevention and idempotency
   - Topology retrieval, search, and category filtering (GET /api/v1/graphops/topology)
2. Attack Paths & Chokepoints:
   - Dijkstra weighted shortest-path analysis with priority queue
   - Ordered nodes, steps, and total path cost
   - Strict non-negative weight validation
   - Directional traversal and cycle prevention
   - Alternative path exploration via DFS
   - Choke-point identification, elimination percentage, and intervention ranking
   - Direct Module 3 Blast Radius linkage (recommended_blast_radius_url)
3. Centrality & PageRank Analysis:
   - PageRank authority scoring (power iteration)
   - Brandes' Betweenness Centrality (lateral bridges)
   - Structural disruption ranking
   - Result caching and cache invalidation after topology changes
   - Analytical interpretation disclaimer (PageRank != compromise)
4. Cross-Module Centralized Integration:
   - Case-to-graph evidence bridge (Module 1 investigation -> Module 2 graph -> Module 3 blast radius)
   - Device enrollment auto-provisioning (Module 0 telemetry -> GraphOps Device node -> centrality cache invalidation)
"""

import pytest
import math
from typing import Dict, List, Any
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
)
from backend.models.graphops import (
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
    AttackPathRequest,
    AttackPathResult,
    ChokePointRequest,
    ChokePointResult,
    InterventionAction,
)
from backend.graphops.ingest import GraphOpsIngestionEngine
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.dijkstra import DijkstraShortestPathEngine, TraversalCostPolicy
from backend.graphops.centrality import (
    CentralityAnalyticsService,
    get_centrality_service,
    invalidate_centrality_cache,
    CentralityAnalysisResult,
)
from backend.graphops.mock_client import get_mock_graphops_client, InMemoryGraphOpsClient


@pytest.fixture
def mock_client():
    """Provides a fresh or reset InMemoryGraphOpsClient preloaded with standard enterprise fixture."""
    return get_mock_graphops_client()


@pytest.fixture
def test_client():
    """Provides FastAPI test client."""
    return TestClient(app)


# =====================================================================
# SUBMODULE 1: GRAPH INGESTION & TOPOLOGY TESTS
# =====================================================================

def test_topology_retrieval_and_canonical_ids(mock_client):
    """
    Verifies that get_graph_topology retrieves all enterprise entities and relationships
    with canonical identifiers, ontological categories, and preserved provenance.
    """
    engine = GraphOpsIngestionEngine(mock_client)
    topo = engine.get_graph_topology(limit=500)

    assert "nodes" in topo
    assert "edges" in topo
    assert topo["total_nodes"] > 0
    assert topo["total_edges"] > 0
    assert isinstance(topo["entity_categories"], list)
    assert isinstance(topo["relationship_categories"], list)
    assert isinstance(topo["relationship_types"], list)

    # Verify canonical ID conventions
    node_ids = [n["id"] for n in topo["nodes"]]
    for nid in node_ids:
        assert ":" in nid, f"Node ID {nid} lacks canonical prefix"
        prefix = nid.split(":", 1)[0]
        assert prefix in ("user", "device", "server", "app", "db", "ip", "vuln", "critical", "event", "email")

    # Verify edge metadata
    for e in topo["edges"]:
        assert "source_id" in e
        assert "target_id" in e
        assert "relationship_type" in e
        assert "evidence_class" in e
        assert e["evidence_class"] in ("OBSERVED", "AUTHORIZED_ACCESS", "INFERRED", "HYPOTHETICAL")
        assert e["weight"] >= 0.0


def test_topology_search_and_filtering(mock_client):
    """
    Verifies keyword search and multi-attribute filtering (entity_type, relationship_type, evidence_class).
    """
    engine = GraphOpsIngestionEngine(mock_client)

    # 1. Search by hostname/ID keyword
    search_res = engine.get_graph_topology(search="dev-ws-101")
    assert search_res["total_nodes"] >= 1
    assert any("dev-ws-101" in n["id"].lower() or "dev-ws-101" in n["name"].lower() for n in search_res["nodes"])

    # 2. Filter by entity_type = "Server"
    server_res = engine.get_graph_topology(entity_type="Server")
    assert server_res["total_nodes"] > 0
    for n in server_res["nodes"]:
        assert n["label"] == "Server" or "Server" in n.get("labels", [])

    # 3. Filter by relationship_type = "USES"
    uses_res = engine.get_graph_topology(relationship_type="USES")
    for e in uses_res["edges"]:
        assert e["relationship_type"] == "USES"

    # 4. Filter by evidence_class = "OBSERVED"
    observed_res = engine.get_graph_topology(evidence_class="OBSERVED")
    for e in observed_res["edges"]:
        assert e["evidence_class"] == "OBSERVED"


def test_topology_api_endpoints(test_client):
    """
    Verifies FastAPI GET /api/v1/graphops/topology and alias /api/v1/graphops/graph.
    """
    # 1. General topology
    resp = test_client.get("/api/v1/graphops/topology?limit=50")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "entity_categories" in data
    assert "relationship_categories" in data
    assert data["total_nodes"] > 0

    # 2. Search query parameter
    resp_search = test_client.get("/api/v1/graphops/topology?search=financial&limit=20")
    assert resp_search.status_code == 200
    search_data = resp_search.json()
    assert search_data["search_applied"] == "financial"

    # 3. Alias /api/v1/graphops/graph
    resp_alias = test_client.get("/api/v1/graphops/graph?limit=10")
    assert resp_alias.status_code == 200
    alias_data = resp_alias.json()
    assert len(alias_data["nodes"]) <= 10


def test_graph_ingestion_idempotency_and_no_duplicates(mock_client):
    """
    Verifies that re-ingesting duplicate entities updates attributes idempotently
    without creating duplicate nodes or corrupting canonical identifiers.
    """
    engine = GraphOpsIngestionEngine(mock_client)
    initial_topo = engine.get_graph_topology(limit=500)
    initial_node_count = initial_topo["total_nodes"]

    # Re-ingest default enterprise fixture
    res = engine.ingest_sample_fixture()
    assert res.status in ("SUCCESS", "PARTIAL")

    subsequent_topo = engine.get_graph_topology(limit=500)
    # Total unique node count must remain constant (no duplicates)
    assert subsequent_topo["total_nodes"] == initial_node_count

    # Check for any duplicate node IDs
    seen_ids = set()
    for n in subsequent_topo["nodes"]:
        assert n["id"] not in seen_ids, f"Duplicate node ID detected: {n['id']}"
        seen_ids.add(n["id"])


# =====================================================================
# SUBMODULE 2: ATTACK PATHS & CHOKEPOINTS TESTS
# =====================================================================

def test_dijkstra_shortest_path_analysis(mock_client):
    """
    Verifies Dijkstra shortest path calculation:
    - Finds minimum-cost route using min-heap priority queue
    - Returns ordered sequence of nodes and edge steps
    - Validates non-negative weights and total path cost
    - Provides recommended_blast_radius_url
    """
    engine = DijkstraShortestPathEngine(mock_client)
    req = DijkstraShortestPathRequest(
        entry_node_id="device:dev-ws-101",
        include_hypothetical=True,
    )
    res = engine.find_shortest_path(req)

    assert isinstance(res, DijkstraShortestPathResult)
    assert res.path_found is True
    assert res.total_cost is not None
    assert res.total_cost >= 0.0
    assert len(res.nodes) >= 2
    assert len(res.steps) == len(res.nodes) - 1

    # Verify ordered connectivity: step[i].target == step[i+1].source
    for i in range(len(res.steps) - 1):
        assert res.steps[i].target_id == res.steps[i + 1].source_id
        assert res.steps[i].cost >= 0.0
        assert res.steps[i].accumulated_cost <= res.steps[i + 1].accumulated_cost

    # Verify direct Module 3 Blast Radius link
    assert res.recommended_blast_radius_url is not None
    assert "start_node_id=device:dev-ws-101" in res.recommended_blast_radius_url


def test_dijkstra_strict_non_negative_weights():
    """
    Verifies that negative or NaN traversal weights are strictly rejected.
    """
    policy = TraversalCostPolicy()

    # Valid non-negative weights
    assert policy.calculate_edge_cost(RelationshipType.LOGGED_IN_TO, explicit_weight=0.0) == 0.0
    assert policy.calculate_edge_cost(RelationshipType.USES, explicit_weight=2.5) == 2.5

    # Negative weights must raise ValueError
    with pytest.raises(ValueError, match="strictly non-negative"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=-1.5)

    # NaN and infinite weights must raise ValueError
    with pytest.raises(ValueError, match="finite number"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=float("nan"))
    with pytest.raises(ValueError, match="finite number"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=float("inf"))


def test_dijkstra_directional_traversal_and_cycles():
    """
    Verifies that Dijkstra strictly obeys edge direction and handles cyclic topologies without looping.
    """
    # Graph with cycle: A -> B -> C -> A, and B -> Target
    nodes = [
        {"id": "device:a", "labels": ["Device"], "properties": {"name": "A"}},
        {"id": "server:b", "labels": ["Server"], "properties": {"name": "B"}},
        {"id": "server:c", "labels": ["Server"], "properties": {"name": "C"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Target", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:a", "target_id": "server:b", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
        {"source_id": "server:b", "target_id": "server:c", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
        {"source_id": "server:c", "target_id": "device:a", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
        {"source_id": "server:b", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 2.0}},
    ]
    client = InMemoryGraphOpsClient(nodes, edges)
    engine = DijkstraShortestPathEngine(client)

    # 1. Traversal from A -> Target: should be A -> B -> Target (cost = 1 + 2 = 3.0)
    res = engine.find_shortest_path(DijkstraShortestPathRequest(entry_node_id="device:a", target_node_id="critical:target"))
    assert res.path_found is True
    assert res.total_cost == 3.0
    assert [n.id for n in res.nodes] == ["device:a", "server:b", "critical:target"]

    # 2. Reverse direction from Target -> A: should be unreachable because edges are directed
    rev_res = engine.find_shortest_path(DijkstraShortestPathRequest(entry_node_id="critical:target", target_node_id="device:a"))
    assert rev_res.path_found is False


def test_alternative_attack_paths_dfs(mock_client):
    """
    Verifies DFS exploration of alternative attack paths to Crown Jewels,
    ranking by risk score and providing recommended_blast_radius_url.
    """
    service = AttackPathService(mock_client)
    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        max_depth=5,
        include_hypothetical=True,
    )
    result = service.find_attack_paths(req)

    assert isinstance(result, AttackPathResult)
    assert result.total_paths_discovered > 0
    assert len(result.paths) > 0
    assert result.recommended_blast_radius_url is not None
    assert "start_node_id=device:dev-ws-101" in result.recommended_blast_radius_url

    # Check risk scoring ordering (descending)
    scores = [p.risk_score for p in result.paths]
    assert scores == sorted(scores, reverse=True)


def test_chokepoints_identification_and_intervention(mock_client):
    """
    Verifies identification of strategic choke points across candidate attack paths,
    calculating traversal elimination percentages and recommended containment actions.
    """
    service = AttackPathService(mock_client)
    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        max_depth=5,
        include_hypothetical=True,
    )
    paths_res = service.find_attack_paths(req)
    assert paths_res.total_paths_discovered > 0

    cp_res = service.analyze_choke_points(paths=paths_res.paths, top_n=5)
    assert isinstance(cp_res, ChokePointResult)
    assert len(cp_res.choke_points) > 0
    assert cp_res.top_recommendation is not None

    top_cp = cp_res.top_recommendation
    assert top_cp.rank == 1
    assert top_cp.paths_traversed_count > 0
    assert top_cp.traversal_percentage > 0.0
    assert top_cp.recommended_action in (
        InterventionAction.ISOLATE_NODE,
        InterventionAction.REVOKE_PERMISSION,
        InterventionAction.DISABLE_ACCOUNT,
        InterventionAction.BLOCK_CONNECTION,
        InterventionAction.PATCH_VULNERABILITY,
    )
    assert top_cp.recommended_blast_radius_url is not None
    assert top_cp.entity_id in top_cp.recommended_blast_radius_url


# =====================================================================
# SUBMODULE 3: CENTRALITY & PAGERANK ANALYSIS TESTS
# =====================================================================

def test_centrality_pagerank_and_betweenness(mock_client):
    """
    Verifies computation of PageRank (authority) and Brandes' Betweenness Centrality (lateral bridges).
    """
    service = get_centrality_service(mock_client)
    res = service.analyze_graph_centrality(top_k=5, force_refresh=True)

    assert isinstance(res, CentralityAnalysisResult)
    assert res.total_nodes_analyzed > 0
    assert res.total_edges_analyzed > 0
    assert len(res.top_disruption_nodes) <= 5
    assert len(res.network_bridge_nodes) <= 5

    # Top disruption nodes should be sorted descending by disruption_score
    scores = [m.disruption_score for m in res.top_disruption_nodes]
    assert scores == sorted(scores, reverse=True)

    # Top network bridges should be sorted descending by betweenness
    betweenness = [m.betweenness for m in res.network_bridge_nodes]
    assert betweenness == sorted(betweenness, reverse=True)


def test_centrality_caching_and_invalidation(mock_client):
    """
    Verifies thread-safe centrality result caching, cache hit detection,
    force_refresh bypass, and invalidation upon graph changes.
    """
    service = get_centrality_service(mock_client)

    # 1. Initial execution with force_refresh=True populates cache
    res1 = service.analyze_graph_centrality(top_k=5, force_refresh=True)
    assert res1.cached is False

    # 2. Subsequent call without force_refresh must return cached result
    res2 = service.analyze_graph_centrality(top_k=5, force_refresh=False)
    assert res2.cached is True
    assert res2.cache_timestamp == res1.cache_timestamp
    assert res2.total_nodes_analyzed == res1.total_nodes_analyzed

    # 3. Call with force_refresh=True must recalculate (cached=False)
    res3 = service.analyze_graph_centrality(top_k=5, force_refresh=True)
    assert res3.cached is False

    # 4. Explicit cache invalidation
    service.invalidate_cache()
    res4 = service.analyze_graph_centrality(top_k=5, force_refresh=False)
    assert res4.cached is False, "Result after invalidate_cache() must not be served from stale cache"


def test_centrality_disclaimer_not_compromise(mock_client):
    """
    Verifies that centrality analytics explicitly note that high PageRank represents structural authority
    and connectivity density, NOT confirmed compromise or malicious behavior.
    """
    service = get_centrality_service(mock_client)
    res = service.analyze_graph_centrality(top_k=5)

    assert hasattr(res, "methodology_disclaimer")
    assert "NOT confirmed compromise" in res.methodology_disclaimer or "not indicate compromise" in res.methodology_disclaimer.lower()


def test_api_centrality_endpoint_caching(test_client):
    """
    Verifies FastAPI GET /api/v1/graphops/centrality respects caching and force_refresh parameter.
    """
    # Force initial refresh
    r1 = test_client.get("/api/v1/graphops/centrality?top_k=5&force_refresh=true")
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["cached"] is False

    # Subsequent request should be served from cache
    r2 = test_client.get("/api/v1/graphops/centrality?top_k=5&force_refresh=false")
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["cached"] is True
    assert d2["cache_timestamp"] == d1["cache_timestamp"]


# =====================================================================
# SUBMODULE 4: CROSS-MODULE CENTRALIZED INTEGRATION TESTS
# =====================================================================

def test_cross_module_case_bridge_and_blast_radius(test_client):
    """
    Verifies that Case-to-Graph bridge (Module 1 -> Module 2) maps investigation evidence
    and provides a direct recommended_blast_radius_url to Module 3 Blast Radius.
    """
    resp = test_client.get("/api/v1/graphops/bridge/case/MT-101")
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == "MT-101"
    assert data["primary_compromised_node"] is not None
    assert "recommended_blast_radius_url" in data
    assert "/api/v1/graphops/blast-radius" in data["recommended_blast_radius_url"]


def test_telemetry_device_auto_provision_invalidates_centrality(mock_client):
    """
    Verifies that enrolling an endpoint in Module 0 auto-provisions a Device node
    into GraphOps and automatically invalidates the centrality cache.
    """
    from backend.collector.registry import auto_provision_device_node

    # Prime the centrality cache
    service = get_centrality_service(mock_client)
    cached_first = service.analyze_graph_centrality(top_k=5, force_refresh=True)
    assert cached_first.cached is False

    cached_second = service.analyze_graph_centrality(top_k=5, force_refresh=False)
    assert cached_second.cached is True

    # Auto-provision a new collector device from telemetry
    auto_provision_device_node(hostname="NEW-WIN-COLLECTOR-99", ip_address="192.168.1.99")

    # Centrality cache should now be invalidated
    cached_after_provision = service.analyze_graph_centrality(top_k=5, force_refresh=False)
    assert cached_after_provision.cached is False, "Provisioning new device should invalidate centrality cache"
