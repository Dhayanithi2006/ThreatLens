"""
ThreatLens GraphOps - Dijkstra Weighted Shortest-Path Test Suite
Phase 3 Verification:
1. Genuine Dijkstra weighted shortest-path algorithm using priority queue (heapq).
2. Minimum accumulated traversal cost calculation and hop-count comparison (Dijkstra vs unweighted BFS).
3. Direct vs multi-hop route cost preference.
4. Multiple possible candidate routes.
5. Disconnected / unreachable targets.
6. Missing source / target handling.
7. Rejection of invalid, negative, NaN, or infinite edge weights.
8. Directional traversal enforcement.
9. Disallowed relationship type filtering.
10. Deterministic tie-breaking on equal costs.
11. Complete reconstruction of nodes, edges, step costs, and cumulative costs.
12. Graphs containing cycles without infinite loops.
13. Multiple critical asset target sets (finding minimum-cost reachable target).
14. What-if containment simulation (node isolation and edge severing without persistent mutations).
15. FastAPI GET and POST /shortest-path endpoints.
"""

import pytest
import math
from typing import Dict, List, Any, Optional, Set
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
    DijkstraEdgeCost,
    ContainmentSimulationRequest,
    ProposedIntervention,
    InterventionAction,
)
from backend.graphops.dijkstra import (
    DijkstraShortestPathEngine,
    TraversalCostPolicy,
)
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.blast_radius import NodeNotFoundError
from backend.graphops.client import get_graphops_client


# =====================================================================
# DETERMINISTIC TEST GRAPH FIXTURES
# =====================================================================

class MockNeo4jClientForDijkstra:
    """In-memory mock graph client implementing exact snapshot extraction."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.edges = edges
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

        # Node resolution query
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

        # Crown Jewels query
        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # Path Search Query: MATCH p = (start)-[r*1..N]->(target)
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
def dijkstra_test_graph() -> MockNeo4jClientForDijkstra:
    """
    Standard deterministic test graph fixture:
    Routes from device:laptop to asset:database:
      - Route 1: laptop -> server_a (cost 2) -> database (cost 3) => Total cost: 5.0, 2 hops
      - Route 2: laptop -> server_b (cost 1) -> server_c (cost 1) -> database (cost 2) => Total cost: 4.0, 3 hops
    Dijkstra MUST choose Route 2 (total cost 4.0) over Route 1 (total cost 5.0),
    even though Route 2 has more hops!

    Additional targets:
      - asset:vault: reachable via laptop -> server_b -> vault (cost 1 + 5 = 6.0)
      - asset:airgap: completely disconnected (unreachable)
    """
    nodes = [
        {
            "id": "device:laptop",
            "labels": ["Device"],
            "properties": {"name": "Analyst Laptop", "device_type": "LAPTOP", "criticality": "LOW"},
        },
        {
            "id": "server:alpha",
            "labels": ["Server"],
            "properties": {"name": "Server Alpha", "server_type": "APP_SERVER", "criticality": "MEDIUM"},
        },
        {
            "id": "server:beta",
            "labels": ["Server"],
            "properties": {"name": "Server Beta", "server_type": "JUMP_HOST", "criticality": "MEDIUM"},
        },
        {
            "id": "server:gamma",
            "labels": ["Server"],
            "properties": {"name": "Server Gamma", "server_type": "INTERNAL_PROXY", "criticality": "MEDIUM"},
        },
        {
            "id": "asset:database",
            "labels": ["CriticalAsset", "Database"],
            "properties": {"name": "Production Customer DB", "criticality": "CRITICAL", "data_classification": "RESTRICTED"},
        },
        {
            "id": "asset:vault",
            "labels": ["CriticalAsset", "Server"],
            "properties": {"name": "Key Vault", "criticality": "CRITICAL"},
        },
        {
            "id": "asset:airgap",
            "labels": ["CriticalAsset"],
            "properties": {"name": "Air-Gapped Cold Vault", "criticality": "CRITICAL"},
        },
    ]

    edges = [
        # Route 1: Laptop -> Server Alpha -> Database
        {
            "source": "device:laptop",
            "target": "server:alpha",
            "type": "CONNECTS_TO",
            "evidence_class": "OBSERVED",
            "properties": {"weight": 2.0, "risk_score": 0.5},
        },
        {
            "source": "server:alpha",
            "target": "asset:database",
            "type": "CAN_REACH",
            "evidence_class": "AUTHORIZED_ACCESS",
            "properties": {"weight": 3.0, "risk_score": 0.7},
        },
        # Route 2: Laptop -> Server Beta -> Server Gamma -> Database
        {
            "source": "device:laptop",
            "target": "server:beta",
            "type": "CONNECTS_TO",
            "evidence_class": "OBSERVED",
            "properties": {"weight": 1.0, "risk_score": 0.2},
        },
        {
            "source": "server:beta",
            "target": "server:gamma",
            "type": "OBSERVED_CONNECTION",
            "evidence_class": "OBSERVED",
            "properties": {"weight": 1.0, "risk_score": 0.3},
        },
        {
            "source": "server:gamma",
            "target": "asset:database",
            "type": "EXPLOITS",
            "evidence_class": "HYPOTHETICAL",
            "properties": {"weight": 2.0, "risk_score": 0.9},
        },
        # Route to Vault: Laptop -> Server Beta -> Vault
        {
            "source": "server:beta",
            "target": "asset:vault",
            "type": "CAN_REACH",
            "evidence_class": "AUTHORIZED_ACCESS",
            "properties": {"weight": 5.0, "risk_score": 0.8},
        },
    ]

    return MockNeo4jClientForDijkstra(nodes, edges)


# =====================================================================
# TEST 1: DIJKSTRA VS UNWEIGHTED BFS (MORE HOPS, LOWER TOTAL COST)
# =====================================================================

def test_dijkstra_chooses_lower_cost_over_fewer_hops(dijkstra_test_graph):
    """
    Priority 1 & 2 verification:
    Fewer hops (2 hops) has cost 5.0 (2 + 3).
    More hops (3 hops) has cost 4.0 (1 + 1 + 2).
    Dijkstra MUST choose the 3-hop route because its cumulative cost (4.0) is strictly lower.
    """
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_id="asset:database",
        include_hypothetical=True,
    )
    result = engine.find_shortest_path(request)

    assert result.path_found is True
    assert result.total_cost == 4.0
    assert result.hop_count == 3
    node_ids = [n.id for n in result.nodes]
    assert node_ids == ["device:laptop", "server:beta", "server:gamma", "asset:database"]

    # Verify edge cost breakdown
    assert len(result.steps) == 3
    assert result.steps[0].source_id == "device:laptop"
    assert result.steps[0].target_id == "server:beta"
    assert result.steps[0].step_cost == 1.0
    assert result.steps[0].accumulated_cost == 1.0

    assert result.steps[1].source_id == "server:beta"
    assert result.steps[1].target_id == "server:gamma"
    assert result.steps[1].step_cost == 1.0
    assert result.steps[1].accumulated_cost == 2.0

    assert result.steps[2].source_id == "server:gamma"
    assert result.steps[2].target_id == "asset:database"
    assert result.steps[2].step_cost == 2.0
    assert result.steps[2].accumulated_cost == 4.0


# =====================================================================
# TEST 2: DIRECT ROUTE CHEAPER THAN ALTERNATIVE
# =====================================================================

def test_dijkstra_direct_cheaper_route():
    """
    A direct edge with lower cost than any multi-hop bypass.
    Direct: A -> Target (cost 1.5)
    Indirect: A -> B (cost 1.0) -> Target (cost 2.0) = Total 3.0
    """
    nodes = [
        {"id": "node:entry", "labels": ["Device"], "properties": {"criticality": "LOW"}},
        {"id": "node:hop", "labels": ["Server"], "properties": {"criticality": "MEDIUM"}},
        {"id": "node:target", "labels": ["CriticalAsset"], "properties": {"criticality": "CRITICAL"}},
    ]
    edges = [
        {"source": "node:entry", "target": "node:target", "type": "CAN_REACH", "properties": {"weight": 1.5}},
        {"source": "node:entry", "target": "node:hop", "type": "NETWORK_ACCESS", "properties": {"weight": 1.0}},
        {"source": "node:hop", "target": "node:target", "type": "CAN_REACH", "properties": {"weight": 2.0}},
    ]
    client = MockNeo4jClientForDijkstra(nodes, edges)
    engine = DijkstraShortestPathEngine(client)

    result = engine.find_shortest_path(DijkstraShortestPathRequest(
        entry_node_id="node:entry",
        target_node_id="node:target",
    ))

    assert result.path_found is True
    assert result.total_cost == 1.5
    assert result.hop_count == 1
    assert [n.id for n in result.nodes] == ["node:entry", "node:target"]


# =====================================================================
# TEST 3: MULTIPLE CANDIDATE PATHS TO SAME TARGET
# =====================================================================

def test_dijkstra_multiple_paths_distinct_costs(dijkstra_test_graph):
    """
    With hypothetical edges excluded, Route 2 (which uses EXPLOITS hypothetical edge)
    is filtered out, forcing Dijkstra to find Route 1 (cost 5.0).
    """
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_id="asset:database",
        include_hypothetical=False,  # Excludes EXPLOITS
    )
    result = engine.find_shortest_path(request)

    assert result.path_found is True
    assert result.total_cost == 5.0
    assert result.hop_count == 2
    assert [n.id for n in result.nodes] == ["device:laptop", "server:alpha", "asset:database"]


# =====================================================================
# TEST 4: UNREACHABLE / DISCONNECTED TARGET
# =====================================================================

def test_dijkstra_unreachable_target(dijkstra_test_graph):
    """
    Target asset:airgap has no incoming edges.
    Dijkstra must terminate safely and report path_found=False, total_cost=None,
    and include asset:airgap in unreachable_targets.
    """
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_id="asset:airgap",
    )
    result = engine.find_shortest_path(request)

    assert result.path_found is False
    assert result.total_cost is None
    assert result.hop_count == 0
    assert len(result.nodes) == 0
    assert "asset:airgap" in result.unreachable_targets


# =====================================================================
# TEST 5: MISSING SOURCE OR TARGET NODE
# =====================================================================

def test_dijkstra_missing_source_node(dijkstra_test_graph):
    """Entry node does not exist in graph -> raises NodeNotFoundError."""
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:ghost-nonexistent",
        target_node_id="asset:database",
    )
    with pytest.raises(NodeNotFoundError):
        engine.find_shortest_path(request)


# =====================================================================
# TEST 6: REJECTION OF INVALID (NEGATIVE, NAN, INFINITY) WEIGHTS
# =====================================================================

def test_dijkstra_rejects_negative_or_nan_weights():
    """Weights policy rejects negative or invalid numbers."""
    policy = TraversalCostPolicy()

    # Negative weight
    with pytest.raises(ValueError, match="strictly non-negative"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=-2.5)

    # NaN weight
    with pytest.raises(ValueError, match="finite"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=float("nan"))

    # Infinite weight
    with pytest.raises(ValueError, match="finite"):
        policy.calculate_edge_cost(RelationshipType.CONNECTS_TO, explicit_weight=float("inf"))


# =====================================================================
# TEST 7: DIRECTIONAL TRAVERSAL ENFORCEMENT
# =====================================================================

def test_dijkstra_enforces_edge_direction():
    """
    Edge is oriented B -> A. Traversing from A to B must fail because edges are strictly directed.
    """
    nodes = [
        {"id": "node:a", "labels": ["Device"], "properties": {}},
        {"id": "node:b", "labels": ["CriticalAsset"], "properties": {"criticality": "CRITICAL"}},
    ]
    edges = [
        # B -> A (Reverse direction)
        {"source": "node:b", "target": "node:a", "type": "CAN_REACH", "properties": {"weight": 1.0}},
    ]
    client = MockNeo4jClientForDijkstra(nodes, edges)
    engine = DijkstraShortestPathEngine(client)

    result = engine.find_shortest_path(DijkstraShortestPathRequest(
        entry_node_id="node:a",
        target_node_id="node:b",
    ))

    assert result.path_found is False
    assert result.total_cost is None


# =====================================================================
# TEST 8: DISALLOWED RELATIONSHIP TYPES FILTERING
# =====================================================================

def test_dijkstra_filters_disallowed_relationship_types(dijkstra_test_graph):
    """
    If allowed_relationship_types only includes NETWORK_ACCESS and CAN_REACH,
    Route 2 (which requires HAS_SESSION and EXPLOITS) cannot be traversed.
    """
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_id="asset:database",
        allowed_relationship_types=[RelationshipType.CONNECTS_TO, RelationshipType.CAN_REACH],
    )
    result = engine.find_shortest_path(request)

    assert result.path_found is True
    assert result.total_cost == 5.0
    assert [n.id for n in result.nodes] == ["device:laptop", "server:alpha", "asset:database"]


# =====================================================================
# TEST 9: EQUAL-COST DETERMINISTIC TIE-BREAKING
# =====================================================================

def test_dijkstra_deterministic_tie_breaking():
    """
    Route A: entry -> node_a -> target (cost 1 + 1 = 2, 2 hops)
    Route B: entry -> node_b1 -> node_b2 -> target (cost 0.5 + 0.5 + 1.0 = 2, 3 hops)
    When costs are identical (2.0), tie-breaking deterministically prefers fewer hops (Route A).
    """
    nodes = [
        {"id": "node:entry", "labels": ["Device"], "properties": {}},
        {"id": "node:a", "labels": ["Server"], "properties": {}},
        {"id": "node:b1", "labels": ["Server"], "properties": {}},
        {"id": "node:b2", "labels": ["Server"], "properties": {}},
        {"id": "node:target", "labels": ["CriticalAsset"], "properties": {"criticality": "CRITICAL"}},
    ]
    edges = [
        {"source": "node:entry", "target": "node:a", "type": "CAN_REACH", "properties": {"weight": 1.0}},
        {"source": "node:a", "target": "node:target", "type": "CAN_REACH", "properties": {"weight": 1.0}},
        {"source": "node:entry", "target": "node:b1", "type": "CAN_REACH", "properties": {"weight": 0.5}},
        {"source": "node:b1", "target": "node:b2", "type": "CAN_REACH", "properties": {"weight": 0.5}},
        {"source": "node:b2", "target": "node:target", "type": "CAN_REACH", "properties": {"weight": 1.0}},
    ]
    client = MockNeo4jClientForDijkstra(nodes, edges)
    engine = DijkstraShortestPathEngine(client)

    result = engine.find_shortest_path(DijkstraShortestPathRequest(
        entry_node_id="node:entry",
        target_node_id="node:target",
    ))

    assert result.path_found is True
    assert result.total_cost == 2.0
    assert result.hop_count == 2
    assert [n.id for n in result.nodes] == ["node:entry", "node:a", "node:target"]


# =====================================================================
# TEST 10: CYCLES TERMINATION WITHOUT RE-ENTRANCY
# =====================================================================

def test_dijkstra_graph_with_cycles():
    """
    Graph contains a cycle: entry -> c1 -> c2 -> c1 -> target.
    Dijkstra must find the optimal acyclic path without looping infinitely.
    """
    nodes = [
        {"id": "node:entry", "labels": ["Device"], "properties": {}},
        {"id": "node:c1", "labels": ["Server"], "properties": {}},
        {"id": "node:c2", "labels": ["Server"], "properties": {}},
        {"id": "node:target", "labels": ["CriticalAsset"], "properties": {"criticality": "CRITICAL"}},
    ]
    edges = [
        {"source": "node:entry", "target": "node:c1", "type": "CAN_REACH", "properties": {"weight": 1.0}},
        {"source": "node:c1", "target": "node:c2", "type": "CAN_REACH", "properties": {"weight": 1.0}},
        {"source": "node:c2", "target": "node:c1", "type": "CAN_REACH", "properties": {"weight": 1.0}},  # Cycle back!
        {"source": "node:c2", "target": "node:target", "type": "CAN_REACH", "properties": {"weight": 1.0}},
    ]
    client = MockNeo4jClientForDijkstra(nodes, edges)
    engine = DijkstraShortestPathEngine(client)

    result = engine.find_shortest_path(DijkstraShortestPathRequest(
        entry_node_id="node:entry",
        target_node_id="node:target",
    ))

    assert result.path_found is True
    assert result.total_cost == 3.0
    assert result.hop_count == 3
    assert [n.id for n in result.nodes] == ["node:entry", "node:c1", "node:c2", "node:target"]


# =====================================================================
# TEST 11: CRITICAL ASSET TARGET SET (FIND GLOBAL MINIMUM REACHABLE)
# =====================================================================

def test_dijkstra_multiple_critical_asset_targets(dijkstra_test_graph):
    """
    Target set: [asset:database (cost 4.0), asset:vault (cost 6.0), asset:airgap (unreachable)].
    Dijkstra must identify asset:database as the minimum-cost reachable target asset.
    """
    engine = DijkstraShortestPathEngine(dijkstra_test_graph)
    request = DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_ids=["asset:database", "asset:vault", "asset:airgap"],
        include_hypothetical=True,
    )
    result = engine.find_shortest_path(request)

    assert result.path_found is True
    assert result.target_node is not None
    assert result.target_node.id == "asset:database"
    assert result.total_cost == 4.0
    assert "asset:database" in result.reachable_targets
    assert "asset:airgap" in result.unreachable_targets


# =====================================================================
# TEST 12: WHAT-IF CONTAINMENT SIMULATION INTEGRATION (SAFE & IN-MEMORY)
# =====================================================================

def test_containment_simulation_with_dijkstra(dijkstra_test_graph):
    """
    Simulate containment using node isolation:
    1. Baseline shortest path: Laptop -> Server Beta -> Server Gamma -> Database (cost 4.0).
    2. Containment action: ISOLATE_NODE 'server:beta'.
    3. Simulated shortest path: Laptop -> Server Alpha -> Database (cost 5.0).
    4. Assert original graph nodes and edges are 100% untouched.
    """
    service = AttackPathService(dijkstra_test_graph)

    # Initial baseline
    baseline = service.find_dijkstra_shortest_path(DijkstraShortestPathRequest(
        entry_node_id="device:laptop",
        target_node_id="asset:database",
        include_hypothetical=True,
    ))
    assert baseline.total_cost == 4.0
    assert "server:beta" in [n.id for n in baseline.nodes]

    # Run containment simulation (Isolate server:beta)
    sim_req = ContainmentSimulationRequest(
        entry_node_id="device:laptop",
        target_asset_ids=["asset:database"],
        proposed_interventions=[
            ProposedIntervention(
                action=InterventionAction.ISOLATE_NODE,
                node_id="server:beta",
                description="Simulate isolating compromised jump host",
            )
        ],
    )
    sim_result = service.simulate_containment(sim_req)

    assert sim_result.live_graph_modified is False
    assert sim_result.paths_eliminated_count > 0
    assert sim_result.remaining_paths_count > 0

    # Verify Dijkstra under simulated isolation
    recalculated = service.dijkstra_engine.find_shortest_path(
        DijkstraShortestPathRequest(
            entry_node_id="device:laptop",
            target_node_id="asset:database",
            include_hypothetical=True,
        ),
        disabled_node_ids={"server:beta"},
    )
    assert recalculated.path_found is True
    assert recalculated.total_cost == 5.0
    assert "server:beta" not in [n.id for n in recalculated.nodes]
    assert [n.id for n in recalculated.nodes] == ["device:laptop", "server:alpha", "asset:database"]

    # Safety verification: ensure underlying graph was NOT mutated
    assert "server:beta" in dijkstra_test_graph.nodes
    assert len(dijkstra_test_graph.edges) == 6


# =====================================================================
# TEST 13: FASTAPI POST AND GET ENDPOINTS
# =====================================================================

def test_fastapi_shortest_path_endpoints(dijkstra_test_graph):
    """
    Test POST and GET /api/v1/graphops/shortest-path endpoints via FastAPI TestClient.
    """
    app.dependency_overrides[get_graphops_client] = lambda: dijkstra_test_graph
    client = TestClient(app)

    try:
        # 1. Test POST /shortest-path
        post_resp = client.post(
            "/api/v1/graphops/shortest-path",
            json={
                "entry_node_id": "device:laptop",
                "target_node_id": "asset:database",
                "include_hypothetical": True,
            },
        )
        assert post_resp.status_code == 200, post_resp.text
        data = post_resp.json()
        assert data["path_found"] is True
        assert data["total_cost"] == 4.0
        assert data["hop_count"] == 3
        assert len(data["steps"]) == 3
        assert data["calculation_time_ms"] >= 0.0

        # 2. Test GET /shortest-path
        get_resp = client.get(
            "/api/v1/graphops/shortest-path",
            params={
                "entry_node_id": "device:laptop",
                "target_node_id": "asset:database",
                "include_hypothetical": "true",
            },
        )
        assert get_resp.status_code == 200, get_resp.text
        get_data = get_resp.json()
        assert get_data["path_found"] is True
        assert get_data["total_cost"] == 4.0

        # 3. Test 404 for nonexistent node
        err_resp = client.post(
            "/api/v1/graphops/shortest-path",
            json={
                "entry_node_id": "device:ghost-nonexistent",
                "target_node_id": "asset:database",
            },
        )
        assert err_resp.status_code == 404
    finally:
        app.dependency_overrides.clear()
