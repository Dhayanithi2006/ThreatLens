"""
ThreatLens GraphOps - Verification Suite for User Attack Path Scenario
Tests the isolated scenario:
  Route 1: Computer A -> Server A -> Server B -> Database A
  Route 2: Computer A -> Server C -> Database A

Verifies:
  1. Lowest-cost valid route selection by Dijkstra (fewer hops vs lower weight).
  2. Alternative attack-path discovery (DFS/search returns both valid routes).
  3. Dynamic weight updates change the selected Dijkstra route.
  4. Edge removal / node isolation changes available paths.
  5. Unreachable targets are handled cleanly.
  6. Strict relationship directionality enforcement.
  7. Evidence preservation (OBSERVED, AUTHORIZED_ACCESS, HYPOTHETICAL).
  8. Methodology disclosures (potential reachability is never presented as proof of an attack).
  9. FastAPI API endpoint serialization and status codes.
"""

import pytest
from typing import Dict, List, Any, Optional
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    InterventionAction,
)
from backend.models.graphops import (
    DijkstraShortestPathRequest,
    AttackPathRequest,
    ContainmentSimulationRequest,
    ProposedIntervention,
)
from backend.graphops.dijkstra import (
    DijkstraShortestPathEngine,
    TraversalCostPolicy,
)
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.blast_radius import NodeNotFoundError
from backend.graphops.client import get_graphops_client


class ScenarioMockGraphClient:
    """In-memory mock graph client configured specifically for the scenario."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.edges = edges
        self.executed_queries: List[str] = []
        self.aliases: Dict[str, str] = {}
        for n in nodes:
            nid = n["id"].lower()
            props = n.get("properties", {})
            for key in ["name", "hostname", "device_id", "server_id", "db_id", "asset_id"]:
                val = props.get(key)
                if val:
                    self.aliases[str(val).lower()] = nid

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.executed_queries.append(query)
        params = params or {}
        q = query.strip()

        # Node resolution query
        if "WHERE n.id =" in q or "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q:
            target_id = str(params.get("id") or params.get("clean_id") or params.get("canonical_id") or "").lower()
            id_without_prefix = str(params.get("id_without_prefix") or "").lower()
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

        # Crown Jewels resolution query
        if "MATCH (c:CriticalAsset)" in q and "OPTIONAL" not in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or "Database" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # Path Search query
        if "MATCH p = (start)-[r*" in q:
            entry_id = str(params.get("entry_id", "")).lower()
            target_ids = {str(t).lower() for t in params.get("target_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            limit = params.get("limit", 50)

            found_paths = []

            def dfs(current_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]], visited: set):
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
                    if tgt in visited:
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

                    dfs(tgt, new_nodes, new_edges, visited | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})

            return found_paths

        return []


@pytest.fixture
def scenario_graph() -> ScenarioMockGraphClient:
    """
    Constructs the isolated scenario test graph:
      Computer A: device:computer-a
      Server A: server:server-a
      Server B: server:server-b
      Server C: server:server-c
      Database A: critical:database-a (Crown Jewel)
      Database B: critical:database-b (Disconnected Crown Jewel)

    Routes:
      Route 1 (3 hops): Computer A -> Server A (cost 1.0) -> Server B (cost 1.0) -> Database A (cost 1.0)
        Total cost = 3.0
      Route 2 (2 hops): Computer A -> Server C (cost 2.5) -> Database A (cost 2.5)
        Total cost = 5.0
    """
    nodes = [
        {"id": "device:computer-a", "labels": ["Device"], "properties": {"name": "Computer A", "criticality": "LOW"}},
        {"id": "server:server-a", "labels": ["Server"], "properties": {"name": "Server A", "criticality": "MEDIUM"}},
        {"id": "server:server-b", "labels": ["Server"], "properties": {"name": "Server B", "criticality": "MEDIUM"}},
        {"id": "server:server-c", "labels": ["Server"], "properties": {"name": "Server C", "criticality": "MEDIUM"}},
        {"id": "critical:database-a", "labels": ["CriticalAsset", "Database"], "properties": {"name": "Database A", "criticality": "CRITICAL", "impact_score": 95}},
        {"id": "critical:database-b", "labels": ["CriticalAsset", "Database"], "properties": {"name": "Database B", "criticality": "CRITICAL", "impact_score": 90}},
    ]
    edges = [
        # Route 1: 3 hops, cost 3.0
        {
            "source": "device:computer-a",
            "target": "server:server-a",
            "type": "OBSERVED_CONNECTION",
            "evidence_class": "OBSERVED",
            "properties": {"traversal_cost": 1.0, "port": 22},
        },
        {
            "source": "server:server-a",
            "target": "server:server-b",
            "type": "CONNECTS_TO",
            "evidence_class": "OBSERVED",
            "properties": {"traversal_cost": 1.0, "port": 443},
        },
        {
            "source": "server:server-b",
            "target": "critical:database-a",
            "type": "CONTAINS_CRITICAL_DATA",
            "evidence_class": "OBSERVED",
            "properties": {"traversal_cost": 1.0, "port": 5432},
        },
        # Route 2: 2 hops, cost 5.0
        {
            "source": "device:computer-a",
            "target": "server:server-c",
            "type": "OBSERVED_CONNECTION",
            "evidence_class": "OBSERVED",
            "properties": {"traversal_cost": 2.5, "port": 8080},
        },
        {
            "source": "server:server-c",
            "target": "critical:database-a",
            "type": "CONTAINS_CRITICAL_DATA",
            "evidence_class": "OBSERVED",
            "properties": {"traversal_cost": 2.5, "port": 5432},
        },
    ]
    return ScenarioMockGraphClient(nodes, edges)


def test_scenario_dijkstra_selects_lowest_cost_route(scenario_graph):
    """
    Verification:
      Route 1: 3 hops with cost 1.0 + 1.0 + 1.0 = 3.0
      Route 2: 2 hops with cost 2.5 + 2.5 = 5.0
      Dijkstra MUST select Route 1 because 3.0 < 5.0, proving that Dijkstra
      optimizes for lowest traversal cost, NOT simply fewest hops (BFS).
    """
    engine = DijkstraShortestPathEngine(scenario_graph)
    req = DijkstraShortestPathRequest(
        entry_node_id="device:computer-a",
        target_node_id="critical:database-a",
        include_hypothetical=True,
    )
    result = engine.find_shortest_path(req)

    assert result.path_found is True
    assert result.total_cost == 3.0
    assert result.hop_count == 3
    node_ids = [n.id for n in result.nodes]
    assert node_ids == [
        "device:computer-a",
        "server:server-a",
        "server:server-b",
        "critical:database-a",
    ]


def test_scenario_alternative_paths_discovered(scenario_graph):
    """
    Verification:
      Alternative path exploration via AttackPathService must discover BOTH valid routes:
      - Route 1: Computer A -> Server A -> Server B -> Database A
      - Route 2: Computer A -> Server C -> Database A
    """
    service = AttackPathService(scenario_graph)
    req = AttackPathRequest(
        entry_node_id="device:computer-a",
        target_node_ids=["critical:database-a"],
        max_depth=5,
        include_hypothetical=True,
    )
    result = service.find_attack_paths(req)

    assert result.total_paths_discovered == 2
    paths_node_sequences = [[n.id for n in p.nodes] for p in result.paths]
    assert [
        "device:computer-a",
        "server:server-a",
        "server:server-b",
        "critical:database-a",
    ] in paths_node_sequences
    assert [
        "device:computer-a",
        "server:server-c",
        "critical:database-a",
    ] in paths_node_sequences


def test_scenario_changing_weights_changes_dijkstra_selection(scenario_graph):
    """
    Verification:
      Changing edge weights dynamically alters the Dijkstra selection:
      Reduce Route 2 edge costs from 2.5 each to 0.8 each (total 1.6).
      Now Route 2 (cost 1.6) is cheaper than Route 1 (cost 3.0).
      Dijkstra MUST now select Route 2!
    """
    # Mutate Route 2 weights in the isolated test graph
    for edge in scenario_graph.edges:
        if edge.get("target") == "server:server-c" or edge.get("source") == "server:server-c":
            edge["properties"]["traversal_cost"] = 0.8

    engine = DijkstraShortestPathEngine(scenario_graph)
    req = DijkstraShortestPathRequest(
        entry_node_id="device:computer-a",
        target_node_id="critical:database-a",
        include_hypothetical=True,
    )
    result = engine.find_shortest_path(req)

    assert result.path_found is True
    assert result.total_cost == 1.6
    assert result.hop_count == 2
    assert [n.id for n in result.nodes] == [
        "device:computer-a",
        "server:server-c",
        "critical:database-a",
    ]


def test_scenario_removing_edge_changes_available_paths(scenario_graph):
    """
    Verification:
      Simulating containment intervention:
      Sever edge Server C -> Database A (or isolate Server C).
      Result:
      - Attack path discovery now finds only Route 1.
      - Dijkstra shortest path chooses Route 1.
      - The underlying live graph remains completely unmutated.
    """
    service = AttackPathService(scenario_graph)

    # What-If containment simulation isolating Server C
    sim_req = ContainmentSimulationRequest(
        entry_node_id="device:computer-a",
        target_asset_ids=["critical:database-a"],
        proposed_interventions=[
            ProposedIntervention(
                action=InterventionAction.ISOLATE_NODE,
                node_id="server:server-c",
                rationale="Isolate Server C",
            )
        ],
    )
    sim_res = service.simulate_containment(sim_req)

    assert sim_res.live_graph_modified is False
    assert sim_res.baseline_paths_count == 2
    assert sim_res.remaining_paths_count == 1
    assert sim_res.paths_eliminated_count == 1

    # Verify Dijkstra under containment isolation
    recalculated = service.dijkstra_engine.find_shortest_path(
        DijkstraShortestPathRequest(
            entry_node_id="device:computer-a",
            target_node_id="critical:database-a",
        ),
        disabled_node_ids={"server:server-c"},
    )
    assert recalculated.path_found is True
    assert recalculated.total_cost == 3.0
    assert "server:server-c" not in [n.id for n in recalculated.nodes]
    assert [n.id for n in recalculated.nodes] == [
        "device:computer-a",
        "server:server-a",
        "server:server-b",
        "critical:database-a",
    ]


def test_scenario_unreachable_target_handling(scenario_graph):
    """
    Verification:
      Database B has no incoming edges (air-gapped / disconnected).
      - Dijkstra returns path_found=False, total_cost=None, hop_count=0, nodes=[].
      - Database B is explicitly listed in unreachable_targets.
      - Warning message explains the reachability constraint.
    """
    engine = DijkstraShortestPathEngine(scenario_graph)
    req = DijkstraShortestPathRequest(
        entry_node_id="device:computer-a",
        target_node_id="critical:database-b",
    )
    result = engine.find_shortest_path(req)

    assert result.path_found is False
    assert result.total_cost is None
    assert result.hop_count == 0
    assert len(result.nodes) == 0
    assert "critical:database-b" in result.unreachable_targets
    assert any("unreachable" in w.lower() for w in result.warnings)


def test_scenario_relationship_directionality_enforcement(scenario_graph):
    """
    Verification:
      Edges are strictly directed. Traversing backwards from Database A
      to Computer A must be rejected as unreachable.
    """
    engine = DijkstraShortestPathEngine(scenario_graph)
    req = DijkstraShortestPathRequest(
        entry_node_id="critical:database-a",
        target_node_id="device:computer-a",
    )
    result = engine.find_shortest_path(req)

    assert result.path_found is False
    assert "device:computer-a" in result.unreachable_targets


def test_scenario_evidence_preservation_and_methodology(scenario_graph):
    """
    Verification:
      - Evidence classifications (OBSERVED, AUTHORIZED_ACCESS, HYPOTHETICAL) are preserved.
      - Results clearly indicate that potential reachability is an architectural model,
        NEVER presented as proof of an actual active attack.
    """
    service = AttackPathService(scenario_graph)
    result = service.find_attack_paths(AttackPathRequest(
        entry_node_id="device:computer-a",
        target_node_ids=["critical:database-a"],
    ))

    # Methodology note explicitly clarifies exposure vs confirmed traversal
    assert "exposure" in result.methodology_note.lower()
    assert "not proof of actual" in result.methodology_note.lower()

    for path in result.paths:
        for step in path.steps:
            assert step.evidence_class == EvidenceClass.OBSERVED
            assert step.relationship_type in [
                RelationshipType.OBSERVED_CONNECTION,
                RelationshipType.CONNECTS_TO,
                RelationshipType.CONTAINS_CRITICAL_DATA,
            ]
            assert step.description != ""
            assert step.source_id != ""
            assert step.target_id != ""


def test_scenario_fastapi_endpoints(scenario_graph):
    """
    Verification:
      Test FastAPI REST API endpoints using the isolated scenario graph:
      - POST /api/v1/graphops/shortest-path
      - POST /api/v1/graphops/attack-paths
    """
    app.dependency_overrides[get_graphops_client] = lambda: scenario_graph
    client = TestClient(app)

    try:
        # POST /shortest-path
        resp_sp = client.post(
            "/api/v1/graphops/shortest-path",
            json={
                "entry_node_id": "device:computer-a",
                "target_node_id": "critical:database-a",
                "include_hypothetical": True,
            },
        )
        assert resp_sp.status_code == 200
        sp_data = resp_sp.json()
        assert sp_data["path_found"] is True
        assert sp_data["total_cost"] == 3.0
        assert sp_data["hop_count"] == 3
        assert len(sp_data["nodes"]) == 4

        # POST /attack-paths
        resp_ap = client.post(
            "/api/v1/graphops/attack-paths",
            json={
                "entry_node_id": "device:computer-a",
                "target_node_ids": ["critical:database-a"],
                "max_depth": 5,
                "include_hypothetical": True,
            },
        )
        assert resp_ap.status_code == 200
        ap_data = resp_ap.json()
        assert ap_data["total_paths_discovered"] == 2
        assert "critical:database-a" in ap_data["targets_reached"]

        # 404 for unknown entry
        resp_err = client.post(
            "/api/v1/graphops/shortest-path",
            json={
                "entry_node_id": "device:nonexistent-machine",
                "target_node_id": "critical:database-a",
            },
        )
        assert resp_err.status_code == 404
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)
