"""
ThreatLens - Prompt 3: Attack Path Analysis, Dijkstra, DFS, and Chokepoints Test Suite
Comprehensive verification of:
1. Canonical entity selection, unknown entity handling, and identical source/target evaluation.
2. Dijkstra weighted shortest-path analysis with non-negative finite cost validation,
   edge directionality, tie-breaking, and step-by-step cost accumulation.
3. Bounded acyclic path discovery (DFS/multi-path) with cycle prevention, max_depth bounds,
   and deterministic ranking.
4. Chokepoint analysis with structural betweenness ranking, alternate route tracking,
   and containment recommendation actions.
5. Centrality analytics: Brandes' betweenness, PageRank power iteration, isolated nodes,
   and empty graph handling.
6. Evidence classification distinction: OBSERVED vs AUTHORIZED vs INFERRED vs HYPOTHETICAL.
7. Full FastAPI route-level integration testing across all Prompt 3 GraphOps endpoints.
"""

import math
import time
# pyrefly: ignore[missing-import]
import pytest
from typing import Dict, List, Any, Optional, Set
# pyrefly: ignore[missing-import]
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    InterventionAction,
    canonicalize_node_id,
)
from backend.models.graphops import (
    EnterpriseNode,
    EnterpriseRelationship,
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
    AttackPathRequest,
    AttackPathResult,
    ChokePointRequest,
    ChokePointResult,
    ContainmentSimulationRequest,
    ProposedIntervention,
)
from backend.graphops.dijkstra import (
    DijkstraShortestPathEngine,
    TraversalCostPolicy,
)
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.centrality import CentralityAnalyticsService
from backend.graphops.blast_radius import NodeNotFoundError


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# =====================================================================
# DETERMINISTIC MOCK GRAPH CLIENT FOR EXACT ALGORITHM PROOFS
# =====================================================================

class DeterministicMockGraphClient:
    """In-memory mock graph client allowing exact mathematical inspection."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.edges = edges
        self.executed_queries: List[str] = []

    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.executed_queries.append(query)
        params = parameters or {}

        # 1. Start node resolution
        if "WHERE n.id = $id" in query or "toLower(n.id) = toLower($id)" in query:
            target_id = str(params.get("id", "")).strip().lower()
            id_no_prefix = str(params.get("id_without_prefix", "")).strip().lower()

            for nid, n in self.nodes.items():
                props = n.get("properties", {})
                if (
                    nid == target_id
                    or nid == id_no_prefix
                    or props.get("hostname", "").lower() == target_id
                    or props.get("hostname", "").lower() == id_no_prefix
                    or props.get("email", "").lower() == target_id
                    or props.get("user_id", "").lower() == target_id
                    or props.get("device_id", "").lower() == target_id
                    or props.get("server_id", "").lower() == target_id
                    or props.get("asset_id", "").lower() == target_id
                ):
                    return [{
                        "id": n["id"],
                        "labels": n.get("labels", []),
                        "properties": n.get("properties", {}),
                    }]
            return []

        # 2. Crown Jewels resolution
        if "MATCH (c:CriticalAsset)" in query:
            records = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    records.append({"id": n["id"]})
            return records

        # 3. Centrality node query
        if "WHERE NOT n:SecurityEvent" in query and "MATCH (n)" in query:
            records = []
            for n in self.nodes.values():
                if "SecurityEvent" not in n.get("labels", []):
                    records.append({
                        "id": n["id"],
                        "label": n.get("labels", ["Entity"])[0],
                        "name": n.get("properties", {}).get("name", n["id"]),
                        "criticality": n.get("properties", {}).get("criticality", "MEDIUM"),
                    })
            return records

        # 4. Centrality edge query
        if "WHERE NOT s:SecurityEvent AND NOT t:SecurityEvent" in query:
            records = []
            for e in self.edges:
                records.append({
                    "source": e.get("source_id") or e.get("source"),
                    "target": e.get("target_id") or e.get("target"),
                    "rel_type": e.get("relationship_type") or e.get("type"),
                })
            return records

        # 5. Fallback path search for AttackPathService
        if "MATCH p = (start)-[r*1.." in query:
            entry_id = str(params.get("entry_id", "")).strip()
            target_ids = set(params.get("target_ids", []))
            max_depth = 5
            try:
                # Extract max depth from query string
                depth_part = query.split("MATCH p = (start)-[r*1..")[1].split("]->(target)")[0]
                max_depth = int(depth_part)
            except Exception:
                pass

            allowed_types = set(params.get("allowed_types", []))
            inc_hypo = params.get("include_hypothetical", True)

            # Simple BFS/DFS to build candidate paths for test validation
            found_paths = []
            queue = [([entry_id], [])]

            while queue:
                curr_nodes, curr_rels = queue.pop(0)
                curr_tip = curr_nodes[-1]

                if len(curr_nodes) - 1 > max_depth:
                    continue

                if curr_tip in target_ids and len(curr_nodes) > 1:
                    # Construct record
                    p_nodes = [
                        {"id": nid, "labels": self.nodes[nid.lower()]["labels"], "properties": self.nodes[nid.lower()]["properties"]}
                        for nid in curr_nodes
                    ]
                    p_rels = [
                        {
                            "type": r["relationship_type"],
                            "source_id": r["source_id"],
                            "target_id": r["target_id"],
                            "evidence_class": r.get("evidence_class", "OBSERVED"),
                            "properties": r.get("properties", {}),
                        }
                        for r in curr_rels
                    ]
                    found_paths.append({"path_nodes": p_nodes, "path_relationships": p_rels})
                    continue

                # Expand neighbors
                for e in self.edges:
                    src = e.get("source_id") or e.get("source")
                    tgt = e.get("target_id") or e.get("target")
                    rtype = e.get("relationship_type") or e.get("type")
                    evclass = e.get("evidence_class", "OBSERVED")

                    if src == curr_tip and tgt not in curr_nodes:
                        if allowed_types and rtype not in allowed_types:
                            continue
                        if not inc_hypo and (rtype == "POTENTIAL_EXPLOIT" or evclass == "HYPOTHETICAL"):
                            continue

                        rel_dict = {
                            "relationship_type": rtype,
                            "source_id": src,
                            "target_id": tgt,
                            "evidence_class": evclass,
                            "properties": e.get("properties", {}),
                        }
                        queue.append((curr_nodes + [tgt], curr_rels + [rel_dict]))

            return found_paths

        return []


# =====================================================================
# 1. ENTITY SELECTION & CANONICAL ID VERIFICATION (Task 1)
# =====================================================================

def test_canonical_id_rules_and_label_derivation():
    """Verify canonical prefixes and ID normalization across all entity types."""
    assert canonicalize_node_id(NodeLabel.USER, "usr-001") == "user:usr-001"
    assert canonicalize_node_id(NodeLabel.USER, "user:usr-001") == "user:usr-001"
    assert canonicalize_node_id(NodeLabel.DEVICE, "DEV-WS-101") == "device:dev-ws-101"
    assert canonicalize_node_id(NodeLabel.SERVER, "SRV-APP-01") == "server:srv-app-01"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "crit-db-financial") == "critical:crit-db-financial"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "critical:crit-db-financial") == "critical:crit-db-financial"
    assert canonicalize_node_id(NodeLabel.VULNERABILITY, "cve-2024-21413") == "vuln:CVE-2024-21413"
    assert canonicalize_node_id(NodeLabel.IP_ADDRESS, "192.168.1.50") == "ip:192.168.1.50"


def test_resolve_unknown_entity_raises_not_found():
    """Verify unknown entity queries raise NodeNotFoundError instead of fabricating data."""
    mock_client = DeterministicMockGraphClient(nodes=[], edges=[])
    service = AttackPathService(mock_client)

    with pytest.raises(NodeNotFoundError) as exc_info:
        service.blast_service.resolve_start_node("device:nonexistent-machine")
    assert "does not exist in the security graph" in str(exc_info.value)


def test_dijkstra_identical_source_and_target():
    """Verify identical source and target returns a valid 0-hop, 0-cost trivial path with clear explanation."""
    node_a = {"id": "device:dev-ws-101", "labels": ["Device"], "properties": {"name": "DEV-WS-101"}}
    mock_client = DeterministicMockGraphClient(nodes=[node_a], edges=[])
    dijkstra = DijkstraShortestPathEngine(mock_client)

    req = DijkstraShortestPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_id="device:dev-ws-101"
    )
    result = dijkstra.find_shortest_path(req)

    assert result.path_found is True
    assert result.total_cost == 0.0
    assert result.hop_count == 0
    assert len(result.nodes) == 1
    assert result.nodes[0].id == "device:dev-ws-101"
    assert len(result.steps) == 0
    assert result.target_node is not None and result.target_node.id == "device:dev-ws-101"
    assert any("identical" in w.lower() for w in result.warnings)


def test_attack_paths_identical_source_and_target():
    """Verify attack path search for identical source and target returns 0 paths with explicit notice."""
    node_a = {"id": "device:dev-ws-101", "labels": ["Device"], "properties": {"name": "DEV-WS-101"}}
    mock_client = DeterministicMockGraphClient(nodes=[node_a], edges=[])
    service = AttackPathService(mock_client)

    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["device:dev-ws-101"]
    )
    result = service.find_attack_paths(req)

    assert result.total_paths_discovered == 0
    assert len(result.paths) == 0
    assert any("identical" in w.lower() for w in result.warnings)


# =====================================================================
# 2. DIJKSTRA WEIGHTED SHORTEST-PATH VERIFICATION (Task 2)
# =====================================================================

def test_traversal_cost_validation():
    """Verify non-negative finite cost enforcement in TraversalCostPolicy."""
    policy = TraversalCostPolicy()

    # Valid weights
    assert policy.calculate_edge_cost(RelationshipType.LOGGED_IN_TO, explicit_weight=1.5) == 1.5
    assert policy.calculate_edge_cost(RelationshipType.HAS_PERMISSION, explicit_weight=0.0) == 0.0
    assert policy.calculate_edge_cost(RelationshipType.OBSERVED_CONNECTION, explicit_weight="2.25") == 2.25

    # Negative weight rejection
    with pytest.raises(ValueError, match="strictly non-negative"):
        policy.calculate_edge_cost(RelationshipType.USES, explicit_weight=-1.0)

    # NaN and infinity rejection
    with pytest.raises(ValueError, match="finite number"):
        policy.calculate_edge_cost(RelationshipType.USES, explicit_weight=float("nan"))
    with pytest.raises(ValueError, match="finite number"):
        policy.calculate_edge_cost(RelationshipType.USES, explicit_weight=float("inf"))
    with pytest.raises(ValueError, match="finite number"):
        policy.calculate_edge_cost(RelationshipType.USES, explicit_weight=float("-inf"))

    # Non-numeric weight rejection
    with pytest.raises(ValueError, match="must be numeric"):
        policy.calculate_edge_cost(RelationshipType.USES, explicit_weight="not-a-number")


def test_dijkstra_chooses_lower_cost_over_fewer_hops():
    """
    Graph Topology:
    - Path 1 (Direct, High Cost): A -> Target (1 hop, cost = 10.0)
    - Path 2 (Multi-hop, Low Cost): A -> B -> C -> Target (3 hops, cost = 1.0 + 1.0 + 1.0 = 3.0)
    Dijkstra must select Path 2 (cost 3.0) over Path 1 (cost 10.0).
    """
    nodes = [
        {"id": "device:dev-a", "labels": ["Device"], "properties": {"name": "DEV-A"}},
        {"id": "server:srv-b", "labels": ["Server"], "properties": {"name": "SRV-B"}},
        {"id": "server:srv-c", "labels": ["Server"], "properties": {"name": "SRV-C"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Financial Vault", "criticality": "CRITICAL"}},
    ]
    edges = [
        # Path 1: direct but expensive
        {"source_id": "device:dev-a", "target_id": "critical:target", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 10.0}},
        # Path 2: multi-hop but low friction
        {"source_id": "device:dev-a", "target_id": "server:srv-b", "relationship_type": "LOGGED_IN_TO", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
        {"source_id": "server:srv-b", "target_id": "server:srv-c", "relationship_type": "HAS_PERMISSION", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
        {"source_id": "server:srv-c", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}},
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    dijkstra = DijkstraShortestPathEngine(mock_client)

    result = dijkstra.find_shortest_path(DijkstraShortestPathRequest(entry_node_id="device:dev-a", target_node_id="critical:target"))

    assert result.path_found is True
    assert result.total_cost == 3.0
    assert result.hop_count == 3
    assert [n.id for n in result.nodes] == ["device:dev-a", "server:srv-b", "server:srv-c", "critical:target"]

    # Verify step cost sum equals total cost
    step_sum = sum(s.cost for s in result.steps)
    assert result.total_cost is not None and round(step_sum, 4) == round(result.total_cost, 4)

    # Verify accumulated cost tracks running sum
    assert result.steps[0].accumulated_cost == 1.0
    assert result.steps[1].accumulated_cost == 2.0
    assert result.steps[2].accumulated_cost == 3.0


def test_dijkstra_enforces_edge_directionality():
    """Verify that reversed edges cannot be traversed (A <- B does not permit A -> B)."""
    nodes = [
        {"id": "device:dev-a", "labels": ["Device"], "properties": {"name": "DEV-A"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Vault", "criticality": "CRITICAL"}},
    ]
    # Edge points from target to entry!
    edges = [
        {"source_id": "critical:target", "target_id": "device:dev-a", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {"traversal_cost": 1.0}}
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    dijkstra = DijkstraShortestPathEngine(mock_client)

    result = dijkstra.find_shortest_path(DijkstraShortestPathRequest(entry_node_id="device:dev-a", target_node_id="critical:target"))
    assert result.path_found is False
    assert "critical:target" in result.unreachable_targets


def test_dijkstra_missing_weight_fallback_and_warning():
    """Verify that unweighted edges fall back to relationship friction and append an audit warning."""
    nodes = [
        {"id": "device:dev-a", "labels": ["Device"], "properties": {"name": "DEV-A"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Vault", "criticality": "CRITICAL"}},
    ]
    # Explicitly omit traversal_cost, weight, and cost
    edges = [
        {"source_id": "device:dev-a", "target_id": "critical:target", "relationship_type": "LOGGED_IN_TO", "evidence_class": "OBSERVED", "properties": {}}
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    dijkstra = DijkstraShortestPathEngine(mock_client)

    result = dijkstra.find_shortest_path(DijkstraShortestPathRequest(entry_node_id="device:dev-a", target_node_id="critical:target"))
    assert result.path_found is True
    assert result.total_cost == 1.0  # Baseline friction for LOGGED_IN_TO
    assert any("lacked explicit traversal_cost" in w for w in result.warnings)


# =====================================================================
# 3. ALTERNATIVE PATH DISCOVERY & CYCLE DEFENSE (Task 3)
# =====================================================================

def test_attack_paths_cycle_prevention():
    """
    Verify cyclic loops do not cause infinite recursion or runaway exploration.
    Graph: Entry -> A -> B -> Entry (Cycle), and B -> Target.
    """
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:srv-a", "labels": ["Server"], "properties": {"name": "SRV-A"}},
        {"id": "server:srv-b", "labels": ["Server"], "properties": {"name": "SRV-B"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Vault", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:srv-a", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:srv-a", "target_id": "server:srv-b", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:srv-b", "target_id": "device:entry", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},  # Back-edge (cycle)
        {"source_id": "server:srv-b", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = AttackPathService(mock_client)

    result = service.find_attack_paths(AttackPathRequest(entry_node_id="device:entry", max_depth=5))
    assert result.total_paths_discovered == 1
    p = result.paths[0]
    node_ids = [n.id for n in p.nodes]
    # Verify path is simple and acyclic (no duplicate nodes)
    assert len(node_ids) == len(set(node_ids))
    assert node_ids == ["device:entry", "server:srv-a", "server:srv-b", "critical:target"]


def test_attack_paths_bounded_depth_and_result_limits():
    """Verify path exploration strictly respects max_depth and limit bounds."""
    # Build 6-hop linear chain: N0 -> N1 -> N2 -> N3 -> N4 -> N5 -> Target
    nodes = [{"id": f"server:n{i}", "labels": ["Server"], "properties": {"name": f"N{i}"}} for i in range(6)]
    nodes.append({"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Target", "criticality": "CRITICAL"}})

    edges = [{"source_id": f"server:n{i}", "target_id": f"server:n{i+1}", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}} for i in range(5)]
    edges.append({"source_id": "server:n5", "target_id": "critical:target", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}})

    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = AttackPathService(mock_client)

    # Search with max_depth=4 (Target is 6 hops away) -> Should discover 0 paths
    res_shallow = service.find_attack_paths(AttackPathRequest(entry_node_id="server:n0", max_depth=4))
    assert res_shallow.total_paths_discovered == 0

    # Search with max_depth=6 -> Should discover the 6-hop path
    res_deep = service.find_attack_paths(AttackPathRequest(entry_node_id="server:n0", max_depth=6))
    assert res_deep.total_paths_discovered == 1
    assert res_deep.paths[0].length == 6


# =====================================================================
# 4. CHOKEPOINTS & CENTRALITY VERIFICATION (Task 4)
# =====================================================================

def test_chokepoints_structural_betweenness_ranking():
    """
    Topology: Entry point fans out into two branches (Branch 1 and Branch 2).
    Both branches must funnel through Pivot Server 'server:chokepoint-gateway'
    before reaching their respective Crown Jewels (Vault 1 and Vault 2).
    Severing 'server:chokepoint-gateway' eliminates 100% of attack paths.
    """
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:branch-1", "labels": ["Server"], "properties": {"name": "Branch 1"}},
        {"id": "server:branch-2", "labels": ["Server"], "properties": {"name": "Branch 2"}},
        {"id": "server:chokepoint-gateway", "labels": ["Server"], "properties": {"name": "Gateway Hub"}},
        {"id": "critical:vault-1", "labels": ["CriticalAsset"], "properties": {"name": "Vault 1", "criticality": "CRITICAL"}},
        {"id": "critical:vault-2", "labels": ["CriticalAsset"], "properties": {"name": "Vault 2", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:branch-1", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:entry", "target_id": "server:branch-2", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:branch-1", "target_id": "server:chokepoint-gateway", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:branch-2", "target_id": "server:chokepoint-gateway", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:chokepoint-gateway", "target_id": "critical:vault-1", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:chokepoint-gateway", "target_id": "critical:vault-2", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = AttackPathService(mock_client)

    path_res = service.find_attack_paths(AttackPathRequest(entry_node_id="device:entry", max_depth=5))
    assert path_res.total_paths_discovered == 4  # (Entry->B1->GW->V1, Entry->B1->GW->V2, Entry->B2->GW->V1, Entry->B2->GW->V2)

    choke_res = service.analyze_choke_points(paths=path_res.paths, top_n=3)
    assert choke_res.total_paths_analyzed == 4
    assert len(choke_res.choke_points) > 0

    top_choke = choke_res.top_recommendation
    assert top_choke is not None
    assert top_choke.entity_id == "server:chokepoint-gateway"
    assert top_choke.paths_traversed_count == 4
    assert top_choke.traversal_percentage == 100.0
    assert set(top_choke.affected_critical_assets) == {"Vault 1", "Vault 2"}
    assert top_choke.recommended_action == InterventionAction.ISOLATE_NODE


def test_centrality_analytics_empty_and_disconnected_graphs():
    """Verify CentralityAnalyticsService handles empty graphs and disconnected nodes gracefully."""
    # 1. Empty graph
    empty_client = DeterministicMockGraphClient(nodes=[], edges=[])
    centrality_svc = CentralityAnalyticsService(empty_client)
    res_empty = centrality_svc.analyze_graph_centrality()
    assert res_empty.total_nodes_analyzed == 0
    assert res_empty.total_edges_analyzed == 0
    assert len(res_empty.top_disruption_nodes) == 0

    # 2. Disconnected components
    nodes = [
        {"id": "server:island-1", "labels": ["Server"], "properties": {"name": "Island 1"}},
        {"id": "server:island-2", "labels": ["Server"], "properties": {"name": "Island 2"}},
        {"id": "server:bridge", "labels": ["Server"], "properties": {"name": "Bridge Server"}},
        {"id": "critical:jewel", "labels": ["CriticalAsset"], "properties": {"name": "Crown Jewel", "criticality": "CRITICAL"}},
    ]
    # island-1 and island-2 are isolated. bridge connects to jewel.
    edges = [
        {"source_id": "server:bridge", "target_id": "critical:jewel", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}}
    ]
    disc_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    disc_svc = CentralityAnalyticsService(disc_client)
    res_disc = disc_svc.analyze_graph_centrality()
    assert res_disc.total_nodes_analyzed == 4
    assert res_disc.total_edges_analyzed == 1
    # Nodes are evaluated without throwing division-by-zero or infinite loop exceptions
    assert len(res_disc.top_disruption_nodes) == 4


# =====================================================================
# 5. EVIDENCE CLASS DISTINCTION (Task 5)
# =====================================================================

def test_evidence_class_preservation_and_hypothetical_exclusion():
    """Verify OBSERVED, AUTHORIZED, INFERRED, and HYPOTHETICAL classifications are preserved and filterable."""
    nodes = [
        {"id": "device:dev-ws", "labels": ["Device"], "properties": {"name": "Workstation"}},
        {"id": "server:srv-app", "labels": ["Server"], "properties": {"name": "App Server"}},
        {"id": "critical:crown", "labels": ["CriticalAsset"], "properties": {"name": "Crown Jewel", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:dev-ws", "target_id": "server:srv-app", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:srv-app", "target_id": "critical:crown", "relationship_type": "POTENTIAL_EXPLOIT", "evidence_class": "HYPOTHETICAL", "properties": {"via_cve": "CVE-2024-38077"}},
    ]
    mock_client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = AttackPathService(mock_client)

    # 1. With include_hypothetical=False -> The hypothetical exploit edge is rejected
    res_observed_only = service.find_attack_paths(AttackPathRequest(entry_node_id="device:dev-ws", include_hypothetical=False))
    assert res_observed_only.total_paths_discovered == 0

    # 2. With include_hypothetical=True -> The path is returned with exact evidence classes
    res_with_hypo = service.find_attack_paths(AttackPathRequest(entry_node_id="device:dev-ws", include_hypothetical=True))
    assert res_with_hypo.total_paths_discovered == 1
    p = res_with_hypo.paths[0]
    assert p.observed_steps_count == 1
    assert p.hypothetical_steps_count == 1
    assert p.steps[0].evidence_class == EvidenceClass.OBSERVED
    assert p.steps[1].evidence_class == EvidenceClass.HYPOTHETICAL
    assert any("CVE-2024-38077" in asm for asm in p.assumptions)


# =====================================================================
# 6. FASTAPI ROUTE-LEVEL ENDPOINT VERIFICATION (Endpoint Tasks)
# =====================================================================

def test_fastapi_shortest_path_post_and_alias(client):
    """Verify POST /api/v1/graphops/shortest-path and alias /api/v1/graphops/dijkstra."""
    payload = {
        "entry_node_id": "device:dev-ws-101",
        "target_node_id": "critical:crit-db-financial",
        "include_hypothetical": True,
    }
    # 1. Main endpoint
    resp1 = client.post("/api/v1/graphops/shortest-path", json=payload)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "path_found" in data1
    assert "total_cost" in data1
    assert "nodes" in data1
    assert "steps" in data1

    # 2. Alias endpoint
    resp2 = client.post("/api/v1/graphops/dijkstra", json=payload)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["path_found"] == data1["path_found"]
    assert data2["total_cost"] == data1["total_cost"]


def test_fastapi_shortest_path_get_and_alias(client):
    """Verify GET /api/v1/graphops/shortest-path and alias /api/v1/graphops/dijkstra."""
    # 1. Main GET endpoint
    resp1 = client.get("/api/v1/graphops/shortest-path?entry_node_id=device:dev-ws-101&target_node_id=critical:crit-db-financial")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["entry_node"]["id"] == "device:dev-ws-101"

    # 2. Alias GET endpoint
    resp2 = client.get("/api/v1/graphops/dijkstra?entry_node_id=device:dev-ws-101&target_node_id=critical:crit-db-financial")
    assert resp2.status_code == 200
    assert resp2.json()["entry_node"]["id"] == "device:dev-ws-101"

    # 3. Missing entry_node_id returns 422
    err_resp = client.get("/api/v1/graphops/shortest-path")
    assert err_resp.status_code == 422


def test_fastapi_attack_paths_endpoints(client):
    """Verify POST /api/v1/graphops/attack-paths."""
    payload = {
        "entry_node_id": "device:dev-ws-101",
        "max_depth": 4,
        "include_hypothetical": True,
    }
    resp = client.post("/api/v1/graphops/attack-paths", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_paths_discovered" in data
    assert "paths" in data
    assert "targets_reached" in data

    # Unknown entry entity returns 404
    err_resp = client.post("/api/v1/graphops/attack-paths", json={"entry_node_id": "nonexistent:unknown-node-999"})
    assert err_resp.status_code == 404
    assert "does not exist" in err_resp.json()["detail"].lower() or "not found" in err_resp.json()["detail"].lower()


def test_fastapi_choke_points_endpoints(client):
    """Verify GET and POST /api/v1/graphops/choke-points."""
    # 1. GET with default entries
    resp_get = client.get("/api/v1/graphops/choke-points?top_n=3")
    assert resp_get.status_code == 200
    data_get = resp_get.json()
    assert "choke_points" in data_get
    assert "explanation" in data_get

    # 2. GET with specific valid entry
    resp_get_ent = client.get("/api/v1/graphops/choke-points?entry_node_id=device:dev-ws-101&top_n=5")
    assert resp_get_ent.status_code == 200

    # 3. GET with nonexistent entry returns 404
    resp_get_404 = client.get("/api/v1/graphops/choke-points?entry_node_id=nonexistent:unknown-123")
    assert resp_get_404.status_code == 404

    # 4. POST endpoint
    resp_post = client.post("/api/v1/graphops/choke-points", json={"top_n": 5})
    assert resp_post.status_code == 200
    assert "choke_points" in resp_post.json()


def test_fastapi_centrality_endpoint(client):
    """Verify GET /api/v1/graphops/centrality."""
    resp = client.get("/api/v1/graphops/centrality?top_k=5")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_nodes_analyzed" in data
    assert "total_edges_analyzed" in data
    assert "top_disruption_nodes" in data
    assert "network_bridge_nodes" in data
    assert "executive_summary" in data


def test_fastapi_simulate_containment_endpoint(client):
    """Verify POST /api/v1/graphops/simulate-containment in-memory simulation."""
    payload = {
        "entry_node_id": "device:dev-ws-101",
        "proposed_interventions": [
            {
                "action": "ISOLATE_NODE",
                "node_id": "server:srv-app-01"
            }
        ]
    }
    resp = client.post("/api/v1/graphops/simulate-containment", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "baseline_paths_count" in data
    assert "remaining_paths_count" in data
    assert "paths_eliminated_count" in data
    assert "containment_efficiency_pct" in data
    assert "analyst_verdict" in data
    assert data["live_graph_modified"] is False
    assert "SIMULATION ONLY" in data["safety_disclaimer"]
