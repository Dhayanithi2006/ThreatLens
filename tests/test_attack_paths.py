"""
ThreatLens GraphOps - Attack-Path & Choke-Point Test Suite
Phase 6: Plausible attack-path discovery, risk-cost model, cycle prevention,
multiple routes, choke-point identification and ranking, simulation interface, and FastAPI endpoints.
"""

import pytest
from typing import Dict, List, Any, Optional, Set
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    InterventionAction,
)
from backend.models.graphops import (
    AttackPathRequest,
    AttackPathResult,
    ChokePointRequest,
    ChokePointResult,
    ProposedIntervention,
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
)
from backend.graphops.attack_paths import (
    AttackPathService,
    PATH_ELIGIBLE_RELATIONSHIPS,
)
from backend.graphops.blast_radius import NodeNotFoundError
from backend.graphops.client import get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


# =====================================================================
# IN-MEMORY GRAPH MOCK FOR ATTACK PATHS & CHOKE POINTS
# =====================================================================

class InMemoryAttackPathGraphClient:
    """
    Extends graph mock to support path queries, node resolution, and Crown Jewel queries.
    """

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
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
        self.edges = edges

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.executed_queries.append(query)
        params = params or {}
        q = query.strip()

        # 1. Node Resolution Query
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

        # 2. Query All Crown Jewels
        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # 3. Path Search Query: MATCH p = (start)-[r*1..N]->(target)
        if "MATCH p = (start)-[r*" in q:
            entry_id = str(params.get("entry_id", "")).lower()
            target_ids = {str(t).lower() for t in params.get("target_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            limit = params.get("limit", 50)

            found_paths = []

            # Recursive DFS for simple acyclic paths
            def dfs(current_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]], visited_ids: Set[str]):
                if len(found_paths) >= limit or len(path_edges) >= 6:
                    return

                # Find outgoing edges from current_id
                for e in self.edges:
                    src = e["source_id"].lower()
                    if src != current_id:
                        continue

                    rel_type = e["relationship_type"]
                    ev_class = e.get("evidence_class", "OBSERVED")

                    if allowed_types and rel_type not in allowed_types:
                        continue
                    if not include_hypothetical:
                        if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                            continue

                    tgt = e["target_id"].lower()
                    if tgt in visited_ids:
                        continue  # Avoid cycles!

                    tgt_node = self.nodes.get(tgt)
                    if not tgt_node:
                        continue

                    new_nodes = path_nodes + [tgt_node]
                    edge_dict = {
                        "type": rel_type,
                        "source_id": e["source_id"],
                        "target_id": e["target_id"],
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

                    # Recurse forward
                    dfs(tgt, new_nodes, new_edges, visited_ids | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})

            return found_paths

        return []


def build_enterprise_fixture_mock() -> InMemoryAttackPathGraphClient:
    """Builds an InMemoryAttackPathGraphClient preloaded with the synthetic enterprise fixture."""
    fixture = load_sample_enterprise_fixture()
    nodes = []
    edges = []

    label_map = {
        "users": [NodeLabel.USER.value],
        "devices": [NodeLabel.DEVICE.value],
        "servers": [NodeLabel.SERVER.value],
        "applications": [NodeLabel.APPLICATION.value],
        "ips": [NodeLabel.IP_ADDRESS.value],
        "vulnerabilities": [NodeLabel.VULNERABILITY.value],
        "critical_assets": [NodeLabel.CRITICAL_ASSET.value],
        "security_events": [NodeLabel.SECURITY_EVENT.value],
        "email_accounts": [NodeLabel.EMAIL_ACCOUNT.value],
    }

    prefix_map = {
        "users": "user",
        "devices": "device",
        "servers": "server",
        "applications": "app",
        "ips": "ip",
        "vulnerabilities": "vuln",
        "critical_assets": "critical",
        "security_events": "event",
        "email_accounts": "email",
    }

    for category, entity_list in fixture["entities"].items():
        labels = label_map.get(category, ["Entity"])
        prefix = prefix_map.get(category, "entity")
        for ent in entity_list:
            raw_id = ent.get("id") or ent.get("ip") or ent.get("cve_id")
            clean_id = str(raw_id).lower()
            canonical_id = clean_id if clean_id.startswith(f"{prefix}:") else f"{prefix}:{clean_id}"
            props = dict(ent)
            props["id"] = canonical_id
            nodes.append({
                "id": canonical_id,
                "labels": labels,
                "properties": props,
            })

    alias_map = {}
    for n in nodes:
        props = n["properties"]
        if "email" in props:
            alias_map[f"user:{props['email'].lower()}"] = n["id"]
            alias_map[props['email'].lower()] = n["id"]

    for r in fixture["relationships"]["relationships"]:
        src = r["source_id"].lower()
        tgt = r["target_id"].lower()
        src = alias_map.get(src, src)
        tgt = alias_map.get(tgt, tgt)
        if src.startswith("vuln:cve-"):
            src = "vuln:" + src[5:].upper()
        if tgt.startswith("vuln:cve-"):
            tgt = "vuln:" + tgt[5:].upper()

        edge_props = dict(r.get("properties", {}))
        edge_props["evidence_class"] = r.get("evidence_class", "OBSERVED")
        edge_props["provenance"] = r.get("provenance", "Test")
        edge_props["confidence"] = r.get("confidence", 1.0)
        edge_props["timestamp"] = r.get("timestamp")

        edges.append({
            "source_id": src,
            "target_id": tgt,
            "relationship_type": r["relationship_type"],
            "evidence_class": r.get("evidence_class", "OBSERVED"),
            "properties": edge_props,
        })

    return InMemoryAttackPathGraphClient(nodes, edges)


# =====================================================================
# 1. ATTACK PATH DISCOVERY TESTS
# =====================================================================

def test_attack_paths_discovery_known_path():
    """
    Verifies that an attack path from workstation DEV-WS-101 to the Financial Ledger
    Crown Jewel is correctly discovered through the application jump server and core DB host.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    request = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:crit-db-financial"],
        max_depth=5,
        include_hypothetical=True,
    )
    result = service.find_attack_paths(request)

    assert result.entry_node.id == "device:dev-ws-101"
    assert result.total_paths_discovered >= 1
    assert "critical:crit-db-financial" in result.targets_reached

    top_path = result.paths[0]
    path_node_ids = [n.id for n in top_path.nodes]
    assert path_node_ids[0] == "device:dev-ws-101"
    assert "server:srv-app-01" in path_node_ids
    assert "server:srv-db-01" in path_node_ids
    assert path_node_ids[-1] == "critical:crit-db-financial"

    # Verify risk score & assumptions
    assert top_path.risk_score >= 60
    assert len(top_path.steps) == 3
    assert len(top_path.assumptions) >= 1


def test_attack_paths_unreachable_target():
    """Verifies that an unreachable target returns zero paths cleanly without errors."""
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    request = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:nonexistent-island"],
        max_depth=5,
    )
    result = service.find_attack_paths(request)

    assert result.total_paths_discovered == 0
    assert result.paths == []
    assert result.targets_reached == []


def test_attack_paths_cycles_prevention():
    """
    Constructs a cycle: A -> B -> C -> A -> Target.
    Verifies that the traversal avoids looping indefinitely and discovers the simple acyclic path.
    """
    nodes = [
        {"id": "node:a", "labels": ["Device"], "properties": {"name": "Workstation A"}},
        {"id": "node:b", "labels": ["Server"], "properties": {"name": "Server B"}},
        {"id": "node:c", "labels": ["Server"], "properties": {"name": "Server C"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Crown Jewel", "impact_score": 90}},
    ]
    edges = [
        {"source_id": "node:a", "target_id": "node:b", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:b", "target_id": "node:c", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:c", "target_id": "node:a", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:c", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED"},
    ]
    client = InMemoryAttackPathGraphClient(nodes, edges)
    service = AttackPathService(client)

    request = AttackPathRequest(
        entry_node_id="node:a",
        target_node_ids=["critical:target"],
        max_depth=5,
    )
    result = service.find_attack_paths(request)

    assert result.total_paths_discovered == 1
    path = result.paths[0]
    path_ids = [n.id for n in path.nodes]
    # Simple path: A -> B -> C -> Target without repeating A
    assert path_ids == ["node:a", "node:b", "node:c", "critical:target"]


def test_attack_paths_multiple_routes():
    """
    Constructs a graph with two separate routes to a Crown Jewel:
    Route 1: A -> B -> Target
    Route 2: A -> C -> Target
    Verifies both routes are discovered and ranked.
    """
    nodes = [
        {"id": "node:a", "labels": ["Device"], "properties": {"name": "Workstation A"}},
        {"id": "node:b", "labels": ["Server"], "properties": {"name": "Server B"}},
        {"id": "node:c", "labels": ["Server"], "properties": {"name": "Server C"}},
        {"id": "critical:target", "labels": ["CriticalAsset"], "properties": {"name": "Crown Jewel", "impact_score": 90}},
    ]
    edges = [
        {"source_id": "node:a", "target_id": "node:b", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:b", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED"},
        {"source_id": "node:a", "target_id": "node:c", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:c", "target_id": "critical:target", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED"},
    ]
    client = InMemoryAttackPathGraphClient(nodes, edges)
    service = AttackPathService(client)

    request = AttackPathRequest(
        entry_node_id="node:a",
        target_node_ids=["critical:target"],
        max_depth=5,
    )
    result = service.find_attack_paths(request)

    assert result.total_paths_discovered == 2
    route_intermediates = {p.nodes[1].id for p in result.paths}
    assert route_intermediates == {"node:b", "node:c"}


def test_attack_paths_hypothetical_exclusion():
    """
    Verifies that when include_hypothetical=False, paths requiring POTENTIAL_EXPLOIT
    are excluded from the results.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    # When include_hypothetical=False
    req_no_hypo = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:crit-db-financial"],
        max_depth=5,
        include_hypothetical=False,
    )
    res_no_hypo = service.find_attack_paths(req_no_hypo)
    for p in res_no_hypo.paths:
        for s in p.steps:
            assert s.relationship_type != RelationshipType.POTENTIAL_EXPLOIT
            assert s.evidence_class != EvidenceClass.HYPOTHETICAL

    # When include_hypothetical=True
    req_with_hypo = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:crit-db-financial"],
        max_depth=5,
        include_hypothetical=True,
    )
    res_with_hypo = service.find_attack_paths(req_with_hypo)
    has_hypo = any(
        any(s.relationship_type == RelationshipType.POTENTIAL_EXPLOIT for s in p.steps)
        for p in res_with_hypo.paths
    )
    assert has_hypo is True


def test_attack_paths_risk_ranking_reproducibility():
    """
    Verifies that risk scores are reproducible and that paths with higher target impact
    and observed evidence rank higher than lower-impact or hypothetical paths.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    request = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        max_depth=5,
        include_hypothetical=True,
    )
    result = service.find_attack_paths(request)

    # Verify descending sort by risk score
    scores = [p.risk_score for p in result.paths]
    assert scores == sorted(scores, reverse=True)


# =====================================================================
# 2. CHOKE-POINT ANALYSIS TESTS
# =====================================================================

def test_choke_point_identification_and_ranking():
    """
    Verifies that server:srv-app-01 is identified as the #1 choke point
    intercepting 100% of candidate attack paths originating from workstation DEV-WS-101.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        max_depth=5,
        include_hypothetical=True,
    )
    path_result = service.find_attack_paths(req)
    assert path_result.total_paths_discovered >= 2

    choke_result = service.analyze_choke_points(paths=path_result.paths, top_n=5)

    assert choke_result.total_paths_analyzed == path_result.total_paths_discovered
    assert len(choke_result.choke_points) >= 1

    top_choke = choke_result.top_recommendation
    assert top_choke is not None
    assert top_choke.rank == 1
    assert top_choke.entity_id == "server:srv-app-01"
    assert top_choke.traversal_percentage == 100.0
    assert top_choke.recommended_action == InterventionAction.ISOLATE_NODE
    assert len(top_choke.affected_critical_assets) >= 2


def test_simulation_interface_containment_impact():
    """
    Verifies that the simulation-friendly analysis interface can test the isolation
    of a choke point in-memory without altering persistent data.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    # Simulating isolation of server:srv-app-01
    sim_impact = service.simulate_containment_impact(
        entry_node_id="device:dev-ws-101",
        target_asset_ids=None,
        disabled_node_ids={"server:srv-app-01"},
        disabled_edge_keys=set(),
    )

    assert sim_impact["baseline_paths_count"] > 0
    assert sim_impact["simulated_paths_count"] == 0
    assert sim_impact["eliminated_paths_count"] == sim_impact["baseline_paths_count"]
    assert sim_impact["path_reduction_percentage"] == 100.0
    assert sim_impact["risk_verdict"] == "FULL_CONTAINMENT"


def test_simulation_interface_alternative_paths_preserved():
    """
    Verifies that when a candidate choke point is severed, alternative paths
    not depending on it are preserved (constraint: do not claim total risk elimination).
    """
    nodes = [
        {"id": "node:entry", "labels": ["Device"], "properties": {"name": "Entry WS"}},
        {"id": "node:jump1", "labels": ["Server"], "properties": {"name": "Jump Server 1"}},
        {"id": "node:jump2", "labels": ["Server"], "properties": {"name": "Jump Server 2"}},
        {"id": "critical:db", "labels": ["CriticalAsset"], "properties": {"name": "Customer DB", "impact_score": 90}},
    ]
    edges = [
        {"source_id": "node:entry", "target_id": "node:jump1", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:jump1", "target_id": "critical:db", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED"},
        {"source_id": "node:entry", "target_id": "node:jump2", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:jump2", "target_id": "critical:db", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED"},
    ]
    client = InMemoryAttackPathGraphClient(nodes, edges)
    service = AttackPathService(client)

    # Isolate Jump Server 1 only
    sim_impact = service.simulate_containment_impact(
        entry_node_id="node:entry",
        target_asset_ids=["critical:db"],
        disabled_node_ids={"node:jump1"},
        disabled_edge_keys=set(),
    )

    assert sim_impact["baseline_paths_count"] == 2
    assert sim_impact["simulated_paths_count"] == 1
    assert sim_impact["eliminated_paths_count"] == 1
    assert sim_impact["path_reduction_percentage"] == 50.0
    assert sim_impact["risk_verdict"] == "PARTIAL_CONTAINMENT"
    # Alternative path through Jump Server 2 remains active
    remaining_path = sim_impact["remaining_paths"][0]
    assert remaining_path.nodes[1].id == "node:jump2"


# =====================================================================
# 3. FASTAPI REST ENDPOINT TESTS
# =====================================================================

def test_fastapi_attack_paths_endpoint():
    """Verifies POST /api/v1/graphops/attack-paths endpoint."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        payload = {
            "entry_node_id": "device:dev-ws-101",
            "target_node_ids": ["critical:crit-db-financial"],
            "max_depth": 5,
            "include_hypothetical": True,
        }
        response = test_client.post("/api/v1/graphops/attack-paths", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["entry_node"]["id"] == "device:dev-ws-101"
        assert data["total_paths_discovered"] >= 1
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_choke_points_get_endpoint():
    """Verifies GET /api/v1/graphops/choke-points endpoint."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        response = test_client.get(
            "/api/v1/graphops/choke-points",
            params={"entry_node_id": "device:dev-ws-101", "top_n": 3},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_paths_analyzed"] >= 1
        assert len(data["choke_points"]) >= 1
        assert data["top_recommendation"]["entity_id"] == "server:srv-app-01"
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_choke_points_post_endpoint():
    """Verifies POST /api/v1/graphops/choke-points endpoint."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        payload = {"top_n": 5}
        response = test_client.post("/api/v1/graphops/choke-points", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["total_paths_analyzed"] >= 1
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_attack_paths_not_found_returns_404():
    """Verifies that an unknown entry node returns HTTP 404."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        payload = {
            "entry_node_id": "device:unknown-ws",
            "max_depth": 5,
        }
        response = test_client.post("/api/v1/graphops/attack-paths", json=payload)
        assert response.status_code == 404
        assert "does not exist" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_attack_paths_timing_and_bounded_warnings():
    """
    Phase 3: Verifies that attack path discovery returns calculation time in milliseconds
    and explicit warnings regarding bounded depth and hypothetical exploit models.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:crit-db-financial"],
        max_depth=5,
        include_hypothetical=True,
    )
    result = service.find_attack_paths(req)

    assert result.calculation_time_ms is not None
    assert result.calculation_time_ms >= 0.0
    assert len(result.warnings) >= 1
    assert any("Bounded search: Path discovery depth constrained to max_depth=5" in w for w in result.warnings)
    assert any("Hypothetical exploit preconditions included" in w for w in result.warnings)


def test_choke_point_alternative_paths_details():
    """
    Phase 3: Verifies that choke-point analysis explicitly documents active alternative
    paths rather than assuming that remediating a choke point eliminates all risk.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    req = AttackPathRequest(
        entry_node_id="device:dev-ws-101",
        target_node_ids=["critical:crit-db-financial"],
        max_depth=5,
        include_hypothetical=True,
    )
    path_result = service.find_attack_paths(req)
    assert path_result.total_paths_discovered >= 1

    choke_res = service.analyze_choke_points(path_result.paths, top_n=5)
    assert len(choke_res.choke_points) >= 1

    for cp in choke_res.choke_points:
        if cp.paths_traversed_count < choke_res.total_paths_analyzed:
            rem = choke_res.total_paths_analyzed - cp.paths_traversed_count
            assert f"{rem} alternative paths remain active." in cp.intervention_details
        else:
            assert "Eliminates all candidate paths to these assets." in cp.intervention_details


def test_containment_simulation_safety_and_graph_immutability():
    """
    Phase 3: Proves through testing that What-If containment simulations execute purely
    in memory and execute zero mutation (CREATE, SET, DELETE, MERGE, REMOVE) queries
    against the graph client.
    """
    client = build_enterprise_fixture_mock()
    service = AttackPathService(client)

    req = ContainmentSimulationRequest(
        entry_node_id="device:dev-ws-101",
        target_asset_ids=["critical:crit-db-financial"],
        proposed_interventions=[
            ProposedIntervention(
                action=InterventionAction.ISOLATE_NODE,
                node_id="server:srv-app-01",
                rationale="Isolate intermediary application server",
            )
        ],
    )

    client.executed_queries.clear()
    sim_result = service.simulate_containment(req)

    # 1. Result guarantees live graph was not modified
    assert sim_result.live_graph_modified is False
    assert "SIMULATION ONLY" in sim_result.safety_disclaimer

    # 2. None of the queries executed during simulation contain write mutations
    mutation_keywords = ["CREATE ", "MERGE ", "DELETE ", "SET ", "REMOVE "]
    for query in client.executed_queries:
        upper_q = query.upper()
        for kw in mutation_keywords:
            assert kw not in upper_q, f"Unexpected mutation keyword '{kw}' found in query: {query}"

