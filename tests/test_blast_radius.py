"""
ThreatLens GraphOps - Blast-Radius Test Suite
Phase 5: Multi-hop neighborhood traversal, minimum hop guarantees, cycle avoidance,
directionality, relationship filtering, critical asset highlighting, and FastAPI endpoints.
"""

import pytest
from typing import Dict, List, Any, Optional
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    TraversalDirection,
)
from backend.models.graphops import (
    EnterpriseNode,
    BlastRadiusRequest,
    BlastRadiusResult,
)
from backend.graphops.blast_radius import (
    BlastRadiusService,
    NodeNotFoundError,
)
from backend.graphops.client import Neo4jClient, GraphOpsConnectionError, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


# =====================================================================
# IN-MEMORY GRAPH MOCK FOR DETERMINISTIC TRAVERSAL TESTING
# =====================================================================

class InMemoryGraphClient:
    """
    Simulates Neo4j query execution over an in-memory graph definition.
    Enables deterministic testing of Cypher semantics, BFS levels, cycles, and filtering.
    """

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        # Also map alias lookups (email, hostname, user_id, etc.)
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
            # Also raw ID without prefix
            if ":" in nid:
                self.aliases[nid.split(":", 1)[1].lower()] = nid
        self.edges = edges

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        params = params or {}
        q = query.strip()

        # 1. Node Resolution Query
        if "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q:
            target_id = str(params.get("id", "")).lower()
            id_without_prefix = str(params.get("id_without_prefix", "")).lower()

            resolved_id = (
                self.nodes.get(target_id)
                or self.nodes.get(id_without_prefix)
                or self.aliases.get(target_id)
                or self.aliases.get(id_without_prefix)
            )

            if resolved_id:
                node = resolved_id if isinstance(resolved_id, dict) else self.nodes[resolved_id]
                return [{
                    "id": node["id"],
                    "labels": node.get("labels", []),
                    "properties": node.get("properties", {}),
                }]
            return []

        # 2. Frontier Edges Query
        if "frontier_ids" in params:
            frontier = [fid.lower() for fid in params.get("frontier_ids", [])]
            allowed_types = params.get("allowed_types", [])
            include_hypothetical = params.get("include_hypothetical", False)

            # Determine direction from query string
            if "(s)<-[r]-(t)" in q:
                direction = "INCOMING"
            elif "(s)-[r]-(t)" in q:
                direction = "BOTH"
            else:
                direction = "OUTGOING"

            results = []
            for e in self.edges:
                src = e["source_id"].lower()
                tgt = e["target_id"].lower()
                rel_type = e["relationship_type"]
                ev_class = e.get("evidence_class", "OBSERVED")

                # Filter by allowed relationship types
                if allowed_types and rel_type not in allowed_types:
                    continue

                # Filter hypothetical edges
                if not include_hypothetical:
                    if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
                        continue

                # Check match against frontier
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
                            "rel_source_id": e["source_id"],
                            "rel_target_id": e["target_id"],
                            "rel_props": e.get("properties", {}),
                        })

            return results

        return []


def build_enterprise_fixture_mock() -> InMemoryGraphClient:
    """Builds an InMemoryGraphClient preloaded with the synthetic enterprise fixture."""
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

    # Relationships
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

    return InMemoryGraphClient(nodes, edges)


# =====================================================================
# 1. ONE-HOP, TWO-HOP, THREE-HOP TESTS
# =====================================================================

def test_blast_radius_one_hop_outgoing():
    """Verifies that max_hops=1 returns only direct neighbors and leaves hops 2 & 3 empty."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(
        start_node_id="user:usr-101",
        max_hops=1,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert result.start_node.id == "user:usr-101"
    assert result.max_hops_evaluated == 1
    assert result.direction == TraversalDirection.OUTGOING
    assert result.hop_1.node_count == 2
    assert result.hop_2.node_count == 0
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 2

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    assert "device:dev-ws-101" in hop_1_ids
    assert "event:evt-mt101-phish" in hop_1_ids


def test_blast_radius_two_hops_outgoing():
    """Verifies that max_hops=2 correctly reaches intermediate pivot servers."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(
        start_node_id="user:usr-101",
        max_hops=2,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert result.hop_1.node_count == 2
    assert result.hop_2.node_count == 1
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 3

    assert result.hop_2.nodes[0].id == "server:srv-app-01"


def test_blast_radius_three_hops_outgoing_critical_assets():
    """
    Verifies that max_hops=3 from a workstation reaches the choke-point server
    and highlights downstream Crown Jewels with accurate shortest paths.
    """
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
        include_hypothetical=True,
    )
    result = service.calculate_blast_radius(request)

    assert result.start_node.id == "device:dev-ws-101"
    assert result.hop_1.node_count == 1
    assert result.hop_1.nodes[0].id == "server:srv-app-01"

    # Hop 2 reaches servers and apps hosted by srv-app-01
    hop_2_ids = {n.id for n in result.hop_2.nodes}
    assert "server:srv-db-01" in hop_2_ids
    assert "server:srv-dc-01" in hop_2_ids

    # Hop 3 reaches Crown Jewels stored in DB and DC
    assert result.hop_3.critical_asset_count >= 2
    assert len(result.critical_assets_at_risk) >= 2

    # Verify shortest path context
    fin_exposure = next(c for c in result.critical_assets_at_risk if "financial" in c.asset_id)
    assert fin_exposure.hop_depth == 3
    assert fin_exposure.shortest_path_nodes == [
        "device:dev-ws-101",
        "server:srv-app-01",
        "server:srv-db-01",
        "critical:crit-db-financial",
    ]
    assert fin_exposure.reachability_status == "EXPOSED"


# =====================================================================
# 2. DIRECTIONAL TRAVERSAL TESTS
# =====================================================================

def test_blast_radius_direction_incoming():
    """Verifies that INCOMING traversal follows edges in reverse to find upstream sources."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    # In incoming direction from srv-app-01, devices dev-ws-101 and dev-ws-102 connect to it
    request = BlastRadiusRequest(
        start_node_id="server:srv-app-01",
        max_hops=1,
        direction=TraversalDirection.INCOMING,
    )
    result = service.calculate_blast_radius(request)

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    assert "device:dev-ws-101" in hop_1_ids
    assert "device:dev-ws-102" in hop_1_ids


def test_blast_radius_direction_both():
    """Verifies that BOTH direction expands both inbound callers and outbound targets."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(
        start_node_id="server:srv-app-01",
        max_hops=1,
        direction=TraversalDirection.BOTH,
    )
    result = service.calculate_blast_radius(request)

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    # Inbound
    assert "device:dev-ws-101" in hop_1_ids
    # Outbound
    assert "server:srv-db-01" in hop_1_ids
    assert "app:app-erp-01" in hop_1_ids


# =====================================================================
# 3. CYCLES AND MULTI-PATH DEDUPLICATION TESTS
# =====================================================================

def test_blast_radius_cycles_and_no_infinite_loop():
    """
    Constructs a directed cycle: Node A -> Node B -> Node C -> Node A.
    Verifies that BFS avoids infinite traversal and each node is visited exactly once.
    """
    nodes = [
        {"id": "node:a", "labels": ["Server"], "properties": {"name": "Host A", "criticality": "LOW"}},
        {"id": "node:b", "labels": ["Server"], "properties": {"name": "Host B", "criticality": "LOW"}},
        {"id": "node:c", "labels": ["Server"], "properties": {"name": "Host C", "criticality": "LOW"}},
    ]
    edges = [
        {"source_id": "node:a", "target_id": "node:b", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:b", "target_id": "node:c", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:c", "target_id": "node:a", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
    ]
    client = InMemoryGraphClient(nodes, edges)
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(start_node_id="node:a", max_hops=3, direction=TraversalDirection.OUTGOING)
    result = service.calculate_blast_radius(request)

    assert result.hop_1.node_count == 1
    assert result.hop_1.nodes[0].id == "node:b"
    assert result.hop_2.node_count == 1
    assert result.hop_2.nodes[0].id == "node:c"
    # Node A is not revisited at Hop 3 because it was the starting node (depth 0)
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 2


def test_blast_radius_multiple_paths_minimum_distance():
    """
    Constructs a graph with two paths to Node C:
    Path 1: A -> C (1 hop)
    Path 2: A -> B -> C (2 hops)
    Verifies that Node C is placed strictly in hop_1 and NOT in hop_2.
    """
    nodes = [
        {"id": "node:a", "labels": ["Server"], "properties": {"name": "Host A", "criticality": "LOW"}},
        {"id": "node:b", "labels": ["Server"], "properties": {"name": "Host B", "criticality": "LOW"}},
        {"id": "node:c", "labels": ["Server"], "properties": {"name": "Host C", "criticality": "LOW"}},
    ]
    edges = [
        {"source_id": "node:a", "target_id": "node:b", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:a", "target_id": "node:c", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
        {"source_id": "node:b", "target_id": "node:c", "relationship_type": "OBSERVED_CONNECTION", "evidence_class": "OBSERVED"},
    ]
    client = InMemoryGraphClient(nodes, edges)
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(start_node_id="node:a", max_hops=2, direction=TraversalDirection.OUTGOING)
    result = service.calculate_blast_radius(request)

    # Both B and C are reachable at hop 1 directly from A
    hop_1_ids = {n.id for n in result.hop_1.nodes}
    assert hop_1_ids == {"node:b", "node:c"}
    # Hop 2 should be empty because C was already visited at hop 1
    assert result.hop_2.node_count == 0
    assert result.total_reachable_nodes == 2


def test_blast_radius_disconnected_node():
    """Verifies that an isolated node with zero edges returns zero reachable nodes without error."""
    nodes = [
        {"id": "node:isolated", "labels": ["Server"], "properties": {"name": "Isolated Server", "criticality": "LOW"}}
    ]
    client = InMemoryGraphClient(nodes, [])
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(start_node_id="node:isolated", max_hops=3)
    result = service.calculate_blast_radius(request)

    assert result.start_node.id == "node:isolated"
    assert result.total_reachable_nodes == 0
    assert result.hop_1.node_count == 0
    assert result.hop_2.node_count == 0
    assert result.hop_3.node_count == 0
    assert result.critical_assets_at_risk == []
    assert len(result.subgraph_nodes) == 1
    assert len(result.subgraph_edges) == 0
    assert "Isolated entity" in result.summary_assessment


def test_blast_radius_nonexistent_node_raises_error():
    """Verifies that an unknown start node raises NodeNotFoundError with an actionable message."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    request = BlastRadiusRequest(start_node_id="user:ghost_analyst@corporation.com", max_hops=3)
    with pytest.raises(NodeNotFoundError, match="does not exist"):
        service.calculate_blast_radius(request)


# =====================================================================
# 4. FILTERING & HYPOTHETICAL ANALYSIS TESTS
# =====================================================================

def test_blast_radius_relationship_type_filtering():
    """Verifies that specifying allowed_relationship_types restricts traversal exclusively to those kinds."""
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    # From user:usr-101, USES connects to dev-ws-101, ASSOCIATED_WITH_CASE connects to evt-mt101-phish
    request = BlastRadiusRequest(
        start_node_id="user:usr-101",
        max_hops=1,
        allowed_relationship_types=[RelationshipType.USES],
    )
    result = service.calculate_blast_radius(request)

    assert result.hop_1.node_count == 1
    assert result.hop_1.nodes[0].id == "device:dev-ws-101"


def test_blast_radius_hypothetical_edge_handling():
    """
    Verifies that POTENTIAL_EXPLOIT edges are excluded when include_hypothetical=False
    and included when include_hypothetical=True.
    """
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client=client)

    # From dev-ws-101, there is OBSERVED_CONNECTION and POTENTIAL_EXPLOIT to srv-app-01
    req_no_hypo = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=1,
        include_hypothetical=False,
    )
    res_no_hypo = service.calculate_blast_radius(req_no_hypo)
    edge_types_no_hypo = {e.relationship_type for e in res_no_hypo.subgraph_edges}
    assert RelationshipType.POTENTIAL_EXPLOIT not in edge_types_no_hypo

    req_with_hypo = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=1,
        include_hypothetical=True,
    )
    res_with_hypo = service.calculate_blast_radius(req_with_hypo)
    edge_types_with_hypo = {e.relationship_type for e in res_with_hypo.subgraph_edges}
    assert RelationshipType.POTENTIAL_EXPLOIT in edge_types_with_hypo


# =====================================================================
# 5. FASTAPI REST ENDPOINT INTEGRATION TESTS
# =====================================================================

def test_fastapi_blast_radius_get_endpoint():
    """Verifies GET /api/v1/graphops/blast-radius query endpoint."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        response = test_client.get(
            "/api/v1/graphops/blast-radius",
            params={
                "start_node_id": "user:usr-101",
                "max_hops": 2,
                "direction": "OUTGOING",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["start_node"]["id"] == "user:usr-101"
        assert data["max_hops_evaluated"] == 2
        assert data["hop_1"]["node_count"] == 2
        assert data["hop_2"]["node_count"] == 1
        assert data["total_reachable_nodes"] == 3
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_blast_radius_post_endpoint():
    """Verifies POST /api/v1/graphops/blast-radius with JSON body."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        payload = {
            "start_node_id": "device:dev-ws-101",
            "max_hops": 3,
            "direction": "OUTGOING",
            "include_hypothetical": True,
        }
        response = test_client.post("/api/v1/graphops/blast-radius", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["start_node"]["id"] == "device:dev-ws-101"
        assert len(data["critical_assets_at_risk"]) >= 2
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_blast_radius_not_found_returns_404():
    """Verifies that an unknown start node returns HTTP 404."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        response = test_client.get(
            "/api/v1/graphops/blast-radius",
            params={"start_node_id": "user:unknown@corporation.com"},
        )
        assert response.status_code == 404
        assert "does not exist" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_fastapi_blast_radius_invalid_filter_returns_422():
    """Verifies that an invalid relationship type filter returns HTTP 422."""
    mock_client = build_enterprise_fixture_mock()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        test_client = TestClient(app)
        response = test_client.get(
            "/api/v1/graphops/blast-radius",
            params={
                "start_node_id": "user:usr-101",
                "relationship_types": "INVALID_REL_KIND",
            },
        )
        assert response.status_code == 422
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_blast_radius_timing_and_bounded_warnings():
    """
    Phase 3: Verifies that blast radius calculations include execution time in milliseconds,
    bounded depth warnings, and explicit distinction between reachable exposed entities
    and confirmed compromises.
    """
    client = build_enterprise_fixture_mock()
    service = BlastRadiusService(client)

    req = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
        include_hypothetical=True,
    )
    result = service.calculate_blast_radius(req)

    # 1. Calculation time is populated
    assert result.calculation_time_ms is not None
    assert result.calculation_time_ms >= 0.0

    # 2. Warnings include bounded depth
    assert len(result.warnings) >= 1
    assert any("Bounded traversal: Traversal reached maximum evaluation limit of 3 hops" in w for w in result.warnings)
    assert any("Includes hypothetical attack transitions" in w for w in result.warnings)

    # 3. Summary assessment distinguishes exposure from compromise
    assert "Reachable assets represent architectural exposure, not confirmed compromise." in result.summary_assessment
    assert "device:dev-ws-101" in result.summary_assessment

    # 4. Hop 1, 2, 3 nodes are mutually disjoint (no entity counted multiple times)
    hop1_ids = {n.id for n in result.hop_1.nodes}
    hop2_ids = {n.id for n in result.hop_2.nodes}
    hop3_ids = {n.id for n in result.hop_3.nodes}
    assert hop1_ids.isdisjoint(hop2_ids)
    assert hop1_ids.isdisjoint(hop3_ids)
    assert hop2_ids.isdisjoint(hop3_ids)
    assert result.total_reachable_nodes == len(hop1_ids) + len(hop2_ids) + len(hop3_ids)


