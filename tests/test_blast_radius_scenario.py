"""
ThreatLens GraphOps - Blast-Radius Test Scenario Verification Suite
Isolated Test Graph Scenario:
Compromised Device A
  |--> Server A --> Server B --> Database A (Critical Asset)
  |--> Server C --------------> Database A (Critical Asset)

Additionally:
  Device B --> Server A
  Server Unrelated (Completely isolated / disconnected)

Verifies all 10 core requirements:
1. 1-hop returns only directly reachable entities (Server A, Server C).
2. 2-hop returns entities reachable within two edges (Server B, Database A).
3. 3-hop returns entities reachable within three edges (minimum distance: Database A not duplicated).
4. Starting node is NOT counted as affected.
5. Duplicate nodes are not returned across hops (Database A visited at Hop 2, excluded from Hop 3).
6. Unrelated systems (Server Unrelated) are strictly excluded.
7. Traversal direction (OUTGOING, INCOMING, BOTH) and permitted relationship types are respected.
8. Critical assets (Crown Jewels) are correctly identified with shortest paths and impact score.
9. Missing starting nodes produce appropriate 404/NodeNotFoundError errors.
10. API responses contain accurate hop counts, entity details, and non-alarmist SOC descriptions.
Also validates What-If containment simulation safety (no live graph mutations).
"""

import pytest
from typing import Dict, List, Any, Optional
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
    BlastRadiusRequest,
    ProposedIntervention,
    BlastRadiusContainmentRequest,
)
from backend.graphops.blast_radius import (
    BlastRadiusService,
    NodeNotFoundError,
)
from backend.graphops.client import get_graphops_client


# =====================================================================
# ISOLATED SCENARIO MOCK GRAPH CLIENT
# =====================================================================

class ScenarioGraphClient:
    """
    Deterministic in-memory graph client implementing the exact user test topology.
    """

    def __init__(self):
        self.nodes = {
            "device:dev-a": {
                "id": "device:dev-a",
                "labels": ["Device"],
                "properties": {
                    "id": "device:dev-a",
                    "device_id": "DEV-A",
                    "name": "Compromised Device A",
                    "hostname": "dev-a.internal.corp",
                    "criticality": "LOW",
                    "ip_address": "10.0.1.10",
                },
            },
            "device:dev-b": {
                "id": "device:dev-b",
                "labels": ["Device"],
                "properties": {
                    "id": "device:dev-b",
                    "device_id": "DEV-B",
                    "name": "Device B",
                    "hostname": "dev-b.internal.corp",
                    "criticality": "LOW",
                    "ip_address": "10.0.1.20",
                },
            },
            "server:srv-a": {
                "id": "server:srv-a",
                "labels": ["Server"],
                "properties": {
                    "id": "server:srv-a",
                    "server_id": "SRV-A",
                    "name": "Server A",
                    "hostname": "srv-a.internal.corp",
                    "criticality": "MEDIUM",
                    "ip_address": "10.0.2.10",
                },
            },
            "server:srv-b": {
                "id": "server:srv-b",
                "labels": ["Server"],
                "properties": {
                    "id": "server:srv-b",
                    "server_id": "SRV-B",
                    "name": "Server B",
                    "hostname": "srv-b.internal.corp",
                    "criticality": "HIGH",
                    "ip_address": "10.0.2.20",
                },
            },
            "server:srv-c": {
                "id": "server:srv-c",
                "labels": ["Server"],
                "properties": {
                    "id": "server:srv-c",
                    "server_id": "SRV-C",
                    "name": "Server C",
                    "hostname": "srv-c.internal.corp",
                    "criticality": "HIGH",
                    "ip_address": "10.0.2.30",
                },
            },
            "db:db-a": {
                "id": "db:db-a",
                "labels": ["Database", "CriticalAsset"],
                "properties": {
                    "id": "db:db-a",
                    "db_id": "DB-A",
                    "name": "Database A",
                    "category": "CUSTOMER_PII",
                    "criticality": "CRITICAL",
                    "impact_score": 95,
                    "is_critical": True,
                },
            },
            "server:srv-unrelated": {
                "id": "server:srv-unrelated",
                "labels": ["Server"],
                "properties": {
                    "id": "server:srv-unrelated",
                    "server_id": "SRV-UNRELATED",
                    "name": "Server Unrelated",
                    "hostname": "srv-unrelated.corp",
                    "criticality": "LOW",
                    "ip_address": "192.168.1.50",
                },
            },
        }

        self.edges = [
            # Main chain: Device A -> Server A -> Server B -> Database A
            {
                "source_id": "device:dev-a",
                "target_id": "server:srv-a",
                "relationship_type": "CONNECTS_TO",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "EDR Telemetry", "confidence": 1.0},
            },
            {
                "source_id": "server:srv-a",
                "target_id": "server:srv-b",
                "relationship_type": "CONNECTS_TO",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "NetFlow", "confidence": 1.0},
            },
            {
                "source_id": "server:srv-b",
                "target_id": "db:db-a",
                "relationship_type": "CONTAINS_CRITICAL_DATA",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "Config", "confidence": 1.0},
            },
            # Side device: Device B -> Server A
            {
                "source_id": "device:dev-b",
                "target_id": "server:srv-a",
                "relationship_type": "CONNECTS_TO",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "EDR Telemetry", "confidence": 1.0},
            },
            # Second route: Device A -> Server C -> Database A
            {
                "source_id": "device:dev-a",
                "target_id": "server:srv-c",
                "relationship_type": "CONNECTS_TO",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "Active Connection", "confidence": 1.0},
            },
            {
                "source_id": "server:srv-c",
                "target_id": "db:db-a",
                "relationship_type": "CONNECTS_TO",
                "evidence_class": "OBSERVED",
                "properties": {"provenance": "NetFlow", "confidence": 1.0},
            },
        ]

    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        params = parameters or {}
        q = query.strip()

        # 1. Start node resolution
        if "WHERE n.id =" in q or "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q or "OPTIONAL MATCH" in q:
            target_id = str(params.get("id") or params.get("clean_id") or params.get("canonical_id") or "").strip().lower()
            id_no_prefix = str(params.get("id_without_prefix") or "").strip().lower()

            for nid, n in self.nodes.items():
                props = n.get("properties", {})
                if (
                    nid == target_id
                    or nid == id_no_prefix
                    or props.get("name", "").lower() == target_id
                    or props.get("name", "").lower() == id_no_prefix
                    or props.get("hostname", "").lower() == target_id
                    or props.get("hostname", "").lower() == id_no_prefix
                    or props.get("device_id", "").lower() == target_id
                    or props.get("server_id", "").lower() == target_id
                    or props.get("db_id", "").lower() == target_id
                ):
                    return [{
                        "id": n["id"],
                        "labels": n.get("labels", []),
                        "properties": n.get("properties", {}),
                    }]
            return []

        # 2. Crown Jewels lookup
        if "MATCH (c:CriticalAsset)" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({"id": n["id"]})
            return results

        # 3. BFS Frontier edges query
        if "WHERE s.id IN $frontier_ids" in q or "s.id in $frontier_ids" in q.lower():
            frontier_ids = {str(fid).lower() for fid in params.get("frontier_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            is_incoming = "<-[r]-" in q
            is_both = "-[r]-" in q and "->" not in q and "<-" not in q

            results = []
            for e in self.edges:
                src_id = e["source_id"].lower()
                tgt_id = e["target_id"].lower()
                rel_type = e["relationship_type"]
                ev_class = e.get("evidence_class", "OBSERVED")

                if allowed_types and rel_type not in allowed_types:
                    continue
                if not include_hypothetical and (rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL"):
                    continue

                matches = []
                if is_incoming:
                    if tgt_id in frontier_ids:
                        matches.append((tgt_id, src_id))
                elif is_both:
                    if src_id in frontier_ids:
                        matches.append((src_id, tgt_id))
                    if tgt_id in frontier_ids and tgt_id != src_id:
                        matches.append((tgt_id, src_id))
                else:  # OUTGOING
                    if src_id in frontier_ids:
                        matches.append((src_id, tgt_id))

                for f_id, n_id in matches:
                    neighbor_node = self.nodes.get(n_id)
                    if neighbor_node:
                        results.append({
                            "frontier_id": self.nodes.get(f_id, {}).get("id", f_id),
                            "neighbor_id": neighbor_node["id"],
                            "neighbor_labels": neighbor_node.get("labels", []),
                            "neighbor_props": neighbor_node.get("properties", {}),
                            "rel_type": rel_type,
                            "rel_source_id": e["source_id"],
                            "rel_target_id": e["target_id"],
                            "rel_props": e.get("properties", {}),
                        })
            return results

        return []


# =====================================================================
# VERIFICATION TESTS
# =====================================================================

def test_scenario_requirement_1_one_hop_reachability():
    """Requirement 1: 1-hop returns only directly reachable entities (Server A and Server C)."""
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=1,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert result.max_hops_evaluated == 1
    assert result.hop_1.node_count == 2
    assert result.hop_2.node_count == 0
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 2

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    assert hop_1_ids == {"server:srv-a", "server:srv-c"}


def test_scenario_requirement_2_two_hop_reachability():
    """Requirement 2: 2-hop returns entities reachable within two edges (Server B and Database A)."""
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=2,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert result.max_hops_evaluated == 2
    assert result.hop_1.node_count == 2
    assert result.hop_2.node_count == 2
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 4

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    hop_2_ids = {n.id for n in result.hop_2.nodes}

    assert hop_1_ids == {"server:srv-a", "server:srv-c"}
    assert hop_2_ids == {"server:srv-b", "db:db-a"}


def test_scenario_requirement_3_and_5_three_hop_and_no_duplicates():
    """
    Requirements 3 & 5:
    - 3-hop returns entities reachable within three edges.
    - Duplicate nodes are NOT returned across hops.
    Database A is reachable via Device A -> Server C -> Database A (hop 2)
    and via Device A -> Server A -> Server B -> Database A (hop 3).
    Because BFS preserves minimum-hop distance, Database A MUST be placed in Hop 2
    and strictly excluded from Hop 3.
    """
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert result.max_hops_evaluated == 3
    assert result.hop_1.node_count == 2
    assert result.hop_2.node_count == 2
    # At hop 3, the candidate from srv-b is db:db-a, but db:db-a was already visited at hop 2!
    assert result.hop_3.node_count == 0
    assert result.total_reachable_nodes == 4

    hop_1_ids = {n.id for n in result.hop_1.nodes}
    hop_2_ids = {n.id for n in result.hop_2.nodes}
    hop_3_ids = {n.id for n in result.hop_3.nodes}

    # Verify mutual exclusion across all hops
    assert hop_1_ids.isdisjoint(hop_2_ids)
    assert hop_1_ids.isdisjoint(hop_3_ids)
    assert hop_2_ids.isdisjoint(hop_3_ids)

    assert "db:db-a" in hop_2_ids
    assert "db:db-a" not in hop_3_ids


def test_scenario_requirement_4_starting_node_not_counted_as_affected():
    """Requirement 4: Starting node is NOT counted as affected."""
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    all_affected_ids = (
        {n.id for n in result.hop_1.nodes}
        | {n.id for n in result.hop_2.nodes}
        | {n.id for n in result.hop_3.nodes}
    )
    assert "device:dev-a" not in all_affected_ids
    assert result.start_node.id == "device:dev-a"
    assert result.total_reachable_nodes == 4


def test_scenario_requirement_6_unrelated_systems_strictly_excluded():
    """Requirement 6: Unrelated systems (Server Unrelated) are strictly excluded."""
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    subgraph_node_ids = {n.id for n in result.subgraph_nodes}
    assert "server:srv-unrelated" not in subgraph_node_ids
    assert not any(n.id == "server:srv-unrelated" for n in result.hop_1.nodes)
    assert not any(n.id == "server:srv-unrelated" for n in result.hop_2.nodes)
    assert not any(n.id == "server:srv-unrelated" for n in result.hop_3.nodes)


def test_scenario_requirement_7_traversal_direction_and_filtering():
    """
    Requirement 7: Traversal direction (OUTGOING, INCOMING, BOTH) and relationship filtering.
    - INCOMING from Server A finds Device A and Device B (both connect to Server A).
    - BOTH from Server A finds Device A, Device B (inbound) and Server B (outbound).
    - Relationship filter restricts expansion strictly to permitted types.
    """
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    # 1. INCOMING from Server A
    req_incoming = BlastRadiusRequest(
        start_node_id="server:srv-a",
        max_hops=1,
        direction=TraversalDirection.INCOMING,
    )
    res_incoming = service.calculate_blast_radius(req_incoming)
    incoming_ids = {n.id for n in res_incoming.hop_1.nodes}
    assert incoming_ids == {"device:dev-a", "device:dev-b"}
    assert "server:srv-b" not in incoming_ids

    # 2. BOTH from Server A
    req_both = BlastRadiusRequest(
        start_node_id="server:srv-a",
        max_hops=1,
        direction=TraversalDirection.BOTH,
    )
    res_both = service.calculate_blast_radius(req_both)
    both_ids = {n.id for n in res_both.hop_1.nodes}
    assert both_ids == {"device:dev-a", "device:dev-b", "server:srv-b"}

    # 3. Filtering by relationship type: CONTAINS_CRITICAL_DATA
    req_filter = BlastRadiusRequest(
        start_node_id="server:srv-b",
        max_hops=1,
        allowed_relationship_types=[RelationshipType.CONTAINS_CRITICAL_DATA],
    )
    res_filter = service.calculate_blast_radius(req_filter)
    assert res_filter.hop_1.node_count == 1
    assert res_filter.hop_1.nodes[0].id == "db:db-a"

    # Disallowed relationship type returns zero nodes
    req_filter_disallowed = BlastRadiusRequest(
        start_node_id="server:srv-b",
        max_hops=1,
        allowed_relationship_types=[RelationshipType.AUTHENTICATED_TO],
    )
    res_filter_disallowed = service.calculate_blast_radius(req_filter_disallowed)
    assert res_filter_disallowed.hop_1.node_count == 0


def test_scenario_requirement_8_critical_asset_identification():
    """
    Requirement 8: Critical assets (Crown Jewels) are correctly identified.
    Database A has criticality=CRITICAL, impact_score=95, category=CUSTOMER_PII.
    Verifies that CriticalAssetExposure is populated with accurate shortest path context.
    """
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
    )
    result = service.calculate_blast_radius(request)

    assert len(result.critical_assets_at_risk) == 1
    crit_asset = result.critical_assets_at_risk[0]

    assert crit_asset.asset_id == "db:db-a"
    assert crit_asset.name == "Database A"
    assert crit_asset.category == "CUSTOMER_PII"
    assert crit_asset.impact_score == 95
    assert crit_asset.hop_depth == 2
    assert crit_asset.shortest_path_nodes == ["device:dev-a", "server:srv-c", "db:db-a"]
    assert crit_asset.reachability_status == "EXPOSED"


def test_scenario_requirement_9_missing_starting_node_raises_404():
    """Requirement 9: Missing starting nodes produce appropriate 404 / NodeNotFoundError."""
    client = ScenarioGraphClient()
    service = BlastRadiusService(client)

    request = BlastRadiusRequest(
        start_node_id="device:ghost-nonexistent",
        max_hops=3,
    )
    with pytest.raises(NodeNotFoundError, match="does not exist in the security graph"):
        service.calculate_blast_radius(request)


def test_scenario_requirement_10_api_responses_and_soc_descriptions():
    """
    Requirement 10: FastAPI responses contain accurate hop counts, entity details,
    and non-alarmist SOC descriptions ("architectural exposure, not confirmed compromise").
    """
    mock_client = ScenarioGraphClient()
    app.dependency_overrides[get_graphops_client] = lambda: mock_client

    try:
        test_client = TestClient(app)

        # GET endpoint
        response = test_client.get(
            "/api/v1/graphops/blast-radius",
            params={
                "start_node_id": "device:dev-a",
                "max_hops": 3,
                "direction": "OUTGOING",
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["start_node"]["id"] == "device:dev-a"
        assert data["max_hops_evaluated"] == 3
        assert data["total_reachable_nodes"] == 4
        assert data["hop_1"]["node_count"] == 2
        assert data["hop_2"]["node_count"] == 2
        assert data["hop_3"]["node_count"] == 0
        assert len(data["critical_assets_at_risk"]) == 1

        # Epistemic, non-alarmist description
        assessment = data["summary_assessment"]
        assert "Reachable assets represent architectural exposure, not confirmed compromise." in assessment
        assert "CRITICAL ASSETS AT RISK (1)" in assessment
        assert "Database A" in assessment

        # POST 404 for missing node
        post_404 = test_client.post(
            "/api/v1/graphops/blast-radius",
            json={"start_node_id": "device:missing", "max_hops": 2},
        )
        assert post_404.status_code == 404
        assert "does not exist in the security graph" in post_404.json()["detail"]

    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


def test_scenario_containment_simulation_safety():
    """
    What-If Containment Simulation:
    Verifies that isolating Server C forces the path to Database A to route through Server A -> Server B,
    while zero live-graph mutations occur.
    """
    mock_client = ScenarioGraphClient()
    service = BlastRadiusService(mock_client)

    request = BlastRadiusRequest(
        start_node_id="device:dev-a",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
    )

    # Containment intervention: isolate Server C
    interventions = [
        ProposedIntervention(
            node_id="server:srv-c",
            action="ISOLATE_NODE",
            description="Isolate Server C to sever shortcut route to Database A",
        )
    ]

    result = service.simulate_blast_containment(request, interventions)

    assert result.live_graph_modified is False
    assert result.entry_node_id == "device:dev-a"
    assert result.baseline_reachable_nodes_count == 4
    # With Server C isolated, reachable nodes are Server A, Server B, and Database A (reached via Server B at hop 3)
    assert "server:srv-c" in result.eliminated_node_ids
    assert result.simulated_reachable_nodes_count == 3
    assert result.containment_efficiency_pct == 25.0
    # Database A is still reached via Server B
    assert result.remaining_critical_assets_count == 1

    # Total containment: isolate Server A and Server C
    full_interventions = [
        ProposedIntervention(node_id="server:srv-a", action="ISOLATE_NODE"),
        ProposedIntervention(node_id="server:srv-c", action="ISOLATE_NODE"),
    ]
    full_result = service.simulate_blast_containment(request, full_interventions)
    assert full_result.live_graph_modified is False
    assert full_result.simulated_reachable_nodes_count == 0
    assert full_result.eliminated_nodes_count == 4
    assert full_result.containment_efficiency_pct == 100.0
    assert full_result.remaining_critical_assets_count == 0
    assert "Full blast-radius containment" in full_result.analyst_verdict
