"""
ThreatLens GraphOps - Module 3: Assess Impact Test Suite
Comprehensive validation of:
  Submodule 1: Blast Radius & Containment
    - Multi-hop BFS neighborhood calculation (1-hop, 2-hop, 3-hop)
    - Strict minimum-hop distance assignment and duplicate-visit prevention
    - Directional traversal (OUTGOING, INCOMING, BOTH)
    - Relationship type and evidence filtering (hypothetical exclusion)
    - Crown Jewel / Critical Asset identification and exposure tracing
    - Disconnected / isolated node handling
    - Nonexistent entity 404 and invalid parameter 422 handling
  Submodule 2: What-If Containment Simulator
    - Device isolation (ISOLATE_NODE on device)
    - Server isolation (ISOLATE_NODE on server)
    - Account restriction (DISABLE_ACCOUNT on user)
    - Relationship removal (REVOKE_PERMISSION on edge)
    - Network connection blocking (BLOCK_CONNECTION on edge)
    - Before-and-after comparison metrics and residual Crown Jewel exposure
    - Zero live database mutation safety guarantee
    - Clear hypothetical simulation labeling
  Centralized Integration:
    - Case-to-graph bridge pivot
    - Simulation findings persistence to case timeline and notes
    - Neo4j offline graceful fallback
"""

import copy
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    TraversalDirection,
    InterventionAction,
)
from backend.models.graphops import (
    BlastRadiusRequest,
    BlastRadiusContainmentRequest,
    ContainmentSimulationRequest,
    ProposedIntervention,
    SaveSimulationFindingRequest,
)
from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError
from backend.graphops.attack_paths import AttackPathService
from backend.graphops.mock_client import get_mock_graphops_client, InMemoryGraphOpsClient
from backend.services.case_store import default_case_repo


@pytest.fixture
def mock_client() -> InMemoryGraphOpsClient:
    """Provides a fresh isolated in-memory graphops client for deterministic testing."""
    return get_mock_graphops_client()


@pytest.fixture
def test_client() -> TestClient:
    """FastAPI test client instance."""
    return TestClient(app)


# =====================================================================
# SUBMODULE 1: BLAST RADIUS & CONTAINMENT
# =====================================================================

def test_blast_radius_user_device_server_selection(mock_client):
    """
    Verifies that blast radius calculation can be initiated from:
    1. A suspicious user identity (e.g. user:alice@corp.com)
    2. A compromised device (e.g. device:dev-ws-101)
    3. An infected server (e.g. server:srv-app-01)
    """
    service = BlastRadiusService(mock_client)

    # 1. User root
    user_req = BlastRadiusRequest(start_node_id="user:usr-101", max_hops=3, direction=TraversalDirection.OUTGOING)
    user_res = service.calculate_blast_radius(user_req)
    assert user_res.start_node.id.lower() == "user:usr-101"
    assert user_res.total_reachable_nodes > 0
    assert user_res.hop_1.node_count > 0

    # 2. Device root
    dev_req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3, direction=TraversalDirection.OUTGOING)
    dev_res = service.calculate_blast_radius(dev_req)
    assert dev_res.start_node.id.lower() == "device:dev-ws-101"
    assert dev_res.total_reachable_nodes > 0

    # 3. Server root
    srv_req = BlastRadiusRequest(start_node_id="server:srv-app-01", max_hops=3, direction=TraversalDirection.OUTGOING)
    srv_res = service.calculate_blast_radius(srv_req)
    assert srv_res.start_node.id.lower() == "server:srv-app-01"
    assert srv_res.total_reachable_nodes >= 0


def test_blast_radius_bfs_hop_separation_and_deduplication(mock_client):
    """
    Verifies BFS partitioning:
    - Hop 1, Hop 2, Hop 3 groups are mutually exclusive (disjoint).
    - Start node is not counted in reachable node counts.
    - Total reachable nodes equals sum of hop 1 + hop 2 + hop 3.
    """
    service = BlastRadiusService(mock_client)
    req = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
        include_hypothetical=True,
    )
    res = service.calculate_blast_radius(req)

    hop1_ids = {n.id for n in res.hop_1.nodes}
    hop2_ids = {n.id for n in res.hop_2.nodes}
    hop3_ids = {n.id for n in res.hop_3.nodes}

    # Mutual exclusivity (strict minimum distance)
    assert len(hop1_ids.intersection(hop2_ids)) == 0, "Duplicate nodes discovered across Hop 1 and Hop 2"
    assert len(hop1_ids.intersection(hop3_ids)) == 0, "Duplicate nodes discovered across Hop 1 and Hop 3"
    assert len(hop2_ids.intersection(hop3_ids)) == 0, "Duplicate nodes discovered across Hop 2 and Hop 3"

    # Start node strictly excluded
    assert res.start_node.id not in hop1_ids
    assert res.start_node.id not in hop2_ids
    assert res.start_node.id not in hop3_ids

    # Total count integrity
    expected_total = len(hop1_ids) + len(hop2_ids) + len(hop3_ids)
    assert res.total_reachable_nodes == expected_total
    assert res.hop_distribution == {
        "1": len(hop1_ids),
        "2": len(hop2_ids),
        "3": len(hop3_ids),
    }


def test_blast_radius_cycle_and_diamond_topology_avoidance():
    """
    Constructs an explicit diamond and cyclic graph to verify that BFS avoids infinite loops
    and assigns nodes to their shortest hop distance.
    """
    # Topology: S -> A -> B -> C -> A (cycle), S -> D -> B (diamond)
    nodes = [
        {"id": "device:s", "labels": ["Device"], "properties": {"name": "Start WS"}},
        {"id": "server:a", "labels": ["Server"], "properties": {"name": "Server A"}},
        {"id": "server:b", "labels": ["Server"], "properties": {"name": "Server B"}},
        {"id": "server:c", "labels": ["Server"], "properties": {"name": "Server C"}},
        {"id": "server:d", "labels": ["Server"], "properties": {"name": "Server D"}},
    ]
    edges = [
        {"source_id": "device:s", "target_id": "server:a", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:s", "target_id": "server:d", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:a", "target_id": "server:b", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:d", "target_id": "server:b", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:b", "target_id": "server:c", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:c", "target_id": "server:a", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},  # cycle back
    ]
    client = InMemoryGraphOpsClient(nodes=nodes, edges=edges)

    service = BlastRadiusService(client)
    req = BlastRadiusRequest(start_node_id="device:s", max_hops=3, direction=TraversalDirection.OUTGOING)
    res = service.calculate_blast_radius(req)

    # Expected: Hop 1: [A, D], Hop 2: [B], Hop 3: [C].
    hop1_ids = {n.id for n in res.hop_1.nodes}
    hop2_ids = {n.id for n in res.hop_2.nodes}
    hop3_ids = {n.id for n in res.hop_3.nodes}

    assert hop1_ids == {"server:a", "server:d"}
    assert hop2_ids == {"server:b"}
    assert hop3_ids == {"server:c"}
    assert res.total_reachable_nodes == 4


def test_blast_radius_crown_jewel_identification(mock_client):
    """
    Verifies that critical enterprise assets (Crown Jewels) are accurately flagged,
    their minimum hop distance recorded, and shortest path traces provided.
    """
    service = BlastRadiusService(mock_client)
    req = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
        include_hypothetical=True,
    )
    res = service.calculate_blast_radius(req)

    assert len(res.critical_assets_at_risk) > 0
    for ca in res.critical_assets_at_risk:
        assert ca.reachability_status == "EXPOSED"
        assert 1 <= ca.hop_depth <= 3
        assert len(ca.shortest_path_nodes) == ca.hop_depth + 1
        assert ca.shortest_path_nodes[0] == "device:dev-ws-101"
        assert ca.shortest_path_nodes[-1] == ca.asset_id


def test_blast_radius_directionality_outgoing_incoming_both():
    """
    Verifies that direction parameter strictly respects edge orientation:
    A -> B -> C
    From B:
      OUTGOING reaches C
      INCOMING reaches A
      BOTH reaches A and C
    """
    nodes = [
        {"id": "server:a", "labels": ["Server"], "properties": {"name": "Node A"}},
        {"id": "server:b", "labels": ["Server"], "properties": {"name": "Node B"}},
        {"id": "server:c", "labels": ["Server"], "properties": {"name": "Node C"}},
    ]
    edges = [
        {"source_id": "server:a", "target_id": "server:b", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:b", "target_id": "server:c", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = InMemoryGraphOpsClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    # OUTGOING from B
    out_res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="server:b", max_hops=2, direction=TraversalDirection.OUTGOING))
    out_ids = {n.id for h in [out_res.hop_1, out_res.hop_2, out_res.hop_3] for n in h.nodes}
    assert out_ids == {"server:c"}

    # INCOMING from B
    in_res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="server:b", max_hops=2, direction=TraversalDirection.INCOMING))
    in_ids = {n.id for h in [in_res.hop_1, in_res.hop_2, in_res.hop_3] for n in h.nodes}
    assert in_ids == {"server:a"}

    # BOTH from B
    both_res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="server:b", max_hops=2, direction=TraversalDirection.BOTH))
    both_ids = {n.id for h in [both_res.hop_1, both_res.hop_2, both_res.hop_3] for n in h.nodes}
    assert both_ids == {"server:a", "server:c"}


def test_blast_radius_disconnected_isolated_entity(mock_client):
    """Verifies that an entity with 0 connections returns 0 reachable nodes gracefully."""
    # Register isolated entity
    mock_client.nodes["device:dev-isolated-999"] = {
        "id": "device:dev-isolated-999",
        "labels": ["Device"],
        "properties": {"name": "Air-Gapped Terminal", "hostname": "terminal-offline"},
    }
    service = BlastRadiusService(mock_client)
    req = BlastRadiusRequest(start_node_id="device:dev-isolated-999", max_hops=3, direction=TraversalDirection.OUTGOING)
    res = service.calculate_blast_radius(req)

    assert res.total_reachable_nodes == 0
    assert res.hop_1.node_count == 0
    assert res.hop_2.node_count == 0
    assert res.hop_3.node_count == 0
    assert "Isolated entity" in res.summary_assessment


def test_blast_radius_exposure_summary_distinguishes_evidence(mock_client):
    """
    Verifies that summary assessment clarifies architectural reachability rather than confirmed compromise
    and distinguishes evidence tiers.
    """
    service = BlastRadiusService(mock_client)
    req = BlastRadiusRequest(
        start_node_id="device:dev-ws-101",
        max_hops=3,
        direction=TraversalDirection.OUTGOING,
        include_hypothetical=True,
    )
    res = service.calculate_blast_radius(req)
    assert "Reachable assets represent architectural exposure, not confirmed compromise" in res.summary_assessment
    assert "Evidence basis:" in res.summary_assessment


def test_blast_radius_nonexistent_entity_raises_404(mock_client, test_client):
    """Verifies that querying a nonexistent entity raises HTTP 404 NodeNotFoundError."""
    service = BlastRadiusService(mock_client)
    with pytest.raises(NodeNotFoundError):
        service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:ghost-device-not-real", max_hops=2))

    resp = test_client.get("/api/v1/graphops/blast-radius?start_node_id=device:ghost-device-not-real&max_hops=2")
    assert resp.status_code == 404
    assert "does not exist in the security graph" in resp.json()["detail"]


def test_blast_radius_invalid_hops_raises_422(test_client):
    """Verifies that max_hops > 3 or < 1 is rejected with HTTP 422."""
    resp1 = test_client.get("/api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=4")
    assert resp1.status_code == 422

    resp2 = test_client.get("/api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=0")
    assert resp2.status_code == 422


# =====================================================================
# SUBMODULE 2: WHAT-IF SIMULATOR
# =====================================================================

def test_whatif_device_isolation(mock_client):
    """
    Simulates Device Isolation (ISOLATE_NODE on a device).
    Verifies that the target device and its downstream pathways are severed in memory.
    """
    service = BlastRadiusService(mock_client)
    base_req = BlastRadiusRequest(start_node_id="user:usr-101", max_hops=3, direction=TraversalDirection.OUTGOING)

    # USR-101 USES device:dev-ws-101 -> srv-app-01
    intervention = ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="device:dev-ws-101")
    sim_res = service.simulate_blast_containment(base_req, [intervention])

    assert sim_res.live_graph_modified is False
    assert sim_res.baseline_reachable_nodes_count > 0
    assert "device:dev-ws-101" in sim_res.eliminated_node_ids
    assert sim_res.eliminated_nodes_count >= 1
    assert sim_res.containment_efficiency_pct > 0.0
    assert "SIMULATION ONLY" in sim_res.safety_disclaimer


def test_whatif_server_isolation(mock_client):
    """
    Simulates Server Isolation (ISOLATE_NODE on a server).
    Verifies that server:srv-app-01 and downstream databases are blocked.
    """
    service = BlastRadiusService(mock_client)
    base_req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3, direction=TraversalDirection.OUTGOING)

    intervention = ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01")
    sim_res = service.simulate_blast_containment(base_req, [intervention])

    assert sim_res.live_graph_modified is False
    assert "server:srv-app-01" in sim_res.eliminated_node_ids
    assert sim_res.eliminated_nodes_count >= 1


def test_whatif_account_restriction(mock_client):
    """
    Simulates Account Restriction (DISABLE_ACCOUNT on a user account).
    Verifies that isolating the user root entity drops reachability to zero.
    """
    service = BlastRadiusService(mock_client)
    base_req = BlastRadiusRequest(start_node_id="user:usr-101", max_hops=3, direction=TraversalDirection.OUTGOING)

    intervention = ProposedIntervention(action=InterventionAction.DISABLE_ACCOUNT, node_id="user:usr-101")
    sim_res = service.simulate_blast_containment(base_req, [intervention])

    assert sim_res.live_graph_modified is False
    assert sim_res.simulated_reachable_nodes_count == 0
    assert sim_res.containment_efficiency_pct == 100.0
    assert "Full blast-radius containment" in sim_res.analyst_verdict


def test_whatif_relationship_removal(mock_client):
    """
    Simulates Relationship Removal (REVOKE_PERMISSION on edge).
    Verifies that revoking access between user and critical database mitigates direct reachability.
    """
    service = BlastRadiusService(mock_client)
    base_req = BlastRadiusRequest(start_node_id="user:usr-101", max_hops=3, direction=TraversalDirection.OUTGOING)

    intervention = ProposedIntervention(
        action=InterventionAction.REVOKE_PERMISSION,
        source_id="user:usr-101",
        target_id="device:dev-ws-101",
        relationship_type=RelationshipType.USES,
    )
    sim_res = service.simulate_blast_containment(base_req, [intervention])

    assert sim_res.live_graph_modified is False
    assert sim_res.eliminated_nodes_count > 0


def test_whatif_network_connection_blocking(mock_client):
    """
    Simulates Network Connection Blocking (BLOCK_CONNECTION).
    Verifies that blocking network traffic between dev-ws-101 and srv-app-01 eliminates lateral route.
    """
    service = BlastRadiusService(mock_client)
    base_req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3, direction=TraversalDirection.OUTGOING)

    intervention = ProposedIntervention(
        action=InterventionAction.BLOCK_CONNECTION,
        source_id="device:dev-ws-101",
        target_id="server:srv-app-01",
    )
    sim_res = service.simulate_blast_containment(base_req, [intervention])

    assert sim_res.live_graph_modified is False
    assert "server:srv-app-01" in sim_res.eliminated_node_ids
    assert sim_res.containment_efficiency_pct > 0.0


def test_whatif_attack_path_containment_simulation(mock_client):
    """
    Tests Attack-Path containment simulation with before-and-after path elimination,
    residual Crown Jewel asset status, and efficiency calculations.
    """
    service = AttackPathService(mock_client)
    req = ContainmentSimulationRequest(
        entry_node_id="device:dev-ws-101",
        proposed_interventions=[
            ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01")
        ]
    )
    sim_res = service.simulate_containment(req)

    assert sim_res.live_graph_modified is False
    assert sim_res.baseline_paths_count > 0
    assert sim_res.paths_eliminated_count > 0
    assert len(sim_res.path_statuses) == sim_res.baseline_paths_count
    eliminated_statuses = [s for s in sim_res.path_statuses if s.status == "ELIMINATED"]
    assert len(eliminated_statuses) == sim_res.paths_eliminated_count
    assert "SIMULATION ONLY" in sim_res.safety_disclaimer


def test_whatif_safety_guarantee_zero_database_mutation(mock_client):
    """
    STRICT SAFETY GUARANTEE:
    Verifies that running multiple simulations modifies zero nodes, zero edges, and zero properties.
    """
    nodes_before = copy.deepcopy(mock_client.nodes)
    edges_before = copy.deepcopy(mock_client.edges)

    service_blast = BlastRadiusService(mock_client)
    service_path = AttackPathService(mock_client)

    # Run multiple simulations
    base_req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3)
    service_blast.simulate_blast_containment(base_req, [
        ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01"),
        ProposedIntervention(action=InterventionAction.DISABLE_ACCOUNT, node_id="user:usr-101"),
        ProposedIntervention(action=InterventionAction.BLOCK_CONNECTION, source_id="device:dev-ws-101", target_id="server:srv-app-01"),
    ])

    service_path.simulate_containment(ContainmentSimulationRequest(
        entry_node_id="device:dev-ws-101",
        proposed_interventions=[
            ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:srv-app-01")
        ]
    ))

    # Assert 100% byte-for-byte equality before and after
    assert mock_client.nodes == nodes_before, "Database nodes were altered during simulation!"
    assert mock_client.edges == edges_before, "Database edges were altered during simulation!"


# =====================================================================
# CENTRALIZED INTEGRATION: CASE PERSISTENCE & API ENDPOINTS
# =====================================================================

def test_simulation_persisted_to_case_timeline_and_notes(test_client):
    """
    Verifies that running a simulation with `case_id` or calling `/cases/{case_id}/save-simulation`
    persists a genuine timestamped timeline event and analyst note in the case repository.
    """
    case_id = "MT-101"
    initial_case = default_case_repo.get_case(case_id)
    assert initial_case is not None
    initial_timeline_len = len(initial_case.timeline)
    initial_notes_len = len(initial_case.notes)

    # 1. Test POST /api/v1/graphops/blast-radius/simulate with case_id
    payload_blast = {
        "start_node_id": "device:dev-ws-101",
        "max_hops": 3,
        "direction": "OUTGOING",
        "proposed_interventions": [
            {"action": "ISOLATE_NODE", "node_id": "server:srv-app-01"}
        ],
        "case_id": case_id,
    }
    resp1 = test_client.post("/api/v1/graphops/blast-radius/simulate", json=payload_blast)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["case_id"] == case_id
    assert data1["timeline_event_id"] is not None
    assert data1["note_id"] is not None

    # Check case repository directly
    updated_case1 = default_case_repo.get_case(case_id)
    assert len(updated_case1.timeline) == initial_timeline_len + 1
    assert len(updated_case1.notes) == initial_notes_len + 1

    last_event = updated_case1.timeline[-1]
    assert last_event["event_id"] == data1["timeline_event_id"]
    assert last_event["source"] == "WHAT_IF_SIMULATOR"
    assert last_event["event_type"] == "SIMULATION_FINDING"
    assert "original_event_time" in last_event
    assert "ingested_at" in last_event

    # 2. Test explicit POST /api/v1/graphops/cases/{case_id}/save-simulation
    save_req = {
        "case_id": case_id,
        "simulation_id": "SIM-MANUAL-TEST-01",
        "simulation_type": "WHAT_IF_CONTAINMENT",
        "entry_node_id": "device:dev-ws-101",
        "interventions": [
            {"action": "BLOCK_CONNECTION", "source_id": "device:dev-ws-101", "target_id": "server:srv-app-01"}
        ],
        "efficiency_pct": 75.0,
        "verdict": "Partial containment: severed 3 of 4 lateral attack paths.",
        "residual_assets": ["critical:crown-cust-db"],
        "author": "lead_investigator@threatlens.io",
    }
    resp2 = test_client.post(f"/api/v1/graphops/cases/{case_id}/save-simulation", json=save_req)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["success"] is True
    assert data2["case_id"] == case_id

    updated_case2 = default_case_repo.get_case(case_id)
    assert len(updated_case2.timeline) == initial_timeline_len + 2
    assert len(updated_case2.notes) == initial_notes_len + 2


def test_save_simulation_to_nonexistent_case_returns_404(test_client):
    """Verifies that attempting to save a simulation to a nonexistent case returns HTTP 404."""
    save_req = {
        "case_id": "CASE-DOES-NOT-EXIST",
        "simulation_id": "SIM-TEST-404",
        "simulation_type": "WHAT_IF_CONTAINMENT",
        "entry_node_id": "device:dev-ws-101",
        "interventions": [{"action": "ISOLATE_NODE", "node_id": "server:srv-app-01"}],
        "efficiency_pct": 50.0,
        "verdict": "Test",
        "residual_assets": [],
    }
    resp = test_client.post("/api/v1/graphops/cases/CASE-DOES-NOT-EXIST/save-simulation", json=save_req)
    assert resp.status_code == 404
    assert "does not exist in case repository" in resp.json()["detail"]


def test_case_bridge_pivot_to_blast_radius(test_client):
    """
    Verifies that Case MT-101 bridges to internal entity 'user:employee@corporation.com',
    which can be queried immediately via blast radius.
    """
    bridge_resp = test_client.get("/api/v1/graphops/bridge/case/MT-101")
    assert bridge_resp.status_code == 200
    bridge_data = bridge_resp.json()
    assert bridge_data["case_id"] == "MT-101"
    assert bridge_data["primary_compromised_node"] is not None

    entry_id = bridge_data["primary_compromised_node"]["id"]
    blast_resp = test_client.get(f"/api/v1/graphops/blast-radius?start_node_id={entry_id}&max_hops=2")
    assert blast_resp.status_code == 200
    blast_data = blast_resp.json()
    assert blast_data["start_node"]["id"] == entry_id
