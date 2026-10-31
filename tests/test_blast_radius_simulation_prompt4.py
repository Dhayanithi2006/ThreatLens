"""
ThreatLens GraphOps - Prompt 4 Blast Radius & What-If Containment Verification Suite
Validates 1-3 hop neighborhood reachability, minimum-hop BFS distance assignment,
cycle avoidance, multi-path deduplication, inventory metadata criticality extraction,
safe in-memory What-If containment simulations, and FastAPI REST endpoints.
"""

import pytest
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    TraversalDirection,
    InterventionAction,
    canonicalize_node_id,
)
from backend.models.graphops import (
    EnterpriseNode,
    EnterpriseRelationship,
    BlastRadiusRequest,
    BlastRadiusResult,
    BlastRadiusContainmentRequest,
    BlastRadiusContainmentResult,
    ProposedIntervention,
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
    AttackPathRequest,
)
from backend.graphops.blast_radius import (
    BlastRadiusService,
    NodeNotFoundError,
)
from backend.graphops.attack_paths import AttackPathService


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# =====================================================================
# DETERMINISTIC MOCK GRAPH CLIENT FOR EXACT BFS & WHAT-IF PROOFS
# =====================================================================

class DeterministicMockGraphClient:
    """In-memory mock graph client allowing exact mathematical inspection of BFS & What-If operations."""

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

        # 3. BFS Frontier Edges Query
        if "WHERE s.id IN $frontier_ids" in query or "s.id in $frontier_ids" in query.lower():
            frontier_ids = {str(fid).lower() for fid in params.get("frontier_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            is_incoming = "<-[r]-" in query
            is_both = "-[r]-" in query and "->" not in query and "<-" not in query

            results = []
            for e in self.edges:
                src_id = (e.get("source_id") or e.get("source", "")).lower()
                tgt_id = (e.get("target_id") or e.get("target", "")).lower()
                rel_type = e.get("relationship_type") or e.get("type", "")
                ev_class = e.get("evidence_class", "OBSERVED")

                if allowed_types and rel_type not in allowed_types:
                    continue
                if not include_hypothetical:
                    if rel_type == "POTENTIAL_EXPLOIT" or ev_class == "HYPOTHETICAL":
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
                            "rel_source_id": e.get("source_id") or e.get("source"),
                            "rel_target_id": e.get("target_id") or e.get("target"),
                            "rel_props": e.get("properties", {}),
                        })
            return results

        # 4. Fallback path search for AttackPathService
        if "MATCH p = (start)-[r*1.." in query:
            entry_id = str(params.get("entry_id", "")).strip()
            target_ids = set(params.get("target_ids", []))
            max_depth = 5
            try:
                depth_part = query.split("MATCH p = (start)-[r*1..")[1].split("]->(target)")[0]
                max_depth = int(depth_part)
            except Exception:
                pass

            allowed_types = set(params.get("allowed_types", []))
            inc_hypo = params.get("include_hypothetical", True)

            found_paths = []
            queue = [([entry_id], [])]

            while queue:
                curr_nodes, curr_rels = queue.pop(0)
                curr_tip = curr_nodes[-1]

                if len(curr_nodes) - 1 > max_depth:
                    continue

                if curr_tip in target_ids and len(curr_nodes) > 1:
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
# 1. BLAST RADIUS HOP DEPTH & BFS TRAVERSAL (Task A)
# =====================================================================

def test_blast_radius_1_hop_exact_neighborhood():
    """Verify 1-hop blast radius strictly evaluates only direct neighbors."""
    nodes = [
        {"id": "device:dev-ws-101", "labels": ["Device"], "properties": {"name": "DEV-WS-101"}},
        {"id": "server:srv-app-01", "labels": ["Server"], "properties": {"name": "SRV-APP-01"}},
        {"id": "critical:crit-db", "labels": ["CriticalAsset"], "properties": {"name": "Financial DB", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:dev-ws-101", "target_id": "server:srv-app-01", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:srv-app-01", "target_id": "critical:crit-db", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=1)
    res = service.calculate_blast_radius(req)

    assert res.total_reachable_nodes == 1
    assert res.hop_1.node_count == 1
    assert res.hop_1.nodes[0].id == "server:srv-app-01"
    assert res.hop_2.node_count == 0
    assert res.hop_3.node_count == 0
    assert len(res.critical_assets_at_risk) == 0  # DB is 2 hops away, not reached at hop 1


def test_blast_radius_2_hops_minimum_distance():
    """Verify 2-hop blast radius reaches 2nd-tier entities without displacing 1-hop entities."""
    nodes = [
        {"id": "device:dev-ws-101", "labels": ["Device"], "properties": {"name": "DEV-WS-101"}},
        {"id": "server:srv-app-01", "labels": ["Server"], "properties": {"name": "SRV-APP-01"}},
        {"id": "critical:crit-db", "labels": ["CriticalAsset"], "properties": {"name": "Financial DB", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:dev-ws-101", "target_id": "server:srv-app-01", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:srv-app-01", "target_id": "critical:crit-db", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=2)
    res = service.calculate_blast_radius(req)

    assert res.total_reachable_nodes == 2
    assert res.hop_1.node_count == 1
    assert res.hop_1.nodes[0].id == "server:srv-app-01"
    assert res.hop_2.node_count == 1
    assert res.hop_2.nodes[0].id == "critical:crit-db"
    assert res.hop_3.node_count == 0
    assert len(res.critical_assets_at_risk) == 1
    assert res.critical_assets_at_risk[0].asset_id == "critical:crit-db"
    assert res.critical_assets_at_risk[0].hop_depth == 2


def test_blast_radius_3_hops_bounded_depth():
    """Verify 3-hop traversal reaches 3rd-tier entities and emits bounded evaluation notice."""
    nodes = [
        {"id": "user:usr-1", "labels": ["User"], "properties": {"name": "Alice"}},
        {"id": "device:ws-1", "labels": ["Device"], "properties": {"name": "Workstation 1"}},
        {"id": "server:app-1", "labels": ["Server"], "properties": {"name": "App Server 1"}},
        {"id": "critical:db-vault", "labels": ["CriticalAsset"], "properties": {"name": "DB Vault", "criticality": "CRITICAL"}},
        {"id": "server:beyond-4th-hop", "labels": ["Server"], "properties": {"name": "Beyond Scope"}},
    ]
    edges = [
        {"source_id": "user:usr-1", "target_id": "device:ws-1", "relationship_type": "LOGGED_IN_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:ws-1", "target_id": "server:app-1", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:app-1", "target_id": "critical:db-vault", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "critical:db-vault", "target_id": "server:beyond-4th-hop", "relationship_type": "REPLICATES_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    req = BlastRadiusRequest(start_node_id="user:usr-1", max_hops=3)
    res = service.calculate_blast_radius(req)

    assert res.total_reachable_nodes == 3
    assert res.hop_1.node_count == 1
    assert res.hop_2.node_count == 1
    assert res.hop_3.node_count == 1
    assert res.hop_3.nodes[0].id == "critical:db-vault"
    # Entities at 4 hops are not evaluated
    assert all(n.id != "server:beyond-4th-hop" for n in res.subgraph_nodes)
    assert any("maximum evaluation limit of 3 hops" in w for w in res.warnings)


def test_blast_radius_invalid_hop_limits():
    """Verify invalid hop depths (0, 4, negative) raise ValueError."""
    client = DeterministicMockGraphClient(nodes=[], edges=[])
    service = BlastRadiusService(client)

    with pytest.raises(ValueError) as exc1:
        service.calculate_blast_radius(BlastRadiusRequest.model_construct(start_node_id="device:ws", max_hops=0))
    assert "max_hops must be between 1 and 3" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        service.calculate_blast_radius(BlastRadiusRequest.model_construct(start_node_id="device:ws", max_hops=4))
    assert "max_hops must be between 1 and 3" in str(exc2.value)


# =====================================================================
# 2. CYCLE AVOIDANCE & MULTI-PATH DEDUPLICATION (Task A)
# =====================================================================

def test_blast_radius_cycle_avoidance_no_infinite_loop():
    """Verify directed cycles (A -> B -> C -> A) do not cause runaway traversal or duplicated nodes."""
    nodes = [
        {"id": "device:node-a", "labels": ["Device"], "properties": {"name": "Node A"}},
        {"id": "server:node-b", "labels": ["Server"], "properties": {"name": "Node B"}},
        {"id": "server:node-c", "labels": ["Server"], "properties": {"name": "Node C"}},
    ]
    edges = [
        {"source_id": "device:node-a", "target_id": "server:node-b", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:node-b", "target_id": "server:node-c", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:node-c", "target_id": "device:node-a", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:node-a", max_hops=3))

    assert res.total_reachable_nodes == 2  # B and C (A is root)
    assert res.hop_1.node_count == 1
    assert res.hop_2.node_count == 1
    assert res.hop_3.node_count == 0  # Cycle back to A is suppressed by visited set


def test_blast_radius_diamond_deduplication():
    """Verify diamond topology (A -> B -> D and A -> C -> D) counts D exactly once at hop 2."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:branch-1", "labels": ["Server"], "properties": {"name": "Branch 1"}},
        {"id": "server:branch-2", "labels": ["Server"], "properties": {"name": "Branch 2"}},
        {"id": "critical:target-d", "labels": ["CriticalAsset"], "properties": {"name": "Target D", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:branch-1", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:entry", "target_id": "server:branch-2", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:branch-1", "target_id": "critical:target-d", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:branch-2", "target_id": "critical:target-d", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:entry", max_hops=2))

    # Total distinct reachable nodes: Branch 1, Branch 2, Target D = 3
    assert res.total_reachable_nodes == 3
    assert res.hop_1.node_count == 2
    assert res.hop_2.node_count == 1
    assert res.hop_2.nodes[0].id == "critical:target-d"
    assert len(res.critical_assets_at_risk) == 1
    assert res.critical_assets_at_risk[0].asset_id == "critical:target-d"


def test_blast_radius_self_loop_handling():
    """Verify self-loop edges (A -> A) do not add root entity to its own reachable neighbor list."""
    nodes = [
        {"id": "device:dev-ws-101", "labels": ["Device"], "properties": {"name": "DEV-WS-101"}},
    ]
    edges = [
        {"source_id": "device:dev-ws-101", "target_id": "device:dev-ws-101", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=2))

    assert res.total_reachable_nodes == 0
    assert res.hop_1.node_count == 0
    assert res.hop_2.node_count == 0


# =====================================================================
# 3. ENTITY RESOLUTION & DISCONNECTED/EMPTY GRAPHS (Task A)
# =====================================================================

def test_blast_radius_unknown_entity_raises_404():
    """Verify query with nonexistent start node raises NodeNotFoundError with descriptive detail."""
    client = DeterministicMockGraphClient(nodes=[], edges=[])
    service = BlastRadiusService(client)

    with pytest.raises(NodeNotFoundError) as exc_info:
        service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:unknown-phantom-404"))
    assert "does not exist in the security graph" in str(exc_info.value)


def test_blast_radius_disconnected_isolated_entity():
    """Verify isolated entity with zero edges returns 0 reachable nodes and isolated assessment."""
    nodes = [
        {"id": "server:isolated-island", "labels": ["Server"], "properties": {"name": "Island Server"}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=[])
    service = BlastRadiusService(client)

    res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="server:isolated-island", max_hops=3))

    assert res.total_reachable_nodes == 0
    assert res.hop_1.node_count == 0
    assert res.hop_2.node_count == 0
    assert res.hop_3.node_count == 0
    assert "Isolated entity: Zero reachable assets" in res.summary_assessment


# =====================================================================
# 4. RELATIONSHIP FILTERING & DIRECTIONALITY (Task A)
# =====================================================================

def test_blast_radius_directionality_outgoing_incoming_both():
    """Verify OUTGOING, INCOMING, and BOTH traversal directions evaluate the appropriate graph flow."""
    nodes = [
        {"id": "device:hub", "labels": ["Device"], "properties": {"name": "Hub"}},
        {"id": "server:out-srv", "labels": ["Server"], "properties": {"name": "Out Server"}},
        {"id": "user:in-usr", "labels": ["User"], "properties": {"name": "In User"}},
    ]
    edges = [
        {"source_id": "device:hub", "target_id": "server:out-srv", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "user:in-usr", "target_id": "device:hub", "relationship_type": "LOGGED_IN_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    # 1. OUTGOING only -> finds out-srv
    res_out = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:hub", max_hops=1, direction=TraversalDirection.OUTGOING))
    assert res_out.total_reachable_nodes == 1
    assert res_out.hop_1.nodes[0].id == "server:out-srv"

    # 2. INCOMING only -> finds in-usr
    res_in = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:hub", max_hops=1, direction=TraversalDirection.INCOMING))
    assert res_in.total_reachable_nodes == 1
    assert res_in.hop_1.nodes[0].id == "user:in-usr"

    # 3. BOTH -> finds out-srv and in-usr
    res_both = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:hub", max_hops=1, direction=TraversalDirection.BOTH))
    assert res_both.total_reachable_nodes == 2


def test_blast_radius_relationship_type_filtering():
    """Verify allowed_relationship_types strictly constrains the traversable edge set."""
    nodes = [
        {"id": "device:dev-1", "labels": ["Device"], "properties": {"name": "Device 1"}},
        {"id": "server:srv-net", "labels": ["Server"], "properties": {"name": "Net Server"}},
        {"id": "server:srv-perm", "labels": ["Server"], "properties": {"name": "Perm Server"}},
    ]
    edges = [
        {"source_id": "device:dev-1", "target_id": "server:srv-net", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:dev-1", "target_id": "server:srv-perm", "relationship_type": "HAS_PERMISSION", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    # Filter for HAS_PERMISSION only
    req = BlastRadiusRequest(
        start_node_id="device:dev-1",
        max_hops=1,
        allowed_relationship_types=[RelationshipType.HAS_PERMISSION],
    )
    res = service.calculate_blast_radius(req)

    assert res.total_reachable_nodes == 1
    assert res.hop_1.nodes[0].id == "server:srv-perm"


# =====================================================================
# 5. EVIDENCE CLASS DISTINCTION & CROWN JEWELS (Task B)
# =====================================================================

def test_blast_radius_evidence_classes_and_hypothetical_filter():
    """Verify include_hypothetical=False blocks hypothetical exploit edges."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:pivot", "labels": ["Server"], "properties": {"name": "Pivot Server"}},
        {"id": "critical:vault", "labels": ["CriticalAsset"], "properties": {"name": "Vault", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:pivot", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:pivot", "target_id": "critical:vault", "relationship_type": "POTENTIAL_EXPLOIT", "evidence_class": "HYPOTHETICAL", "properties": {"cve": "CVE-2024-38077"}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    # 1. include_hypothetical=False -> vault is unreachable
    res_obs = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:entry", max_hops=2, include_hypothetical=False))
    assert res_obs.total_reachable_nodes == 1
    assert len(res_obs.critical_assets_at_risk) == 0

    # 2. include_hypothetical=True -> vault is reachable with explicit warning
    res_hypo = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:entry", max_hops=2, include_hypothetical=True))
    assert res_hypo.total_reachable_nodes == 2
    assert len(res_hypo.critical_assets_at_risk) == 1
    assert any("Includes hypothetical attack transitions" in w for w in res_hypo.warnings)


def test_blast_radius_crown_jewels_identification():
    """Verify Crown Jewels are identified strictly from inventory properties, never guessed."""
    nodes = [
        {"id": "device:root", "labels": ["Device"], "properties": {"name": "Root"}},
        {"id": "server:standard-srv", "labels": ["Server"], "properties": {"name": "Standard Server"}},  # No criticality
        {"id": "server:high-impact", "labels": ["Server"], "properties": {"name": "High Impact Server", "impact_score": 90}},  # High impact >= 85
        {"id": "critical:crown-vault", "labels": ["CriticalAsset"], "properties": {"name": "Crown Vault", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:root", "target_id": "server:standard-srv", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:root", "target_id": "server:high-impact", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "device:root", "target_id": "critical:crown-vault", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    res = service.calculate_blast_radius(BlastRadiusRequest(start_node_id="device:root", max_hops=1))

    assert res.total_reachable_nodes == 3
    # Only high-impact and crown-vault qualify as critical assets
    jewel_ids = {c.asset_id for c in res.critical_assets_at_risk}
    assert jewel_ids == {"server:high-impact", "critical:crown-vault"}
    assert "server:standard-srv" not in jewel_ids


# =====================================================================
# 6. WHAT-IF CONTAINMENT SIMULATION (Task C)
# =====================================================================

def test_blast_radius_containment_simulation_isolated_bridge():
    """Verify What-If containment isolating bridge server cuts off downstream assets and calculates exact efficiency."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:bridge", "labels": ["Server"], "properties": {"name": "Bridge Server"}},
        {"id": "critical:vault-1", "labels": ["CriticalAsset"], "properties": {"name": "Vault 1", "criticality": "CRITICAL"}},
        {"id": "critical:vault-2", "labels": ["CriticalAsset"], "properties": {"name": "Vault 2", "criticality": "CRITICAL"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:bridge", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:bridge", "target_id": "critical:vault-1", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
        {"source_id": "server:bridge", "target_id": "critical:vault-2", "relationship_type": "CONTAINS_CRITICAL_DATA", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    interventions = [
        ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:bridge")
    ]
    sim_res = service.simulate_blast_containment(
        request=BlastRadiusRequest(start_node_id="device:entry", max_hops=2),
        proposed_interventions=interventions,
    )

    assert sim_res.baseline_reachable_nodes_count == 3  # bridge, vault-1, vault-2
    assert sim_res.simulated_reachable_nodes_count == 0  # all severed
    assert sim_res.eliminated_nodes_count == 3
    assert sim_res.containment_efficiency_pct == 100.0
    assert sim_res.baseline_critical_assets_count == 2
    assert sim_res.remaining_critical_assets_count == 0
    assert sim_res.eliminated_critical_assets_count == 2
    assert sim_res.live_graph_modified is False
    assert "Full blast-radius containment" in sim_res.analyst_verdict


def test_blast_radius_containment_simulation_root_isolation():
    """Verify What-If containment isolating the root entry point itself achieves 100% containment."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:srv-1", "labels": ["Server"], "properties": {"name": "Server 1"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:srv-1", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    interventions = [
        ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="device:entry")
    ]
    sim_res = service.simulate_blast_containment(
        request=BlastRadiusRequest(start_node_id="device:entry", max_hops=1),
        proposed_interventions=interventions,
    )

    assert sim_res.baseline_reachable_nodes_count == 1
    assert sim_res.simulated_reachable_nodes_count == 0
    assert sim_res.eliminated_nodes_count == 1
    assert sim_res.containment_efficiency_pct == 100.0


def test_blast_radius_containment_simulation_no_change_and_nonexistent_target():
    """Verify What-If containment with nonexistent node produces 0% reduction without crashing."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:srv-1", "labels": ["Server"], "properties": {"name": "Server 1"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:srv-1", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    interventions = [
        ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:phantom-nonexistent-node")
    ]
    sim_res = service.simulate_blast_containment(
        request=BlastRadiusRequest(start_node_id="device:entry", max_hops=1),
        proposed_interventions=interventions,
    )

    assert sim_res.baseline_reachable_nodes_count == 1
    assert sim_res.simulated_reachable_nodes_count == 1
    assert sim_res.eliminated_nodes_count == 0
    assert sim_res.containment_efficiency_pct == 0.0
    assert "Partial blast-radius containment" in sim_res.analyst_verdict


def test_simulation_safety_guarantee_zero_database_mutation():
    """Verify What-If simulation strictly preserves all underlying nodes and edges without mutating database state."""
    nodes = [
        {"id": "device:entry", "labels": ["Device"], "properties": {"name": "Entry"}},
        {"id": "server:bridge", "labels": ["Server"], "properties": {"name": "Bridge Server"}},
    ]
    edges = [
        {"source_id": "device:entry", "target_id": "server:bridge", "relationship_type": "CONNECTS_TO", "evidence_class": "OBSERVED", "properties": {}},
    ]
    client = DeterministicMockGraphClient(nodes=nodes, edges=edges)
    service = BlastRadiusService(client)

    initial_node_count = len(client.nodes)
    initial_edge_count = len(client.edges)

    # Run simulation
    service.simulate_blast_containment(
        request=BlastRadiusRequest(start_node_id="device:entry", max_hops=1),
        proposed_interventions=[ProposedIntervention(action=InterventionAction.ISOLATE_NODE, node_id="server:bridge")],
    )

    # Assert underlying graph data in client is 100% untouched
    assert len(client.nodes) == initial_node_count
    assert len(client.edges) == initial_edge_count
    assert "server:bridge" in client.nodes


# =====================================================================
# 7. FASTAPI REST ENDPOINT VERIFICATION (Task D & Verification)
# =====================================================================

def test_fastapi_blast_radius_get_endpoint(client):
    """Verify GET /api/v1/graphops/blast-radius query parameter evaluation."""
    # 1. Valid request
    resp = client.get("/api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=2&direction=OUTGOING")
    assert resp.status_code == 200
    data = resp.json()
    assert data["start_node"]["id"] == "device:dev-ws-101"
    assert "hop_1" in data
    assert "hop_2" in data
    assert "hop_3" in data
    assert "hop_distribution" in data
    assert "total_reachable_nodes" in data
    assert "summary_assessment" in data

    # 2. Unknown node returns 404
    resp_404 = client.get("/api/v1/graphops/blast-radius?start_node_id=device:unknown-phantom-machine")
    assert resp_404.status_code == 404
    assert "does not exist in the security graph" in resp_404.json()["detail"]

    # 3. Invalid max_hops (4) returns 422
    resp_422 = client.get("/api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=4")
    assert resp_422.status_code == 422

    # 4. Missing required start_node_id returns 422
    resp_missing = client.get("/api/v1/graphops/blast-radius")
    assert resp_missing.status_code == 422


def test_fastapi_blast_radius_post_endpoint(client):
    """Verify POST /api/v1/graphops/blast-radius payload evaluation."""
    payload = {
        "start_node_id": "device:dev-ws-101",
        "max_hops": 3,
        "direction": "OUTGOING",
        "include_hypothetical": True,
    }
    resp = client.post("/api/v1/graphops/blast-radius", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["start_node"]["id"] == "device:dev-ws-101"
    assert data["max_hops_evaluated"] == 3
    assert data["hop_distribution"]["1"] >= 0

    # Unknown start node in POST returns 404
    err_resp = client.post("/api/v1/graphops/blast-radius", json={"start_node_id": "device:ghost-node-999"})
    assert err_resp.status_code == 404


def test_fastapi_blast_radius_simulate_endpoint(client):
    """Verify POST /api/v1/graphops/blast-radius/simulate."""
    payload = {
        "start_node_id": "device:dev-ws-101",
        "max_hops": 2,
        "direction": "OUTGOING",
        "include_hypothetical": True,
        "proposed_interventions": [
            {
                "action": "ISOLATE_NODE",
                "node_id": "server:srv-app-01"
            }
        ]
    }
    resp = client.post("/api/v1/graphops/blast-radius/simulate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "simulation_id" in data
    assert data["live_graph_modified"] is False
    assert "baseline_reachable_nodes_count" in data
    assert "simulated_reachable_nodes_count" in data
    assert "eliminated_nodes_count" in data
    assert "containment_efficiency_pct" in data
    assert "analyst_verdict" in data
    assert "SIMULATION ONLY" in data["safety_disclaimer"]

    # Unknown node in simulate returns 404
    err_resp = client.post("/api/v1/graphops/blast-radius/simulate", json={
        "start_node_id": "device:unknown-phantom-start",
        "proposed_interventions": [{"action": "ISOLATE_NODE", "node_id": "server:srv-app-01"}]
    })
    assert err_resp.status_code == 404


def test_fastapi_simulate_containment_attack_paths(client):
    """Verify POST /api/v1/graphops/simulate-containment in-memory path simulation."""
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
    assert data["live_graph_modified"] is False
    assert "baseline_paths_count" in data
    assert "remaining_paths_count" in data
    assert "paths_eliminated_count" in data
    assert "containment_efficiency_pct" in data
    assert "SIMULATION ONLY" in data["safety_disclaimer"]

