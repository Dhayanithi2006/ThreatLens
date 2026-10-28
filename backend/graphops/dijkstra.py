"""
ThreatLens GraphOps - Dijkstra Weighted Shortest-Path Analytics Engine
Implements a genuine Dijkstra shortest-path algorithm with a priority queue (heapq)
to identify minimum-cost candidate attack routes from entry points to Crown Jewels.
Validates non-negative finite traversal costs, supports multiple target assets,
enforces edge eligibility rules, and provides deterministic tie-breaking.
"""

import heapq
import math
import time
from typing import Dict, List, Optional, Any, Set, Tuple
import logging

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
)
from backend.models.graphops import (
    EnterpriseNode,
    EnterpriseRelationship,
    DijkstraEdgeCost,
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

logger = logging.getLogger("threatlens.graphops.dijkstra")

# Relationships permitted to participate in candidate attack-path traversal
PATH_ELIGIBLE_RELATIONSHIPS: Set[RelationshipType] = {
    RelationshipType.USES,
    RelationshipType.LOGGED_IN_TO,
    RelationshipType.AUTHENTICATED_TO,
    RelationshipType.OBSERVED_CONNECTION,
    RelationshipType.HAS_PERMISSION,
    RelationshipType.HOSTS,
    RelationshipType.HOSTED_ON,
    RelationshipType.CONTAINS_CRITICAL_DATA,
    RelationshipType.POTENTIAL_EXPLOIT,
    RelationshipType.EXPLOITS,
    RelationshipType.RUNS_ON,
    RelationshipType.CONNECTS_TO,
    RelationshipType.CAN_REACH,
}


class TraversalCostPolicy:
    """
    Defines and validates traversal-cost calculation for GraphOps attack-path edges.
    Cost represents attacker resistance / traversal friction where lower cost indicates
    easier or faster candidate traversal.

    Strict validation:
    - Costs must be strictly non-negative (>= 0.0).
    - Costs must be finite numbers (rejects NaN, +inf, -inf).
    - Extracts cost from explicit edge properties ('traversal_cost', 'weight', or 'cost').
    - If absent, assigns defensible baseline friction by relationship type and evidence class.
    """

    # Baseline friction by relationship type when explicit cost is absent
    DEFAULT_RELATIONSHIP_FRICTION: Dict[RelationshipType, float] = {
        RelationshipType.LOGGED_IN_TO: 1.0,
        RelationshipType.HAS_PERMISSION: 1.0,
        RelationshipType.OBSERVED_CONNECTION: 1.5,
        RelationshipType.AUTHENTICATED_TO: 1.5,
        RelationshipType.USES: 2.0,
        RelationshipType.HOSTS: 2.0,
        RelationshipType.HOSTED_ON: 2.0,
        RelationshipType.RUNS_ON: 2.0,
        RelationshipType.CONNECTS_TO: 2.5,
        RelationshipType.CAN_REACH: 2.5,
        RelationshipType.CONTAINS_CRITICAL_DATA: 3.0,
        RelationshipType.POTENTIAL_EXPLOIT: 4.0,
        RelationshipType.EXPLOITS: 4.0,
    }

    def calculate_edge_cost(
        self,
        relationship_type: RelationshipType,
        evidence_class: Optional[EvidenceClass] = None,
        explicit_weight: Optional[Any] = None,
        default_cost: float = 2.0,
    ) -> float:
        """
        Validates explicit weight or computes baseline cost.
        Raises ValueError if explicit weight is negative, NaN, or non-finite.
        """
        if explicit_weight is not None:
            try:
                cost = float(explicit_weight)
            except (ValueError, TypeError):
                raise ValueError(f"Traversal cost must be numeric, got: {explicit_weight}")

            if math.isnan(cost) or math.isinf(cost):
                raise ValueError(f"Traversal cost must be a finite number, got: {cost}")
            if cost < 0.0:
                raise ValueError(f"Traversal cost must be strictly non-negative (>= 0), got: {cost}")
            return cost

        base_friction = self.DEFAULT_RELATIONSHIP_FRICTION.get(relationship_type, default_cost)
        if evidence_class == EvidenceClass.HYPOTHETICAL:
            base_friction *= 1.5

        return round(base_friction, 2)


class DijkstraShortestPathEngine:
    """
    Genuine Dijkstra weighted shortest-path engine using a min-heap priority queue.
    Calculates minimum-cost attack paths, produces per-edge cost breakdowns,
    enforces non-negative finite weight validation, and supports What-If containment exclusions.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()
        self.blast_service = BlastRadiusService(self.client)
        self.cost_policy = TraversalCostPolicy()

    def _resolve_target_asset_ids(
        self,
        target_node_id: Optional[str],
        target_node_ids: Optional[List[str]],
    ) -> List[str]:
        """Resolves requested target ID(s) or defaults to all Crown Jewels in the graph."""
        if target_node_id:
            try:
                node = self.blast_service.resolve_start_node(target_node_id)
                return [node.id]
            except NodeNotFoundError:
                return [target_node_id.strip()]

        if target_node_ids:
            resolved = []
            for tid in target_node_ids:
                try:
                    node = self.blast_service.resolve_start_node(tid)
                    resolved.append(node.id)
                except NodeNotFoundError:
                    resolved.append(tid.strip())
            return resolved

        # Query all CriticalAsset nodes or CRITICAL tier nodes from graph
        cypher = """
        MATCH (c:CriticalAsset)
        RETURN c.id AS id
        UNION
        MATCH (n)
        WHERE n.criticality = 'CRITICAL'
        RETURN n.id AS id
        """
        try:
            records = self.client.execute_query(cypher)
            return [r["id"] for r in records if r.get("id")]
        except Exception as e:
            logger.warning(f"Failed to query all Crown Jewels: {e}")
            return []

    def _get_graph_snapshot(
        self,
        allowed_types: Set[RelationshipType],
        include_hypothetical: bool,
    ) -> Tuple[Dict[str, EnterpriseNode], List[Dict[str, Any]]]:
        """
        Retrieves a bounded graph snapshot of all path-eligible directed edges and nodes.
        Avoids querying Neo4j repeatedly inside traversal loops.
        """
        nodes_map: Dict[str, EnterpriseNode] = {}
        edges_list: List[Dict[str, Any]] = []

        # Support direct inspection of in-memory test clients
        if hasattr(self.client, "nodes") and hasattr(self.client, "edges"):
            for nid, n_dict in self.client.nodes.items():
                node_obj = self.blast_service._record_to_enterprise_node(
                    labels=n_dict.get("labels", []),
                    properties=n_dict.get("properties", {}),
                    fallback_id=n_dict.get("id"),
                )
                nodes_map[node_obj.id] = node_obj

            for e in self.client.edges:
                rel_type_str = e.get("relationship_type") or e.get("type")
                try:
                    rel_type = RelationshipType(rel_type_str)
                except ValueError:
                    continue

                if rel_type not in allowed_types:
                    continue

                ev_str = str(e.get("evidence_class", "OBSERVED")).upper()
                try:
                    ev_class = EvidenceClass(ev_str)
                except ValueError:
                    ev_class = EvidenceClass.OBSERVED

                if not include_hypothetical:
                    if rel_type == RelationshipType.POTENTIAL_EXPLOIT or ev_class == EvidenceClass.HYPOTHETICAL:
                        continue

                edges_list.append({
                    "source_id": e.get("source_id") or e.get("source"),
                    "target_id": e.get("target_id") or e.get("target"),
                    "relationship_type": rel_type,
                    "evidence_class": ev_class,
                    "properties": e.get("properties", {}),
                })
            return nodes_map, edges_list

        # Execute single snapshot query on Neo4j
        type_strings = [t.value for t in allowed_types]
        cypher = """
        MATCH (s)-[r]->(t)
        WHERE (size($allowed_types) = 0 OR type(r) IN $allowed_types)
          AND ($include_hypothetical OR (type(r) <> 'POTENTIAL_EXPLOIT' AND coalesce(r.evidence_class, 'OBSERVED') <> 'HYPOTHETICAL'))
        RETURN s.id AS source_id, labels(s) AS source_labels, properties(s) AS source_props,
               t.id AS target_id, labels(t) AS target_labels, properties(t) AS target_props,
               type(r) AS rel_type, properties(r) AS rel_props
        """
        params = {
            "allowed_types": type_strings,
            "include_hypothetical": bool(include_hypothetical),
        }

        try:
            records = self.client.execute_query(cypher, params)
        except Exception as e:
            logger.warning(f"Snapshot query returned empty or failed: {e}")
            records = []

        for rec in records:
            src_id = rec.get("source_id")
            tgt_id = rec.get("target_id")
            if not src_id or not tgt_id:
                continue

            if src_id not in nodes_map:
                nodes_map[src_id] = self.blast_service._record_to_enterprise_node(
                    labels=rec.get("source_labels", []),
                    properties=rec.get("source_props", {}),
                    fallback_id=src_id,
                )
            if tgt_id not in nodes_map:
                nodes_map[tgt_id] = self.blast_service._record_to_enterprise_node(
                    labels=rec.get("target_labels", []),
                    properties=rec.get("target_props", {}),
                    fallback_id=tgt_id,
                )

            rel_props = rec.get("rel_props") or {}
            rel_type_str = rec.get("rel_type")
            try:
                rel_type = RelationshipType(rel_type_str)
            except ValueError:
                continue

            ev_str = str(rel_props.get("evidence_class", "OBSERVED")).upper()
            try:
                ev_class = EvidenceClass(ev_str)
            except ValueError:
                ev_class = EvidenceClass.OBSERVED

            edges_list.append({
                "source_id": src_id,
                "target_id": tgt_id,
                "relationship_type": rel_type,
                "evidence_class": ev_class,
                "properties": rel_props,
            })

        return nodes_map, edges_list

    def find_shortest_path(
        self,
        request: DijkstraShortestPathRequest,
        disabled_node_ids: Optional[Set[str]] = None,
        disabled_edge_keys: Optional[Set[Tuple[str, str, str]]] = None,
        default_unweighted_cost: float = 1.0,
    ) -> DijkstraShortestPathResult:
        """
        Executes Dijkstra weighted shortest-path analysis from entry_node to designated critical asset(s).
        Returns minimum-cost path, per-edge cost breakdown, reachable targets, and execution metrics.
        """
        start_time = time.perf_counter()
        warnings: List[str] = []

        disabled_nodes = {nid.lower() for nid in (disabled_node_ids or set())}
        disabled_edges = {
            (src.lower(), tgt.lower(), rt)
            for src, tgt, rt in (disabled_edge_keys or set())
        }

        # 1. Resolve entry node
        entry_node = self.blast_service.resolve_start_node(request.entry_node_id)
        if entry_node.id.lower() in disabled_nodes:
            calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return DijkstraShortestPathResult(
                entry_node=entry_node,
                target_node=None,
                path_found=False,
                total_cost=None,
                hop_count=0,
                nodes=[],
                steps=[],
                reachable_targets=[],
                unreachable_targets=[],
                calculation_time_ms=calc_time_ms,
                warnings=["Entry node is isolated under simulated containment."],
            )

        # 2. Resolve target Crown Jewels
        target_ids_list = self._resolve_target_asset_ids(request.target_node_id, request.target_node_ids)
        target_ids = set(target_ids_list)
        target_ids.discard(entry_node.id)

        if not target_ids:
            calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return DijkstraShortestPathResult(
                entry_node=entry_node,
                target_node=None,
                path_found=False,
                total_cost=None,
                hop_count=0,
                nodes=[],
                steps=[],
                reachable_targets=[],
                unreachable_targets=[],
                calculation_time_ms=calc_time_ms,
                warnings=["No designated critical asset targets found in graph."],
            )

        # 3. Determine allowed relationship types
        if request.allowed_relationship_types:
            allowed_types = set(request.allowed_relationship_types).intersection(PATH_ELIGIBLE_RELATIONSHIPS)
            if not allowed_types:
                raise ValueError("None of the specified relationship types are eligible for attack path traversal.")
        else:
            allowed_types = PATH_ELIGIBLE_RELATIONSHIPS

        # 4. Retrieve graph snapshot and build adjacency list
        nodes_map, edges_list = self._get_graph_snapshot(
            allowed_types=allowed_types,
            include_hypothetical=request.include_hypothetical,
        )
        nodes_map[entry_node.id] = entry_node

        adj: Dict[str, List[Dict[str, Any]]] = {}
        for edge_dict in edges_list:
            src = edge_dict["source_id"]
            tgt = edge_dict["target_id"]
            rel_type = edge_dict["relationship_type"]
            ev_class = edge_dict["evidence_class"]
            props = edge_dict.get("properties") or {}

            # Traversal cost extraction & validation using TraversalCostPolicy
            cost_val = props.get("traversal_cost")
            if cost_val is None:
                cost_val = props.get("weight")
            if cost_val is None:
                cost_val = props.get("cost")

            if cost_val is not None:
                edge_cost = self.cost_policy.calculate_edge_cost(
                    relationship_type=rel_type,
                    evidence_class=ev_class,
                    explicit_weight=cost_val,
                    default_cost=default_unweighted_cost,
                )
            else:
                edge_cost = self.cost_policy.calculate_edge_cost(
                    relationship_type=rel_type,
                    evidence_class=ev_class,
                    explicit_weight=None,
                    default_cost=default_unweighted_cost,
                )
                warn_msg = f"Edge {src}->{tgt} ({rel_type.value}) lacked explicit traversal_cost; applied baseline friction {edge_cost}."
                if warn_msg not in warnings:
                    warnings.append(warn_msg)

            if src not in adj:
                adj[src] = []
            adj[src].append({
                "target_id": tgt,
                "cost": edge_cost,
                "relationship_type": rel_type,
                "evidence_class": ev_class,
                "properties": props,
            })

        # 5. Execute Dijkstra using min-heap priority queue
        distances: Dict[str, float] = {entry_node.id: 0.0}
        # predecessors[node_id] = (prev_id, edge_dict, edge_cost)
        predecessors: Dict[str, Tuple[str, Dict[str, Any], float]] = {}
        # Heap elements: (cumulative_cost, hop_depth, node_id)
        pq: List[Tuple[float, int, str]] = [(0.0, 0, entry_node.id)]
        visited: Set[str] = set()

        first_reached_target: Optional[str] = None

        while pq:
            curr_cost, curr_hops, curr_id = heapq.heappop(pq)

            if curr_id in visited:
                continue
            visited.add(curr_id)

            # Check if target reached
            if curr_id in target_ids:
                if first_reached_target is None:
                    first_reached_target = curr_id
                    # If evaluating a single specific target, we can stop immediately!
                    if request.target_node_id or len(target_ids) == 1:
                        break

            # Relax outgoing edges
            for edge in adj.get(curr_id, []):
                tgt_id = edge["target_id"]
                edge_cost = edge["cost"]
                rel_type = edge["relationship_type"]

                # Containment simulation filter
                if tgt_id.lower() in disabled_nodes:
                    continue
                edge_sig_typed = (curr_id.lower(), tgt_id.lower(), rel_type.value)
                edge_sig_untyped = (curr_id.lower(), tgt_id.lower(), "")
                if edge_sig_typed in disabled_edges or edge_sig_untyped in disabled_edges:
                    continue

                new_cost = curr_cost + edge_cost

                # Bounded maximum cost ceiling
                if request.max_cost is not None and new_cost > request.max_cost:
                    continue

                if new_cost < distances.get(tgt_id, float("inf")):
                    distances[tgt_id] = new_cost
                    predecessors[tgt_id] = (curr_id, edge, edge_cost)
                    heapq.heappush(pq, (new_cost, curr_hops + 1, tgt_id))

        # 6. Reconstruct optimal path to best target
        reachable_targets = [t for t in target_ids if t in distances]
        unreachable_targets = [t for t in target_ids if t not in distances]

        best_target_id = None
        if reachable_targets:
            # Select target with lowest cumulative distance
            best_target_id = min(reachable_targets, key=lambda t: (distances[t], t))

        calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        if not best_target_id:
            warnings.append("Target(s) unreachable from entry point under current graph reachability constraints.")
            return DijkstraShortestPathResult(
                entry_node=entry_node,
                target_node=None,
                path_found=False,
                total_cost=None,
                hop_count=0,
                nodes=[],
                steps=[],
                reachable_targets=[],
                unreachable_targets=unreachable_targets,
                calculation_time_ms=calc_time_ms,
                warnings=warnings,
            )

        # Backtrack from target to entry
        path_node_ids: List[str] = [best_target_id]
        reversed_edges: List[Tuple[str, str, Dict[str, Any], float]] = []
        curr = best_target_id
        while curr != entry_node.id:
            prev_id, edge_dict, cost = predecessors[curr]
            reversed_edges.append((prev_id, curr, edge_dict, cost))
            curr = prev_id
            path_node_ids.append(curr)

        path_node_ids.reverse()
        reversed_edges.reverse()

        # Build ordered EnterpriseNode list
        path_nodes: List[EnterpriseNode] = []
        for nid in path_node_ids:
            if nid in nodes_map:
                path_nodes.append(nodes_map[nid])
            else:
                try:
                    node_obj = self.blast_service.resolve_start_node(nid)
                    path_nodes.append(node_obj)
                except NodeNotFoundError:
                    path_nodes.append(EnterpriseNode(id=nid, label=NodeLabel.SERVER, name=nid))

        # Build per-edge breakdown
        steps: List[DijkstraEdgeCost] = []
        running_cost = 0.0
        for step_idx, (src_id, tgt_id, edge_dict, cost) in enumerate(reversed_edges, start=1):
            running_cost += cost
            rel_type = edge_dict["relationship_type"]
            ev_class = edge_dict["evidence_class"]
            props = edge_dict.get("properties") or {}

            # Generate SOC explanation
            desc = self._describe_step(src_id, tgt_id, rel_type, props)
            rationale = (
                f"Traversed {rel_type.value} edge with cost {cost} (cumulative cost: {round(running_cost, 2)}). "
                f"Evidence: {ev_class.value}."
            )

            steps.append(
                DijkstraEdgeCost(
                    step_number=step_idx,
                    source_id=src_id,
                    target_id=tgt_id,
                    relationship_type=rel_type,
                    evidence_class=ev_class,
                    cost=cost,
                    accumulated_cost=round(running_cost, 4),
                    provenance=props.get("provenance", "System Topology"),
                    description=desc,
                    rationale=rationale,
                )
            )

        target_node = path_nodes[-1]
        total_accumulated_cost = round(distances[best_target_id], 4)

        return DijkstraShortestPathResult(
            entry_node=entry_node,
            target_node=target_node,
            path_found=True,
            total_cost=total_accumulated_cost,
            hop_count=len(steps),
            nodes=path_nodes,
            steps=steps,
            reachable_targets=reachable_targets,
            unreachable_targets=unreachable_targets,
            cost_model_description=(
                "Dijkstra weighted shortest-path analysis using min-heap priority queue. "
                "Calculates lowest cumulative friction/difficulty candidate route."
            ),
            calculation_time_ms=calc_time_ms,
            warnings=warnings,
        )

    def _describe_step(
        self,
        src_id: str,
        tgt_id: str,
        rel_type: RelationshipType,
        props: Dict[str, Any],
    ) -> str:
        """Helper to create human-readable step explanations."""
        port = props.get("port")
        proto = props.get("protocol", "TCP")
        port_info = f" on port {port}/{proto}" if port else ""

        if rel_type == RelationshipType.USES:
            return f"User session on assigned endpoint {tgt_id}."
        elif rel_type == RelationshipType.OBSERVED_CONNECTION:
            return f"Observed network traffic from {src_id} to {tgt_id}{port_info}."
        elif rel_type == RelationshipType.LOGGED_IN_TO:
            return f"Active authenticated interactive logon on {tgt_id}."
        elif rel_type == RelationshipType.HAS_PERMISSION:
            priv = props.get("privilege_level", "ACCESS")
            return f"Authorized permission grant ({priv}) on {tgt_id}."
        elif rel_type == RelationshipType.HOSTS:
            return f"Host infrastructure executes component {tgt_id}."
        elif rel_type == RelationshipType.CONTAINS_CRITICAL_DATA:
            return f"System hosts designated Crown Jewel repository {tgt_id}."
        elif rel_type == RelationshipType.POTENTIAL_EXPLOIT:
            cve = props.get("via_cve", "CVE")
            return f"Potential exploit vector exploiting {cve} to pivot to {tgt_id}."
        return f"Traversed from {src_id} to {tgt_id} via {rel_type.value}."
