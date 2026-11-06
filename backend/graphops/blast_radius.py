"""
ThreatLens GraphOps - Blast-Radius Analytics Engine
Calculates bounded 1-hop, 2-hop, and 3-hop blast-radius neighborhoods from a potentially
compromised entity with strict minimum-hop distances, cycle avoidance, evidence separation,
critical-asset highlighting, and subgraph construction for Cytoscape.js visualization.
"""

import time
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple
import logging

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    TraversalDirection,
)
from backend.models.graphops import (
    EnterpriseNode,
    EnterpriseRelationship,
    BlastRadiusRequest,
    BlastRadiusHopGroup,
    CriticalAssetExposure,
    BlastRadiusResult,
    BlastRadiusContainmentResult,
    ProposedIntervention,
)
from backend.graphops.client import Neo4jClient, get_graphops_client, GraphOpsConnectionError

logger = logging.getLogger("threatlens.graphops.blast_radius")


class NodeNotFoundError(ValueError):
    """Raised when a requested start node or alias does not exist in the security graph."""
    pass


class BlastRadiusService:
    """
    Dedicated service for multi-hop blast-radius analysis across the organizational security graph.
    Enforces bounded traversal (max 3 hops), strict minimum-hop BFS distance assignment,
    cycle and multi-path deduplication, evidence categorization, and Crown Jewel exposure analysis.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    def resolve_start_node(self, node_id_or_alias: str) -> EnterpriseNode:
        """
        Locates an existing node in Neo4j by canonical identifier or common attribute alias
        (e.g., email address, hostname, user_id, device_id, server_id, asset_id).
        Raises NodeNotFoundError if no matching entity exists in the graph.
        """
        clean_id = node_id_or_alias.strip()
        id_without_prefix = clean_id.split(":", 1)[1] if ":" in clean_id else clean_id

        cypher = """
        MATCH (n)
        WHERE n.id = $id
           OR toLower(n.id) = toLower($id)
           OR toLower(coalesce(n.email, '')) = toLower($id)
           OR toLower(coalesce(n.email, '')) = toLower($id_without_prefix)
           OR toLower(coalesce(n.hostname, '')) = toLower($id)
           OR toLower(coalesce(n.hostname, '')) = toLower($id_without_prefix)
           OR toLower(coalesce(n.user_id, '')) = toLower($id)
           OR toLower(coalesce(n.user_id, '')) = toLower($id_without_prefix)
           OR toLower(coalesce(n.device_id, '')) = toLower($id)
           OR toLower(coalesce(n.device_id, '')) = toLower($id_without_prefix)
           OR toLower(coalesce(n.server_id, '')) = toLower($id)
           OR toLower(coalesce(n.server_id, '')) = toLower($id_without_prefix)
           OR toLower(coalesce(n.asset_id, '')) = toLower($id)
           OR toLower(coalesce(n.asset_id, '')) = toLower($id_without_prefix)
        RETURN n.id AS id, labels(n) AS labels, properties(n) AS properties
        LIMIT 1
        """
        params = {"id": clean_id, "id_without_prefix": id_without_prefix}
        records = self.client.execute_query(cypher, params)

        if not records:
            raise NodeNotFoundError(
                f"Start node '{node_id_or_alias}' does not exist in the security graph."
            )

        rec = records[0]
        return self._record_to_enterprise_node(
            labels=rec.get("labels", []),
            properties=rec.get("properties", {}),
            fallback_id=rec.get("id"),
        )

    def _record_to_enterprise_node(
        self,
        labels: List[str],
        properties: Dict[str, Any],
        fallback_id: Optional[str] = None,
    ) -> EnterpriseNode:
        """Constructs a validated EnterpriseNode from raw Neo4j record properties."""
        node_id = properties.get("id") or fallback_id or ""

        # Map labels to primary NodeLabel
        primary_label = NodeLabel.SERVER
        for lbl in labels:
            try:
                primary_label = NodeLabel(lbl)
                break
            except ValueError:
                continue

        # Friendly display name
        name = (
            properties.get("name")
            or properties.get("hostname")
            or properties.get("email")
            or properties.get("cve_id")
            or properties.get("ip")
            or properties.get("user_id")
            or properties.get("device_id")
            or properties.get("server_id")
            or properties.get("asset_id")
            or node_id
        )

        # Criticality rating
        crit_tier: Optional[CriticalityTier] = None
        crit_val = properties.get("criticality")
        if crit_val:
            try:
                crit_tier = CriticalityTier(str(crit_val).upper())
            except ValueError:
                pass

        if primary_label == NodeLabel.CRITICAL_ASSET and not crit_tier:
            impact = properties.get("impact_score", 0)
            crit_tier = CriticalityTier.CRITICAL if impact >= 90 else CriticalityTier.HIGH

        return EnterpriseNode(
            id=node_id,
            label=primary_label,
            name=name,
            criticality=crit_tier,
            properties=properties,
        )

    def _is_critical_asset(
        self,
        node: EnterpriseNode,
        labels: List[str],
        props: Dict[str, Any],
    ) -> bool:
        """Determines if a reachable entity qualifies as a designated Crown Jewel."""
        if node.label == NodeLabel.CRITICAL_ASSET:
            return True
        if NodeLabel.CRITICAL_ASSET.value in labels:
            return True
        if node.criticality == CriticalityTier.CRITICAL:
            return True
        if int(props.get("impact_score", 0)) >= 85:
            return True
        return False

    def _query_frontier_edges(
        self,
        frontier_ids: List[str],
        direction: TraversalDirection,
        allowed_types: Optional[List[str]],
        include_hypothetical: bool,
    ) -> List[Dict[str, Any]]:
        """
        Executes a bounded parameterized Cypher query expanding the current BFS frontier
        along the specified direction and relationship constraints.
        """
        if not frontier_ids:
            return []

        if direction == TraversalDirection.OUTGOING:
            pattern = "(s)-[r]->(t)"
        elif direction == TraversalDirection.INCOMING:
            pattern = "(s)<-[r]-(t)"
        else:  # BOTH
            pattern = "(s)-[r]-(t)"

        cypher = f"""
        MATCH (s)
        WHERE s.id IN $frontier_ids
        MATCH {pattern}
        WHERE (size($allowed_types) = 0 OR type(r) IN $allowed_types)
          AND ($include_hypothetical OR (type(r) <> 'POTENTIAL_EXPLOIT' AND coalesce(r.evidence_class, 'OBSERVED') <> 'HYPOTHETICAL'))
        RETURN s.id AS frontier_id,
               t.id AS neighbor_id,
               labels(t) AS neighbor_labels,
               properties(t) AS neighbor_props,
               type(r) AS rel_type,
               startNode(r).id AS rel_source_id,
               endNode(r).id AS rel_target_id,
               properties(r) AS rel_props
        """
        params = {
            "frontier_ids": frontier_ids,
            "allowed_types": allowed_types or [],
            "include_hypothetical": bool(include_hypothetical),
        }
        return self.client.execute_query(cypher, params)

    def calculate_blast_radius(
        self,
        request: BlastRadiusRequest,
        disabled_node_ids: Optional[Set[str]] = None,
        disabled_edge_keys: Optional[Set[Tuple[str, str, str]]] = None,
    ) -> BlastRadiusResult:
        """
        Calculates bounded 1-hop, 2-hop, and 3-hop blast radius neighborhoods using BFS.
        Guarantees minimum-hop distance, eliminates duplicate visits, identifies exposed
        Crown Jewels, and constructs a connected subgraph. Supports in-memory What-If
        containment simulation by suppressing specified disabled nodes and edge keys.
        """
        start_time = time.perf_counter()

        # Validate depth boundary
        if request.max_hops < 1 or request.max_hops > 3:
            raise ValueError(f"max_hops must be between 1 and 3, received {request.max_hops}")

        # Validate allowed relationship types if specified
        allowed_types_list: Optional[List[str]] = None
        if request.allowed_relationship_types:
            allowed_types_list = []
            for t in request.allowed_relationship_types:
                val = t.value if hasattr(t, "value") else str(t)
                if val not in RelationshipType._value2member_map_:
                    raise ValueError(f"Invalid relationship type filter: '{val}'")
                allowed_types_list.append(val)

        # Resolve initial compromise root entity
        start_node = self.resolve_start_node(request.start_node_id)

        # What-If containment check on root entity
        disabled_nodes = {nid.lower() for nid in (disabled_node_ids or set())}
        disabled_edges = {(src.lower(), tgt.lower(), rt) for src, tgt, rt in (disabled_edge_keys or set())}

        if disabled_nodes and start_node.id.lower() in disabled_nodes:
            calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return BlastRadiusResult(
                start_node=start_node,
                max_hops_evaluated=request.max_hops,
                direction=request.direction,
                hop_1=BlastRadiusHopGroup(hop_number=1, node_count=0, nodes=[], critical_asset_count=0),
                hop_2=BlastRadiusHopGroup(hop_number=2, node_count=0, nodes=[], critical_asset_count=0),
                hop_3=BlastRadiusHopGroup(hop_number=3, node_count=0, nodes=[], critical_asset_count=0),
                total_reachable_nodes=0,
                critical_assets_at_risk=[],
                subgraph_nodes=[start_node],
                subgraph_edges=[],
                summary_assessment=f"Isolated entity: Start node '{start_node.name}' ({start_node.id}) is isolated under simulated containment.",
                calculation_time_ms=calc_time_ms,
                warnings=["Start node is isolated under simulated containment."],
            )

        # Bounded traversal warnings
        warnings: List[str] = []
        if request.max_hops == 3:
            warnings.append(
                "Bounded traversal: Traversal reached maximum evaluation limit of 3 hops; "
                "entities beyond 3 hops were not evaluated."
            )
        if request.include_hypothetical:
            warnings.append(
                "Includes hypothetical attack transitions (e.g. unpatched vulnerabilities). "
                "Modeled paths indicate architectural exposure, not confirmed attacker traversal."
            )

        # BFS state trackers
        visited_ids: Set[str] = {start_node.id}
        shortest_path_to: Dict[str, List[str]] = {start_node.id: [start_node.id]}
        hop_nodes_map: Dict[int, List[EnterpriseNode]] = {1: [], 2: [], 3: []}
        critical_assets_at_risk: List[CriticalAssetExposure] = []
        subgraph_nodes: List[EnterpriseNode] = [start_node]
        subgraph_edges_map: Dict[str, EnterpriseRelationship] = {}
        evidence_counts: Dict[str, int] = {
            "OBSERVED": 0,
            "AUTHORIZED_ACCESS": 0,
            "INFERRED": 0,
            "HYPOTHETICAL": 0,
        }

        current_frontier = [start_node.id]

        # Multi-hop Breadth-First Search
        for current_hop in range(1, request.max_hops + 1):
            if not current_frontier:
                break

            records = self._query_frontier_edges(
                frontier_ids=current_frontier,
                direction=request.direction,
                allowed_types=allowed_types_list,
                include_hypothetical=request.include_hypothetical,
            )

            next_frontier_candidates: List[str] = []

            for rec in records:
                frontier_id = rec["frontier_id"]
                neighbor_id = rec["neighbor_id"]
                rel_type_str = rec["rel_type"]
                rel_props = rec.get("rel_props") or {}

                # Determine true native edge endpoints
                rel_source_id = rec.get("rel_source_id") or (
                    frontier_id if request.direction == TraversalDirection.OUTGOING else neighbor_id
                )
                rel_target_id = rec.get("rel_target_id") or (
                    neighbor_id if request.direction == TraversalDirection.OUTGOING else frontier_id
                )

                # What-If containment checks: disabled nodes and edges
                if disabled_nodes and (neighbor_id.lower() in disabled_nodes or frontier_id.lower() in disabled_nodes):
                    continue

                if disabled_edges:
                    edge_tuple = (rel_source_id.lower(), rel_target_id.lower(), rel_type_str)
                    edge_tuple_wildcard = (rel_source_id.lower(), rel_target_id.lower(), "")
                    if edge_tuple in disabled_edges or edge_tuple_wildcard in disabled_edges:
                        continue

                # Validate relationship type enum
                try:
                    rel_type = RelationshipType(rel_type_str)
                except ValueError:
                    continue

                # Evidence categorization
                ev_str = str(rel_props.get("evidence_class", "OBSERVED")).upper()
                try:
                    ev_class = EvidenceClass(ev_str)
                except ValueError:
                    ev_class = EvidenceClass.OBSERVED

                evidence_counts[ev_class.value] = evidence_counts.get(ev_class.value, 0) + 1

                # Subgraph edge registration
                edge_id = f"{rel_source_id}->{rel_target_id}:{rel_type.value}"
                if edge_id not in subgraph_edges_map:
                    edge = EnterpriseRelationship(
                        id=edge_id,
                        source_id=rel_source_id,
                        target_id=rel_target_id,
                        relationship_type=rel_type,
                        evidence_class=ev_class,
                        source_record_id=rel_props.get("source_record_id"),
                        provenance=rel_props.get("provenance", "System Inventory"),
                        timestamp=rel_props.get("timestamp"),
                        confidence=float(rel_props.get("confidence", 1.0)),
                        properties=rel_props,
                    )
                    subgraph_edges_map[edge_id] = edge

                # Check neighbor node: if already visited at a strictly smaller or equal hop, skip node creation
                if neighbor_id not in visited_ids:
                    visited_ids.add(neighbor_id)
                    neighbor_labels = rec.get("neighbor_labels") or []
                    neighbor_props = rec.get("neighbor_props") or {}
                    neighbor_node = self._record_to_enterprise_node(
                        labels=neighbor_labels,
                        properties=neighbor_props,
                        fallback_id=neighbor_id,
                    )

                    hop_nodes_map[current_hop].append(neighbor_node)
                    subgraph_nodes.append(neighbor_node)

                    # Minimum hop shortest path assignment
                    shortest_path_to[neighbor_id] = shortest_path_to[frontier_id] + [neighbor_id]
                    next_frontier_candidates.append(neighbor_id)

                    # Crown Jewel exposure check
                    if self._is_critical_asset(neighbor_node, neighbor_labels, neighbor_props):
                        critical_assets_at_risk.append(
                            CriticalAssetExposure(
                                asset_id=neighbor_id,
                                name=neighbor_node.name,
                                category=neighbor_props.get(
                                    "category",
                                    "CROWN_JEWEL" if neighbor_node.label == NodeLabel.CRITICAL_ASSET else neighbor_node.label.value.upper(),
                                ),
                                impact_score=int(
                                    neighbor_props.get(
                                        "impact_score",
                                        100 if neighbor_node.criticality == CriticalityTier.CRITICAL else 85,
                                    )
                                ),
                                hop_depth=current_hop,
                                shortest_path_nodes=shortest_path_to[neighbor_id],
                                reachability_status="EXPOSED",
                            )
                        )

            # Advance frontier to newly discovered distinct entities
            current_frontier = next_frontier_candidates

        # Assemble strictly separated hop groups
        hop_1 = BlastRadiusHopGroup(
            hop_number=1,
            node_count=len(hop_nodes_map[1]),
            nodes=hop_nodes_map[1],
            critical_asset_count=sum(1 for c in critical_assets_at_risk if c.hop_depth == 1),
        )
        hop_2 = BlastRadiusHopGroup(
            hop_number=2,
            node_count=len(hop_nodes_map[2]),
            nodes=hop_nodes_map[2],
            critical_asset_count=sum(1 for c in critical_assets_at_risk if c.hop_depth == 2),
        )
        hop_3 = BlastRadiusHopGroup(
            hop_number=3,
            node_count=len(hop_nodes_map[3]),
            nodes=hop_nodes_map[3],
            critical_asset_count=sum(1 for c in critical_assets_at_risk if c.hop_depth == 3),
        )

        total_reachable = len(hop_nodes_map[1]) + len(hop_nodes_map[2]) + len(hop_nodes_map[3])
        calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Generate descriptive SOC analyst assessment
        summary_assessment = self._generate_summary_assessment(
            start_node=start_node,
            max_hops=request.max_hops,
            direction=request.direction,
            total_reachable=total_reachable,
            critical_assets=critical_assets_at_risk,
            evidence_counts=evidence_counts,
            hop_counts={1: len(hop_nodes_map[1]), 2: len(hop_nodes_map[2]), 3: len(hop_nodes_map[3])},
        )

        return BlastRadiusResult(
            start_node=start_node,
            max_hops_evaluated=request.max_hops,
            direction=request.direction,
            hop_1=hop_1,
            hop_2=hop_2,
            hop_3=hop_3,
            total_reachable_nodes=total_reachable,
            critical_assets_at_risk=critical_assets_at_risk,
            subgraph_nodes=subgraph_nodes,
            subgraph_edges=list(subgraph_edges_map.values()),
            summary_assessment=summary_assessment,
            calculation_time_ms=calc_time_ms,
            warnings=warnings,
        )

    def _generate_summary_assessment(
        self,
        start_node: EnterpriseNode,
        max_hops: int,
        direction: TraversalDirection,
        total_reachable: int,
        critical_assets: List[CriticalAssetExposure],
        evidence_counts: Dict[str, int],
        hop_counts: Dict[int, int],
    ) -> str:
        """Constructs an explanatory SOC assessment distinguishing evidence certainty tiers."""
        dir_label = direction.value.lower()
        if total_reachable == 0:
            return (
                f"Isolated entity: Zero reachable assets discovered within {max_hops} hops ({dir_label}) "
                f"from initial entity '{start_node.name}' ({start_node.id})."
            )

        lines = [
            f"Compromise of {start_node.name} ({start_node.id}) exposes {total_reachable} reachable entities "
            f"within {max_hops} {dir_label} hops (Hop 1: {hop_counts[1]}, Hop 2: {hop_counts[2]}, Hop 3: {hop_counts[3]})."
        ]

        # Evidence classification breakdown
        ev_parts = []
        if evidence_counts.get("OBSERVED", 0) > 0:
            ev_parts.append(f"{evidence_counts['OBSERVED']} observed connections")
        if evidence_counts.get("AUTHORIZED_ACCESS", 0) > 0:
            ev_parts.append(f"{evidence_counts['AUTHORIZED_ACCESS']} authorized access grants")
        if evidence_counts.get("INFERRED", 0) > 0:
            ev_parts.append(f"{evidence_counts['INFERRED']} inferred links")
        if evidence_counts.get("HYPOTHETICAL", 0) > 0:
            ev_parts.append(f"{evidence_counts['HYPOTHETICAL']} hypothetical exploit vectors")

        if ev_parts:
            lines.append(f"Evidence basis: {', '.join(ev_parts)}.")

        # Critical assets exposure
        if critical_assets:
            jewel_names = [f"{c.name} (hop {c.hop_depth}, impact {c.impact_score})" for c in critical_assets]
            lines.append(
                f"CRITICAL ASSETS AT RISK ({len(critical_assets)}): {'; '.join(jewel_names)}. "
                f"Immediate containment or credential rotation recommended."
            )
        else:
            lines.append("No designated Crown Jewel assets exposed within current traversal depth.")

        lines.append("Reachable assets represent architectural exposure, not confirmed compromise.")
        return " ".join(lines)

    def simulate_blast_containment(
        self,
        request: BlastRadiusRequest,
        proposed_interventions: List[ProposedIntervention],
    ) -> BlastRadiusContainmentResult:
        """
        Calculates baseline vs simulated blast-radius reachability under hypothetical containment interventions.
        Guarantees zero live-graph modification.
        """
        # Baseline
        baseline_res = self.calculate_blast_radius(request)

        # Parse interventions
        disabled_node_ids: Set[str] = set()
        disabled_edge_keys: Set[Tuple[str, str, str]] = set()

        for interv in proposed_interventions:
            if interv.node_id:
                disabled_node_ids.add(interv.node_id.strip())
            if interv.source_id and interv.target_id:
                rt = interv.relationship_type.value if interv.relationship_type else ""
                disabled_edge_keys.add((interv.source_id.strip(), interv.target_id.strip(), rt))

        # Simulated
        sim_res = self.calculate_blast_radius(
            request=request,
            disabled_node_ids=disabled_node_ids,
            disabled_edge_keys=disabled_edge_keys,
        )

        baseline_ids = {n.id for h in [baseline_res.hop_1, baseline_res.hop_2, baseline_res.hop_3] for n in h.nodes}
        sim_ids = {n.id for h in [sim_res.hop_1, sim_res.hop_2, sim_res.hop_3] for n in h.nodes}

        eliminated_ids = sorted(list(baseline_ids - sim_ids))
        remaining_ids = sorted(list(sim_ids))

        baseline_crit = {c.asset_id for c in baseline_res.critical_assets_at_risk}
        remaining_crit = {c.asset_id for c in sim_res.critical_assets_at_risk}
        eliminated_crit = sorted(list(baseline_crit - remaining_crit))

        eliminated_count = len(eliminated_ids)
        efficiency = (
            round((eliminated_count / max(1, len(baseline_ids))) * 100.0, 1)
            if len(baseline_ids) > 0
            else 0.0
        )

        if len(remaining_ids) == 0 and len(baseline_ids) > 0:
            verdict = f"Full blast-radius containment: All {len(baseline_ids)} previously reachable entities successfully isolated."
        elif len(baseline_ids) == 0:
            verdict = "Zero baseline entities reachable; target entity was already isolated."
        else:
            verdict = (
                f"Partial blast-radius containment: Isolated {eliminated_count} of {len(baseline_ids)} entities "
                f"({efficiency}% reduction). {len(remaining_ids)} entities remain reachable."
            )

        return BlastRadiusContainmentResult(
            simulation_id=f"SIM-BLAST-{uuid.uuid4().hex[:8].upper()}",
            entry_node_id=baseline_res.start_node.id,
            max_hops=request.max_hops,
            live_graph_modified=False,
            baseline_reachable_nodes_count=len(baseline_ids),
            simulated_reachable_nodes_count=len(remaining_ids),
            eliminated_nodes_count=eliminated_count,
            containment_efficiency_pct=efficiency,
            baseline_critical_assets_count=len(baseline_crit),
            remaining_critical_assets_count=len(remaining_crit),
            eliminated_critical_assets_count=len(eliminated_crit),
            eliminated_node_ids=eliminated_ids,
            remaining_node_ids=remaining_ids,
            analyst_verdict=verdict,
        )


# Global default blast radius service instance
default_blast_radius_service = BlastRadiusService()

