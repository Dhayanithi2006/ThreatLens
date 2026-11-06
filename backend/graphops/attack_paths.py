"""
ThreatLens GraphOps - Attack-Path Discovery & Choke-Point Analytics Engine
Discovers plausible lateral movement paths from compromised entry points to high-value Crown Jewels,
calculates explainable risk scores, identifies critical structural choke points, and provides
a simulation-friendly interface for in-memory containment testing.
"""

from datetime import datetime, timezone
import time
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple
import logging

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    InterventionAction,
)
from backend.models.graphops import (
    EnterpriseNode,
    EnterpriseRelationship,
    AttackPathRequest,
    AttackPathStep,
    AttackPathItem,
    AttackPathResult,
    ChokePointRequest,
    ChokePointItem,
    ChokePointResult,
    SimulatedPathStatus,
    ProposedIntervention,
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
    CaseBridgeResponse,
    BridgeMappingItem,
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
)
from backend.graphops.client import Neo4jClient, get_graphops_client, GraphOpsConnectionError
from backend.graphops.blast_radius import NodeNotFoundError, BlastRadiusService
from backend.graphops.dijkstra import DijkstraShortestPathEngine

logger = logging.getLogger("threatlens.graphops.attack_paths")


class CaseNotFoundError(ValueError):
    """Raised when an email investigation case does not exist in the case repository."""
    pass

# Explicitly documented relationship types eligible for lateral movement traversal
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

MAX_PATHS_LIMIT = 50


class AttackPathService:
    """
    Dedicated service for candidate attack-path discovery, risk-cost modeling,
    betweenness choke-point identification, and in-memory intervention simulation.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()
        self.blast_service = BlastRadiusService(self.client)
        self.dijkstra_engine = DijkstraShortestPathEngine(self.client)

    def _resolve_target_asset_ids(self, requested_target_ids: Optional[List[str]]) -> List[str]:
        """
        Resolves target IDs. If omitted, queries all designated Crown Jewels from the graph.
        """
        if requested_target_ids:
            resolved = []
            for tid in requested_target_ids:
                try:
                    node = self.blast_service.resolve_start_node(tid)
                    resolved.append(node.id)
                except NodeNotFoundError:
                    resolved.append(tid)
            return resolved

        # Query all CriticalAsset nodes or nodes with CRITICAL criticality
        cypher = """
        MATCH (c:CriticalAsset)
        RETURN c.id AS id
        UNION
        MATCH (n)
        WHERE n.criticality = 'CRITICAL'
        RETURN n.id AS id
        """
        records = self.client.execute_query(cypher)
        return [r["id"] for r in records if r.get("id")]

    def _calculate_step_feasibility(
        self,
        rel_type: RelationshipType,
        evidence_class: EvidenceClass,
        rel_props: Dict[str, Any],
    ) -> Tuple[int, str]:
        """
        Calculates feasibility score (0-100) and rationale for a single step.
        - OBSERVED: Verified live telemetry (NetFlow, active logon) -> 90
        - AUTHORIZED_ACCESS: Existing directory permissions -> 80
        - INFERRED: Proximity heuristic -> 60
        - HYPOTHETICAL: Exploit precondition based on verified CVE score
        """
        if evidence_class == EvidenceClass.OBSERVED:
            return 90, "Active observed communication or logon session telemetry."
        elif evidence_class == EvidenceClass.AUTHORIZED_ACCESS:
            priv = rel_props.get("privilege_level", "STANDARD")
            return 80, f"Granted directory entitlement or role assignment ({priv})."
        elif evidence_class == EvidenceClass.INFERRED:
            return 60, "Inferred architectural proximity or subnet routing."
        elif evidence_class == EvidenceClass.HYPOTHETICAL:
            via_cve = rel_props.get("via_cve") or rel_props.get("cve_id")
            if via_cve:
                return 75, f"Simulated exploit vector leveraging vulnerability {via_cve}."
            return 50, "Hypothetical pivot vector (severity unconfirmed)."
        return 70, "Standard access pathway."

    def _generate_step_description(
        self,
        src_id: str,
        tgt_id: str,
        rel_type: RelationshipType,
        rel_props: Dict[str, Any],
    ) -> str:
        """Constructs a clear SOC description for an individual step."""
        port = rel_props.get("port")
        proto = rel_props.get("protocol", "TCP")
        port_info = f" (Port {port}/{proto})" if port else ""

        if rel_type == RelationshipType.USES:
            return f"User session on assigned device {tgt_id}."
        elif rel_type == RelationshipType.OBSERVED_CONNECTION:
            return f"Observed network traffic from {src_id} to {tgt_id}{port_info}."
        elif rel_type == RelationshipType.LOGGED_IN_TO:
            return f"Active authenticated interactive logon session on {tgt_id}."
        elif rel_type == RelationshipType.HAS_PERMISSION:
            priv = rel_props.get("privilege_level", "ACCESS")
            return f"Authorized permission grant ({priv}) on {tgt_id}."
        elif rel_type == RelationshipType.HOSTS:
            return f"Host infrastructure executes service component {tgt_id}."
        elif rel_type == RelationshipType.CONTAINS_CRITICAL_DATA:
            return f"Database/host stores designated Crown Jewel repository {tgt_id}."
        elif rel_type == RelationshipType.POTENTIAL_EXPLOIT:
            cve = rel_props.get("via_cve", "CVE")
            vector = rel_props.get("attack_vector", "Remote Exploit")
            return f"Potential attack vector exploiting {cve} ({vector}) to pivot to {tgt_id}."
        return f"Transition from {src_id} to {tgt_id} via {rel_type.value}."

    def _compute_path_risk_score(
        self,
        target_impact: int,
        steps: List[AttackPathStep],
        step_feasibilities: List[int],
    ) -> int:
        """
        Computes composite path risk score (0-100) based on:
        - Target business impact (55% weight)
        - Mean step feasibility (45% weight)
        - Hop length penalty (-3 per hop beyond 1)
        """
        mean_feasibility = sum(step_feasibilities) / max(1, len(step_feasibilities))
        hop_penalty = (len(steps) - 1) * 3
        raw_score = int(target_impact * 0.55 + mean_feasibility * 0.45 - hop_penalty)
        return max(5, min(100, raw_score))

    def _find_paths_graph_search(
        self,
        entry_node: EnterpriseNode,
        target_ids: Set[str],
        max_depth: int,
        include_hypothetical: bool,
        allowed_types: Optional[Set[RelationshipType]],
        disabled_node_ids: Set[str],
        disabled_edge_keys: Set[Tuple[str, str, str]],
    ) -> List[Dict[str, Any]]:
        """
        Finds bounded acyclic paths from entry_node to targets using Neo4j Cypher queries
        or local graph expansion.
        """
        type_filter = allowed_types or PATH_ELIGIBLE_RELATIONSHIPS
        type_strings = [t.value for t in type_filter]

        # Use Cypher for paths
        cypher = f"""
        MATCH (start {{id: $entry_id}}), (target)
        WHERE target.id IN $target_ids
        MATCH p = (start)-[r*1..{max_depth}]->(target)
        WHERE ALL(rel IN relationships(p) WHERE type(rel) IN $allowed_types)
          AND ALL(rel IN relationships(p) WHERE $include_hypothetical OR (type(rel) <> 'POTENTIAL_EXPLOIT' AND coalesce(rel.evidence_class, 'OBSERVED') <> 'HYPOTHETICAL'))
        RETURN [n IN nodes(p) | {{id: n.id, labels: labels(n), properties: properties(n)}}] AS path_nodes,
               [rel IN relationships(p) | {{
                   type: type(rel),
                   source_id: startNode(rel).id,
                   target_id: endNode(rel).id,
                   evidence_class: coalesce(rel.evidence_class, 'OBSERVED'),
                   properties: properties(rel)
               }}] AS path_relationships
        LIMIT $limit
        """
        params = {
            "entry_id": entry_node.id,
            "target_ids": list(target_ids),
            "allowed_types": type_strings,
            "include_hypothetical": bool(include_hypothetical),
            "limit": MAX_PATHS_LIMIT,
        }

        try:
            records = self.client.execute_query(cypher, params)
        except Exception as e:
            logger.warning(f"Cypher path query fallback or empty: {e}")
            records = []

        # Filter out disabled nodes and edges for simulation mode
        filtered_records = []
        for rec in records:
            p_nodes = rec["path_nodes"]
            p_rels = rec["path_relationships"]

            # Check if any intermediate node is disabled
            node_ids = {n["id"] for n in p_nodes}
            if node_ids.intersection(disabled_node_ids):
                continue

            # Check if any edge is disabled
            has_disabled_edge = False
            for r in p_rels:
                src_l = r["source_id"].lower()
                tgt_l = r["target_id"].lower()
                rel_t = r["type"]
                if (src_l, tgt_l, rel_t) in disabled_edge_keys or (src_l, tgt_l, "") in disabled_edge_keys:
                    has_disabled_edge = True
                    break
            if has_disabled_edge:
                continue

            filtered_records.append(rec)

        return filtered_records

    def find_dijkstra_shortest_path(
        self,
        request: DijkstraShortestPathRequest,
        disabled_node_ids: Optional[Set[str]] = None,
        disabled_edge_keys: Optional[Set[Tuple[str, str, str]]] = None,
    ) -> DijkstraShortestPathResult:
        """
        Calculates the genuine minimum-cost candidate attack route using Dijkstra weighted shortest-path algorithm.
        Supports multiple target assets, per-edge cost breakdown, and What-If containment exclusions.
        """
        return self.dijkstra_engine.find_shortest_path(
            request=request,
            disabled_node_ids=disabled_node_ids,
            disabled_edge_keys=disabled_edge_keys,
        )

    def find_attack_paths(
        self,
        request: AttackPathRequest,
        disabled_node_ids: Optional[Set[str]] = None,
        disabled_edge_keys: Optional[Set[Tuple[str, str, str]]] = None,
    ) -> AttackPathResult:
        """
        Discovers candidate attack paths from entry point to target critical assets.
        Supports in-memory simulation by filtering out disabled nodes or edges.
        """
        start_time = time.perf_counter()
        disabled_nodes = {nid.lower() for nid in (disabled_node_ids or set())}
        disabled_edges = {(src.lower(), tgt.lower(), rt) for src, tgt, rt in (disabled_edge_keys or set())}

        # Resolve entry node
        entry_node = self.blast_service.resolve_start_node(request.entry_node_id)
        if entry_node.id.lower() in disabled_nodes:
            # Entry node itself is isolated in simulation
            calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return AttackPathResult(
                entry_node=entry_node,
                total_paths_discovered=0,
                paths=[],
                targets_reached=[],
                calculation_time_ms=calc_time_ms,
                warnings=["Entry node is isolated under simulated containment."],
                methodology_note="Entry node is isolated under simulated containment.",
            )

        # Resolve target critical assets
        target_ids_list = self._resolve_target_asset_ids(request.target_node_ids)
        if target_ids_list and all(tid.lower() == entry_node.id.lower() for tid in target_ids_list):
            calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return AttackPathResult(
                entry_node=entry_node,
                total_paths_discovered=0,
                paths=[],
                targets_reached=[entry_node.id],
                calculation_time_ms=calc_time_ms,
                warnings=["Source and target entities are identical; self-traversal does not represent a lateral movement path."],
                methodology_note="Source and target entities are identical; 0 candidate lateral movement paths.",
            )

        target_ids = set(target_ids_list)
        # Exclude entry node from targets if accidentally included
        target_ids.discard(entry_node.id)

        # Validate allowed relationship types
        allowed_types_set = None
        if request.relationship_types:
            allowed_types_set = set(request.relationship_types).intersection(PATH_ELIGIBLE_RELATIONSHIPS)
            if not allowed_types_set:
                raise ValueError("None of the specified relationship types are eligible for attack path traversal.")

        # Execute bounded path search
        path_records = self._find_paths_graph_search(
            entry_node=entry_node,
            target_ids=target_ids,
            max_depth=request.max_depth,
            include_hypothetical=request.include_hypothetical,
            allowed_types=allowed_types_set,
            disabled_node_ids=disabled_nodes,
            disabled_edge_keys=disabled_edges,
        )

        discovered_paths: List[AttackPathItem] = []
        targets_reached: Set[str] = set()

        for idx, rec in enumerate(path_records, start=1):
            raw_nodes = rec["path_nodes"]
            raw_rels = rec["path_relationships"]

            # Cycle defense: ensure simple acyclic paths (no repeated nodes)
            raw_node_ids = [n.get("id") for n in raw_nodes if n.get("id")]
            if len(raw_node_ids) != len(set(raw_node_ids)):
                continue

            path_nodes: List[EnterpriseNode] = [
                self.blast_service._record_to_enterprise_node(
                    labels=n.get("labels", []),
                    properties=n.get("properties", {}),
                    fallback_id=n.get("id"),
                )
                for n in raw_nodes
            ]

            target_node = path_nodes[-1]
            targets_reached.add(target_node.id)

            steps: List[AttackPathStep] = []
            step_feasibilities: List[int] = []
            assumptions: List[str] = []
            observed_count = 0
            hypothetical_count = 0

            for step_num, r in enumerate(raw_rels, start=1):
                src_id = r["source_id"]
                tgt_id = r["target_id"]
                rel_type = RelationshipType(r["type"])
                try:
                    ev_class = EvidenceClass(r["evidence_class"])
                except (ValueError, KeyError):
                    if str(r.get("evidence_class", "")).upper() == "AUTHORIZED":
                        ev_class = EvidenceClass.AUTHORIZED_ACCESS
                    else:
                        ev_class = EvidenceClass.OBSERVED
                rel_props = r.get("properties", {})

                if ev_class == EvidenceClass.OBSERVED:
                    observed_count += 1
                elif ev_class == EvidenceClass.HYPOTHETICAL:
                    hypothetical_count += 1

                desc = self._generate_step_description(src_id, tgt_id, rel_type, rel_props)
                feasibility, rationale = self._calculate_step_feasibility(rel_type, ev_class, rel_props)
                step_feasibilities.append(feasibility)

                step_obj = AttackPathStep(
                    step_number=step_num,
                    source_id=src_id,
                    target_id=tgt_id,
                    relationship_type=rel_type,
                    evidence_class=ev_class,
                    provenance=rel_props.get("provenance", "System Inventory"),
                    description=desc,
                )
                steps.append(step_obj)

                # Generate explicit technical assumption for this step
                if ev_class == EvidenceClass.HYPOTHETICAL:
                    cve = rel_props.get("via_cve", "unpatched vulnerability")
                    assumptions.append(f"Step {step_num}: Attacker exploits {cve} on {tgt_id} to establish execution.")
                elif rel_type == RelationshipType.LOGGED_IN_TO:
                    assumptions.append(f"Step {step_num}: Attacker leverages cached credential token or interactive session on {tgt_id}.")
                elif rel_type == RelationshipType.HAS_PERMISSION:
                    priv = rel_props.get("privilege_level", "authorized")
                    assumptions.append(f"Step {step_num}: Attacker abuses valid {priv} entitlement on {tgt_id}.")
                elif rel_type == RelationshipType.OBSERVED_CONNECTION:
                    port = rel_props.get("port")
                    port_str = f"on port {port}" if port else "network listener"
                    assumptions.append(f"Step {step_num}: Assumes {port_str} on {tgt_id} is accessible from {src_id}.")

            if not assumptions:
                assumptions.append("Attacker possesses sufficient privilege and network reachability to traverse observed pathway.")

            target_impact = int(target_node.properties.get("impact_score", 90 if target_node.criticality == CriticalityTier.CRITICAL else 75))
            risk_score = self._compute_path_risk_score(target_impact, steps, step_feasibilities)

            path_item = AttackPathItem(
                path_id=f"PATH-{idx:03d}",
                target_id=target_node.id,
                target_name=target_node.name,
                length=len(steps),
                risk_score=risk_score,
                nodes=path_nodes,
                steps=steps,
                observed_steps_count=observed_count,
                hypothetical_steps_count=hypothetical_count,
                assumptions=assumptions,
            )
            discovered_paths.append(path_item)

        # Sort paths by risk_score descending, then length ascending
        discovered_paths.sort(key=lambda p: (-p.risk_score, p.length))

        calc_time_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        warnings = [
            f"Bounded search: Path discovery depth constrained to max_depth={request.max_depth} (limit: {MAX_PATHS_LIMIT} paths)."
        ]
        if request.include_hypothetical:
            warnings.append(
                "Hypothetical exploit preconditions included; paths represent modeled exposure, not confirmed traversal."
            )

        return AttackPathResult(
            entry_node=entry_node,
            total_paths_discovered=len(discovered_paths),
            paths=discovered_paths,
            targets_reached=sorted(list(targets_reached)),
            calculation_time_ms=calc_time_ms,
            warnings=warnings,
            methodology_note=(
                "Candidate paths discovered via bounded graph search. "
                "Calculated risk reflects target impact, step evidence certainty, and pivot friction. "
                "A modeled path indicates architectural exposure, not proof of actual attacker traversal."
            ),
        )

    def analyze_choke_points(
        self,
        paths: List[AttackPathItem],
        top_n: int = 5,
    ) -> ChokePointResult:
        """
        Analyzes candidate attack paths to identify shared intermediate nodes and relationships
        acting as strategic choke points. Ranks candidates by path intersection betweenness.
        """
        if not paths:
            return ChokePointResult(
                total_paths_analyzed=0,
                choke_points=[],
                top_recommendation=None,
                explanation="No candidate attack paths were supplied for choke-point analysis.",
            )

        total_paths = len(paths)
        # Track which path IDs traverse each intermediate entity
        entity_path_map: Dict[str, Set[str]] = {}
        entity_asset_map: Dict[str, Set[str]] = {}
        entity_info_map: Dict[str, Dict[str, Any]] = {}

        for p in paths:
            pid = p.path_id
            target_name = p.target_name

            # Evaluate intermediate nodes (exclude entry node and final target)
            if len(p.nodes) > 2:
                for node in p.nodes[1:-1]:
                    nid = node.id
                    if nid not in entity_path_map:
                        entity_path_map[nid] = set()
                        entity_asset_map[nid] = set()
                        entity_info_map[nid] = {
                            "label": node.name,
                            "type": node.label.value,
                            "action": InterventionAction.ISOLATE_NODE if node.label == NodeLabel.SERVER else InterventionAction.DISABLE_ACCOUNT,
                        }
                    entity_path_map[nid].add(pid)
                    entity_asset_map[nid].add(target_name)

            # Evaluate intermediate relationships/edges
            for step in p.steps:
                edge_id = f"{step.source_id}->{step.target_id}:{step.relationship_type.value}"
                if edge_id not in entity_path_map:
                    entity_path_map[edge_id] = set()
                    entity_asset_map[edge_id] = set()

                    action = InterventionAction.BLOCK_CONNECTION
                    if step.relationship_type == RelationshipType.HAS_PERMISSION:
                        action = InterventionAction.REVOKE_PERMISSION
                    elif step.relationship_type == RelationshipType.POTENTIAL_EXPLOIT:
                        action = InterventionAction.PATCH_VULNERABILITY

                    entity_info_map[edge_id] = {
                        "label": f"{step.source_id} -> {step.target_id} ({step.relationship_type.value})",
                        "type": "Relationship",
                        "action": action,
                    }
                entity_path_map[edge_id].add(pid)
                entity_asset_map[edge_id].add(target_name)

        # Build candidate list
        candidates: List[ChokePointItem] = []
        for ent_id, pids in entity_path_map.items():
            traversed_count = len(pids)
            pct = round((traversed_count / total_paths) * 100.0, 1)
            info = entity_info_map[ent_id]
            assets = sorted(list(entity_asset_map[ent_id]))

            action = info["action"]
            action_verb = "Severing" if action == InterventionAction.BLOCK_CONNECTION else "Remediating"
            if action == InterventionAction.ISOLATE_NODE:
                action_verb = "Isolating"
            elif action == InterventionAction.REVOKE_PERMISSION:
                action_verb = "Revoking access on"
            elif action == InterventionAction.PATCH_VULNERABILITY:
                action_verb = "Patching"

            alternate_count = total_paths - traversed_count
            alt_text = f" ({alternate_count} alternative paths remain active.)" if alternate_count > 0 else " (Eliminates all candidate paths to these assets.)"
            details = (
                f"{action_verb} {ent_id} eliminates {traversed_count} of {total_paths} candidate attack path(s) ({pct}%), "
                f"protecting {len(assets)} Crown Jewel(s): {', '.join(assets)}.{alt_text}"
            )

            candidates.append(
                ChokePointItem(
                    rank=0,
                    entity_id=ent_id,
                    entity_label=info["label"],
                    entity_type=info["type"],
                    paths_traversed_count=traversed_count,
                    traversal_percentage=pct,
                    affected_critical_assets=assets,
                    recommended_action=action,
                    intervention_details=details,
                )
            )

        # Sort candidates: most paths traversed, then most critical assets affected
        candidates.sort(key=lambda c: (-c.paths_traversed_count, -len(c.affected_critical_assets), c.entity_id))

        # Assign ranks
        for rank_idx, c in enumerate(candidates, start=1):
            c.rank = rank_idx

        top_candidates = candidates[:top_n]
        top_rec = top_candidates[0] if top_candidates else None

        explanation = (
            f"Analyzed {total_paths} candidate attack paths. Choke points are ranked by structural betweenness. "
            f"Remediating the top choke point intercepts {top_rec.paths_traversed_count if top_rec else 0} paths. "
            "Note: Choke-point remediation eliminates dependent paths, but alternative pathways to critical assets "
            "must be verified independently."
        )

        return ChokePointResult(
            total_paths_analyzed=total_paths,
            choke_points=top_candidates,
            top_recommendation=top_rec,
            explanation=explanation,
        )

    def simulate_containment_impact(
        self,
        entry_node_id: str,
        target_asset_ids: Optional[List[str]],
        disabled_node_ids: Set[str],
        disabled_edge_keys: Set[Tuple[str, str, str]],
    ) -> Dict[str, Any]:
        """
        Simulation-friendly interface: Recalculates paths before and after proposed interventions
        strictly in memory without modifying the persistent database.
        """
        req = AttackPathRequest(
            entry_node_id=entry_node_id,
            target_node_ids=target_asset_ids,
            max_depth=5,
            include_hypothetical=True,
        )

        # 1. Baseline analysis
        baseline_res = self.find_attack_paths(req)

        # 2. Simulated post-intervention analysis
        sim_res = self.find_attack_paths(
            request=req,
            disabled_node_ids=disabled_node_ids,
            disabled_edge_keys=disabled_edge_keys,
        )

        eliminated = baseline_res.total_paths_discovered - sim_res.total_paths_discovered
        pct_reduced = (
            round((eliminated / max(1, baseline_res.total_paths_discovered)) * 100.0, 1)
            if baseline_res.total_paths_discovered > 0
            else 0.0
        )

        return {
            "entry_node_id": entry_node_id,
            "baseline_paths_count": baseline_res.total_paths_discovered,
            "simulated_paths_count": sim_res.total_paths_discovered,
            "eliminated_paths_count": eliminated,
            "path_reduction_percentage": pct_reduced,
            "baseline_targets": baseline_res.targets_reached,
            "remaining_targets": sim_res.targets_reached,
            "eliminated_targets": list(set(baseline_res.targets_reached) - set(sim_res.targets_reached)),
            "remaining_paths": sim_res.paths,
            "risk_verdict": (
                "FULL_CONTAINMENT"
                if sim_res.total_paths_discovered == 0
                else "PARTIAL_CONTAINMENT"
            ),
        }

    def simulate_containment(self, request: ContainmentSimulationRequest) -> ContainmentSimulationResult:
        """
        Executes an in-memory What-If containment simulation against proposed interventions.
        Calculates baseline vs remaining paths, eliminated routes, and residual Crown Jewel exposure
        without mutating the live graph.
        """
        disabled_node_ids = set()
        disabled_edge_keys = set()

        for interv in request.proposed_interventions:
            if interv.node_id:
                disabled_node_ids.add(interv.node_id.strip())
            if interv.source_id and interv.target_id:
                rt = interv.relationship_type.value if interv.relationship_type else ""
                disabled_edge_keys.add((interv.source_id.strip(), interv.target_id.strip(), rt))

        # Baseline analysis
        baseline_req = AttackPathRequest(
            entry_node_id=request.entry_node_id,
            target_node_ids=request.target_asset_ids,
            max_depth=5,
            include_hypothetical=True,
        )
        baseline_res = self.find_attack_paths(baseline_req)

        # Simulated post-intervention analysis
        sim_res = self.find_attack_paths(
            request=baseline_req,
            disabled_node_ids=disabled_node_ids,
            disabled_edge_keys=disabled_edge_keys,
        )

        baseline_count = baseline_res.total_paths_discovered
        sim_count = sim_res.total_paths_discovered
        eliminated_count = baseline_count - sim_count
        efficiency_pct = (
            round((eliminated_count / max(1, baseline_count)) * 100.0, 1)
            if baseline_count > 0
            else 0.0
        )

        path_statuses: List[SimulatedPathStatus] = []
        sim_path_ids = {p.path_id for p in sim_res.paths}
        for bp in baseline_res.paths:
            if bp.path_id in sim_path_ids:
                path_statuses.append(
                    SimulatedPathStatus(
                        path_id=bp.path_id,
                        target_id=bp.target_id,
                        status="ACTIVE",
                        severed_at_step=None,
                    )
                )
            else:
                severed_reason = (
                    f"Severed by containment of {list(disabled_node_ids)[0]}"
                    if disabled_node_ids
                    else "Severed by connection rule"
                )
                path_statuses.append(
                    SimulatedPathStatus(
                        path_id=bp.path_id,
                        target_id=bp.target_id,
                        status="ELIMINATED",
                        severed_at_step=severed_reason,
                    )
                )

        verdict = (
            f"Full containment achieved: All {baseline_count} attack path(s) successfully eliminated."
            if sim_count == 0 and baseline_count > 0
            else f"Partial containment: Eliminated {eliminated_count} of {baseline_count} path(s) ({efficiency_pct}%). {sim_count} alternative pathway(s) remain active."
        )
        if baseline_count == 0:
            verdict = "Zero baseline attack paths discovered from entry node to designated targets."

        return ContainmentSimulationResult(
            simulation_id=f"SIM-{uuid.uuid4().hex[:8].upper()}",
            live_graph_modified=False,
            proposed_interventions=request.proposed_interventions,
            baseline_paths_count=baseline_count,
            remaining_paths_count=sim_count,
            paths_eliminated_count=eliminated_count,
            containment_efficiency_pct=efficiency_pct,
            path_statuses=path_statuses,
            residual_exposed_assets=sim_res.targets_reached,
            analyst_verdict=verdict,
            safety_disclaimer=(
                "SIMULATION ONLY: No actual permissions were revoked, no devices were disconnected, "
                "and no live infrastructure was modified."
            ),
        )

    def bridge_case_to_graph(self, case_id: str) -> CaseBridgeResponse:
        """
        Resolves an email investigation case to the organizational security graph.
        Correlates victim recipient with directory users and assigned workstations,
        and isolates external attacker IOCs under unmapped_external_iocs.
        """
        clean_cid = case_id.strip()
        from backend.services.case_store import default_case_repo
        case = default_case_repo.get_case(clean_cid)
        if not case:
            raise CaseNotFoundError(f"Case '{clean_cid}' was not found in the investigation case repository.")

        recipient_email = case.recipient
        if not recipient_email:
            if hasattr(case, "forensics") and case.forensics and hasattr(case.forensics, "recipient") and case.forensics.recipient:
                recipient_email = case.forensics.recipient

        external_iocs = []
        if hasattr(case, "iocs") and case.iocs:
            ext = []
            for ioc_list in case.iocs.values():
                for val in ioc_list:
                    if not val.endswith("@corporation.com") and not val.startswith("10."):
                        ext.append(val)
            if ext:
                external_iocs = list(set(ext))

        primary_node = None
        mapped_entities: List[BridgeMappingItem] = []
        if recipient_email:
            try:
                user_node = self.blast_service.resolve_start_node(recipient_email)
                primary_node = user_node
                mapped_entities.append(
                    BridgeMappingItem(
                        evidence_type="RECIPIENT_EMAIL",
                        raw_value=recipient_email,
                        mapped_node_id=user_node.id,
                        node_label=user_node.label,
                        match_confidence=1.0,
                        match_rationale="Exact Active Directory email address match.",
                    )
                )

                records = self.client.execute_query(
                    "MATCH (u {id: $uid})-[:USES]->(d) RETURN d.id AS id, labels(d) AS labels, properties(d) AS properties LIMIT 1",
                    {"uid": user_node.id},
                )
                if records:
                    dev_rec = records[0]
                    dev_id = dev_rec["id"]
                    mapped_entities.append(
                        BridgeMappingItem(
                            evidence_type="ASSIGNED_DEVICE",
                            raw_value=dev_rec.get("properties", {}).get("hostname", dev_id),
                            mapped_node_id=dev_id,
                            node_label=NodeLabel.DEVICE,
                            match_confidence=1.0,
                            match_rationale="Active corporate device assignment for user (NOTE: receipt of email indicates potential exposure, not confirmed device compromise).",
                        )
                    )
            except NodeNotFoundError:
                logger.info(f"Recipient {recipient_email} not found in enterprise graph directory.")
                if recipient_email not in external_iocs:
                    external_iocs.append(recipient_email)
            except Exception as e:
                logger.warning(f"Could not resolve recipient to graph: {e}")
                if recipient_email not in external_iocs:
                    external_iocs.append(recipient_email)

        blast_url = f"/api/v1/graphops/blast-radius?start_node_id={primary_node.id if primary_node else (recipient_email or clean_cid)}"

        return CaseBridgeResponse(
            case_id=clean_cid,
            primary_compromised_node=primary_node,
            mapped_entities=mapped_entities,
            unmapped_external_iocs=external_iocs,
            recommended_blast_radius_url=blast_url,
        )


# Global default instance
default_attack_path_service = AttackPathService()

