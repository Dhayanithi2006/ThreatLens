"""
ThreatLens GraphOps - In-Memory Fixture Graph Client
Provides an in-memory fallback client preloaded with the synthetic enterprise graph.
Used for offline demonstrations, development environments, and deterministic integration tests.
"""

from typing import Dict, List, Any, Optional, Set
from backend.graphops.schema import NodeLabel
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


class InMemoryGraphOpsClient:
    """Mock client simulating Neo4j with path search, Crown Jewels, and USES queries."""

    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
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

        # 3. User to Assigned Device Query: MATCH (u {id: $uid})-[:USES]->(d)
        if "-[:USES]->(d)" in q:
            uid = str(params.get("uid", "")).lower()
            results = []
            for e in self.edges:
                if e["source_id"].lower() == uid and e["relationship_type"] == "USES":
                    target_node = self.nodes.get(e["target_id"].lower())
                    if target_node:
                        results.append({
                            "id": target_node["id"],
                            "labels": target_node.get("labels", []),
                            "properties": target_node.get("properties", {}),
                        })
            return results

        # 4. BFS Frontier Query: MATCH (s) WHERE s.id IN $frontier_ids
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
                else:
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

        # 5. Path Search Query: MATCH p = (start)-[r*1..N]->(target)
        if "MATCH p = (start)-[r*" in q:
            entry_id = str(params.get("entry_id", "")).lower()
            target_ids = {str(t).lower() for t in params.get("target_ids", [])}
            allowed_types = set(params.get("allowed_types", []))
            include_hypothetical = params.get("include_hypothetical", False)
            limit = params.get("limit", 50)

            found_paths = []

            def dfs(current_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]], visited_ids: Set[str]):
                if len(found_paths) >= limit or len(path_edges) >= 6:
                    return

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
                        continue

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
                            "path_nodes": new_nodes,
                            "path_relationships": new_edges,
                        })

                    dfs(tgt, new_nodes, new_edges, visited_ids | {tgt})

            start_node = self.nodes.get(entry_id)
            if start_node:
                dfs(entry_id, [start_node], [], {entry_id})

            return found_paths

        # 5. Ingestion MERGE statement (record without failure in mock mode)
        if "MERGE (e:SecurityEvent" in q or "MERGE (target)-[:" in q or "CREATE" in q or "MERGE" in q:
            return [{"status": "MOCKED_PERSISTENCE_SUCCESS"}]

        return []

    def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "connected": True,
            "database": "neo4j (in-memory demo replica)",
            "active_nodes": len(self.nodes),
            "active_relationships": len(self.edges),
            "error": None,
        }


_global_mock_client: Optional[InMemoryGraphOpsClient] = None


def get_mock_graphops_client() -> InMemoryGraphOpsClient:
    """Builds or returns cached InMemoryGraphOpsClient preloaded with enterprise fixture."""
    global _global_mock_client
    if _global_mock_client is not None:
        return _global_mock_client

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
        edge_props["provenance"] = r.get("provenance", "Enterprise Topology")
        edge_props["confidence"] = r.get("confidence", 1.0)
        edge_props["timestamp"] = r.get("timestamp")

        edges.append({
            "source_id": src,
            "target_id": tgt,
            "relationship_type": r["relationship_type"],
            "evidence_class": r.get("evidence_class", "OBSERVED"),
            "properties": edge_props,
        })

    _global_mock_client = InMemoryGraphOpsClient(nodes, edges)
    return _global_mock_client
