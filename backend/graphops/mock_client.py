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
        self.edges = edges
        self.security_events: Dict[str, Dict[str, Any]] = {}
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

    def init_schema_constraints(self, database: Optional[str] = None) -> Dict[str, Any]:
        """In-memory mock implementation of schema constraints initialization."""
        from backend.graphops.schema import CYPHER_SCHEMA_STATEMENTS
        return {
            "applied": CYPHER_SCHEMA_STATEMENTS,
            "errors": [],
            "total": len(CYPHER_SCHEMA_STATEMENTS),
            "status": "CONSTRAINTS_APPLIED",
        }

    def execute_write(self, query: str, params: Optional[Dict[str, Any]] = None, database: Optional[str] = None) -> Dict[str, Any]:
        """In-memory implementation of Cypher write operations with transaction counters."""
        params = params or {}
        q = query.strip()
        nodes_created = 0
        relationships_created = 0

        # Handle batch node UNWIND
        if "UNWIND $batch AS item" in q and "MERGE (n:" in q:
            batch = params.get("batch", [])
            for item in batch:
                nid = str(item.get("id", "")).lower()
                props = item.get("properties", {})
                if nid:
                    if nid not in self.nodes:
                        nodes_created += 1
                    self.nodes[nid] = {
                        "id": item.get("id"),
                        "labels": ["Entity"],
                        "properties": props,
                    }
                    if ":" in nid:
                        self.aliases[nid.split(":", 1)[1].lower()] = nid
            return {"nodes_created": nodes_created, "properties_set": len(batch)}

        # Handle batch relationship UNWIND
        if "UNWIND $batch AS item" in q and ("MERGE (src)-[r:" in q or "MERGE (s)-[r:" in q or "CREATE (src)-[r:" in q):
            batch = params.get("batch", [])
            for item in batch:
                rel_type = item.get("type", "CONNECTED_TO")
                props = item.get("properties", {})
                self.edges.append({
                    "source_id": item.get("source_id"),
                    "target_id": item.get("target_id"),
                    "relationship_type": rel_type,
                    "evidence_class": props.get("evidence_class", "OBSERVED"),
                    "properties": props,
                })
                relationships_created += 1
            return {"relationships_created": relationships_created, "properties_set": len(batch)}

        return {"nodes_created": 0, "relationships_created": 0, "properties_set": 0}

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

        # 5. Graph Topology & Summary Queries
        if "MATCH (n) RETURN n.id AS id" in q:
            results = []
            for n in self.nodes.values():
                results.append({
                    "id": n.get("id"),
                    "email": n.get("properties", {}).get("email")
                })
            return results

        if "RETURN labels(n)[0] AS label" in q:
            counts = {}
            for n in self.nodes.values():
                lbl = (n.get("labels") or ["Entity"])[0]
                counts[lbl] = counts.get(lbl, 0) + 1
            return [{"label": k, "count": v} for k, v in counts.items()]

        if "RETURN type(r) AS rel_type" in q:
            counts = {}
            for e in self.edges:
                rt = e.get("relationship_type", "RELATED_TO")
                counts[rt] = counts.get(rt, 0) + 1
            return [{"rel_type": k, "count": v} for k, v in counts.items()]

        if "MATCH (c:CriticalAsset) RETURN" in q:
            results = []
            for n in self.nodes.values():
                if "CriticalAsset" in n.get("labels", []) or n.get("properties", {}).get("criticality") == "CRITICAL":
                    results.append({
                        "id": n.get("id"),
                        "name": n.get("properties", {}).get("name", n.get("id")),
                        "impact": n.get("properties", {}).get("impact_score", 9.0),
                        "category": n.get("properties", {}).get("category", "DATABASE")
                    })
            return results

        # 6. Centrality & Community Detection Queries
        if "MATCH (n)" in q and ("WHERE NOT n:SecurityEvent" in q or "labels(n)" in q):
            results = []
            for n in self.nodes.values():
                if "SecurityEvent" in n.get("labels", []):
                    continue
                props = n.get("properties", {})
                name = props.get("name") or props.get("hostname") or props.get("email") or n.get("id")
                results.append({
                    "id": n.get("id"),
                    "label": (n.get("labels") or ["Entity"])[0],
                    "labels": n.get("labels", ["Entity"]),
                    "name": name,
                    "criticality": props.get("criticality", "MEDIUM"),
                })
            return results

        if "MATCH (s)-[r]->(t)" in q:
            results = []
            for e in self.edges:
                results.append({
                    "source": e.get("source_id"),
                    "target": e.get("target_id"),
                    "rel_type": e.get("relationship_type"),
                    "type": e.get("relationship_type"),
                })
            return results

        # 7. Zero-Trust Audit Queries
        if "HAS_PERMISSION" in q:
            results = []
            for e in self.edges:
                if e.get("relationship_type") == "HAS_PERMISSION":
                    u = self.nodes.get(e["source_id"].lower(), {})
                    t = self.nodes.get(e["target_id"].lower(), {})

                    # Dynamically resolve user's assigned device via USES relationship
                    user_device = None
                    for dev_edge in self.edges:
                        if dev_edge.get("relationship_type") == "USES" and dev_edge.get("source_id", "").lower() == e["source_id"].lower():
                            user_device = dev_edge.get("target_id")
                            break

                    results.append({
                        "user_id": e["source_id"],
                        "user_label": (u.get("labels") or ["User"])[0],
                        "device_id": user_device or "device:dev-ws-101",
                        "target_id": e["target_id"],
                        "target_label": (t.get("labels") or ["Server"])[0],
                        "target_criticality": t.get("properties", {}).get("criticality", "HIGH"),
                        "permission_level": e.get("properties", {}).get("permission_level", "ADMIN"),
                        "granted_at": e.get("properties", {}).get("granted_at", "2024-01-01T00:00:00Z"),
                        "last_used_at": e.get("properties", {}).get("last_used_at"),
                    })
            return results

        # 7. Observed activity query for Zero-Trust audit (MATCH ... OBSERVED_CONNECTION|LOGGED_IN_TO)
        if "MERGE" not in q and ("OBSERVED_CONNECTION" in q or "LOGGED_IN_TO" in q):
            results = []
            for e in self.edges:
                if e.get("relationship_type") in ("OBSERVED_CONNECTION", "LOGGED_IN_TO"):
                    s = self.nodes.get(e["source_id"].lower(), {})
                    t = self.nodes.get(e["target_id"].lower(), {})
                    results.append({
                        "source_id": e["source_id"],
                        "source_label": (s.get("labels") or ["Device"])[0],
                        "target_id": e["target_id"],
                        "target_label": (t.get("labels") or ["Server"])[0],
                        "target_criticality": t.get("properties", {}).get("criticality", "MEDIUM"),
                        "last_observed": "2026-10-28T00:00:00Z",
                    })
            return results

        # 8. SecurityEvent Marker Query (Deduplication Check)
        if "MATCH (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid and eid in self.security_events:
                return [{"id": eid}]
            return []

        # 9. Ingestion MERGE statements for SecurityEvent, Device auto-provisioning, and relationships
        if "MERGE (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid:
                self.security_events[eid] = params
                self.nodes[eid.lower()] = {
                    "id": eid,
                    "labels": ["SecurityEvent"],
                    "properties": params,
                }
            return [{"status": "MOCKED_PERSISTENCE_SUCCESS"}]

        if "MERGE (d:Device {id: $id})" in q:
            dev_id = params.get("id")
            if dev_id:
                norm_dev = dev_id.lower()
                self.nodes[norm_dev] = {
                    "id": dev_id,
                    "labels": ["Device"],
                    "properties": {
                        "device_id": params.get("device_id", ""),
                        "hostname": params.get("hostname", ""),
                        "criticality": "MEDIUM",
                        "created_at": params.get("timestamp", ""),
                    },
                }
                clean_host = norm_dev.split(":", 1)[1] if ":" in norm_dev else norm_dev
                self.aliases[clean_host] = norm_dev
            return [{"status": "MOCKED_PERSISTENCE_SUCCESS"}]

        if "MERGE (s)-[r:OBSERVED_CONNECTION]->(t)" in q:
            src_id = params.get("src_id")
            tgt_id = params.get("tgt_id")
            if src_id and tgt_id:
                self.edges.append({
                    "source_id": src_id,
                    "target_id": tgt_id,
                    "relationship_type": "OBSERVED_CONNECTION",
                    "evidence_class": "OBSERVED",
                    "port": params.get("port", 443),
                    "traversal_cost": 1.5,
                    "last_observed": params.get("timestamp", ""),
                })
            return [{"status": "MOCKED_PERSISTENCE_SUCCESS"}]

        if "MERGE (u)-[r:LOGGED_IN_TO]->(t)" in q:
            user_id = params.get("user_id")
            target_id = params.get("target_id")
            if user_id and target_id:
                self.edges.append({
                    "source_id": user_id,
                    "target_id": target_id,
                    "relationship_type": "LOGGED_IN_TO",
                    "evidence_class": "OBSERVED",
                    "traversal_cost": 1.0,
                    "last_observed": params.get("timestamp", ""),
                })
            return [{"status": "MOCKED_PERSISTENCE_SUCCESS"}]

        if "MERGE" in q or "CREATE" in q:
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
