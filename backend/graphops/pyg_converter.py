"""
ThreatLens GraphOps - PyTorch Geometric (PyG) Graph-Data Conversion Layer
Transforms canonical ThreatLens enterprise security graphs (from Neo4j or snapshot dictionaries)
into deterministic PyTorch Geometric Data representations with stable node indices,
rich feature matrices, and explicit relationship topology.
"""

import logging
from typing import Dict, List, Tuple, Any, Optional, Set
import hashlib
import torch
from torch_geometric.data import Data

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    canonicalize_node_id,
    get_node_label_from_id,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture

logger = logging.getLogger("threatlens.graphops.pyg_converter")

# Canonical Node Labels for one-hot encoding (9 categories)
CANONICAL_NODE_LABELS = [
    NodeLabel.USER.value,
    NodeLabel.DEVICE.value,
    NodeLabel.SERVER.value,
    NodeLabel.APPLICATION.value,
    NodeLabel.IP_ADDRESS.value,
    NodeLabel.VULNERABILITY.value,
    NodeLabel.CRITICAL_ASSET.value,
    NodeLabel.SECURITY_EVENT.value,
    NodeLabel.EMAIL_ACCOUNT.value,
]
NODE_LABEL_TO_IDX = {lbl: i for i, lbl in enumerate(CANONICAL_NODE_LABELS)}
NUM_NODE_LABEL_CLASSES = len(CANONICAL_NODE_LABELS)

# Canonical Relationship Types for edge categorization
CANONICAL_RELATIONSHIP_TYPES = [rel.value for rel in RelationshipType]
RELATIONSHIP_TYPE_TO_IDX = {rel: i for i, rel in enumerate(CANONICAL_RELATIONSHIP_TYPES)}
NUM_RELATIONSHIP_CLASSES = len(CANONICAL_RELATIONSHIP_TYPES)

# Total Node Feature Dimension:
# 9 (node label one-hot) + 1 (criticality) + 1 (is_admin) + 1 (is_isolated) + 1 (in_degree_norm) + 1 (out_degree_norm) = 14
NODE_FEATURE_DIM = NUM_NODE_LABEL_CLASSES + 5

# Total Edge Feature Dimension:
# 1 (traversal_cost) + 1 (confidence) + 1 (evidence_class_numeric) + NUM_RELATIONSHIP_CLASSES
EDGE_FEATURE_DIM = 3 + NUM_RELATIONSHIP_CLASSES


class PyGGraphSnapshot:
    """Encapsulates a converted PyG Data object along with bidirectional ID mapping tables."""

    def __init__(
        self,
        data: Data,
        node_to_idx: Dict[str, int],
        idx_to_node: Dict[int, str],
        snapshot_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.data = data
        self.node_to_idx = node_to_idx
        self.idx_to_node = idx_to_node
        self.snapshot_id = snapshot_id
        self.metadata = metadata or {}

    @property
    def num_nodes(self) -> int:
        return self.data.num_nodes if self.data.x is not None else len(self.node_to_idx)

    @property
    def num_edges(self) -> int:
        return self.data.num_edges if self.data.edge_index is not None else 0


class PyGGraphConverter:
    """
    Transforms enterprise knowledge graph topology and properties into PyG tensors.
    Supports deterministic indexing, missing value handling, empty graphs, and bounded subgraphs.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    @staticmethod
    def _criticality_to_scalar(crit: Optional[str]) -> float:
        if not crit:
            return 0.25
        norm = str(crit).strip().upper()
        if norm == CriticalityTier.CRITICAL.value:
            return 1.0
        elif norm == CriticalityTier.HIGH.value:
            return 0.75
        elif norm == CriticalityTier.MEDIUM.value:
            return 0.50
        return 0.25

    @staticmethod
    def _evidence_class_to_scalar(ev_class: Optional[str]) -> float:
        if not ev_class:
            return 0.5
        norm = str(ev_class).strip().upper()
        if norm == EvidenceClass.OBSERVED.value:
            return 1.0
        elif norm == EvidenceClass.AUTHORIZED_ACCESS.value:
            return 0.8
        elif norm == EvidenceClass.INFERRED.value:
            return 0.5
        elif norm == EvidenceClass.HYPOTHETICAL.value:
            return 0.2
        return 0.5

    def extract_graph_snapshot_from_neo4j(
        self,
        max_nodes: int = 1000,
        max_edges: int = 5000,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Queries the connected Neo4j database using parameterized Cypher to fetch nodes and relationships.
        Falls back to the fixture graph if Neo4j is offline or empty.
        """
        nodes_list: List[Dict[str, Any]] = []
        edges_list: List[Dict[str, Any]] = []

        try:
            # Query all nodes with their properties
            node_query = """
            MATCH (n)
            RETURN n.id AS id, labels(n) AS labels, n.criticality AS criticality,
                   n.is_admin AS is_admin, n.is_isolated AS is_isolated,
                   n.name AS name, n.department AS department, n.role AS role,
                   n.email AS email
            LIMIT $max_nodes
            """
            user_aliases: Dict[str, List[str]] = {}
            node_records = self.client.execute_query(node_query, {"max_nodes": max_nodes})
            for r in node_records:
                nid = r.get("id")
                if not nid:
                    continue
                lbls = r.get("labels", [])
                primary_label = lbls[0] if lbls else "Entity"
                node_entry = {
                    "id": nid,
                    "label": primary_label,
                    "criticality": r.get("criticality", "LOW"),
                    "is_admin": bool(r.get("is_admin", False)),
                    "is_isolated": bool(r.get("is_isolated", False)),
                    "name": r.get("name", ""),
                    "department": r.get("department", ""),
                    "role": r.get("role", ""),
                }
                nodes_list.append(node_entry)

                # Register canonical email alias if present to mirror fixture and support dual lookups
                email_val = r.get("email")
                if email_val and ("User" in lbls or primary_label == "User"):
                    email_cid = canonicalize_node_id(NodeLabel.USER, email_val)
                    if email_cid != nid:
                        alt_entry = dict(node_entry)
                        alt_entry["id"] = email_cid
                        nodes_list.append(alt_entry)
                        user_aliases.setdefault(nid, []).append(email_cid)

            # Query all relationships with their properties
            rel_query = """
            MATCH (s)-[r]->(t)
            RETURN s.id AS source_id, type(r) AS rel_type, t.id AS target_id,
                   r.traversal_cost AS traversal_cost, r.confidence AS confidence,
                   r.evidence_class AS evidence_class
            LIMIT $max_edges
            """
            rel_records = self.client.execute_query(rel_query, {"max_edges": max_edges})
            for r in rel_records:
                src = r.get("source_id")
                tgt = r.get("target_id")
                rel_type = r.get("rel_type", "OBSERVED_CONNECTION")
                if src and tgt:
                    edge_entry = {
                        "source_id": src,
                        "target_id": tgt,
                        "relationship_type": rel_type,
                        "traversal_cost": float(r.get("traversal_cost") or 1.0),
                        "confidence": float(r.get("confidence") or 1.0),
                        "evidence_class": r.get("evidence_class") or "OBSERVED",
                    }
                    edges_list.append(edge_entry)
                    for alias_id in user_aliases.get(src, []):
                        edges_list.append({**edge_entry, "source_id": alias_id})
                    for alias_id in user_aliases.get(tgt, []):
                        edges_list.append({**edge_entry, "target_id": alias_id})

            if nodes_list and edges_list:
                logger.info(f"Loaded {len(nodes_list)} nodes and {len(edges_list)} edges from Neo4j.")
                return nodes_list, edges_list

        except Exception as e:
            logger.warning(f"Could not load graph from Neo4j ({e}); falling back to enterprise fixture.")

        # Fallback to local baseline fixture
        return self.extract_graph_snapshot_from_fixture()

    def extract_graph_snapshot_from_fixture(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Loads canonical nodes and edges from sample_enterprise_graph.json."""
        raw_fixture = load_sample_enterprise_fixture()
        entities = raw_fixture.get("entities", {})
        relationships_data = raw_fixture.get("relationships", {}).get("relationships", [])

        nodes_list: List[Dict[str, Any]] = []

        # Parse users
        for u in entities.get("users", []):
            primary_id = u.get("email") or u.get("id") or u.get("user_id")
            cid = canonicalize_node_id(NodeLabel.USER, primary_id)
            user_entry = {
                "id": cid,
                "label": NodeLabel.USER.value,
                "criticality": "LOW",
                "is_admin": bool(u.get("is_admin", False)),
                "is_isolated": False,
                "name": u.get("name", ""),
                "department": u.get("department", "Unassigned"),
                "role": u.get("role", "Standard User"),
            }
            nodes_list.append(user_entry)
            # Also register raw user_id as an alias if different
            raw_uid = u.get("user_id") or u.get("id")
            if raw_uid and raw_uid != primary_id:
                alt_cid = canonicalize_node_id(NodeLabel.USER, raw_uid)
                alt_entry = dict(user_entry)
                alt_entry["id"] = alt_cid
                nodes_list.append(alt_entry)

        # Parse devices
        for d in entities.get("devices", []):
            cid = canonicalize_node_id(NodeLabel.DEVICE, d.get("id") or d.get("device_id") or d.get("hostname"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.DEVICE.value,
                "criticality": d.get("criticality", "LOW"),
                "is_admin": False,
                "is_isolated": bool(d.get("is_isolated", False)),
                "name": d.get("hostname", ""),
                "department": "Workstation",
                "role": "Endpoint",
            })

        # Parse servers
        for s in entities.get("servers", []):
            cid = canonicalize_node_id(NodeLabel.SERVER, s.get("id") or s.get("server_id") or s.get("hostname"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.SERVER.value,
                "criticality": s.get("criticality", "HIGH"),
                "is_admin": False,
                "is_isolated": bool(s.get("is_isolated", False)),
                "name": s.get("name", ""),
                "department": s.get("tier", "Infrastructure"),
                "role": "Server",
            })

        # Parse applications
        for a in entities.get("applications", []):
            cid = canonicalize_node_id(NodeLabel.APPLICATION, a.get("id") or a.get("app_id") or a.get("name"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.APPLICATION.value,
                "criticality": "MEDIUM",
                "is_admin": False,
                "is_isolated": False,
                "name": a.get("name", ""),
                "department": a.get("service_type", "Application"),
                "role": "Application",
            })

        # Parse IP addresses
        for ip in entities.get("ip_addresses", []):
            cid = canonicalize_node_id(NodeLabel.IP_ADDRESS, ip.get("id") or ip.get("ip"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.IP_ADDRESS.value,
                "criticality": "LOW",
                "is_admin": False,
                "is_isolated": False,
                "name": ip.get("ip", ""),
                "department": ip.get("scope", "Network"),
                "role": "IPAddress",
            })

        # Parse vulnerabilities
        for v in entities.get("vulnerabilities", []):
            cid = canonicalize_node_id(NodeLabel.VULNERABILITY, v.get("id") or v.get("cve_id"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.VULNERABILITY.value,
                "criticality": v.get("severity", "HIGH"),
                "is_admin": False,
                "is_isolated": False,
                "name": v.get("cve_id", ""),
                "department": "Security",
                "role": "Vulnerability",
            })

        # Parse critical assets
        for ca in entities.get("critical_assets", []):
            cid = canonicalize_node_id(NodeLabel.CRITICAL_ASSET, ca.get("id") or ca.get("asset_id"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.CRITICAL_ASSET.value,
                "criticality": "CRITICAL",
                "is_admin": False,
                "is_isolated": False,
                "name": ca.get("name", ""),
                "department": ca.get("owner_department", "Crown Jewel"),
                "role": "CriticalAsset",
            })

        # Parse email accounts
        for ea in entities.get("email_accounts", []):
            cid = canonicalize_node_id(NodeLabel.EMAIL_ACCOUNT, ea.get("id") or ea.get("email_address"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.EMAIL_ACCOUNT.value,
                "criticality": "LOW",
                "is_admin": False,
                "is_isolated": False,
                "name": ea.get("account_name", ""),
                "department": "Email",
                "role": "Mailbox",
            })

        # Parse security events
        for se in entities.get("security_events", []):
            cid = canonicalize_node_id(NodeLabel.SECURITY_EVENT, se.get("id") or se.get("event_id"))
            nodes_list.append({
                "id": cid,
                "label": NodeLabel.SECURITY_EVENT.value,
                "criticality": se.get("severity", "MEDIUM"),
                "is_admin": False,
                "is_isolated": False,
                "name": se.get("event_type", ""),
                "department": "SOC",
                "role": "SecurityAlert",
            })

        # Deduplicate nodes by ID
        unique_nodes = {n["id"]: n for n in nodes_list}
        nodes_list = list(unique_nodes.values())

        # Normalize relationships
        edges_list: List[Dict[str, Any]] = []
        for r in relationships_data:
            src = str(r.get("source_id", "")).strip()
            tgt = str(r.get("target_id", "")).strip()
            if not src or not tgt:
                continue

            edges_list.append({
                "source_id": src,
                "target_id": tgt,
                "relationship_type": r.get("relationship_type", "OBSERVED_CONNECTION"),
                "traversal_cost": float(r.get("traversal_cost", 1.0)),
                "confidence": float(r.get("confidence", 1.0)),
                "evidence_class": r.get("evidence_class", "OBSERVED"),
            })

        return nodes_list, edges_list

    def convert_to_pyg_data(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        snapshot_id: Optional[str] = None,
    ) -> PyGGraphSnapshot:
        """
        Converts raw node and edge lists into a PyG Data tensor representation.
        Handles empty or disconnected graphs gracefully.
        """
        # 1. Deterministic Node Index Mapping (sorted for strict reproducibility)
        node_ids_sorted = sorted(list({n["id"] for n in nodes if "id" in n and n["id"]}))
        node_to_idx: Dict[str, int] = {nid: i for i, nid in enumerate(node_ids_sorted)}
        idx_to_node: Dict[int, str] = {i: nid for nid, i in node_to_idx.items()}
        num_nodes = len(node_ids_sorted)

        # Generate snapshot ID if not provided
        if not snapshot_id:
            h = hashlib.sha256()
            for nid in node_ids_sorted:
                h.update(nid.encode("utf-8"))
            for e in sorted(edges, key=lambda x: (x.get("source_id", ""), x.get("target_id", ""))):
                h.update(f"{e.get('source_id')}:{e.get('relationship_type')}:{e.get('target_id')}".encode("utf-8"))
            snapshot_id = f"snap-{h.hexdigest()[:12]}"

        # Handle Empty Graph
        if num_nodes == 0:
            empty_data = Data(
                x=torch.zeros((0, NODE_FEATURE_DIM), dtype=torch.float),
                edge_index=torch.zeros((2, 0), dtype=torch.long),
                edge_attr=torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float),
            )
            return PyGGraphSnapshot(empty_data, node_to_idx, idx_to_node, snapshot_id, {"is_empty": True})

        # Calculate node degrees for normalization
        in_degrees: Dict[str, int] = {nid: 0 for nid in node_ids_sorted}
        out_degrees: Dict[str, int] = {nid: 0 for nid in node_ids_sorted}

        valid_edges: List[Dict[str, Any]] = []
        for e in edges:
            src = e.get("source_id")
            tgt = e.get("target_id")
            if src in node_to_idx and tgt in node_to_idx:
                valid_edges.append(e)
                out_degrees[src] += 1
                in_degrees[tgt] += 1

        max_deg = max(max(in_degrees.values(), default=1), max(out_degrees.values(), default=1), 1)

        # 2. Build Node Feature Matrix X [num_nodes, NODE_FEATURE_DIM]
        node_dict_by_id = {n["id"]: n for n in nodes}
        node_features = torch.zeros((num_nodes, NODE_FEATURE_DIM), dtype=torch.float)

        for i, nid in enumerate(node_ids_sorted):
            nd = node_dict_by_id.get(nid, {})
            label_str = nd.get("label") or get_node_label_from_id(nid).value if hasattr(get_node_label_from_id(nid), "value") else "Entity"

            # One-hot label encoding
            if label_str in NODE_LABEL_TO_IDX:
                node_features[i, NODE_LABEL_TO_IDX[label_str]] = 1.0
            else:
                # Unknown label fallback
                pass

            # Numeric attributes
            offset = NUM_NODE_LABEL_CLASSES
            node_features[i, offset + 0] = self._criticality_to_scalar(nd.get("criticality"))
            node_features[i, offset + 1] = 1.0 if nd.get("is_admin") else 0.0
            node_features[i, offset + 2] = 1.0 if nd.get("is_isolated") else 0.0
            node_features[i, offset + 3] = float(in_degrees.get(nid, 0)) / max_deg
            node_features[i, offset + 4] = float(out_degrees.get(nid, 0)) / max_deg

        # 3. Build Edge Index [2, num_edges] and Edge Attributes [num_edges, EDGE_FEATURE_DIM]
        num_edges = len(valid_edges)
        if num_edges > 0:
            edge_index = torch.zeros((2, num_edges), dtype=torch.long)
            edge_attr = torch.zeros((num_edges, EDGE_FEATURE_DIM), dtype=torch.float)

            for i, e in enumerate(valid_edges):
                src_idx = node_to_idx[e["source_id"]]
                tgt_idx = node_to_idx[e["target_id"]]
                edge_index[0, i] = src_idx
                edge_index[1, i] = tgt_idx

                # Edge features
                cost = float(e.get("traversal_cost", 1.0))
                conf = float(e.get("confidence", 1.0))
                ev_scalar = self._evidence_class_to_scalar(e.get("evidence_class"))

                edge_attr[i, 0] = cost
                edge_attr[i, 1] = conf
                edge_attr[i, 2] = ev_scalar

                # One-hot relationship type
                rel_type = e.get("relationship_type", "OBSERVED_CONNECTION")
                if rel_type in RELATIONSHIP_TYPE_TO_IDX:
                    edge_attr[i, 3 + RELATIONSHIP_TYPE_TO_IDX[rel_type]] = 1.0
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)
            edge_attr = torch.zeros((0, EDGE_FEATURE_DIM), dtype=torch.float)

        pyg_data = Data(
            x=node_features,
            edge_index=edge_index,
            edge_attr=edge_attr,
            num_nodes=num_nodes,
        )

        metadata = {
            "snapshot_id": snapshot_id,
            "num_nodes": num_nodes,
            "num_edges": num_edges,
            "node_feature_dim": NODE_FEATURE_DIM,
            "edge_feature_dim": EDGE_FEATURE_DIM,
        }

        return PyGGraphSnapshot(pyg_data, node_to_idx, idx_to_node, snapshot_id, metadata)

    def extract_and_convert(self) -> PyGGraphSnapshot:
        """Helper to fetch from Neo4j/fixture and return PyGGraphSnapshot."""
        nodes, edges = self.extract_graph_snapshot_from_neo4j()
        return self.convert_to_pyg_data(nodes, edges)

    def extract_subgraph_around_nodes(
        self,
        target_node_ids: List[str],
        full_snapshot: PyGGraphSnapshot,
        num_hops: int = 2,
        max_subgraph_nodes: int = 150,
    ) -> PyGGraphSnapshot:
        """
        Extracts a bounded k-hop ego-network around target nodes to bound inference latency and memory.
        """
        from torch_geometric.utils import k_hop_subgraph

        target_indices = [
            full_snapshot.node_to_idx[nid]
            for nid in target_node_ids
            if nid in full_snapshot.node_to_idx
        ]

        if not target_indices:
            # If target nodes don't exist in graph, return empty snapshot
            return self.convert_to_pyg_data([], [], snapshot_id=f"{full_snapshot.snapshot_id}-empty")

        subset, sub_edge_index, mapping, edge_mask = k_hop_subgraph(
            node_idx=torch.tensor(target_indices, dtype=torch.long),
            num_hops=num_hops,
            edge_index=full_snapshot.data.edge_index,
            relabel_nodes=True,
            num_nodes=full_snapshot.num_nodes,
        )

        # Enforce maximum subgraph node limit
        if subset.size(0) > max_subgraph_nodes:
            subset = subset[:max_subgraph_nodes]
            # re-filter edge index
            sub_mask = (sub_edge_index[0] < max_subgraph_nodes) & (sub_edge_index[1] < max_subgraph_nodes)
            sub_edge_index = sub_edge_index[:, sub_mask]
            edge_mask = edge_mask[sub_mask] if edge_mask.size(0) == sub_mask.size(0) else edge_mask

        sub_x = full_snapshot.data.x[subset]
        sub_edge_attr = full_snapshot.data.edge_attr[edge_mask] if full_snapshot.data.edge_attr is not None else None

        sub_node_to_idx: Dict[str, int] = {}
        sub_idx_to_node: Dict[int, str] = {}
        for new_idx, old_idx_tensor in enumerate(subset):
            old_idx = old_idx_tensor.item()
            orig_nid = full_snapshot.idx_to_node.get(old_idx, f"unknown:{old_idx}")
            sub_node_to_idx[orig_nid] = new_idx
            sub_idx_to_node[new_idx] = orig_nid

        sub_data = Data(
            x=sub_x,
            edge_index=sub_edge_index,
            edge_attr=sub_edge_attr,
            num_nodes=sub_x.size(0),
        )

        return PyGGraphSnapshot(
            data=sub_data,
            node_to_idx=sub_node_to_idx,
            idx_to_node=sub_idx_to_node,
            snapshot_id=f"{full_snapshot.snapshot_id}-sub",
            metadata={"parent_snapshot": full_snapshot.snapshot_id, "num_hops": num_hops},
        )
