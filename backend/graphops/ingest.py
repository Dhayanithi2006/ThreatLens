"""
ThreatLens GraphOps - Data Ingestion and Construction Engine
Validates, normalizes, and idempotently imports enterprise entities and relationships into Neo4j.
Enforces canonical ID rules, validates endpoint references, tracks unresolved links,
and uses parameterized Cypher transactions with bounded batch sizes.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import logging
import csv
import io
import re
from pydantic import ValidationError

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    canonicalize_node_id,
    get_node_label_from_id,
    VALID_RELATIONSHIP_ENDPOINTS,
)
from backend.models.graphops import (
    UserNode,
    DeviceNode,
    ServerNode,
    ApplicationNode,
    DatabaseNode,
    IpAddressNode,
    VulnerabilityNode,
    CriticalAssetNode,
    SecurityEventNode,
    EmailAccountNode,
    EnterpriseRelationship,
    EntityIngestRequest,
    RelationshipIngestRequest,
    BulkIngestPayload,
    IngestSummaryResponse,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture

logger = logging.getLogger("threatlens.graphops.ingest")

BATCH_SIZE = 50


class GraphOpsIngestionEngine:
    """
    Ingests and normalizes enterprise graph datasets into Neo4j with full validation and idempotency.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    @staticmethod
    def _register_alias(alias_map: Dict[str, str], raw_key: str, canonical_id: str):
        """
        Registers an alias mapping case-insensitively.
        Marks conflicting mappings as ambiguous to prevent cross-entity collisions.
        """
        clean = raw_key.strip().lower()
        if not clean:
            return
        if clean in alias_map and alias_map[clean] != canonical_id:
            alias_map[clean] = "__AMBIGUOUS__"
        else:
            alias_map[clean] = canonical_id

    def validate_entity(self, label: NodeLabel, raw_data: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates raw dictionary data against the corresponding Pydantic entity model.
        Returns (normalized_node_dict, None) or (None, error_message).
        """
        try:
            if label == NodeLabel.USER:
                node = UserNode(**raw_data)
                props = {
                    "id": node.id,
                    "user_id": node.user_id,
                    "email": node.email,
                    "name": node.name,
                    "department": node.department,
                    "role": node.role,
                    "is_service_account": node.is_service_account,
                    "is_admin": node.is_admin,
                    "status": node.status,
                }
            elif label == NodeLabel.DEVICE:
                node = DeviceNode(**raw_data)
                props = {
                    "id": node.id,
                    "device_id": node.device_id,
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "mac_address": node.mac_address or "",
                    "os": node.os,
                    "subnet": node.subnet or "",
                    "is_isolated": node.is_isolated,
                    "criticality": node.criticality.value,
                }
            elif label == NodeLabel.SERVER:
                node = ServerNode(**raw_data)
                props = {
                    "id": node.id,
                    "server_id": node.server_id,
                    "name": node.name,
                    "hostname": node.hostname,
                    "ip_address": node.ip_address,
                    "tier": node.tier,
                    "environment": node.environment,
                    "criticality": node.criticality.value,
                    "is_isolated": node.is_isolated,
                }
            elif label == NodeLabel.APPLICATION:
                node = ApplicationNode(**raw_data)
                props = {
                    "id": node.id,
                    "app_id": node.app_id,
                    "name": node.name,
                    "version": node.version or "",
                    "port": node.port if node.port is not None else 0,
                    "service_type": node.service_type,
                    "environment": node.environment,
                }
            elif label == NodeLabel.DATABASE:
                node = DatabaseNode(**raw_data)
                props = {
                    "id": node.id,
                    "db_id": node.db_id,
                    "name": node.name,
                    "engine": node.engine,
                    "port": node.port if node.port is not None else 5432,
                    "tier": node.tier,
                    "environment": node.environment,
                    "is_clustered": node.is_clustered,
                    "criticality": node.criticality.value,
                }
            elif label == NodeLabel.IP_ADDRESS:
                node = IpAddressNode(**raw_data)
                props = {
                    "id": node.id,
                    "ip": node.ip,
                    "version": node.version,
                    "scope": node.scope,
                    "subnet": node.subnet or "",
                    "is_monitored": node.is_monitored,
                }
            elif label == NodeLabel.VULNERABILITY:
                node = VulnerabilityNode(**raw_data)
                props = {
                    "id": node.id,
                    "cve_id": node.cve_id,
                    "cvss_score": node.cvss_score,
                    "severity": node.severity.value,
                    "description": node.description,
                    "exploit_available": node.exploit_available,
                    "patch_available": node.patch_available,
                }
            elif label == NodeLabel.CRITICAL_ASSET:
                node = CriticalAssetNode(**raw_data)
                props = {
                    "id": node.id,
                    "asset_id": node.asset_id,
                    "name": node.name,
                    "category": node.category,
                    "impact_score": node.impact_score,
                    "data_classification": node.data_classification.value,
                    "owner_department": node.owner_department,
                }
            elif label == NodeLabel.SECURITY_EVENT:
                node = SecurityEventNode(**raw_data)
                props = {
                    "id": node.id,
                    "event_id": node.event_id,
                    "event_type": node.event_type,
                    "severity": node.severity.value,
                    "timestamp": node.timestamp,
                    "case_id": node.case_id or "",
                    "provenance": node.provenance,
                }
            elif label == NodeLabel.EMAIL_ACCOUNT:
                node = EmailAccountNode(**raw_data)
                domain = node.domain
                if not domain and "@" in node.email_address:
                    domain = node.email_address.split("@", 1)[1]
                props = {
                    "id": node.id,
                    "email_address": node.email_address,
                    "account_name": node.account_name or "",
                    "domain": domain or "",
                    "mailbox_type": node.mailbox_type,
                    "is_internal": node.is_internal,
                    "is_compromised": node.is_compromised,
                }
            else:
                return None, f"Unsupported entity label: {label}"

            # Merge extra metadata fields if present
            extra_data = raw_data.get("data")
            if isinstance(extra_data, dict):
                for k, v in extra_data.items():
                    if k not in props and isinstance(v, (str, int, float, bool)):
                        props[k] = v

            return {"label": label.value, "id": props["id"], "properties": props}, None
        except ValidationError as e:
            err_msg = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in e.errors() if 'loc' in err)
            return None, f"Validation failure for {label.value} ({raw_data.get('id', 'unknown')}): {err_msg}"
        except Exception as e:
            return None, f"Failed to parse {label.value} ({raw_data.get('id', 'unknown')}): {str(e)}"

    def validate_relationship(
        self,
        raw_rel: Dict[str, Any],
        known_node_ids: Set[str],
        id_aliases: Optional[Dict[str, str]] = None,
        node_label_map: Optional[Dict[str, NodeLabel]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates relationship structure and ensures source and target exist.
        Resolves entity aliases case-insensitively and maps native IDs to canonical IDs.
        Enforces endpoint typing rules strictly.
        """
        rel_data = dict(raw_rel)
        src_raw = str(rel_data.get("source_id", "")).strip()
        tgt_raw = str(rel_data.get("target_id", "")).strip()

        if not src_raw:
            return None, "Relationship validation failed: source_id cannot be empty."
        if not tgt_raw:
            return None, "Relationship validation failed: target_id cannot be empty."

        src = src_raw
        tgt = tgt_raw

        # Resolve aliases case-insensitively
        if id_aliases:
            src_lookup = id_aliases.get(src_raw.lower())
            if src_lookup:
                if src_lookup == "__AMBIGUOUS__":
                    return None, f"Ambiguous relationship source_id '{src_raw}' matches multiple entities. Use a canonical prefixed ID."
                src = src_lookup
            tgt_lookup = id_aliases.get(tgt_raw.lower())
            if tgt_lookup:
                if tgt_lookup == "__AMBIGUOUS__":
                    return None, f"Ambiguous relationship target_id '{tgt_raw}' matches multiple entities. Use a canonical prefixed ID."
                tgt = tgt_lookup

        # Normalize CVE case
        if src.lower().startswith("vuln:cve-"):
            src = "vuln:" + src[5:].upper()
        elif src.lower().startswith("cve-"):
            src = "vuln:" + src.upper()

        if tgt.lower().startswith("vuln:cve-"):
            tgt = "vuln:" + tgt[5:].upper()
        elif tgt.lower().startswith("cve-"):
            tgt = "vuln:" + tgt.upper()

        rel_data["source_id"] = src
        rel_data["target_id"] = tgt

        try:
            rel = EnterpriseRelationship(**rel_data)
        except ValidationError as e:
            err_msg = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in e.errors())
            return None, f"Relationship validation failed: {err_msg}"
        except Exception as e:
            return None, f"Relationship validation failed: {str(e)}"

        # Reference verification: Ensure source and target endpoints exist (with case-insensitive resolution)
        known_lower_map = {k.lower(): k for k in known_node_ids}
        if rel.source_id not in known_node_ids:
            if rel.source_id.lower() in known_lower_map:
                rel.source_id = known_lower_map[rel.source_id.lower()]
            elif id_aliases and rel.source_id.lower() in id_aliases:
                alias_id = id_aliases[rel.source_id.lower()]
                if alias_id in known_node_ids:
                    rel.source_id = alias_id
                elif alias_id.lower() in known_lower_map:
                    rel.source_id = known_lower_map[alias_id.lower()]
                else:
                    return None, f"Unresolved relationship reference: source_id '{src_raw}' does not exist."
            else:
                return None, f"Unresolved relationship reference: source_id '{src_raw}' does not exist."

        if rel.target_id not in known_node_ids:
            if rel.target_id.lower() in known_lower_map:
                rel.target_id = known_lower_map[rel.target_id.lower()]
            elif id_aliases and rel.target_id.lower() in id_aliases:
                alias_id = id_aliases[rel.target_id.lower()]
                if alias_id in known_node_ids:
                    rel.target_id = alias_id
                elif alias_id.lower() in known_lower_map:
                    rel.target_id = known_lower_map[alias_id.lower()]
                else:
                    return None, f"Unresolved relationship reference: target_id '{tgt_raw}' does not exist."
            else:
                return None, f"Unresolved relationship reference: target_id '{tgt_raw}' does not exist."

        # Endpoint typing verification: Ensure source and target entities match schema rules
        if rel.relationship_type in VALID_RELATIONSHIP_ENDPOINTS:
            allowed_sources, allowed_targets = VALID_RELATIONSHIP_ENDPOINTS[rel.relationship_type]
            src_label = get_node_label_from_id(rel.source_id)
            tgt_label = get_node_label_from_id(rel.target_id)
            if not src_label and node_label_map:
                src_label = node_label_map.get(rel.source_id) or node_label_map.get(rel.source_id.lower())
            if not tgt_label and node_label_map:
                tgt_label = node_label_map.get(rel.target_id) or node_label_map.get(rel.target_id.lower())

            if not src_label:
                return None, (
                    f"Invalid relationship endpoint: Unable to determine entity type for source_id '{rel.source_id}'. "
                    f"Must have a valid canonical prefix or known entity label."
                )
            if not tgt_label:
                return None, (
                    f"Invalid relationship endpoint: Unable to determine entity type for target_id '{rel.target_id}'. "
                    f"Must have a valid canonical prefix or known entity label."
                )

            if src_label not in allowed_sources:
                allowed_src_names = sorted([s.value for s in allowed_sources])
                return None, (
                    f"Invalid relationship endpoint typing: {rel.relationship_type.value} cannot originate from "
                    f"'{src_label.value}' (source: '{rel.source_id}'). Allowed source types: {allowed_src_names}."
                )
            if tgt_label not in allowed_targets:
                allowed_tgt_names = sorted([t.value for t in allowed_targets])
                return None, (
                    f"Invalid relationship endpoint typing: {rel.relationship_type.value} cannot target "
                    f"'{tgt_label.value}' (target: '{rel.target_id}'). Allowed target types: {allowed_tgt_names}."
                )

        edge_id = f"{rel.source_id}->{rel.target_id}:{rel.relationship_type.value}"
        props = {
            "id": edge_id,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "relationship_type": rel.relationship_type.value,
            "evidence_class": rel.evidence_class.value,
            "source_record_id": rel.source_record_id or "",
            "provenance": rel.provenance,
            "timestamp": rel.timestamp or "",
            "confidence": rel.confidence,
        }
        if rel.traversal_cost is not None:
            props["traversal_cost"] = rel.traversal_cost
        if rel.properties:
            for k, v in rel.properties.items():
                if isinstance(v, (str, int, float, bool)):
                    props[k] = v

        return {
            "type": rel.relationship_type.value,
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "source_label": src_label.value if src_label else None,
            "target_label": tgt_label.value if tgt_label else None,
            "properties": props
        }, None

    def ingest_payload(self, payload: BulkIngestPayload) -> IngestSummaryResponse:
        """
        Idempotently ingests validated entities and relationships into Neo4j.
        Uses targeted database lookups and bounded transactional batches.
        """
        # Ensure schema constraints and indexes exist before loading data
        self.client.init_schema_constraints()

        nodes_imported = 0
        nodes_updated = 0
        nodes_rejected = 0
        relationships_imported = 0
        relationships_updated = 0
        relationships_rejected = 0
        errors: List[str] = []

        validated_nodes_by_label: Dict[str, List[Dict[str, Any]]] = {}
        known_node_ids: Set[str] = set()
        id_aliases: Dict[str, str] = {}
        node_label_map: Dict[str, NodeLabel] = {}

        entity_sources = [
            (NodeLabel.USER, payload.entities.users),
            (NodeLabel.DEVICE, payload.entities.devices),
            (NodeLabel.SERVER, payload.entities.servers),
            (NodeLabel.APPLICATION, payload.entities.applications),
            (NodeLabel.DATABASE, payload.entities.databases),
            (NodeLabel.IP_ADDRESS, payload.entities.ips),
            (NodeLabel.VULNERABILITY, payload.entities.vulnerabilities),
            (NodeLabel.CRITICAL_ASSET, payload.entities.critical_assets),
            (NodeLabel.SECURITY_EVENT, payload.entities.security_events),
            (NodeLabel.EMAIL_ACCOUNT, payload.entities.email_accounts),
        ]

        # Collect candidate IDs from payload for targeted pre-query (FIX 5: removes unbounded MATCH (n))
        candidate_ids: Set[str] = set()
        for _, entity_list in entity_sources:
            for item in entity_list:
                item_dict = item if isinstance(item, dict) else (item.model_dump() if hasattr(item, "model_dump") else dict(item))
                for k in ("id", "user_id", "email", "server_id", "device_id", "app_id", "db_id", "cve_id", "asset_id", "ip", "event_id", "email_address"):
                    val = item_dict.get(k)
                    if val and isinstance(val, str):
                        candidate_ids.add(val.strip())
        for rel in payload.relationships.relationships:
            rel_dict = rel if isinstance(rel, dict) else (rel.model_dump() if hasattr(rel, "model_dump") else dict(rel))
            for k in ("source_id", "target_id"):
                val = rel_dict.get(k)
                if val and isinstance(val, str):
                    candidate_ids.add(val.strip())

        if candidate_ids:
            try:
                cypher_lookup = """
                UNWIND $candidates AS cid
                MATCH (n)
                WHERE n.id = cid OR toLower(n.id) = toLower(cid)
                RETURN n.id AS id, labels(n)[0] AS label, n.email AS email, n.user_id AS user_id,
                       n.server_id AS server_id, n.device_id AS device_id, n.app_id AS app_id,
                       n.db_id AS db_id, n.cve_id AS cve_id, n.asset_id AS asset_id
                """
                existing_records = self.client.execute_query(cypher_lookup, {"candidates": list(candidate_ids)})
                for r in existing_records:
                    nid = r.get("id")
                    if nid:
                        known_node_ids.add(nid)
                        lbl_str = r.get("label")
                        if lbl_str:
                            try:
                                node_label_map[nid] = NodeLabel(lbl_str)
                            except ValueError:
                                pass
                    for key in ("email", "user_id", "server_id", "device_id", "app_id", "db_id", "cve_id", "asset_id"):
                        val = r.get(key)
                        if val and nid:
                            self._register_alias(id_aliases, str(val), nid)
            except Exception as e:
                logger.warning(f"Targeted pre-fetch of existing node IDs failed: {e}")

        # 1. Process & Validate Nodes with intra-payload deduplication
        seen_node_canonical_ids: Set[str] = set()

        for label, entity_list in entity_sources:
            validated_nodes_by_label[label.value] = []
            for item in entity_list:
                item_dict = item if isinstance(item, dict) else (item.model_dump() if hasattr(item, "model_dump") else dict(item))
                valid_node, err = self.validate_entity(label, item_dict)
                if err:
                    nodes_rejected += 1
                    errors.append(err)
                else:
                    canonical_id = valid_node["id"]
                    lbl = NodeLabel(valid_node["label"])
                    node_label_map[canonical_id] = lbl

                    if canonical_id in seen_node_canonical_ids:
                        # Intra-payload duplicate node: update existing properties
                        for existing_node in validated_nodes_by_label[label.value]:
                            if existing_node["id"] == canonical_id:
                                existing_node["properties"].update(valid_node["properties"])
                                break
                    else:
                        seen_node_canonical_ids.add(canonical_id)
                        validated_nodes_by_label[label.value].append(valid_node)
                        known_node_ids.add(canonical_id)

                        # FIX 2: Comprehensive alias registration across all entity types
                        self._register_alias(id_aliases, canonical_id, canonical_id)
                        raw_id_val = item_dict.get("id")
                        if raw_id_val:
                            self._register_alias(id_aliases, raw_id_val, canonical_id)

                        if label == NodeLabel.USER:
                            email = item_dict.get("email")
                            uid = item_dict.get("user_id")
                            if email:
                                self._register_alias(id_aliases, f"user:{email.lower()}", canonical_id)
                                self._register_alias(id_aliases, email, canonical_id)
                            if uid:
                                self._register_alias(id_aliases, f"user:{uid.lower()}", canonical_id)
                                self._register_alias(id_aliases, uid, canonical_id)
                        elif label == NodeLabel.DEVICE:
                            dev_id = item_dict.get("device_id")
                            host = item_dict.get("hostname")
                            if dev_id:
                                self._register_alias(id_aliases, f"device:{dev_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, dev_id, canonical_id)
                            if host:
                                self._register_alias(id_aliases, host, canonical_id)
                        elif label == NodeLabel.SERVER:
                            srv_id = item_dict.get("server_id")
                            host = item_dict.get("hostname")
                            if srv_id:
                                self._register_alias(id_aliases, f"server:{srv_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, srv_id, canonical_id)
                            if host:
                                self._register_alias(id_aliases, host, canonical_id)
                        elif label == NodeLabel.APPLICATION:
                            app_id = item_dict.get("app_id")
                            name = item_dict.get("name")
                            if app_id:
                                self._register_alias(id_aliases, f"app:{app_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, app_id, canonical_id)
                            if name:
                                self._register_alias(id_aliases, name, canonical_id)
                        elif label == NodeLabel.DATABASE:
                            db_id = item_dict.get("db_id")
                            name = item_dict.get("name")
                            if db_id:
                                self._register_alias(id_aliases, f"db:{db_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, db_id, canonical_id)
                            if name:
                                self._register_alias(id_aliases, name, canonical_id)
                        elif label == NodeLabel.IP_ADDRESS:
                            ip_val = item_dict.get("ip")
                            if ip_val:
                                self._register_alias(id_aliases, f"ip:{ip_val}", canonical_id)
                                self._register_alias(id_aliases, ip_val, canonical_id)
                        elif label == NodeLabel.VULNERABILITY:
                            cve = item_dict.get("cve_id")
                            if cve:
                                self._register_alias(id_aliases, f"vuln:{cve.upper()}", canonical_id)
                                self._register_alias(id_aliases, cve, canonical_id)
                        elif label == NodeLabel.CRITICAL_ASSET:
                            asset_id = item_dict.get("asset_id")
                            name = item_dict.get("name")
                            if asset_id:
                                self._register_alias(id_aliases, f"critical:{asset_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, asset_id, canonical_id)
                            if name:
                                self._register_alias(id_aliases, name, canonical_id)
                        elif label == NodeLabel.EMAIL_ACCOUNT:
                            email_addr = item_dict.get("email_address")
                            if email_addr:
                                self._register_alias(id_aliases, f"email:{email_addr.lower()}", canonical_id)
                                self._register_alias(id_aliases, email_addr, canonical_id)
                        elif label == NodeLabel.SECURITY_EVENT:
                            evt_id = item_dict.get("event_id")
                            if evt_id:
                                self._register_alias(id_aliases, f"event:{evt_id.lower()}", canonical_id)
                                self._register_alias(id_aliases, evt_id, canonical_id)

        # Ingest nodes into Neo4j using bounded batches
        now_ts = datetime.now(timezone.utc).isoformat()
        for label_name, nodes in validated_nodes_by_label.items():
            if not nodes:
                continue

            for i in range(0, len(nodes), BATCH_SIZE):
                batch = nodes[i : i + BATCH_SIZE]
                cypher = f"""
                UNWIND $batch AS item
                MERGE (n:{label_name} {{id: item.id}})
                ON CREATE SET n += item.properties, n.created_at = $timestamp
                ON MATCH SET n += item.properties, n.updated_at = $timestamp
                """
                params = {"batch": batch, "timestamp": now_ts}
                counters = self.client.execute_write(cypher, params)
                nodes_imported += counters.get("nodes_created", 0)
                if counters.get("nodes_created", 0) < len(batch):
                    nodes_updated += (len(batch) - counters.get("nodes_created", 0))

        # 2. Process & Validate Relationships with intra-payload deduplication
        all_resolvable_ids = known_node_ids.union(id_aliases.keys())
        validated_rels_by_type: Dict[str, List[Dict[str, Any]]] = {}
        seen_rel_keys: Set[str] = set()
        for rel in payload.relationships.relationships:
            rel_dict = rel if isinstance(rel, dict) else (rel.model_dump() if hasattr(rel, "model_dump") else dict(rel))
            valid_rel, err = self.validate_relationship(rel_dict, all_resolvable_ids, id_aliases, node_label_map)
            if err:
                relationships_rejected += 1
                errors.append(err)
            else:
                rel_type = valid_rel["type"]
                rel_key = f"{valid_rel['source_id']}->{valid_rel['target_id']}:{rel_type}"
                if rel_type not in validated_rels_by_type:
                    validated_rels_by_type[rel_type] = []

                if rel_key in seen_rel_keys:
                    for existing_rel in validated_rels_by_type[rel_type]:
                        existing_key = f"{existing_rel['source_id']}->{existing_rel['target_id']}:{existing_rel['type']}"
                        if existing_key == rel_key:
                            existing_rel["properties"].update(valid_rel["properties"])
                            break
                else:
                    seen_rel_keys.add(rel_key)
                    validated_rels_by_type[rel_type].append(valid_rel)

        # Ingest relationships into Neo4j using bounded batches with label-qualified matches & deterministic order
        validated_rels_grouped: Dict[Tuple[str, Optional[str], Optional[str]], List[Dict[str, Any]]] = {}
        for rel_type, rel_list in validated_rels_by_type.items():
            for rel_item in rel_list:
                group_key = (rel_type, rel_item.get("source_label"), rel_item.get("target_label"))
                if group_key not in validated_rels_grouped:
                    validated_rels_grouped[group_key] = []
                validated_rels_grouped[group_key].append(rel_item)

        for (rel_type, src_lbl, tgt_lbl), rel_list in validated_rels_grouped.items():
            for i in range(0, len(rel_list), BATCH_SIZE):
                batch = rel_list[i : i + BATCH_SIZE]
                # FIX 5: Sort deterministically to prevent concurrent UNWIND deadlocks
                batch.sort(key=lambda r: (r["source_id"], r["target_id"]))

                # FIX 4: Label-qualified MATCH queries using verified schema labels
                src_match = f"(s:{src_lbl} {{id: rel.source_id}})" if src_lbl else "(s {id: rel.source_id})"
                tgt_match = f"(t:{tgt_lbl} {{id: rel.target_id}})" if tgt_lbl else "(t {id: rel.target_id})"

                cypher = f"""
                UNWIND $batch AS rel
                MATCH {src_match}
                MATCH {tgt_match}
                MERGE (s)-[r:{rel_type}]->(t)
                ON CREATE SET r += rel.properties, r.created_at = $timestamp
                ON MATCH SET r += rel.properties, r.updated_at = $timestamp
                """
                params = {"batch": batch, "timestamp": now_ts}
                counters = self.client.execute_write(cypher, params)
                created_count = counters.get("relationships_created", 0)
                relationships_imported += created_count
                if created_count < len(batch):
                    relationships_updated += (len(batch) - created_count)

        status = "SUCCESS"
        if errors and (nodes_imported > 0 or relationships_imported > 0 or nodes_updated > 0 or relationships_updated > 0):
            status = "PARTIAL"
        elif errors and nodes_imported == 0 and relationships_imported == 0 and nodes_updated == 0 and relationships_updated == 0:
            status = "FAILED"

        return IngestSummaryResponse(
            status=status,
            dataset_name=payload.dataset_name,
            nodes_imported=nodes_imported,
            nodes_updated=nodes_updated,
            nodes_rejected=nodes_rejected,
            relationships_imported=relationships_imported,
            relationships_updated=relationships_updated,
            relationships_rejected=relationships_rejected,
            errors=errors,
            timestamp=now_ts,
        )

    def parse_csv_entities(self, csv_text: str) -> EntityIngestRequest:
        """
        Parses CSV records into typed entity objects for bulk ingestion.
        Normalizes header case (Label, LABEL, label).
        Implements row-level fault tolerance without phantom fallback IDs.
        """
        clean_text = csv_text.strip()
        req = EntityIngestRequest()
        if not clean_text:
            return req

        reader = csv.DictReader(io.StringIO(clean_text))
        for row_idx, raw_row in enumerate(reader, start=2):
            # Normalize headers to lowercase and strip whitespace
            row = {k.strip().lower(): v.strip() for k, v in raw_row.items() if k and v is not None}
            if not row or not any(row.values()):
                continue

            try:
                # Determine label
                label_val = row.pop("label", None)
                if not label_val:
                    if "cve_id" in row:
                        label_val = "Vulnerability"
                    elif "email_address" in row:
                        label_val = "EmailAccount"
                    elif "impact_score" in row or "asset_id" in row:
                        label_val = "CriticalAsset"
                    elif "tier" in row or "server_id" in row:
                        label_val = "Server"
                    elif "os" in row or "device_id" in row:
                        label_val = "Device"
                    elif "app_id" in row:
                        label_val = "Application"
                    elif "ip" in row:
                        label_val = "IPAddress"
                    elif "event_type" in row:
                        label_val = "SecurityEvent"
                    elif "email" in row and ("role" in row or "department" in row):
                        label_val = "User"
                    else:
                        label_val = "User"

                label_clean = label_val.strip().lower()

                def to_bool(val: Any) -> bool:
                    return str(val).strip().lower() in ("true", "1", "yes")

                def to_int(val: Any, default: int = 0) -> int:
                    try:
                        return int(float(val))
                    except (ValueError, TypeError):
                        return default

                def to_float(val: Any, default: float = 0.0) -> float:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        return default

                # Extract IDs strictly without manufacturing phantom values that merge unrelated records
                if label_clean in ("user", "nodelabel.user"):
                    raw_id = row.get("id") or row.get("user_id") or row.get("email")
                    if not raw_id:
                        raise ValueError("Missing required User identifier ('id', 'user_id', or 'email').")
                    email = row.get("email")
                    if not email:
                        raise ValueError("Missing required User corporate email.")
                    req.users.append(UserNode(
                        id=raw_id,
                        user_id=row.get("user_id", raw_id),
                        email=email,
                        name=row.get("name") or f"User {raw_id}",
                        department=row.get("department", "Unassigned"),
                        role=row.get("role", "Standard User"),
                        is_service_account=to_bool(row.get("is_service_account", False)),
                        is_admin=to_bool(row.get("is_admin", False)),
                        status=row.get("status", "ACTIVE"),
                    ))
                elif label_clean in ("device", "nodelabel.device"):
                    raw_id = row.get("id") or row.get("device_id")
                    if not raw_id:
                        raise ValueError("Missing required Device identifier ('id' or 'device_id').")
                    ip_addr = row.get("ip_address") or row.get("ip")
                    if not ip_addr:
                        raise ValueError("Missing required IP address for Device.")
                    req.devices.append(DeviceNode(
                        id=raw_id,
                        device_id=row.get("device_id", raw_id),
                        hostname=row.get("hostname") or f"device-{raw_id}.corp",
                        ip_address=ip_addr,
                        mac_address=row.get("mac_address"),
                        os=row.get("os", "Windows 11 Enterprise"),
                        subnet=row.get("subnet"),
                        is_isolated=to_bool(row.get("is_isolated", False)),
                    ))
                elif label_clean in ("server", "nodelabel.server"):
                    raw_id = row.get("id") or row.get("server_id")
                    if not raw_id:
                        raise ValueError("Missing required Server identifier ('id' or 'server_id').")
                    ip_addr = row.get("ip_address") or row.get("ip")
                    if not ip_addr:
                        raise ValueError("Missing required IP address for Server.")
                    req.servers.append(ServerNode(
                        id=raw_id,
                        server_id=row.get("server_id", raw_id),
                        name=row.get("name") or f"Server {raw_id}",
                        hostname=row.get("hostname") or f"srv-{raw_id}.corp",
                        ip_address=ip_addr,
                        tier=row.get("tier", "Application"),
                        environment=row.get("environment", "Production"),
                        is_isolated=to_bool(row.get("is_isolated", False)),
                    ))
                elif label_clean in ("application", "app", "nodelabel.application"):
                    raw_id = row.get("id") or row.get("app_id")
                    if not raw_id:
                        raise ValueError("Missing required Application identifier ('id' or 'app_id').")
                    req.applications.append(ApplicationNode(
                        id=raw_id,
                        app_id=row.get("app_id", raw_id),
                        name=row.get("name") or f"App {raw_id}",
                        version=row.get("version", "1.0.0"),
                        port=to_int(row.get("port", 0)) if row.get("port") else None,
                        service_type=row.get("service_type", "API"),
                        environment=row.get("environment", "Production"),
                    ))
                elif label_clean in ("database", "db", "nodelabel.database"):
                    raw_id = row.get("id") or row.get("db_id")
                    if not raw_id:
                        raise ValueError("Missing required Database identifier ('id' or 'db_id').")
                    req.databases.append(DatabaseNode(
                        id=raw_id,
                        db_id=row.get("db_id", raw_id),
                        name=row.get("name") or f"Database {raw_id}",
                        engine=row.get("engine", "PostgreSQL"),
                        port=to_int(row.get("port", 5432)) if row.get("port") else 5432,
                        tier=row.get("tier", "Database"),
                        environment=row.get("environment", "Production"),
                        is_clustered=to_bool(row.get("is_clustered", False)),
                    ))
                elif label_clean in ("ipaddress", "ip", "nodelabel.ip_address"):
                    raw_id = row.get("id") or row.get("ip")
                    if not raw_id:
                        raise ValueError("Missing required IP Address identifier ('id' or 'ip').")
                    req.ips.append(IpAddressNode(
                        id=raw_id,
                        ip=row.get("ip", raw_id),
                        version=to_int(row.get("version", 4)),
                        scope=row.get("scope", "internal"),
                        subnet=row.get("subnet"),
                        is_monitored=to_bool(row.get("is_monitored", True)),
                    ))
                elif label_clean in ("vulnerability", "vuln", "nodelabel.vulnerability"):
                    cve = (row.get("cve_id") or row.get("id") or "").strip()
                    if not cve:
                        raise ValueError("Missing required CVE ID for Vulnerability.")
                    cvss = to_float(row.get("cvss_score") or 5.0)
                    sev = (row.get("severity") or "").strip().upper()
                    if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                        if cvss >= 9.0:
                            sev = "CRITICAL"
                        elif cvss >= 7.0:
                            sev = "HIGH"
                        elif cvss >= 4.0:
                            sev = "MEDIUM"
                        else:
                            sev = "LOW"
                    req.vulnerabilities.append(VulnerabilityNode(
                        id=cve,
                        cve_id=cve,
                        cvss_score=cvss,
                        severity=sev,
                        description=row.get("description") or "",
                        exploit_available=to_bool(row.get("exploit_available", False)),
                        patch_available=to_bool(row.get("patch_available", True)),
                    ))
                elif label_clean in ("criticalasset", "critical", "crit", "nodelabel.critical_asset"):
                    raw_id = row.get("id") or row.get("asset_id")
                    if not raw_id:
                        raise ValueError("Missing required identifier for CriticalAsset ('id' or 'asset_id').")
                    req.critical_assets.append(CriticalAssetNode(
                        id=raw_id,
                        asset_id=row.get("asset_id", raw_id),
                        name=row.get("name") or f"Critical Asset {raw_id}",
                        category=row.get("category", "CUSTOMER_PII"),
                        impact_score=to_int(row.get("impact_score", 90)),
                        data_classification=row.get("data_classification", "CONFIDENTIAL"),
                        owner_department=row.get("owner_department", "IT Infrastructure"),
                    ))
                elif label_clean in ("emailaccount", "email", "nodelabel.email_account"):
                    email_addr = row.get("email_address") or row.get("email") or row.get("id")
                    if not email_addr:
                        raise ValueError("Missing required email address for EmailAccount.")
                    req.email_accounts.append(EmailAccountNode(
                        id=email_addr,
                        email_address=email_addr,
                        account_name=row.get("account_name"),
                        domain=row.get("domain"),
                        mailbox_type=row.get("mailbox_type", "USER"),
                        is_internal=to_bool(row.get("is_internal", True)),
                        is_compromised=to_bool(row.get("is_compromised", False)),
                    ))
                elif label_clean in ("securityevent", "event", "nodelabel.security_event"):
                    raw_id = row.get("id") or row.get("event_id")
                    if not raw_id:
                        raise ValueError("Missing required identifier for SecurityEvent ('id' or 'event_id').")
                    req.security_events.append(SecurityEventNode(
                        id=raw_id,
                        event_id=row.get("event_id", raw_id),
                        event_type=row.get("event_type", "PHISHING_INCIDENT"),
                        severity=row.get("severity", "HIGH"),
                        timestamp=row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        case_id=row.get("case_id"),
                        provenance=row.get("provenance", "CSV Import"),
                    ))
            except Exception as e:
                # Row-level exception handling: record rejected row and continue
                req.rejected_count += 1
                req.parsing_errors.append(f"Row {row_idx} rejected: {str(e)}")

        return req

    def parse_csv_relationships(self, csv_text: str) -> RelationshipIngestRequest:
        """
        Parses CSV records into EnterpriseRelationship models.
        Normalizes header case and implements row-level fault tolerance.
        """
        clean_text = csv_text.strip()
        req = RelationshipIngestRequest()
        if not clean_text:
            return req

        reader = csv.DictReader(io.StringIO(clean_text))
        for row_idx, raw_row in enumerate(reader, start=2):
            row = {k.strip().lower(): v.strip() for k, v in raw_row.items() if k and v is not None}
            if not row or not any(row.values()):
                continue

            if "source_id" not in row or "target_id" not in row:
                req.rejected_count += 1
                req.parsing_errors.append(f"Row {row_idx} rejected: Missing 'source_id' or 'target_id'.")
                continue

            try:
                cost = None
                if "traversal_cost" in row and row["traversal_cost"]:
                    try:
                        cost = float(row["traversal_cost"])
                    except ValueError:
                        cost = None

                conf = 1.0
                if "confidence" in row and row["confidence"]:
                    try:
                        conf = float(row["confidence"])
                    except ValueError:
                        conf = 1.0

                rel_type = row.get("relationship_type", row.get("type", "CONNECTS_TO"))
                ev_class = row.get("evidence_class", "OBSERVED")

                props = {}
                reserved = {"source_id", "target_id", "relationship_type", "type", "evidence_class",
                            "traversal_cost", "provenance", "confidence", "timestamp", "id", "source_record_id"}
                for k, v in row.items():
                    if k not in reserved and v:
                        props[k] = v

                req.relationships.append(EnterpriseRelationship(
                    id=row.get("id"),
                    source_id=row["source_id"],
                    target_id=row["target_id"],
                    relationship_type=rel_type,
                    evidence_class=ev_class,
                    source_record_id=row.get("source_record_id"),
                    provenance=row.get("provenance", "CSV Ingestion"),
                    timestamp=row.get("timestamp"),
                    confidence=conf,
                    traversal_cost=cost,
                    properties=props,
                ))
            except Exception as e:
                req.rejected_count += 1
                req.parsing_errors.append(f"Row {row_idx} rejected: {str(e)}")

        return req

    def ingest_csv(
        self,
        csv_text: str,
        dataset_name: str = "csv_import",
        data_type: str = "auto",
    ) -> IngestSummaryResponse:
        """
        Ingests CSV content containing either nodes or relationships into Neo4j.
        Detects data type automatically from header columns if data_type='auto'.
        """
        clean_text = csv_text.strip()
        if not clean_text:
            return IngestSummaryResponse(
                status="FAILED",
                dataset_name=dataset_name,
                errors=["Empty CSV content provided."],
            )

        first_line = clean_text.splitlines()[0].lower()
        headers = [h.strip() for h in first_line.split(",")]

        is_relationship_csv = (
            data_type == "relationships"
            or ("source_id" in headers and "target_id" in headers)
        )

        if is_relationship_csv:
            rel_req = self.parse_csv_relationships(clean_text)
            rel_req.dataset_name = dataset_name
            payload = BulkIngestPayload(
                dataset_name=dataset_name,
                entities=EntityIngestRequest(dataset_name=dataset_name),
                relationships=rel_req,
            )
            summary = self.ingest_payload(payload)
            summary.relationships_rejected += rel_req.rejected_count
            summary.errors = rel_req.parsing_errors + summary.errors
            if rel_req.rejected_count > 0:
                if summary.relationships_imported > 0 or summary.relationships_updated > 0:
                    summary.status = "PARTIAL"
                else:
                    summary.status = "FAILED"
            return summary
        else:
            ent_req = self.parse_csv_entities(clean_text)
            ent_req.dataset_name = dataset_name
            payload = BulkIngestPayload(
                dataset_name=dataset_name,
                entities=ent_req,
                relationships=RelationshipIngestRequest(dataset_name=dataset_name),
            )
            summary = self.ingest_payload(payload)
            summary.nodes_rejected += ent_req.rejected_count
            summary.errors = ent_req.parsing_errors + summary.errors
            if ent_req.rejected_count > 0:
                if summary.nodes_imported > 0 or summary.nodes_updated > 0:
                    summary.status = "PARTIAL"
                else:
                    summary.status = "FAILED"
            return summary

    def ingest_sample_fixture(self) -> IngestSummaryResponse:
        """
        Loads and ingests the default synthetic SOC enterprise security graph fixture.
        """
        raw_json = load_sample_enterprise_fixture()
        payload = BulkIngestPayload(**raw_json)
        return self.ingest_payload(payload)

    def get_graph_summary(self) -> Dict[str, Any]:
        """
        Queries and returns comprehensive topological metrics of the organizational security graph.
        """
        node_count_records = self.client.execute_query(
            "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"
        )
        node_counts = {r["label"]: r["count"] for r in node_count_records if r.get("label")}

        rel_count_records = self.client.execute_query(
            "MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS count ORDER BY count DESC"
        )
        rel_counts = {r["rel_type"]: r["count"] for r in rel_count_records if r.get("rel_type")}

        critical_records = self.client.execute_query(
            "MATCH (c:CriticalAsset) RETURN c.id AS id, c.name AS name, c.impact_score AS impact, c.category AS category"
        )

        return {
            "total_nodes": sum(node_counts.values()),
            "total_relationships": sum(rel_counts.values()),
            "node_counts_by_label": node_counts,
            "relationship_counts_by_type": rel_counts,
            "critical_assets": critical_records,
            "status": "POPULATED" if node_counts else "EMPTY",
        }


# Global default ingestion service
default_ingestion_engine = GraphOpsIngestionEngine()


def run_sample_ingestion() -> IngestSummaryResponse:
    """Convenience helper to run sample ingestion via python script."""
    engine = GraphOpsIngestionEngine()
    return engine.ingest_sample_fixture()


if __name__ == "__main__":
    import json
    print("=" * 65)
    print("THREATLENS GRAPHOPS - SAMPLE ENTERPRISE INGESTION")
    print("=" * 65)
    summary = run_sample_ingestion()
    print(json.dumps(summary.model_dump(), indent=2))
