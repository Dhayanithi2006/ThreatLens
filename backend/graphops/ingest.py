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
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Validates relationship structure and ensures source and target exist.
        Resolves entity aliases (e.g. user:email -> user:id) and normalizes vulnerability case.
        Prevents manufactured or broken links.
        """
        rel_data = dict(raw_rel)
        src = str(rel_data.get("source_id", "")).strip()
        tgt = str(rel_data.get("target_id", "")).strip()

        # Resolve aliases if present
        if id_aliases:
            src = id_aliases.get(src, src)
            tgt = id_aliases.get(tgt, tgt)

        # Normalize CVE case
        if src.lower().startswith("vuln:cve-"):
            src = "vuln:" + src[5:].upper()
        if tgt.lower().startswith("vuln:cve-"):
            tgt = "vuln:" + tgt[5:].upper()

        rel_data["source_id"] = src
        rel_data["target_id"] = tgt

        try:
            rel = EnterpriseRelationship(**rel_data)
        except ValidationError as e:
            err_msg = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in e.errors())
            return None, f"Relationship validation failed: {err_msg}"

        # Reference verification: Ensure source and target endpoints exist (with case-insensitive resolution)
        known_lower_map = {k.lower(): k for k in known_node_ids}
        if rel.source_id not in known_node_ids:
            if rel.source_id.lower() in known_lower_map:
                rel.source_id = known_lower_map[rel.source_id.lower()]
            else:
                return None, f"Unresolved relationship reference: source_id '{rel.source_id}' does not exist."
        if rel.target_id not in known_node_ids:
            if rel.target_id.lower() in known_lower_map:
                rel.target_id = known_lower_map[rel.target_id.lower()]
            else:
                return None, f"Unresolved relationship reference: target_id '{rel.target_id}' does not exist."

        # Endpoint typing verification: Ensure source and target entities match schema rules
        if rel.relationship_type in VALID_RELATIONSHIP_ENDPOINTS:
            allowed_sources, allowed_targets = VALID_RELATIONSHIP_ENDPOINTS[rel.relationship_type]
            src_label = get_node_label_from_id(rel.source_id)
            tgt_label = get_node_label_from_id(rel.target_id)
            if src_label and src_label not in allowed_sources:
                allowed_src_names = sorted([s.value for s in allowed_sources])
                return None, (
                    f"Invalid relationship endpoint typing: {rel.relationship_type.value} cannot originate from "
                    f"'{src_label.value}' (source: '{rel.source_id}'). Allowed source types: {allowed_src_names}."
                )
            if tgt_label and tgt_label not in allowed_targets:
                allowed_tgt_names = sorted([t.value for t in allowed_targets])
                return None, (
                    f"Invalid relationship endpoint typing: {rel.relationship_type.value} cannot target "
                    f"'{tgt_label.value}' (target: '{rel.target_id}'). Allowed target types: {allowed_tgt_names}."
                )

        props = {
            "id": rel.id,
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
            "properties": props
        }, None

    def ingest_payload(self, payload: BulkIngestPayload) -> IngestSummaryResponse:
        """
        Idempotently ingests validated entities and relationships into Neo4j.
        Splits operations into bounded transactional batches.
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

        # Pre-query existing node IDs from the database to allow relationships to link to existing assets
        try:
            existing_records = self.client.execute_query("MATCH (n) RETURN n.id AS id, n.email AS email")
            for r in existing_records:
                if r.get("id"):
                    known_node_ids.add(r["id"])
                if r.get("email"):
                    id_aliases[f"user:{r['email'].lower()}"] = r["id"]
        except Exception as e:
            logger.warning(f"Could not pre-fetch existing node IDs (database may be empty or starting up): {e}")

        # 1. Process & Validate Nodes with intra-payload deduplication
        seen_node_canonical_ids: Set[str] = set()
        entity_sources = [
            (NodeLabel.USER, payload.entities.users),
            (NodeLabel.DEVICE, payload.entities.devices),
            (NodeLabel.SERVER, payload.entities.servers),
            (NodeLabel.APPLICATION, payload.entities.applications),
            (NodeLabel.IP_ADDRESS, payload.entities.ips),
            (NodeLabel.VULNERABILITY, payload.entities.vulnerabilities),
            (NodeLabel.CRITICAL_ASSET, payload.entities.critical_assets),
            (NodeLabel.SECURITY_EVENT, payload.entities.security_events),
            (NodeLabel.EMAIL_ACCOUNT, payload.entities.email_accounts),
        ]

        for label, entity_list in entity_sources:
            validated_nodes_by_label[label.value] = []
            for item in entity_list:
                item_dict = item.model_dump() if hasattr(item, "model_dump") else dict(item)
                valid_node, err = self.validate_entity(label, item_dict)
                if err:
                    nodes_rejected += 1
                    errors.append(err)
                else:
                    canonical_id = valid_node["id"]
                    if canonical_id in seen_node_canonical_ids:
                        # Intra-payload duplicate node: update existing properties rather than sending duplicate UNWIND rows
                        for existing_node in validated_nodes_by_label[label.value]:
                            if existing_node["id"] == canonical_id:
                                existing_node["properties"].update(valid_node["properties"])
                                break
                    else:
                        seen_node_canonical_ids.add(canonical_id)
                        validated_nodes_by_label[label.value].append(valid_node)
                        known_node_ids.add(canonical_id)
                        # Register user email and ID aliases for clean reference resolution
                        if label == NodeLabel.USER:
                            email = item_dict.get("email")
                            uid = item_dict.get("user_id")
                            if email:
                                id_aliases[f"user:{email.lower()}"] = canonical_id
                                id_aliases[email.lower()] = canonical_id
                            if uid:
                                id_aliases[f"user:{uid.lower()}"] = canonical_id
                                id_aliases[uid.lower()] = canonical_id
                        elif label == NodeLabel.EMAIL_ACCOUNT:
                            email_addr = item_dict.get("email_address")
                            if email_addr:
                                id_aliases[f"email:{email_addr.lower()}"] = canonical_id
                                id_aliases[email_addr.lower()] = canonical_id

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
                # If node already existed, properties were set on match
                if counters.get("nodes_created", 0) < len(batch):
                    nodes_updated += (len(batch) - counters.get("nodes_created", 0))

        # 2. Process & Validate Relationships with intra-payload deduplication
        all_resolvable_ids = known_node_ids.union(id_aliases.keys())
        validated_rels_by_type: Dict[str, List[Dict[str, Any]]] = {}
        seen_rel_keys: Set[str] = set()
        for rel in payload.relationships.relationships:
            rel_dict = rel.model_dump() if hasattr(rel, "model_dump") else dict(rel)
            valid_rel, err = self.validate_relationship(rel_dict, all_resolvable_ids, id_aliases)
            if err:
                relationships_rejected += 1
                errors.append(err)
            else:
                rel_type = valid_rel["type"]
                rel_key = f"{valid_rel['source_id']}->{valid_rel['target_id']}:{rel_type}"
                if rel_type not in validated_rels_by_type:
                    validated_rels_by_type[rel_type] = []

                if rel_key in seen_rel_keys:
                    # Intra-payload duplicate relationship: update properties on existing entry
                    for existing_rel in validated_rels_by_type[rel_type]:
                        existing_key = f"{existing_rel['source_id']}->{existing_rel['target_id']}:{existing_rel['type']}"
                        if existing_key == rel_key:
                            existing_rel["properties"].update(valid_rel["properties"])
                            break
                else:
                    seen_rel_keys.add(rel_key)
                    validated_rels_by_type[rel_type].append(valid_rel)

        # Ingest relationships into Neo4j using bounded batches
        for rel_type, rel_list in validated_rels_by_type.items():
            for i in range(0, len(rel_list), BATCH_SIZE):
                batch = rel_list[i : i + BATCH_SIZE]
                cypher = f"""
                UNWIND $batch AS rel
                MATCH (s {{id: rel.source_id}})
                MATCH (t {{id: rel.target_id}})
                MERGE (s)-[r:{rel_type}]->(t)
                ON CREATE SET r += rel.properties, r.created_at = $timestamp
                ON MATCH SET r += rel.properties, r.updated_at = $timestamp
                """
                params = {"batch": batch, "timestamp": now_ts}
                counters = self.client.execute_write(cypher, params)
                relationships_imported += counters.get("relationships_created", 0)
                if counters.get("relationships_created", 0) < len(batch):
                    relationships_updated += (len(batch) - counters.get("relationships_created", 0))

        status = "SUCCESS"
        if errors and (nodes_imported > 0 or relationships_imported > 0):
            status = "PARTIAL"
        elif errors and nodes_imported == 0 and relationships_imported == 0:
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
        Supports columns: label (or inferred), id, name, and type-specific attributes.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        req = EntityIngestRequest()
        for raw_row in reader:
            row = {k.strip(): v.strip() for k, v in raw_row.items() if k and v is not None}
            if not row:
                continue

            # Determine label
            label_val = row.pop("label", None)
            if not label_val:
                # Infer from characteristic columns
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

            if label_clean in ("user", "nodelabel.user"):
                req.users.append(UserNode(
                    id=row.get("id", row.get("user_id", row.get("email", "unknown"))),
                    user_id=row.get("user_id", row.get("id", "USR-000")),
                    email=row.get("email", "unknown@corp.com"),
                    name=row.get("name", "Unknown User"),
                    department=row.get("department", "Unassigned"),
                    role=row.get("role", "Standard User"),
                    is_service_account=to_bool(row.get("is_service_account", False)),
                    is_admin=to_bool(row.get("is_admin", False)),
                    status=row.get("status", "ACTIVE"),
                ))
            elif label_clean in ("device", "nodelabel.device"):
                req.devices.append(DeviceNode(
                    id=row.get("id", row.get("device_id", "DEV-WS-000")),
                    device_id=row.get("device_id", row.get("id", "DEV-WS-000")),
                    hostname=row.get("hostname", "ws-unknown.corp"),
                    ip_address=row.get("ip_address", "10.0.0.1"),
                    mac_address=row.get("mac_address"),
                    os=row.get("os", "Windows 11 Enterprise"),
                    subnet=row.get("subnet"),
                    is_isolated=to_bool(row.get("is_isolated", False)),
                ))
            elif label_clean in ("server", "nodelabel.server"):
                req.servers.append(ServerNode(
                    id=row.get("id", row.get("server_id", "SRV-000")),
                    server_id=row.get("server_id", row.get("id", "SRV-000")),
                    name=row.get("name", "Server"),
                    hostname=row.get("hostname", "srv.corp"),
                    ip_address=row.get("ip_address", "10.0.0.2"),
                    tier=row.get("tier", "Application"),
                    environment=row.get("environment", "Production"),
                    is_isolated=to_bool(row.get("is_isolated", False)),
                ))
            elif label_clean in ("application", "app", "nodelabel.application"):
                req.applications.append(ApplicationNode(
                    id=row.get("id", row.get("app_id", "APP-000")),
                    app_id=row.get("app_id", row.get("id", "APP-000")),
                    name=row.get("name", "Application"),
                    version=row.get("version", "1.0.0"),
                    port=to_int(row.get("port", 0)) if row.get("port") else None,
                    service_type=row.get("service_type", "API"),
                    environment=row.get("environment", "Production"),
                ))
            elif label_clean in ("ipaddress", "ip", "nodelabel.ip_address"):
                req.ips.append(IpAddressNode(
                    id=row.get("id", row.get("ip", "10.0.0.1")),
                    ip=row.get("ip", row.get("id", "10.0.0.1")),
                    version=to_int(row.get("version", 4)),
                    scope=row.get("scope", "internal"),
                    subnet=row.get("subnet"),
                    is_monitored=to_bool(row.get("is_monitored", True)),
                ))
            elif label_clean in ("vulnerability", "vuln", "nodelabel.vulnerability"):
                cve = (row.get("cve_id") or row.get("id") or "CVE-2024-0000").strip()
                if not cve.upper().startswith("CVE-"):
                    cve = f"CVE-2024-{cve}" if cve.isdigit() else "CVE-2024-0000"
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
                req.critical_assets.append(CriticalAssetNode(
                    id=row.get("id", row.get("asset_id", "CRIT-000")),
                    asset_id=row.get("asset_id", row.get("id", "CRIT-000")),
                    name=row.get("name", "Critical Asset"),
                    category=row.get("category", "CUSTOMER_PII"),
                    impact_score=to_int(row.get("impact_score", 90)),
                    data_classification=row.get("data_classification", "CONFIDENTIAL"),
                    owner_department=row.get("owner_department", "IT Infrastructure"),
                ))
            elif label_clean in ("emailaccount", "email", "nodelabel.email_account"):
                req.email_accounts.append(EmailAccountNode(
                    id=row.get("id", row.get("email_address", "user@corp.com")),
                    email_address=row.get("email_address", row.get("id", "user@corp.com")),
                    account_name=row.get("account_name"),
                    domain=row.get("domain"),
                    mailbox_type=row.get("mailbox_type", "USER"),
                    is_internal=to_bool(row.get("is_internal", True)),
                    is_compromised=to_bool(row.get("is_compromised", False)),
                ))
            elif label_clean in ("securityevent", "event", "nodelabel.security_event"):
                req.security_events.append(SecurityEventNode(
                    id=row.get("id", row.get("event_id", "EVT-000")),
                    event_id=row.get("event_id", row.get("id", "EVT-000")),
                    event_type=row.get("event_type", "PHISHING_INCIDENT"),
                    severity=row.get("severity", "HIGH"),
                    timestamp=row.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    case_id=row.get("case_id"),
                    provenance=row.get("provenance", "CSV Import"),
                ))
        return req

    def parse_csv_relationships(self, csv_text: str) -> RelationshipIngestRequest:
        """
        Parses CSV records into EnterpriseRelationship models.
        Supports columns: source_id, target_id, relationship_type, evidence_class,
        traversal_cost, provenance, confidence, timestamp, etc.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        req = RelationshipIngestRequest()
        for raw_row in reader:
            row = {k.strip(): v.strip() for k, v in raw_row.items() if k and v is not None}
            if not row or "source_id" not in row or "target_id" not in row:
                continue

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
        else:
            ent_req = self.parse_csv_entities(clean_text)
            ent_req.dataset_name = dataset_name
            payload = BulkIngestPayload(
                dataset_name=dataset_name,
                entities=ent_req,
                relationships=RelationshipIngestRequest(dataset_name=dataset_name),
            )

        return self.ingest_payload(payload)

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
