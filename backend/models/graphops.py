"""
ThreatLens GraphOps - Pydantic Data Models & API Contracts
Defines enterprise graph entities, typed relationships, ingestion payloads,
blast-radius requests/results, attack-path discovery, choke-point analysis,
and what-if containment simulation contracts.
"""

from typing import List, Dict, Optional, Any, Set
from enum import Enum
from datetime import datetime, timezone
import re
import ipaddress
import math
from pydantic import BaseModel, Field, field_validator, model_validator, computed_field

from backend.graphops.schema import (
    NodeLabel,
    EvidenceClass,
    RelationshipType,
    CriticalityTier,
    DataClassification,
    TraversalDirection,
    InterventionAction,
    canonicalize_node_id,
    VALID_RELATIONSHIP_ENDPOINTS,
)


# =====================================================================
# 1. TYPED ENTERPRISE GRAPH NODES
# =====================================================================

class UserNode(BaseModel):
    """Corporate employee or service account identity."""
    id: str = Field(description="Canonical node ID e.g. user:alice@corp.com or user:usr-101")
    user_id: str = Field(description="Native identifier e.g. USR-101 or alice@corp.com")
    email: str = Field(description="Corporate email address")
    name: str = Field(description="Full name of user")
    department: str = Field(default="Unassigned", description="Corporate department")
    role: str = Field(default="Standard User", description="Assigned role or title")
    is_service_account: bool = Field(default=False, description="Whether account is a non-human service principal")
    is_admin: bool = Field(default=False, description="Whether user holds administrative privileges")
    status: str = Field(default="ACTIVE", description="Account status: ACTIVE, SUSPENDED, DECOMMISSIONED")
    data: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary directory metadata")

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str, info) -> str:
        return canonicalize_node_id(NodeLabel.USER, v)


class DeviceNode(BaseModel):
    """Physical or virtual workstation/endpoint."""
    id: str = Field(description="Canonical node ID e.g. device:dev-ws-109")
    device_id: str = Field(description="Asset tag or device hostname e.g. DEV-WS-109")
    hostname: str = Field(description="DNS or NetBIOS hostname")
    ip_address: str = Field(description="Current primary assigned IP address")
    mac_address: Optional[str] = Field(default=None, description="Hardware MAC address")
    os: str = Field(default="Windows 11 Enterprise", description="Operating system release")
    subnet: Optional[str] = Field(default=None, description="Network subnet CIDR e.g. 10.0.1.0/24")
    is_isolated: bool = Field(default=False, description="Whether endpoint has been isolated at EDR/network tier")
    criticality: CriticalityTier = Field(default=CriticalityTier.LOW, description="Asset criticality tier")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.DEVICE, v)


class ServerNode(BaseModel):
    """Core infrastructure server or virtualization host."""
    id: str = Field(description="Canonical node ID e.g. server:srv-app-01")
    server_id: str = Field(description="Infrastructure server ID e.g. SRV-APP-01")
    name: str = Field(description="Display server name")
    hostname: str = Field(description="FQDN or internal hostname")
    ip_address: str = Field(description="Static network IP address")
    tier: str = Field(default="Application", description="Architectural tier: Web, Application, Database, Core, DMZ")
    environment: str = Field(default="Production", description="Deployment environment: Production, Staging, Dev")
    criticality: CriticalityTier = Field(default=CriticalityTier.HIGH, description="Asset criticality tier")
    is_isolated: bool = Field(default=False, description="Whether server is network-isolated")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.SERVER, v)


class ApplicationNode(BaseModel):
    """Internal enterprise application or microservice."""
    id: str = Field(description="Canonical node ID e.g. app:payment-gateway")
    app_id: str = Field(description="Application key e.g. APP-PAY-01")
    name: str = Field(description="Application title")
    version: Optional[str] = Field(default="1.0.0", description="Software version")
    port: Optional[int] = Field(default=None, description="Standard listening TCP/UDP port")
    service_type: str = Field(default="API", description="Service category: Web, API, Batch, DB, Auth")
    environment: str = Field(default="Production", description="Deployment environment")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.APPLICATION, v)


class IpAddressNode(BaseModel):
    """Observed network IP entity."""
    id: str = Field(description="Canonical node ID e.g. ip:10.0.1.15")
    ip: str = Field(description="Valid IPv4 or IPv6 string")
    version: int = Field(default=4, description="IP protocol version (4 or 6)")
    scope: str = Field(default="internal", description="Scope: internal, public, loopback, reserved")
    subnet: Optional[str] = Field(default=None, description="Subnet CIDR")
    is_monitored: bool = Field(default=True, description="Whether traffic is monitored by IDS/firewall")

    @field_validator("ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        ip_str = v.strip()
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {ip_str}")
        return ip_str

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.IP_ADDRESS, v)


class VulnerabilityNode(BaseModel):
    """CVE or software security vulnerability."""
    id: str = Field(description="Canonical node ID e.g. vuln:CVE-2024-21413")
    cve_id: str = Field(description="Standard Common Vulnerabilities and Exposures identifier e.g. CVE-2024-21413")
    cvss_score: float = Field(ge=0.0, le=10.0, description="Common Vulnerability Scoring System score (0.0 to 10.0)")
    severity: CriticalityTier = Field(description="Severity tier: LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(default="", description="Summary of vulnerability and exploit mechanism")
    exploit_available: bool = Field(default=False, description="Whether a public weaponized exploit exists in wild")
    patch_available: bool = Field(default=True, description="Whether a vendor mitigation or patch exists")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_format(cls, v: str) -> str:
        norm = v.strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", norm):
            raise ValueError(f"Invalid CVE identifier format: '{v}'. Must match 'CVE-YYYY-NNNN...'")
        return norm

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.VULNERABILITY, v)


class CriticalAssetNode(BaseModel):
    """High-value Crown Jewel asset (e.g. Domain Controller, Customer PII DB, SWIFT gateway)."""
    id: str = Field(description="Canonical node ID e.g. critical:crit-db-01")
    asset_id: str = Field(description="High-value asset key e.g. CRIT-DB-01")
    name: str = Field(description="Asset title e.g. Customer Core PII Database")
    category: str = Field(
        description="Category: CUSTOMER_PII, FINANCIAL_RECORDS, DOMAIN_CONTROLLER, SOURCE_CODE, CREDENTIAL_STORE, INTELLECTUAL_PROPERTY"
    )
    impact_score: int = Field(ge=1, le=100, description="Business impact assessment score (1-100)")
    data_classification: DataClassification = Field(default=DataClassification.CONFIDENTIAL)
    owner_department: str = Field(default="IT Infrastructure", description="Responsible organization unit")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.CRITICAL_ASSET, v)


class SecurityEventNode(BaseModel):
    """Audit reference or security alert node linking evidence to the graph."""
    id: str = Field(description="Canonical node ID e.g. event:evt-8821")
    event_id: str = Field(description="Event identifier")
    event_type: str = Field(description="Event classification: PHISHING_INCIDENT, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT")
    severity: CriticalityTier = Field(default=CriticalityTier.HIGH)
    timestamp: str = Field(description="ISO 8601 incident timestamp")
    case_id: Optional[str] = Field(default=None, description="Associated ThreatLens investigation case ID (e.g. MT-101)")
    provenance: str = Field(default="ThreatLens Forensic Pipeline")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.SECURITY_EVENT, v)


class EmailAccountNode(BaseModel):
    """Email identity/mailbox mapped to organizational users or external correspondents."""
    id: str = Field(description="Canonical node ID e.g. email:alice@corp.com")
    email_address: str = Field(description="RFC 5322 formatted email address")
    account_name: Optional[str] = Field(default=None, description="Display name or mailbox owner")
    domain: Optional[str] = Field(default=None, description="Email domain e.g. corp.com")
    mailbox_type: str = Field(default="USER", description="USER, SHARED, DISTRIBUTION_LIST, SERVICE")
    is_internal: bool = Field(default=True, description="Whether domain is internally managed")
    is_compromised: bool = Field(default=False, description="Whether mailbox is flagged in an active security case")
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("email_address")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
            raise ValueError(f"Invalid email address format: '{v}'")
        return clean

    @field_validator("id", mode="before")
    @classmethod
    def set_canonical_id(cls, v: str) -> str:
        return canonicalize_node_id(NodeLabel.EMAIL_ACCOUNT, v)

    @model_validator(mode="after")
    def populate_domain_if_missing(self):
        if not self.domain and "@" in self.email_address:
            self.domain = self.email_address.split("@", 1)[1]
        return self


class EnterpriseNode(BaseModel):
    """Generic/polymorphic container for any organizational security graph node."""
    id: str = Field(description="Canonical node identifier")
    label: NodeLabel = Field(description="Primary node label")
    name: str = Field(description="Human readable display name")
    criticality: Optional[CriticalityTier] = Field(default=None, description="Criticality rating if applicable")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Typed attributes specific to node category")


# =====================================================================
# 2. TYPED ENTERPRISE GRAPH RELATIONSHIPS
# =====================================================================

class EnterpriseRelationship(BaseModel):
    """
    Typed relationship between two nodes in the security graph.
    Retains explicit provenance, timestamp, evidence classification, and confidence.
    """
    id: Optional[str] = Field(default=None, description="Unique relationship ID e.g. edge-user:1->device:1:USES")
    source_id: str = Field(description="Canonical ID of source node")
    target_id: str = Field(description="Canonical ID of target node")
    relationship_type: RelationshipType = Field(description="Typed relationship kind")
    evidence_class: EvidenceClass = Field(
        default=EvidenceClass.OBSERVED,
        description="Epistemological certainty: OBSERVED, AUTHORIZED_ACCESS, INFERRED, HYPOTHETICAL"
    )
    source_record_id: Optional[str] = Field(
        default=None,
        description="ID of source log, scan record, or directory object supporting this relationship"
    )
    provenance: str = Field(
        default="System Inventory",
        description="Reporting sensor/system (e.g. ActiveDirectory, NetFlow_Sensor_01, Qualys_Scanner, EML_Relay)"
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp when relationship was observed or configured"
    )
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Confidence score for this relationship (1.0 for verified direct observations)"
    )
    traversal_cost: Optional[float] = Field(
        default=None,
        description="Non-negative finite traversal cost (difficulty/friction) for shortest-path analysis. Lower cost indicates easier traversal/exploitation."
    )
    properties: Dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata payload (e.g. port, protocol, auth_type, privilege_level)"
    )

    @field_validator("traversal_cost")
    @classmethod
    def validate_traversal_cost(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if not isinstance(v, (int, float)):
                raise ValueError("traversal_cost must be a numeric value")
            if math.isnan(v) or math.isinf(v):
                raise ValueError("traversal_cost must be a finite number")
            if v < 0.0:
                raise ValueError(f"traversal_cost must be non-negative (>= 0.0), got {v}")
            return float(v)
        return None

    @model_validator(mode="after")
    def compute_edge_id_and_validate(self):
        # Auto-compute deterministic edge ID if missing
        if not self.id:
            self.id = f"{self.source_id}->{self.target_id}:{self.relationship_type.value}"
        return self


# =====================================================================
# 3. INGESTION DATA CONTRACTS
# =====================================================================

class EntityIngestRequest(BaseModel):
    """Batch ingestion payload for nodes."""
    dataset_name: str = Field(default="enterprise_inventory", description="Label for imported data source")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Batch ingestion ISO timestamp"
    )
    users: List[UserNode] = Field(default_factory=list)
    devices: List[DeviceNode] = Field(default_factory=list)
    servers: List[ServerNode] = Field(default_factory=list)
    applications: List[ApplicationNode] = Field(default_factory=list)
    ips: List[IpAddressNode] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityNode] = Field(default_factory=list)
    critical_assets: List[CriticalAssetNode] = Field(default_factory=list)
    security_events: List[SecurityEventNode] = Field(default_factory=list)
    email_accounts: List[EmailAccountNode] = Field(default_factory=list)


class RelationshipIngestRequest(BaseModel):
    """Batch ingestion payload for relationships."""
    dataset_name: str = Field(default="enterprise_topology", description="Dataset identifier")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Batch ingestion ISO timestamp"
    )
    relationships: List[EnterpriseRelationship] = Field(default_factory=list)


class BulkIngestPayload(BaseModel):
    """Combined atomic ingestion bundle containing both entities and relationships."""
    dataset_name: str = Field(default="synthetic_soc_environment", description="Logical environment name")
    entities: EntityIngestRequest = Field(default_factory=EntityIngestRequest)
    relationships: RelationshipIngestRequest = Field(default_factory=RelationshipIngestRequest)


class IngestSummaryResponse(BaseModel):
    """Standard audit response returned after ingestion execution."""
    status: str = Field(default="SUCCESS", description="SUCCESS, PARTIAL, or FAILED")
    dataset_name: str
    nodes_imported: int = Field(default=0, description="Total nodes newly created")
    nodes_updated: int = Field(default=0, description="Total nodes updated via idempotent MERGE")
    nodes_rejected: int = Field(default=0, description="Nodes failing schema validation")
    relationships_imported: int = Field(default=0, description="Total relationships newly created")
    relationships_updated: int = Field(default=0, description="Relationships updated")
    relationships_rejected: int = Field(default=0, description="Relationships failing endpoint validation")
    errors: List[str] = Field(default_factory=list, description="Descriptive validation or conflict errors")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @computed_field
    @property
    def nodes_created_or_updated(self) -> int:
        return self.nodes_imported + self.nodes_updated

    @computed_field
    @property
    def relationships_created_or_updated(self) -> int:
        return self.relationships_imported + self.relationships_updated


# =====================================================================
# 4. GRAPH & ASSET QUERY CONTRACTS
# =====================================================================

class EntityQueryFilter(BaseModel):
    """Filter parameters for querying entities in the graph."""
    label: Optional[NodeLabel] = None
    criticality: Optional[CriticalityTier] = None
    department: Optional[str] = None
    subnet: Optional[str] = None
    query: Optional[str] = Field(default=None, description="Free-text search substring on name, IP, or ID")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class EntityListResponse(BaseModel):
    """Paginated list of matching enterprise nodes."""
    total_count: int
    returned_count: int
    offset: int
    limit: int
    items: List[EnterpriseNode]


class EntityDetailResponse(BaseModel):
    """Comprehensive single entity view including 1-hop inbound and outbound connections."""
    entity: EnterpriseNode
    inbound_relationships: List[EnterpriseRelationship] = Field(default_factory=list)
    outbound_relationships: List[EnterpriseRelationship] = Field(default_factory=list)
    connected_nodes: List[EnterpriseNode] = Field(default_factory=list)


# =====================================================================
# 5. BLAST-RADIUS ANALYTICS CONTRACTS
# =====================================================================

class BlastRadiusRequest(BaseModel):
    """Input parameters for blast-radius calculation."""
    start_node_id: str = Field(
        description="Canonical ID of compromised or initial entity (e.g. user:alice@corp.com or device:dev-ws-109)"
    )
    max_hops: int = Field(default=3, ge=1, le=3, description="Maximum neighborhood search depth (1, 2, or 3 hops)")
    direction: TraversalDirection = Field(
        default=TraversalDirection.OUTGOING,
        description="Graph traversal direction: OUTGOING, INCOMING, or BOTH"
    )
    allowed_relationship_types: Optional[List[RelationshipType]] = Field(
        default=None,
        description="Optional filter limiting traversable relationship types"
    )
    include_hypothetical: bool = Field(
        default=False,
        description="If True, includes hypothetical exploit/pivot edges in calculation"
    )


class BlastRadiusHopGroup(BaseModel):
    """Distinct set of nodes reached at a specific hop depth without double-counting."""
    hop_number: int = Field(ge=1, le=3, description="Distance from start node (1, 2, or 3)")
    node_count: int = Field(default=0, description="Distinct node count at this hop depth")
    nodes: List[EnterpriseNode] = Field(default_factory=list, description="Entities reached at this exact depth")
    critical_asset_count: int = Field(default=0, description="Count of Crown Jewels exposed at this hop")


class CriticalAssetExposure(BaseModel):
    """Identification and shortest path context for an exposed Crown Jewel asset."""
    asset_id: str = Field(description="Canonical ID of critical asset")
    name: str = Field(description="Name of critical asset")
    category: str = Field(description="Category of critical asset")
    impact_score: int = Field(description="Impact severity rating")
    hop_depth: int = Field(description="Shortest distance from initial compromise node")
    shortest_path_nodes: List[str] = Field(description="Ordered sequence of node IDs along shortest path")
    reachability_status: str = Field(default="EXPOSED", description="EXPOSED or MITIGATED")


class BlastRadiusResult(BaseModel):
    """Master output contract for Blast-Radius analysis."""
    start_node: EnterpriseNode = Field(description="Root entity evaluated as compromised")
    max_hops_evaluated: int
    direction: TraversalDirection
    hop_1: BlastRadiusHopGroup
    hop_2: BlastRadiusHopGroup
    hop_3: BlastRadiusHopGroup
    total_reachable_nodes: int = Field(description="Total distinct nodes across all hops (excluding start node)")
    critical_assets_at_risk: List[CriticalAssetExposure] = Field(
        default_factory=list,
        description="Crown Jewels reachable within configured depth"
    )
    subgraph_nodes: List[EnterpriseNode] = Field(default_factory=list, description="All nodes for Cytoscape rendering")
    subgraph_edges: List[EnterpriseRelationship] = Field(default_factory=list, description="All edges in blast subgraph")
    summary_assessment: str = Field(description="Human-readable summary of exposure severity and critical findings")
    calculation_time_ms: Optional[float] = Field(default=None, description="Execution time in milliseconds")
    warnings: List[str] = Field(default_factory=list, description="Warnings about bounded traversal limits or assumptions")


# =====================================================================
# 6. ATTACK-PATH DISCOVERY CONTRACTS
# =====================================================================

class AttackPathRequest(BaseModel):
    """Input parameters for candidate attack-path discovery."""
    entry_node_id: str = Field(description="Entry point entity ID e.g. device:dev-ws-109")
    target_node_ids: Optional[List[str]] = Field(
        default=None,
        description="Target critical asset IDs. If omitted, evaluates paths to all Crown Jewels."
    )
    max_depth: int = Field(default=5, ge=1, le=8, description="Maximum path length traversal limit")
    include_hypothetical: bool = Field(
        default=True,
        description="Whether to evaluate hypothetical pivot paths (e.g. unpatched CVE pivots)"
    )
    relationship_types: Optional[List[RelationshipType]] = Field(
        default=None,
        description="Constrain traversal to specified relationship types"
    )


class AttackPathStep(BaseModel):
    """Single transition along an attack path."""
    step_number: int
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    evidence_class: EvidenceClass
    provenance: str
    description: str


class AttackPathItem(BaseModel):
    """Single discovered attack path from entry to critical asset."""
    path_id: str = Field(description="Deterministic path identifier e.g. PATH-001")
    target_id: str = Field(description="Destination critical asset ID")
    target_name: str = Field(description="Destination critical asset display name")
    length: int = Field(description="Total hop count from entry to target")
    risk_score: int = Field(ge=0, le=100, description="Calculated composite risk score along this vector")
    nodes: List[EnterpriseNode] = Field(description="Ordered sequence of nodes along the path")
    steps: List[AttackPathStep] = Field(description="Detailed relationship steps along the path")
    observed_steps_count: int = Field(default=0, description="Steps backed by real observed telemetry")
    hypothetical_steps_count: int = Field(default=0, description="Steps requiring hypothetical attacker exploitation")
    assumptions: List[str] = Field(
        default_factory=list,
        description="Explicit technical assumptions required for attacker to traverse this path"
    )


class AttackPathResult(BaseModel):
    """Master response contract for Attack-Path discovery."""
    entry_node: EnterpriseNode
    total_paths_discovered: int
    paths: List[AttackPathItem]
    targets_reached: List[str]
    methodology_note: str = Field(
        default="Candidate paths discovered via directed traversal. "
                "Paths containing HYPOTHETICAL steps represent potential vectors, not proof of attacker movement."
    )
    calculation_time_ms: Optional[float] = Field(default=None, description="Execution time in milliseconds")
    warnings: List[str] = Field(default_factory=list, description="Explicit limits and assumptions of the path search")


# =====================================================================
# 6.5 DIJKSTRA WEIGHTED SHORTEST-PATH CONTRACTS
# =====================================================================

class DijkstraEdgeCost(BaseModel):
    """Detailed cost breakdown and evidence for a single edge traversed in Dijkstra shortest path."""
    step_number: int
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    evidence_class: EvidenceClass
    cost: float = Field(ge=0.0, description="Non-negative traversal cost of this specific hop")
    accumulated_cost: float = Field(ge=0.0, description="Running total cost from entry point to this hop")
    provenance: str = Field(default="System Topology")
    description: str = Field(default="")
    rationale: str = Field(default="")

    @property
    def step_cost(self) -> float:
        return self.cost


class DijkstraShortestPathRequest(BaseModel):
    """Input parameters for Dijkstra weighted shortest-path analysis."""
    entry_node_id: str = Field(
        description="Canonical ID or alias of starting node (e.g. device:dev-ws-101 or user:victim1@corporation.com)"
    )
    target_node_id: Optional[str] = Field(
        default=None,
        description="Specific target CriticalAsset ID (e.g. critical:crit-db-financial)"
    )
    target_node_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional target set of CriticalAsset IDs; if omitted and target_node_id is omitted, evaluates across all Crown Jewels"
    )
    allowed_relationship_types: Optional[List[RelationshipType]] = Field(
        default=None,
        description="Constrain traversal to specified relationship types"
    )
    include_hypothetical: bool = Field(
        default=True,
        description="Whether to permit hypothetical exploit vectors (e.g. unpatched vulnerabilities)"
    )
    max_cost: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Optional maximum cumulative cost ceiling"
    )


class DijkstraShortestPathResult(BaseModel):
    """Output result of Dijkstra weighted shortest-path analysis."""
    entry_node: EnterpriseNode
    target_node: Optional[EnterpriseNode] = None
    path_found: bool = Field(description="Whether a valid candidate route was found to any designated target")
    total_cost: Optional[float] = Field(default=None, description="Minimum accumulated traversal cost")
    hop_count: int = Field(default=0, description="Number of edges in the shortest path")
    nodes: List[EnterpriseNode] = Field(default_factory=list, description="Ordered sequence of nodes along the minimum-cost route")
    steps: List[DijkstraEdgeCost] = Field(default_factory=list, description="Per-edge cost and evidence breakdown")
    reachable_targets: List[str] = Field(default_factory=list, description="Target IDs reached by search")
    unreachable_targets: List[str] = Field(default_factory=list, description="Target IDs evaluated but unreachable")
    cost_model_description: str = Field(
        default="Deterministic non-negative traversal friction model where lower cost reflects lower attacker resistance/difficulty."
    )
    calculation_time_ms: float = Field(default=0.0, description="Execution time in milliseconds")
    warnings: List[str] = Field(default_factory=list, description="Search bounds, assumptions, or missing weight notices")


# =====================================================================
# 7. CHOKE-POINT ANALYSIS CONTRACTS
# =====================================================================

class ChokePointRequest(BaseModel):
    """Parameters for choke-point calculation."""
    analyzed_path_ids: Optional[List[str]] = Field(
        default=None,
        description="Specific path IDs to evaluate; if omitted, calculates across all active attack paths"
    )
    top_n: int = Field(default=5, ge=1, le=20, description="Number of top ranked choke points to return")


class ChokePointItem(BaseModel):
    """Intervention recommendation for an identified graph choke point."""
    rank: int = Field(description="Intervention priority rank (1 = highest impact)")
    entity_id: str = Field(description="Canonical ID of node or relationship acting as choke point")
    entity_label: str = Field(description="Display label of choke-point entity")
    entity_type: str = Field(description="Node or Edge category")
    paths_traversed_count: int = Field(description="Total candidate attack paths traversing this entity")
    traversal_percentage: float = Field(
        description="Percentage of all evaluated paths eliminated if this choke point is severed"
    )
    affected_critical_assets: List[str] = Field(description="Crown Jewels protected by this single intervention")
    recommended_action: InterventionAction = Field(description="Recommended containment action")
    intervention_details: str = Field(description="Actionable SOC containment instructions")


class ChokePointResult(BaseModel):
    """Master response contract for Choke-Point analysis."""
    total_paths_analyzed: int
    choke_points: List[ChokePointItem]
    top_recommendation: Optional[ChokePointItem] = None
    explanation: str = Field(description="Methodological explanation of betweenness calculation and path reduction")


# =====================================================================
# 8. WHAT-IF CONTAINMENT SIMULATION CONTRACTS
# =====================================================================

class ProposedIntervention(BaseModel):
    """Single proposed containment action to simulate in memory."""
    action: InterventionAction = Field(description="Type of intervention")
    node_id: Optional[str] = Field(
        default=None,
        description="Node canonical ID (required for ISOLATE_NODE, DISABLE_ACCOUNT, PATCH_VULNERABILITY)"
    )
    source_id: Optional[str] = Field(
        default=None,
        description="Source node ID (required for REVOKE_PERMISSION or BLOCK_CONNECTION)"
    )
    target_id: Optional[str] = Field(
        default=None,
        description="Target node ID (required for REVOKE_PERMISSION or BLOCK_CONNECTION)"
    )
    relationship_type: Optional[RelationshipType] = None
    rationale: str = Field(default="SOC proactive blast-radius containment")


class ContainmentSimulationRequest(BaseModel):
    """Request payload to simulate one or more containment actions without modifying live graph."""
    entry_node_id: str = Field(description="Starting compromise node ID")
    target_asset_ids: Optional[List[str]] = Field(default=None, description="Crown Jewels to evaluate")
    proposed_interventions: List[ProposedIntervention] = Field(
        min_length=1,
        description="List of proposed revocations or isolations to test"
    )


class SimulatedPathStatus(BaseModel):
    """Status of an attack path under simulation."""
    path_id: str
    target_id: str
    status: str = Field(description="ELIMINATED or ACTIVE")
    severed_at_step: Optional[str] = Field(
        default=None,
        description="Explanation of exact node or relationship severed by simulation"
    )


class ContainmentSimulationResult(BaseModel):
    """Master response contract for What-If containment simulation."""
    simulation_id: str = Field(description="Unique simulation execution identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    live_graph_modified: bool = Field(
        default=False,
        description="Strict safety guarantee: Live database was NOT modified during this simulation."
    )
    proposed_interventions: List[ProposedIntervention]
    baseline_paths_count: int = Field(description="Number of attack paths before intervention")
    remaining_paths_count: int = Field(description="Number of attack paths surviving proposed intervention")
    paths_eliminated_count: int = Field(description="Number of attack paths successfully severed")
    containment_efficiency_pct: float = Field(
        description="Percentage of risky paths eliminated (0.0 to 100.0%)"
    )
    path_statuses: List[SimulatedPathStatus] = Field(description="Per-path breakdown of containment outcome")
    residual_exposed_assets: List[str] = Field(
        default_factory=list,
        description="Critical assets that remain reachable via alternative unmitigated vectors"
    )
    analyst_verdict: str = Field(description="Executive assessment of intervention effectiveness")
    safety_disclaimer: str = Field(
        default="SIMULATION ONLY: No actual permissions were revoked, no devices were disconnected, "
                "and no live infrastructure was modified."
    )


# =====================================================================
# 9. CASE-TO-ORGANIZATION BRIDGE CONTRACTS
# =====================================================================

class CaseBridgeRequest(BaseModel):
    """Request to resolve an email investigation case to the organizational security graph."""
    case_id: str = Field(description="ThreatLens case identifier e.g. MT-101")


class BridgeMappingItem(BaseModel):
    """Single verified entity linkage between email evidence and organizational graph."""
    evidence_type: str = Field(description="RECIPIENT_EMAIL, SENDER_ACCOUNT, INTERNAL_RELAY_IP, INTERNAL_DOMAIN")
    raw_value: str = Field(description="Observed value from email case")
    mapped_node_id: str = Field(description="Resolved canonical ID in enterprise graph")
    node_label: NodeLabel = Field(description="Label of mapped enterprise node")
    match_confidence: float = Field(description="Resolution confidence score (1.0 for exact key match)")
    match_rationale: str = Field(description="Evidence supporting this organizational connection")


class CaseBridgeResponse(BaseModel):
    """Results of bridging an email case into the enterprise graph."""
    case_id: str
    primary_compromised_node: Optional[EnterpriseNode] = Field(
        default=None,
        description="Best candidate entry-point node for blast-radius calculation"
    )
    mapped_entities: List[BridgeMappingItem] = Field(default_factory=list)
    unmapped_external_iocs: List[str] = Field(
        default_factory=list,
        description="External threat IOCs (e.g. C2 IP, attacker domain) correctly NOT mapped as corporate assets"
    )
    recommended_blast_radius_url: Optional[str] = Field(
        default=None,
        description="Direct API link to run blast-radius from the primary compromised node"
    )
    investigation_disclaimer: str = Field(
        default="RECEIPT IS NOT COMPROMISE: Delivery or receipt of a suspicious email indicates exposure. "
                "The recipient user and assigned device represent candidate starting points for blast-radius analysis, "
                "not confirmed compromised infrastructure.",
        description="Explicit SOC caveat distinguishing email exposure from host exploitation"
    )


# =====================================================================
# 10. GRAPH ACCESS ANOMALY DETECTION CONTRACTS (PHASE 9)
# =====================================================================

class AnomalyClassification(str, Enum):
    """
    4-Tier Classification Matrix for Access Sequence Behavior.
    Strictly distinguishes unobserved legitimate behavior from unauthorized policy violations
    and confirmed malicious activity.
    """
    BENIGN_EXPECTED = "BENIGN_EXPECTED"                       # Known historical or authorized baseline
    UNOBSERVED_NEW_LEGITIMATE = "UNOBSERVED_NEW_LEGITIMATE"   # Novel activity conforming to policy & role
    POLICY_VIOLATION_UNAUTHORIZED = "POLICY_VIOLATION_UNAUTHORIZED" # Violates policy/tier, no exploit indicators
    SUSPICIOUS_ANOMALOUS = "SUSPICIOUS_ANOMALOUS"             # High-risk anomaly, exploit, or compromised pivot


class DeviationType(str, Enum):
    """Specific technical category of baseline deviation."""
    TIER_BYPASS = "TIER_BYPASS"                       # Workstation-to-database or workstation-to-DC bypass
    MISSING_AUTHORIZATION = "MISSING_AUTHORIZATION"   # No HAS_PERMISSION grant for target resource
    DEPARTMENT_MISMATCH = "DEPARTMENT_MISMATCH"       # User department conflicts with target resource role
    EXPLOIT_PRECONDITION = "EXPLOIT_PRECONDITION"     # Traversal through known vulnerability or exploit edge
    UNOBSERVED_RELATIONSHIP = "UNOBSERVED_RELATIONSHIP" # Edge not previously present in baseline graph
    HIGH_RISK_PIVOT = "HIGH_RISK_PIVOT"               # Lateral hop originating from compromised entity


class HistoryCompleteness(str, Enum):
    """Assessment of prior activity history for cold-start determination."""
    COMPLETE = "COMPLETE"       # Rich longitudinal baseline available
    PARTIAL = "PARTIAL"         # Limited historical connections observed
    INCOMPLETE = "INCOMPLETE"   # New user, newly provisioned asset, or cold start


class BaselineConfidence(str, Enum):
    """Confidence level of the baseline profile used for evaluation."""
    HIGH = "HIGH"       # Direct individual historical profile with high confidence
    MEDIUM = "MEDIUM"   # Department or peer-group proxy baseline
    LOW = "LOW"         # Sparse data / cold start; conservative thresholds applied


class AccessSequenceStep(BaseModel):
    """Single ordered traversal step or observed relationship in an access sequence."""
    step_index: int = Field(ge=0, description="0-indexed position in sequence")
    source_id: str = Field(description="Canonical source node ID")
    relationship_type: RelationshipType = Field(description="Typed relationship traversed")
    target_id: str = Field(description="Canonical target node ID")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp of event")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as port, protocol, or privilege")


class AccessSequenceRequest(BaseModel):
    """Request payload to evaluate an access sequence for graph-based anomalies."""
    sequence_id: str = Field(default_factory=lambda: f"seq-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    evaluated_entity_id: str = Field(description="Primary user, device, or identity initiating the sequence")
    steps: List[AccessSequenceStep] = Field(description="Ordered list of relationships traversed")
    include_explanations: bool = Field(default=True, description="Whether to include detailed step explanations")
    client_context: Dict[str, Any] = Field(default_factory=dict, description="Client environment or case reference")


class UnexpectedRelationship(BaseModel):
    """Explicit finding describing why a particular relationship in the sequence is anomalous."""
    finding_id: Optional[str] = Field(
        default=None,
        description="Unique identifier for this anomaly finding e.g. ANOM-RULE-01"
    )
    rule_id: Optional[str] = Field(
        default=None,
        description="Deterministic policy rule identifier e.g. RULE-TIER-01"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Finding severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    )
    affected_entity: Optional[str] = Field(
        default=None,
        description="Identifier of primary affected corporate entity"
    )
    step_index: int = Field(ge=0)
    source_id: str
    relationship_type: RelationshipType
    target_id: str
    deviation_type: DeviationType
    baseline_reference: str = Field(description="Documented rule, policy, or historical baseline referenced")
    explanation: str = Field(description="Human-readable rationale explaining why this step is unexpected")
    detection_rationale: Optional[str] = Field(
        default=None,
        description="Detailed technical rationale explaining rule trigger conditions"
    )
    recommended_investigation: Optional[str] = Field(
        default=None,
        description="Actionable next steps for security operations analyst"
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO 8601 timestamp when anomaly was evaluated"
    )
    supporting_event_sequence: Optional[str] = Field(
        default=None,
        description="Sequence identifier or step transition context"
    )
    relevant_graph_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Graph metadata (labels, department, role, tier) for source and target"
    )
    step_score: int = Field(ge=0, le=100, description="Step anomaly score contribution")


class AccessSequenceAnomalyResult(BaseModel):
    """Complete diagnostic report from graph access anomaly evaluation."""
    sequence_id: str
    evaluated_entity_id: str
    classification: AnomalyClassification
    anomaly_score: int = Field(ge=0, le=100, description="Overall sequence anomaly score (0-100)")
    baseline_confidence: BaselineConfidence
    history_completeness: HistoryCompleteness
    is_anomalous: bool = Field(description="True if score >= 40 (Policy Violation or Suspicious)")
    unexpected_relationships: List[UnexpectedRelationship] = Field(default_factory=list)
    summary_explanation: str = Field(description="Executive summary of sequence evaluation")
    recommended_investigation_actions: List[str] = Field(default_factory=list)
    safety_disclaimer: str = Field(
        default="ADVISORY ONLY: Anomaly findings are diagnostic indicators and do NOT execute automated "
                "blocking or modify graph data."
    )


class BaselineProfileSummary(BaseModel):
    """Documented baseline rules and profile summary."""
    total_baseline_entities: int
    total_baseline_relationships: int
    network_tiering_rules: List[str]
    department_profiles: Dict[str, List[str]]
    authorized_service_accounts: List[str]
    scoring_formula: str


class AnomalyTestSuiteItem(BaseModel):
    """Evaluation result for a single labeled test sequence."""
    sequence_id: str
    description: str
    ground_truth_label: AnomalyClassification
    predicted_label: AnomalyClassification
    anomaly_score: int
    is_match: bool
    unexpected_count: int


class AnomalyTestSuiteResult(BaseModel):
    """Held-out test set evaluation metrics report."""
    total_evaluated: int
    total_correct: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    confusion_matrix: Dict[str, int]
    results: List[AnomalyTestSuiteItem]


# =====================================================================
# 10. KAFKA EVENT STREAMING & FINDINGS CONTRACTS
# =====================================================================

class SecurityEventType(str, Enum):
    """Categorization of supported streaming security event types."""
    ENDPOINT_ALERT = "ENDPOINT_ALERT"
    IDENTITY_EVENT = "IDENTITY_EVENT"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    PROCESS_EVENT = "PROCESS_EVENT"
    COMPROMISE_INDICATOR = "COMPROMISE_INDICATOR"
    EMAIL_INVESTIGATION_RESULT = "EMAIL_INVESTIGATION_RESULT"


class SecurityEventEnvelope(BaseModel):
    """Canonical security event envelope for Apache Kafka ingestion."""
    event_id: str = Field(description="Unique stable event identifier (UUID or hash)")
    schema_version: str = Field(default="1.0.0", description="Event contract version")
    event_type: SecurityEventType = Field(description="Domain category of the security event")
    source: str = Field(description="Originating telemetry producer or sensor")
    occurred_at: str = Field(description="ISO8601 UTC timestamp of occurrence")
    ingested_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC timestamp of ingestion into ThreatLens"
    )
    entity_ids: List[str] = Field(
        min_length=1,
        description="List of primary and related enterprise entity identifiers"
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Validated event-specific telemetry attributes"
    )
    correlation_id: Optional[str] = Field(
        default=None,
        description="Optional case or investigation tracking ID"
    )
    severity: Optional[CriticalityTier] = Field(
        default=None,
        description="Normalized severity assessment"
    )
    evidence_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Provenance and source telemetry metadata"
    )


class DeadLetterEventEnvelope(BaseModel):
    """Dead-letter queue payload for failed or unprocessable security events."""
    event_id: Optional[str] = Field(default=None, description="Event ID if extractable")
    source_topic: str = Field(description="Kafka topic where event was received")
    partition: Optional[int] = Field(default=None, description="Kafka partition")
    offset: Optional[int] = Field(default=None, description="Kafka message offset")
    failure_category: str = Field(description="Error classification: PERMANENT_SCHEMA_ERROR, TRANSIENT_NEO4J_ERROR, etc.")
    sanitized_error: str = Field(description="Sanitized exception explanation without sensitive credentials")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    retry_count: int = Field(default=0, description="Total retry attempts executed before dead-lettering")
    raw_payload: Optional[Dict[str, Any]] = Field(default=None, description="Safely encoded event content")


class SecurityFindingRecord(BaseModel):
    """Normalized security finding produced by event-triggered GraphOps analytics."""
    finding_id: str = Field(description="Unique finding identifier")
    source_event_id: str = Field(description="Originating Kafka security event identifier")
    analysis_type: str = Field(
        description="Analytics engine: DIJKSTRA_SHORTEST_PATH, BFS_BLAST_RADIUS, ATTACK_PATH_DISCOVERY, CHOKE_POINT, ANOMALY_DETECTION"
    )
    affected_entity_id: str = Field(description="Primary compromised or anomalous entity canonical ID")
    critical_asset_impacted: Optional[str] = Field(
        default=None,
        description="Designated Crown Jewel exposed or targeted"
    )
    severity: CriticalityTier = Field(description="Normalized finding severity rating")
    title: str = Field(description="Concise finding headline")
    summary: str = Field(description="Actionable executive summary for SOC analysts")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured algorithmic output (hops, paths, costs, anomaly scores, steps)"
    )
    evidence_class: EvidenceClass = Field(
        default=EvidenceClass.OBSERVED,
        description="Epistemological certainty: OBSERVED, AUTHORIZED_ACCESS, INFERRED, HYPOTHETICAL"
    )
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EventPublishResponse(BaseModel):
    """Response returned when an event is accepted by the Kafka producer interface."""
    event_id: str
    status: str = Field(description="ACCEPTED_FOR_STREAMING or REJECTED")
    topic: str
    partition: Optional[int] = None
    offset: Optional[int] = None
    delivery_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    message: str = Field(default="Security event successfully published to streaming topic.")


class KafkaServiceStatus(BaseModel):
    """Operational health diagnostics for Kafka producer and consumer workers."""
    broker_connected: bool
    bootstrap_servers: str
    consumer_worker_running: bool
    active_consumer_group: str
    processed_events_count: int
    dead_letter_events_count: int
    findings_generated_count: int
    last_processed_timestamp: Optional[str] = None


# =====================================================================
# 11. SCIKIT-LEARN EVENT ANOMALY DETECTION CONTRACTS
# =====================================================================

class EventFeatureRecord(BaseModel):
    """Normalized feature vector extracted from a security event and graph context."""
    feature_schema_version: str = Field(default="1.0.0", description="Feature schema semantic version")
    event_id: str = Field(description="Unique event identifier")
    event_type: str = Field(description="Event domain category")
    source_entity_id: str = Field(description="Originating actor or device ID")
    target_entity_id: Optional[str] = Field(default=None, description="Target asset or resource ID")

    # Numerical features
    auth_failure_count: float = Field(default=0.0, ge=0.0, description="Recent failed logon attempts")
    distinct_destinations: float = Field(default=0.0, ge=0.0, description="Distinct target assets contacted in window")
    distinct_servers_contacted: float = Field(default=0.0, ge=0.0, description="Distinct server entities touched")
    outbound_bytes: float = Field(default=0.0, ge=0.0, description="Data volume transferred in bytes")
    traversal_cost: float = Field(default=1.0, ge=0.0, description="Relationship traversal friction cost")
    port: float = Field(default=443.0, ge=0.0, le=65535.0, description="Target destination port")
    historical_events_count: float = Field(default=0.0, ge=0.0, description="Historical observed events for entity")
    is_new_destination: float = Field(default=0.0, ge=0.0, le=1.0, description="1.0 if destination unobserved in baseline")
    asset_criticality_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Criticality rating: Low=10, Med=40, High=70, Crit=100")

    # Categorical features
    source_label: str = Field(default="DEVICE", description="NodeLabel of originating entity")
    target_label: str = Field(default="SERVER", description="NodeLabel of target entity")
    protocol: str = Field(default="TCP", description="Observed network/session protocol")

    # Contextual metadata
    historical_context_available: bool = Field(default=True, description="Whether historical baseline exists for entity")
    insufficient_context: bool = Field(default=False, description="True if essential telemetry fields are missing")
    extraction_warnings: List[str] = Field(default_factory=list, description="Warnings encountered during extraction")


class EventAnomalyPrediction(BaseModel):
    """Output contract produced by scikit-learn Isolation Forest model inference."""
    event_id: str = Field(description="Evaluated security event ID")
    is_anomaly: bool = Field(description="True if raw score is below configured threshold")
    anomaly_classification: str = Field(description="NORMAL, ANOMALY, or INSUFFICIENT_CONTEXT")
    raw_score: float = Field(description="Raw decision_function anomaly score from Isolation Forest")
    normalized_score: float = Field(description="Calibrated anomaly severity rating from 0.0 (normal) to 100.0 (extreme anomaly)")
    threshold: float = Field(description="Decision threshold used for classification")
    model_name: str = Field(default="IsolationForest", description="Machine learning algorithm name")
    model_version: str = Field(description="Trained model artifact semantic version")
    feature_schema_version: str = Field(default="1.0.0", description="Feature contract version")
    insufficient_context: bool = Field(default=False, description="True if inference was skipped due to cold start or missing fields")
    historical_context_status: str = Field(default="SUFFICIENT", description="SUFFICIENT, COLD_START_INSUFFICIENT, or UNKNOWN")
    rationale: str = Field(description="Interpretable narrative explanation of anomaly score")
    feature_vector: Dict[str, Any] = Field(default_factory=dict, description="Feature attributes supplied to model")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MLModelStatus(BaseModel):
    """Operational health and provenance metadata for the active scikit-learn model."""
    model_loaded: bool = Field(description="Whether a trained pipeline artifact is loaded in memory")
    model_name: str = Field(default="IsolationForest")
    model_version: str = Field(description="Active model semantic version")
    feature_schema_version: str = Field(default="1.0.0")
    model_path: str = Field(description="Filesystem path of persisted model artifact")
    contamination: float = Field(description="Expected outlier proportion parameter")
    threshold: float = Field(description="Active decision boundary threshold")
    training_timestamp: Optional[str] = None
    training_sample_count: Optional[int] = None
    evaluation_metrics: Optional[Dict[str, Any]] = None


class MLTrainResponse(BaseModel):
    """Response returned upon completing controlled model training."""
    status: str = Field(description="SUCCESS or FAILED")
    model_version: str
    training_samples: int
    validation_samples: int
    test_samples: int
    threshold: float
    metrics: Dict[str, Any] = Field(description="Precision, Recall, F1, FPR, Confusion Matrix")
    artifact_path: str
    message: str


# =====================================================================
# 12. PYTORCH GEOMETRIC (PYG) GRAPH LEARNING CONTRACTS
# =====================================================================

class GraphStructureAnomalyResult(BaseModel):
    """
    Structured outcome of PyTorch Geometric link-prediction inference,
    scoring the structural plausibility / anomaly of a candidate relationship.
    """
    model_name: str = Field(default="StructuralGraphSAGE", description="PyG neural network architecture")
    model_version: str = Field(default="1.0.0", description="Semantic model version")
    model_available: bool = Field(default=True, description="Whether PyG model was loaded and evaluated")
    prediction_type: str = Field(
        default="RELATIONSHIP_PLAUSIBILITY_ANOMALY",
        description="Graph-learning task: RELATIONSHIP_PLAUSIBILITY_ANOMALY or SUBGRAPH_ANOMALY"
    )
    is_anomaly: bool = Field(default=False, description="True if structural anomaly score exceeds decision threshold")
    structural_anomaly_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Bounded anomaly rating: 0.0 (highly expected) to 100.0 (structurally anomalous/unexpected)"
    )
    predicted_plausibility: float = Field(
        ge=0.0,
        le=1.0,
        description="Raw predicted link probability from GNN edge decoder (0.0 to 1.0)"
    )
    threshold: float = Field(default=60.0, description="Decision threshold applied")
    score_interpretation: str = Field(
        description="Interpretation category: EXPECTED_TOPOLOGY, ELEVATED_STRUCTURAL_RISK, UNUSUAL_ACCESS_PATH, or MODEL_UNAVAILABLE"
    )
    source_entity_id: str = Field(description="Canonical source node ID")
    target_entity_id: str = Field(description="Canonical target node ID")
    relationship_type: str = Field(description="Relationship label e.g. OBSERVED_CONNECTION, LOGGED_IN_TO")
    graph_snapshot_id: str = Field(default="live_snapshot", description="Snapshot ID or provenance marker")
    supporting_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Topological context: common neighbors, path distance, entity labels, node degrees"
    )
    reason_codes: List[str] = Field(
        default_factory=list,
        description="List of explainable structural factor codes"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit methodological limitations (e.g. static snapshot, unobserved historical period)"
    )
    scored_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of inference"
    )


class PyGEvaluateRequest(BaseModel):
    """Request payload to evaluate structural anomaly of a candidate relationship."""
    source_entity_id: str = Field(description="Originating node ID e.g. user:victim1@corporation.com or device:dev-ws-101")
    target_entity_id: str = Field(description="Target destination node ID e.g. server:srv-db-01")
    relationship_type: str = Field(default="OBSERVED_CONNECTION", description="Relationship type")
    traversal_cost: float = Field(default=1.0, ge=0.0, description="Friction / traversal cost")
    evidence_class: str = Field(default="OBSERVED", description="OBSERVED or AUTHORIZED_ACCESS")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Additional relationship properties")


class PyGModelStatus(BaseModel):
    """Operational health, configuration, and evaluation metadata for PyG graph model."""
    model_loaded: bool = Field(description="Whether PyG model weights are loaded and ready in memory")
    model_name: str = Field(default="StructuralGraphSAGE")
    model_version: str = Field(default="1.0.0")
    device: str = Field(default="cpu", description="Execution device: cpu or cuda")
    model_path: str = Field(description="Filesystem location of persisted .pt weights")
    meta_path: str = Field(description="Filesystem location of metadata JSON")
    num_nodes: int = Field(default=0, description="Number of nodes in the graph snapshot")
    num_edges: int = Field(default=0, description="Number of edges in the graph snapshot")
    embedding_dim: int = Field(default=64)
    hidden_dim: int = Field(default=64)
    threshold: float = Field(default=60.0)
    training_timestamp: Optional[str] = None
    evaluation_metrics: Optional[Dict[str, Any]] = None
    limitations: List[str] = Field(default_factory=list)


class PyGTrainResponse(BaseModel):
    """Response returned upon completing PyG model training and evaluation."""
    status: str = Field(description="SUCCESS or FAILED")
    model_version: str
    num_nodes: int
    num_edges: int
    train_edges: int
    val_edges: int
    test_edges: int
    threshold: float
    metrics: Dict[str, Any] = Field(description="ROC-AUC, Average Precision, F1, Precision, Recall, Confusion Matrix")
    artifact_path: str
    message: str


