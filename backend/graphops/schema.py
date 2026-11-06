"""
ThreatLens GraphOps - Schema & Canonical Metadata Definitions
Defines node labels, relationship types, evidence categories, canonical identifier rules,
and Cypher constraint definitions for the organizational security graph.
"""

from enum import Enum
from typing import Dict, Set, Tuple, Optional, Any


class NodeLabel(str, Enum):
    """Supported entity labels in the organizational security graph."""
    USER = "User"
    DEVICE = "Device"
    SERVER = "Server"
    APPLICATION = "Application"
    IP_ADDRESS = "IPAddress"
    VULNERABILITY = "Vulnerability"
    CRITICAL_ASSET = "CriticalAsset"
    SECURITY_EVENT = "SecurityEvent"
    EMAIL_ACCOUNT = "EmailAccount"


class EvidenceClass(str, Enum):
    """
    Categorizes the epistemological certainty of a graph element.
    Prevents confusing actual observed telemetry with authorized access or hypothetical attack paths.
    """
    OBSERVED = "OBSERVED"                 # Direct telemetry (NetFlow, Syslog, EDR, EML header)
    AUTHORIZED_ACCESS = "AUTHORIZED_ACCESS"  # Directory entitlement, IAM role, ACL grant
    INFERRED = "INFERRED"                 # Heuristic correlation, subnet proximity, resolution
    HYPOTHETICAL = "HYPOTHETICAL"         # Simulated attack path or exploit precondition


class RelationshipType(str, Enum):
    """Supported typed relationships in the organizational security graph."""
    USES = "USES"                                       # (User) -> (Device | EmailAccount)
    LOGGED_IN_TO = "LOGGED_IN_TO"                       # (User) -> (Server | Device)
    AUTHENTICATED_TO = "AUTHENTICATED_TO"               # (User | EmailAccount) -> (Server | Device | Application)
    CAN_REACH = "CAN_REACH"                             # (Device | Server | IPAddress) -> (Device | Server | IPAddress | CriticalAsset)
    CONNECTS_TO = "CONNECTS_TO"                         # (Device | Server | Application | IPAddress) -> (Device | Server | Application | IPAddress)
    OBSERVED_CONNECTION = "OBSERVED_CONNECTION"         # (Device | Server) -> (Device | Server | IPAddress)
    HAS_PERMISSION = "HAS_PERMISSION"                   # (User) -> (Server | CriticalAsset)
    HOSTS = "HOSTS"                                     # (Server) -> (Application | CriticalAsset)
    HOSTED_ON = "HOSTED_ON"                             # (Application | CriticalAsset) -> (Server | Device)
    RUNS_ON = "RUNS_ON"                                 # (Server | Application) -> (Device | Server)
    HAS_VULNERABILITY = "HAS_VULNERABILITY"             # (Device | Server | Application) -> (Vulnerability)
    CONTAINS_CRITICAL_DATA = "CONTAINS_CRITICAL_DATA"   # (Server | Application) -> (CriticalAsset)
    POTENTIAL_EXPLOIT = "POTENTIAL_EXPLOIT"             # (Device | Server) -> (Server)
    EXPLOITS = "EXPLOITS"                               # (Device | Server | SecurityEvent) -> (Vulnerability | Server | CriticalAsset | Application)
    MEMBER_OF = "MEMBER_OF"                             # (User | EmailAccount) -> (User | Application)
    OWNS = "OWNS"                                       # (User) -> (Device | Server | Application | EmailAccount | CriticalAsset)
    ASSOCIATED_WITH_CASE = "ASSOCIATED_WITH_CASE"       # (User | Device | IPAddress | Server | EmailAccount) -> (SecurityEvent)


class CriticalityTier(str, Enum):
    """Asset importance rating for prioritization and risk weighting."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataClassification(str, Enum):
    """Information security sensitivity rating for critical crown jewels."""
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"


class TraversalDirection(str, Enum):
    """Graph traversal direction for blast-radius and path queries."""
    OUTGOING = "OUTGOING"
    INCOMING = "INCOMING"
    BOTH = "BOTH"


class InterventionAction(str, Enum):
    """Type of proposed security containment action in what-if simulation."""
    ISOLATE_NODE = "ISOLATE_NODE"
    REVOKE_PERMISSION = "REVOKE_PERMISSION"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    PATCH_VULNERABILITY = "PATCH_VULNERABILITY"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"


# Canonical prefix mapping for deterministic node IDs
CANONICAL_PREFIXES: Dict[NodeLabel, str] = {
    NodeLabel.USER: "user",
    NodeLabel.DEVICE: "device",
    NodeLabel.SERVER: "server",
    NodeLabel.APPLICATION: "app",
    NodeLabel.IP_ADDRESS: "ip",
    NodeLabel.VULNERABILITY: "vuln",
    NodeLabel.CRITICAL_ASSET: "critical",
    NodeLabel.SECURITY_EVENT: "event",
    NodeLabel.EMAIL_ACCOUNT: "email",
}


def canonicalize_node_id(label: NodeLabel, raw_id: str) -> str:
    """
    Generates a deterministic canonical node identifier with prefix.
    Prevents ID collision across different entity types (e.g. server 'app01' vs application 'app01').
    """
    clean_id = raw_id.strip()
    prefix = CANONICAL_PREFIXES.get(label, "entity")
    
    # Handle critical asset prefix variations ('crit:' or 'critical:')
    if label == NodeLabel.CRITICAL_ASSET:
        if clean_id.lower().startswith("critical:"):
            suffix = clean_id[len("critical") + 1:].strip()
        elif clean_id.lower().startswith("crit:"):
            suffix = clean_id[len("crit") + 1:].strip()
        else:
            suffix = clean_id
        return f"critical:{suffix.lower()}"

    # If already prefixed properly, normalize suffix
    if clean_id.startswith(f"{prefix}:"):
        suffix = clean_id[len(prefix) + 1:].strip()
    else:
        suffix = clean_id

    # Canonical case normalization
    if label == NodeLabel.VULNERABILITY:
        suffix = suffix.upper()  # CVE-2024-21413
    elif label == NodeLabel.IP_ADDRESS:
        suffix = suffix.strip()  # preserve exact IP string
    else:
        suffix = suffix.lower()
    
    return f"{prefix}:{suffix}"


# Inverse mapping from prefix string to NodeLabel
PREFIX_TO_LABEL: Dict[str, NodeLabel] = {v: k for k, v in CANONICAL_PREFIXES.items()}
PREFIX_TO_LABEL["crit"] = NodeLabel.CRITICAL_ASSET


def get_node_label_from_id(node_id: str) -> Optional[NodeLabel]:
    """
    Extracts NodeLabel from a canonical node ID prefix if present.
    Example: 'user:usr-101' -> NodeLabel.USER, 'vuln:CVE-2024-21413' -> NodeLabel.VULNERABILITY.
    """
    if not node_id:
        return None
    clean = str(node_id).strip()
    if ":" in clean:
        prefix = clean.split(":", 1)[0].lower()
        return PREFIX_TO_LABEL.get(prefix)
    return None


# Valid endpoint typing rules: maps RelationshipType to allowed (source_labels, target_labels)
VALID_RELATIONSHIP_ENDPOINTS: Dict[RelationshipType, Tuple[Set[NodeLabel], Set[NodeLabel]]] = {
    RelationshipType.USES: (
        {NodeLabel.USER},
        {NodeLabel.DEVICE, NodeLabel.EMAIL_ACCOUNT, NodeLabel.APPLICATION}
    ),
    RelationshipType.LOGGED_IN_TO: (
        {NodeLabel.USER, NodeLabel.EMAIL_ACCOUNT},
        {NodeLabel.SERVER, NodeLabel.DEVICE}
    ),
    RelationshipType.AUTHENTICATED_TO: (
        {NodeLabel.USER, NodeLabel.EMAIL_ACCOUNT},
        {NodeLabel.SERVER, NodeLabel.DEVICE, NodeLabel.APPLICATION}
    ),
    RelationshipType.CAN_REACH: (
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.IP_ADDRESS},
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.IP_ADDRESS, NodeLabel.CRITICAL_ASSET}
    ),
    RelationshipType.CONNECTS_TO: (
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.APPLICATION, NodeLabel.IP_ADDRESS},
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.APPLICATION, NodeLabel.IP_ADDRESS}
    ),
    RelationshipType.OBSERVED_CONNECTION: (
        {NodeLabel.DEVICE, NodeLabel.SERVER},
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.IP_ADDRESS}
    ),
    RelationshipType.HAS_PERMISSION: (
        {NodeLabel.USER, NodeLabel.EMAIL_ACCOUNT},
        {NodeLabel.SERVER, NodeLabel.CRITICAL_ASSET, NodeLabel.APPLICATION}
    ),
    RelationshipType.HOSTS: (
        {NodeLabel.SERVER},
        {NodeLabel.APPLICATION, NodeLabel.CRITICAL_ASSET}
    ),
    RelationshipType.HOSTED_ON: (
        {NodeLabel.APPLICATION, NodeLabel.CRITICAL_ASSET},
        {NodeLabel.SERVER, NodeLabel.DEVICE}
    ),
    RelationshipType.RUNS_ON: (
        {NodeLabel.SERVER, NodeLabel.APPLICATION},
        {NodeLabel.DEVICE, NodeLabel.SERVER}
    ),
    RelationshipType.HAS_VULNERABILITY: (
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.APPLICATION},
        {NodeLabel.VULNERABILITY}
    ),
    RelationshipType.CONTAINS_CRITICAL_DATA: (
        {NodeLabel.SERVER, NodeLabel.APPLICATION},
        {NodeLabel.CRITICAL_ASSET}
    ),
    RelationshipType.POTENTIAL_EXPLOIT: (
        {NodeLabel.DEVICE, NodeLabel.SERVER},
        {NodeLabel.SERVER}
    ),
    RelationshipType.EXPLOITS: (
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.SECURITY_EVENT},
        {NodeLabel.VULNERABILITY, NodeLabel.SERVER, NodeLabel.CRITICAL_ASSET, NodeLabel.APPLICATION}
    ),
    RelationshipType.MEMBER_OF: (
        {NodeLabel.USER, NodeLabel.EMAIL_ACCOUNT},
        {NodeLabel.USER, NodeLabel.APPLICATION}
    ),
    RelationshipType.OWNS: (
        {NodeLabel.USER},
        {NodeLabel.DEVICE, NodeLabel.SERVER, NodeLabel.APPLICATION, NodeLabel.EMAIL_ACCOUNT, NodeLabel.CRITICAL_ASSET}
    ),
    RelationshipType.ASSOCIATED_WITH_CASE: (
        {NodeLabel.USER, NodeLabel.DEVICE, NodeLabel.IP_ADDRESS, NodeLabel.SERVER, NodeLabel.EMAIL_ACCOUNT},
        {NodeLabel.SECURITY_EVENT}
    ),
}


# Cypher schema definition statements (Constraints & Indexes) for GraphOps
CYPHER_SCHEMA_STATEMENTS = [
    # Unique Constraints for canonical IDs
    "CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT device_id_unique IF NOT EXISTS FOR (n:Device) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT server_id_unique IF NOT EXISTS FOR (n:Server) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT app_id_unique IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT ip_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT crit_id_unique IF NOT EXISTS FOR (n:CriticalAsset) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (n:SecurityEvent) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT email_id_unique IF NOT EXISTS FOR (n:EmailAccount) REQUIRE n.id IS UNIQUE",
    
    # Indexes for rapid property lookups during graph traversal
    "CREATE INDEX user_email_idx IF NOT EXISTS FOR (n:User) ON (n.email)",
    "CREATE INDEX device_ip_idx IF NOT EXISTS FOR (n:Device) ON (n.ip_address)",
    "CREATE INDEX server_ip_idx IF NOT EXISTS FOR (n:Server) ON (n.ip_address)",
    "CREATE INDEX vuln_cve_idx IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
    "CREATE INDEX crit_impact_idx IF NOT EXISTS FOR (n:CriticalAsset) ON (n.impact_score)",
    "CREATE INDEX email_addr_idx IF NOT EXISTS FOR (n:EmailAccount) ON (n.email_address)",
]
