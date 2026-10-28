"""
ThreatLens GraphOps - Phase 2 Knowledge Graph, Schema & Data Ingestion Tests
Covers Section 10 requirements:
- Node models (EmailAccount, User, Device, Server, Vulnerability, CriticalAsset)
- Canonical ID normalization and deterministic prefixes
- Traversal cost contract validation (non-negative, finite, None vs 0.0)
- Relationship endpoint typing rules for Phase 2 types (AUTHENTICATED_TO, OWNS, CAN_REACH, HOSTED_ON, EXPLOITS)
- CSV ingestion (nodes and relationships)
- Fast API POST /api/v1/graphops/ingest/csv endpoint
- Deduplication inside ingestion payload
- Unresolved endpoint reference rejection
- Sample fixture validation (unreachable critical asset, alternative path, choke point, traversal costs)
- Schema Cypher constraints and index definitions
"""

import pytest
import math
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.main import app
from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
    DataClassification,
    canonicalize_node_id,
    get_node_label_from_id,
    VALID_RELATIONSHIP_ENDPOINTS,
    CYPHER_SCHEMA_STATEMENTS,
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
from backend.graphops.ingest import GraphOpsIngestionEngine
from backend.graphops.client import get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture


# =====================================================================
# 1. SCHEMA & CANONICAL IDENTIFIER TESTS
# =====================================================================

def test_phase2_email_account_model_valid():
    """Verifies valid EmailAccountNode creation and normalization."""
    account = EmailAccountNode(
        id="ALICE@corporation.com",
        email_address="ALICE@corporation.com",
        account_name="Alice Vance",
        mailbox_type="USER",
        is_internal=True,
    )
    assert account.id == "email:alice@corporation.com"
    assert account.email_address == "alice@corporation.com"
    assert account.domain == "corporation.com"
    assert account.is_internal is True
    assert account.is_compromised is False


def test_phase2_email_account_model_invalid_email():
    """Verifies that malformed email addresses are rejected by Pydantic RFC 5322 validator."""
    with pytest.raises(ValidationError):
        EmailAccountNode(
            id="bad-email",
            email_address="not-an-email-address",
        )


def test_phase2_canonical_id_crit_variants():
    """Verifies that crit: and critical: prefixes are normalized deterministically."""
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "crit:vault-01") == "critical:vault-01"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "critical:vault-01") == "critical:vault-01"
    assert canonicalize_node_id(NodeLabel.CRITICAL_ASSET, "CRIT-VAULT-01") == "critical:crit-vault-01"
    assert canonicalize_node_id(NodeLabel.EMAIL_ACCOUNT, "email:bob@corp.com") == "email:bob@corp.com"
    assert canonicalize_node_id(NodeLabel.EMAIL_ACCOUNT, "bob@corp.com") == "email:bob@corp.com"


def test_phase2_schema_cypher_statements_completeness():
    """Verifies that CYPHER_SCHEMA_STATEMENTS includes unique constraints for all required node labels."""
    stmt_text = " ".join(CYPHER_SCHEMA_STATEMENTS)
    assert "FOR (n:User) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:Device) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:Server) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:Application) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:IPAddress) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:CriticalAsset) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:SecurityEvent) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "FOR (n:EmailAccount) REQUIRE n.id IS UNIQUE" in stmt_text
    assert "CREATE INDEX email_addr_idx" in stmt_text


# =====================================================================
# 2. TRAVERSAL COST CONTRACT FOR DIJKSTRA (SECTION 5)
# =====================================================================

def test_phase2_traversal_cost_valid_and_distinguishable():
    """Verifies non-negative traversal costs are accepted and 0.0 is distinct from None."""
    # Positive cost
    rel_pos = EnterpriseRelationship(
        source_id="device:dev-ws-101",
        target_id="server:srv-app-01",
        relationship_type=RelationshipType.OBSERVED_CONNECTION,
        traversal_cost=1.5,
    )
    assert rel_pos.traversal_cost == 1.5

    # Zero cost (zero friction/immediate traversal)
    rel_zero = EnterpriseRelationship(
        source_id="device:dev-ws-101",
        target_id="server:srv-app-01",
        relationship_type=RelationshipType.OBSERVED_CONNECTION,
        traversal_cost=0.0,
    )
    assert rel_zero.traversal_cost == 0.0
    assert rel_zero.traversal_cost is not None

    # Unweighted/ineligible relationship defaults to None
    rel_none = EnterpriseRelationship(
        source_id="user:alice",
        target_id="device:ws-1",
        relationship_type=RelationshipType.USES,
    )
    assert rel_none.traversal_cost is None


def test_phase2_traversal_cost_negative_rejected():
    """Verifies that negative traversal costs are strictly rejected."""
    with pytest.raises(ValidationError) as exc:
        EnterpriseRelationship(
            source_id="device:dev-ws-101",
            target_id="server:srv-app-01",
            relationship_type=RelationshipType.OBSERVED_CONNECTION,
            traversal_cost=-0.5,
        )
    assert "traversal_cost must be non-negative" in str(exc.value)


def test_phase2_traversal_cost_non_finite_rejected():
    """Verifies that NaN and Infinite costs are rejected."""
    with pytest.raises(ValidationError):
        EnterpriseRelationship(
            source_id="device:dev-ws-101",
            target_id="server:srv-app-01",
            relationship_type=RelationshipType.OBSERVED_CONNECTION,
            traversal_cost=float("nan"),
        )
    with pytest.raises(ValidationError):
        EnterpriseRelationship(
            source_id="device:dev-ws-101",
            target_id="server:srv-app-01",
            relationship_type=RelationshipType.OBSERVED_CONNECTION,
            traversal_cost=float("inf"),
        )


# =====================================================================
# 3. RELATIONSHIP ENDPOINT TYPING RULES (SECTION 3.2)
# =====================================================================

def test_phase2_relationship_endpoint_typing_extensions():
    """Verifies typing constraints on newly registered Phase 2 relationships."""
    engine = GraphOpsIngestionEngine(client=MagicMock())
    known_ids = {
        "user:usr-101",
        "email:alice@corp.com",
        "device:dev-ws-101",
        "server:srv-app-01",
        "app:erp-01",
        "vuln:CVE-2024-21413",
        "critical:crit-vault-01",
    }

    # 1. OWNS: User -> EmailAccount is valid; Device -> User is invalid
    valid_owns, err = engine.validate_relationship(
        {"source_id": "user:usr-101", "target_id": "email:alice@corp.com", "relationship_type": "OWNS"},
        known_ids,
    )
    assert err is None
    assert valid_owns["type"] == "OWNS"

    _, err_owns = engine.validate_relationship(
        {"source_id": "device:dev-ws-101", "target_id": "user:usr-101", "relationship_type": "OWNS"},
        known_ids,
    )
    assert "Invalid relationship endpoint typing" in err_owns

    # 2. AUTHENTICATED_TO: User -> Server is valid; Vulnerability -> Server is invalid
    valid_auth, err = engine.validate_relationship(
        {"source_id": "user:usr-101", "target_id": "server:srv-app-01", "relationship_type": "AUTHENTICATED_TO"},
        known_ids,
    )
    assert err is None
    assert valid_auth["type"] == "AUTHENTICATED_TO"

    # 3. CAN_REACH: Device -> CriticalAsset is valid; User -> CriticalAsset is invalid for CAN_REACH
    valid_reach, err = engine.validate_relationship(
        {"source_id": "device:dev-ws-101", "target_id": "critical:crit-vault-01", "relationship_type": "CAN_REACH"},
        known_ids,
    )
    assert err is None
    assert valid_reach["type"] == "CAN_REACH"

    _, err_reach = engine.validate_relationship(
        {"source_id": "user:usr-101", "target_id": "critical:crit-vault-01", "relationship_type": "CAN_REACH"},
        known_ids,
    )
    assert "Invalid relationship endpoint typing" in err_reach

    # 4. EXPLOITS: Device -> Vulnerability is valid; User -> EmailAccount is invalid
    valid_exploit, err = engine.validate_relationship(
        {"source_id": "device:dev-ws-101", "target_id": "vuln:CVE-2024-21413", "relationship_type": "EXPLOITS"},
        known_ids,
    )
    assert err is None
    assert valid_exploit["type"] == "EXPLOITS"


def test_phase2_unresolved_references_rejected():
    """Verifies that unknown node references are never connected and reported as errors."""
    engine = GraphOpsIngestionEngine(client=MagicMock())
    known_ids = {"user:usr-101", "device:dev-ws-101"}

    _, err = engine.validate_relationship(
        {"source_id": "user:usr-101", "target_id": "device:ghost-endpoint", "relationship_type": "USES"},
        known_ids,
    )
    assert err is not None
    assert "Unresolved relationship reference: target_id 'device:ghost-endpoint' does not exist" in err


# =====================================================================
# 4. CSV INGESTION (SECTION 8)
# =====================================================================

def test_phase2_csv_nodes_parsing_and_ingestion():
    """Verifies CSV entity parsing across heterogeneous node types."""
    engine = GraphOpsIngestionEngine(client=MagicMock())
    engine.client.execute_query.return_value = []
    engine.client.execute_write.return_value = {"nodes_created": 3}

    csv_data = """label,id,name,email,department,role,ip_address,hostname,cve_id,cvss_score,severity,impact_score,category
User,usr-901,Grace Hopper,grace@navy.mil,Engineering,Admiral,,,,,,,
Device,dev-ws-901,Admiral Workstation,,,,10.0.9.1,ws-grace.corp,,,,,
Vulnerability,CVE-2024-9999,Hypothetical Overflow,,,,,,CVE-2024-9999,9.1,CRITICAL,,
CriticalAsset,crit-secrets,Naval Code Vault,,,,,,,,,98,CREDENTIAL_STORE
EmailAccount,grace@navy.mil,Grace Hopper Mailbox,,,,,,,,,,
"""
    parsed = engine.parse_csv_entities(csv_data)
    assert len(parsed.users) == 1
    assert parsed.users[0].email == "grace@navy.mil"
    assert len(parsed.devices) == 1
    assert parsed.devices[0].ip_address == "10.0.9.1"
    assert len(parsed.vulnerabilities) == 1
    assert parsed.vulnerabilities[0].cvss_score == 9.1
    assert len(parsed.critical_assets) == 1
    assert parsed.critical_assets[0].impact_score == 98
    assert len(parsed.email_accounts) == 1
    assert parsed.email_accounts[0].email_address == "grace@navy.mil"


def test_phase2_csv_relationships_parsing():
    """Verifies CSV relationship parsing with traversal_cost and evidence preservation."""
    engine = GraphOpsIngestionEngine(client=MagicMock())
    csv_data = """source_id,target_id,relationship_type,evidence_class,traversal_cost,provenance,confidence
user:usr-901,device:dev-ws-901,USES,OBSERVED,,HR_Inventory,1.0
device:dev-ws-901,server:srv-db-01,OBSERVED_CONNECTION,OBSERVED,2.5,FirewallNetFlow,1.0
server:srv-db-01,critical:crit-secrets,CONTAINS_CRITICAL_DATA,OBSERVED,0.5,CMDB,1.0
"""
    parsed = engine.parse_csv_relationships(csv_data)
    assert len(parsed.relationships) == 3
    assert parsed.relationships[0].relationship_type == RelationshipType.USES
    assert parsed.relationships[0].traversal_cost is None
    assert parsed.relationships[1].relationship_type == RelationshipType.OBSERVED_CONNECTION
    assert parsed.relationships[1].traversal_cost == 2.5
    assert parsed.relationships[2].traversal_cost == 0.5


def test_phase2_fastapi_csv_ingestion_endpoint():
    """Verifies POST /api/v1/graphops/ingest/csv endpoint validation and execution."""
    mock_client = MagicMock()
    mock_client.execute_query.return_value = []
    mock_client.execute_write.return_value = {"nodes_created": 2, "relationships_created": 0}

    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        client = TestClient(app)
        
        # 1. Valid nodes CSV
        csv_payload = {
            "dataset_name": "test_csv_batch",
            "csv_data": "label,id,name,email\nUser,usr-301,Test User,testuser@corp.com\nUser,usr-302,Admin User,admin@corp.com\n"
        }
        res = client.post("/api/v1/graphops/ingest/csv", json=csv_payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "SUCCESS"
        assert data["dataset_name"] == "test_csv_batch"

        # 2. Missing csv_data returns 400
        res_empty = client.post("/api/v1/graphops/ingest/csv", json={"csv_data": ""})
        assert res_empty.status_code == 400
        assert "Missing 'csv_data'" in res_empty.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


# =====================================================================
# 5. DEDUPLICATION & IDEMPOTENCY (SECTION 4 & 7)
# =====================================================================

def test_phase2_intra_payload_deduplication():
    """Verifies that multiple entries for the same entity in a single payload are merged cleanly."""
    mock_client = MagicMock()
    mock_client.execute_query.return_value = []
    mock_client.execute_write.return_value = {"nodes_created": 1, "relationships_created": 0}

    engine = GraphOpsIngestionEngine(client=mock_client)
    payload = BulkIngestPayload(
        dataset_name="dedup_test",
        entities=EntityIngestRequest(
            users=[
                UserNode(id="USR-001", user_id="USR-001", email="dup@corp.com", name="Initial Name", role="Junior"),
                UserNode(id="USR-001", user_id="USR-001", email="dup@corp.com", name="Updated Name", role="Senior"),
            ]
        )
    )
    summary = engine.ingest_payload(payload)
    assert summary.nodes_rejected == 0
    # execute_write should only be called once with a single de-duplicated item in batch
    write_calls = mock_client.execute_write.call_args_list
    assert len(write_calls) == 1
    batch_arg = write_calls[0][0][1]["batch"]
    assert len(batch_arg) == 1
    assert batch_arg[0]["properties"]["name"] == "Updated Name"
    assert batch_arg[0]["properties"]["role"] == "Senior"


# =====================================================================
# 6. SAMPLE ENTERPRISE FIXTURE VERIFICATION (SECTION 8.1)
# =====================================================================

def test_phase2_sample_fixture_requirements():
    """
    Validates Section 8.1 sample fixture topology:
    - Multiple users, devices, servers, apps, vulnerabilities, IPs
    - At least two critical assets + unreachable air-gapped vault
    - Known low-trust to critical asset attack path
    - Choke point srv-app-01 shared by multiple paths
    - Alternative path from dev-ws-201 that survives srv-app-01 isolation
    - Non-negative traversal costs on path-eligible relationships
    """
    fixture = load_sample_enterprise_fixture()
    entities = fixture["entities"]
    relationships = fixture["relationships"]["relationships"]

    # 1. Critical assets check
    crit_ids = [c["id"] for c in entities["critical_assets"]]
    assert "CRIT-DB-FINANCIAL" in crit_ids
    assert "CRIT-AD-DOMAIN-ROOT" in crit_ids
    assert "CRIT-PII-CUSTOMER" in crit_ids
    assert "CRIT-AIRGAPPED-VAULT" in crit_ids

    # 2. Unreachable critical asset check (no incoming edges)
    incoming_to_airgap = [
        r for r in relationships if "crit-airgapped-vault" in r["target_id"].lower()
    ]
    assert len(incoming_to_airgap) == 0, "CRIT-AIRGAPPED-VAULT must be completely unreachable"

    # 3. Email accounts present
    email_accs = entities.get("email_accounts", [])
    assert len(email_accs) >= 4
    email_addrs = [e["email_address"] for e in email_accs]
    assert "victim1@corporation.com" in email_addrs
    assert "victim2@corporation.com" in email_addrs

    # 4. Traversal costs populated on path relationships
    path_rels = [
        r for r in relationships
        if r.get("relationship_type") in ("OBSERVED_CONNECTION", "POTENTIAL_EXPLOIT", "CONTAINS_CRITICAL_DATA")
        and "traversal_cost" in r
    ]
    assert len(path_rels) >= 6
    for r in path_rels:
        cost = r["traversal_cost"]
        assert isinstance(cost, (int, float))
        assert cost >= 0.0
        assert not math.isnan(cost) and not math.isinf(cost)

    # 5. Alternative path that survives choke point srv-app-01
    alt_edges = [
        r for r in relationships
        if r["source_id"] == "device:dev-ws-201" and r["target_id"] == "server:srv-db-01"
    ]
    assert len(alt_edges) == 1
    assert alt_edges[0]["traversal_cost"] == 2.0
