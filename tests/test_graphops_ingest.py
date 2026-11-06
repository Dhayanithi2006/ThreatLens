"""
ThreatLens GraphOps - Ingestion Test Suite
Phase 4: Sample Data Loading, Entity Validation, Reference Resolution, Idempotency, and API Endpoints.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.schema import NodeLabel, RelationshipType, EvidenceClass
from backend.graphops.ingest import GraphOpsIngestionEngine
from backend.data.graphops_fixtures import load_sample_enterprise_fixture
from backend.models.graphops import (
    BulkIngestPayload,
    EntityIngestRequest,
    RelationshipIngestRequest,
    UserNode,
    DeviceNode,
    EnterpriseRelationship,
)
from backend.graphops.client import get_graphops_client, Neo4jClient


# =====================================================================
# 1. FIXTURE INTEGRITY TESTS
# =====================================================================

def test_load_sample_enterprise_fixture_structure():
    """Verifies that the synthetic enterprise fixture is valid and explicitly labeled."""
    fixture = load_sample_enterprise_fixture()
    assert fixture["dataset_name"] == "simulated_soc_enterprise_fixture_v1"
    assert "SIMULATED" in fixture["disclaimer"]
    
    entities = fixture["entities"]
    assert len(entities["users"]) >= 4
    assert len(entities["devices"]) >= 3
    assert len(entities["servers"]) >= 3
    assert len(entities["applications"]) >= 2
    assert len(entities["vulnerabilities"]) >= 2
    assert len(entities["critical_assets"]) >= 2
    assert len(fixture["relationships"]["relationships"]) >= 15


# =====================================================================
# 2. VALIDATION & REFERENCE RESOLUTION TESTS
# =====================================================================

def test_entity_validation_success():
    engine = GraphOpsIngestionEngine(client=MagicMock())
    valid_user, err = engine.validate_entity(NodeLabel.USER, {
        "id": "USR-101",
        "user_id": "USR-101",
        "email": "alice@corp.com",
        "name": "Alice Vance"
    })
    assert err is None
    assert valid_user["id"] == "user:usr-101"
    assert valid_user["label"] == "User"
    assert valid_user["properties"]["department"] == "Unassigned"


def test_entity_validation_actionable_errors():
    engine = GraphOpsIngestionEngine(client=MagicMock())

    # 1. Invalid CVE format
    _, err_cve = engine.validate_entity(NodeLabel.VULNERABILITY, {
        "id": "bad",
        "cve_id": "INVALID-FORMAT",
        "cvss_score": 9.0,
        "severity": "CRITICAL"
    })
    assert err_cve is not None
    assert "Invalid CVE identifier format" in err_cve

    # 2. Invalid IP address
    _, err_ip = engine.validate_entity(NodeLabel.IP_ADDRESS, {
        "id": "bad",
        "ip": "999.1.2.3"
    })
    assert err_ip is not None
    assert "Invalid IP address format" in err_ip


def test_relationship_validation_missing_endpoints():
    """
    Verifies that relationships pointing to non-existent nodes are rejected
    with clear error messages rather than silently manufacturing phantom nodes.
    """
    engine = GraphOpsIngestionEngine(client=MagicMock())
    known_nodes = {"user:alice@corp.com"}

    # Missing target
    raw_rel = {
        "source_id": "user:alice@corp.com",
        "target_id": "device:non-existent",
        "relationship_type": "USES"
    }
    valid_rel, err = engine.validate_relationship(raw_rel, known_nodes)
    assert valid_rel is None
    assert "Unresolved relationship reference: target_id 'device:non-existent'" in err

    # Missing source
    raw_rel_source = {
        "source_id": "user:ghost@corp.com",
        "target_id": "user:alice@corp.com",
        "relationship_type": "USES"
    }
    valid_rel2, err2 = engine.validate_relationship(raw_rel_source, known_nodes)
    assert valid_rel2 is None
    assert "Unresolved relationship reference: source_id 'user:ghost@corp.com'" in err2


# =====================================================================
# 3. IDEMPOTENT INGESTION EXECUTION TESTS
# =====================================================================

def test_ingest_payload_idempotency():
    """
    Simulates fresh import followed by re-import of the exact same data.
    Verifies that nodes and relationships are updated on match, not duplicated.
    """
    mock_client = MagicMock()
    mock_client.init_schema_constraints.return_value = {"applied_count": 13}
    mock_client.execute_query.return_value = []
    
    # Run 1: Fresh Import (nodes_created = 2)
    mock_client.execute_write.side_effect = [
        {"nodes_created": 1, "nodes_deleted": 0, "relationships_created": 0},  # users
        {"nodes_created": 1, "nodes_deleted": 0, "relationships_created": 0},  # devices
        {"nodes_created": 0, "nodes_deleted": 0, "relationships_created": 1},  # relationships
    ]

    engine = GraphOpsIngestionEngine(client=mock_client)
    payload = BulkIngestPayload(
        dataset_name="test_idempotency_v1",
        entities=EntityIngestRequest(
            users=[UserNode(id="USR-1", user_id="USR-1", email="u1@corp.com", name="User 1")],
            devices=[DeviceNode(id="DEV-1", device_id="DEV-1", hostname="WS-01", ip_address="10.0.1.1")]
        ),
        relationships=RelationshipIngestRequest(
            relationships=[
                EnterpriseRelationship(
                    source_id="user:u1@corp.com",
                    target_id="device:dev-1",
                    relationship_type=RelationshipType.USES
                )
            ]
        )
    )

    summary_run1 = engine.ingest_payload(payload)
    assert summary_run1.status == "SUCCESS"
    assert summary_run1.nodes_imported == 2
    assert summary_run1.relationships_imported == 1
    assert summary_run1.nodes_rejected == 0

    # Run 2: Re-import same data (nodes_created = 0, nodes_updated = 2)
    mock_client.execute_write.side_effect = [
        {"nodes_created": 0, "nodes_deleted": 0, "relationships_created": 0},  # users updated
        {"nodes_created": 0, "nodes_deleted": 0, "relationships_created": 0},  # devices updated
        {"nodes_created": 0, "nodes_deleted": 0, "relationships_created": 0},  # rels updated
    ]
    summary_run2 = engine.ingest_payload(payload)
    assert summary_run2.status == "SUCCESS"
    assert summary_run2.nodes_imported == 0
    assert summary_run2.nodes_updated == 2
    assert summary_run2.relationships_imported == 0
    assert summary_run2.relationships_updated == 1


def test_ingest_sample_fixture_workflow():
    """Verifies that the complete sample enterprise fixture can be ingested without schema errors."""
    mock_client = MagicMock()
    mock_client.execute_query.return_value = []
    mock_client.execute_write.return_value = {
        "nodes_created": 5,
        "relationships_created": 5,
        "properties_set": 20
    }

    engine = GraphOpsIngestionEngine(client=mock_client)
    summary = engine.ingest_sample_fixture()
    assert summary.status in ["SUCCESS", "PARTIAL"]
    assert summary.nodes_rejected == 0
    assert summary.relationships_rejected == 0


def test_get_graph_summary():
    mock_client = MagicMock()
    mock_client.execute_query.side_effect = [
        # 1. Node counts by label
        [{"label": "User", "count": 6}, {"label": "Device", "count": 4}, {"label": "Server", "count": 4}],
        # 2. Relationship counts by type
        [{"rel_type": "USES", "count": 4}, {"rel_type": "OBSERVED_CONNECTION", "count": 4}],
        # 3. Critical assets
        [{"id": "critical:crit-db-financial", "name": "Customer Financial Ledger", "impact": 95, "category": "FINANCIAL_RECORDS"}]
    ]

    engine = GraphOpsIngestionEngine(client=mock_client)
    summary = engine.get_graph_summary()
    assert summary["total_nodes"] == 14
    assert summary["total_relationships"] == 8
    assert summary["node_counts_by_label"]["User"] == 6
    assert summary["status"] == "POPULATED"
    assert len(summary["critical_assets"]) == 1


# =====================================================================
# 4. FASTAPI ENDPOINT INGESTION TESTS
# =====================================================================

def test_fastapi_ingest_sample_and_summary_endpoints():
    client = TestClient(app)
    mock_client = MagicMock()
    mock_client.execute_query.return_value = [{"label": "User", "count": 6}]
    mock_client.execute_write.return_value = {"nodes_created": 6, "relationships_created": 4}

    app.dependency_overrides[get_graphops_client] = lambda: mock_client
    try:
        # Ingest sample endpoint
        resp_ingest = client.post("/api/v1/graphops/ingest/sample")
        assert resp_ingest.status_code == 200
        data = resp_ingest.json()
        assert data["status"] in ["SUCCESS", "PARTIAL"]

        # Summary endpoint
        resp_summary = client.get("/api/v1/graphops/summary")
        assert resp_summary.status_code == 200
        sum_data = resp_summary.json()
        assert "total_nodes" in sum_data
    finally:
        app.dependency_overrides.pop(get_graphops_client, None)


# =====================================================================
# 5. PHASE 2 STRENGTHENED DATA INTEGRITY & DEDUPLICATION TESTS
# =====================================================================

def test_relationship_validation_endpoint_typing_mismatch():
    """
    Verifies that relationships violating VALID_RELATIONSHIP_ENDPOINTS
    are rejected with clear, actionable typing mismatch errors.
    """
    engine = GraphOpsIngestionEngine(client=MagicMock())
    known_nodes = {"device:dev-ws-101", "vuln:cve-2024-21413", "server:srv-app-01"}

    # Invalid: Device cannot 'USE' a Vulnerability
    invalid_rel = {
        "source_id": "device:dev-ws-101",
        "target_id": "vuln:cve-2024-21413",
        "relationship_type": "USES"
    }
    valid_res, err = engine.validate_relationship(invalid_rel, known_nodes)
    assert valid_res is None
    assert "Invalid relationship endpoint typing" in err
    assert "cannot originate from 'Device'" in err or "cannot target 'Vulnerability'" in err

    # Valid: Server HAS_VULNERABILITY Vulnerability
    valid_rel = {
        "source_id": "server:srv-app-01",
        "target_id": "vuln:cve-2024-21413",
        "relationship_type": "HAS_VULNERABILITY"
    }
    res, err = engine.validate_relationship(valid_rel, known_nodes)
    assert err is None
    assert res is not None
    assert res["type"] == "HAS_VULNERABILITY"


def test_ingest_payload_intra_payload_deduplication():
    """
    Verifies that duplicate nodes and duplicate relationships present within
    the same payload are deduplicated into unique entries with property merges.
    """
    mock_client = MagicMock()
    mock_client.init_schema_constraints.return_value = {"applied_count": 13}
    mock_client.execute_query.return_value = []
    
    # Track Cypher UNWIND batches executed
    executed_batches = []
    def fake_execute_write(query, params=None, database=None):
        if params and "batch" in params:
            executed_batches.append(params["batch"])
        return {"nodes_created": len(params.get("batch", [])) if params else 0}

    mock_client.execute_write.side_effect = fake_execute_write
    engine = GraphOpsIngestionEngine(client=mock_client)

    # Payload with duplicate User entries and duplicate relationships
    payload = BulkIngestPayload(
        dataset_name="dedup_test_v1",
        entities=EntityIngestRequest(
            users=[
                UserNode(id="USR-1", user_id="USR-1", email="u1@corp.com", name="User 1", department="Engineering"),
                UserNode(id="USR-1", user_id="USR-1", email="u1@corp.com", name="User 1", department="Security"),  # duplicate with updated dept
            ],
            devices=[
                DeviceNode(id="DEV-1", device_id="DEV-1", hostname="WS-01", ip_address="10.0.1.1")
            ]
        ),
        relationships=RelationshipIngestRequest(
            relationships=[
                EnterpriseRelationship(
                    source_id="user:u1@corp.com",
                    target_id="device:dev-1",
                    relationship_type=RelationshipType.USES,
                    properties={"confidence": 0.9}
                ),
                EnterpriseRelationship(
                    source_id="user:u1@corp.com",
                    target_id="device:dev-1",
                    relationship_type=RelationshipType.USES,
                    properties={"confidence": 1.0}  # duplicate relationship
                )
            ]
        )
    )

    summary = engine.ingest_payload(payload)
    assert summary.status == "SUCCESS"
    assert summary.nodes_rejected == 0
    assert summary.relationships_rejected == 0

    # Verify that the User batch sent to Neo4j contained exactly 1 deduplicated record
    user_batches = [b for b in executed_batches if any(n.get("label") == "User" for n in b)]
    assert len(user_batches) == 1
    assert len(user_batches[0]) == 1
    # Check that updated properties were merged
    assert user_batches[0][0]["properties"]["department"] == "Security"

    # Verify that relationship batch contained exactly 1 deduplicated record
    rel_batches = [b for b in executed_batches if any("relationship_type" in r.get("properties", {}) for r in b)]
    assert len(rel_batches) == 1
    assert len(rel_batches[0]) == 1
    assert rel_batches[0][0]["properties"]["confidence"] == 1.0


def test_partial_failure_reporting():
    """
    Verifies that malformed entities and invalid relationships are properly recorded
    in 'errors' and 'rejected' counts, leading to status='PARTIAL'.
    """
    mock_client = MagicMock()
    mock_client.init_schema_constraints.return_value = {"applied_count": 13}
    mock_client.execute_query.return_value = []
    mock_client.execute_write.return_value = {"nodes_created": 1, "relationships_created": 0}

    engine = GraphOpsIngestionEngine(client=mock_client)

    payload = BulkIngestPayload(
        dataset_name="partial_test",
        entities=EntityIngestRequest(
            users=[
                UserNode(id="USR-VALID", user_id="USR-VALID", email="valid@corp.com", name="Valid User")
            ]
        ),
        relationships=RelationshipIngestRequest(
            relationships=[
                EnterpriseRelationship(
                    source_id="user:usr-valid",
                    target_id="device:non-existent-device",
                    relationship_type=RelationshipType.USES
                )
            ]
        )
    )

    summary = engine.ingest_payload(payload)
    assert summary.status == "PARTIAL"
    assert summary.nodes_imported == 1
    assert summary.relationships_rejected == 1
    assert len(summary.errors) == 1
    assert "Unresolved relationship reference" in summary.errors[0]
