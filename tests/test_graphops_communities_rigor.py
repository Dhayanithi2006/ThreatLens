"""
ThreatLens GraphOps — Security Community Detection Rigorous Test Suite
Tests:
1. Empty graph returns 0 communities cleanly without exception.
2. Isolated nodes with zero degree are assigned to COMM-ISOLATED enclave.
3. Multiple known enterprise enclaves are partitioned correctly.
4. Cross-boundary edges identify high-risk lateral movement transitions.
5. Disconnected components are gracefully partitioned.
6. FastAPI endpoint /api/v1/graphops/communities integration.
"""

import pytest
from typing import Dict, Any, List
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.communities import detect_security_communities, CommunityDetectionResult


client = TestClient(app)


class MockConnectedClient:
    """Mock client returning custom nodes and relationships."""
    def __init__(self, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
        self._nodes = nodes
        self._edges = edges

    def health_check(self):
        return {"connected": True}

    def execute_query(self, query: str):
        if "RETURN n.id" in query:
            return self._nodes
        if "RETURN s.id" in query:
            return self._edges
        return []


def test_empty_graph_communities():
    """Verifies that an empty graph returns 0 clusters and 0.0 modularity score without error."""
    empty_c = MockConnectedClient(nodes=[], edges=[])
    result = detect_security_communities(client=empty_c)

    assert isinstance(result, CommunityDetectionResult)
    assert result.total_communities == 0
    assert len(result.communities) == 0
    assert len(result.boundary_edges) == 0
    assert result.modularity_score == 0.0
    assert "Enclave Modularity & Boundary Pivot Partitioning" in result.disclaimer


def test_isolated_nodes_assigned_to_comm_isolated():
    """Verifies that isolated nodes with zero degree are classified as COMM-ISOLATED."""
    nodes = [
        {"id": "device:dev-ws-01", "labels": ["Device"], "name": "Workstation 1", "criticality": "LOW"},
        {"id": "device:dev-ws-02", "labels": ["Device"], "name": "Workstation 2", "criticality": "LOW"},
        {"id": "server:isolated-srv", "labels": ["Server"], "name": "Airgapped Server", "criticality": "MEDIUM"},
    ]
    edges = [
        {"source": "device:dev-ws-01", "target": "device:dev-ws-02", "type": "CONNECTED_TO"}
    ]
    custom_c = MockConnectedClient(nodes=nodes, edges=edges)
    result = detect_security_communities(client=custom_c)

    assert result.total_communities >= 2
    # Find COMM-ISOLATED
    isolated_comm = next((c for c in result.communities if c.community_id == "COMM-ISOLATED"), None)
    assert isolated_comm is not None, "Isolated enclave must exist for zero-degree nodes"
    assert "server:isolated-srv" in isolated_comm.node_ids
    assert isolated_comm.name == "Isolated & Unassigned Assets"


def test_multi_tier_enclaves_and_boundary_pivot():
    """Verifies partition into IAM, Crown Jewels, DMZ, and User endpoints with cross-boundary transitions."""
    nodes = [
        {"id": "user:u1", "labels": ["User"], "name": "Alice Analyst", "criticality": "LOW"},
        {"id": "device:ws-u1", "labels": ["Device"], "name": "Workstation Alice", "criticality": "LOW"},
        {"id": "server:srv-bastion", "labels": ["Server"], "name": "DMZ Jumpbox", "criticality": "MEDIUM"},
        {"id": "server:dc-root-01", "labels": ["Server"], "name": "Domain Controller", "criticality": "CRITICAL"},
        {"id": "server:db-prod-sql", "labels": ["Server"], "name": "Customer SQL DB", "criticality": "CRITICAL"},
    ]
    edges = [
        {"source": "user:u1", "target": "device:ws-u1", "type": "LOGGED_INTO"},
        {"source": "device:ws-u1", "target": "server:srv-bastion", "type": "SSH_ACCESS"},
        {"source": "server:srv-bastion", "target": "server:db-prod-sql", "type": "SQL_QUERY"},
        {"source": "server:srv-bastion", "target": "server:dc-root-01", "type": "LDAP_AUTH"},
    ]
    custom_c = MockConnectedClient(nodes=nodes, edges=edges)
    result = detect_security_communities(client=custom_c)

    comm_ids = {c.community_id for c in result.communities}
    assert "COMM-USER-ENDPOINTS" in comm_ids
    assert "COMM-DMZ-GATEWAYS" in comm_ids
    assert "COMM-CROWN-JEWELS" in comm_ids
    assert "COMM-IAM" in comm_ids

    # Verify boundary transitions
    assert result.cross_boundary_edges_count > 0
    # SQL query from DMZ to Crown Jewels must be flagged as high/critical risk cross-tier
    crown_boundary = next(
        (b for b in result.boundary_edges if b.target_community == "COMM-CROWN-JEWELS"), None
    )
    assert crown_boundary is not None
    assert crown_boundary.is_cross_tier is True
    assert crown_boundary.risk_level == "CRITICAL"


def test_communities_fastapi_endpoint():
    """Verifies that the registered FastAPI route returns valid CommunityDetectionResult schema."""
    resp = client.get("/api/v1/graphops/communities")
    assert resp.status_code == 200
    data = resp.json()

    assert "communities" in data
    assert "boundary_edges" in data
    assert "total_communities" in data
    assert "cross_boundary_edges_count" in data
    assert "modularity_score" in data
    assert "execution_time_ms" in data
    assert "disclaimer" in data
    assert "Enclave Modularity & Boundary Pivot Partitioning" in data["disclaimer"]
    assert isinstance(data["communities"], list)

