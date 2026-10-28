"""
ThreatLens - Zero-Trust Access Audit & Graph Centrality Analytics Test Suite
Validates:
1. Zero-Trust Access Audit Service: Entitled vs. Observed graph diff, dormant credentials, shadow access, compliance ratio.
2. Graph Centrality Analytics Service: Brandes' Betweenness Centrality, Google PageRank, structural disruption index.
3. Fast REST API Endpoints: /api/v1/graphops/zero-trust/audit and /api/v1/graphops/centrality.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.zero_trust import ZeroTrustAuditService, ZeroTrustAuditResult
from backend.graphops.centrality import CentralityAnalyticsService, CentralityAnalysisResult
from backend.graphops.client import get_graphops_client


def test_zero_trust_audit_service_execution():
    """Validates that ZeroTrustAuditService executes relational access diffing and returns compliance metrics."""
    client = get_graphops_client()
    service = ZeroTrustAuditService(client=client)
    result = service.audit_access_entitlements()

    assert isinstance(result, ZeroTrustAuditResult)
    assert result.timestamp is not None
    assert result.total_entitled_permissions >= 0
    assert 0.0 <= result.least_privilege_compliance_pct <= 100.0
    assert 0.0 <= result.over_privilege_risk_score <= 100.0
    assert len(result.access_breakdown) > 0

    valid_statuses = {"ACTIVE_VERIFIED", "OVER_PRIVILEGED_DORMANT", "UNENTITLED_SHADOW"}
    for item in result.access_breakdown:
        assert item.source_id is not None
        assert item.target_id is not None
        assert item.status in valid_statuses
        assert item.recommendation is not None


def test_centrality_analytics_service_execution():
    """Validates that CentralityAnalyticsService computes PageRank and Brandes' Betweenness Centrality."""
    client = get_graphops_client()
    service = CentralityAnalyticsService(client=client)
    result = service.analyze_graph_centrality(top_k=10)

    assert isinstance(result, CentralityAnalysisResult)
    assert result.total_nodes_analyzed > 0
    assert result.total_edges_analyzed > 0
    assert len(result.network_bridge_nodes) > 0
    assert len(result.top_disruption_nodes) > 0

    # Ensure Betweenness and PageRank scores are mathematically valid
    for metric in result.network_bridge_nodes:
        assert metric.node_id is not None
        assert metric.betweenness >= 0.0
        assert 0.0 <= metric.pagerank <= 1.0
        assert 0.0 <= metric.disruption_score <= 100.0

    # Top bridge node in our enterprise graph should be the central server application
    top_bridge = result.network_bridge_nodes[0]
    assert top_bridge.node_id == "server:srv-app-01"
    assert top_bridge.betweenness > 0.0


def test_api_zero_trust_and_centrality_endpoints():
    """Tests the new REST endpoints via FastAPI TestClient."""
    test_client = TestClient(app)

    # 1. GET /api/v1/graphops/zero-trust/audit
    res_zt = test_client.get("/api/v1/graphops/zero-trust/audit")
    assert res_zt.status_code == 200
    zt_data = res_zt.json()
    assert "least_privilege_compliance_pct" in zt_data
    assert "access_breakdown" in zt_data
    assert len(zt_data["access_breakdown"]) > 0
    assert "total_entitled_permissions" in zt_data
    assert "dormant_overprivileged_permissions" in zt_data
    assert "unentitled_shadow_connections" in zt_data

    # 2. GET /api/v1/graphops/centrality
    res_cent = test_client.get("/api/v1/graphops/centrality")
    assert res_cent.status_code == 200
    cent_data = res_cent.json()
    assert "total_nodes_analyzed" in cent_data
    assert "total_edges_analyzed" in cent_data
    assert "network_bridge_nodes" in cent_data
    assert "top_disruption_nodes" in cent_data
    assert len(cent_data["network_bridge_nodes"]) > 0
    assert cent_data["network_bridge_nodes"][0]["node_id"] == "server:srv-app-01"
