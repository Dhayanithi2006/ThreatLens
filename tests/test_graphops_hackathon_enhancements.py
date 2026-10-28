"""
ThreatLens - Hackathon Enhancements Test Suite
Validates:
1. Community Detection Engine: Modularity clustering, security enclaves, cross-boundary transitions.
2. Alert Consolidation Engine: Raw alert reduction, kill-chain narrative synthesis, MITRE mapping.
3. Fast REST API Endpoints: /api/v1/graphops/communities and /api/v1/graphops/incident-narrative/{case_id}.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.communities import detect_security_communities
from backend.graphops.alert_consolidation import synthesize_incident_narrative


def test_community_detection_partitioning():
    """Validates that community detection clusters nodes into security enclaves and identifies boundary edges."""
    res = detect_security_communities()
    
    assert res.total_communities >= 3
    cluster_ids = {c.community_id for c in res.communities}
    assert "COMM-CROWN-JEWELS" in cluster_ids
    assert "COMM-DMZ-GATEWAYS" in cluster_ids
    assert "COMM-USER-ENDPOINTS" in cluster_ids

    # Modularity score must be positive and reasonable
    assert res.modularity_score > 0.4
    assert res.execution_time_ms > 0

    # Boundary edges must detect cross-tier pivots
    assert res.cross_boundary_edges_count > 0
    cross_tier_edges = [b for b in res.boundary_edges if b.is_cross_tier]
    assert len(cross_tier_edges) > 0

    # Ensure Crown Jewel enclaves flag critical assets
    cj_cluster = next(c for c in res.communities if c.community_id == "COMM-CROWN-JEWELS")
    assert cj_cluster.critical_asset_count > 0
    assert cj_cluster.risk_level == "CRITICAL"


def test_incident_narrative_alert_reduction():
    """Validates that raw alert storm is compressed into a single cohesive incident narrative."""
    res = synthesize_incident_narrative("MT-101")
    
    assert res.case_reference == "MT-101"
    assert res.raw_alerts_count >= 10
    assert res.consolidated_incidents_count == 1
    assert res.alert_noise_reduction_pct >= 85.0
    assert res.time_to_reconstruct_ms > 0

    # Validate kill chain progression
    tactics = [step.mitre_tactic for step in res.kill_chain_steps]
    assert "Initial Access" in tactics
    assert "Execution" in tactics
    assert "Lateral Movement" in tactics

    # Validate primary choke point recommendation
    assert res.primary_choke_point is not None
    assert "containment" in res.recommended_action.lower()


def test_api_endpoints_hackathon_enhancements():
    """Tests the new REST endpoints via FastAPI TestClient."""
    client = TestClient(app)

    # 1. GET /api/v1/graphops/communities
    res_comm = client.get("/api/v1/graphops/communities")
    assert res_comm.status_code == 200
    comm_data = res_comm.json()
    assert comm_data["total_communities"] >= 3
    assert len(comm_data["boundary_edges"]) > 0

    # 2. GET /api/v1/graphops/incident-narrative/{case_id}
    res_narr = client.get("/api/v1/graphops/incident-narrative/MT-101")
    assert res_narr.status_code == 200
    narr_data = res_narr.json()
    assert narr_data["incident_id"] == "INC-MT-101"
    assert narr_data["alert_noise_reduction_pct"] > 80.0
    assert len(narr_data["kill_chain_steps"]) >= 4
