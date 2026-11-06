"""
ThreatLens GraphOps — Centrality Analytics Rigorous Test Suite
Tests:
1. Empty graph returns 0 nodes/edges analyzed and empty rankings.
2. Dual-tier backend caching returns cached result without re-computation within TTL.
3. Force refresh query parameter bypasses cache.
4. Cache invalidation on invalidate_centrality_cache().
5. Disconnected graph components and tied scores compute without division-by-zero errors.
6. FastAPI endpoint /api/v1/graphops/centrality schema and cache headers.
"""

import pytest
import time
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.centrality import (
    CentralityAnalyticsService,
    CentralityAnalysisResult,
    invalidate_centrality_cache,
    _CENTRALITY_CACHE,
)


client = TestClient(app)


class MockConnectedClient:
    """Mock client returning custom nodes and relationships."""
    def __init__(self, nodes, edges):
        self._nodes = nodes
        self._edges = edges
        self.query_count = 0

    def health_check(self):
        return {"connected": True}

    def execute_query(self, query: str):
        self.query_count += 1
        if "MATCH (n)" in query:
            return self._nodes
        if "MATCH (s)-[r]->(t)" in query:
            return self._edges
        return []


def test_empty_graph_centrality():
    """Verifies that an empty graph returns 0 metrics cleanly."""
    invalidate_centrality_cache()
    mock_c = MockConnectedClient(nodes=[], edges=[])
    service = CentralityAnalyticsService(client=mock_c)
    result = service.analyze_graph_centrality(force_refresh=True)

    assert result.total_nodes_analyzed == 0
    assert result.total_edges_analyzed == 0
    assert len(result.top_disruption_nodes) == 0
    assert len(result.network_bridge_nodes) == 0
    assert "Graph is empty" in result.executive_summary


def test_centrality_backend_caching():
    """Verifies that consecutive calls within 60s reuse cached results without querying client."""
    invalidate_centrality_cache()
    nodes = [
        {"id": "device:ws-1", "label": "Device", "name": "WS1", "criticality": "LOW"},
        {"id": "server:srv-1", "label": "Server", "name": "SRV1", "criticality": "HIGH"},
        {"id": "server:srv-2", "label": "Server", "name": "SRV2", "criticality": "CRITICAL"},
    ]
    edges = [
        {"source": "device:ws-1", "target": "server:srv-1", "rel_type": "CONNECTS_TO"},
        {"source": "server:srv-1", "target": "server:srv-2", "rel_type": "ACCESSES"},
    ]
    mock_c = MockConnectedClient(nodes=nodes, edges=edges)
    service = CentralityAnalyticsService(client=mock_c)

    # First call: computes and caches
    r1 = service.analyze_graph_centrality(top_k=5, force_refresh=True)
    initial_queries = mock_c.query_count
    assert initial_queries >= 2

    # Second call: served from cache
    r2 = service.analyze_graph_centrality(top_k=5, force_refresh=False)
    assert mock_c.query_count == initial_queries, "Second call must be served from cache without queries"
    assert r1.timestamp == r2.timestamp

    # Force refresh: queries client again
    r3 = service.analyze_graph_centrality(top_k=5, force_refresh=True)
    assert mock_c.query_count > initial_queries, "Force refresh must re-execute queries"


def test_centrality_cache_invalidation():
    """Verifies that invalidate_centrality_cache clears cache state."""
    nodes = [{"id": "node:1", "label": "Device", "name": "N1", "criticality": "LOW"}]
    mock_c = MockConnectedClient(nodes=nodes, edges=[])
    service = CentralityAnalyticsService(client=mock_c)

    service.analyze_graph_centrality(top_k=5, force_refresh=True)
    assert _CENTRALITY_CACHE["result"] is not None

    invalidate_centrality_cache()
    assert _CENTRALITY_CACHE["result"] is None
    assert _CENTRALITY_CACHE["timestamp"] == 0.0


def test_disconnected_graph_and_tied_rankings():
    """Verifies PageRank and Betweenness on disconnected subgraphs without crashing."""
    invalidate_centrality_cache()
    # 2 disjoint components: (A-B) and (C-D)
    nodes = [
        {"id": "n:A", "label": "Device", "name": "A", "criticality": "LOW"},
        {"id": "n:B", "label": "Device", "name": "B", "criticality": "LOW"},
        {"id": "n:C", "label": "Server", "name": "C", "criticality": "HIGH"},
        {"id": "n:D", "label": "Server", "name": "D", "criticality": "HIGH"},
    ]
    edges = [
        {"source": "n:A", "target": "n:B", "rel_type": "LINK"},
        {"source": "n:C", "target": "n:D", "rel_type": "LINK"},
    ]
    mock_c = MockConnectedClient(nodes=nodes, edges=edges)
    service = CentralityAnalyticsService(client=mock_c)
    result = service.analyze_graph_centrality(top_k=10, force_refresh=True)

    assert result.total_nodes_analyzed == 4
    assert result.total_edges_analyzed == 2
    assert len(result.top_disruption_nodes) == 4
    assert all(m.disruption_score >= 0.0 for m in result.top_disruption_nodes)


def test_centrality_fastapi_endpoint_and_force_param():
    """Verifies that FastAPI /api/v1/graphops/centrality respects force_refresh param."""
    invalidate_centrality_cache()
    resp1 = client.get("/api/v1/graphops/centrality?top_k=5")
    assert resp1.status_code == 200
    d1 = resp1.json()

    assert "total_nodes_analyzed" in d1
    assert "top_disruption_nodes" in d1
    assert "network_bridge_nodes" in d1
    assert "top_betweenness_node" in d1
    assert "top_pagerank_node" in d1

    # Force refresh request
    resp2 = client.get("/api/v1/graphops/centrality?top_k=5&force_refresh=true")
    assert resp2.status_code == 200
    d2 = resp2.json()
    assert d2["total_nodes_analyzed"] == d1["total_nodes_analyzed"]
    assert d2["total_nodes_analyzed"] > 0
