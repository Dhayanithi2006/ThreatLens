"""
ThreatLens GraphOps - Phase 7 Integration Test Suite
Verifies:
1. Unified Tri-Detector Findings Stream API (Kafka-triggered rule, scikit-learn ML, PyG GNN findings).
2. Dijkstra minimum-cost shortest path endpoints (/shortest-path and /dijkstra alias).
3. PyG structural relationship evaluation endpoint (/events/pyg/evaluate).
4. Multi-engine status and health monitoring endpoints.
5. Frontend HTML, CSS, and JavaScript contract integrity for the unified analyst workspace.
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app
from backend.graphops.client import get_graphops_client
from backend.graphops.mock_client import get_mock_graphops_client
from backend.graphops.kafka_producer import GraphOpsKafkaProducer
from backend.graphops.kafka_processor import GraphOpsEventProcessor
from backend.graphops.kafka_worker import GraphOpsKafkaWorker
from backend.api.graphops_routes import get_kafka_producer_dep, get_kafka_worker_dep
from backend.models.graphops import (
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
    PyGEvaluateRequest,
)


def build_phase7_fixture_mock():
    """Returns in-memory mock client preloaded with enterprise fixture for tests."""
    return get_mock_graphops_client()


@pytest.fixture
def test_client():
    """Provides a TestClient with dependency override to the in-memory mock graph and streaming pipeline."""
    mock_cli = get_mock_graphops_client()
    mock_prod = GraphOpsKafkaProducer(mock_mode=True)
    mock_proc = GraphOpsEventProcessor(client=mock_cli, producer=mock_prod)
    mock_worker = GraphOpsKafkaWorker(processor=mock_proc, producer=mock_prod, mock_mode=True)

    app.dependency_overrides[get_graphops_client] = lambda: mock_cli
    app.dependency_overrides[get_kafka_producer_dep] = lambda: mock_prod
    app.dependency_overrides[get_kafka_worker_dep] = lambda: mock_worker
    client = TestClient(app)
    yield client
    app.dependency_overrides.pop(get_graphops_client, None)
    app.dependency_overrides.pop(get_kafka_producer_dep, None)
    app.dependency_overrides.pop(get_kafka_worker_dep, None)


# =====================================================================
# 1. DIJKSTRA ENDPOINT TESTS & ALIASES
# =====================================================================

def test_fastapi_dijkstra_post_endpoint(test_client):
    """Verifies POST /api/v1/graphops/dijkstra and /api/v1/graphops/shortest-path."""
    payload = {
        "entry_node_id": "device:dev-ws-101",
        "target_node_id": "critical:crit-db-financial",
        "include_hypothetical": True,
    }

    # Test alias
    resp_alias = test_client.post("/api/v1/graphops/dijkstra", json=payload)
    assert resp_alias.status_code == 200
    data_alias = resp_alias.json()
    assert "path_found" in data_alias
    assert "total_cost" in data_alias
    assert "hop_count" in data_alias
    assert "nodes" in data_alias
    assert "steps" in data_alias

    # Test canonical
    resp_canon = test_client.post("/api/v1/graphops/shortest-path", json=payload)
    assert resp_canon.status_code == 200
    data_canon = resp_canon.json()

    assert data_alias["path_found"] == data_canon["path_found"]
    assert data_alias["total_cost"] == data_canon["total_cost"]


def test_fastapi_dijkstra_get_endpoint(test_client):
    """Verifies GET /api/v1/graphops/dijkstra with query parameters."""
    resp = test_client.get(
        "/api/v1/graphops/dijkstra?entry_node_id=device:dev-ws-101&target_node_id=critical:crit-db-financial&include_hypothetical=true"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["path_found"] is True
    assert data["total_cost"] is not None
    assert data["total_cost"] > 0
    assert len(data["steps"]) > 0


# =====================================================================
# 2. EVENT STREAMING SIMULATION & TRI-DETECTOR FINDINGS
# =====================================================================

def test_fastapi_simulate_compromise_indicator_event(test_client):
    """Verifies POST /api/v1/graphops/events/simulate?scenario=COMPROMISE_INDICATOR."""
    resp = test_client.post("/api/v1/graphops/events/simulate?scenario=COMPROMISE_INDICATOR")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert "event_published" in data
    assert "event_id" in data["event_published"]
    assert data["findings_generated_count"] >= 1
    assert len(data["findings"]) >= 1

    # Verify structured fields of returned finding
    finding = data["findings"][0]
    assert "finding_id" in finding
    assert "analysis_type" in finding
    assert "affected_entity_id" in finding
    assert "severity" in finding
    assert "title" in finding
    assert "summary" in finding


def test_fastapi_simulate_identity_logon_event(test_client):
    """Verifies POST /api/v1/graphops/events/simulate?scenario=IDENTITY_LOGON."""
    resp = test_client.post("/api/v1/graphops/events/simulate?scenario=IDENTITY_LOGON")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert "event_published" in data
    assert "event_id" in data["event_published"]


def test_fastapi_simulate_network_connection_event(test_client):
    """Verifies POST /api/v1/graphops/events/simulate?scenario=NETWORK_CONNECTION."""
    resp = test_client.post("/api/v1/graphops/events/simulate?scenario=NETWORK_CONNECTION")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert "event_published" in data
    assert "event_id" in data["event_published"]


def test_fastapi_get_event_findings(test_client):
    """Verifies GET /api/v1/graphops/events/findings returns structured findings."""
    # First inject an event to guarantee findings exist
    test_client.post("/api/v1/graphops/events/simulate?scenario=COMPROMISE_INDICATOR")

    resp = test_client.get("/api/v1/graphops/events/findings?limit=20")
    assert resp.status_code == 200
    findings = resp.json()
    assert isinstance(findings, list)
    assert len(findings) > 0

    first = findings[0]
    assert "finding_id" in first
    assert "analysis_type" in first
    assert "affected_entity_id" in first
    assert "severity" in first


# =====================================================================
# 3. PYG STRUCTURAL EVALUATION ENDPOINT
# =====================================================================

def test_fastapi_pyg_evaluate_endpoint(test_client):
    """Verifies POST /api/v1/graphops/events/pyg/evaluate."""
    payload = {
        "source_entity_id": "device:dev-ws-101",
        "target_entity_id": "server:srv-app-01",
        "relationship_type": "NETWORK_CONNECTION",
    }
    resp = test_client.post("/api/v1/graphops/events/pyg/evaluate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "structural_anomaly_score" in data
    assert "predicted_plausibility" in data
    assert "is_anomaly" in data
    assert "model_name" in data
    assert 0.0 <= data["structural_anomaly_score"] <= 100.0


def test_fastapi_pyg_status_endpoint(test_client):
    """Verifies GET /api/v1/graphops/events/pyg/status."""
    resp = test_client.get("/api/v1/graphops/events/pyg/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_name" in data
    assert "device" in data
    assert "threshold" in data


# =====================================================================
# 4. HEALTH MONITORING ENDPOINTS
# =====================================================================

def test_fastapi_all_engine_health_endpoints(test_client):
    """Verifies all five engine health endpoints required by the topbar."""
    resp_core = test_client.get("/api/v1/health")
    assert resp_core.status_code == 200

    resp_graph = test_client.get("/api/v1/graphops/health")
    assert resp_graph.status_code == 200

    resp_kafka = test_client.get("/api/v1/graphops/events/status")
    assert resp_kafka.status_code == 200

    resp_ml = test_client.get("/api/v1/graphops/events/ml/status")
    assert resp_ml.status_code == 200

    resp_pyg = test_client.get("/api/v1/graphops/events/pyg/status")
    assert resp_pyg.status_code == 200


# =====================================================================
# 5. FRONTEND CONTRACT INTEGRITY TESTS
# =====================================================================

def test_frontend_html_contracts():
    """Verifies required Phase 7 UI element IDs and data attributes exist in index.html."""
    html_path = Path("frontend/index.html")
    assert html_path.exists(), "frontend/index.html must exist"
    content = html_path.read_text(encoding="utf-8")


    # GraphOps mode tabs
    assert 'id="tab-graphops-blast"' in content
    assert 'id="tab-graphops-paths"' in content
    assert 'id="tab-graphops-simulator"' in content
    assert 'id="tab-graphops-anomalies"' in content
    assert 'id="tab-graphops-communities"' in content
    assert 'id="tab-graphops-findings"' in content
    assert 'id="badge-findings-count"' in content

    # Controls
    assert 'id="controls-group-path-algo"' in content
    assert 'id="graphops-path-algo-select"' in content
    assert 'id="controls-group-findings-scenario"' in content
    assert 'id="graphops-simulate-scenario-select"' in content

    # Inspector actions
    assert 'id="insp-actions-box"' in content
    assert 'id="btn-insp-action-blast"' in content
    assert 'id="btn-insp-action-dijkstra"' in content
    assert 'id="btn-insp-action-isolate"' in content
    assert 'id="btn-insp-action-pyg"' in content

    # Findings Panel & Table
    assert 'id="panel-findings-results"' in content
    assert 'id="findings-filter-chips"' in content
    assert 'id="findings-severity-filter"' in content
    assert 'id="findings-tbody"' in content
    assert 'id="btn-refresh-findings"' in content
    assert 'id="btn-simulate-event-action"' in content

    # Finding Detail Modal
    assert 'id="modal-finding-detail"' in content
    assert 'id="finding-modal-title"' in content
    assert 'id="finding-modal-engine"' in content
    assert 'id="finding-modal-severity-badge"' in content
    assert 'id="finding-modal-source-badge"' in content
    assert 'id="finding-modal-entity"' in content
    assert 'id="finding-modal-details-container"' in content


def test_frontend_css_contracts():
    """Verifies required Phase 7 CSS classes exist in styles.css."""
    css_path = Path("frontend/css/styles.css")
    assert css_path.exists(), "frontend/css/styles.css must exist"
    content = css_path.read_text(encoding="utf-8")

    assert ".detector-pill" in content
    assert ".detector-rule" in content
    assert ".detector-sklearn" in content
    assert ".detector-pyg" in content
    assert ".detector-dijkstra" in content
    assert ".detector-blast" in content
    assert ".finding-row-new" in content


def test_frontend_js_contracts():
    """Verifies required Phase 7 functions and state variables exist in app.js."""
    js_path = Path("frontend/js/app.js")
    assert js_path.exists(), "frontend/js/app.js must exist"
    content = js_path.read_text(encoding="utf-8")

    # State properties
    assert "graphOpsLastDijkstra:" in content
    assert "findingsList:" in content
    assert "findingsFilter:" in content
    assert "findingsSeverityFilter:" in content

    # Functions
    assert "runDijkstraShortestPath" in content
    assert "renderDijkstraBreakdown" in content
    assert "fetchAndRenderFindings" in content
    assert "renderFindingsTableRows" in content
    assert "simulateStreamingSecurityEvent" in content
    assert "openFindingDetailModal" in content
    assert "closeFindingDetailModal" in content
    assert "evaluatePyGRelationship" in content
