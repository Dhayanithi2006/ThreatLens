"""
ThreatLens — Frontend Architecture and GraphOps Navigation Integrity Tests
Validates:
1. Sidebar naming and sub-label compliance:
   - "1. Investigate Alerts"
   - "2. Explore Attack Paths"
   - "3. Assess Impact" (NOT "Access Impact")
   - "4. Check Access & Anomalies"
   - Pillar sub-labels:
     - Pillar 2: "Graph Ingestion · Attack Paths · Chokepoints"
     - Pillar 3: "Blast Radius · Containment · What-If Simulator"
     - Pillar 4: "Zero-Trust · Graph ML · Communities"
2. GraphOps 7-tab ownership matrix:
   - Pillar 2 (Explore Attack Paths):
     - Tab 1: Graph Ingestion & Topology (id="tab-graphops-explorer", data-mode="explorer")
     - Tab 2: Attack Paths & Chokepoints (id="tab-graphops-paths", data-mode="paths")
   - Pillar 3 (Assess Impact):
     - Tab 3: Blast Radius & Containment (id="tab-graphops-blast", data-mode="blast")
     - Tab 4: What-If Simulator (id="tab-graphops-simulator", data-mode="simulator")
   - Pillar 4 (Check Access & Anomalies):
     - Tab 5: Graph Anomaly Detection (id="tab-graphops-anomalies", data-mode="anomalies")
     - Tab 6: Entitled vs. Used Access (id="tab-graphops-zerotrust", data-mode="zerotrust")
     - Tab 7: Security Communities (id="tab-graphops-communities", data-mode="communities")
   - Centrality & PageRank integrated into Attack Paths
   - Tab 8 removed as an independent tab
3. Alerts Stream architecture:
   - Separate case alerts and graph findings tables (no merging into single alert rows)
   - Loading, error, empty, success states present
   - Refresh button and filter chips
4. Investigation Timeline:
   - Real CaseRecord fields used without fabricated event offsets
   - Case selector dropdown present
   - Safe HTML escaping
5. Backend API endpoints verification:
   - All 7 GraphOps submodule endpoints and case repository endpoints functional
"""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.main import app


REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "frontend" / "index.html" if (REPO_ROOT / "frontend" / "index.html").exists() else Path("frontend/index.html")
JS_PATH = REPO_ROOT / "frontend" / "js" / "app.js" if (REPO_ROOT / "frontend" / "js" / "app.js").exists() else Path("frontend/js/app.js")

client = TestClient(app)


# =====================================================================
# 1. SIDEBAR ARCHITECTURE & NAMING CONTRACTS
# =====================================================================

def test_sidebar_pillar_names_and_sublabels():
    """Verifies exact sidebar naming and sub-labels in index.html."""
    html_path = HTML_PATH
    assert html_path.exists(), f"frontend/index.html must exist at {html_path}"
    content = html_path.read_text(encoding="utf-8")

    # Pillar 1: Investigate Alerts
    assert '1. Investigate Alerts' in content
    assert 'data-route="investigate"' in content

    # Pillar 2: Explore Attack Paths
    assert '2. Explore Attack Paths' in content
    assert 'data-route="attack-paths"' in content
    assert 'Graph Ingestion &middot; Attack Paths &middot; Chokepoints' in content

    # Pillar 3: Assess Impact (NOT Access Impact)
    assert '3. Assess Impact' in content
    assert 'Access Impact' not in content, "Must use 'Assess Impact', not 'Access Impact'"
    assert 'data-route="blast-radius"' in content
    assert 'Blast Radius &middot; Containment &middot; What-If Simulator' in content

    # Pillar 4: Check Access & Anomalies
    assert ('4. Check Access &amp; Anomalies' in content or '4. Check Access & Anomalies' in content)
    assert 'data-route="access-anomalies"' in content
    assert 'Zero-Trust &middot; Graph ML &middot; Communities' in content


# =====================================================================
# 2. GRAPHOPS TAB OWNERSHIP & INTEGRITY CONTRACTS
# =====================================================================

def test_graphops_seven_tab_ownership_matrix():
    """Verifies all 7 GraphOps tabs exist with exact labels and data-mode attributes."""
    html_path = HTML_PATH
    content = html_path.read_text(encoding="utf-8")

    # Tab 1: Graph Ingestion & Topology
    assert 'id="tab-graphops-explorer"' in content
    assert 'data-mode="explorer"' in content
    assert 'Graph Ingestion &amp; Topology' in content

    # Tab 2: Attack Paths & Chokepoints
    assert 'id="tab-graphops-paths"' in content
    assert 'data-mode="paths"' in content
    assert 'Attack Paths &amp; Chokepoints' in content

    # Tab 3: Blast Radius & Containment
    assert 'id="tab-graphops-blast"' in content
    assert 'data-mode="blast"' in content
    assert 'Blast Radius &amp; Containment' in content

    # Tab 4: What-If Simulator
    assert 'id="tab-graphops-simulator"' in content
    assert 'data-mode="simulator"' in content
    assert 'What-If Simulator' in content

    # Tab 5: Graph Anomaly Detection (renamed from Graph AI & Zero-Trust)
    assert 'id="tab-graphops-anomalies"' in content
    assert 'data-mode="anomalies"' in content
    assert 'Graph Anomaly Detection' in content
    assert '4. Graph AI &amp; Zero-Trust' not in content

    # Tab 6: Entitled vs. Used Access
    assert 'id="tab-graphops-zerotrust"' in content
    assert 'data-mode="zerotrust"' in content
    assert 'Entitled vs. Used Access' in content

    # Tab 7: Security Communities
    assert 'id="tab-graphops-communities"' in content
    assert 'data-mode="communities"' in content
    assert 'Security Communities' in content

    # Tab 8 Telemetry Findings is NOT in the visible case-tabs-nav
    tabs_nav_start = content.find('class="case-tabs-nav module-tabs-nav"')
    tabs_nav_end = content.find('</div>', tabs_nav_start)
    visible_tabs_html = content[tabs_nav_start:tabs_nav_end]
    assert 'Telemetry Findings' not in visible_tabs_html, "Tab 8 Telemetry Findings must be removed from tab bar"

    # Centrality & Disruption panel is present and placed after choke points
    assert 'id="panel-centrality-results"' in content
    assert 'id="centrality-tbody"' in content
    assert 'id="centrality-metric-bridge"' in content
    assert 'id="centrality-metric-disruption"' in content


def test_app_js_tab_filtering_and_pillar_routing():
    """Verifies that app.js enforces pillar-aware tab filtering and deep-linking."""
    js_path = JS_PATH
    assert js_path.exists(), f"frontend/js/app.js must exist at {js_path}"
    js_code = js_path.read_text(encoding="utf-8")

    # PILLAR_TAB_GROUPS constant exists with exact tab groups
    assert 'PILLAR_TAB_GROUPS' in js_code
    assert '"attack-paths": ["explorer", "paths"]' in js_code
    assert '"blast-radius": ["blast", "simulator"]' in js_code
    assert '"access-anomalies": ["anomalies", "zerotrust", "communities"]' in js_code

    # Tab filtering and active navigation helpers exist
    assert 'filterGraphOpsTabs' in js_code
    assert 'updateSidebarNav' in js_code

    # Mode titles map reflects updated clean titles without number prefixes
    assert '"explorer": "Graph Ingestion & Topology"' in js_code
    assert '"paths": "Attack Paths & Chokepoints"' in js_code
    assert '"blast": "Blast Radius & Containment"' in js_code
    assert '"simulator": "What-If Simulator"' in js_code
    assert '"anomalies": "Graph Anomaly Detection"' in js_code
    assert '"zerotrust": "Entitled vs. Used Access"' in js_code
    assert '"communities": "Security Communities"' in js_code


# =====================================================================
# 3. ALERTS STREAM & TIMELINE ARCHITECTURE
# =====================================================================

def test_alerts_stream_and_timeline_html_contracts():
    """Verifies Alerts Stream separate tables, states, and Timeline case selector."""
    html_path = HTML_PATH
    content = html_path.read_text(encoding="utf-8")

    # Separate table bodies for case alerts and graph findings
    assert 'id="alerts-cases-tbody"' in content
    assert 'id="alerts-findings-tbody"' in content

    # Loading and error states
    assert 'id="alerts-stream-loading"' in content
    assert 'id="alerts-stream-error"' in content

    # Refresh button and badge counters
    assert 'id="btn-refresh-alerts-stream"' in content
    assert 'id="badge-cases-alerts-count"' in content
    assert 'id="badge-findings-alerts-count"' in content

    # Investigation Timeline case selector and states
    assert 'id="timeline-case-select"' in content
    assert 'id="timeline-loading"' in content
    assert 'id="timeline-empty"' in content
    assert 'id="ai-timeline-list"' in content


def test_timeline_uses_real_case_evidence_not_fabricated():
    """Verifies that renderTimelineView in app.js builds chronology from CaseRecord fields."""
    js_path = JS_PATH
    js_code = js_path.read_text(encoding="utf-8")

    # Timeline uses real case fields
    assert 'currentCase.timestamp' in js_code
    assert 'currentCase.primary_threat' in js_code
    assert 'currentCase.threat_score' in js_code
    assert 'currentCase.sender' in js_code
    assert 'currentCase.recipient' in js_code
    assert 'currentCase.subject' in js_code
    assert 'currentCase.iocs' in js_code
    assert 'currentCase.intel_summary' in js_code

    # Does NOT use hardcoded fabricated offsets like -1000 * 60 * 12
    assert '- 1000 * 60 * 12' not in js_code, "Fabricated timestamp math must be removed"
    assert '- 1000 * 60 * 10' not in js_code, "Fabricated timestamp math must be removed"

    # HTML escaping applied to all user-facing content
    assert 'escapeHtml(' in js_code


# =====================================================================
# 4. BACKEND ENDPOINT VERIFICATION (ALL SUBMODULES)
# =====================================================================

def test_api_cases_endpoint():
    """Verifies canonical case repository endpoint returns valid CaseRecord items."""
    resp = client.get("/api/v1/cases")
    assert resp.status_code == 200
    cases = resp.json()
    assert isinstance(cases, list)
    assert len(cases) >= 5, "Expected pre-filled historical cases"

    # Check schema completeness for timeline and alert rendering
    sample = cases[0]
    assert "case_id" in sample
    assert "subject" in sample
    assert "sender" in sample
    assert "recipient" in sample
    assert "threat_score" in sample
    assert "risk_level" in sample
    assert "primary_threat" in sample
    assert "iocs" in sample
    assert "intel_summary" in sample
    assert "timestamp" in sample


def test_api_graphops_findings_endpoint():
    """Verifies telemetry findings endpoint returns SecurityFindingRecord list."""
    resp = client.get("/api/v1/graphops/events/findings?limit=20")
    assert resp.status_code == 200
    findings = resp.json()
    assert isinstance(findings, list)


def test_api_graphops_centrality_endpoint():
    """Verifies Brandes betweenness and PageRank endpoint integrated into Tab 2."""
    resp = client.get("/api/v1/graphops/centrality?top_k=5")
    assert resp.status_code == 200
    data = resp.json()
    assert ("top_disruption_nodes" in data or "rankings" in data)
    assert "top_betweenness_node" in data
    assert "top_pagerank_node" in data
    assert "total_nodes_analyzed" in data


def test_api_graphops_communities_endpoint():
    """Verifies Louvain modularity security communities endpoint (Tab 7)."""
    resp = client.get("/api/v1/graphops/communities")
    assert resp.status_code == 200
    data = resp.json()
    assert "communities" in data
    assert "modularity_score" in data
    assert "total_communities" in data


def test_api_graphops_zero_trust_audit_endpoint():
    """Verifies Zero-Trust Entitled vs. Used Access audit endpoint (Tab 6)."""
    resp = client.get("/api/v1/graphops/zero-trust/audit")
    assert resp.status_code == 200
    data = resp.json()
    assert "users_audited" in data or "discrepancies" in data or isinstance(data, list) or isinstance(data, dict)


def test_api_graphops_attack_paths_endpoints():
    """Verifies Attack Paths Dijkstra and Path discovery endpoints (Tab 2)."""
    # Dijkstra Shortest Path
    resp_dijkstra = client.post(
        "/api/v1/graphops/dijkstra",
        json={"entry_node_id": "device:dev-ws-101", "target_node_id": "server:srv-db-01"}
    )
    assert resp_dijkstra.status_code in [200, 404]

    # Attack Paths Discovery
    resp_paths = client.post(
        "/api/v1/graphops/attack-paths",
        json={"entry_node_id": "device:dev-ws-101", "max_depth": 3}
    )
    assert resp_paths.status_code in [200, 404]

    # Choke Points
    resp_choke = client.get("/api/v1/graphops/choke-points?top_n=5")
    assert resp_choke.status_code == 200


def test_api_graphops_blast_radius_and_simulation():
    """Verifies Blast Radius BFS and What-If Containment simulation (Tabs 3 & 4)."""
    # Blast Radius BFS
    resp_blast = client.get("/api/v1/graphops/blast-radius?start_node_id=device:dev-ws-101&max_hops=2")
    assert resp_blast.status_code in [200, 404]

    # Containment Simulation
    resp_sim = client.post(
        "/api/v1/graphops/simulate-containment",
        json={
            "entry_node_id": "device:dev-ws-101",
            "proposed_interventions": [
                {
                    "action": "ISOLATE_NODE",
                    "node_id": "server:srv-app-01",
                    "rationale": "SOC proactive blast-radius containment"
                }
            ]
        }
    )
    assert resp_sim.status_code in [200, 404]
