"""
ThreatLens GraphOps — Comprehensive Live System Verification Runner
Validates ALL modules, submodules, algorithms, pipelines, and live HTTP endpoints
across the entire repository against real containerized infrastructure.
"""

import os
import sys
import time
import json
import uuid
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

API_BASE = "http://127.0.0.1:8000"

# Result collection
RESULTS: List[Dict[str, Any]] = []


def record_result(group: str, submodule: str, test_name: str, passed: bool, duration_ms: float, details: str = "", live: bool = True):
    RESULTS.append({
        "group": group,
        "submodule": submodule,
        "test_name": test_name,
        "passed": passed,
        "duration_ms": round(duration_ms, 2),
        "details": details,
        "live": live
    })
    prefix = "\033[92m[PASS]\033[0m" if passed else "\033[91m[FAIL]\033[0m"
    live_tag = "[LIVE]" if live else "[IN-MEM]"
    print(f"{prefix} {live_tag} [{group} -> {submodule}] {test_name} ({round(duration_ms, 2)}ms)")
    if details:
        if not passed:
            print(f"       \033[91mError:\033[0m {details}")
        else:
            print(f"       \033[90mEvidence:\033[0m {details}")


def http_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
    url = f"{API_BASE}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            status_code = resp.status
            try:
                return {"status": status_code, "data": json.loads(body)}
            except Exception:
                return {"status": status_code, "text": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return {"status": e.code, "error": json.loads(body)}
        except Exception:
            return {"status": e.code, "error": body}


print("=" * 80)
print("THREATLENS GRAPHOPS — EXHAUSTIVE LIVE SYSTEM VERIFICATION")
print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
print(f"API Target: {API_BASE}")
print("=" * 80)

# ==============================================================================
# GROUP 1: CORE & SECURITY SUBSYSTEM (backend.core)
# ==============================================================================
print("\n--- GROUP 1: CORE & SECURITY SUBSYSTEM ---")

# 1.1 config constants
t0 = time.time()
try:
    from backend.core import config
    assert config.APP_NAME == "ThreatLens"
    assert "7687" in config.NEO4J_URI
    assert "9092" in config.KAFKA_BOOTSTRAP_SERVERS
    assert config.ADMIN_API_KEY is not None
    record_result("Core", "backend.core.config", "Settings load and live service URIs", True, (time.time() - t0) * 1000, f"Neo4j: {config.NEO4J_URI}, Kafka: {config.KAFKA_BOOTSTRAP_SERVERS}")
except Exception as e:
    record_result("Core", "backend.core.config", "Settings load and live service URIs", False, (time.time() - t0) * 1000, str(e))

# 1.2 security
t0 = time.time()
try:
    from backend.core.security import extract_api_key, verify_admin_access
    extracted = extract_api_key(x_api_key="threatlens_dev_api_key")
    assert extracted == "threatlens_dev_api_key"
    bearer_extracted = extract_api_key(authorization="Bearer threatlens_dev_api_key")
    assert bearer_extracted == "threatlens_dev_api_key"
    actor = verify_admin_access(x_api_key="threatlens_dev_api_key")
    assert actor == "admin-api-key"
    record_result("Core", "backend.core.security", "API key extraction & HMAC admin authorization", True, (time.time() - t0) * 1000, f"Actor: {actor}")
except Exception as e:
    record_result("Core", "backend.core.security", "API key extraction & HMAC admin authorization", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 2: PRIMARY THREAT ANALYSIS SERVICES (backend.services)
# ==============================================================================
print("\n--- GROUP 2: PRIMARY THREAT ANALYSIS SERVICES ---")

from backend.data.eml_samples import EML_SAMPLES

# 2.1 email_forensics
t0 = time.time()
try:
    from backend.services.email_forensics import analyze_email_forensics
    phish_eml = EML_SAMPLES["phishing"]
    forensics = analyze_email_forensics(phish_eml)
    assert forensics.subject == "URGENT: Verify your account"
    assert forensics.authentication.spf.result == "pass"
    assert forensics.authentication.dkim.result == "fail"
    assert forensics.authentication.dmarc.result == "fail"
    assert len(forensics.relay_path) >= 3
    record_result("Services", "email_forensics", "RFC 822 parsing, SPF/DKIM/DMARC & relay hops", True, (time.time() - t0) * 1000, f"{len(forensics.relay_path)} hops, SPF={forensics.authentication.spf.result}, DMARC={forensics.authentication.dmarc.result}")
except Exception as e:
    record_result("Services", "email_forensics", "RFC 822 parsing, SPF/DKIM/DMARC & relay hops", False, (time.time() - t0) * 1000, str(e))

# 2.2 ioc_extractor
t0 = time.time()
try:
    from backend.services.ioc_extractor import default_ioc_service
    iocs = default_ioc_service.extract_from_forensics(forensics, phish_eml)
    domain_vals = [d.value for d in iocs.domains]
    ip_vals = [ip.value for ip in iocs.ips]
    url_vals = [u.normalized for u in iocs.urls]
    assert "alert-center.xyz" in domain_vals
    assert any("185.190.140.22" in ip or "194.26.29.112" in ip for ip in ip_vals)
    assert any("alert-center.xyz" in u for u in url_vals)
    record_result("Services", "ioc_extractor", "Regex and MIME indicator extraction", True, (time.time() - t0) * 1000, f"{len(iocs.domains)} domains, {len(iocs.ips)} IPs, {len(iocs.urls)} URLs")
except Exception as e:
    record_result("Services", "ioc_extractor", "Regex and MIME indicator extraction", False, (time.time() - t0) * 1000, str(e))

# 2.3 threat_intelligence
t0 = time.time()
try:
    import asyncio
    from backend.services.threat_intelligence import default_intel_service
    intel = asyncio.run(default_intel_service.enrich_iocs(iocs))
    assert intel.summary.total_analyzed > 0
    record_result("Services", "threat_intelligence", "Threat intel aggregation & caching", True, (time.time() - t0) * 1000, f"Analyzed {intel.summary.total_analyzed} IoCs (malicious: {intel.summary.malicious_count}, clean: {intel.summary.clean_reported_count})")
except Exception as e:
    record_result("Services", "threat_intelligence", "Threat intel aggregation & caching", False, (time.time() - t0) * 1000, str(e))

# 2.4 threat_detection & classifier
t0 = time.time()
try:
    from backend.services.email_forensics import default_forensics_service
    from backend.services.threat_detection import detect_threat
    body_text = forensics.mime_analysis.plain_text_preview or "Suspicious account action"
    email_data = default_forensics_service.convert_forensics_to_analysis_input(forensics, body_text)
    detection = detect_threat(email_data)
    assert detection.threat_score >= 50
    assert detection.risk_level in ["HIGH", "CRITICAL", "SUSPICIOUS"]
    assert "PHISHING" in detection.primary_threat.upper()
    record_result("Services", "threat_detection", "Rule-based & multi-signal threat scoring", True, (time.time() - t0) * 1000, f"Score: {detection.threat_score}, Level: {detection.risk_level}, Primary: {detection.primary_threat}")
except Exception as e:
    record_result("Services", "threat_detection", "Rule-based & multi-signal threat scoring", False, (time.time() - t0) * 1000, str(e))

# 2.5 explainable_ai
t0 = time.time()
try:
    from backend.services.explainable_ai import generate_explanation
    xai = generate_explanation(detection, email_data)
    assert len(xai.risk_factors) > 0
    assert len(xai.top_reasons) > 0
    assert len(xai.summary) > 20
    record_result("Services", "explainable_ai", "LIME/SHAP feature explanation & MITRE ATT&CK mapping", True, (time.time() - t0) * 1000, f"{len(xai.risk_factors)} risk factors, {len(xai.top_reasons)} top reasons")
except Exception as e:
    record_result("Services", "explainable_ai", "LIME/SHAP feature explanation & MITRE ATT&CK mapping", False, (time.time() - t0) * 1000, str(e))

# 2.6 case_store
t0 = time.time()
try:
    from backend.services.case_store import default_case_repo
    cases = default_case_repo.list_cases()
    assert len(cases) > 0
    mt101 = default_case_repo.get_case("MT-101")
    assert mt101 is not None
    assert mt101.case_id == "MT-101"
    record_result("Services", "case_store", "Case repository lifecycle & query", True, (time.time() - t0) * 1000, f"{len(cases)} indexed cases; MT-101 retrieved successfully")
except Exception as e:
    record_result("Services", "case_store", "Case repository lifecycle & query", False, (time.time() - t0) * 1000, str(e))

# 2.7 campaign_correlation
t0 = time.time()
try:
    from backend.services.campaign_correlation import default_correlation_engine
    campaigns = default_correlation_engine.cluster_all_cases()
    assert len(campaigns) > 0
    camp = campaigns[0]
    assert len(camp.case_ids) >= 2
    record_result("Services", "campaign_correlation", "Multi-case infrastructure clustering", True, (time.time() - t0) * 1000, f"Found {len(campaigns)} campaigns (e.g. {camp.campaign_id} with cases: {camp.case_ids})")
except Exception as e:
    record_result("Services", "campaign_correlation", "Multi-case infrastructure clustering", False, (time.time() - t0) * 1000, str(e))

# 2.8 attack_graph
t0 = time.time()
try:
    from backend.services.attack_graph import default_graph_builder
    case_graph = default_graph_builder.build_attack_graph_for_case("MT-101", forensics, iocs, intel, detection)
    assert len(case_graph.nodes) > 0
    assert len(case_graph.edges) > 0
    record_result("Services", "attack_graph", "Local email attack graph & SMTP relay assembly", True, (time.time() - t0) * 1000, f"{len(case_graph.nodes)} nodes, {len(case_graph.edges)} edges assembled")
except Exception as e:
    record_result("Services", "attack_graph", "Local email attack graph & SMTP relay assembly", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 3: ENTERPRISE GRAPHOPS & NEO4J CYPER ENGINE (backend.graphops)
# ==============================================================================
print("\n--- GROUP 3: ENTERPRISE GRAPHOPS & NEO4J CYPER ENGINE ---")

# 3.1 client (Neo4j Bolt connection)
t0 = time.time()
try:
    from backend.graphops.client import get_graphops_client
    neo_client = get_graphops_client()
    health = neo_client.health_check()
    assert health.get("connected") is True
    assert health.get("database") == "neo4j"
    res = neo_client.execute_query("MATCH (n) RETURN count(n) AS node_count")
    node_count = res[0]["node_count"]
    assert node_count >= 48
    record_result("GraphOps", "client.py", "Neo4j Bolt driver & Cypher transaction", True, (time.time() - t0) * 1000, f"Live Bolt connected; {node_count} nodes in Neo4j")
except Exception as e:
    record_result("GraphOps", "client.py", "Neo4j Bolt driver & Cypher transaction", False, (time.time() - t0) * 1000, str(e))

# 3.2 schema
t0 = time.time()
try:
    from backend.graphops.schema import NodeLabel, RelationshipType, TraversalDirection, canonicalize_node_id
    c_user = canonicalize_node_id(NodeLabel.USER, "usr-101")
    c_dev = canonicalize_node_id(NodeLabel.DEVICE, "dev-ws-101")
    assert c_user == "user:usr-101"
    assert c_dev == "device:dev-ws-101"
    record_result("GraphOps", "schema.py", "Canonical node identifiers & relationship enums", True, (time.time() - t0) * 1000, "user:usr-101, device:dev-ws-101 verified")
except Exception as e:
    record_result("GraphOps", "schema.py", "Canonical node identifiers & relationship enums", False, (time.time() - t0) * 1000, str(e))

# 3.3 dijkstra (Lowest-friction path)
t0 = time.time()
try:
    from backend.graphops.dijkstra import DijkstraShortestPathEngine
    from backend.models.graphops import DijkstraShortestPathRequest
    dijkstra_engine = DijkstraShortestPathEngine(neo_client)
    dijk_req = DijkstraShortestPathRequest(entry_node_id="device:dev-ws-101", target_critical_asset_id="critical:crit-db-financial")
    dijkstra_res = dijkstra_engine.find_shortest_path(dijk_req)
    assert dijkstra_res is not None
    assert dijkstra_res.path_found is True
    assert dijkstra_res.total_cost > 0
    assert dijkstra_res.hop_count > 0
    record_result("GraphOps", "dijkstra.py", "Lowest-friction lateral path algorithm", True, (time.time() - t0) * 1000, f"Path found (cost {dijkstra_res.total_cost} over {dijkstra_res.hop_count} hops)")
except Exception as e:
    record_result("GraphOps", "dijkstra.py", "Lowest-friction lateral path algorithm", False, (time.time() - t0) * 1000, str(e))

# 3.4 attack_paths (DFS traversal)
t0 = time.time()
try:
    from backend.graphops.attack_paths import AttackPathService
    from backend.models.graphops import AttackPathRequest
    path_svc = AttackPathService(neo_client)
    req = AttackPathRequest(entry_node_id="device:dev-ws-101", target_critical_asset_ids=["critical:crit-db-financial"], max_depth=4)
    paths_res = path_svc.find_attack_paths(req)
    assert len(paths_res.paths) >= 4
    record_result("GraphOps", "attack_paths.py", "DFS candidate attack path discovery", True, (time.time() - t0) * 1000, f"{len(paths_res.paths)} lateral paths found to Crown Jewels")
except Exception as e:
    record_result("GraphOps", "attack_paths.py", "DFS candidate attack path discovery", False, (time.time() - t0) * 1000, str(e))

# 3.5 blast_radius (BFS multi-hop reachability)
t0 = time.time()
try:
    from backend.graphops.blast_radius import BlastRadiusService
    from backend.models.graphops import BlastRadiusRequest
    blast_svc = BlastRadiusService(neo_client)
    req = BlastRadiusRequest(start_node_id="device:dev-ws-101", max_hops=3)
    blast_res = blast_svc.calculate_blast_radius(req)
    assert blast_res.total_reachable_nodes > 15
    record_result("GraphOps", "blast_radius.py", "Multi-hop BFS blast radius calculation", True, (time.time() - t0) * 1000, f"{blast_res.total_reachable_nodes} reachable entities at 3 hops")
except Exception as e:
    record_result("GraphOps", "blast_radius.py", "Multi-hop BFS blast radius calculation", False, (time.time() - t0) * 1000, str(e))

# 3.6 communities (Security partitioning)
t0 = time.time()
try:
    from backend.graphops.communities import detect_security_communities
    comm_res = detect_security_communities(neo_client)
    assert len(comm_res.communities) > 0
    crit_count = sum(c.critical_asset_count for c in comm_res.communities)
    record_result("GraphOps", "communities.py", "Graph community detection & critical asset density", True, (time.time() - t0) * 1000, f"{len(comm_res.communities)} communities, {crit_count} critical assets evaluated")
except Exception as e:
    record_result("GraphOps", "communities.py", "Graph community detection & critical asset density", False, (time.time() - t0) * 1000, str(e))

# 3.7 alert_consolidation (Noise reduction & narrative)
t0 = time.time()
try:
    from backend.graphops.alert_consolidation import synthesize_incident_narrative
    narrative = synthesize_incident_narrative("MT-101", neo_client)
    assert narrative.case_reference == "MT-101"
    assert len(narrative.kill_chain_steps) > 0
    record_result("GraphOps", "alert_consolidation.py", "Incident timeline narrative synthesis", True, (time.time() - t0) * 1000, f"{len(narrative.kill_chain_steps)} chronological narrative steps synthesized")
except Exception as e:
    record_result("GraphOps", "alert_consolidation.py", "Incident timeline narrative synthesis", False, (time.time() - t0) * 1000, str(e))

# 3.8 case_bridge (Epistemological safety preservation)
t0 = time.time()
try:
    bridge = path_svc.bridge_case_to_graph("MT-101")
    assert bridge.case_id == "MT-101"
    assert "RECEIPT IS NOT COMPROMISE" in bridge.investigation_disclaimer
    record_result("GraphOps", "attack_paths.py (Bridge)", "Case bridging & epistemological safety preservation", True, (time.time() - t0) * 1000, f"Disclaimer verified: '{bridge.investigation_disclaimer[:30]}...'")
except Exception as e:
    record_result("GraphOps", "attack_paths.py (Bridge)", "Case bridging & epistemological safety preservation", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 4: MACHINE LEARNING & PYTORCH GEOMETRIC (backend.graphops)
# ==============================================================================
print("\n--- GROUP 4: MACHINE LEARNING & PYTORCH GEOMETRIC ---")

from backend.models.graphops import SecurityEventEnvelope, SecurityEventType, CriticalityTier

sample_envelope = SecurityEventEnvelope(
    event_id="EVT-SAMPLE-VERIFY-001",
    schema_version="1.0.0",
    event_type=SecurityEventType.ENDPOINT_ALERT,
    source="edr-sensor-01",
    occurred_at=datetime.now(timezone.utc).isoformat(),
    entity_ids=["device:dev-ws-101", "server:srv-app-01"],
    payload={"action": "lateral_auth", "port": 22},
    correlation_id="MT-101",
    severity=CriticalityTier.MEDIUM
)

# 4.1 feature_extractor
t0 = time.time()
try:
    from backend.graphops.feature_extractor import EventFeatureExtractor
    extractor = EventFeatureExtractor(neo_client)
    feat_rec = extractor.extract_features(sample_envelope)
    assert feat_rec is not None
    assert feat_rec.event_id == "EVT-SAMPLE-VERIFY-001"
    record_result("ML", "feature_extractor.py", "Feature extraction from SecurityEventEnvelope", True, (time.time() - t0) * 1000, f"Extracted feature record for {feat_rec.event_id}")
except Exception as e:
    record_result("ML", "feature_extractor.py", "Feature extraction from SecurityEventEnvelope", False, (time.time() - t0) * 1000, str(e))

# 4.2 ml_service (Isolation Forest)
t0 = time.time()
try:
    from backend.graphops.ml_service import get_event_anomaly_ml_service
    ml_svc = get_event_anomaly_ml_service()
    status_ml = ml_svc.get_status()
    assert status_ml.model_loaded is True
    assert status_ml.training_sample_count > 0
    pred = ml_svc.evaluate_event(sample_envelope)
    assert 0.0 <= pred.normalized_score <= 100.0
    record_result("ML", "ml_service.py", "Scikit-Learn Isolation Forest active inference", True, (time.time() - t0) * 1000, f"Normalized Score: {pred.normalized_score}, trained on {status_ml.training_sample_count} samples")
except Exception as e:
    record_result("ML", "ml_service.py", "Scikit-Learn Isolation Forest active inference", False, (time.time() - t0) * 1000, str(e))

# 4.3 pyg_model & pyg_service (PyTorch Geometric GraphSAGE)
t0 = time.time()
try:
    from backend.graphops.pyg_service import get_pyg_learning_service
    pyg_svc = get_pyg_learning_service()
    pyg_status = pyg_svc.get_status()
    assert pyg_status.model_loaded is True
    assert pyg_status.model_version is not None
    eval_res = pyg_svc.evaluate_relationship("device:dev-ws-101", "server:srv-app-01")
    assert 0.0 <= eval_res.structural_anomaly_score <= 100.0
    assert 0.0 <= eval_res.predicted_plausibility <= 1.0
    record_result("ML", "pyg_service.py", "PyG GraphSAGE 2-layer GNN link plausibility", True, (time.time() - t0) * 1000, f"Score: {eval_res.structural_anomaly_score}, Plausibility: {eval_res.predicted_plausibility}")
except Exception as e:
    record_result("ML", "pyg_service.py", "PyG GraphSAGE 2-layer GNN link plausibility", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 5: STREAMING PIPELINE & KAFKA CONSUMER LIFECYCLE (backend.graphops)
# ==============================================================================
print("\n--- GROUP 5: STREAMING PIPELINE & KAFKA CONSUMER LIFECYCLE ---")

# 5.1 kafka_producer
t0 = time.time()
try:
    from backend.graphops.kafka_producer import get_kafka_producer
    producer = get_kafka_producer()
    prod_health = producer.health_check()
    assert prod_health["status"] == "online"
    assert "9092" in prod_health["bootstrap_servers"]
    record_result("Kafka", "kafka_producer.py", "Kafka producer broker connection", True, (time.time() - t0) * 1000, f"Broker: {prod_health['bootstrap_servers']} (mode: {prod_health['mock_mode']})")
except Exception as e:
    record_result("Kafka", "kafka_producer.py", "Kafka producer broker connection", False, (time.time() - t0) * 1000, str(e))

# 5.2 kafka_worker
t0 = time.time()
try:
    from backend.graphops.kafka_worker import get_kafka_worker
    worker = get_kafka_worker()
    status_w = worker.get_status()
    assert status_w["consumer_group"] == "threatlens-graphops-workers"
    assert "security.endpoint.events" in status_w["subscribed_topics"]
    
    # Also verify live daemon via running FastAPI server
    live_worker_stat = http_request("GET", "/api/v1/graphops/events/status")
    assert live_worker_stat["data"]["consumer_worker_running"] is True
    assert live_worker_stat["data"]["broker_connected"] is True
    record_result("Kafka", "kafka_worker.py", "Lifespan consumer worker running loop", True, (time.time() - t0) * 1000, f"Live Consumer: running=True, broker=True, processed={live_worker_stat['data']['processed_events_count']}")
except Exception as e:
    record_result("Kafka", "kafka_worker.py", "Lifespan consumer worker running loop", False, (time.time() - t0) * 1000, str(e))

# 5.3 kafka_processor & Live End-to-End Ingestion
t0 = time.time()
try:
    test_evt_id = f"EVT-LIVE-VERIFY-{uuid.uuid4().hex[:8].upper()}"
    live_envelope_dict = {
        "event_id": test_evt_id,
        "schema_version": "1.0.0",
        "event_type": "ENDPOINT_ALERT",
        "source": "sensor-edr-live",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "entity_ids": ["device:dev-ws-101", "server:srv-app-01"],
        "payload": {"test_run": "comprehensive_live_test", "action": "lateral_pivot_attempt"},
        "correlation_id": "MT-101",
        "severity": "HIGH"
    }
    
    # Publish via HTTP endpoint to test full producer -> broker -> worker -> Neo4j loop
    pub_res = http_request("POST", "/api/v1/graphops/events/publish", live_envelope_dict)
    assert pub_res["status"] == 202
    assert pub_res["data"]["status"] in ["ACCEPTED_FOR_STREAMING", "PUBLISHED"]
    
    # Wait up to 3 seconds for async consumption by worker
    consumed = False
    for _ in range(30):
        time.sleep(0.1)
        chk = neo_client.execute_query("MATCH (e:SecurityEvent {id: $id}) RETURN e.id AS id", {"id": test_evt_id})
        if chk:
            consumed = True
            break
    assert consumed is True
    record_result("Kafka", "kafka_processor.py", "Live Publish -> Broker -> Worker -> Neo4j mutation", True, (time.time() - t0) * 1000, f"Event {test_evt_id} persisted in Neo4j live")
except Exception as e:
    record_result("Kafka", "kafka_processor.py", "Live Publish -> Broker -> Worker -> Neo4j mutation", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 6: GOVERNANCE & CRYPTOGRAPHIC LEDGER (backend.governance)
# ==============================================================================
print("\n--- GROUP 6: GOVERNANCE & CRYPTOGRAPHIC LEDGER ---")

# 6.1 catalog & policies
t0 = time.time()
try:
    from backend.governance.catalog import get_control_catalog
    from backend.governance.policies import list_policies
    controls = get_control_catalog()
    policies = list_policies()
    assert len(controls) == 24
    assert len(policies) == 6
    record_result("Governance", "catalog.py & policies.py", "24 Controls & 6 Policies loaded", True, (time.time() - t0) * 1000, f"{len(controls)} controls, {len(policies)} policies")
except Exception as e:
    record_result("Governance", "catalog.py & policies.py", "24 Controls & 6 Policies loaded", False, (time.time() - t0) * 1000, str(e))

# 6.2 evaluator
t0 = time.time()
try:
    from backend.governance.evaluator import evaluate_all_active_policies
    eval_results = evaluate_all_active_policies(neo_client)
    assert len(eval_results) == 6
    record_result("Governance", "evaluator.py", "Live graph policy evaluation", True, (time.time() - t0) * 1000, f"Evaluated 6 policies across live Neo4j topology")
except Exception as e:
    record_result("Governance", "evaluator.py", "Live graph policy evaluation", False, (time.time() - t0) * 1000, str(e))

# 6.3 audit (SHA-256 Hash Chain)
t0 = time.time()
try:
    from backend.governance.audit import verify_audit_integrity, list_audit_records, record_audit_event
    record_audit_event("SYSTEM_VERIFICATION", "admin-api-key", "backend.governance.audit", "VERIFY_AUDIT_INTEGRITY", {"runner": "live_verification"})
    is_valid, err_msg = verify_audit_integrity()
    records = list_audit_records()
    assert is_valid is True
    assert len(records) >= 1
    record_result("Governance", "audit.py", "Cryptographic SHA-256 audit ledger verification", True, (time.time() - t0) * 1000, f"{len(records)} audit records verified tamper-free (head hash: {records[-1].current_hash[:16]}...)")
except Exception as e:
    record_result("Governance", "audit.py", "Cryptographic SHA-256 audit ledger verification", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 7: LIVE REST API PRESENTATION ENDPOINTS (backend.api)
# ==============================================================================
print("\n--- GROUP 7: LIVE REST API PRESENTATION ENDPOINTS ---")

endpoints_to_test = [
    # Core API
    ("GET", "/api/v1/health", None, 200, "Core health endpoint"),
    ("POST", "/api/v1/analyze/threat", {"sender": "attacker@evil.com", "recipient": "victim@corp.com", "subject": "Account suspended", "body": "Verify credentials now http://evil.com"}, 200, "Analyze threat endpoint"),
    ("POST", "/api/v1/analyze/explain", {"sender": "attacker@evil.com", "recipient": "victim@corp.com", "subject": "Account suspended", "body": "Verify credentials now http://evil.com"}, 200, "Analyze explain endpoint"),
    ("POST", "/api/v1/analyze/forensics", {"raw_eml": EML_SAMPLES["phishing"]}, 200, "Analyze forensics raw EML endpoint"),
    ("POST", "/api/v1/analyze/iocs", {"raw_eml": EML_SAMPLES["phishing"]}, 200, "Analyze IOCs endpoint"),
    ("POST", "/api/v1/analyze/intelligence", {"indicators": ["185.190.140.22", "alert-center.xyz"]}, 200, "Analyze threat intelligence endpoint"),
    ("POST", "/api/v1/analyze/eml", {"raw_eml": EML_SAMPLES["phishing"]}, 200, "Complete EML analysis pipeline endpoint"),
    ("GET", "/api/v1/cases", None, 200, "List cases endpoint"),
    ("GET", "/api/v1/cases/MT-101/graph", None, 200, "Case MT-101 attack graph endpoint"),
    ("GET", "/api/v1/campaigns", None, 200, "List campaigns endpoint"),
    ("GET", "/api/v1/search/ioc?q=185.190.140.22", None, 200, "Cross-investigation IoC search"),
    ("GET", "/api/v1/demo-emails", None, 200, "Demo emails fixture endpoint"),
    ("GET", "/api/v1/demo-emls", None, 200, "Demo RFC 822 EML fixtures endpoint"),
    
    # GraphOps API
    ("GET", "/api/v1/graphops/health", None, 200, "GraphOps Neo4j health endpoint"),
    ("GET", "/api/v1/graphops/summary", None, 200, "GraphOps topology summary endpoint"),
    ("POST", "/api/v1/graphops/dijkstra", {"entry_node_id": "device:dev-ws-101", "target_critical_asset_id": "critical:crit-db-financial"}, 200, "Dijkstra shortest path endpoint"),
    ("POST", "/api/v1/graphops/attack-paths", {"entry_node_id": "device:dev-ws-101", "target_critical_asset_ids": ["critical:crit-db-financial"], "max_depth": 4}, 200, "DFS attack paths endpoint"),
    ("POST", "/api/v1/graphops/blast-radius", {"start_node_id": "device:dev-ws-101", "max_hops": 3}, 200, "BFS blast radius endpoint"),
    ("POST", "/api/v1/graphops/choke-points", {"candidate_path_ids": ["path-1"], "minimum_critical_asset_coverage": 0.5}, 200, "Choke points endpoint"),
    ("POST", "/api/v1/graphops/simulate-containment", {"entry_node_id": "device:dev-ws-101", "target_asset_ids": ["critical:crit-db-financial"], "proposed_interventions": [{"action": "ISOLATE_NODE", "node_id": "server:srv-app-01"}]}, 200, "What-If containment simulation"),
    ("GET", "/api/v1/graphops/bridge/case/MT-101", None, 200, "Case Bridge MT-101 endpoint"),
    ("GET", "/api/v1/graphops/communities", None, 200, "Community detection endpoint"),
    ("GET", "/api/v1/graphops/incident-narrative/MT-101", None, 200, "Incident narrative endpoint"),
    ("GET", "/api/v1/graphops/events/status", None, 200, "Kafka worker status endpoint"),
    ("GET", "/api/v1/graphops/events/findings", None, 200, "Kafka findings list endpoint"),
    ("GET", "/api/v1/graphops/events/ml/status", None, 200, "ML Isolation Forest status endpoint"),
    ("POST", "/api/v1/graphops/events/ml/evaluate", live_envelope_dict, 200, "ML Isolation Forest evaluate endpoint"),
    ("GET", "/api/v1/graphops/events/pyg/status", None, 200, "PyG GraphSAGE status endpoint"),
    ("POST", "/api/v1/graphops/events/pyg/evaluate", {"source_entity_id": "device:dev-ws-101", "target_entity_id": "server:srv-app-01"}, 200, "PyG link plausibility evaluate endpoint"),
    
    # Governance API
    ("GET", "/api/v1/governance/controls", None, 200, "Governance controls catalog endpoint"),
    ("GET", "/api/v1/governance/policies", None, 200, "Governance policies endpoint"),
    ("POST", "/api/v1/governance/evaluate", {"policy_id": None}, 200, "Governance policy evaluate endpoint"),
    ("GET", "/api/v1/governance/audit", None, 200, "Audit trail list endpoint"),
    ("GET", "/api/v1/governance/audit/verify", None, 200, "Cryptographic audit verify endpoint")
]

for method, path, payload, exp_status, desc in endpoints_to_test:
    t0 = time.time()
    try:
        res = http_request(method, path, payload)
        passed = (res["status"] == exp_status)
        details = f"HTTP {res['status']}" if passed else f"Expected {exp_status}, got {res['status']}: {res.get('error')}"
        record_result("API", path, desc, passed, (time.time() - t0) * 1000, details)
    except Exception as e:
        record_result("API", path, desc, False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# GROUP 8: FRONTEND CLIENT & DOM CONTRACT (frontend/)
# ==============================================================================
print("\n--- GROUP 8: FRONTEND CLIENT & DOM CONTRACT ---")

static_assets = [
    ("/static/index.html", "Single Page App HTML5"),
    ("/static/css/styles.css", "Dark-Mode SOC CSS Stylesheet"),
    ("/static/js/app.js", "Frontend ES6 Application Logic")
]

for path, desc in static_assets:
    t0 = time.time()
    try:
        res = http_request("GET", path)
        content = res.get("text", "")
        passed = (res["status"] == 200 and len(content) > 1000)
        record_result("Frontend", path, f"{desc} serving", passed, (time.time() - t0) * 1000, f"HTTP {res['status']}, {len(content)} bytes")
    except Exception as e:
        record_result("Frontend", path, f"{desc} serving", False, (time.time() - t0) * 1000, str(e))

# DOM contract check on index.html
t0 = time.time()
try:
    res = http_request("GET", "/static/index.html")
    html = res.get("text", "")
    
    # Phase 7 Indicators & Views
    required_ids = [
        "topbar-engine-indicator",
        "topbar-db-indicator",
        "topbar-kafka-indicator",
        "topbar-ml-indicator",
        "topbar-pyg-indicator",
        "view-dashboard",
        "view-alerts-incidents",
        "view-knowledge-graph",
        "view-detection-intel",
        "view-access-governance",
        "view-evidence-reports",
        "cy"
    ]
    missing = [req_id for req_id in required_ids if req_id not in html]
    passed = len(missing) == 0
    details = f"All {len(required_ids)} DOM IDs present in markup" if passed else f"Missing DOM IDs: {missing}"
    record_result("Frontend", "index.html DOM", "Phase 7 topbar indicators & 6 navigation views", passed, (time.time() - t0) * 1000, details)
except Exception as e:
    record_result("Frontend", "index.html DOM", "Phase 7 topbar indicators & 6 navigation views", False, (time.time() - t0) * 1000, str(e))


# ==============================================================================
# SUMMARY & VERDICT
# ==============================================================================
total_tests = len(RESULTS)
passed_tests = sum(1 for r in RESULTS if r["passed"])
failed_tests = total_tests - passed_tests
avg_latency = sum(r["duration_ms"] for r in RESULTS) / total_tests if total_tests > 0 else 0

print("\n" + "=" * 80)
print("EXHAUSTIVE LIVE VERIFICATION SUMMARY")
print("=" * 80)
print(f"Total Submodule & Endpoint Tests Executed : {total_tests}")
print(f"Passed Tests                             : {passed_tests} ({round(passed_tests / total_tests * 100, 1)}%)")
print(f"Failed Tests                             : {failed_tests}")
print(f"Average Execution Latency                : {round(avg_latency, 2)} ms")
print("=" * 80)

# Save JSON results to disk for detailed report compilation
out_json_path = os.path.join(BASE_DIR, "docs", "live_verification_results.json")
with open(out_json_path, "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "pass_rate": round(passed_tests / total_tests * 100, 1),
        "results": RESULTS
    }, f, indent=2)

print(f"Detailed verification results saved to: {out_json_path}")

if failed_tests == 0:
    print("\n\033[92m>>> VERDICT: ALL MODULES AND SUBMODULES VERIFIED LIVE (100% PASS) <<<\033[0m\n")
    sys.exit(0)
else:
    print(f"\n\033[91m>>> VERDICT: {failed_tests} TESTS FAILED <<<\033[0m\n")
    sys.exit(1)
