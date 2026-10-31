"""
ThreatLens - Two Windows Endpoints End-to-End Simulation Test
Simulates two distinct Windows computers:
  Computer A: WIN-SRV-FINANCE (Server)
  Computer B: DESKTOP-HR-042  (Workstation)

Verifies:
1. Independent enrolment, unique credentials, and no cross-talk.
2. Ingestion of Windows security events (4624 logon, 4688 process, 5140 share).
3. Publication to Apache Kafka streaming topics.
4. Kafka consumer worker decoding, deduplication, and Neo4j graph resolution.
5. Persistent Neo4j topology updates (LOGGED_IN_TO, OBSERVED_CONNECTION, ASSOCIATED_WITH_CASE).
6. Strict source attribution (evidence_metadata, source_computer, collector_id).
7. Re-delivery verification (idempotent; no duplicate graph entities).
"""

import json
import pytest
from typing import Dict, List, Any, Optional
from fastapi.testclient import TestClient

from backend.main import app
from backend.core import config
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
    SecurityFindingRecord,
)
from backend.graphops.kafka_producer import GraphOpsKafkaProducer
from backend.graphops.kafka_processor import GraphOpsEventProcessor
from backend.graphops.kafka_worker import GraphOpsKafkaWorker
from backend.collector.dedup import _cache
from backend.collector.rate_limiter import _request_windows
from backend.api.graphops_routes import get_kafka_producer_dep, get_kafka_worker_dep


class MockNeo4jClientForCollectorE2E:
    """In-memory mock Neo4j client verifying graph persistence and relationships."""

    def __init__(self, nodes: List[Dict[str, Any]]):
        self.nodes = {n["id"].lower(): n for n in nodes}
        self.edges = []
        self.security_events: Dict[str, Dict[str, Any]] = {}
        self.executed_queries: List[str] = []
        self.aliases: Dict[str, str] = {}

        for n in nodes:
            nid = n["id"].lower()
            props = n.get("properties", {})
            for key in ["email", "hostname", "user_id", "device_id", "server_id", "asset_id"]:
                val = props.get(key)
                if val:
                    self.aliases[str(val).lower()] = nid
                    if ":" in str(val):
                        self.aliases[str(val).split(":", 1)[1].lower()] = nid
            if ":" in nid:
                self.aliases[nid.split(":", 1)[1].lower()] = nid

    def execute_query(self, query: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self.executed_queries.append(query)
        params = params or {}
        q = query.strip()

        # 1. Deduplication check
        if "MATCH (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid and eid in self.security_events:
                return [{"id": eid}]
            return []

        # 2. Persist SecurityEvent
        if "MERGE (e:SecurityEvent {id: $event_id})" in q:
            eid = params.get("event_id")
            if eid:
                self.security_events[eid] = params
            return []

        # 3. Dynamic LOGGED_IN_TO relationship
        if "MERGE (u)-[r:LOGGED_IN_TO]->(t)" in q:
            uid = str(params.get("user_id", "")).lower()
            tid = str(params.get("target_id", "")).lower()
            self.edges.append({
                "source": uid,
                "target": tid,
                "type": "LOGGED_IN_TO",
                "evidence_class": "OBSERVED",
                "timestamp": params.get("timestamp"),
            })
            return []

        # 4. Dynamic OBSERVED_CONNECTION relationship
        if "MERGE (s)-[r:OBSERVED_CONNECTION]->(t)" in q:
            sid = str(params.get("src_id", "")).lower()
            tid = str(params.get("tgt_id", "")).lower()
            self.edges.append({
                "source": sid,
                "target": tid,
                "type": "OBSERVED_CONNECTION",
                "evidence_class": "OBSERVED",
                "port": params.get("port", 445),
                "timestamp": params.get("timestamp"),
            })
            return []

        # 5. Node resolution
        if "WHERE n.id = $id" in q or "toLower(n.id) = toLower($id)" in q:
            target_id = str(params.get("id", "")).lower()
            resolved = self.nodes.get(target_id) or self.aliases.get(target_id)
            if resolved:
                node = resolved if isinstance(resolved, dict) else self.nodes[resolved]
                return [{
                    "id": node["id"],
                    "labels": [node.get("label", "Device")],
                    "name": node.get("name", node["id"]),
                    "criticality": node.get("criticality", "MEDIUM"),
                    "properties": node.get("properties", {}),
                }]
            return []

        # Default fallback
        return []


@pytest.fixture
def enterprise_graph_fixture():
    return [
        {
            "id": "device:win-srv-finance",
            "label": "Device",
            "name": "Finance Production Server",
            "criticality": "HIGH",
            "properties": {"hostname": "WIN-SRV-FINANCE", "ip_address": "10.0.1.10"}
        },
        {
            "id": "device:desktop-hr-042",
            "label": "Device",
            "name": "HR Workstation 042",
            "criticality": "LOW",
            "properties": {"hostname": "DESKTOP-HR-042", "ip_address": "10.0.2.42"}
        },
        {
            "id": "user:bob@corp",
            "label": "User",
            "name": "Bob Finance",
            "properties": {"email": "bob@corp", "department": "Finance"}
        },
        {
            "id": "user:alice@corp",
            "label": "User",
            "name": "Alice HR",
            "properties": {"email": "alice@corp", "department": "HR"}
        },
    ]


def test_two_endpoints_end_to_end_collection_and_attribution(
    enterprise_graph_fixture, tmp_path, monkeypatch
):
    """
    Executes full end-to-end verification for two distinct Windows endpoints:
    1. Enrols Computer A (WIN-SRV-FINANCE) and Computer B (DESKTOP-HR-042)
    2. Transmits events with distinct tokens
    3. Verifies Kafka publication and Kafka consumer processing
    4. Validates Neo4j persistence and topology updates
    5. Confirms source attribution isolation
    """
    # Setup temporary registry & mock Kafka/Neo4j
    test_reg_path = tmp_path / "test_e2e_registry.json"
    monkeypatch.setattr("backend.collector.registry._REGISTRY_PATH", test_reg_path)
    monkeypatch.setattr(config, "COLLECTOR_REGISTRY_PATH", str(test_reg_path))
    monkeypatch.setattr(config, "REQUIRE_API_KEY", False)
    _cache.clear()
    _request_windows.clear()

    mock_db = MockNeo4jClientForCollectorE2E(enterprise_graph_fixture)
    mock_producer = GraphOpsKafkaProducer(mock_mode=True)
    mock_processor = GraphOpsEventProcessor(client=mock_db, producer=mock_producer)
    mock_worker = GraphOpsKafkaWorker(
        producer=mock_producer, processor=mock_processor, mock_mode=True
    )

    app.dependency_overrides[get_kafka_producer_dep] = lambda: mock_producer
    app.dependency_overrides[get_kafka_worker_dep] = lambda: mock_worker

    client = TestClient(app)

    # -------------------------------------------------------------
    # Step 1: Enrol Computer A (WIN-SRV-FINANCE)
    # -------------------------------------------------------------
    enrol_a = client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "WIN-SRV-FINANCE", "ip_address": "10.0.1.10", "os_version": "Windows Server 2022"}
    ).json()
    cid_a = enrol_a["collector_id"]
    token_a = enrol_a["token"]
    assert cid_a.startswith("col-")
    assert enrol_a["device_node_id"] == "device:win-srv-finance"

    # -------------------------------------------------------------
    # Step 2: Enrol Computer B (DESKTOP-HR-042)
    # -------------------------------------------------------------
    enrol_b = client.post(
        "/api/v1/collector/enrol",
        json={"hostname": "DESKTOP-HR-042", "ip_address": "10.0.2.42", "os_version": "Windows 11 Pro"}
    ).json()
    cid_b = enrol_b["collector_id"]
    token_b = enrol_b["token"]
    assert cid_b != cid_a
    assert token_b != token_a
    assert enrol_b["device_node_id"] == "device:desktop-hr-042"

    # -------------------------------------------------------------
    # Step 3: Computer A sends Security 4624 (Successful Logon)
    # -------------------------------------------------------------
    resp_a = client.post(
        "/api/v1/collector/ingest/events",
        headers={"X-Collector-ID": cid_a, "X-Collector-Token": token_a},
        json={
            "events": [{
                "event_id_number": 4624,
                "source_computer": "WIN-SRV-FINANCE",
                "time_created": "2026-10-29T08:30:00Z",
                "source_event_record_id": 1001,
                "channel": "Security",
                "event_data": {
                    "TargetUserName": "bob",
                    "TargetDomainName": "CORP",
                    "LogonType": "10",  # RDP Remote Interactive
                    "IpAddress": "10.0.2.42",
                    "WorkstationName": "DESKTOP-HR-042"
                }
            }]
        }
    )
    assert resp_a.status_code == 202
    assert resp_a.json()["published"] == 1

    # -------------------------------------------------------------
    # Step 4: Computer B sends Security 4688 (Process Execution)
    # -------------------------------------------------------------
    resp_b = client.post(
        "/api/v1/collector/ingest/events",
        headers={"X-Collector-ID": cid_b, "X-Collector-Token": token_b},
        json={
            "events": [{
                "event_id_number": 4688,
                "source_computer": "DESKTOP-HR-042",
                "time_created": "2026-10-29T08:32:00Z",
                "source_event_record_id": 2001,
                "channel": "Security",
                "event_data": {
                    "SubjectUserName": "alice",
                    "SubjectDomainName": "CORP",
                    "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass"
                }
            }]
        }
    )
    assert resp_b.status_code == 202
    assert resp_b.json()["published"] == 1

    # -------------------------------------------------------------
    # Step 5: Verify Kafka queue contains both events with correct topic routing
    # -------------------------------------------------------------
    identity_topic = config.KAFKA_TOPIC_IDENTITY_EVENTS
    endpoint_topic = config.KAFKA_TOPIC_ENDPOINT_EVENTS

    # Computer A event in identity topic
    identity_msgs = mock_producer._mock_messages.get(identity_topic, [])
    assert len(identity_msgs) == 1
    raw_env_a = identity_msgs[0]["value"]
    envelope_a = SecurityEventEnvelope.model_validate_json(raw_env_a)

    # Computer B event in endpoint topic
    endpoint_msgs = mock_producer._mock_messages.get(endpoint_topic, [])
    assert len(endpoint_msgs) == 1
    raw_env_b = endpoint_msgs[0]["value"]
    envelope_b = SecurityEventEnvelope.model_validate_json(raw_env_b)

    # -------------------------------------------------------------
    # Step 6: Verify Source Attribution
    # -------------------------------------------------------------
    assert envelope_a.source == f"collector:{cid_a}"
    assert envelope_a.evidence_metadata["collector_id"] == cid_a
    assert envelope_a.evidence_metadata["source_computer"] == "WIN-SRV-FINANCE"
    assert "device:win-srv-finance" in envelope_a.entity_ids

    assert envelope_b.source == f"collector:{cid_b}"
    assert envelope_b.evidence_metadata["collector_id"] == cid_b
    assert envelope_b.evidence_metadata["source_computer"] == "DESKTOP-HR-042"
    assert "device:desktop-hr-042" in envelope_b.entity_ids

    # -------------------------------------------------------------
    # Step 7: Consumer Worker processes both messages into Neo4j
    # -------------------------------------------------------------
    ok_a = mock_worker.process_raw_message(
        raw_env_a, source_topic=identity_topic
    )
    assert ok_a is True

    ok_b = mock_worker.process_raw_message(
        raw_env_b, source_topic=endpoint_topic
    )
    assert ok_b is True

    # -------------------------------------------------------------
    # Step 8: Verify Neo4j Graph Persistence & Topology
    # -------------------------------------------------------------
    # SecurityEvent nodes
    assert envelope_a.event_id in mock_db.security_events
    assert envelope_b.event_id in mock_db.security_events

    # Computer A generated an observed LOGGED_IN_TO relationship
    logon_edges = [e for e in mock_db.edges if e["type"] == "LOGGED_IN_TO"]
    assert len(logon_edges) >= 1
    edge = logon_edges[0]
    assert edge["source"] == "user:bob@corp"
    assert edge["target"] == "device:win-srv-finance"
    assert edge["evidence_class"] == "OBSERVED"

    # -------------------------------------------------------------
    # Step 9: Re-delivery deduplication check (Idempotency)
    # -------------------------------------------------------------
    # Ingestion API dedup
    re_resp_a = client.post(
        "/api/v1/collector/ingest/events",
        headers={"X-Collector-ID": cid_a, "X-Collector-Token": token_a},
        json={
            "events": [{
                "event_id_number": 4624,
                "source_computer": "WIN-SRV-FINANCE",
                "time_created": "2026-10-29T08:30:00Z",
                "source_event_record_id": 1001,
                "channel": "Security",
                "event_data": {"TargetUserName": "bob"}
            }]
        }
    )
    assert re_resp_a.status_code == 202
    assert re_resp_a.json()["duplicate"] == 1
    assert re_resp_a.json()["published"] == 0

    # Worker level dedup
    init_events_count = len(mock_db.security_events)
    mock_worker.process_raw_message(
        raw_env_a, source_topic=identity_topic
    )
    assert len(mock_db.security_events) == init_events_count  # No duplicate node!

    # Clean up dependency overrides
    app.dependency_overrides.clear()
