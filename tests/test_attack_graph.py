"""
MailTrace AI - Attack Graph & Campaign Correlation Test Suite
Feature 6: Attack Graph + Campaign Correlation
"""

import sys
import os
import asyncio

# Add workspace to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.graph import CaseRecord
from backend.services.attack_graph import default_graph_builder
from backend.services.campaign_correlation import default_correlation_engine
from backend.services.case_store import default_case_repo
from backend.services.email_forensics import analyze_email_forensics
from backend.services.ioc_extractor import extract_iocs
from backend.services.threat_intelligence import default_intel_service
from backend.services.threat_detection import detect_threat
from backend.services.email_forensics import default_forensics_service
from backend.data.eml_samples import EML_SAMPLES


async def run_all_tests_async():
    print("=" * 65)
    print("MAILTRACE AI - FEATURE 6 (ATTACK GRAPH & CAMPAIGN) TEST SUITE")
    print("=" * 65)

    # -----------------------------------------------------------
    # TEST 1: Single Email Attack Graph Generation
    # -----------------------------------------------------------
    forensics = analyze_email_forensics(EML_SAMPLES["phishing"])
    iocs = extract_iocs(EML_SAMPLES["phishing"])
    intel = await default_intel_service.enrich_iocs(iocs)
    email_data = default_forensics_service.convert_forensics_to_analysis_input(forensics, forensics.mime_analysis.plain_text_preview or "")
    threat = detect_threat(email_data)

    graph = default_graph_builder.build_attack_graph_for_case(
        case_id="TEST-001",
        forensics=forensics,
        iocs=iocs,
        intel=intel,
        threat_detection=threat
    )

    print("\n[TEST 1] Attack Graph Construction:")
    print("  Total Nodes:", len(graph.nodes))
    print("  Total Edges:", len(graph.edges))
    print("  Node Types:", set(n.type for n in graph.nodes))
    print("  Relationships:", set(e.relationship for e in graph.edges))

    node_types = set(n.type for n in graph.nodes)
    assert "email" in node_types
    assert "domain" in node_types
    assert "url" in node_types
    assert "ip" in node_types
    assert len(graph.edges) >= 4
    print("[PASS] Test 1 passed")

    # -----------------------------------------------------------
    # TEST 2: Node Deduplication
    # -----------------------------------------------------------
    node_ids = [n.id for n in graph.nodes]
    assert len(node_ids) == len(set(node_ids)), "Duplicate node IDs detected in graph"
    print("\n[TEST 2] Node Deduplication: All", len(node_ids), "nodes are uniquely identified.")
    print("[PASS] Test 2 passed")

    # -----------------------------------------------------------
    # TEST 3: SMTP Relay Chain Representation
    # -----------------------------------------------------------
    relay_edges = [e for e in graph.edges if e.relationship == "OBSERVED_RELAY"]
    print("\n[TEST 3] SMTP Transmission Relay Chain:")
    print("  Relay Hops Connected:", len(relay_edges))
    assert len(relay_edges) >= 1
    print("[PASS] Test 3 passed")

    # -----------------------------------------------------------
    # TEST 4: Threat Intelligence Node Enrichment
    # -----------------------------------------------------------
    malicious_nodes = [n for n in graph.nodes if n.status == "MALICIOUS"]
    print("\n[TEST 4] Threat Intelligence Status Enrichment:")
    print("  Malicious Nodes Count:", len(malicious_nodes))
    print("  Sample Malicious Node:", malicious_nodes[0].id if malicious_nodes else "None")
    assert len(malicious_nodes) >= 1
    print("[PASS] Test 4 passed")

    # -----------------------------------------------------------
    # TEST 5: Campaign Correlation Between Related Emails
    # -----------------------------------------------------------
    case_a = CaseRecord(
        case_id="TEST-A",
        subject="Urgent Security Alert",
        sender="service@alert-center.xyz",
        threat_score=100,
        risk_level="CRITICAL",
        primary_threat="PHISHING",
        iocs={"domains": ["alert-center.xyz"], "ips": ["185.190.140.22"], "urls": ["http://alert-center.xyz/login"]},
        timestamp="2026-08-28T10:00:00Z"
    )
    case_b = CaseRecord(
        case_id="TEST-B",
        subject="Account Deactivation Notice",
        sender="notify@alert-center.xyz",
        threat_score=95,
        risk_level="CRITICAL",
        primary_threat="PHISHING",
        iocs={"domains": ["alert-center.xyz"], "ips": ["185.190.140.22"], "urls": ["http://alert-center.xyz/auth"]},
        timestamp="2026-08-28T11:00:00Z"
    )

    c_score, shared_list, reasons = default_correlation_engine.calculate_pairwise_correlation(case_a, case_b)
    print("\n[TEST 5] Campaign Correlation for Shared Infrastructure:")
    print("  Correlation Score:", c_score, "/ 100")
    print("  Shared Indicators:", [f"{s.type}:{s.value}" for s in shared_list])
    print("  Reasons:", reasons)
    assert c_score >= 50, f"Expected correlation score >= 50, got {c_score}"
    assert len(shared_list) >= 2
    print("[PASS] Test 5 passed")

    # -----------------------------------------------------------
    # TEST 6: Attachment Hash Campaign Correlation
    # -----------------------------------------------------------
    case_c = CaseRecord(
        case_id="TEST-C1",
        subject="Invoice Overdue",
        sender="billing@invoice-sys.com",
        threat_score=90,
        risk_level="CRITICAL",
        primary_threat="MALWARE",
        iocs={"hashes": ["b778c51f4bf491f4ccbb6f34f0c33448771a8bce8720778db981978cfd33852c"]},
        timestamp="2026-08-28T09:00:00Z"
    )
    case_d = CaseRecord(
        case_id="TEST-C2",
        subject="Payment Receipt",
        sender="vendor@pay-portal.com",
        threat_score=90,
        risk_level="CRITICAL",
        primary_threat="MALWARE",
        iocs={"hashes": ["b778c51f4bf491f4ccbb6f34f0c33448771a8bce8720778db981978cfd33852c"]},
        timestamp="2026-08-28T12:00:00Z"
    )

    hash_score, hash_shared, hash_reasons = default_correlation_engine.calculate_pairwise_correlation(case_c, case_d)
    print("\n[TEST 6] Attachment Hash Correlation:")
    print("  Score:", hash_score)
    assert hash_score >= 35
    assert any(s.type == "hash" for s in hash_shared)
    print("[PASS] Test 6 passed")

    # -----------------------------------------------------------
    # TEST 7: Negative Test - Unrelated Emails
    # -----------------------------------------------------------
    unrelated_a = CaseRecord(
        case_id="UNREL-1",
        subject="Phishing Campaign 1",
        sender="attacker@domain-one.com",
        threat_score=80,
        risk_level="HIGH",
        primary_threat="PHISHING",
        iocs={"domains": ["domain-one.com"], "ips": ["198.51.100.1"], "urls": ["http://domain-one.com/a"]},
        timestamp="2026-08-28T01:00:00Z"
    )
    unrelated_b = CaseRecord(
        case_id="UNREL-2",
        subject="Phishing Campaign 2",
        sender="attacker@domain-two.com",
        threat_score=85,
        risk_level="HIGH",
        primary_threat="PHISHING",
        iocs={"domains": ["domain-two.com"], "ips": ["198.51.100.99"], "urls": ["http://domain-two.com/b"]},
        timestamp="2026-08-28T02:00:00Z"
    )

    unrel_score, unrel_shared, _ = default_correlation_engine.calculate_pairwise_correlation(unrelated_a, unrelated_b)
    print("\n[TEST 7] Negative Test (Unrelated Emails):")
    print("  Correlation Score:", unrel_score)
    assert unrel_score < 30, f"Unrelated emails should have score < 30, got {unrel_score}"
    assert len(unrel_shared) == 0
    print("[PASS] Test 7 passed")

    # -----------------------------------------------------------
    # TEST 8: Campaign Clustering
    # -----------------------------------------------------------
    campaigns = default_correlation_engine.cluster_all_cases()
    print("\n[TEST 8] Campaign Clustering:")
    print("  Active Campaigns Count:", len(campaigns))
    for c in campaigns:
        print(f"  - {c.campaign_id}: {c.name} (Score: {c.correlation_score}, Cases: {c.case_ids})")
    assert len(campaigns) >= 1
    print("[PASS] Test 8 passed")

    # -----------------------------------------------------------
    # TEST 9: Cross-Investigation IOC Search
    # -----------------------------------------------------------
    search_res = default_correlation_engine.search_ioc("185.190.140.22")
    print("\n[TEST 9] Cross-Investigation IOC Search:")
    print("  Query: 185.190.140.22")
    print("  Matching Cases:", len(search_res["matching_cases"]))
    print("  Associated Campaigns:", len(search_res["matching_campaigns"]))
    assert search_res["total_matches"] >= 2
    print("[PASS] Test 9 passed")

    # -----------------------------------------------------------
    # TEST 10: Fault Tolerance (Missing Intel)
    # -----------------------------------------------------------
    sparse_graph = default_graph_builder.build_attack_graph_for_case(
        case_id="SPARSE-001",
        forensics=None,
        iocs=iocs,
        intel=None,
        threat_detection=None
    )
    print("\n[TEST 10] Fault Tolerance Without Intel/Forensics:")
    print("  Nodes Created:", len(sparse_graph.nodes))
    assert len(sparse_graph.nodes) >= 1
    print("[PASS] Test 10 passed")

    # -----------------------------------------------------------
    # TEST 11: Multi-Case Campaign Graph
    # -----------------------------------------------------------
    top_camp = campaigns[0]
    multi_graph = default_graph_builder.build_multi_case_campaign_graph(
        campaign=top_camp,
        cases=default_case_repo.list_cases()
    )
    print("\n[TEST 11] Multi-Case Campaign Graph:")
    print("  Campaign Nodes:", len(multi_graph.nodes))
    print("  Campaign Edges:", len(multi_graph.edges))
    assert len(multi_graph.nodes) >= len(top_camp.case_ids) + 1
    print("[PASS] Test 11 passed")

    # -----------------------------------------------------------
    # TEST 12: FastAPI Endpoints Integration
    # -----------------------------------------------------------
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        
        # Test /cases
        cases_resp = client.get("/api/v1/cases")
        assert cases_resp.status_code == 200
        assert len(cases_resp.json()) >= 1
        
        # Test /cases/MT-101/graph
        case_graph_resp = client.get("/api/v1/cases/MT-101/graph")
        assert case_graph_resp.status_code == 200
        assert "nodes" in case_graph_resp.json()
        assert "edges" in case_graph_resp.json()
        
        # Test /campaigns
        camp_resp = client.get("/api/v1/campaigns")
        assert camp_resp.status_code == 200
        assert len(camp_resp.json()) >= 1
        
        # Test /search/ioc
        search_resp = client.get("/api/v1/search/ioc?q=185.190.140.22")
        assert search_resp.status_code == 200
        assert search_resp.json()["total_matches"] >= 1

        # Test complete EML analysis pipeline (Features 1–6)
        pipeline_resp = client.post(
            "/api/v1/analyze/eml",
            json={"raw_eml": EML_SAMPLES["phishing"]}
        )
        assert pipeline_resp.status_code == 200
        p_data = pipeline_resp.json()
        assert "attack_graph" in p_data
        assert "campaign_correlation" in p_data
        assert len(p_data["attack_graph"]["nodes"]) >= 3
        print("[PASS] Test 12 passed (FastAPI endpoints)")
    except ImportError:
        print("[SKIP] TestClient not available")

    print("=" * 65)
    print("ALL FEATURE 6 ATTACK GRAPH & CAMPAIGN TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)


def test_feature6_attack_graph_and_campaign_correlation():
    """Pytest entrypoint executing the 12 Feature 6 attack graph & campaign correlation tests."""
    asyncio.run(run_all_tests_async())


def main():
    asyncio.run(run_all_tests_async())


if __name__ == "__main__":
    main()
