"""
ThreatLens GraphOps — Graph Centrality Analytics Engine
Implements PageRank, Betweenness Centrality (Brandes' algorithm), and Degree Centrality
to mathematically identify which enterprise nodes would cause the most systemic disruption
or facilitate the most lateral movement if compromised.
"""

from typing import List, Dict, Any, Optional, Set
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from collections import deque, defaultdict
import logging

from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.graphops.schema import NodeLabel, CriticalityTier

logger = logging.getLogger("threatlens.graphops.centrality")


class CentralityNodeMetric(BaseModel):
    """Calculated centrality and disruption metrics for an individual graph entity."""
    node_id: str = Field(description="Canonical node identifier")
    node_label: str = Field(description="Entity type (Server, Device, User, Application)")
    node_name: str = Field(description="Human-readable asset or account name")
    criticality: str = Field(default="MEDIUM", description="Configured criticality tier")
    pagerank: float = Field(description="PageRank authority score")
    betweenness: float = Field(description="Betweenness centrality (lateral bridge score)")
    in_degree: int = Field(description="Number of incoming connections/entitlements")
    out_degree: int = Field(description="Number of outgoing reachable connections")
    disruption_score: float = Field(description="Composite disruption impact rating 0.0 - 100.0")
    disruption_tier: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    role_in_attack_chain: str = Field(description="Qualitative role: Lateral Bridge, Pivot Hub, Crown Jewel Target, Entry Point")


class CentralityAnalysisResult(BaseModel):
    """Consolidated outcome of enterprise graph centrality analytics."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_nodes_analyzed: int = Field(description="Total evaluated nodes in graph snapshot")
    total_edges_analyzed: int = Field(description="Total evaluated edges in graph snapshot")
    top_disruption_nodes: List[CentralityNodeMetric] = Field(description="Nodes sorted descending by composite disruption score")
    network_bridge_nodes: List[CentralityNodeMetric] = Field(description="Nodes sorted descending by Betweenness centrality")
    executive_summary: str = Field(description="Analyst narrative summarizing high-centrality choke points")


class CentralityAnalyticsService:
    """
    Computes PageRank and Betweenness Centrality over the enterprise knowledge graph
    to identify high-value targets, critical bridges, and lateral pivot hubs.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    def analyze_graph_centrality(self, top_k: int = 10) -> CentralityAnalysisResult:
        """
        Executes PageRank (power iteration) and Betweenness Centrality (Brandes' algorithm)
        across the live Neo4j topology.
        """
        # 1. Fetch live nodes and edges from Neo4j (with in-memory fallback)
        try:
            node_records = self.client.execute_query(
                """
                MATCH (n)
                WHERE NOT n:SecurityEvent
                RETURN n.id AS id, labels(n)[0] AS label,
                       coalesce(n.name, n.hostname, n.email, n.id) AS name,
                       coalesce(n.criticality, 'MEDIUM') AS criticality
                """
            )
            edge_records = self.client.execute_query(
                """
                MATCH (s)-[r]->(t)
                WHERE NOT s:SecurityEvent AND NOT t:SecurityEvent
                RETURN s.id AS source, t.id AS target, type(r) AS rel_type
                """
            )
        except Exception as e:
            logger.warning("Neo4j unreachable for Centrality analysis (%s); using in-memory mock client.", e)
            from backend.graphops.mock_client import get_mock_graphops_client
            mock_c = get_mock_graphops_client()
            node_records = mock_c.execute_query("MATCH (n) WHERE NOT n:SecurityEvent")
            edge_records = mock_c.execute_query("MATCH (s)-[r]->(t)")

        nodes_map: Dict[str, Dict[str, Any]] = {}
        for nr in node_records:
            nid = nr["id"]
            nodes_map[nid] = {
                "id": nid,
                "label": nr.get("label", "Entity"),
                "name": nr.get("name", nid),
                "criticality": str(nr.get("criticality", "MEDIUM")).upper(),
            }

        adj: Dict[str, List[str]] = {nid: [] for nid in nodes_map}
        in_adj: Dict[str, List[str]] = {nid: [] for nid in nodes_map}
        in_degree: Dict[str, int] = {nid: 0 for nid in nodes_map}
        out_degree: Dict[str, int] = {nid: 0 for nid in nodes_map}

        valid_edges_count = 0
        for er in edge_records:
            src = er.get("source")
            dst = er.get("target")
            if src in nodes_map and dst in nodes_map:
                adj[src].append(dst)
                in_adj[dst].append(src)
                out_degree[src] += 1
                in_degree[dst] += 1
                valid_edges_count += 1

        total_nodes = len(nodes_map)
        if total_nodes == 0:
            return CentralityAnalysisResult(
                total_nodes_analyzed=0,
                total_edges_analyzed=0,
                top_disruption_nodes=[],
                network_bridge_nodes=[],
                executive_summary="Graph is empty; no centrality metrics could be computed."
            )

        # 2. Compute PageRank (Power Iteration, damping=0.85)
        damping = 0.85
        pagerank: Dict[str, float] = {nid: 1.0 / total_nodes for nid in nodes_map}
        
        for _ in range(30):
            next_pr: Dict[str, float] = {}
            dangling_sum = sum(pagerank[nid] for nid in nodes_map if out_degree[nid] == 0)
            base_val = (1.0 - damping) / total_nodes + (damping * dangling_sum / total_nodes)
            
            for nid in nodes_map:
                rank_sum = sum(pagerank[in_node] / out_degree[in_node] for in_node in in_adj[nid] if out_degree[in_node] > 0)
                next_pr[nid] = base_val + (damping * rank_sum)
            pagerank = next_pr

        # 3. Compute Betweenness Centrality (Brandes' Algorithm)
        betweenness: Dict[str, float] = {nid: 0.0 for nid in nodes_map}
        all_nodes = list(nodes_map.keys())

        for s in all_nodes:
            stack = []
            predecessors: Dict[str, List[str]] = {w: [] for w in all_nodes}
            sigma: Dict[str, int] = {w: 0 for w in all_nodes}
            sigma[s] = 1
            distance: Dict[str, int] = {w: -1 for w in all_nodes}
            distance[s] = 0
            queue = deque([s])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in adj[v]:
                    if distance[w] < 0:
                        queue.append(w)
                        distance[w] = distance[v] + 1
                    if distance[w] == distance[v] + 1:
                        sigma[w] += sigma[v]
                        predecessors[w].append(v)

            delta: Dict[str, float] = {w: 0.0 for w in all_nodes}
            while stack:
                w = stack.pop()
                for v in predecessors[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    betweenness[w] += delta[w]

        # Normalize betweenness
        max_b = max(betweenness.values()) if betweenness and max(betweenness.values()) > 0 else 1.0
        max_pr = max(pagerank.values()) if pagerank and max(pagerank.values()) > 0 else 1.0

        # 4. Synthesize Disruption Potential Score & Qualitative Attack-Chain Role
        node_metrics: List[CentralityNodeMetric] = []
        for nid, info in nodes_map.items():
            norm_b = betweenness[nid] / max_b
            norm_pr = pagerank[nid] / max_pr
            crit = info["criticality"]

            crit_multiplier = 1.4 if crit == "CRITICAL" else (1.2 if crit == "HIGH" else 1.0)
            raw_disruption = ((0.5 * norm_b) + (0.3 * norm_pr) + (0.2 * (in_degree[nid] + out_degree[nid]) / 10.0)) * 100.0 * crit_multiplier
            disruption_score = round(min(100.0, max(0.0, raw_disruption)), 1)

            if disruption_score >= 70.0:
                tier = "CRITICAL"
            elif disruption_score >= 45.0:
                tier = "HIGH"
            elif disruption_score >= 20.0:
                tier = "MEDIUM"
            else:
                tier = "LOW"

            # Derive role in attack chain
            if norm_b >= 0.5:
                role = "Lateral Bridge / Choke Point Gateway"
            elif crit == "CRITICAL" and in_degree[nid] >= 2:
                role = "Crown Jewel Data Sink / Primary Objective"
            elif out_degree[nid] >= 3:
                role = "High-Degree Lateral Pivot Hub"
            elif in_degree[nid] == 0:
                role = "Entry Endpoint / Identity Origin"
            else:
                role = "Intermediate Enterprise Node"

            node_metrics.append(
                CentralityNodeMetric(
                    node_id=nid,
                    node_label=info["label"],
                    node_name=info["name"],
                    criticality=crit,
                    pagerank=round(pagerank[nid], 5),
                    betweenness=round(betweenness[nid], 3),
                    in_degree=in_degree[nid],
                    out_degree=out_degree[nid],
                    disruption_score=disruption_score,
                    disruption_tier=tier,
                    role_in_attack_chain=role,
                )
            )

        # Sort top disruption nodes and top bridge nodes
        top_disruption = sorted(node_metrics, key=lambda m: m.disruption_score, reverse=True)[:top_k]
        top_bridges = sorted(node_metrics, key=lambda m: m.betweenness, reverse=True)[:top_k]

        top_bridge_names = [f"{b.node_name} ({b.node_id})" for b in top_bridges[:3]]
        summary = (
            f"Centrality analytics evaluated {total_nodes} enterprise nodes and {valid_edges_count} directional interaction edges. "
            f"Brandes' Betweenness Centrality identified the primary lateral movement choke points as: {', '.join(top_bridge_names)}. "
            f"These systems sit on the highest density of multi-hop shortest paths. Securing or micro-segmenting these key bridge nodes "
            f"will eliminate the largest percentage of adversary attack routes prior to exploitation."
        )

        return CentralityAnalysisResult(
            total_nodes_analyzed=total_nodes,
            total_edges_analyzed=valid_edges_count,
            top_disruption_nodes=top_disruption,
            network_bridge_nodes=top_bridges,
            executive_summary=summary,
        )


def get_centrality_service(client: Optional[Neo4jClient] = None) -> CentralityAnalyticsService:
    """Dependency injector for CentralityAnalyticsService."""
    return CentralityAnalyticsService(client=client)

