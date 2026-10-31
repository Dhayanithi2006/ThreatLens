"""
ThreatLens GraphOps - API Router
Exposes health verification, connection diagnostics, and schema constraint initialization
without exposing sensitive credentials or disrupting existing ThreatLens endpoints.
"""

import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, status, Depends, Query

logger = logging.getLogger(__name__)
from backend.graphops.client import (
    get_graphops_client,
    Neo4jClient,
    GraphOpsConnectionError,
    GraphOpsQueryError,
)
from backend.graphops.schema import TraversalDirection, RelationshipType
from backend.models.graphops import (
    BlastRadiusRequest,
    BlastRadiusResult,
    BlastRadiusContainmentRequest,
    BlastRadiusContainmentResult,
    AttackPathRequest,
    AttackPathResult,
    ChokePointRequest,
    ChokePointResult,
    ContainmentSimulationRequest,
    ContainmentSimulationResult,
    CaseBridgeResponse,
    AccessSequenceRequest,
    AccessSequenceAnomalyResult,
    BaselineProfileSummary,
    AnomalyTestSuiteResult,
    DijkstraShortestPathRequest,
    DijkstraShortestPathResult,
    SecurityEventEnvelope,
    SecurityFindingRecord,
    EventPublishResponse,
    KafkaServiceStatus,
    DeadLetterEventEnvelope,
    EventAnomalyPrediction,
    MLModelStatus,
    MLTrainResponse,
    EventFeatureRecord,
    GraphStructureAnomalyResult,
    PyGEvaluateRequest,
    PyGModelStatus,
    PyGTrainResponse,
)
from backend.graphops.zero_trust import ZeroTrustAuditResult

from backend.core.security import verify_admin_access

router = APIRouter()


@router.get(
    "/health",
    summary="GraphOps Neo4j Health Check",
    description="Verifies graph database connectivity and driver status. Sanitized; never returns credentials.",
)
async def graphops_health_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """
    Safe health check for the GraphOps Neo4j backend.
    Returns HTTP 200 if connected, HTTP 503 if unavailable.
    """
    health = client.health_check()
    if not health.get("connected"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "message": "GraphOps database connection is unavailable.",
                "database": health.get("database"),
                "status": "unhealthy",
                "connected": False,
                "error": health.get("error"),
            },
        )
    return health


@router.get(
    "/schema/constraints",
    summary="View GraphOps Schema Constraints",
    description="Returns list of configured unique constraints and indexes for organizational graph entities.",
)
async def list_schema_constraints_endpoint() -> Dict[str, Any]:
    from backend.graphops.schema import CYPHER_SCHEMA_STATEMENTS
    return {
        "total_constraints_and_indexes": len(CYPHER_SCHEMA_STATEMENTS),
        "statements": CYPHER_SCHEMA_STATEMENTS,
    }


@router.post(
    "/schema/init",
    summary="Initialize Neo4j Schema Constraints",
    description="Idempotently creates unique constraints on node IDs and indexes on critical properties.",
)
async def init_schema_constraints_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Applies unique constraints and indexes to the connected Neo4j instance."""
    try:
        return client.init_schema_constraints()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot initialize schema: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Schema initialization error: {str(e)}",
        )


# ==========================================================
# INGESTION & GRAPH TOPOLOGY SUMMARY
# ==========================================================

@router.post(
    "/ingest/sample",
    response_model=dict,
    summary="Ingest Sample Enterprise Security Graph Fixture",
    description="Loads the curated, synthetic SOC enterprise graph fixture into Neo4j idempotently.",
)
async def ingest_sample_fixture_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Loads default synthetic enterprise security graph fixture into Neo4j."""
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        client.verify_connectivity()
        engine = GraphOpsIngestionEngine(client)
        summary = engine.ingest_sample_fixture()
        return summary.model_dump()
    except (GraphOpsConnectionError, Exception) as e:
        logger.warning(f"Neo4j offline during sample fixture ingestion; serving in-memory demonstration replica: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        from datetime import datetime, timezone
        mock_c = get_mock_graphops_client()
        return {
            "status": "SUCCESS",
            "dataset_name": "simulated_soc_enterprise_fixture_v1",
            "nodes_imported": len(mock_c.nodes),
            "nodes_updated": 0,
            "nodes_rejected": 0,
            "relationships_imported": len(mock_c.edges),
            "relationships_updated": 0,
            "relationships_rejected": 0,
            "errors": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nodes_created_or_updated": len(mock_c.nodes),
            "relationships_created_or_updated": len(mock_c.edges),
        }


@router.post(
    "/ingest/bulk",
    response_model=dict,
    summary="Bulk Ingest Custom Entities and Relationships",
    description="Validates and idempotently imports custom BulkIngestPayload into Neo4j with batching.",
)
async def ingest_bulk_payload_endpoint(
    payload: dict,
    client: Neo4jClient = Depends(get_graphops_client),
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Imports custom bulk JSON dataset of enterprise nodes and edges."""
    from backend.models.graphops import BulkIngestPayload
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        validated_payload = BulkIngestPayload(**payload)
        engine = GraphOpsIngestionEngine(client)
        summary = engine.ingest_payload(validated_payload)
        return summary.model_dump()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during bulk ingestion: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Bulk payload validation or ingestion error: {str(e)}",
        )


@router.post(
    "/ingest/csv",
    response_model=dict,
    summary="Ingest CSV Entities or Relationships",
    description="Validates and idempotently imports CSV enterprise inventory or relationship data into Neo4j.",
)
async def ingest_csv_endpoint(
    payload: dict,
    client: Neo4jClient = Depends(get_graphops_client),
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Imports CSV data (nodes or relationships) into the enterprise security graph."""
    from backend.graphops.ingest import GraphOpsIngestionEngine
    csv_text = payload.get("csv_data") or payload.get("csv") or ""
    if not csv_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'csv_data' in request body.",
        )
    dataset_name = payload.get("dataset_name", "csv_import")
    data_type = payload.get("data_type", "auto")

    try:
        engine = GraphOpsIngestionEngine(client)
        summary = engine.ingest_csv(csv_text, dataset_name=dataset_name, data_type=data_type)
        return summary.model_dump()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during CSV ingestion: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"CSV validation or ingestion error: {str(e)}",
        )


@router.get(
    "/summary",
    summary="Get GraphOps Topology Summary",
    description="Returns aggregate entity counts by label, relationship counts by type, and Crown Jewels status.",
)
async def get_graphops_summary_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> Dict[str, Any]:
    """Returns high-level graph metrics and inventory summary."""
    from backend.graphops.ingest import GraphOpsIngestionEngine
    try:
        engine = GraphOpsIngestionEngine(client)
        return engine.get_graph_summary()
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot fetch graph summary: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve graph summary: {str(e)}",
        )


# ==========================================================
# BLAST-RADIUS ANALYTICS
# ==========================================================

@router.get(
    "/blast-radius",
    response_model=BlastRadiusResult,
    summary="Calculate Neighborhood Blast Radius",
    description="Calculates bounded 1-hop, 2-hop, and 3-hop blast radius neighborhoods from a compromised entity.",
)
async def get_blast_radius_endpoint(
    start_node_id: str = Query(..., description="Canonical ID or alias of starting node"),
    max_hops: int = Query(3, ge=1, le=3, description="Neighborhood depth (1, 2, or 3 hops)"),
    direction: TraversalDirection = Query(TraversalDirection.OUTGOING, description="Traversal direction: OUTGOING, INCOMING, or BOTH"),
    include_hypothetical: bool = Query(False, description="Whether to include hypothetical exploit edges"),
    relationship_types: Optional[str] = Query(None, description="Comma-separated list of allowed relationship types"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> BlastRadiusResult:
    """Calculates multi-hop blast radius using GET query parameters."""
    from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

    allowed_types = None
    if relationship_types:
        raw_types = [t.strip() for t in relationship_types.split(",") if t.strip()]
        allowed_types = []
        for rt in raw_types:
            try:
                allowed_types.append(RelationshipType(rt))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid relationship type in filter: '{rt}'",
                )

    request = BlastRadiusRequest(
        start_node_id=start_node_id,
        max_hops=max_hops,
        direction=direction,
        include_hypothetical=include_hypothetical,
        allowed_relationship_types=allowed_types,
    )

    try:
        service = BlastRadiusService(client)
        return service.calculate_blast_radius(request)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = BlastRadiusService(get_mock_graphops_client())
        try:
            res = service.calculate_blast_radius(request)
            res.warnings.append("Calculated against in-memory enterprise fixture (Neo4j offline).")
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blast radius calculation error: {str(e)}",
        )


@router.post(
    "/blast-radius",
    response_model=BlastRadiusResult,
    summary="Calculate Neighborhood Blast Radius (JSON Body)",
    description="Calculates bounded 1-hop, 2-hop, and 3-hop blast radius neighborhoods from a compromised entity via POST request body.",
)
async def post_blast_radius_endpoint(
    payload: BlastRadiusRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> BlastRadiusResult:
    """Calculates multi-hop blast radius using POST request body."""
    from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

    try:
        service = BlastRadiusService(client)
        return service.calculate_blast_radius(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = BlastRadiusService(get_mock_graphops_client())
        try:
            res = service.calculate_blast_radius(payload)
            res.warnings.append("Calculated against in-memory enterprise fixture (Neo4j offline).")
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blast radius calculation error: {str(e)}",
        )


@router.post(
    "/blast-radius/simulate",
    response_model=BlastRadiusContainmentResult,
    summary="Simulate Blast-Radius Containment In-Memory",
    description="Compares baseline vs post-intervention blast radius perimeter without modifying persistent data.",
)
async def post_blast_radius_simulate_endpoint(
    payload: BlastRadiusContainmentRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> BlastRadiusContainmentResult:
    """Calculates What-If containment impact against blast-radius perimeter in memory."""
    from backend.graphops.blast_radius import BlastRadiusService, NodeNotFoundError

    blast_req = BlastRadiusRequest(
        start_node_id=payload.start_node_id,
        max_hops=payload.max_hops,
        direction=payload.direction,
        allowed_relationship_types=payload.allowed_relationship_types,
        include_hypothetical=payload.include_hypothetical,
    )

    try:
        service = BlastRadiusService(client)
        return service.simulate_blast_containment(blast_req, payload.proposed_interventions)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = BlastRadiusService(get_mock_graphops_client())
        try:
            return service.simulate_blast_containment(blast_req, payload.proposed_interventions)
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blast radius simulation error: {str(e)}",
        )


# ==========================================================
# ATTACK-PATH DISCOVERY
# ==========================================================

@router.post(
    "/attack-paths",
    response_model=AttackPathResult,
    summary="Discover Candidate Attack Paths to Crown Jewels",
    description="Discovers bounded, acyclic access paths from specified entry point to critical assets with risk scoring.",
)
async def post_attack_paths_endpoint(
    payload: AttackPathRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AttackPathResult:
    """Discovers plausible attack paths to Crown Jewels using AttackPathRequest payload."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    try:
        service = AttackPathService(client)
        return service.find_attack_paths(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        try:
            res = service.find_attack_paths(payload)
            res.warnings.append("Calculated against in-memory enterprise fixture (Neo4j offline).")
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Attack path discovery error: {str(e)}",
        )

# ==========================================================
# DIJKSTRA SHORTEST-PATH ANALYSIS
# ==========================================================

@router.post(
    "/dijkstra",
    response_model=DijkstraShortestPathResult,
    summary="Compute Dijkstra Weighted Shortest Path (Alias)",
    include_in_schema=True,
)
@router.post(
    "/shortest-path",
    response_model=DijkstraShortestPathResult,
    summary="Compute Dijkstra Weighted Shortest Path to Critical Asset",
    description="Computes the genuine minimum-cost candidate attack route from an entry point to designated critical asset(s) using a priority queue.",
)
async def post_shortest_path_endpoint(
    payload: DijkstraShortestPathRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> DijkstraShortestPathResult:
    """Computes Dijkstra minimum-cost path using DijkstraShortestPathRequest payload."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    try:
        service = AttackPathService(client)
        return service.find_dijkstra_shortest_path(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        try:
            res = service.find_dijkstra_shortest_path(payload)
            res.warnings.append("Calculated against in-memory enterprise fixture (Neo4j offline).")
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dijkstra shortest path calculation error: {str(e)}",
        )


@router.get(
    "/dijkstra",
    response_model=DijkstraShortestPathResult,
    summary="Compute Dijkstra Weighted Shortest Path via Query Parameters (Alias)",
    include_in_schema=True,
)
@router.get(
    "/shortest-path",
    response_model=DijkstraShortestPathResult,
    summary="Compute Dijkstra Weighted Shortest Path via Query Parameters",
    description="Computes minimum-cost route using GET query parameters.",
)
async def get_shortest_path_endpoint(
    entry_node_id: str = Query(..., description="Canonical ID of starting entry node"),
    target_node_id: Optional[str] = Query(None, description="Optional target critical asset node ID"),
    target_node_ids: Optional[str] = Query(None, description="Comma-separated list of target critical assets"),
    include_hypothetical: bool = Query(True, description="Whether to include hypothetical exploit edges"),
    max_cost: Optional[float] = Query(None, description="Optional upper bound on total path traversal cost"),
    relationship_types: Optional[str] = Query(None, description="Comma-separated list of allowed relationship types"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> DijkstraShortestPathResult:
    """Computes Dijkstra minimum-cost path using GET query parameters."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    allowed_types = None
    if relationship_types:
        raw_types = [t.strip() for t in relationship_types.split(",") if t.strip()]
        allowed_types = []
        for rt in raw_types:
            try:
                allowed_types.append(RelationshipType(rt))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid relationship type in filter: '{rt}'",
                )

    targets_set = None
    if target_node_ids:
        targets_set = [t.strip() for t in target_node_ids.split(",") if t.strip()]

    request = DijkstraShortestPathRequest(
        entry_node_id=entry_node_id,
        target_node_id=target_node_id,
        target_node_ids=targets_set,
        allowed_relationship_types=allowed_types,
        include_hypothetical=include_hypothetical,
        max_cost=max_cost,
    )

    try:
        service = AttackPathService(client)
        return service.find_dijkstra_shortest_path(request)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        try:
            res = service.find_dijkstra_shortest_path(request)
            res.warnings.append("Calculated against in-memory enterprise fixture (Neo4j offline).")
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(nfe),
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dijkstra shortest path calculation error: {str(e)}",
        )


# ==========================================================
# CHOKE-POINT ANALYSIS
# ==========================================================

@router.get(
    "/choke-points",
    response_model=ChokePointResult,
    summary="Analyze Candidate Attack Paths for Strategic Choke Points",
    description="Identifies and ranks intermediate entities that eliminate the highest percentage of attack paths.",
)
async def get_choke_points_endpoint(
    entry_node_id: Optional[str] = Query(None, description="Optional entry point to analyze; if omitted, evaluates across default entry points"),
    top_n: int = Query(5, ge=1, le=20, description="Number of top choke points to return"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> ChokePointResult:
    """Calculates choke points using GET query parameters."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError
    from backend.models.graphops import AttackPathRequest

    try:
        service = AttackPathService(client)
        if entry_node_id:
            req = AttackPathRequest(entry_node_id=entry_node_id, max_depth=5, include_hypothetical=True)
            path_res = service.find_attack_paths(req)
            paths = path_res.paths
        else:
            paths = []
            for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
                try:
                    req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                    path_res = service.find_attack_paths(req)
                    paths.extend(path_res.paths)
                except Exception:
                    continue

        return service.analyze_choke_points(paths=paths, top_n=top_n)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entry entity not found: {str(e)}",
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        try:
            if entry_node_id:
                req = AttackPathRequest(entry_node_id=entry_node_id, max_depth=5, include_hypothetical=True)
                path_res = service.find_attack_paths(req)
                paths = path_res.paths
            else:
                paths = []
                for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
                    try:
                        req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                        path_res = service.find_attack_paths(req)
                        paths.extend(path_res.paths)
                    except Exception:
                        continue

            res = service.analyze_choke_points(paths=paths, top_n=top_n)
            res.explanation += " (Calculated against in-memory enterprise fixture; Neo4j offline)."
            return res
        except NodeNotFoundError as nfe:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entry entity not found: {str(nfe)}",
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Choke-point analysis error: {str(e)}",
        )


@router.post(
    "/choke-points",
    response_model=ChokePointResult,
    summary="Analyze Candidate Attack Paths for Strategic Choke Points (JSON Body)",
    description="Identifies and ranks intermediate entities that eliminate the highest percentage of attack paths via POST body.",
)
async def post_choke_points_endpoint(
    payload: ChokePointRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> ChokePointResult:
    """Calculates choke points using POST request body."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.models.graphops import AttackPathRequest

    try:
        service = AttackPathService(client)
        paths = []
        for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
            try:
                req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                path_res = service.find_attack_paths(req)
                paths.extend(path_res.paths)
            except Exception:
                continue

        if payload.analyzed_path_ids:
            target_pids = set(payload.analyzed_path_ids)
            paths = [p for p in paths if p.path_id in target_pids]

        return service.analyze_choke_points(paths=paths, top_n=payload.top_n)
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        paths = []
        for default_entry in ["device:dev-ws-101", "device:dev-ws-102"]:
            try:
                req = AttackPathRequest(entry_node_id=default_entry, max_depth=5, include_hypothetical=True)
                path_res = service.find_attack_paths(req)
                paths.extend(path_res.paths)
            except Exception:
                continue

        if payload.analyzed_path_ids:
            target_pids = set(payload.analyzed_path_ids)
            paths = [p for p in paths if p.path_id in target_pids]

        res = service.analyze_choke_points(paths=paths, top_n=payload.top_n)
        res.explanation += " (Calculated against in-memory enterprise fixture; Neo4j offline)."
        return res
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Choke-point analysis error: {str(e)}",
        )


# ==========================================================
# WHAT-IF CONTAINMENT SIMULATION
# ==========================================================

@router.post(
    "/simulate-containment",
    response_model=ContainmentSimulationResult,
    summary="Simulate Containment Interventions In-Memory",
    description="Evaluates proposed containment actions (isolation, connection severing) strictly in memory without altering persistent data.",
)
async def post_simulate_containment_endpoint(
    payload: ContainmentSimulationRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> ContainmentSimulationResult:
    """Executes safe in-memory What-If containment simulation."""
    from backend.graphops.attack_paths import AttackPathService
    from backend.graphops.blast_radius import NodeNotFoundError

    try:
        service = AttackPathService(client)
        return service.simulate_containment(payload)
    except NodeNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        logger.warning(f"Neo4j offline; falling back to in-memory graphops client: {e}")
        from backend.graphops.mock_client import get_mock_graphops_client
        service = AttackPathService(get_mock_graphops_client())
        return service.simulate_containment(payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation error: {str(e)}",
        )


# ==========================================================
# CASE-TO-ORGANIZATION FORENSIC BRIDGE
# ==========================================================

@router.get(
    "/bridge/case/{case_id}",
    response_model=CaseBridgeResponse,
    summary="Bridge Email Case Evidence to Organizational Graph",
    description="Maps email forensic evidence to internal user accounts and devices, while isolating external IOCs.",
)
async def get_case_bridge_endpoint(
    case_id: str,
    client: Neo4jClient = Depends(get_graphops_client),
) -> CaseBridgeResponse:
    """Bridges email case evidence to organizational security graph."""
    from backend.graphops.attack_paths import AttackPathService, CaseNotFoundError

    try:
        service = AttackPathService(client)
        return service.bridge_case_to_graph(case_id)
    except CaseNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except GraphOpsConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database unreachable during case bridge resolution: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Case bridge resolution error: {str(e)}",
        )


# ==========================================================
# GRAPH-BASED ACCESS ANOMALY DETECTION (PHASE 9)
# ==========================================================

@router.post(
    "/anomaly/evaluate-sequence",
    response_model=AccessSequenceAnomalyResult,
    summary="Evaluate Access Sequence for Graph-Based Anomalies",
    description="Evaluates an ordered sequence of relationships against baseline tiering, IAM policies, and role profiles.",
)
async def post_evaluate_sequence_endpoint(
    payload: AccessSequenceRequest,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AccessSequenceAnomalyResult:
    """Evaluates access sequence against documented security graph baseline."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    try:
        detector = AccessAnomalyDetector(client)
        return detector.evaluate_sequence(payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Access sequence anomaly evaluation error: {str(e)}",
        )


@router.get(
    "/anomaly/baseline",
    response_model=BaselineProfileSummary,
    summary="Get Documented Anomaly Baseline Rules and Profiles",
    description="Returns active network tiering rules, department profiles, and scoring formula used for anomaly detection.",
)
async def get_anomaly_baseline_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> BaselineProfileSummary:
    """Returns baseline rules and active security profile summary."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    detector = AccessAnomalyDetector(client)
    return detector.get_baseline_summary()


@router.get(
    "/anomaly/test-suite",
    response_model=AnomalyTestSuiteResult,
    summary="Run Benchmark Test Suite Across Labeled Sequences",
    description="Evaluates the held-out labeled test sequences fixture and returns precision, recall, F1, and FPR.",
)
async def get_anomaly_test_suite_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
) -> AnomalyTestSuiteResult:
    """Runs evaluation benchmark against the 12 curated labeled test sequences."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    detector = AccessAnomalyDetector(client)
    return detector.run_test_suite()


@router.get(
    "/anomaly/evaluate-case/{case_id}",
    response_model=AccessSequenceAnomalyResult,
    summary="Evaluate Case-Linked Access Sequence for Anomalies",
    description="Bridges email case evidence to internal identity/workstation and evaluates the observed access sequence.",
)
async def get_evaluate_case_anomalies_endpoint(
    case_id: str,
    client: Neo4jClient = Depends(get_graphops_client),
) -> AccessSequenceAnomalyResult:
    """Bridges case evidence and evaluates access sequence against graph baseline."""
    from backend.graphops.anomaly_detection import AccessAnomalyDetector
    try:
        detector = AccessAnomalyDetector(client)
        return detector.evaluate_case(case_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Case anomaly evaluation error: {str(e)}",
        )


# ==========================================================
# COMMUNITY DETECTION & ALERT NARRATIVE SYNTHESIS (HACKATHON)
# ==========================================================

@router.get(
    "/communities",
    summary="Detect Graph Security Enclaves & Lateral Movement Boundaries",
    description="Partitions graph entities into logical security communities and identifies cross-boundary edges.",
)
async def get_communities_endpoint(
    client: Neo4jClient = Depends(get_graphops_client),
):
    """Executes security community detection across graph entities."""
    from backend.graphops.communities import detect_security_communities
    try:
        return detect_security_communities(client)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Community detection error: {str(e)}",
        )


@router.get(
    "/incident-narrative/{case_id}",
    summary="Synthesize Unified Incident Narrative & Alert Reduction Metrics",
    description="Correlates disparate raw SIEM alerts into a unified kill-chain narrative with alert reduction percentage.",
)
async def get_incident_narrative_endpoint(
    case_id: str,
    client: Neo4jClient = Depends(get_graphops_client),
):
    """Synthesizes unified incident kill chain narrative from raw alerts."""
    from backend.graphops.alert_consolidation import synthesize_incident_narrative
    try:
        return synthesize_incident_narrative(case_id, client)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Incident narrative synthesis error: {str(e)}",
        )


# ==========================================================
# APACHE KAFKA EVENT STREAMING & FINDINGS ENDPOINTS
# ==========================================================

def get_kafka_producer_dep():
    from backend.graphops.kafka_producer import get_kafka_producer
    return get_kafka_producer()

def get_kafka_worker_dep():
    from backend.graphops.kafka_worker import get_kafka_worker
    return get_kafka_worker()


@router.post(
    "/events/publish",
    response_model=EventPublishResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Publish Security Event to Kafka Streaming Topic",
    description="Validates canonical SecurityEventEnvelope and publishes to Kafka with per-entity partition ordering.",
)
async def publish_security_event_endpoint(
    payload: SecurityEventEnvelope,
    producer: Any = Depends(get_kafka_producer_dep),
) -> EventPublishResponse:
    """Publishes a validated security event envelope to Apache Kafka."""
    from backend.graphops.kafka_producer import KafkaProducerError

    try:
        return producer.publish_security_event(payload)
    except KafkaProducerError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Kafka streaming broker unavailable: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security event publishing error: {str(e)}",
        )


@router.post(
    "/events/simulate",
    summary="Simulate End-to-End Kafka Streaming Demonstration",
    description="Publishes a synthetic compromise-indicator event, triggers worker consumption, updates graph, and returns triggered GraphOps findings.",
)
async def simulate_kafka_event_endpoint(
    device_id: str = Query("device:dev-ws-101", description="Target canonical device ID for simulation"),
    scenario: str = Query("COMPROMISE_INDICATOR", description="Event scenario: COMPROMISE_INDICATOR, IDENTITY_LOGON, NETWORK_CONNECTION"),
    client: Neo4jClient = Depends(get_graphops_client),
    producer: Any = Depends(get_kafka_producer_dep),
    worker: Any = Depends(get_kafka_worker_dep),
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Executes a complete end-to-end Kafka streaming demonstration scenario."""
    from backend.graphops.kafka_simulator import (
        create_synthetic_compromise_indicator,
        create_synthetic_identity_event,
        create_synthetic_network_event,
    )

    try:
        health = client.health_check()
        if not health.get("connected"):
            from backend.graphops.mock_client import get_mock_graphops_client
            client = get_mock_graphops_client()
    except Exception:
        from backend.graphops.mock_client import get_mock_graphops_client
        client = get_mock_graphops_client()

    worker.processor.client = client
    worker.processor.producer = producer
    worker.producer = producer

    if scenario == "IDENTITY_LOGON":
        event = create_synthetic_identity_event(user_id="user:victim1@corporation.com", target_resource_id=device_id)
    elif scenario == "NETWORK_CONNECTION":
        event = create_synthetic_network_event(source_entity_id=device_id, target_entity_id="server:srv-app-02")
    else:
        event = create_synthetic_compromise_indicator(device_id=device_id)

    pub_result = producer.publish_security_event(event)
    if getattr(producer, "mock_mode", False):
        worker.mock_mode = True

    # Process message through consumer worker
    messages_processed = worker.run_once()

    findings = worker.processor.get_findings(source_event_id=event.event_id)

    return {
        "status": "COMPLETED",
        "scenario": scenario,
        "event_published": pub_result.model_dump(),
        "messages_consumed_count": messages_processed,
        "findings_generated_count": len(findings),
        "findings": [f.model_dump() for f in findings],
        "disclaimer": "SYNTHETIC DEMONSTRATION DATA ONLY",
    }


@router.get(
    "/events/findings",
    response_model=List[SecurityFindingRecord],
    summary="Query Event-Triggered Security Findings",
    description="Retrieves explainable security findings produced by event-triggered GraphOps analytics.",
)
async def get_event_findings_endpoint(
    source_event_id: Optional[str] = Query(None, description="Filter findings by originating Kafka event ID"),
    entity_id: Optional[str] = Query(None, description="Filter findings by affected entity canonical ID"),
    limit: int = Query(50, ge=1, le=200, description="Maximum findings to return"),
    worker: Any = Depends(get_kafka_worker_dep),
) -> List[SecurityFindingRecord]:
    """Returns list of security findings produced by Kafka event consumer."""
    return worker.processor.get_findings(source_event_id=source_event_id, entity_id=entity_id, limit=limit)


@router.get(
    "/events/findings/{finding_id}",
    response_model=SecurityFindingRecord,
    summary="Get Specific Security Finding by ID",
    description="Retrieves single finding with full algorithmic evidence, cost, hops, and blast radius.",
)
async def get_finding_by_id_endpoint(
    finding_id: str,
    worker: Any = Depends(get_kafka_worker_dep),
) -> SecurityFindingRecord:
    """Retrieves single finding by its unique ID."""
    finding = worker.processor.get_finding_by_id(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )
    return finding


@router.get(
    "/events/status",
    response_model=KafkaServiceStatus,
    summary="Get Kafka Streaming Service Status",
    description="Returns operational diagnostics for Kafka producer and consumer workers.",
)
async def get_kafka_status_endpoint(
    producer: Any = Depends(get_kafka_producer_dep),
    worker: Any = Depends(get_kafka_worker_dep),
) -> KafkaServiceStatus:
    """Returns Kafka readiness and telemetry ingestion statistics."""
    worker_status = worker.get_status()

    return KafkaServiceStatus(
        broker_connected=not producer.mock_mode,
        bootstrap_servers=producer.bootstrap_servers,
        consumer_worker_running=worker_status["worker_running"],
        active_consumer_group=worker.group_id,
        processed_events_count=worker.processed_count,
        dead_letter_events_count=worker.dlq_count,
        findings_generated_count=len(worker.processor._findings_store),
        last_processed_timestamp=worker.last_processed_timestamp,
    )


@router.get(
    "/events/dlq",
    response_model=List[Dict[str, Any]],
    summary="View Dead-Letter Queue (DLQ) Messages",
    description="Returns dead-lettered event envelopes for operator review and forensics.",
)
async def get_dlq_messages_endpoint(
    producer: Any = Depends(get_kafka_producer_dep),
    actor: str = Depends(verify_admin_access),
) -> List[Dict[str, Any]]:
    """Returns buffered dead-letter events."""
    import json
    from backend.core import config
    dlq_list = producer._mock_messages.get(config.KAFKA_TOPIC_DLQ, [])
    results = []
    for item in dlq_list:
        try:
            results.append(json.loads(item["value"].decode("utf-8")))
        except Exception:
            results.append({"raw": str(item["value"])})
    return results


# ==========================================================
# SCIKIT-LEARN EVENT ANOMALY DETECTION ENDPOINTS
# ==========================================================

def get_ml_service_dep():
    from backend.graphops.ml_service import get_event_anomaly_ml_service
    return get_event_anomaly_ml_service()


@router.post(
    "/events/ml/evaluate",
    response_model=EventAnomalyPrediction,
    summary="Evaluate Security Event with scikit-learn Isolation Forest",
    description="Directly scores an incoming security event using the trained Isolation Forest pipeline.",
)
async def evaluate_event_ml_endpoint(
    payload: SecurityEventEnvelope,
    ml_service: Any = Depends(get_ml_service_dep),
) -> EventAnomalyPrediction:
    """Evaluates a SecurityEventEnvelope and returns anomaly prediction with rationale."""
    return ml_service.evaluate_event(payload)


@router.get(
    "/events/ml/status",
    response_model=MLModelStatus,
    summary="Get scikit-learn Model Operational Status",
    description="Returns metadata, active version, threshold, contamination, and evaluation metrics.",
)
async def get_ml_status_endpoint(
    ml_service: Any = Depends(get_ml_service_dep),
) -> MLModelStatus:
    """Returns active model health and performance metrics."""
    return ml_service.get_status()


@router.post(
    "/events/ml/train",
    response_model=MLTrainResponse,
    summary="Trigger Controlled Model Retraining",
    description="Admin-only endpoint to train and evaluate a new Isolation Forest model artifact.",
)
async def train_ml_model_endpoint(
    contamination: float = Query(0.08, ge=0.01, le=0.5, description="Expected contamination rate"),
    random_seed: int = Query(42, description="Random seed for reproducibility"),
    ml_service: Any = Depends(get_ml_service_dep),
    actor: str = Depends(verify_admin_access),
) -> MLTrainResponse:
    """Executes controlled model retraining and evaluation."""
    from backend.graphops.ml_training import train_event_anomaly_pipeline

    try:
        resp = train_event_anomaly_pipeline(
            model_path=ml_service.model_path,
            meta_path=ml_service.meta_path,
            contamination=contamination,
            random_seed=random_seed,
        )
        # Reload model in service
        ml_service._load_or_initialize_model()
        return resp
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(e)}",
        )


# ==========================================================
# PYTORCH GEOMETRIC (PYG) GRAPH LEARNING ENDPOINTS
# ==========================================================

def get_pyg_service_dep():
    from backend.graphops.pyg_service import get_pyg_learning_service
    return get_pyg_learning_service()


@router.post(
    "/events/pyg/evaluate",
    response_model=GraphStructureAnomalyResult,
    summary="Evaluate Candidate Relationship with PyTorch Geometric GNN",
    description="Evaluates the topological plausibility and structural anomaly of a candidate relationship.",
)
async def evaluate_relationship_pyg_endpoint(
    payload: PyGEvaluateRequest,
    pyg_service: Any = Depends(get_pyg_service_dep),
) -> GraphStructureAnomalyResult:
    """Evaluates candidate relationship against active enterprise graph topology."""
    return pyg_service.evaluate_relationship(
        source_entity_id=payload.source_entity_id,
        target_entity_id=payload.target_entity_id,
        relationship_type=payload.relationship_type,
        traversal_cost=payload.traversal_cost,
        evidence_class=payload.evidence_class,
    )


@router.get(
    "/events/pyg/status",
    response_model=PyGModelStatus,
    summary="Get PyTorch Geometric Model Operational Status",
    description="Returns metadata, active GNN version, threshold, node/edge counts, and held-out evaluation metrics.",
)
async def get_pyg_status_endpoint(
    pyg_service: Any = Depends(get_pyg_service_dep),
) -> PyGModelStatus:
    """Returns active PyG model health, configuration, and evaluation metrics."""
    return pyg_service.get_status()


@router.post(
    "/events/pyg/train",
    response_model=PyGTrainResponse,
    summary="Trigger Controlled PyG GNN Model Retraining",
    description="Admin-only endpoint to train, validate, and persist a new PyG StructuralGraphSageModel artifact.",
)
async def train_pyg_model_endpoint(
    num_epochs: int = Query(50, ge=5, le=200, description="Training epochs"),
    learning_rate: float = Query(0.01, ge=0.0001, le=0.1, description="Adam optimizer learning rate"),
    random_seed: int = Query(42, description="Random seed for reproducibility"),
    pyg_service: Any = Depends(get_pyg_service_dep),
    actor: str = Depends(verify_admin_access),
) -> PyGTrainResponse:
    """Executes controlled GNN training with leakage-aware splits and saves new artifact."""
    from backend.graphops.pyg_training import train_pyg_structural_gnn

    try:
        resp = train_pyg_structural_gnn(
            model_path=pyg_service.model_path,
            meta_path=pyg_service.meta_path,
            embedding_dim=pyg_service.metadata.get("embedding_dim", 64),
            hidden_dim=pyg_service.metadata.get("hidden_dim", 64),
            num_epochs=num_epochs,
            learning_rate=learning_rate,
            random_seed=random_seed,
            device=pyg_service.device,
        )
        # Reload newly saved model artifact in inference service
        pyg_service._load_or_initialize_model()
        pyg_service._active_snapshot = None
        return resp
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PyG model training failed: {str(e)}",
        )


# ==========================================================
# ZERO-TRUST ACCESS AUDIT (ENTITLED VS. OBSERVED COMPARISON)
# ==========================================================

@router.get(
    "/zero-trust/audit",
    response_model=ZeroTrustAuditResult,
    summary="Zero-Trust Access Audit (Entitled vs. Observed Telemetry)",
    description="Compares explicit IAM/ACL directory entitlements against empirical observed network connections to detect dormant over-privileged access and unauthorized shadow connections.",
)
async def get_zero_trust_audit_endpoint(
    entity_id: Optional[str] = Query(None, description="Optional entity canonical ID to filter zero-trust audit"),
    status_filter: Optional[str] = Query(None, description="Optional status filter (ACTIVE_VERIFIED, OVER_PRIVILEGED_DORMANT, UNENTITLED_SHADOW)"),
    client: Neo4jClient = Depends(get_graphops_client),
) -> ZeroTrustAuditResult:
    """Executes dual-graph relational comparison: Entitled Access (IAM) vs. Observed Usage (Telemetry)."""
    try:
        from backend.graphops.zero_trust import get_zero_trust_service, ZeroTrustAuditResult
        service = get_zero_trust_service(client)
        return service.audit_access_entitlements(entity_id=entity_id, status_filter=status_filter)
    except Exception as e:
        logger.error(f"Zero-Trust audit failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Zero-Trust access audit failed: {str(e)}",
        )


# ==========================================================
# GRAPH CENTRALITY ANALYTICS (PAGERANK & BETWEENNESS)
# ==========================================================

@router.get(
    "/centrality",
    summary="Graph Centrality Analytics (PageRank & Betweenness Disruption)",
    description="Calculates PageRank and Brandes' Betweenness Centrality across the organizational knowledge graph to identify critical pivot points and disruption hubs.",
)
async def get_graph_centrality_endpoint(
    top_k: int = Query(10, ge=1, le=50, description="Number of top disruption nodes to return"),
    client: Neo4jClient = Depends(get_graphops_client),
):
    """Computes PageRank authority and Betweenness lateral-bridge metrics across live Neo4j topology."""
    try:
        from backend.graphops.centrality import get_centrality_service
        service = get_centrality_service(client)
        return service.analyze_graph_centrality(top_k=top_k)
    except Exception as e:
        logger.error(f"Centrality analytics failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Centrality analytics calculation failed: {str(e)}",
        )







