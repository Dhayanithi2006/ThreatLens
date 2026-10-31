# ThreatLens GraphOps — Complete API Endpoint Inventory

## 1. Overview & Distribution Statistics

This inventory provides a verified map of all **80 registered API routes** in the ThreatLens FastAPI application.
Every route has been verified directly from the live `FastAPI` router configuration.

| Subsystem / Router | Base Prefix | Route Count | Primary Dependencies | Status |
|---|---|---|---|---|
| **Core Email & Alert Ingestion** | `/api/v1` | 17 | Case Store, IOC Extractor, VirusTotal, AbuseIPDB, NLP, Readiness Probe | `LOCAL INTEGRATION VERIFIED` |
| **GraphOps & Streaming Pipeline** | `/api/v1/graphops` | 38 | Neo4j (Bolt/Mock), Kafka (Producer/Worker), PyG GNN, Isolation Forest | `LOCAL INTEGRATION VERIFIED` |
| **Governance, Compliance & Audit** | `/api/v1/governance` | 19 | Standards Catalog (NIST CSF 2.0 / CIS), SHA-256 Ledger, Policy Store, Reports & Evidence Service | `LOCAL INTEGRATION VERIFIED` |
| **Remote Windows Collector** | `/api/v1/collector` | 5 | Collector Registry (FileLock), Normalizer, Rate Limiter, Kafka | `LOCAL INTEGRATION VERIFIED` |
| **Root Application** | `/` | 1 | FastAPI Metadata | `IMPLEMENTED` |
| **Total Registered Routes** | — | **80** | Full ThreatLens Detection Fabric | **100% DISCOVERED** |

---

## 2. Authentication & Authorization Model

The application enforces three distinct authentication schemes across its endpoints:
1. **Administrative Authorization (`verify_admin_access`)**:
   * Applied to state-mutating operations: schema initialization, bulk ingestion, policy modifications, collector enrollment, and token revocation.
   * Checks `X-API-Key` or `Authorization: Bearer <key>` using constant-time comparison against `config.ADMIN_API_KEY` (`hmac.compare_digest`).
   * When `config.REQUIRE_API_KEY=True`, missing or invalid keys return HTTP 401 Unauthorized. In development (`config.REQUIRE_API_KEY=False`), defaults to `dev-user-local` unless an invalid key is explicitly passed.
2. **Collector Token Authentication (`authenticate_collector`)**:
   * Applied to `POST /api/v1/collector/ingest/events`.
   * Requires `X-Collector-ID` and `X-Collector-Token` HTTP headers.
   * Verified against HMAC-SHA256 digests stored in `backend/collector/registry.py`. Revoked or unverified collectors are rejected with HTTP 401.
3. **Audited Analyst Access (`get_actor_identity`) / Public Health**:
   * Non-blocking identity resolution extracting the caller ID for tamper-evident audit logging, defaulting to `analyst-session`.

---

## 3. Comprehensive Endpoint Inventory Table

### Core Email & Threat Detection Endpoints (/api/v1)

#### `POST /api/v1/analyze/threat`
- **Handler**: `backend.api.routes.analyze_threat_endpoint`
- **Summary / Purpose**: Dedicated endpoint for Threat Detection.
- **Input Schema**: Body: `<class 'backend.models.threat.EmailAnalysisInput'>` (Required: True)<br>`email_data`: `<class 'backend.models.threat.EmailAnalysisInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ThreatDetectionResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: AbuseIPDB / VirusTotal
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_threat_detection.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/analyze/explain`
- **Handler**: `backend.api.routes.explain_threat_endpoint`
- **Summary / Purpose**: Dedicated endpoint for Explainable AI.
- **Input Schema**: Body: `<class 'backend.models.threat.EmailAnalysisInput'>` (Required: True)<br>`email_data`: `<class 'backend.models.threat.EmailAnalysisInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ExplainableThreatResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_explainable_ai.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/analyze`
- **Handler**: `backend.api.routes.unified_analyze_endpoint`
- **Summary / Purpose**: Unified email analysis endpoint returning threat assessment with evidence explanations.
- **Input Schema**: Body: `<class 'backend.models.threat.EmailAnalysisInput'>` (Required: True)<br>`email_data`: `<class 'backend.models.threat.EmailAnalysisInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ExplainableThreatResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_explainable_ai.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/analyze/forensics`
- **Handler**: `backend.api.routes.analyze_forensics_endpoint`
- **Summary / Purpose**: Accepts raw .eml string and returns comprehensive forensic analysis.
- **Input Schema**: Body: `<class 'backend.models.forensics.RawEmlInput'>` (Required: True)<br>`payload`: `<class 'backend.models.forensics.RawEmlInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ForensicEvidenceResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_email_forensics.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/analyze/forensics/upload`
- **Handler**: `backend.api.routes.upload_forensics_endpoint`
- **Summary / Purpose**: Handles raw .eml file upload with size boundaries and extension validation.
- **Input Schema**: Body: `<class 'fastapi._compat.v2.Body_upload_forensics_endpoint_api_v1_analyze_forensics_upload_post'>` (Required: True)<br>`file`: `<class 'fastapi.datastructures.UploadFile'>` (Default: annotation=UploadFile required=True alias='file' json_schema_extra={})
- **Success Response**: HTTP `200` $\rightarrow$ `ForensicEvidenceResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/analyze/iocs`
- **Handler**: `backend.api.routes.analyze_iocs_endpoint`
- **Summary / Purpose**: Dedicated endpoint for IOC Extraction.
- **Input Schema**: Body: `<class 'backend.models.ioc.IocExtractionInput'>` (Required: True)<br>`payload`: `<class 'backend.models.ioc.IocExtractionInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `IocExtractionResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_ioc_extractor.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/analyze/intelligence`
- **Handler**: `backend.api.routes.analyze_intelligence_endpoint`
- **Summary / Purpose**: Dedicated endpoint for Threat Intelligence.
- **Input Schema**: Body: `<class 'backend.models.intel.ThreatIntelligenceInput'>` (Required: True)<br>`payload`: `<class 'backend.models.intel.ThreatIntelligenceInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ThreatIntelligenceResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: AbuseIPDB / VirusTotal
- **Frontend Trigger / View**: `/api/v1/analyze/intelligence`
- **Existing Test Coverage**: `test_phase4_integration.py`, `test_threat_intelligence.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/cases`
- **Handler**: `backend.api.routes.list_cases_endpoint`
- **Summary / Purpose**: Retrieves all indexed cases in repository.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/cases`
- **Existing Test Coverage**: `test_attack_graph.py`, `test_neo4j_integration.py` (+1 more)
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/cases/{case_id}/graph`
- **Handler**: `backend.api.routes.get_case_graph_endpoint`
- **Summary / Purpose**: Generates attack graph for a specific case.
- **Input Schema**: `case_id`: `<class 'str'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `AttackGraph`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_attack_graph.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/campaigns`
- **Handler**: `backend.api.routes.list_campaigns_endpoint`
- **Summary / Purpose**: Returns detected campaign clusters across all cases.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: `/api/v1/campaigns`
- **Existing Test Coverage**: `test_attack_graph.py`, `test_neo4j_integration.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/campaigns/{campaign_id}/graph`
- **Handler**: `backend.api.routes.get_campaign_graph_endpoint`
- **Summary / Purpose**: Generates multi-email campaign cluster graph.
- **Input Schema**: `campaign_id`: `<class 'str'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `AttackGraph`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/campaigns/CMP-001/graph`
- **Existing Test Coverage**: `test_phase8_verification.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/search/ioc`
- **Handler**: `backend.api.routes.search_ioc_endpoint`
- **Summary / Purpose**: Cross-investigation indicator search.
- **Input Schema**: `q`: `<class 'str'>` (Default: annotation=str required=True alias='q' description='Indicator string e.g. 185.190.140.22, alert-center.xyz' json_schema_extra={})
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/analyze/eml`
- **Handler**: `backend.api.routes.analyze_complete_eml_endpoint`
- **Summary / Purpose**: Complete end-to-end pipeline starting from raw .eml RFC 822 input.
- **Input Schema**: Body: `<class 'backend.models.forensics.RawEmlInput'>` (Required: True)<br>`payload`: `<class 'backend.models.forensics.RawEmlInput'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Isolation Forest ML, AbuseIPDB / VirusTotal
- **Frontend Trigger / View**: `/api/v1/analyze/eml`
- **Existing Test Coverage**: `test_attack_graph.py`, `test_email_forensics.py` (+3 more)
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/demo-emails`
- **Handler**: `backend.api.routes.get_demo_emails`
- **Summary / Purpose**: No docstring provided.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_threat_detection.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/demo-emls`
- **Handler**: `backend.api.routes.get_demo_emls`
- **Summary / Purpose**: No docstring provided.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Isolation Forest ML, AbuseIPDB / VirusTotal
- **Frontend Trigger / View**: `/api/v1/demo-emls`
- **Existing Test Coverage**: `test_email_forensics.py`, `test_phase8_verification.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/health`
- **Handler**: `backend.api.routes.health_check`
- **Summary / Purpose**: Basic HTTP server liveness check returning service and application version.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: `/api/v1/health`
- **Existing Test Coverage**: `test_graphops_phase7.py`, `test_neo4j_integration.py` (+1 more)
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/ready`
- **Handler**: `backend.api.routes.readiness_check`
- **Summary / Purpose**: Deep operational readiness probe evaluating Neo4j connectivity, Kafka streaming producer & worker, audit ledger integrity, and collector registry accessibility.
- **Input Schema**: `allow_mock`: bool (Default: True)
- **Success Response**: HTTP `200` $\rightarrow$ `dict` (or HTTP `503` if unready)
- **Authentication**: None (Public / Analyst / K8s Probe)
- **Infrastructure Dependencies**: Neo4j Client, Kafka Producer/Worker, Audit Ledger, Collector Registry
- **Frontend Trigger / View**: `/api/v1/ready`
- **Existing Test Coverage**: `test_shared_event_pipeline_prompt7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

### GraphOps Knowledge Graph & Streaming Endpoints (/api/v1/graphops)

#### `GET /api/v1/graphops/health`
- **Handler**: `backend.api.graphops_routes.graphops_health_endpoint`
- **Summary / Purpose**: Safe health check for the GraphOps Neo4j backend.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/health`
- **Existing Test Coverage**: `test_graphops_phase7.py`, `test_neo4j_integration.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/schema/constraints`
- **Handler**: `backend.api.graphops_routes.list_schema_constraints_endpoint`
- **Summary / Purpose**: No docstring provided.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_neo4j_integration.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/schema/init`
- **Handler**: `backend.api.graphops_routes.init_schema_constraints_endpoint`
- **Summary / Purpose**: Applies unique constraints and indexes to the connected Neo4j instance.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/graphops/ingest/sample`
- **Handler**: `backend.api.graphops_routes.ingest_sample_fixture_endpoint`
- **Summary / Purpose**: Loads default synthetic enterprise security graph fixture into Neo4j.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/ingest/sample`
- **Existing Test Coverage**: `test_graphops_ingest.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/ingest/bulk`
- **Handler**: `backend.api.graphops_routes.ingest_bulk_payload_endpoint`
- **Summary / Purpose**: Imports custom bulk JSON dataset of enterprise nodes and edges.
- **Input Schema**: Body: `<class 'dict'>` (Required: True)<br>`payload`: `<class 'dict'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/graphops/ingest/csv`
- **Handler**: `backend.api.graphops_routes.ingest_csv_endpoint`
- **Summary / Purpose**: Imports CSV data (nodes or relationships) into the enterprise security graph.
- **Input Schema**: Body: `<class 'dict'>` (Required: True)<br>`payload`: `<class 'dict'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_phase2.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/summary`
- **Handler**: `backend.api.graphops_routes.get_graphops_summary_endpoint`
- **Summary / Purpose**: Returns high-level graph metrics and inventory summary.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_ingest.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/blast-radius`
- **Handler**: `backend.api.graphops_routes.get_blast_radius_endpoint`
- **Summary / Purpose**: Calculates multi-hop blast radius using GET query parameters.
- **Input Schema**: `start_node_id`: `<class 'str'>` (Default: annotation=str required=True alias='start_node_id' description='Canonical ID or alias of starting node' json_schema_extra={})<br>`max_hops`: `<class 'int'>` (Default: annotation=int required=False default=3 alias='max_hops' description='Neighborhood depth (1, 2, or 3 hops)' json_schema_extra={} metadata=[Ge(ge=1), Le(le=3)])<br>`direction`: `<enum 'TraversalDirection'>` (Default: annotation=TraversalDirection required=False default=<TraversalDirection.OUTGOING: 'OUTGOING'> alias='direction' description='Traversal direction: OUTGOING, INCOMING, or BOTH' json_schema_extra={})<br>`include_hypothetical`: `<class 'bool'>` (Default: annotation=bool required=False default=False alias='include_hypothetical' description='Whether to include hypothetical exploit edges' json_schema_extra={})<br>`relationship_types`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='relationship_types' description='Comma-separated list of allowed relationship types' json_schema_extra={})<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `BlastRadiusResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/blast-radius` (Pillar 3: Assess Impact)
- **Existing Test Coverage**: `test_blast_radius.py`, `test_phase4_integration.py`, `test_blast_radius_simulation_prompt4.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/blast-radius`
- **Handler**: `backend.api.graphops_routes.post_blast_radius_endpoint`
- **Summary / Purpose**: Calculates multi-hop blast radius using POST request body.
- **Input Schema**: Body: `<class 'backend.models.graphops.BlastRadiusRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.BlastRadiusRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `BlastRadiusResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/blast-radius` (Pillar 3: Assess Impact)
- **Existing Test Coverage**: `test_blast_radius.py`, `test_phase4_integration.py`, `test_blast_radius_simulation_prompt4.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/blast-radius/simulate`
- **Handler**: `backend.api.graphops_routes.post_blast_radius_simulate_endpoint`
- **Summary / Purpose**: Calculates What-If containment impact against blast-radius perimeter in memory.
- **Input Schema**: Body: `<class 'backend.models.graphops.BlastRadiusContainmentRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.BlastRadiusContainmentRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `BlastRadiusContainmentResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/blast-radius/simulate` (Pillar 3: What-If Containment)
- **Existing Test Coverage**: `test_blast_radius_simulation_prompt4.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/attack-paths`
- **Handler**: `backend.api.graphops_routes.post_attack_paths_endpoint`
- **Summary / Purpose**: Discovers plausible attack paths to Crown Jewels using AttackPathRequest payload.
- **Input Schema**: Body: `<class 'backend.models.graphops.AttackPathRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.AttackPathRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `AttackPathResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/attack-paths`
- **Existing Test Coverage**: `test_attack_paths.py`, `test_attack_path_analysis_prompt3.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/shortest-path`
- **Handler**: `backend.api.graphops_routes.post_shortest_path_endpoint`
- **Summary / Purpose**: Computes Dijkstra minimum-cost path using DijkstraShortestPathRequest payload.
- **Input Schema**: Body: `<class 'backend.models.graphops.DijkstraShortestPathRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.DijkstraShortestPathRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `DijkstraShortestPathResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/shortest-path`
- **Existing Test Coverage**: `test_dijkstra.py`, `test_graphops_phase7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/dijkstra`
- **Handler**: `backend.api.graphops_routes.post_shortest_path_endpoint`
- **Summary / Purpose**: Computes Dijkstra minimum-cost path using DijkstraShortestPathRequest payload.
- **Input Schema**: Body: `<class 'backend.models.graphops.DijkstraShortestPathRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.DijkstraShortestPathRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `DijkstraShortestPathResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_phase7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/shortest-path`
- **Handler**: `backend.api.graphops_routes.get_shortest_path_endpoint`
- **Summary / Purpose**: Computes Dijkstra minimum-cost path using GET query parameters.
- **Input Schema**: `entry_node_id`: `<class 'str'>` (Default: annotation=str required=True alias='entry_node_id' description='Canonical ID of starting entry node' json_schema_extra={})<br>`target_node_id`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='target_node_id' description='Optional target critical asset node ID' json_schema_extra={})<br>`target_node_ids`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='target_node_ids' description='Comma-separated list of target critical assets' json_schema_extra={})<br>`include_hypothetical`: `<class 'bool'>` (Default: annotation=bool required=False default=True alias='include_hypothetical' description='Whether to include hypothetical exploit edges' json_schema_extra={})<br>`max_cost`: `typing.Optional[float]` (Default: annotation=Union[float, NoneType] required=False default=None alias='max_cost' description='Optional upper bound on total path traversal cost' json_schema_extra={})<br>`relationship_types`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='relationship_types' description='Comma-separated list of allowed relationship types' json_schema_extra={})<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `DijkstraShortestPathResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/shortest-path`
- **Existing Test Coverage**: `test_dijkstra.py`, `test_graphops_phase7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/dijkstra`
- **Handler**: `backend.api.graphops_routes.get_shortest_path_endpoint`
- **Summary / Purpose**: Computes Dijkstra minimum-cost path using GET query parameters.
- **Input Schema**: `entry_node_id`: `<class 'str'>` (Default: annotation=str required=True alias='entry_node_id' description='Canonical ID of starting entry node' json_schema_extra={})<br>`target_node_id`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='target_node_id' description='Optional target critical asset node ID' json_schema_extra={})<br>`target_node_ids`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='target_node_ids' description='Comma-separated list of target critical assets' json_schema_extra={})<br>`include_hypothetical`: `<class 'bool'>` (Default: annotation=bool required=False default=True alias='include_hypothetical' description='Whether to include hypothetical exploit edges' json_schema_extra={})<br>`max_cost`: `typing.Optional[float]` (Default: annotation=Union[float, NoneType] required=False default=None alias='max_cost' description='Optional upper bound on total path traversal cost' json_schema_extra={})<br>`relationship_types`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='relationship_types' description='Comma-separated list of allowed relationship types' json_schema_extra={})<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `DijkstraShortestPathResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_phase7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/choke-points`
- **Handler**: `backend.api.graphops_routes.get_choke_points_endpoint`
- **Summary / Purpose**: Calculates choke points using GET query parameters.
- **Input Schema**: `entry_node_id`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='entry_node_id' description='Optional entry point to analyze; if omitted, evaluates across default entry points' json_schema_extra={})<br>`top_n`: `<class 'int'>` (Default: annotation=int required=False default=5 alias='top_n' description='Number of top choke points to return' json_schema_extra={} metadata=[Ge(ge=1), Le(le=20)])<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `ChokePointResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/choke-points`
- **Existing Test Coverage**: `test_attack_paths.py`, `test_attack_path_analysis_prompt3.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/choke-points`
- **Handler**: `backend.api.graphops_routes.post_choke_points_endpoint`
- **Summary / Purpose**: Calculates choke points using POST request body.
- **Input Schema**: Body: `<class 'backend.models.graphops.ChokePointRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.ChokePointRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `ChokePointResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/choke-points`
- **Existing Test Coverage**: `test_attack_paths.py`, `test_attack_path_analysis_prompt3.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/simulate-containment`
- **Handler**: `backend.api.graphops_routes.post_simulate_containment_endpoint`
- **Summary / Purpose**: Executes safe in-memory What-If containment simulation.
- **Input Schema**: Body: `<class 'backend.models.graphops.ContainmentSimulationRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.ContainmentSimulationRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `ContainmentSimulationResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/simulate-containment`
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `GET /api/v1/graphops/bridge/case/{case_id}`
- **Handler**: `backend.api.graphops_routes.get_case_bridge_endpoint`
- **Summary / Purpose**: Bridges email case evidence to organizational security graph.
- **Input Schema**: `case_id`: `<class 'str'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `CaseBridgeResponse`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_phase4_integration.py`, `test_phase8_verification.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/anomaly/evaluate-sequence`
- **Handler**: `backend.api.graphops_routes.post_evaluate_sequence_endpoint`
- **Summary / Purpose**: Evaluates access sequence against documented security graph baseline.
- **Input Schema**: Body: `<class 'backend.models.graphops.AccessSequenceRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.AccessSequenceRequest'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `AccessSequenceAnomalyResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Isolation Forest ML
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_anomaly.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/anomaly/baseline`
- **Handler**: `backend.api.graphops_routes.get_anomaly_baseline_endpoint`
- **Summary / Purpose**: Returns baseline rules and active security profile summary.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `BaselineProfileSummary`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Isolation Forest ML
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_anomaly.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/anomaly/test-suite`
- **Handler**: `backend.api.graphops_routes.get_anomaly_test_suite_endpoint`
- **Summary / Purpose**: Runs evaluation benchmark against the 12 curated labeled test sequences.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `AnomalyTestSuiteResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Isolation Forest ML
- **Frontend Trigger / View**: `/api/v1/graphops/anomaly/test-suite`
- **Existing Test Coverage**: `test_graphops_anomaly.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/anomaly/evaluate-case/{case_id}`
- **Handler**: `backend.api.graphops_routes.get_evaluate_case_anomalies_endpoint`
- **Summary / Purpose**: Bridges case evidence and evaluates access sequence against graph baseline.
- **Input Schema**: `case_id`: `<class 'str'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `AccessSequenceAnomalyResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Isolation Forest ML
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_anomaly.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/communities`
- **Handler**: `backend.api.graphops_routes.get_communities_endpoint`
- **Summary / Purpose**: Executes security community detection across graph entities.
- **Input Schema**: `client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/communities`
- **Existing Test Coverage**: `test_graphops_hackathon_enhancements.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/incident-narrative/{case_id}`
- **Handler**: `backend.api.graphops_routes.get_incident_narrative_endpoint`
- **Summary / Purpose**: Synthesizes unified incident kill chain narrative from raw alerts.
- **Input Schema**: `case_id`: `<class 'str'>` (Default: REQUIRED)<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_hackathon_enhancements.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/events/publish`
- **Handler**: `backend.api.graphops_routes.publish_security_event_endpoint`
- **Summary / Purpose**: Publishes a validated security event envelope to Apache Kafka.
- **Input Schema**: Body: `<class 'backend.models.graphops.SecurityEventEnvelope'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.SecurityEventEnvelope'>` (Default: REQUIRED)<br>`producer`: `typing.Any` (Default: Depends(dependency=<function get_kafka_producer_dep at 0x000001F472F46B60>, use_cache=True, scope=None))
- **Success Response**: HTTP `202` $\rightarrow$ `EventPublishResponse`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_kafka.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/events/simulate`
- **Handler**: `backend.api.graphops_routes.simulate_kafka_event_endpoint`
- **Summary / Purpose**: Executes a complete end-to-end Kafka streaming demonstration scenario.
- **Input Schema**: `device_id`: `<class 'str'>` (Default: annotation=str required=False default='device:dev-ws-101' alias='device_id' description='Target canonical device ID for simulation' json_schema_extra={})<br>`scenario`: `<class 'str'>` (Default: annotation=str required=False default='COMPROMISE_INDICATOR' alias='scenario' description='Event scenario: COMPROMISE_INDICATOR, IDENTITY_LOGON, NETWORK_CONNECTION' json_schema_extra={})<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))<br>`producer`: `typing.Any` (Default: Depends(dependency=<function get_kafka_producer_dep at 0x000001F472F46B60>, use_cache=True, scope=None))<br>`worker`: `typing.Any` (Default: Depends(dependency=<function get_kafka_worker_dep at 0x000001F40D60D940>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_kafka.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/events/findings`
- **Handler**: `backend.api.graphops_routes.get_event_findings_endpoint`
- **Summary / Purpose**: Returns list of security findings produced by Kafka event consumer.
- **Input Schema**: `source_event_id`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='source_event_id' description='Filter findings by originating Kafka event ID' json_schema_extra={})<br>`entity_id`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='entity_id' description='Filter findings by affected entity canonical ID' json_schema_extra={})<br>`limit`: `<class 'int'>` (Default: annotation=int required=False default=50 alias='limit' description='Maximum findings to return' json_schema_extra={} metadata=[Ge(ge=1), Le(le=200)])<br>`worker`: `typing.Any` (Default: Depends(dependency=<function get_kafka_worker_dep at 0x000001F40D60D940>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: `/api/v1/graphops/events/findings`
- **Existing Test Coverage**: `test_graphops_kafka.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/events/findings/{finding_id}`
- **Handler**: `backend.api.graphops_routes.get_finding_by_id_endpoint`
- **Summary / Purpose**: Retrieves single finding by its unique ID.
- **Input Schema**: `finding_id`: `<class 'str'>` (Default: REQUIRED)<br>`worker`: `typing.Any` (Default: Depends(dependency=<function get_kafka_worker_dep at 0x000001F40D60D940>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `SecurityFindingRecord`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_kafka.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/events/status`
- **Handler**: `backend.api.graphops_routes.get_kafka_status_endpoint`
- **Summary / Purpose**: Returns Kafka readiness and telemetry ingestion statistics.
- **Input Schema**: `producer`: `typing.Any` (Default: Depends(dependency=<function get_kafka_producer_dep at 0x000001F472F46B60>, use_cache=True, scope=None))<br>`worker`: `typing.Any` (Default: Depends(dependency=<function get_kafka_worker_dep at 0x000001F40D60D940>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `KafkaServiceStatus`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: `/api/v1/graphops/events/status`
- **Existing Test Coverage**: `test_graphops_kafka.py`, `test_graphops_phase7.py` (+1 more)
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/events/dlq`
- **Handler**: `backend.api.graphops_routes.get_dlq_messages_endpoint`
- **Summary / Purpose**: Returns buffered dead-letter events.
- **Input Schema**: `producer`: `typing.Any` (Default: Depends(dependency=<function get_kafka_producer_dep at 0x000001F472F46B60>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/graphops/events/ml/evaluate`
- **Handler**: `backend.api.graphops_routes.evaluate_event_ml_endpoint`
- **Summary / Purpose**: Evaluates a SecurityEventEnvelope and returns anomaly prediction with rationale.
- **Input Schema**: Body: `<class 'backend.models.graphops.SecurityEventEnvelope'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.SecurityEventEnvelope'>` (Default: REQUIRED)<br>`ml_service`: `typing.Any` (Default: Depends(dependency=<function get_ml_service_dep at 0x000001F40D60D9E0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `EventAnomalyPrediction`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, Isolation Forest ML
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_ml.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/graphops/events/ml/status`
- **Handler**: `backend.api.graphops_routes.get_ml_status_endpoint`
- **Summary / Purpose**: Returns active model health and performance metrics.
- **Input Schema**: `ml_service`: `typing.Any` (Default: Depends(dependency=<function get_ml_service_dep at 0x000001F40D60D9E0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `MLModelStatus`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, Isolation Forest ML
- **Frontend Trigger / View**: `/api/v1/graphops/events/ml/status`
- **Existing Test Coverage**: `test_graphops_ml.py`, `test_graphops_phase7.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/events/ml/train`
- **Handler**: `backend.api.graphops_routes.train_ml_model_endpoint`
- **Summary / Purpose**: Executes controlled model retraining and evaluation.
- **Input Schema**: `contamination`: `<class 'float'>` (Default: annotation=float required=False default=0.08 alias='contamination' description='Expected contamination rate' json_schema_extra={} metadata=[Ge(ge=0.01), Le(le=0.5)])<br>`random_seed`: `<class 'int'>` (Default: annotation=int required=False default=42 alias='random_seed' description='Random seed for reproducibility' json_schema_extra={})<br>`ml_service`: `typing.Any` (Default: Depends(dependency=<function get_ml_service_dep at 0x000001F40D60D9E0>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `MLTrainResponse`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, Isolation Forest ML
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_graphops_ml.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/graphops/events/pyg/evaluate`
- **Handler**: `backend.api.graphops_routes.evaluate_relationship_pyg_endpoint`
- **Summary / Purpose**: Evaluates candidate relationship against active enterprise graph topology.
- **Input Schema**: Body: `<class 'backend.models.graphops.PyGEvaluateRequest'>` (Required: True)<br>`payload`: `<class 'backend.models.graphops.PyGEvaluateRequest'>` (Default: REQUIRED)<br>`pyg_service`: `typing.Any` (Default: Depends(dependency=<function get_pyg_service_dep at 0x000001F40D60E980>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `GraphStructureAnomalyResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, PyTorch Geometric GNN
- **Frontend Trigger / View**: `/api/v1/graphops/events/pyg/evaluate`
- **Existing Test Coverage**: `test_graphops_phase7.py`, `test_graphops_pyg.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/graphops/events/pyg/status`
- **Handler**: `backend.api.graphops_routes.get_pyg_status_endpoint`
- **Summary / Purpose**: Returns active PyG model health, configuration, and evaluation metrics.
- **Input Schema**: `pyg_service`: `typing.Any` (Default: Depends(dependency=<function get_pyg_service_dep at 0x000001F40D60E980>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `PyGModelStatus`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, PyTorch Geometric GNN
- **Frontend Trigger / View**: `/api/v1/graphops/events/pyg/status`
- **Existing Test Coverage**: `test_graphops_phase7.py`, `test_graphops_pyg.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/graphops/events/pyg/train`
- **Handler**: `backend.api.graphops_routes.train_pyg_model_endpoint`
- **Summary / Purpose**: Executes controlled GNN training with leakage-aware splits and saves new artifact.
- **Input Schema**: `num_epochs`: `<class 'int'>` (Default: annotation=int required=False default=50 alias='num_epochs' description='Training epochs' json_schema_extra={} metadata=[Ge(ge=5), Le(le=200)])<br>`learning_rate`: `<class 'float'>` (Default: annotation=float required=False default=0.01 alias='learning_rate' description='Adam optimizer learning rate' json_schema_extra={} metadata=[Ge(ge=0.0001), Le(le=0.1)])<br>`random_seed`: `<class 'int'>` (Default: annotation=int required=False default=42 alias='random_seed' description='Random seed for reproducibility' json_schema_extra={})<br>`pyg_service`: `typing.Any` (Default: Depends(dependency=<function get_pyg_service_dep at 0x000001F40D60E980>, use_cache=True, scope=None))<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `PyGTrainResponse`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock, Kafka Producer / Worker, PyTorch Geometric GNN
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `GET /api/v1/graphops/zero-trust/audit`
- **Handler**: `backend.api.graphops_routes.get_zero_trust_audit_endpoint`
- **Summary / Purpose**: Executes dual-graph relational comparison: Entitled Access (IAM) vs. Observed Usage (Telemetry) with contextual principal, device, and resource matching.
- **Input Schema**: Query parameters:
  - `entity_id`: Optional[str] (Canonical entity ID filter)
  - `status_filter`: Optional[str] (Status filter: `ACTIVE_VERIFIED`, `OVER_PRIVILEGED_DORMANT`, `UNENTITLED_SHADOW`)
  - `client`: `Neo4jClient` (Dependency)
- **Success Response**: HTTP `200` $\rightarrow$ `ZeroTrustAuditResult`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: Check Access & Anomalies workspace (`runZeroTrustAudit()` in `frontend/js/app.js`)
- **Existing Test Coverage**: `test_graphops_zero_trust_centrality.py`, `test_zero_trust_anomaly_prompt5.py`
- **Verification Classification**: `INTEGRATION TESTED & VERIFIED (Prompt 5)`
- **Epistemological Guardrails**:
  - Unobserved grants are categorized as `UNEXERCISED_GRANT` requiring operational review (not automatically unnecessary privileges).
  - Unentitled observed connections are categorized as `POTENTIAL_UNENTITLED_ACCESS` indicating policy discrepancies (not conclusive proof of malicious breach).

#### `GET /api/v1/graphops/centrality`
- **Handler**: `backend.api.graphops_routes.get_graph_centrality_endpoint`
- **Summary / Purpose**: Computes PageRank authority and Betweenness lateral-bridge metrics across live Neo4j topology.
- **Input Schema**: `top_k`: `<class 'int'>` (Default: annotation=int required=False default=10 alias='top_k' description='Number of top disruption nodes to return' json_schema_extra={} metadata=[Ge(ge=1), Le(le=50)])<br>`client`: `<class 'backend.graphops.client.Neo4jClient'>` (Default: Depends(dependency=<function get_graphops_client at 0x000001F40D541EE0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Neo4j Bolt / Mock
- **Frontend Trigger / View**: `/api/v1/graphops/centrality`
- **Existing Test Coverage**: `test_graphops_zero_trust_centrality.py`
- **Verification Classification**: `UNIT TESTED`

### Governance, Compliance & Tamper-Evident Audit Endpoints (/api/v1/governance)

#### `GET /api/v1/governance/controls`
- **Handler**: `backend.api.governance_routes.list_standard_controls`
- **Summary / Purpose**: Returns verified, authoritative standards controls mapped to GraphOps findings.
- **Input Schema**: `framework`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='framework' description="Filter by framework (e.g. 'NIST CSF', 'CIS', 'ISO')" json_schema_extra={})<br>`applicability`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='applicability' description="Filter by category (e.g. 'Identity', 'Exposure')" json_schema_extra={})
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/controls`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/controls/{control_id}`
- **Handler**: `backend.api.governance_routes.get_standard_control`
- **Summary / Purpose**: Retrieves a specific standard control by normalized identifier (e.g. 'PR.AA-01', 'AC-3').
- **Input Schema**: `control_id`: `<class 'str'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `ControlRecord`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/policies`
- **Handler**: `backend.api.governance_routes.get_organization_policies`
- **Summary / Purpose**: Lists organization-specific policies with rule conditions and standards mappings.
- **Input Schema**: `scope`: `typing.Optional[str]` (Default: annotation=Union[str, NoneType] required=False default=None alias='scope' description='Filter by policy scope (e.g. ENTERPRISE, PRODUCTION)' json_schema_extra={})<br>`enabled_only`: `<class 'bool'>` (Default: annotation=bool required=False default=False alias='enabled_only' description='Filter for active policies only' json_schema_extra={})
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/policies`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/policies/{policy_id}`
- **Handler**: `backend.api.governance_routes.get_organization_policy`
- **Summary / Purpose**: Retrieves an organization policy by identifier.
- **Input Schema**: `policy_id`: `<class 'str'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `OrganizationPolicy`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/governance/policies`
- **Handler**: `backend.api.governance_routes.create_or_update_organization_policy`
- **Summary / Purpose**: Creates or updates an organization policy. Requires administrative privileges.
- **Input Schema**: Body: `<class 'backend.governance.schema.OrganizationPolicy'>` (Required: True)<br>`policy`: `<class 'backend.governance.schema.OrganizationPolicy'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `OrganizationPolicy`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/policies`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `DELETE /api/v1/governance/policies/{policy_id}`
- **Handler**: `backend.api.governance_routes.delete_organization_policy`
- **Summary / Purpose**: Deletes an organization policy. Requires administrative privileges.
- **Input Schema**: `policy_id`: `<class 'str'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`

#### `POST /api/v1/governance/evaluate`
- **Handler**: `backend.api.governance_routes.evaluate_governance_policies`
- **Summary / Purpose**: Evaluates organization policies against real finding evidence.
- **Input Schema**: Body: `<class 'backend.api.governance_routes.EvaluateRequest'>` (Required: True)<br>`payload`: `<class 'backend.api.governance_routes.EvaluateRequest'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/evaluate`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/remediations`
- **Handler**: `backend.api.governance_routes.get_remediations`
- **Summary / Purpose**: Lists remediation records with optional status and priority filtering.
- **Input Schema**: `status_filter`: `typing.Optional[backend.governance.schema.RemediationStatus]` (Default: annotation=Union[RemediationStatus, NoneType] required=False default=None alias='status' alias_priority=2 json_schema_extra={})<br>`priority_filter`: `typing.Optional[backend.governance.schema.RemediationPriority]` (Default: annotation=Union[RemediationPriority, NoneType] required=False default=None alias='priority' alias_priority=2 json_schema_extra={})
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/remediations`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/governance/remediations`
- **Handler**: `backend.api.governance_routes.create_new_remediation`
- **Summary / Purpose**: Files a new remediation record linked to a graph or policy finding.
- **Input Schema**: Body: `<class 'backend.api.governance_routes.CreateRemediationRequest'>` (Required: True)<br>`payload`: `<class 'backend.api.governance_routes.CreateRemediationRequest'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function get_actor_identity at 0x000001F40D5AD3A0>, use_cache=True, scope=None))
- **Success Response**: HTTP `201` $\rightarrow$ `RemediationRecord`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/remediations`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/remediations/{remediation_id}`
- **Handler**: `backend.api.governance_routes.get_remediation_item`
- **Summary / Purpose**: Retrieves a single remediation record by ID.
- **Input Schema**: `remediation_id`: `<class 'str'>` (Default: REQUIRED)
- **Success Response**: HTTP `200` $\rightarrow$ `RemediationRecord`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/remediations/${remId}`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `PATCH /api/v1/governance/remediations/{remediation_id}`
- **Handler**: `backend.api.governance_routes.update_remediation_item`
- **Summary / Purpose**: Updates remediation state and resolution evidence with audit tracking.
- **Input Schema**: Body: `<class 'backend.api.governance_routes.UpdateRemediationRequest'>` (Required: True)<br>`remediation_id`: `<class 'str'>` (Default: REQUIRED)<br>`payload`: `<class 'backend.api.governance_routes.UpdateRemediationRequest'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function get_actor_identity at 0x000001F40D5AD3A0>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `RemediationRecord`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/remediations/${remId}`
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/audit`
- **Handler**: `backend.api.governance_routes.get_audit_trail`
- **Summary / Purpose**: Returns chronological audit records from the cryptographic ledger.
- **Input Schema**: `limit`: `<class 'int'>` (Default: annotation=int required=False default=100 alias='limit' json_schema_extra={} metadata=[Ge(ge=1), Le(le=1000)])
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_phase6_governance_security.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/audit/verify`
- **Handler**: `backend.api.governance_routes.verify_ledger_cryptographic_integrity`
- **Summary / Purpose**: Validates SHA-256 hash chaining across all entries in the audit ledger.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/audit/verify`
- **Existing Test Coverage**: `test_phase6_governance_security.py`, `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/governance/reports/generate`
- **Handler**: `backend.api.governance_routes.generate_governance_report`
- **Summary / Purpose**: Generates an evidence-backed governance report evaluating active policies against real cases, graph topology, and collector telemetry.
- **Input Schema**: Body: `GenerateReportRequest` (framework: Optional[str], scope: Optional[str], start_time: Optional[str], end_time: Optional[str])
- **Success Response**: HTTP `201` $\rightarrow$ `GovernanceReport`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Evaluator, Policies Store, Case Store, SHA-256 Chained Hash Ledger
- **Frontend Trigger / View**: `/api/v1/governance/reports/generate`
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/reports`
- **Handler**: `backend.api.governance_routes.list_governance_reports`
- **Summary / Purpose**: Lists generated governance reports in reverse chronological order.
- **Input Schema**: `limit`: int (Default: 50, ge=1, le=200)
- **Success Response**: HTTP `200` $\rightarrow$ `List[GovernanceReport]`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: GovernanceReportService In-Memory Store
- **Frontend Trigger / View**: `/api/v1/governance/reports` (Reports Hub Pane)
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/reports/{report_id}`
- **Handler**: `backend.api.governance_routes.get_governance_report_by_id`
- **Summary / Purpose**: Retrieves a generated governance report by canonical report ID.
- **Input Schema**: `report_id`: str (Required)
- **Success Response**: HTTP `200` $\rightarrow$ `GovernanceReport`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: GovernanceReportService In-Memory Store
- **Frontend Trigger / View**: `/api/v1/governance/reports/{report_id}`
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/reports/{report_id}/export`
- **Handler**: `backend.api.governance_routes.export_governance_report`
- **Summary / Purpose**: Exports a generated governance report in JSON, CSV, or safe HTML format with strict XSS sanitization (html.escape).
- **Input Schema**: `report_id`: str, `format`: str (json, csv, html)
- **Success Response**: HTTP `200` $\rightarrow$ Formatted File Stream (`application/json`, `text/csv`, `text/html`)
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: GovernanceReportService, html.escape Sanitization
- **Frontend Trigger / View**: `/api/v1/governance/reports/{report_id}/export`
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/governance/evidence/ledger`
- **Handler**: `backend.api.governance_routes.get_evidence_ledger`
- **Summary / Purpose**: Retrieves cryptographic chain-of-custody records for email cases, graph findings, and collector telemetry with verified SHA-256 hashes.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `List[EvidenceLedgerItem]`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Case Store, Audit Ledger, SHA-256 Digest Engine
- **Frontend Trigger / View**: `/api/v1/governance/evidence/ledger` (Evidence Hub Pane)
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `POST /api/v1/governance/evidence/verify`
- **Handler**: `backend.api.governance_routes.verify_evidence_hash`
- **Summary / Purpose**: Verifies SHA-256 digest for an evidence item against chain-of-custody ledger using constant-time comparison.
- **Input Schema**: Body: `VerifyEvidenceRequest` (evidence_id: str, provided_hash: Optional[str])
- **Success Response**: HTTP `200` $\rightarrow$ `dict` (verified: bool, status: str, detail: str)
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: Constant-time HMAC comparison, Evidence Ledger
- **Frontend Trigger / View**: `/api/v1/governance/evidence/verify` (Evidence Verify Hash button)
- **Existing Test Coverage**: `test_governance_reports_prompt6.py`
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

### Remote Windows Collector Endpoints (/api/v1/collector)

#### `POST /api/v1/collector/enrol`
- **Handler**: `backend.api.collector_routes.enrol_collector_endpoint`
- **Summary / Purpose**: Admin-only: registers a new collector and returns its one-time token.
- **Input Schema**: Body: `<class 'backend.api.collector_routes.EnrolRequest'>` (Required: True)<br>`payload`: `<class 'backend.api.collector_routes.EnrolRequest'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `201` $\rightarrow$ `EnrolResponse`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: Kafka Producer / Worker
- **Frontend Trigger / View**: `/api/v1/collector/enrol`
- **Existing Test Coverage**: `test_collector_api.py`, `test_collector_e2e_simulation.py` (+1 more)
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

#### `GET /api/v1/collector/collectors`
- **Handler**: `backend.api.collector_routes.list_collectors_endpoint`
- **Summary / Purpose**: Admin-only: lists all registered collectors.
- **Input Schema**: `actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `List`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: Kafka Producer / Worker
- **Frontend Trigger / View**: `/api/v1/collector/collectors`
- **Existing Test Coverage**: `test_collector_api.py`, `test_collector_ui_telemetry_states.py`
- **Verification Classification**: `UNIT TESTED`

#### `GET /api/v1/collector/collectors/{collector_id}`
- **Handler**: `backend.api.collector_routes.get_collector_endpoint`
- **Summary / Purpose**: Admin-only: retrieves a single collector's operational status.
- **Input Schema**: `collector_id`: `<class 'str'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `CollectorStatusResponse`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_collector_api.py`, `test_collector_ui_telemetry_states.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/collector/collectors/{collector_id}/revoke`
- **Handler**: `backend.api.collector_routes.revoke_collector_endpoint`
- **Summary / Purpose**: Admin-only: revokes a collector's token.
- **Input Schema**: `collector_id`: `<class 'str'>` (Default: REQUIRED)<br>`actor`: `<class 'str'>` (Default: Depends(dependency=<function verify_admin_access at 0x000001F40D542D40>, use_cache=True, scope=None))
- **Success Response**: HTTP `200` $\rightarrow$ `Dict`
- **Authentication**: Admin (`X-API-Key` / `Bearer`)
- **Infrastructure Dependencies**: Kafka Producer / Worker
- **Frontend Trigger / View**: `/api/v1/collector/collectors/${cid}/revoke`
- **Existing Test Coverage**: `test_collector_api.py`, `test_collector_ui_telemetry_states.py`
- **Verification Classification**: `UNIT TESTED`

#### `POST /api/v1/collector/ingest/events`
- **Handler**: `backend.api.collector_routes.ingest_collector_events`
- **Summary / Purpose**: Ingestion endpoint for enrolled Windows collector agents.
- **Input Schema**: Body: `<class 'backend.api.collector_routes.CollectorIngestRequest'>` (Required: True)<br>`payload`: `<class 'backend.api.collector_routes.CollectorIngestRequest'>` (Default: REQUIRED)<br>`collector`: `<class 'inspect._empty'>` (Default: Depends(dependency=<function _get_collector_credentials at 0x000001F40D541D00>, use_cache=True, scope=None))<br>`producer`: `typing.Any` (Default: Depends(dependency=<function get_kafka_producer_dep at 0x000001F472F46B60>, use_cache=True, scope=None))
- **Success Response**: HTTP `202` $\rightarrow$ `CollectorIngestResponse`
- **Authentication**: Collector Token (`X-Collector-ID` & `X-Collector-Token`)
- **Infrastructure Dependencies**: Kafka Producer / Worker
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: `test_collector_api.py`, `test_collector_e2e_simulation.py` (+2 more)
- **Verification Classification**: `LOCAL INTEGRATION VERIFIED`

### Root & Application Meta Endpoints

#### `GET /`
- **Handler**: `backend.main.root`
- **Summary / Purpose**: No docstring provided.
- **Input Schema**: *None (empty)*
- **Success Response**: HTTP `200` $\rightarrow$ `dict`
- **Authentication**: None (Public / Analyst)
- **Infrastructure Dependencies**: In-Memory State
- **Frontend Trigger / View**: *Headless / Administrative / Background*
- **Existing Test Coverage**: *None (Direct HTTP test gap)*
- **Verification Classification**: `IMPLEMENTED (Needs HTTP test)`
