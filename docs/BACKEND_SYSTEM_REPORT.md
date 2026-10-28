# ThreatLens — Comprehensive Backend System Architecture & Validation Report

**Document Version:** 1.0.0  
**Date:** October 2026  
**Auditor / Architect:** Senior Backend Architect & Distributed Graph Intelligence Engineer  
**Scope:** `backend/` directory, core services, graph algorithms, ML/GNN pipelines, streaming infrastructure, security mechanisms, and automated test suites.  
**Repository:** `d:/Desktop/Hackathon/ThreatLens`

---

## Table of Contents
1. [Section 1: Executive Architecture Overview](#section-1-executive-architecture-overview)
2. [Section 2: Directory & Module Decomposition](#section-2-directory--module-decomposition)
3. [Section 3: API Endpoint Registry & Data Contracts](#section-3-api-endpoint-registry--data-contracts)
4. [Section 4: Algorithmic, ML & Graph Engines Deep Dive](#section-4-algorithmic-ml--graph-engines-deep-dive)
5. [Section 5: Security, Authorization & Configuration Framework](#section-5-security-authorization--configuration-framework)
6. [Section 6: Canonical Schema, Entity Ontology & Baseline Fixtures](#section-6-canonical-schema-entity-ontology--baseline-fixtures)
7. [Section 7: Automated Test Suite Coverage & Verification Metrics](#section-7-automated-test-suite-coverage--verification-metrics)
8. [Section 8: Independent Backend Validation Protocol (Runbook)](#section-8-independent-backend-validation-protocol-runbook)

---

## Section 1: Executive Architecture Overview

The ThreatLens backend is an asynchronous, high-throughput security intelligence service built on modern Python standards. It unifies email forensics, enterprise identity data, knowledge graph topology, real-time telemetry streaming, and hybrid machine learning into a coherent decision-support engine for Security Operations Centers (SOCs).

```
                             +-----------------------------------+
                             |     Client Requests / UI / SOC    |
                             +-----------------+-----------------+
                                               | (HTTP / REST)
                                               v
+-------------------------------------------------------------------------------------------------+
|                                    FastAPI Application Gateway                                  |
|                             (CORS, Error Handlers, Lifespan Hooks)                              |
+---------------------+------------------------+-------------------------+------------------------+
                      |                        |                         |
                      v                        v                         v
        +---------------------------+ +-------------------+ +-----------------------------+
        |   Email Forensics & IOC   | |  Governance Hub   | |   GraphOps Intelligence      |
        |   [backend/api/routes.py] | | [governance_routes| |  [api/graphops_routes.py]   |
        +-------------+-------------+ +---------+---------+ +--------------+--------------+
                      |                         |                          |
                      v                         v                          v
        +---------------------------+ +-------------------+ +-----------------------------+
        | Forensics Services Layer  | | Policy Evaluator  | | Graph Algorithms Engine     |
        | - MIME RFC 822 Parser     | | - Standards (25)  | | - Multi-Hop Blast Radius    |
        | - IOC Extractor & Hasher  | | - IAM / Exposure  | | - Dijkstra Shortest Path    |
        | - Explainable AI Scoring  | | - SHA-256 Ledger  | | - Attack Paths & Choke Pt   |
        | - Case Store & Campaigns  | |   Chained Audit   | | - What-If Containment (Mem) |
        +---------------------------+ +-------------------+ | - Louvain Communities       |
                                                            +--------------+--------------+
                                                                           |
                                            +------------------------------+------------------------------+
                                            |                                                             |
                                            v                                                             v
                            +-------------------------------+                             +-------------------------------+
                            |   Machine Learning & GNN      |                             |   Streaming & Telemetry Bus   |
                            | - 11-d Isolation Forest       |                             | - Kafka Event Processor       |
                            | - PyG 2-layer GCN Link Pred   |                             | - Kafka Consumer / Producer   |
                            | - Node Embedding Generator    |                             | - In-Memory Simulator Fallback|
                            +---------------+---------------+                             +---------------+---------------+
                                            |                                                             |
                                            +------------------------------+------------------------------+
                                                                           |
                                                                           v
                                                            +-------------------------------+
                                                            | Graph Driver / Storage Layer  |
                                                            | - Neo4j Managed Client (Bolt) |
                                                            | - Standalone Mock Client      |
                                                            | - Parameterized Cypher Driver |
                                                            +-------------------------------+
```

### Core Technology Stack

| Layer | Component | Version | Role in Architecture |
| :--- | :--- | :--- | :--- |
| **Web Gateway** | FastAPI | 0.115.11 | High-concurrency ASGI framework with native OpenAPI docs |
| **ASGI Engine** | Uvicorn | 0.34.0 | Asynchronous event-loop server running on uvloop/asyncio |
| **Data Validation** | Pydantic | 2.12.5 | Strict schema modeling, field parsing, and serialization |
| **Graph Database** | Neo4j Python Driver | 5.28.1 | Managed connection pool (Bolt protocol) with Cypher query parameterization |
| **Classical ML** | Scikit-learn / Joblib | 1.6.1 / 1.4.2 | 100-estimator Isolation Forest for tabular security event anomaly detection |
| **Graph Neural Net** | PyTorch / PyG | 2.6.0 / 2.6.1 | 2-layer Graph Convolutional Network (GCN) for topological link prediction |
| **Streaming** | Kafka-Python / Confluent | 2.0.2 | Real-time event pub/sub with automatic in-memory queue fallback |
| **Cryptography** | Standard `hashlib` | SHA-256 | RFC 6234 tamper-evident cryptographic chaining for audit trails |
| **Testing Engine** | Pytest / AnyIO | 9.1.1 / 4.12.0 | Automated regression, mock integration, and behavioral test suite |

---

## Section 2: Directory & Module Decomposition

The backend is cleanly structured into modular packages under `backend/`:

### 1. `backend/core/` — Foundation, Configuration & Security
* [backend/core/config.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/core/config.py):
  - Loads environment variables dynamically using `python-dotenv`.
  - Defines operational constants: `STATIC_DIR`, `BASE_DIR`, `CORS_ORIGINS` (explicit whitelisted local origins).
  - Configures threat intelligence API keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`), operational modes (`THREAT_INTEL_MODE`), and request timeouts (`INTEL_REQUEST_TIMEOUT_SECONDS = 10.0`).
  - Sets file upload boundaries: `MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024` (10 MB), `ALLOWED_UPLOAD_EXTENSIONS = [".eml", ".msg", ".txt"]`.
  - Manages administrative security flags: `ADMIN_API_KEY`, `REQUIRE_API_KEY` (strict vs development mode).
* [backend/core/security.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/core/security.py):
  - Enforces administrative access validation via `verify_admin_access`.
  - Extracts credentials from either `X-API-Key` or `Authorization: Bearer <token>` headers.
  - Utilizes constant-time string comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.
  - Rejects unauthorized mutation requests with HTTP 401 in production mode (`REQUIRE_API_KEY=true`).

### 2. `backend/api/` — API Routing & Request Orchestration
* [backend/api/routes.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/api/routes.py):
  - Core threat detection and email forensics router (prefixed `/api/v1`).
  - Implements multipart upload parser for `.eml` forensic files.
  - Exposes demo email payloads, campaign correlation graphs, and case store retrieval.
* [backend/api/graphops_routes.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/api/graphops_routes.py):
  - Comprehensive GraphOps analytical suite (prefixed `/api/v1/graphops`).
  - Exposes schema initialization, bulk ingestion, blast radius, attack paths, Dijkstra shortest paths, Louvain community detection, What-If containment simulation, ML event anomaly scoring, PyG GNN link prediction, Kafka streaming status, alert consolidation, and the forensic case exposure bridge.
* [backend/api/governance_routes.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/api/governance_routes.py):
  - Governance and compliance router (prefixed `/api/v1/governance`).
  - Exposes standards catalog (25 control mappings across NIST, CIS, MITRE, ISO), organizational policies, evidence-backed evaluation against graph topology, remediation tracking, and tamper-evident audit ledger verification.

### 3. `backend/graphops/` — Graph Database, Algorithms & ML Engines
* [backend/graphops/schema.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/schema.py):
  - Central enum registry: `NodeLabel` (8 enterprise types), `RelationshipType` (11 types), `EvidenceClass` (`OBSERVED`, `AUTHORIZED_ACCESS`, `INFERRED`, `HYPOTHETICAL`), `CriticalityTier` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `InterventionAction` (`ISOLATE_NODE`, `BLOCK_CONNECTION`, `APPLY_PATCH`, `REVOKE_CREDENTIALS`).
  - Canonical prefix registry (`user:`, `device:`, `server:`, `app:`, `vuln:`, `ip:`, `critical:`, `event:`).
* [backend/graphops/client.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/client.py) & [mock_client.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/mock_client.py):
  - `Neo4jClient`: Manages driver connection pools with retry logic, timeouts, and safe shutdown.
  - Parameterized query execution (`execute_query(query, params)`).
  - `InMemoryPhase7GraphClient`: Thread-safe mock implementation allowing zero-dependency local testing with Cypher emulation.
* [backend/graphops/ingest.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/ingest.py):
  - `GraphOpsIngestionEngine`: Validates nodes/edges against canonical schemas, enforces endpoint type pairing (`VALID_RELATIONSHIP_ENDPOINTS`), eliminates intra-payload duplicates, chunks operations into batches (50 items/batch), and applies idempotent Cypher `MERGE`.
* [backend/graphops/blast_radius.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/blast_radius.py):
  - `BlastRadiusService`: Breadth-First Search (BFS) neighborhood traversal engine.
  - Computes minimum hop distances, isolates Crown Jewels (`CriticalAsset`), and generates Cytoscape.js export graphs.
* [backend/graphops/attack_paths.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/attack_paths.py):
  - `AttackPathService`: Bounded Depth-First Search (DFS) for candidate attack paths to high-value assets.
  - Evaluates intermediate node betweenness centrality to identify strategic choke points.
  - Implements the in-memory **What-If Containment Simulator** calculating path elimination efficiency without live database mutation.
* [backend/graphops/dijkstra.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/dijkstra.py):
  - `DijkstraPathService`: Priority-queue weighted shortest path routing based on edge resistance, exploit difficulty, and evidence confidence.
* [backend/graphops/communities.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/communities.py):
  - `CommunityDetectionService`: Graph partitioning via modularity maximization and label propagation into enterprise security zones.
* [backend/graphops/anomaly_detection.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/anomaly_detection.py):
  - `AccessAnomalyDetector`: Rule-based graph access anomaly engine emitting structured 9-field findings.
* [backend/graphops/feature_extractor.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/feature_extractor.py), [ml_training.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/ml_training.py), [ml_service.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/ml_service.py):
  - 11-dimensional feature vector extraction and Scikit-Learn `IsolationForest` anomaly inference with saved model artifacts in `backend/data/models/event_isolation_forest.joblib`.
* [backend/graphops/pyg_converter.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/pyg_converter.py), [pyg_model.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/pyg_model.py), [pyg_training.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/pyg_training.py), [pyg_service.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/pyg_service.py):
  - PyTorch Geometric Graph Convolutional Network (GCN) pipeline. Converts graph topology into PyG `Data` tensors, computes 16-dimensional node embeddings, performs cosine link prediction, and detects topological structure anomalies. Saved weights in `backend/data/models/pyg_structural_gnn.pt`.
* [backend/graphops/kafka_processor.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/kafka_processor.py), [kafka_producer.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/kafka_producer.py), [kafka_worker.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/kafka_worker.py), [kafka_simulator.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/kafka_simulator.py):
  - Real-time Kafka consumer and processor pipeline with graceful auto-fallback to an in-memory queue simulator.
* [backend/graphops/alert_consolidation.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/graphops/alert_consolidation.py):
  - Correlates isolated alerts by shared asset clusters and attack paths into consolidated incident campaigns.

### 4. `backend/governance/` — Policy Evaluation & Cryptographic Audit
* [backend/governance/schema.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/governance/schema.py): Data models for frameworks, controls, policies, evaluation results, and audit ledger entries.
* [backend/governance/catalog.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/governance/catalog.py): 25 authoritative controls mapped to NIST CSF 2.0, NIST SP 800-53 Rev. 5, CIS Controls v8.1, MITRE ATT&CK, and ISO 27001.
* [backend/governance/policies.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/governance/policies.py): Built-in organizational policies (`POL-IAM-01`, `POL-IAM-02`, `POL-EXPOSURE-01`, `POL-VULN-01`, `POL-LOG-01`, `POL-INC-01`).
* [backend/governance/evaluator.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/governance/evaluator.py): Deterministic policy evaluation engine. Enforces core rule: missing evidence yields `NEEDS_REVIEW` (never `PASS`).
* [backend/governance/audit.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/governance/audit.py): Tamper-evident cryptographic audit ledger using SHA-256 hash chaining (`current_hash = SHA-256(payload + previous_hash)`).

### 5. `backend/services/` — Forensics, Classification & Signals
* [backend/services/email_forensics.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/services/email_forensics.py): RFC 822 MIME parser, SPF/DKIM/DMARC authentication extractor, and SHA-256 evidence digest calculator.
* [backend/services/ioc_extractor.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/services/ioc_extractor.py): Regex engine for extracting IPs, URLs, domains, MD5, and SHA-256 hashes with defanging.
* [backend/services/explainable_ai.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/services/explainable_ai.py): Explainable AI scoring engine producing normalized risk scores with weighted factor attributions.
* [backend/services/case_store.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/services/case_store.py): In-memory store for investigation cases (`MT-101` to `MT-105`).
* [backend/services/campaign_correlation.py](file:///d:/Desktop/Hackathon/ThreatLens/backend/services/campaign_correlation.py): Correlates cases into attack campaigns (`CMP-001`).

---

## Section 3: API Endpoint Registry & Data Contracts

The ThreatLens backend registers 42 REST endpoints across four routers:

### 1. General & Health Endpoints
| HTTP Method | Route Path | Auth Tier | Description & Payload |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Welcome banner, link to `/docs` and `/static/index.html` |
| `GET` | `/api/v1/health` | Public | System status, service connectivity, and uptime metrics |

### 2. Forensics, Cases & Intelligence (`/api/v1`)
| HTTP Method | Route Path | Auth Tier | Description & Input / Output Models |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/analyze/email` | Analyst | Analyze raw email text for threats. Input: `EmailAnalysisRequest`, Output: `EmailAnalysisResponse` |
| `POST` | `/api/v1/analyze/forensics/upload` | Analyst | Upload raw `.eml` or `.msg` file (10MB max). Output: `EmailForensicsResult` |
| `GET` | `/api/v1/demo-emls` | Analyst | Returns five raw EML demonstration fixtures (phishing, bec, impersonation, benign, malware) |
| `GET` | `/api/v1/cases` | Analyst | Retrieve all active investigation cases (`MT-101` to `MT-105`) |
| `GET` | `/api/v1/cases/{case_id}` | Analyst | Retrieve complete case dossier by identifier |
| `GET` | `/api/v1/campaigns` | Analyst | Retrieve all correlated attack campaigns |
| `GET` | `/api/v1/campaigns/{campaign_id}/graph` | Analyst | Retrieve Cytoscape graph payload for an attack campaign |
| `POST` | `/api/v1/intel/lookup` | Analyst | Query threat intelligence for an indicator (VirusTotal / AbuseIPDB / Mock) |

### 3. GraphOps Analytical Suite (`/api/v1/graphops`)
| HTTP Method | Route Path | Auth Tier | Description & Input / Output Models |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/graphops/schema/init` | **Admin** | Initialize Neo4j unique constraints and indexes. Output: `SchemaStatusResponse` |
| `GET` | `/api/v1/graphops/schema/status` | Analyst | Check active Neo4j database schema constraints and health |
| `POST` | `/api/v1/graphops/ingest/sample` | **Admin** | Ingest default enterprise baseline fixture (30 nodes, 43 edges) |
| `POST` | `/api/v1/graphops/ingest/bulk` | **Admin** | Bulk ingest arbitrary graph payload. Input: `BulkIngestRequest`, Output: `BulkIngestResponse` |
| `GET` | `/api/v1/graphops/summary` | Analyst | High-level graph inventory (node counts by label, relationship counts) |
| `POST` | `/api/v1/graphops/blast-radius` | Analyst | Calculate multi-hop blast radius. Input: `BlastRadiusRequest`, Output: `BlastRadiusResponse` |
| `POST` | `/api/v1/graphops/attack-paths` | Analyst | Find candidate paths to Crown Jewels. Input: `AttackPathRequest`, Output: `AttackPathResponse` |
| `POST` | `/api/v1/graphops/choke-points` | Analyst | Rank strategic choke points. Input: `ChokePointRequest`, Output: `ChokePointAnalysisResponse` |
| `POST` | `/api/v1/graphops/dijkstra/shortest-path` | Analyst | Compute weighted shortest path. Input: `DijkstraRequest`, Output: `DijkstraResponse` |
| `GET` | `/api/v1/graphops/communities` | Analyst | Partition graph via Louvain modularity clustering. Output: `CommunityResponse` |
| `POST` | `/api/v1/graphops/simulate-containment` | Analyst | Simulate in-memory node/edge containment. Input: `ContainmentSimulationRequest`, Output: `ContainmentSimulationResponse` |
| `POST` | `/api/v1/graphops/anomaly/evaluate-sequence`| Analyst | Rule-based graph access anomaly detection. Input: `EventSequenceRequest`, Output: `AnomalyResponse` |
| `POST` | `/api/v1/graphops/ml/predict-event` | Analyst | Isolation Forest anomaly scoring on 11-d event vector. Output: `MLEventAnomalyResponse` |
| `POST` | `/api/v1/graphops/pyg/score-link` | Analyst | PyG 2-layer GCN link prediction between two entities. Output: `PyGLinkScoreResponse` |
| `POST` | `/api/v1/graphops/pyg/detect-structural-anomalies` | Analyst | PyG unsupervised structural anomaly detection. Output: `PyGStructuralAnomalyResponse` |
| `GET` | `/api/v1/graphops/stream/status` | Analyst | Real-time Kafka consumer and queue status |
| `POST` | `/api/v1/graphops/stream/simulate-event` | Analyst | Inject synthetic security telemetry event into Kafka/Simulator bus |
| `POST` | `/api/v1/graphops/alerts/consolidate` | Analyst | Consolidate disparate alert findings into unified incident campaigns |
| `GET` | `/api/v1/graphops/bridge/case/{case_id}` | Analyst | Correlate case recipient to internal User/Device and quarantine external IOCs |

### 4. Governance & Compliance Hub (`/api/v1/governance`)
| HTTP Method | Route Path | Auth Tier | Description & Input / Output Models |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/governance/frameworks` | Analyst | List standard frameworks (NIST CSF 2.0, NIST SP 800-53, CIS, MITRE, ISO) |
| `GET` | `/api/v1/governance/catalog` | Analyst | List all 25 mapped security controls with official URLs |
| `GET` | `/api/v1/governance/policies` | Analyst | Retrieve organizational security policies |
| `POST` | `/api/v1/governance/policies` | **Admin** | Create or update organizational policy. Input: `PolicyDefinition` |
| `DELETE` | `/api/v1/governance/policies/{policy_id}` | **Admin** | Delete an organizational policy |
| `POST` | `/api/v1/governance/evaluate` | Analyst | Deterministic policy evaluation against graph topology. Output: `PolicyEvaluationSummary` |
| `GET` | `/api/v1/governance/remediations` | Analyst | List remediation tasks with priority and lifecycle status |
| `PATCH` | `/api/v1/governance/remediations/{remediation_id}` | **Admin** | Update remediation task status (`OPEN`, `IN_PROGRESS`, `RESOLVED`) |
| `GET` | `/api/v1/governance/audit/ledger` | Analyst | Retrieve immutable SHA-256 audit ledger records |
| `GET` | `/api/v1/governance/audit/verify` | Analyst | Verify cryptographic hash chain integrity of the audit ledger |

---

## Section 4: Algorithmic, ML & Graph Engines Deep Dive

### 1. BFS Multi-Hop Blast Radius Engine
* **Algorithm:** Bounded Breadth-First Search with frontier expansion.
* **Invariant:** Minimum hop distance guarantee. If a node is reachable at 1 hop, it is strictly excluded from hop 2 and hop 3 sets ($H_1 \cap H_2 = \emptyset$, $H_2 \cap H_3 = \emptyset$).
* **Implementation:** `BlastRadiusService.calculate_blast_radius` maintains a `visited` set initialized with the start entity. For each frontier iteration $k \in \{1, \dots, \text{max\_hops}\}$, adjacent neighbors are collected, filtered for unvisited status, assigned to tier $H_k$, and added to `visited`.
* **Crown Jewel Tagging:** Nodes tagged with label `CriticalAsset` or property `criticality: CRITICAL` are segregated into `critical_assets_at_risk` with path distance and exposure rationale.

### 2. Attack Path Discovery & Choke Point Analysis
* **Algorithm:** Recursive Depth-First Search with acyclic path backtracking up to depth limit (default 5).
* **Cycle Prevention:** A path-local `visited_in_path` set prevents looping on cyclic topologies.
* **Step Feasibility Scoring:** Path risk is computed multiplicatively over step friction:
  $$\text{Risk}(P) = \prod_{e \in P} \text{Confidence}(e) \times \text{SeverityWeight}(e)$$
* **Choke Point Betweenness:** For all discovered paths $\mathcal{P}$, node betweenness frequency is evaluated:
  $$\text{Centrality}(v) = \frac{|\{p \in \mathcal{P} \mid v \in p\}|}{|\mathcal{P}|} \times 100\%$$
  Nodes with highest centrality are ranked as primary choke points. In the enterprise fixture, gateway server `server:srv-app-01` exhibits 100% centrality.

### 3. In-Memory What-If Containment Simulation
* **Algorithm:** Graph virtual subtraction without mutation.
* **Safety Contract:** Live database records are **never modified** (`live_graph_modified: false`).
* **Implementation:** When an analyst proposes isolating a node $v_{\text{iso}}$ or blocking an edge $(u, w)$, the traversal algorithm wraps the underlying client in a virtual filter layer that treats $v_{\text{iso}}$ or $(u, w)$ as non-existent during path computation.
* **Efficiency Metric:**
  $$\text{Efficiency} = \frac{|\mathcal{P}_{\text{baseline}}| - |\mathcal{P}_{\text{residual}}|}{|\mathcal{P}_{\text{baseline}}|} \times 100\%$$

### 4. Classical ML Anomaly Detection (Isolation Forest)
* **Model:** Scikit-Learn `IsolationForest` (100 base estimators, 0.10 contamination factor).
* **Input Features (11-Dimensional Vector):**
  1. `hour_of_day`: Normalized time of event $[0, 23]$.
  2. `day_of_week`: Day index $[0, 6]$.
  3. `privilege_delta`: Numeric elevation jump (e.g., standard to domain admin).
  4. `cross_subnet_flag`: Binary flag indicating traversal across network perimeters.
  5. `unapproved_process_flag`: Binary flag indicating unlisted binary execution.
  6. `failed_auth_count`: Number of preceding authentication failures.
  7. `session_duration_seconds`: Normalized session length.
  8. `lateral_movement_flag`: Binary flag indicating inter-workstation communication.
  9. `target_criticality_tier`: Numeric weight of target asset ($1 \dots 4$).
  10. `external_egress_ratio`: Outbound byte volume ratio.
  11. `known_cve_exploit_tag`: Binary indicator if communication references known CVEs.
* **Decision Boundary:** Raw anomaly scores $\le 0.0$ are classified as `ANOMALOUS`; scores $> 0.0$ are classified as `NORMAL`.

### 5. PyTorch Geometric Structural Graph Convolutional Network (GCN)
* **Architecture:** 2-layer Graph Convolutional Network (`GCNConv` 16 $\rightarrow$ 16) with node feature dimension $d = 16$.
* **Forward Pass Formulation:**
  $$Z^{(1)} = \text{ReLU}\left(\tilde{D}^{-\frac{1}{2}} \tilde{A} \tilde{D}^{-\frac{1}{2}} X W^{(0)}\right)$$
  $$Z^{(2)} = \tilde{D}^{-\frac{1}{2}} \tilde{A} \tilde{D}^{-\frac{1}{2}} Z^{(1)} W^{(1)}$$
  where $\tilde{A} = A + I_N$ is the graph adjacency matrix with self-loops, and $\tilde{D}$ is the diagonal degree matrix.
* **Link Prediction Scoring:** Plausibility of relationship between entities $u$ and $v$ is evaluated via cosine similarity and dot product:
  $$\text{Score}(u, v) = \sigma\left(\frac{z_u \cdot z_v}{\|z_u\| \|z_v\|}\right)$$
* **Topological Anomaly Detection:** Compares predicted structural link scores against observed connectivity. Unobserved edges with unusually high link plausibility are flagged as stealth lateral movement paths.

### 6. Cryptographic Tamper-Evident Audit Ledger
* **Algorithm:** SHA-256 hash chaining (RFC 6234).
* **Hash Computation:**
  $$H_0 = \text{SHA-256}(\text{"GENESIS"})$$
  $$H_k = \text{SHA-256}\left(H_{k-1} \,\|\, \text{Timestamp} \,\|\, \text{Actor} \,\|\, \text{Action} \,\|\, \text{PayloadJSON}\right)$$
* **Verification:** `AuditLedger.verify_integrity()` recomputes all hashes sequentially from genesis. If any record payload or previous hash pointer has been altered, validation fails and pinpoints the exact tampered index.

---

## Section 5: Security, Authorization & Configuration Framework

The backend implements strict defense-in-depth principles:

### 1. Administrative Authorization Gate
All mutating operations (schema initialization, bulk ingestion, policy creation/deletion, remediation lifecycle changes) require administrative privileges via FastAPI dependency injection:
```python
# backend/core/security.py
async def verify_admin_access(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    auth_header: Optional[str] = Header(None, alias="Authorization"),
) -> bool:
    if not REQUIRE_API_KEY:
        return True
    # Constant-time comparison prevents timing attacks
    if x_api_key and hmac.compare_digest(x_api_key, ADMIN_API_KEY):
        return True
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        if hmac.compare_digest(token, ADMIN_API_KEY):
            return True
    raise HTTPException(status_code=401, detail="Unauthorized: Administrative API key required")
```

### 2. Cypher Query Parameterization
To eliminate Cypher injection risks, all graph queries in `backend/graphops/client.py`, `ingest.py`, `blast_radius.py`, and `attack_paths.py` execute strictly via bound parameter dictionaries:
```python
# Secure: Values passed as parameters, never string-interpolated
query = "MATCH (n) WHERE n.id = $id RETURN n"
session.run(query, {"id": user_input_id})
```
Static code audits confirm zero instances of dynamic string formatting (`f"MATCH...{input}"`) in database queries.

### 3. CORS Configuration
Permissive wildcard CORS (`allow_origins=["*"]`) with credentials is explicitly prohibited. The application binds to verified local endpoints:
```python
# backend/core/config.py
CORS_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
```

### 4. File Upload Security
The raw email upload route `/api/v1/analyze/forensics/upload` enforces:
1. **Extension Whitelisting:** Accepts only `.eml`, `.msg`, `.txt`. Unapproved extensions return HTTP 400.
2. **Size Clamping:** Enforces `MAX_UPLOAD_SIZE_BYTES = 10MB`. Payloads exceeding limit return HTTP 413.
3. **In-Memory Streaming:** Processes bytes directly through `io.BytesIO` without writing unverified files to host disk storage.

---

## Section 6: Canonical Schema, Entity Ontology & Baseline Fixtures

### 1. Canonical Prefix Specification
All node identifiers must adhere to strict prefixing to ensure cross-subsystem consistency:

| Entity Category | Canonical Prefix | Example Identifier | Node Label |
| :--- | :--- | :--- | :--- |
| **User / Identity** | `user:` | `user:usr-101` | `User` |
| **Workstation / Laptop** | `device:` | `device:dev-ws-101` | `Device` |
| **Server / Infrastructure**| `server:` | `server:srv-app-01` | `Server` |
| **Application / Service** | `app:` | `app:app-erp-01` | `Application` |
| **Vulnerability / CVE** | `vuln:` | `vuln:CVE-2024-21413` | `Vulnerability` |
| **Network IP Address** | `ip:` | `ip:192.168.10.15` | `IPAddress` |
| **Critical Asset / Crown Jewel**| `critical:` | `critical:crit-db-financial` | `CriticalAsset` |
| **Security Telemetry Event**| `event:` | `event:evt-20261022-001` | `SecurityEvent` |

### 2. Relationship Registry & Valid Endpoints
Allowed relationship pairs are strictly validated during ingestion via `VALID_RELATIONSHIP_ENDPOINTS`:
* `USES`: `(User) -> (Device)`
* `ADMINISTERS`: `(User) -> (Server)`, `(User) -> (Application)`
* `LOGGED_IN_TO`: `(User) -> (Device)`, `(User) -> (Server)`
* `CONNECTS_TO`: `(Device) -> (Server)`, `(Server) -> (Server)`
* `HOSTS`: `(Server) -> (Application)`, `(Server) -> (CriticalAsset)`
* `AFFECTS`: `(Vulnerability) -> (Server)`, `(Vulnerability) -> (Application)`
* `PROTECTS`: `(Application) -> (CriticalAsset)`
* `COMMUNICATED_WITH`: `(Device) -> (IPAddress)`, `(Server) -> (IPAddress)`

---

## Section 7: Automated Test Suite Coverage & Verification Metrics

The backend contains twenty (20) comprehensive automated test modules covering 231 unit, integration, and scenario tests:

```
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\Desktop\Hackathon\ThreatLens
collected 231 items

tests\test_attack_paths.py ................                              [  6%]
tests\test_blast_radius.py ................                              [ 13%]
tests\test_dijkstra.py .............                                     [ 19%]
tests\test_email_forensics.py .......                                    [ 22%]
tests\test_explainable_ai.py ......                                      [ 25%]
tests\test_graphops_anomaly.py ............                              [ 30%]
tests\test_graphops_hackathon_enhancements.py ...                        [ 31%]
tests\test_graphops_ingest.py ...........                                [ 36%]
tests\test_graphops_kafka.py ............                                [ 41%]
tests\test_graphops_ml.py ............                                   [ 46%]
tests\test_graphops_models.py ...................                        [ 54%]
tests\test_graphops_phase2.py ..............                             [ 61%]
tests\test_graphops_phase7.py ............                               [ 66%]
tests\test_graphops_pyg.py ...................                           [ 74%]
tests\test_ioc_extractor.py .........                                    [ 78%]
tests\test_neo4j_integration.py .............                            [ 83%]
tests\test_phase4_integration.py .........                               [ 87%]
tests\test_phase6_governance_security.py ..............                  [ 93%]
tests\test_phase8_verification.py .........                              [ 97%]
tests\test_threat_detection.py .....                                     [100%]

================ 231 passed, 205 warnings in 70.81s =================
```

* **Pass Rate:** **100% (231 passed, 0 failed, 0 errors)**.
* **Warnings:** 205 benign third-party deprecation warnings (PyTorch Geometric `typing._eval_type` notice for Python 3.15, PyTorch JIT script warning, Kafka unclosed socket cleanup).

---

## Section 8: Independent Backend Validation Protocol (Runbook)

Follow this step-by-step protocol to validate the ThreatLens backend in isolation using Windows PowerShell without launching the frontend.

### Step 1: Start the Backend Service
In a PowerShell terminal, navigate to the project root and launch Uvicorn:
```powershell
# Navigate to workspace
cd d:\Desktop\Hackathon\ThreatLens

# Launch Uvicorn ASGI server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Expected output:
```
INFO:     Started server process [PID]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Step 2: Validate Interactive Swagger API Documentation
Open your browser or run an HTTP request against the documentation endpoint:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8000/docs" -Method GET
```
**Verification Criterion:** Returns HTTP `200 OK` with Swagger UI interactive API explorer.

### Step 3: Validate Core Health & Inventory
```powershell
# Health check
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/health" -Method GET

# GraphOps inventory summary
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/summary" -Method GET
```
**Verification Criterion:**
* Health returns `status: "healthy"` or `status: "ok"`.
* Summary returns JSON containing total node count ($\ge 30$) and total relationship count ($\ge 43$).

### Step 4: Validate Multi-Hop Blast Radius Calculation
Execute a blast-radius calculation starting from compromised workstation `device:dev-ws-101`:
```powershell
$body = @{
    start_node_id = "device:dev-ws-101"
    max_hops = 3
    direction = "OUTGOING"
    include_hypothetical = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/blast-radius" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```
**Verification Criterion:**
* Returns HTTP `200 OK`.
* `hop_1.node_count` includes `server:srv-app-01`.
* `critical_assets_at_risk` includes `critical:crit-db-financial` or `critical:crit-ad-domain-root`.
* All hop groups are mutually disjoint.

### Step 5: Validate Attack Paths & Choke Point Analysis
```powershell
# Attack paths discovery
$pathBody = @{
    entry_node_id = "device:dev-ws-101"
    max_depth = 5
    include_hypothetical = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/attack-paths" `
    -Method POST `
    -ContentType "application/json" `
    -Body $pathBody

# Strategic choke points
$cpBody = @{
    entry_node_id = "device:dev-ws-101"
    max_depth = 5
    top_n = 5
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/choke-points" `
    -Method POST `
    -ContentType "application/json" `
    -Body $cpBody
```
**Verification Criterion:**
* Discovers candidate paths reaching Crown Jewels.
* Choke point analysis ranks `server:srv-app-01` at #1 with `traversal_percentage: 100.0`.

### Step 6: Validate What-If Containment Simulation (Zero-Mutation Guarantee)
```powershell
$simBody = @{
    entry_node_id = "device:dev-ws-101"
    proposed_interventions = @(
        @{
            action = "ISOLATE_NODE"
            node_id = "server:srv-app-01"
        }
    )
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/simulate-containment" `
    -Method POST `
    -ContentType "application/json" `
    -Body $simBody
```
**Verification Criterion:**
* Returns `live_graph_modified: false`.
* Returns `containment_efficiency_pct: 100.0`.
* Returns `remaining_paths_count: 0`.

### Step 7: Validate Classical ML & PyG Structural GNN Inference
```powershell
# ML Event Anomaly Scoring
$mlBody = @{
    hour_of_day = 23
    day_of_week = 6
    privilege_delta = 3
    cross_subnet_flag = 1
    unapproved_process_flag = 1
    failed_auth_count = 5
    session_duration_seconds = 18000
    lateral_movement_flag = 1
    target_criticality_tier = 4
    external_egress_ratio = 0.85
    known_cve_exploit_tag = 1
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/ml/predict-event" `
    -Method POST `
    -ContentType "application/json" `
    -Body $mlBody

# PyG GNN Link Prediction
$pygBody = @{
    source_entity_id = "device:dev-ws-101"
    target_entity_id = "server:srv-app-01"
    relationship_type = "CONNECTS_TO"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/graphops/pyg/score-link" `
    -Method POST `
    -ContentType "application/json" `
    -Body $pygBody
```
**Verification Criterion:**
* ML endpoint returns `classification: "ANOMALOUS"` with numeric risk score.
* PyG endpoint returns `predicted_link_score` between `0.0` and `1.0` and `is_plausible: true`.

### Step 8: Validate Policy Evaluation & Cryptographic Audit Verification
```powershell
# Evaluate organizational policies against graph topology
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/governance/evaluate" -Method POST

# Verify cryptographic SHA-256 audit ledger
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/governance/audit/verify" -Method GET
```
**Verification Criterion:**
* Governance evaluation returns policy statuses (`PASS`, `FAIL`, or `NEEDS_REVIEW`).
* Audit verification returns `valid: true`, `total_records: >0`, and `message: "Audit ledger cryptographic integrity verified"`.

### Step 9: Run Automated Unit & Integration Tests
In a terminal, execute:
```powershell
python -m pytest tests/test_phase8_verification.py -v
```
**Verification Criterion:** All 9 scenario and safety tests pass cleanly in under 5 seconds.
