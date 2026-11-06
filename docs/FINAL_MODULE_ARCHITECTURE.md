# ThreatLens — Final Module Architecture & GraphOps Navigation Matrix

**Document Version:** 2.0.0  
**Status:** IMPLEMENTED & LOCAL INTEGRATION VERIFIED  
**Date:** November 2026  
**Scope:** Frontend Navigation, GraphOps Tab Partitioning, Telemetry Pipeline, and Data Integrity Contracts

---

## 1. Executive Summary

Following extensive architecture audits and refactoring, the ThreatLens user interface and underlying backend services have been consolidated into four distinct operational pillars. The GraphOps threat hunting engine provides a unified graph workspace where tab ownership is dynamically filtered based on analyst workflow, eliminating redundant controls, duplicate API calls, and confusing nomenclature.

---

## 2. Four Operational Sidebar Pillars

The application sidebar navigation enforces strict separation of concerns across four primary investigation workflows:

```
+-----------------------------------------------------------------------------------------+
|                                THREATLENS SOC PLATFORM                                   |
+-----------------------------------------------------------------------------------------+
| 1. Investigate Alerts           -> Tri-detector triage, case dossiers, verified timeline|
| 2. Explore Attack Paths         -> Graph ingestion topology & multi-hop lateral paths   |
| 3. Assess Impact                -> BFS blast radius & What-If containment simulation    |
| 4. Check Access & Anomalies     -> Structural GNN, Zero-Trust audit & Security Enclaves  |
+-----------------------------------------------------------------------------------------+
```

### Pillar 1: Investigate Alerts (`data-route="investigate"`)
* **Sub-label:** *Tri-Detector Triage · Case Dossiers · Investigation Timeline*
* **Core Views:**
  1. **Correlated Security Alerts Stream:** Live display of ingested telemetry events and Graph Security Findings with severity filters (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`), loading states, and error resilience.
  2. **Active Incident Cases Repository:** Primary repository of email forensics cases (`MT-101`, `MT-102`, etc.) with threat scores, primary threat classifications, and direct deep-links to case investigation.
  3. **Case Detail Workspace:** Full-spectrum email forensics, IOC extraction, NLP semantic signals, and campaign correlation.
  4. **Investigation Timeline:** Verified chronological sequence of evidence events with active case selector, evidence ledger hash seals, and correlated graph findings.

### Pillar 2: Explore Attack Paths (`data-route="attack-paths"`)
* **Sub-label:** *Graph Ingestion · Attack Paths · Chokepoints*
* **Active GraphOps Tabs:**
  * **Tab 1: Graph Ingestion & Topology** (`id="tab-graphops-explorer"`, `data-mode="explorer"`)
  * **Tab 2: Attack Paths & Chokepoints** (`id="tab-graphops-paths"`, `data-mode="paths"`)
* **Key Capabilities:**
  * Interactive Cytoscape.js canvas rendering enterprise assets and relationships.
  * Dijkstra shortest-path calculation (hop count, weight, and traversal time).
  * Brandes' Betweenness Centrality and Google PageRank algorithms to mathematically identify structural choke points.
  * Dual-tier 60-second caching to prevent redundant calculations during lateral path discovery.

### Pillar 3: Assess Impact (`data-route="blast-radius"`)
* **Sub-label:** *Blast Radius · Containment · What-If Simulator*
* **Active GraphOps Tabs:**
  * **Tab 3: Blast Radius & Containment** (`id="tab-graphops-blast"`, `data-mode="blast"`)
  * **Tab 4: What-If Simulator** (`id="tab-graphops-simulator"`, `data-mode="simulator"`)
* **Key Capabilities:**
  * Multi-hop breadth-first search (BFS) radial expansion up to 4 hops.
  * Real-time calculation of crown jewel reachability percentage and compromised assets.
  * Proactive What-If containment sandbox modeling node isolation, credential revocation, and firewall segment severing.
  * Side-by-side delta visualization showing attack path severing before enacting remediation.

### Pillar 4: Check Access & Anomalies (`data-route="access-anomalies"`)
* **Sub-label:** *Zero-Trust · Graph ML · Communities*
* **Active GraphOps Tabs:**
  * **Tab 5: Graph Anomaly Detection** (`id="tab-graphops-anomalies"`, `data-mode="anomalies"`)
  * **Tab 6: Entitled vs. Used Access** (`id="tab-graphops-zerotrust"`, `data-mode="zerotrust"`)
  * **Tab 7: Security Communities** (`id="tab-graphops-communities"`, `data-mode="communities"`)
* **Key Capabilities:**
  * Dual-engine machine learning: scikit-learn Isolation Forest (feature-space) and PyTorch Geometric Structural GNN (topological embedding space).
  * Zero-Trust privilege audit identifying dormant entitlements, excess administrative rights, and policy discrepancies.
  * Enclave Modularity & Boundary Pivot Partitioning: partitions enterprise topology into logical security zones and surfaces cross-tier lateral movement boundaries.

---

## 3. GraphOps 7-Tab Ownership Matrix

| Tab ID | Tab Number & Title | Data Mode | Parent Pillar | Primary Algorithms & Endpoints | Status |
|---|---|---|---|---|---|
| `tab-graphops-explorer` | Tab 1: Graph Ingestion & Topology | `explorer` | Pillar 2: Explore Attack Paths | Neo4j Cypher / Mock Client, `/api/v1/graphops/summary`, `/api/v1/graphops/ingest/sample` | VERIFIED |
| `tab-graphops-paths` | Tab 2: Attack Paths & Chokepoints | `paths` | Pillar 2: Explore Attack Paths | Dijkstra Shortest Path, DFS All Paths, Brandes' Betweenness Centrality, PageRank (`/api/v1/graphops/dijkstra`, `/api/v1/graphops/attack-paths`, `/api/v1/graphops/centrality`) | VERIFIED |
| `tab-graphops-blast` | Tab 3: Blast Radius & Containment | `blast` | Pillar 3: Assess Impact | Multi-hop BFS expansion, Crown Jewel reachability (`/api/v1/graphops/blast-radius`) | VERIFIED |
| `tab-graphops-simulator` | Tab 4: What-If Simulator | `simulator` | Pillar 3: Assess Impact | Graph Counterfactual Mutation, Remediation Simulation (`/api/v1/graphops/simulate-containment`) | VERIFIED |
| `tab-graphops-anomalies` | Tab 5: Graph Anomaly Detection | `anomalies` | Pillar 4: Check Access & Anomalies | Isolation Forest (`/api/v1/graphops/events/ml/evaluate`), PyTorch Geometric GNN (`/api/v1/graphops/events/pyg/evaluate`) | VERIFIED |
| `tab-graphops-zerotrust` | Tab 6: Entitled vs. Used Access | `zerotrust` | Pillar 4: Check Access & Anomalies | Active Directory vs. Observed Logons (`/api/v1/graphops/zero-trust/audit`) | VERIFIED |
| `tab-graphops-communities` | Tab 7: Security Communities | `communities` | Pillar 4: Check Access & Anomalies | Enclave Modularity & Boundary Pivot Partitioning (`/api/v1/graphops/communities`) | VERIFIED |

> **Note on Former Tab 8 (Telemetry Findings):**  
> Independent Tab 8 has been removed from the GraphOps navigation bar. Live telemetry findings and Kafka streaming events are surfaced directly within the **Correlated Security Alerts Stream** in Pillar 1, complete with contextual deep-links (`#/blast-radius?start_node_id=...`) to graph analysis.

---

## 4. Alerts Stream Data Classification & Integrity Contracts

A strict distinction is maintained between **Active Indexed Incident Cases** and **Graph Security Findings**:

1. **No Case Record Renaming:** `CaseRecord` objects fetched from `/api/v1/cases` are explicitly presented as *Active Indexed Incident Cases (Repository Dossiers)* with case-centric metadata:
   * Case ID (`MT-101`, `MT-102`)
   * Ingestion Time (UTC)
   * Risk Level (`CRITICAL`, `HIGH`, `MEDIUM`)
   * Primary Threat (`PHISHING`, `CREDENTIAL_HARVESTING`, `RANSOMWARE`)
   * Originating Sender
   * Incident Subject
   * Direct Action: "Investigate &rarr;" (`#/alerts-incidents/case-detail/{case_id}`)
2. **Graph Security Findings Table:** Fed from the canonical findings service `/api/v1/graphops/events/findings`:
   * Recorded Timestamp (UTC)
   * Severity Badge
   * Detector Source (`ISOLATION_FOREST`, `PYG_GNN_STRUCTURAL`, `DIJKSTRA_FLOW`, `BLAST_RADIUS_BFS`)
   * Affected Entity
   * Finding Description
   * Graph Context Action: "Blast Radius &rarr;"

---

## 5. Investigation Timeline Architecture

To guarantee empirical forensics rigor and avoid fabricated chronologies:

1. **Top-Level Case Intelligence Dossier Card:**
   * Summarizes non-timestamped analytical conclusions: Threat Score (0–100), Risk Level badge, Primary Threat, Originating Sender, External Threat Intel Verdict (`VERIFIED`, `MALICIOUS`), and Extracted IOC pills (domains, IP addresses, weaponized URLs).
   * Prevents arbitrary time-offset invention for static case summaries.
2. **Chronological Verified Evidence Stream:**
   * **Telemetry Ingestion Gateway Event:** Recorded case timestamp and transmission envelope metadata.
   * **Cryptographic Evidence Ledger Hash Seal:** Verified against immutable chain of custody `/api/v1/governance/evidence/ledger` with recorded verification timestamp and SHA-256 digest.
   * **Correlated Graph Security Findings:** Explicit relationship matching `f.related_case_id === currentCase.case_id`, displaying actual finding timestamp and detector engine source.
   * **Analyst Action Records:** Chronological investigation actions recorded by analysts.
   * **Strict Chronological Sorting:** Events sorted by raw ISO 8601 timestamps.
   * **Safe DOM Escaping:** All strings escaped via `escapeHtml()`.

---

## 6. Centrality & Disruption Dual-Tier Caching

* **Backend Caching:** `CentralityAnalyticsService` maintains an in-memory cache with a 60-second TTL. Calls to `/api/v1/graphops/centrality` serve cached Brandes' and PageRank calculations unless `force_refresh=true` is requested.
* **Cache Invalidation:** Ingestion endpoints (`/api/v1/graphops/ingest/sample`, `/api/v1/graphops/ingest/bulk`) invoke `invalidate_centrality_cache()` immediately upon graph mutation.
* **Frontend Caching:** `runCentralityAnalysis` checks local timestamp (`state.lastCentralityTimestamp`). Repeat tab selections within 60 seconds render instantly from memory without redundant network requests.
* **Analyst Override:** The "Refresh Centrality" action explicitly sends `force_refresh=true` to force a full recomputation.

---

## 7. Security Communities Algorithm Specification

* **Algorithm Name:** **Enclave Modularity & Boundary Pivot Partitioning**
* **Enclaves Identified:**
  1. `COMM-CROWN-JEWELS`: Production databases, financial ledgers, restricted customer data.
  2. `COMM-IAM`: Active Directory domain controllers, Kerberos/LDAP authentication roots.
  3. `COMM-DMZ-GATEWAYS`: Public reverse proxies, API gateways, DMZ jumpboxes, bastion hosts.
  4. `COMM-USER-ENDPOINTS`: Corporate developer laptops, client workstations, standard user identities.
  5. `COMM-GENERAL-ASSETS`: Network switches, print servers, utility relays.
  6. `COMM-ISOLATED`: Airgapped, disconnected, or zero-degree assets.
* **Edge Boundary Crossings:** High-risk transitions (e.g. Workstation to Crown Jewels or DMZ to Crown Jewels) are flagged as `CRITICAL` or `HIGH` cross-tier lateral paths.
* **Boundary Conditions:**
  * Empty graph snapshots return 0 communities with 0.0 modularity score without exceptions.
  * Disconnected components partition into their respective functional tiers without graph connectivity bottlenecks.

