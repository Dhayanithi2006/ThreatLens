# ThreatLens GraphOps — Hackathon Demo & Presentation Guide

**Challenge:** GraphOps — Graph analytics for proactive threat hunting and blast radius containment in security operations centers  
**Platform URL:** `http://localhost:8000/static/index.html`  
**Execution Runtime:** Python 3.13 / FastAPI / Neo4j 5.28 / Cytoscape.js / Zero-Dependency Dark SOC Web Engine  

---

## 1. Executive Summary & Problem-Solution Fit

Security operations centers (SOCs) are overwhelmed by alert fatigue. Traditional SIEM and SOAR platforms store events in relational tables and rely on static rules. When an adversary moves laterally, this produces a storm of disconnected, low-fidelity alerts. Tracing a multi-hop path across users, endpoints, servers, and privileges requires complex, slow SQL joins.

**ThreatLens GraphOps solves this by replacing relational alert queues with a connected enterprise security knowledge graph:**
- **Millisecond Traversal:** Evaluates multi-hop blast radius (1-3 hops) and acyclic attack paths in `<20ms`.
- **92.9% Alert Noise Compression:** Consolidates 14 discrete SIEM alerts into **1 unified, MITRE ATT&CK-mapped incident narrative**.
- **Proactive Choke Point Defense:** Discovers intermediate bottleneck nodes (`srv-app-01`) that cut off 75% of attack pathways **before** adversaries exploit them.
- **Safe In-Memory What-If Simulator:** Tests containment actions (node isolation, edge severance) against an in-memory graph projection with **zero live database downtime**.
- **Zero-Trust Governance & Cryptographic Audit:** Continuously evaluates policy compliance (`POL-IAM-01`, `POL-EXPOSURE-01`) and records all operations to a tamper-evident SHA-256 hash-chained ledger.

---

## 2. 3-Minute Live Judging Presentation Script

### `[0:00 - 0:30]` Act 1: The Problem & The GraphOps Advantage
> **Speaker:** *"Judges, today SOC analysts drown in alert fatigue. An attacker phishes an employee, pivots through an internal workstation, compromises an app server, and exfiltrates financial data. In a legacy SIEM, that shows up as 14 isolated, low-fidelity alerts across EDR, NetFlow, and Active Directory. Analysts spend 4 hours manually piecing together relational tables.*  
> *With ThreatLens GraphOps, we model identities, assets, and telemetry as a live connected knowledge graph. As you see right here on our dashboard, our GraphOps engine compresses those 14 disconnected alerts into 1 unified incident narrative in under 15 milliseconds—a 92.9% reduction in analyst cognitive noise."*

- **Action on Screen:** Start at `http://localhost:8000/static/index.html#/dashboard`. Highlight the **92.9% Alert Noise Reduction** metric card and the **GraphOps Advantage Banner**.
- **Click:** Click **"View Unified Narrative (14 Alerts) &rarr;"**.
- **Showcase:** The modal displays the 5-stage MITRE ATT&CK progression (`Initial Access` &rarr; `Execution` &rarr; `Discovery` &rarr; `Lateral Movement` &rarr; `Impact`) and the primary choke point recommendation. Close the modal.

---

### `[0:30 - 1:15]` Act 2: Real-Time Blast Radius & Critical Asset Exposure
> **Speaker:** *"Let's see what happens during an active incident. Suppose an EDR indicator fires on an internal workstation, `dev-ws-101`. In most SOCs, analysts cannot answer: 'What is at direct risk right now?'*  
> *Let's navigate to the GraphOps Workspace. We select `dev-ws-101` and run our multi-hop Blast Radius engine."*

- **Action on Screen:** Click **"Enterprise GraphOps"** in sidebar (or `#/graphops`).
- **Click:** Ensure Tab 1 (**"1. Blast Radius"**) is active. Select entity `device:dev-ws-101` and 3 hops. Click **"Run Blast Radius"**.
- **Speaker:** *"In 12 milliseconds, GraphOps calculates the strict 1-hop, 2-hop, and 3-hop topological neighborhood. Notice the immediate verdict on the right panel: our Crown Jewel Database (`crit:crown-jewel-db`) and Active Directory Root (`crit:crown-jewel-ad`) are highlighted in red as exposed assets reachable within 2 hops."*
- **Click:** Click on `crit:crown-jewel-db` on the interactive Cytoscape canvas to showcase the **Telemetry Inspector**, showing verified evidence classification (`AUTHORIZED_ACCESS`), sensor provenance, and timestamp.

---

### `[1:15 - 2:00]` Act 3: Attack Paths & Pre-Incident Choke Point Discovery
> **Speaker:** *"A reactive SOC waits for the attack to happen. ThreatLens proactively hunts for paths before they are used. Let's switch to Tab 2: Attack Paths & Choke Points."*

- **Click:** Click Tab 2 (**"2. Attack Paths & Choke Points"**). Target is `crit:crown-jewel-db`. Click **"Discover Attack Paths"**.
- **Speaker:** *"GraphOps executes an acyclic shortest-path traversal to our Crown Jewels, revealing 4 distinct lateral movement pathways. Below the canvas, our path betweenness centrality analyzer surfaces the critical choke point: server `srv-app-01`. By intercepting this single node, we eliminate 75% of candidate attack routes. This proves our pre-incident capability: finding and fixing the vulnerability before adversary exploitation."*

---

### `[2:00 - 2:30]` Act 4: Safe What-If Containment Simulator
> **Speaker:** *"When a SOC decides to contain an asset, they risk taking down business-critical services. ThreatLens introduces the What-If Containment Simulator."*

- **Click:** On the choke point table next to `srv-app-01`, click the **"Simulate &rarr;"** button (or navigate to Tab 3).
- **Click:** Action is `ISOLATE_NODE`, target `srv-app-01`. Click **"Simulate Containment"**.
- **Speaker:** *"Notice the visual feedback: `srv-app-01` is severed on canvas with dashed red lines. The side-by-side comparison grid proves that reachable paths drop from 4 to 1—a 75% risk reduction—while residual exposed assets are immediately recalculated. Crucially, this simulation executes entirely against an in-memory graph projection. Zero live database mutation. Zero accidental downtime."*

---

### `[2:30 - 3:00]` Act 5: Community Detection & Zero-Trust Governance
> **Speaker:** *"Finally, how do we enforce Zero Trust? Let's check Tab 5: Security Enclaves & Communities."*

- **Click:** Click Tab 5 (**"5. Security Enclaves & Communities"**).
- **Speaker:** *"Using modularity-based community detection ($Q = 0.742$), our graph clusters nodes into 4 operational enclaves: Crown Jewels, IAM Core, DMZ Gateways, and User Endpoints. Below, the system flags high-risk cross-boundary transitions—such as a user endpoint hopping directly into the IAM tier."*
- **Click:** Click **"Governance & Controls"** in sidebar (`#/governance`).
- **Speaker:** *"Every graph observation feeds into our Governance Hub. We deterministically audit NIST CSF 2.0, CIS Controls, and MITRE ATT&CK. To ensure compliance auditability, every single action, ingestion, and simulation is cryptographically chained in our SHA-256 tamper-evident ledger."*
- **Click:** Click **"Verify Hash Chain Integrity"**. Badge confirms: **"100% Cryptographically Verified"**.

---

## 3. Judging Criteria Traceability Matrix

| Hackathon Evaluation Criterion | ThreatLens Proof in Code & Demo | Live Demo Action |
| :--- | :--- | :--- |
| **1. Visibly shorter path from raw alert to connected picture** | Consolidates 14 discrete SIEM alerts into 1 connected incident kill-chain narrative in `<15ms`. | Click "View Unified Narrative" from Dashboard or GraphOps. |
| **2. Fewer, higher-quality alerts (Noise Reduction)** | Mathematical noise reduction metric: **92.9% alert compression ratio** (`alert_noise_reduction_pct`). | Displayed on Dashboard KPI card and narrative modal. |
| **3. Pre-incident choke point identification** | Path betweenness centrality discovers `srv-app-01` eliminating 75% of candidate attack routes before breach. | Tab 2: Strategic Graph Choke Points table. |
| **4. Zero-Trust connection (actual vs entitled)** | Cross-enclave border audit (`communities.py`) and IAM policy evaluations (`POL-IAM-01`/`02`). | Tab 5: Cross-Enclave Border Crossings table + Governance Hub. |
| **5. Multi-Hop Blast Radius (1, 2, 3 hops)** | Strict minimum-hop BFS distance assignment with Crown Jewel detection and Cytoscape visualization. | Tab 1: Blast Radius calculation on `dev-ws-101`. |
| **6. Algorithmic Foundation** | Dijkstra shortest paths, betweenness centrality, modularity community clustering, MITRE kill chains. | Verified via 158/158 automated pytest tests. |

---

## 4. Live Verification Checklist & Cheat Sheet

To run the verification steps locally:

1. **Verify Test Suite (100% Pass Rate):**
   ```powershell
   py -m pytest -q
   ```
   *Expected Output:* `158 passed in ~28s (100% pass rate, 0 failures)`.

2. **Verify Server Health:**
   ```powershell
   curl -s http://localhost:8000/api/v1/health
   ```
   *Expected Output:* `{"status":"ok", ...}`

3. **Verify Communities Endpoint:**
   ```powershell
   curl -s http://localhost:8000/api/v1/graphops/communities
   ```
   *Expected Output:* JSON with 4 communities, modularity Q = 0.742, and cross-boundary transitions.

4. **Verify Incident Narrative Endpoint:**
   ```powershell
   curl -s http://localhost:8000/api/v1/graphops/incident-narrative/MT-101
   ```
   *Expected Output:* JSON with `alert_noise_reduction_pct: 92.9`, 14 alerts consolidated, and 5-step MITRE ATT&CK sequence.

---

## 5. Summary of Architecture Invariants

- **Zero DB Mutation in Simulation:** All What-If containment tests run in-memory; live Neo4j and fixture datasets remain immutable.
- **Resilient Offline Fallback:** If Neo4j is offline, the system seamlessly uses verified in-memory telemetry fixtures with zero socket blocking.
- **Strict Evidence Classification:** Every graph edge is explicitly typed (`OBSERVED`, `AUTHORIZED_ACCESS`, `INFERRED`, `HYPOTHETICAL`) with cryptographic SHA-256 provenance.
