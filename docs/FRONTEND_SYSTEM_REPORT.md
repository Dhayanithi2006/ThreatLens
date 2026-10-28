# ThreatLens — Comprehensive Frontend System Architecture & Validation Report

**Document Version:** 1.0.0  
**Date:** October 2026  
**Auditor / Architect:** Senior Frontend Engineer & SOC Interface Architect  
**Scope:** `frontend/` directory, Single-Page Application (SPA) architecture, Cytoscape.js graph canvas, CSS design tokens, view controllers, and standalone validation procedures.  
**Repository:** `d:/Desktop/Hackathon/ThreatLens`

---

## Table of Contents
1. [Section 1: Executive Architecture Overview](#section-1-executive-architecture-overview)
2. [Section 2: File Structure & Asset Inventory](#section-2-file-structure--asset-inventory)
3. [Section 3: Design System, Tokens & Visual Hierarchy](#section-3-design-system-tokens--visual-hierarchy)
4. [Section 4: Client-Side State Management & Hash Routing](#section-4-client-side-state-management--hash-routing)
5. [Section 5: Detailed Component & View Pane Deep Dive (All 10 Panes)](#section-5-detailed-component--view-pane-deep-dive-all-10-panes)
6. [Section 6: Cytoscape.js Graph Canvas Integration](#section-6-cytoscapejs-graph-canvas-integration)
7. [Section 7: Error Handling, Loading States & Offline Resiliency](#section-7-error-handling-loading-states--offline-resiliency)
8. [Section 8: Independent Frontend Validation Protocol (Runbook)](#section-8-independent-frontend-validation-protocol-runbook)

---

## Section 1: Executive Architecture Overview

The ThreatLens frontend is an industrial-grade Single-Page Application (SPA) designed specifically for Security Operations Center (SOC) tier-1/tier-2 analysts and incident response teams. It delivers high-density threat telemetry, multi-hop graph visualization, and interactive containment simulation without the runtime overhead or build complexity of heavy frontend frameworks.

```
+----------------------------------------------------------------------------------------------------+
|                                    ThreatLens SOC Shell Header                                     |
|  [Logo & Brand]  |  [Global Search]  |  [Breadcrumb Trail]  |  [Service Health: API / Neo4j / Kafka]  |
+----------------------------------------------------------------------------------------------------+
|   Sidebar Navigation    |                               Main Workspace                              |
|                         |                                                                          |
| - Dashboard             |  +--------------------------------------------------------------------+  |
| - Email Forensics       |  | View Pane Container (#view-pane active)                           |  |
| - Investigations        |  |                                                                    |  |
| - Threat Intelligence   |  |  [Interactive Graph Canvas] <---> [Action & Filter Control Toolbar]|  |
| - Attack Graph          |  |  (Cytoscape.js Hardware Accel)    (Chips, Search, Layouts, Toggles)|  |
| - Evidence Vault        |  |                                                                    |  |
| - Governance & Controls |  |  [Detail Cards / Drawers]  <---> [Side-by-Side Comparison Modals]  |  |
| - GraphOps Workspace    |  |  (Entity Attributes, CVEs)        (What-If Containment Simulator)  |  |
|                         |  +--------------------------------------------------------------------+  |
+-------------------------+--------------------------------------------------------------------------+
|                                    Global Notifications / Toast Bar                                |
+----------------------------------------------------------------------------------------------------+
```

### Core Architecture Tenets
1. **Zero Build Step / Maximum Portability:** Built natively with HTML5, Vanilla CSS, and modern Vanilla JavaScript (ES6+). Can be served statically by any web server (Python `http.server`, Nginx, Apache) or accessed directly via the file system without `npm install` or compilation pipelines.
2. **Hardware-Accelerated Graph Rendering:** Utilizes [Cytoscape.js 3.30.4](file:///d:/Desktop/Hackathon/ThreatLens/frontend/index.html) to render multi-hop enterprise graphs, blast radius subgraphs, and attack pathways with smooth panning, zooming, and physics-based layouts (Cola, Cose, Breadthfirst).
3. **High-Contrast Dark SOC Aesthetics:** Designed strictly to meet WCAG AA contrast standards (minimum 4.5:1 text-to-background ratio), utilizing curated dark surface elevations (`#0b0f19`, `#111827`, `#1f2937`) and standard security color semantics (`CRITICAL: #ef4444`, `HIGH: #f97316`, `MEDIUM: #eab308`, `LOW: #3b82f6`).
4. **Resilient Dual-Mode Operation:** Functions seamlessly in **Connected Mode** (calling live FastAPI backend endpoints) and **Standalone Demo Mode** (utilizing baked-in client-side demonstration fixtures when backend services are offline).

---

## Section 2: File Structure & Asset Inventory

The frontend is housed in the `frontend/` directory:

```
frontend/
├── index.html            # Main SPA DOM structure, modals, templates (124,864 bytes)
├── css/
│   └── styles.css        # Design tokens, layouts, animations, Cytoscape rules (28,673 bytes)
└── js/
    └── app.js            # State store, hash router, Cytoscape controller, API client (178,234 bytes)
```

### 1. `frontend/index.html`
* Contains the overall application shell: Topbar header, global search bar, breadcrumbs, sidebar navigation with notification badges, ten (10) view pane containers, and overlay modal dialogs.
* Integrates external vendor scripts via secure CDN:
  - `Cytoscape.js v3.30.4` (`https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.4/cytoscape.min.js`)
  - `Cola.js layout extension` (`https://unpkg.com/webcola/cola.min.js` and `cytoscape-cola.js`)
  - `Lucide Icons` / `FontAwesome` for security iconography.

### 2. `frontend/css/styles.css`
* Implements the design token system using CSS Custom Properties (`:root`).
* Defines responsive CSS Grid and Flexbox view layouts.
* Contains dedicated styling for graph overlays, canvas tooltips, node attribute inspection cards, and the side-by-side What-If containment comparison modal.

### 3. `frontend/js/app.js`
* Monolithic, highly organized client controller (3,973 lines).
* Encapsulates global state, hash-based URL routing, DOM event listeners, asynchronous API fetch clients, Cytoscape instance lifecycles, and real-time streaming table handlers.

---

## Section 3: Design System, Tokens & Visual Hierarchy

The application interface adheres to a strict dark SOC design system:

### 1. CSS Custom Properties (`:root` Tokens)
```css
:root {
  /* Surfaces & Backgrounds */
  --bg-primary: #0b0f19;      /* Root viewport background */
  --bg-secondary: #111827;    /* Sidebar and header background */
  --bg-card: #1f2937;         /* Card, panel, and table background */
  --bg-card-hover: #374151;   /* Hover state elevation */

  /* Borders & Dividers */
  --border-color: #374151;
  --border-accent: #4b5563;

  /* Typography Colors */
  --text-primary: #f9fafb;    /* High contrast headings and values */
  --text-secondary: #9ca3af;  /* Secondary metadata and labels */
  --text-muted: #6b7280;      /* Disclaimers and timestamps */

  /* Brand & Accents */
  --primary-accent: #6366f1;  /* Indigo primary button and active tab */
  --primary-hover: #4f46e5;
  --focus-ring: #818cf8;

  /* Standard Security Severity Tokens */
  --severity-critical: #ef4444; /* Bright Red */
  --severity-high: #f97316;     /* Orange */
  --severity-medium: #eab308;   /* Amber / Yellow */
  --severity-low: #3b82f6;      /* Blue */
  --severity-info: #10b981;     /* Emerald / Green */
}
```

### 2. System Status & Health Indicators
The topbar header continuously displays dynamic health status pills for backend subsystems without hardcoded fake metrics:
* **API Gateway Pill (`#health-pill-api`):** Green `CONNECTED` (HTTP 200 from `/api/v1/health`), Yellow `DEGRADED`, or Red `DISCONNECTED`.
* **Neo4j Graph Database Pill (`#health-pill-neo4j`):** Reflects database connectivity from `/api/v1/graphops/schema/status`.
* **Kafka Event Bus Pill (`#health-pill-kafka`):** Indicates active Kafka broker or fallback in-memory event bus mode.

---

## Section 4: Client-Side State Management & Hash Routing

### 1. Global State Store (`state` object in `app.js`)
All UI state is maintained in a centralized, reactive state object:
```javascript
const state = {
  currentRoute: "dashboard",     // Active hash route (e.g., 'graphops', 'governance')
  currentCaseId: null,           // Selected investigation case (e.g., 'MT-101')
  activeCase: null,              // Loaded case dossier JSON
  casesList: [],                 // Catalog of investigation cases
  campaignsList: [],             // Correlated attack campaigns
  demoEmls: {},                  // Cached demo email fixtures
  currentEntityFilter: "all",    // GraphOps filter chip ('all', 'user', 'device', etc.)
  canvasSearchTerm: "",          // Active text filter on canvas nodes
  showEdgeLabels: true,          // Toggle for Cy edge labels
  cyGraphOps: null,              // Main Cytoscape instance for GraphOps canvas
  graphOpsMode: "blast",         // Active sub-mode ('blast', 'paths', 'containment', 'communities')
  graphOpsLastBlast: null,       // Last blast radius API response
  graphOpsLastPaths: null,       // Last attack paths API response
  graphOpsSimResult: null,       // Last what-if containment simulation response
  findingsList: [],              // Telemetry findings stream items
  findingsFilter: "ALL"          // Findings stream severity filter
};
```

### 2. Hash-Based SPA Router
Routing is managed via window hash change events (`window.addEventListener("hashchange", handleRouting)`):
* `#/dashboard` $\rightarrow$ Activates `#view-dashboard`
* `#/email-analysis` $\rightarrow$ Activates `#view-email-analysis`
* `#/investigations` $\rightarrow$ Activates `#view-investigations`
* `#/case-detail?case=MT-101` $\rightarrow$ Activates `#view-case-detail` and loads case dossier
* `#/threat-intelligence` $\rightarrow$ Activates `#view-threat-intelligence`
* `#/attack-graph` $\rightarrow$ Activates `#view-attack-graph`
* `#/evidence` $\rightarrow$ Activates `#view-evidence`
* `#/governance` $\rightarrow$ Activates `#view-governance`
* `#/graphops` $\rightarrow$ Activates `#view-graphops` and resizes Cytoscape canvas

---

## Section 5: Detailed Component & View Pane Deep Dive (All 10 Panes)

### View 1: Executive Dashboard (`#view-dashboard`)
* **KPI Metrics Grid:** Displays active cases count, high-risk emails, average risk score, and Crown Jewels at risk.
* **Alert Stream Feed:** Displays chronological incoming security alerts with severity badges and direct jump links.
* **Risk Distribution Charts:** Visual representation of threat breakdown (Phishing, BEC, Malware, Impersonation).

### View 2: Email Threat Forensics (`#view-email-analysis`)
* **MIME Upload Dropzone:** Drag-and-drop or file selector accepting `.eml` and `.msg` files.
* **Demonstration Injector Buttons:** 1-click loading of realistic attack fixtures (`Phishing`, `BEC`, `Impersonation`, `Benign`, `Malware`).
* **Header Inspection Grid:** Displays parsed `From`, `Reply-To`, `Return-Path`, `Subject`, and authentication status badges (`SPF: PASS`, `DKIM: PASS`, `DMARC: FAIL`).
* **IOC Extraction Table:** Lists extracted IPs, URLs, and domains with one-click defanging.
* **Explainable AI Attribution Gauge:** Renders composite risk score ($0 \dots 100$) and itemizes weighted factor contributions (e.g., Domain Spoofing +35, Urgent Financial Keywords +25, Blacklisted IP +40).

### View 3: Active Investigations (`#view-investigations`)
* **Case Catalog Grid:** Displays historical and active investigation dossiers (`MT-101` to `MT-105`).
* **Filtering Controls:** Search by subject/recipient, filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), or filter by status (`OPEN`, `TRIAGED`, `RESOLVED`).

### View 4: Case Management Dossier & Enterprise Exposure (`#view-case-detail`)
* **Dossier Header:** Case ID, victim details, incident timestamp, risk gauge, and status transitions.
* **Horizontal Navigation Tabs:**
  1. `Overview`: Incident synopsis and executive summary.
  2. `Indicators`: Extracted IOCs and threat reputation.
  3. `Timeline`: Forensic event sequence.
  4. `Campaigns`: Links to broader attack campaigns (`CMP-001`).
  5. **`Enterprise Exposure` Tab (`#tab-exposure`):**
     - Correlates victim email address to Active Directory identity (`user:usr-101`) and assigned laptop (`device:dev-ws-101`).
     - Quarantines external adversary IOCs (`185.190.140.22`).
     - Features direct jump button: **"Calculate Blast Radius for DEV-WS-101"** linking directly into GraphOps.

### View 5: Threat Intelligence Lookup (`#view-threat-intelligence`)
* **Search Interface:** Input field for arbitrary IP, domain, URL, or file hash.
* **Reputation Cards:** Aggregated intelligence from VirusTotal, AbuseIPDB, and internal threat cache.

### View 6: Attack Graph Canvas (`#view-attack-graph`)
* **Cytoscape Canvas:** Displays campaign-level topology mapping relationships between phishing emails, senders, attacker infrastructure, and target organizations.

### View 7: Forensic Reports (`#view-reports`)
* **Exportable Dossier:** Generates printable incident summary reports with cryptographic evidence hashes for compliance handoffs.

### View 8: Forensic Evidence Chain of Custody (`#view-evidence`)
* **Cryptographic Vault:** Displays SHA-256 digests of raw email artifacts, extracted attachments, and forensic logs, establishing audit-ready provenance.

### View 9: Governance & Controls Hub (`#view-governance`)
* **Sub-Navigation Tabs:**
  1. `Standards Catalog`: Interactive explorer of 25 controls across NIST CSF 2.0, NIST SP 800-53, CIS v8.1, MITRE ATT&CK, and ISO 27001 with official external reference links.
  2. `Organizational Policies`: Table of policies (`POL-IAM-01`, `POL-EXPOSURE-01`, etc.) with action buttons.
  3. **`Evidence-Backed Evaluation`:** Evaluates policies against live graph topology. Highlights compliance (`PASS`), non-compliance (`FAIL`), and strict missing-evidence demarcation (`NEEDS_REVIEW`).
  4. `Remediation Tracking`: Lifecycle task board (P1-P4 priority).
  5. `Cryptographic Audit Ledger`: Immutable SHA-256 hash-chain record viewer with live **"Verify Chain Integrity"** button.

### View 10: GraphOps Intelligence Workspace (`#view-graphops`)
* **Hardware-Accelerated Cytoscape Canvas:** Full-viewport interactive graph rendering.
* **Toolbar & Filtering Controls:**
  - **Entity Filter Chips:** `All`, `User`, `Device`, `Server`, `App`, `CVE`, `IP`, `Crown Jewels`.
  - **Layout Selector:** `Cola` (physics-based), `Breadthfirst` (hierarchical), `Cose` (force-directed), `Circle`.
  - **Live Search Input:** Highlights nodes on canvas matching typed text in real time.
  - **Edge Labels Toggle:** Switch display of relationship types on canvas edges.
* **Analytical Workflow Panels:**
  - **Blast Radius Analysis:** Start node input, max hops (1-3), direction selector, Crown Jewel exposure summary cards.
  - **Attack Paths & Choke Points:** Entry and target node selectors, step-by-step Attack Paths Breakdown accordion, and strategic choke points table.
  - **In-Memory What-If Containment Simulator:**
    - Modal dialog allows analyst to select nodes to isolate or connections to block.
    - Side-by-side comparison grid displays Baseline Paths vs Residual Paths and Containment Efficiency %.
    - Displays explicit safety guarantee: **"SIMULATION ONLY - Live Graph Not Modified"**.
  - **Communities & Clustering:** Color-codes network nodes by Louvain community partitions.
  - **Real-Time Findings Stream:** Live telemetry table updating with anomaly and link-prediction findings. Clicking any row opens a comprehensive detail modal.

---

## Section 6: Cytoscape.js Graph Canvas Integration

### 1. Visual Styling Rules (CSS-in-JS Stylesheet)
Cytoscape instances in `app.js` are configured with enterprise styling rules:
```javascript
const graphOpsStylesheet = [
  // Base Node Style
  {
    selector: "node",
    style: {
      "label": "data(label)",
      "color": "#f9fafb",
      "font-size": "11px",
      "text-valign": "bottom",
      "text-margin-y": 6,
      "background-color": "#4b5563",
      "border-width": 2,
      "border-color": "#1f2937"
    }
  },
  // Node Label Specializations
  { selector: "node[label = 'User']", style: { "shape": "ellipse", "background-color": "#3b82f6" } },
  { selector: "node[label = 'Device']", style: { "shape": "round-rectangle", "background-color": "#8b5cf6" } },
  { selector: "node[label = 'Server']", style: { "shape": "barrel", "background-color": "#10b981" } },
  { selector: "node[label = 'Application']", style: { "shape": "diamond", "background-color": "#ec4899" } },
  { selector: "node[label = 'Vulnerability']", style: { "shape": "triangle", "background-color": "#f97316" } },
  { selector: "node[label = 'CriticalAsset'], node[criticality = 'CRITICAL']",
    style: {
      "shape": "star",
      "background-color": "#ef4444",
      "border-width": 4,
      "border-color": "#fca5a5"
    }
  },
  // Edges
  {
    selector: "edge",
    style: {
      "width": 2,
      "line-color": "#6b7280",
      "target-arrow-color": "#6b7280",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "font-size": "9px",
      "color": "#9ca3af"
    }
  },
  // Hypothetical Exploit Edges
  {
    selector: "edge[evidence_class = 'HYPOTHETICAL']",
    style: {
      "line-style": "dashed",
      "line-color": "#f97316",
      "target-arrow-color": "#f97316"
    }
  }
];
```

### 2. Canvas Interactions & Event Handlers
* **Node Tap (`cy.on('tap', 'node', ...)`):** Opens the Entity Inspection Drawer on the right, displaying node properties, CVE associations, connected relationships, and 1-click blast radius calculation.
* **Canvas Tap (`cy.on('tap', (e) => ...)`):** Tapping empty canvas clears selection and resets node highlighting.
* **Responsive Resize:** Automatically calls `cy.resize()` and `cy.fit()` whenever the GraphOps tab is activated or the browser window resizes.

---

## Section 7: Error Handling, Loading States & Offline Resiliency

1. **Toast Notification System:** Asynchronous operations notify the analyst via non-blocking toast alerts (`showToast(message, type)` with types `success`, `error`, `info`, `warning`).
2. **Canvas Loading Overlay:** Graph operations display an animated spinner overlay (`#graphops-loading-overlay`) with status text (e.g., *"Calculating 3-hop Blast Radius..."*), preventing duplicate requests during calculation.
3. **Graceful API Fallbacks:** If the backend API is unreachable, the frontend does not crash with unhandled promise rejections. It displays clear warning banners and enables local mock demonstration data.

---

## Section 8: Independent Frontend Validation Protocol (Runbook)

Follow this step-by-step protocol to validate the ThreatLens frontend in isolation using Windows PowerShell and a web browser.

### Step 1: Validate JavaScript Syntax
Before launching, confirm that `frontend/js/app.js` is free of syntax errors using Node.js:
```powershell
node --check d:\Desktop\Hackathon\ThreatLens\frontend\js\app.js
```
**Verification Criterion:** Command exits with code 0 and zero syntax errors reported.

### Step 2: Serve the Frontend Locally
Serve the `frontend/` directory statically using Python's built-in HTTP server:
```powershell
# Navigate to workspace
cd d:\Desktop\Hackathon\ThreatLens

# Serve frontend directory on port 3000
python -m http.server 3000 --directory frontend
```
Expected output:
```
Serving HTTP on :: port 3000 (http://[::]:3000/) ...
```

### Step 3: Launch & Verify Browser Application Shell
1. Open Google Chrome or Microsoft Edge.
2. Navigate to `http://localhost:3000` (or `http://127.0.0.1:3000`).
3. Open Browser Developer Tools (`F12`) and switch to the **Console** tab.
**Verification Criterion:**
* Application loads immediately with dark SOC styling.
* Console shows zero uncaught JavaScript exceptions (`TypeError`, `ReferenceError`).

### Step 4: Validate Navigation & SPA Hash Routing
Click each item in the left sidebar navigation and confirm hash update and pane activation:
1. Click **Dashboard** $\rightarrow$ URL becomes `#/dashboard`, `#view-dashboard` displays KPI cards.
2. Click **Email Forensics** $\rightarrow$ URL becomes `#/email-analysis`, upload form displays.
3. Click **Investigations** $\rightarrow$ URL becomes `#/investigations`, case list displays.
4. Click **Governance & Controls** $\rightarrow$ URL becomes `#/governance`, standards catalog displays.
5. Click **GraphOps Workspace** $\rightarrow$ URL becomes `#/graphops`, Cytoscape canvas initializes.

### Step 5: Validate Email Forensics Demo Injectors
1. In the sidebar, click **Email Forensics**.
2. Click the **"Phishing Demo"** button.
**Verification Criterion:**
* Sender (`attacker@secure-bank-login.xyz`), recipient, subject, and body populate instantly.
* Click **"Run Threat Analysis"**.
* Analysis cards render: Risk Score displays $\ge 85$ (CRITICAL), SPF/DKIM/DMARC badges display, extracted IOCs populate the table, and Explainable AI factor breakdown shows attribution bars.

### Step 6: Validate Case Dossier & Enterprise Exposure Bridge
1. In the sidebar, click **Investigations**.
2. Click on case **`MT-101`** (Victim: Alice Vance).
3. Confirm case dossier opens (`#/case-detail?case=MT-101`).
4. Click the **"Enterprise Exposure"** horizontal tab.
**Verification Criterion:**
* Victim email `victim1@corporation.com` maps to `user:usr-101` and `device:dev-ws-101`.
* External adversary IP `185.190.140.22` is clearly listed under "Quarantined External Indicators".
* Click the blue button **"Calculate Blast Radius for DEV-WS-101"**.
* The application navigates directly to the GraphOps Workspace with `device:dev-ws-101` pre-filled.

### Step 7: Validate GraphOps Cytoscape Canvas & Controls
1. Navigate to `#/graphops`.
2. Verify Cytoscape canvas rendering.
3. Test layout selector: Switch between **Cola**, **Breadthfirst**, and **Cose**. Confirm nodes reposition smoothly.
4. Test filter chips: Click **"Crown Jewels"** chip. Confirm standard nodes fade and Crown Jewels remain prominently highlighted.
5. Test live search: Type `srv-app-01` in the canvas search box. Confirm `server:srv-app-01` is zoomed and highlighted.

### Step 8: Validate What-If Containment Simulation Modal
1. On the GraphOps toolbar, click the **"What-If Containment Simulator"** button.
2. In the modal, select **Isolate Node**: choose `server:srv-app-01`.
3. Click **"Run Containment Simulation"**.
**Verification Criterion:**
* The modal updates displaying side-by-side metric comparison.
* Containment Efficiency displays `100.0%`.
* Active residual attack paths drop to `0`.
* The banner displays: *"SIMULATION ONLY - Live Graph Not Modified"*.
* Click **"Close Simulation"** to return to the active canvas.

### Step 9: Validate Governance & Audit Verification
1. Navigate to `#/governance`.
2. Click the **"Audit Ledger"** tab.
3. Click **"Verify Chain Integrity"**.
**Verification Criterion:**
* Ledger records display sequential SHA-256 hashes.
* Verification alert confirms: *"Audit ledger cryptographic integrity verified (Valid: true)"*.
