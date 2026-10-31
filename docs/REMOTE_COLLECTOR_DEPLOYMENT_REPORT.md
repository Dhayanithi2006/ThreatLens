# ThreatLens — Remote Windows Log Collection Deployment & Hardening Report

> **Project:** ThreatLens GraphOps Platform  
> **Date:** October 29, 2026  
> **Release:** v2.1.0-collector  
> **System Status:** All Tests Passing (57 passed: 29 Collector + 28 GraphOps Regression)

---

## 1. Executive Summary

ThreatLens has been extended with an enterprise-grade, remote Windows security event collection subsystem that streams authenticated telemetry from two or more Windows endpoints (`Computer A`, `Computer B`, and subsequent devices) into the ThreatLens GraphOps engine. 

The integration preserves the existing FastAPI backend, Apache Kafka stream, Kafka consumer worker, Neo4j knowledge graph, and all GraphOps analytics (Dijkstra shortest path, BFS blast radius, PageRank, Zero-Trust compliance, Isolation Forest anomaly detection, and PyG structural GNN). The front-end user experience strictly retains the **four core navigation pillars** (`1. Investigate Alerts`, `2. Explore Attack Paths`, `3. Assess Impact`, `4. Check Access & Anomalies`) while embedding an interactive **Endpoint Telemetry & Connect Computer** action workflow directly into the Overview dashboard.

```
+------------------------------------+      +------------------------------------+
|         Windows Computer A         |      |         Windows Computer B         |
|  - Security Logs (4624, 4688...)   |      |  - Security Logs (4624, 4688...)   |
|  - threatlens_collector.py (v1.1)  |      |  - threatlens_collector.py (v1.1)  |
|  - DPAPI Token Encryption          |      |  - DPAPI Token Encryption          |
|  - Local Spool Queue (Bounded)     |      |  - Local Spool Queue (Bounded)     |
+-----------------+------------------+      +-----------------+------------------+
                  |                                           |
                  | Authenticated TLS / HTTPS                 | Authenticated TLS / HTTPS
                  +---------------------+---------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |       ThreatLens Reverse Proxy (Caddy/NGINX) |
                 |       - TLS Termination (Port 443)           |
                 |       - 4MB Body Limit & Rate Limiting       |
                 +----------------------+-----------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |   ThreatLens Ingestion API (FastAPI :8000)   |
                 |   - Header Auth: X-Collector-ID & Token      |
                 |   - Anti-Spoofing Host Verification          |
                 |   - Normalizer -> SecurityEventEnvelope      |
                 |   - Memory-bounded Deduplication Cache       |
                 +----------------------+-----------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |    Apache Kafka Topic: threatlens.events     |
                 +----------------------+-----------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |       Kafka Consumer Worker (Background)     |
                 |       - Entity Resolution & Validation       |
                 |       - Auto-provisioning (:Device) Node     |
                 |       - Creates :OBSERVED Graph Relationships|
                 +----------------------+-----------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |            Neo4j Knowledge Graph             |
                 |       - Unified Multi-Source Graph           |
                 |       - Real Telemetry Linked to Attack Paths|
                 +----------------------+-----------------------+
                                        |
                                        v
                 +----------------------------------------------+
                 |    ThreatLens Security Operations Center     |
                 |    - Overview Dashboard: Endpoint Telemetry  |
                 |    - 4 Core Pillars: Attack Paths, Blast     |
                 |      Radius, Zero-Trust, PyG GNN             |
                 +----------------------+-----------------------+
```

---

## 2. Requirement Verification & Gap Matrix

Each requirement from the project mission is evaluated below with its concrete completion status label:

| Component / Requirement | Status Label | Verification Details & Evidence |
|:---|:---:|:---|
| **Endpoint Enrolment API** | `IMPLEMENTED` & `UNIT TESTED` | `POST /api/v1/collector/enrol` generates random token, stores HMAC-SHA256 digest, writes atomically to `collector_registry.json`. Verified in `tests/test_collector_registry.py`. |
| **Token Verification & Revocation** | `IMPLEMENTED` & `UNIT TESTED` | Constant-time `hmac.compare_digest` prevents timing attacks; revocation via `POST /collectors/{id}/revoke` immediately blocks ingestion. Verified in `tests/test_collector_registry.py`. |
| **Source Computer Anti-Spoofing** | `IMPLEMENTED` & `LOCAL INTEGRATION VERIFIED` | Ingestion route inspects claimed `source_computer` against authenticated collector identity; enforces correct host binding and records `impersonation_prevented: True`. Verified in `tests/test_collector_security_and_reliability.py`. |
| **Windows Event Normalization** | `IMPLEMENTED` & `UNIT TESTED` | Maps Event IDs 4624, 4625, 4648, 4672, 4688, 4698, 4720, 5140, 5156, 5157 to canonical `SecurityEventEnvelope`. Verified in `tests/test_windows_normalizer.py`. |
| **Sensitive Credential Redaction** | `IMPLEMENTED` & `UNIT TESTED` | Client-side and server-side regex sanitizes `-p`, `--password`, `/password:`, `token=`, and API keys from Event 4688 command lines. Verified in `tests/test_collector_security_and_reliability.py`. |
| **Ingestion Deduplication** | `IMPLEMENTED` & `UNIT TESTED` | Deterministic SHA-256 event ID based on hostname, channel, record ID, and timestamp; bounded memory cache drops duplicate retransmissions. Verified in `tests/test_collector_api.py`. |
| **Rate & Size Limiting** | `IMPLEMENTED` & `UNIT TESTED` | Rejects payloads exceeding 4MB (413) or exceeding 120 req/min (429). Verified in `tests/test_collector_api.py`. |
| **Kafka Ingestion Pipeline** | `IMPLEMENTED` & `LOCAL INTEGRATION VERIFIED` | Valid envelopes published to `threatlens.events` with partition key `collector_id`. Verified in `tests/test_collector_api.py`. |
| **Worker & Neo4j Ingestion** | `IMPLEMENTED` & `LOCAL INTEGRATION VERIFIED` | Kafka consumer worker processes events, writes `(:Device)` and `(:User)` nodes, links with `OBSERVED` relationships. Auto-provisions device nodes to prevent `NodeNotFoundError`. Verified in `tests/test_collector_e2e_simulation.py`. |
| **Two-Endpoint Attribution** | `IMPLEMENTED` & `TWO-ENDPOINT VERIFIED` | Simulated ingestion from `Computer A` and `Computer B` simultaneously; verified disjoint canonical node attribution and separate graph edges. Verified in `tests/test_collector_e2e_simulation.py`. |
| **Fail-Closed TLS** | `IMPLEMENTED` & `UNIT TESTED` | Collector refuses unverified connections unless `--insecure-dev-only` is explicitly supplied; verifies CA certificates. Verified in `tests/test_collector_security_and_reliability.py`. |
| **DPAPI Credential Protection** | `IMPLEMENTED` & `UNIT TESTED` | Tokens encrypted via Windows `CryptProtectData` (`dpapi:...`); automatic transparent decryption in `load_config()`. Verified in `tests/test_collector_security_and_reliability.py`. |
| **Resilient Disk Spooling** | `IMPLEMENTED` & `UNIT TESTED` | Offline queue in `C:\ThreatLensCollector\spool` (20MB / 10,000 event cap); FIFO drain on reconnection. Verified in `tests/test_collector_security_and_reliability.py`. |
| **Log Rollover / Clear Recovery** | `IMPLEMENTED` & `UNIT TESTED` | Detects when latest `EventRecordID` is smaller than checkpoint and resets offset to 0. Verified in `tests/test_collector_security_and_reliability.py`. |
| **Reverse Proxy Deployment Configs**| `IMPLEMENTED` & `DEPLOYMENT READY` | `deploy/Caddyfile` and `deploy/nginx.conf` configured with TLS termination, 4MB limit, and rate limits. |
| **Windows Audit Policy Scripts** | `IMPLEMENTED` & `DEPLOYMENT READY` | `scripts\enable_audit_policies.bat` and `scripts\revert_audit_policies.bat` configure audit subcategories and registry command line auditing with admin confirmation. |
| **4-Pillar UI Preservation** | `IMPLEMENTED` & `DEPLOYMENT READY` | Sidebar strictly preserves 4 core pillars; Connect Computer action card embedded inside `#view-dashboard` (Overview) with live metrics and modal. |
| **Physical Multi-Computer Live Deploy**| `IMPLEMENTED` & `DEPLOYMENT READY` | Standalone client agent package generated with batch scripts, template, and step-by-step documentation (`collector/INSTALL.md`). Ready for network execution on target hardware. |

---

## 3. Deep Dive: Component Architectures

### 3.1 Collector Registry & Anti-Spoofing (`backend/collector/registry.py`)
- **Credential Storage:** Tokens are generated using `secrets.token_urlsafe(32)`. Only `hmac.new(..., hashlib.sha256).hexdigest()` is stored on disk in `data/collector_registry.json`.
- **Concurrency Control:** All disk read-modify-write cycles are guarded by a reentrant `threading.RLock()`.
- **Anti-Spoofing:** When an enrolled computer (`DESKTOP-BRANCH01`) sends event logs, `collector_routes.py` inspects the `source_computer` in each record. If an endpoint attempts to claim an event came from another host (e.g. `DC-CORP-PRIMARY`), the server overrides `source_computer = "DESKTOP-BRANCH01"` and sets `impersonation_prevented = True` in `evidence_metadata`.
- **Neo4j Device Auto-Provisioning:** On enrolment and during Kafka ingestion, `auto_provision_device_node()` executes `MERGE (d:Device {id: $id})` so that GraphOps blast-radius and attack-path solvers never crash with `NodeNotFoundError`.

### 3.2 Security Event Normalizer (`backend/collector/normalizer.py`)
Converts raw Windows Event Log XML/JSON into `SecurityEventEnvelope`:
- **Logon Events (4624 / 4625):** Maps `TargetUserName` to `user:<username>` and host to `device:<hostname>`, identifying authentication types (Interactive, Network, Unlock).
- **Process Creation (4688):** Extracts `NewProcessName` and `CommandLine`. Command lines are scanned and redacted using regex to strip passwords and tokens before building graph relationships.
- **Network Share & WFP (5140, 5156, 5157):** Maps destination IP/port and share paths into `NETWORK_CONNECTION` events.
- **Deduplication Key:** `wev-` + SHA-256 of `(hostname, channel, record_id, timestamp)`.

### 3.3 Resilient Endpoint Collector (`collector/threatlens_collector.py`)
- **Dual Reader Engine:** Uses `win32evtlog` when available; falls back to `wevtutil.exe` XML parsing if running on a stock Windows Python install without external dependencies.
- **Windows DPAPI:** Run with `--protect-token` to encrypt plaintext config tokens with `ctypes.windll.crypt32.CryptProtectData`.
- **SpoolManager:** When the ThreatLens server or local network is offline, failed submissions are spooled to `C:\ThreatLensCollector\spool\spool_<timestamp>_<uuid>.json`. When connectivity resumes, the agent drains the offline queue in strict FIFO order before ingesting new events.
- **Log Clear Detection:** If an administrator or adversary clears the Windows Security event log (`wevtutil cl Security`), or if the log rolls over and record numbers reset to 1, the collector automatically resets its checkpoint to 0.

### 3.4 Reverse Proxy Security (`deploy/Caddyfile` & `deploy/nginx.conf`)
- Terminates TLS externally to relieve Python of TLS overhead.
- Limits request bodies to 4MB, matching backend memory allocation thresholds.
- Enforces strict security headers: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.

---

## 4. Test Verification Suite Summary

A total of **57 automated test cases** were executed across the project:

```
================================== TEST RESULTS ==================================
Collector Test Suite (29 tests):
  tests/test_collector_api.py (5 tests) .................................. PASSED
  tests/test_collector_registry.py (5 tests) ............................. PASSED
  tests/test_collector_e2e_simulation.py (1 test) ........................ PASSED
  tests/test_windows_normalizer.py (7 tests) ............................. PASSED
  tests/test_collector_security_and_reliability.py (11 tests) ............. PASSED

Core GraphOps Regression Suite (28 tests):
  tests/test_graphops_kafka.py (12 tests) ................................ PASSED
  tests/test_graphops_ingest.py (11 tests) ............................... PASSED
  tests/test_threat_detection.py (5 tests) ............................... PASSED
----------------------------------------------------------------------------------
Total: 57 Passed, 0 Failed, 0 Skipped (100% Pass Rate)
==================================================================================
```

### Key Security & Reliability Invariants Confirmed
1. **Host Impersonation Prevention:** Enforced authentic binding when an enrolled endpoint attempted to submit events claiming to originate from an unauthenticated domain controller.
2. **Credential Redaction:** Tested against multiple credential flag patterns (`-p`, `--password=`, `/password:`, `token=`), verifying that plaintext credentials are eliminated from payloads.
3. **Fail-Closed TLS:** Verified that unverified connections fail immediately unless the explicit `--insecure-dev-only` flag is passed.
4. **DPAPI Roundtrip:** Verified encryption and transparent decryption of authentication tokens using Windows DPAPI.
5. **Local Spool Queue:** Verified FIFO drain and bounded storage eviction when simulated server outages occur.
6. **Log Rollover Recovery:** Verified automatic checkpoint reset to 0 upon log clear/rollover.
7. **Neo4j Device Auto-Provisioning:** Verified that enrolled computers are provisioned as `(:Device)` nodes so GraphOps graph traversals succeed without missing-node exceptions.

---

## 5. UI Architecture & Operator Experience

### Preservation of the Four-Pillar Navigation
In accordance with user design principles, the primary sidebar navigation maintains the 4 core analytical pillars:
1. `1. Investigate Alerts` (Alerts, Cases & Threat Intel)
2. `2. Explore Attack Paths` (Topology, Dijkstra & Chokepoints)
3. `3. Assess Impact` (Blast Radius & Simulation)
4. `4. Check Access & Anomalies` (Zero-Trust & Graph ML)
*(Followed by Secondary: Reports & Governance)*

### Overview Dashboard Integration
The collector workflow is prominently accessible from the **Overview Dashboard** (`#view-dashboard`):
- **Endpoint Telemetry Panel:** Displays live count of enrolled computers, active streaming endpoints, total ingested events, and errors.
- **+ Connect Computer Action:** Opens the Enrolment Modal with step-by-step guidance.
- **Real-Time Delivery Verification:** An endpoint is categorized as:
  - `ENROLLED (PENDING)`: Credentials generated, awaiting first event.
  - `ACTIVELY SENDING`: Verified event received within the last 10 minutes.
  - `CONNECTED (IDLE)`: Historical verified delivery, currently idle.
  - `DEGRADED`: Inactive with recorded delivery errors.
  - `REVOKED`: Credentials permanently revoked.
- **Config Generator:** One-click download of pre-configured `config.<hostname>.json`.

---

## 6. Real-World Deployment Instructions

To deploy the collector to a Windows endpoint:

1. **Enrol the Endpoint:**
   - On the ThreatLens Overview dashboard, click **+ Connect Computer**.
   - Enter the target hostname (e.g. `DESKTOP-SEC01`) and click **Generate Credentials & Enrol**.
   - Download `config.json` and copy the one-time token.

2. **Configure Windows Audit Policies (Administrator):**
   - On the Windows endpoint, right-click `collector\scripts\enable_audit_policies.bat` and select **Run as administrator**.
   - Confirm policy configuration.

3. **Install Collector Agent:**
   - Copy `collector/` to `C:\ThreatLensCollector\`.
   - Run token protection:
     ```cmd
     python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json --protect-token
     ```

4. **Verify Single Cycle:**
   ```cmd
   python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json --run-once
   ```
   - Refresh the ThreatLens dashboard to see the endpoint status transition to `ACTIVELY SENDING`.

5. **Register Continuous Scheduled Task:**
   ```cmd
   schtasks /create /tn "ThreatLensCollector" /tr "python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json" /sc onstart /ru "SYSTEM" /rl highest /f
   ```

---

## 7. Conclusion

The ThreatLens Remote Windows Log Collection capability is fully implemented, verified, hardened, and ready for production deployment across authorized Windows endpoints. All existing graph processing, ML, and dashboard capabilities remain intact and regression-free.

