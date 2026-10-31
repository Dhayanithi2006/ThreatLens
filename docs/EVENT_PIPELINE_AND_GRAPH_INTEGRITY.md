# ThreatLens Shared Event Pipeline, Neo4j Graph Integrity & API Contracts Specification

## 1. Executive Summary

This specification establishes the architectural truth, data flow contracts, and validation requirements for the ThreatLens shared event pipeline, Apache Kafka event streaming, Neo4j enterprise security graph persistence, and API lifecycle management.

```
+------------------------------------+
|  Remote Windows Collector Agent    | (Win32 / pyevtx-rs)
+------------------------------------+
                  |
                  | HTTPS :443 (Token Auth via X-Collector-ID / X-Collector-Token)
                  v
+------------------------------------+
| Ingestion & Normalization Layer    | (backend/api/collector_routes.py)
| - Rate Limiter                     | (backend/collector/rate_limiter.py)
| - Host Anti-Spoofing Binding       | (enforces authenticated collector hostname)
| - Normalizer                       | (Windows Event ID -> SecurityEventType)
| - Secret / Credential Redaction    | (redact_sensitive_cmdline)
| - Deterministic ID Generation      | (_make_stable_event_id: wev-{sha256[:24]})
| - In-Memory Deduplication Cache    | (backend/collector/dedup.py)
+------------------------------------+
                  |
                  | SecurityEventEnvelope
                  v
+------------------------------------+
|  GraphOps Kafka Event Producer     | (backend/graphops/kafka_producer.py)
|  - Per-Entity Key Partitioning     | (primary entity_ids[0] as message key)
|  - Durability Guarantee: acks=all  | (synchronous flush verification)
|  - Local Sandbox Fallback Mode     | (explicit mock queue in dev environments)
+------------------------------------+
                  |
                  v (Kafka Topics: security.endpoint.events, security.identity.events, etc.)
+------------------------------------+
|  GraphOps Kafka Consumer Worker    | (backend/graphops/kafka_worker.py)
|  - Manual Offset Commit            | (commits strictly after persistence or DLQ)
|  - Transient Retry with Backoff    | (up to 3 retries with linear backoff)
|  - Poison Message Handling         | (immediate DeadLetterEventEnvelope write)
+------------------------------------+
                  |
                  | Bounded Cypher MERGE Queries
                  v
+------------------------------------+
|  Neo4j Enterprise Security Graph   | (backend/graphops/client.py)
|  - 9 Unique Label Constraints      | (User, Device, Server, Application, ...)
|  - 6 Property Indexes              | (rapid traversal and entity resolution)
|  - Idempotent Event Deduplication  | (MATCH (e:SecurityEvent {id: $id}))
|  - Automatic Device Provisioning   | (provisions unindexed enrolled devices)
|  - Evidence Class Attribution      | (OBSERVED, AUTHORIZED_ACCESS, INFERRED, HYPOTHETICAL)
+------------------------------------+
                  |
                  v
+------------------------------------+
|  Deterministic Graph Analytics     | (BFS 3-Hop Blast Radius, Dijkstra, Attack Paths, ML/PyG)
+------------------------------------+
```

---

## 2. Event Contracts & Schemas

### A. Registered Security Event Types (`SecurityEventType`)

| Event Type Enum | Domain Category | Windows Event IDs Mapped | Default Kafka Topic |
|---|---|---|---|
| `ENDPOINT_ALERT` | General host alerts & unmapped telemetry | Fallback for unclassified events | `security.endpoint.events` |
| `PROCESS_EVENT` | Host process creation & scheduled tasks | 4688 (Process Creation), 4698 (Task Created), 4699 (Task Deleted) | `security.endpoint.events` |
| `COMPROMISE_INDICATOR` | EDR detection & attack signatures | High-severity behavioral triggers | `security.endpoint.events` |
| `IDENTITY_EVENT` | Authentication, logon & account mutations | 4624 (Logon), 4625 (Failed Logon), 4648 (Explicit Creds), 4672 (Admin Privs), 4720 (User Created), 4726 (User Deleted) | `security.identity.events` |
| `NETWORK_CONNECTION` | Network shares & filtering connections | 5140 (Network Share Access), 5156 (WFP Connect Allowed), 5157 (WFP Connect Blocked) | `security.network.events` |
| `EMAIL_INVESTIGATION_RESULT` | Phishing, BEC & forensic email findings | MailTrace AI pipeline outputs | `security.email.events` |

### B. Canonical Security Event Envelope (`SecurityEventEnvelope`)

```json
{
  "event_id": "wev-3a9f8b1c4e7d2f0a1b5c8d2e",
  "schema_version": "1.0.0",
  "event_type": "IDENTITY_EVENT",
  "source": "sensor:windows-collector",
  "occurred_at": "2026-08-28T10:15:30.123456Z",
  "ingested_at": "2026-08-28T10:15:31.002145Z",
  "entity_ids": [
    "user:victim1@corporation.com",
    "device:dev-ws-101"
  ],
  "payload": {
    "user_id": "user:victim1@corporation.com",
    "target_resource_id": "device:dev-ws-101",
    "auth_status": "SUCCESS",
    "logon_type": 2
  },
  "correlation_id": "CASE-2026-0828",
  "severity": "MEDIUM",
  "evidence_metadata": {
    "collector_id": "col-win-8a7b9c",
    "source_computer": "DEV-WS-101",
    "channel": "Security",
    "event_record_id": 142055
  }
}
```

#### Field Contract Specifications:
- `event_id` *(required)*: Deterministic stable identifier (`wev-{sha256[:24]}`) produced from `source_computer | event_id_number | source_event_record_id | occurred_at`. Ensures replayed logs generate identical IDs.
- `schema_version` *(required)*: Semantic contract version (`1.0.0`). Evolved versions (`1.1.0`) with extra attributes in `payload` or `evidence_metadata` are processed without failure.
- `event_type` *(required)*: One of the 6 validated `SecurityEventType` enums.
- `source` *(required)*: Telemetry origin identifier e.g. `sensor:windows-collector`, `mailtrace:email-gateway`.
- `occurred_at` *(required)*: RFC 3339 / ISO 8601 UTC timestamp of occurrence on the endpoint.
- `entity_ids` *(required, min_length=1)*: List of canonical entity IDs. The first item (`entity_ids[0]`) serves as the primary entity and Kafka partitioning key.
- `payload` *(required)*: Validated telemetry dictionary.
- `correlation_id` *(optional)*: Incident or case reference identifier.
- `severity` *(optional)*: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `evidence_metadata` *(optional)*: Collector provenance, raw record IDs, and channel metadata.

### C. Secret and Credential Redaction (`redact_sensitive_cmdline`)
To prevent credential leakage into Kafka streams, Neo4j graphs, or log sinks, all command lines forwarded in `PROCESS_EVENT` records undergo regex sanitization:
- Matches: `--password`, `/password`, `-p`, `/p`, `Bearer <token>`, `api_key=...`, `token=...`, `secret=...`.
- Replaces values with `[REDACTED]`.
- Guarantees surrounding arguments and command syntax remain intact for forensic execution analysis.

---

## 3. Kafka Streaming Pipeline Architecture

### A. Centralized Topic Routing & Consumer Groups

| Topic Name | Purpose | Producers | Consumers |
|---|---|---|---|
| `security.endpoint.events` | Host alerts, process telemetry, and indicators | Remote Collector, EDR Sensors | `threatlens-graphops-workers` |
| `security.identity.events` | Directory logons, Kerberos tickets, privilege assignment | Remote Collector, Active Directory | `threatlens-graphops-workers` |
| `security.network.events` | Network connections, share access, firewall blocks | Remote Collector, NetFlow | `threatlens-graphops-workers` |
| `security.email.events` | Forensic email verdicts and indicators | MailTrace Ingestion Gateway | `threatlens-graphops-workers` |
| `graphops.findings` | Event-triggered explainable security findings | GraphOps Event Processor | SOC Dashboard, Alert Hub |
| `graphops.events.dlq` | Dead-letter queue for unprocessable messages | Kafka Consumer Worker | Forensics Review, SRE Alerts |

- **Consumer Group**: `threatlens-graphops-workers` (`KAFKA_CONSUMER_GROUP`).
- **Partition Key**: `message_key = event.entity_ids[0]`. Guarantees all events for a specific device, user, or server are routed to the same partition, enforcing strict chronological order per entity.
- **Publication Durability**: In live production mode, producer enforces `"acks": "all"` (`all` in-sync replicas confirmed) with 3 retries and 250ms backoff.

### B. Error Handling, Retries & Dead-Letter Queue (DLQ)

```
Incoming Kafka Message
          |
          +---> [1] JSON Decoding Failed? --------> Route to DLQ (PERMANENT_MALFORMED_JSON)
          |
          +---> [2] Pydantic Validation Error? ---> Route to DLQ (PERMANENT_SCHEMA_VALIDATION_ERROR)
          |
          +---> [3] Permanent Entity Error? ------> Route to DLQ (PERMANENT_ENTITY_ERROR)
          |         (e.g. unresolvable entity)
          |
          +---> [4] Transient Database Error? ----> Retry loop (up to 3 attempts, linear backoff)
                    (e.g. temporary Neo4j glitch)         |
                                                          +---> Exhausted? -> Route to DLQ (TRANSIENT_RETRIES_EXHAUSTED)
```

- **Dead-Letter Envelope (`DeadLetterEventEnvelope`)**:
  - `event_id`: Extracted event ID if readable.
  - `source_topic`: Originating Kafka topic.
  - `partition` & `offset`: Exact message coordinates for tracing.
  - `failure_category`: Machine-readable classification.
  - `sanitized_error`: Exception details without secrets.
  - `retry_count`: Total attempts prior to abandonment.
  - `raw_payload`: Safely encoded original payload for manual replay.

### C. Manual Offset Commit Contract
To prevent message loss during broker failovers or container restarts:
1. `enable.auto.commit` is set to `False`.
2. Offset commits are executed **synchronously and manually** (`consumer.commit(message=msg, asynchronous=False)`).
3. Commits occur **only after**:
   - The event has been written and committed to Neo4j, AND deterministic GraphOps analytics have completed; OR
   - The poison message has been published to `graphops.events.dlq`.

---

## 4. Neo4j Graph Integrity & Data Model

### A. Canonical Node Labels & Unique ID Constraints

Every node in the ThreatLens security graph belongs to a defined `NodeLabel` and has a strictly enforced unique identifier:

| Label | Canonical Prefix | Example Canonical ID | Unique Constraint Statement |
|---|---|---|---|
| `User` | `user:` | `user:victim1@corporation.com` | `CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (n:User) REQUIRE n.id IS UNIQUE` |
| `Device` | `device:` | `device:dev-ws-101` | `CREATE CONSTRAINT device_id_unique IF NOT EXISTS FOR (n:Device) REQUIRE n.id IS UNIQUE` |
| `Server` | `server:` | `server:srv-app-01` | `CREATE CONSTRAINT server_id_unique IF NOT EXISTS FOR (n:Server) REQUIRE n.id IS UNIQUE` |
| `Application` | `app:` | `app:payment-gateway` | `CREATE CONSTRAINT app_id_unique IF NOT EXISTS FOR (n:Application) REQUIRE n.id IS UNIQUE` |
| `IPAddress` | `ip:` | `ip:10.0.1.15` | `CREATE CONSTRAINT ip_id_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.id IS UNIQUE` |
| `Vulnerability` | `vuln:` | `vuln:CVE-2024-21413` | `CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE` |
| `CriticalAsset` | `critical:` | `critical:db-prod-core` | `CREATE CONSTRAINT crit_id_unique IF NOT EXISTS FOR (n:CriticalAsset) REQUIRE n.id IS UNIQUE` |
| `SecurityEvent` | `event:` / `wev-` | `wev-3a9f8b1c4e7d2f0a1b5c8d2e` | `CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (n:SecurityEvent) REQUIRE n.id IS UNIQUE` |
| `EmailAccount` | `email:` | `email:sender@external.com` | `CREATE CONSTRAINT email_id_unique IF NOT EXISTS FOR (n:EmailAccount) REQUIRE n.id IS UNIQUE` |

### B. Property Indexes
Configured for sub-millisecond property lookups during graph traversal:
- `(n:User).email`
- `(n:Device).ip_address`
- `(n:Server).ip_address`
- `(n:Vulnerability).cve_id`
- `(n:CriticalAsset).impact_score`
- `(n:EmailAccount).email_address`

### C. Relationship Types & Evidence Classes

ThreatLens strictly distinguishes the certainty of graph relationships via `r.evidence_class`:
- **`OBSERVED`**: Direct telemetry from an EDR sensor, Windows event, NetFlow record, or email header.
  - Examples: `LOGGED_IN_TO` (Event 4624), `OBSERVED_CONNECTION` (Event 5156).
- **`AUTHORIZED_ACCESS`**: Statically provisioned rights from Active Directory, IAM role definitions, or ACLs.
  - Examples: `HAS_PERMISSION`, `CAN_REACH`.
- **`INFERRED`**: Algorithmically derived links based on subnet proximity, account clustering, or heuristic similarity.
  - Examples: `MEMBER_OF`, `HOSTED_ON`.
- **`HYPOTHETICAL`**: Ephemeral edges created exclusively within What-If simulations or attack path exploration.
  - Examples: `POTENTIAL_EXPLOIT`, `EXPLOITS`.

### D. Idempotent Persistence & Deduplication
To guarantee replayed Kafka events never corrupt graph topology or duplicate entities:
1. `is_event_processed(event_id)` checks the in-memory processed set and executes a fast query:
   ```cypher
   MATCH (e:SecurityEvent {id: $event_id}) RETURN e.id AS id
   ```
2. If already processed, existing findings are returned without modifying the graph.
3. If new, the event node is merged using parameterized Cypher:
   ```cypher
   MERGE (e:SecurityEvent {id: $event_id})
   ON CREATE SET
       e.event_type = $event_type,
       e.source = $source,
       e.occurred_at = $occurred_at,
       e.ingested_at = $ingested_at,
       e.correlation_id = $correlation_id,
       e.processed_at = $processed_at
   WITH e
   MATCH (target {id: $resolved_id})
   MERGE (target)-[:ASSOCIATED_WITH_CASE]->(e)
   ```

### E. Automatic Provisioning of Enrolled Devices
When an authenticated collector forwards telemetry for a newly enrolled Windows endpoint not yet indexed in Neo4j, the processor automatically provisions the node rather than failing:
```cypher
MERGE (d:Device {id: $id})
ON CREATE SET
    d.device_id = $device_id,
    d.hostname = $hostname,
    d.criticality = 'MEDIUM',
    d.created_at = $timestamp
```

---

## 5. Route Inventory & Dependency Attribution

| Route Method & Path | Primary Purpose | Reads From / Writes To | Auth Requirement |
|---|---|---|---|
| `GET /api/v1/health` | HTTP server liveness check | Static Memory | None (Public) |
| `GET /api/v1/ready` | Deep readiness probe for all dependencies | Neo4j, Kafka Producer, Worker, Ledger, Registry | None (Public / Monitoring) |
| `POST /api/v1/collector/enrol` | Enrol new Windows endpoint agent | Collector Registry (FileLock) | Admin (`X-API-Key`) |
| `GET /api/v1/collector/collectors` | List enrolled collector devices | Collector Registry (FileLock) | Admin (`X-API-Key`) |
| `GET /api/v1/collector/collectors/{id}` | Status of single collector device | Collector Registry (FileLock) | Admin (`X-API-Key`) |
| `POST /api/v1/collector/collectors/{id}/revoke` | Revoke collector token | Collector Registry (FileLock) | Admin (`X-API-Key`) |
| `POST /api/v1/collector/ingest/events` | Ingest raw Windows event batch | Rate Limiter, Normalizer, Kafka Producer | Collector (`X-Collector-ID/Token`) |
| `GET /api/v1/graphops/health` | Neo4j graph database health | Live Neo4j / Mock DB | None (Public) |
| `GET /api/v1/graphops/schema/constraints` | View constraints & indexes | Static Schema Definitions | None (Public) |
| `POST /api/v1/graphops/schema/init` | Apply constraints to Neo4j | Live Neo4j / Mock DB | Admin (`X-API-Key`) |
| `POST /api/v1/graphops/events/publish` | Direct security event publishing | Kafka Producer (`security.*.events`) | None (Public / Analyst) |
| `POST /api/v1/graphops/events/simulate` | End-to-end streaming simulation | Kafka Producer, Consumer Worker, Neo4j | Admin (`X-API-Key`) |
| `GET /api/v1/graphops/events/findings` | Query event-triggered findings | Findings Store / Consumer Worker | None (Public / Analyst) |
| `GET /api/v1/graphops/events/findings/{id}` | Query single finding by ID | Findings Store / Consumer Worker | None (Public / Analyst) |
| `GET /api/v1/graphops/events/status` | Kafka operational diagnostics | Kafka Producer, Consumer Worker | None (Public / Analyst) |
| `GET /api/v1/graphops/events/dlq` | Inspect dead-letter messages | Kafka DLQ Buffer | Admin (`X-API-Key`) |
| `POST /api/v1/graphops/blast-radius` | Bounded BFS blast radius calculation | Neo4j Bolt / In-Memory Graph Mock | None (Public / Analyst) |
| `POST /api/v1/graphops/dijkstra/shortest-path` | Weighted Dijkstra path calculation | Neo4j Bolt / In-Memory Graph Mock | None (Public / Analyst) |
| `POST /api/v1/graphops/attack-paths` | Bounded DFS path discovery | Neo4j Bolt / In-Memory Graph Mock | None (Public / Analyst) |
| `POST /api/v1/graphops/simulate-containment` | What-If containment simulation | Ephemeral Subgraph Copy (Zero DB Write) | None (Public / Analyst) |
| `GET /api/v1/graphops/zero-trust/audit` | Identity & access policy audit | Neo4j Bolt / Mock Policies Store | None (Public / Analyst) |
| `GET /api/v1/governance/reports` | List generated compliance reports | Reports Store (In-Memory) | None (Public / Analyst) |
| `POST /api/v1/governance/reports/generate` | Generate evidence-backed report | Evaluator, GraphOps Context, Cases | None (Public / Analyst) |
| `GET /api/v1/governance/reports/{id}/export` | Export report as JSON, CSV, HTML | Reports Store (Strict `html.escape`) | None (Public / Analyst) |
| `GET /api/v1/governance/evidence/ledger` | Chain of custody evidence items | Case Store, Audit Ledger (SHA-256) | None (Public / Analyst) |
| `POST /api/v1/governance/evidence/verify` | Verify evidence hash | Constant-Time HMAC Digest Engine | None (Public / Analyst) |
| `GET /api/v1/governance/audit/verify` | Verify SHA-256 audit ledger | SHA-256 Chained Hash Ledger | None (Public / Analyst) |

