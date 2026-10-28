# ThreatLens MVP - Known Limitations & Operational Boundaries

**Document Version:** 1.0.0  
**Phase:** Phase 6 (Governance, Security, and ThreatLens MVP Readiness)  
**Status:** Documented Baseline  
**Date:** October 2026

---

## 1. Graph Database & Environment Boundaries

### 1.1 Neo4j Community Edition Constraints
- **Single Database Topology:** Neo4j Community Edition operates exclusively on a single active database (`neo4j`). Multi-database tenancy, Fabric federations, and database mirroring are features of Neo4j Enterprise and are not available in the local Community build.
- **Connection Pool Boundedness:** The managed client maintains a connection pool capped at 50 connections with a 5.0s connection timeout and 3600.0s lifetime. High concurrent loads exceeding pool limits will queue or encounter connection timeouts.

### 1.2 Path Traversal & Hop Depth Boundaries
- **Traversal Depth Limits:** GraphOps blast radius and attack path queries enforce explicit hop depth limits (`max_hops = 3` by default, configurable up to 5). Unbounded recursive traversals are disallowed to prevent exponential path explosion and memory exhaustion on dense subgraphs.
- **Synthetic Fixture Scale:** The provided enterprise baseline fixture contains 30 nodes and 43 relationships. While verified for algorithmic correctness, scaling to enterprise topologies with hundreds of thousands of nodes requires index-tuned batch ingestion and read replicas.

---

## 2. Governance & Policy Assessment Boundaries

### 2.1 Empirical Evidence vs. Legal Compliance
- **Not a Formal Certification Engine:** Technical evaluations in ThreatLens assess topological adjacency and logged events against heuristic policy rules. They do not constitute formal ISO 27001 certification, SOC 2 Type II attestation, or regulatory compliance sign-offs.
- **Missing Evidence Boundary:** If an assessment payload lacks graph traversal paths or observation logs, the evaluator deterministically issues `NEEDS_REVIEW` or `NOT_EVALUATED`. Compliance (`PASS`) is never granted on negative or missing evidence.

### 2.2 Audit Ledger Persistence
- **In-Memory Ledger with Hash Chaining:** The cryptographic audit trail computes SHA-256 digests over payload and previous hash in memory. This demonstrates tamper-evident verification for MVP operations. Production deployment requires backing the hash chain to write-once append-only storage (e.g., AWS QLDB, immutable S3 object lock, or a dedicated append-only PostgreSQL ledger).

---

## 3. Threat Intelligence & External API Boundaries

### 3.1 Rate Limiting & Quotas
- **Public API Quotas:** Public API keys for VirusTotal and AbuseIPDB operate under strict rate limits (e.g., 4 requests per minute for VirusTotal Community).
- **Auto Fallback Mode:** In `THREAT_INTEL_MODE=auto`, missing or exhausted API keys trigger graceful fallback to local heuristic mock intelligence to prevent pipeline interruption during analyst investigations.

---

## 4. Authentication & Production Hardening Boundaries

### 4.1 Single API Key Model
- **Administrative Key Verification:** Administrative operations (schema mutation, bulk ingest, policy updates) are secured by `ADMIN_API_KEY` via `verify_admin_access`. Enterprise Single Sign-On (SSO) with SAML 2.0 / OIDC / Okta / Azure AD is outside the scope of the local MVP.
- **Development vs. Production Mode:** Setting `REQUIRE_API_KEY=false` (default for local development) permits local prototyping while still enforcing API key validation when credentials are provided. Setting `REQUIRE_API_KEY=true` enforces strict 401 Unauthorized rejection for unauthenticated administrative calls.
