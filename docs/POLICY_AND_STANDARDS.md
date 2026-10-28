# ThreatLens Governance & Controls - Policy & Standards Architecture

**Document Version:** 1.0.0  
**Phase:** Phase 6 (Governance, Security, and ThreatLens MVP Readiness)  
**Status:** Approved Baseline  
**Date:** October 2026

---

## 1. Architectural Overview

ThreatLens bridges technical GraphOps telemetry (multi-hop lateral movement paths, blast radius calculations, access anomaly scores, and email forensic indicators) with cybersecurity compliance and organizational governance.

Rather than functioning as a standalone paperwork compliance portal, the ThreatLens Governance & Controls module performs **evidence-backed evaluations** against real graph topology and security events.

```
+---------------------------------------------------------------------------------+
|                          ThreatLens Security GraphOps                           |
|   (Blast Radius | Attack Paths | Access Anomalies | RFC 822 Email Forensics)    |
+---------------------------------------+-----------------------------------------+
                                        | Empirical Telemetry Evidence
                                        v
+---------------------------------------------------------------------------------+
|                        Governance Policy Evaluation Engine                      |
|                                                                                 |
|   - Deterministic rule checks against graph traversal and blast boundaries      |
|   - Missing evidence strictly resolves to NEEDS_REVIEW (NEVER Pass)             |
|   - Returns: Status, Supporting Evidence, Rule, Reasoning, Limitations, Action  |
+-------------------+---------------------------------------+---------------------+
                    |                                       |
                    v                                       v
+-----------------------------------+   +-----------------------------------------+
|     Standards Control Catalog     |   |         Remediation & Audit Ledger      |
|                                   |   |                                         |
|  - NIST CSF 2.0                   |   |  - Remediation tracking (P1-P4, Status) |
|  - NIST SP 800-53 Rev. 5          |   |  - Immutable SHA-256 hash chained log   |
|  - CIS Controls v8.1              |   |  - Cryptographic tamper verification    |
|  - MITRE ATT&CK v14.1             |   +-----------------------------------------+
|  - ISO/IEC 27001:2022             |
+-----------------------------------+
```

---

## 2. Normative Assessment Principles & Disclaimers

> [!IMPORTANT]
> **Normative Boundary Disclaimer:**
> A technical finding in ThreatLens (such as a reachable graph path to a database or an access anomaly) serves as **empirical evidence for assessment**; it does not automatically constitute legal or regulatory proof of a standards violation.
>
> ThreatLens makes **no claim of formal regulatory certification, government accreditation, or formal audit completion**. Technical control evaluations provide explainable SOC context to assist security analysts, not binding legal compliance guarantees.

### The Missing Evidence Rule
In strict adherence to sound cybersecurity governance:
**Absence of evidence must NEVER automatically be treated as compliance.**
If an evaluation payload lacks graph traversal paths, telemetry streams, or identity context, the evaluator deterministically returns `NEEDS_REVIEW` or `NOT_EVALUATED`, documenting concrete `data_limitations` (e.g., *"No graph traversal or blast radius evidence supplied in assessment context"*).

---

## 3. Verified Standards Control Catalog

The catalog focuses on identity and access management, asset exposure, vulnerability management, logging/monitoring, and incident response.

| Control ID | Framework | Version | Title | Normative Scope & Mapping Rationale | Verified Official Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PR.AA-01** | NIST CSF | 2.0 | Identity & Credential Management | Maps to GraphOps User and Device nodes, validating credential assignments and active logins. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **PR.AA-05** | NIST CSF | 2.0 | Access Permissions & Least Privilege | Evaluates `HAS_PERMISSION` relationships to detect unprivileged workstations with direct database access. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **PR.IR-01** | NIST CSF | 2.0 | Network & Boundary Protection | Evaluates lateral movement paths bypassing network segmentation boundaries. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **ID.AM-01** | NIST CSF | 2.0 | Hardware & Asset Inventory | Validates device and server graph nodes against enterprise CMDB inventories. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **DE.CM-01** | NIST CSF | 2.0 | Network Monitoring & Adverse Events | Correlates graph edge transitions with `OBSERVED_CONNECTION` network monitoring telemetry. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **RS.AN-01** | NIST CSF | 2.0 | Incident Investigation & Root Cause | Connects email forensic phishing cases to internal blast radius and choke points. | [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29) |
| **AC-2** | NIST SP 800-53 | Rev. 5 | Account Management | Analyzes user-to-device mapping and detects unlinked or hijacked service accounts. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **AC-3** | NIST SP 800-53 | Rev. 5 | Access Enforcement | Detects lateral paths connecting workstations to Crown Jewels without jumpboxes. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **AC-6** | NIST SP 800-53 | Rev. 5 | Least Privilege | Evaluates service accounts possessing interactive logon rights to user workstations. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **CM-8** | NIST SP 800-53 | Rev. 5 | Information System Component Inventory | Assesses topology completeness and unindexed network nodes. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **AU-2** | NIST SP 800-53 | Rev. 5 | Event Logging | Verifies audit logging for path transitions and administrative actions. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **IR-4** | NIST SP 800-53 | Rev. 5 | Incident Handling | Coordinates containment simulation actions with incident response workflows. | [NIST SP 800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5) |
| **CIS-3.3** | CIS Controls | v8.1 | Configure Network Access Control Lists | Evaluates ACL boundaries between workstation subnets and database enclaves. | [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) |
| **CIS-5.1** | CIS Controls | v8.1 | Establish Inventory of Accounts | Identifies active directory accounts and flags service accounts on workstations. | [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) |
| **CIS-7.1** | CIS Controls | v8.1 | Establish Vulnerability Management | Evaluates unmitigated CVEs on lateral movement attack routes. | [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) |
| **CIS-8.2** | CIS Controls | v8.1 | Collect Audit Logs | Enforces log collection requirements across critical network hops. | [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) |
| **CIS-17.1** | CIS Controls | v8.1 | Incident Management Process | Enforces immediate endpoint quarantine upon detecting malicious C2 indicators. | [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) |
| **T1078** | MITRE ATT&CK | v14.1 | Valid Accounts | Assesses adversary use of stolen credentials to traverse between network tiers. | [MITRE T1078](https://attack.mitre.org/techniques/T1078/) |
| **T1021** | MITRE ATT&CK | v14.1 | Remote Services | Identifies lateral movement hops utilizing SMB, RDP, or SSH across trust boundaries. | [MITRE T1021](https://attack.mitre.org/techniques/T1021/) |
| **T1190** | MITRE ATT&CK | v14.1 | Exploit Public-Facing Application | Analyzes initial compromise vectors targeting edge servers and gateways. | [MITRE T1190](https://attack.mitre.org/techniques/T1190/) |
| **T1562** | MITRE ATT&CK | v14.1 | Impair Defenses | Flags lateral movement sequences lacking SIEM / Sysmon logging telemetry. | [MITRE T1562](https://attack.mitre.org/techniques/T1562/) |
| **T1566** | MITRE ATT&CK | v14.1 | Phishing | Connects initial email ingress IOCs to corporate recipient identities. | [MITRE T1566](https://attack.mitre.org/techniques/T1566/) |
| **A.5.15** | ISO/IEC 27001 | 2022 | Access Control | Enforces access tiering rules to prevent direct workstation-to-database bypass. | [ISO/IEC 27001](https://www.iso.org/standard/27001) |
| **A.8.8** | ISO/IEC 27001 | 2022 | Management of Technical Vulnerabilities | Identifies critical CVE exploit preconditions on attack paths to Crown Jewels. | [ISO/IEC 27001](https://www.iso.org/standard/27001) |
| **A.8.20** | ISO/IEC 27001 | 2022 | Network Security | Validates segmentation barriers isolating sensitive databases and directory tiers. | [ISO/IEC 27001](https://www.iso.org/standard/27001) |

---

## 4. Organization Security Policies

| Policy ID | Policy Name | Severity | Scope | Linked Standards | Rule Conditions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **POL-IAM-01** | Zero Direct Workstation Access to Crown Jewels | CRITICAL | ENTERPRISE | PR.AA-05, AC-3, CIS-3.3, T1021, A.5.15 | Direct workstation-to-database access prohibited without traversing jumpbox. |
| **POL-IAM-02** | Service Account Interactive Logon Prevention | HIGH | WORKSTATIONS | PR.AA-01, AC-6, CIS-5.1, T1078, A.5.15 | Non-human service credentials prohibited from interactive workstation login. |
| **POL-EXPOSURE-01** | Crown Jewel Blast Radius Isolation Boundary | HIGH | PRODUCTION | PR.IR-01, AC-3, CIS-3.3, A.8.20 | Compromised entity blast radius must not reach >0 Crown Jewels or exceed 20% exposure. |
| **POL-VULN-01** | Critical Exploit Precondition Remediation | HIGH | ENTERPRISE | PR.IP-01, CM-8, CIS-7.1, T1190, A.8.8 | Lateral paths must not contain unmitigated CVEs with CVSS >= 8.0. |
| **POL-LOG-01** | Comprehensive Log Audit & Traversal Telemetry | MEDIUM | ENTERPRISE | DE.CM-01, AU-2, CIS-8.2, T1562 | Observed paths must be backed by verified network connection telemetry. |
| **POL-INC-01** | Attacker Infrastructure & Phishing Quarantine | CRITICAL | ENTERPRISE | RS.AN-01, IR-4, CIS-17.1, T1566 | Malicious C2 indicators linked to internal users must trigger immediate isolation. |

---

## 5. Cryptographic Audit Ledger & Remediation Lifecycle

Sensitive policy mutations and remediation status transitions are recorded in a thread-safe, cryptographically chained audit log:

$$\text{Hash}_n = \text{SHA-256}\left(\text{audit\_id} \parallel \text{event\_type} \parallel \text{actor\_id} \parallel \text{target} \parallel \text{action} \parallel \text{details} \parallel \text{timestamp} \parallel \text{Hash}_{n-1}\right)$$

Genesis block uses $64\times\text{"0"}$. The `/api/v1/governance/audit/verify` endpoint verifies chain integrity on demand, immediately detecting unauthorized tampering or record insertion.
