# ThreatLens Windows Collector — Enterprise Installation & Deployment Guide

> **Version:** 1.1.0 — Enterprise Grade Remote Windows Security Event Collection  
> **Compatible with:** ThreatLens API v2.0.0+ | Python 3.8+ | Windows 10/11 & Server 2016-2025

---

## 1. Architectural Overview

The ThreatLens Windows Collector forwards selected high-fidelity Windows Security Event Logs to the authenticated ThreatLens HTTPS Ingestion API. Events are normalized into `SecurityEventEnvelope`, published to Apache Kafka, consumed by GraphOps worker, and linked into the Neo4j Knowledge Graph with `OBSERVED` relationships.

```
Windows Endpoint A ──┐
                     ├──► HTTPS / TLS ──► Ingestion API ──► Kafka ──► Worker ──► Neo4j ──► GraphOps ──► Dashboard
Windows Endpoint B ──┘
```

### Core Security & Resilience Capabilities
- **Fail-Closed TLS:** Enforces valid TLS certificate verification by default (`--insecure-dev-only` strictly required for testing).
- **DPAPI Credential Protection:** Protects collector tokens using Windows Data Protection API (`CryptProtectData`).
- **Resilient Local Disk Spooling:** When disconnected, events queue in `C:\ThreatLensCollector\spool` (max 20MB / 10,000 events) and drain automatically upon reconnection.
- **Log Clear / Rollover Detection:** Detects event log clears or ID rollovers and resets checkpoint safely.
- **Client-Side Sensitive Data Redaction:** Automatically sanitizes passwords/tokens from Event 4688 command lines.
- **Anti-Spoofing Verification:** Backend validates incoming records against the authenticated collector hostname.

---

## 2. Windows Audit Policy Requirements

By default, Windows does not log detailed process command lines or network filtering events. Run `scripts\enable_audit_policies.bat` as Administrator, or configure via Group Policy (GPO):

| Event ID | Description | Advanced Audit Policy Subcategory | Required Audit Setting |
|:---|:---|:---|:---|
| **4624** | Successful Logon | *Logon/Logoff* &rarr; **Logon** | Success |
| **4625** | Failed Logon | *Logon/Logoff* &rarr; **Logon** | Failure |
| **4648** | Explicit Credential Logon (RunAs) | *Logon/Logoff* &rarr; **Other Logon/Logoff Events** | Success |
| **4672** | Special Privileges Logon | *Logon/Logoff* &rarr; **Special Logon** | Success |
| **4688** | Process Creation | *Detailed Tracking* &rarr; **Process Creation** | Success |
| **4698** | Scheduled Task Created | *Object Access* &rarr; **Other Object Access Events** | Success |
| **4720** | User Account Created | *Account Management* &rarr; **User Account Management** | Success + Failure |
| **5140** | Network Share Object Accessed | *Object Access* &rarr; **File Share** | Success + Failure |
| **5156** | WFP Connection Permitted | *Policy Change* &rarr; **Filtering Platform Connection** | Success |
| **5157** | WFP Connection Blocked | *Policy Change* &rarr; **Filtering Platform Connection** | Failure |

### Enabling Process Command Line Auditing (Event 4688)
To capture arguments (e.g. `powershell.exe -enc ...`), enable the registry key:
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Automated Policy Scripts
- **Enable all policies:** Run `scripts\enable_audit_policies.bat` as Administrator.
- **Revert to default:** Run `scripts\revert_audit_policies.bat` as Administrator.

### Event Log Sizing & Circular Rollover
To prevent event log truncation under high activity, expand the Security event log buffer to 512 MB:
```cmd
wevtutil sl Security /ms:536870912 /ab:true
```

---

## 3. Server-Side Enrolment

Enrol endpoints before deploying the agent.

### Option A: Via ThreatLens Security Dashboard (Overview)
1. Open the ThreatLens dashboard in your browser (`http://localhost:8000` or `https://threatlens.example.com`).
2. On the **Overview** dashboard, navigate to the **Remote Endpoint Telemetry & Log Collection** card.
3. Click **+ Connect Computer**.
4. Enter the computer hostname (e.g. `DESKTOP-SEC01`).
5. Click **Generate Credentials & Enrol**.
6. Copy the displayed one-time token and click **Download config.json**.

### Option B: Via Admin API
```bash
curl -X POST https://threatlens.example.com/api/v1/collector/enrol \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_ADMIN_API_KEY" \
  -d '{
    "hostname": "DESKTOP-SEC01",
    "ip_address": "192.168.1.105",
    "os_version": "Windows 11 Enterprise"
  }'
```

---

## 4. Agent Installation on Windows Endpoint

### 4.1 Deploy Agent Files
1. Create `C:\ThreatLensCollector\` (or run `scripts\install.bat` as Administrator).
2. Place `threatlens_collector.py` and `config.json` in `C:\ThreatLensCollector\`.

### 4.2 Encrypt Credential with Windows DPAPI
Encrypt the plaintext token using Windows DPAPI:
```cmd
python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json --protect-token
```
*Output:*
```
[SUCCESS] Collector token successfully encrypted with DPAPI in C:\ThreatLensCollector\config.json
```
The config file token is converted to `"token": "dpapi:AQAAANCMnd8BFdERjHo..."`. Only processes running under the same Windows account can decrypt it.

### 4.3 Test Single Batch Execution
```cmd
python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json --run-once
```

### 4.4 Install as a Scheduled Task (Continuous Service)
Register a scheduled task running at system boot or on schedule:
```cmd
schtasks /create /tn "ThreatLensCollector" /tr "python C:\ThreatLensCollector\threatlens_collector.py --config C:\ThreatLensCollector\config.json" /sc onstart /ru "SYSTEM" /rl highest /f
```

---

## 5. Reverse Proxy & Production HTTPS Termination

Do not expose raw FastAPI or Kafka ports to remote endpoints. Deploy Caddy or NGINX on the ThreatLens host.

### Using Caddy (Recommended)
Place `deploy/Caddyfile` on the host:
```caddy
:443 {
    tls internal
    request_body {
        max_size 4MB
    }
    reverse_proxy 127.0.0.1:8000
}
```
Run `caddy run --config deploy/Caddyfile`.

### Using NGINX
Use `deploy/nginx.conf` configured with `client_max_body_size 4M;` and `limit_req_zone` rate limiting.

---

## 6. Verification and Troubleshooting

| Diagnostic Goal | Command / Action | Expected Result |
|:---|:---|:---|
| **Check enrolled status** | Dashboard &rarr; Endpoint Telemetry | Badge reads `ENROLLED (PENDING)` |
| **Verify first event delivery** | Run collector with `--run-once` | Badge transitions to `ACTIVELY SENDING` |
| **Check Kafka delivery** | Server logs (`backend/collector/normalizer.py`) | Message published to `threatlens.events` |
| **Check Neo4j persistence** | Neo4j browser: `MATCH (d:Device) RETURN d` | Device node exists with matching hostname |
| **Test Offline Spooling** | Stop server, run collector cycle | Batch saved to `C:\ThreatLensCollector\spool` |
| **Test Spool Drain** | Start server, run collector cycle | Spool drained and file deleted |

### Uninstallation
To completely remove the agent:
1. Run `scripts\uninstall.bat` as Administrator.
2. Run `scripts\revert_audit_policies.bat` to restore audit policies.
3. In ThreatLens dashboard, click **Revoke** on the collector card.
