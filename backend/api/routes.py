"""
ThreatLens - API Endpoints
Enterprise Email Threat Investigation, Forensics, IOC Extraction, Threat Intelligence & Attack Graph
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query

from backend.models.threat import EmailAnalysisInput, ThreatDetectionResult
from backend.models.explanation import ExplainableThreatResult
from backend.models.forensics import ForensicEvidenceResult, RawEmlInput
from backend.models.ioc import IocExtractionResult, IocExtractionInput
from backend.models.intel import ThreatIntelligenceResult, ThreatIntelligenceInput
from backend.models.graph import (
    AttackGraph,
    CampaignCluster,
    CampaignCorrelationResult,
    CaseRecord,
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseNoteRequest,
    TimelineEventRecord,
    AlertItem
)

from backend.services.threat_detection import detect_threat
from backend.services.explainable_ai import generate_explanation
from backend.services.email_forensics import default_forensics_service, analyze_email_forensics
from backend.services.ioc_extractor import default_ioc_service, extract_iocs
from backend.services.threat_intelligence import default_intel_service, enrich_iocs_with_threat_intel
from backend.services.attack_graph import default_graph_builder
from backend.services.campaign_correlation import default_correlation_engine
from backend.services.case_store import default_case_repo
from backend.core.security import verify_admin_access, get_actor_identity

from backend.data.demo_emails import DEMO_EMAILS
from backend.data.eml_samples import EML_SAMPLES
from backend.core.config import MAX_UPLOAD_SIZE_BYTES, ALLOWED_UPLOAD_EXTENSIONS

router = APIRouter()


# ==========================================================
# THREAT DETECTION
# ==========================================================

@router.post(
    "/analyze/threat",
    response_model=ThreatDetectionResult,
    summary="Analyze email payload for cyber threats",
    description="Processes structured email metadata and content to compute threat score, risk level, and primary/secondary threat categories."
)
async def analyze_threat_endpoint(email_data: EmailAnalysisInput) -> ThreatDetectionResult:
    """Dedicated endpoint for Threat Detection."""
    try:
        return detect_threat(email_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat detection failed: {str(e)}")


# ==========================================================
# EXPLAINABLE AI
# ==========================================================

@router.post(
    "/analyze/explain",
    response_model=ExplainableThreatResult,
    summary="Explain threat analysis with evidence and risk factor ranking",
    description="Evaluates email threat score and produces human-readable explanations, evidence mappings, contribution ranking, and natural language assessment."
)
async def explain_threat_endpoint(email_data: EmailAnalysisInput) -> ExplainableThreatResult:
    """Dedicated endpoint for Explainable AI."""
    try:
        threat_result = detect_threat(email_data)
        explanation = generate_explanation(threat_result, email_data)
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation generation failed: {str(e)}")


@router.post(
    "/analyze",
    response_model=ExplainableThreatResult,
    summary="Unified email threat analysis & explanation endpoint",
    description="Standard analysis entry point executing both Threat Detection and Explainable AI."
)
async def unified_analyze_endpoint(email_data: EmailAnalysisInput) -> ExplainableThreatResult:
    """Unified email analysis endpoint returning threat assessment with evidence explanations."""
    return await explain_threat_endpoint(email_data)


# ==========================================================
# EMAIL FORENSICS
# ==========================================================

@router.post(
    "/analyze/forensics",
    response_model=ForensicEvidenceResult,
    summary="Deep forensic analysis of raw RFC 822 .eml string",
    description="Extracts headers, reconstructs SMTP Received relay path, verifies SPF/DKIM/DMARC evidence, computes attachment SHA-256 hashes, and records anomalies."
)
async def analyze_forensics_endpoint(payload: RawEmlInput) -> ForensicEvidenceResult:
    """Accepts raw .eml string and returns comprehensive forensic analysis."""
    try:
        return analyze_email_forensics(payload.raw_eml)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic analysis failed: {str(e)}")


@router.post(
    "/analyze/forensics/upload",
    response_model=ForensicEvidenceResult,
    summary="Upload raw .eml file for forensic investigation",
    description="Accepts a raw .eml file upload and performs in-memory RFC 822 forensic parsing."
)
async def upload_forensics_endpoint(file: UploadFile = File(...)) -> ForensicEvidenceResult:
    """Handles raw .eml file upload with size boundaries and extension validation."""
    if not file.filename or not any(file.filename.lower().endswith(ext) for ext in ALLOWED_UPLOAD_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file format: upload must have an allowed extension ({', '.join(ALLOWED_UPLOAD_EXTENSIONS)})."
        )

    try:
        content_bytes = await file.read()
        if len(content_bytes) > MAX_UPLOAD_SIZE_BYTES:
            max_mb = MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"Payload Too Large: email upload exceeds maximum limit of {max_mb} MB."
            )
        if len(content_bytes) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        return analyze_email_forensics(content_bytes)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload forensic analysis failed: {str(e)}")


# ==========================================================
# IOC EXTRACTION
# ==========================================================

@router.post(
    "/analyze/iocs",
    response_model=IocExtractionResult,
    summary="Extract and normalize Indicators of Compromise",
    description="Extracts URLs, domains, IPv4/IPv6 addresses, emails, cryptographic hashes, and hostnames with source provenance and scope classification."
)
async def analyze_iocs_endpoint(payload: IocExtractionInput) -> IocExtractionResult:
    """Dedicated endpoint for IOC Extraction."""
    try:
        forensics = analyze_email_forensics(payload.raw_eml)
        return default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC extraction failed: {str(e)}")


# ==========================================================
# THREAT INTELLIGENCE
# ==========================================================

@router.post(
    "/analyze/intelligence",
    response_model=ThreatIntelligenceResult,
    summary="Enrich IOCs with VirusTotal and AbuseIPDB threat intelligence",
    description="Asynchronously queries external threat intelligence providers, applies caching and private IP protections, and normalizes reputation findings."
)
async def analyze_intelligence_endpoint(payload: ThreatIntelligenceInput) -> ThreatIntelligenceResult:
    """Dedicated endpoint for Threat Intelligence."""
    try:
        if payload.raw_eml:
            forensics = analyze_email_forensics(payload.raw_eml)
            iocs = default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)
        elif payload.indicators:
            from backend.models.ioc import IpIoc, DomainIoc, UrlIoc, HashIoc
            iocs = IocExtractionResult()
            for ind in payload.indicators:
                if ind.startswith("http://") or ind.startswith("https://"):
                    iocs.urls.append(UrlIoc(value=ind, normalized=ind))
                elif "@" in ind:
                    iocs.emails.append(ind)
                elif any(c in ind for c in [":", "."]) and ind.replace(".", "").isdigit():
                    iocs.ips.append(IpIoc(value=ind, scope="public"))
                elif len(ind) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in ind):
                    iocs.hashes.append(HashIoc(value=ind, algorithm="SHA256" if len(ind)==64 else ("SHA1" if len(ind)==40 else "MD5")))
                else:
                    iocs.domains.append(DomainIoc(value=ind))
        else:
            raise HTTPException(status_code=400, detail="Must provide either 'raw_eml' or 'indicators'")

        return await default_intel_service.enrich_iocs(iocs)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intelligence query failed: {str(e)}")


# ==========================================================
# MODULE 1: INVESTIGATE ALERTS & INCIDENTS (SUBMODULES 1-5)
# ==========================================================

@router.get(
    "/alerts",
    summary="Correlated Security Alerts Stream",
    description="Returns merged stream of indexed case alerts, graph security findings, and endpoint telemetry alerts."
)
async def get_alerts_endpoint(
    severity: Optional[str] = Query(None, description="Filter by severity: ALL, CRITICAL, HIGH, MEDIUM, LOW"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type: ALL, case_alert, graph_finding, telemetry_alert"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN, INVESTIGATING, CLOSED"),
    search: Optional[str] = Query(None, description="Search term in alert title, entity, or source"),
    limit: int = Query(100, ge=1, le=500)
) -> Dict[str, Any]:
    """Retrieves normalized alerts stream with separate categorization of cases, graph findings, and telemetry."""
    from backend.graphops.kafka_worker import get_kafka_worker

    all_alerts: List[Dict[str, Any]] = []

    # 1. Case Alerts (indexed incident cases)
    cases = default_case_repo.list_cases()
    for case in cases:
        sev = (case.severity or case.risk_level or "MEDIUM").upper()
        if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev = "CRITICAL" if case.threat_score >= 80 else ("HIGH" if case.threat_score >= 50 else "MEDIUM")

        all_alerts.append({
            "alert_id": f"ALRT-{case.case_id}",
            "alert_type": "case_alert",
            "timestamp": case.timestamp,
            "severity": sev,
            "detector_source": "EMAIL_SECURITY_GATEWAY",
            "affected_entity": case.recipient or case.sender or "victim@corporation.com",
            "title": case.subject,
            "classification": case.primary_threat,
            "status": case.status or "OPEN",
            "case_id": case.case_id,
            "threat_score": case.threat_score,
            "is_sample": getattr(case, "is_sample", False),
            "details": {
                "sender": case.sender,
                "recipient": case.recipient,
                "assigned_to": case.assigned_to,
                "notes_count": len(case.notes) if case.notes else 0
            }
        })

    # 2. Graph Security Findings (from Kafka worker or seeded baseline)
    graph_alerts: List[Dict[str, Any]] = []
    try:
        worker = get_kafka_worker()
        raw_findings = worker.processor.get_findings(limit=50)
    except Exception:
        raw_findings = []

    if raw_findings:
        for f in raw_findings:
            f_dict = f.model_dump() if hasattr(f, "model_dump") else f
            graph_alerts.append({
                "alert_id": f_dict.get("finding_id"),
                "alert_type": "graph_finding",
                "timestamp": f_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "severity": str(f_dict.get("severity", "HIGH")).upper(),
                "detector_source": f_dict.get("analysis_type", "GRAPH_ANOMALY"),
                "affected_entity": f_dict.get("affected_entity_id", "Graph Entity"),
                "title": f_dict.get("title", "Graph Anomaly Finding"),
                "classification": "GRAPH_ANOMALY",
                "status": "OPEN",
                "case_id": f_dict.get("details", {}).get("case_id", "MT-101"),
                "finding_id": f_dict.get("finding_id"),
                "details": f_dict
            })
    else:
        # Seeded realistic baseline graph findings
        seeded_graph_findings = [
            {
                "finding_id": "FND-BFS-8821",
                "source_event_id": "EVT-KAFKA-101",
                "analysis_type": "BFS_BLAST_RADIUS",
                "affected_entity_id": "device:dev-ws-101",
                "critical_asset_impacted": "CRIT-DB-01",
                "severity": "HIGH",
                "title": "Lateral Movement Exposure to Crown Jewel CRIT-DB-01",
                "summary": "Compromised workstation dev-ws-101 has 3-hop shortest blast path to Customer Core PII Database.",
                "evidence_class": "OBSERVED",
                "timestamp": "2026-10-23T11:30:00Z",
                "related_case_id": "MT-101"
            },
            {
                "finding_id": "FND-CHOKE-8822",
                "source_event_id": "EVT-KAFKA-102",
                "analysis_type": "CHOKE_POINT",
                "affected_entity_id": "server:srv-app-01",
                "critical_asset_impacted": "CRIT-DB-01",
                "severity": "CRITICAL",
                "title": "Critical Choke Point Exposure on Gateway Server",
                "summary": "Application gateway server:srv-app-01 controls 75% of lateral traversals to database tier.",
                "evidence_class": "OBSERVED",
                "timestamp": "2026-10-23T11:35:00Z",
                "related_case_id": "MT-101"
            },
            {
                "finding_id": "FND-PATH-8823",
                "source_event_id": "EVT-KAFKA-103",
                "analysis_type": "DIJKSTRA_SHORTEST_PATH",
                "affected_entity_id": "user:usr-101",
                "critical_asset_impacted": "CRIT-DC-01",
                "severity": "HIGH",
                "title": "Privilege Escalation Path to Domain Controller",
                "summary": "Credential harvesting on user:usr-101 provides shortest cost path to Active Directory root.",
                "evidence_class": "OBSERVED",
                "timestamp": "2026-10-23T11:40:00Z",
                "related_case_id": "MT-103"
            }
        ]
        for sf in seeded_graph_findings:
            graph_alerts.append({
                "alert_id": sf["finding_id"],
                "alert_type": "graph_finding",
                "timestamp": sf["timestamp"],
                "severity": sf["severity"],
                "detector_source": sf["analysis_type"],
                "affected_entity": sf["affected_entity_id"],
                "title": sf["title"],
                "classification": "GRAPH_ANOMALY",
                "status": "OPEN",
                "case_id": sf.get("related_case_id", "MT-101"),
                "finding_id": sf["finding_id"],
                "is_sample": sf.get("is_sample", True),
                "details": sf
            })
    all_alerts.extend(graph_alerts)

    # 3. Telemetry Alerts (Module 0 collector events)
    try:
        from backend.collector.registry import list_collectors
        collectors = list_collectors()
        for d in collectors:
            if d.get("status") == "REVOKED":
                all_alerts.append({
                    "alert_id": f"ALRT-TEL-{d.get('collector_id', 'unknown')[:8]}",
                    "alert_type": "telemetry_alert",
                    "timestamp": d.get("last_seen") or datetime.now(timezone.utc).isoformat(),
                    "severity": "HIGH",
                    "detector_source": "COLLECTOR_REGISTRY",
                    "affected_entity": f"{d.get('hostname')} ({d.get('collector_id', '')[:8]})",
                    "title": f"Revoked Collector Activity Attempt from {d.get('hostname')}",
                    "classification": "ENDPOINT_AUTH_REVOKED",
                    "status": "CONTAINED",
                    "is_sample": False,
                    "details": d
                })
    except Exception:
        pass

    # Sort descending by timestamp
    all_alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    # Filtering
    filtered = all_alerts
    if severity and severity.upper() != "ALL":
        filtered = [a for a in filtered if a.get("severity", "").upper() == severity.upper()]
    if alert_type and alert_type.lower() != "all":
        filtered = [a for a in filtered if a.get("alert_type", "").lower() == alert_type.lower()]
    if status and status.upper() != "ALL":
        filtered = [a for a in filtered if a.get("status", "").upper() == status.upper()]
    if search:
        q = search.lower().strip()
        filtered = [
            a for a in filtered
            if q in a.get("title", "").lower()
            or q in a.get("affected_entity", "").lower()
            or q in a.get("alert_id", "").lower()
            or q in a.get("classification", "").lower()
            or (a.get("case_id") and q in a.get("case_id", "").lower())
        ]

    return {
        "total_alerts": len(filtered),
        "case_alerts_count": len([a for a in filtered if a.get("alert_type") == "case_alert"]),
        "graph_findings_count": len([a for a in filtered if a.get("alert_type") == "graph_finding"]),
        "telemetry_alerts_count": len([a for a in filtered if a.get("alert_type") == "telemetry_alert"]),
        "alerts": filtered[:limit]
    }


@router.get(
    "/cases",
    response_model=List[CaseRecord],
    summary="List all indexed investigation cases",
    description="Returns stored email investigation cases with filtering by status, severity, primary threat, or search query."
)
async def list_cases_endpoint(
    status: Optional[str] = Query(None, description="Filter by status e.g. OPEN, INVESTIGATING, CLOSED"),
    severity: Optional[str] = Query(None, description="Filter by risk level or severity e.g. CRITICAL, HIGH, LOW"),
    primary_threat: Optional[str] = Query(None, description="Filter by threat category e.g. PHISHING, BEC"),
    search: Optional[str] = Query(None, description="Search keyword across case_id, subject, sender, recipient")
) -> List[CaseRecord]:
    """Retrieves all indexed cases in repository with optional filtering."""
    cases = default_case_repo.list_cases()
    if status and status.upper() != "ALL":
        cases = [c for c in cases if (c.status or "OPEN").upper() == status.upper()]
    if severity and severity.upper() != "ALL":
        cases = [c for c in cases if (c.severity or c.risk_level or "").upper() == severity.upper()]
    if primary_threat and primary_threat.upper() != "ALL":
        cases = [c for c in cases if (c.primary_threat or "").upper() == primary_threat.upper()]
    if search:
        q = search.lower().strip()
        cases = [
            c for c in cases
            if q in c.case_id.lower()
            or q in c.subject.lower()
            or q in c.sender.lower()
            or (c.recipient and q in c.recipient.lower())
            or q in c.primary_threat.lower()
        ]
    return cases


@router.post(
    "/cases",
    response_model=CaseRecord,
    status_code=201,
    summary="Create an investigation case",
    description="Manually registers or escalates a new security incident case."
)
async def create_case_endpoint(
    payload: CaseCreateRequest,
    actor: str = Depends(verify_admin_access)
) -> CaseRecord:
    """Creates a new incident case and indexes it in the centralized case repository."""
    case_id = payload.case_id or f"MT-{uuid.uuid4().hex[:6].upper()}"
    existing = default_case_repo.get_case(case_id)
    if existing:
        raise HTTPException(status_code=400, detail=f"Case with ID '{case_id}' already exists.")

    now_iso = datetime.now(timezone.utc).isoformat()
    record = CaseRecord(
        case_id=case_id,
        subject=payload.subject,
        sender=payload.sender,
        recipient=payload.recipient,
        threat_score=payload.threat_score,
        risk_level=payload.risk_level,
        primary_threat=payload.primary_threat,
        status=payload.status or "OPEN",
        assigned_to=payload.assigned_to,
        is_sample=payload.is_sample or False,
        iocs=payload.iocs or {},
        intel_summary=payload.intel_summary or {},
        forensics_summary=payload.forensics_summary or {},
        evidence_references=payload.evidence_references or [],
        notes=payload.notes or [],
        timeline=payload.timeline or [
            {
                "event_id": f"EVT-{uuid.uuid4().hex[:6].upper()}",
                "original_event_time": now_iso,
                "ingested_at": now_iso,
                "source": "MANUAL_CREATION",
                "event_type": "CASE_CREATED",
                "title": f"Incident Case {case_id} Created",
                "description": f"Analyst created case: {payload.subject}",
                "severity": payload.risk_level,
                "evidence_ref": f"CASE-{case_id}",
                "details": {"created_by": payload.assigned_to or actor or "analyst"}
            }
        ],
        timestamp=now_iso
    )
    default_case_repo.save_case(record)
    return record


@router.get(
    "/cases/{case_id}",
    summary="Retrieve complete case investigation dossier",
    description="Returns detailed case metadata, risk rating, explanation, IOCs, forensics, intel, notes, evidence references, and related findings."
)
async def get_case_endpoint(case_id: str) -> Dict[str, Any]:
    """Retrieves full case investigation workspace details."""
    case = default_case_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    case_dict = case.model_dump()

    # Query related graph findings
    from backend.graphops.kafka_worker import get_kafka_worker
    related_findings: List[Dict[str, Any]] = []
    try:
        worker = get_kafka_worker()
        raw_f = worker.processor.get_findings(limit=50)
        for f in raw_f:
            f_dump = f.model_dump() if hasattr(f, "model_dump") else f
            if f_dump.get("details", {}).get("case_id") == case_id or f_dump.get("source_event_id") == case_id:
                related_findings.append(f_dump)
    except Exception:
        pass

    # Provide explanation if not present
    explanation = None
    try:
        threat_detection = ThreatDetectionResult(
            threat_score=case.threat_score,
            risk_level=case.risk_level,
            primary_threat=case.primary_threat
        )
        fake_email = EmailAnalysisInput(
            sender=case.sender,
            recipient=case.recipient or "victim@corporation.com",
            subject=case.subject,
            body="Suspicious inbound email subject to investigation."
        )
        explanation = generate_explanation(threat_detection, fake_email).model_dump()
    except Exception:
        pass

    case_dict["explanation"] = explanation
    case_dict["related_graph_findings"] = related_findings
    case_dict["graphops_bridge_url"] = f"/api/v1/graphops/bridge/case/{case_id}"
    case_dict["narrative_url"] = f"/api/v1/graphops/incident-narrative/{case_id}"
    case_dict["investigation_report_url"] = f"/api/v1/governance/reports/investigation/{case_id}"
    return case_dict


@router.patch(
    "/cases/{case_id}",
    response_model=CaseRecord,
    summary="Update case status, assignment, severity, or attributes",
    description="Updates case triage status (OPEN, INVESTIGATING, CONTAINED, CLOSED), assigned analyst, or severity."
)
async def update_case_endpoint(
    case_id: str,
    payload: CaseUpdateRequest,
    actor: str = Depends(verify_admin_access)
) -> CaseRecord:
    """Applies patch updates to an existing case."""
    updates = payload.model_dump(exclude_unset=True)
    updated = default_case_repo.update_case(case_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")
    return updated


@router.post(
    "/cases/{case_id}/notes",
    summary="Add an analyst note to a case",
    description="Persists an analyst note with author and ISO timestamp into the case record."
)
async def add_case_note_endpoint(
    case_id: str,
    payload: CaseNoteRequest,
    actor: str = Depends(verify_admin_access)
) -> Dict[str, Any]:
    """Adds a timestamped analyst observation to the case record."""
    author = payload.author if payload.author and payload.author != "soc_analyst" else (actor if actor != "dev-user-local" else "soc_analyst")
    note = default_case_repo.add_note(case_id, author, payload.note)
    if not note:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")
    return note


@router.get(
    "/cases/{case_id}/timeline",
    summary="Retrieve genuine chronological investigation timeline",
    description="Returns genuine timestamped events with distinct original event times and platform ingestion times."
)
async def get_case_timeline_endpoint(case_id: str) -> Dict[str, Any]:
    """Retrieves strictly chronologically sorted timeline events for a case."""
    case = default_case_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    events = default_case_repo.get_case_timeline(case_id)
    return {
        "case_id": case_id,
        "total_events": len(events),
        "timeline": events
    }


@router.post(
    "/cases/{case_id}/timeline",
    summary="Append a genuine timestamped event to investigation timeline",
    description="Adds a genuine event with required original_event_time and ingested_at timestamps."
)
async def add_case_timeline_event_endpoint(
    case_id: str,
    payload: TimelineEventRecord,
    actor: str = Depends(verify_admin_access)
) -> Dict[str, Any]:
    """Appends an event to the case timeline after verifying timestamp validity."""
    case = default_case_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    try:
        created = default_case_repo.add_timeline_event(case_id, payload.model_dump())
        return created
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


class LinkFindingRequest(BaseModel):
    finding_id: str = Field(description="Unique identifier of graph finding, anomaly, or attack path")
    finding_type: str = Field(default="GRAPH_ANOMALY", description="Classification e.g. GRAPH_ANOMALY, ZERO_TRUST_VIOLATION, ATTACK_PATH, SIMULATION_FINDING")
    title: str = Field(description="Descriptive summary of the finding")
    description: str = Field(description="Detailed explanation of the security observation")
    severity: str = Field(default="HIGH", description="Severity level: CRITICAL, HIGH, MEDIUM, LOW")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured finding payload and evidence")
    author: Optional[str] = Field(default=None, description="Analyst identity linking finding")


@router.post(
    "/cases/{case_id}/findings",
    summary="Link operational graph finding or anomaly to investigation case",
    description="Associates a graph finding, anomaly, or access discrepancy to a case, updating evidence references, timeline, analyst notes, and audit ledger."
)
async def link_finding_to_case_endpoint(
    case_id: str,
    payload: LinkFindingRequest,
    actor: str = Depends(verify_admin_access),
) -> Dict[str, Any]:
    """Links a graph finding or anomaly directly to an investigation case."""
    author = payload.author or (actor if actor != "dev-user-local" else "soc_analyst@threatlens.io")
    result = default_case_repo.link_finding(
        case_id=case_id,
        finding_id=payload.finding_id,
        finding_type=payload.finding_type,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        details=payload.details,
        author=author,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    # Register in EvidenceLedgerService
    try:
        from backend.governance.evidence_ledger import EvidenceLedgerService
        EvidenceLedgerService.register_evidence(
            evidence_id=f"evi:{payload.finding_id.lower()}",
            evidence_type=payload.finding_type,
            source="GRAPHOPS_FINDING",
            payload={
                "finding_id": payload.finding_id,
                "title": payload.title,
                "description": payload.description,
                "severity": payload.severity,
                "details": payload.details,
            },
            case_id=case_id,
            finding_id=payload.finding_id,
            actor_id=author,
        )
    except Exception as exc:
        logger.debug("Evidence registration for linked finding: %s", exc)

    # Record tamper-evident audit ledger event
    try:
        from backend.governance.audit import record_audit_event
        record_audit_event(
            event_type="FINDING_LINKED_TO_CASE",
            actor_id=author,
            target_resource=f"case:{case_id}",
            action="LINK_FINDING",
            details={
                "case_id": case_id,
                "finding_id": payload.finding_id,
                "finding_type": payload.finding_type,
            },
            related_case_id=case_id,
            result="SUCCESS",
        )
    except Exception as exc:
        logger.debug("Audit record for linked finding: %s", exc)

    return result


@router.get(
    "/cases/{case_id}/narrative",
    summary="Retrieve correlated incident narrative and kill chain",
    description="Synthesizes multi-hop incident sequence with MITRE tactics and explicit analytical interpretation disclaimer."
)
async def get_case_narrative_endpoint(case_id: str) -> Dict[str, Any]:
    """Returns synthesized incident narrative for the case."""
    case = default_case_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    from backend.graphops.alert_consolidation import synthesize_incident_narrative
    narrative = synthesize_incident_narrative(case_id)
    return narrative.model_dump()



@router.get(
    "/cases/{case_id}/graph",
    response_model=AttackGraph,
    summary="Retrieve relationship attack graph for a specific case",
    description="Returns nodes and edges representing the email entities, domains, URLs, IPs, hashes, and relay paths."
)
async def get_case_graph_endpoint(case_id: str) -> AttackGraph:
    """Generates attack graph for a specific case."""
    case = default_case_repo.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    from backend.models.ioc import IocExtractionResult, DomainIoc, IpIoc, UrlIoc, HashIoc
    iocs = IocExtractionResult(
        domains=[DomainIoc(value=d) for d in case.iocs.get("domains", [])],
        ips=[IpIoc(value=ip, scope="public") for ip in case.iocs.get("ips", [])],
        urls=[UrlIoc(value=u, normalized=u) for u in case.iocs.get("urls", [])],
        hashes=[HashIoc(value=h, algorithm="SHA256") for h in case.iocs.get("hashes", [])]
    )
    threat_detection = ThreatDetectionResult(
        threat_score=case.threat_score,
        risk_level=case.risk_level,
        primary_threat=case.primary_threat
    )
    return default_graph_builder.build_attack_graph_for_case(
        case_id=case.case_id,
        forensics=None,
        iocs=iocs,
        intel=None,
        threat_detection=threat_detection
    )


@router.get(
    "/campaigns",
    response_model=List[CampaignCluster],
    summary="Retrieve all detected threat campaigns",
    description="Clusters all indexed investigation cases and returns active campaign groups sharing infrastructure."
)
async def list_campaigns_endpoint() -> List[CampaignCluster]:
    """Returns detected campaign clusters across all cases."""
    return default_correlation_engine.cluster_all_cases()


@router.get(
    "/campaigns/{campaign_id}/graph",
    response_model=AttackGraph,
    summary="Retrieve multi-case attack graph for a campaign cluster",
    description="Returns multi-node cluster graph displaying shared infrastructure across all correlated emails in a campaign."
)
async def get_campaign_graph_endpoint(campaign_id: str) -> AttackGraph:
    """Generates multi-email campaign cluster graph."""
    campaigns = default_correlation_engine.cluster_all_cases()
    camp = next((c for c in campaigns if c.campaign_id == campaign_id), None)
    if not camp:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")

    all_cases = default_case_repo.list_cases()
    return default_graph_builder.build_multi_case_campaign_graph(camp, all_cases)


@router.get(
    "/search/ioc",
    summary="Cross-investigation search for an IOC",
    description="Searches all historical cases and campaign clusters for a specific IP, domain, URL, or hash."
)
async def search_ioc_endpoint(q: str = Query(..., description="Indicator string e.g. 185.190.140.22, alert-center.xyz")):
    """Cross-investigation indicator search."""
    return default_correlation_engine.search_ioc(q)


# ==========================================================
# COMPLETE MULTI-FEATURE PIPELINE
# ==========================================================

@router.post(
    "/analyze/eml",
    summary="Complete ThreatLens analysis pipeline",
    description="Executes Forensics, IOC Extraction, Threat Intelligence, Threat Detection, Explainable AI, Attack Graph, and Campaign Correlation."
)
async def analyze_complete_eml_endpoint(payload: RawEmlInput) -> Dict[str, Any]:
    """Complete end-to-end pipeline starting from raw .eml RFC 822 input."""
    try:
        case_id = f"MT-{uuid.uuid4().hex[:6].upper()}"

        # 1. Forensics
        forensics = analyze_email_forensics(payload.raw_eml)

        # 2. IOC Extraction
        iocs = default_ioc_service.extract_from_forensics(forensics, payload.raw_eml)

        # 3. Threat Intelligence
        intel = await default_intel_service.enrich_iocs(iocs)

        # 4. Detection & Explanation
        body_content = forensics.mime_analysis.plain_text_preview or ""
        email_data = default_forensics_service.convert_forensics_to_analysis_input(forensics, body_content)
        threat_result = detect_threat(email_data)
        explanation = generate_explanation(threat_result, email_data)

        # 5. Campaign Correlation & Indexing
        recipient_addr = forensics.headers.get("To") or forensics.headers.get("to")
        if not recipient_addr and hasattr(email_data, "recipient") and email_data.recipient:
            recipient_addr = email_data.recipient
        if recipient_addr and "<" in str(recipient_addr) and ">" in str(recipient_addr):
            recipient_addr = str(recipient_addr).split("<")[1].split(">")[0].strip()
        elif recipient_addr:
            recipient_addr = str(recipient_addr).strip()

        case_record = CaseRecord(
            case_id=case_id,
            subject=forensics.subject or "Untitled Email",
            sender=forensics.sender_identity.from_address or "Unknown",
            recipient=recipient_addr,
            threat_score=threat_result.threat_score,
            risk_level=threat_result.risk_level,
            primary_threat=threat_result.primary_threat,
            iocs={
                "domains": [d.value for d in iocs.domains],
                "ips": [ip.value for ip in iocs.ips],
                "urls": [u.normalized for u in iocs.urls],
                "hashes": [h.value for h in iocs.hashes]
            },
            intel_summary={
                "malicious_count": intel.summary.malicious_count,
                "suspicious_count": intel.summary.suspicious_count,
                "clean_count": intel.summary.clean_reported_count
            },
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        campaign_result = default_correlation_engine.correlate_current_case(case_record)
        matched_camp_id = campaign_result.current_case_campaign.campaign_id if campaign_result.current_case_campaign else None

        # 6. Attack Graph Generation
        attack_graph = default_graph_builder.build_attack_graph_for_case(
            case_id=case_id,
            forensics=forensics,
            iocs=iocs,
            intel=intel,
            threat_detection=threat_result,
            campaign_id=matched_camp_id
        )

        return {
            "case_id": case_id,
            "forensics": forensics,
            "iocs": iocs,
            "threat_intelligence": intel,
            "attack_graph": attack_graph,
            "campaign_correlation": campaign_result,
            "threat_analysis": threat_result,
            "explanation": explanation,
            "graphops_bridge_url": f"/api/v1/graphops/bridge/case/{case_id}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Complete EML analysis failed: {str(e)}")


# ==========================================================
# DEMO FIXTURES & HEALTH
# ==========================================================

@router.get("/demo-emails", summary="Retrieve pre-configured demo email test cases")
async def get_demo_emails():
    return DEMO_EMAILS


@router.get("/demo-emls", summary="Retrieve raw RFC 822 .eml test fixtures")
async def get_demo_emls():
    return EML_SAMPLES


@router.get("/health", summary="System health check")
async def health_check():
    return {
        "status": "healthy",
        "service": "ThreatLens - AI Threat Detection, XAI, Forensics, IOCs, Threat Intel & Attack Graph",
        "version": "2.0.0"
    }


def get_readiness_graph_client_dep():
    from backend.graphops.client import get_graphops_client
    return get_graphops_client()


def get_readiness_producer_dep():
    from backend.graphops.kafka_producer import get_kafka_producer
    return get_kafka_producer()


def get_readiness_worker_dep():
    from backend.graphops.kafka_worker import get_kafka_worker
    return get_kafka_worker()


@router.get("/ready", summary="System readiness check")
async def readiness_check(
    allow_mock: bool = Query(True, description="Whether authorized mock/sandbox mode constitutes operational readiness"),
    client: Any = Depends(get_readiness_graph_client_dep),
    producer: Any = Depends(get_readiness_producer_dep),
    worker: Any = Depends(get_readiness_worker_dep),
):
    """
    Evaluates essential subsystem readiness:
    - Neo4j graph database connectivity
    - Apache Kafka streaming producer & consumer worker
    - Tamper-evident governance audit ledger integrity
    - Collector registry accessibility

    Readiness semantics:
    - If allow_mock=False, all dependencies must be connected to live infrastructure (no in-memory mock fallback).
    - If allow_mock=True, operational mock components are accepted, with mock_mode clearly identified.
    - If any required component is offline, uninitialized, or compromised, returns HTTP 503.
    """
    components = {}
    is_ready = True

    # 1. Neo4j GraphOps Client
    try:
        neo4j_health = client.health_check()
        is_mock_db = getattr(client, "mock_mode", False) or "in-memory" in str(neo4j_health.get("database", "")).lower()
        is_connected = neo4j_health.get("connected", False)

        components["neo4j"] = {
            "status": "online" if is_connected and not is_mock_db else ("mock" if is_mock_db else "offline"),
            "connected": is_connected,
            "mock_mode": is_mock_db,
            "database": neo4j_health.get("database"),
        }
        if not is_connected:
            if not (allow_mock and is_mock_db):
                is_ready = False
        elif is_mock_db and not allow_mock:
            is_ready = False
    except Exception as e:
        components["neo4j"] = {"status": "error", "connected": False, "error": str(e)}
        is_ready = False

    # 2. Kafka Producer
    try:
        prod_health = producer.health_check()
        components["kafka_producer"] = prod_health
        if prod_health.get("status") == "offline":
            is_ready = False
        elif prod_health.get("mock_mode") and not allow_mock:
            is_ready = False
    except Exception as e:
        components["kafka_producer"] = {"status": "error", "error": str(e)}
        is_ready = False

    # 3. Kafka Consumer Worker
    try:
        worker_status = worker.get_status()
        components["kafka_worker"] = worker_status
        if worker_status.get("mock_mode") and not allow_mock:
            is_ready = False
    except Exception as e:
        components["kafka_worker"] = {"status": "error", "error": str(e)}

    # 4. Governance Audit Ledger
    try:
        from backend.governance.audit import verify_audit_integrity
        audit_intact, audit_err = verify_audit_integrity()
        components["audit_ledger"] = {
            "status": "intact" if audit_intact else "tamper_detected",
            "intact": audit_intact,
            "error": audit_err,
        }
        if not audit_intact:
            is_ready = False
    except Exception as e:
        components["audit_ledger"] = {"status": "error", "intact": False, "error": str(e)}
        is_ready = False

    # 5. Collector Registry
    try:
        from backend.collector.registry import list_collectors
        collectors = list_collectors()
        components["collector_registry"] = {
            "status": "accessible",
            "enrolled_collectors_count": len(collectors),
        }
    except Exception as e:
        components["collector_registry"] = {"status": "error", "error": str(e)}
        is_ready = False

    response_payload = {
        "status": "ready" if is_ready else "not_ready",
        "allow_mock": allow_mock,
        "service": "ThreatLens Enterprise Event Pipeline & Detection Fabric",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }

    if not is_ready:
        raise HTTPException(
            status_code=503,
            detail=response_payload,
        )

    return response_payload


@router.get("/overview", summary="Security overview dashboard aggregation")
async def get_security_overview():
    """
    Centralized Security Overview:
    Aggregates email threat investigation metrics, remote telemetry collector fleet metrics,
    authentication failures, recent ingestion activity, and real-time Neo4j/Kafka connectivity.
    """
    from backend.collector.registry import get_collector_overview
    from backend.api.collector_routes import get_connectivity_status

    all_cases = default_case_repo.list_cases()
    campaigns = default_correlation_engine.cluster_all_cases()
    critical_count = sum(1 for c in all_cases if getattr(c, "threat_score", 0) >= 80)

    total_iocs = 0
    for c in all_cases:
        iocs = getattr(c, "iocs", None)
        if iocs:
            if isinstance(iocs, dict):
                for v in iocs.values():
                    total_iocs += len(v) if isinstance(v, list) else 1
            elif isinstance(iocs, list):
                total_iocs += len(iocs)

    collector_overview = get_collector_overview()
    connectivity = get_connectivity_status()

    return {
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "threat_investigations": {
            "total_cases": len(all_cases),
            "critical_threats": critical_count,
            "suspicious_iocs": total_iocs,
            "active_campaigns": len(campaigns),
            "recent_cases": [
                {
                    "case_id": c.case_id,
                    "subject": c.subject,
                    "threat_score": c.threat_score,
                    "primary_threat": getattr(c, "primary_threat", "Unknown"),
                    "created_at": getattr(c, "created_at", None),
                }
                for c in all_cases[:5]
            ],
        },
        "telemetry_fleet": collector_overview,
        "connectivity": connectivity,
        "neo4j_status": "MOCK_CONNECTED" if connectivity.get("neo4j", {}).get("mock_mode") else ("CONNECTED" if connectivity.get("neo4j", {}).get("connected") else "DISCONNECTED"),
        "kafka_status": "MOCK_CONNECTED" if connectivity.get("kafka", {}).get("mock_mode") else ("CONNECTED" if connectivity.get("kafka", {}).get("connected") else "DISCONNECTED"),
    }
