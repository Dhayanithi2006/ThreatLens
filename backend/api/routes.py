"""
ThreatLens - API Endpoints
Enterprise Email Threat Investigation, Forensics, IOC Extraction, Threat Intelligence & Attack Graph
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Query

from backend.models.threat import EmailAnalysisInput, ThreatDetectionResult
from backend.models.explanation import ExplainableThreatResult
from backend.models.forensics import ForensicEvidenceResult, RawEmlInput
from backend.models.ioc import IocExtractionResult, IocExtractionInput
from backend.models.intel import ThreatIntelligenceResult, ThreatIntelligenceInput
from backend.models.graph import AttackGraph, CampaignCluster, CampaignCorrelationResult, CaseRecord

from backend.services.threat_detection import detect_threat
from backend.services.explainable_ai import generate_explanation
from backend.services.email_forensics import default_forensics_service, analyze_email_forensics
from backend.services.ioc_extractor import default_ioc_service, extract_iocs
from backend.services.threat_intelligence import default_intel_service, enrich_iocs_with_threat_intel
from backend.services.attack_graph import default_graph_builder
from backend.services.campaign_correlation import default_correlation_engine
from backend.services.case_store import default_case_repo

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
# ATTACK GRAPH & CAMPAIGN CORRELATION
# ==========================================================

@router.get(
    "/cases",
    response_model=List[CaseRecord],
    summary="List all indexed investigation cases",
    description="Returns all stored email investigation cases with threat scores and extracted IOC summaries."
)
async def list_cases_endpoint() -> List[CaseRecord]:
    """Retrieves all indexed cases in repository."""
    return default_case_repo.list_cases()


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
