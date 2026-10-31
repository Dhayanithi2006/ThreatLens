"""
ThreatLens Governance & Controls - API Endpoints
Provides authoritative controls catalog querying, organizational policy lifecycle management,
evidence-backed policy evaluations, remediation tracking, and tamper-evident audit ledger inspection.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from backend.core.security import get_actor_identity, verify_admin_access
from backend.governance.catalog import (
    find_controls_by_applicability,
    find_controls_by_framework,
    get_control,
    get_control_catalog,
)
from backend.governance.evaluator import (
    evaluate_all_active_policies,
    evaluate_policy,
)
from backend.governance.policies import (
    delete_policy,
    get_policy,
    list_policies,
    save_policy,
)
from backend.governance.reports import (
    EvidenceLedgerItem,
    GovernanceReport,
    GovernanceReportService,
)
from backend.governance.schema import (
    AuditRecord,
    ControlRecord,
    OrganizationPolicy,
    PolicyEvaluation,
    RemediationPriority,
    RemediationRecord,
    RemediationStatus,
)
from backend.governance.audit import (
    create_remediation,
    get_remediation,
    list_audit_records,
    list_remediations,
    record_audit_event,
    update_remediation_status,
    verify_audit_integrity,
)

router = APIRouter(prefix="/api/v1/governance", tags=["governance"])


# =============================================================================
# Request / Response Schemas
# =============================================================================

class EvaluateRequest(BaseModel):
    policy_id: Optional[str] = Field(
        default=None,
        description="Optional single policy identifier to evaluate. If omitted, all active policies are evaluated.",
    )
    finding_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Finding evidence payload: blast radius, attack paths, anomalies, or IOC records.",
    )
    scope: Optional[str] = Field(
        default=None,
        description="Optional policy scope filter e.g. ENTERPRISE, PRODUCTION, WORKSTATIONS.",
    )


class CreateRemediationRequest(BaseModel):
    finding_reference: str = Field(description="Reference ID of generating finding, path ID, or evaluation ID")
    recommended_action: str = Field(description="Actionable mitigation or containment instruction")
    priority: RemediationPriority = Field(default=RemediationPriority.P2_HIGH, description="Remediation urgency")
    owner: Optional[str] = Field(default=None, description="Assigned remediation team or analyst")


class UpdateRemediationRequest(BaseModel):
    status: RemediationStatus = Field(description="New status: OPEN, IN_PROGRESS, RESOLVED, ACCEPTED_RISK")
    resolution_evidence: Optional[str] = Field(default=None, description="Resolution notes, ticket ID, or patch proof")


class GenerateReportRequest(BaseModel):
    framework: Optional[str] = Field(
        default="ALL",
        description="Target framework: 'NIST CSF', 'CIS Controls', 'ISO/IEC 27001', or 'ALL'",
    )
    scope: Optional[str] = Field(
        default="ENTERPRISE",
        description="Operational scope e.g. ENTERPRISE, PRODUCTION, WORKSTATIONS",
    )
    start_time: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 UTC start datetime filter",
    )
    end_time: Optional[str] = Field(
        default=None,
        description="Optional ISO-8601 UTC end datetime filter",
    )


class VerifyEvidenceRequest(BaseModel):
    evidence_id: str = Field(description="Evidence record identifier e.g. case ID or audit ID")
    provided_hash: Optional[str] = Field(
        default=None,
        description="Optional SHA-256 digest to compare against the stored chain-of-custody hash",
    )


# =============================================================================
# 1. Standards Control Catalog Endpoints
# =============================================================================

@router.get("/controls", response_model=List[ControlRecord])
async def list_standard_controls(
    framework: Optional[str] = Query(None, description="Filter by framework (e.g. 'NIST CSF', 'CIS', 'ISO')"),
    applicability: Optional[str] = Query(None, description="Filter by category (e.g. 'Identity', 'Exposure')"),
):
    """
    Returns verified, authoritative standards controls mapped to GraphOps findings.
    Technical findings provide evidence for assessment; they do not constitute formal certification.
    """
    if framework:
        return find_controls_by_framework(framework)
    if applicability:
        return find_controls_by_applicability(applicability)
    return get_control_catalog()


@router.get("/controls/{control_id}", response_model=ControlRecord)
async def get_standard_control(control_id: str):
    """Retrieves a specific standard control by normalized identifier (e.g. 'PR.AA-01', 'AC-3')."""
    control = get_control(control_id)
    if not control:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control identifier '{control_id}' not found in standards catalog.",
        )
    return control


# =============================================================================
# 2. Organization Policies Endpoints
# =============================================================================

@router.get("/policies", response_model=List[OrganizationPolicy])
async def get_organization_policies(
    scope: Optional[str] = Query(None, description="Filter by policy scope (e.g. ENTERPRISE, PRODUCTION)"),
    enabled_only: bool = Query(False, description="Filter for active policies only"),
):
    """Lists organization-specific policies with rule conditions and standards mappings."""
    return list_policies(scope=scope, enabled_only=enabled_only)


@router.get("/policies/{policy_id}", response_model=OrganizationPolicy)
async def get_organization_policy(policy_id: str):
    """Retrieves an organization policy by identifier."""
    policy = get_policy(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found.",
        )
    return policy


@router.post("/policies", response_model=OrganizationPolicy)
async def create_or_update_organization_policy(
    policy: OrganizationPolicy,
    actor: str = Depends(verify_admin_access),
):
    """
    Creates or updates an organization policy. Requires administrative privileges.
    Writes tamper-evident audit ledger record.
    """
    saved = save_policy(policy)
    record_audit_event(
        event_type="POLICY_UPSERTED",
        actor_id=actor,
        target_resource=f"policy:{saved.policy_id}",
        action="UPSERT",
        details={
            "policy_id": saved.policy_id,
            "name": saved.name,
            "enabled": saved.enabled,
            "severity": saved.severity,
            "linked_controls": saved.linked_control_ids,
        },
    )
    return saved


@router.delete("/policies/{policy_id}")
async def delete_organization_policy(
    policy_id: str,
    actor: str = Depends(verify_admin_access),
):
    """
    Deletes an organization policy. Requires administrative privileges.
    Writes tamper-evident audit ledger record.
    """
    existing = get_policy(policy_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy '{policy_id}' not found.",
        )
    deleted = delete_policy(policy_id)
    if deleted:
        record_audit_event(
            event_type="POLICY_DELETED",
            actor_id=actor,
            target_resource=f"policy:{policy_id.upper()}",
            action="DELETE",
            details={"policy_id": policy_id.upper(), "name": existing.name},
        )
    return {"status": "success", "policy_id": policy_id.upper(), "deleted": deleted}


# =============================================================================
# 3. Policy Evaluation Endpoints
# =============================================================================

@router.post("/evaluate", response_model=List[PolicyEvaluation])
async def evaluate_governance_policies(payload: EvaluateRequest):
    """
    Evaluates organization policies against real finding evidence.
    CRITICAL: Absence of evidence is strictly prohibited from returning compliance (PASS).
    Returns evaluated status, evidence references, reasoning, data limitations, and recommendations.
    """
    if payload.policy_id:
        result = evaluate_policy(payload.policy_id, payload.finding_context)
        return [result]
    else:
        results = evaluate_all_active_policies(payload.finding_context, scope=payload.scope)
        return results


# =============================================================================
# 4. Remediation Records Endpoints
# =============================================================================

@router.get("/remediations", response_model=List[RemediationRecord])
async def get_remediations(
    status_filter: Optional[RemediationStatus] = Query(None, alias="status"),
    priority_filter: Optional[RemediationPriority] = Query(None, alias="priority"),
):
    """Lists remediation records with optional status and priority filtering."""
    return list_remediations(status=status_filter, priority=priority_filter)


@router.post("/remediations", response_model=RemediationRecord, status_code=status.HTTP_201_CREATED)
async def create_new_remediation(
    payload: CreateRemediationRequest,
    actor: str = Depends(get_actor_identity),
):
    """Files a new remediation record linked to a graph or policy finding."""
    return create_remediation(
        finding_reference=payload.finding_reference,
        recommended_action=payload.recommended_action,
        priority=payload.priority,
        owner=payload.owner,
        actor_id=actor,
    )


@router.get("/remediations/{remediation_id}", response_model=RemediationRecord)
async def get_remediation_item(remediation_id: str):
    """Retrieves a single remediation record by ID."""
    rec = get_remediation(remediation_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation record '{remediation_id}' not found.",
        )
    return rec


@router.patch("/remediations/{remediation_id}", response_model=RemediationRecord)
async def update_remediation_item(
    remediation_id: str,
    payload: UpdateRemediationRequest,
    actor: str = Depends(get_actor_identity),
):
    """Updates remediation state and resolution evidence with audit tracking."""
    updated = update_remediation_status(
        remediation_id=remediation_id,
        new_status=payload.status,
        resolution_evidence=payload.resolution_evidence,
        actor_id=actor,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation record '{remediation_id}' not found.",
        )
    return updated


# =============================================================================
# 5. Audit History & Integrity Endpoints
# =============================================================================

@router.get("/audit", response_model=List[AuditRecord])
async def get_audit_trail(limit: int = Query(100, ge=1, le=1000)):
    """Returns chronological audit records from the cryptographic ledger."""
    return list_audit_records(limit=limit)


@router.get("/audit/verify")
async def verify_ledger_cryptographic_integrity():
    """
    Validates SHA-256 hash chaining across all entries in the audit ledger.
    Protects audit history against unauthorized manipulation.
    """
    is_valid, error_msg = verify_audit_integrity()
    return {
        "ledger_intact": is_valid,
        "status": "VERIFIED_TAMPER_FREE" if is_valid else "INTEGRITY_VIOLATION_DETECTED",
        "error_detail": error_msg,
    }


# =============================================================================
# 6. Report Generation & Evidence Endpoints
# =============================================================================

@router.post("/reports/generate", response_model=GovernanceReport, status_code=status.HTTP_201_CREATED)
async def generate_governance_report(
    payload: GenerateReportRequest,
    actor: str = Depends(get_actor_identity),
):
    """
    Generates an evidence-backed governance report evaluating active policies
    against real cases, graph topology, and collector telemetry.
    """
    try:
        return GovernanceReportService.generate_report(
            framework=payload.framework,
            scope=payload.scope,
            start_time=payload.start_time,
            end_time=payload.end_time,
            actor_id=actor,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("/reports", response_model=List[GovernanceReport])
async def list_governance_reports(
    limit: int = Query(50, ge=1, le=200, description="Maximum reports to return"),
):
    """Lists generated governance reports in reverse chronological order."""
    return GovernanceReportService.list_reports(limit=limit)


@router.get("/reports/{report_id}", response_model=GovernanceReport)
async def get_governance_report_by_id(report_id: str):
    """Retrieves a generated governance report by canonical report ID."""
    rpt = GovernanceReportService.get_report(report_id)
    if not rpt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance report '{report_id}' not found.",
        )
    return rpt


@router.get("/reports/{report_id}/export")
async def export_governance_report(
    report_id: str,
    format: str = Query("json", description="Export format: 'json', 'csv', or 'html'"),
    actor: str = Depends(get_actor_identity),
):
    """
    Exports a generated governance report in JSON, CSV, or safe HTML format.
    Ensures XSS safety on HTML exports via strict HTML escaping.
    """
    try:
        content, media_type = GovernanceReportService.export_report(
            report_id=report_id,
            export_format=format,
            actor_id=actor,
        )
        return Response(content=content, media_type=media_type)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance report '{report_id}' not found.",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("/evidence/ledger", response_model=List[EvidenceLedgerItem])
async def get_evidence_ledger():
    """
    Retrieves cryptographic chain of custody records for email cases,
    graph findings, and collector telemetry with verified SHA-256 hashes.
    """
    return GovernanceReportService.get_evidence_ledger()


@router.post("/evidence/verify")
async def verify_evidence_hash(payload: VerifyEvidenceRequest):
    """
    Verifies SHA-256 digest for an evidence item against chain-of-custody ledger.
    """
    res = GovernanceReportService.verify_evidence_hash(
        evidence_id=payload.evidence_id,
        provided_hash=payload.provided_hash,
    )
    if not res.get("verified") and res.get("status") == "EVIDENCE_NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=res.get("detail", "Evidence not found."),
        )
    return res
