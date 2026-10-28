"""
ThreatLens Governance & Controls - Domain Schema & Models
Formal Pydantic v2 data models for framework controls, organizational policies,
evidence-backed evaluations, remediation tracking, and cryptographic audit records.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class EvaluationStatus(str, Enum):
    """
    Deterministic compliance evaluation statuses.
    In accordance with governance standards, lack of evidence must
    NEVER be treated as compliant; it resolves to NEEDS_REVIEW or NOT_EVALUATED.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_EVALUATED = "NOT_EVALUATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class RemediationPriority(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class ControlRecord(BaseModel):
    """
    Authoritative security control definition mapped to verified public standards.
    Disclaimers apply: Technical graph findings serve as evidence for assessment;
    they do not constitute formal regulatory certification or audit completion.
    """
    model_config = ConfigDict(frozen=True)

    framework_name: str = Field(description="Catalog name e.g. NIST CSF, NIST SP 800-53, CIS Controls, MITRE ATT&CK")
    framework_version: str = Field(description="Exact catalog revision e.g. 2.0, Rev. 5, v8.1, v14.1")
    control_id: str = Field(description="Standardized control identifier e.g. PR.AA-01, AC-3, CIS-5.1, T1078")
    title: str = Field(description="Official control title")
    description: str = Field(description="Official normative description of the control requirement")
    mapping_rationale: str = Field(description="Explanation of why this control applies to enterprise graph findings")
    official_reference: str = Field(description="Verified publication URL, DOI, or official document citation")
    applicability: str = Field(description="Operational scope e.g. Identity & Access, Asset Exposure, Vulnerability")


class OrganizationPolicy(BaseModel):
    """
    Configurable organizational security policy enforced against GraphOps and email findings.
    """
    policy_id: str = Field(description="Canonical policy identifier e.g. POL-IAM-01")
    name: str = Field(description="Descriptive policy name")
    description: str = Field(description="Detailed statement of policy intent and operational boundaries")
    rule_conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured parameter conditions evaluated against graph topology and telemetry"
    )
    severity: str = Field(default="HIGH", description="Severity tier: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    scope: str = Field(default="ENTERPRISE", description="Target environment scope e.g. PRODUCTION, WORKSTATIONS, CROWN_JEWELS")
    version: str = Field(default="1.0", description="Policy version string")
    enabled: bool = Field(default=True, description="Whether policy is active in automated evaluation cycles")
    linked_control_ids: List[str] = Field(
        default_factory=list,
        description="List of standard control identifiers linked to this policy"
    )


class PolicyEvaluation(BaseModel):
    """
    Evidence-backed assessment result of an organization policy against real findings.
    """
    evaluation_id: str = Field(description="Unique evaluation event identifier")
    policy_id: str = Field(description="Associated organization policy ID")
    control_id: Optional[str] = Field(default=None, description="Primary mapped industry standard control ID")
    status: EvaluationStatus = Field(description="Evaluation verdict: PASS, FAIL, NEEDS_REVIEW, NOT_EVALUATED, NOT_APPLICABLE")
    supporting_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Concrete graph entities, edge transitions, anomaly IDs, or email digests forming evidence"
    )
    applicable_rule: str = Field(description="Exact operational rule evaluated")
    reasoning: str = Field(description="Detailed human-readable explanation of why finding passed, failed, or requires review")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="ISO 8601 UTC evaluation timestamp"
    )
    data_limitations: List[str] = Field(
        default_factory=list,
        description="Defensive notes on evidence boundaries, bounded search limits, or unindexed context"
    )
    recommended_remediation: Optional[str] = Field(
        default=None,
        description="Actionable mitigation or control modification to address failure"
    )


class RemediationRecord(BaseModel):
    """
    Actionable remediation tracking record for policy violations and graph choke points.
    """
    remediation_id: str = Field(description="Canonical remediation ID e.g. REM-2026-001")
    finding_reference: str = Field(description="Reference to generating finding, path ID, or evaluation ID")
    recommended_action: str = Field(description="Prescribed mitigation action e.g. ISOLATE_NODE, REVOKE_PERMISSION")
    owner: Optional[str] = Field(default=None, description="Assigned remediation team or operational owner")
    priority: RemediationPriority = Field(default=RemediationPriority.P2_HIGH, description="Remediation urgency")
    status: RemediationStatus = Field(default=RemediationStatus.OPEN, description="Current remediation state")
    resolution_evidence: Optional[str] = Field(default=None, description="Verification proof or ticket reference")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = Field(default="system", description="Actor or automation engine that filed remediation")


class AuditRecord(BaseModel):
    """
    Tamper-evident cryptographic ledger entry for sensitive policy, remediation, and governance mutations.
    """
    audit_id: str = Field(description="Sequential or unique audit entry identifier")
    event_type: str = Field(description="Classification of event e.g. POLICY_UPDATED, REMEDIATION_STATUS_CHANGED")
    actor_id: str = Field(description="Authenticated identity or API key responsible for the action")
    target_resource: str = Field(description="Resource identifier affected e.g. policy:POL-IAM-01")
    action: str = Field(description="Action verb e.g. CREATE, UPDATE, RESOLVE, OVERRIDE")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured before/after change details")
    previous_hash: str = Field(description="Cryptographic SHA-256 digest of previous audit record in ledger")
    current_hash: str = Field(description="SHA-256 digest computed over payload + previous_hash")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
