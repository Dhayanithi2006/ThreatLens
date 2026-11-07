"""
ThreatLens SOAR — Closed-Loop Containment & Guardrails Schema
Defines contracts for actionable incident containment, adapter dispatch,
and tamper-evident reversible rollbacks.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EnforcementAction(str, Enum):
    ISOLATE_NODE = "ISOLATE_NODE"
    BLOCK_CONNECTION = "BLOCK_CONNECTION"
    SUSPEND_ACCOUNT = "SUSPEND_ACCOUNT"
    SEVER_EDGE = "SEVER_EDGE"


class EnforcementState(str, Enum):
    PENDING = "PENDING"
    ENFORCED = "ENFORCED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class EnforceContainmentRequest(BaseModel):
    """Request payload to actively enforce a containment intervention."""
    target_node_id: str = Field(description="Canonical entity identifier to contain (e.g. server:srv-app-01)")
    action: EnforcementAction = Field(default=EnforcementAction.ISOLATE_NODE, description="Specific containment action to execute")
    remediation_id: Optional[str] = Field(default=None, description="Optional link to existing RemediationRecord")
    simulation_id: Optional[str] = Field(default=None, description="Optional link to What-If simulation ID")
    destination_node_id: Optional[str] = Field(default=None, description="Target destination if severing a specific connection")
    target_relationship_type: Optional[str] = Field(default=None, description="Relationship type if severing specific edge")
    reason: str = Field(default="SOC Incident Responder automated containment guardrail", description="Justification for containment")
    ttl_seconds: Optional[int] = Field(default=3600, ge=60, le=86400 * 7, description="Auto-rollback TTL safety ceiling in seconds")


class EnforceContainmentResult(BaseModel):
    """Response contract documenting successful live containment enforcement."""
    enforcement_id: str = Field(description="Deterministic unique enforcement identifier")
    remediation_id: str = Field(description="Associated canonical RemediationRecord ID")
    target_node_id: str = Field(description="Contained entity ID")
    action: EnforcementAction = Field(description="Enforced containment action")
    state: EnforcementState = Field(default=EnforcementState.ENFORCED, description="Current execution state")
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    adapter_name: str = Field(description="Underlying dispatch adapter that executed containment")
    rollback_token: str = Field(description="Cryptographic secret token required to authorize rollback")
    pre_state_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Captured pre-containment state for safe rollback")
    audit_hash: str = Field(description="SHA-256 hash sealed in tamper-evident governance ledger")
    message: str = Field(description="Executive execution summary")


class RollbackRequest(BaseModel):
    """Request payload to safely reverse an active containment intervention."""
    remediation_id: str = Field(description="Canonical remediation ID of containment to revert")
    rollback_token: Optional[str] = Field(default=None, description="Rollback authorization token issued at enforcement")
    reason: str = Field(default="SOC Analyst cleared threat / Incident resolved", description="Operational justification for rollback")


class RollbackResult(BaseModel):
    """Response contract documenting successful containment rollback."""
    enforcement_id: str = Field(description="Enforcement record ID")
    remediation_id: str = Field(description="Associated remediation ID")
    target_node_id: str = Field(description="Uncontained entity ID restored to normal operation")
    state: EnforcementState = Field(default=EnforcementState.ROLLED_BACK)
    restored_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_hash: str = Field(description="SHA-256 hash sealed in tamper-evident governance ledger for rollback")
    message: str = Field(description="Executive rollback summary")


class ActiveEnforcementSummary(BaseModel):
    """Summary of an active containment guardrail currently enforced on the network."""
    enforcement_id: str
    remediation_id: str
    target_node_id: str
    action: EnforcementAction
    state: EnforcementState
    adapter_name: str
    executed_at: str
    reason: str
    created_by: str

