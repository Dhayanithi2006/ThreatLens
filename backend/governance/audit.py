"""
ThreatLens Governance & Controls - Remediation Tracking & Tamper-Evident Audit Ledger
Provides thread-safe tracking for remediation lifecycle items and an immutable,
cryptographically chained SHA-256 audit log protecting sensitive governance mutations.
"""

import copy
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.governance.schema import (
    AuditRecord,
    RemediationPriority,
    RemediationRecord,
    RemediationStatus,
)

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

_audit_lock = threading.Lock()
_audit_ledger: List[AuditRecord] = []
_remediation_store: Dict[str, RemediationRecord] = {}


def _compute_hash(
    audit_id: str,
    event_type: str,
    actor_id: str,
    target_resource: str,
    action: str,
    details: Dict[str, Any],
    timestamp: datetime,
    previous_hash: str,
) -> str:
    """Computes deterministic SHA-256 digest over audit record payload and previous hash."""
    payload = {
        "audit_id": audit_id,
        "event_type": event_type,
        "actor_id": actor_id,
        "target_resource": target_resource,
        "action": action,
        "details": details,
        "timestamp": timestamp.isoformat(),
        "previous_hash": previous_hash,
    }
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def record_audit_event(
    event_type: str,
    actor_id: str,
    target_resource: str,
    action: str,
    details: Optional[Dict[str, Any]] = None,
) -> AuditRecord:
    """
    Appends an immutable event to the cryptographic audit chain.
    Thread-safe and tamper-evident.
    """
    with _audit_lock:
        now = datetime.now(timezone.utc)
        audit_id = f"aud-{uuid.uuid4().hex[:12]}"
        prev_hash = _audit_ledger[-1].current_hash if _audit_ledger else GENESIS_HASH
        safe_details = details or {}
        
        curr_hash = _compute_hash(
            audit_id=audit_id,
            event_type=event_type,
            actor_id=actor_id,
            target_resource=target_resource,
            action=action,
            details=safe_details,
            timestamp=now,
            previous_hash=prev_hash,
        )
        
        entry = AuditRecord(
            audit_id=audit_id,
            event_type=event_type,
            actor_id=actor_id,
            target_resource=target_resource,
            action=action,
            details=safe_details,
            previous_hash=prev_hash,
            current_hash=curr_hash,
            timestamp=now,
        )
        _audit_ledger.append(entry)
        return copy.deepcopy(entry)


def list_audit_records(limit: int = 100) -> List[AuditRecord]:
    """Returns the most recent audit records in chronological order."""
    with _audit_lock:
        return [copy.deepcopy(r) for r in _audit_ledger[-limit:]]


def verify_audit_integrity() -> Tuple[bool, Optional[str]]:
    """
    Verifies cryptographic hash chain integrity across all recorded audit entries.
    Returns (True, None) if the chain is unblemished, or (False, error_message)
    if tampering or broken linkages are detected.
    """
    with _audit_lock:
        expected_prev = GENESIS_HASH
        for idx, entry in enumerate(_audit_ledger):
            # Check previous hash linkage
            if entry.previous_hash != expected_prev:
                return (
                    False,
                    f"Chain break at index {idx} (ID: {entry.audit_id}): previous_hash '{entry.previous_hash}' does not match expected '{expected_prev}'.",
                )
            
            # Recalculate payload hash
            recomputed = _compute_hash(
                audit_id=entry.audit_id,
                event_type=entry.event_type,
                actor_id=entry.actor_id,
                target_resource=entry.target_resource,
                action=entry.action,
                details=entry.details,
                timestamp=entry.timestamp,
                previous_hash=entry.previous_hash,
            )
            
            if entry.current_hash != recomputed:
                return (
                    False,
                    f"Digest mismatch at index {idx} (ID: {entry.audit_id}): stored '{entry.current_hash}' != computed '{recomputed}'.",
                )
            
            expected_prev = entry.current_hash
            
        return (True, None)


# =============================================================================
# Remediation Records Store
# =============================================================================

def create_remediation(
    finding_reference: str,
    recommended_action: str,
    priority: RemediationPriority = RemediationPriority.P2_HIGH,
    owner: Optional[str] = None,
    actor_id: str = "system",
) -> RemediationRecord:
    """
    Creates a new remediation tracking record and writes a tamper-evident audit entry.
    """
    now = datetime.now(timezone.utc)
    rem_id = f"REM-{now.year}-{uuid.uuid4().hex[:6].upper()}"
    
    rec = RemediationRecord(
        remediation_id=rem_id,
        finding_reference=finding_reference,
        recommended_action=recommended_action,
        owner=owner,
        priority=priority,
        status=RemediationStatus.OPEN,
        resolution_evidence=None,
        created_at=now,
        updated_at=now,
        created_by=actor_id,
    )
    
    with _audit_lock:
        _remediation_store[rem_id] = rec
        
    record_audit_event(
        event_type="REMEDIATION_CREATED",
        actor_id=actor_id,
        target_resource=f"remediation:{rem_id}",
        action="CREATE",
        details={
            "remediation_id": rem_id,
            "finding_reference": finding_reference,
            "priority": priority.value,
            "owner": owner,
        },
    )
    return copy.deepcopy(rec)


def update_remediation_status(
    remediation_id: str,
    new_status: RemediationStatus,
    resolution_evidence: Optional[str] = None,
    actor_id: str = "system",
) -> Optional[RemediationRecord]:
    """
    Updates the state of an existing remediation record and writes an audit log.
    """
    norm_id = remediation_id.strip().upper()
    with _audit_lock:
        rec = _remediation_store.get(norm_id)
        if not rec:
            return None
        
        old_status = rec.status
        now = datetime.now(timezone.utc)
        
        updated = RemediationRecord(
            remediation_id=rec.remediation_id,
            finding_reference=rec.finding_reference,
            recommended_action=rec.recommended_action,
            owner=rec.owner,
            priority=rec.priority,
            status=new_status,
            resolution_evidence=resolution_evidence or rec.resolution_evidence,
            created_at=rec.created_at,
            updated_at=now,
            created_by=rec.created_by,
        )
        _remediation_store[norm_id] = updated
        
    record_audit_event(
        event_type="REMEDIATION_STATUS_CHANGED",
        actor_id=actor_id,
        target_resource=f"remediation:{norm_id}",
        action="UPDATE",
        details={
            "old_status": old_status.value,
            "new_status": new_status.value,
            "resolution_evidence": resolution_evidence,
        },
    )
    return copy.deepcopy(updated)


def get_remediation(remediation_id: str) -> Optional[RemediationRecord]:
    """Retrieves remediation record by ID."""
    norm_id = remediation_id.strip().upper()
    with _audit_lock:
        rec = _remediation_store.get(norm_id)
        return copy.deepcopy(rec) if rec else None


def list_remediations(
    status: Optional[RemediationStatus] = None,
    priority: Optional[RemediationPriority] = None,
) -> List[RemediationRecord]:
    """Lists remediation records with optional filtering."""
    with _audit_lock:
        items = list(_remediation_store.values())
        
    if status:
        items = [i for i in items if i.status == status]
    if priority:
        items = [i for i in items if i.priority == priority]
        
    return [copy.deepcopy(i) for i in items]


def reset_audit_and_remediations() -> None:
    """Resets audit ledger and remediation store (primarily for unit test isolation)."""
    with _audit_lock:
        _audit_ledger.clear()
        _remediation_store.clear()


def tamper_audit_record_for_test(index: int, **field_overrides) -> None:
    """
    Test utility: intentionally modifies a ledger entry in-place to verify
    cryptographic detection of unauthorized tampering.
    """
    with _audit_lock:
        if 0 <= index < len(_audit_ledger):
            entry = _audit_ledger[index]
            _audit_ledger[index] = entry.model_copy(update=field_overrides)
