"""
ThreatLens SOAR — Centralized Containment Dispatcher & Guardrails Engine
Orchestrates active containment enforcement, pre-state preservation,
and cryptographic 1-click reversible rollbacks.
"""

import uuid
import copy
import threading
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.soar.schema import (
    EnforcementAction,
    EnforcementState,
    EnforceContainmentRequest,
    EnforceContainmentResult,
    RollbackRequest,
    RollbackResult,
    ActiveEnforcementSummary,
)
from backend.soar.adapters import (
    BaseContainmentAdapter,
    WindowsHostFirewallAdapter,
    ActiveDirectoryAccountAdapter,
    GraphTopologyContainmentAdapter,
)
from backend.governance.audit import (
    record_audit_event,
    list_audit_records,
    create_remediation,
    get_remediation,
    update_remediation_status,
)
from backend.governance.schema import RemediationStatus, RemediationPriority

logger = logging.getLogger("threatlens.soar.dispatcher")


class SOARDispatcher:
    """
    Singleton dispatcher for active SOAR containment guardrails.
    Thread-safe, state-preserving, and integrated with the SHA-256 governance audit ledger.
    """

    _instance: Optional["SOARDispatcher"] = None
    _lock = threading.RLock()

    def __new__(cls) -> "SOARDispatcher":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._adapters: List[BaseContainmentAdapter] = [
            WindowsHostFirewallAdapter(),
            ActiveDirectoryAccountAdapter(),
            GraphTopologyContainmentAdapter(),
        ]
        self._graph_adapter = GraphTopologyContainmentAdapter()
        self._enforcements: Dict[str, EnforceContainmentResult] = {}
        self._initialized = True
        logger.info("SOARDispatcher initialized with 3 containment adapters.")

    def select_adapter(self, target_node_id: str, action: EnforcementAction) -> BaseContainmentAdapter:
        """Finds the most specific adapter for the given entity and action."""
        for adapter in self._adapters:
            if not isinstance(adapter, GraphTopologyContainmentAdapter) and adapter.can_handle(target_node_id, action):
                return adapter
        return self._graph_adapter

    def enforce_containment(
        self,
        request: EnforceContainmentRequest,
        actor: str = "soc_incident_responder",
    ) -> EnforceContainmentResult:
        """
        Executes active containment on the target node, records pre-state snapshot,
        updates the knowledge graph, and seals the action in the SHA-256 audit ledger.
        """
        with self._lock:
            now_str = datetime.now(timezone.utc).isoformat()
            enforcement_id = f"ENF-{uuid.uuid4().hex[:8].upper()}"
            rollback_token = f"rbk_{uuid.uuid4().hex}"

            # 1. Resolve or create associated RemediationRecord
            rem_id = request.remediation_id
            if not rem_id:
                rec = create_remediation(
                    finding_reference=request.simulation_id or f"MANUAL_CONTAINMENT:{request.target_node_id}",
                    recommended_action=f"{request.action.value} on {request.target_node_id}",
                    priority=RemediationPriority.P1_CRITICAL,
                    owner="SOC Incident Response Team",
                    actor_id=actor,
                )
                rem_id = rec.remediation_id

            # 2. Select primary adapter and capture pre-state
            primary_adapter = self.select_adapter(request.target_node_id, request.action)
            primary_pre_state = primary_adapter.enforce(request)

            # 3. Always apply Knowledge Graph topological severance
            graph_pre_state = self._graph_adapter.enforce(request)

            composite_pre_state = {
                "target_node_id": request.target_node_id,
                "primary_adapter": primary_adapter.adapter_name(),
                "primary_state": primary_pre_state,
                "graph_state": graph_pre_state,
                "reason": request.reason,
                "enforced_by": actor,
                "enforced_at": now_str,
            }

            # 4. Update remediation record status
            update_remediation_status(
                remediation_id=rem_id,
                new_status=RemediationStatus.RESOLVED,
                resolution_evidence=f"Active SOAR containment enforced via {primary_adapter.adapter_name()} (Enforcement ID: {enforcement_id})",
                actor_id=actor,
            )

            # 5. Record tamper-evident SHA-256 audit ledger entry
            record_audit_event(
                event_type="SOAR_CONTAINMENT_ENFORCED",
                actor_id=actor,
                target_resource=f"entity:{request.target_node_id}",
                action="ENFORCE_CONTAINMENT",
                details={
                    "enforcement_id": enforcement_id,
                    "remediation_id": rem_id,
                    "action": request.action.value,
                    "adapter": primary_adapter.adapter_name(),
                    "rollback_token": rollback_token,
                    "target_node_id": request.target_node_id,
                },
            )

            # 6. Retrieve latest audit record hash
            audit_records = list_audit_records()
            head_hash = audit_records[-1].current_hash if audit_records else "SHA256_GENESIS"

            result = EnforceContainmentResult(
                enforcement_id=enforcement_id,
                remediation_id=rem_id,
                target_node_id=request.target_node_id,
                action=request.action,
                state=EnforcementState.ENFORCED,
                executed_at=now_str,
                adapter_name=primary_adapter.adapter_name(),
                rollback_token=rollback_token,
                pre_state_snapshot=composite_pre_state,
                audit_hash=head_hash,
                message=(
                    f"Successfully enforced {request.action.value} on {request.target_node_id}. "
                    f"Network routes isolated via {primary_adapter.adapter_name()} and knowledge graph updated. "
                    f"1-Click Rollback is armed."
                ),
            )

            self._enforcements[rem_id] = result
            self._enforcements[enforcement_id] = result
            logger.info(f"Containment enforced successfully: {enforcement_id} (Remediation: {rem_id})")
            return copy.deepcopy(result)

    def rollback_containment(
        self,
        request: RollbackRequest,
        actor: str = "soc_incident_responder",
    ) -> RollbackResult:
        """
        Reverses active containment, restores previous network and graph states,
        and seals the rollback in the SHA-256 governance audit ledger.
        """
        with self._lock:
            rem_id = request.remediation_id.strip()
            enf = self._enforcements.get(rem_id)
            if not enf:
                # Try finding by remediation ID in values
                for k, v in self._enforcements.items():
                    if v.remediation_id == rem_id or v.enforcement_id == rem_id:
                        enf = v
                        break

            if not enf:
                raise ValueError(f"No active enforcement found for remediation identifier '{rem_id}'.")

            if enf.state == EnforcementState.ROLLED_BACK:
                raise ValueError(f"Containment '{enf.enforcement_id}' has already been rolled back.")

            # Validate rollback token if supplied
            if request.rollback_token and request.rollback_token != enf.rollback_token:
                raise PermissionError("Invalid rollback token provided. Rollback rejected.")

            now_str = datetime.now(timezone.utc).isoformat()
            pre_state = enf.pre_state_snapshot

            # 1. Rollback primary adapter
            primary_name = pre_state.get("primary_adapter", "")
            primary_adapter = next((a for a in self._adapters if a.adapter_name() == primary_name), None)
            if primary_adapter:
                primary_adapter.rollback(pre_state.get("primary_state", {}))

            # 2. Rollback knowledge graph adapter
            self._graph_adapter.rollback(pre_state.get("graph_state", {}))

            # 3. Update state
            enf.state = EnforcementState.ROLLED_BACK

            # 4. Update remediation record status
            update_remediation_status(
                remediation_id=enf.remediation_id,
                new_status=RemediationStatus.RESOLVED,
                resolution_evidence=f"Containment safely reversed and restored to normal baseline: {request.reason}",
                actor_id=actor,
            )

            # 5. Record tamper-evident SHA-256 audit entry
            record_audit_event(
                event_type="SOAR_CONTAINMENT_ROLLED_BACK",
                actor_id=actor,
                target_resource=f"entity:{enf.target_node_id}",
                action="ROLLBACK_CONTAINMENT",
                details={
                    "enforcement_id": enf.enforcement_id,
                    "remediation_id": enf.remediation_id,
                    "target_node_id": enf.target_node_id,
                    "reason": request.reason,
                    "restored_at": now_str,
                },
            )

            audit_records = list_audit_records()
            head_hash = audit_records[-1].current_hash if audit_records else "SHA256_GENESIS"

            res = RollbackResult(
                enforcement_id=enf.enforcement_id,
                remediation_id=enf.remediation_id,
                target_node_id=enf.target_node_id,
                state=EnforcementState.ROLLED_BACK,
                restored_at=now_str,
                audit_hash=head_hash,
                message=f"Containment safely rolled back on {enf.target_node_id}. Normal operational baseline restored.",
            )
            logger.info(f"Rollback successful for enforcement {enf.enforcement_id} on {enf.target_node_id}")
            return res

    def list_active_enforcements(self) -> List[ActiveEnforcementSummary]:
        """Returns all currently active containment guardrails."""
        with self._lock:
            # Deduplicate by enforcement_id
            seen = set()
            summaries = []
            for enf in self._enforcements.values():
                if enf.enforcement_id not in seen:
                    seen.add(enf.enforcement_id)
                    summaries.append(
                        ActiveEnforcementSummary(
                            enforcement_id=enf.enforcement_id,
                            remediation_id=enf.remediation_id,
                            target_node_id=enf.target_node_id,
                            action=enf.action,
                            state=enf.state,
                            adapter_name=enf.adapter_name,
                            executed_at=enf.executed_at,
                            reason=enf.pre_state_snapshot.get("reason", "N/A"),
                            created_by=enf.pre_state_snapshot.get("enforced_by", "system"),
                        )
                    )
            return sorted(summaries, key=lambda s: s.executed_at, reverse=True)

    def get_enforcement(self, identifier: str) -> Optional[EnforceContainmentResult]:
        """Retrieves enforcement result by enforcement_id or remediation_id."""
        with self._lock:
            return self._enforcements.get(identifier)


# Global singleton instance accessor
_dispatcher = SOARDispatcher()

def get_soar_dispatcher() -> SOARDispatcher:
    return _dispatcher

