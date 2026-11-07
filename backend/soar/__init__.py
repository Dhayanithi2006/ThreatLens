"""
ThreatLens SOAR — Closed-Loop Containment & Guardrails Package
"""

from backend.soar.schema import (
    EnforcementAction,
    EnforcementState,
    EnforceContainmentRequest,
    EnforceContainmentResult,
    RollbackRequest,
    RollbackResult,
    ActiveEnforcementSummary,
)
from backend.soar.dispatcher import SOARDispatcher, get_soar_dispatcher

__all__ = [
    "EnforcementAction",
    "EnforcementState",
    "EnforceContainmentRequest",
    "EnforceContainmentResult",
    "RollbackRequest",
    "RollbackResult",
    "ActiveEnforcementSummary",
    "SOARDispatcher",
    "get_soar_dispatcher",
]

