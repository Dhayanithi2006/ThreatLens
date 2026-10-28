"""
ThreatLens Governance & Controls - Organization Security Policies
Defines default organization-level policies, configuration constraints,
and in-memory policy registry.
"""

import copy
import threading
from typing import Dict, List, Optional
from backend.governance.schema import OrganizationPolicy

# Default enterprise policies baseline
DEFAULT_POLICIES: List[OrganizationPolicy] = [
    OrganizationPolicy(
        policy_id="POL-IAM-01",
        name="Zero Direct Workstation Access to Crown Jewels",
        description="Prohibits direct access from user workstations to sensitive databases or Crown Jewel assets without traversing an authenticated bastion/jumpbox gateway.",
        rule_conditions={
            "forbidden_transitions": [
                "Workstation->Database",
                "Workstation->CrownJewel",
                "Endpoint->CrownJewel",
            ],
            "max_allowed_hops_without_jumpbox": 0,
        },
        severity="CRITICAL",
        scope="ENTERPRISE",
        version="1.0",
        enabled=True,
        linked_control_ids=["PR.AA-05", "AC-3", "CIS-3.3", "T1021", "A.5.15"],
    ),
    OrganizationPolicy(
        policy_id="POL-IAM-02",
        name="Service Account Interactive and Cross-Tier Logon Prevention",
        description="Service accounts and non-human identities must not authenticate interactively to user workstations or client endpoints.",
        rule_conditions={
            "prohibit_service_logon_workstations": True,
            "check_account_type": "SERVICE",
        },
        severity="HIGH",
        scope="WORKSTATIONS",
        version="1.0",
        enabled=True,
        linked_control_ids=["PR.AA-01", "AC-6", "CIS-5.1", "T1078", "A.5.15"],
    ),
    OrganizationPolicy(
        policy_id="POL-EXPOSURE-01",
        name="Crown Jewel Blast Radius Isolation Boundary",
        description="Compromise of an unprivileged endpoint must not expose more than 20% of enterprise Crown Jewels or reach mission-critical database assets within 3 hops.",
        rule_conditions={
            "max_crown_jewel_reachability_pct": 20.0,
            "max_critical_assets_compromised": 0,
            "max_reachability_hops": 3,
        },
        severity="HIGH",
        scope="PRODUCTION",
        version="1.0",
        enabled=True,
        linked_control_ids=["PR.IR-01", "AC-3", "CIS-3.3", "A.8.20"],
    ),
    OrganizationPolicy(
        policy_id="POL-VULN-01",
        name="Critical Exploit Precondition Remediation on Lateral Paths",
        description="Exploitable vulnerabilities and unpatched CVEs on attack paths reaching Crown Jewels must be mitigated or isolated.",
        rule_conditions={
            "disallow_exploitable_edges_in_paths": True,
            "cvss_threshold": 8.0,
        },
        severity="HIGH",
        scope="ENTERPRISE",
        version="1.0",
        enabled=True,
        linked_control_ids=["PR.IP-01", "CM-8", "CIS-7.1", "T1190", "A.8.8"],
    ),
    OrganizationPolicy(
        policy_id="POL-LOG-01",
        name="Comprehensive Log Audit & Path Traversal Telemetry",
        description="Lateral movement paths and connection sequences must be backed by verified network observation telemetry rather than unmonitored structural adjacency.",
        rule_conditions={
            "require_connection_telemetry": True,
            "min_telemetry_types": ["OBSERVED_CONNECTION", "ACCESS"],
        },
        severity="MEDIUM",
        scope="ENTERPRISE",
        version="1.0",
        enabled=True,
        linked_control_ids=["DE.CM-01", "AU-2", "CIS-8.2", "T1562"],
    ),
    OrganizationPolicy(
        policy_id="POL-INC-01",
        name="Attacker Infrastructure & Phishing Indicator Quarantine",
        description="Any external C2 IP, phishing sender, or malicious attachment linked to internal corporate identities must trigger immediate isolation of target endpoints.",
        rule_conditions={
            "quarantine_external_c2": True,
            "block_phishing_targets": True,
        },
        severity="CRITICAL",
        scope="ENTERPRISE",
        version="1.0",
        enabled=True,
        linked_control_ids=["RS.AN-01", "IR-4", "CIS-17.1", "T1566"],
    ),
]

_policy_lock = threading.Lock()
_policies_store: Dict[str, OrganizationPolicy] = {p.policy_id: copy.deepcopy(p) for p in DEFAULT_POLICIES}


def reset_policies_to_default() -> None:
    """Resets the policy registry to the default baseline."""
    global _policies_store
    with _policy_lock:
        _policies_store = {p.policy_id: copy.deepcopy(p) for p in DEFAULT_POLICIES}


def list_policies(scope: Optional[str] = None, enabled_only: bool = False) -> List[OrganizationPolicy]:
    """Retrieves policies with optional scope and enabled filters."""
    with _policy_lock:
        results = list(_policies_store.values())

    if scope:
        norm_scope = scope.strip().upper()
        results = [p for p in results if p.scope.upper() == norm_scope]

    if enabled_only:
        results = [p for p in results if p.enabled]

    return results


def get_policy(policy_id: str) -> Optional[OrganizationPolicy]:
    """Retrieves policy by canonical identifier."""
    if not policy_id:
        return None
    with _policy_lock:
        return _policies_store.get(policy_id.strip().upper())


def save_policy(policy: OrganizationPolicy) -> OrganizationPolicy:
    """Creates or updates an organizational policy."""
    with _policy_lock:
        _policies_store[policy.policy_id.upper()] = copy.deepcopy(policy)
        return _policies_store[policy.policy_id.upper()]


def delete_policy(policy_id: str) -> bool:
    """Removes a policy by ID."""
    norm_id = policy_id.strip().upper()
    with _policy_lock:
        if norm_id in _policies_store:
            del _policies_store[norm_id]
            return True
        return False
