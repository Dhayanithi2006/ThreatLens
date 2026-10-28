"""
ThreatLens GraphOps — Zero-Trust Entitlement vs. Observed Usage Engine
Implements comparative graph analytics contrasting granted entitlements (IAM/ACLs)
with empirical observed network telemetry (EDR/NetFlow). Surfaces dormant over-privileged
identities, unauthorized shadow connections, and quantifiable least-privilege compliance.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import logging

from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.graphops.schema import NodeLabel, RelationshipType, CriticalityTier

logger = logging.getLogger("threatlens.graphops.zero_trust")


class ZeroTrustAccessItem(BaseModel):
    """Single assessed access entitlement or observed connection."""
    source_id: str = Field(description="Originating identity or endpoint canonical ID")
    source_label: str = Field(description="Source entity type (User, Device, Server)")
    target_id: str = Field(description="Destination entity canonical ID")
    target_label: str = Field(description="Target entity type (Server, Database, CriticalAsset)")
    target_criticality: str = Field(default="MEDIUM", description="Criticality level of target")
    access_type: str = Field(description="HAS_PERMISSION, OBSERVED_CONNECTION, LOGGED_IN_TO")
    status: str = Field(
        description="ACTIVE_VERIFIED (used & entitled), OVER_PRIVILEGED_DORMANT (entitled but unused), UNENTITLED_SHADOW (observed but not entitled)"
    )
    risk_severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    recommendation: str = Field(description="Prescriptive Zero-Trust remediation action")


class ZeroTrustAuditResult(BaseModel):
    """Consolidated outcome of an enterprise-wide Zero-Trust access comparison."""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_entitled_permissions: int = Field(description="Total formal IAM/ACL permissions in graph")
    active_verified_permissions: int = Field(description="Permissions actively backed by observed telemetry")
    dormant_overprivileged_permissions: int = Field(description="Unexercised entitlements creating lateral exposure")
    unentitled_shadow_connections: int = Field(description="Observed connections lacking formal authorization")
    least_privilege_compliance_pct: float = Field(description="Percentage of granted access verified as necessary")
    over_privilege_risk_score: float = Field(description="Composite risk rating 0-100 of lateral attack surface")
    access_breakdown: List[ZeroTrustAccessItem] = Field(default_factory=list)
    recommended_revocations: List[Dict[str, Any]] = Field(default_factory=list)
    zero_trust_summary: str = Field(description="Executive narrative explaining Zero-Trust posture")


class ZeroTrustAuditService:
    """
    Engine executing dual-graph relational comparison:
    Entitled Access (IAM) vs. Observed Usage (Telemetry).
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    def audit_access_entitlements(self) -> ZeroTrustAuditResult:
        """
        Queries Neo4j for entitled vs observed subgraphs and derives
        the Zero-Trust divergence metrics.
        """
        # 1. Query all explicit permissions (Entitled Graph)
        entitled_records = self.client.execute_query(
            """
            MATCH (u:User)-[r:HAS_PERMISSION]->(t)
            OPTIONAL MATCH (u)-[:USES]->(d:Device)
            RETURN u.id AS user_id, labels(u)[0] AS user_label,
                   d.id AS device_id,
                   t.id AS target_id, labels(t)[0] AS target_label,
                   coalesce(t.criticality, 'MEDIUM') AS target_criticality,
                   type(r) AS rel_type
            """
        )

        # 2. Query observed connections (Observed Usage Graph)
        observed_records = self.client.execute_query(
            """
            MATCH (s)-[r:OBSERVED_CONNECTION|LOGGED_IN_TO]->(t)
            RETURN s.id AS source_id, labels(s)[0] AS source_label,
                   t.id AS target_id, labels(t)[0] AS target_label,
                   coalesce(t.criticality, 'MEDIUM') AS target_criticality,
                   type(r) AS rel_type
            """
        )

        # Index observed transitions: (source_id, target_id) -> record
        observed_pairs = set()
        observed_by_source_target = {}
        for obs in observed_records:
            s_id = str(obs.get("source_id", "")).lower()
            t_id = str(obs.get("target_id", "")).lower()
            observed_pairs.add((s_id, t_id))
            observed_by_source_target[(s_id, t_id)] = obs

        access_items: List[ZeroTrustAccessItem] = []
        entitled_pairs = set()
        dormant_count = 0
        active_count = 0
        recommended_revocations = []

        # 3. Evaluate Entitled permissions
        for ent in entitled_records:
            u_id = str(ent.get("user_id", "")).lower()
            d_id = str(ent.get("device_id", "")).lower() if ent.get("device_id") else None
            t_id = str(ent.get("target_id", "")).lower()
            t_crit = str(ent.get("target_criticality", "MEDIUM")).upper()

            entitled_pairs.add((u_id, t_id))
            if d_id:
                entitled_pairs.add((d_id, t_id))

            # Is this permission verified by active usage (either directly or via assigned device)?
            is_active = (u_id, t_id) in observed_pairs or (d_id and (d_id, t_id) in observed_pairs)

            if is_active:
                active_count += 1
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=ent.get("user_id"),
                        source_label=ent.get("user_label", "User"),
                        target_id=ent.get("target_id"),
                        target_label=ent.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type="HAS_PERMISSION",
                        status="ACTIVE_VERIFIED",
                        risk_severity="LOW",
                        recommendation="Access is actively required and authorized. Maintain continuous behavioral baseline.",
                    )
                )
            else:
                dormant_count += 1
                severity = "CRITICAL" if t_crit in ("CRITICAL", "HIGH") else "MEDIUM"
                rec_action = f"Revoke dormant entitlement '{ent.get('user_id')} -> {ent.get('target_id')}'. Identity has not exercised this privilege, creating unnecessary lateral attack surface."
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=ent.get("user_id"),
                        source_label=ent.get("user_label", "User"),
                        target_id=ent.get("target_id"),
                        target_label=ent.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type="HAS_PERMISSION",
                        status="OVER_PRIVILEGED_DORMANT",
                        risk_severity=severity,
                        recommendation=rec_action,
                    )
                )
                recommended_revocations.append({
                    "revocation_id": f"REV-{len(recommended_revocations) + 1:03d}",
                    "identity": ent.get("user_id"),
                    "target_asset": ent.get("target_id"),
                    "criticality": t_crit,
                    "risk_reduction_impact": "HIGH" if t_crit in ("CRITICAL", "HIGH") else "MEDIUM",
                    "action": "REVOKE_PERMISSION",
                    "justification": "Dormant entitlement unexercised during telemetry observation window."
                })

        # 4. Evaluate Observed connections that lack formal entitlement (Shadow / Unauthorized Access)
        unentitled_count = 0
        for obs in observed_records:
            s_id = str(obs.get("source_id", "")).lower()
            t_id = str(obs.get("target_id", "")).lower()
            s_label = obs.get("source_label", "Device")
            t_crit = str(obs.get("target_criticality", "MEDIUM")).upper()

            # Skip internal server-to-server infrastructure hops
            if s_id.startswith("server:") and t_id.startswith("server:"):
                continue

            if (s_id, t_id) not in entitled_pairs:
                unentitled_count += 1
                severity = "HIGH" if t_crit in ("CRITICAL", "HIGH") else "MEDIUM"
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=obs.get("source_id"),
                        source_label=s_label,
                        target_id=obs.get("target_id"),
                        target_label=obs.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type=obs.get("rel_type", "OBSERVED_CONNECTION"),
                        status="UNENTITLED_SHADOW",
                        risk_severity=severity,
                        recommendation=f"Quarantine or investigate unentitled connection '{obs.get('source_id')} -> {obs.get('target_id')}'. Potential lateral movement or shadow access.",
                    )
                )

        total_entitled = len(entitled_records)
        compliance_pct = round((active_count / total_entitled * 100.0), 1) if total_entitled > 0 else 100.0
        risk_score = round(min(100.0, (dormant_count * 15.0) + (unentitled_count * 25.0)), 1)

        summary_narrative = (
            f"Zero-Trust Access Audit evaluated {total_entitled} granted permission(s) and {len(observed_records)} observed transition(s). "
            f"Found {active_count} active legitimate permission(s), {dormant_count} over-privileged dormant entitlement(s), "
            f"and {unentitled_count} unentitled shadow connection(s). Least-Privilege compliance is {compliance_pct}%, "
            f"with an overall lateral attack surface risk rating of {risk_score} / 100."
        )

        return ZeroTrustAuditResult(
            total_entitled_permissions=total_entitled,
            active_verified_permissions=active_count,
            dormant_overprivileged_permissions=dormant_count,
            unentitled_shadow_connections=unentitled_count,
            least_privilege_compliance_pct=compliance_pct,
            over_privilege_risk_score=risk_score,
            access_breakdown=access_items,
            recommended_revocations=recommended_revocations,
            zero_trust_summary=summary_narrative,
        )


def get_zero_trust_service(client: Optional[Neo4jClient] = None) -> ZeroTrustAuditService:
    """Dependency injector for ZeroTrustAuditService."""
    return ZeroTrustAuditService(client=client)

