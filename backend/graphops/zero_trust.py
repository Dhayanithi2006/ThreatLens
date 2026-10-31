"""
ThreatLens GraphOps — Zero-Trust Entitlement vs. Observed Usage Engine
Implements comparative graph analytics contrasting granted entitlements (IAM/ACLs)
with empirical observed network telemetry (EDR/NetFlow). Surfaces dormant over-privileged
identities, unauthorized shadow connections, and quantifiable least-privilege compliance.
Adheres strictly to the principle that unexercised grants are dormant entitlements to review
(not automatically unnecessary privileges), and observed connections without matching grants
are potential policy discrepancies (not conclusive proof of malicious breach).
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
    discrepancy_type: str = Field(
        default="MATCHING_ACCESS",
        description="Categorical discrepancy: MATCHING_ACCESS, UNEXERCISED_GRANT, POTENTIAL_UNENTITLED_ACCESS, POLICY_GAP, or INCONCLUSIVE"
    )
    risk_severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    recommendation: str = Field(description="Prescriptive Zero-Trust remediation action")
    basis: Optional[str] = Field(
        default=None,
        description="Evidence rationale explaining why this was categorized as verified, unexercised, or potential discrepancy"
    )
    policy_id: Optional[str] = Field(
        default=None,
        description="Associated IAM/ACL entitlement policy ID if known"
    )
    supporting_events_count: Optional[int] = Field(
        default=None,
        description="Number of empirical telemetry observations supporting this relationship"
    )


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
    disclaimer: str = Field(
        default="Unobserved grants represent dormant entitlements to review, not confirmed unnecessary privileges; unentitled observed connections represent potential policy discrepancies, not conclusive proof of malicious activity.",
        description="Interpretive guidance distinguishing discrepancies from confirmed compromise"
    )
    audit_scope: Dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata describing audit scope, filters, and entity context applied"
    )


class ZeroTrustAuditService:
    """
    Engine executing dual-graph relational comparison:
    Entitled Access (IAM) vs. Observed Usage (Telemetry).
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()

    def audit_access_entitlements(
        self,
        entity_id: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> ZeroTrustAuditResult:
        """
        Queries Neo4j for entitled vs observed subgraphs and derives
        the Zero-Trust divergence metrics with contextual principal, device, and resource matching.
        """
        # 1. Query all explicit permissions (Entitled Graph) and observed connections (Observed Usage Graph)
        try:
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
            observed_records = self.client.execute_query(
                """
                MATCH (s)-[r:OBSERVED_CONNECTION|LOGGED_IN_TO]->(t)
                RETURN s.id AS source_id, labels(s)[0] AS source_label,
                       t.id AS target_id, labels(t)[0] AS target_label,
                       coalesce(t.criticality, 'MEDIUM') AS target_criticality,
                       type(r) AS rel_type
                """
            )
        except Exception as e:
            logger.warning("Neo4j unreachable for Zero-Trust audit (%s); using in-memory mock client.", e)
            from backend.graphops.mock_client import get_mock_graphops_client
            mock_c = get_mock_graphops_client()
            entitled_records = mock_c.execute_query("MATCH (u:User)-[r:HAS_PERMISSION]->(t)")
            observed_records = mock_c.execute_query("MATCH (s)-[r:OBSERVED_CONNECTION|LOGGED_IN_TO]->(t)")

        # Index observed transitions: (source_id, target_id) -> count
        observed_pairs = set()
        observed_pair_counts: Dict[tuple, int] = {}
        for obs in observed_records:
            s_id = str(obs.get("source_id", "")).lower()
            t_id = str(obs.get("target_id", "")).lower()
            pair = (s_id, t_id)
            observed_pairs.add(pair)
            observed_pair_counts[pair] = observed_pair_counts.get(pair, 0) + 1

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

            # Is this permission verified by active usage (either directly by user or via their assigned device)?
            direct_active = (u_id, t_id) in observed_pairs
            device_active = bool(d_id and (d_id, t_id) in observed_pairs)
            is_active = direct_active or device_active

            obs_count = 0
            if direct_active:
                obs_count += observed_pair_counts.get((u_id, t_id), 0)
            if device_active and d_id:
                obs_count += observed_pair_counts.get((d_id, t_id), 0)

            if is_active:
                active_count += 1
                basis_desc = (
                    f"Entitlement verified by empirical telemetry "
                    f"({'direct user activity' if direct_active else 'assigned endpoint activity'})."
                )
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=ent.get("user_id"),
                        source_label=ent.get("user_label", "User"),
                        target_id=ent.get("target_id"),
                        target_label=ent.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type="HAS_PERMISSION",
                        status="ACTIVE_VERIFIED",
                        discrepancy_type="MATCHING_ACCESS",
                        risk_severity="LOW",
                        recommendation="Access is actively required and authorized. Maintain continuous behavioral baseline.",
                        basis=basis_desc,
                        policy_id=f"POL-IAM-{u_id[-6:] if len(u_id)>=6 else u_id}-{t_id[-6:] if len(t_id)>=6 else t_id}",
                        supporting_events_count=max(1, obs_count),
                    )
                )
            else:
                dormant_count += 1
                severity = "CRITICAL" if t_crit in ("CRITICAL", "HIGH") else "MEDIUM"
                rec_action = (
                    f"Review dormant entitlement '{ent.get('user_id')} -> {ent.get('target_id')}'. "
                    f"Identity has not exercised this privilege during the observation window; validate operational "
                    f"requirement before considering revocation (unobserved grants may represent contingency or scheduled access)."
                )
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=ent.get("user_id"),
                        source_label=ent.get("user_label", "User"),
                        target_id=ent.get("target_id"),
                        target_label=ent.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type="HAS_PERMISSION",
                        status="OVER_PRIVILEGED_DORMANT",
                        discrepancy_type="UNEXERCISED_GRANT",
                        risk_severity=severity,
                        recommendation=rec_action,
                        basis="Configured IAM entitlement has no recorded access telemetry during the observation window.",
                        policy_id=f"POL-IAM-{u_id[-6:] if len(u_id)>=6 else u_id}-{t_id[-6:] if len(t_id)>=6 else t_id}",
                        supporting_events_count=0,
                    )
                )
                recommended_revocations.append({
                    "revocation_id": f"REV-{len(recommended_revocations) + 1:03d}",
                    "identity": ent.get("user_id"),
                    "target_asset": ent.get("target_id"),
                    "criticality": t_crit,
                    "risk_reduction_impact": "HIGH" if t_crit in ("CRITICAL", "HIGH") else "MEDIUM",
                    "action": "REVIEW_OR_REVOKE_PERMISSION",
                    "justification": "Dormant entitlement unexercised during telemetry observation window; potential lateral exposure."
                })

        # 4. Evaluate Observed connections that lack formal entitlement (Shadow / Potential Discrepancy)
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
                rec_action = (
                    f"Investigate unentitled connection '{obs.get('source_id')} -> {obs.get('target_id')}'. "
                    f"Potential policy discrepancy or unmapped workflow; validate entitlement coverage or adjust segmentation "
                    f"(observed connections without matching grants indicate policy discrepancies, not conclusive proof of breach)."
                )
                access_items.append(
                    ZeroTrustAccessItem(
                        source_id=obs.get("source_id"),
                        source_label=s_label,
                        target_id=obs.get("target_id"),
                        target_label=obs.get("target_label", "Entity"),
                        target_criticality=t_crit,
                        access_type=obs.get("rel_type", "OBSERVED_CONNECTION"),
                        status="UNENTITLED_SHADOW",
                        discrepancy_type="POTENTIAL_UNENTITLED_ACCESS",
                        risk_severity=severity,
                        recommendation=rec_action,
                        basis="Empirical telemetry indicates network connection or logon without matching explicit HAS_PERMISSION grant.",
                        policy_id=None,
                        supporting_events_count=observed_pair_counts.get((s_id, t_id), 1),
                    )
                )

        # 5. Apply Optional Entity or Status Filters
        filtered_items = access_items
        if entity_id:
            target_eid = entity_id.strip().lower()
            filtered_items = [
                item for item in filtered_items
                if str(item.source_id).lower() == target_eid or str(item.target_id).lower() == target_eid
            ]
        if status_filter:
            s_filter = status_filter.strip().upper()
            filtered_items = [
                item for item in filtered_items
                if item.status.upper() == s_filter or item.discrepancy_type.upper() == s_filter
            ]

        total_entitled = len(entitled_records)
        compliance_pct = round((active_count / total_entitled * 100.0), 1) if total_entitled > 0 else 100.0
        risk_score = round(min(100.0, (dormant_count * 15.0) + (unentitled_count * 25.0)), 1)

        summary_narrative = (
            f"Zero-Trust Access Audit evaluated {total_entitled} granted permission(s) and {len(observed_records)} observed transition(s). "
            f"Found {active_count} active legitimate permission(s), {dormant_count} unexercised dormant entitlement(s), "
            f"and {unentitled_count} potential unentitled connection(s). Least-Privilege compliance is {compliance_pct}%, "
            f"with an overall lateral attack surface risk rating of {risk_score} / 100. "
            f"Note: Unexercised grants warrant review rather than automatic revocation; unentitled connections indicate policy discrepancies rather than confirmed compromises."
        )

        return ZeroTrustAuditResult(
            total_entitled_permissions=total_entitled,
            active_verified_permissions=active_count,
            dormant_overprivileged_permissions=dormant_count,
            unentitled_shadow_connections=unentitled_count,
            least_privilege_compliance_pct=compliance_pct,
            over_privilege_risk_score=risk_score,
            access_breakdown=filtered_items,
            recommended_revocations=recommended_revocations,
            zero_trust_summary=summary_narrative,
            disclaimer=(
                "Unobserved grants represent dormant entitlements to review, not confirmed unnecessary privileges; "
                "unentitled observed connections represent potential policy discrepancies, not conclusive proof of malicious activity."
            ),
            audit_scope={
                "filtered_by_entity": entity_id,
                "status_filter": status_filter,
                "total_items_returned": len(filtered_items),
                "total_unfiltered_items": len(access_items),
            },
        )


def get_zero_trust_service(client: Optional[Neo4jClient] = None) -> ZeroTrustAuditService:
    """Dependency injector for ZeroTrustAuditService."""
    return ZeroTrustAuditService(client=client)
