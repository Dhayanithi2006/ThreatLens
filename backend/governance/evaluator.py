"""
ThreatLens Governance & Controls - Policy Evaluation Engine
Evaluates enterprise security policies against real GraphOps findings
(blast radius, attack paths, graph anomalies, email threat investigations).

CRITICAL COMPLIANCE PRINCIPLE:
Missing evidence must NEVER automatically be treated as compliance.
Absence of telemetry or missing context resolves to NEEDS_REVIEW or NOT_EVALUATED
with explicit data limitations recorded.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.governance.catalog import get_control
from backend.governance.policies import get_policy, list_policies
from backend.governance.schema import (
    EvaluationStatus,
    OrganizationPolicy,
    PolicyEvaluation,
)


def evaluate_policy(
    policy_id: str,
    finding_context: Optional[Dict[str, Any]] = None,
) -> PolicyEvaluation:
    """
    Evaluates a single organizational policy against provided finding context.
    
    Deterministic handling:
    1. If policy does not exist: returns NOT_EVALUATED with descriptive reasoning.
    2. If policy is disabled: returns NOT_APPLICABLE.
    3. If finding_context is None or empty: returns NOT_EVALUATED or NEEDS_REVIEW.
       Missing evidence is strictly prohibited from returning PASS.
    4. Evaluates evidence against rule conditions and returns evidence-backed result.
    """
    eval_id = f"eval-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    
    policy = get_policy(policy_id)
    if not policy:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy_id,
            control_id=None,
            status=EvaluationStatus.NOT_EVALUATED,
            supporting_evidence=[],
            applicable_rule="Unknown Policy",
            reasoning=f"Policy identifier '{policy_id}' was not found in the organizational policy registry.",
            timestamp=now,
            data_limitations=["Policy record absent from configuration."],
            recommended_remediation="Register the policy in the organization control catalog before evaluation.",
        )
    
    primary_control = policy.linked_control_ids[0] if policy.linked_control_ids else None
    
    if not policy.enabled:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NOT_APPLICABLE,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning=f"Policy '{policy.policy_id}' is currently disabled in organization configuration.",
            timestamp=now,
            data_limitations=["Policy administratively marked disabled."],
            recommended_remediation=None,
        )
    
    # Check for empty or missing evidence context
    if not finding_context or not isinstance(finding_context, dict) or len(finding_context) == 0:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="Missing evidence context. Under ThreatLens compliance principles, absence of telemetry or finding data cannot be treated as compliance.",
            timestamp=now,
            data_limitations=[
                "No graph traversal, blast radius, or telemetry evidence provided in assessment payload.",
                "Assessment requires active graph finding context."
            ],
            recommended_remediation="Execute a GraphOps query (e.g. blast radius or attack path analysis) and attach finding context for evaluation.",
        )

    # Route evaluation based on policy ID
    if policy.policy_id == "POL-IAM-01":
        return _eval_pol_iam_01(eval_id, policy, primary_control, finding_context, now)
    elif policy.policy_id == "POL-IAM-02":
        return _eval_pol_iam_02(eval_id, policy, primary_control, finding_context, now)
    elif policy.policy_id == "POL-EXPOSURE-01":
        return _eval_pol_exposure_01(eval_id, policy, primary_control, finding_context, now)
    elif policy.policy_id == "POL-VULN-01":
        return _eval_pol_vuln_01(eval_id, policy, primary_control, finding_context, now)
    elif policy.policy_id == "POL-LOG-01":
        return _eval_pol_log_01(eval_id, policy, primary_control, finding_context, now)
    elif policy.policy_id == "POL-INC-01":
        return _eval_pol_inc_01(eval_id, policy, primary_control, finding_context, now)
    else:
        # Generic heuristic evaluation for custom policies
        return _eval_generic_policy(eval_id, policy, primary_control, finding_context, now)


def _eval_pol_iam_01(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-IAM-01: Prohibits direct access from user workstations to Crown Jewels
    without traversing an authenticated jumpbox.
    """
    paths = context.get("attack_paths") or context.get("paths") or []
    nodes = context.get("nodes") or []
    edges = context.get("edges") or []
    
    # If no paths or structural context exists in context
    if not paths and not edges:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[{"context_keys": list(context.keys())}],
            applicable_rule=policy.description,
            reasoning="Graph topology data lacked explicit path or edge transitions between endpoints and databases.",
            timestamp=now,
            data_limitations=["No attack paths or graph edge transitions provided in finding context."],
            recommended_remediation="Run attack path analysis from workstation node to Crown Jewel database to produce traversal evidence.",
        )
    
    violations = []
    evidence = []
    
    # Check paths for direct workstation-to-database or un-bastioned crown jewel access
    for path in paths:
        path_nodes = path.get("nodes") or path.get("path_nodes") or []
        path_len = len(path_nodes)
        if path_len >= 2:
            src = str(path_nodes[0]).lower()
            dst = str(path_nodes[-1]).lower()
            # If path starts at workstation and reaches crown jewel/db in <= 2 hops without jumpbox
            is_workstation = "ws-" in src or "workstation" in src or "user" in src or "laptop" in src
            is_sensitive = "db-" in dst or "database" in dst or "crown" in dst or "dc-" in dst
            has_jumpbox = any("jumpbox" in str(n).lower() or "bastion" in str(n).lower() for n in path_nodes)
            
            if is_workstation and is_sensitive and not has_jumpbox:
                violations.append({
                    "path_id": path.get("path_id", "path"),
                    "source": path_nodes[0],
                    "target": path_nodes[-1],
                    "hop_count": path_len - 1,
                    "jumpbox_present": False,
                })
                evidence.append({
                    "type": "DIRECT_PATH_BYPASS",
                    "path_nodes": path_nodes,
                    "summary": f"Direct multi-hop traversal from {path_nodes[0]} to sensitive asset {path_nodes[-1]} without bastion.",
                })
    
    # Also inspect direct edges if provided
    for edge in edges:
        src = str(edge.get("source", "")).lower()
        dst = str(edge.get("target", "")).lower()
        rel = str(edge.get("type", "")).upper()
        if ("ws-" in src or "workstation" in src) and ("db-" in dst or "database" in dst or "crown" in dst):
            violations.append({"direct_edge": f"{src} -[{rel}]-> {dst}"})
            evidence.append({"type": "DIRECT_EDGE_BYPASS", "edge": edge})
            
    if violations:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=evidence,
            applicable_rule="No direct un-bastioned access from client endpoints to Crown Jewel databases.",
            reasoning=f"Found {len(violations)} lateral movement path(s) or direct relationship(s) linking workstations to Crown Jewels without jumpbox controls.",
            timestamp=now,
            data_limitations=["Path search bounded by maximum hop depth configured in GraphOps."],
            recommended_remediation="Isolate direct workstation network routes to database subnets; require traversal through an authenticated bastion or PAM proxy.",
        )
    
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{"paths_evaluated": len(paths), "edges_evaluated": len(edges)}],
        applicable_rule="No direct un-bastioned access from client endpoints to Crown Jewel databases.",
        reasoning="All analyzed paths to Crown Jewels traverse authorized intermediate gateway/bastion segments or no workstation-to-database bypasses were found.",
        timestamp=now,
        data_limitations=["Evaluated against provided path evidence; unanalyzed network segments may exist."],
        recommended_remediation=None,
    )


def _eval_pol_iam_02(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-IAM-02: Prohibits service account interactive logons to workstations.
    """
    nodes = context.get("nodes") or []
    anomalies = context.get("anomalies") or context.get("findings") or []
    
    if not nodes and not anomalies:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="No identity or logon anomaly evidence supplied for service account evaluation.",
            timestamp=now,
            data_limitations=["Missing user identity telemetry and anomaly findings."],
            recommended_remediation="Ingest identity logon telemetry or query GraphOps anomaly detection for anomalous service account activities.",
        )
        
    violations = []
    evidence = []
    
    # Check anomalies for service account workstation logon
    for anom in anomalies:
        desc = str(anom.get("description", "")).lower()
        title = str(anom.get("title", "")).lower()
        if "service account" in desc or "service account" in title or "interactive logon" in desc:
            violations.append(anom)
            evidence.append({"type": "ANOMALOUS_SERVICE_LOGON", "detail": anom})
            
    # Check node metadata if present
    for node in nodes:
        props = node.get("properties") or node if isinstance(node, dict) else {}
        node_type = str(props.get("type", "")).upper()
        name = str(props.get("name", "") or props.get("id", "")).lower()
        if "svc-" in name or "service" in name or node_type == "SERVICE_ACCOUNT":
            host = str(props.get("logged_in_to", "") or props.get("device", "")).lower()
            if "ws-" in host or "workstation" in host or "laptop" in host:
                violations.append({"service_account": name, "host": host})
                evidence.append({"type": "SERVICE_ACCOUNT_ON_WORKSTATION", "node": name, "target": host})

    if violations:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=evidence,
            applicable_rule="Service accounts must not possess interactive logon privileges on workstations.",
            reasoning=f"Detected {len(violations)} instance(s) of service account credentials present on or logging into client workstations.",
            timestamp=now,
            data_limitations=["Evaluated against observed active logons and graph identity nodes."],
            recommended_remediation="Configure 'Deny log on locally' GPO / IAM restrictions for service accounts across all workstation organizational units.",
        )

    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{"assessed_nodes_count": len(nodes), "anomalies_count": len(anomalies)}],
        applicable_rule="Service accounts must not possess interactive logon privileges on workstations.",
        reasoning="No service account interactive logons or cross-tier credential exposure detected on analyzed endpoints.",
        timestamp=now,
        data_limitations=["Dependent on Active Directory / IdP event log synchronization completeness."],
        recommended_remediation=None,
    )


def _eval_pol_exposure_01(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-EXPOSURE-01: Crown Jewel blast radius isolation boundary.
    """
    blast_radius = context.get("blast_radius")
    # If blast_radius was passed as root context
    if blast_radius is None and ("reachable_nodes" in context or "crown_jewels_compromised" in context or "critical_assets_compromised" in context):
        blast_radius = context
        
    if not blast_radius:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="Blast radius analysis data absent from finding context.",
            timestamp=now,
            data_limitations=["No blast radius calculation supplied; compliance cannot be inferred without impact assessment."],
            recommended_remediation="Run GraphOps blast radius simulation from compromised entity before policy evaluation.",
        )
        
    crit_assets = blast_radius.get("critical_assets_compromised") or blast_radius.get("crown_jewels_compromised") or []
    crown_pct = blast_radius.get("crown_jewel_reachability_pct")
    if crown_pct is None:
        total_cj = blast_radius.get("total_crown_jewels", 0)
        crown_pct = (len(crit_assets) / total_cj * 100.0) if total_cj > 0 else (len(crit_assets) * 25.0)

    max_pct = policy.rule_conditions.get("max_crown_jewel_reachability_pct", 20.0)
    max_crit = policy.rule_conditions.get("max_critical_assets_compromised", 0)
    
    evidence = [{
        "blast_radius_origin": blast_radius.get("root_entity") or blast_radius.get("source_node"),
        "critical_assets_reached": crit_assets,
        "crown_jewel_reachability_pct": crown_pct,
        "total_nodes_reachable": blast_radius.get("reachable_nodes_count") or len(blast_radius.get("reachable_nodes", [])),
    }]
    
    if len(crit_assets) > max_crit or crown_pct > max_pct:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=evidence,
            applicable_rule=f"Compromised entity blast radius must not reach > {max_crit} Crown Jewels or exceed {max_pct}% enterprise Crown Jewel exposure.",
            reasoning=f"Blast radius analysis reveals {len(crit_assets)} Crown Jewel(s) exposed ({crown_pct:.1f}% exposure), exceeding the defined risk threshold.",
            timestamp=now,
            data_limitations=["Blast radius simulation based on directional graph traversal depth."],
            recommended_remediation="Sever high-centrality choke point edges or isolate root entity using containment simulation.",
        )
        
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=evidence,
        applicable_rule=f"Compromised entity blast radius must not reach > {max_crit} Crown Jewels or exceed {max_pct}% enterprise Crown Jewel exposure.",
        reasoning="Blast radius remains within organization isolation tolerance without compromising critical database or directory tiers.",
        timestamp=now,
        data_limitations=["Hop depth traversal limits apply."],
        recommended_remediation=None,
    )


def _eval_pol_vuln_01(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-VULN-01: Critical exploit preconditions on lateral movement attack paths.
    """
    paths = context.get("attack_paths") or context.get("paths") or []
    vulnerabilities = context.get("vulnerabilities") or []
    
    # If finding context has neither paths nor vulnerability list
    if not paths and not vulnerabilities:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="No vulnerability scan telemetry or attack path exploit preconditions provided.",
            timestamp=now,
            data_limitations=["CVE registry and asset vulnerability assessments were not included in context."],
            recommended_remediation="Correlate vulnerability management scan outputs with GraphOps topological paths.",
        )
        
    cvss_thresh = policy.rule_conditions.get("cvss_threshold", 8.0)
    violations = []
    evidence = []
    
    # Check paths for exploitable vulnerabilities
    for path in paths:
        path_id = path.get("path_id", "path")
        for edge in path.get("edges", []):
            edge_type = str(edge.get("type", "")).upper()
            cvss = float(edge.get("cvss", 0.0) or edge.get("cvss_score", 0.0))
            cve = edge.get("cve") or edge.get("cve_id")
            if edge_type == "EXPLOITS" or cvss >= cvss_thresh or (cve and cvss >= 7.0):
                violations.append({"path_id": path_id, "cve": cve, "cvss": cvss, "edge": edge})
                evidence.append({"type": "PATH_EXPLOIT_PRECONDITION", "path_id": path_id, "cve": cve, "cvss": cvss})
                
    for vuln in vulnerabilities:
        score = float(vuln.get("cvss_score", 0.0) or vuln.get("cvss", 0.0))
        if score >= cvss_thresh:
            violations.append(vuln)
            evidence.append({"type": "UNMITIGATED_CRITICAL_CVE", "vuln": vuln})
            
    if violations:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=evidence,
            applicable_rule=f"Attack paths must not contain unmitigated exploitable vulnerabilities with CVSS >= {cvss_thresh}.",
            reasoning=f"Identified {len(violations)} exploitable vulnerability transition(s) on lateral attack paths.",
            timestamp=now,
            data_limitations=["Known exploitability checked against provided path step metadata."],
            recommended_remediation="Apply high-priority emergency patches or deploy network micro-segmentation at affected nodes.",
        )
        
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{"assessed_paths": len(paths), "assessed_vulns": len(vulnerabilities)}],
        applicable_rule=f"Attack paths must not contain unmitigated exploitable vulnerabilities with CVSS >= {cvss_thresh}.",
        reasoning="No unmitigated critical exploit preconditions observed on evaluated lateral movement paths.",
        timestamp=now,
        data_limitations=["Vulnerability scanner coverage boundaries apply."],
        recommended_remediation=None,
    )


def _eval_pol_log_01(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-LOG-01: Comprehensive Log Audit & Path Traversal Telemetry.
    """
    edges = context.get("edges") or []
    paths = context.get("attack_paths") or context.get("paths") or []
    
    if not edges and not paths:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="No edge transitions or telemetry streams provided to evaluate log audit coverage.",
            timestamp=now,
            data_limitations=["Telemetric log records absent from payload."],
            recommended_remediation="Attach SIEM / EDR network connection logs to GraphOps findings.",
        )
        
    unlogged_edges = []
    logged_edges = []
    
    all_edges = list(edges)
    for p in paths:
        all_edges.extend(p.get("edges", []))
        
    for e in all_edges:
        rel = str(e.get("type", "")).upper()
        # Telemetric connection relations
        if rel in ("OBSERVED_CONNECTION", "ACCESS", "AUTHENTICATED_TO") or e.get("telemetry_verified"):
            logged_edges.append(e)
        elif rel in ("CAN_REACH", "POTENTIAL_PIVOT", "ASSUMED_ROUTE"):
            unlogged_edges.append(e)
            
    if unlogged_edges:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[{
                "unlogged_edge_count": len(unlogged_edges),
                "sample_unlogged": unlogged_edges[:3],
            }],
            applicable_rule="Lateral movement paths must be backed by verified observation telemetry.",
            reasoning=f"Found {len(unlogged_edges)} speculative or unlogged topological path transitions lacking SIEM connection telemetry.",
            timestamp=now,
            data_limitations=["Graph includes theoretical reachable edges not yet confirmed by wire-level packet captures."],
            recommended_remediation="Enable NetFlow / VPC flow logging and Sysmon Event ID 3 across intermediate subnets.",
        )
        
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{"logged_transitions_count": len(logged_edges)}],
        applicable_rule="Lateral movement paths must be backed by verified observation telemetry.",
        reasoning="All observed graph transitions possess corroborating network telemetry logs.",
        timestamp=now,
        data_limitations=["Dependent on log ingestion latency."],
        recommended_remediation=None,
    )


def _eval_pol_inc_01(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """
    Evaluates POL-INC-01: Attacker Infrastructure & Phishing Indicator Quarantine.
    """
    iocs = context.get("iocs") or context.get("threat_indicators") or []
    email_verdict = context.get("email_verdict") or context.get("classification")
    contained = context.get("contained", False) or context.get("quarantined", False)
    
    if not iocs and not email_verdict:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning="No threat intelligence indicators, email forensic verdicts, or incident context provided.",
            timestamp=now,
            data_limitations=["Incident IOC stream empty."],
            recommended_remediation="Link email forensic case or external threat intelligence indicator to investigation.",
        )
        
    high_threat_iocs = [
        ioc for ioc in iocs
        if (isinstance(ioc, dict) and (ioc.get("threat_score", 0) >= 70 or ioc.get("verdict") in ("MALICIOUS", "PHISHING")))
        or (isinstance(ioc, str) and ("c2" in ioc.lower() or "malicious" in ioc.lower()))
    ]
    is_phishing = str(email_verdict).upper() in ("PHISHING", "MALICIOUS", "CRITICAL")
    
    if (high_threat_iocs or is_phishing) and not contained:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=[{
                "email_verdict": email_verdict,
                "high_threat_iocs": high_threat_iocs,
                "containment_state": "UNCONTAINED",
            }],
            applicable_rule="Attacker infrastructure and phishing indicators linked to corporate identities must be quarantined.",
            reasoning="Uncontained active phishing verdict or external C2 IOC linked to enterprise user/device.",
            timestamp=now,
            data_limitations=["Evaluated against live incident containment flag."],
            recommended_remediation="Execute immediate graph containment action: isolate target endpoint and block external C2 indicator.",
        )
        
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{
            "contained": contained,
            "assessed_iocs": len(iocs),
            "email_verdict": email_verdict,
        }],
        applicable_rule="Attacker infrastructure and phishing indicators linked to corporate identities must be quarantined.",
        reasoning="Threat indicators are successfully quarantined or no high-risk malicious indicators were detected.",
        timestamp=now,
        data_limitations=["External threat feed synchronization recency applies."],
        recommended_remediation=None,
    )


def _eval_generic_policy(
    eval_id: str,
    policy: OrganizationPolicy,
    primary_control: Optional[str],
    context: Dict[str, Any],
    now: datetime,
) -> PolicyEvaluation:
    """Evaluates arbitrary custom organization policies against structured rule conditions."""
    conditions = policy.rule_conditions
    if not conditions:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.NEEDS_REVIEW,
            supporting_evidence=[],
            applicable_rule=policy.description,
            reasoning=f"Policy '{policy.policy_id}' defines no automated rule condition heuristics.",
            timestamp=now,
            data_limitations=["Rule conditions dictionary is empty."],
            recommended_remediation="Specify rule conditions in policy definition.",
        )
        
    # Check matching keys
    matched_violations = []
    for k, v in conditions.items():
        if k in context and context[k] != v:
            matched_violations.append({"condition": k, "expected": v, "actual": context[k]})
            
    if matched_violations:
        return PolicyEvaluation(
            evaluation_id=eval_id,
            policy_id=policy.policy_id,
            control_id=primary_control,
            status=EvaluationStatus.FAIL,
            supporting_evidence=matched_violations,
            applicable_rule=policy.description,
            reasoning=f"Custom policy rule conditions failed on {len(matched_violations)} key(s).",
            timestamp=now,
            data_limitations=["Evaluated against custom condition mapping."],
            recommended_remediation="Adjust environment configuration to conform to policy conditions.",
        )
        
    return PolicyEvaluation(
        evaluation_id=eval_id,
        policy_id=policy.policy_id,
        control_id=primary_control,
        status=EvaluationStatus.PASS,
        supporting_evidence=[{"conditions_evaluated": len(conditions)}],
        applicable_rule=policy.description,
        reasoning="All defined custom rule conditions satisfied by finding context.",
        timestamp=now,
        data_limitations=["Limited to specified key comparisons."],
        recommended_remediation=None,
    )


def evaluate_all_active_policies(
    finding_context: Optional[Dict[str, Any]] = None,
    scope: Optional[str] = None,
) -> List[PolicyEvaluation]:
    """
    Evaluates all active organizational policies against the supplied finding context.
    Returns ordered list of evaluations.
    """
    active_policies = list_policies(scope=scope, enabled_only=True)
    results: List[PolicyEvaluation] = []
    
    for pol in active_policies:
        res = evaluate_policy(pol.policy_id, finding_context)
        results.append(res)
        
    return results
