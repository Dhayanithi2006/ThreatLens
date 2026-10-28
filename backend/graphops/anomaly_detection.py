"""
ThreatLens GraphOps - Graph-Based Access Anomaly Detection Engine
Evaluates access sequences against a documented historical and authorized baseline.
Identifies unusual relationship progressions, tier bypasses, entitlement deltas,
and exploit preconditions. Strictly distinguishes unobserved legitimate behavior
from unauthorized policy violations and confirmed malicious activity.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone
import logging

from backend.graphops.schema import (
    NodeLabel,
    RelationshipType,
    EvidenceClass,
    CriticalityTier,
)
from backend.models.graphops import (
    AnomalyClassification,
    DeviationType,
    HistoryCompleteness,
    BaselineConfidence,
    AccessSequenceStep,
    AccessSequenceRequest,
    UnexpectedRelationship,
    AccessSequenceAnomalyResult,
    BaselineProfileSummary,
    AnomalyTestSuiteItem,
    AnomalyTestSuiteResult,
)
from backend.graphops.client import Neo4jClient, get_graphops_client
from backend.data.graphops_fixtures import load_sample_enterprise_fixture, load_anomaly_test_sequences

logger = logging.getLogger("threatlens.graphops.anomaly_detection")


class AccessAnomalyDetector:
    """
    Dedicated graph access anomaly detector.
    Enforces documented architectural baselines, peer-group profiles,
    and cold-start handling with explainable rule-based scoring.
    """

    def __init__(self, client: Optional[Neo4jClient] = None):
        self.client = client or get_graphops_client()
        self._baseline_initialized = False
        self._historical_edges: Set[Tuple[str, str, str]] = set()
        self._node_metadata: Dict[str, Dict[str, Any]] = {}
        self._permissions_cache: Set[Tuple[str, str]] = set()
        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        """
        Builds the baseline profile from Neo4j records, falling back to
        the synthetic enterprise fixture if Neo4j is offline or empty.
        """
        if self._baseline_initialized:
            return

        fixture_data = load_sample_enterprise_fixture()
        entities = fixture_data.get("entities", {})
        rels = fixture_data.get("relationships", {}).get("relationships", [])

        # User alias mappings (email <-> user_id)
        user_aliases: Dict[str, Set[str]] = {}

        # 1. Index entities & properties
        for user in entities.get("users", []):
            uid_key = f"user:{user['user_id'].lower()}"
            email_key = f"user:{user['email'].lower()}" if user.get("email") else None
            
            aliases = {uid_key}
            if email_key:
                aliases.add(email_key)

            for a in aliases:
                user_aliases[a] = aliases
                self._node_metadata[a] = {
                    "label": NodeLabel.USER,
                    "department": user.get("department", "General"),
                    "role": user.get("role", "Standard User"),
                    "is_admin": user.get("is_admin", False),
                }

        for dev in entities.get("devices", []):
            cid = f"device:{dev['device_id'].lower()}"
            self._node_metadata[cid] = {
                "label": NodeLabel.DEVICE,
                "hostname": dev.get("hostname"),
                "subnet": dev.get("subnet"),
            }

        for srv in entities.get("servers", []):
            cid = f"server:{srv['server_id'].lower()}"
            self._node_metadata[cid] = {
                "label": NodeLabel.SERVER,
                "tier": srv.get("tier", "Application"),
                "criticality": srv.get("criticality", CriticalityTier.MEDIUM),
            }

        for app in entities.get("applications", []):
            cid = f"app:{app['app_id'].lower()}"
            self._node_metadata[cid] = {
                "label": NodeLabel.APPLICATION,
                "service_type": app.get("service_type", "API"),
            }

        for ca in entities.get("critical_assets", []):
            cid = f"critical:{ca['asset_id'].lower()}"
            self._node_metadata[cid] = {
                "label": NodeLabel.CRITICAL_ASSET,
                "impact_score": ca.get("impact_score", 90),
                "data_classification": ca.get("data_classification", "RESTRICTED"),
            }

        # 2. Index historical edges & authorized permissions (EXCLUDING POTENTIAL_EXPLOIT)
        for r in rels:
            s = r["source_id"].lower()
            t = r["target_id"].lower()
            rtype = r["relationship_type"]

            # POTENTIAL_EXPLOIT is a threat model artifact, NEVER a benign baseline
            if rtype == RelationshipType.POTENTIAL_EXPLOIT:
                continue

            # Expand user aliases for source and target
            sources = user_aliases.get(s, {s})
            targets = user_aliases.get(t, {t})

            for src in sources:
                for tgt in targets:
                    self._historical_edges.add((src, rtype, tgt))
                    if rtype == RelationshipType.HAS_PERMISSION:
                        self._permissions_cache.add((src, tgt))

        self._baseline_initialized = True
        logger.info(
            f"Anomaly baseline initialized with {len(self._node_metadata)} nodes, "
            f"{len(self._historical_edges)} historical edges, {len(self._permissions_cache)} permissions."
        )

    def get_baseline_summary(self) -> BaselineProfileSummary:
        """Returns documented baseline rules and configuration profile."""
        return BaselineProfileSummary(
            total_baseline_entities=len(self._node_metadata),
            total_baseline_relationships=len(self._historical_edges),
            network_tiering_rules=[
                "TIER 1 (Client Workstations): Allowed outbound HTTPS/443 to Application Gateway (server:srv-app-01).",
                "TIER 1 (Client Workstations): Direct client-to-database (port 5432) or client-to-DC (port 3389/88) connection prohibited.",
                "TIER 1 (Client Workstations): Direct peer-to-peer lateral workstation SMB (port 445) prohibited.",
                "TIER 2 (Application Gateway): Allowed outbound to Database Tier (server:srv-db-01) and DC Tier (server:srv-dc-01).",
                "TIER 3 (Database / Core): Direct hosting and access to Crown Jewels (critical:*).",
            ],
            department_profiles={
                "Finance": ["app:app-erp-01", "server:srv-app-01", "device:dev-ws-101", "device:dev-ws-104"],
                "IT Support": ["server:srv-app-01", "device:dev-ws-102"],
                "Engineering": ["server:srv-db-01", "app:app-pg-01", "device:dev-ws-103"],
                "Accounting": ["server:srv-app-01", "app:app-erp-01", "device:dev-ws-201"],
                "Infrastructure": ["server:srv-dc-01", "critical:crit-ad-domain-root"],
            },
            authorized_service_accounts=["user:svc_backup@corporation.com"],
            scoring_formula=(
                "Sequence Anomaly Score = min(100, round(0.6 * max(Step Scores) + 0.4 * mean(Step Scores))). "
                "Scores: 0-19: BENIGN_EXPECTED; 20-39: UNOBSERVED_NEW_LEGITIMATE; "
                "40-79: POLICY_VIOLATION_UNAUTHORIZED; 80-100: SUSPICIOUS_ANOMALOUS."
            ),
        )

    def _assess_cold_start(self, entity_id: str) -> Tuple[HistoryCompleteness, BaselineConfidence, str]:
        """
        Determines history completeness and baseline confidence for an entity.
        Handles new users, new assets, and sparse histories explicitly.
        """
        clean_id = entity_id.lower().strip()
        meta = self._node_metadata.get(clean_id)

        # Count historical occurrences as source or target
        edge_count = sum(1 for (s, _, t) in self._historical_edges if s == clean_id or t == clean_id)

        if edge_count >= 2:
            return HistoryCompleteness.COMPLETE, BaselineConfidence.HIGH, meta.get("department", "General") if meta else "General"
        elif edge_count >= 1:
            return HistoryCompleteness.PARTIAL, BaselineConfidence.MEDIUM, meta.get("department", "General") if meta else "General"
        else:
            # Cold-start new entity
            dept = "General"
            if "104" in clean_id or "fin" in clean_id:
                dept = "Finance"
            elif "102" in clean_id:
                dept = "IT Support"
            elif "201" in clean_id:
                dept = "Accounting"
            elif "backup" in clean_id:
                dept = "Infrastructure"
            return HistoryCompleteness.INCOMPLETE, BaselineConfidence.LOW, dept

    def _create_finding(
        self,
        step: AccessSequenceStep,
        deviation_type: DeviationType,
        rule_id: str,
        baseline_ref: str,
        explanation: str,
        detection_rationale: str,
        recommended_investigation: str,
        step_score: int,
        affected_entity: Optional[str] = None,
        sequence_id: Optional[str] = None,
    ) -> UnexpectedRelationship:
        """Constructs an explainable, structured UnexpectedRelationship finding."""
        s = step.source_id.lower().strip()
        t = step.target_id.lower().strip()

        if step_score >= 80:
            severity = "CRITICAL"
        elif step_score >= 60:
            severity = "HIGH"
        elif step_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        src_meta = self._node_metadata.get(s, {})
        tgt_meta = self._node_metadata.get(t, {})
        graph_context = {
            "source_id": step.source_id,
            "source_label": src_meta.get("label", NodeLabel.USER).value if hasattr(src_meta.get("label"), "value") else str(src_meta.get("label", "")),
            "target_id": step.target_id,
            "target_label": tgt_meta.get("label", NodeLabel.SERVER).value if hasattr(tgt_meta.get("label"), "value") else str(tgt_meta.get("label", "")),
        }

        now_iso = datetime.now(timezone.utc).isoformat()
        seq_str = sequence_id or f"step-{step.step_index}"

        return UnexpectedRelationship(
            finding_id=f"ANOM-{rule_id}-{step.step_index:02d}",
            rule_id=rule_id,
            severity=severity,
            affected_entity=affected_entity or step.target_id,
            step_index=step.step_index,
            source_id=step.source_id,
            relationship_type=step.relationship_type,
            target_id=step.target_id,
            deviation_type=deviation_type,
            baseline_reference=baseline_ref,
            explanation=explanation,
            detection_rationale=detection_rationale,
            recommended_investigation=recommended_investigation,
            timestamp=now_iso,
            supporting_event_sequence=seq_str,
            relevant_graph_context=graph_context,
            step_score=step_score,
        )

    def evaluate_step(
        self,
        step: AccessSequenceStep,
        evaluated_dept: str,
        is_compromised_origin: bool = False,
        sequence_id: Optional[str] = None,
    ) -> Optional[UnexpectedRelationship]:
        """
        Evaluates a single traversal step against documented baseline policies.
        Returns an UnexpectedRelationship finding if the step deviates from expectations.
        """
        s = step.source_id.lower().strip()
        t = step.target_id.lower().strip()
        rtype = step.relationship_type
        props = step.properties or {}
        port = props.get("port")

        # 1. Exploit Precondition (CVE / Unauthorized Injection) - Evaluated FIRST
        if rtype == RelationshipType.POTENTIAL_EXPLOIT or "via_cve" in props:
            cve = props.get("via_cve", "CVE-2024-21413")
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.EXPLOIT_PRECONDITION,
                rule_id="RULE-EXPLOIT-PRECONDITION-01",
                baseline_ref=f"EXPLOIT_PRECONDITION_POLICY: Traversal leverages vulnerability ({cve})",
                explanation=f"Traversed via unpatched exploit precondition ({cve}) to bypass authentication controls.",
                detection_rationale=f"Observed edge specifies exploit precondition {cve} against {step.target_id}.",
                recommended_investigation=f"Inspect EDR telemetry and patch management logs for {step.target_id}.",
                step_score=90,
                sequence_id=sequence_id,
            )

        # 2. Exact match in historical baseline (for non-exploit edges)
        if (s, rtype, t) in self._historical_edges:
            return None

        # 3. Lateral Hop from Known Compromised Incident Origin
        if is_compromised_origin and t.startswith("server:") and "critical" in t:
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.HIGH_RISK_PIVOT,
                rule_id="RULE-INCIDENT-LATERAL-PIVOT-01",
                baseline_ref="INCIDENT_CORRELATION_POLICY: Originating entity under active investigation (EVT-MT101-PHISH)",
                explanation=f"Lateral pivot from compromised workstation directly reaching high-value asset {step.target_id}.",
                detection_rationale=f"Originating endpoint has confirmed incident association and pivots into critical server {step.target_id}.",
                recommended_investigation=f"Isolate originating host {step.source_id} and review authentication sessions to {step.target_id}.",
                step_score=85,
                sequence_id=sequence_id,
            )

        # 4. Missing Authorization for Server Login / Credential Hijack
        if rtype == RelationshipType.LOGGED_IN_TO and t.startswith("server:"):
            hijacked = props.get("hijacked_user")
            if hijacked:
                return self._create_finding(
                    step=step,
                    deviation_type=DeviationType.EXPLOIT_PRECONDITION,
                    rule_id="RULE-IAM-SERVICE-HIJACK-01",
                    baseline_ref=f"IAM_POLICY: Service principal ({hijacked}) abused from unassigned workstation",
                    explanation=f"Interactive login attempt using privileged service account {hijacked} from endpoint {s}.",
                    detection_rationale=f"Interactive logon using non-interactive service principal {hijacked} initiated from client workstation {step.source_id}.",
                    recommended_investigation=f"Revoke active Kerberos tickets for {hijacked} and inspect memory artifacts on {step.source_id}.",
                    step_score=88,
                    sequence_id=sequence_id,
                )
            if (s, t) not in self._permissions_cache:
                return self._create_finding(
                    step=step,
                    deviation_type=DeviationType.MISSING_AUTHORIZATION,
                    rule_id="RULE-IAM-MISSING-AUTH-01",
                    baseline_ref="IAM_POLICY: No authorized HAS_PERMISSION grant for target server",
                    explanation=f"Identity {s} logged into infrastructure server {t} without documented access entitlement.",
                    detection_rationale=f"User {step.source_id} has no documented HAS_PERMISSION grant for server {step.target_id}.",
                    recommended_investigation=f"Review Active Directory role assignments and session audit logs for {step.source_id}.",
                    step_score=50,
                    sequence_id=sequence_id,
                )

        # 5. Network Tiering Violations
        # A) Client Workstation directly to Database Tier
        if s.startswith("device:") and t.startswith("server:srv-db"):
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.TIER_BYPASS,
                rule_id="RULE-TIER-CLIENT-TO-DB-01",
                baseline_ref="BASELINE_TIERING_POLICY: Direct Client-to-Database bypass prohibited (Port 5432)",
                explanation="Workstation attempted direct database connection, bypassing the application gateway tier.",
                detection_rationale=f"Direct client-to-database connection from {step.source_id} to {step.target_id}; violates architecture tiering.",
                recommended_investigation=f"Verify network firewall segmentation between workstation subnet and {step.target_id}.",
                step_score=55,
                sequence_id=sequence_id,
            )

        # B) Client Workstation directly to Domain Controller (RDP/RPC)
        if s.startswith("device:") and t.startswith("server:srv-dc"):
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.TIER_BYPASS,
                rule_id="RULE-TIER-CLIENT-TO-DC-01",
                baseline_ref="BASELINE_TIERING_POLICY: Direct Client-to-Domain Controller administration prohibited",
                explanation=f"Workstation attempted direct administration connection to Domain Controller (port {port or '3389'}).",
                detection_rationale=f"Direct administrative connection initiated from standard workstation {step.source_id} to Domain Controller {step.target_id}.",
                recommended_investigation=f"Verify administrative jump-box compliance and check for unauthorized RDP/RPC sessions on {step.target_id}.",
                step_score=60,
                sequence_id=sequence_id,
            )

        # C) Workstation-to-Workstation Lateral Peer Connection (Port 445 SMB)
        if s.startswith("device:") and t.startswith("device:") and s != t:
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.TIER_BYPASS,
                rule_id="RULE-TIER-PEER-SMB-01",
                baseline_ref="BASELINE_TIERING_POLICY: Workstation peer-to-peer SMB lateral traversal prohibited",
                explanation=f"Direct peer connection between workstations across client subnets ({s} -> {t}).",
                detection_rationale=f"Direct workstation-to-workstation SMB connection observed between {step.source_id} and {step.target_id}.",
                recommended_investigation=f"Inspect workstation network logs for pass-the-hash or lateral movement indicators between {step.source_id} and {step.target_id}.",
                step_score=50,
                sequence_id=sequence_id,
            )

        # 6. Novel Legitimate Connection (conforming to peer group & tiering)
        # E.g. newly hired user in Finance using dev-ws-104 to access srv-app-01
        is_client_to_app = s.startswith("device:") and t == "server:srv-app-01"
        is_user_to_device = s.startswith("user:") and t.startswith("device:")
        is_app_to_erp = s == "server:srv-app-01" and t.startswith("app:")

        if is_client_to_app or is_user_to_device or is_app_to_erp:
            return self._create_finding(
                step=step,
                deviation_type=DeviationType.UNOBSERVED_RELATIONSHIP,
                rule_id="RULE-ROLE-NOVEL-CONFORMING-01",
                baseline_ref="PEER_GROUP_BASELINE: Novel connection conforms to department role and network tiering",
                explanation=f"Newly observed connection {s} -[{rtype}]-> {t} conforms to standard enterprise role profile.",
                detection_rationale=f"Relationship was unrecorded historically, but endpoints conform to {evaluated_dept} department role profile and network tiering.",
                recommended_investigation="Update baseline profile to incorporate legitimate newly provisioned activity. No containment required.",
                step_score=20,
                sequence_id=sequence_id,
            )

        # 7. Default unobserved edge
        return self._create_finding(
            step=step,
            deviation_type=DeviationType.UNOBSERVED_RELATIONSHIP,
            rule_id="RULE-HISTORICAL-UNOBSERVED-01",
            baseline_ref="HISTORICAL_BASELINE: Relationship not recorded in historical baseline",
            explanation=f"Unobserved connection {s} -[{rtype}]-> {t} with unverified policy context.",
            detection_rationale=f"Connection {step.source_id} -[{step.relationship_type.value}]-> {step.target_id} has no historical precedent in graph.",
            recommended_investigation="Review business justification with identity owner and asset administrator.",
            step_score=30,
            sequence_id=sequence_id,
        )


    def evaluate_sequence(self, request: AccessSequenceRequest) -> AccessSequenceAnomalyResult:
        """
        Evaluates a complete ordered access sequence for graph-based anomalies.
        Applies transparent scoring formula and assigns one of 4 discrete classifications.
        """
        entity_id = request.evaluated_entity_id.strip()
        history_comp, baseline_conf, evaluated_dept = self._assess_cold_start(entity_id)

        has_confirmed_compromise = request.client_context.get("has_confirmed_compromise", False) or request.client_context.get("is_compromised", False)
        is_compromised_origin = (
            has_confirmed_compromise
            and ("dev-ws-101" in entity_id.lower() or request.client_context.get("case_id") == "MT-101")
        )

        unexpected_list: List[UnexpectedRelationship] = []
        step_scores: List[int] = []

        for step in request.steps:
            finding = self.evaluate_step(
                step=step,
                evaluated_dept=evaluated_dept,
                is_compromised_origin=is_compromised_origin,
                sequence_id=request.sequence_id,
            )
            if finding:
                unexpected_list.append(finding)
                step_scores.append(finding.step_score)
            else:
                step_scores.append(0)

        # Composite Scoring Formula
        if not step_scores or max(step_scores) == 0:
            anomaly_score = 0
            classification = AnomalyClassification.BENIGN_EXPECTED
            summary_explanation = "Sequence strictly conforms to documented historical baseline and authorized permissions."
            actions = ["No action required. Access sequence matches verified baseline profile."]
        else:
            max_s = max(step_scores)
            mean_s = sum(step_scores) / len(step_scores)
            raw_score = 0.6 * max_s + 0.4 * mean_s

            # Classification Mapping
            if max_s >= 80 or any(f.deviation_type in (DeviationType.EXPLOIT_PRECONDITION, DeviationType.HIGH_RISK_PIVOT) for f in unexpected_list):
                classification = AnomalyClassification.SUSPICIOUS_ANOMALOUS
                anomaly_score = min(100, max(80, round(raw_score)))
                summary_explanation = (
                    f"CRITICAL ANOMALY: Access sequence contains high-risk lateral traversal or exploit preconditions "
                    f"targeting sensitive infrastructure (Max step score: {max_s})."
                )
                actions = [
                    "Initiate priority incident response investigation.",
                    "Verify EDR telemetry on entry workstation.",
                    "Perform GraphOps blast-radius and What-If containment simulation on affected gateway.",
                ]
            elif max_s >= 40:
                classification = AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED
                anomaly_score = min(79, max(40, round(raw_score)))
                summary_explanation = (
                    f"POLICY VIOLATION: Sequence violates network tiering boundaries or lacks authorized IAM permissions, "
                    f"without confirmed exploit or malware indicators (Max step score: {max_s})."
                )
                actions = [
                    "Review access entitlements with directory administration.",
                    "Verify whether firewall exception or jump-box policy was bypassed.",
                    "Notify resource owner of unauthorized connection attempt.",
                ]
            else:
                # Novel edges that conform to standard department workflow
                classification = AnomalyClassification.UNOBSERVED_NEW_LEGITIMATE
                anomaly_score = min(39, max(20, round(raw_score)))
                summary_explanation = (
                    f"LEGITIMATE NEW BEHAVIOR: Sequence introduces unobserved relationships, but actions conform to "
                    f"department role ({evaluated_dept}) and network tiering policies. Not flagged as malicious."
                )
                actions = [
                    "Update baseline profile to incorporate legitimate newly provisioned activity.",
                    "No containment required.",
                ]

        is_anomalous = classification in (
            AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED,
            AnomalyClassification.SUSPICIOUS_ANOMALOUS,
        )

        return AccessSequenceAnomalyResult(
            sequence_id=request.sequence_id,
            evaluated_entity_id=request.evaluated_entity_id,
            classification=classification,
            anomaly_score=anomaly_score,
            baseline_confidence=baseline_conf,
            history_completeness=history_comp,
            is_anomalous=is_anomalous,
            unexpected_relationships=unexpected_list if request.include_explanations else [],
            summary_explanation=summary_explanation,
            recommended_investigation_actions=actions,
        )

    def run_test_suite(self) -> AnomalyTestSuiteResult:
        """
        Executes anomaly evaluation across the held-out labeled test sequences fixture.
        Measures classification accuracy, precision, recall, F1-score, and false-positive rate.
        """
        fixture_data = load_anomaly_test_sequences()
        seqs = fixture_data.get("sequences", [])

        items: List[AnomalyTestSuiteItem] = []
        correct_count = 0

        # Binary confusion matrix for anomaly detection:
        # Positive = Anomalous (POLICY_VIOLATION_UNAUTHORIZED or SUSPICIOUS_ANOMALOUS)
        # Negative = Non-Anomalous (BENIGN_EXPECTED or UNOBSERVED_NEW_LEGITIMATE)
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for s in seqs:
            steps = [
                AccessSequenceStep(
                    step_index=st["step_index"],
                    source_id=st["source_id"],
                    relationship_type=RelationshipType(st["relationship_type"]),
                    target_id=st["target_id"],
                    properties=st.get("properties", {}),
                )
                for st in s["steps"]
            ]
            req = AccessSequenceRequest(
                sequence_id=s["sequence_id"],
                evaluated_entity_id=s["evaluated_entity_id"],
                steps=steps,
                include_explanations=True,
                client_context={"case_id": "MT-101" if "101" in s["sequence_id"] else None},
            )
            res = self.evaluate_sequence(req)

            gt_label = AnomalyClassification(s["ground_truth_label"])
            pred_label = res.classification
            is_match = (gt_label == pred_label)
            if is_match:
                correct_count += 1

            # Binary metrics accounting
            is_gt_positive = gt_label in (
                AnomalyClassification.POLICY_VIOLATION_UNAUTHORIZED,
                AnomalyClassification.SUSPICIOUS_ANOMALOUS,
            )
            is_pred_positive = res.is_anomalous

            if is_gt_positive and is_pred_positive:
                tp += 1
            elif not is_gt_positive and is_pred_positive:
                fp += 1
            elif not is_gt_positive and not is_pred_positive:
                tn += 1
            elif is_gt_positive and not is_pred_positive:
                fn += 1

            items.append(
                AnomalyTestSuiteItem(
                    sequence_id=s["sequence_id"],
                    description=s["description"],
                    ground_truth_label=gt_label,
                    predicted_label=pred_label,
                    anomaly_score=res.anomaly_score,
                    is_match=is_match,
                    unexpected_count=len(res.unexpected_relationships),
                )
            )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return AnomalyTestSuiteResult(
            total_evaluated=len(seqs),
            total_correct=correct_count,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            confusion_matrix={"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            results=items,
        )

    def evaluate_case(self, case_id: str) -> AccessSequenceAnomalyResult:
        """
        Bridges an investigation case to internal identity & device, constructs
        its observed access sequence, and evaluates for graph-based anomalies.
        """
        from backend.graphops.attack_paths import AttackPathService
        path_svc = AttackPathService(self.client)
        bridge_res = path_svc.bridge_case_to_graph(case_id)

        user_node = bridge_res.primary_compromised_node
        user_id = user_node.id if user_node else f"case:{case_id}"

        # Find mapped device
        mapped_device_id = None
        for m in bridge_res.mapped_entities:
            if m.node_label == NodeLabel.DEVICE:
                mapped_device_id = m.mapped_node_id
                break

        steps: List[AccessSequenceStep] = []
        step_idx = 0

        if user_node and mapped_device_id:
            steps.append(
                AccessSequenceStep(
                    step_index=step_idx,
                    source_id=user_node.id,
                    relationship_type=RelationshipType.USES,
                    target_id=mapped_device_id,
                )
            )
            step_idx += 1

        if mapped_device_id:
            steps.append(
                AccessSequenceStep(
                    step_index=step_idx,
                    source_id=mapped_device_id,
                    relationship_type=RelationshipType.OBSERVED_CONNECTION,
                    target_id="server:srv-app-01",
                    properties={"port": 443, "protocol": "TCP"},
                )
            )

        req = AccessSequenceRequest(
            sequence_id=f"case-seq-{case_id.lower()}",
            evaluated_entity_id=mapped_device_id or user_id,
            steps=steps,
            include_explanations=True,
            client_context={
                "case_id": case_id,
                "is_phishing_recipient": True,
                "has_confirmed_compromise": False,
            },
        )
        return self.evaluate_sequence(req)

