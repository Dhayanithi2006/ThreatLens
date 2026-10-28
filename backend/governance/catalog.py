"""
ThreatLens Governance & Controls - Standards Control Catalog
Authoritative, verified mappings to NIST CSF 2.0, NIST SP 800-53 Rev. 5,
CIS Critical Security Controls v8.1, MITRE ATT&CK v14.1, and ISO/IEC 27001:2022.

Disclaimer:
A technical finding is evidence for assessment; it is not automatically proof of
a standards violation. ThreatLens does not claim formal certification or regulatory
audit completion. Control mappings provide explainable SOC context.
"""

from typing import Dict, List, Optional
from backend.governance.schema import ControlRecord

STANDARD_CONTROLS: List[ControlRecord] = [
    # =========================================================================
    # 1. NIST CYBERSECURITY FRAMEWORK (CSF) 2.0
    # =========================================================================
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="PR.AA-01",
        title="Identity & Credential Management",
        description="Identities and credentials for authorized users, services, and hardware are managed by the organization.",
        mapping_rationale="Applies to GraphOps user identity nodes, service account principals, and assigned device USES relationships.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Identity and Access Management",
    ),
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="PR.AA-05",
        title="Access Permissions & Least Privilege",
        description="Access permissions, entitlements, and authorizations are defined in a policy, managed, and enforce separation of duties.",
        mapping_rationale="Evaluates direct HAS_PERMISSION relationships against Crown Jewels and flags excessive workstation permissions.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="PR.IR-01",
        title="Network & Boundary Protection",
        description="Networks and environments are protected from unauthorized logical access and usage.",
        mapping_rationale="Detects lateral movement pathways that bypass intermediate gateway layers or directly connect to high-value servers.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Network Segmentation",
    ),
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="ID.AM-01",
        title="Hardware & Asset Inventory",
        description="Inventories of hardware managed by the organization are maintained.",
        mapping_rationale="Maps internal workstation and server nodes to enterprise CMDB records, flagging unindexed or shadow devices.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Asset Management",
    ),
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="DE.CM-01",
        title="Network Monitoring & Adverse Events",
        description="Networks and network services are monitored to find potentially adverse events.",
        mapping_rationale="Applies to OBSERVED_CONNECTION relationships and graph access anomaly detection rules.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Monitoring & Detection",
    ),
    ControlRecord(
        framework_name="NIST CSF",
        framework_version="2.0",
        control_id="RS.AN-01",
        title="Incident Investigation & Root Cause",
        description="An incident is investigated, and root causes are identified.",
        mapping_rationale="Correlates email phishing evidence to corporate identities, lateral movement blast radius, and choke points.",
        official_reference="https://doi.org/10.6028/NIST.CSWP.29",
        applicability="Incident Response",
    ),

    # =========================================================================
    # 2. NIST SP 800-53 REV. 5
    # =========================================================================
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="AC-2",
        title="Account Management",
        description="The organization manages information system accounts, group memberships, and authorized role mappings.",
        mapping_rationale="Evaluates user-to-device mapping and detects unlinked accounts or hijacked service principals.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Identity and Access Management",
    ),
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="AC-3",
        title="Access Enforcement",
        description="The information system enforces approved authorizations for logical access to information and system resources.",
        mapping_rationale="Identifies unauthorized pathways connecting unprivileged endpoints to restricted database systems.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="AC-6",
        title="Least Privilege",
        description="The organization employs the principle of least privilege, allowing only authorized accesses necessary for accomplishments.",
        mapping_rationale="Quantifies intermediate choke points and highlights excessive standing permissions across lateral paths.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="CM-8",
        title="Information System Component Inventory",
        description="The organization develops and documents an inventory of information system components that accurately reflects the system.",
        mapping_rationale="GraphOps knowledge graph acts as an authoritative security topology inventory linking systems to identities and vulnerabilities.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Asset Management",
    ),
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="SI-4",
        title="System Monitoring",
        description="The information system monitors inbound and outbound communications for unauthorized connections.",
        mapping_rationale="Directly supports graph anomaly detection comparing access patterns against organizational baselines.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Monitoring & Detection",
    ),
    ControlRecord(
        framework_name="NIST SP 800-53",
        framework_version="Rev. 5",
        control_id="IR-4",
        title="Incident Handling",
        description="The organization implements an incident handling capability for security incidents that includes containment and remediation.",
        mapping_rationale="Validates What-If containment simulations (node isolation, edge severance) to evaluate blast radius reduction.",
        official_reference="https://doi.org/10.6028/NIST.SP.800-53r5",
        applicability="Incident Response",
    ),

    # =========================================================================
    # 3. CIS CRITICAL SECURITY CONTROLS V8.1
    # =========================================================================
    ControlRecord(
        framework_name="CIS Controls",
        framework_version="v8.1",
        control_id="CIS-1.1",
        title="Establish and Maintain an Enterprise Asset Inventory",
        description="Utilize an active discovery tool to identify all devices connected to the enterprise's network.",
        mapping_rationale="GraphOps node schema tracks active devices, servers, and IP addresses with verified provenances.",
        official_reference="https://www.cisecurity.org/controls/v8-1",
        applicability="Asset Management",
    ),
    ControlRecord(
        framework_name="CIS Controls",
        framework_version="v8.1",
        control_id="CIS-3.3",
        title="Configure Data Access Control Lists",
        description="Configure data access control lists to grant access only to authorized personnel.",
        mapping_rationale="Validates HAS_PERMISSION edges to CriticalAsset and Database nodes, flagging unauthorized access.",
        official_reference="https://www.cisecurity.org/controls/v8-1",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="CIS Controls",
        framework_version="v8.1",
        control_id="CIS-5.1",
        title="Establish and Maintain an Inventory of Accounts",
        description="Establish and maintain an inventory of all user accounts, service accounts, and administrator accounts.",
        mapping_rationale="Tracks user and service identities and correlates credentials to endpoint activity.",
        official_reference="https://www.cisecurity.org/controls/v8-1",
        applicability="Identity and Access Management",
    ),
    ControlRecord(
        framework_name="CIS Controls",
        framework_version="v8.1",
        control_id="CIS-6.1",
        title="Establish an Access Granting Process",
        description="Establish and follow a process for granting access to enterprise assets upon approval.",
        mapping_rationale="Distinguishes authorized access from unauthorized tier violations and novel unobserved activity.",
        official_reference="https://www.cisecurity.org/controls/v8-1",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="CIS Controls",
        framework_version="v8.1",
        control_id="CIS-7.1",
        title="Establish and Maintain a Vulnerability Management Process",
        description="Establish and maintain a documented vulnerability management process for enterprise assets.",
        mapping_rationale="Connects CVE vulnerability nodes to host servers and highlights exploit preconditions in lateral paths.",
        official_reference="https://www.cisecurity.org/controls/v8-1",
        applicability="Vulnerability Management",
    ),

    # =========================================================================
    # 4. MITRE ATT&CK V14.1
    # =========================================================================
    ControlRecord(
        framework_name="MITRE ATT&CK",
        framework_version="v14.1",
        control_id="T1078",
        title="Valid Accounts",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Privilege Escalation.",
        mapping_rationale="GraphOps models account compromise and evaluates lateral blast radius from stolen user and service credentials.",
        official_reference="https://attack.mitre.org/techniques/T1078/",
        applicability="Identity and Access Management",
    ),
    ControlRecord(
        framework_name="MITRE ATT&CK",
        framework_version="v14.1",
        control_id="T1021",
        title="Remote Services",
        description="Adversaries may use Valid Accounts to log into remote services (RDP, SSH, SMB) to move laterally.",
        mapping_rationale="Identifies multi-hop paths traversing internal networks via remote services to reach high-value targets.",
        official_reference="https://attack.mitre.org/techniques/T1021/",
        applicability="Lateral Movement",
    ),
    ControlRecord(
        framework_name="MITRE ATT&CK",
        framework_version="v14.1",
        control_id="T1190",
        title="Exploit Public-Facing Application",
        description="Adversaries may attempt to exploit vulnerabilities in Internet-facing applications to gain initial code execution.",
        mapping_rationale="Models POTENTIAL_EXPLOIT relationships linking known CVEs to application servers on attack paths.",
        official_reference="https://attack.mitre.org/techniques/T1190/",
        applicability="Vulnerability Management",
    ),
    ControlRecord(
        framework_name="MITRE ATT&CK",
        framework_version="v14.1",
        control_id="T1566",
        title="Phishing",
        description="Adversaries may send phishing messages to gain access to victim systems and harvesting credentials.",
        mapping_rationale="ThreatLens email analysis extracts phishing indicators and bridges recipient identity into corporate graph.",
        official_reference="https://attack.mitre.org/techniques/T1566/",
        applicability="Initial Access",
    ),

    # =========================================================================
    # 5. ISO/IEC 27001:2022
    # =========================================================================
    ControlRecord(
        framework_name="ISO/IEC 27001",
        framework_version="2022",
        control_id="A.5.15",
        title="Access Control",
        description="Rules to control physical and logical access to information and other associated assets shall be established and implemented.",
        mapping_rationale="Evaluates access permissions and tiering rules to detect unauthorized direct access to critical data stores.",
        official_reference="https://www.iso.org/standard/27001",
        applicability="Access Control & Tiering",
    ),
    ControlRecord(
        framework_name="ISO/IEC 27001",
        framework_version="2022",
        control_id="A.8.8",
        title="Management of Technical Vulnerabilities",
        description="Information about technical vulnerabilities of information systems being used shall be obtained and evaluated.",
        mapping_rationale="Analyzes exploit preconditions on multi-hop attack routes and prioritizes patch intervention choke points.",
        official_reference="https://www.iso.org/standard/27001",
        applicability="Vulnerability Management",
    ),
    ControlRecord(
        framework_name="ISO/IEC 27001",
        framework_version="2022",
        control_id="A.8.20",
        title="Network Security",
        description="Networks and network devices shall be secured, managed and controlled to protect information in systems.",
        mapping_rationale="Validates segmentation barriers between endpoint tiers, application gateways, and core database enclaves.",
        official_reference="https://www.iso.org/standard/27001",
        applicability="Network Segmentation",
    ),
]

_CONTROLS_BY_ID: Dict[str, ControlRecord] = {c.control_id.upper(): c for c in STANDARD_CONTROLS}


def get_control_catalog() -> List[ControlRecord]:
    """Returns the full authoritative security standards control catalog."""
    return list(STANDARD_CONTROLS)


def get_control(control_id: str) -> Optional[ControlRecord]:
    """Resolves control record by normalized identifier e.g. 'PR.AA-01' or 'AC-3'."""
    if not control_id:
        return None
    return _CONTROLS_BY_ID.get(control_id.strip().upper())


def find_controls_by_applicability(applicability: str) -> List[ControlRecord]:
    """Filters catalog controls by operational applicability category."""
    norm = applicability.lower().strip()
    return [c for c in STANDARD_CONTROLS if norm in c.applicability.lower()]


def find_controls_by_framework(framework_name: str) -> List[ControlRecord]:
    """Filters catalog controls by framework name e.g. 'NIST CSF'."""
    norm = framework_name.lower().strip()
    return [c for c in STANDARD_CONTROLS if norm in c.framework_name.lower()]
