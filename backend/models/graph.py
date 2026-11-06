"""
MailTrace AI - Attack Graph & Campaign Correlation Data Models
Feature 6: Attack Graph + Campaign Correlation
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    """
    Normalized Graph Node representation.
    """
    id: str = Field(description="Unique node identifier e.g. email:case001, ip:185.190.140.22, domain:evil.com")
    type: str = Field(description="Entity type: email, domain, url, ip, hash, attachment, hostname, campaign")
    label: str = Field(description="Display label in visualization")
    status: str = Field(
        default="UNKNOWN",
        description="Reputation status: MALICIOUS, SUSPICIOUS, CLEAN_REPORTED, UNKNOWN, NO_REPUTATION_DATA"
    )
    data: Dict[str, Any] = Field(default_factory=dict, description="Metadata payload including threat intel, scores, etc.")


class GraphEdge(BaseModel):
    """
    Observed Relationship Edge between graph entities.
    """
    id: str = Field(description="Unique edge identifier e.g. edge-1")
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    relationship: str = Field(
        description="Relationship type: CONTAINS, REFERENCES, RESOLVES_TO, HOSTED_ON, OBSERVED_RELAY, HAS_ATTACHMENT, PART_OF, SHARES_INFRASTRUCTURE"
    )
    label: Optional[str] = Field(default=None, description="Human readable edge label")


class AttackGraph(BaseModel):
    """
    Consolidated Graph containing all nodes and edges for one or more cases.
    """
    case_id: Optional[str] = Field(default=None, description="Associated primary case ID")
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    stats: Dict[str, int] = Field(default_factory=dict, description="Node and edge category metrics")


class SharedIndicator(BaseModel):
    """
    Specific indicator shared across multiple email investigations.
    """
    type: str = Field(description="Indicator type: ip, domain, url, hash, hostname")
    value: str = Field(description="Indicator string value")
    occurrences: int = Field(default=1, description="Number of cases sharing this indicator")
    case_ids: List[str] = Field(default_factory=list, description="IDs of cases sharing this indicator")


class CampaignCluster(BaseModel):
    """
    Detected threat campaign group representing multiple correlated email cases.
    """
    campaign_id: str = Field(description="Unique campaign identifier e.g. CMP-001")
    name: str = Field(description="Descriptive campaign title")
    status: str = Field(
        description="Correlation strength: STRONG_CAMPAIGN, LIKELY_RELATED, POSSIBLE_RELATIONSHIP, NO_CORRELATION"
    )
    correlation_score: int = Field(description="Transparent correlation score (0-100)")
    case_ids: List[str] = Field(default_factory=list, description="List of email case IDs in this campaign")
    primary_threat: str = Field(default="PHISHING", description="Dominant threat category across cases")
    shared_indicators: List[SharedIndicator] = Field(default_factory=list, description="List of common infrastructure IOCs")
    reasons: List[str] = Field(default_factory=list, description="Evidence-grounded explanations for clustering")
    first_seen: Optional[str] = Field(default=None, description="Earliest case timestamp")
    last_seen: Optional[str] = Field(default=None, description="Latest case timestamp")


class CampaignCorrelationResult(BaseModel):
    """
    Result object returned by campaign correlation engine.
    """
    current_case_campaign: Optional[CampaignCluster] = Field(default=None, description="Campaign cluster for current case")
    all_campaigns: List[CampaignCluster] = Field(default_factory=list, description="All detected campaign clusters across historical cases")
    total_cases_indexed: int = Field(default=0, description="Total number of historical cases in repository")
    total_campaigns_detected: int = Field(default=0, description="Total number of active campaign clusters")


class CaseRecord(BaseModel):
    """
    Normalized repository record representing an analyzed email investigation case.
    """
    case_id: str
    subject: str
    sender: str
    recipient: Optional[str] = None
    threat_score: int
    risk_level: str
    primary_threat: str
    iocs: Dict[str, List[str]] = Field(default_factory=dict)
    intel_summary: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str
    status: str = Field(default="OPEN", description="Triage status: OPEN, TRIAGED, INVESTIGATING, CONTAINED, CLOSED")
    assigned_to: Optional[str] = Field(default=None, description="Assigned SOC analyst email or name")
    severity: Optional[str] = Field(default=None, description="Analyst assigned severity override: CRITICAL, HIGH, MEDIUM, LOW")
    notes: List[Dict[str, Any]] = Field(default_factory=list, description="Analyst notes with timestamp, author, and text")
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list, description="References to raw EML, event IDs, finding IDs, or file hashes")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Explicit timeline events with original_event_time and ingested_at")
    forensics_summary: Optional[Dict[str, Any]] = Field(default_factory=dict, description="SPF/DKIM/DMARC auth results, sender IP, relay hops")
    is_sample: bool = Field(default=False, description="Distinguishes synthetic/historical demo cases from live incidents")


class CaseCreateRequest(BaseModel):
    """Payload to create an investigation case."""
    subject: str = Field(min_length=1, description="Email subject line or incident title")
    sender: str = Field(min_length=1, description="Sender address or origin")
    recipient: Optional[str] = None
    threat_score: int = Field(default=50, ge=0, le=100)
    risk_level: str = Field(default="MEDIUM")
    primary_threat: str = Field(default="SUSPICIOUS_EMAIL")
    status: str = Field(default="OPEN")
    assigned_to: Optional[str] = None
    case_id: Optional[str] = None
    iocs: Dict[str, List[str]] = Field(default_factory=dict)
    intel_summary: Dict[str, Any] = Field(default_factory=dict)
    forensics_summary: Dict[str, Any] = Field(default_factory=dict)
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    is_sample: bool = Field(default=False, description="Whether this is a synthetic demonstration case")


class CaseUpdateRequest(BaseModel):
    """Payload to update an investigation case."""
    status: Optional[str] = None
    risk_level: Optional[str] = None
    threat_score: Optional[int] = Field(default=None, ge=0, le=100)
    assigned_to: Optional[str] = None
    primary_threat: Optional[str] = None
    subject: Optional[str] = None
    is_sample: Optional[bool] = None


class CaseNoteRequest(BaseModel):
    """Payload to add an analyst note."""
    note: str = Field(min_length=1, description="Analyst observation or findings")
    author: str = Field(default="soc_analyst", description="Analyst identity")


class TimelineEventRecord(BaseModel):
    """A genuine chronologically sorted event with distinct original vs ingestion timestamps."""
    event_id: Optional[str] = Field(default=None, description="Unique event identifier (auto-generated if omitted)")
    original_event_time: str = Field(description="Original timestamp when the event occurred (ISO 8601)")
    ingested_at: str = Field(description="Timestamp when event was ingested into the platform (ISO 8601)")
    source: str = Field(description="Detector or subsystem source e.g. SMTP_RELAY, AUTH_VALIDATOR, EDR, ANALYST")
    event_type: str = Field(description="Classification e.g. EMAIL_RECEIPT, AUTH_FAILURE, LATERAL_HOP, NOTE_ADDED")
    title: str = Field(description="Human readable event title")
    description: str = Field(default="", description="Detailed narrative or metadata payload")
    severity: str = Field(default="MEDIUM")
    evidence_ref: Optional[str] = Field(default=None, description="Pointer to evidence record or raw artifact")
    details: Dict[str, Any] = Field(default_factory=dict)


class AlertItem(BaseModel):
    """Normalized security alert item in the consolidated stream."""
    alert_id: str
    alert_type: str = Field(description="Alert category: case_alert, graph_finding, telemetry_alert")
    timestamp: str = Field(description="ISO 8601 alert generation timestamp")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    detector_source: str = Field(description="Engine or sensor that produced the alert")
    affected_entity: str = Field(description="Entity or identity targeted or compromised")
    title: str = Field(description="Short alert summary")
    classification: str = Field(description="Threat category e.g. PHISHING, LATERAL_MOVEMENT, BEC, SPOOFING")
    status: str = Field(default="OPEN")
    case_id: Optional[str] = None
    finding_id: Optional[str] = None
    threat_score: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)
