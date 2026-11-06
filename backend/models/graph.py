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
