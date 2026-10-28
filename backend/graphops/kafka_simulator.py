"""
ThreatLens GraphOps - Synthetic Security Event Simulation Engine
Generates deterministic, explicitly-labeled synthetic security events for hackathon demonstration,
end-to-end verification, and testing of the Kafka event-streaming pipeline.
"""

import uuid
from typing import Dict, Any, List
from datetime import datetime, timezone

from backend.graphops.schema import CriticalityTier
from backend.models.graphops import (
    SecurityEventType,
    SecurityEventEnvelope,
)


def create_synthetic_compromise_indicator(
    device_id: str = "device:dev-ws-101",
    threat_actor: str = "APT-SIMULATED-FINANCE",
    cve_id: str = "CVE-2024-38077",
) -> SecurityEventEnvelope:
    """
    Creates an explicitly labeled synthetic COMPROMISE_INDICATOR event targeting a known device.
    Triggers BFS blast-radius, Dijkstra minimum-cost path, and choke-point analytics.
    """
    event_id = f"EVT-COMPROMISE-{uuid.uuid4().hex[:8].upper()}"
    return SecurityEventEnvelope(
        event_id=event_id,
        schema_version="1.0.0",
        event_type=SecurityEventType.COMPROMISE_INDICATOR,
        source="EDR_SENSOR_DEMO",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=[device_id],
        payload={
            "compromised_entity_id": device_id,
            "indicator_type": "REMOTE_CODE_EXECUTION",
            "threat_actor": threat_actor,
            "tactics": ["Initial Access", "Execution", "Lateral Movement"],
            "via_cve": cve_id,
            "confidence": 0.95,
            "summary": f"SYNTHETIC ALERT: Confirmed RCE exploit on endpoint {device_id}.",
        },
        correlation_id="CASE-SIM-2026-001",
        severity=CriticalityTier.CRITICAL,
        evidence_metadata={
            "provenance": "SIMULATED_EDR_TELEMETRY",
            "disclaimer": "SYNTHETIC DEMONSTRATION DATA ONLY",
        },
    )


def create_synthetic_identity_event(
    user_id: str = "user:victim1@corporation.com",
    target_resource_id: str = "server:srv-app-01",
    auth_status: str = "SUCCESS",
) -> SecurityEventEnvelope:
    """Creates a synthetic IDENTITY_EVENT recording an authenticated session."""
    event_id = f"EVT-AUTH-{uuid.uuid4().hex[:8].upper()}"
    return SecurityEventEnvelope(
        event_id=event_id,
        schema_version="1.0.0",
        event_type=SecurityEventType.IDENTITY_EVENT,
        source="OKTA_IAM_DEMO",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=[user_id, target_resource_id],
        payload={
            "user_id": user_id,
            "target_resource_id": target_resource_id,
            "action": "INTERACTIVE_LOGON",
            "auth_status": auth_status,
            "privilege_level": "ELEVATED",
            "ip_address": "10.0.1.101",
        },
        severity=CriticalityTier.MEDIUM,
        evidence_metadata={
            "provenance": "SIMULATED_IAM_LOG",
            "disclaimer": "SYNTHETIC DEMONSTRATION DATA ONLY",
        },
    )


def create_synthetic_network_event(
    source_entity_id: str = "device:dev-ws-101",
    target_entity_id: str = "server:srv-app-02",
    port: int = 445,
) -> SecurityEventEnvelope:
    """Creates a synthetic NETWORK_CONNECTION event recording lateral movement telemetry."""
    event_id = f"EVT-NET-{uuid.uuid4().hex[:8].upper()}"
    return SecurityEventEnvelope(
        event_id=event_id,
        schema_version="1.0.0",
        event_type=SecurityEventType.NETWORK_CONNECTION,
        source="ZEEK_NETWORK_TAP",
        occurred_at=datetime.now(timezone.utc).isoformat(),
        entity_ids=[source_entity_id, target_entity_id],
        payload={
            "source_entity_id": source_entity_id,
            "target_entity_id": target_entity_id,
            "port": port,
            "protocol": "SMB",
            "bytes_transferred": 1048576,
            "direction": "LATERAL",
        },
        severity=CriticalityTier.HIGH,
        evidence_metadata={
            "provenance": "SIMULATED_NETFLOW",
            "disclaimer": "SYNTHETIC DEMONSTRATION DATA ONLY",
        },
    )
