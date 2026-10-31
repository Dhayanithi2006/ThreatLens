"""
ThreatLens Collector - Windows Security Event Normalizer

Converts raw Windows Event Log records (as parsed by pyevtx-rs / win32evtlog
or forwarded as XML/dict) into canonical ThreatLens SecurityEventEnvelope objects.

Supported Windows Event IDs (initial set):
  4624 - Successful Logon         -> IDENTITY_EVENT
  4625 - Failed Logon             -> IDENTITY_EVENT
  4688 - Process Creation         -> PROCESS_EVENT
  4648 - Logon Using Explicit Credentials -> IDENTITY_EVENT
  4672 - Special Privileges Assigned     -> IDENTITY_EVENT
  4698 - Scheduled Task Created          -> PROCESS_EVENT
  4720 - User Account Created            -> IDENTITY_EVENT
  5140 - Network Share Object Accessed   -> NETWORK_CONNECTION
  5156 - Filtering Platform Connection   -> NETWORK_CONNECTION

The normalizer is conservative: unmapped or malformed events are returned
as ENDPOINT_ALERT with the raw payload preserved for analyst review.
"""

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.graphops.schema import CriticalityTier
from backend.models.graphops import SecurityEventEnvelope, SecurityEventType

logger = logging.getLogger("threatlens.collector.normalizer")

# ---------------------------------------------------------------------------
# Event ID → SecurityEventType mapping
# ---------------------------------------------------------------------------
_EVENT_TYPE_MAP: Dict[int, SecurityEventType] = {
    4624: SecurityEventType.IDENTITY_EVENT,
    4625: SecurityEventType.IDENTITY_EVENT,
    4648: SecurityEventType.IDENTITY_EVENT,
    4672: SecurityEventType.IDENTITY_EVENT,
    4720: SecurityEventType.IDENTITY_EVENT,
    4726: SecurityEventType.IDENTITY_EVENT,
    4688: SecurityEventType.PROCESS_EVENT,
    4698: SecurityEventType.PROCESS_EVENT,
    4699: SecurityEventType.PROCESS_EVENT,
    5140: SecurityEventType.NETWORK_CONNECTION,
    5156: SecurityEventType.NETWORK_CONNECTION,
    5157: SecurityEventType.NETWORK_CONNECTION,
}

# Event IDs considered high-severity indicators
_HIGH_SEVERITY_IDS = {4625, 4648, 4672, 5157}
_CRITICAL_SEVERITY_IDS = {4698, 4720, 4726}

# Sensitive command-line token/password redaction patterns
_REDACT_PATTERNS = [
    re.compile(r"(-[-]?password[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(/password[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(-[-]?p[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(/p[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(Bearer\s+)([A-Za-z0-9_\-\.]+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(token[=:\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(secret[=:\s]+)([^\s]+)", re.IGNORECASE),
]


def redact_sensitive_cmdline(cmd: str) -> str:
    """Redacts passwords, secrets, and API tokens from process command lines."""
    if not cmd:
        return ""
    result = cmd
    for pat in _REDACT_PATTERNS:
        result = pat.sub(r"\1[REDACTED]", result)
    return result

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _canonical_hostname(hostname: str) -> str:
    """Normalizes hostname to lowercase, strips domain suffix for entity id."""
    if not hostname:
        return "unknown"
    return hostname.lower().split(".")[0].strip()


def _canonical_device_id(hostname: str) -> str:
    return f"device:{_canonical_hostname(hostname)}"


def _canonical_user_id(username: str, domain: str = "") -> str:
    if not username or username in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return ""
    user = username.lower().strip()
    if domain and domain not in ("-", "NT AUTHORITY", "WORKGROUP"):
        return f"user:{user}@{domain.lower()}"
    return f"user:{user}"


def _make_stable_event_id(
    source_event_record_id: Any,
    source_computer: str,
    event_id_number: int,
    occurred_at: str,
) -> str:
    """
    Produces a deterministic, collision-resistant event ID from stable fields.
    Ensures idempotent re-delivery does not create duplicate Neo4j nodes.
    """
    raw = f"{source_computer}|{event_id_number}|{source_event_record_id}|{occurred_at}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"wev-{digest}"


def _parse_timestamp(ts: Any) -> str:
    """
    Parses various timestamp representations into ISO 8601 UTC string.
    Accepts datetime objects, epoch floats/ints, or ISO strings.
    """
    if ts is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    # Try ISO string
    raw = str(ts).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    logger.warning("Could not parse timestamp '%s'; using now()", raw)
    return datetime.now(timezone.utc).isoformat()


def _severity_for_event(event_id_number: int) -> CriticalityTier:
    if event_id_number in _CRITICAL_SEVERITY_IDS:
        return CriticalityTier.CRITICAL
    if event_id_number in _HIGH_SEVERITY_IDS:
        return CriticalityTier.HIGH
    return CriticalityTier.MEDIUM


# ---------------------------------------------------------------------------
# Per-event-ID payload builders
# ---------------------------------------------------------------------------

def _build_logon_payload(
    event_data: Dict[str, Any],
    event_id_number: int,
    source_computer: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds payload and entity_ids for logon events (4624, 4625, 4648, 4672, 4720)."""
    subject_username = _safe_str(event_data.get("SubjectUserName") or event_data.get("subject_username"))
    subject_domain = _safe_str(event_data.get("SubjectDomainName") or event_data.get("subject_domain"))
    target_username = _safe_str(event_data.get("TargetUserName") or event_data.get("target_username"))
    target_domain = _safe_str(event_data.get("TargetDomainName") or event_data.get("target_domain"))
    logon_type = _safe_str(event_data.get("LogonType") or event_data.get("logon_type", ""))
    auth_package = _safe_str(event_data.get("AuthenticationPackageName") or event_data.get("auth_package", ""))
    workstation = _safe_str(event_data.get("WorkstationName") or event_data.get("workstation", ""))
    ip_addr = _safe_str(event_data.get("IpAddress") or event_data.get("ip_address", ""))
    failure_reason = _safe_str(event_data.get("FailureReason") or event_data.get("failure_reason", ""))
    privileges = _safe_str(event_data.get("PrivilegeList") or event_data.get("privilege_list", ""))

    # Determine auth status from event_id
    auth_status = "FAILED" if event_id_number == 4625 else "SUCCESS"

    # Resolve canonical user (prefer target for 4624/4625; subject for 4672)
    primary_user = target_username if target_username and target_username != "-" else subject_username
    primary_domain = target_domain if target_domain and target_domain != "-" else subject_domain
    user_canonical = _canonical_user_id(primary_user, primary_domain)
    device_canonical = _canonical_device_id(source_computer)
    workstation_canonical = _canonical_device_id(workstation) if workstation and workstation != "-" else ""

    entity_ids = [eid for eid in [user_canonical, device_canonical, workstation_canonical] if eid]
    if not entity_ids:
        entity_ids = [device_canonical]

    payload = {
        "windows_event_id": event_id_number,
        "auth_status": auth_status,
        "user_id": user_canonical,
        "target_resource_id": device_canonical,
        "logon_type": logon_type,
        "auth_package": auth_package,
        "source_ip": ip_addr,
        "workstation": workstation,
        "failure_reason": failure_reason,
        "privileges": privileges,
        "subject_username": subject_username,
        "target_username": target_username,
    }
    return payload, entity_ids


def _build_process_payload(
    event_data: Dict[str, Any],
    source_computer: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds payload and entity_ids for process creation events (4688)."""
    subject_username = _safe_str(event_data.get("SubjectUserName") or event_data.get("subject_username"))
    subject_domain = _safe_str(event_data.get("SubjectDomainName") or event_data.get("subject_domain"))
    new_process = _safe_str(event_data.get("NewProcessName") or event_data.get("new_process_name", ""))
    parent_process = _safe_str(event_data.get("ParentProcessName") or event_data.get("parent_process_name", ""))
    cmd_line = redact_sensitive_cmdline(_safe_str(event_data.get("CommandLine") or event_data.get("command_line", "")))
    process_id = _safe_str(event_data.get("NewProcessId") or event_data.get("process_id", ""))
    parent_pid = _safe_str(event_data.get("ProcessId") or event_data.get("parent_pid", ""))
    token_elev = _safe_str(event_data.get("TokenElevationType") or event_data.get("token_elevation_type", ""))

    user_canonical = _canonical_user_id(subject_username, subject_domain)
    device_canonical = _canonical_device_id(source_computer)

    entity_ids = [eid for eid in [device_canonical, user_canonical] if eid]

    payload = {
        "windows_event_id": 4688,
        "new_process_name": new_process,
        "parent_process_name": parent_process,
        "command_line": cmd_line,
        "process_id": process_id,
        "parent_process_id": parent_pid,
        "token_elevation_type": token_elev,
        "subject_username": subject_username,
        "user_id": user_canonical,
        "device_id": device_canonical,
    }
    return payload, entity_ids


def _build_scheduled_task_payload(
    event_data: Dict[str, Any],
    event_id_number: int,
    source_computer: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds payload for scheduled task events (4698, 4699)."""
    subject_username = _safe_str(event_data.get("SubjectUserName") or event_data.get("subject_username"))
    subject_domain = _safe_str(event_data.get("SubjectDomainName") or event_data.get("subject_domain"))
    task_name = _safe_str(event_data.get("TaskName") or event_data.get("task_name", ""))
    task_content = _safe_str(event_data.get("TaskContentXml") or event_data.get("task_content", ""))

    user_canonical = _canonical_user_id(subject_username, subject_domain)
    device_canonical = _canonical_device_id(source_computer)

    entity_ids = [eid for eid in [device_canonical, user_canonical] if eid]

    payload = {
        "windows_event_id": event_id_number,
        "task_name": task_name,
        "task_content_summary": task_content[:200] if task_content else "",
        "subject_username": subject_username,
        "user_id": user_canonical,
        "device_id": device_canonical,
        "action": "CREATED" if event_id_number == 4698 else "DELETED",
    }
    return payload, entity_ids


def _build_network_share_payload(
    event_data: Dict[str, Any],
    source_computer: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds payload for network share access events (5140)."""
    subject_username = _safe_str(event_data.get("SubjectUserName") or event_data.get("subject_username"))
    subject_domain = _safe_str(event_data.get("SubjectDomainName") or event_data.get("subject_domain"))
    share_name = _safe_str(event_data.get("ShareName") or event_data.get("share_name", ""))
    share_path = _safe_str(event_data.get("ShareLocalPath") or event_data.get("share_path", ""))
    ip_addr = _safe_str(event_data.get("IpAddress") or event_data.get("ip_address", ""))
    access_mask = _safe_str(event_data.get("AccessMask") or event_data.get("access_mask", ""))

    user_canonical = _canonical_user_id(subject_username, subject_domain)
    device_canonical = _canonical_device_id(source_computer)
    source_ip_id = f"ip:{ip_addr}" if ip_addr and ip_addr not in ("-", "") else ""

    entity_ids = [eid for eid in [device_canonical, user_canonical, source_ip_id] if eid]

    payload = {
        "windows_event_id": 5140,
        "share_name": share_name,
        "share_path": share_path,
        "source_ip": ip_addr,
        "access_mask": access_mask,
        "user_id": user_canonical,
        "device_id": device_canonical,
        "source_entity_id": source_ip_id or device_canonical,
        "target_entity_id": device_canonical,
    }
    return payload, entity_ids


def _build_network_filter_payload(
    event_data: Dict[str, Any],
    event_id_number: int,
    source_computer: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Builds payload for filtering platform connection events (5156, 5157)."""
    app_name = _safe_str(event_data.get("Application") or event_data.get("application", ""))
    direction = _safe_str(event_data.get("Direction") or event_data.get("direction", ""))
    src_addr = _safe_str(event_data.get("SourceAddress") or event_data.get("source_address", ""))
    src_port = _safe_str(event_data.get("SourcePort") or event_data.get("source_port", ""))
    dst_addr = _safe_str(event_data.get("DestAddress") or event_data.get("dest_address", ""))
    dst_port = _safe_str(event_data.get("DestPort") or event_data.get("dest_port", ""))
    protocol = _safe_str(event_data.get("Protocol") or event_data.get("protocol", ""))

    device_canonical = _canonical_device_id(source_computer)
    src_ip_id = f"ip:{src_addr}" if src_addr and src_addr not in ("-", "") else device_canonical
    dst_ip_id = f"ip:{dst_addr}" if dst_addr and dst_addr not in ("-", "") else ""

    entity_ids = [eid for eid in [src_ip_id, dst_ip_id, device_canonical] if eid]

    payload = {
        "windows_event_id": event_id_number,
        "application": app_name,
        "direction": direction,
        "source_address": src_addr,
        "source_port": src_port,
        "dest_address": dst_addr,
        "dest_port": dst_port,
        "protocol": protocol,
        "blocked": event_id_number == 5157,
        "source_entity_id": src_ip_id,
        "target_entity_id": dst_ip_id,
        "device_id": device_canonical,
        "port": int(dst_port) if dst_port.isdigit() else None,
    }
    return payload, entity_ids


# ---------------------------------------------------------------------------
# Main normalizer
# ---------------------------------------------------------------------------

class WindowsEventNormalizer:
    """
    Converts a raw Windows event record dict into a SecurityEventEnvelope.

    Expected input keys (snake_case or PascalCase EventData):
      - event_id_number (int): Windows event ID (e.g. 4624)
      - source_event_record_id: Windows record ID for deduplication
      - source_computer (str): Originating hostname
      - time_created (str|datetime|float): Event timestamp
      - channel (str): Log channel (Security, System, …)
      - event_data (dict): EventData key-value pairs from Windows

    ``collector_id`` is passed through to ``source`` and ``evidence_metadata``
    for source attribution in the graph.
    """

    def normalize(
        self,
        raw: Dict[str, Any],
        collector_id: str,
        device_node_id: str,
    ) -> SecurityEventEnvelope:
        """
        Normalises one raw Windows event record.

        Raises ValueError for structurally invalid records (missing required fields).
        """
        if not isinstance(raw, dict):
            raise TypeError(f"Expected event record to be a dict, got {type(raw).__name__}")

        event_id_number = int(raw.get("event_id_number") or raw.get("EventID") or 0)
        source_computer = _safe_str(
            raw.get("source_computer") or raw.get("Computer") or raw.get("hostname") or "unknown"
        )
        time_created = raw.get("time_created") or raw.get("TimeCreated") or raw.get("timestamp")
        channel = _safe_str(raw.get("channel") or raw.get("Channel") or "Security")
        source_event_record_id = raw.get("source_event_record_id") or raw.get("EventRecordID") or uuid.uuid4().hex
        event_data: Dict[str, Any] = raw.get("event_data") or raw.get("EventData") or {}

        occurred_at = _parse_timestamp(time_created)

        # Determine event type
        event_type = _EVENT_TYPE_MAP.get(event_id_number, SecurityEventType.ENDPOINT_ALERT)
        severity = _severity_for_event(event_id_number)

        # Build type-specific payload + entity IDs
        try:
            if event_id_number in (4624, 4625, 4648, 4672, 4720, 4726):
                payload, entity_ids = _build_logon_payload(event_data, event_id_number, source_computer)
            elif event_id_number == 4688:
                payload, entity_ids = _build_process_payload(event_data, source_computer)
            elif event_id_number in (4698, 4699):
                payload, entity_ids = _build_scheduled_task_payload(event_data, event_id_number, source_computer)
            elif event_id_number == 5140:
                payload, entity_ids = _build_network_share_payload(event_data, source_computer)
            elif event_id_number in (5156, 5157):
                payload, entity_ids = _build_network_filter_payload(event_data, event_id_number, source_computer)
            else:
                # Fallback: generic ENDPOINT_ALERT preserving raw data
                device_canonical = _canonical_device_id(source_computer)
                payload = {
                    "windows_event_id": event_id_number,
                    "channel": channel,
                    "raw_event_data": {k: str(v)[:500] for k, v in event_data.items()},
                }
                entity_ids = [device_canonical]
        except Exception as exc:
            logger.warning("Payload builder failed for event %d: %s", event_id_number, exc)
            device_canonical = _canonical_device_id(source_computer)
            payload = {"windows_event_id": event_id_number, "parse_error": str(exc)}
            entity_ids = [device_canonical]

        # Ensure entity_ids always has at least one entry
        if not entity_ids:
            entity_ids = [_canonical_device_id(source_computer)]

        # Remove empty entity IDs
        entity_ids = [eid for eid in entity_ids if eid]
        if not entity_ids:
            entity_ids = [_canonical_device_id(source_computer)]

        # Deterministic event_id for deduplication
        stable_event_id = _make_stable_event_id(
            source_event_record_id, source_computer, event_id_number, occurred_at
        )

        evidence_metadata = {
            "collector_id": collector_id,
            "device_node_id": device_node_id,
            "source_computer": source_computer,
            "channel": channel,
            "windows_event_id": event_id_number,
            "source_event_record_id": str(source_event_record_id),
            "schema": "windows_security_event_v1",
        }
        if raw.get("impersonation_prevented"):
            evidence_metadata["impersonation_prevented"] = True
            evidence_metadata["claimed_source_computer"] = raw.get("claimed_source_computer")

        return SecurityEventEnvelope(
            event_id=stable_event_id,
            schema_version="1.0.0",
            event_type=event_type,
            source=f"collector:{collector_id}",
            occurred_at=occurred_at,
            entity_ids=entity_ids,
            payload=payload,
            severity=severity,
            evidence_metadata=evidence_metadata,
        )

    def normalize_batch(
        self,
        records: List[Dict[str, Any]],
        collector_id: str,
        device_node_id: str,
    ) -> Tuple[List[SecurityEventEnvelope], List[Dict[str, Any]]]:
        """
        Normalises a batch of raw Windows event records.
        Returns (valid_envelopes, rejected_records_with_reason).
        """
        valid: List[SecurityEventEnvelope] = []
        rejected: List[Dict[str, Any]] = []

        for i, raw in enumerate(records):
            try:
                envelope = self.normalize(raw, collector_id, device_node_id)
                valid.append(envelope)
            except Exception as exc:
                logger.warning("Rejected event at index %d: %s", i, exc)
                rejected.append({
                    "index": i,
                    "reason": str(exc),
                    "event_id_number": (raw.get("event_id_number") or raw.get("EventID")) if isinstance(raw, dict) else None,
                    "source_computer": (raw.get("source_computer") or raw.get("Computer")) if isinstance(raw, dict) else None,
                })

        return valid, rejected


# Module-level singleton
_normalizer = WindowsEventNormalizer()


def normalize_windows_events(
    records: List[Dict[str, Any]],
    collector_id: str,
    device_node_id: str,
) -> Tuple[List[SecurityEventEnvelope], List[Dict[str, Any]]]:
    """Module-level convenience wrapper."""
    return _normalizer.normalize_batch(records, collector_id, device_node_id)

