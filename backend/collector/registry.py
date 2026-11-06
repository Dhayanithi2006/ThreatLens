"""
ThreatLens Collector - Device Registry
Manages enrolled collector devices: enrolment, token issuance, revocation,
last-seen tracking and event counters.

Storage: file-backed JSON store (COLLECTOR_REGISTRY_PATH env var).
No credentials are stored in plain-text — only HMAC-SHA256 token digests.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from filelock import FileLock

from backend.core import config as _cfg

logger = logging.getLogger("threatlens.collector.registry")

# ---------------------------------------------------------------------------
# Registry storage path & cross-process locking
# ---------------------------------------------------------------------------
_REGISTRY_PATH = Path(
    os.getenv("COLLECTOR_REGISTRY_PATH", "backend/data/collector_registry.json")
)

def _get_registry_path() -> Path:
    global _REGISTRY_PATH
    env_path = os.getenv("COLLECTOR_REGISTRY_PATH")
    if env_path:
        return Path(env_path)
    return _REGISTRY_PATH

def _get_lock_path() -> Path:
    p = _get_registry_path()
    return p.with_name(p.name + ".lock")

def _get_stats_path() -> Path:
    p = _get_registry_path()
    return p.with_name(p.stem + "_telemetry_stats.json")

_THREAD_LOCK = threading.RLock()


@contextmanager
def _registry_lock():
    """
    Acquires both an in-process threading.RLock and an inter-process FileLock to guarantee
    safe read-modify-write synchronization across multi-worker Uvicorn processes.
    """
    with _THREAD_LOCK:
        lock_path = _get_lock_path()
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            file_lock = FileLock(str(lock_path), timeout=15.0)
            with file_lock:
                yield
        except Exception as exc:
            logger.error("Registry file lock acquisition error: %s — falling back to thread lock", exc)
            yield


def _load_stats_unlocked() -> Dict[str, Any]:
    path = _get_stats_path()
    if not path.exists():
        return {
            "total_accepted_events": 0,
            "total_rejected_events": 0,
            "auth_failures_count": 0,
            "recent_auth_failures": [],
            "recent_ingestion_activity": [],
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.error("Failed to load telemetry stats: %s", e)
    return {
        "total_accepted_events": 0,
        "total_rejected_events": 0,
        "auth_failures_count": 0,
        "recent_auth_failures": [],
        "recent_ingestion_activity": [],
    }


def _save_stats_unlocked(data: Dict[str, Any]) -> None:
    path = _get_stats_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        logger.error("Failed to save telemetry stats: %s", e)


# ---------------------------------------------------------------------------
# Data classes (plain dicts for JSON portability)
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_token() -> str:
    """Generates a cryptographically random 48-character collector token."""
    return secrets.token_urlsafe(36)  # ~288 bits entropy


def _digest_token(token: str) -> str:
    """Returns HMAC-SHA256 hex digest of the token keyed on SECRET_KEY."""
    key = _cfg.COLLECTOR_REGISTRY_SECRET.encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def _verify_token(raw: str, stored_digest: str) -> bool:
    """Constant-time comparison of provided token against stored digest."""
    computed = _digest_token(raw)
    return hmac.compare_digest(computed, stored_digest)


# ---------------------------------------------------------------------------
# Registry I/O (thread-safe and atomic across read-modify-write)
# ---------------------------------------------------------------------------

def _load_registry_unlocked() -> Dict[str, Any]:
    path = _get_registry_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load collector registry: %s", e)
    return {}


def _save_registry_unlocked(data: Dict[str, Any]) -> None:
    path = _get_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError as e:
        logger.error("Failed to save collector registry: %s", e)


def _load_registry() -> Dict[str, Any]:
    with _registry_lock():
        return _load_registry_unlocked()


def _save_registry(data: Dict[str, Any]) -> None:
    with _registry_lock():
        _save_registry_unlocked(data)


def auto_provision_device_node(
    hostname: str,
    ip_address: str = "",
    os_version: str = "Windows",
) -> None:
    """
    Idempotently provisions or updates the Device node in Neo4j for an enrolled collector.
    Ensures that incoming security telemetry resolves cleanly in GraphOps without NodeNotFoundError.
    """
    clean_host = hostname.lower().split(".")[0].strip()
    device_id = f"device:{clean_host}"
    cypher = """
    MERGE (d:Device {id: $id})
    ON CREATE SET
        d.device_id = $device_id,
        d.hostname = $hostname,
        d.ip_address = $ip,
        d.os = $os,
        d.criticality = 'MEDIUM',
        d.created_at = $timestamp
    ON MATCH SET
        d.hostname = $hostname,
        d.last_enrolled = $timestamp
    """
    params = {
        "id": device_id,
        "device_id": clean_host.upper(),
        "hostname": hostname,
        "ip": ip_address or "127.0.0.1",
        "os": os_version or "Windows",
        "timestamp": _now_iso(),
    }
    try:
        from backend.graphops.client import get_graphops_client
        client = get_graphops_client()
        try:
            client.execute_query(cypher, params)
            logger.info("Auto-provisioned Neo4j Device node for enrolled collector: %s", device_id)
        except Exception as exc:
            logger.debug("Neo4j auto-provision note for %s: %s", device_id, exc)
            fallback = getattr(client, "_get_mock_fallback", lambda: None)()
            if fallback:
                fallback.execute_query(cypher, params)
            else:
                from backend.graphops.mock_client import get_mock_graphops_client
                get_mock_graphops_client().execute_query(cypher, params)
    finally:
        try:
            from backend.graphops.centrality import invalidate_centrality_cache
            invalidate_centrality_cache()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CollectorRecord:
    """View of a single enrolled collector device."""

    __slots__ = (
        "collector_id",
        "hostname",
        "ip_address",
        "os_version",
        "enrolled_at",
        "enrolled_by",
        "last_seen",
        "event_count",
        "error_count",
        "status",
        "device_node_id",
        "recent_errors",
        "pending_spool_events",
        "auth_failures",
    )

    def __init__(self, d: Dict[str, Any]):
        self.collector_id: str = d["collector_id"]
        self.hostname: str = d["hostname"]
        self.ip_address: str = d.get("ip_address", "")
        self.os_version: str = d.get("os_version", "Windows")
        self.enrolled_at: str = d.get("enrolled_at", "")
        self.enrolled_by: str = d.get("enrolled_by", "")
        self.last_seen: Optional[str] = d.get("last_seen")
        self.event_count: int = d.get("event_count", 0)
        self.error_count: int = d.get("error_count", 0)
        self.status: str = d.get("status", "ENROLLED")
        self.device_node_id: str = d.get("device_node_id", "")
        self.recent_errors: List[str] = d.get("recent_errors", [])
        self.pending_spool_events: int = d.get("pending_spool_events", 0)
        self.auth_failures: int = d.get("auth_failures", 0)

    def online_status(self, threshold_seconds: int = 600) -> str:
        """
        Determines real-time operational connectivity state:
        - REVOKED: Credentials explicitly invalidated
        - ENROLLED (PENDING): Initial state awaiting first event delivery
        - ACTIVELY SENDING: Connected and streaming within threshold (default 10m)
        - DEGRADED: Inactive beyond threshold with logged errors
        - CONNECTED (IDLE): Past communication recorded, but silent beyond threshold
        """
        if self.status == "REVOKED":
            return "REVOKED"
        if not self.last_seen or (self.event_count or 0) == 0:
            return "ENROLLED (PENDING)"
        try:
            ls = datetime.fromisoformat(self.last_seen.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - ls).total_seconds()
            if age <= threshold_seconds:
                return "ACTIVELY SENDING"
            else:
                if (self.error_count or 0) > 0:
                    return "DEGRADED"
                return "CONNECTED (IDLE)"
        except Exception:
            return "ENROLLED (PENDING)"

    def is_online(self, threshold_seconds: int = 600) -> bool:
        return self.online_status(threshold_seconds) == "ACTIVELY SENDING"

    def to_dict(self) -> Dict[str, Any]:
        d = {k: getattr(self, k) for k in self.__slots__}
        d["online_status"] = self.online_status()
        d["is_online"] = self.is_online()
        return d

    def is_active(self) -> bool:
        return self.status == "ACTIVE"

    def is_enrolled(self) -> bool:
        return self.status in ("ENROLLED", "ACTIVE")


def enrol_collector(
    hostname: str,
    ip_address: str,
    os_version: str,
    enrolled_by: str,
) -> Dict[str, str]:
    """
    Registers a new collector device and issues a one-time secret token.

    Returns a dict with ``collector_id`` and ``token`` (raw — shown once).
    The registry stores only the HMAC digest; the caller must relay the raw
    token to the administrator for installation on the Windows host.
    """
    clean_host = hostname.lower().split(".")[0].strip()
    device_node_id = f"device:{clean_host}"

    result = None
    with _registry_lock():
        registry = _load_registry_unlocked()

        # Prevent duplicate hostname enrolment (update instead)
        for cid, rec in registry.items():
            if rec.get("hostname", "").lower() == hostname.lower() or rec.get("device_node_id") == device_node_id:
                # Re-issue token for existing collector
                token = _make_token()
                rec["token_digest"] = _digest_token(token)
                rec["enrolled_at"] = _now_iso()
                rec["enrolled_by"] = enrolled_by
                rec["ip_address"] = ip_address
                rec["os_version"] = os_version
                rec["status"] = "ENROLLED"
                rec["last_seen"] = None
                rec["event_count"] = 0
                rec["error_count"] = 0
                rec["recent_errors"] = []
                _save_registry_unlocked(registry)
                logger.info("Re-enrolled existing collector %s (%s)", cid, hostname)
                result = {"collector_id": cid, "token": token}
                break

        if result is None:
            collector_id = f"col-{secrets.token_hex(6)}"
            token = _make_token()

            registry[collector_id] = {
                "collector_id": collector_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "os_version": os_version,
                "enrolled_at": _now_iso(),
                "enrolled_by": enrolled_by,
                "last_seen": None,
                "event_count": 0,
                "error_count": 0,
                "status": "ENROLLED",
                "device_node_id": device_node_id,
                "recent_errors": [],
                "token_digest": _digest_token(token),
            }
            _save_registry_unlocked(registry)
            logger.info("Enrolled new collector %s (%s)", collector_id, hostname)
            result = {"collector_id": collector_id, "token": token}

    # Auto-provision device in Neo4j outside the lock to guarantee graph resolution
    auto_provision_device_node(hostname, ip_address, os_version)

    # Record tamper-evident audit ledger entry (never logs raw secret token)
    try:
        from backend.governance.audit import record_audit_event
        record_audit_event(
            event_type="COLLECTOR_ENROLLED",
            actor_id=enrolled_by or "system",
            target_resource=f"collector:{result['collector_id']}",
            action="ENROLL",
            details={
                "collector_id": result["collector_id"],
                "hostname": hostname,
                "ip_address": ip_address,
                "os_version": os_version,
                "device_node_id": device_node_id,
            },
        )
    except Exception as exc:
        logger.debug("Audit logging for collector enrollment skipped: %s", exc)

    return result


def record_auth_failure(
    collector_id: str,
    ip_address: str = "",
    reason: str = "INVALID_CREDENTIALS",
) -> None:
    """Records an authentication failure both globally and on the specific collector if known."""
    with _registry_lock():
        stats = _load_stats_unlocked()
        stats["auth_failures_count"] = stats.get("auth_failures_count", 0) + 1
        failures = stats.get("recent_auth_failures", [])
        failures.append({
            "timestamp": _now_iso(),
            "collector_id": collector_id or "UNKNOWN",
            "ip_address": ip_address,
            "reason": reason,
        })
        stats["recent_auth_failures"] = failures[-50:]  # Keep last 50
        _save_stats_unlocked(stats)

        # Update per-collector counter if collector exists
        if collector_id:
            reg = _load_registry_unlocked()
            if collector_id in reg:
                reg[collector_id]["auth_failures"] = reg[collector_id].get("auth_failures", 0) + 1
                _save_registry_unlocked(reg)

    logger.warning("Collector authentication failure: id=%s ip=%s reason=%s", collector_id, ip_address, reason)

    try:
        from backend.governance.audit import record_audit_event
        record_audit_event(
            event_type="COLLECTOR_AUTH_FAILED",
            actor_id=collector_id or "unknown",
            target_resource=f"collector:{collector_id}",
            action="AUTHENTICATE",
            details={"collector_id": collector_id, "ip_address": ip_address, "reason": reason},
        )
    except Exception as exc:
        logger.debug("Audit logging for auth failure skipped: %s", exc)


def record_ingestion_activity(
    collector_id: str,
    hostname: str,
    accepted: int,
    rejected: int,
    duplicate: int,
    published: int,
    is_synthetic: bool = False,
    errors: Optional[List[str]] = None,
    pending_spool_events: Optional[int] = None,
) -> None:
    """Records an ingestion activity batch for the security overview stream."""
    with _registry_lock():
        stats = _load_stats_unlocked()
        stats["total_accepted_events"] = stats.get("total_accepted_events", 0) + accepted
        stats["total_rejected_events"] = stats.get("total_rejected_events", 0) + rejected
        activity = stats.get("recent_ingestion_activity", [])
        activity.append({
            "timestamp": _now_iso(),
            "collector_id": collector_id,
            "hostname": hostname,
            "accepted": accepted,
            "rejected": rejected,
            "duplicate": duplicate,
            "published": published,
            "is_synthetic": is_synthetic,
            "telemetry_source": "SYNTHETIC_SIMULATION" if is_synthetic else "GENUINE_WINDOWS_TELEMETRY",
            "status": "ACCEPTED" if (published > 0 or accepted > 0) else ("REJECTED" if rejected > 0 else "IDLE"),
            "errors": errors or [],
            "pending_spool_events": pending_spool_events if pending_spool_events is not None else 0,
        })
        stats["recent_ingestion_activity"] = activity[-50:]  # Keep last 50
        _save_stats_unlocked(stats)


def authenticate_collector(
    collector_id: str,
    token: str,
    ip_address: str = "",
) -> Optional[CollectorRecord]:
    """
    Validates (collector_id, token) pair.
    Returns CollectorRecord on success; None on failure.
    Records authentication failures on bad credentials or revoked devices.
    Never logs the raw token.
    """
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)

    if rec is None:
        record_auth_failure(collector_id, ip_address, "UNKNOWN_COLLECTOR")
        return None

    if rec.get("status") == "REVOKED":
        record_auth_failure(collector_id, ip_address, "REVOKED_CREDENTIALS")
        return None

    stored_digest = rec.get("token_digest", "")
    if not stored_digest or not _verify_token(token, stored_digest):
        record_auth_failure(collector_id, ip_address, "INVALID_TOKEN")
        return None

    return CollectorRecord(rec)


def record_event_delivery(
    collector_id: str,
    count: int = 1,
    error: Optional[str] = None,
    accepted: int = 0,
    rejected: int = 0,
    pending_spool_events: Optional[int] = None,
) -> None:
    """Updates last-seen, event/error counters and status after a successful or failed delivery."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)
        if rec is None:
            return
        rec["last_seen"] = _now_iso()
        if pending_spool_events is not None:
            rec["pending_spool_events"] = pending_spool_events
        if count > 0:
            rec["event_count"] = rec.get("event_count", 0) + count
            rec["status"] = "ACTIVE"
        if error:
            rec["error_count"] = rec.get("error_count", 0) + 1
            errs: List[str] = rec.get("recent_errors", [])
            errs.append(f"{_now_iso()} {error[:200]}")
            rec["recent_errors"] = errs[-10:]  # keep last 10
        _save_registry_unlocked(registry)


def get_collector_overview(online_threshold_seconds: int = 600) -> Dict[str, Any]:
    """Compiles aggregated security overview metrics for all enrolled collectors and telemetry streams."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        stats = _load_stats_unlocked()

    collectors = [CollectorRecord(v) for v in registry.values()]
    online_count = sum(1 for c in collectors if c.online_status(online_threshold_seconds) == "ACTIVELY SENDING")
    offline_count = sum(1 for c in collectors if c.online_status(online_threshold_seconds) in ("OFFLINE", "CONNECTED (IDLE)", "ENROLLED (PENDING)", "DEGRADED"))
    revoked_count = sum(1 for c in collectors if c.status == "REVOKED")
    total_events = sum(c.event_count for c in collectors)
    total_errors = sum(c.error_count for c in collectors)

    return {
        "total_registered_devices": len(collectors),
        "online_collectors": online_count,
        "offline_collectors": offline_count,
        "revoked_collectors": revoked_count,
        "total_events_received": total_events,
        "total_accepted_events": stats.get("total_accepted_events", total_events),
        "total_rejected_events": stats.get("total_rejected_events", 0),
        "total_ingestion_errors": total_errors,
        "authentication_failures_count": stats.get("auth_failures_count", 0),
        "recent_auth_failures": stats.get("recent_auth_failures", []),
        "recent_ingestion_activity": stats.get("recent_ingestion_activity", []),
        "collectors": [c.to_dict() for c in collectors],
        "timestamp": _now_iso(),
    }


def list_collectors() -> List[CollectorRecord]:
    """Returns all registered collectors."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        return [CollectorRecord(v) for v in registry.values()]


def get_collector(collector_id: str) -> Optional[CollectorRecord]:
    """Returns a single collector record by ID."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)
        return CollectorRecord(rec) if rec else None


def revoke_collector(collector_id: str, actor: str = "system") -> bool:
    """Revokes a collector token (sets status=REVOKED). Returns True if found."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)
        if rec is None:
            return False
        rec["status"] = "REVOKED"
        rec["token_digest"] = ""  # Invalidate stored digest immediately
        _save_registry_unlocked(registry)
        logger.info("Collector %s revoked by %s", collector_id, actor)

    # Record tamper-evident audit ledger entry
    try:
        from backend.governance.audit import record_audit_event
        record_audit_event(
            event_type="COLLECTOR_REVOKED",
            actor_id=actor or "system",
            target_resource=f"collector:{collector_id}",
            action="REVOKE",
            details={"collector_id": collector_id, "revoked_by": actor},
        )
    except Exception as exc:
        logger.debug("Audit logging for collector revocation skipped: %s", exc)

    return True

