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
        # Fast path if client is already known to be in mock/disconnected mode
        if getattr(client, "mock_mode", False) is True or getattr(client, "_is_available", None) is False:
            fallback = getattr(client, "_get_mock_fallback", lambda: None)()
            if fallback:
                fallback.execute_query(cypher, params)
            return

        client.execute_query(cypher, params)
        logger.info("Auto-provisioned Neo4j Device node for enrolled collector: %s", device_id)
    except Exception as exc:
        logger.debug("Neo4j auto-provision note for %s: %s", device_id, exc)


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

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}

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


def authenticate_collector(collector_id: str, token: str) -> Optional[CollectorRecord]:
    """
    Validates (collector_id, token) pair.
    Returns CollectorRecord on success; None on failure.
    Never logs the raw token.
    """
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)
        if rec is None:
            return None
        stored_digest = rec.get("token_digest", "")
        if not stored_digest:
            return None
        if not _verify_token(token, stored_digest):
            return None
        if rec.get("status") == "REVOKED":
            return None
        return CollectorRecord(rec)


def record_event_delivery(
    collector_id: str,
    count: int = 1,
    error: Optional[str] = None,
) -> None:
    """Updates last-seen, event/error counters and status after a successful or failed delivery."""
    with _registry_lock():
        registry = _load_registry_unlocked()
        rec = registry.get(collector_id)
        if rec is None:
            return
        rec["last_seen"] = _now_iso()
        if error:
            rec["error_count"] = rec.get("error_count", 0) + 1
            errs: List[str] = rec.get("recent_errors", [])
            errs.append(f"{_now_iso()} {error[:200]}")
            rec["recent_errors"] = errs[-10:]  # keep last 10
        else:
            rec["event_count"] = rec.get("event_count", 0) + count
            rec["status"] = "ACTIVE"
        _save_registry_unlocked(registry)


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


def revoke_collector(collector_id: str, actor: str) -> bool:
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

