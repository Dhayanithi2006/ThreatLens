"""
ThreatLens Governance & Controls - Evidence & Chain-of-Custody Ledger
Provides a tamper-evident, cryptographically chained SHA-256 evidence ledger
preserving dual timestamps, provenance, case/finding references, and verification history.
"""

import copy
import hashlib
import hmac
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.governance.schema import EvidenceRecord
from backend.governance.audit import record_audit_event

logger = logging.getLogger("threatlens.governance.evidence")

GENESIS_EVIDENCE_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

_evidence_lock = threading.Lock()
_evidence_ledger: List[EvidenceRecord] = []
_evidence_lookup: Dict[str, EvidenceRecord] = {}


def compute_evidence_hash(
    evidence_id: str,
    evidence_type: str,
    source: str,
    payload: Dict[str, Any],
    collected_at: str,
    ingested_at: str,
    previous_hash: str,
) -> str:
    """Computes a deterministic SHA-256 digest over the canonical evidence payload and previous hash."""
    envelope = {
        "evidence_id": evidence_id,
        "evidence_type": evidence_type,
        "source": source,
        "payload": payload,
        "collected_at": collected_at,
        "ingested_at": ingested_at,
        "previous_hash": previous_hash,
    }
    serialized = json.dumps(envelope, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class EvidenceLedgerService:
    """
    Centralized Chain-of-Custody Service managing immutable evidence records,
    cryptographic verification, cross-module indexing, and tamper detection.
    """

    @classmethod
    def register_evidence(
        cls,
        evidence_id: Optional[str] = None,
        evidence_type: str = "GENERIC_EVIDENCE",
        source: str = "THREATLENS_SOC",
        payload: Optional[Dict[str, Any]] = None,
        case_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        collected_at: Optional[datetime] = None,
        actor_id: str = "system",
    ) -> EvidenceRecord:
        """
        Appends an evidence item to the chain-of-custody ledger with a deterministic SHA-256 hash.
        Thread-safe and cryptographically chained.
        """
        now = datetime.now(timezone.utc)
        coll_time = collected_at or now
        eid = evidence_id or f"evi:{uuid.uuid4().hex[:12]}"
        safe_payload = payload or {}
        safe_provenance = provenance or {"ingestion_actor": actor_id, "environment": "PRODUCTION"}

        with _evidence_lock:
            # Check for existing record
            existing = _evidence_lookup.get(eid.lower())
            if existing:
                return copy.deepcopy(existing)

            prev_hash = _evidence_ledger[-1].sha256_hash if _evidence_ledger else GENESIS_EVIDENCE_HASH

            computed_hash = compute_evidence_hash(
                evidence_id=eid,
                evidence_type=evidence_type,
                source=source,
                payload=safe_payload,
                collected_at=coll_time.isoformat(),
                ingested_at=now.isoformat(),
                previous_hash=prev_hash,
            )

            record = EvidenceRecord(
                evidence_id=eid,
                evidence_type=evidence_type,
                source=source,
                provenance=safe_provenance,
                collected_at=coll_time,
                ingested_at=now,
                case_id=case_id,
                finding_id=finding_id,
                investigation_id=investigation_id,
                payload=safe_payload,
                sha256_hash=computed_hash,
                previous_hash=prev_hash,
                verification_status="VERIFIED",
                verification_history=[{
                    "action": "REGISTERED",
                    "timestamp": now.isoformat(),
                    "actor": actor_id,
                    "sha256_hash": computed_hash,
                }],
            )

            _evidence_ledger.append(record)
            _evidence_lookup[eid.lower()] = record

        # Anchor audit ledger event
        record_audit_event(
            event_type="EVIDENCE_REGISTERED",
            actor_id=actor_id,
            target_resource=f"evidence:{eid}",
            action="REGISTER",
            details={
                "evidence_id": eid,
                "evidence_type": evidence_type,
                "case_id": case_id,
                "sha256_hash": computed_hash,
            },
            related_case_id=case_id,
        )

        return copy.deepcopy(record)

    @classmethod
    def get_evidence(cls, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves an evidence record by ID."""
        with _evidence_lock:
            rec = _evidence_lookup.get(evidence_id.strip().lower())
            return copy.deepcopy(rec) if rec else None

    @classmethod
    def list_evidence(
        cls,
        case_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        evidence_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[EvidenceRecord]:
        """Lists evidence records with optional case/type filtering."""
        with _evidence_lock:
            records = list(_evidence_ledger)

        filtered = records
        if case_id:
            c_norm = case_id.strip().lower()
            filtered = [r for r in filtered if r.case_id and r.case_id.lower() == c_norm]
        if finding_id:
            f_norm = finding_id.strip().lower()
            filtered = [r for r in filtered if r.finding_id and r.finding_id.lower() == f_norm]
        if evidence_type:
            t_norm = evidence_type.strip().upper()
            filtered = [r for r in filtered if r.evidence_type.upper() == t_norm]

        return [copy.deepcopy(r) for r in filtered[-limit:]]

    @classmethod
    def verify_evidence(
        cls,
        evidence_id: str,
        provided_hash: Optional[str] = None,
        actor_id: str = "analyst-session",
    ) -> Dict[str, Any]:
        """
        Verifies SHA-256 payload digest for an evidence record against stored chain-of-custody entry.
        Records verification check in evidence verification history.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with _evidence_lock:
            record = _evidence_lookup.get(evidence_id.strip().lower())
            if not record:
                return {
                    "evidence_id": evidence_id,
                    "verified": False,
                    "status": "EVIDENCE_NOT_FOUND",
                    "computed_hash": None,
                    "detail": f"Evidence record '{evidence_id}' was not found in the chain of custody ledger.",
                }

            # Recalculate deterministic hash
            recomputed = compute_evidence_hash(
                evidence_id=record.evidence_id,
                evidence_type=record.evidence_type,
                source=record.source,
                payload=record.payload,
                collected_at=record.collected_at.isoformat(),
                ingested_at=record.ingested_at.isoformat(),
                previous_hash=record.previous_hash,
            )

            is_tamper_free = hmac.compare_digest(record.sha256_hash.lower(), recomputed.lower())

            if not is_tamper_free:
                record.verification_status = "TAMPER_DETECTED"
                record.verification_history.append({
                    "action": "VERIFICATION_FAILED",
                    "timestamp": now_iso,
                    "actor": actor_id,
                    "expected_hash": record.sha256_hash,
                    "recomputed_hash": recomputed,
                })
                return {
                    "evidence_id": evidence_id,
                    "verified": False,
                    "status": "TAMPER_DETECTED",
                    "computed_hash": recomputed,
                    "stored_hash": record.sha256_hash,
                    "detail": "Cryptographic digest mismatch: payload contents have been altered since ingestion.",
                }

            if provided_hash:
                matches_provided = hmac.compare_digest(record.sha256_hash.lower(), provided_hash.strip().lower())
                record.verification_history.append({
                    "action": "VERIFIED_PROVIDED_HASH",
                    "timestamp": now_iso,
                    "actor": actor_id,
                    "matched": matches_provided,
                })
                return {
                    "evidence_id": evidence_id,
                    "verified": matches_provided,
                    "status": "VERIFIED_TAMPER_FREE" if matches_provided else "HASH_MISMATCH",
                    "computed_hash": record.sha256_hash,
                    "provided_hash": provided_hash,
                    "detail": "Cryptographic hash matches stored ledger entry." if matches_provided else "Provided hash does not match computed ledger digest.",
                }

            record.verification_history.append({
                "action": "VERIFIED_INTEGRITY",
                "timestamp": now_iso,
                "actor": actor_id,
                "result": "TAMPER_FREE",
            })
            return {
                "evidence_id": evidence_id,
                "verified": True,
                "status": "VERIFIED_TAMPER_FREE",
                "computed_hash": record.sha256_hash,
                "detail": "Evidence record digest is verified against chain of custody.",
            }

    @classmethod
    def verify_chain_integrity(cls) -> Tuple[bool, Optional[str]]:
        """
        Validates cryptographic hash chaining across all entries in the evidence ledger.
        """
        with _evidence_lock:
            if not _evidence_ledger:
                return (True, None)

            expected_prev = GENESIS_EVIDENCE_HASH
            seen_ids = set()

            for idx, entry in enumerate(_evidence_ledger):
                # 1. Check duplicate evidence_id
                if entry.evidence_id in seen_ids:
                    return (False, f"Duplicate evidence_id at index {idx}: '{entry.evidence_id}'.")
                seen_ids.add(entry.evidence_id)

                # 2. Check previous hash linkage
                if entry.previous_hash != expected_prev:
                    return (False, f"Evidence chain break at index {idx} (ID: {entry.evidence_id}): previous_hash '{entry.previous_hash}' != expected '{expected_prev}'.")

                # 3. Recalculate payload hash
                recomputed = compute_evidence_hash(
                    evidence_id=entry.evidence_id,
                    evidence_type=entry.evidence_type,
                    source=entry.source,
                    payload=entry.payload,
                    collected_at=entry.collected_at.isoformat(),
                    ingested_at=entry.ingested_at.isoformat(),
                    previous_hash=entry.previous_hash,
                )

                if entry.sha256_hash != recomputed:
                    return (False, f"Evidence digest mismatch at index {idx} (ID: {entry.evidence_id}): stored '{entry.sha256_hash}' != computed '{recomputed}'.")

                expected_prev = entry.sha256_hash

            return (True, None)

    @classmethod
    def auto_sync_from_subsystems(cls) -> int:
        """
        Discovers unindexed cases, collector devices, and findings from Modules 0-4
        and indexes them into the chain-of-custody ledger.
        """
        indexed_count = 0

        # 1. Index cases from Module 1
        try:
            from backend.services.case_store import default_case_repo
            cases = default_case_repo.list_cases()
            for c in cases:
                eid = f"evi:case:{c.case_id}"
                if not cls.get_evidence(eid):
                    coll_time = None
                    if c.timestamp:
                        try:
                            coll_time = datetime.fromisoformat(c.timestamp.replace("Z", "+00:00"))
                        except Exception:
                            coll_time = None

                    cls.register_evidence(
                        evidence_id=eid,
                        evidence_type="EMAIL_FORENSICS",
                        source="EMAIL_GATEWAY",
                        payload={
                            "case_id": c.case_id,
                            "subject": c.subject,
                            "sender": c.sender,
                            "recipient": c.recipient,
                            "threat_score": c.threat_score,
                            "primary_threat": c.primary_threat,
                            "iocs": c.iocs,
                        },
                        case_id=c.case_id,
                        provenance={"gateway": "EXCHANGE_ONLINE", "case_status": c.status},
                        collected_at=coll_time,
                        actor_id="case-sync-worker",
                    )
                    indexed_count += 1
        except Exception as exc:
            logger.debug("Evidence auto-sync cases: %s", exc)

        # 2. Index collector devices from Module 0
        try:
            from backend.telemetry.collector_registry import default_collector_registry
            devices = default_collector_registry.list_devices()
            for d in devices:
                eid = f"evi:device:{d.device_id}"
                if not cls.get_evidence(eid):
                    cls.register_evidence(
                        evidence_id=eid,
                        evidence_type="ENDPOINT_TELEMETRY",
                        source="EDR_COLLECTOR",
                        payload={
                            "device_id": d.device_id,
                            "hostname": d.hostname,
                            "os_version": d.os_version,
                            "status": d.status.value if hasattr(d.status, "value") else str(d.status),
                            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                        },
                        provenance={"collector_version": getattr(d, "collector_version", "1.0.0")},
                        collected_at=d.last_seen,
                        actor_id="collector-registry-sync",
                    )
                    indexed_count += 1
        except Exception as exc:
            logger.debug("Evidence auto-sync devices: %s", exc)

        return indexed_count

    @classmethod
    def reset_ledger(cls) -> None:
        """Resets ledger state (primarily for test suite isolation)."""
        with _evidence_lock:
            _evidence_ledger.clear()
            _evidence_lookup.clear()
