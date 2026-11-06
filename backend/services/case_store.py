"""
MailTrace AI - Case Repository & Storage
Feature 6: Attack Graph + Campaign Correlation
"""

import json
import logging
import os
from pathlib import Path
import threading
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from filelock import FileLock

from backend.models.graph import CaseRecord

logger = logging.getLogger("threatlens.case_store")

_DEFAULT_CASES_PATH = Path(
    os.getenv("CASES_STORE_PATH", "backend/data/cases_store.json")
)


class CaseRepository:
    """
    Thread-safe, file-backed repository for indexing and querying analyzed email investigation cases.
    Persists cases, status updates, notes, and timeline events across application restarts.
    """
    def __init__(self, storage_path: Optional[Path] = None):
        self._cases: Dict[str, CaseRecord] = {}
        self._lock = threading.RLock()
        self._storage_path = storage_path or _DEFAULT_CASES_PATH
        if not self._load_from_disk():
            self._prefill_historical_cases()
            self._save_to_disk()

    def _get_storage_path(self) -> Path:
        env_path = os.getenv("CASES_STORE_PATH")
        if env_path:
            return Path(env_path)
        return self._storage_path

    def _save_to_disk(self) -> None:
        path = self._get_storage_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = path.with_name(path.name + ".lock")
            with FileLock(str(lock_path), timeout=5):
                data = {cid: case.model_dump() for cid, case in self._cases.items()}
                temp_path = path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                temp_path.replace(path)
        except Exception as e:
            logger.warning(f"Failed to persist case store to disk: {e}")

    def _load_from_disk(self) -> bool:
        path = self._get_storage_path()
        if not path.exists():
            return False
        lock_path = path.with_name(path.name + ".lock")
        try:
            with FileLock(str(lock_path), timeout=5):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                loaded_cases = {}
                for cid, cdata in data.items():
                    loaded_cases[cid] = CaseRecord(**cdata)
                self._cases = loaded_cases
                return True
        except Exception as e:
            logger.warning(f"Failed to load case store from disk: {e}")
            return False

    def _prefill_historical_cases(self):
        """Initializes repository with realistic historical investigation cases for campaign demonstration."""
        historical = [
            CaseRecord(
                case_id="MT-101",
                subject="URGENT: Verify your account immediately",
                sender="Security Alert <service-update@alert-center.xyz>",
                recipient="victim1@corporation.com",
                threat_score=100,
                risk_level="CRITICAL",
                primary_threat="PHISHING",
                status="OPEN",
                assigned_to="soc_analyst@threatlens.io",
                is_sample=True,
                iocs={
                    "domains": ["alert-center.xyz", "corporation.com"],
                    "ips": ["185.190.140.22", "194.26.29.112"],
                    "urls": ["http://secure-login.alert-center.xyz/auth/verify"],
                    "emails": ["service-update@alert-center.xyz"],
                    "hashes": ["7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"]
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
                forensics_summary={
                    "spf": "FAIL",
                    "dkim": "FAIL",
                    "dmarc": "FAIL",
                    "auth_results": "spf=fail (sender IP 185.190.140.22); dkim=fail header.d=alert-center.xyz; dmarc=fail action=quarantine",
                    "sender_ip": "185.190.140.22",
                    "originating_server": "mail-relay.alert-center.xyz"
                },
                evidence_references=[
                    {
                        "evidence_id": "EV-EML-101",
                        "type": "RAW_EMAIL",
                        "filename": "account_verification_urgent.eml",
                        "sha256": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
                    },
                    {
                        "evidence_id": "EV-IOC-IP-01",
                        "type": "NETWORK_INDICATOR",
                        "value": "185.190.140.22",
                        "provenance": "SMTP Received Header"
                    }
                ],
                notes=[
                    {
                        "note_id": "NOTE-001",
                        "author": "soc_lead@threatlens.io",
                        "timestamp": "2026-08-28T10:18:00Z",
                        "note": "Initial triage: High-confidence phishing with credential-harvesting payload. Escalated to Tier 2."
                    }
                ],
                timeline=[
                    {
                        "event_id": "EVT-101-01",
                        "original_event_time": "2026-08-28T10:14:22Z",
                        "ingested_at": "2026-08-28T10:15:00Z",
                        "source": "SMTP_RELAY",
                        "event_type": "EMAIL_RECEIPT",
                        "title": "External Email Ingress Accepted",
                        "description": "Inbound SMTP gateway accepted message from 185.190.140.22 for victim1@corporation.com",
                        "severity": "LOW",
                        "evidence_ref": "EV-EML-101",
                        "details": {"client_ip": "185.190.140.22", "helo": "mail-relay.alert-center.xyz"}
                    },
                    {
                        "event_id": "EVT-101-02",
                        "original_event_time": "2026-08-28T10:14:45Z",
                        "ingested_at": "2026-08-28T10:15:01Z",
                        "source": "AUTH_VALIDATOR",
                        "event_type": "AUTH_FAILURE",
                        "title": "SPF/DKIM/DMARC Authentication Failure",
                        "description": "SPF softfail and unsigned DKIM header detected for domain alert-center.xyz",
                        "severity": "HIGH",
                        "evidence_ref": "EV-EML-101",
                        "details": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
                    },
                    {
                        "event_id": "EVT-101-03",
                        "original_event_time": "2026-08-28T10:15:00Z",
                        "ingested_at": "2026-08-28T10:15:02Z",
                        "source": "THREAT_DETECTOR",
                        "event_type": "DETECTION_TRIGGERED",
                        "title": "ThreatLens Detection: Phishing Score 100/100",
                        "description": "Automated pipeline classified email as CRITICAL RISK Phishing targeting account credentials.",
                        "severity": "CRITICAL",
                        "evidence_ref": "CASE-MT-101",
                        "details": {"threat_score": 100, "primary_threat": "PHISHING"}
                    },
                    {
                        "event_id": "EVT-101-04",
                        "original_event_time": "2026-08-28T10:18:00Z",
                        "ingested_at": "2026-08-28T10:18:00Z",
                        "source": "ANALYST_ACTION",
                        "event_type": "CASE_ASSIGNED",
                        "title": "Case Assigned to SOC Analyst",
                        "description": "Analyst soc_analyst@threatlens.io assigned for triage and exposure blast radius investigation.",
                        "severity": "LOW",
                        "evidence_ref": "NOTE-001",
                        "details": {"assigned_to": "soc_analyst@threatlens.io", "action": "ASSIGN"}
                    }
                ],
                timestamp="2026-08-28T10:15:00Z"
            ),
            CaseRecord(
                case_id="MT-102",
                subject="Notice: Your corporate account is flagged for deactivation",
                sender="IT Support Desk <notify@alert-center.xyz>",
                recipient="victim2@corporation.com",
                threat_score=95,
                risk_level="CRITICAL",
                primary_threat="PHISHING",
                status="INVESTIGATING",
                assigned_to="dfir_specialist@threatlens.io",
                is_sample=True,
                iocs={
                    "domains": ["alert-center.xyz", "corporation.com"],
                    "ips": ["185.190.140.22"],
                    "urls": ["http://secure-login.alert-center.xyz/auth"],
                    "emails": ["notify@alert-center.xyz"],
                    "hashes": []
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
                forensics_summary={
                    "spf": "FAIL",
                    "dkim": "FAIL",
                    "dmarc": "FAIL",
                    "sender_ip": "185.190.140.22"
                },
                evidence_references=[
                    {"evidence_id": "EV-EML-102", "type": "RAW_EMAIL", "filename": "account_deactivation.eml"}
                ],
                notes=[
                    {
                        "note_id": "NOTE-002",
                        "author": "dfir_specialist@threatlens.io",
                        "timestamp": "2026-08-28T11:50:00Z",
                        "note": "Coincides with MT-101 infrastructure (same IP 185.190.140.22). Correlated campaign cluster detected."
                    }
                ],
                timeline=[
                    {
                        "event_id": "EVT-102-01",
                        "original_event_time": "2026-08-28T11:44:10Z",
                        "ingested_at": "2026-08-28T11:45:00Z",
                        "source": "SMTP_RELAY",
                        "event_type": "EMAIL_RECEIPT",
                        "title": "Inbound Transmission Received",
                        "description": "Message received for victim2@corporation.com from 185.190.140.22",
                        "severity": "LOW",
                        "evidence_ref": "EV-EML-102",
                        "details": {}
                    },
                    {
                        "event_id": "EVT-102-02",
                        "original_event_time": "2026-08-28T11:45:00Z",
                        "ingested_at": "2026-08-28T11:45:01Z",
                        "source": "THREAT_DETECTOR",
                        "event_type": "DETECTION_TRIGGERED",
                        "title": "Phishing Threat Scored 95/100",
                        "description": "Identical infrastructure to MT-101 campaign cluster.",
                        "severity": "CRITICAL",
                        "evidence_ref": "CASE-MT-102",
                        "details": {}
                    }
                ],
                timestamp="2026-08-28T11:45:00Z"
            ),
            CaseRecord(
                case_id="MT-103",
                subject="Action Required: Microsoft 365 Password Expiration Notice",
                sender="Microsoft IT Support <admin-office365@support-portal.top>",
                recipient="employee@corporation.com",
                threat_score=100,
                risk_level="CRITICAL",
                primary_threat="SPOOFING / IMPERSONATION",
                status="OPEN",
                assigned_to="soc_analyst@threatlens.io",
                is_sample=True,
                iocs={
                    "domains": ["support-portal.top", "corporation.com"],
                    "ips": ["185.190.140.22"],
                    "urls": ["http://185.190.140.22/login"],
                    "emails": ["admin-office365@support-portal.top"],
                    "hashes": []
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
                forensics_summary={
                    "spf": "FAIL",
                    "dkim": "NONE",
                    "dmarc": "FAIL",
                    "sender_ip": "185.190.140.22"
                },
                evidence_references=[],
                notes=[],
                timeline=[
                    {
                        "event_id": "EVT-103-01",
                        "original_event_time": "2026-08-28T14:01:30Z",
                        "ingested_at": "2026-08-28T14:02:00Z",
                        "source": "SMTP_RELAY",
                        "event_type": "EMAIL_RECEIPT",
                        "title": "Spoofed Microsoft Notice Ingress",
                        "description": "Spoofed Microsoft administrative notice received from 185.190.140.22",
                        "severity": "CRITICAL",
                        "evidence_ref": "CASE-MT-103",
                        "details": {}
                    }
                ],
                timestamp="2026-08-28T14:02:00Z"
            ),
            CaseRecord(
                case_id="MT-201",
                subject="Urgent Payment Request - Strictly Confidential",
                sender="CEO James Vance <ceo@corporation.com>",
                recipient="accounting@corporation.com",
                threat_score=85,
                risk_level="CRITICAL",
                primary_threat="BEC",
                status="CONTAINED",
                assigned_to="incident_commander@threatlens.io",
                is_sample=True,
                iocs={
                    "domains": ["corporation.com", "gmail.com"],
                    "ips": ["198.51.100.44"],
                    "urls": [],
                    "emails": ["ceo@corporation.com", "james.vance.confidential@gmail.com"],
                    "hashes": ["664f61f41747557613589"]
                },
                intel_summary={"malicious_count": 0, "suspicious_count": 1, "status": "SUSPICIOUS"},
                forensics_summary={
                    "spf": "FAIL",
                    "dkim": "FAIL",
                    "dmarc": "FAIL",
                    "sender_ip": "198.51.100.44"
                },
                evidence_references=[],
                notes=[
                    {
                        "note_id": "NOTE-201",
                        "author": "incident_commander@threatlens.io",
                        "timestamp": "2026-08-28T09:00:00Z",
                        "note": "Finance department notified. Wire transfer revoked. External mailbox quarantined."
                    }
                ],
                timeline=[
                    {
                        "event_id": "EVT-201-01",
                        "original_event_time": "2026-08-28T08:29:15Z",
                        "ingested_at": "2026-08-28T08:30:00Z",
                        "source": "SMTP_RELAY",
                        "event_type": "EMAIL_RECEIPT",
                        "title": "BEC Impersonation Message Ingress",
                        "description": "Inbound spoofed CEO wire request received from unauthorized IP 198.51.100.44",
                        "severity": "HIGH",
                        "evidence_ref": "CASE-MT-201",
                        "details": {}
                    },
                    {
                        "event_id": "EVT-201-02",
                        "original_event_time": "2026-08-28T08:50:00Z",
                        "ingested_at": "2026-08-28T08:50:00Z",
                        "source": "ANALYST_ACTION",
                        "event_type": "CONTAINMENT_EXECUTED",
                        "title": "Mailbox Quarantined & Finance Alerted",
                        "description": "Protective containment action executed. Target bank account flagged.",
                        "severity": "LOW",
                        "evidence_ref": "NOTE-201",
                        "details": {}
                    }
                ],
                timestamp="2026-08-28T08:30:00Z"
            ),
            CaseRecord(
                case_id="MT-301",
                subject="Meeting tomorrow - Quarterly Project Sync",
                sender="Alice Johnson <alice@corporation.com>",
                recipient="bob@corporation.com",
                threat_score=0,
                risk_level="LOW",
                primary_threat="BENIGN",
                status="CLOSED",
                assigned_to="auto_triage",
                is_sample=True,
                iocs={
                    "domains": ["corporation.com"],
                    "ips": ["10.0.0.2", "10.0.0.5"],
                    "urls": [],
                    "emails": ["alice@corporation.com", "bob@corporation.com"],
                    "hashes": ["10775f5b56a9025039c056134825f24c7cbfa647ea08be84c536ca681dacf511"]
                },
                intel_summary={"malicious_count": 0, "suspicious_count": 0, "status": "CLEAN_REPORTED"},
                forensics_summary={
                    "spf": "PASS",
                    "dkim": "PASS",
                    "dmarc": "PASS",
                    "sender_ip": "10.0.0.2"
                },
                evidence_references=[],
                notes=[],
                timeline=[
                    {
                        "event_id": "EVT-301-01",
                        "original_event_time": "2026-08-28T09:29:40Z",
                        "ingested_at": "2026-08-28T09:30:00Z",
                        "source": "SMTP_RELAY",
                        "event_type": "EMAIL_RECEIPT",
                        "title": "Internal Communication Verified",
                        "description": "Internal message authenticated successfully with passing SPF/DKIM/DMARC.",
                        "severity": "LOW",
                        "evidence_ref": "CASE-MT-301",
                        "details": {}
                    }
                ],
                timestamp="2026-08-28T09:30:00Z"
            )
        ]
        for c in historical:
            self._cases[c.case_id] = c

    def save_case(self, case: CaseRecord) -> None:
        """Saves or updates a case record."""
        with self._lock:
            self._cases[case.case_id] = case
            self._save_to_disk()

    save = save_case

    def get_case(self, case_id: str) -> Optional[CaseRecord]:
        """Retrieves a single case by ID."""
        with self._lock:
            return self._cases.get(case_id)

    get = get_case

    def list_cases(self) -> List[CaseRecord]:
        """Returns all indexed cases."""
        with self._lock:
            return list(self._cases.values())

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Optional[CaseRecord]:
        """Thread-safely updates case fields (e.g. status, assigned_to, severity, risk_level)."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            data = case.model_dump()
            for key, val in updates.items():
                if val is not None and key in data:
                    data[key] = val
            updated_case = CaseRecord(**data)
            self._cases[case_id] = updated_case
            self._save_to_disk()
            return updated_case

    def add_note(self, case_id: str, author: str, note_text: str) -> Optional[Dict[str, Any]]:
        """Appends an analyst note to the case record."""
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            note_obj = {
                "note_id": f"NOTE-{uuid.uuid4().hex[:6].upper()}",
                "author": author or "soc_analyst",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "note": note_text.strip()
            }
            case.notes.append(note_obj)
            self._save_to_disk()
            return note_obj

    def add_timeline_event(self, case_id: str, event_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Appends a genuine timestamped event to the case timeline.
        Rejects events without both original_event_time and ingested_at.
        """
        orig_time = event_dict.get("original_event_time")
        ingest_time = event_dict.get("ingested_at")
        if not orig_time or not ingest_time:
            raise ValueError("Timeline event must contain both 'original_event_time' and 'ingested_at' ISO timestamps")

        # Validate timestamp formats
        try:
            datetime.fromisoformat(orig_time.replace("Z", "+00:00"))
            datetime.fromisoformat(ingest_time.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"Invalid timestamp format in timeline event: {e}")

        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None

            clean_event = {
                "event_id": event_dict.get("event_id") or f"EVT-{uuid.uuid4().hex[:6].upper()}",
                "original_event_time": orig_time,
                "ingested_at": ingest_time,
                "source": event_dict.get("source", "MANUAL_ENTRY"),
                "event_type": event_dict.get("event_type", "ANALYST_EVENT"),
                "title": event_dict.get("title", "Investigation Activity"),
                "description": event_dict.get("description", ""),
                "severity": event_dict.get("severity", "MEDIUM"),
                "evidence_ref": event_dict.get("evidence_ref"),
                "details": event_dict.get("details", {})
            }
            case.timeline.append(clean_event)
            # Maintain strict chronological ordering
            case.timeline.sort(key=lambda ev: ev.get("original_event_time", ""))
            self._save_to_disk()
            return clean_event

    def get_case_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """
        Returns genuine timestamped events for a case sorted chronologically.
        Excludes fabricated or undated events.
        """
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return []
            valid_events = []
            for ev in case.timeline:
                orig = ev.get("original_event_time")
                ingest = ev.get("ingested_at")
                if orig and ingest:
                    try:
                        datetime.fromisoformat(orig.replace("Z", "+00:00"))
                        valid_events.append(ev)
                    except Exception:
                        continue
            # Sort chronologically by original event time
            valid_events.sort(key=lambda e: e.get("original_event_time", ""))
            return valid_events

    def find_cases_by_ioc(self, ioc_value: str) -> List[CaseRecord]:
        """Finds all cases containing a specific indicator value."""
        target = ioc_value.strip().lower()
        results = []
        with self._lock:
            for case in self._cases.values():
                found = False
                for ioc_list in case.iocs.values():
                    if any(target == item.lower() or target in item.lower() for item in ioc_list):
                        found = True
                        break
                if found:
                    results.append(case)
        return results

    def link_finding(
        self,
        case_id: str,
        finding_id: str,
        finding_type: str,
        title: str,
        description: str,
        severity: str = "HIGH",
        details: Optional[Dict[str, Any]] = None,
        author: str = "soc_analyst@threatlens.io",
    ) -> Optional[Dict[str, Any]]:
        """
        Links an operational graph finding, anomaly, or attack path to an investigation case.
        Updates evidence references, adds a timeline event, and records an analyst note.
        """
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            now_iso = datetime.now(timezone.utc).isoformat()
            ref = {
                "evidence_id": finding_id,
                "type": finding_type,
                "title": title,
                "linked_at": now_iso,
                "details": details or {},
            }
            if not any(r.get("evidence_id") == finding_id for r in case.evidence_references):
                case.evidence_references.append(ref)

            evt_id = f"EVT-FND-{uuid.uuid4().hex[:6].upper()}"
            timeline_event = {
                "event_id": evt_id,
                "original_event_time": now_iso,
                "ingested_at": now_iso,
                "source": finding_type,
                "event_type": "LINKED_FINDING",
                "title": f"Linked Security Finding: {title}",
                "description": description,
                "severity": severity,
                "evidence_ref": finding_id,
                "details": details or {},
            }
            case.timeline.append(timeline_event)
            case.timeline.sort(key=lambda ev: ev.get("original_event_time", ""))

            note_entry = {
                "note_id": f"NOTE-FND-{uuid.uuid4().hex[:6].upper()}",
                "author": author,
                "timestamp": now_iso,
                "note": f"[Linked Finding: {finding_id}] ({finding_type}) {title}: {description}",
            }
            case.notes.append(note_entry)

            self._save_to_disk()
            return {
                "case_id": case_id,
                "finding_id": finding_id,
                "timeline_event_id": evt_id,
                "note_id": note_entry["note_id"],
                "evidence_ref": ref,
            }



# Global case repository instance
default_case_repo = CaseRepository()
