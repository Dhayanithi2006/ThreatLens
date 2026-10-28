"""
MailTrace AI - Case Repository & Storage
Feature 6: Attack Graph + Campaign Correlation
"""

import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from backend.models.graph import CaseRecord


class CaseRepository:
    """
    Thread-safe repository for indexing and querying analyzed email investigation cases.
    """
    def __init__(self):
        self._cases: Dict[str, CaseRecord] = {}
        self._lock = threading.Lock()
        self._prefill_historical_cases()

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
                iocs={
                    "domains": ["alert-center.xyz", "corporation.com"],
                    "ips": ["185.190.140.22", "194.26.29.112"],
                    "urls": ["http://secure-login.alert-center.xyz/auth/verify"],
                    "emails": ["service-update@alert-center.xyz"],
                    "hashes": []
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
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
                iocs={
                    "domains": ["alert-center.xyz", "corporation.com"],
                    "ips": ["185.190.140.22"],
                    "urls": ["http://secure-login.alert-center.xyz/auth"],
                    "emails": ["notify@alert-center.xyz"],
                    "hashes": []
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
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
                iocs={
                    "domains": ["support-portal.top", "corporation.com"],
                    "ips": ["185.190.140.22"],
                    "urls": ["http://185.190.140.22/login"],
                    "emails": ["admin-office365@support-portal.top"],
                    "hashes": []
                },
                intel_summary={"malicious_count": 2, "suspicious_count": 0, "status": "MALICIOUS"},
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
                iocs={
                    "domains": ["corporation.com", "gmail.com"],
                    "ips": ["198.51.100.44"],
                    "urls": [],
                    "emails": ["ceo@corporation.com", "james.vance.confidential@gmail.com"],
                    "hashes": ["664f61f41747557613589"]
                },
                intel_summary={"malicious_count": 0, "suspicious_count": 1, "status": "SUSPICIOUS"},
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
                iocs={
                    "domains": ["corporation.com"],
                    "ips": ["10.0.0.2", "10.0.0.5"],
                    "urls": [],
                    "emails": ["alice@corporation.com", "bob@corporation.com"],
                    "hashes": ["10775f5b56a9025039c056134825f24c7cbfa647ea08be84c536ca681dacf511"]
                },
                intel_summary={"malicious_count": 0, "suspicious_count": 0, "status": "CLEAN_REPORTED"},
                timestamp="2026-08-28T09:30:00Z"
            )
        ]
        for c in historical:
            self._cases[c.case_id] = c

    def save_case(self, case: CaseRecord) -> None:
        """Saves or updates a case record."""
        with self._lock:
            self._cases[case.case_id] = case

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


# Global case repository instance
default_case_repo = CaseRepository()
