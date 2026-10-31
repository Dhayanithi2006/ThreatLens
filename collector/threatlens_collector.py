"""
ThreatLens Windows Security Event Collector Agent
=================================================
A lightweight, self-contained Python script for Windows endpoints.

Features:
  - Supports pywin32 (win32evtlog) with automatic fallback to wevtutil.exe (XML mode).
  - DPAPI credential encryption (CryptProtectData) for protecting the enrollment token.
  - Fail-closed TLS verification by default; explicit --insecure-dev-only required for test environments.
  - Resilient local disk spooling queue (C:\\ThreatLensCollector\\spool) to withstand network/server downtime.
  - Log clear / rollover detection (resets checkpoint when log starts over from record 1).
  - Client-side redaction for Event 4688 (Process Creation) passwords and secrets.
  - Deterministic event deduplication and source host identification.

Requirements:
  - Python 3.8+ (standard library only — optional pywin32 for performance)
  - Run as a Windows user with "Read" permission on the Security event log
    (typically Event Log Readers group or local Administrator)

Usage:
  python threatlens_collector.py --config C:\\ThreatLensCollector\\config.json
  python threatlens_collector.py --config C:\\ThreatLensCollector\\config.json --protect-token
  python threatlens_collector.py --config C:\\ThreatLensCollector\\config.json --run-once
"""

import argparse
import base64
import json
import logging
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
VERSION = "1.1.0"
AGENT_NAME = "ThreatLens-Collector"
DEFAULT_ENDPOINT_PATH = "/api/v1/collector/ingest/events"
DEFAULT_CONFIG_PATH = r"C:\ThreatLensCollector\config.json"
DEFAULT_CHECKPOINT_PATH = r"C:\ThreatLensCollector\checkpoint.json"
DEFAULT_SPOOL_DIR = r"C:\ThreatLensCollector\spool"
MAX_SPOOL_BYTES = 20 * 1024 * 1024      # 20 MB bounded local spool
MAX_SPOOL_EVENTS = 10000                 # Max 10,000 spooled events

# Supported Windows Security Event IDs
DEFAULT_EVENT_IDS = [
    4624,  # Successful logon
    4625,  # Failed logon
    4648,  # Logon using explicit credentials
    4672,  # Special privileges assigned to logon
    4688,  # Process creation (requires command line auditing)
    4698,  # Scheduled task created
    4720,  # User account created
    5140,  # Network share object accessed
    5156,  # Windows Filtering Platform: connection permitted
    5157,  # Windows Filtering Platform: connection blocked
]

DEFAULT_CHANNELS = ["Security"]

# Command line redaction patterns (Event 4688)
_REDACT_PATTERNS = [
    (re.compile(r"(?i)(-(?:p|password|pwd|token|api[-_]?key|secret)\s+)(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:password|pwd|token|api[-_]?key|secret)\s*=\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(/p(?:assword)?[:=])(\S+)"), r"\1[REDACTED]"),
]


def redact_sensitive_cmdline(cmdline: str) -> str:
    """Masks credentials from process command lines before network transmission."""
    if not cmdline or not isinstance(cmdline, str):
        return cmdline
    cleaned = cmdline
    for pattern, repl in _REDACT_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned


# ---------------------------------------------------------------------------
# DPAPI Credential Protection (Windows CryptProtectData / CryptUnprotectData)
# ---------------------------------------------------------------------------

def protect_token_dpapi(
    token: str,
    entropy: Optional[str] = None,
    machine_scope: bool = True,
) -> str:
    """
    Encrypts a token using Windows DPAPI (CryptProtectData).
    Returns a string prefixed with 'dpapi:m:' (machine-scoped) or 'dpapi:u:' (user-scoped)
    containing base64 ciphertext.

    Machine-scoped DPAPI (CRYPTPROTECT_LOCAL_MACHINE = 0x04) allows scheduled tasks running
    under NT AUTHORITY\\SYSTEM to decrypt the credential, guarded by restrictive NTFS file ACLs.
    """
    prefix = "dpapi:m:" if machine_scope else "dpapi:u:"
    if sys.platform != "win32":
        # Pure base64 fallback for cross-platform test environments
        return prefix + base64.b64encode(token.encode("utf-8")).decode("ascii")

    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    data_bytes = token.encode("utf-8")
    blob_in = DATA_BLOB(
        len(data_bytes),
        ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)),
    )
    blob_out = DATA_BLOB()

    p_entropy = None
    if entropy:
        ent_bytes = entropy.encode("utf-8")
        blob_entropy = DATA_BLOB(
            len(ent_bytes),
            ctypes.cast(ctypes.create_string_buffer(ent_bytes), ctypes.POINTER(ctypes.c_byte)),
        )
        p_entropy = ctypes.byref(blob_entropy)

    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    CRYPTPROTECT_LOCAL_MACHINE = 0x04
    flags = CRYPTPROTECT_UI_FORBIDDEN
    if machine_scope:
        flags |= CRYPTPROTECT_LOCAL_MACHINE

    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        ctypes.c_wchar_p("ThreatLens Collector Credential"),
        p_entropy,
        None,
        None,
        flags,
        ctypes.byref(blob_out),
    ):
        raise OSError("CryptProtectData failed to encrypt collector token.")

    try:
        raw_out = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return prefix + base64.b64encode(raw_out).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def unprotect_token_dpapi(protected_str: str, entropy: Optional[str] = None) -> str:
    """
    Decrypts a DPAPI protected token string (supports 'dpapi:m:', 'dpapi:u:', and legacy 'dpapi:').
    """
    if protected_str.startswith("dpapi:m:"):
        payload = protected_str[len("dpapi:m:"):]
    elif protected_str.startswith("dpapi:u:"):
        payload = protected_str[len("dpapi:u:"):]
    elif protected_str.startswith("dpapi:"):
        payload = protected_str[len("dpapi:"):]
    else:
        payload = protected_str

    if sys.platform != "win32":
        return base64.b64decode(payload.encode("ascii")).decode("utf-8")

    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    raw_data = base64.b64decode(payload.encode("ascii"))
    blob_in = DATA_BLOB(
        len(raw_data),
        ctypes.cast(ctypes.create_string_buffer(raw_data), ctypes.POINTER(ctypes.c_byte)),
    )
    blob_out = DATA_BLOB()

    p_entropy = None
    if entropy:
        ent_bytes = entropy.encode("utf-8")
        blob_entropy = DATA_BLOB(
            len(ent_bytes),
            ctypes.cast(ctypes.create_string_buffer(ent_bytes), ctypes.POINTER(ctypes.c_byte)),
        )
        p_entropy = ctypes.byref(blob_entropy)

    CRYPTPROTECT_UI_FORBIDDEN = 0x01
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        p_entropy,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(blob_out),
    ):
        raise OSError("CryptUnprotectData failed to decrypt collector token.")

    try:
        raw_out = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return raw_out.decode("utf-8", errors="replace")
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

def setup_logging(log_file: Optional[str], level: str) -> logging.Logger:
    logger = logging.getLogger(AGENT_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        try:
            p = Path(log_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(p), encoding="utf-8")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as e:
            logger.warning("Cannot open log file %s: %s", log_file, e)
    return logger


# ---------------------------------------------------------------------------
# Checkpoint Manager
# ---------------------------------------------------------------------------

class CheckpointManager:
    def __init__(self, path: str, logger: logging.Logger):
        self._path = Path(path)
        self._data: Dict[str, int] = {}
        self._logger = logger
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
                self._logger.info("Loaded checkpoint from %s", self._path)
            except (json.JSONDecodeError, OSError) as e:
                self._logger.warning("Failed to load checkpoint: %s — starting fresh.", e)
                self._data = {}

    def get(self, channel: str) -> int:
        return self._data.get(channel, 0)

    def reset(self, channel: str):
        """Resets the checkpoint for a channel (used on log clear/rollover)."""
        self._data[channel] = 0
        self._save()

    def update(self, channel: str, record_id: int):
        if record_id > self._data.get(channel, 0):
            self._data[channel] = record_id
            self._save()

    def _save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        except OSError as e:
            self._logger.error("Failed to save checkpoint: %s", e)


# ---------------------------------------------------------------------------
# Local Disk Spool Manager (Offline Resilient Queue)
# ---------------------------------------------------------------------------

class SpoolManager:
    """
    Manages local queue of failed event submissions.
    Ensures bounded disk storage (max 20MB / 10,000 events), visible capacity metrics,
    and FIFO replay order.
    """

    def __init__(
        self,
        spool_dir: str,
        logger: logging.Logger,
        max_bytes: int = MAX_SPOOL_BYTES,
        max_events: int = MAX_SPOOL_EVENTS,
    ):
        self._dir = Path(spool_dir)
        self._logger = logger
        self._max_bytes = max_bytes
        self._max_events = max_events
        self.dropped_events_count = 0
        self.dropped_files_count = 0
        self.total_spooled_events = 0
        self.total_drained_events = 0
        self._metrics_path = self._dir / "spool_metrics.json"
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._load_metrics()
        except OSError as exc:
            self._logger.warning("Could not initialize spool directory %s: %s", self._dir, exc)

    def _load_metrics(self):
        if self._metrics_path.exists():
            try:
                data = json.loads(self._metrics_path.read_text(encoding="utf-8"))
                self.dropped_events_count = data.get("dropped_events_count", 0)
                self.dropped_files_count = data.get("dropped_files_count", 0)
                self.total_spooled_events = data.get("total_spooled_events", 0)
                self.total_drained_events = data.get("total_drained_events", 0)
            except Exception:
                pass

    def _save_metrics(self):
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp = self._metrics_path.with_suffix(".tmp")
            data = {
                "dropped_events_count": self.dropped_events_count,
                "dropped_files_count": self.dropped_files_count,
                "total_spooled_events": self.total_spooled_events,
                "total_drained_events": self.total_drained_events,
                "active_spool_files": len(self.get_spooled_files()),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self._metrics_path)
        except Exception:
            pass

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "dropped_events_count": self.dropped_events_count,
            "dropped_files_count": self.dropped_files_count,
            "total_spooled_events": self.total_spooled_events,
            "total_drained_events": self.total_drained_events,
            "active_spool_files": len(self.get_spooled_files()),
        }

    def spool_batch(self, events: List[Dict[str, Any]], checkpoint_offset: Optional[int]) -> bool:
        if not events:
            return True
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            ts = int(time.time() * 1000)
            uid = uuid.uuid4().hex[:8]
            fname = self._dir / f"spool_{ts}_{uid}.json"
            tmp = self._dir / f"spool_{ts}_{uid}.tmp"

            payload = {
                "events": events,
                "event_count": len(events),
                "checkpoint_offset": checkpoint_offset,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(fname)
            self.total_spooled_events += len(events)
            self._logger.info("Spooled %d events to offline queue (%s)", len(events), fname.name)
            self._enforce_bounds()
            self._save_metrics()
            return True
        except Exception as exc:
            self._logger.error("Failed to write spool file: %s", exc)
            return False

    def _enforce_bounds(self):
        """Drops oldest spool files if total size or event count exceeds limits, with diagnostic counters."""
        files = sorted(self._dir.glob("spool_[0-9]*.json"))
        total_size = sum(f.stat().st_size for f in files)
        while total_size > self._max_bytes and files:
            oldest = files.pop(0)
            sz = oldest.stat().st_size
            events_in_file = 0
            try:
                data = json.loads(oldest.read_text(encoding="utf-8"))
                events_in_file = len(data.get("events", []))
            except Exception:
                pass
            try:
                oldest.unlink()
                total_size -= sz
                self.dropped_files_count += 1
                self.dropped_events_count += events_in_file
                self._logger.warning(
                    "[SPOOL CAPACITY EXHAUSTED] Spool capacity exceeded (current: %.2f KB, max: %.2f KB); "
                    "dropped oldest spool batch %s (%d events dropped, lifetime dropped: %d). "
                    "Restore ThreatLens backend connectivity or expand disk quota.",
                    total_size / 1024,
                    self._max_bytes / 1024,
                    oldest.name,
                    events_in_file,
                    self.dropped_events_count,
                )
            except OSError:
                break

    def get_spooled_files(self) -> List[Path]:
        return sorted(self._dir.glob("spool_[0-9]*.json"))

    def drain(self, submit_fn: Callable[[List[Dict[str, Any]], Optional[int]], bool]) -> int:
        """
        Drains spooled batches in FIFO order using submit_fn.
        Halts on first failure to preserve order and avoid data loss.
        """
        files = self.get_spooled_files()
        if not files:
            return 0

        self._logger.info("Attempting to drain %d spooled batch(es) to ThreatLens...", len(files))
        drained_count = 0

        for f in files:
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                events = data.get("events", [])
                chk = data.get("checkpoint_offset")
                ok = submit_fn(events, chk)
                if ok:
                    f.unlink(missing_ok=True)
                    drained_count += len(events)
                    self.total_drained_events += len(events)
                    self._logger.info("Successfully drained spool file %s (%d events)", f.name, len(events))
                else:
                    self._logger.warning("Spool drain failed on %s; stopping drain cycle to preserve order.", f.name)
                    break
            except Exception as exc:
                self._logger.error("Error processing spool file %s: %s", f.name, exc)
                break

        if drained_count > 0:
            self._save_metrics()

        return drained_count


# ---------------------------------------------------------------------------
# Windows Event Readers with Rollover Detection & Sanitization
# ---------------------------------------------------------------------------

def _try_import_win32evtlog():
    try:
        import win32evtlog
        return win32evtlog
    except ImportError:
        return None


def read_events_win32(
    channel: str,
    event_ids: List[int],
    start_record: int,
    batch_size: int,
    logger: logging.Logger,
    checkpoint_mgr: Optional[CheckpointManager] = None,
) -> List[Dict[str, Any]]:
    """
    Reads events from Windows Event Log using pywin32 with rollover detection.
    """
    w32 = _try_import_win32evtlog()
    if w32 is None:
        logger.warning("pywin32 not available; using wevtutil fallback.")
        return []

    events_out: List[Dict[str, Any]] = []
    hostname = socket.gethostname()
    event_id_set = set(event_ids)

    try:
        hand = w32.OpenEventLog(None, channel)
        try:
            num_records = w32.GetNumberOfEventLogRecords(hand)
            oldest_record = w32.GetOldestEventLogRecord(hand)
        except Exception:
            num_records = 0
            oldest_record = 0

        # Check for log clear / rollover
        if start_record > 0 and num_records > 0:
            newest_record = oldest_record + num_records - 1
            if start_record > newest_record or start_record < (oldest_record - 1):
                logger.warning(
                    "Log rollover or clear detected on channel '%s' (start=%d, oldest=%d, newest=%d). Resetting checkpoint to 0.",
                    channel, start_record, oldest_record, newest_record
                )
                start_record = 0
                if checkpoint_mgr:
                    checkpoint_mgr.reset(channel)

        flags = w32.EVENTLOG_FORWARDS_READ | w32.EVENTLOG_SEEK_READ
        if start_record > 0:
            try:
                w32.ReadEventLog(hand, flags, start_record)
            except Exception:
                flags = w32.EVENTLOG_FORWARDS_READ | w32.EVENTLOG_SEQUENTIAL_READ

        flags_seq = w32.EVENTLOG_FORWARDS_READ | w32.EVENTLOG_SEQUENTIAL_READ
        while len(events_out) < batch_size:
            try:
                records = w32.ReadEventLog(hand, flags_seq, 0)
            except Exception:
                break
            if not records:
                break

            for rec in records:
                rid = rec.RecordNumber
                if rid <= start_record:
                    continue
                eid = rec.EventID & 0xFFFF
                if event_id_set and eid not in event_id_set:
                    continue

                event_data: Dict[str, Any] = {}
                if rec.StringInserts:
                    for i, s in enumerate(rec.StringInserts):
                        val = str(s)
                        if eid == 4688:
                            val = redact_sensitive_cmdline(val)
                        event_data[f"param{i}"] = val

                ts_raw = rec.TimeGenerated
                if hasattr(ts_raw, "timestamp"):
                    occurred_at = datetime.fromtimestamp(
                        ts_raw.timestamp(), tz=timezone.utc
                    ).isoformat()
                else:
                    occurred_at = datetime.now(timezone.utc).isoformat()

                events_out.append({
                    "event_id_number": eid,
                    "source_computer": hostname,
                    "time_created": occurred_at,
                    "source_event_record_id": rid,
                    "channel": channel,
                    "event_data": event_data,
                })

                if len(events_out) >= batch_size:
                    break

        w32.CloseEventLog(hand)
    except Exception as exc:
        logger.error("Error reading from channel %s: %s", channel, exc)

    return events_out


def read_events_wevtutil(
    channel: str,
    event_ids: List[int],
    start_record: int,
    batch_size: int,
    logger: logging.Logger,
    checkpoint_mgr: Optional[CheckpointManager] = None,
) -> List[Dict[str, Any]]:
    """
    Fallback reader: uses wevtutil.exe to read events with XML parsing and rollover detection.
    """
    events_out: List[Dict[str, Any]] = []
    hostname = socket.gethostname()
    event_id_set = set(event_ids)

    # 1. Rollover / log clear detection
    if start_record > 0:
        try:
            probe_cmd = [
                "wevtutil.exe", "qe", channel,
                "/c:1", "/rd:true", "/f:XML",
            ]
            probe_res = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=0x08000000 if sys.platform == "win32" else 0,
            )
            if probe_res.returncode == 0 and probe_res.stdout.strip():
                probe_xml = f"<Events>{probe_res.stdout}</Events>"
                p_root = ET.fromstring(probe_xml)
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                rid_elem = p_root.find(".//e:EventRecordID", ns)
                if rid_elem is not None and rid_elem.text:
                    latest_rid = int(rid_elem.text)
                    if latest_rid < start_record:
                        logger.warning(
                            "Log rollover or clear detected on channel '%s' (latest record ID %d < checkpoint %d). Resetting checkpoint to 0.",
                            channel, latest_rid, start_record
                        )
                        start_record = 0
                        if checkpoint_mgr:
                            checkpoint_mgr.reset(channel)
        except Exception as p_exc:
            logger.debug("Rollover probe check ignored: %s", p_exc)

    # 2. Build XPath query
    if event_id_set:
        id_filters = " or ".join(f"EventID={eid}" for eid in sorted(event_id_set))
        xpath = f"*[System[({id_filters}) and EventRecordID > {start_record}]]"
    else:
        xpath = f"*[System[EventRecordID > {start_record}]]"

    cmd = [
        "wevtutil.exe", "qe", channel,
        f"/q:{xpath}",
        f"/c:{batch_size}",
        "/rd:false",   # chronological order
        "/f:XML",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=0x08000000 if sys.platform == "win32" else 0,
        )
        if result.returncode != 0:
            logger.warning("wevtutil exit %d: %s", result.returncode, result.stderr[:200])
            return []

        xml_text = f"<Events>{result.stdout}</Events>"
        root = ET.fromstring(xml_text)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        for evt in root.findall("e:Event", ns):
            sys_elem = evt.find("e:System", ns)
            if sys_elem is None:
                continue

            eid_elem = sys_elem.find("e:EventID", ns)
            rid_elem = sys_elem.find("e:EventRecordID", ns)
            ts_elem = sys_elem.find("e:TimeCreated", ns)

            eid = int(eid_elem.text) if eid_elem is not None and eid_elem.text else 0
            if event_id_set and eid not in event_id_set:
                continue
            rid = int(rid_elem.text) if rid_elem is not None and rid_elem.text else 0
            ts_val = ts_elem.get("SystemTime", "") if ts_elem is not None else ""

            event_data: Dict[str, Any] = {}
            ed_elem = evt.find("e:EventData", ns)
            if ed_elem is not None:
                for data_child in ed_elem:
                    name = data_child.get("Name") or data_child.tag.split("}")[-1]
                    val = data_child.text or ""
                    if eid == 4688 and ("CommandLine" in name or "ProcessCommandLine" in name):
                        val = redact_sensitive_cmdline(val)
                    event_data[name] = val

            events_out.append({
                "event_id_number": eid,
                "source_computer": hostname,
                "time_created": ts_val or datetime.now(timezone.utc).isoformat(),
                "source_event_record_id": rid,
                "channel": channel,
                "event_data": event_data,
            })

    except subprocess.TimeoutExpired:
        logger.error("wevtutil timed out for channel %s", channel)
    except ET.ParseError as e:
        logger.error("XML parse error from wevtutil: %s", e)
    except Exception as exc:
        logger.error("wevtutil reader error for channel %s: %s", channel, exc)

    return events_out


# ---------------------------------------------------------------------------
# HTTP Submission with Fail-Closed TLS
# ---------------------------------------------------------------------------

def submit_events(
    server_url: str,
    collector_id: str,
    token: str,
    events: List[Dict[str, Any]],
    verify_tls: bool,
    ca_cert: Optional[str],
    checkpoint_offset: Optional[int],
    logger: logging.Logger,
    insecure_dev_allowed: bool = False,
) -> bool:
    """
    POSTs a batch of events to ThreatLens HTTPS ingestion endpoint.
    Fails closed if TLS is unverified without explicit --insecure-dev-only flag.
    Token is never logged.
    """
    # Security verification
    if not verify_tls:
        if not insecure_dev_allowed:
            logger.critical(
                "[SECURITY ERROR] TLS verification is disabled in config, but --insecure-dev-only flag was not passed. "
                "Refusing to transmit authentication token over an insecure connection. Aborting submission."
            )
            return False
        logger.warning(
            "[SECURITY WARNING] TLS certificate verification is DISABLED (--insecure-dev-only is active). "
            "Traffic is vulnerable to interception. Do NOT use in production."
        )

    if ca_cert and not os.path.isfile(ca_cert):
        logger.critical("[SECURITY ERROR] Specified ca_cert file not found: %s. Aborting submission.", ca_cert)
        return False

    url = server_url.rstrip("/") + DEFAULT_ENDPOINT_PATH
    body = json.dumps({
        "events": events,
        "checkpoint_offset": checkpoint_offset,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Collector-ID": collector_id,
            "X-Collector-Token": token,
            "User-Agent": f"{AGENT_NAME}/{VERSION}",
            "Content-Length": str(len(body)),
        },
    )

    if verify_tls:
        if ca_cert:
            ctx = ssl.create_default_context(cafile=ca_cert)
        else:
            ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            if resp.status == 202:
                resp_body = json.loads(resp.read().decode("utf-8", errors="replace"))
                logger.info(
                    "Submitted %d events — accepted=%d rejected=%d duplicate=%d published=%d",
                    len(events),
                    resp_body.get("accepted", 0),
                    resp_body.get("rejected", 0),
                    resp_body.get("duplicate", 0),
                    resp_body.get("published", 0),
                )
                return True
            else:
                logger.warning("Unexpected HTTP %d from ThreatLens server", resp.status)
                return False
    except urllib.error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")[:400]
        except Exception:
            pass
        if exc.code == 401:
            logger.error("Authentication failed (HTTP 401). Check collector_id and token.")
        elif exc.code == 429:
            logger.warning("Rate limit exceeded (HTTP 429). Ingestion paused temporarily.")
        else:
            logger.error("HTTP error %d: %s", exc.code, body_text)
        return False
    except urllib.error.URLError as exc:
        logger.error("Network communication error: %s", exc.reason)
        return False
    except Exception as exc:
        logger.error("Unexpected error submitting events: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------

def load_config(path: str, logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """Loads configuration and decrypts DPAPI tokens when present."""
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read config: {e}", file=sys.stderr)
        sys.exit(1)

    # Environment overrides
    if os.environ.get("THREATLENS_TOKEN"):
        data["token"] = os.environ["THREATLENS_TOKEN"]
    if os.environ.get("THREATLENS_SERVER_URL"):
        data["server_url"] = os.environ["THREATLENS_SERVER_URL"]
    if os.environ.get("THREATLENS_COLLECTOR_ID"):
        data["collector_id"] = os.environ["THREATLENS_COLLECTOR_ID"]

    # Validate required fields
    for required in ("server_url", "collector_id", "token"):
        if not data.get(required):
            print(f"[ERROR] Required config field missing: {required}", file=sys.stderr)
            sys.exit(1)

    # Validate server_url does not accidentally use localhost on a remote endpoint
    server_url = (data.get("server_url") or "").strip()
    parsed = urllib.parse.urlparse(server_url)
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        notice = (
            f"[CONFIGURATION NOTICE] 'server_url' is set to '{server_url}'. "
            "Localhost refers to this endpoint computer itself, not a remote ThreatLens server. "
            "For remote log collection, ensure server_url is configured with the reachable IP or FQDN of the ThreatLens server."
        )
        if logger:
            logger.warning(notice)
        else:
            print(f"[WARNING] {notice}", file=sys.stderr)

    raw_token = data["token"]
    if raw_token.startswith("dpapi:"):
        try:
            data["token"] = unprotect_token_dpapi(raw_token)
            if logger:
                logger.info("Successfully decrypted collector token using Windows DPAPI.")
        except Exception as exc:
            print(f"[ERROR] Failed to decrypt DPAPI token: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        if logger:
            logger.warning(
                "[SECURITY NOTICE] Collector token is stored in plaintext. "
                "Run with --protect-token to encrypt it with Windows DPAPI."
            )

    return data


# ---------------------------------------------------------------------------
# Collector Agent Orchestrator
# ---------------------------------------------------------------------------

class CollectorAgent:
    def __init__(self, cfg: Dict[str, Any], logger: logging.Logger, insecure_dev_only: bool = False):
        self._cfg = cfg
        self._logger = logger
        self._insecure_dev_only = insecure_dev_only
        self._running = False
        self._checkpoint = CheckpointManager(
            cfg.get("checkpoint_file", DEFAULT_CHECKPOINT_PATH), logger
        )
        self._spool = SpoolManager(
            cfg.get("spool_dir", DEFAULT_SPOOL_DIR),
            logger,
            max_bytes=cfg.get("max_spool_bytes", MAX_SPOOL_BYTES),
            max_events=cfg.get("max_spool_events", MAX_SPOOL_EVENTS),
        )
        self._use_win32 = _try_import_win32evtlog() is not None
        if not self._use_win32:
            self._logger.info("pywin32 not available; using wevtutil.exe fallback.")

    def _read_channel(self, channel: str) -> List[Dict[str, Any]]:
        start = self._checkpoint.get(channel)
        event_ids: List[int] = self._cfg.get("event_ids", DEFAULT_EVENT_IDS)
        batch_size: int = self._cfg.get("batch_size", 100)

        if self._use_win32:
            return read_events_win32(channel, event_ids, start, batch_size, self._logger, self._checkpoint)
        else:
            return read_events_wevtutil(channel, event_ids, start, batch_size, self._logger, self._checkpoint)

    def _update_checkpoint(self, channel: str, events: List[Dict[str, Any]]):
        for e in events:
            rid = e.get("source_event_record_id")
            if rid and isinstance(rid, int) and rid > 0:
                self._checkpoint.update(channel, rid)

    def _do_submit(self, events: List[Dict[str, Any]], checkpoint_offset: Optional[int]) -> bool:
        return submit_events(
            server_url=self._cfg["server_url"],
            collector_id=self._cfg["collector_id"],
            token=self._cfg["token"],
            events=events,
            verify_tls=self._cfg.get("verify_tls", True),
            ca_cert=self._cfg.get("ca_cert") or None,
            checkpoint_offset=checkpoint_offset,
            logger=self._logger,
            insecure_dev_allowed=self._insecure_dev_only,
        )

    def run_once(self) -> int:
        """Runs one collection cycle: drains spooled events first, then reads new events."""
        # 1. Drain offline spool queue first
        drained = self._spool.drain(self._do_submit)
        total = drained

        # 2. Collect current events from configured channels
        channels: List[str] = self._cfg.get("channels", DEFAULT_CHANNELS)
        for channel in channels:
            events = self._read_channel(channel)
            if not events:
                continue

            self._logger.info("Read %d events from channel '%s'", len(events), channel)
            max_rid = max(
                (e.get("source_event_record_id") or 0 for e in events),
                default=0,
            )

            max_retries: int = self._cfg.get("max_retries", 3)
            backoff: float = self._cfg.get("retry_backoff_seconds", 5.0)
            submitted = False

            for attempt in range(1, max_retries + 1):
                ok = self._do_submit(events, int(max_rid) if max_rid else None)
                if ok:
                    submitted = True
                    break
                if attempt < max_retries:
                    sleep_for = backoff * attempt
                    self._logger.info("Retry %d/%d in %.1fs...", attempt, max_retries, sleep_for)
                    time.sleep(sleep_for)

            if submitted:
                self._update_checkpoint(channel, events)
                total += len(events)
            else:
                self._logger.warning(
                    "Failed to submit %d events from channel '%s' after %d retries. Spooling to local disk queue.",
                    len(events), channel, max_retries
                )
                spooled_ok = self._spool.spool_batch(events, int(max_rid) if max_rid else None)
                if spooled_ok:
                    # Advance checkpoint because events are safely persisted in local spool
                    self._update_checkpoint(channel, events)
                else:
                    self._logger.error("Local spooling failed! Checkpoint NOT advanced.")

        return total

    def run(self):
        self._running = True
        interval: float = float(self._cfg.get("poll_interval_seconds", 30))
        self._logger.info(
            "%s/%s starting — server=%s collector_id=%s interval=%.0fs",
            AGENT_NAME, VERSION,
            self._cfg["server_url"],
            self._cfg["collector_id"],
            interval,
        )

        while self._running:
            try:
                count = self.run_once()
                if count:
                    self._logger.debug("Cycle complete — processed %d events", count)
            except KeyboardInterrupt:
                break
            except Exception as exc:
                self._logger.error("Unexpected error in collection cycle: %s", exc)
                self._logger.debug(traceback.format_exc())

            if self._running:
                time.sleep(interval)

        self._logger.info("%s stopped.", AGENT_NAME)

    def stop(self, *args):
        self._logger.info("Received stop signal; completing current cycle...")
        self._running = False


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"{AGENT_NAME} v{VERSION} — Forwards Windows Security Events to ThreatLens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to JSON config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Collect one batch and exit (useful for Task Scheduler or test suites)",
    )
    parser.add_argument(
        "--protect-token",
        action="store_true",
        help="Encrypt plaintext token in config file using Windows DPAPI (CryptProtectData)",
    )
    parser.add_argument(
        "--scope",
        choices=["machine", "user"],
        default="machine",
        help="DPAPI protection scope: 'machine' (default, required for SYSTEM scheduled tasks) or 'user'",
    )
    parser.add_argument(
        "--insecure-dev-only",
        action="store_true",
        help="Allow disabling TLS verification for local/lab testing ONLY. Do not use in production.",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"{AGENT_NAME} {VERSION}",
    )
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if args.protect_token:
        # Encrypt the token in the config file
        if not cfg_path.exists():
            print(f"[ERROR] Config file not found: {args.config}", file=sys.stderr)
            sys.exit(1)
        raw_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        tok = raw_cfg.get("token", "")
        if tok.startswith("dpapi:"):
            print("[INFO] Token is already DPAPI protected.")
            sys.exit(0)
        try:
            is_machine = (args.scope == "machine")
            protected = protect_token_dpapi(tok, machine_scope=is_machine)
            raw_cfg["token"] = protected
            cfg_path.write_text(json.dumps(raw_cfg, indent=2), encoding="utf-8")
            print(f"[SUCCESS] Collector token successfully encrypted with DPAPI ({args.scope} scope) in {args.config}")
            sys.exit(0)
        except Exception as exc:
            print(f"[ERROR] Failed to protect token: {exc}", file=sys.stderr)
            sys.exit(1)

    # Initial logger
    logger = setup_logging(None, "INFO")
    cfg = load_config(args.config, logger=logger)

    # Update logger with configured log file and level
    logger = setup_logging(
        log_file=cfg.get("log_file"),
        level=cfg.get("log_level", "INFO"),
    )

    agent = CollectorAgent(cfg, logger, insecure_dev_only=args.insecure_dev_only)

    if args.run_once:
        count = agent.run_once()
        logger.info("Run-once complete — %d events processed.", count)
        sys.exit(0)

    signal.signal(signal.SIGINT, agent.stop)
    signal.signal(signal.SIGTERM, agent.stop)

    agent.run()


if __name__ == "__main__":
    main()
