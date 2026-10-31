"""
ThreatLens - Windows Security Event Normalizer Tests
Validates conversion of Windows Event Logs (4624, 4625, 4688, 5140, etc.)
into SecurityEventEnvelope contracts, entity ID resolution, and error handling.
"""

import pytest
from datetime import datetime, timezone
from backend.collector.normalizer import WindowsEventNormalizer, normalize_windows_events
from backend.models.graphops import SecurityEventType, SecurityEventEnvelope
from backend.graphops.schema import CriticalityTier


@pytest.fixture
def normalizer():
    return WindowsEventNormalizer()


def test_normalize_event_4624_successful_logon(normalizer):
    """Event ID 4624: Successful Logon -> IDENTITY_EVENT with user, target device, and auth payload."""
    raw = {
        "event_id_number": 4624,
        "source_computer": "WIN-SRV-APP01.corp.internal",
        "time_created": "2026-10-29T08:00:00Z",
        "source_event_record_id": 10025,
        "channel": "Security",
        "event_data": {
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "LogonType": "3",  # Network logon
            "AuthenticationPackageName": "Kerberos",
            "IpAddress": "10.0.1.55",
            "WorkstationName": "DEV-WS-109",
        }
    }

    env = normalizer.normalize(raw, collector_id="col-srv01", device_node_id="device:win-srv-app01")
    assert isinstance(env, SecurityEventEnvelope)
    assert env.event_type == SecurityEventType.IDENTITY_EVENT
    assert env.source == "collector:col-srv01"
    assert env.payload["windows_event_id"] == 4624
    assert env.payload["auth_status"] == "SUCCESS"
    assert env.payload["user_id"] == "user:jdoe@corp"
    assert env.payload["target_resource_id"] == "device:win-srv-app01"
    assert "user:jdoe@corp" in env.entity_ids
    assert "device:win-srv-app01" in env.entity_ids
    assert env.evidence_metadata["collector_id"] == "col-srv01"
    assert env.evidence_metadata["source_computer"] == "WIN-SRV-APP01.corp.internal"
    assert env.evidence_metadata["windows_event_id"] == 4624


def test_normalize_event_4625_failed_logon(normalizer):
    """Event ID 4625: Failed Logon -> IDENTITY_EVENT with FAILED status and HIGH severity."""
    raw = {
        "event_id_number": 4625,
        "source_computer": "WIN-DC-01",
        "time_created": "2026-10-29T08:05:00Z",
        "source_event_record_id": 50124,
        "channel": "Security",
        "event_data": {
            "TargetUserName": "administrator",
            "TargetDomainName": "CORP",
            "FailureReason": "%%2313",  # Unknown username or bad password
            "IpAddress": "192.168.1.200",
            "WorkstationName": "UNKNOWN-BOX"
        }
    }

    env = normalizer.normalize(raw, collector_id="col-dc01", device_node_id="device:win-dc-01")
    assert env.event_type == SecurityEventType.IDENTITY_EVENT
    assert env.payload["auth_status"] == "FAILED"
    assert env.severity == CriticalityTier.HIGH
    assert env.payload["user_id"] == "user:administrator@corp"


def test_normalize_event_4688_process_creation(normalizer):
    """Event ID 4688: Process Creation -> PROCESS_EVENT with cmd line and process details."""
    raw = {
        "event_id_number": 4688,
        "source_computer": "DEV-WS-101",
        "time_created": "2026-10-29T08:10:00Z",
        "source_event_record_id": 88301,
        "channel": "Security",
        "event_data": {
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami /all",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "NewProcessId": "0x1a40",
            "ProcessId": "0x4b8",
        }
    }

    env = normalizer.normalize(raw, collector_id="col-ws101", device_node_id="device:dev-ws-101")
    assert env.event_type == SecurityEventType.PROCESS_EVENT
    assert env.payload["windows_event_id"] == 4688
    assert env.payload["new_process_name"] == "C:\\Windows\\System32\\cmd.exe"
    assert env.payload["command_line"] == "cmd.exe /c whoami /all"
    assert "device:dev-ws-101" in env.entity_ids
    assert "user:alice@corp" in env.entity_ids


def test_normalize_event_5140_network_share(normalizer):
    """Event ID 5140: Network Share Access -> NETWORK_CONNECTION."""
    raw = {
        "event_id_number": 5140,
        "source_computer": "FILE-SRV-01",
        "time_created": "2026-10-29T08:15:00Z",
        "source_event_record_id": 9920,
        "channel": "Security",
        "event_data": {
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "ShareName": "\\\\*\\C$",
            "ShareLocalPath": "C:\\",
            "IpAddress": "10.0.1.20",
            "AccessMask": "0x1",
        }
    }

    env = normalizer.normalize(raw, collector_id="col-fs01", device_node_id="device:file-srv-01")
    assert env.event_type == SecurityEventType.NETWORK_CONNECTION
    assert env.payload["share_name"] == "\\\\*\\C$"
    assert "ip:10.0.1.20" in env.entity_ids
    assert "device:file-srv-01" in env.entity_ids


def test_deterministic_event_id_deduplication(normalizer):
    """Identical event records produce identical deterministic event_ids."""
    raw = {
        "event_id_number": 4624,
        "source_computer": "WS-10",
        "time_created": "2026-10-29T08:20:00Z",
        "source_event_record_id": 44100,
        "channel": "Security",
        "event_data": {"TargetUserName": "user1"}
    }

    env1 = normalizer.normalize(raw, "col-1", "device:ws-10")
    env2 = normalizer.normalize(raw, "col-1", "device:ws-10")

    assert env1.event_id == env2.event_id
    assert env1.event_id.startswith("wev-")


def test_unmapped_event_id_falls_back_to_endpoint_alert(normalizer):
    """Unknown Windows event ID cleanly degrades to ENDPOINT_ALERT without throwing."""
    raw = {
        "event_id_number": 9999,
        "source_computer": "CUSTOM-HOST",
        "time_created": "2026-10-29T08:25:00Z",
        "source_event_record_id": 11,
        "channel": "Security",
        "event_data": {"Key1": "Val1"}
    }

    env = normalizer.normalize(raw, "col-custom", "device:custom-host")
    assert env.event_type == SecurityEventType.ENDPOINT_ALERT
    assert env.payload["windows_event_id"] == 9999
    assert env.payload["raw_event_data"]["Key1"] == "Val1"


def test_batch_normalization_with_rejected_records():
    """Batch normalization safely handles malformed entries and reports rejections."""
    records = [
        {
            "event_id_number": 4624,
            "source_computer": "HOST-A",
            "time_created": "2026-10-29T08:00:00Z",
            "source_event_record_id": 1,
            "channel": "Security",
            "event_data": {"TargetUserName": "userA"}
        },
        # Missing required fields
        "not a valid record dict",
        {
            "event_id_number": 4688,
            "source_computer": "HOST-A",
            "time_created": "2026-10-29T08:01:00Z",
            "source_event_record_id": 2,
            "channel": "Security",
            "event_data": {"NewProcessName": "notepad.exe"}
        }
    ]

    valid, rejected = normalize_windows_events(records, "col-test", "device:host-a")
    assert len(valid) == 2
    assert len(rejected) == 1
    assert rejected[0]["index"] == 1

