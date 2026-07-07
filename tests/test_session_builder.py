"""Tests for session builder logic."""

from datetime import datetime, timezone

from credscope.parser import LogonEvent
from credscope.session_builder import build_sessions


def _make_event(event_id: str, timestamp: str, **fields) -> LogonEvent:
    return LogonEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(timestamp),
        data=fields,
    )


def test_basic_session_creation():
    """4624 event creates a session."""
    events = [
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xA1", TargetUserName="alice",
            TargetDomainName="CORP", LogonType="10",
            IpAddress="192.168.1.100",
        ),
    ]
    sessions = build_sessions(events)
    assert len(sessions) == 1
    assert sessions[0].account == "alice"
    assert sessions[0].logon_type == 10
    assert sessions[0].source_ip == "192.168.1.100"
    assert sessions[0].logoff_time is None


def test_logoff_closes_session():
    """4634 event sets logoff_time on matching session."""
    events = [
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xA1", TargetUserName="alice",
            TargetDomainName="CORP", LogonType="2",
        ),
        _make_event(
            "4634", "2026-07-01T12:00:00+00:00",
            TargetLogonId="0xA1", TargetUserName="alice",
            TargetDomainName="CORP",
        ),
    ]
    sessions = build_sessions(events)
    assert len(sessions) == 1
    assert sessions[0].logoff_time is not None
    assert sessions[0].logoff_time.hour == 12


def test_4647_also_closes_session():
    """4647 (user-initiated logoff) also sets logoff_time."""
    events = [
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xB1", TargetUserName="bob",
            TargetDomainName="CORP", LogonType="10",
        ),
        _make_event(
            "4647", "2026-07-01T11:30:00+00:00",
            TargetLogonId="0xB1", TargetUserName="bob",
            TargetDomainName="CORP",
        ),
    ]
    sessions = build_sessions(events)
    assert sessions[0].logoff_time is not None


def test_privilege_assignment():
    """4672 event marks session as privileged."""
    events = [
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xC1", TargetUserName="admin",
            TargetDomainName="CORP", LogonType="2",
        ),
        _make_event(
            "4672", "2026-07-01T10:00:01+00:00",
            SubjectLogonId="0xC1", SubjectUserName="admin",
            SubjectDomainName="CORP",
        ),
    ]
    sessions = build_sessions(events)
    assert sessions[0].is_privileged is True


def test_privilege_before_logon():
    """4672 arriving before 4624 should still mark session as privileged."""
    events = [
        _make_event(
            "4672", "2026-07-01T10:00:00+00:00",
            SubjectLogonId="0xD1", SubjectUserName="admin",
            SubjectDomainName="CORP",
        ),
        _make_event(
            "4624", "2026-07-01T10:00:01+00:00",
            TargetLogonId="0xD1", TargetUserName="admin",
            TargetDomainName="CORP", LogonType="2",
        ),
    ]
    sessions = build_sessions(events)
    assert sessions[0].is_privileged is True


def test_noise_accounts_filtered():
    """SYSTEM, machine accounts ($), etc. should be filtered out."""
    events = [
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xE1", TargetUserName="SYSTEM",
            TargetDomainName="NT AUTHORITY", LogonType="5",
        ),
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xE2", TargetUserName="DC01$",
            TargetDomainName="CORP", LogonType="3",
        ),
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xE3", TargetUserName="alice",
            TargetDomainName="CORP", LogonType="10",
        ),
    ]
    sessions = build_sessions(events)
    assert len(sessions) == 1
    assert sessions[0].account == "alice"


def test_multiple_sessions_sorted():
    """Multiple sessions should be sorted by logon time."""
    events = [
        _make_event(
            "4624", "2026-07-01T12:00:00+00:00",
            TargetLogonId="0xF2", TargetUserName="bob",
            TargetDomainName="CORP", LogonType="10",
        ),
        _make_event(
            "4624", "2026-07-01T10:00:00+00:00",
            TargetLogonId="0xF1", TargetUserName="alice",
            TargetDomainName="CORP", LogonType="2",
        ),
    ]
    sessions = build_sessions(events)
    assert len(sessions) == 2
    assert sessions[0].account == "alice"
    assert sessions[1].account == "bob"


def test_orphan_logoff_ignored():
    """Logoff without matching logon should not crash."""
    events = [
        _make_event(
            "4634", "2026-07-01T12:00:00+00:00",
            TargetLogonId="0xFF", TargetUserName="ghost",
            TargetDomainName="CORP",
        ),
    ]
    sessions = build_sessions(events)
    assert len(sessions) == 0
