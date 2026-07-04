"""Basic tests for the EVTX parser."""

from credscope.session import LogonSession, CREDENTIAL_CACHED_TYPES
from datetime import datetime, timezone


def test_credential_cached_types():
    """Logon types 2, 4, 5, 7, 8, 9, 10, 11 should cache credentials."""
    for lt in CREDENTIAL_CACHED_TYPES:
        session = LogonSession(
            logon_id="0x1234",
            account="testuser",
            domain="TESTDOMAIN",
            logon_type=lt,
            logon_time=datetime.now(timezone.utc),
        )
        assert session.is_credential_cached is True


def test_network_logon_no_cache():
    """Type 3 (Network) should NOT cache credentials by default."""
    session = LogonSession(
        logon_id="0x5678",
        account="testuser",
        domain="TESTDOMAIN",
        logon_type=3,
        logon_time=datetime.now(timezone.utc),
    )
    assert session.is_credential_cached is False


def test_is_active_at():
    """Session should be active at compromise time if within logon/logoff window."""
    t1 = datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 7, 1, 14, 0, tzinfo=timezone.utc)

    session = LogonSession(
        logon_id="0x1111",
        account="admin",
        domain="CORP",
        logon_type=10,
        logon_time=t1,
        logoff_time=t3,
    )
    assert session.is_active_at(t2) is True
    assert session.is_active_at(datetime(2026, 7, 1, 15, 0, tzinfo=timezone.utc)) is False


def test_no_logoff_always_active():
    """Session without logoff should be considered still active."""
    t1 = datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc)
    session = LogonSession(
        logon_id="0x2222",
        account="user1",
        domain="CORP",
        logon_type=2,
        logon_time=t1,
        logoff_time=None,
    )
    assert session.is_active_at(datetime(2026, 12, 31, tzinfo=timezone.utc)) is True
