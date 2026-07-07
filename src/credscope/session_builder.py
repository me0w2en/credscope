"""Build LogonSession objects from parsed EVTX events."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .analyzer import is_noise_account
from .parser import LogonEvent, parse_evtx
from .session import LogonSession


def build_sessions(events: Iterable[LogonEvent]) -> list[LogonSession]:
    sessions: dict[str, LogonSession] = {}
    privilege_logon_ids: set[str] = set()

    sorted_events = sorted(events, key=lambda e: e.timestamp)

    for event in sorted_events:
        data = event.data

        if event.event_id == "4624":
            logon_id = data.get("TargetLogonId", "")
            account = data.get("TargetUserName", "")
            if not logon_id or not account or is_noise_account(account):
                continue

            logon_type_str = data.get("LogonType", "0")
            try:
                logon_type = int(logon_type_str)
            except (ValueError, TypeError):
                logon_type = 0

            session = LogonSession(
                logon_id=logon_id,
                account=account,
                domain=data.get("TargetDomainName", ""),
                logon_type=logon_type,
                logon_time=event.timestamp,
                source_ip=data.get("IpAddress"),
                is_privileged=logon_id in privilege_logon_ids,
            )
            sessions[logon_id] = session

        elif event.event_id in ("4634", "4647"):
            logon_id = data.get("TargetLogonId", "")
            if logon_id in sessions:
                sessions[logon_id].logoff_time = event.timestamp

        elif event.event_id == "4672":
            logon_id = data.get("SubjectLogonId", "")
            privilege_logon_ids.add(logon_id)
            if logon_id in sessions:
                sessions[logon_id].is_privileged = True

    return sorted(sessions.values(), key=lambda s: s.logon_time)


def build_sessions_from_evtx(evtx_path: str | Path) -> list[LogonSession]:
    return build_sessions(parse_evtx(evtx_path))
