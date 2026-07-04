"""Logon session model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


# Logon types that cache credentials in LSASS
CREDENTIAL_CACHED_TYPES = {2, 4, 5, 7, 8, 9, 10, 11}


@dataclass
class LogonSession:
    logon_id: str
    account: str
    domain: str
    logon_type: int
    logon_time: datetime
    logoff_time: datetime | None = None
    source_ip: str | None = None
    is_privileged: bool = False
    hostname: str = ""

    @property
    def is_credential_cached(self) -> bool:
        return self.logon_type in CREDENTIAL_CACHED_TYPES

    @property
    def display_account(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.account}"
        return self.account

    def is_active_at(self, compromise_time: datetime) -> bool:
        if self.logon_time > compromise_time:
            return False
        if self.logoff_time is None:
            return True
        return self.logoff_time >= compromise_time
