"""Credential exposure analysis logic."""

from __future__ import annotations

from datetime import datetime

from .session import LogonSession


# Accounts to filter out (noise)
NOISE_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "ANONYMOUS LOGON", "-"}


def is_noise_account(account: str) -> bool:
    if account in NOISE_ACCOUNTS:
        return True
    if account.endswith("$"):
        return True
    return False
