"""CLI entry point."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from .parser import parse_evtx
from .session_builder import build_sessions_from_evtx


@click.group()
def main() -> None:
    """Credential Exposure Scoper - EVTX logon session analyzer."""


@main.command()
@click.argument("evtx_path", type=click.Path(exists=True))
def parse(evtx_path: str) -> None:
    """Parse EVTX and display raw logon events."""
    for event in parse_evtx(evtx_path):
        data = event.data
        if event.event_id == "4624":
            click.echo(
                f"[4624] {data.get('TargetDomainName')}\\{data.get('TargetUserName')} "
                f"Type:{data.get('LogonType')} "
                f"LogonId:{data.get('TargetLogonId')} "
                f"IP:{data.get('IpAddress')}"
            )
        elif event.event_id in ("4634", "4647"):
            click.echo(
                f"[{event.event_id}] {data.get('TargetDomainName')}\\{data.get('TargetUserName')} "
                f"LogonId:{data.get('TargetLogonId')}"
            )
        elif event.event_id == "4672":
            click.echo(
                f"[4672] {data.get('SubjectDomainName')}\\{data.get('SubjectUserName')} "
                f"LogonId:{data.get('SubjectLogonId')}"
            )


@main.command()
@click.argument("evtx_path", type=click.Path(exists=True))
def sessions(evtx_path: str) -> None:
    """Build and display logon sessions from EVTX."""
    session_list = build_sessions_from_evtx(evtx_path)

    console = Console()
    table = Table(title=f"Logon Sessions ({len(session_list)} sessions)")

    table.add_column("Logon ID", style="dim")
    table.add_column("Account")
    table.add_column("Type", justify="center")
    table.add_column("Logon Time")
    table.add_column("Logoff Time")
    table.add_column("Source IP")
    table.add_column("Privileged", justify="center")
    table.add_column("Cred Cached", justify="center")

    for s in session_list:
        logoff_str = s.logoff_time.strftime("%Y-%m-%d %H:%M:%S") if s.logoff_time else "(active)"
        table.add_row(
            s.logon_id,
            s.display_account,
            str(s.logon_type),
            s.logon_time.strftime("%Y-%m-%d %H:%M:%S"),
            logoff_str,
            s.source_ip or "-",
            "Y" if s.is_privileged else "",
            "Y" if s.is_credential_cached else "",
        )

    console.print(table)


if __name__ == "__main__":
    main()
