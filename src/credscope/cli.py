"""CLI entry point."""

from __future__ import annotations

import click

from .parser import parse_evtx


@click.command()
@click.argument("evtx_path", type=click.Path(exists=True))
def main(evtx_path: str) -> None:
    """Parse Windows Security EVTX and display logon events."""
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


if __name__ == "__main__":
    main()
