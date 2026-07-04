"""EVTX Security log parser for logon-related events."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx

NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

TARGET_EVENT_IDS = {"4624", "4634", "4647", "4672"}


@dataclass
class LogonEvent:
    event_id: str
    timestamp: datetime
    data: dict[str, str | None]


def _parse_record(record) -> LogonEvent | None:
    root = ET.fromstring(record.xml())

    event_id_el = root.find(".//ns:EventID", NS)
    if event_id_el is None or event_id_el.text not in TARGET_EVENT_IDS:
        return None

    time_el = root.find(".//ns:TimeCreated", NS)
    timestamp_str = time_el.attrib.get("SystemTime", "") if time_el is not None else ""
    try:
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        timestamp = datetime.min

    data: dict[str, str | None] = {}
    for item in root.findall(".//ns:Data", NS):
        name = item.attrib.get("Name", "")
        data[name] = item.text

    return LogonEvent(
        event_id=event_id_el.text,
        timestamp=timestamp,
        data=data,
    )


def parse_evtx(evtx_path: str | Path) -> Iterator[LogonEvent]:
    with evtx.Evtx(str(evtx_path)) as log:
        for record in log.records():
            event = _parse_record(record)
            if event is not None:
                yield event
