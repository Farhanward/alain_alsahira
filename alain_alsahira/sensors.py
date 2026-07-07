from __future__ import annotations

import csv
import io
import json
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any

from .models import RuntimeEvent


def collect_process_events() -> list[RuntimeEvent]:
    if platform.system().lower().startswith("win"):
        completed = subprocess.run(["tasklist", "/fo", "csv", "/v"], capture_output=True, text=True, shell=False)
        if completed.returncode != 0:
            return []
        rows = csv.DictReader(io.StringIO(completed.stdout))
        events = []
        for row in rows:
            events.append(RuntimeEvent(kind="process", process_name=row.get("Image Name", ""), pid=_int(row.get("PID")), sensor="tasklist"))
        return events
    proc = Path("/proc")
    if not proc.exists():
        return []
    events = []
    for path in proc.iterdir():
        if path.name.isdigit():
            events.append(RuntimeEvent(kind="process", process_name=_read(path / "comm").strip(), command_line=_read(path / "cmdline").replace("\x00", " "), pid=int(path.name), sensor="procfs"))
    return events


def collect_netstat_events() -> list[RuntimeEvent]:
    completed = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, shell=False)
    if completed.returncode != 0:
        return []
    events: list[RuntimeEvent] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper().startswith("TCP"):
            remote = parts[2]
            port = 0
            if ":" in remote:
                try:
                    port = int(remote.rsplit(":", 1)[1])
                except ValueError:
                    port = 0
            events.append(RuntimeEvent(kind="network", command_line=line, remote_port=port, sensor="netstat"))
    return events


def snapshot() -> dict[str, Any]:
    events = collect_process_events() + collect_netstat_events()
    return {"host": socket.gethostname(), "events": [event.to_dict() for event in events]}


def write_snapshot(path: str | Path) -> dict[str, Any]:
    data = snapshot()
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _int(value) -> int:
    try:
        return int(str(value or "0").replace(",", ""))
    except ValueError:
        return 0
