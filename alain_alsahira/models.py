from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        match = re.search(r"\d+", str(value))
        return int(match.group(0)) if match else default


def _safe_metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if value in (None, ""):
        return {}
    return {"raw_metadata": value}


@dataclass
class RuntimeEvent:
    kind: str
    process_name: str = ""
    command_line: str = ""
    parent_process: str = ""
    path: str = ""
    remote_ip: str = ""
    remote_port: int = 0
    pid: int = 0
    sensor: str = "local"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuntimeEvent":
        return cls(
            kind=str(data.get("kind") or "process"),
            process_name=str(data.get("process_name") or data.get("process") or ""),
            command_line=str(data.get("command_line") or data.get("cmdline") or data.get("cmd") or ""),
            parent_process=str(data.get("parent_process") or data.get("parent") or ""),
            path=str(data.get("path") or ""),
            remote_ip=str(data.get("remote_ip") or data.get("destination_ip") or ""),
            remote_port=_safe_int(data.get("remote_port") or data.get("destination_port") or 0),
            pid=_safe_int(data.get("pid") or 0),
            sensor=str(data.get("sensor") or "local"),
            metadata=_safe_metadata(data.get("metadata")),
        )

    def scan_text(self) -> str:
        return " ".join(
            [
                self.kind,
                self.process_name,
                self.command_line,
                self.parent_process,
                self.path,
                self.remote_ip,
                str(self.remote_port),
            ]
        ).lower()

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Detection:
    rule_id: str
    severity: str
    title_ar: str
    detail_ar: str
    evidence: str
    action_ar: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Assessment:
    event_count: int
    detections: list[Detection]
    risk_score: int
    highest_severity: str
    decision: str
    summary_ar: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "risk_score": self.risk_score,
            "highest_severity": self.highest_severity,
            "decision": self.decision,
            "summary_ar": self.summary_ar,
            "detections": [item.to_dict() for item in self.detections],
        }
