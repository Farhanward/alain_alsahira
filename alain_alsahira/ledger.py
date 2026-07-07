from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_LEDGER = Path("ledger") / "alain-ledger.jsonl"
DEFAULT_SECRET = Path("ledger") / ".alain-secret"


def canonical(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _secret() -> bytes:
    DEFAULT_SECRET.parent.mkdir(parents=True, exist_ok=True)
    if not DEFAULT_SECRET.exists():
        DEFAULT_SECRET.write_text(secrets.token_hex(32), encoding="utf-8")
    return DEFAULT_SECRET.read_text(encoding="utf-8").strip().encode("utf-8")


def append(payload: dict[str, Any], path: str | Path = DEFAULT_LEDGER) -> dict[str, Any]:
    target = Path(path)
    previous = "GENESIS"
    index = 0
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                previous = rec["record_hash"]
                index = int(rec["index"])
    base = {
        "index": index + 1,
        "timestamp": datetime.now(UTC).isoformat(),
        "previous_hash": previous,
        "payload_hash": hashlib.sha256(canonical(payload).encode()).hexdigest(),
    }
    record_hash = hashlib.sha256(canonical(base).encode()).hexdigest()
    seal = hmac.new(_secret(), record_hash.encode(), hashlib.sha256).hexdigest()
    record = {**base, "record_hash": record_hash, "seal": seal, "payload": payload}
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(canonical(record) + "\n")
    return {k: record[k] for k in ("index", "timestamp", "record_hash", "seal")}


def verify(path: str | Path = DEFAULT_LEDGER) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"ok": True, "records": 0, "message": "ledger file does not exist yet"}
    previous = "GENESIS"
    count = 0
    key = _secret()
    for line_number, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        rec = json.loads(line)
        base = {k: rec[k] for k in ("index", "timestamp", "previous_hash", "payload_hash")}
        if rec["previous_hash"] != previous:
            return {"ok": False, "line": line_number, "message": "broken hash chain"}
        if rec["payload_hash"] != hashlib.sha256(canonical(rec["payload"]).encode()).hexdigest():
            return {"ok": False, "line": line_number, "message": "payload hash mismatch"}
        if rec["record_hash"] != hashlib.sha256(canonical(base).encode()).hexdigest():
            return {"ok": False, "line": line_number, "message": "record hash mismatch"}
        if rec["seal"] != hmac.new(key, rec["record_hash"].encode(), hashlib.sha256).hexdigest():
            return {"ok": False, "line": line_number, "message": "seal mismatch"}
        previous = rec["record_hash"]
        count += 1
    return {"ok": True, "records": count, "message": "ledger verified"}
