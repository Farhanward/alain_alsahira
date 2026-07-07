from __future__ import annotations

import argparse
import json
from pathlib import Path

from .batch import evaluate_events
from .datasets import convert_nvd_to_events
from .engine import analyze_events
from .ledger import append, verify
from .models import RuntimeEvent
from .reports import markdown
from .sensors import write_snapshot


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="alain", description="العين الساهرة: حارس Runtime محلي.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--out", default="reports/runtime_snapshot.json")
    scan = sub.add_parser("scan")
    scan.add_argument("--input", required=True)
    convert = sub.add_parser("convert-nvd")
    convert.add_argument("--input", default="C:/Projects/kashif/data/external/nvd_cves_12000.jsonl")
    convert.add_argument("--out", default="data/benchmarks/alain_nvd_runtime_events.jsonl")
    batch = sub.add_parser("batch")
    batch.add_argument("--input", required=True)
    batch.add_argument("--json-out", default="reports/alain_nvd_benchmark.json")
    batch.add_argument("--report", default="reports/alain_nvd_benchmark.md")
    stress = sub.add_parser("stress")
    stress.add_argument("--input", required=True)
    stress.add_argument("--repeat", type=int, default=3)
    stress.add_argument("--json-out", default="reports/alain_nvd_stress.json")
    stress.add_argument("--report", default="reports/alain_nvd_stress.md")
    sub.add_parser("verify-ledger")
    serve = sub.add_parser("serve")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    sub.add_parser("version")
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        from .service import run_server

        run_server(host=args.host, port=args.port)
        return 0
    if args.cmd == "version":
        from .version import __version__

        print(json.dumps({"service": "alain-alsahira", "version": __version__}, ensure_ascii=False))
        return 0
    if args.cmd == "snapshot":
        data = write_snapshot(args.out)
        assessment = analyze_events([RuntimeEvent.from_dict(e) for e in data["events"]])
        append({"kind": "snapshot", "assessment": assessment.to_dict()})
        print(json.dumps({"snapshot": args.out, "assessment": assessment.to_dict()}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "scan":
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        events = data.get("events", data if isinstance(data, list) else [data])
        assessment = analyze_events([RuntimeEvent.from_dict(e) for e in events])
        append({"kind": "scan", "assessment": assessment.to_dict()})
        print(json.dumps(assessment.to_dict(), ensure_ascii=False, indent=2))
        return 0 if assessment.decision == "OK" else 2
    if args.cmd == "convert-nvd":
        print(json.dumps(convert_nvd_to_events(args.input, args.out), ensure_ascii=False, indent=2))
        return 0
    if args.cmd in {"batch", "stress"}:
        summary = evaluate_events(args.input, repeat=getattr(args, "repeat", 1))
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        Path(args.report).write_text(markdown(summary, "تقرير ضغط العين الساهرة" if args.cmd == "stress" else "تقرير العين الساهرة"), encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if summary["collapse_check"]["passed"] else 2
    if args.cmd == "verify-ledger":
        print(json.dumps(verify(), ensure_ascii=False, indent=2))
        return 0
    raise ValueError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())
