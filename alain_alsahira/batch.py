from __future__ import annotations

import json
import statistics
import time
import tracemalloc
from pathlib import Path

from .engine import analyze_events
from .models import RuntimeEvent


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(round((pct / 100) * (len(values) - 1))))]


def evaluate_events(path: str | Path, repeat: int = 1) -> dict:
    records = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    tp = tn = fp = fn = errors = 0
    latencies = []
    started = time.perf_counter()
    tracemalloc.start()
    for _ in range(repeat):
        for record in records:
            expected = bool(record.get("expected_unsafe") or record.get("label") == 1)
            event = RuntimeEvent.from_dict(record.get("event") or record)
            t0 = time.perf_counter()
            try:
                assessment = analyze_events([event])
                predicted = assessment.decision != "OK"
            except Exception:
                errors += 1
                predicted = True
            latencies.append((time.perf_counter() - t0) * 1000)
            if expected and predicted:
                tp += 1
            elif expected and not predicted:
                fn += 1
            elif not expected and predicted:
                fp += 1
            else:
                tn += 1
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "input": str(Path(path).resolve()),
        "records": len(records),
        "repeat": repeat,
        "processed": len(records) * repeat,
        "errors": errors,
        "metrics": {"accuracy": accuracy, "precision": precision, "recall": recall, "specificity": specificity, "f1": f1, "tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "latency_ms": {"mean": statistics.fmean(latencies) if latencies else 0.0, "p50": _percentile(latencies, 50), "p95": _percentile(latencies, 95), "p99": _percentile(latencies, 99), "max": max(latencies) if latencies else 0.0},
        "memory_mb": {"current": current / 1_000_000, "peak": peak / 1_000_000},
        "elapsed_seconds": time.perf_counter() - started,
        "collapse_check": {"passed": errors == 0, "criteria": "errors == 0"},
    }
