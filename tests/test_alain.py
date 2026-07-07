from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from alain_alsahira.batch import evaluate_events
from alain_alsahira.datasets import convert_nvd_to_events
from alain_alsahira.engine import analyze_events
from alain_alsahira.models import RuntimeEvent


class AlAinTests(unittest.TestCase):
    def test_detects_encoded_powershell(self):
        event = RuntimeEvent(kind="process", process_name="powershell.exe", command_line="powershell -enc SQBFAFgA")
        result = analyze_events([event])
        self.assertEqual(result.decision, "ISOLATE")
        self.assertEqual(result.highest_severity, "critical")

    def test_safe_event_is_ok(self):
        event = RuntimeEvent(kind="process", process_name="python.exe", command_line="python -m unittest discover")
        result = analyze_events([event])
        self.assertEqual(result.decision, "OK")

    def test_malformed_sensor_values_do_not_crash(self):
        event = RuntimeEvent.from_dict(
            {
                "kind": "network",
                "process_name": "worker.exe",
                "remote_port": "not-a-port",
                "pid": "unknown",
                "metadata": "raw sensor payload",
            }
        )
        self.assertEqual(event.remote_port, 0)
        self.assertEqual(event.pid, 0)
        self.assertEqual(event.metadata["raw_metadata"], "raw sensor payload")
        result = analyze_events([event])
        self.assertEqual(result.decision, "OK")

    def test_string_network_port_is_still_detected(self):
        event = RuntimeEvent.from_dict({"kind": "network", "process_name": "nc.exe", "remote_port": "4444/tcp"})
        result = analyze_events([event])
        self.assertEqual(result.decision, "INVESTIGATE")
        self.assertEqual(result.detections[0].rule_id, "SUSPICIOUS_PORT")

    def test_convert_and_evaluate_fixture(self):
        with tempfile.TemporaryDirectory(dir="C:/Projects") as tmp:
            nvd = Path(tmp) / "nvd.jsonl"
            out = Path(tmp) / "events.jsonl"
            nvd.write_text('{"id":"CVE-1","severity":"HIGH"}\n{"id":"CVE-2","severity":"LOW"}\n', encoding="utf-8")
            summary = convert_nvd_to_events(nvd, out)
            self.assertEqual(summary["rows"], 2)
            result = evaluate_events(out)
            self.assertEqual(result["processed"], 2)
            self.assertEqual(result["errors"], 0)
            self.assertGreaterEqual(result["metrics"]["f1"], 0.99)


if __name__ == "__main__":
    unittest.main()
