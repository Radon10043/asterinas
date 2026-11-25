#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Synthetic regression tests for benchmark-summary.py; no guest is booted."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SUMMARY_SCRIPT = Path(__file__).with_name("benchmark-summary.py")
MODES = ("off", "kcov", "kasan", "both")
WORKLOADS = ("syscalls", "pipe", "file", "mmap")
TRACE_MODES = {
    "off": ("off",),
    "kcov": ("off", "pc", "cmp"),
    "kasan": ("off",),
    "both": ("off", "pc", "cmp"),
}
FACTORS = {
    ("off", "off"): (1, 1),
    ("kcov", "off"): (11, 10),
    ("kcov", "pc"): (3, 2),
    ("kcov", "cmp"): (7, 4),
    ("kasan", "off"): (3, 4),
    ("both", "off"): (13, 10),
    ("both", "pc"): (2, 1),
    ("both", "cmp"): (9, 4),
}


def make_fixture():
    config = {
        "modes": ",".join(MODES),
        "guest_cpus": "1,4",
        "repetitions": 3,
    }
    boots = []
    rows = []
    for mode in MODES:
        for trace in TRACE_MODES[mode]:
            numerator, denominator = FACTORS[(mode, trace)]
            for cpus in (1, 4):
                for rep in (1, 2, 3):
                    boot_id = f"r{rep}-cpu{cpus}-{mode}-{trace}"
                    boots.append(
                        {
                            "boot_id": boot_id,
                            "mode": mode,
                            "guest_cpus": cpus,
                            "rep": rep,
                            "result": "PASS",
                        }
                    )
                    for workload in WORKLOADS:
                        base_elapsed = rep * 1_000_000
                        elapsed = base_elapsed * numerator // denominator
                        capacity = {
                            "pc": 262143,
                            "cmp": 65535,
                        }.get(trace, 0)
                        rows.append(
                            {
                                "boot_id": boot_id,
                                "guest_cpus": cpus,
                                "mode": mode,
                                "trace": trace,
                                "rep": rep,
                                "workload": workload,
                                "elapsed_ns": elapsed,
                                "total_ops": 1000,
                                "scale": 5,
                                "records": rep * 100 if trace != "off" else 0,
                                "max_records": rep * 10 if trace != "off" else 0,
                                "capacity": capacity,
                                "boot_memtotal_kib": 4096000,
                                "memfree_kib": 1_000_000 + rep * 100,
                            }
                        )
    return config, boots, rows

class SummaryHarness:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="benchmark-summary-test-")
        self.directory = Path(self.temp.name)
        self.config, self.boots, self.rows = make_fixture()

    def close(self):
        self.temp.cleanup()

    def write_inputs(self, *, config=None, boots=None, rows=None):
        inputs = {
            "config.json": self.config if config is None else config,
            "boots.json": self.boots if boots is None else boots,
            "measurements.json": self.rows if rows is None else rows,
        }
        for name, value in inputs.items():
            (self.directory / name).write_text(json.dumps(value))

    def run_summary(self):
        return subprocess.run(
            [sys.executable, str(SUMMARY_SCRIPT), str(self.directory)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )


class BenchmarkSummaryTests(unittest.TestCase):
    def setUp(self):
        self.harness = SummaryHarness()

    def tearDown(self):
        self.harness.close()

    def assert_rejected(self, expected_message):
        result = self.harness.run_summary()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected_message, result.stdout)

    def test_complete_matrix_calculates_medians_and_signed_overhead(self):
        self.harness.write_inputs()
        result = self.harness.run_summary()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("BENCH_SUMMARY_PASS boots=48 rows=192 groups=64", result.stdout)

        with (self.harness.directory / "summary.tsv").open(newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(len(rows), 64)
        indexed = {
            (int(row["guest_cpus"]), row["mode"], row["trace"], row["workload"]): row
            for row in rows
        }

        baseline = indexed[(1, "off", "off", "syscalls")]
        self.assertEqual(float(baseline["median_ns_per_op"]), 2000.0)
        self.assertEqual(float(baseline["min_ns_per_op"]), 1000.0)
        self.assertEqual(float(baseline["max_ns_per_op"]), 3000.0)
        self.assertEqual(float(baseline["median_ops_per_second"]), 500000.0)
        self.assertEqual(float(baseline["median_overhead_pct"]), 0.0)

        positive = indexed[(1, "kcov", "pc", "syscalls")]
        self.assertEqual(float(positive["median_ns_per_op"]), 3000.0)
        self.assertEqual(float(positive["median_overhead_pct"]), 50.0)
        self.assertEqual(float(positive["min_overhead_pct"]), 50.0)
        self.assertEqual(float(positive["max_overhead_pct"]), 50.0)
        self.assertEqual(int(positive["max_records"]), 30)
        self.assertEqual(int(positive["capacity"]), 262143)

        negative = indexed[(1, "kasan", "off", "syscalls")]
        self.assertEqual(float(negative["median_ns_per_op"]), 1500.0)
        self.assertEqual(float(negative["median_overhead_pct"]), -25.0)
        self.assertEqual(float(negative["min_overhead_pct"]), -25.0)
        self.assertEqual(float(negative["max_overhead_pct"]), -25.0)

        both = indexed[(4, "both", "cmp", "mmap")]
        self.assertEqual(float(both["median_overhead_pct"]), 125.0)
        self.assertEqual(int(both["total_ops_per_boot"]), 1000)
        self.assertEqual(int(both["max_records"]), 30)
        self.assertEqual(int(both["capacity"]), 65535)
        self.assertEqual(float(both["median_ready_used_kib"]), 3095800.0)

    def test_rejects_missing_entire_measurement_group(self):
        rows = [
            row
            for row in self.harness.rows
            if not (
                row["guest_cpus"] == 1
                and row["mode"] == "both"
                and row["trace"] == "cmp"
                and row["workload"] == "mmap"
            )
        ]
        self.harness.write_inputs(rows=rows)
        self.assert_rejected("measurement group mismatch")

    def test_rejects_duplicate_sample(self):
        rows = list(self.harness.rows)
        rows.append(dict(rows[0]))
        self.harness.write_inputs(rows=rows)
        self.assert_rejected("duplicate measurement")

    def test_rejects_missing_repetition(self):
        rows = [
            row
            for row in self.harness.rows
            if not (
                row["guest_cpus"] == 4
                and row["mode"] == "kcov"
                and row["trace"] == "pc"
                and row["workload"] == "pipe"
                and row["rep"] == 2
            )
        ]
        self.harness.write_inputs(rows=rows)
        self.assert_rejected("sample count mismatch")

    def test_rejects_incomplete_boot_list(self):
        self.harness.write_inputs(boots=self.harness.boots[:-1])
        self.assert_rejected("all configured boots must pass")

    def test_rejects_total_ops_mismatch_with_off_reference(self):
        rows = [dict(row) for row in self.harness.rows]
        selected = next(
            row
            for row in rows
            if row["guest_cpus"] == 1
            and row["mode"] == "kcov"
            and row["trace"] == "pc"
            and row["workload"] == "syscalls"
            and row["rep"] == 1
        )
        selected["total_ops"] += 1
        self.harness.write_inputs(rows=rows)
        self.assert_rejected("workload size mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)