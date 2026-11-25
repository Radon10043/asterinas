#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Synthetic log tests for benchmark-run.py parse_log."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest


DIRECTORY = Path(__file__).resolve().parent
RUNNER_PATH = DIRECTORY / "benchmark-run.py"
SPEC = importlib.util.spec_from_file_location("benchmark_runner_under_test", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load benchmark runner: {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)

WORKLOAD_ITERATIONS = {
    "syscalls": 20_000,
    "pipe": 2_000,
    "file": 500,
    "mmap": 1_000,
}
COMMON_FIELDS = (
    "workload", "trace", "workers", "iterations", "total_ops", "elapsed_ns",
    "records", "max_records", "capacity", "memfree_kib", "scale",
    "syscall_calls", "capacity_words", "capacity_unit",
    "warmup_iterations_per_worker", "join_included", "validation",
)


def make_rows(traces, cpus):
    rows = []
    for trace in traces:
        for workload, iterations in WORKLOAD_ITERATIONS.items():
            total_ops = iterations * cpus
            if trace == "off":
                capacity = records = max_records = 0
                capacity_unit = "none"
            elif trace == "pc":
                capacity, records, max_records = 1_048_575, total_ops * 3, 3
                capacity_unit = "pc_records"
            else:
                capacity, records, max_records = 262_143, total_ops * 3, 3
                capacity_unit = "cmp_records"
            row = {
                "workload": workload,
                "trace": trace,
                "workers": cpus,
                "iterations": iterations,
                "total_ops": total_ops,
                "elapsed_ns": total_ops * 1_000,
                "records": records,
                "max_records": max_records,
                "capacity": capacity,
                "memfree_kib": 128_000,
                "scale": 1,
                "syscall_calls": total_ops * (6 if workload == "file" else 2),
                "capacity_words": 1_048_576,
                "capacity_unit": capacity_unit,
                "warmup_iterations_per_worker": iterations,
                "join_included": False,
                "validation": "passed",
            }
            if workload == "file":
                row["tmpfs_root"] = "/tmp"
            rows.append(row)
    return rows


def make_log(mode="off", cpus=1, traces=None, rows=None):
    if traces is None:
        traces = ["off", "pc", "cmp"] if mode in ("kcov", "both") else ["off"]
    if rows is None:
        rows = make_rows(traces, cpus)
    lines = []
    if mode in ("kasan", "both"):
        lines.append("[kasan] KernelAddressSanitizer enabled")
    lines.extend([
        "BENCH_MEM_BOOT_BEGIN",
        "MemTotal: 2097152 kB",
        "MemFree: 1800000 kB",
        "MemAvailable: 1800000 kB",
        "BENCH_MEM_BOOT_END",
    ])
    lines.extend("BENCH_RESULT " + json.dumps(row, separators=(",", ":")) for row in rows)
    lines.extend("BENCH_PROGRAM_PASS" for _ in traces)
    lines.append("BENCH_GUEST_EXIT=0")
    return "\n".join(lines) + "\n"


class BenchmarkRunnerParseLogTests(unittest.TestCase):
    def assert_rejected(self, log, mode="off", cpus=1, traces=None, status=33):
        if traces is None:
            traces = ["off", "pc", "cmp"] if mode in ("kcov", "both") else ["off"]
        with self.assertRaises((AssertionError, KeyError, ValueError)):
            RUNNER.parse_log(log, mode, cpus, traces, status)

    def test_synthetic_current_c_schema_passes_all_modes_and_cpu_counts(self):
        for mode in RUNNER.MODES:
            traces = ["off", "pc", "cmp"] if mode in ("kcov", "both") else ["off"]
            for cpus in (1, 4):
                with self.subTest(mode=mode, cpus=cpus):
                    rows = RUNNER.parse_log(make_log(mode, cpus, traces), mode, cpus, traces, 33)
                    self.assertEqual(len(rows), len(traces) * len(WORKLOAD_ITERATIONS))
                    for row in rows:
                        self.assertEqual(row["workers"], cpus)
                        self.assertEqual(row["capacity_words"], 1_048_576)
                        self.assertIn(row["capacity_unit"], ("none", "pc_records", "cmp_records"))
                        self.assertIn("boot_memtotal_kib", row)
                        self.assertIn("boot_memfree_kib", row)
                        self.assertIn("boot_used_kib", row)

    def test_missing_and_duplicate_measurement_rows_are_rejected(self):
        traces = ["off"]
        rows = make_rows(traces, 1)
        with self.subTest("missing"):
            self.assert_rejected(make_log(rows=rows[:-1]), traces=traces)
        with self.subTest("duplicate"):
            self.assert_rejected(make_log(rows=rows + [rows[0]]), traces=traces)

    def test_missing_or_duplicate_guest_and_program_completion_markers_are_rejected(self):
        traces = ["off"]
        valid = make_log(traces=traces)
        with self.subTest("guest completion missing"):
            self.assert_rejected(valid.replace("BENCH_GUEST_EXIT=0\n", ""), traces=traces)
        with self.subTest("guest completion duplicated"):
            self.assert_rejected(valid + "BENCH_GUEST_EXIT=0\n", traces=traces)
        with self.subTest("program completion missing"):
            self.assert_rejected(valid.replace("BENCH_PROGRAM_PASS\n", ""), traces=traces)
        with self.subTest("program completion duplicated"):
            self.assert_rejected(valid.replace("BENCH_PROGRAM_PASS\n", "BENCH_PROGRAM_PASS\nBENCH_PROGRAM_PASS\n"), traces=traces)

    def test_non_successful_qemu_exit_is_rejected(self):
        self.assert_rejected(make_log(), status=65)

    def test_wrong_worker_count_is_rejected(self):
        rows = make_rows(["off"], 1)
        rows[0]["workers"] = 4
        self.assert_rejected(make_log(rows=rows), cpus=1, traces=["off"])

    def test_zero_active_records_and_saturated_trace_are_rejected(self):
        traces = ["off", "pc", "cmp"]
        rows = make_rows(traces, 1)
        saturated = copy.deepcopy(rows)
        pc_row = next(row for row in rows if row["trace"] == "pc")
        pc_row["records"] = 0
        next(row for row in saturated if row["trace"] == "pc")["max_records"] = 1_048_575
        next(row for row in saturated if row["trace"] == "cmp")["max_records"] = 262_143
        with self.subTest("zero"):
            self.assert_rejected(make_log("kcov", 1, traces, rows), mode="kcov", traces=traces)
        with self.subTest("saturated"):
            self.assert_rejected(make_log("kcov", 1, traces, saturated), mode="kcov", traces=traces)

    def test_wrong_capacity_and_word_count_are_rejected(self):
        traces = ["off", "pc", "cmp"]
        cases = (
            ("pc capacity", "pc", "capacity", 1_048_574),
            ("cmp capacity", "cmp", "capacity", 262_142),
            ("word count", "pc", "capacity_words", 1_048_575),
        )
        for name, trace, field, value in cases:
            rows = make_rows(traces, 1)
            next(row for row in rows if row["trace"] == trace)[field] = value
            with self.subTest(name=name):
                self.assert_rejected(
                    make_log("kcov", 1, traces, rows), mode="kcov", traces=traces
                )

    def test_wrong_warmup_count_is_rejected(self):
        rows = make_rows(["off"], 1)
        rows[0]["warmup_iterations_per_worker"] += 1
        self.assert_rejected(make_log(rows=rows), traces=["off"])

    def test_kasan_banner_must_match_instrumentation_mode(self):
        with self.subTest("missing for kasan"):
            self.assert_rejected(make_log("off"), mode="kasan", traces=["off"])
        with self.subTest("unexpected for off"):
            self.assert_rejected(
                "[kasan] KernelAddressSanitizer enabled\n" + make_log("off"),
                mode="off", traces=["off"])

    def test_failure_and_panic_markers_are_rejected(self):
        valid = make_log(traces=["off"])
        for marker in ("FAIL synthetic failure", "BUG: KASAN: synthetic report", "panicked at synthetic panic"):
            with self.subTest(marker=marker):
                self.assert_rejected(valid + marker + "\n", traces=["off"])

    def test_missing_memory_section_or_meminfo_fields_are_rejected(self):
        valid = make_log(traces=["off"])
        cases = {
            "begin marker": valid.replace("BENCH_MEM_BOOT_BEGIN\n", ""),
            "end marker": valid.replace("BENCH_MEM_BOOT_END\n", ""),
            "MemTotal": valid.replace("MemTotal: 2097152 kB\n", ""),
            "MemFree": valid.replace("MemFree: 1800000 kB\n", ""),
            "MemAvailable": valid.replace("MemAvailable: 1800000 kB\n", ""),
        }
        for name, log in cases.items():
            with self.subTest(name=name):
                self.assert_rejected(log, traces=["off"])

    def test_rows_reject_missing_current_c_schema_fields(self):
        traces = ["off"]
        for field in COMMON_FIELDS:
            rows = make_rows(traces, 1)
            del rows[0][field]
            with self.subTest(field=field):
                self.assert_rejected(make_log(rows=rows), traces=traces)
        rows = make_rows(traces, 1)
        file_row = next(row for row in rows if row["workload"] == "file")
        del file_row["tmpfs_root"]
        with self.subTest(field="tmpfs_root"):
            self.assert_rejected(make_log(rows=rows), traces=traces)


if __name__ == "__main__":
    unittest.main()