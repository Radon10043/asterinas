#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Summarize complete sanitizer benchmark measurements by independent boot."""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import median


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    config = json.loads((args.directory / "config.json").read_text())
    rows = json.loads((args.directory / "measurements.json").read_text())
    boots = json.loads((args.directory / "boots.json").read_text())
    expected_boots = config["repetitions"] * sum(3 if m in ("kcov", "both") else 1 for m in config["modes"].split(",")) * len(config["guest_cpus"].split(","))
    if len(boots) != expected_boots or any(b["result"] != "PASS" for b in boots):
        raise ValueError("all configured boots must pass")
    groups = defaultdict(list)
    reference = {}
    seen = set()
    for row in rows:
        identity = (row["boot_id"], row["trace"], row["workload"])
        if identity in seen:
            raise ValueError(f"duplicate measurement {identity}")
        seen.add(identity)
        groups[(row["guest_cpus"], row["mode"], row["trace"], row["workload"])].append(row)
        if row["mode"] == "off" and row["trace"] == "off":
            reference[(row["guest_cpus"], row["rep"], row["workload"])] = row
    expected_groups = {
        (int(cpu), mode, trace, workload)
        for cpu in config["guest_cpus"].split(",")
        for mode in config["modes"].split(",")
        for trace in (["off", "pc", "cmp"] if mode in ("kcov", "both") else ["off"])
        for workload in ("syscalls", "pipe", "file", "mmap")
    }
    if set(groups) != expected_groups:
        raise ValueError("measurement group mismatch")
    summary = []
    for (cpus, mode, trace, workload), samples in sorted(groups.items()):
        if len(samples) != config["repetitions"] or {r["rep"] for r in samples} != set(range(1, config["repetitions"] + 1)):
            raise ValueError("sample count mismatch")
        latencies = [r["elapsed_ns"] / r["total_ops"] for r in samples]
        ratios = []
        for row in samples:
            base = reference[(cpus, row["rep"], workload)]
            if row["total_ops"] != base["total_ops"] or row["scale"] != base["scale"]:
                raise ValueError("workload size mismatch")
            ratios.append(100 * (row["elapsed_ns"] / base["elapsed_ns"] - 1))
        summary.append(dict(guest_cpus=cpus, mode=mode, trace=trace, workload=workload,
            boots=len(samples), total_ops_per_boot=samples[0]["total_ops"],
            median_ns_per_op=median(latencies), min_ns_per_op=min(latencies), max_ns_per_op=max(latencies),
            median_ops_per_second=median(1e9 / n for n in latencies),
            median_overhead_pct=median(ratios), min_overhead_pct=min(ratios), max_overhead_pct=max(ratios),
            max_records=max(r["max_records"] for r in samples),
            capacity=samples[0]["capacity"],
            median_ready_used_kib=median(r["boot_memtotal_kib"] - r["memfree_kib"] for r in samples)))
    with (args.directory / "summary.tsv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(summary[0]), delimiter="\t")
        writer.writeheader()
        writer.writerows(summary)
    print(f"BENCH_SUMMARY_PASS boots={len(boots)} rows={len(rows)} groups={len(summary)}")


if __name__ == "__main__":
    main()
