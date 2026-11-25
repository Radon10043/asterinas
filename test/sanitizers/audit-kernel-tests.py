#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Audit named kernel test executions against the reviewed test inventory."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TEST = re.compile(r"^test (\S+) \.\.\.", re.MULTILINE)
SUMMARY = re.compile(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) filtered out\.$",
    re.MULTILINE,
)
HEADER = re.compile(r'^running (\d+) tests in crate "([^"]+)"$', re.MULTILINE)
SKIP = re.compile(r"\bskip(?:ped|ping)?\b", re.IGNORECASE)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit_log(raw, crate, expected, allowed_skips, required_output=None):
    text = ANSI.sub("", raw).replace("\r", "")
    require(len(expected) == len(set(expected)), "duplicate inventory entries")
    require(text.count("[ktest runner] All crates tested.") == 1,
            "missing or duplicate completion marker")
    headers = HEADER.findall(text)
    summaries = list(SUMMARY.finditer(text))
    tests = list(TEST.finditer(text))
    if not expected:
        require(not headers and not summaries and not tests,
                "zero-test crate contains unexpected test executions")
        return []
    require(headers == [(str(len(expected)), crate)],
            "selected crate or registered test count differs from inventory")
    require(len(summaries) == 1, "missing or duplicate success summary")
    summary = summaries[0]
    require(text.index("[ktest runner] All crates tested.") > summary.end(),
            "completion marker precedes the test summary")
    require(tuple(map(int, summary.groups())) == (len(expected), 0, 0),
            "failed, filtered or missing tests")
    names = [match.group(1) for match in tests]
    require(len(names) == len(set(names)), "duplicate test execution")
    require(set(names) == set(expected), "named executions differ from inventory")
    require(all(match.start() < summary.start() for match in tests),
            "test execution appears after summary")
    results = []
    for index, match in enumerate(tests):
        end = tests[index + 1].start() if index + 1 < len(tests) else summary.start()
        body = text[match.end():end].strip()
        require(re.search(r"(?:^|\s)ok$", body) is not None,
                f"test has no terminal success status: {match.group(1)}")
        markers = re.findall(r"\[skipped: ([^\]\r\n]+)\]", body)
        remainder = re.sub(r"\[skipped: [^\]\r\n]+\]", "", body)
        require(SKIP.search(remainder) is None,
                f"unclassified skip message: {match.group(1)}")
        name = match.group(1)
        status = "executed"
        reason = ""
        if markers:
            require(len(markers) == 1 and allowed_skips.get(name) == markers[0],
                    f"unexpected skipped test: {name}")
            status, reason = "skipped", markers[0]
        if status == "executed":
            for marker, minimum in (required_output or {}).get(name, {}).items():
                require(body.count(marker) >= minimum,
                        f"required test activity is absent: {name}")
        results.append({"name": name, "status": status, "reason": reason})
    return results


def audit_bundle(directory, inventory, allowed_skips, instrumented, required_output):
    require(directory.is_dir(), f"missing result directory: {directory}")
    require({p.name for p in directory.iterdir() if p.is_dir()} == set(inventory),
            "result directories differ from the expected crate list")
    rows = []
    cases = []
    for crate, expected in sorted(inventory.items()):
        path = directory / crate
        require((path / "qemu-exit.txt").read_text().strip() == "33",
                f"QEMU did not return success: {crate}")
        raw = (path / "serial.log").read_text()
        require(("[kasan] KernelAddressSanitizer enabled" in raw) == instrumented,
                f"unexpected instrumentation mode: {crate}")
        digest = (path / "image.sha256").read_text().split()[0]
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                f"invalid image digest: {crate}")
        actual = hashlib.sha256((path / "efi/bzImage").read_bytes()).hexdigest()
        require(actual == digest, f"retained image digest mismatch: {crate}")
        results = audit_log(raw, crate, expected, allowed_skips, required_output)
        executed = sum(row["status"] == "executed" for row in results)
        skipped = len(results) - executed
        rows.append({
            "crate": crate, "reported_ok": len(results), "executed": executed,
            "skipped": skipped, "zero_tests": int(not expected),
            "image_sha256": digest,
        })
        cases.extend({"crate": crate, **row} for row in results)
    return rows, cases


def write_tsv(path, rows, fields):
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t",
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--instrumented", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    catalog = json.loads(Path(__file__).with_name("expected-kernel-tests.json").read_text())
    default = catalog["default"]
    instrumented = {name: default[name] + additions
                    for name, additions in catalog["instrumented_additions"].items()}
    all_rows, all_cases = [], []
    for mode, directory, inventory in [
        ("default", args.workspace, default),
        ("kcov-kasan", args.instrumented, instrumented),
    ]:
        rows, cases = audit_bundle(directory, inventory, catalog["allowed_skips"],
                                   mode == "kcov-kasan", catalog["required_output"])
        all_rows.extend({"configuration": mode, **row} for row in rows)
        all_cases.extend({"configuration": mode, **row} for row in cases)
    args.output.mkdir(parents=True, exist_ok=False)
    write_tsv(args.output / "summary.tsv", all_rows,
              ["configuration", "crate", "reported_ok", "executed", "skipped",
               "zero_tests", "image_sha256"])
    write_tsv(args.output / "tests.tsv", all_cases,
              ["configuration", "crate", "name", "status", "reason"])
    for mode in ("default", "kcov-kasan"):
        rows = [row for row in all_rows if row["configuration"] == mode]
        print(f"{mode}: reported_ok={sum(r['reported_ok'] for r in rows)} "
              f"executed={sum(r['executed'] for r in rows)} "
              f"skipped={sum(r['skipped'] for r in rows)} "
              f"zero_test_crates={sum(r['zero_tests'] for r in rows)}")


if __name__ == "__main__":
    main()
