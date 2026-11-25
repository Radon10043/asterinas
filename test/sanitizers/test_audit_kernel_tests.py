#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Unit tests for named kernel-test log auditing."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


DIRECTORY = Path(__file__).resolve().parent
AUDIT_PATH = DIRECTORY / "audit-kernel-tests.py"
CATALOG_PATH = DIRECTORY / "expected-kernel-tests.json"
SPEC = importlib.util.spec_from_file_location("audit_kernel_tests_under_test", AUDIT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load audit module: {AUDIT_PATH}")
AUDITOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDITOR
SPEC.loader.exec_module(AUDITOR)

COMPLETION = "[ktest runner] All crates tested."
EXPECTED_KNOWN_SKIPS = {
    "ostd::arch::vm::vmx::test::multiple_vmx_guards_lifecycle": "VMX unavailable",
    "ostd::arch::vm::vmx::vmcs::test::switch_and_reuse_vmcs": "VMX unavailable",
    "ostd::vm::gpm_space::test::guest_mapping_lifecycle":
        "VMX/EPT invalidation unavailable",
}


def make_log(crate, names, statuses=None, passed=None, failed=0, filtered=0):
    if statuses is None:
        statuses = ["ok"] * len(names)
    if passed is None:
        passed = len(names) - failed
    lines = [f'running {len(names)} tests in crate "{crate}"']
    lines.extend(f"test {name} ... {status}" for name, status in zip(names, statuses))
    lines.append(
        f"test result: ok. {passed} passed; {failed} failed; {filtered} filtered out."
    )
    lines.append(COMPLETION)
    return "\n".join(lines)


class AuditKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allowed_skips = json.loads(CATALOG_PATH.read_text())["allowed_skips"]

    def assert_rejected(
        self, raw, crate="demo", expected=None, allowed=None, required_output=None
    ):
        if expected is None:
            expected = ["demo::test::one"]
        if allowed is None:
            allowed = {}
        with self.assertRaises(ValueError):
            AUDITOR.audit_log(raw, crate, expected, allowed, required_output)

    def test_catalog_allows_exactly_the_three_known_hardware_skips(self):
        self.assertEqual(self.allowed_skips, EXPECTED_KNOWN_SKIPS)

    def test_full_pass_returns_each_named_execution(self):
        names = ["demo::test::one", "demo::test::two"]
        result = AUDITOR.audit_log(make_log("demo", names), "demo", names, {})
        self.assertEqual(
            result,
            [
                {"name": names[0], "status": "executed", "reason": ""},
                {"name": names[1], "status": "executed", "reason": ""},
            ],
        )

    def test_zero_test_crate_is_distinct_from_a_full_pass(self):
        zero_log = f'[ktest runner] skipping crate "empty".\n{COMPLETION}'
        zero_result = AUDITOR.audit_log(zero_log, "empty", [], {})
        pass_result = AUDITOR.audit_log(
            make_log("demo", ["demo::test::one"]),
            "demo",
            ["demo::test::one"],
            {},
        )
        self.assertEqual(zero_result, [])
        self.assertEqual(len(pass_result), 1)
        self.assertEqual(pass_result[0]["status"], "executed")

    def test_zero_test_crate_rejects_test_summary_or_execution(self):
        with self.subTest("summary"):
            raw = f"test result: ok. 0 passed; 0 failed; 0 filtered out.\n{COMPLETION}"
            self.assert_rejected(raw, crate="empty", expected=[])
        with self.subTest("named execution"):
            raw = f"test demo::test::one ... ok\n{COMPLETION}"
            self.assert_rejected(raw, crate="empty", expected=[])

    def test_summary_without_named_test_is_rejected(self):
        raw = (
            'running 1 tests in crate "demo"\n'
            "test result: ok. 1 passed; 0 failed; 0 filtered out.\n"
            f"{COMPLETION}"
        )
        self.assert_rejected(raw)

    def test_missing_named_execution_is_rejected(self):
        raw = (
            'running 1 tests in crate "demo"\n'
            "test result: ok. 1 passed; 0 failed; 0 filtered out.\n"
            f"{COMPLETION}"
        )
        self.assert_rejected(raw)

    def test_duplicate_named_execution_is_rejected(self):
        names = ["demo::test::one", "demo::test::two"]
        raw = make_log("demo", [names[0], names[0]], passed=2)
        self.assert_rejected(raw, expected=names)

    def test_wrong_named_execution_is_rejected(self):
        raw = make_log("demo", ["demo::test::other"])
        self.assert_rejected(raw, expected=["demo::test::wanted"])

    def test_wrong_crate_header_is_rejected(self):
        raw = make_log("other", ["other::test::one"])
        self.assert_rejected(raw, expected=["demo::test::one"])

    def test_execution_after_summary_is_rejected(self):
        raw = (
            'running 1 tests in crate "demo"\n'
            "test result: ok. 1 passed; 0 failed; 0 filtered out.\n"
            "test demo::test::one ... ok\n"
            f"{COMPLETION}"
        )
        self.assert_rejected(raw)

    def test_failed_and_filtered_summaries_are_rejected(self):
        failed = (
            'running 1 tests in crate "demo"\n'
            "test demo::test::one ... FAILED\n"
            "test result: FAILED. 0 passed; 1 failed; 0 filtered out.\n"
            f"{COMPLETION}"
        )
        filtered = (
            'running 1 tests in crate "demo"\n'
            "test demo::test::one ... ok\n"
            "test result: ok. 1 passed; 0 failed; 1 filtered out.\n"
            f"{COMPLETION}"
        )
        with self.subTest("failed"):
            self.assert_rejected(failed)
        with self.subTest("filtered"):
            self.assert_rejected(filtered)

    def test_truncated_test_without_terminal_ok_is_rejected(self):
        raw = (
            'running 1 tests in crate "demo"\n'
            "test demo::test::one ...\n"
            "test result: ok. 1 passed; 0 failed; 0 filtered out.\n"
            f"{COMPLETION}"
        )
        self.assert_rejected(raw)

    def test_missing_or_duplicate_completion_marker_is_rejected(self):
        raw = make_log("demo", ["demo::test::one"]).replace(
            COMPLETION, "[ktest runner] All crates tested.", 1
        )
        self.assert_rejected(raw.replace("[ktest runner] All crates tested.", ""), expected=["demo::test::one"])
        self.assert_rejected(raw + "\n" + COMPLETION, expected=["demo::test::one"])

    def test_unclassified_skip_message_is_rejected(self):
        raw = make_log("demo", ["demo::test::one"], statuses=["skipped because VMX is unavailable ok"])
        self.assert_rejected(raw)

    def test_each_catalogued_hardware_skip_is_reported_as_skipped(self):
        for name, reason in self.allowed_skips.items():
            with self.subTest(name=name):
                raw = make_log("ostd", [name], statuses=[f"[skipped: {reason}] ok"])
                result = AUDITOR.audit_log(raw, "ostd", [name], self.allowed_skips)
                self.assertEqual(
                    result,
                    [{"name": name, "status": "skipped", "reason": reason}],
                )

    def test_unknown_skip_test_or_reason_is_rejected(self):
        known_name, known_reason = next(iter(self.allowed_skips.items()))
        unknown_name = "ostd::test::unknown"
        with self.subTest("unknown test"):
            raw = make_log("ostd", [unknown_name],
                           statuses=[f"[skipped: {known_reason}] ok"])
            self.assert_rejected(
                raw, crate="ostd", expected=[unknown_name], allowed=self.allowed_skips
            )
        with self.subTest("wrong reason"):
            raw = make_log("ostd", [known_name],
                           statuses=[f"[skipped: {known_reason} because host lacks support] ok"])
            self.assert_rejected(
                raw, crate="ostd", expected=[known_name], allowed=self.allowed_skips
            )

    def test_duplicate_inventory_and_duplicate_summaries_are_rejected(self):
        raw = make_log("demo", ["demo::test::one"])
        with self.subTest("inventory"):
            self.assert_rejected(raw, expected=["demo::test::one", "demo::test::one"])
        with self.subTest("summary"):
            duplicated = raw.replace(COMPLETION, raw.splitlines()[-2] + "\n" + COMPLETION)
            self.assert_rejected(duplicated)


    def test_required_output_marker_missing_is_rejected(self):
        name = "ostd::smp::test::pending_ipis_waits_for_remote_cpu"
        marker = "Performing inter-processor call"
        raw = make_log("ostd", [name])
        required_output = {name: {marker: 1}}
        self.assert_rejected(
            raw, crate="ostd", expected=[name], required_output=required_output
        )

    def test_required_output_marker_count_is_enforced(self):
        name = "ostd::smp::test::pending_ipis_can_be_extended"
        marker = "Performing inter-processor call"
        required_output = {name: {marker: 2}}
        one_marker = make_log("ostd", [name]).replace(
            f"test {name} ... ok",
            f"test {name} ...\nDEBUG: {marker}\nok",
        )
        two_markers = make_log("ostd", [name]).replace(
            f"test {name} ... ok",
            f"test {name} ...\nDEBUG: {marker}\nDEBUG: {marker}\nok",
        )
        with self.subTest("one marker is insufficient"):
            self.assert_rejected(
                one_marker, crate="ostd", expected=[name],
                required_output=required_output,
            )
        with self.subTest("two markers pass"):
            result = AUDITOR.audit_log(
                two_markers, "ostd", [name], {}, required_output
            )
            self.assertEqual(
                result, [{"name": name, "status": "executed", "reason": ""}]
            )

    def test_completion_marker_must_follow_summary(self):
        raw = make_log("demo", ["demo::test::one"])
        lines = raw.splitlines()
        lines.remove(COMPLETION)
        summary_index = next(
            index for index, line in enumerate(lines)
            if line.startswith("test result:")
        )
        lines.insert(summary_index, COMPLETION)
        self.assert_rejected("\n".join(lines))

    @staticmethod
    def make_bundle(root, qemu_exit="33", image_hash=None, include_hash=True):
        directory = root / "results"
        crate_dir = directory / "demo"
        efi_dir = crate_dir / "efi"
        efi_dir.mkdir(parents=True)
        image = b"synthetic kernel image"
        (efi_dir / "bzImage").write_bytes(image)
        digest = image_hash or hashlib.sha256(image).hexdigest()
        if include_hash:
            (crate_dir / "image.sha256").write_text(f"{digest}  bzImage\n")
        (crate_dir / "qemu-exit.txt").write_text(f"{qemu_exit}\n")
        (crate_dir / "serial.log").write_text(
            make_log("demo", ["demo::test::one"]) + "\n"
        )
        return directory

    def test_audit_bundle_accepts_valid_image_hash_and_qemu_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.make_bundle(Path(temporary))
            rows, cases = AUDITOR.audit_bundle(
                directory, {"demo": ["demo::test::one"]}, {}, False, {}
            )
        self.assertEqual(rows[0]["executed"], 1)
        self.assertEqual(cases[0]["status"], "executed")

    def test_audit_bundle_rejects_invalid_qemu_exit_and_image_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = self.make_bundle(root, qemu_exit="0")
            with self.subTest("QEMU exit status"):
                with self.assertRaises(ValueError):
                    AUDITOR.audit_bundle(
                        directory, {"demo": ["demo::test::one"]}, {}, False, {}
                    )
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.make_bundle(
                Path(temporary), image_hash="0" * 64
            )
            with self.subTest("image hash mismatch"):
                with self.assertRaises(ValueError):
                    AUDITOR.audit_bundle(
                        directory, {"demo": ["demo::test::one"]}, {}, False, {}
                    )

    def test_audit_bundle_rejects_missing_image_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = self.make_bundle(Path(temporary), include_hash=False)
            with self.assertRaises(FileNotFoundError):
                AUDITOR.audit_bundle(
                    directory, {"demo": ["demo::test::one"]}, {}, False, {}
                )


if __name__ == "__main__":
    unittest.main()
