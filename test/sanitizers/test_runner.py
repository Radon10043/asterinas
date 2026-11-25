#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Synthetic regression tests for test/sanitizers/run.sh; no guest is booted."""
from __future__ import annotations
import csv
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE_RUNNER = Path(__file__).with_name("run.sh").read_text()


class RunnerHarness:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sanitizer-runner-test-")
        self.base = Path(self.temp.name)
        self.root = self.base / "mini"
        self.runner = self.root / "test" / "sanitizers" / "run.sh"
        self.runner.parent.mkdir(parents=True)
        self.runner.write_text(SOURCE_RUNNER)
        self.runner.chmod(0o755)
        for mode in ("off", "kcov", "kasan", "both"):
            image = self.root / "target" / "sanitizers" / mode / "osdk" / "asterinas" / "asterinas-osdk-bin"
            image.parent.mkdir(parents=True, exist_ok=True)
            image.write_bytes(b"synthetic image")
        self.initrd = self.base / "fake-initrd.cpio.gz"
        self.initrd.write_bytes(b"synthetic initrd")
        self.firmware = self.base / "firmware"
        self.firmware.mkdir()
        (self.firmware / "OVMF_CODE_4M.fd").write_bytes(b"code")
        (self.firmware / "OVMF_VARS_4M.fd").write_bytes(b"vars")
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.calls = self.base / "qemu-calls.txt"
        self.fake_grub = self.bin / "grub-mkstandalone"
        self.fake_grub.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "args=sys.argv[1:]\n"
            "out=pathlib.Path(args[args.index('-o')+1])\n"
            "out.parent.mkdir(parents=True, exist_ok=True)\n"
            "out.write_bytes(b'fake EFI')\n"
            "sys.exit(int(os.environ.get('FAKE_GRUB_STATUS','0')))\n"
        )
        self.fake_grub.chmod(0o755)
        self.fake_qemu = self.bin / "qemu"
        self.fake_qemu.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "fat=next(a for a in sys.argv if a.startswith('file=fat:rw:'))\n"
            "efi=pathlib.Path(fat[len('file=fat:rw:'):].split(',',1)[0])\n"
            "case_run=efi.parent.name\n"
            "case, cpu, run=case_run.rsplit('-',2)\n"
            "with open(os.environ['FAKE_QEMU_CALLS'],'a') as f: f.write(case_run+'\\n')\n"
            "mode=os.environ['FAKE_MODE']\n"
            "mutation=os.environ.get('FAKE_MUTATION','')\n"
            "mutate_case=os.environ.get('FAKE_MUTATE_CASE','')\n"
            "kas=(mode in ('kasan','both'))\n"
            "kc=(mode in ('kcov','both'))\n"
            "lines=[]\n"
            "if kas: lines.append('[kasan] KernelAddressSanitizer enabled')\n"
            "if case in ('normal','shadow'):\n"
            "  if case=='shadow':\n"
            "    n='347405' if mutation!='low-shadow' or case!=mutate_case else os.environ.get('FAKE_SHADOW_COUNT','10000')\n"
            "    lines.append('[kasan-selftest] shadow passed checks='+n)\n"
            "  if kc: lines.extend(['PASS: real KCOV PCs, count=10','PASS: real KCOV CMP, count=10','PASS: real KCOV parallel'])\n"
            "  else: lines.append('KCOV_OFF_PASS')\n"
            "  if mutation=='missing-kcov' and case==mutate_case: lines=[x for x in lines if not x.startswith('PASS: real KCOV PCs,')]\n"
            "  if mutation!='missing-workload' or case!=mutate_case: lines.append('SANITIZER_WORKLOAD_PASS workers=8 rounds=256')\n"
            "  if mutation!='missing-exit' or case!=mutate_case: lines.append('KCOV_GUEST_EXIT=0')\n"
            "  if mutation=='unexpected-panic' and case==mutate_case: lines.append('panicked at synthetic')\n"
            "  status=33\n"
            "else:\n"
            "  lines.append('[kasan-selftest] running '+case)\n"
            "  bug={'oob':'slab-out-of-bounds','partial':'slab-out-of-bounds','uaf':'use-after-free','df':'double-free'}[case]\n"
            "  if mutation=='wrong-diagnostic' and case==mutate_case: bug='use-after-free'\n"
            "  lines.append('BUG: KASAN: '+bug+' in 0xffffffff81234567')\n"
            "  access={'oob':'Read of size 1 at addr 0xffff','partial':'Write of size 1 at addr 0xffff','uaf':'Read of size 8 at addr 0xffff','df':'Free at addr 0xffff'}[case]\n"
            "  lines.append(access)\n"
            "  if mutation!='missing-stack' or case!=mutate_case: lines.append('Printing stack trace:')\n"
            "  status=65\n"
            "if mutation=='wrong-status' and case==mutate_case: status=64\n"
            "print('\\n'.join(lines), flush=True)\n"
            "sys.exit(status)\n"
        )
        self.fake_qemu.chmod(0o755)

    def close(self):
        self.temp.cleanup()

    def run(self, mode="kcov", *, cpus="1", repeat="1", mutation="", mutate_case="",
            shadow_count="10000", grub_status="0", memory="512"):
        out = self.base / ("out-" + str(len(list(self.base.glob("out-*")))))
        env = os.environ.copy()
        env.update({
            "QEMU": str(self.fake_qemu),
            "GRUB_MKSTANDALONE": str(self.fake_grub),
            "GRUB_MODULES": str(self.base),
            "OVMF_DIR": str(self.firmware),
            "QEMU_DATA_DIR": "",
            "CPUS": cpus,
            "REPEAT": repeat,
            "MEMORY_MIB": memory,
            "FAKE_MODE": mode,
            "FAKE_MUTATION": mutation,
            "FAKE_MUTATE_CASE": mutate_case,
            "FAKE_SHADOW_COUNT": shadow_count,
            "FAKE_GRUB_STATUS": grub_status,
            "FAKE_QEMU_CALLS": str(self.calls),
        })
        result = subprocess.run(
            ["bash", str(self.runner), mode, str(self.initrd), str(out)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=30,
        )
        rows = []
        table = out / "results.tsv"
        if table.exists():
            with table.open(newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter="\t"))
        return result, out, rows

    def call_count(self):
        return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.h = RunnerHarness()

    def tearDown(self):
        self.h.close()

    def test_all_four_modes_complete_expected_rows(self):
        total = 0
        for mode in ("off", "kcov", "kasan", "both"):
            result, _, rows = self.h.run(mode, cpus="1 4", repeat="2")
            self.assertEqual(result.returncode, 0, result.stdout)
            expected = (1 if mode in ("off", "kcov") else 6) * 2 * 2
            self.assertEqual(len(rows), expected)
            self.assertTrue(all(row["result"] == "PASS" for row in rows), result.stdout)
            total += expected
        self.assertEqual(total, 56)
        self.assertEqual(self.h.call_count(), 56)

    def test_invalid_cpu_and_repeat_inputs_do_not_start_qemu(self):
        for cpus, repeat in (("   ", "1"), ("1 1", "1"), ("1\n4", "1"),
                             ("1\r4", "1"), ("1", "1000000000")):
            with self.subTest(cpus=repr(cpus), repeat=repeat):
                result, _, _ = self.h.run(cpus=cpus, repeat=repeat)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.h.call_count(), 0)

    def test_shadow_requires_exact_check_count(self):
        for count in ("10000", "347341"):
            with self.subTest(count=count):
                result, _, rows = self.h.run("kasan", cpus="1", mutation="low-shadow",
                                               mutate_case="shadow", shadow_count=count)
                self.assertNotEqual(result.returncode, 0)
                shadow = [row for row in rows if row["case"] == "shadow"]
                self.assertEqual(len(shadow), 1)
                self.assertEqual(shadow[0]["result"], "FAIL")

    def test_missing_required_success_markers_fail(self):
        for mutation, mode, case in (
            ("missing-workload", "kcov", "normal"),
            ("missing-kcov", "kcov", "normal"),
            ("missing-exit", "kcov", "normal"),
            ("missing-stack", "kasan", "uaf"),
        ):
            with self.subTest(mutation=mutation):
                result, _, rows = self.h.run(mode, mutation=mutation, mutate_case=case)
                self.assertNotEqual(result.returncode, 0)
                selected = [row for row in rows if row["case"] == case]
                self.assertEqual(len(selected), 1)
                self.assertEqual(selected[0]["result"], "FAIL")

    def test_wrong_status_diagnostic_and_panic_fail(self):
        for mutation, mode, case in (
            ("wrong-status", "kasan", "uaf"),
            ("wrong-diagnostic", "kasan", "oob"),
            ("unexpected-panic", "both", "normal"),
        ):
            with self.subTest(mutation=mutation):
                result, _, rows = self.h.run(mode, mutation=mutation, mutate_case=case)
                self.assertNotEqual(result.returncode, 0)
                selected = [row for row in rows if row["case"] == case]
                self.assertEqual(len(selected), 1)
                self.assertEqual(selected[0]["result"], "FAIL")

    def test_grub_failure_stops_before_qemu(self):
        result, _, _ = self.h.run(grub_status="7")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.h.call_count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
