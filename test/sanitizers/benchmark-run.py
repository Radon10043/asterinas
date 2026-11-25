#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run sanitizer microbenchmarks in independent, CPU-pinned KVM guests."""
import argparse
import csv
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

MODES = ("off", "kcov", "kasan", "both")
WORKLOADS = {"syscalls", "pipe", "file", "mmap"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_log(log, mode, cpus, traces, status):
    if not __debug__:
        raise RuntimeError("Run without Python optimization so validation remains enabled")
    lines = log.replace("\r", "").splitlines()
    assert status == 33, f"QEMU exit {status}"
    assert lines.count("BENCH_GUEST_EXIT=0") == 1, "guest completion missing"
    assert lines.count("BENCH_PROGRAM_PASS") == len(traces), "program completion count"
    assert not re.search(r"BUG: KASAN:|panicked at|FAIL", log), "guest failure"
    assert ("[kasan] KernelAddressSanitizer enabled" in log) == (mode in ("kasan", "both"))
    start = lines.index("BENCH_MEM_BOOT_BEGIN")
    stop = lines.index("BENCH_MEM_BOOT_END", start + 1)
    memory = {}
    for line in lines[start + 1:stop]:
        match = re.fullmatch(r"(MemTotal|MemFree|MemAvailable):\s+(\d+) kB", line)
        if match:
            memory[match[1]] = int(match[2])
    assert set(memory) == {"MemTotal", "MemFree", "MemAvailable"}, "boot memory missing"
    assert 0 < memory["MemFree"] <= memory["MemTotal"]
    rows = [json.loads(line[len("BENCH_RESULT "):]) for line in lines
            if line.startswith("BENCH_RESULT ")]
    expected = {(trace, workload) for trace in traces for workload in WORKLOADS}
    assert len(rows) == len(expected), "measurement count"
    assert {(r["trace"], r["workload"]) for r in rows} == expected
    for row in rows:
        assert row["workers"] == cpus
        base = {"syscalls": 20000, "pipe": 2000, "file": 500, "mmap": 1000}
        assert row["iterations"] == base[row["workload"]] * row["scale"]
        assert row["capacity_unit"] == {"off": "none", "pc": "pc_records", "cmp": "cmp_records"}[row["trace"]]
        for key in ("iterations", "total_ops", "elapsed_ns", "memfree_kib", "scale"):
            assert isinstance(row[key], int) and row[key] > 0, (key, row)
        assert row["total_ops"] == row["iterations"] * cpus
        assert row["warmup_iterations_per_worker"] == row["iterations"]
        assert row["validation"] == "passed" and row["join_included"] is False
        assert row["capacity_words"] == 1048576
        calls = 6 if row["workload"] == "file" else 2
        assert row["syscall_calls"] >= calls * row["total_ops"]
        if row["workload"] == "file":
            assert row["tmpfs_root"] == "/tmp"
        if row["trace"] == "off":
            assert row["records"] == row["max_records"] == row["capacity"] == 0
        else:
            assert row["capacity"] == (1048575 if row["trace"] == "pc" else 262143)
            assert row["records"] >= row["total_ops"]
            assert 0 < row["max_records"] < row["capacity"]
            assert row["records"] <= row["total_ops"] * row["max_records"]
        row.update(boot_memtotal_kib=memory["MemTotal"], boot_memfree_kib=memory["MemFree"],
                   boot_used_kib=memory["MemTotal"] - memory["MemFree"])
    return rows


def make_initrd(directory, busybox, benchmark, mode, cpus, scale, traces):
    root = directory / "root"
    for item in ("bin", "dev", "proc", "tmp"):
        (root / item).mkdir(parents=True)
    shutil.copy2(busybox, root / "bin/busybox")
    for applet in ("sh", "mount", "cat", "poweroff"):
        (root / "bin" / applet).symlink_to("busybox")
    shutil.copy2(benchmark, root / "benchmark")
    check = "test -c /dev/kcov" if mode in ("kcov", "both") else "test ! -e /dev/kcov"
    calls = "\n".join(f"/benchmark {trace} {cpus} {scale} || return 1" for trace in traces)
    script = f"""#!/bin/busybox sh
export PATH=/bin
run_benchmark() {{
    /bin/busybox mount -t devtmpfs devtmpfs /dev || return 1
    /bin/busybox mount -t proc proc /proc || return 1
    /bin/busybox mount -t tmpfs tmpfs /tmp || return 1
    {check} || return 1
    echo BENCH_MEM_BOOT_BEGIN
    /bin/busybox cat /proc/meminfo || return 1
    echo BENCH_MEM_BOOT_END
    {calls}
}}
status=0
run_benchmark || status=1
echo BENCH_GUEST_EXIT=$status
/bin/busybox poweroff -f
"""
    (root / "init").write_text(script)
    (root / "init").chmod(0o755)
    names = ["."] + ["./" + str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
    archive = subprocess.check_output(["cpio", "--null", "-o", "--format=newc", "--owner=0:0"],
        input=("\0".join(names) + "\0").encode(), cwd=root, stderr=subprocess.DEVNULL)
    target = directory / "initrd.cpio.gz"
    target.write_bytes(gzip.compress(archive, mtime=0))
    shutil.rmtree(root)
    return target


def main():
    if not __debug__:
        raise RuntimeError("Run without Python optimization so validation remains enabled")
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, default=root / "target/sanitizer-bench")
    parser.add_argument("--busybox", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-cpus", default="8,9,10,11")
    parser.add_argument("--guest-cpus", default="1,4")
    parser.add_argument("--modes", default="off,kcov,kasan,both")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--scale", type=int, default=1)
    parser.add_argument("--memory-mib", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    cpus = [int(v) for v in args.guest_cpus.split(",")]
    host_cpus = [int(v) for v in args.host_cpus.split(",")]
    modes = args.modes.split(",")
    assert len(set(cpus)) == len(cpus) and all(n in (1, 4) and n <= len(host_cpus) for n in cpus)
    assert len(set(host_cpus)) == len(host_cpus) and set(host_cpus) <= os.sched_getaffinity(0)
    assert len(set(modes)) == len(modes) and set(modes) <= set(MODES)
    assert args.repetitions > 0 and args.scale > 0 and args.memory_mib > 0
    args.output = args.output.resolve()
    args.images = args.images.resolve()
    args.busybox = args.busybox.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    qemu = os.environ.get("QEMU", "qemu-system-x86_64")
    grub = os.environ.get("GRUB_MKSTANDALONE", "grub-mkstandalone")
    modules = os.environ.get("GRUB_MODULES", "/usr/lib/grub/x86_64-efi")
    firmware = Path(os.environ.get("OVMF_DIR", "/usr/share/OVMF"))
    source = root / "test/sanitizers/benchmark.c"
    benchmark = args.output / "benchmark"
    compile_command = ["cc", "-std=gnu11", "-O2", "-static", "-pthread",
                       "-Wall", "-Wextra", "-Werror", str(source), "-o", str(benchmark)]
    subprocess.run(compile_command, check=True)
    for binary in (args.busybox, benchmark):
        headers = subprocess.check_output(["readelf", "-l", str(binary)], text=True)
        if "INTERP" in headers:
            raise ValueError(f"initramfs binary must be static: {binary}")
    config = {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}
    config.update(trace_isolation="one_boot_per_trace", source_commit=subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        tracked_diff_sha256=hashlib.sha256(subprocess.check_output(["git", "-C", str(root), "diff", "HEAD"])).hexdigest(),
        benchmark_source_sha256=digest(source), benchmark_sha256=digest(benchmark),
        runner_sha256=digest(Path(__file__)), busybox_sha256=digest(args.busybox),
        compile_command=compile_command,
        host_uname=subprocess.check_output(["uname", "-a"], text=True).strip(),
        host_lscpu=subprocess.check_output(["lscpu"], text=True),
        compiler=subprocess.check_output(["cc", "--version"], text=True),
        qemu_version=subprocess.check_output([qemu, "--version"], text=True))
    images = {mode: args.images / mode / "osdk/asterinas/asterinas-osdk-bin" for mode in modes}
    config["images"] = {mode: {"path": str(p), "bytes": p.stat().st_size, "sha256": digest(p)}
                        for mode, p in images.items()}
    (args.output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    template = args.output / "template"
    (template / "EFI/BOOT").mkdir(parents=True)
    cfg = template / "grub.cfg"
    cfg.write_text("""serial --unit=0 --speed=115200
terminal_output serial
search --file --set=root /bzImage
linux /bzImage console=ttyS0 earlycon loglevel=error rdinit=/init
initrd /initrd
boot
""")
    subprocess.run([grub, "-d", modules, "-O", "x86_64-efi",
        "--modules=part_gpt part_msdos fat normal linux search search_fs_file serial terminal",
        "--locales=", "--fonts=", "-o", str(template / "EFI/BOOT/BOOTX64.EFI"),
        f"boot/grub/grub.cfg={cfg}"], check=True)
    all_rows, boots = [], []
    for rep in range(1, args.repetitions + 1):
        offset = (rep - 1) % len(modes)
        order = modes[offset:] + modes[:offset]
        if rep % 2 == 0:
            order.reverse()
        for cpu in cpus:
            settings = []
            for mode in order:
                trace_order = ["off", "pc", "cmp"] if mode in ("kcov", "both") else ["off"]
                shift = (rep - 1) % len(trace_order)
                settings.extend((mode, trace) for trace in trace_order[shift:] + trace_order[:shift])
            for mode, trace in settings:
                boot_id = f"r{rep}-cpu{cpu}-{mode}-{trace}"
                directory = args.output / boot_id
                directory.mkdir()
                traces = [trace]
                initrd = make_initrd(directory, args.busybox, benchmark, mode, cpu, args.scale, traces)
                efi = directory / "efi"
                shutil.copytree(template / "EFI", efi / "EFI")
                shutil.copy2(images[mode], efi / "bzImage")
                shutil.copy2(initrd, efi / "initrd")
                shutil.copy2(firmware / "OVMF_VARS_4M.fd", directory / "vars.fd")
                command = ["taskset", "-c", ",".join(map(str, host_cpus[:cpu])), qemu]
                if os.environ.get("QEMU_DATA_DIR"):
                    command += ["-L", os.environ["QEMU_DATA_DIR"]]
                command += ["-accel", "kvm", "-machine", "q35,kernel-irqchip=split",
                    "-cpu", "host", "-smp", str(cpu), "-m", str(args.memory_mib),
                    "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
                    "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,unit=1,file={directory}/vars.fd",
                    "-drive", f"file=fat:rw:{efi},format=raw,if=ide",
                    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
                meta = dict(boot_id=boot_id, rep=rep, mode=mode, guest_cpus=cpu, traces=traces,
                    command=command, initrd_sha256=digest(initrd),
                    image_sha256=config["images"][mode]["sha256"],
                    host_load_before=Path("/proc/loadavg").read_text().strip(),
                    host_stat_before=Path("/proc/stat").read_text(),
                    started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                print(f"START {boot_id} traces={','.join(traces)}", flush=True)
                started = time.monotonic()
                with (directory / "serial.log").open("wb") as output:
                    try:
                        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                                stderr=subprocess.STDOUT, timeout=args.timeout)
                        status = result.returncode
                    except subprocess.TimeoutExpired:
                        status = 124
                meta.update(qemu_exit=status, duration_seconds=time.monotonic() - started,
                    host_load_after=Path("/proc/loadavg").read_text().strip(),
                    host_stat_after=Path("/proc/stat").read_text())
                log = (directory / "serial.log").read_text(errors="replace")
                (directory / "serial.txt").write_text(log.replace("\r", ""))
                try:
                    rows = parse_log(log, mode, cpu, traces, status)
                    for row in rows:
                        base = {"syscalls": 20000, "pipe": 2000, "file": 500, "mmap": 1000}
                        assert row["scale"] == args.scale
                        assert row["iterations"] == base[row["workload"]] * args.scale
                        row.update(boot_id=boot_id, rep=rep, mode=mode, guest_cpus=cpu)
                        row["ns_per_op"] = row["elapsed_ns"] / row["total_ops"]
                        row["ops_per_second"] = row["total_ops"] * 1e9 / row["elapsed_ns"]
                    all_rows.extend(rows)
                    meta["result"] = "PASS"
                except (AssertionError, ValueError, KeyError) as error:
                    meta.update(result="FAIL", error=str(error))
                    (directory / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
                    raise RuntimeError(f"{boot_id}: {error}; see {directory}/serial.txt") from error
                (directory / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
                boots.append(meta)
                (args.output / "boots.json").write_text(json.dumps(boots, indent=2) + "\n")
                (args.output / "measurements.json").write_text(json.dumps(all_rows, indent=2) + "\n")
                with (args.output / "measurements.tsv").open("w", newline="") as output:
                    writer = csv.DictWriter(output, fieldnames=list(all_rows[0]), delimiter="\t")
                    writer.writeheader()
                    writer.writerows(all_rows)
                print(f"PASS {boot_id} rows={len(rows)}", flush=True)
    assert len(boots) == args.repetitions * len(cpus) * sum(3 if m in ("kcov", "both") else 1 for m in modes)
    print(f"BENCH_SUITE_PASS boots={len(boots)} rows={len(all_rows)}", flush=True)


if __name__ == "__main__":
    main()
