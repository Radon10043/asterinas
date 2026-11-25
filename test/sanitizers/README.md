# KASAN and sanitizer integration tests

This directory contains KASAN workloads and diagnostic tests,
plus shared build and VM helpers for testing instrumentation combinations.
The KCOV device tests and their entry point are in [../kcov](../kcov/README.md).

KASAN instruments the configured kernel crates and OSTD with kernel-address
callbacks and 1:8 shadow memory.
Heap allocations have redzones and a bounded freed-object quarantine.
Stack and global redzone instrumentation are disabled.

## Build

Use the repository development environment, pinned Rust toolchain,
installed `cargo-osdk` and `VDSO_LIBRARY_DIR`.

```bash
for mode in off kcov kasan both; do
    test/sanitizers/build-kernel.sh "$mode"
done
test/sanitizers/check-symbols.sh
test/sanitizers/check-wrapper.sh
```

Each mode has a separate target directory under `target/sanitizers/MODE`.
The correctness profile sets dev optimization to 2, `aster-core` optimization
to 0, 64 kernel stack pages and LTO off.
The image is `osdk/asterinas/asterinas-osdk-bin` below that directory;
the matching unstripped ELF is under `x86_64-unknown-none/debug/`.

## Run KASAN tests

Install QEMU with KVM access, OVMF, GRUB's x86_64 EFI modules, a static BusyBox,
a static C toolchain, binutils, cpio and gzip.
Run from the repository root:

```bash
mkdir -p test/sanitizers/output
test/sanitizers/make-initramfs.sh /path/to/static/busybox \
    test/sanitizers/output/tests.cpio.gz
for mode in kasan both; do
    test/sanitizers/run.sh "$mode" test/sanitizers/output/tests.cpio.gz \
        "test/sanitizers/output/$mode"
done
```

The initramfs compiles the KCOV program from `test/kcov/kcov-smoke.c`
and the shared workload from `test/sanitizers/workload.c`.
The combined mode exercises both interfaces in the same guest.

Each run output directory must be new.
Defaults are five repetitions on each of 1, 2 and 4 vCPUs,
2 GiB RAM and a 120-second timeout per boot.
Set `REPEAT`, space-separated `CPUS` and `MEMORY_MIB` to change these values.
CPU selections must be distinct positive integers on one line.
Set `QEMU`, `QEMU_DATA_DIR`, `GRUB_MKSTANDALONE`, `GRUB_MODULES`
and `OVMF_DIR` for nonstandard installations.

| Case | Verification |
| --- | --- |
| normal | Device checks and the shared workload |
| shadow | Shadow checks, then the normal guest checks |
| oob | Compiler-instrumented heap redzone read |
| partial | Compiler-instrumented partial-granule write |
| uaf | Address callback on freed, quarantined storage |
| df | Allocator diagnostic after a real free |

The shadow case checks allocation sizes and alignments, zeroing,
growth/shrinkage preservation, partial tails, boundaries and quarantine limits.
The shared workload uses eight threads to exercise mappings, pipes and files,
checking their contents and cleaning up resources.

Normal and shadow cases require QEMU status 33 and completed workloads.
Diagnostic cases require status 65, the selected bug category,
the expected access description and a stack trace.
The runner checks every planned boot and the exact shadow assertion count.
It writes `results.tsv`, hashes and serial logs to the selected output directory.

## Host checks and kernel-test auditing

```bash
make test
make check
make ktest
```

`make test` includes the Python tests for the VM runner, named-test auditor
and performance statistics.
They use synthetic logs and are reported separately from real guest executions.

`expected-kernel-tests.json` is the declarative input to
`audit-kernel-tests.py`.
It specifies registered test names, permitted hardware skips and required
activity messages for the selected kernel configurations.
Update it when test registrations change.

```bash
python3 test/sanitizers/audit-kernel-tests.py \
    --workspace /path/to/default-crate-results \
    --instrumented /path/to/instrumented-ostd-and-core-results \
    --output test/sanitizers/output/kernel-audit
```

Each input crate directory contains `serial.log`, `qemu-exit.txt`,
`image.sha256` and `efi/bzImage`.
The auditor checks named executions, completion markers, skips and image hashes.
Its output separates executed tests, hardware skips and zero-test crates.
Use two vCPUs for OSTD's remote-interrupt tests and the required virtual disks
for storage tests.

## Performance measurements

Build the optimized profile with `build-benchmark.sh`.
It uses release optimization level 2 for every crate, LTO off,
debug information enabled, debug assertions and overflow checks disabled,
and 64 task-stack pages.

```bash
for mode in off kcov kasan both; do
    test/sanitizers/build-benchmark.sh "$mode"
done
python3 test/sanitizers/benchmark-run.py \
    --busybox /path/to/static/busybox \
    --output test/sanitizers/output/performance \
    --host-cpus 8,9,10,11 --guest-cpus 1,4 \
    --modes off,kcov,kasan,both --repetitions 3 --scale 20 \
    --memory-mib 2048 --timeout 1200
python3 test/sanitizers/benchmark-summary.py test/sanitizers/output/performance
```

Choose host CPU numbers appropriate for the machine.
Each recording condition uses an independent guest.
The program checks syscall results, pipe/file contents and mapped bytes.
It performs equal-length warmup and measured work, with setup and cleanup
outside the timed interval.
Each active recording worker uses an 8 MiB buffer.
Every round resets the counter and checks nonzero, unsaturated coverage.
The summary computes paired overhead against the matching uninstrumented
workload and preserves each repetition's timing.

Keep generated measurements, profiles, images and logs in the ignored
`output/` directories.
Include measured results and build/run parameters in the PR description.
