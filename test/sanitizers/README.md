# KCOV and KASAN regression tests

These tests exercise x86_64 per-task coverage and heap address diagnostics.
The implementation targets Asterinas commit
`879e2c51cc3e8776b9b385645c6b0bbe45b7dbd5`.

KCOV records PCs and comparison operands from `aster_core` during the
attached task's synchronous syscall execution. The root-only `/dev/kcov`
interface uses a complete shared mapping. KASAN instruments the configured
kernel crates and OSTD with kernel-address callbacks and 1:8 shadow memory.
Heap allocations have left and right redzones. Freed slots enter a bounded
quarantine. Stack and global redzone instrumentation are disabled.

## Build

Use the repository's development environment, pinned Rust toolchain,
installed `cargo-osdk`, and `VDSO_LIBRARY_DIR`. The test build uses separate
Cargo target directories for each instrumentation combination.

```bash
for mode in off kcov kasan both; do
    test/sanitizers/build-kernel.sh "$mode"
done
test/sanitizers/check-symbols.sh
test/sanitizers/check-wrapper.sh
```

The build script sets dev optimization to 2, `aster-core` optimization to 0,
64 kernel stack pages and LTO off. Each mode produces
`target/sanitizers/MODE/osdk/asterinas/asterinas-osdk-bin` and the matching
unstripped ELF under `target/sanitizers/MODE/x86_64-unknown-none/debug/`.

## Run

Install QEMU with KVM access, OVMF, GRUB's x86_64 EFI modules, a static BusyBox,
a static C toolchain, binutils, cpio and gzip. Run from the repository root.

```bash
mkdir -p .workdir/sanitizers
test/sanitizers/make-initramfs.sh /path/to/static/busybox \
    .workdir/sanitizers/tests.cpio.gz
for mode in off kcov kasan both; do
    test/sanitizers/run.sh "$mode" .workdir/sanitizers/tests.cpio.gz \
        ".workdir/sanitizers/$mode"
done
```

Each output directory must be new. Defaults are five repetitions on each of
1, 2 and 4 vCPUs with 2 GiB RAM and a 120-second timeout per boot.
Set `REPEAT` and space-separated `CPUS` to change the run count.
CPU counts must be distinct positive integers on one line.
`REPEAT` accepts a positive decimal integer of at most nine digits.
The runner requires every planned boot to finish and checks the current
shadow test's exact assertion count.
Set `MEMORY_MIB` to change guest memory (default 2048).
Set `QEMU`, `QEMU_DATA_DIR`, `GRUB_MKSTANDALONE`, `GRUB_MODULES` and
`OVMF_DIR` for nonstandard installations. Shared library paths may also be
needed when running an extracted distribution package.

Every boot has its own FAT tree and OVMF variable file. The runner saves
`results.tsv`, image/initramfs hashes and individual serial logs. It checks
the QEMU exit status, expected reports and guest success markers. Any failed
case makes the runner exit unsuccessfully. Normal shutdown returns 33 through
the QEMU debug exit device. A deliberate KASAN diagnostic returns 65.

## Cases

| Case | Verification |
| --- | --- |
| normal | KCOV guest regression or disabled-interface checks, followed by the workload |
| shadow | 347,405 shadow assertions, followed by the normal guest checks |
| oob | Compiler-instrumented read of a byte marked as a heap redzone |
| partial | Compiler-instrumented write to an inaccessible partial-granule byte |
| uaf | Read callback checking the shadow of an actually freed, quarantined allocation |
| df | Allocator validation detecting the freed tag of a quarantined allocation |

The access diagnostics use live backing storage with deliberately changed
shadow metadata. The free diagnostics inspect allocator metadata after one
real free. Each case requires the matching bug category, access description,
stack trace and failure exit status. The positive shadow test checks actual
heap allocations, every partial tail tag, aligned and unaligned access,
granule/64-byte/page crossings, zero lengths and freed tags. It also
checks 70 allocation size/alignment combinations, zeroing, data preservation
through growth and shrinkage, and quarantine limits after 5,000 small allocations followed by sixteen
512 KiB allocations.

The KCOV guest program checks real kernel PCs, comparison types and operand
widths, exact small-buffer capacity, a comparison record crossing a page,
untouched padding, saturation, reset, access permissions and ioctl errors.
It also covers independent opens, descriptor duplication, mapping lifetime,
owner exit, fork handoff and concurrently active PC/CMP sessions. Atomic
handshakes isolate each thread's writes.

The workload runs eight threads for 256 rounds each. Every round checks
mapped page boundaries, exchanges a fixed pipe message, and writes and reads
a thread-specific temporary file. Read/write helpers handle interruptions
and partial transfers. Files, descriptors and mappings are cleaned up.

The four configurations produce 210 boots with the default settings.
There are 90 successful workload boots, totaling 184,320 thread-rounds, and
120 boots that must terminate with their selected KASAN diagnostic.

## Repository checks

Run the host suite, repository checks and workspace kernel tests in the
repository development environment:

```bash
make test
make check
make ktest
```

The workspace kernel tests use the test disk images, including an NVMe
device. Run OSTD on two vCPUs so its remote-CPU interrupt tests execute;
the other workspace crates use the default single-vCPU configuration.
The sanitizer boot tests above separately exercise 1, 2 and 4 vCPUs.

The validation server also runs OSTD and `aster-core` kernel tests with
both `kcov,kasan` features, address/coverage instrumentation and two vCPUs.
[TEST-RESULTS.md](TEST-RESULTS.md) records the exact native-host commands,
tool versions, test counts and retained launchers.

## Auditing actual execution

`make test` also runs the self-contained Python tests for the guest runner
and named kernel-log auditor. These use synthetic logs and command substitutes;
their counts are separate from real guest boots.

`audit-kernel-tests.py` checks each expected test name, its terminal result,
the selected crate and count, completion markers, QEMU status and retained
image digest. It requires activity output from the two remote-CPU interrupt
tests. The reviewed `expected-kernel-tests.json` lists all registrations
for the tested x86_64 configuration and the three permitted VMX/EPT skips.
Update this inventory when the registered test set changes.

```bash
python3 test/sanitizers/audit-kernel-tests.py \
    --workspace /path/to/default-crate-results \
    --instrumented /path/to/instrumented-ostd-and-core-results \
    --output /path/to/new-audit-directory
```

Each input crate directory contains `serial.log`, `qemu-exit.txt`,
`image.sha256` and `efi/bzImage`, as produced by the retained QEMU
launchers. The output directory must be new. Its `summary.tsv` separates
reported success, completed tests, permitted skips and crates with no tests;
`tests.tsv` lists every named outcome.

The wrapper check uses compiler argument capture for all workspace default
members plus an unknown dependency, four target types, four feature
combinations and two argument forms. Real instrumentation is verified
separately with compiled ELF files and guest tests.

See [EXECUTION-AUDIT.md](EXECUTION-AUDIT.md) for named execution counts,
standalone OSDK outcomes and checks against incomplete test runs.

[LLVM-COVERAGE.md](LLVM-COVERAGE.md) describes OSDK profile export, real
profile validation and the current sanitizer regression. Use matching OSDK
and OSTD revisions when collecting LLVM profiles.

## Performance measurements

[PERFORMANCE.md](PERFORMANCE.md) describes the optimized kernel profile,
independent-guest measurements, PC/CMP recording conditions, memory accounting
and reproduction commands.
Use `build-benchmark.sh` for these images and `benchmark-run.py` for the timed
workloads; `benchmark-summary.py` computes paired overhead statistics.
