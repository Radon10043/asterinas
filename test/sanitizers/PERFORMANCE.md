# KCOV and KASAN overhead

These measurements compare eight instrumentation/recording conditions on
Asterinas x86_64.
Each condition runs four checked microbenchmarks on one and four vCPUs,
with three independent guest boots per condition and CPU count.
The measurements describe this implementation, build profile and workload.

## Measured results

All 48 independent boots passed and produced 192 checked measurements,
forming 64 workload/condition/CPU groups with three samples each.
The timed portions completed 56,400,000 workload rounds and 117,600,000
explicit workload syscalls.
Warmup completed another 56,400,000 rounds.
The shortest timed sample was 26.816 ms.

Elapsed-time multipliers below use the same-CPU off configuration as 1.00.
Each cell is the median of the three paired ratios.
The current implementation has substantial runtime overhead,
especially when KASAN and comparison recording are enabled together.
For the one-worker syscall pair, the median time is 0.283 microseconds
without instrumentation and 270.086 microseconds with both/CMP;
the median paired multiplier is 956.66.

### Reference time per round

| vCPUs / workers | Syscall pair | Pipe round | File round | mmap round |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.283 us | 0.672 us | 6.007 us | 2.417 us |
| 4 | 0.298 us | 0.433 us | 2.104 us | 19.595 us |

These are median wall-clock microseconds per completed round across all workers.
The four-worker mmap reference takes 19.595 us per round, compared with
2.417 us for one worker; use these absolute values alongside the ratios.

### 1 vCPU / 1 worker

| Condition | Syscall pair | Pipe | File | mmap |
| --- | ---: | ---: | ---: | ---: |
| KCOV, inactive | 2.55x | 2.55x | 2.88x | 2.13x |
| KCOV, PC | 4.36x | 4.52x | 5.54x | 3.33x |
| KCOV, CMP | 26.88x | 14.60x | 9.93x | 7.47x |
| KASAN | 6.44x | 6.41x | 8.48x | 7.42x |
| Both, KCOV inactive | 8.17x | 7.65x | 11.00x | 7.73x |
| Both, PC | 49.91x | 84.81x | 120.73x | 51.52x |
| Both, CMP | 956.66x | 478.18x | 272.37x | 205.44x |

### 4 vCPUs / 4 workers

| Condition | Syscall pair | Pipe | File | mmap |
| --- | ---: | ---: | ---: | ---: |
| KCOV, inactive | 1.41x | 1.27x | 2.24x | 1.22x |
| KCOV, PC | 1.93x | 1.91x | 4.17x | 1.40x |
| KCOV, CMP | 6.46x | 5.79x | 7.44x | 1.67x |
| KASAN | 2.36x | 2.68x | 6.62x | 2.21x |
| Both, KCOV inactive | 3.37x | 3.38x | 8.27x | 2.28x |
| Both, PC | 12.31x | 33.45x | 92.26x | 9.17x |
| Both, CMP | 229.73x | 187.40x | 196.65x | 14.89x |

The [per-group summary](performance-summary.tsv) includes the minimum and
maximum paired percentages for every cell, as well as absolute timing and throughput.
The [192 measurements](performance-measurements.tsv) retain each individual result.
All 96 active-recording measurements contain coverage.
The largest PC round used 650,887 of 1,048,575 records (62.07%);
the largest comparison round used 25,699 of 262,143 records (9.80%).
No recording buffer saturated.

### Memory and image size

Startup memory increases below are reductions in median `MemFree`,
using the three inactive-recording boots for each kernel/CPU configuration.
They include reserved image/shadow memory and initial runtime allocations.

| Kernel mode | Extra memory, 1 vCPU | Extra memory, 4 vCPUs | Boot image | Image increase |
| --- | ---: | ---: | ---: | ---: |
| off | 0.00 MiB | 0.00 MiB | 5.215 MiB | 0.00% |
| kcov | 1.25 MiB | 1.25 MiB | 6.469 MiB | 24.04% |
| kasan | 263.64 MiB | 263.55 MiB | 6.496 MiB | 24.57% |
| both | 265.07 MiB | 264.96 MiB | 7.766 MiB | 48.91% |

Active KCOV additionally reserves an 8 MiB buffer per worker in this experiment.
The [build table](performance-builds.tsv) records exact image/ELF sizes,
section sizes and SHA-256 values.
The [48 boot records](performance-boots.tsv) retain startup memory and
image/initramfs/serial hashes.
[performance-config.json](performance-config.json) records tool versions,
CPU settings, benchmark hashes and run parameters.

## Build and machine

Kernel implementation source: `f0f2d37d74c714eef143460bd48bcbc191d4746f`.
Benchmark source: `c697cfb4e16bfc5da1b755a35eec2fbf06102bbf`.

- Host: `idcai-60525`, AMD EPYC 7H12, 64 physical cores and 128 logical CPUs.
- Guest: QEMU 8.2.2 with KVM, q35, host CPU model, GRUB/OVMF,
  2,048 MiB RAM and one or four vCPUs.
- Host affinity: CPU 8 for the one-vCPU guests; CPUs 8–11 for four-vCPU guests.
  These are distinct physical cores in NUMA node 0.
  Their SMT siblings are CPUs 72–75.
  The existing `schedutil` governor and `acpi-cpufreq` driver are retained.
- Toolchain: nightly-2026-11-16, rustc 1.102.0-nightly,
  LLVM 23.1.5-rust.
- Kernel profile: release, optimization level 2 for every crate,
  LTO disabled, debug information enabled,
  debug assertions and overflow checks disabled, 64 task-stack pages.
  Each mode has a separate Cargo target directory.
- Userspace benchmark: static C executable, `-O2 -pthread`,
  identical binary in all guests.
- Guests run sequentially, with no concurrent kernel compilation or other
  test VM during measurement.
  Per-boot host load and CPU counters are retained with the raw logs.

The optimized profile is set explicitly by
[build-benchmark.sh](build-benchmark.sh).
The correctness-test profile described in [README.md](README.md) is separate.

ELF inspection verifies ten coverage callback kinds in `aster_core`
for KCOV-enabled builds.
The KASAN-enabled builds contain eleven load/store callback kinds in
`aster_core` and twelve in OSTD.
Disabled builds have no corresponding callback references.

## Conditions

| Kernel mode | Recording | Meaning |
| --- | --- | --- |
| off | off | Neither KCOV nor KASAN compiled in |
| kcov | off | KCOV compiled in, no recording session |
| kcov | pc | KCOV records program counters |
| kcov | cmp | KCOV records comparisons |
| kasan | off | KASAN active |
| both | off | KASAN active, KCOV compiled in without a session |
| both | pc | KASAN active with KCOV PC recording |
| both | cmp | KASAN active with KCOV comparison recording |

KCOV instruments `aster_core` and records the attached task's synchronous
syscall execution.
KASAN instruments the configured kernel crates and OSTD, with heap redzones,
1:8 shadow memory and bounded quarantine.
Stack/global redzone instrumentation is disabled.

Each recording worker has an independent device descriptor and an 8 MiB
shared buffer: 1,048,576 64-bit words including the counter.
Capacity is 1,048,575 PC records or 262,143 comparison records.
Every workload round clears the counter, performs its work and checks that
the resulting count is nonzero and strictly below capacity.
The recorded maximum is the largest count in one round, before the next reset.
Inactive conditions allocate no KCOV buffer.

## Workloads and timing

The command uses `SCALE=20`.
Each worker completes the following work once for warmup and again for timing.

| Workload | Rounds per worker | Work in one round |
| --- | ---: | --- |
| syscalls | 400,000 | Direct `getpid` and `getuid` syscalls, checking both results |
| pipe | 40,000 | Write and read 4 KiB on a worker-owned pipe, then compare all bytes |
| file | 10,000 | Create a tmpfs file, write 4 KiB, seek, read/compare, close and unlink |
| mmap | 20,000 | Map one anonymous page, write/read at 64-byte intervals and the final byte, then unmap |

The file workload verifies that `/tmp` is tmpfs.
Each worker has its own file directory and pipe.
The worker threads share one process address space.
Mappings, file contents, syscall results and cleanup operations are checked.
Interrupted and partial transfers are handled.
The syscall workload uses `syscall()` directly.

Workers finish the equal-length warmup and wait on a condition variable.
The main thread reads `MemFree`, records the start time and releases them.
Each worker records its finish time immediately after its last round.
A completion barrier holds resource cleanup until all finish times are captured.
Elapsed time is the latest worker finish time minus the common start time.

Timing includes worker wakeup, payload checks, and, for active KCOV,
counter resets, count reads and count validation.
It excludes setup, warmup, buffer initialization, teardown and thread joins.
The main thread blocks while workers execute.
No benchmark result is printed in the timed loops.

A round is the complete operation in the table.
Reported nanoseconds per round equal wall-clock elapsed time divided by
the total number of rounds across workers.
For four workers this is an aggregate throughput measure.

Each mode/recording/CPU/repetition combination has its own guest boot.
Mode and recording order rotate across repetitions.
Within each guest the workload order is syscalls, pipe, file, mmap.

## Statistics and memory accounting

Each elapsed-time multiplier is the median of three paired elapsed-time ratios.
The raw summary expresses the same paired comparisons as percentage increases:

```text
100 × (elapsed_condition / elapsed_off − 1)
```

The reference has the same workload, CPU count, repetition and total work.
The raw summary also contains minimum and maximum paired percentages,
median/minimum/maximum nanoseconds per round and median throughput.
The three independent boots are the statistical samples;
individual syscall iterations are not treated as independent samples.

Startup `/proc/meminfo` is captured after mounting the guest filesystems
and before starting the benchmark.
Memory overhead is the reduction in median startup `MemFree`
relative to the off image at the same RAM and CPU configuration.
In this kernel, `MemFree` and `MemAvailable` both report free physical
frame-allocator bytes.
`MemTotal` also varies with reserved kernel memory, so both fields
are retained in the measurement data.

The per-workload `memfree_kib` field is sampled after warmup while workers
are waiting with their resources allocated.
It includes the effects of earlier workloads in that guest, caches and quarantine.
It is not a peak-memory measurement.
KCOV's configured buffer storage is separately known:
8 MiB per active worker, or 32 MiB with four workers.
KASAN's quarantine is bounded by 4,096 entries and 8 MiB.

Boot-image sizes refer to the packaged image built with `--strip-elf`.
The unstripped ELF's debug-file size is not a runtime-memory measurement.

## Execution checks

[benchmark-run.py](benchmark-run.py) requires QEMU status 33,
one guest completion marker, one program completion marker and
exactly four distinct workload results for each boot.
It checks the configured KASAN banner and device availability,
worker and iteration counts, warmup counts, payload-validation results,
KCOV capacities and actual recording counts.
Any failure, panic, missing result or saturated recording rejects the run.
The summary rejects incomplete boot sets, missing measurement groups,
duplicate samples and inconsistent work counts.

The benchmark runner and statistics controls are part of the 47 Python
test-driver tests.
Their synthetic logs and arithmetic checks are counted separately from
the guest measurements.
Final `make test` passed 93 Rust tests/doctests and 47 Python tests;
14 contextual rustdoc examples remain ignored.
`make check`, the benchmark's strict static C build, clang-format,
shell syntax and spelling checks also passed.
Their logs and exit statuses are retained under `performance/final-checks/`.

## Reproduce

Use the project build environment and the dependencies listed in
[README.md](README.md).
The following commands run from the repository root.
Choose host CPU numbers appropriate for the machine.

```bash
for mode in off kcov kasan both; do
    test/sanitizers/build-benchmark.sh "$mode"
done

python3 test/sanitizers/benchmark-run.py \
    --busybox /path/to/static/busybox \
    --output /path/to/new/performance-results \
    --host-cpus 8,9,10,11 --guest-cpus 1,4 \
    --modes off,kcov,kasan,both --repetitions 3 --scale 20 \
    --memory-mib 2048 --timeout 1200

python3 test/sanitizers/benchmark-summary.py /path/to/new/performance-results
python3 -m unittest discover -s test/sanitizers -p 'test_*.py'
```

Set `QEMU`, `QEMU_DATA_DIR`, `GRUB_MKSTANDALONE`, `GRUB_MODULES`
and `OVMF_DIR` for nonstandard installations.
The output directory must not exist.
Run Python without `-O` so validation remains enabled.

The retained server directory is
`/root/SyzOxide/.workdir/kcov-expanded/performance/`.
It contains the four build logs, explicit build environments, tool versions,
ELF checks, CPU settings, per-boot commands, serial logs, hashes,
`formal/config.json`, `formal/boots.json`,
`formal/measurements.json` and the generated TSV files.
