# KCOV tests

`kcov-smoke.c` exercises the root-only `/dev/kcov` interface in Asterinas.
It checks real kernel PCs and comparisons, ioctl errors, permissions,
buffer capacity, page crossings, padding, saturation and reset.
It also covers ownership, parallel PC/CMP sessions, fork, descriptor duplication,
mapping lifetime and task-exit cleanup.

## Build and run

Use the repository development environment and the VM dependencies listed in
[the sanitizer test guide](../sanitizers/README.md).

```bash
test/sanitizers/build-kernel.sh off
test/sanitizers/build-kernel.sh kcov
test/kcov/run.sh /path/to/static/busybox test/kcov/output
```

The output directory must be new.
`run.sh` creates the initramfs and runs the uninstrumented and KCOV configurations.
It uses the shared VM helpers in `test/sanitizers` and includes the common
mapping, pipe and file workload.
Set `REPEAT`, `CPUS` and `MEMORY_MIB` to select repetitions, vCPU counts and RAM.
For example:

```bash
REPEAT=1 CPUS="1 4" test/kcov/run.sh /path/to/static/busybox test/kcov/output
```

Coverage records must be actual kernel addresses or valid comparison records.
The VM runner requires the success markers, completed workload and QEMU status 33.
It saves logs, hashes and results in the selected output directory.
Combined KCOV/KASAN execution and performance measurements are described in
[the sanitizer test guide](../sanitizers/README.md).

## Standalone program

Build a static executable and place it in an Asterinas guest with KCOV enabled:

```bash
mkdir -p test/kcov/output
cc -std=gnu11 -O2 -static -pthread -Wall -Wextra -Werror \
    test/kcov/kcov-smoke.c -o test/kcov/output/kcov-smoke
```

Run the program as root inside the guest.
Generated binaries and test results belong in the ignored output directory.
