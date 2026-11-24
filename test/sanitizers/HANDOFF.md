# Maintainer handoff

The delivery branch targets `Radon10043/asterinas:main` at
`879e2c51cc3e8776b9b385645c6b0bbe45b7dbd5`.
Development and validation run on the SSH host `idcai-60525`.
The working checkout is `/root/asterinas` on
`codex/asterinas-kcov-kasan`.

## Implementation

- `ostd/src/kcov.rs` owns per-task tracing, PC/CMP records and lifecycle.
  `kernel/core/src/device/misc/kcov.rs` implements the root-only device.
- `tools/kcov-rustc.sh` selects coverage and address instrumentation
  independently. Coverage is limited to `aster_core`; OSTD has no coverage
  callbacks. Address instrumentation includes OSTD and configured kernel crates.
- `ostd/src/mm/kasan.rs` manages shadow mappings, heap poisoning,
  quarantine, compiler callbacks and report serialization.
- `ostd/src/mm/kasan/selftest.rs` implements boot diagnostics selected with
  `kasan_selftest=shadow|oob|partial|uaf|df`.
- `test/sanitizers/` contains the build, image creation, runner, workload,
  symbol check and validation documentation. `tools/kcov-smoke.c` is the
  userspace KCOV regression program.

The KASAN runtime was adapted from Jiaming Zhang's v0.19.0 implementation.
Its shadow mapping offset is `0xdffffc0000000000`, with an eight-byte granule.
The quarantine limits are 4,096 slots and 8 MiB, with a maximum item size of
1 MiB. An insertion evicts enough slots to satisfy both limits.

## Reproduction and retained files

Follow [README.md](README.md) for commands independent of SyzOxide.
The server retains build caches under `/root/asterinas/target/sanitizers/`.
Logs and run summaries are under
`/root/SyzOxide/.workdir/kcov-expanded/verified-{off,kcov,kasan,both}/`.
Task-scoped toolchains, host binaries and offline Cargo dependencies are
under `/root/SyzOxide/.workdir/`. `native-build.sh` and `run-all.sh` in
the retained task directory configure those server-specific paths.

Read [TEST-RESULTS.md](TEST-RESULTS.md) for the tested versions, outcomes
and per-configuration results. Preserve the matching ELF when investigating a report.
The serial output includes fault PCs, access types and stack traces that
can be resolved against that ELF.

## Validated source and checks

Kernel and self-test source commit `f68d03d84e537cc87cabe169a9a185282dbf9bb0`
passed 54 sanitizer regression boots, all 35 default workspace kernel
executables (522 tests), and the instrumented OSTD/aster-core suites
(225 and 148 tests). The complete `make check` and host `make test`
passed. The result tables record hardware-dependent skips separately.

The task directory contains `run-workspace-tests.sh`,
`run-ostd-sanitizer-final.sh`, `run-core-sanitizer-tests.sh` and
`clippy-features-strict.sh` for the native-server environment.
The current per-boot records are `review-results.tsv` and
`kernel-test-results.tsv` in this directory. Keep the matching
images, ELF files and logs listed in `TEST-RESULTS.md`.

## VMX/EPT coverage

The validation host is an AMD EPYC 7H12 with SVM/NPT and AMD nested
virtualization enabled. Its KVM guest exposes no Intel VMX/EPT; QEMU 8.2.2
TCG also rejects required VMX. The three OSTD VMX/EPT subcases remain
skipped. Run the default and instrumented OSTD suites on an Intel VMX/EPT
host with nested virtualization enabled to complete these subcases.
[TEST-RESULTS.md](TEST-RESULTS.md#vmxept-host-capability-check) records the
host capability checks and required follow-up results.

## Follow-up review

Review the sanitizer callback ABI, recursion exclusions, allocator accounting
and task-exit ordering. Evaluate coverage of additional kernel crates
separately from the current per-task ABI. KASAN currently checks the mapped
linear, frame metadata and kernel text ranges. Expanding stack/global
diagnostics requires compiler/runtime support and separate tests.

Use [UPSTREAM.md](UPSTREAM.md) to prepare submissions to Asterinas upstream.
