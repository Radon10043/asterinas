# Test execution audit

This audit ran on 2026-11-25 on SSH host `idcai-60525`.
Kernel and self-test source: `f68d03d84e537cc87cabe169a9a185282dbf9bb0`.
Test drivers: `5f41fda99e5c836544f4f66c2cedfb87e18847b8`.

## Kernel tests

| Configuration | Named successful returns | Completed executions | Hardware skips | Crates with zero tests |
| --- | --- | --- | --- | --- |
| Default workspace | 522 | 519 | 3 | 18 |
| KCOV+KASAN OSTD | 225 | 222 | 3 | 0 |
| KCOV+KASAN aster-core | 148 | 148 | 0 | 0 |

All 37 selected crate boots returned QEMU status 33. The
[per-crate results](kernel-test-results.tsv) include image digests.
The [named results](kernel-test-executions.tsv) contain 895 outcomes across
the configurations: 889 completed executions and six skip occurrences.
These counts include repeated tests across configurations.

The reviewed inventory contains every default workspace test registration
for x86_64, plus three KCOV tests in instrumented OSTD.
`audit-kernel-tests.py` checks the exact crate and test names, individual
terminal results, summary counts, final runner completion, QEMU status,
KASAN mode and the retained image digest. Missing, duplicate, filtered or
unexpected executions fail the audit. Zero-test crates contribute no passed
tests.

The default OSTD suite runs on two vCPUs. The tests
`pending_ipis_waits_for_remote_cpu` and `pending_ipis_can_be_extended`
require at least two CPUs; their serial output records one and two
inter-processor calls respectively. The auditor requires this activity for
each test in both OSTD configurations. Other default crates use one vCPU.
The seven NVMe tests ran with a disposable 128 MiB NVMe disk; their logs
contain device and block-I/O activity.

The three accepted skips are `multiple_vmx_guards_lifecycle`,
`switch_and_reuse_vmcs` and `guest_mapping_lifecycle`. The auditor accepts
only the named tests and their exact unavailable-feature messages.
The host capability check is recorded in
[TEST-RESULTS.md](TEST-RESULTS.md#vmxept-host-capability-check).
Review of direct early returns in the selected test bodies identified no
additional unaccounted skips.

## Sanitizer guest regressions

The current runner requires a nonempty selection of distinct positive CPU
counts, a positive bounded repetition count and exactly the planned number
of completed boots. A shadow run must report exactly 347,405 assertions.
Successful normal/shadow runs also require the KCOV mode marker, completed
eight-thread workload, guest exit marker and QEMU status 33. Each deliberate
KASAN diagnostic requires its specific access description, exactly one
matching report, a stack trace and status 65.

The current driver completed 132 additional real guest boots, all passed:
78 covering all memory configurations on 1/2/4 vCPUs and 54 repeating the
1/4-vCPU memory configurations. Each batch also includes off/KCOV runs on
1/2/4 vCPUs at 2 GiB. These boots performed 6,948,100 shadow assertions and
106,496 workload thread-rounds.
[audit-guest-results.tsv](audit-guest-results.tsv) lists every boot.

The earlier 360 boots were also audited against their serial logs, expected
markers, exit statuses and archived image/initramfs digests. The combined
record contains 492 sanitizer boots, 16,192,478 shadow assertions and
401,408 workload thread-rounds. The 37 kernel unit-test boots and OSDK
integrations are counted separately.

## Test-driver and host checks

`make test` passed 68 Rust host tests, 25 doctests and 29 Python test-driver
tests. Fourteen contextual rustdoc examples are explicitly ignored.
Seventeen host targets have zero tests and contribute no passed count.

The Python tests exercise malformed and incomplete logs, missing test
activity, allowed and unexpected skips, image/status mismatches, zero-test
crates, invalid runner parameters, incomplete shadow counts, missing guest
markers and incorrect diagnostic results. Their substitute QEMU commands
are synthetic controls; they contribute no real guest boots.

The compiler-wrapper test derives all 35 default members from Cargo
manifests and checks an unknown dependency as well. It covers four feature
combinations, four target triples and two argument forms, totaling 1,152
combinations, plus an implicit host invocation. These are compiler-argument
checks. Separate ELF checks verify actual x86_64 callback references for all
four sanitizer builds.

The complete `make check` and `check-symbols.sh` returned zero.
Strict feature-enabled Clippy checks also passed for the tested kernel
source.

## Standalone OSDK

OSDK is excluded from the root workspace. Its 14 host unit tests and 22
integration tests are therefore tracked separately. The unit tests all passed;
21 integrations passed and one failed.
[osdk-test-results.tsv](osdk-test-results.tsv) lists all 36 named outcomes.
The 13 integrations
without QEMU passed; the other nine were selected individually with
`--exact`. `INTEL_TDX` was unset so the three TDX guards did not return
early.

The guest tests use the real built `cargo-osdk`, QEMU 8.2.2 and KVM.
Task-local adapters select Linux EFI64 boot through GRUB/OVMF, the host CPU,
no network device and dev optimization level 2. Each test runs in a private
mount namespace with a task-local `/tmp`. The kernel example uses the
verified `align_ext 0.1.0` package in the task-local offline vendor directory;
repository lockfiles are unchanged. QEMU commands, retained images,
digests, serial output and statuses are saved for each actual boot.
These results describe that native EFI configuration. The nine selected
integrations produced eleven guest boots, including three in the workspace
example. All eleven retained images matched their recorded digests, and
all eleven QEMU processes returned 33. Successful guest shutdown alone does
not satisfy the coverage-export assertion.

The hypervisor example passed its VMX-unavailable diagnostic branch. Its
output is `Error: VMX is not supported by the VM`; this is not counted as
VMX/EPT execution. The library example actually ran
`mylib::tests::it_works` and reported one passed test.

The LLVM coverage integration currently fails: the guest prints its
coverage buffer address and size and exits with QEMU status 33, but
`coverage.profraw` is absent. The integration assertion fails although the
OSDK command returns zero. The configured `isa-debug-exit` device terminates
QEMU before the monitor can export the buffer. This result is recorded as a
failure and is separate from the passing KCOV PC/CMP regressions.

## Retained files and reproduction

Portable sanitizer commands and the named-auditor invocation are in
[README.md](README.md). Native artifacts reside under
`/root/SyzOxide/.workdir/kcov-expanded/`:

- `execution-audit-verified/{summary,tests}.tsv` and the inputs in
  `execution-audit-workspace/` and `core-sanitizer-ktests-final/`.
- `run-audit-ostd.sh` and `audit-ostd-smp.log` for the two-vCPU OSTD run.
- `audit-final-*` and `audit-54-*` for the 132 sanitizer boots.
- `audit-make-test.log`, `audit-make-check-final.log` and
  `audit-symbols.log`, each with an exit-status `.meta` file.
- `audit-osdk-host-bin-f68d03d.log`,
  `audit-osdk-host-integration-f68d03d.log`,
  `audit-osdk-guest-*.log` and `audit-osdk-guests/guest-*/`.
- `run-audit-osdk-guest.sh`, `audit-osdk-command.py` and
  `audit-osdk-qemu.py` for the native OSDK execution environment.

Rerun the standalone OSDK coverage integration when changing profiling or
shutdown behavior. Require both successful execution and an exported
profile before reporting that integration as passed.
