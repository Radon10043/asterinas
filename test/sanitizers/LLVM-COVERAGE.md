# LLVM profile export

The OSDK `coverage` feature collects LLVM execution profiles through
`cargo osdk run --coverage` and `cargo osdk test --coverage`.
It is separate from the per-task KCOV PC/CMP interface.

## Export lifecycle

At poweroff, OSTD captures the profile in an immutable buffer, writes its
address, length and guest success/failure status to the serial log, and
halts the calling CPU. OSDK connects to QMP, stops the VM and confirms that
it is no longer running before requesting a memory export.

The export uses a temporary file in the working directory. OSDK waits for
the monitor response, checks the exact byte count against the guest record
and validates the LLVM raw-profile magic. It then publishes
`coverage.profraw`, requests QEMU termination and checks its process
status. A successful guest returns command status 0; a failed guest returns
status 1 after exporting its profile.

Before launching QEMU, OSDK clears the previous profile and serial log.
Incomplete records are ignored until the complete line arrives.
Invalid records, failed monitor commands, connection loss, missing files,
length mismatches and invalid profile headers cause command failure.
QMP command responses have bounded timeouts.

The command reference describes the required serial-log configuration and
LLVM commands: [cargo osdk run](../../book/src/osdk/reference/commands/run.md).

## Validation method

The real guest checks require a newly exported profile, successful
`llvm-profdata merge` and `llvm-profdata show`, and nonzero execution counts.
The integration tests prepopulate the output with a sentinel so that
retaining an existing file cannot satisfy the assertions. Guest-failure
tests require command status 1 and a readable profile.

The host tests use paired UNIX sockets to exercise QMP negotiation,
asynchronous events, partial responses, invalid replies and disconnects.
They check that memory export is acknowledged and that malformed or
incomplete output is not published. These tests use simulated monitor
responses and are counted separately from real guest boots.

The KCOV/KASAN regression rebuilds all four configurations and runs the
applicable normal, shadow and diagnostic cases on 1/2 vCPUs with 2 GiB.
[coverage-regression-results.tsv](coverage-regression-results.tsv) records
all 28 boots. They passed, including 1,389,620 shadow assertions and 24,576
workload thread-rounds. ELF instrumentation checks passed for all four
rebuilt configurations.

## Recorded results

Validation ran on SSH host `idcai-60525` using source content committed as
`2d078e3bd402a8c27aea9ef5f9c238ffe27c68ba`.
The tested OSDK executable SHA-256 is
`d5338f593c3239fe0a6eee4c4b994200ddb37c264bf4c7ea274f096659e097b5`.
The toolchain is nightly-2026-11-16 with LLVM 23.1.5.
Guests use QEMU 8.2.2/KVM and Linux EFI64 boot through GRUB/OVMF.

| Focused case | vCPUs | Guest outcome | OSDK exit | QEMU exit | Verified target counts |
| --- | --- | --- | --- | --- | --- |
| `run --coverage` | 1, 2, 4 | Success | 0 | 0 | `kernel_main=1`, `coverage_probe=1` |
| `run --coverage` | 1, 2, 4 | Failure | 1 | 0 | `kernel_main=1`, `coverage_probe=1` |
| `test --coverage` | 1 | One passing test | 0 | 0 | `coverage_test_case=1` |
| `test --coverage` | 1 | One failing test | 1 | 0 | `coverage_test_case=1` |

All eight real guest cases met their expected outcomes. Each profile was
read by `llvm-profdata merge/show` and `llvm-cov export/report/show` with
the matching unstripped ELF. All forty LLVM commands returned zero.
The profile sizes range from 3,053,544 to 4,750,512 bytes. Every byte count
matches the guest's coverage record; retained guest image hashes also match
the recorded QEMU inputs. The two test-mode serial logs each show exactly
one selected test and its individual result, with zero filtered tests.

[llvm-coverage-results.tsv](llvm-coverage-results.tsv) records each case's
statuses, raw profile size and SHA-256, target counts and tool diagnostics.

The separate early-exit control prepopulates a profile and serial record,
then runs a QEMU substitute that returns zero without creating a VM.
OSDK returns 6, removes the old output and record, and produces no new
profile. No real guest boot is counted for this control.

The complete OSDK suite passed 28 host unit tests and 23 integration tests,
with no ignored or filtered tests. The integration suite includes separate
normal-exit and failed-exit profile checks. Its twelve real guest boots are
separate from the eight focused cases and the 28 sanitizer boots.
Root `make test` passed 93 Rust tests and 29 Python driver tests.
Root `make check`, OSDK formatting and strict OSDK Clippy passed.

## LLVM source-mapping diagnostic

For all eight profiles, `llvm-profdata merge` and `show` complete without
warnings. The matching LLVM toolchain's `llvm-cov export`, `report` and
`show` each report one function with mismatched data in the complete image.

In the one-vCPU success artifact, the diagnostic identifies a
`core::convert::num` conversion function. Its ELF coverage mapping requests hash
`0x0`, while the raw profile contains the same function with hash
`0x08db4f3cbe3ec729` and count 164. That function is omitted from the
source-mapping export. The selected project functions appear in the export
with count 1, as checked in every case.

The raw profile and matching ELF are preserved without modifying their
records to suppress this diagnostic. Each tool's standard error is retained
alongside its output. Whole-image source reports should retain this
diagnostic when interpreted or shared.

## Retained artifacts

The server stores the focused cases under
`/root/SyzOxide/.workdir/kcov-expanded/coverage-regression/`.
`summary.json` indexes the eight profiles and early-exit control.
Each real-case directory retains the source, manifest, raw/indexed profiles,
matching ELF, QEMU command, image hash, serial output, command statuses,
LLVM output and standard error.

The same task directory contains `run-real.sh`, test-mode launchers,
`qemu-private.py` and the validation helpers used on this host.
The command reference above provides the portable collection procedure.

Additional results are under `/root/SyzOxide/.workdir/kcov-expanded/`:

- `llvm-coverage-checks/`: current host test, format, build and Clippy logs
  with exit-status files.
- `coverage-integration-full.log` and `.log.meta`: all 23 integrations.
- `coverage-integration-guests.json`: the twelve corresponding QEMU records.
- `coverage-fix-regression-{off,kcov,kasan,both}/`: the 28 sanitizer boots.
- `coverage-fix-regression-build-*.log`, `.log.meta` and `.sha256`:
  rebuilt image/ELF records.
- `coverage-fix-regression-symbols.log` and `.log.meta`: instrumentation checks.
