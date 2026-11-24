# Validation results

Validation ran on 2026-11-24 and 2026-11-25 on SSH host `idcai-60525`.
The Asterinas base is `879e2c51cc3e8776b9b385645c6b0bbe45b7dbd5`.
The latest kernel and self-test source is
`f68d03d84e537cc87cabe169a9a185282dbf9bb0`.

## Latest source results

| Check | Result |
| --- | --- |
| Four sanitizer configurations | All built |
| Sanitizer guest regression | 54/54 boots passed |
| Default workspace kernel suite | 522 passed, 0 failed, 0 filtered |
| Instrumented OSTD kernel suite | 225 passed, 0 failed, 0 filtered |
| Instrumented aster-core kernel suite | 148 passed, 0 failed, 0 filtered |
| Host `make test` | 93 passed, 0 failed, 14 ignored documentation examples |
| Complete `make check` | Exit 0 |
| Strict feature-enabled Clippy | OSTD and kernel passed |
| Compiler wrapper | 64 combinations and implicit host invocation passed |
| ELF instrumentation checks | All four configurations passed |

The default workspace suite booted all 35 default members. Seventeen crates
contain tests; the other eighteen completed with zero tests. All 35 QEMU
processes returned 33. The NVMe suite passed all seven tests with a disposable
128 MiB NVMe disk. XArray passed all twenty tests.

Both instrumented suites enabled `kcov,kasan`, disabled default features
and used the compiler wrapper. They booted on two vCPUs with KASAN enabled.
Their 373 test executions are reported separately from the default suite.
See [kernel-test-results.tsv](kernel-test-results.tsv) for all 37 images,
per-crate counts, QEMU statuses and image hashes.

The OSTD suites each reported three hardware-dependent subcase skips:
`multiple_vmx_guards_lifecycle`, `switch_and_reuse_vmcs` and
`guest_mapping_lifecycle`. The guest does not provide VMX/EPT facilities.
The 14 ignored host items are rustdoc examples requiring surrounding macro,
module or kernel context; they are not executable ignored unit tests.

## Environment

| Setting | Value |
| --- | --- |
| Rust channel | nightly-2026-11-16 |
| rustc | 1.102.0-nightly, 5f4effd57, 2026-11-13 |
| LLVM | 23.1.5 |
| QEMU | 8.2.2 |
| Boot | x86_64 EFI64, GRUB, OVMF, KVM, q35 |
| Sanitizer guest compilation | dev, opt-level 2, aster-core opt-level 0 |
| Default workspace compilation | dev, opt-level 2 |
| LTO | disabled |
| Kernel task stack | 64 pages |
| Default workspace guest | 1 vCPU, 2 GiB |
| Instrumented unit-test guests | 2 vCPUs, 2 GiB |
| nixfmt | 1.4.0 |
| clang-format | 18.1.3 |
| typos | 1.39.0 |

Dependencies and tool binaries are installed under
`/root/SyzOxide/.workdir/`. NixOS test dependencies follow the existing
`test/nixos/Cargo.lock`; its contents were preserved.

## Latest sanitizer guest runs

| Configuration | RAM | vCPUs | Cases | Passed |
| --- | --- | --- | --- | --- |
| Both disabled | 2 GiB | 1, 2, 4 | normal | 3/3 |
| KCOV | 2 GiB | 1, 2, 4 | normal | 3/3 |
| KASAN | 512 MiB, 4 GiB | 1, 4 | all six | 24/24 |
| KCOV and KASAN | 512 MiB, 4 GiB | 1, 4 | all six | 24/24 |

Each combination ran once. The cases are `normal`, `shadow`, `oob`,
`partial`, `uaf` and `df`. The 22 normal/shadow boots returned 33 and
completed eight workload threads with 256 rounds each: 45,056 thread-rounds.
Each of the eight shadow boots passed 347,405 assertions, totaling 2,779,240.
The 32 deliberate diagnostic boots returned 65 with exactly one matching
KASAN category, the expected read/write/free description and a stack trace.
The runner rejects timeouts, missing markers and unexpected failures.

See [review-results.tsv](review-results.tsv) for all 54 results.

The shadow tests cover 70 allocation size/alignment combinations, zeroed
allocations, data preservation during growth/shrinkage, exact partial tail
tags and accesses crossing granule, 64-byte and page boundaries. Quarantine
checks use 5,000 small allocation/free cycles and sixteen 512 KiB allocations
to exercise both the 4,096-slot and 8 MiB limits.

KCOV tests cover actual kernel PCs, comparison operands and widths, exact
small-buffer capacity, page-crossing records, padding, saturation, reset,
ioctl errors, ownership, descriptor duplication, mapping lifetime, owner
exit, fork handoff and parallel PC/CMP sessions.

### Latest image SHA-256

| Mode | SHA-256 |
| --- | --- |
| off | `06989cba4a370f70a2f2402d9c461f8fab57731ae7f3cec9392ceec0c911ab0e` |
| kcov | `ee34da77a20f7fffdb0615ce22bab978b6efdc24356de7eaddab119d53aa796c` |
| kasan | `2c30912b9358c21102ba1e3f744cc239c2f8e4d783f347231f9f78c017ba3659` |
| both | `f46ecc3c2e893ca5422f24ff6f2000e5da5a7e97bd61dc55c26beedcc5e52e0a` |

Initramfs SHA-256:
`d4574f3b3b68dc5267c9af48ec3f509e6238959e75e93c3c81cec1465827fc95`.

## Repository and instrumentation checks

The complete `make check` passed Rust formatting, workspace Clippy,
kernel-test Clippy, dependency usage checks, Nix formatting, initramfs C
formatting, NixOS test-tool formatting/Clippy and spelling checks.
The dependency checker reported that all dependencies were used.
Separate feature-enabled OSTD and kernel Clippy commands passed with
`--no-deps -D warnings`.

The ELF checks found ten coverage callback references in `aster_core`
when KCOV is enabled and zero in OSTD in every mode. Both archives contain
twelve address-check callback references when KASAN is enabled. Disabled
configurations contain no corresponding instrumentation references.

Both C test programs compiled statically with
`-std=gnu11 -O2 -pthread -Wall -Wextra -Werror`. The workload also passed
on the Linux host. Shell syntax and Git whitespace checks passed.
The complete committed diff applies to the exact base; changed files
are checked byte for byte.

An independent KCOV capacity-control build reduced comparison capacity by
one. The expanded regression rejected its five-word buffer for returning
zero records where one record fits. A matching-ELF check resolved sampled
PCs to `sys_getpid` and `sys_getuid`. SyzOxide's 42 host tests and
instrumentation checker passed separately.

## Recorded guest runs

| Source/test stage | Boots | Shadow assertions | Workload thread-rounds | Results |
| --- | --- | --- | --- | --- |
| Initial four configurations | 210 | 907,170 | 184,320 | [results.tsv](results.tsv) |
| Allocation-size tests, 82d925d | 48 | 2,778,728 | 32,768 | [memory-results.tsv](memory-results.tsv) |
| Quarantine byte-budget tests, 652be95 | 48 | 2,779,240 | 32,768 | [quarantine-results.tsv](quarantine-results.tsv) |
| Latest source, f68d03d | 54 | 2,779,240 | 45,056 | [review-results.tsv](review-results.tsv) |
| Total | 360 | 9,244,378 | 294,912 | All passed |

These totals count sanitizer guest regressions. The 37 latest kernel
unit-test boots are separate. The initial run used five repetitions on
1/2/4 vCPUs with 2 GiB. Each subsequent memory run used 512 MiB and 4 GiB,
1/4 vCPUs and one repetition of all six cases for KASAN and KCOV+KASAN.

Historical KASAN image hashes identify the test revisions:

| Stage | kasan | both |
| --- | --- | --- |
| Initial | `c2d8f5f39b58a30c16c6eb7b2ff26d95333d45ad3e8cf7a8bcbea0e0fce5efe5` | `eab5fdbb49a5dfddedf7a03f6d6b81f0d30dffda587335d82565b1a0ab081de3` |
| Allocation-size | `35be987afef49366a020c51225acdfc2b719ee60e9639636ff54514d2f767e4f` | `5622ea14859fb9e94d8a12ea1b9c44369789e6fae2f19446aeca2e74f6c2a8ce` |
| Quarantine byte-budget | `2bf7b7733a53ab661cdf56e498c9cdf8b34c626905f2f5ab0459ad001276deb8` | `850887060321d7cc4e44f21a8ac240a8e4f93cb01b40c46740f26b93f26c106a` |

## Reproduction and retained artifacts

Use [README.md](README.md) for portable sanitizer build and run commands.
The native server retains scripts, tool configuration and logs under
`/root/SyzOxide/.workdir/kcov-expanded/`.

- `run-workspace-tests.sh` invokes the full-workspace `cargo osdk test`
  used by `make ktest`, with Linux EFI64 boot, dev optimization 2 and
  `workspace-qemu.sh`. The launcher provides one vCPU and a disposable
  NVMe disk for the NVMe suite. Results are in `workspace-ktests-final/`
  and `workspace-ktests-final.log`.
- `run-ostd-sanitizer-final.sh` and `run-core-sanitizer-tests.sh` run
  the instrumented unit suites. They pass `--features=kcov,kasan`,
  `--no-default-features`, `--boot-method=vmm-direct`,
  `--grub-boot-protocol=linux` and `--strip-elf`, using
  `core-sanitizer-qemu.sh`. Results are in
  `core-sanitizer-ktests-final/`, `ostd-sanitizer-final.log` and
  `core-sanitizer-final.log`.
- `clippy-features-strict.sh` and `clippy-features-strict.log` retain
  the separate strict feature checks.
- `upstream-unit-make-test-f68d03d.log` records the repeated
  host suite; `upstream-make-check-final-20261125.log` records the
  complete repository check.
- `review-memory-{kasan,both}-{512,4096}/` and
  `review-standard-{off,kcov}/` contain the latest per-boot serial logs,
  firmware state, image hashes and result tables.

Compiled sanitizer images and matching ELF files are under
`/root/asterinas/target/sanitizers/MODE/`. Keep each ELF with its image
and serial logs when resolving report addresses.
