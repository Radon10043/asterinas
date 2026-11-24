# Validation results

Validation was performed on 2026-11-24 and 2026-11-25 on the Linux SSH
development server. The target base is
`879e2c51cc3e8776b9b385645c6b0bbe45b7dbd5`.
The kernel implementation is commit `091bc7f`; the reproducible test
scripts are in `a6edcd2`.

## Environment

| Setting | Value |
| --- | --- |
| Rust channel | nightly-2026-11-16 |
| rustc | 1.102.0-nightly, 5f4effd57, 2026-11-13 |
| LLVM | 23.1.5 |
| QEMU | 8.2.2 |
| Boot | x86_64 EFI64, GRUB, OVMF, KVM, q35 |
| Guest RAM | 2 GiB |
| vCPUs | 1, 2, 4 |
| Repetitions | 5 per case and CPU count |
| Compilation | dev, opt-level 2, aster-core opt-level 0, debug information |
| LTO | disabled |
| Kernel task stack | 64 pages |

## Guest results

| Configuration | Cases | Boots | Passed |
| --- | --- | --- | --- |
| Both disabled | normal | 15 | 15 |
| KCOV | normal | 15 | 15 |
| KASAN | normal, shadow, oob, partial, uaf, df | 90 | 90 |
| KCOV and KASAN | normal, shadow, oob, partial, uaf, df | 90 | 90 |
| Total | | 210 | 210 |

All normal and shadow boots returned QEMU status 33 and the guest success
markers. The 120 deliberately selected diagnostics returned status 65 with
exactly one matching KASAN bug category, the expected access description and
a stack trace. Timeouts, absent markers and unexpected failures fail the test.

Each of the 30 shadow boots executed 30,239 assertions, totaling 907,170.
The 90 normal/shadow boots completed eight workload threads with 256 rounds
each, totaling 184,320 thread-rounds. KCOV-enabled boots ran the full guest
regression before the workload.

## Instrumentation and regression checks

- All four kernel configurations compiled.
- The ELF symbol check verified the configured presence of KCOV and KASAN
  callbacks. The `aster_core` archive references ten coverage callbacks when
  KCOV is enabled. OSTD references zero coverage callbacks in every mode.
  Both archives reference address-check callbacks when KASAN is enabled.
- The implementation diff applied cleanly to a fresh archive of the exact
  base commit. All 55 changed implementation and test files matched the
  working source byte for byte.
- Both C programs compiled statically with
  `-std=gnu11 -O2 -pthread -Wall -Wextra -Werror`.
- The workload also completed on the Linux host.
- Shell syntax checks and Git whitespace checks passed.
- A separate KCOV capacity control reduced the allowed comparison record
  count by one in a disposable build. The previous guest test passed that
  build; the expanded test rejected its five-word buffer with an expected
  count of one and an observed count of zero.
- A separate matching-ELF check resolved recorded PCs to the actual
  `sys_getpid` and `sys_getuid` handler ranges.
- SyzOxide's Rust tools built, its 42 tests passed, and its instrumentation
  checker passed.

## Repository checks

The host `make test` suite passed for 19 of 20 package targets.
The `short-vis-path::syntax_and_behavior` test requires `cargo-expand`,
which was absent from the task toolchain. The same failure was reproduced
with the unchanged base source and identical tools.

The whitespace, workspace lint configuration and Rust formatting checks
passed. The full `make check` command reached Clippy, whose executable was
absent from the pinned task toolchain. Full Clippy and `make ktest` are
pending. The guest regression results above are independently completed.

## Artifacts

The retained server directory is
`/root/SyzOxide/.workdir/kcov-expanded/`.
Each `verified-MODE/` directory contains the machine-readable result table,
input hashes, per-boot serial output and firmware state.
The kernel build output remains under
`/root/asterinas/target/sanitizers/MODE/`.

### Boot image SHA-256

| Mode | SHA-256 |
| --- | --- |
| off | `06989cba4a370f70a2f2402d9c461f8fab57731ae7f3cec9392ceec0c911ab0e` |
| kcov | `ee34da77a20f7fffdb0615ce22bab978b6efdc24356de7eaddab119d53aa796c` |
| kasan | `c2d8f5f39b58a30c16c6eb7b2ff26d95333d45ad3e8cf7a8bcbea0e0fce5efe5` |
| both | `eab5fdbb49a5dfddedf7a03f6d6b81f0d30dffda587335d82565b1a0ab081de3` |
