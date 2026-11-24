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
  base commit. All changed implementation and test files matched their committed
  source byte for byte.
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

The complete host `make test` suite passed after installing its tooling
dependencies in the task directory. It reported 93 passed, zero failed and
14 ignored tests. The compiler wrapper additionally passed 64 explicit
target/crate/feature/argument-form combinations and an implicit host invocation.

Clippy completed successfully with both `kcov,kasan` features enabled, using
the test build settings. It emitted warnings in OSTD and component-macro.
The feature-enabled check log is retained as `clippy-features.log`.

The repository's `make check` completed its Rust formatting, workspace Clippy,
kernel-test Clippy and dependency usage checks. The dependency checker reported
that all dependencies were used. The aggregate command then stopped because
`nixfmt` was unavailable in the task environment.

Independent follow-up checks found that the initramfs formatting check needs
`clang-format`, the NixOS test check needs the unavailable offline dependency
`rexpect`, and the spelling check needs `typos`. These checks remain pending.
The task environment also lacks `nixfmt`; a complete `make check` result is
therefore unavailable. None of these pending checks is included in the
passing test counts.

## OSTD kernel tests

The feature-enabled OSTD test kernel ran 225 tests with zero failures and
zero filtered tests under QEMU/KVM, 2 vCPUs and 2 GiB RAM. This includes
`shared_count_is_bounded`, `records_across_page_boundary` and
`records_cmp_across_page_boundary`. Three tests reported skipped VMX/EPT subcases because these facilities
were unavailable to the guest: `multiple_vmx_guards_lifecycle`,
`switch_and_reuse_vmcs` and `guest_mapping_lifecycle`.

The test kernel used `kcov,kasan`, no default features, dev optimization 2
and 64 task stack pages. It was booted through Linux EFI64 with GRUB/OVMF.
The retained command script is `run-ostd-tests.sh`, the QEMU launcher is
`osdk-test-qemu.sh`, and the successful log is `ostd-all-repacked.log`.
The Linux setup payload was rebuilt before the run so the selected tests
matched the generated kernel. This run covers the OSTD crate; the full
workspace `make ktest` target is a separate check.

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


## Expanded allocator and memory-size runs

Commit `82d925d` adds 70 allocation size/alignment combinations, checks zeroed
memory, preserves data through growth and shrinkage, verifies exact tail
shadow tags and checks quarantine limits after 5,000 allocation/free cycles.

The expanded tests passed another 48 boots with KASAN and KCOV+KASAN,
512 MiB and 4 GiB RAM, 1 and 4 vCPUs, and all six cases once per combination.
Each of the eight shadow boots passed 347,341 assertions. These runs add
2,778,728 shadow assertions and 32,768 workload thread-rounds.

Across both recorded runs there are 258 successful boots, 3,685,898 shadow
assertions and 217,088 workload thread-rounds. The original 210-run table
uses the earlier test image; the additional results use the expanded image.
See [memory-results.tsv](memory-results.tsv) for every additional result.

| Expanded image | SHA-256 |
| --- | --- |
| kasan | `35be987afef49366a020c51225acdfc2b719ee60e9639636ff54514d2f767e4f` |
| both | `5622ea14859fb9e94d8a12ea1b9c44369789e6fae2f19446aeca2e74f6c2a8ce` |

## Quarantine byte-budget verification

Commit `652be95` extends the allocator check with sixteen 512 KiB live
allocations after the small-object churn. Each free checks both quarantine
limits. This exercises eviction by memory usage as well as slot count.

The four memory/configuration combinations completed another 48 boots.
All passed. Each of the eight shadow runs performed 347,405 assertions.
See [quarantine-results.tsv](quarantine-results.tsv) for the final test image.

Together the three recorded runs completed 306 boots, 6,465,138 shadow
assertions and 249,856 workload thread-rounds. Serial logs for the final
run are in `final-memory-MODE-RAM/` in the retained server directory.

| Final image | SHA-256 |
| --- | --- |
| kasan | `2bf7b7733a53ab661cdf56e498c9cdf8b34c626905f2f5ab0459ad001276deb8` |
| both | `850887060321d7cc4e44f21a8ac240a8e4f93cb01b40c46740f26b93f26c106a` |
