# Preparing an Asterinas upstream PR

The reviewed integration branch is hosted in `Radon10043/asterinas`.
An upstream submission targets `asterinas/asterinas:main`.
Start from the reviewed commits, fetch upstream main, inspect intervening
changes and replay the commits on a new branch. Rerun the documented tests
after resolving any changes to allocation, task lifecycle or the compiler.

A focused submission sequence makes each feature independently reviewable.

- Submit the per-task KCOV runtime, device, compiler selection and userspace
  regression together. Describe the supported ioctl ABI and syscall-only
  recording semantics.
- Submit the KASAN runtime and its allocation/boot changes with the deterministic
  diagnostics. State the mapped ranges, quarantine limits and disabled
  stack/global instrumentation.
- Include the relevant build and test scripts with each feature and retain
  the combined configuration test in the integration branch.

Preserve attribution to the v0.19.0 implementation authors. Write imperative
commit subjects within 72 characters and keep each commit focused on one
logical change. Use OSTD for unsafe implementation and safe APIs in the
kernel components.

The PR description should include the exact source revision, Rust/LLVM
versions, build settings, image hashes, vCPU/RAM configuration, repetitions,
per-case outcomes and commands. Report host tests and guest tests separately.
Record any unavailable checks explicitly. The integration branch's
[results](TEST-RESULTS.md) provide a starting point that must be refreshed
after rebasing.

Run `make test`, `make check` and the repository's applicable kernel tests
in the revision's development container. Confirm the x86_64 workflow results
before requesting upstream review. A clean local sanitizer run complements
the repository's boot, regression and conformance workflows.

The repository's contribution guidance covers focused PRs, imperative
subjects and testing user-observable behavior. Consult the current versions
when preparing the submission.

- [Contribution process](../../book/src/to-contribute/coding-guidelines/for-maintainability/process.md)
- [Testing guidelines](../../book/src/to-contribute/coding-guidelines/for-development/testing.md)
- [Boterinas review commands](../../book/src/to-contribute/boterinas.md)
