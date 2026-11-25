#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
if [[ $# != 1 ]]; then
    echo "Usage: $0 {off|kcov|kasan|both}" >&2
    exit 2
fi
case "$1" in
    off) features=(); kcov=0; kasan=0 ;;
    kcov) features=(--features=kcov); kcov=1; kasan=0 ;;
    kasan) features=(--features=kasan); kcov=0; kasan=1 ;;
    both) features=(--features=kcov,kasan); kcov=1; kasan=1 ;;
    *) exit 2 ;;
esac
root=$(realpath "$(dirname "$0")/../..")
export CARGO_TARGET_DIR="$root/target/sanitizer-bench/$1"
export OSDK_LOCAL_DEV=1 OSDK_TARGET_ARCH=x86_64 OSTD_TASK_STACK_SIZE_IN_PAGES=64
export CARGO_PROFILE_DEV_LTO=false CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2 CARGO_PROFILE_RELEASE_DEBUG=true
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=false
export ASTERINAS_KCOV="$kcov" ASTERINAS_KASAN="$kasan"
if [[ -n "${RUSTC_WRAPPER:-}${RUSTC_WORKSPACE_WRAPPER:-}" ]]; then
    echo "Unset external Rust compiler wrappers for this build." >&2
    exit 2
fi
if [[ $1 != off ]]; then
    export RUSTC_WRAPPER="$root/tools/kcov-rustc.sh"
fi
cd "$root/kernel"
cargo osdk build --profile release --target-arch=x86_64 --boot-method=vmm-direct \
    --grub-boot-protocol=linux --strip-elf --kcmd-args=earlycon \
    --kcmd-args=console=ttyS0 "${features[@]}" \
    --config profile.release.opt-level=2 --config 'profile.release.package."*".opt-level=2' \
    --config profile.release.lto=false \
    --config profile.release.debug=true --config 'profile.release.package."*".debug=true' \
    --config profile.release.debug-assertions=false --config 'profile.release.package."*".debug-assertions=false' \
    --config profile.release.overflow-checks=false --config 'profile.release.package."*".overflow-checks=false'
image="$CARGO_TARGET_DIR/osdk/asterinas/asterinas-osdk-bin"
elf="$CARGO_TARGET_DIR/x86_64-unknown-none/release/asterinas-osdk-bin"
test -s "$image"
test -s "$elf"
sha256sum "$image" "$elf"
size "$elf"
