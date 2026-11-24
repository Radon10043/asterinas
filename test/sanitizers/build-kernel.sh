#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

if [[ $# != 1 ]]; then
    echo "Usage: $0 {off|kcov|kasan|both}" >&2
    exit 2
fi
case "$1" in
    off)  features=(); kcov=0; kasan=0 ;;
    kcov) features=(--features=kcov); kcov=1; kasan=0 ;;
    kasan) features=(--features=kasan); kcov=0; kasan=1 ;;
    both) features=(--features=kcov,kasan); kcov=1; kasan=1 ;;
    *) echo "Unknown instrumentation mode: $1" >&2; exit 2 ;;
esac
root=$(realpath "$(dirname "$0")/../..")
export CARGO_TARGET_DIR="$root/target/sanitizers/$1"
export OSDK_LOCAL_DEV=1 OSDK_TARGET_ARCH=x86_64 OSTD_TASK_STACK_SIZE_IN_PAGES=64
export CARGO_PROFILE_DEV_LTO=false CARGO_PROFILE_RELEASE_LTO=false
export ASTERINAS_KCOV="$kcov" ASTERINAS_KASAN="$kasan"
if [[ -n "${RUSTC_WRAPPER:-}${RUSTC_WORKSPACE_WRAPPER:-}" ]]; then
    echo "Unset external Rust compiler wrappers for this build." >&2
    exit 2
fi
if [[ $1 != off ]]; then
    export RUSTC_WRAPPER="$root/tools/kcov-rustc.sh"
fi

cd "$root/kernel"
cargo osdk build --target-arch=x86_64 --boot-method=vmm-direct \
    --grub-boot-protocol=linux --strip-elf --kcmd-args=earlycon \
    --kcmd-args=console=ttyS0 "${features[@]}" \
    --config profile.dev.opt-level=2 --config 'profile.dev.package."*".opt-level=2' \
    --config profile.dev.package.aster-core.opt-level=0 --config profile.dev.debug=true
image="$CARGO_TARGET_DIR/osdk/asterinas/asterinas-osdk-bin"
elf="$CARGO_TARGET_DIR/x86_64-unknown-none/debug/asterinas-osdk-bin"
test -s "$image"
test -s "$elf"
sha256sum "$image" "$elf"
