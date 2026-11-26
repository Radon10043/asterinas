#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

# `RUSTC_WRAPPER` script used when building Asterinas with `KASAN=1`.
#
# Enables LLVM KernelAddressSanitizer (`-Zsanitizer=kernel-address`) with
# Linux-compatible x86_64 Generic KASAN mapping parameters for `ostd` and
# Asterinas kernel crates, while keeping host tools, standard library crates,
# and OSDK allocator/harness crates uninstrumented.

set -euo pipefail

RUSTC="$1"
shift

TARGET=""
CRATE_NAME=""
PREV=""
for arg in "$@"; do
    case "$PREV" in
        --target)
            TARGET="$arg"
            PREV=""
            continue
            ;;
        --crate-name)
            CRATE_NAME="$arg"
            PREV=""
            continue
            ;;
    esac
    case "$arg" in
        --target|--crate-name)
            PREV="$arg"
            ;;
        --target=*)
            TARGET="${arg#--target=}"
            ;;
        --crate-name=*)
            CRATE_NAME="${arg#--crate-name=}"
            ;;
    esac
done

# Leave host builds, non-x86_64 targets, and probe invocations (`-vV`, `--print`) untouched.
if [ "$TARGET" != "x86_64-unknown-none" ] || [ -z "$CRATE_NAME" ]; then
    exec "$RUSTC" "$@"
fi

KASAN_COMMON_FLAGS=(
    -Cunsafe-allow-abi-mismatch=sanitizer
)

KASAN_INSTRUMENT_FLAGS=(
    -Zsanitizer=kernel-address
    -Cllvm-args=-asan-mapping-offset=0xdffffc0000000000
    -Cllvm-args=-asan-mapping-scale=3
    -Cllvm-args=-asan-stack=0
    -Cllvm-args=-asan-globals=0
    -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1
    -Cllvm-args=-asan-instrumentation-with-call-threshold=0
    "${KASAN_COMMON_FLAGS[@]}"
)

case "$CRATE_NAME" in
    ostd|asterinas|aster_*|device_id|dma_pool|fdt_util|io_util|ring_buffer|sparse_id_alloc|xarray)
        exec "$RUSTC" "$@" "${KASAN_INSTRUMENT_FLAGS[@]}"
        ;;
    *)
        exec "$RUSTC" "$@" "${KASAN_COMMON_FLAGS[@]}"
        ;;
esac
