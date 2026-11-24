#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

# Instrument only the safe syscall implementation crate. OSTD, the allocator,
# and the compiler's host tools must never acquire sanitizer callbacks.
set -euo pipefail
rustc=$1
shift
args=("$@")
crate_name=
target=
while (($#)); do
    case "$1" in
        --crate-name) crate_name=$2; shift 2 ;;
        --crate-name=*) crate_name=${1#*=}; shift ;;
        --target) target=$2; shift 2 ;;
        --target=*) target=${1#*=}; shift ;;
        *) shift ;;
    esac
done
if [[ "$crate_name" == aster_core && "$target" == x86_64-unknown-none ]]; then
    exec "$rustc" "${args[@]}" \
        -C passes=sancov-module \
        -C llvm-args=-sanitizer-coverage-level=3 \
        -C llvm-args=-sanitizer-coverage-trace-pc \
        -C llvm-args=-sanitizer-coverage-trace-compares
fi
exec "$rustc" "${args[@]}"
