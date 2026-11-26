#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

# Enable LLVM SanitizerCoverage instrumentation for `aster_core` on x86-64
# while leaving OSTD, build scripts, proc-macros, and host crates uninstrumented.

set -euo pipefail

if (($# < 1)); then
    echo "Usage: $0 <rustc> [args...]" >&2
    exit 2
fi

rustc=$1
shift
args=("$@")

crate_name=
target=
while (($#)); do
    case "$1" in
        --crate-name)
            if (($# < 2)); then break; fi
            crate_name=$2
            shift 2
            ;;
        --crate-name=*)
            crate_name=${1#*=}
            shift
            ;;
        --target)
            if (($# < 2)); then break; fi
            target=$2
            shift 2
            ;;
        --target=*)
            target=${1#*=}
            shift
            ;;
        *)
            shift
            ;;
    esac
done

extra_flags=()
if [[ "$target" == x86_64-unknown-none && "$crate_name" == aster_core ]]; then
    extra_flags+=(
        -C passes=sancov-module
        -C llvm-args=-sanitizer-coverage-level=3
        -C llvm-args=-sanitizer-coverage-trace-pc
        -C llvm-args=-sanitizer-coverage-trace-compares
    )
fi

exec "$rustc" "${args[@]}" "${extra_flags[@]}"
