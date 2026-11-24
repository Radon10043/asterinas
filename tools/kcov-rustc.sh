#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0

# Select instrumentation separately for each target kernel crate.
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
kcov=${ASTERINAS_KCOV:-1}
kasan=${ASTERINAS_KASAN:-0}
extra_flags=()

if [[ "$target" == x86_64-unknown-none ]]; then
    if [[ "$kcov" == 1 ]] && [[ "$crate_name" == aster_core ]]; then
        extra_flags+=(
            -C passes=sancov-module
            -C llvm-args=-sanitizer-coverage-level=3
            -C llvm-args=-sanitizer-coverage-trace-pc
            -C llvm-args=-sanitizer-coverage-trace-compares
        )
    fi

    if [[ "$kasan" == 1 ]]; then
        case "$crate_name" in
            ostd | asterinas | aster_core | \
            aster_block | aster_cmdline | aster_console | aster_device | \
            aster_drm | aster_framebuffer | aster_i8042 | aster_input | \
            aster_logger | aster_mlsdisk | aster_network | aster_nvme | \
            aster_pci | aster_simpledrm | aster_softirq | aster_systree | \
            aster_time | aster_uart | aster_virtio | \
            aster_bigtcp | aster_fuse | aster_util | \
            device_id | dma_pool | fdt_util | io_util | \
            ring_buffer | sparse_id_alloc | xarray)
                extra_flags+=(
                    -Zsanitizer=kernel-address
                    -Cllvm-args=-asan-mapping-offset=0xdffffc0000000000
                    -Cllvm-args=-asan-mapping-scale=3
                    -Cllvm-args=-asan-stack=0
                    -Cllvm-args=-asan-globals=0
                    -Cllvm-args=-asan-kernel-mem-intrinsic-prefix=1
                    -Cllvm-args=-asan-instrumentation-with-call-threshold=0
                    -Cunsafe-allow-abi-mismatch=sanitizer
                )
                ;;
            *)
                extra_flags+=(-Cunsafe-allow-abi-mismatch=sanitizer)
                ;;
        esac
    fi
fi

exec "$rustc" "${args[@]}" "${extra_flags[@]}"
