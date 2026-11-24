#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
root=$(realpath "$(dirname "$0")/../..")
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
for mode in off kcov kasan both; do
    dir="$root/target/sanitizers/$mode/x86_64-unknown-none/debug"
    nm -g --defined-only "$dir/asterinas-osdk-bin" > "$tmp/defined"
    expected_kcov=0
    expected_kasan=0
    case "$mode" in kcov|both) expected_kcov=1;; esac
    case "$mode" in kasan|both) expected_kasan=1;; esac
    [[ $(grep -c ' __sanitizer_cov_trace_pc$' "$tmp/defined" || true) == "$expected_kcov" ]]
    for name in load1 store1; do
        [[ $(grep -c " __asan_$name$" "$tmp/defined" || true) == "$expected_kasan" ]]
    done
    for crate in aster_core ostd; do
        mapfile -t libs < <(find "$dir" -name "lib$crate-*.rlib")
        [[ ${#libs[@]} == 1 ]]
        nm -u "${libs[0]}" > "$tmp/undefined" 2>"$tmp/nm.log"
        grep -oE '__sanitizer_cov_[a-z0-9_]+' "$tmp/undefined" | sort -u > "$tmp/kcov" || true
        grep -oE '__asan_(load|store)[0-9N]+' "$tmp/undefined" | sort -u > "$tmp/kasan" || true
        count=$(wc -l < "$tmp/kcov")
        expected=0
        if [[ $crate == aster_core && $expected_kcov == 1 ]]; then expected=10; fi
        [[ $count == "$expected" ]]
        if [[ $expected_kasan == 1 ]]; then test -s "$tmp/kasan"; else test ! -s "$tmp/kasan"; fi
        printf '%s %s coverage_callbacks=%s address_callbacks=%s\n' "$mode" "$crate" "$count" "$(wc -l < "$tmp/kasan")"
    done
done
