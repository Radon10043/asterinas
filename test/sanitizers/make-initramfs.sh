#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 STATIC_BUSYBOX OUTPUT.cpio.gz" >&2
    exit 2
fi
source_dir=$(realpath "$(dirname "$0")/../..")
busybox=$(realpath "$1")
output=$(realpath -m "$2")
test -f "$source_dir/test/kcov/kcov-smoke.c"
test -x "$busybox"
if readelf -l "$busybox" | grep 'INTERP' >/dev/null; then
    echo "The test initramfs requires a statically linked BusyBox." >&2
    exit 2
fi
root=$(mktemp -d)
archive=$(mktemp --tmpdir="$(dirname "$output")" .sanitizer-initramfs.XXXXXXXX)
trap 'rm -rf -- "$root"; rm -f -- "$archive"' EXIT
mkdir -p "$root"/{bin,dev,proc,tmp}
install -m 0755 "$busybox" "$root/bin/busybox"
flags=(-std=gnu11 -O2 -static -pthread -Wall -Wextra -Werror)
"${CC:-cc}" "${flags[@]}" "$source_dir/test/kcov/kcov-smoke.c" -o "$root/kcov-smoke"
"${CC:-cc}" "${flags[@]}" "$source_dir/test/sanitizers/workload.c" -o "$root/sanitizer-workload"
cat > "$root/init" <<'INIT'
#!/bin/busybox sh
run_tests() {
    /bin/busybox mount -t devtmpfs devtmpfs /dev || return 1
    /bin/busybox mount -t proc proc /proc || return 1
    /bin/busybox mount -t tmpfs tmpfs /tmp || return 1
    if [ -e /dev/kcov ]; then
        /kcov-smoke || return 1
    elif [ -e /proc/kallsyms ]; then
        echo "FAIL: kernel text bounds present without /dev/kcov"
        return 1
    else
        echo "KCOV_OFF_PASS"
    fi
    /sanitizer-workload
}
run_tests
rc=$?
echo "KCOV_GUEST_EXIT=$rc"
/bin/busybox poweroff -f
INIT
chmod 0755 "$root/init"
(cd "$root"; find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc --owner=0:0 --quiet) |
    gzip -n >"$archive"
mv -- "$archive" "$output"
