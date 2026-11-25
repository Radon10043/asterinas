#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 STATIC_BUSYBOX OUTPUT_DIRECTORY" >&2
    exit 2
fi
root=$(realpath "$(dirname "$0")/../..")
busybox=$(realpath "$1")
output=$(realpath -m "$2")
test ! -e "$output"
mkdir -p "$output"
"$root/test/sanitizers/make-initramfs.sh" "$busybox" "$output/tests.cpio.gz"
for mode in off kcov; do
    "$root/test/sanitizers/run.sh" "$mode" "$output/tests.cpio.gz" "$output/$mode"
done
