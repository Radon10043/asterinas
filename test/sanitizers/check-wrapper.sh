#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
root=$(realpath "$(dirname "$0")/../..")
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cat > "$tmp/rustc" <<'RUSTC'
#!/usr/bin/env bash
printf '%s\n' "$@"
RUSTC
chmod +x "$tmp/rustc"
checks=0
for kcov in 0 1; do
    for kasan in 0 1; do
        for crate in aster_core ostd aster_uart unknown_dependency; do
            for target in x86_64-unknown-none x86_64-unknown-linux-gnu; do
                for syntax in separate equals; do
                    if [[ $syntax == separate ]]; then
                        args=(--crate-name "$crate" --target "$target")
                    else
                        args=("--crate-name=$crate" "--target=$target")
                    fi
                    ASTERINAS_KCOV="$kcov" ASTERINAS_KASAN="$kasan" \
                        "$root/tools/kcov-rustc.sh" "$tmp/rustc" "${args[@]}" --cfg 'example="two words"' >"$tmp/args"
                    coverage=0
                    address=0
                    if [[ $target == x86_64-unknown-none ]]; then
                        if [[ $crate == aster_core ]]; then coverage=$kcov; fi
                        if [[ $crate != unknown_dependency ]]; then address=$kasan; fi
                    fi
                    [[ $(grep -cxF 'passes=sancov-module' "$tmp/args" || true) == "$coverage" ]]
                    [[ $(grep -cxF 'llvm-args=-sanitizer-coverage-trace-compares' "$tmp/args" || true) == "$coverage" ]]
                    [[ $(grep -cxF -- '-Zsanitizer=kernel-address' "$tmp/args" || true) == "$address" ]]
                    grep -qxF 'example="two words"' "$tmp/args"
                    checks=$((checks+1))
                done
            done
        done
    done
done
# Rust build scripts and proc macros can invoke rustc without an explicit target.
ASTERINAS_KCOV=1 ASTERINAS_KASAN=1 \
    "$root/tools/kcov-rustc.sh" "$tmp/rustc" --crate-name aster_core >"$tmp/host"
if grep -qE 'sanitizer|sancov' "$tmp/host"; then exit 1; fi
printf 'Compiler wrapper passed %s target combinations and implicit host invocation\n' "$checks"
