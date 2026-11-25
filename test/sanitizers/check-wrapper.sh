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
python3 - "$root" > "$tmp/crates" <<'PYTHON'
from pathlib import Path
import sys
import tomllib

root = Path(sys.argv[1])
workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
members = workspace["default-members"]
assert members
for member in members:
    name = tomllib.loads((root / member / "Cargo.toml").read_text())["package"]["name"]
    supported = member == "ostd" or member.startswith("kernel")
    print(name.replace("-", "_"), int(supported))
print("unknown_dependency", 0)
PYTHON
crate_count=$(wc -l < "$tmp/crates")
((crate_count > 1))
checks=0
for kcov in 0 1; do
    for kasan in 0 1; do
        while read -r crate kasan_supported; do
            for target in x86_64-unknown-none x86_64-unknown-linux-gnu riscv64gc-unknown-none-elf loongarch64-unknown-none; do
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
                        if [[ $kasan_supported == 1 ]]; then address=$kasan; fi
                    fi
                    [[ $(grep -cxF 'passes=sancov-module' "$tmp/args" || true) == "$coverage" ]]
                    [[ $(grep -cxF 'llvm-args=-sanitizer-coverage-trace-compares' "$tmp/args" || true) == "$coverage" ]]
                    [[ $(grep -cxF -- '-Zsanitizer=kernel-address' "$tmp/args" || true) == "$address" ]]
                    grep -qxF 'example="two words"' "$tmp/args"
                    checks=$((checks+1))
                done
            done
        done < "$tmp/crates"
    done
done
[[ $checks == $((crate_count * 4 * 4 * 2)) ]]
# Rust build scripts and proc macros can invoke rustc without an explicit target.
ASTERINAS_KCOV=1 ASTERINAS_KASAN=1 \
    "$root/tools/kcov-rustc.sh" "$tmp/rustc" --crate-name aster_core >"$tmp/host"
if grep -qE 'sanitizer|sancov' "$tmp/host"; then exit 1; fi
printf 'Compiler wrapper passed %s target combinations and implicit host invocation\n' "$checks"
