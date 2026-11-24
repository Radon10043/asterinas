#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: $0 {off|kcov|kasan|both} INITRAMFS OUTPUT_DIRECTORY" >&2
    exit 2
fi
mode=$1
case "$mode" in off|kcov) cases=(normal);; kasan|both) cases=(normal shadow oob partial uaf df);; *) exit 2;; esac
root=$(realpath "$(dirname "$0")/../..")
initrd=$(realpath "$2")
output=$(realpath -m "$3")
image="$root/target/sanitizers/$mode/osdk/asterinas/asterinas-osdk-bin"
test -s "$image"
test -s "$initrd"
mkdir -p "$output"
test ! -e "$output/results.tsv"
qemu=${QEMU:-qemu-system-x86_64}
grub=${GRUB_MKSTANDALONE:-grub-mkstandalone}
modules=${GRUB_MODULES:-/usr/lib/grub/x86_64-efi}
firmware=${OVMF_DIR:-/usr/share/OVMF}
repeat=${REPEAT:-5}
memory=${MEMORY_MIB:-2048}
[[ "$memory" =~ ^[1-9][0-9]*$ ]]
[[ "$repeat" =~ ^[1-9][0-9]*$ ]]
read -r -a cpus <<< "${CPUS:-1 2 4}"
for cpu in "${cpus[@]}"; do [[ "$cpu" =~ ^[1-9][0-9]*$ ]]; done
printf 'mode\tcase\tcpus\trun\texit\tresult\n' > "$output/results.tsv"
sha256sum "$image" "$initrd" > "$output/inputs.sha256"
qemu_extra=()
if [[ -n "${QEMU_DATA_DIR:-}" ]]; then qemu_extra=(-L "$QEMU_DATA_DIR"); fi
printf 'memory_mib=%s\ncpus=%s\nrepeat=%s\n' "$memory" "${cpus[*]}" "$repeat" > "$output/config.txt"
failures=0
for test_case in "${cases[@]}"; do
    template="$output/$test_case"
    mkdir -p "$template/EFI/BOOT"
    extra=
    if [[ $test_case != normal ]]; then extra="kasan_selftest=$test_case"; fi
    cat > "$template/grub.cfg" <<CFG
serial --unit=0 --speed=115200
terminal_output serial
search --file --set=root /bzImage
linux /bzImage console=ttyS0 earlycon loglevel=error rdinit=/init $extra
initrd /initrd
boot
CFG
    "$grub" -d "$modules" -O x86_64-efi --modules="part_gpt part_msdos fat normal linux search search_fs_file serial terminal" --locales="" --fonts="" -o "$template/EFI/BOOT/BOOTX64.EFI" "boot/grub/grub.cfg=$template/grub.cfg"
    for cpu in "${cpus[@]}"; do
        for ((run=1; run<=repeat; run++)); do
            dir="$output/$test_case-$cpu-$run"
            mkdir -p "$dir/efi/EFI/BOOT"
            cp "$template/EFI/BOOT/BOOTX64.EFI" "$dir/efi/EFI/BOOT/"
            cp "$image" "$dir/efi/bzImage"
            cp "$initrd" "$dir/efi/initrd"
            cp "$firmware/OVMF_VARS_4M.fd" "$dir/vars.fd"
            status=0
            timeout -k 5 120 "$qemu" "${qemu_extra[@]}" -accel kvm -machine q35,kernel-irqchip=split -cpu host -smp "$cpu" -m "$memory" -display none -serial stdio -monitor none -no-reboot -nic none \
                -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware/OVMF_CODE_4M.fd" \
                -drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
                -drive "file=fat:rw:$dir/efi,format=raw,if=ide" \
                -device isa-debug-exit,iobase=0xf4,iosize=0x04 </dev/null >"$dir/serial.log" 2>&1 || status=$?
            tr -d '\r' <"$dir/serial.log" >"$dir/serial.txt"
            log="$dir/serial.txt"
            pass=true
            if [[ $mode == kasan || $mode == both ]]; then
                grep -qF '[kasan] KernelAddressSanitizer enabled' "$log" || pass=false
            elif grep -qF '[kasan] KernelAddressSanitizer enabled' "$log"; then pass=false
            fi
            case "$test_case" in
                normal|shadow)
                    [[ $status == 33 ]] || pass=false
                    grep -qxF 'KCOV_GUEST_EXIT=0' "$log" || pass=false
                    grep -qxF 'SANITIZER_WORKLOAD_PASS workers=8 rounds=256' "$log" || pass=false
                    if [[ $mode == kcov || $mode == both ]]; then
                        grep -q '^PASS: real KCOV PCs,' "$log" || pass=false
                    else
                        grep -qxF 'KCOV_OFF_PASS' "$log" || pass=false
                    fi
                    if [[ $test_case == shadow ]]; then
                        grep -qE '^\[kasan-selftest\] shadow passed checks=[1-9][0-9]{4,}$' "$log" || pass=false
                    fi
                    if grep -qE 'BUG: KASAN:|FAIL|panicked at' "$log"; then pass=false; fi
                    ;;
                *)
                    [[ $status == 65 ]] || pass=false
                    grep -qxF "[kasan-selftest] running $test_case" "$log" || pass=false
                    [[ $(grep -c 'BUG: KASAN:' "$log") == 1 ]] || pass=false
                    case "$test_case" in
                        oob) bug=slab-out-of-bounds; access='Read of size 1 at addr';;
                        partial) bug=slab-out-of-bounds; access='Write of size 1 at addr';;
                        uaf) bug=use-after-free; access='Read of size 8 at addr';;
                        df) bug=double-free; access='Free at addr';;
                    esac
                    grep -qF "BUG: KASAN: $bug in 0x" "$log" || pass=false
                    grep -qF "$access" "$log" || pass=false
                    grep -qF 'Printing stack trace:' "$log" || pass=false
                    if grep -qE 'KCOV_GUEST_EXIT|panicked at|FAIL' "$log"; then pass=false; fi
                    ;;
            esac
            result=PASS
            if [[ $pass != true ]]; then result=FAIL; failures=$((failures+1)); fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$mode" "$test_case" "$cpu" "$run" "$status" "$result" | tee -a "$output/results.tsv"
        done
    done
done
test "$failures" = 0
