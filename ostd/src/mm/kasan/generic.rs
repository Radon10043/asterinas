// SPDX-License-Identifier: MPL-2.0

//! Generic KASAN memory access checks and compiler ABI hooks.
//!
//! Mirrors Linux's `mm/kasan/generic.c`: fast-path granule checks for 1, 2, 4,
//! 8, 16, and N-byte accesses plus word-aligned shadow scanning (`memory_is_nonzero`).

use super::{
    AccessType, KASAN_ALLOCA_LEFT, KASAN_ALLOCA_RIGHT, KASAN_GRANULE_MASK, KASAN_GRANULE_SIZE,
    KASAN_SHADOW_INIT, addr_has_metadata, align_down, align_up, checked_align_up, is_enabled,
    mem_to_shadow, report, shadow,
};

const KASAN_ALLOCA_REDZONE_SIZE: usize = 32;

/// Checks a single byte at `addr`, mirroring Linux's `memory_is_poisoned_1`.
///
/// # Safety
///
/// `addr` must satisfy [`addr_has_metadata`].
#[inline]
#[sanitize(address = "off")]
unsafe fn memory_is_poisoned_1(addr: usize) -> bool {
    // SAFETY: Caller guarantees `addr` has mapped shadow memory.
    let shadow_val = unsafe { shadow::shadow_byte(addr) } as i8;
    if shadow_val != 0 {
        let last_accessible_byte = (addr & KASAN_GRANULE_MASK) as i8;
        return last_accessible_byte >= shadow_val;
    }
    false
}

/// Checks a 2-, 4-, or 8-byte access at `addr`, mirroring Linux's
/// `memory_is_poisoned_2_4_8`.
///
/// # Safety
///
/// `size` must be `2`, `4`, or `8`, and `[addr .. addr + size)` must satisfy
/// [`addr_has_metadata`] without overflowing.
#[inline]
#[sanitize(address = "off")]
unsafe fn memory_is_poisoned_2_4_8(addr: usize, size: usize) -> bool {
    let last_addr = addr + size - 1;
    // Access crosses an 8-byte granule boundary when the last byte's offset is
    // smaller than `size - 1`. In that case the first granule must be fully
    // unpoisoned (0x00) and the last byte of the second granule must be valid.
    if (last_addr & KASAN_GRANULE_MASK) < size - 1 {
        // SAFETY: Caller guarantees the full range has mapped shadow memory.
        let first_shadow = unsafe { shadow::shadow_byte(addr) };
        if first_shadow != KASAN_SHADOW_INIT {
            return true;
        }
        // SAFETY: Caller guarantees `last_addr` has mapped shadow memory.
        return unsafe { memory_is_poisoned_1(last_addr) };
    }
    // Within a single granule, accessible bytes are always a prefix `[0..s)`,
    // so the access is valid iff its last byte is accessible.
    // SAFETY: Caller guarantees `last_addr` has mapped shadow memory.
    unsafe { memory_is_poisoned_1(last_addr) }
}

/// Checks a 16-byte access at `addr`, mirroring Linux's `memory_is_poisoned_16`.
///
/// # Safety
///
/// `[addr .. addr + 16)` must satisfy [`addr_has_metadata`] and not overflow.
#[inline]
#[sanitize(address = "off")]
unsafe fn memory_is_poisoned_16(addr: usize) -> bool {
    let shadow_ptr = mem_to_shadow(addr) as *const u16;
    if (addr & KASAN_GRANULE_MASK) == 0 {
        // SAFETY: 8-byte aligned kernel address covers two contiguous shadow bytes.
        return unsafe { shadow_ptr.read_unaligned() } != 0;
    }
    // Unaligned 16-byte access spans 3 granules: the first two must be 0x00,
    // and the last byte in the third granule must be accessible.
    // SAFETY: All three shadow bytes lie within mapped shadow memory.
    unsafe { shadow_ptr.read_unaligned() != 0 || memory_is_poisoned_1(addr + 15) }
}

/// Scans `[start .. end)` byte-by-byte for any non-zero shadow byte.
///
/// # Safety
///
/// `[start .. end)` must point to mapped shadow memory.
#[inline]
#[sanitize(address = "off")]
unsafe fn bytes_is_nonzero(mut start: usize, end: usize) -> bool {
    while start < end {
        // SAFETY: Caller guarantees `[start .. end)` is mapped shadow memory.
        if unsafe { *(start as *const u8) } != 0 {
            return true;
        }
        start += 1;
    }
    false
}

/// Scans `[start .. end)` word-by-word for any non-zero shadow byte.
///
/// Mirrors Linux's `memory_is_nonzero` in `mm/kasan/generic.c`.
///
/// # Safety
///
/// `[start .. end)` must point to mapped shadow memory.
#[inline]
#[sanitize(address = "off")]
unsafe fn memory_is_nonzero(start: usize, end: usize) -> bool {
    let mut cur = start;

    let prefix = end - cur;
    if prefix < size_of::<u64>() {
        // SAFETY: `[cur .. end)` is a subrange of `[start .. end)`.
        return unsafe { bytes_is_nonzero(cur, end) };
    }

    let aligned_start = align_up(cur, size_of::<u64>());
    if cur < aligned_start {
        // SAFETY: `[cur .. aligned_start)` is within `[start .. end)`.
        if unsafe { bytes_is_nonzero(cur, aligned_start) } {
            return true;
        }
        cur = aligned_start;
    }

    let words = (end - cur) / size_of::<u64>();
    let mut i = 0;
    while i < words {
        // SAFETY: `cur` is 8-byte aligned and `[cur .. cur + words * 8)` is
        // within `[start .. end)`.
        if unsafe { *((cur + i * size_of::<u64>()) as *const u64) } != 0 {
            return true;
        }
        i += 1;
    }
    cur += words * size_of::<u64>();

    if cur < end {
        // SAFETY: `[cur .. end)` is within `[start .. end)`.
        return unsafe { bytes_is_nonzero(cur, end) };
    }
    false
}

/// Checks an arbitrary `size`-byte access at `addr`, mirroring Linux's
/// `memory_is_poisoned_n`.
///
/// # Safety
///
/// `size > 0`, `addr + size` must not overflow, and `[addr .. addr + size)`
/// must satisfy [`addr_has_metadata`].
#[inline]
#[sanitize(address = "off")]
unsafe fn memory_is_poisoned_n(addr: usize, size: usize) -> bool {
    let shadow_first = mem_to_shadow(addr);
    let last_addr = addr + size - 1;
    let shadow_last = mem_to_shadow(last_addr);

    if shadow_first == shadow_last {
        // SAFETY: Single granule within mapped shadow.
        return unsafe { memory_is_poisoned_1(last_addr) };
    }

    // All granules strictly before `shadow_last` must be completely unpoisoned
    // (0x00) because the access reaches past byte 7 of each of them.
    // SAFETY: `[shadow_first .. shadow_last)` lies in mapped shadow memory.
    if unsafe { memory_is_nonzero(shadow_first, shadow_last) } {
        return true;
    }

    // SAFETY: `last_addr` lies in mapped shadow memory.
    unsafe { memory_is_poisoned_1(last_addr) }
}

/// Returns whether `[addr .. addr + size)` contains any poisoned byte.
///
/// # Safety
///
/// `size > 0`, `addr + size` must not overflow, and `addr` must satisfy
/// [`addr_has_metadata`].
#[inline]
#[sanitize(address = "off")]
pub(super) unsafe fn memory_is_poisoned(addr: usize, size: usize) -> bool {
    // SAFETY: Preconditions are upheld by the caller.
    unsafe {
        match size {
            1 => memory_is_poisoned_1(addr),
            2 | 4 | 8 => memory_is_poisoned_2_4_8(addr, size),
            16 => memory_is_poisoned_16(addr),
            _ => memory_is_poisoned_n(addr, size),
        }
    }
}

/// Validates a memory access of `size` bytes at `addr`, reporting on violation.
///
/// Mirrors Linux's `check_region_inline()` in `mm/kasan/generic.c`.
#[inline]
#[sanitize(address = "off")]
pub(super) fn check_region_inline(addr: usize, size: usize, access: AccessType, pc: usize) {
    if size == 0 || !is_enabled() {
        return;
    }
    if addr > usize::MAX - size || !addr_has_metadata(addr) {
        report::report_access_error(addr, size, access, pc);
    }
    // SAFETY: `size > 0`, `addr + size` does not overflow, and `addr` satisfies
    // `addr_has_metadata`.
    if unsafe { memory_is_poisoned(addr, size) } {
        report::report_access_error(addr, size, access, pc);
    }
}

#[sanitize(address = "off")]
extern "C" fn handle_load_1(addr: usize, pc: usize) {
    check_region_inline(addr, 1, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_2(addr: usize, pc: usize) {
    check_region_inline(addr, 2, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_4(addr: usize, pc: usize) {
    check_region_inline(addr, 4, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_8(addr: usize, pc: usize) {
    check_region_inline(addr, 8, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_16(addr: usize, pc: usize) {
    check_region_inline(addr, 16, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_n(addr: usize, size: usize, pc: usize) {
    check_region_inline(addr, size, AccessType::Read, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_store_1(addr: usize, pc: usize) {
    check_region_inline(addr, 1, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_2(addr: usize, pc: usize) {
    check_region_inline(addr, 2, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_4(addr: usize, pc: usize) {
    check_region_inline(addr, 4, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_8(addr: usize, pc: usize) {
    check_region_inline(addr, 8, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_16(addr: usize, pc: usize) {
    check_region_inline(addr, 16, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_n(addr: usize, size: usize, pc: usize) {
    check_region_inline(addr, size, AccessType::Write, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_report_load_1(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 1, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_2(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 2, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_4(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 4, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_8(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 8, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_16(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 16, AccessType::Read, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_n(addr: usize, size: usize, pc: usize) -> ! {
    report::report_access_error(addr, size, AccessType::Read, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_report_store_1(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 1, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_2(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 2, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_4(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 4, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_8(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 8, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_16(addr: usize, pc: usize) -> ! {
    report::report_access_error(addr, 16, AccessType::Write, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_n(addr: usize, size: usize, pc: usize) -> ! {
    report::report_access_error(addr, size, AccessType::Write, pc);
}

/// Provides the no-op runtime hook emitted before diverging calls.
// SAFETY: Symbol matches the LLVM KernelAddressSanitizer runtime ABI.
#[sanitize(address = "off")]
#[unsafe(no_mangle)]
extern "C" fn __asan_handle_no_return() {}

/// Poisons redzones around a dynamic stack allocation (`alloca`), mirroring
/// Linux's `__asan_alloca_poison`.
// SAFETY: Symbol matches the LLVM KernelAddressSanitizer runtime ABI.
#[sanitize(address = "off")]
#[unsafe(no_mangle)]
extern "C" fn __asan_alloca_poison(addr: usize, size: usize) {
    if size == 0 {
        return;
    }
    let Some(rounded_up_size) = checked_align_up(size, KASAN_GRANULE_SIZE) else {
        return;
    };
    let Some(aligned_redzone_size) = checked_align_up(size, KASAN_ALLOCA_REDZONE_SIZE) else {
        return;
    };
    let padding_size = aligned_redzone_size - rounded_up_size;
    let rounded_down_size = align_down(size, KASAN_GRANULE_SIZE);

    let Some(left_redzone) = addr.checked_sub(KASAN_ALLOCA_REDZONE_SIZE) else {
        return;
    };
    let Some(tail_addr) = addr.checked_add(rounded_down_size) else {
        return;
    };
    let Some(right_redzone) = addr.checked_add(rounded_up_size) else {
        return;
    };
    let Some(right_len) = padding_size.checked_add(KASAN_ALLOCA_REDZONE_SIZE) else {
        return;
    };

    shadow::kasan_unpoison(tail_addr, size - rounded_down_size);
    shadow::kasan_poison(left_redzone, KASAN_ALLOCA_REDZONE_SIZE, KASAN_ALLOCA_LEFT);
    shadow::kasan_poison(right_redzone, right_len, KASAN_ALLOCA_RIGHT);
}

/// Unpoisons dynamic stack allocations on scope exit, mirroring Linux's
/// `__asan_allocas_unpoison`.
// SAFETY: Symbol matches the LLVM KernelAddressSanitizer runtime ABI.
#[sanitize(address = "off")]
#[unsafe(no_mangle)]
extern "C" fn __asan_allocas_unpoison(stack_top: usize, stack_bottom: usize) {
    if stack_top == 0 || stack_top > stack_bottom {
        return;
    }
    let aligned_top = align_down(stack_top, KASAN_GRANULE_SIZE);
    let Some(aligned_bottom) = checked_align_up(stack_bottom, KASAN_GRANULE_SIZE) else {
        return;
    };
    let len = aligned_bottom - aligned_top;
    shadow::kasan_poison(aligned_top, len, KASAN_SHADOW_INIT);
}

// Each naked thunk captures the caller PC from `[rsp]` into the next unused
// SysV AMD64 argument register and tail-jumps to the Rust handler, keeping the
// `16n + 8` stack alignment invariant on entry.
macro_rules! kasan_thunk_1 {
    ($sym:ident, $target:path) => {
        // SAFETY: Symbol matches the LLVM KernelAddressSanitizer runtime ABI.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rsi, [rsp]", "jmp {}", sym $target);
        }
    };
}

macro_rules! kasan_thunk_2 {
    ($sym:ident, $target:path) => {
        // SAFETY: Symbol matches the LLVM KernelAddressSanitizer runtime ABI.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rdx, [rsp]", "jmp {}", sym $target);
        }
    };
}

kasan_thunk_1!(__asan_load1, handle_load_1);
kasan_thunk_1!(__asan_load2, handle_load_2);
kasan_thunk_1!(__asan_load4, handle_load_4);
kasan_thunk_1!(__asan_load8, handle_load_8);
kasan_thunk_1!(__asan_load16, handle_load_16);
kasan_thunk_2!(__asan_loadN, handle_load_n);

kasan_thunk_1!(__asan_load1_noabort, handle_load_1);
kasan_thunk_1!(__asan_load2_noabort, handle_load_2);
kasan_thunk_1!(__asan_load4_noabort, handle_load_4);
kasan_thunk_1!(__asan_load8_noabort, handle_load_8);
kasan_thunk_1!(__asan_load16_noabort, handle_load_16);
kasan_thunk_2!(__asan_loadN_noabort, handle_load_n);

kasan_thunk_1!(__asan_store1, handle_store_1);
kasan_thunk_1!(__asan_store2, handle_store_2);
kasan_thunk_1!(__asan_store4, handle_store_4);
kasan_thunk_1!(__asan_store8, handle_store_8);
kasan_thunk_1!(__asan_store16, handle_store_16);
kasan_thunk_2!(__asan_storeN, handle_store_n);

kasan_thunk_1!(__asan_store1_noabort, handle_store_1);
kasan_thunk_1!(__asan_store2_noabort, handle_store_2);
kasan_thunk_1!(__asan_store4_noabort, handle_store_4);
kasan_thunk_1!(__asan_store8_noabort, handle_store_8);
kasan_thunk_1!(__asan_store16_noabort, handle_store_16);
kasan_thunk_2!(__asan_storeN_noabort, handle_store_n);

kasan_thunk_1!(__asan_report_load1, handle_report_load_1);
kasan_thunk_1!(__asan_report_load2, handle_report_load_2);
kasan_thunk_1!(__asan_report_load4, handle_report_load_4);
kasan_thunk_1!(__asan_report_load8, handle_report_load_8);
kasan_thunk_1!(__asan_report_load16, handle_report_load_16);
kasan_thunk_2!(__asan_report_load_n, handle_report_load_n);

kasan_thunk_1!(__asan_report_load1_noabort, handle_report_load_1);
kasan_thunk_1!(__asan_report_load2_noabort, handle_report_load_2);
kasan_thunk_1!(__asan_report_load4_noabort, handle_report_load_4);
kasan_thunk_1!(__asan_report_load8_noabort, handle_report_load_8);
kasan_thunk_1!(__asan_report_load16_noabort, handle_report_load_16);
kasan_thunk_2!(__asan_report_load_n_noabort, handle_report_load_n);

kasan_thunk_1!(__asan_report_store1, handle_report_store_1);
kasan_thunk_1!(__asan_report_store2, handle_report_store_2);
kasan_thunk_1!(__asan_report_store4, handle_report_store_4);
kasan_thunk_1!(__asan_report_store8, handle_report_store_8);
kasan_thunk_1!(__asan_report_store16, handle_report_store_16);
kasan_thunk_2!(__asan_report_store_n, handle_report_store_n);

kasan_thunk_1!(__asan_report_store1_noabort, handle_report_store_1);
kasan_thunk_1!(__asan_report_store2_noabort, handle_report_store_2);
kasan_thunk_1!(__asan_report_store4_noabort, handle_report_store_4);
kasan_thunk_1!(__asan_report_store8_noabort, handle_report_store_8);
kasan_thunk_1!(__asan_report_store16_noabort, handle_report_store_16);
kasan_thunk_2!(__asan_report_store_n_noabort, handle_report_store_n);
