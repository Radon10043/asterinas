// SPDX-License-Identifier: MPL-2.0

//! KASAN shadow memory poisoning and memory-intrinsic interceptors.
//!
//! Mirrors Linux's `mm/kasan/shadow.c`.

use core::ffi::c_void;

use super::{
    AccessType, KASAN_GRANULE_MASK, KASAN_SHADOW_INIT, KASAN_SHADOW_SCALE_SHIFT, addr_has_metadata,
    generic, init, is_enabled, mem_to_shadow,
};

unsafe extern "C" {
    #[link_name = "memcpy"]
    fn raw_memcpy(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    #[link_name = "memmove"]
    fn raw_memmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    #[link_name = "memset"]
    fn raw_memset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void;
}

/// Reads the shadow byte corresponding to `addr`.
///
/// # Safety
///
/// `addr` must satisfy [`addr_has_metadata`], guaranteeing that
/// `mem_to_shadow(addr)` is mapped in the kernel page table.
#[inline]
#[sanitize(address = "off")]
pub(super) unsafe fn shadow_byte(addr: usize) -> u8 {
    debug_assert!(addr_has_metadata(addr));
    // SAFETY: Caller guarantees `addr` has mapped shadow memory.
    unsafe { *(mem_to_shadow(addr) as *const u8) }
}

/// Fills the shadow bytes covering `[addr .. addr + len)` with `tag`.
///
/// # Safety
///
/// `addr` and `len` must be aligned to [`super::KASAN_GRANULE_SIZE`], and
/// `[addr .. addr + len)` must lie within writable shadow memory.
#[inline]
#[sanitize(address = "off")]
pub(super) unsafe fn fill_shadow(addr: usize, len: usize, tag: u8) {
    debug_assert!(addr & KASAN_GRANULE_MASK == 0);
    debug_assert!(len & KASAN_GRANULE_MASK == 0);
    if len == 0 {
        return;
    }
    let shadow_ptr = mem_to_shadow(addr) as *mut u8;
    // SAFETY: Caller guarantees `[addr .. addr + len)` is backed by writable shadow.
    unsafe {
        raw_memset(
            shadow_ptr.cast::<c_void>(),
            tag as i32,
            len >> KASAN_SHADOW_SCALE_SHIFT,
        );
    }
}

/// Poisons `[addr .. addr + size)` with `tag`, mirroring Linux's `kasan_poison`.
#[sanitize(address = "off")]
pub(super) fn kasan_poison(addr: usize, size: usize, tag: u8) {
    if !is_enabled() || size == 0 || !init::is_writable_shadow_range(addr, size) {
        return;
    }
    debug_assert!(addr & KASAN_GRANULE_MASK == 0);
    debug_assert!(size & KASAN_GRANULE_MASK == 0);
    // SAFETY: Range was verified to lie within writable shadow memory.
    unsafe { fill_shadow(addr, size, tag) };
}

/// Unpoisons `[addr .. addr + size)`, writing a partial granule byte if `size`
/// is not a multiple of [`super::KASAN_GRANULE_SIZE`].
///
/// Mirrors Linux's `kasan_unpoison`.
#[sanitize(address = "off")]
pub(super) fn kasan_unpoison(addr: usize, size: usize) {
    if !is_enabled() || size == 0 || !init::is_writable_shadow_range(addr, size) {
        return;
    }
    debug_assert!(addr & KASAN_GRANULE_MASK == 0);

    let full_granules = size >> KASAN_SHADOW_SCALE_SHIFT;
    // SAFETY: Range was verified to lie within writable shadow memory.
    unsafe {
        if full_granules > 0 {
            raw_memset(
                mem_to_shadow(addr) as *mut c_void,
                KASAN_SHADOW_INIT as i32,
                full_granules,
            );
        }
        let rem = size & KASAN_GRANULE_MASK;
        if rem != 0 {
            let tail_shadow = mem_to_shadow(addr) + full_granules;
            *(tail_shadow as *mut u8) = rem as u8;
        }
    }
}

#[sanitize(address = "off")]
extern "C" fn handle_memcpy(dst: *mut u8, src: *const u8, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        generic::check_region_inline(src as usize, len, AccessType::Read, pc);
        generic::check_region_inline(dst as usize, len, AccessType::Write, pc);
        // SAFETY: Ranges passed shadow checks and compiler ABI guarantees non-overlap.
        unsafe { raw_memcpy(dst.cast::<c_void>(), src.cast::<c_void>(), len) };
    }
    dst
}

#[sanitize(address = "off")]
extern "C" fn handle_memmove(dst: *mut u8, src: *const u8, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        generic::check_region_inline(src as usize, len, AccessType::Read, pc);
        generic::check_region_inline(dst as usize, len, AccessType::Write, pc);
        // SAFETY: Ranges passed shadow checks and `memmove` handles overlapping buffers.
        unsafe { raw_memmove(dst.cast::<c_void>(), src.cast::<c_void>(), len) };
    }
    dst
}

#[sanitize(address = "off")]
extern "C" fn handle_memset(dst: *mut u8, val: i32, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        generic::check_region_inline(dst as usize, len, AccessType::Write, pc);
        // SAFETY: Range passed shadow checks.
        unsafe { raw_memset(dst.cast::<c_void>(), val, len) };
    }
    dst
}

// Each naked thunk reads the caller return address from `[rsp]` into `rcx`
// (the 4th SysV AMD64 argument) and tail-jumps to the handler while preserving
// the `16n + 8` stack alignment expected upon function entry.
macro_rules! kasan_mem_thunk {
    ($sym:ident, $target:path) => {
        // SAFETY: Symbol matches the LLVM `-asan-kernel-mem-intrinsic-prefix=1` ABI.
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rcx, [rsp]", "jmp {}", sym $target);
        }
    };
}

kasan_mem_thunk!(__asan_memcpy, handle_memcpy);
kasan_mem_thunk!(__asan_memmove, handle_memmove);
kasan_mem_thunk!(__asan_memset, handle_memset);
