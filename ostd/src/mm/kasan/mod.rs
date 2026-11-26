// SPDX-License-Identifier: MPL-2.0

//! Kernel AddressSanitizer (KASAN) shadow memory and runtime support.
//!
//! This module implements Generic KASAN for `x86_64` following the Linux
//! kernel's `mm/kasan/` design:
//!
//! - Every 8-byte kernel granule maps to 1 shadow byte at
//!   `KASAN_SHADOW_OFFSET + (addr >> KASAN_SHADOW_SCALE_SHIFT)`.
//! - Early boot maps the entire 16 TiB shadow window
//!   (`0xffff_ec00_0000_0000..0xffff_fc00_0000_0000`) read-only to a shared
//!   zero page (`bsp_boot.S`), matching Linux's `kasan_early_shadow_page`.
//! - `init_shadow` populates writable zeroed shadow pages (preferring 2 MiB
//!   huge pages) for physical RAM linear mappings, frame metadata, and the
//!   kernel image, and maps all remaining shadow space read-only to a shared
//!   zero page.
//! - Compiler instrumentation (`-Zsanitizer=kernel-address`) invokes the
//!   `__asan_*` hooks in `generic` and `shadow`, which report violations
//!   through `report`.

mod generic;
mod init;
mod report;
mod shadow;

use core::sync::atomic::{AtomicBool, AtomicUsize};

pub(crate) use self::report::is_reporting;
pub(super) use self::{
    init::init_shadow,
    shadow::{poison_pages, unpoison_pages},
};
use crate::{
    const_assert,
    mm::{Vaddr, kspace},
};

/// Direction of a checked memory access.
#[derive(Clone, Copy)]
enum AccessType {
    Read,
    Write,
}

/// Shadow memory mapping offset passed to LLVM `-asan-mapping-offset`.
///
/// Matches Linux x86_64 4-level paging (`KASAN_SHADOW_OFFSET`).
const KASAN_SHADOW_OFFSET: usize = 0xdfff_fc00_0000_0000;

/// Log2 of the KASAN shadow scale (1 shadow byte per 8 kernel bytes).
const KASAN_SHADOW_SCALE_SHIFT: usize = 3;

/// Number of kernel bytes described by a single shadow byte.
const KASAN_GRANULE_SIZE: usize = 1 << KASAN_SHADOW_SCALE_SHIFT;

/// Bitmask for the byte offset within an 8-byte KASAN granule.
const KASAN_GRANULE_MASK: usize = KASAN_GRANULE_SIZE - 1;

/// Start virtual address of the 16 TiB KASAN shadow region (PML4 slot 472).
const KASAN_SHADOW_START: Vaddr = 0xffff_ec00_0000_0000;

/// Exclusive end virtual address of the KASAN shadow region (PML4 slot 504).
const KASAN_SHADOW_END: Vaddr = 0xffff_fc00_0000_0000;

/// Bit shift of the x86_64 PML4 index within a 48-bit virtual address.
const PML4_SHIFT: usize = 39;

/// Mask for a 9-bit x86_64 page-table level index.
const PT_INDEX_MASK: usize = 0x1ff;

/// Top-level (PML4) index range covering [`KASAN_SHADOW_START`]..[`KASAN_SHADOW_END`].
pub(super) const KASAN_SHADOW_PML4_RANGE: core::ops::Range<usize> = 472..504;

// Shadow byte values matching Linux `mm/kasan/kasan.h`.
/// Shadow value for a fully accessible 8-byte granule.
const KASAN_SHADOW_INIT: u8 = 0x00;
/// Shadow value for dynamic stack (`alloca`) left redzones.
const KASAN_ALLOCA_LEFT: u8 = 0xCA;
/// Shadow value for dynamic stack (`alloca`) right redzones.
const KASAN_ALLOCA_RIGHT: u8 = 0xCB;
/// Shadow value for freed slab objects (quarantined or on slab free lists).
const KASAN_SLAB_FREE: u8 = 0xFB;
/// Shadow value for slab object redzones.
const KASAN_SLAB_REDZONE: u8 = 0xFC;
/// Shadow value for page-backed large allocation redzones.
const KASAN_PAGE_REDZONE: u8 = 0xFE;
/// Shadow value for freed physical page frames.
const KASAN_PAGE_FREE: u8 = 0xFF;

// Verify that the 16 TiB KASAN shadow window fits cleanly inside the unused
// hole between frame metadata and the kernel image and covers all high
// canonical kernel addresses.
const_assert!(mem_to_shadow(kspace::KERNEL_BASE_VADDR) == KASAN_SHADOW_START);
const_assert!(mem_to_shadow(usize::MAX) < KASAN_SHADOW_END);
const_assert!(KASAN_SHADOW_START >= kspace::FRAME_METADATA_RANGE.end);
const_assert!(KASAN_SHADOW_END <= kspace::KERNEL_CODE_BASE_VADDR);
const_assert!((KASAN_SHADOW_START >> PML4_SHIFT) & PT_INDEX_MASK == KASAN_SHADOW_PML4_RANGE.start);
const_assert!((KASAN_SHADOW_END >> PML4_SHIFT) & PT_INDEX_MASK == KASAN_SHADOW_PML4_RANGE.end);

static KASAN_ENABLED: AtomicBool = AtomicBool::new(false);

/// Returns whether KASAN shadow validation and poisoning are active.
#[inline]
#[sanitize(address = "off")]
fn is_enabled() -> bool {
    load_bool_acquire(&KASAN_ENABLED)
}

/// Enables KASAN runtime checks after the kernel page table is active.
#[sanitize(address = "off")]
pub(crate) fn enable() {
    store_bool_release(&KASAN_ENABLED, true);
    crate::early_println!("[kasan] KernelAddressSanitizer enabled");
}

/// Disables KASAN runtime checks during fatal error reporting.
#[inline]
#[sanitize(address = "off")]
fn disable_for_report() {
    store_bool_release(&KASAN_ENABLED, false);
}

/// Translates a kernel virtual address to its KASAN shadow byte address.
#[inline]
#[sanitize(address = "off")]
const fn mem_to_shadow(addr: usize) -> usize {
    KASAN_SHADOW_OFFSET.wrapping_add(addr >> KASAN_SHADOW_SCALE_SHIFT)
}

/// Translates a KASAN shadow byte address back to the corresponding kernel address.
#[inline]
#[sanitize(address = "off")]
const fn shadow_to_mem(shadow_addr: usize) -> usize {
    shadow_addr.wrapping_sub(KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT
}

/// Returns whether `addr` lies in the high canonical kernel range backed by shadow memory.
///
/// Mirrors Linux's `addr_has_metadata()`: on x86_64 4-level paging, every high
/// canonical address (`>= KERNEL_BASE_VADDR`) maps into `[KASAN_SHADOW_START, KASAN_SHADOW_END)`.
#[inline]
#[sanitize(address = "off")]
const fn addr_has_metadata(addr: usize) -> bool {
    addr >= kspace::KERNEL_BASE_VADDR
}

#[inline]
#[sanitize(address = "off")]
const fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

#[inline]
#[sanitize(address = "off")]
const fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

#[inline]
#[sanitize(address = "off")]
const fn checked_align_up(addr: usize, align: usize) -> Option<usize> {
    match addr.checked_add(align - 1) {
        Some(v) => Some(v & !(align - 1)),
        None => None,
    }
}

// Direct uninstrumented atomic helpers for KASAN runtime paths.
//
// `ostd` itself is compiled with `-Zsanitizer=kernel-address`, so generic
// `core::sync::atomic` methods monomorphized into `ostd` inherit sanitizer
// instrumentation. Calling them from `#[sanitize(address = "off")]` callbacks
// can re-enter `__asan_load*`/`__asan_store*` and recurse infinitely.

#[inline]
#[sanitize(address = "off")]
fn load_bool_acquire(atom: &AtomicBool) -> bool {
    let val: u8;
    let ptr = atom as *const AtomicBool as *const u8;
    // SAFETY: `AtomicBool` has the layout of `u8`; x86_64 TSO byte loads have
    // Acquire semantics, and omitting `readonly` acts as a compiler barrier.
    unsafe {
        core::arch::asm!(
            "mov {val}, byte ptr [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg_byte) val,
            options(nostack, preserves_flags),
        );
    }
    val != 0
}

#[inline]
#[sanitize(address = "off")]
fn store_bool_release(atom: &AtomicBool, val: bool) {
    let byte = val as u8;
    let ptr = atom as *const AtomicBool as *mut u8;
    // SAFETY: `AtomicBool` has the layout of `u8`; x86_64 TSO byte stores have
    // Release semantics, and omitting `readonly` acts as a compiler barrier.
    unsafe {
        core::arch::asm!(
            "mov byte ptr [{ptr}], {byte}",
            ptr = in(reg) ptr,
            byte = in(reg_byte) byte,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
#[sanitize(address = "off")]
fn load_usize_relaxed(atom: &AtomicUsize) -> usize {
    let val: usize;
    let ptr = atom as *const AtomicUsize as *const usize;
    // SAFETY: `AtomicUsize` has the layout of `usize`; aligned 64-bit loads are
    // atomic on x86_64.
    unsafe {
        core::arch::asm!(
            "mov {val}, [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg) val,
            options(nostack, readonly, preserves_flags),
        );
    }
    val
}

#[inline]
#[sanitize(address = "off")]
fn load_usize_acquire(atom: &AtomicUsize) -> usize {
    let val: usize;
    let ptr = atom as *const AtomicUsize as *const usize;
    // SAFETY: `AtomicUsize` has the layout of `usize`; x86_64 TSO loads have
    // Acquire semantics, and omitting `readonly` acts as a compiler barrier.
    unsafe {
        core::arch::asm!(
            "mov {val}, [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg) val,
            options(nostack, preserves_flags),
        );
    }
    val
}

#[inline]
#[sanitize(address = "off")]
fn store_usize_release(atom: &AtomicUsize, val: usize) {
    let ptr = atom as *const AtomicUsize as *mut usize;
    // SAFETY: `AtomicUsize` has the layout of `usize`; x86_64 TSO stores have
    // Release semantics, and omitting `readonly` acts as a compiler barrier.
    unsafe {
        core::arch::asm!(
            "mov [{ptr}], {val}",
            ptr = in(reg) ptr,
            val = in(reg) val,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
#[sanitize(address = "off")]
fn cmpxchg_usize(atom: &AtomicUsize, current: usize, new: usize) -> Result<usize, usize> {
    let prev: usize;
    let ptr = atom as *const AtomicUsize as *mut usize;
    // SAFETY: `AtomicUsize` has the layout of `usize`; `lock cmpxchg` performs
    // an atomic SeqCst compare-exchange on x86_64.
    unsafe {
        core::arch::asm!(
            "lock cmpxchg [{ptr}], {new}",
            ptr = in(reg) ptr,
            new = in(reg) new,
            inout("rax") current => prev,
            options(nostack),
        );
    }
    if prev == current { Ok(prev) } else { Err(prev) }
}
