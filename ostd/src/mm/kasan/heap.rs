// SPDX-License-Identifier: MPL-2.0

//! KASAN heap redzones, allocation poisoning, and free validation.
//!
//! Wraps `AllocDispatch` so every heap allocation is flanked by poisoned left
//! and right redzones, every deallocation validates those redzones against
//! double-free and invalid-free errors, and freed slots are poisoned with
//! `KASAN_SLAB_FREE` and deferred through the quarantine ring.

use core::alloc::Layout;

use super::{
    KASAN_GRANULE_SIZE, KASAN_PAGE_FREE, KASAN_PAGE_REDZONE, KASAN_SHADOW_INIT, KASAN_SLAB_FREE,
    KASAN_SLAB_REDZONE, addr_has_metadata, align_up, init, is_enabled, quarantine, report, shadow,
};
use crate::mm::{
    PAGE_SIZE, Vaddr,
    heap::{self, HeapSlot, SlotInfo},
};

/// Minimum left and right redzone size in bytes (2 KASAN granules).
const KASAN_REDZONE_MIN: usize = 16;

/// Returns the left redzone size prepended before a user allocation of `layout`.
///
/// Always a multiple of both [`KASAN_REDZONE_MIN`] and `layout.align()`, so
/// adding it to an aligned slot base preserves `layout.align()`.
#[inline]
#[sanitize(address = "off")]
fn padded_left_redzone(layout: Layout) -> usize {
    layout.align().max(KASAN_REDZONE_MIN)
}

/// Computes the padded allocation layout including left and right KASAN redzones.
///
/// Returns `None` if adding redzone overhead overflows valid [`Layout`] bounds.
#[inline]
#[sanitize(address = "off")]
pub(in crate::mm) fn padded_layout(layout: Layout) -> Option<Layout> {
    let left_rz = padded_left_redzone(layout);
    let total_size = left_rz
        .checked_add(layout.size())?
        .checked_add(KASAN_REDZONE_MIN)?;
    Layout::from_size_align(total_size, left_rz).ok()
}

/// Returns the expected redzone shadow tag for `slot_info`.
#[inline]
#[sanitize(address = "off")]
const fn redzone_tag_for_slot(slot_info: SlotInfo) -> u8 {
    match slot_info {
        SlotInfo::SlabSlot(_) => KASAN_SLAB_REDZONE,
        SlotInfo::LargeSlot(_) => KASAN_PAGE_REDZONE,
    }
}

/// Poisons the redzones of a newly allocated heap slot, unpoisons the exact
/// user region, and returns the user pointer.
#[sanitize(address = "off")]
pub(in crate::mm) fn on_heap_alloc(
    slot_addr: Vaddr,
    slot_size: usize,
    slot_info: SlotInfo,
    layout: Layout,
) -> *mut u8 {
    let left_rz = padded_left_redzone(layout);
    let user_addr = slot_addr + left_rz;

    if is_enabled() {
        let rz_tag = redzone_tag_for_slot(slot_info);
        shadow::kasan_poison(slot_addr, slot_size, rz_tag);
        shadow::kasan_unpoison(user_addr, layout.size());
    }

    user_addr as *mut u8
}

/// Validates a heap deallocation pointer against KASAN shadow state and returns
/// the underlying slot base address.
///
/// Reports `"double-free"` or `"invalid-free"` and aborts if the pointer is
/// misaligned, out of bounds, already freed, or has corrupted redzone shadow.
#[sanitize(address = "off")]
pub(in crate::mm) fn validate_heap_free(
    user_ptr: Vaddr,
    layout: Layout,
    padded: Layout,
    slot_info: SlotInfo,
) -> Vaddr {
    let left_rz = padded_left_redzone(layout);
    let slot_size = slot_info.size();

    if user_ptr < left_rz
        || !addr_has_metadata(user_ptr)
        || !user_ptr.is_multiple_of(layout.align())
    {
        report::report_free_error("invalid-free", user_ptr);
    }

    let slot_addr = user_ptr - left_rz;
    let required_align = match slot_info {
        SlotInfo::SlabSlot(_) => padded.align(),
        SlotInfo::LargeSlot(_) => PAGE_SIZE,
    };
    if !slot_addr.is_multiple_of(required_align) {
        report::report_free_error("invalid-free", user_ptr);
    }

    if !is_enabled() {
        return slot_addr;
    }

    // Every live `HeapSlot` resides in physical RAM's linear mapping, which
    // always has writable shadow once KASAN is enabled.
    if !init::is_writable_shadow_range(slot_addr, slot_size) {
        report::report_free_error("invalid-free", user_ptr);
    }

    let expected_rz = redzone_tag_for_slot(slot_info);

    // SAFETY: `[slot_addr .. slot_addr + slot_size)` is within writable shadow,
    // and `left_rz >= KASAN_REDZONE_MIN >= KASAN_GRANULE_SIZE`.
    let left_shadow = unsafe { shadow::shadow_byte(user_ptr - KASAN_GRANULE_SIZE) };
    if left_shadow == KASAN_SLAB_FREE || left_shadow == KASAN_PAGE_FREE {
        report::report_free_error("double-free", user_ptr);
    }
    if left_shadow != expected_rz {
        report::report_free_error("invalid-free", user_ptr);
    }

    if layout.size() > 0 {
        // SAFETY: `user_ptr` lies inside `[slot_addr .. slot_addr + slot_size)`.
        let first_shadow = unsafe { shadow::shadow_byte(user_ptr) };
        if first_shadow == KASAN_SLAB_FREE || first_shadow == KASAN_PAGE_FREE {
            report::report_free_error("double-free", user_ptr);
        }
        let expected_first = if layout.size() >= KASAN_GRANULE_SIZE {
            KASAN_SHADOW_INIT
        } else {
            layout.size() as u8
        };
        if first_shadow != expected_first {
            report::report_free_error("invalid-free", user_ptr);
        }
    }

    let right_rz_addr = align_up(user_ptr + layout.size(), KASAN_GRANULE_SIZE);
    debug_assert!(right_rz_addr < slot_addr + slot_size);
    // SAFETY: `right_rz_addr` lies inside `[slot_addr .. slot_addr + slot_size)`.
    let right_shadow = unsafe { shadow::shadow_byte(right_rz_addr) };
    if right_shadow == KASAN_SLAB_FREE || right_shadow == KASAN_PAGE_FREE {
        report::report_free_error("double-free", user_ptr);
    }
    if right_shadow != expected_rz {
        report::report_free_error("invalid-free", user_ptr);
    }

    slot_addr
}

/// Poisons a freed heap slot and either places it in quarantine or releases it
/// directly to the underlying allocator.
#[sanitize(address = "off")]
pub(in crate::mm) fn on_heap_free(slot: HeapSlot) {
    if quarantine::should_quarantine(&slot) {
        shadow::kasan_poison(slot.as_ptr() as Vaddr, slot.size(), KASAN_SLAB_FREE);
        quarantine::quarantine_put(slot);
    } else {
        // Oversized `LargeSlot`s return directly to `Frame::drop`, which poisons
        // every page with `KASAN_PAGE_FREE`, avoiding a redundant shadow pass.
        if matches!(slot.info(), SlotInfo::SlabSlot(_)) {
            shadow::kasan_poison(slot.as_ptr() as Vaddr, slot.size(), KASAN_SLAB_FREE);
        }
        heap::dealloc_slot_raw(slot);
    }
}
