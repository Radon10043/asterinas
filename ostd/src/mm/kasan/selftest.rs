// SPDX-License-Identifier: MPL-2.0

//! Boot-time KASAN diagnostic selftests triggered via `kasan_selftest=<mode>`.
//!
//! Mirrors Linux's KASAN runtime tests (`mm/kasan/kasan_test.c`): provides a
//! non-fatal `shadow` sanity check and intentional memory-corruption triggers
//! (`oob`, `partial`, `uaf`, `df`, `page-uaf`) that verify end-to-end LLVM
//! instrumentation, violation classification, and emergency serial reporting.

#[cfg(sanitize = "address")]
use alloc::boxed::Box;
use core::{alloc::Layout, hint};

use super::{
    KASAN_GRANULE_SIZE, KASAN_PAGE_FREE, KASAN_PAGE_REDZONE, KASAN_SHADOW_INIT, KASAN_SLAB_FREE,
    KASAN_SLAB_REDZONE, align_up, is_enabled, shadow,
};
use crate::mm::{FrameAllocOptions, HasPaddr, PAGE_SIZE, paddr_to_vaddr};

/// Runs the requested boot-time KASAN selftest `mode`.
///
/// Supported modes:
/// - `"shadow"`: non-fatal check of shadow translation, heap redzones,
///   quarantine poisoning, and freed-frame poisoning.
/// - `"oob"`: triggers a slab right out-of-bounds write (requires `-Zsanitizer=kernel-address`).
/// - `"partial"`: triggers a partial-granule out-of-bounds write (requires `-Zsanitizer=kernel-address`).
/// - `"uaf"`: triggers a heap slab use-after-free read (requires `-Zsanitizer=kernel-address`).
/// - `"df"`: triggers a heap double-free.
/// - `"page-uaf"`: triggers a freed physical page use-after-free read (requires `-Zsanitizer=kernel-address`).
///
/// # Panics
///
/// Panics if KASAN is not enabled yet, or if an instrumentation-dependent mode
/// is invoked in a build compiled without `-Zsanitizer=kernel-address`.
pub fn run(mode: &str) {
    assert!(
        is_enabled(),
        "KASAN must be enabled before running selftests"
    );
    crate::early_println!("[kasan-selftest] running mode: {}", mode);
    match mode {
        "shadow" => run_shadow_check(),
        "oob" => run_instrumented_trigger("oob", trigger_slab_oob),
        "partial" => run_instrumented_trigger("partial", trigger_partial_granule_oob),
        "uaf" => run_instrumented_trigger("uaf", trigger_slab_uaf),
        "df" => trigger_double_free(),
        "page-uaf" => run_instrumented_trigger("page-uaf", trigger_page_uaf),
        other => {
            crate::early_println!("[kasan-selftest] unknown mode: {}", other);
        }
    }
}

#[cfg(sanitize = "address")]
fn run_instrumented_trigger(_mode: &str, trigger: fn()) {
    trigger();
}

#[cfg(not(sanitize = "address"))]
fn run_instrumented_trigger(mode: &str, _trigger: fn()) {
    panic!(
        "kasan_selftest={mode} requires compiling with -Zsanitizer=kernel-address (build with `KASAN=1`)"
    );
}

#[inline(never)]
fn run_shadow_check() {
    // Verify slab redzone and partial-granule shadow encoding.
    let layout = Layout::from_size_align(13, 8).unwrap();
    // SAFETY: Standard heap allocation and shadow inspection.
    unsafe {
        let ptr = alloc::alloc::alloc(layout);
        assert!(!ptr.is_null());
        let addr = ptr as usize;
        assert_eq!(
            shadow::shadow_byte(addr - KASAN_GRANULE_SIZE),
            KASAN_SLAB_REDZONE
        );
        assert_eq!(shadow::shadow_byte(addr), KASAN_SHADOW_INIT);
        assert_eq!(shadow::shadow_byte(addr + 8), 5);
        assert_eq!(
            shadow::shadow_byte(align_up(addr + 13, KASAN_GRANULE_SIZE)),
            KASAN_SLAB_REDZONE
        );
        alloc::alloc::dealloc(ptr, layout);
        assert_eq!(shadow::shadow_byte(addr), KASAN_SLAB_FREE);
    }

    // Verify page-backed large allocation redzone encoding.
    let large_layout = Layout::from_size_align(4096, 8).unwrap();
    // SAFETY: Standard heap allocation and shadow inspection.
    unsafe {
        let ptr = alloc::alloc::alloc(large_layout);
        assert!(!ptr.is_null());
        let addr = ptr as usize;
        assert_eq!(
            shadow::shadow_byte(addr - KASAN_GRANULE_SIZE),
            KASAN_PAGE_REDZONE
        );
        assert_eq!(shadow::shadow_byte(addr + 4096), KASAN_PAGE_REDZONE);
        alloc::alloc::dealloc(ptr, large_layout);
    }

    // Verify physical frame free poisoning (`KASAN_PAGE_FREE`).
    let frame = FrameAllocOptions::new().alloc_frame().unwrap();
    let frame_vaddr = paddr_to_vaddr(frame.paddr());
    // SAFETY: Live physical frame linear mapping is backed by writable shadow.
    assert_eq!(
        unsafe { shadow::shadow_byte(frame_vaddr) },
        KASAN_SHADOW_INIT
    );
    drop(frame);
    // SAFETY: Freed physical frame shadow remains mapped and writable.
    assert_eq!(unsafe { shadow::shadow_byte(frame_vaddr) }, KASAN_PAGE_FREE);
    assert_eq!(
        // SAFETY: Last granule of the freed frame has writable shadow.
        unsafe { shadow::shadow_byte(frame_vaddr + PAGE_SIZE - KASAN_GRANULE_SIZE) },
        KASAN_PAGE_FREE
    );

    crate::early_println!("[kasan-selftest] shadow: PASS");
}

// The trigger functions below intentionally omit `#[sanitize(address = "off")]`
// so LLVM instrumentation detects the bug and invokes the KASAN runtime.
// They are only executed when `cfg(sanitize = "address")` holds.

#[cfg(sanitize = "address")]
#[inline(never)]
fn trigger_slab_oob() {
    let mut buf = Box::new([0u8; 16]);
    let ptr = hint::black_box(buf.as_mut_ptr());
    // SAFETY: Intentional out-of-bounds write into the right slab redzone to
    // verify KASAN detection; LLVM emits `__asan_store1`, which aborts before
    // the store executes.
    unsafe {
        *ptr.add(16) = 0xAA;
    }
    hint::black_box(buf);
}

#[cfg(not(sanitize = "address"))]
fn trigger_slab_oob() {}

#[cfg(sanitize = "address")]
#[inline(never)]
fn trigger_partial_granule_oob() {
    let layout = Layout::from_size_align(13, 8).unwrap();
    // SAFETY: Intentional 1-byte write at offset 13 (inside partial granule
    // with shadow value 5) to verify KASAN partial-granule detection; LLVM
    // emits `__asan_store1`, which aborts before the store executes.
    unsafe {
        let ptr = hint::black_box(alloc::alloc::alloc(layout));
        assert!(!ptr.is_null());
        *ptr.add(13) = 0xBB;
        alloc::alloc::dealloc(ptr, layout);
    }
}

#[cfg(not(sanitize = "address"))]
fn trigger_partial_granule_oob() {}

#[cfg(sanitize = "address")]
#[inline(never)]
fn trigger_slab_uaf() {
    let buf = Box::new([0x42u8; 64]);
    let dangling = hint::black_box(buf.as_ptr());
    drop(buf);
    // SAFETY: Intentional use-after-free read from a quarantined heap object
    // to verify KASAN detection; LLVM emits `__asan_load1`, which aborts before
    // the load executes.
    let val = unsafe { *dangling };
    hint::black_box(val);
}

#[cfg(not(sanitize = "address"))]
fn trigger_slab_uaf() {}

#[inline(never)]
fn trigger_double_free() {
    let layout = Layout::from_size_align(64, 8).unwrap();
    // SAFETY: Intentional double-free to verify `validate_heap_free` detection;
    // the second `dealloc` aborts inside KASAN before touching the allocator.
    unsafe {
        let ptr = hint::black_box(alloc::alloc::alloc(layout));
        assert!(!ptr.is_null());
        alloc::alloc::dealloc(ptr, layout);
        alloc::alloc::dealloc(ptr, layout);
    }
}

#[cfg(sanitize = "address")]
#[inline(never)]
fn trigger_page_uaf() {
    let frame = FrameAllocOptions::new().alloc_frame().unwrap();
    let dangling = hint::black_box(paddr_to_vaddr(frame.paddr()) as *const u8);
    drop(frame);
    // SAFETY: Intentional use-after-free read from a freed physical frame
    // poisoned with `KASAN_PAGE_FREE` to verify KASAN detection; LLVM emits
    // `__asan_load1`, which aborts before the load executes.
    let val = unsafe { *dangling };
    hint::black_box(val);
}

#[cfg(not(sanitize = "address"))]
fn trigger_page_uaf() {}
