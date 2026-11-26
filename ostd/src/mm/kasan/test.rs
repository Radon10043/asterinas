// SPDX-License-Identifier: MPL-2.0

//! Kernel-mode unit tests for KASAN shadow checks, heap redzones, quarantine,
//! and frame poisoning.

use alloc::boxed::Box;
use core::alloc::Layout;

use super::{
    KASAN_GRANULE_SIZE, KASAN_PAGE_FREE, KASAN_PAGE_REDZONE, KASAN_SHADOW_END, KASAN_SHADOW_INIT,
    KASAN_SHADOW_START, KASAN_SLAB_FREE, KASAN_SLAB_REDZONE, addr_has_metadata, align_up, generic,
    init, is_enabled, mem_to_shadow, quarantine, report, shadow, shadow_to_mem,
};
use crate::{
    mm::{FrameAllocOptions, HasPaddr, PAGE_SIZE, kspace, paddr_to_vaddr},
    prelude::ktest,
};

#[ktest]
fn shadow_address_translation() {
    assert!(is_enabled());

    assert!(!addr_has_metadata(0));
    assert!(!addr_has_metadata(0x0000_7fff_ffff_f000));
    assert!(!addr_has_metadata(0x8000_0000_0000_0000));
    assert!(addr_has_metadata(kspace::KERNEL_BASE_VADDR));
    assert!(addr_has_metadata(kspace::FRAME_METADATA_RANGE.start));
    assert!(addr_has_metadata(kspace::KERNEL_CODE_BASE_VADDR));

    for addr in [
        kspace::KERNEL_BASE_VADDR,
        kspace::KERNEL_BASE_VADDR + 0x1234_5678,
        kspace::FRAME_METADATA_RANGE.start + 0x1000,
        kspace::KERNEL_CODE_BASE_VADDR + 0x2000,
    ] {
        let shadow_addr = mem_to_shadow(addr);
        assert!((KASAN_SHADOW_START..KASAN_SHADOW_END).contains(&shadow_addr));
        assert_eq!(shadow_to_mem(shadow_addr), addr & !(KASAN_GRANULE_SIZE - 1));
    }

    assert!(!init::is_writable_shadow_range(0, 8));
    assert!(!init::is_writable_shadow_range(
        kspace::KERNEL_BASE_VADDR,
        0
    ));
    assert!(!init::is_writable_shadow_range(usize::MAX - 4, 16));
}

#[ktest]
fn poison_and_check_primitives() {
    // Allocate a 128-byte buffer (16 granules) so word-aligned scans in
    // `memory_is_nonzero` (>= 8 shadow bytes = 64 kernel bytes) are exercised.
    let buf = Box::new([0u8; 128]);
    let base = buf.as_ptr() as usize;
    assert!(init::is_writable_shadow_range(base, 128));

    // Freshly allocated buffer is completely unpoisoned across all check sizes.
    for size in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        // SAFETY: `[base .. base + size)` lies inside the allocated buffer.
        assert!(!unsafe { generic::memory_is_poisoned(base, size) });
    }

    // Poison the entire 128-byte buffer and unpoison an odd-length 75-byte prefix
    // (9 full granules = 72 bytes, plus 3 accessible bytes in granule 9).
    shadow::kasan_poison(base, 128, KASAN_SLAB_REDZONE);
    shadow::kasan_unpoison(base, 75);

    // SAFETY: All queried addresses lie inside the allocated buffer.
    unsafe {
        assert_eq!(shadow::shadow_byte(base), KASAN_SHADOW_INIT);
        assert_eq!(shadow::shadow_byte(base + 72), 3);
        assert_eq!(shadow::shadow_byte(base + 80), KASAN_SLAB_REDZONE);

        // Single-byte and small accesses inside the 75-byte valid prefix pass.
        assert!(!generic::memory_is_poisoned(base, 1));
        assert!(!generic::memory_is_poisoned(base + 74, 1));
        assert!(!generic::memory_is_poisoned(base + 72, 2));
        assert!(!generic::memory_is_poisoned(base + 71, 4));
        assert!(!generic::memory_is_poisoned(base + 67, 8));
        assert!(!generic::memory_is_poisoned(base + 59, 16));
        assert!(!generic::memory_is_poisoned(base, 75));

        // Accesses touching byte 75 (just past the partial granule) fail.
        assert!(generic::memory_is_poisoned(base + 75, 1));
        assert!(generic::memory_is_poisoned(base + 74, 2));
        assert!(generic::memory_is_poisoned(base + 72, 4));
        assert!(generic::memory_is_poisoned(base + 68, 8));
        assert!(generic::memory_is_poisoned(base + 60, 16));
        assert!(generic::memory_is_poisoned(base, 76));
        assert!(generic::memory_is_poisoned(base, 128));
    }

    // `find_first_bad_addr` must pinpoint the exact first inaccessible byte.
    assert_eq!(report::find_first_bad_addr(base, 76), base + 75);
    assert_eq!(report::find_first_bad_addr(base + 72, 8), base + 75);
    assert_eq!(report::find_first_bad_addr(base + 80, 16), base + 80);

    // Restore clean shadow before dropping `buf`.
    shadow::kasan_unpoison(base, 128);
    drop(buf);
}

#[ktest]
fn heap_redzones_and_layouts() {
    // Exercise slab allocations of varied sizes (including partial granules) and alignments.
    let slab_cases: &[(usize, usize)] = &[
        (1, 1),
        (3, 1),
        (7, 1),
        (8, 8),
        (9, 1),
        (13, 1),
        (16, 16),
        (33, 8),
        (64, 64),
        (500, 16),
    ];

    for &(size, align) in slab_cases {
        let layout = Layout::from_size_align(size, align).unwrap();
        // SAFETY: `layout` has non-zero size.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        assert!(!ptr.is_null());
        let addr = ptr as usize;
        assert_eq!(addr % align, 0);

        // SAFETY: Redzone bytes immediately flanking a live heap allocation lie
        // inside the same writable-shadow heap slot.
        unsafe {
            assert_eq!(
                shadow::shadow_byte(addr - KASAN_GRANULE_SIZE),
                KASAN_SLAB_REDZONE
            );
            assert!(!generic::memory_is_poisoned(addr, size));
            if !size.is_multiple_of(KASAN_GRANULE_SIZE) {
                assert_eq!(
                    shadow::shadow_byte(addr + (size & !(KASAN_GRANULE_SIZE - 1))),
                    (size % KASAN_GRANULE_SIZE) as u8
                );
                assert!(generic::memory_is_poisoned(addr + size, 1));
            }
            let right_rz = align_up(addr + size, KASAN_GRANULE_SIZE);
            assert_eq!(shadow::shadow_byte(right_rz), KASAN_SLAB_REDZONE);

            // Verify valid user payload bytes are writable and readable.
            core::ptr::write_bytes(ptr, 0x5A, size);
            assert_eq!(*ptr, 0x5A);
            assert_eq!(*ptr.add(size - 1), 0x5A);
            alloc::alloc::dealloc(ptr, layout);
        }
    }

    // Exercise page-backed `LargeSlot` allocations (tagged with `KASAN_PAGE_REDZONE`).
    let large_cases: &[(usize, usize)] = &[(3000, 8), (4096, 16), (4099, 8), (4096, PAGE_SIZE)];
    for &(size, align) in large_cases {
        let layout = Layout::from_size_align(size, align).unwrap();
        // SAFETY: `layout` has non-zero size.
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        let addr = ptr as usize;
        assert_eq!(addr % align, 0);

        // SAFETY: Flanking redzones and user bytes lie within the allocated large slot.
        unsafe {
            assert_eq!(
                shadow::shadow_byte(addr - KASAN_GRANULE_SIZE),
                KASAN_PAGE_REDZONE
            );
            assert!(!generic::memory_is_poisoned(addr, size));
            assert_eq!(*ptr, 0);
            assert_eq!(*ptr.add(size - 1), 0);
            let right_rz = align_up(addr + size, KASAN_GRANULE_SIZE);
            assert_eq!(shadow::shadow_byte(right_rz), KASAN_PAGE_REDZONE);
            alloc::alloc::dealloc(ptr, layout);
        }
    }

    // Exercise `realloc` growing and shrinking across slab and large size classes.
    let small_layout = Layout::from_size_align(24, 8).unwrap();
    // SAFETY: Standard `alloc` -> `realloc` -> `dealloc` sequence with matching layouts.
    unsafe {
        let p1 = alloc::alloc::alloc(small_layout);
        assert!(!p1.is_null());
        core::ptr::write_bytes(p1, 0xA5, 24);

        let p2 = alloc::alloc::realloc(p1, small_layout, 3000);
        assert!(!p2.is_null());
        assert_eq!(*p2, 0xA5);
        assert_eq!(*p2.add(23), 0xA5);
        assert_eq!(
            shadow::shadow_byte((p2 as usize) - KASAN_GRANULE_SIZE),
            KASAN_PAGE_REDZONE
        );

        let grown_layout = Layout::from_size_align(3000, 8).unwrap();
        let p3 = alloc::alloc::realloc(p2, grown_layout, 13);
        assert!(!p3.is_null());
        assert_eq!(*p3, 0xA5);
        assert_eq!(*p3.add(12), 0xA5);
        assert_eq!(
            shadow::shadow_byte((p3 as usize) - KASAN_GRANULE_SIZE),
            KASAN_SLAB_REDZONE
        );
        assert_eq!(shadow::shadow_byte((p3 as usize) + 8), 5);

        let shrunk_layout = Layout::from_size_align(13, 8).unwrap();
        alloc::alloc::dealloc(p3, shrunk_layout);
    }
}

#[ktest]
fn quarantine_fifo_and_eviction() {
    quarantine::quarantine_drain();
    assert_eq!(quarantine::quarantine_stats(), (0, 0));

    let max_bytes = quarantine::quarantine_max_bytes();
    assert!(max_bytes >= 1024 * 1024);

    // Freeing a small object poisons it with `KASAN_SLAB_FREE` and retains it in quarantine.
    let first = Box::new([0x33u8; 32]);
    let first_addr = first.as_ptr() as usize;
    drop(first);

    // SAFETY: `first_addr` lies in the linear mapping of physical RAM (writable shadow).
    assert_eq!(unsafe { shadow::shadow_byte(first_addr) }, KASAN_SLAB_FREE);
    let (count_after_one, bytes_after_one) = quarantine::quarantine_stats();
    assert!(count_after_one >= 1);
    assert!(bytes_after_one >= 64);

    // Free enough 64 KiB page-backed slots to exceed `max_bytes`, genuinely
    // triggering FIFO byte-budget eviction in `quarantine_put`.
    const CHUNK_SIZE: usize = 64 * 1024;
    let layout = Layout::from_size_align(CHUNK_SIZE, PAGE_SIZE).unwrap();
    let iterations = (max_bytes / CHUNK_SIZE) + 8;
    let mut total_freed = 0usize;
    for _ in 0..iterations {
        // SAFETY: Non-zero page-aligned layout allocated and immediately freed.
        unsafe {
            let ptr = alloc::alloc::alloc(layout);
            assert!(!ptr.is_null());
            alloc::alloc::dealloc(ptr, layout);
        }
        total_freed += CHUNK_SIZE;
    }

    assert!(total_freed > max_bytes);
    let (count_after_eviction, bytes_after_eviction) = quarantine::quarantine_stats();
    assert!(count_after_eviction > 0);
    assert!(bytes_after_eviction <= max_bytes);
    // Confirm eviction actually released older slots rather than accumulating unboundedly.
    assert!(bytes_after_eviction < total_freed);

    quarantine::quarantine_drain();
    assert_eq!(quarantine::quarantine_stats(), (0, 0));
}

#[ktest]
fn frame_allocator_page_poisoning() {
    // Single physical frame: unpoisoned while live, `KASAN_PAGE_FREE` after drop.
    let frame = FrameAllocOptions::new().alloc_frame().unwrap();
    let vaddr = paddr_to_vaddr(frame.paddr());

    // SAFETY: Physical frame linear mapping is backed by writable shadow.
    unsafe {
        assert!(!generic::memory_is_poisoned(vaddr, PAGE_SIZE));
    }

    drop(frame);

    // SAFETY: Freed physical frame shadow remains mapped and writable.
    unsafe {
        for off in (0..PAGE_SIZE).step_by(KASAN_GRANULE_SIZE) {
            assert_eq!(shadow::shadow_byte(vaddr + off), KASAN_PAGE_FREE);
        }
    }

    // Multi-page contiguous segment: all frames unpoisoned while live and
    // poisoned with `KASAN_PAGE_FREE` after drop (including buddy chunk head).
    let seg = FrameAllocOptions::new().alloc_segment(4).unwrap();
    let seg_vaddr = paddr_to_vaddr(seg.paddr());
    let seg_size = 4 * PAGE_SIZE;

    // SAFETY: Physical segment linear mapping is backed by writable shadow.
    unsafe {
        assert!(!generic::memory_is_poisoned(seg_vaddr, seg_size));
    }

    drop(seg);

    // SAFETY: Freed segment shadow remains mapped and writable.
    unsafe {
        for page in 0..4 {
            let page_vaddr = seg_vaddr + page * PAGE_SIZE;
            assert_eq!(shadow::shadow_byte(page_vaddr), KASAN_PAGE_FREE);
            assert_eq!(
                shadow::shadow_byte(page_vaddr + PAGE_SIZE - KASAN_GRANULE_SIZE),
                KASAN_PAGE_FREE
            );
        }
    }
}
