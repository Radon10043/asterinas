// SPDX-License-Identifier: MPL-2.0

//! KASAN shadow page table initialization.
//!
//! Mirrors Linux's `arch/x86/mm/kasan_init_64.c`: populates writable zeroed
//! shadow memory (using 2 MiB huge pages where aligned) for active kernel
//! ranges and backs all remaining shadow addresses with a shared read-only
//! zero page.

use core::{ops::Range, sync::atomic::AtomicUsize};

use super::{
    KASAN_SHADOW_PML4_RANGE, align_down, align_up, load_usize_acquire, load_usize_relaxed,
    mem_to_shadow, store_usize_release,
};
use crate::{
    arch::mm::{PageTableEntry, PagingConsts},
    boot::memory_region::MemoryRegionType,
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, Paddr, PageFlags, PageProperty,
        PrivilegedPageFlags, Vaddr,
        kspace::{self, KernelPtConfig, MappedItem},
        nr_subpage_per_huge, paddr_to_vaddr,
        page_prop::PageTableFlags,
        page_size,
        page_table::{PageTable, PteScalar, PteTrait},
    },
    task::DisabledPreemptGuard,
};

const MAX_WRITABLE_SHADOW_RANGES: usize = 64;
const ENTRIES_PER_PT: usize = nr_subpage_per_huge::<PagingConsts>();
const HUGE_PAGE_SIZE: usize = page_size::<PagingConsts>(2);
const PAGES_PER_HUGE_PAGE: usize = HUGE_PAGE_SIZE / PAGE_SIZE;

static WRITABLE_RANGE_COUNT: AtomicUsize = AtomicUsize::new(0);
static WRITABLE_RANGES: [(AtomicUsize, AtomicUsize); MAX_WRITABLE_SHADOW_RANGES] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_WRITABLE_SHADOW_RANGES];

/// Returns whether `[addr .. addr + size)` is backed by writable shadow memory.
///
/// Unpopulated kernel ranges (such as `KVirtArea` or PCI holes) map to the
/// shared read-only zero page, so poisoning and unpoisoning must skip them.
#[inline]
#[sanitize(address = "off")]
pub(super) fn is_writable_shadow_range(addr: usize, size: usize) -> bool {
    if size == 0 || addr > usize::MAX - size {
        return false;
    }
    let end = addr + size;
    let count = load_usize_acquire(&WRITABLE_RANGE_COUNT).min(MAX_WRITABLE_SHADOW_RANGES);
    let mut i = 0;
    while i < count {
        let start = load_usize_relaxed(&WRITABLE_RANGES[i].0);
        let range_end = load_usize_relaxed(&WRITABLE_RANGES[i].1);
        if addr >= start && end <= range_end {
            return true;
        }
        i += 1;
    }
    false
}

#[sanitize(address = "off")]
fn record_writable_range(start: usize, end: usize) {
    if start >= end {
        return;
    }
    let count = load_usize_relaxed(&WRITABLE_RANGE_COUNT);
    if count > 0 {
        let prev_end = load_usize_relaxed(&WRITABLE_RANGES[count - 1].1);
        if start <= prev_end {
            if end > prev_end {
                store_usize_release(&WRITABLE_RANGES[count - 1].1, end);
            }
            return;
        }
    }
    assert!(
        count < MAX_WRITABLE_SHADOW_RANGES,
        "exceeded KASAN writable shadow range capacity"
    );
    store_usize_release(&WRITABLE_RANGES[count].0, start);
    store_usize_release(&WRITABLE_RANGES[count].1, end);
    store_usize_release(&WRITABLE_RANGE_COUNT, count + 1);
}

/// Maps KASAN shadow memory into the kernel page table.
///
/// Populates writable zeroed shadow pages for all physical RAM linear regions,
/// `meta_range`, and `kernel_range`, then maps all remaining absent entries in
/// [`KASAN_SHADOW_PML4_RANGE`] read-only to a shared zero page.
#[sanitize(address = "off")]
pub(in crate::mm) fn init_shadow(
    kpt: &PageTable<KernelPtConfig>,
    preempt_guard: &DisabledPreemptGuard,
    meta_range: Range<Vaddr>,
    kernel_range: Range<Vaddr>,
) {
    let regions = &crate::boot::EARLY_INFO.get().unwrap().memory_regions;
    let mut ranges = [(0usize, 0usize); MAX_WRITABLE_SHADOW_RANGES];
    let mut range_count = 0usize;
    let mut usable_ram_bytes = 0usize;

    // Collect coalesced physical RAM linear ranges so non-RAM holes (such as
    // the PCI MMIO hole below 4 GiB) do not consume writable shadow memory.
    for region in regions.iter().filter(|r| r.typ().is_physical()) {
        if region.typ() == MemoryRegionType::Usable {
            usable_ram_bytes = usable_ram_bytes.saturating_add(region.len());
        }
        let start = kspace::LINEAR_MAPPING_BASE_VADDR + region.base();
        let end = kspace::LINEAR_MAPPING_BASE_VADDR + region.end();
        if start >= end {
            continue;
        }
        if range_count > 0 && start <= ranges[range_count - 1].1 {
            ranges[range_count - 1].1 = ranges[range_count - 1].1.max(end);
        } else {
            assert!(
                range_count < MAX_WRITABLE_SHADOW_RANGES - 2,
                "exceeded KASAN writable shadow range capacity"
            );
            ranges[range_count] = (start, end);
            range_count += 1;
        }
    }

    ranges[range_count] = (meta_range.start, meta_range.end);
    range_count += 1;
    ranges[range_count] = (kernel_range.start, kernel_range.end);
    range_count += 1;

    let rw_prop = PageProperty {
        flags: PageFlags::RW,
        cache: CachePolicy::Writeback,
        priv_flags: PrivilegedPageFlags::GLOBAL,
    };

    let mut last_mapped_shadow_end = 0usize;
    let mut total_shadow_bytes = 0usize;

    for &(raw_start, raw_end) in &ranges[..range_count] {
        if raw_start >= raw_end {
            continue;
        }
        record_writable_range(raw_start, raw_end);

        let shadow_start =
            align_down(mem_to_shadow(raw_start), PAGE_SIZE).max(last_mapped_shadow_end);
        let shadow_end = align_up(mem_to_shadow(raw_end - 1) + 1, PAGE_SIZE);
        if shadow_start >= shadow_end {
            continue;
        }

        populate_writable_shadow(kpt, preempt_guard, shadow_start, shadow_end, rw_prop);
        total_shadow_bytes += shadow_end - shadow_start;
        last_mapped_shadow_end = shadow_end;
    }

    // SAFETY: `kpt` is exclusively owned during `init_kernel_page_table` before
    // activation or publication, and no cursor will later modify the shadow
    // PML4 range.
    unsafe { populate_zero_shadow(kpt.root_paddr()) };

    super::quarantine::configure_from_usable_ram(usable_ram_bytes);

    crate::info!(
        "KASAN shadow initialized ({} KiB writable across {} ranges)",
        total_shadow_bytes / 1024,
        load_usize_relaxed(&WRITABLE_RANGE_COUNT)
    );
}

#[sanitize(address = "off")]
fn populate_writable_shadow(
    kpt: &PageTable<KernelPtConfig>,
    preempt_guard: &DisabledPreemptGuard,
    shadow_start: Vaddr,
    shadow_end: Vaddr,
    prop: PageProperty,
) {
    let mut va = shadow_start;
    while va < shadow_end {
        let remaining_bytes = shadow_end - va;
        if va.is_multiple_of(HUGE_PAGE_SIZE)
            && remaining_bytes >= HUGE_PAGE_SIZE
            && let Ok(segment) = FrameAllocOptions::new()
                .zeroed(true)
                .alloc_segment(PAGES_PER_HUGE_PAGE)
        {
            let chunk_end = va + HUGE_PAGE_SIZE;
            let pa_range = segment.into_raw();
            if pa_range.start.is_multiple_of(HUGE_PAGE_SIZE) {
                let mut cursor = kpt
                    .cursor_mut_with_min_level(preempt_guard, &(va..chunk_end), 2)
                    .unwrap();
                // SAFETY: Mapping a freshly allocated, zeroed 2 MiB KASAN shadow huge page.
                unsafe { cursor.map(MappedItem::Untracked(pa_range.start, 2, prop)) };
            } else {
                let mut cursor = kpt
                    .cursor_mut_with_min_level(preempt_guard, &(va..chunk_end), 1)
                    .unwrap();
                for pa in (pa_range.start..pa_range.end).step_by(PAGE_SIZE) {
                    // SAFETY: Mapping freshly allocated, zeroed KASAN shadow frames.
                    unsafe { cursor.map(MappedItem::Untracked(pa, 1, prop)) };
                }
            }
            va = chunk_end;
            continue;
        }

        let frame = FrameAllocOptions::new().zeroed(true).alloc_frame().unwrap();
        let pa = frame.into_raw();
        let next_va = va + PAGE_SIZE;
        let mut cursor = kpt
            .cursor_mut_with_min_level(preempt_guard, &(va..next_va), 1)
            .unwrap();
        // SAFETY: Mapping a freshly allocated, zeroed KASAN shadow frame.
        unsafe { cursor.map(MappedItem::Untracked(pa, 1, prop)) };
        va = next_va;
    }
}

/// Fills all unmapped entries in [`KASAN_SHADOW_PML4_RANGE`] with a shared
/// read-only zero page hierarchy (`zero_l2 -> zero_l1 -> zero_page`).
///
/// # Safety
///
/// The caller must hold exclusive access to the kernel page table at
/// `root_paddr`, which must outlive the system and never have cursors modify
/// [`KASAN_SHADOW_PML4_RANGE`] afterwards.
#[sanitize(address = "off")]
unsafe fn populate_zero_shadow(root_paddr: Paddr) {
    let ro_prop = PageProperty {
        flags: PageFlags::R,
        cache: CachePolicy::Writeback,
        priv_flags: PrivilegedPageFlags::GLOBAL,
    };

    let zero_page_pa = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_frame()
        .unwrap()
        .into_raw();
    let zero_l1_pa = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_frame()
        .unwrap()
        .into_raw();
    let zero_l2_pa = FrameAllocOptions::new()
        .zeroed(true)
        .alloc_frame()
        .unwrap()
        .into_raw();

    let zero_l1_pte = PageTableEntry::from_repr(&PteScalar::Mapped(zero_page_pa, ro_prop), 1);
    let zero_l2_pte = PageTableEntry::from_repr(
        &PteScalar::PageTable(zero_l1_pa, PageTableFlags::empty()),
        2,
    );
    let zero_l3_pte = PageTableEntry::from_repr(
        &PteScalar::PageTable(zero_l2_pa, PageTableFlags::empty()),
        3,
    );

    let zero_l1_ptr = paddr_to_vaddr(zero_l1_pa) as *mut PageTableEntry;
    let zero_l2_ptr = paddr_to_vaddr(zero_l2_pa) as *mut PageTableEntry;
    for i in 0..ENTRIES_PER_PT {
        // SAFETY: `zero_l1_pa` and `zero_l2_pa` are freshly allocated 4 KiB
        // frames with 512 `PageTableEntry` slots each.
        unsafe {
            *zero_l1_ptr.add(i) = zero_l1_pte;
            *zero_l2_ptr.add(i) = zero_l2_pte;
        }
    }

    let l4_ptr = paddr_to_vaddr(root_paddr) as *mut PageTableEntry;
    for pml4_idx in KASAN_SHADOW_PML4_RANGE {
        // SAFETY: Caller guarantees exclusive access to the valid root PT frame.
        let l4_pte = unsafe { *l4_ptr.add(pml4_idx) };
        let PteScalar::PageTable(l3_pa, _) = l4_pte.to_repr(4) else {
            panic!("KASAN shadow PML4 entry {pml4_idx} is missing its L3 table");
        };

        let l3_ptr = paddr_to_vaddr(l3_pa) as *mut PageTableEntry;
        for l3_idx in 0..ENTRIES_PER_PT {
            // SAFETY: `l3_pa` is a valid L3 page table frame owned by `kpt`.
            let l3_entry = unsafe { l3_ptr.add(l3_idx) };
            // SAFETY: Exclusive access to `kpt` during initialization.
            let l3_pte = unsafe { *l3_entry };
            match l3_pte.to_repr(3) {
                PteScalar::Absent => {
                    // SAFETY: Filling an absent L3 slot with the shared zero L2 table.
                    unsafe { *l3_entry = zero_l3_pte };
                }
                PteScalar::PageTable(l2_pa, _) => {
                    // SAFETY: `l2_pa` is a valid L2 table owned by `kpt`.
                    unsafe { fill_zero_l2(l2_pa, zero_l2_pte, zero_l1_pte) };
                }
                PteScalar::Mapped(_, _) => {}
            }
        }
    }
}

/// Fills absent entries inside an existing L2 page table and its L1 children.
///
/// # Safety
///
/// `l2_pa` must be a valid L2 page table frame exclusively owned by the caller.
#[sanitize(address = "off")]
unsafe fn fill_zero_l2(l2_pa: Paddr, zero_l2_pte: PageTableEntry, zero_l1_pte: PageTableEntry) {
    let l2_ptr = paddr_to_vaddr(l2_pa) as *mut PageTableEntry;
    for l2_idx in 0..ENTRIES_PER_PT {
        // SAFETY: `l2_pa` holds 512 entries.
        let l2_entry = unsafe { l2_ptr.add(l2_idx) };
        // SAFETY: Exclusive access guaranteed by caller.
        let l2_pte = unsafe { *l2_entry };
        match l2_pte.to_repr(2) {
            PteScalar::Absent => {
                // SAFETY: Filling an absent L2 slot with the shared zero L1 table.
                unsafe { *l2_entry = zero_l2_pte };
            }
            PteScalar::PageTable(l1_pa, _) => {
                let l1_ptr = paddr_to_vaddr(l1_pa) as *mut PageTableEntry;
                for l1_idx in 0..ENTRIES_PER_PT {
                    // SAFETY: `l1_pa` is a valid L1 table with 512 entries.
                    let l1_entry = unsafe { l1_ptr.add(l1_idx) };
                    // SAFETY: Exclusive access guaranteed by caller.
                    if matches!(unsafe { *l1_entry }.to_repr(1), PteScalar::Absent) {
                        // SAFETY: Filling an absent L1 slot with the read-only zero page.
                        unsafe { *l1_entry = zero_l1_pte };
                    }
                }
            }
            PteScalar::Mapped(_, _) => {}
        }
    }
}
