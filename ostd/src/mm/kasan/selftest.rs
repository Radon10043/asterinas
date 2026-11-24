// SPDX-License-Identifier: MPL-2.0

use super::*;

/// Boot-time KASAN self-test scenarios triggered via `kasan_selftest=...`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelftestMode {
    /// Verifies the shadow map for allocated and quarantined memory.
    Shadow,
    /// Read from a synthetic trailing redzone.
    Oob,
    /// Out-of-bounds write into an unaddressable sub-granule byte.
    Partial,
    /// Use-after-free read against a quarantined heap allocation.
    Uaf,
    /// Double-free detection on a previously freed heap allocation.
    Df,
}

impl core::str::FromStr for SelftestMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "shadow" => Ok(Self::Shadow),
            "oob" => Ok(Self::Oob),
            "partial" => Ok(Self::Partial),
            "uaf" => Ok(Self::Uaf),
            "df" => Ok(Self::Df),
            _ => Err(()),
        }
    }
}

#[inline(never)]
fn selftest_read(buf: &[u8], index: usize) -> u8 {
    core::hint::black_box(buf)[index]
}

#[inline(never)]
fn selftest_write(buf: &mut [u8], index: usize) {
    core::hint::black_box(buf)[index] = 0x55;
}

/// Runs the selected diagnostic in the first kernel thread.
pub fn run_selftest(mode: SelftestMode) {
    match mode {
        SelftestMode::Shadow => {
            run_shadow_selftest();
            return;
        }
        SelftestMode::Oob | SelftestMode::Partial => {
            let mut buf = alloc::vec![0x42u8; 32];
            let base = buf.as_ptr().addr();
            // Both accesses stay within the live allocation. Mark just the last
            // bytes inaccessible in shadow and exercise compiler-inserted checks.
            if mode == SelftestMode::Oob {
                crate::early_println!("[kasan-selftest] running oob");
                poison_heap_alloc(base, buf.len(), 0, 24);
                core::hint::black_box(selftest_read(&buf, 24));
            } else {
                crate::early_println!("[kasan-selftest] running partial");
                poison_heap_alloc(base, buf.len(), 0, 19);
                selftest_write(&mut buf, 19);
            }
            poison_heap_alloc(base, buf.len(), 0, buf.len());
        }
        SelftestMode::Uaf | SelftestMode::Df => {
            let buf = alloc::boxed::Box::new([0x77u64; 4]);
            let layout = Layout::for_value(&*buf);
            let addr = buf.as_ptr().addr();
            let slot_addr = addr - padded_left_redzone(layout);
            // Check the address saved from a real quarantined allocation. The
            // diagnostics only read shadow and leave ownership with the allocator.
            drop(buf);
            if mode == SelftestMode::Uaf {
                crate::early_println!("[kasan-selftest] running uaf");
                handle_load_8(addr, capture_caller_pc(1));
            } else {
                crate::early_println!("[kasan-selftest] running df");
                validate_heap_free(
                    addr,
                    layout,
                    slot_addr,
                    padded_layout(layout).unwrap().size(),
                );
            }
        }
    }
    panic!("KASAN diagnostic returned without a report: {mode:?}");
}

/// Checks KASAN shadow geometry using valid heap allocations only.
fn run_shadow_selftest() {
    let mut checks = 0usize;
    macro_rules! check {
        ($condition:expr) => {{
            assert!($condition);
            checks += 1;
        }};
    }
    macro_rules! check_clear {
        ($addr:expr, $size:expr) => {{
            assert_eq!(check_range_poisoned($addr, $size), None);
            checks += 1;
        }};
    }
    macro_rules! check_poisoned {
        ($addr:expr, $size:expr, $bad:expr, $tag:expr) => {{
            assert_eq!(check_range_poisoned($addr, $size), Some(($bad, $tag)));
            checks += 1;
        }};
    }

    check!(is_enabled());
    let granule = KASAN_SHADOW_GRANULE_SIZE;
    let len = PAGE_SIZE * 3 + 257;
    let mut test_buf = alloc::vec![0x31u8; len].into_boxed_slice();
    let buf_len = test_buf.len();
    let base = test_buf.as_mut_ptr() as usize;
    let end = base + buf_len;

    check!(buf_len == len);
    check!(base & (granule - 1) == 0);
    test_buf[0] = 0x5a;
    test_buf[buf_len - 1] = 0xa5;
    check!(test_buf[0] == 0x5a);
    check!(test_buf[buf_len - 1] == 0xa5);

    // Check every allocated byte and every aligned full granule.
    for offset in 0..buf_len {
        check_clear!(base + offset, 1);
    }
    let mut granule_addr = base;
    while granule_addr + granule <= end {
        check_clear!(granule_addr, granule);
        check_clear!(granule_addr + 1, granule - 1);
        granule_addr += granule;
    }

    // Check unaligned accesses and crossings at granule and 64-byte boundaries.
    for offset in 0..buf_len - 7 {
        check_clear!(base + offset, 8);
    }
    let mut boundary = base + granule;
    while boundary < end {
        check_clear!(boundary - 1, 2);
        boundary += granule;
    }
    let mut block = (base + 63) & !63usize;
    while block + 64 <= end {
        check_clear!(block, 64);
        block += 64;
    }
    boundary = (base / 64 + 1) * 64;
    while boundary < end {
        check_clear!(boundary - 1, 2);
        boundary += 64;
    }

    // Check spans that cross each page boundary inside the same allocation.
    boundary = (base / PAGE_SIZE + 1) * PAGE_SIZE;
    while boundary < end {
        check_clear!(boundary - 1, 2);
        if boundary >= base + 32 && boundary + 32 <= end {
            check_clear!(boundary - 32, 64);
        }
        boundary += PAGE_SIZE;
    }

    check_clear!(base, buf_len);
    let tail_tag = if buf_len & (granule - 1) == 0 {
        KASAN_SLAB_REDZONE
    } else {
        (buf_len & (granule - 1)) as u8
    };
    check_poisoned!(end, 1, end, tail_tag);
    check_poisoned!(end - 2, 4, end, tail_tag);
    check_clear!(end, 0);

    // A freed Box remains in quarantine; inspect only its shadow metadata.
    drop(test_buf);
    check_poisoned!(base, 1, base, KASAN_SLAB_FREE);

    // Exercise the full-granule redzone and quarantine marker.
    let mut whole = alloc::vec![0u8; granule].into_boxed_slice();
    let whole_base = whole.as_mut_ptr() as usize;
    check_clear!(whole_base, granule);
    check_poisoned!(
        whole_base + granule,
        1,
        whole_base + granule,
        KASAN_SLAB_REDZONE
    );
    drop(whole);
    check_poisoned!(whole_base, 1, whole_base, KASAN_SLAB_FREE);

    // Exercise every partial-granule tail tag with separate real allocations.
    for rem in 1..granule {
        let size = granule + rem;
        let mut partial = alloc::vec![0u8; size].into_boxed_slice();
        let partial_base = partial.as_mut_ptr() as usize;
        let partial_end = partial_base + size;

        check_clear!(partial_base, granule);
        check_clear!(partial_base + granule, rem);
        check_poisoned!(partial_end - 1, 2, partial_end, rem as u8);
        check_poisoned!(partial_end, 1, partial_end, rem as u8);
        check_clear!(partial_end, 0);

        drop(partial);
        check_poisoned!(partial_base, 1, partial_base, KASAN_SLAB_FREE);
    }

    for align in [1, 8, 16, 64, PAGE_SIZE] {
        for size in [1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 4095, 4096, 4097, 8193] {
            let layout = Layout::from_size_align(size, align).unwrap();
            // SAFETY: Layout has a nonzero size and valid alignment.
            let mut ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            check!(!ptr.is_null());
            check!(ptr.addr() % align == 0);
            check_clear!(ptr.addr(), size);
            for i in 0..size {
                // SAFETY: The successful allocation contains exactly size bytes.
                unsafe {
                    check!(*ptr.add(i) == 0);
                    *ptr.add(i) = (i % 251) as u8;
                }
            }
            let left = ptr.addr() - 1;
            check_poisoned!(left, 1, left, KASAN_SLAB_REDZONE);
            let tail = ptr.addr() + size;
            let tag = if size % 8 == 0 {
                KASAN_SLAB_REDZONE
            } else {
                (size % 8) as u8
            };
            check_poisoned!(tail, 1, tail, tag);
            let grown = size + 33;
            // SAFETY: ptr owns the live allocation with the matching layout.
            ptr = unsafe { alloc::alloc::realloc(ptr, layout, grown) };
            check!(!ptr.is_null());
            check!(ptr.addr() % align == 0);
            check_clear!(ptr.addr(), grown);
            for i in 0..grown {
                // SAFETY: The reallocated object contains grown bytes.
                unsafe {
                    if i < size {
                        check!(*ptr.add(i) == (i % 251) as u8);
                    }
                    *ptr.add(i) = (i % 239) as u8;
                }
            }
            let grown_layout = Layout::from_size_align(grown, align).unwrap();
            // SAFETY: ptr owns the grown allocation and size is nonzero.
            ptr = unsafe { alloc::alloc::realloc(ptr, grown_layout, size) };
            check!(!ptr.is_null());
            check!(ptr.addr() % align == 0);
            check_clear!(ptr.addr(), size);
            for i in 0..size {
                // SAFETY: The shrunken allocation contains size bytes.
                check!(unsafe { *ptr.add(i) } == (i % 239) as u8);
            }
            let addr = ptr.addr();
            check_poisoned!(addr + size, 1, addr + size, tag);
            // SAFETY: ptr is live and layout matches its current size/alignment.
            unsafe { alloc::alloc::dealloc(ptr, layout) };
            check_poisoned!(addr, 1, addr, KASAN_SLAB_FREE);
        }
    }

    for value in 0..5000u64 {
        let item = alloc::boxed::Box::new(value);
        check!(*item == value);
        drop(item);
    }
    let ring = QUARANTINE.lock();
    check!(ring.len <= QUARANTINE_MAX_SLOTS);
    check!(ring.total_bytes <= QUARANTINE_MAX_BYTES);
    drop(ring);

    // Large slots force eviction by byte budget while many small slots remain.
    for value in 0..16u8 {
        let item = alloc::vec![value; 512 * 1024].into_boxed_slice();
        check!(item[0] == value && item[item.len() - 1] == value);
        check_clear!(item.as_ptr().addr(), item.len());
        drop(item);
        let ring = QUARANTINE.lock();
        check!(ring.len <= QUARANTINE_MAX_SLOTS);
        check!(ring.total_bytes <= QUARANTINE_MAX_BYTES);
    }

    crate::early_println!("[kasan-selftest] shadow passed checks={}", checks);
}
