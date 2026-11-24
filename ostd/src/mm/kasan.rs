// SPDX-License-Identifier: MPL-2.0

//! Kernel AddressSanitizer (KASAN) shadow memory and runtime support.

use core::{
    alloc::Layout,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize},
};

use super::{
    CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, PrivilegedPageFlags, Vaddr,
    heap::{HeapSlot, get_global_heap_allocator},
    kspace::{KernelPtConfig, MappedItem},
    page_table::PageTable,
};
use crate::{
    sync::{LocalIrqDisabled, SpinLock},
    task::DisabledPreemptGuard,
    util::id_set::Id,
};

/// Shadow memory mapping offset passed to `-asan-mapping-offset`.
pub const KASAN_SHADOW_OFFSET: usize = 0xdfff_fc00_0000_0000;
/// Log2 of KASAN shadow scale (8 bytes mapped per 1 shadow byte).
pub const KASAN_SHADOW_SCALE_SHIFT: usize = 3;
/// Number of kernel bytes described by each shadow byte.
pub const KASAN_SHADOW_GRANULE_SIZE: usize = 1 << KASAN_SHADOW_SCALE_SHIFT;

/// Shadow tag for completely accessible memory.
const KASAN_UNPOISONED: u8 = 0x00;
/// Shadow tag for heap slab left/right redzones.
const KASAN_SLAB_REDZONE: u8 = 0xFA;
/// Shadow tag for freed heap slots (quarantined or in slab free lists).
const KASAN_SLAB_FREE: u8 = 0xFB;
/// Shadow tag for freed physical frames returned to the frame allocator.
const KASAN_PAGE_FREE: u8 = 0xFF;

const MAX_MONITORED_RANGES: usize = 8;

/// Quarantine limits balance UAF detection window against 2 GiB guest RAM.
const QUARANTINE_MAX_SLOTS: usize = 4096;
const QUARANTINE_MAX_BYTES: usize = 8 * 1024 * 1024;
const QUARANTINE_MAX_ITEM_SIZE: usize = 1024 * 1024;

static KASAN_ENABLED: AtomicBool = AtomicBool::new(false);
static REPORTING_CPU: AtomicUsize = AtomicUsize::new(usize::MAX);
static MONITORED_COUNT: AtomicUsize = AtomicUsize::new(0);
static MONITORED_RANGES: [(AtomicUsize, AtomicUsize); MAX_MONITORED_RANGES] =
    [const { (AtomicUsize::new(0), AtomicUsize::new(0)) }; MAX_MONITORED_RANGES];

static QUARANTINE: SpinLock<QuarantineRing, LocalIrqDisabled> =
    SpinLock::new(QuarantineRing::new());

struct QuarantineRing {
    slots: [Option<HeapSlot>; QUARANTINE_MAX_SLOTS],
    head: usize,
    tail: usize,
    len: usize,
    total_bytes: usize,
}

// SAFETY: `QuarantineRing` is guarded by `QUARANTINE`'s spinlock, and queued
// `HeapSlot`s are exclusively owned until deallocated on eviction.
unsafe impl Send for QuarantineRing {}

impl QuarantineRing {
    const fn new() -> Self {
        Self {
            slots: [const { None }; QUARANTINE_MAX_SLOTS],
            head: 0,
            tail: 0,
            len: 0,
            total_bytes: 0,
        }
    }

    #[sanitize(address = "off")]
    fn push(&mut self, slot: HeapSlot) {
        debug_assert!(self.len < QUARANTINE_MAX_SLOTS);
        let size = slot.size();
        self.slots[self.tail] = Some(slot);
        self.tail = (self.tail + 1) % QUARANTINE_MAX_SLOTS;
        self.len += 1;
        self.total_bytes += size;
    }

    #[sanitize(address = "off")]
    fn pop(&mut self) -> Option<HeapSlot> {
        if self.len == 0 {
            return None;
        }
        let slot = self.slots[self.head].take()?;
        self.head = (self.head + 1) % QUARANTINE_MAX_SLOTS;
        self.len -= 1;
        self.total_bytes -= slot.size();
        Some(slot)
    }
}

// Direct uninstrumented atomic and bulk-memory helpers for KASAN runtime paths.
// In optimized builds (`opt-level >= 2`), generic `core::sync::atomic::Atomic`
// methods monomorphized into `ostd` inherit `-Zsanitizer=kernel-address`, so
// calling them inside `#[sanitize(address = "off")]` callbacks would re-enter
// `__asan_load*`/`__asan_store*` and recurse infinitely.
#[inline]
#[sanitize(address = "off")]
fn kasan_load_bool_acquire(atom: &AtomicBool) -> bool {
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
fn kasan_store_bool_release(atom: &AtomicBool, val: bool) {
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
fn kasan_load_usize_relaxed(atom: &AtomicUsize) -> usize {
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
fn kasan_load_usize_acquire(atom: &AtomicUsize) -> usize {
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
fn kasan_store_usize_release(atom: &AtomicUsize, val: usize) {
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
fn kasan_cmpxchg_usize(atom: &AtomicUsize, current: usize, new: usize) -> Result<usize, usize> {
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

unsafe extern "C" {
    #[link_name = "memcpy"]
    fn raw_memcpy(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    #[link_name = "memmove"]
    fn raw_memmove(dst: *mut c_void, src: *const c_void, len: usize) -> *mut c_void;
    #[link_name = "memset"]
    fn raw_memset(dst: *mut c_void, val: i32, len: usize) -> *mut c_void;
}

/// Returns whether KASAN shadow checks and poisoning are active.
#[inline]
#[sanitize(address = "off")]
pub fn is_enabled() -> bool {
    kasan_load_bool_acquire(&KASAN_ENABLED)
}

/// Returns whether any CPU is currently emitting a KASAN report.
#[inline]
#[sanitize(address = "off")]
pub fn is_reporting() -> bool {
    kasan_load_usize_acquire(&REPORTING_CPU) != usize::MAX
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

/// Translates a kernel virtual address to its KASAN shadow byte address.
#[inline]
#[sanitize(address = "off")]
const fn mem_to_shadow(addr: usize) -> usize {
    KASAN_SHADOW_OFFSET.wrapping_add(addr >> KASAN_SHADOW_SCALE_SHIFT)
}

#[inline]
#[sanitize(address = "off")]
fn is_monitored_range(addr: usize, size: usize) -> bool {
    if size == 0 || addr > usize::MAX - size {
        return false;
    }
    let end = addr + size;
    let count = kasan_load_usize_acquire(&MONITORED_COUNT);
    let limit = if count > MAX_MONITORED_RANGES {
        MAX_MONITORED_RANGES
    } else {
        count
    };
    let mut i = 0;
    while i < limit {
        let start = kasan_load_usize_relaxed(&MONITORED_RANGES[i].0);
        let range_end = kasan_load_usize_relaxed(&MONITORED_RANGES[i].1);
        if addr >= start && end <= range_end {
            return true;
        }
        i += 1;
    }
    false
}

#[sanitize(address = "off")]
fn record_monitored_range(start: usize, end: usize) {
    if start >= end {
        return;
    }
    let idx = kasan_load_usize_relaxed(&MONITORED_COUNT);
    assert!(
        idx < MAX_MONITORED_RANGES,
        "exceeded KASAN monitored range capacity"
    );
    kasan_store_usize_release(&MONITORED_RANGES[idx].0, start);
    kasan_store_usize_release(&MONITORED_RANGES[idx].1, end);
    kasan_store_usize_release(&MONITORED_COUNT, idx + 1);
}

/// Maps zero-initialized KASAN shadow pages into the kernel page table.
#[sanitize(address = "off")]
pub(super) fn init_shadow(
    kpt: &PageTable<KernelPtConfig>,
    preempt_guard: &DisabledPreemptGuard,
    ranges: &[(Vaddr, Vaddr)],
) {
    let prop = PageProperty {
        flags: PageFlags::RW,
        cache: CachePolicy::Writeback,
        priv_flags: PrivilegedPageFlags::GLOBAL,
    };

    let mut last_mapped_shadow_end = 0usize;
    let mut total_shadow_bytes = 0usize;

    for &(raw_start, raw_end) in ranges {
        if raw_start >= raw_end {
            continue;
        }
        record_monitored_range(raw_start, raw_end);

        let shadow_start =
            align_down(mem_to_shadow(raw_start), PAGE_SIZE).max(last_mapped_shadow_end);
        let shadow_end = align_up(mem_to_shadow(raw_end - 1) + 1, PAGE_SIZE);
        if shadow_start >= shadow_end {
            continue;
        }

        let mut va = shadow_start;
        while va < shadow_end {
            let remaining_pages = (shadow_end - va) / PAGE_SIZE;
            if remaining_pages >= 512 {
                if let Ok(segment) = FrameAllocOptions::new().zeroed(true).alloc_segment(512) {
                    let chunk_end = va + 512 * PAGE_SIZE;
                    let mut cursor = kpt
                        .cursor_mut_with_min_level(preempt_guard, &(va..chunk_end), 1)
                        .unwrap();
                    let pa_range = segment.into_raw();
                    for pa in (pa_range.start..pa_range.end).step_by(PAGE_SIZE) {
                        // SAFETY: Mapping freshly allocated, zeroed KASAN shadow frames.
                        unsafe { cursor.map(MappedItem::Untracked(pa, 1, prop)) };
                    }
                    va = chunk_end;
                    continue;
                }
            }

            let frame = FrameAllocOptions::new().zeroed(true).alloc_frame().unwrap();
            let pa = frame.into_raw();
            let next_va = va + PAGE_SIZE;
            let mut cursor = kpt
                .cursor_mut_with_min_level(preempt_guard, &(va..next_va), 1)
                .unwrap();
            // SAFETY: Mapping freshly allocated, zeroed KASAN shadow frame.
            unsafe { cursor.map(MappedItem::Untracked(pa, 1, prop)) };
            va = next_va;
        }

        total_shadow_bytes += shadow_end - shadow_start;
        last_mapped_shadow_end = shadow_end;
    }

    crate::info!(
        "KASAN shadow initialized ({} KiB across {} ranges)",
        total_shadow_bytes / 1024,
        kasan_load_usize_relaxed(&MONITORED_COUNT)
    );
}

/// Enables KASAN runtime shadow validation after the kernel page table is active.
#[sanitize(address = "off")]
pub(crate) fn enable() {
    kasan_store_bool_release(&KASAN_ENABLED, true);
    crate::early_println!("[kasan] KernelAddressSanitizer enabled");
}

/// Computes the left redzone size (a multiple of 8 bytes >= `layout.align()`).
#[inline]
#[sanitize(address = "off")]
pub(crate) const fn padded_left_redzone(layout: Layout) -> usize {
    if layout.align() > KASAN_SHADOW_GRANULE_SIZE {
        layout.align()
    } else {
        KASAN_SHADOW_GRANULE_SIZE
    }
}

/// Expands `layout` with deterministic left and right KASAN redzones.
#[inline]
#[sanitize(address = "off")]
pub(crate) fn padded_layout(layout: Layout) -> Option<Layout> {
    let left_rz = padded_left_redzone(layout);
    let right_rz = KASAN_SHADOW_GRANULE_SIZE;
    let total_size = left_rz.checked_add(layout.size())?.checked_add(right_rz)?;
    Layout::from_size_align(total_size, left_rz).ok()
}

#[inline]
#[sanitize(address = "off")]
unsafe fn fill_shadow(addr: usize, len: usize, tag: u8) {
    debug_assert!(addr & (KASAN_SHADOW_GRANULE_SIZE - 1) == 0);
    debug_assert!(len & (KASAN_SHADOW_GRANULE_SIZE - 1) == 0);
    let shadow_ptr = mem_to_shadow(addr) as *mut u8;
    // SAFETY: Caller guarantees `[addr .. addr + len)` is within mapped shadow.
    unsafe {
        raw_memset(
            shadow_ptr.cast::<c_void>(),
            tag as i32,
            len >> KASAN_SHADOW_SCALE_SHIFT,
        );
    }
}

/// Poisons a full page frame as freed (`KASAN_PAGE_FREE`).
#[sanitize(address = "off")]
pub(crate) fn poison_page_free(vaddr: Vaddr) {
    if !is_enabled() || !is_monitored_range(vaddr, PAGE_SIZE) {
        return;
    }
    // SAFETY: Monitored page-aligned range has mapped shadow.
    unsafe { fill_shadow(vaddr, PAGE_SIZE, KASAN_PAGE_FREE) };
}

/// Unpoisons a full page frame upon allocation (`KASAN_UNPOISONED`).
#[sanitize(address = "off")]
pub(crate) fn unpoison_page(vaddr: Vaddr) {
    if !is_enabled() || !is_monitored_range(vaddr, PAGE_SIZE) {
        return;
    }
    // SAFETY: Monitored page-aligned range has mapped shadow.
    unsafe { fill_shadow(vaddr, PAGE_SIZE, KASAN_UNPOISONED) };
}

/// Marks all slots of a newly initialized slab page as freed (`KASAN_SLAB_FREE`).
#[sanitize(address = "off")]
pub(crate) fn poison_slab_free(vaddr: Vaddr, size: usize) {
    if !is_enabled() || !is_monitored_range(vaddr, size) {
        return;
    }
    // SAFETY: Monitored slab range has mapped shadow and is granule-aligned.
    unsafe { fill_shadow(vaddr, size, KASAN_SLAB_FREE) };
}

/// Poisons redzones around a newly allocated heap object while unpoisoning
/// exact user bytes `[slot_addr + left_rz .. slot_addr + left_rz + user_size)`.
#[sanitize(address = "off")]
pub(crate) fn poison_heap_alloc(
    slot_addr: usize,
    slot_size: usize,
    left_rz: usize,
    user_size: usize,
) {
    if !is_enabled() || !is_monitored_range(slot_addr, slot_size) {
        return;
    }
    debug_assert!(slot_addr & (KASAN_SHADOW_GRANULE_SIZE - 1) == 0);
    debug_assert!(slot_size & (KASAN_SHADOW_GRANULE_SIZE - 1) == 0);
    debug_assert!(left_rz & (KASAN_SHADOW_GRANULE_SIZE - 1) == 0);
    debug_assert!(left_rz + user_size <= slot_size);

    // SAFETY: Entire slot lies inside a monitored range with mapped shadow.
    unsafe {
        fill_shadow(slot_addr, slot_size, KASAN_SLAB_REDZONE);
        let user_addr = slot_addr + left_rz;
        let full_granules = user_size >> KASAN_SHADOW_SCALE_SHIFT;
        if full_granules > 0 {
            raw_memset(
                mem_to_shadow(user_addr) as *mut c_void,
                KASAN_UNPOISONED as i32,
                full_granules,
            );
        }
        let rem = user_size & (KASAN_SHADOW_GRANULE_SIZE - 1);
        if rem != 0 {
            let tail_shadow = mem_to_shadow(user_addr) + full_granules;
            *(tail_shadow as *mut u8) = rem as u8;
        }
    }
}

/// Checks allocator metadata without modifying the slot or its shadow.
#[sanitize(address = "off")]
fn validate_heap_free(user_ptr: usize, layout: Layout, slot_addr: usize, slot_size: usize) {
    if (user_ptr & (layout.align() - 1)) != 0 || !is_monitored_range(slot_addr, slot_size) {
        let pc = capture_caller_pc(2);
        report_bug("invalid-free", "Free", user_ptr, pc, KASAN_SLAB_REDZONE);
    }

    // SAFETY: `slot_addr` and `user_ptr` were verified to lie inside a monitored range.
    let left_tag = unsafe { *(mem_to_shadow(slot_addr) as *const u8) };
    if left_tag == KASAN_SLAB_FREE || left_tag == KASAN_PAGE_FREE {
        let pc = capture_caller_pc(2);
        report_bug("double-free", "Free", user_ptr, pc, left_tag);
    }
    if left_tag != KASAN_SLAB_REDZONE {
        let pc = capture_caller_pc(2);
        report_bug("invalid-free", "Free", user_ptr, pc, left_tag);
    }

    if layout.size() > 0 {
        // SAFETY: `user_ptr` is within `[slot_addr + left_rz .. slot_addr + slot_size)`.
        let user_tag = unsafe { *(mem_to_shadow(user_ptr) as *const u8) };
        if user_tag == KASAN_SLAB_FREE || user_tag == KASAN_PAGE_FREE {
            let pc = capture_caller_pc(2);
            report_bug("double-free", "Free", user_ptr, pc, user_tag);
        }
        if user_tag == KASAN_SLAB_REDZONE {
            let pc = capture_caller_pc(2);
            report_bug("invalid-free", "Free", user_ptr, pc, user_tag);
        }
    }
}

/// Validates a heap free and quarantines the freed slot (or drains on overflow).
///
/// # Safety
///
/// `user_ptr` must be the pointer previously returned by `GlobalAlloc::alloc`
/// for `layout`, and `slot_addr`/`slot_size` must describe the padded backing slot.
#[sanitize(address = "off")]
pub(crate) unsafe fn on_heap_free(
    user_ptr: usize,
    layout: Layout,
    slot_addr: usize,
    slot: HeapSlot,
) {
    let slot_size = slot.size();
    if is_enabled() {
        validate_heap_free(user_ptr, layout, slot_addr, slot_size);

        // SAFETY: Entire slot lies inside a monitored range with mapped shadow.
        unsafe { fill_shadow(slot_addr, slot_size, KASAN_SLAB_FREE) };
    }

    if slot_size <= QUARANTINE_MAX_ITEM_SIZE {
        quarantine_push(slot);
    } else {
        let _ = get_global_heap_allocator().dealloc(slot);
    }
}

#[sanitize(address = "off")]
fn quarantine_push(slot: HeapSlot) {
    // Return evicted slots outside the ring lock. A large incoming slot can
    // require more than one eviction before both memory limits are satisfied.
    loop {
        let old = {
            let mut ring = QUARANTINE.lock();
            if ring.len < QUARANTINE_MAX_SLOTS
                && ring.total_bytes + slot.size() <= QUARANTINE_MAX_BYTES
            {
                ring.push(slot);
                return;
            }
            ring.pop().expect("a full quarantine must contain a slot")
        };
        let _ = get_global_heap_allocator().dealloc(old);
    }
}

/// Evicts all queued quarantine entries back to the underlying heap allocator.
#[sanitize(address = "off")]
pub(crate) fn quarantine_drain() {
    loop {
        let mut batch: [Option<HeapSlot>; 64] = [const { None }; 64];
        let mut count = 0usize;
        {
            let mut ring = QUARANTINE.lock();
            while count < batch.len() {
                if let Some(old) = ring.pop() {
                    batch[count] = Some(old);
                    count += 1;
                } else {
                    break;
                }
            }
        }
        if count == 0 {
            break;
        }
        let alloc = get_global_heap_allocator();
        for item in &mut batch[..count] {
            if let Some(old) = item.take() {
                let _ = alloc.dealloc(old);
            }
        }
    }
}

#[inline]
#[sanitize(address = "off")]
fn shadow_byte(addr: usize) -> u8 {
    // SAFETY: Caller only invokes this on addresses inside monitored ranges.
    unsafe { *(mem_to_shadow(addr) as *const u8) }
}

/// Checks `[addr .. addr + size)` in KASAN shadow, returning `(bad_addr, shadow_tag)`
/// for the first inaccessible byte if any.
#[inline]
#[sanitize(address = "off")]
fn check_range_poisoned(addr: usize, size: usize) -> Option<(usize, u8)> {
    if size == 0 || !is_enabled() || !is_monitored_range(addr, size) {
        return None;
    }

    // Fast path for natural small accesses within one 8-byte granule.
    let offset = addr & (KASAN_SHADOW_GRANULE_SIZE - 1);
    if size <= KASAN_SHADOW_GRANULE_SIZE && offset + size <= KASAN_SHADOW_GRANULE_SIZE {
        let raw = shadow_byte(addr);
        if raw == KASAN_UNPOISONED {
            return None;
        }
        let s = raw as i8;
        let last = (offset + size - 1) as i8;
        if s > 0 && last < s {
            return None;
        }
        let bad_offset = if s > 0 && (offset as i8) < s {
            s as usize - offset
        } else {
            0
        };
        return Some((addr + bad_offset, raw));
    }

    let mut cur = addr;
    let end = addr + size;

    while cur < end {
        let gran_off = cur & (KASAN_SHADOW_GRANULE_SIZE - 1);
        let bytes_left = end - cur;

        if gran_off == 0 && bytes_left >= 64 && (cur & 63) == 0 {
            // SAFETY: `(cur & 63) == 0` implies `mem_to_shadow(cur)` is 8-byte aligned and
            // `[cur .. cur + 64)` lies within the monitored range.
            let word = unsafe { *(mem_to_shadow(cur) as *const u64) };
            if word == 0 {
                cur += 64;
                continue;
            }
        }

        let rem_in_gran = KASAN_SHADOW_GRANULE_SIZE - gran_off;
        let chunk = if rem_in_gran < bytes_left {
            rem_in_gran
        } else {
            bytes_left
        };
        let raw = shadow_byte(cur);
        if raw != KASAN_UNPOISONED {
            let s = raw as i8;
            let last = (gran_off + chunk - 1) as i8;
            if s <= 0 || last >= s {
                let bad_off = if s > 0 && (gran_off as i8) < s {
                    s as usize - gran_off
                } else {
                    0
                };
                return Some((cur + bad_off, raw));
            }
        }
        cur += chunk;
    }

    None
}

#[sanitize(address = "off")]
fn capture_caller_pc(skip_frames: usize) -> usize {
    use unwinding::abi::{_Unwind_Backtrace, _Unwind_GetIP, UnwindContext, UnwindReasonCode};

    struct State {
        skip: usize,
        pc: usize,
    }

    #[sanitize(address = "off")]
    extern "C" fn cb(ctx: &UnwindContext<'_>, arg: *mut c_void) -> UnwindReasonCode {
        // SAFETY: `arg` points to stack-local `State`.
        let state = unsafe { &mut *(arg as *mut State) };
        let pc = _Unwind_GetIP(ctx);
        if state.skip == 0 {
            if pc > 0 {
                state.pc = pc;
                return UnwindReasonCode::END_OF_STACK;
            }
        } else {
            state.skip -= 1;
        }
        UnwindReasonCode::NO_REASON
    }

    let mut state = State {
        skip: skip_frames,
        pc: 0,
    };
    _Unwind_Backtrace(cb, &mut state as *mut State as *mut c_void);
    state.pc
}

#[sanitize(address = "off")]
const fn bug_type_from_shadow(tag: u8) -> &'static str {
    match tag {
        KASAN_SLAB_REDZONE | 1..=7 => "slab-out-of-bounds",
        KASAN_SLAB_FREE | KASAN_PAGE_FREE => "use-after-free",
        _ => "out-of-bounds",
    }
}

#[sanitize(address = "off")]
fn acquire_report_slot_or_halt(addr: usize, pc: usize) -> crate::irq::DisabledLocalIrqGuard {
    let irq_guard = crate::irq::disable_local();
    let cpu_tag = crate::arch::cpu::local::get_base() as usize;

    match kasan_cmpxchg_usize(&REPORTING_CPU, usize::MAX, cpu_tag) {
        Ok(_) => {
            // Disable nested KASAN checks while emitting the report and stack trace.
            kasan_store_bool_release(&KASAN_ENABLED, false);
            // Allow any peer CPU already mid-write on COM1 to drain before header output.
            for _ in 0..50_000 {
                core::hint::spin_loop();
            }
            irq_guard
        }
        Err(owner) if owner == cpu_tag => {
            crate::force_early_println!(
                "BUG: KASAN: recursive fault while reporting on addr {:#x} (pc {:#x})",
                addr,
                pc
            );
            crate::panic::abort();
        }
        Err(_) => {
            crate::arch::irq::disable_local_and_halt();
        }
    }
}

#[sanitize(address = "off")]
fn emit_kasan_report_and_abort(
    bug_type: &str,
    op_desc: &str,
    size: Option<usize>,
    addr: usize,
    pc: usize,
) -> ! {
    let _irq_guard = acquire_report_slot_or_halt(addr, pc);
    let cpu_id = crate::cpu::CpuId::current_racy().as_usize();

    crate::force_early_println!(
        "\n=================================================================="
    );
    crate::force_early_println!("BUG: KASAN: {} in {:#x}", bug_type, pc);
    match size {
        Some(n) => crate::force_early_println!(
            "{} of size {} at addr {:#x} by CPU {}",
            op_desc,
            n,
            addr,
            cpu_id
        ),
        None => crate::force_early_println!("{} at addr {:#x} by CPU {}", op_desc, addr, cpu_id),
    }
    if pc != 0 {
        crate::force_early_println!("KASAN: pc {:#x}", pc);
    }
    crate::panic::print_stack_trace_force();
    crate::force_early_println!(
        "=================================================================="
    );
    crate::panic::abort();
}

#[sanitize(address = "off")]
fn report_bug(bug_type: &str, access: &str, addr: usize, pc: usize, _shadow_tag: u8) -> ! {
    emit_kasan_report_and_abort(bug_type, access, None, addr, pc);
}

#[sanitize(address = "off")]
fn report_access_error(addr: usize, size: usize, is_write: bool, pc: usize, bad_tag: u8) -> ! {
    let op = if is_write { "Write" } else { "Read" };
    let bug_type = bug_type_from_shadow(bad_tag);
    emit_kasan_report_and_abort(bug_type, op, Some(size), addr, pc);
}

#[inline]
#[sanitize(address = "off")]
fn check_access(addr: usize, size: usize, is_write: bool, pc: usize) {
    if let Some((bad_addr, bad_tag)) = check_range_poisoned(addr, size) {
        report_access_error(bad_addr, size, is_write, pc, bad_tag);
    }
}

#[inline]
#[sanitize(address = "off")]
fn report_inline(addr: usize, size: usize, is_write: bool, pc: usize) -> ! {
    let (bad_addr, bad_tag) =
        check_range_poisoned(addr, size).unwrap_or((addr, KASAN_SLAB_REDZONE));
    report_access_error(bad_addr, size, is_write, pc, bad_tag);
}

#[sanitize(address = "off")]
extern "C" fn handle_load_1(addr: usize, pc: usize) {
    check_access(addr, 1, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_2(addr: usize, pc: usize) {
    check_access(addr, 2, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_4(addr: usize, pc: usize) {
    check_access(addr, 4, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_8(addr: usize, pc: usize) {
    check_access(addr, 8, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_16(addr: usize, pc: usize) {
    check_access(addr, 16, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_load_n(addr: usize, size: usize, pc: usize) {
    check_access(addr, size, false, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_store_1(addr: usize, pc: usize) {
    check_access(addr, 1, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_2(addr: usize, pc: usize) {
    check_access(addr, 2, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_4(addr: usize, pc: usize) {
    check_access(addr, 4, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_8(addr: usize, pc: usize) {
    check_access(addr, 8, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_16(addr: usize, pc: usize) {
    check_access(addr, 16, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_store_n(addr: usize, size: usize, pc: usize) {
    check_access(addr, size, true, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_report_load_1(addr: usize, pc: usize) -> ! {
    report_inline(addr, 1, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_2(addr: usize, pc: usize) -> ! {
    report_inline(addr, 2, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_4(addr: usize, pc: usize) -> ! {
    report_inline(addr, 4, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_8(addr: usize, pc: usize) -> ! {
    report_inline(addr, 8, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_16(addr: usize, pc: usize) -> ! {
    report_inline(addr, 16, false, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_load_n(addr: usize, size: usize, pc: usize) -> ! {
    report_inline(addr, size, false, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_report_store_1(addr: usize, pc: usize) -> ! {
    report_inline(addr, 1, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_2(addr: usize, pc: usize) -> ! {
    report_inline(addr, 2, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_4(addr: usize, pc: usize) -> ! {
    report_inline(addr, 4, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_8(addr: usize, pc: usize) -> ! {
    report_inline(addr, 8, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_16(addr: usize, pc: usize) -> ! {
    report_inline(addr, 16, true, pc);
}
#[sanitize(address = "off")]
extern "C" fn handle_report_store_n(addr: usize, size: usize, pc: usize) -> ! {
    report_inline(addr, size, true, pc);
}

#[sanitize(address = "off")]
extern "C" fn handle_memcpy(dst: *mut u8, src: *const u8, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        check_access(src as usize, len, false, pc);
        check_access(dst as usize, len, true, pc);
        // SAFETY: Ranges passed shadow checks and compiler ABI guarantees non-overlap.
        unsafe { raw_memcpy(dst.cast::<c_void>(), src.cast::<c_void>(), len) };
    }
    dst
}

#[sanitize(address = "off")]
extern "C" fn handle_memmove(dst: *mut u8, src: *const u8, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        check_access(src as usize, len, false, pc);
        check_access(dst as usize, len, true, pc);
        // SAFETY: Ranges passed shadow checks and `memmove` allows overlap.
        unsafe { raw_memmove(dst.cast::<c_void>(), src.cast::<c_void>(), len) };
    }
    dst
}

#[sanitize(address = "off")]
extern "C" fn handle_memset(dst: *mut u8, val: i32, len: usize, pc: usize) -> *mut u8 {
    if len > 0 {
        check_access(dst as usize, len, true, pc);
        // SAFETY: Range passed shadow checks.
        unsafe { raw_memset(dst.cast::<c_void>(), val, len) };
    }
    dst
}

/// No-op handler required by `-Zsanitizer=kernel-address` around diverging calls.
#[sanitize(address = "off")]
#[unsafe(no_mangle)]
extern "C" fn __asan_handle_no_return() {}

macro_rules! kasan_thunk_1 {
    ($sym:ident, $target:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rsi, [rsp]", "jmp {}", sym $target);
        }
    };
}

macro_rules! kasan_thunk_2 {
    ($sym:ident, $target:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rdx, [rsp]", "jmp {}", sym $target);
        }
    };
}

macro_rules! kasan_thunk_3 {
    ($sym:ident, $target:path) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $sym() {
            core::arch::naked_asm!("mov rcx, [rsp]", "jmp {}", sym $target);
        }
    };
}

kasan_thunk_1!(__asan_load1, handle_load_1);
kasan_thunk_1!(__asan_load2, handle_load_2);
kasan_thunk_1!(__asan_load4, handle_load_4);
kasan_thunk_1!(__asan_load8, handle_load_8);
kasan_thunk_1!(__asan_load16, handle_load_16);
kasan_thunk_2!(__asan_loadN, handle_load_n);

kasan_thunk_1!(__asan_store1, handle_store_1);
kasan_thunk_1!(__asan_store2, handle_store_2);
kasan_thunk_1!(__asan_store4, handle_store_4);
kasan_thunk_1!(__asan_store8, handle_store_8);
kasan_thunk_1!(__asan_store16, handle_store_16);
kasan_thunk_2!(__asan_storeN, handle_store_n);

kasan_thunk_1!(__asan_report_load1_noabort, handle_report_load_1);
kasan_thunk_1!(__asan_report_load2_noabort, handle_report_load_2);
kasan_thunk_1!(__asan_report_load4_noabort, handle_report_load_4);
kasan_thunk_1!(__asan_report_load8_noabort, handle_report_load_8);
kasan_thunk_1!(__asan_report_load16_noabort, handle_report_load_16);
kasan_thunk_2!(__asan_report_load_n_noabort, handle_report_load_n);

kasan_thunk_1!(__asan_report_store1_noabort, handle_report_store_1);
kasan_thunk_1!(__asan_report_store2_noabort, handle_report_store_2);
kasan_thunk_1!(__asan_report_store4_noabort, handle_report_store_4);
kasan_thunk_1!(__asan_report_store8_noabort, handle_report_store_8);
kasan_thunk_1!(__asan_report_store16_noabort, handle_report_store_16);
kasan_thunk_2!(__asan_report_store_n_noabort, handle_report_store_n);

kasan_thunk_1!(__asan_report_load1, handle_report_load_1);
kasan_thunk_1!(__asan_report_load2, handle_report_load_2);
kasan_thunk_1!(__asan_report_load4, handle_report_load_4);
kasan_thunk_1!(__asan_report_load8, handle_report_load_8);
kasan_thunk_1!(__asan_report_load16, handle_report_load_16);
kasan_thunk_2!(__asan_report_load_n, handle_report_load_n);

kasan_thunk_1!(__asan_report_store1, handle_report_store_1);
kasan_thunk_1!(__asan_report_store2, handle_report_store_2);
kasan_thunk_1!(__asan_report_store4, handle_report_store_4);
kasan_thunk_1!(__asan_report_store8, handle_report_store_8);
kasan_thunk_1!(__asan_report_store16, handle_report_store_16);
kasan_thunk_2!(__asan_report_store_n, handle_report_store_n);

kasan_thunk_3!(__asan_memcpy, handle_memcpy);
kasan_thunk_3!(__asan_memmove, handle_memmove);
kasan_thunk_3!(__asan_memset, handle_memset);

mod selftest;
pub use selftest::{SelftestMode, run_selftest};
