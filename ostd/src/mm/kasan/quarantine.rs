// SPDX-License-Identifier: MPL-2.0

//! Bounded FIFO quarantine for freed KASAN heap slots.
//!
//! Mirrors Linux's `mm/kasan/quarantine.c`: freed heap slots remain poisoned
//! with `KASAN_SLAB_FREE` inside a bounded ring buffer before returning to the
//! underlying allocator, enlarging the temporal detection window for
//! use-after-free bugs.

use core::sync::atomic::AtomicUsize;

use super::{is_enabled, load_usize_relaxed, store_usize_release};
use crate::{
    mm::heap::{self, HeapSlot},
    sync::{LocalIrqDisabled, SpinLock},
};

/// Fraction of usable physical RAM allocated to the quarantine byte budget,
/// matching Linux's `QUARANTINE_FRACTION`.
const QUARANTINE_FRACTION: usize = 32;

/// Maximum number of slots retained in the quarantine ring.
const QUARANTINE_MAX_SLOTS: usize = 4096;

/// Lower bound on the dynamic quarantine byte budget (1 MiB).
const QUARANTINE_MIN_BYTES: usize = 1024 * 1024;

/// Upper bound on the dynamic quarantine byte budget (8 MiB).
const QUARANTINE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Allocations larger than this threshold bypass quarantine and return
/// immediately to the frame allocator (where they are poisoned with
/// `KASAN_PAGE_FREE`).
const QUARANTINE_MAX_ITEM_SIZE: usize = 1024 * 1024;

/// Number of slots popped per critical section before releasing them outside
/// the quarantine lock.
const QUARANTINE_DRAIN_BATCH: usize = 64;

static QUARANTINE_BYTE_LIMIT: AtomicUsize = AtomicUsize::new(QUARANTINE_MAX_BYTES);

/// Wrapper around an exclusively owned freed [`HeapSlot`] held in quarantine.
struct QuarantinedSlot(HeapSlot);

// SAFETY: A freed `HeapSlot` in quarantine is exclusively owned and unaliased;
// moving it across CPUs under `QUARANTINE`'s spinlock before returning it to
// the thread-safe global heap allocator is sound.
unsafe impl Send for QuarantinedSlot {}

struct QuarantineRing {
    slots: [Option<QuarantinedSlot>; QUARANTINE_MAX_SLOTS],
    head: usize,
    tail: usize,
    count: usize,
    bytes: usize,
}

impl QuarantineRing {
    const fn new() -> Self {
        Self {
            slots: [const { None }; QUARANTINE_MAX_SLOTS],
            head: 0,
            tail: 0,
            count: 0,
            bytes: 0,
        }
    }

    #[sanitize(address = "off")]
    fn pop_front(&mut self) -> Option<QuarantinedSlot> {
        if self.count == 0 {
            return None;
        }
        let slot = self.slots[self.head].take();
        self.head = (self.head + 1) % QUARANTINE_MAX_SLOTS;
        self.count -= 1;
        if let Some(ref s) = slot {
            self.bytes = self.bytes.saturating_sub(s.0.size());
        }
        slot
    }

    #[sanitize(address = "off")]
    fn push_back(&mut self, slot: QuarantinedSlot) {
        debug_assert!(self.count < QUARANTINE_MAX_SLOTS);
        let size = slot.0.size();
        self.slots[self.tail] = Some(slot);
        self.tail = (self.tail + 1) % QUARANTINE_MAX_SLOTS;
        self.count += 1;
        self.bytes = self.bytes.saturating_add(size);
    }
}

static QUARANTINE: SpinLock<QuarantineRing, LocalIrqDisabled> =
    SpinLock::new(QuarantineRing::new());

/// Configures the quarantine byte budget from total usable physical RAM.
///
/// Called once during KASAN shadow initialization on the BSP.
#[sanitize(address = "off")]
pub(super) fn configure_from_usable_ram(usable_bytes: usize) {
    let limit =
        (usable_bytes / QUARANTINE_FRACTION).clamp(QUARANTINE_MIN_BYTES, QUARANTINE_MAX_BYTES);
    store_usize_release(&QUARANTINE_BYTE_LIMIT, limit);
}

#[sanitize(address = "off")]
fn release_batch(batch: &mut [Option<QuarantinedSlot>; QUARANTINE_DRAIN_BATCH], len: usize) {
    for slot in &mut batch[..len] {
        if let Some(evicted) = slot.take() {
            heap::dealloc_slot_raw(evicted.0);
        }
    }
}

/// Returns whether `slot` should be retained in quarantine upon deallocation.
#[inline]
#[sanitize(address = "off")]
pub(super) fn should_quarantine(slot: &HeapSlot) -> bool {
    is_enabled() && slot.size() <= QUARANTINE_MAX_ITEM_SIZE
}

/// Inserts a freed, poisoned [`HeapSlot`] into the quarantine ring.
///
/// Evicts the oldest quarantined slots outside the quarantine lock when either
/// the slot count or byte budget would be exceeded.
#[sanitize(address = "off")]
pub(super) fn quarantine_put(slot: HeapSlot) {
    let slot_size = slot.size();
    if !should_quarantine(&slot) {
        heap::dealloc_slot_raw(slot);
        return;
    }

    let max_bytes = load_usize_relaxed(&QUARANTINE_BYTE_LIMIT);
    let mut pending = Some(QuarantinedSlot(slot));
    let mut batch: [Option<QuarantinedSlot>; QUARANTINE_DRAIN_BATCH] =
        [const { None }; QUARANTINE_DRAIN_BATCH];

    loop {
        let mut evicted_len = 0;
        {
            let mut ring = QUARANTINE.lock();
            while evicted_len < QUARANTINE_DRAIN_BATCH
                && (ring.count >= QUARANTINE_MAX_SLOTS
                    || (ring.count > 0 && ring.bytes.saturating_add(slot_size) > max_bytes))
            {
                let Some(old) = ring.pop_front() else {
                    break;
                };
                batch[evicted_len] = Some(old);
                evicted_len += 1;
            }

            if ring.count < QUARANTINE_MAX_SLOTS
                && (ring.count == 0 || ring.bytes.saturating_add(slot_size) <= max_bytes)
                && let Some(item) = pending.take()
            {
                ring.push_back(item);
            }
        }

        // Return evicted slots to the allocator outside `QUARANTINE`'s lock to
        // prevent lock-order inversions with slab or frame allocator locks.
        release_batch(&mut batch, evicted_len);

        if pending.is_none() {
            return;
        }
    }
}

/// Drains all currently quarantined slots back to the underlying heap allocator.
///
/// Used as an OOM recovery fallback when heap allocation fails under pressure.
#[sanitize(address = "off")]
pub(in crate::mm) fn quarantine_drain() {
    let mut batch: [Option<QuarantinedSlot>; QUARANTINE_DRAIN_BATCH] =
        [const { None }; QUARANTINE_DRAIN_BATCH];

    loop {
        let mut drained_len = 0;
        {
            let mut ring = QUARANTINE.lock();
            while drained_len < QUARANTINE_DRAIN_BATCH {
                let Some(old) = ring.pop_front() else {
                    break;
                };
                batch[drained_len] = Some(old);
                drained_len += 1;
            }
        }

        if drained_len == 0 {
            return;
        }
        release_batch(&mut batch, drained_len);
    }
}

/// Returns the current `(slot_count, total_bytes)` held in quarantine.
#[cfg(ktest)]
#[sanitize(address = "off")]
pub(super) fn quarantine_stats() -> (usize, usize) {
    let ring = QUARANTINE.lock();
    (ring.count, ring.bytes)
}

/// Returns the configured quarantine byte budget.
#[cfg(ktest)]
#[sanitize(address = "off")]
pub(super) fn quarantine_max_bytes() -> usize {
    load_usize_relaxed(&QUARANTINE_BYTE_LIMIT)
}
