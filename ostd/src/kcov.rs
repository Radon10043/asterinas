// SPDX-License-Identifier: MPL-2.0

//! Task-scoped Linux KCOV recording for coverage-guided kernel testing.
//!
//! This module provides the runtime half of KCOV:
//!
//! - [`KcovBuffer`] owns the shared physical frames mapped into userspace and
//!   manages per-task attachment in [`KcovMode::TracePc`] or
//!   [`KcovMode::TraceCmp`].
//! - [`enter_trace_scope`] returns a [`TraceGuard`] that limits recording to
//!   synchronous user requests (system calls and user exceptions), excluding
//!   asynchronous interrupt returns and context switches.
//! - LLVM SanitizerCoverage runtime callbacks record executed PCs and
//!   comparison operands into the active task's buffer while inside a
//!   [`TraceGuard`].
//!
//! Only safe kernel crates are instrumented.
//! OSTD must remain uninstrumented, including at link time,
//! so coverage builds disable cross-crate LTO.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.18/source/kernel/kcov.c>.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{self, AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::{
    Error, Result,
    irq::InterruptLevel,
    mm::{PAGE_SIZE, UFrame, VmIoOnce},
    sync::SpinLock,
    task::{CurrentTask, Task},
};

const WORD_SIZE: usize = size_of::<usize>();
const WORDS_PER_PAGE: usize = PAGE_SIZE / WORD_SIZE;
const WORDS_PER_CMP: usize = 4;

// Linux `<uapi/linux/kcov.h>` comparison type encoding.
pub(crate) const KCOV_CMP_CONST: u64 = 1;
pub(crate) const KCOV_CMP_SIZE1: u64 = 0;
pub(crate) const KCOV_CMP_SIZE2: u64 = 2;
pub(crate) const KCOV_CMP_SIZE4: u64 = 4;
pub(crate) const KCOV_CMP_SIZE8: u64 = 6;

// Per-task state encoding in `TaskKcov::state`:
// - Bits 0..=1: active trace mode (`STATE_DETACHED`, `STATE_TRACE_PC`, or `STATE_TRACE_CMP`).
// - Bit 2: inside a synchronous user trace scope (`IN_TRACE_SCOPE`).
// - Bit 3: inside a scheduler context switch (`IN_CTXSW`, matching Linux `KCOV_IN_CTXSW`).
const MODE_MASK: u8 = 0b11;
const STATE_DETACHED: u8 = 0;
const STATE_TRACE_PC: u8 = 1;
const STATE_TRACE_CMP: u8 = 2;
const IN_TRACE_SCOPE: u8 = 1 << 2;
const IN_CTXSW: u8 = 1 << 3;

/// Number of tasks with an active `KCOV_TRACE_PC` attachment.
///
/// Checked lock-free at the entry of `record_pc` so cold boot and non-PC
/// workloads return immediately without touching CPU-local or task state.
static NR_ACTIVE_PC_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Number of tasks with an active `KCOV_TRACE_CMP` attachment.
///
/// Checked lock-free at the entry of `record_cmp` and `record_switch` so a
/// `KCOV_TRACE_PC` session pays only one relaxed load per comparison callback.
static NR_ACTIVE_CMP_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Tracing mode selected via `KCOV_ENABLE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcovMode {
    /// Record basic-block program counters (`KCOV_TRACE_PC`).
    TracePc,
    /// Record comparison operands (`KCOV_TRACE_CMP`).
    TraceCmp,
}

impl KcovMode {
    const fn state_tag(self) -> u8 {
        match self {
            Self::TracePc => STATE_TRACE_PC,
            Self::TraceCmp => STATE_TRACE_CMP,
        }
    }
}

/// Errors returned by [`KcovBuffer`] attachment state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcovError {
    /// The operation was invoked outside task context.
    NotInTaskContext,
    /// This buffer is already attached to a task.
    BufferAlreadyActive,
    /// The calling task already has another KCOV buffer attached.
    TaskAlreadyAttached,
    /// The calling task does not own this KCOV buffer.
    NotAttached,
}

/// Fixed-size shared coverage area, with at most one task producing samples.
#[derive(Debug)]
pub struct KcovBuffer {
    frames: Vec<UFrame>,
    nr_entries: usize,
    active: AtomicBool,
}

impl KcovBuffer {
    /// Creates a coverage area from retained, shared untyped frames.
    ///
    /// `nr_entries` is the total capacity in `usize` words, including word 0
    /// holding the number of recorded entries.
    pub fn new(frames: Vec<UFrame>, nr_entries: usize) -> Result<Arc<Self>> {
        if nr_entries < 2 || frames.len() != nr_entries.div_ceil(WORDS_PER_PAGE) {
            return Err(Error::InvalidArgs);
        }
        Ok(Arc::new(Self {
            frames,
            nr_entries,
            active: AtomicBool::new(false),
        }))
    }

    /// Returns the backing untyped frames of this coverage area.
    pub fn frames(&self) -> &[UFrame] {
        &self.frames
    }

    /// Returns the total word capacity of this coverage area.
    pub fn nr_entries(&self) -> usize {
        self.nr_entries
    }

    /// Returns whether this coverage area is currently attached to a task.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Attaches the area to the calling task in `mode`.
    ///
    /// Matches Linux's check order by reporting [`KcovError::BufferAlreadyActive`]
    /// if this buffer is already attached (even when the calling task also owns
    /// another buffer) and [`KcovError::TaskAlreadyAttached`] if the calling task
    /// is already attached to a different buffer.
    pub fn enable(self: &Arc<Self>, mode: KcovMode) -> core::result::Result<(), KcovError> {
        if !InterruptLevel::current().is_task_context() {
            return Err(KcovError::NotInTaskContext);
        }
        let Some(task) = Task::current() else {
            return Err(KcovError::NotInTaskContext);
        };

        let mut slot = task.kcov().slot.lock();
        if let Some(existing) = slot.as_ref() {
            if existing.matches(self) || self.active.load(Ordering::Acquire) {
                return Err(KcovError::BufferAlreadyActive);
            }
            return Err(KcovError::TaskAlreadyAttached);
        }
        if self
            .active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(KcovError::BufferAlreadyActive);
        }

        *slot = Some(Attachment::new(self.clone(), mode));
        debug_assert_eq!(task.kcov().state() & MODE_MASK, STATE_DETACHED);
        task.kcov()
            .state
            .fetch_or(mode.state_tag(), Ordering::Release);
        Ok(())
    }

    /// Detaches the area if and only if the calling task owns it.
    pub fn disable(&self) -> core::result::Result<(), KcovError> {
        if !InterruptLevel::current().is_task_context() {
            return Err(KcovError::NotInTaskContext);
        }
        let Some(task) = Task::current() else {
            return Err(KcovError::NotInTaskContext);
        };

        let detached_buffer = {
            let mut slot = task.kcov().slot.lock();
            if !slot
                .as_ref()
                .is_some_and(|attachment| attachment.matches(self))
            {
                return Err(KcovError::NotAttached);
            }
            task.kcov().state.fetch_and(!MODE_MASK, Ordering::Release);
            // Release active tracking before dropping the slot lock so another
            // task never observes a detached buffer still marked active, while
            // deferring `Arc<KcovBuffer>` deallocation until outside the lock.
            slot.take().map(Attachment::detach)
        };
        drop(detached_buffer);
        Ok(())
    }

    #[inline]
    fn write_word(&self, word_index: usize, value: usize) -> bool {
        let frame = &self.frames[word_index / WORDS_PER_PAGE];
        frame
            .write_once((word_index % WORDS_PER_PAGE) * WORD_SIZE, &value)
            .is_ok()
    }

    #[inline]
    fn record_pc(&self, pc: usize) {
        let Ok(count) = self.frames[0].read_once::<usize>(0) else {
            return;
        };
        // Word 0 is shared with userspace and must be treated as hostile input.
        // Read it once and check bounds before arithmetic or frame indexing.
        if count >= self.nr_entries - 1 {
            return;
        }
        if !self.write_word(count + 1, pc) {
            return;
        }
        // x86-64 stores are ordered; prevent compiler reordering before
        // publishing the new count.
        atomic::compiler_fence(Ordering::Release);
        let _ = self.frames[0].write_once(0, &(count + 1));
    }

    #[inline]
    fn record_cmp(&self, cmp_type: u64, arg1: u64, arg2: u64, ip: u64) -> bool {
        let Ok(count) = self.frames[0].read_once::<usize>(0) else {
            return false;
        };
        // Each comparison occupies 4 `u64` words after word 0:
        // `[type, arg1, arg2, ip]`, while word 0 holds the comparison count.
        let max_comps = (self.nr_entries - 1) / WORDS_PER_CMP;
        if count >= max_comps {
            return false;
        }
        let base = 1 + count * WORDS_PER_CMP;
        if !self.write_word(base, cmp_type as usize)
            || !self.write_word(base + 1, arg1 as usize)
            || !self.write_word(base + 2, arg2 as usize)
            || !self.write_word(base + 3, ip as usize)
        {
            return false;
        }
        atomic::compiler_fence(Ordering::Release);
        let _ = self.frames[0].write_once(0, &(count + 1));
        true
    }
}

/// Guard keeping KCOV recording active while the calling task handles a user request.
#[must_use]
pub struct TraceGuard(CurrentTask);

/// Starts recording for an attached task until the returned guard is dropped.
///
/// Asterinas also returns to task context when an asynchronous interrupt interrupts userspace.
/// Scoping recording to synchronous user entries (system calls and user exceptions)
/// prevents asynchronous scheduling and signal checks from polluting an idle thread's trace.
pub fn enter_trace_scope() -> Option<TraceGuard> {
    if !has_active_tasks() || !InterruptLevel::current().is_task_context() {
        return None;
    }
    let task = Task::current()?;
    let state = task.kcov().state();
    if (state & MODE_MASK) == STATE_DETACHED || (state & IN_TRACE_SCOPE) != 0 {
        return None;
    }
    task.kcov()
        .state
        .fetch_or(IN_TRACE_SCOPE, Ordering::Relaxed);
    Some(TraceGuard(task))
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        // `KCOV_DISABLE` or task exit may have already cleared the mode.
        self.0
            .kcov()
            .state
            .fetch_and(!IN_TRACE_SCOPE, Ordering::Relaxed);
    }
}

/// Detaches coverage on task exit, without requiring a surviving file descriptor.
pub fn disable_current() {
    if !InterruptLevel::current().is_task_context() {
        return;
    }
    let Some(task) = Task::current() else {
        return;
    };
    if !task.kcov().is_attached() {
        return;
    }

    let detached_buffer = {
        let mut slot = task.kcov().slot.lock();
        task.kcov().state.fetch_and(!MODE_MASK, Ordering::Release);
        slot.take().map(Attachment::detach)
    };
    drop(detached_buffer);
}

/// Per-task KCOV attachment slot with a lock-free mode fast path.
#[derive(Debug)]
pub(crate) struct TaskKcov {
    state: AtomicU8,
    slot: SpinLock<Option<Attachment>>,
}

impl TaskKcov {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_DETACHED),
            slot: SpinLock::new(None),
        }
    }

    #[inline]
    fn state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }

    #[inline]
    fn is_attached(&self) -> bool {
        (self.state() & MODE_MASK) != STATE_DETACHED
    }
}

/// Marks the outgoing task as entering a context switch so schedule hooks do
/// not record coverage noise.
pub(crate) fn prepare_switch() {
    if !has_active_tasks() {
        return;
    }
    let Some(task) = Task::current() else {
        return;
    };
    if task.kcov().is_attached() {
        task.kcov().state.fetch_or(IN_CTXSW, Ordering::Relaxed);
    }
}

/// A guard that clears the context-switch marker on the incoming task when dropped.
#[must_use]
pub(crate) struct FinishSwitchGuard;

impl Drop for FinishSwitchGuard {
    fn drop(&mut self) {
        finish_switch();
    }
}

/// Clears the context-switch marker on the incoming task once schedule hooks
/// and previous-task teardown have completed.
fn finish_switch() {
    let Some(task) = Task::current() else {
        return;
    };
    if (task.kcov().state() & IN_CTXSW) != 0 {
        task.kcov().state.fetch_and(!IN_CTXSW, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct Attachment {
    buffer: Arc<KcovBuffer>,
    mode: KcovMode,
}

impl Attachment {
    fn new(buffer: Arc<KcovBuffer>, mode: KcovMode) -> Self {
        match mode {
            KcovMode::TracePc => {
                NR_ACTIVE_PC_TASKS.fetch_add(1, Ordering::Release);
            }
            KcovMode::TraceCmp => {
                NR_ACTIVE_CMP_TASKS.fetch_add(1, Ordering::Release);
            }
        }
        Self { buffer, mode }
    }

    fn matches(&self, target: &KcovBuffer) -> bool {
        core::ptr::eq(Arc::as_ptr(&self.buffer), target)
    }

    fn buffer(&self) -> &KcovBuffer {
        &self.buffer
    }

    fn detach(self) -> Arc<KcovBuffer> {
        let buffer = self.buffer.clone();
        drop(self);
        buffer
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        match self.mode {
            KcovMode::TracePc => {
                NR_ACTIVE_PC_TASKS.fetch_sub(1, Ordering::Release);
            }
            KcovMode::TraceCmp => {
                NR_ACTIVE_CMP_TASKS.fetch_sub(1, Ordering::Release);
            }
        }
        self.buffer.active.store(false, Ordering::Release);
    }
}

#[inline]
fn has_active_tasks() -> bool {
    NR_ACTIVE_PC_TASKS.load(Ordering::Relaxed) != 0
        || NR_ACTIVE_CMP_TASKS.load(Ordering::Relaxed) != 0
}

#[inline]
fn current_active_task(expected_state: u8) -> Option<CurrentTask> {
    // CPU-local state is not usable before OSTD initialization, and IRQ
    // handlers never contribute to per-task coverage.
    if crate::IN_BOOTSTRAP_CONTEXT.load(Ordering::Relaxed)
        || !InterruptLevel::current().is_task_context()
    {
        return None;
    }
    let task = Task::current()?;
    if task.kcov().state() != expected_state {
        return None;
    }
    Some(task)
}

#[inline]
fn with_active_buffer(mode: KcovMode, record_fn: impl FnOnce(&KcovBuffer)) {
    let nr_active_tasks = match mode {
        KcovMode::TracePc => &NR_ACTIVE_PC_TASKS,
        KcovMode::TraceCmp => &NR_ACTIVE_CMP_TASKS,
    };
    if nr_active_tasks.load(Ordering::Relaxed) == 0 {
        return;
    }
    let Some(task) = current_active_task(mode.state_tag() | IN_TRACE_SCOPE) else {
        return;
    };
    // Never spin in a callback: nested invocations while mutating an
    // attachment are dropped.
    let Some(slot) = task.kcov().slot.try_lock() else {
        return;
    };
    if let Some(attachment) = slot.as_ref()
        && attachment.mode == mode
    {
        record_fn(attachment.buffer());
    }
}

pub(crate) extern "C" fn record_pc(pc: usize) {
    with_active_buffer(KcovMode::TracePc, |buffer| {
        buffer.record_pc(pc);
    });
}

pub(crate) extern "C" fn record_cmp(arg1: u64, arg2: u64, cmp_type: u64, ip: usize) {
    with_active_buffer(KcovMode::TraceCmp, |buffer| {
        let _ = buffer.record_cmp(cmp_type, arg1, arg2, ip as u64);
    });
}

/// Records comparisons from an LLVM SanitizerCoverage switch table.
///
/// # Safety
///
/// If `cases` is non-null, it must be properly aligned and point to a readable
/// `u64` table `[num_cases, val_bits, case_0, ..., case_{num_cases - 1}]`
/// valid for the duration of this call.
pub(crate) unsafe extern "C" fn record_switch(val: u64, cases: *const u64, ip: usize) {
    if cases.is_null() {
        return;
    }
    with_active_buffer(KcovMode::TraceCmp, |buffer| {
        // SAFETY: The caller guarantees `cases` is non-null, properly aligned,
        // and points to a readable `[num_cases, val_bits, case_0, ...]` table.
        let (num_cases, val_bits) = unsafe { (cases.read(), cases.add(1).read()) };
        let cmp_type = match val_bits {
            8 => KCOV_CMP_SIZE1 | KCOV_CMP_CONST,
            16 => KCOV_CMP_SIZE2 | KCOV_CMP_CONST,
            32 => KCOV_CMP_SIZE4 | KCOV_CMP_CONST,
            64 => KCOV_CMP_SIZE8 | KCOV_CMP_CONST,
            _ => return,
        };
        let max_cases = num_cases.min(((buffer.nr_entries - 1) / WORDS_PER_CMP) as u64);
        for i in 0..max_cases {
            // SAFETY: `i < num_cases`, so `2 + i` lies within the caller's table.
            let case_val = unsafe { cases.add(2 + i as usize).read() };
            if !buffer.record_cmp(cmp_type, case_val, val, ip as u64) {
                break;
            }
        }
    });
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{mm::FrameAllocOptions, prelude::*};

    #[ktest]
    fn new_rejects_invalid_geometry() {
        let frame: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        assert!(KcovBuffer::new(alloc::vec![frame.clone()], 0).is_err());
        assert!(KcovBuffer::new(alloc::vec![frame.clone()], 1).is_err());
        assert!(KcovBuffer::new(Vec::new(), 2).is_err());
        assert!(KcovBuffer::new(alloc::vec![frame], WORDS_PER_PAGE + 1).is_err());
    }

    #[ktest]
    fn shared_count_is_bounded() {
        let frame: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let buffer = KcovBuffer::new(alloc::vec![frame.clone()], 3).unwrap();

        buffer.record_pc(0x1234);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 1);
        assert_eq!(frame.read_once::<usize>(WORD_SIZE).unwrap(), 0x1234);

        buffer.record_pc(0x5678);
        buffer.record_pc(0x9abc);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 2);

        frame.write_once(0, &usize::MAX).unwrap();
        buffer.record_pc(0xdead);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), usize::MAX);

        frame.write_once(0, &0usize).unwrap();
        buffer.record_pc(0xbeef);
        assert_eq!(frame.read_once::<usize>(WORD_SIZE).unwrap(), 0xbeef);
    }

    #[ktest]
    fn records_across_page_boundary() {
        let frames: Vec<UFrame> = (0..2)
            .map(|_| FrameAllocOptions::new().alloc_frame().unwrap().into())
            .collect();
        frames[0].write_once(0, &(WORDS_PER_PAGE - 1)).unwrap();
        let buffer = KcovBuffer::new(frames.clone(), WORDS_PER_PAGE + 1).unwrap();

        buffer.record_pc(0xcafe);
        assert_eq!(frames[1].read_once::<usize>(0).unwrap(), 0xcafe);
        assert_eq!(frames[0].read_once::<usize>(0).unwrap(), WORDS_PER_PAGE);
    }

    #[ktest]
    fn records_cmp_across_page_boundary() {
        let frames: Vec<UFrame> = (0..2)
            .map(|_| FrameAllocOptions::new().alloc_frame().unwrap().into())
            .collect();
        // Comparison #127 starts at word index 509 (words 509..=511 on page 0, word 512 on page 1).
        let idx = (WORDS_PER_PAGE / WORDS_PER_CMP) - 1;
        frames[0].write_once(0, &idx).unwrap();
        let buffer = KcovBuffer::new(frames.clone(), WORDS_PER_PAGE + 4).unwrap();

        assert!(buffer.record_cmp(KCOV_CMP_SIZE4 | KCOV_CMP_CONST, 0xdeadbeef, 0x42, 0xcafe));
        assert_eq!(frames[0].read_once::<usize>(0).unwrap(), idx + 1);
        assert_eq!(frames[0].read_once::<usize>(509 * WORD_SIZE).unwrap(), 5);
        assert_eq!(
            frames[0].read_once::<usize>(510 * WORD_SIZE).unwrap(),
            0xdeadbeef
        );
        assert_eq!(frames[0].read_once::<usize>(511 * WORD_SIZE).unwrap(), 0x42);
        assert_eq!(frames[1].read_once::<usize>(0).unwrap(), 0xcafe);

        // Next comparison would require words 513..=516, exceeding `WORDS_PER_PAGE + 4` (516 words).
        assert!(!buffer.record_cmp(KCOV_CMP_SIZE8, 1, 2, 0xbeef));
        frames[0].write_once(0, &usize::MAX).unwrap();
        assert!(!buffer.record_cmp(KCOV_CMP_SIZE8, 1, 2, 0xbeef));
    }

    #[ktest]
    fn enable_disable_and_trace_scope_lifecycle() {
        let frame: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let other_frame: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let buffer = KcovBuffer::new(alloc::vec![frame.clone()], 16).unwrap();
        let other = KcovBuffer::new(alloc::vec![other_frame], 16).unwrap();

        assert!(enter_trace_scope().is_none());
        assert_eq!(buffer.disable(), Err(KcovError::NotAttached));
        assert!(!buffer.is_active());

        assert_eq!(buffer.enable(KcovMode::TracePc), Ok(()));
        assert!(buffer.is_active());
        assert_eq!(
            buffer.enable(KcovMode::TracePc),
            Err(KcovError::BufferAlreadyActive)
        );
        assert_eq!(
            other.enable(KcovMode::TracePc),
            Err(KcovError::TaskAlreadyAttached)
        );
        assert_eq!(other.disable(), Err(KcovError::NotAttached));
        assert_eq!(NR_ACTIVE_PC_TASKS.load(Ordering::Relaxed), 1);

        // Recording is suppressed outside a trace scope.
        record_pc(0x1111);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 0);

        {
            let _guard = enter_trace_scope().unwrap();
            assert!(enter_trace_scope().is_none());

            record_pc(0x2222);
            assert_eq!(frame.read_once::<usize>(0).unwrap(), 1);
            assert_eq!(frame.read_once::<usize>(WORD_SIZE).unwrap(), 0x2222);

            // Context switches suppress recording until `FinishSwitchGuard` drops.
            prepare_switch();
            {
                let _switch_guard = FinishSwitchGuard;
                record_pc(0x3333);
                assert_eq!(frame.read_once::<usize>(0).unwrap(), 1);
            }

            record_pc(0x4444);
            assert_eq!(frame.read_once::<usize>(0).unwrap(), 2);
            assert_eq!(frame.read_once::<usize>(2 * WORD_SIZE).unwrap(), 0x4444);
        }

        // Guard drop restores non-recording state.
        record_pc(0x5555);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 2);

        assert_eq!(buffer.disable(), Ok(()));
        assert!(!buffer.is_active());
        assert_eq!(buffer.disable(), Err(KcovError::NotAttached));
        assert_eq!(NR_ACTIVE_PC_TASKS.load(Ordering::Relaxed), 0);

        // Re-enable in comparison mode and test `disable_current`.
        frame.write_once(0, &0usize).unwrap();
        assert_eq!(buffer.enable(KcovMode::TraceCmp), Ok(()));
        assert_eq!(NR_ACTIVE_CMP_TASKS.load(Ordering::Relaxed), 1);
        {
            let _guard = enter_trace_scope().unwrap();
            record_cmp(0xaa, 0xbb, KCOV_CMP_SIZE8, 0x9999);
            assert_eq!(frame.read_once::<usize>(0).unwrap(), 1);
        }
        disable_current();
        assert_eq!(NR_ACTIVE_CMP_TASKS.load(Ordering::Relaxed), 0);
        assert_eq!(buffer.disable(), Err(KcovError::NotAttached));
    }

    #[ktest]
    fn trace_guard_survives_disable_and_reenable() {
        let frame1: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let frame2: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let buffer1 = KcovBuffer::new(alloc::vec![frame1.clone()], 16).unwrap();
        let buffer2 = KcovBuffer::new(alloc::vec![frame2.clone()], 16).unwrap();

        assert_eq!(buffer1.enable(KcovMode::TracePc), Ok(()));
        {
            let _guard = enter_trace_scope().unwrap();
            assert_eq!(buffer1.disable(), Ok(()));
            record_pc(0x1111);
            assert_eq!(frame1.read_once::<usize>(0).unwrap(), 0);
            assert!(enter_trace_scope().is_none());

            // Re-attaching another buffer while `_guard` is still live keeps
            // `IN_TRACE_SCOPE` set and prevents a second overlapping guard.
            assert_eq!(buffer2.enable(KcovMode::TracePc), Ok(()));
            assert!(enter_trace_scope().is_none());
            record_pc(0x2222);
            assert_eq!(frame2.read_once::<usize>(0).unwrap(), 1);
            assert_eq!(frame2.read_once::<usize>(WORD_SIZE).unwrap(), 0x2222);
        }

        // Dropping `_guard` clears `IN_TRACE_SCOPE` cleanly.
        record_pc(0x3333);
        assert_eq!(frame2.read_once::<usize>(0).unwrap(), 1);
        assert_eq!(buffer2.disable(), Ok(()));
    }
}
