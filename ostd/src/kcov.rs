// SPDX-License-Identifier: MPL-2.0

//! Task-scoped Linux KCOV recording for coverage-guided kernel testing.
//!
//! Only safe kernel crates are instrumented. This runtime must remain
//! uninstrumented, including when linking: coverage builds must disable
//! cross-crate LTO.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("KCOV currently supports only x86_64");

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering, compiler_fence};

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

const KCOV_CMP_CONST: u64 = 1;
const KCOV_CMP_SIZE1: u64 = 0;
const KCOV_CMP_SIZE2: u64 = 2;
const KCOV_CMP_SIZE4: u64 = 4;
const KCOV_CMP_SIZE8: u64 = 6;

const STATE_DETACHED: u8 = 0;
const STATE_TRACE_PC: u8 = 1;
const STATE_TRACE_CMP: u8 = 2;
const IN_SYSCALL: u8 = 4;

/// KCOV tracing mode selected via `KCOV_ENABLE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KcovMode {
    /// Record basic-block PCs (`KCOV_TRACE_PC`).
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

/// Number of tasks with an active `KCOV_TRACE_PC` attachment.
///
/// Checked lock-free at the entry of `record_pc()` so cold boot and non-PC
/// workloads return immediately without touching CPU-local or task lock state.
static ACTIVE_KCOV_TASKS: AtomicUsize = AtomicUsize::new(0);

/// Number of tasks with an active `KCOV_TRACE_CMP` attachment.
///
/// Checked lock-free at the entry of `record_cmp()` and `record_switch()` so
/// a `KCOV_TRACE_PC` session pays only a single relaxed load per callback.
static ACTIVE_KCOV_CMP_TASKS: AtomicUsize = AtomicUsize::new(0);

#[inline]
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
fn load_usize_relaxed(atom: &AtomicUsize) -> usize {
    let val: usize;
    let ptr = atom as *const AtomicUsize as *const usize;
    // SAFETY: `AtomicUsize` has the same size and alignment as `usize`, and
    // aligned 64-bit loads are atomic on x86_64. Direct asm avoids calling a
    // sanitizer-instrumented generic `Atomic::load` monomorphization in
    // optimized builds.
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
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
fn load_u8_relaxed(atom: &AtomicU8) -> u8 {
    let val: u8;
    let ptr = atom as *const AtomicU8 as *const u8;
    // SAFETY: `AtomicU8` has the same size and alignment as `u8`, and byte
    // loads are atomic on x86_64.
    unsafe {
        core::arch::asm!(
            "mov {val}, byte ptr [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg_byte) val,
            options(nostack, readonly, preserves_flags),
        );
    }
    val
}

#[inline]
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
fn load_bool_relaxed(atom: &AtomicBool) -> bool {
    let val: u8;
    let ptr = atom as *const AtomicBool as *const u8;
    // SAFETY: `AtomicBool` has the same size and alignment as `u8` (0 or 1),
    // and byte loads are atomic on x86_64.
    unsafe {
        core::arch::asm!(
            "mov {val}, byte ptr [{ptr}]",
            ptr = in(reg) ptr,
            val = out(reg_byte) val,
            options(nostack, readonly, preserves_flags),
        );
    }
    val != 0
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
    #[cfg_attr(feature = "kasan", sanitize(address = "off"))]
    fn state(&self) -> u8 {
        load_u8_relaxed(&self.state)
    }

    #[inline]
    #[cfg_attr(feature = "kasan", sanitize(address = "off"))]
    fn is_attached(&self) -> bool {
        self.state() != STATE_DETACHED
    }
}

/// A fixed-size shared coverage area, with at most one task producing samples.
#[derive(Debug)]
pub struct KcovBuffer {
    frames: Vec<UFrame>,
    entries: usize,
    active: AtomicBool,
}

impl KcovBuffer {
    /// Creates a coverage area from retained, shared untyped frames.
    ///
    /// `entries` is the total capacity in `u64` words, including word 0 holding
    /// the number of recorded entries.
    pub fn new(frames: Vec<UFrame>, entries: usize) -> Result<Arc<Self>> {
        if entries < 2 || frames.len() != entries.div_ceil(WORDS_PER_PAGE) {
            return Err(Error::InvalidArgs);
        }
        Ok(Arc::new(Self {
            frames,
            entries,
            active: AtomicBool::new(false),
        }))
    }

    /// Attaches the area to the calling task in `mode`, unless either is already attached.
    pub fn enable(self: &Arc<Self>, mode: KcovMode) -> bool {
        if !InterruptLevel::current().is_task_context() {
            return false;
        }
        let Some(task) = Task::current() else {
            return false;
        };
        let mut slot = task.kcov.slot.lock();
        if slot.is_some()
            || self
                .active
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return false;
        }
        *slot = Some(Attachment::new(self.clone(), mode));
        task.kcov.state.store(mode.state_tag(), Ordering::Release);
        true
    }

    /// Detaches the area if and only if the calling task owns it.
    pub fn disable(&self) -> bool {
        let Some(task) = Task::current() else {
            return false;
        };
        let mut slot = task.kcov.slot.lock();
        if !slot
            .as_ref()
            .is_some_and(|attachment| core::ptr::eq(Arc::as_ptr(&attachment.buffer), self))
        {
            return false;
        }
        task.kcov.state.store(STATE_DETACHED, Ordering::Release);
        // Drop the attachment before releasing the task slot so that another
        // task cannot observe a detached area still marked as active.
        drop(slot.take());
        true
    }

    #[inline]
    fn write_word(&self, word_index: usize, value: usize) -> bool {
        let frame = &self.frames[word_index / WORDS_PER_PAGE];
        frame
            .write_once((word_index % WORDS_PER_PAGE) * WORD_SIZE, &value)
            .is_ok()
    }

    #[inline]
    #[cfg_attr(feature = "kasan", sanitize(address = "off"))]
    fn record(&self, pc: usize) {
        let Ok(count) = self.frames[0].read_once::<usize>(0) else {
            return;
        };
        // The shared count is hostile input. Read it only once, and bound it
        // before doing arithmetic or indexing any retained frame.
        if count >= self.entries - 1 {
            return;
        }
        if !self.write_word(count + 1, pc) {
            return;
        }
        // x86_64 stores are ordered; prevent compiler reordering before
        // publishing the new count. VmIoOnce tolerates racing userspace writes.
        compiler_fence(Ordering::Release);
        let _ = self.frames[0].write_once(0, &(count + 1));
    }

    #[inline]
    #[cfg_attr(feature = "kasan", sanitize(address = "off"))]
    fn record_cmp(&self, cmp_type: u64, arg1: u64, arg2: u64, ip: u64) -> bool {
        let Ok(count) = self.frames[0].read_once::<usize>(0) else {
            return false;
        };
        // Each comparison occupies 4 `u64` words after word 0:
        // `[type, arg1, arg2, ip]`, while `buf[0]` holds the comparison count.
        let max_comps = (self.entries - 1) / WORDS_PER_CMP;
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
        compiler_fence(Ordering::Release);
        let _ = self.frames[0].write_once(0, &(count + 1));
        true
    }
}

#[derive(Debug)]
pub(crate) struct Attachment {
    buffer: Arc<KcovBuffer>,
    mode: KcovMode,
}

impl Attachment {
    fn new(buffer: Arc<KcovBuffer>, mode: KcovMode) -> Self {
        match mode {
            KcovMode::TracePc => {
                ACTIVE_KCOV_TASKS.fetch_add(1, Ordering::Release);
            }
            KcovMode::TraceCmp => {
                ACTIVE_KCOV_CMP_TASKS.fetch_add(1, Ordering::Release);
            }
        }
        Self { buffer, mode }
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        match self.mode {
            KcovMode::TracePc => {
                ACTIVE_KCOV_TASKS.fetch_sub(1, Ordering::Release);
            }
            KcovMode::TraceCmp => {
                ACTIVE_KCOV_CMP_TASKS.fetch_sub(1, Ordering::Release);
            }
        }
        self.buffer.active.store(false, Ordering::Release);
    }
}

/// Keeps tracing active while the calling task handles a system call.
#[must_use]
pub struct SyscallGuard(CurrentTask);

/// Starts recording for an attached task until the guard is dropped.
///
/// Asterinas also runs task-context code when an interrupt returns to
/// userspace. Limit samples to syscall handling so asynchronous scheduling
/// and signal checks do not appear in an otherwise idle thread's trace.
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
pub fn enter_syscall() -> Option<SyscallGuard> {
    if load_usize_relaxed(&ACTIVE_KCOV_TASKS) == 0
        && load_usize_relaxed(&ACTIVE_KCOV_CMP_TASKS) == 0
    {
        return None;
    }
    let task = Task::current()?;
    let state = task.kcov.state();
    if state == STATE_DETACHED || state & IN_SYSCALL != 0 {
        return None;
    }
    task.kcov.state.store(state | IN_SYSCALL, Ordering::Relaxed);
    Some(SyscallGuard(task))
}

impl Drop for SyscallGuard {
    fn drop(&mut self) {
        // KCOV_DISABLE may have already detached the task inside this syscall.
        self.0.kcov.state.fetch_and(!IN_SYSCALL, Ordering::Relaxed);
    }
}

/// Detaches coverage on task exit, without requiring a surviving file descriptor.
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
pub fn disable_current() {
    let Some(task) = Task::current() else {
        return;
    };
    if !task.kcov.is_attached() {
        return;
    }
    let mut slot = task.kcov.slot.lock();
    task.kcov.state.store(STATE_DETACHED, Ordering::Release);
    drop(slot.take());
}

/// Returns the runtime addresses bounding the executable kernel text.
pub fn kernel_text_range() -> core::ops::Range<usize> {
    unsafe extern "C" {
        static __stext: u8;
        static __etext: u8;
    }
    (&raw const __stext).addr()..(&raw const __etext).addr()
}

// SAFETY: The sanitizer ABI invokes this symbol as an ordinary SysV function.
// Its return address is at [rsp]. Tail-jumping preserves the caller's stack
// alignment and return address while passing that PC to the Rust dispatcher.
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_pc() {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "jmp {}",
        sym record_pc,
    );
}

// The SysV arguments arrive in rdi and rsi. Zero-extend subword operands
// before the tail call because the caller may leave their upper bits unspecified.
macro_rules! trace_cmp_callback {
    ($name:ident, $kind:expr $(, $extend:literal)*) => {
        #[unsafe(naked)]
        #[unsafe(no_mangle)]
        extern "C" fn $name() {
            core::arch::naked_asm!(
                $($extend,)*
                "mov edx, {kind}",
                "mov rcx, [rsp]",
                "jmp {record}",
                kind = const $kind,
                record = sym record_cmp,
            );
        }
    };
}

trace_cmp_callback!(
    __sanitizer_cov_trace_cmp1,
    KCOV_CMP_SIZE1,
    "movzx edi, dil",
    "movzx esi, sil"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_cmp2,
    KCOV_CMP_SIZE2,
    "movzx edi, di",
    "movzx esi, si"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_cmp4,
    KCOV_CMP_SIZE4,
    "mov edi, edi",
    "mov esi, esi"
);
trace_cmp_callback!(__sanitizer_cov_trace_cmp8, KCOV_CMP_SIZE8);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp1,
    KCOV_CMP_SIZE1 | KCOV_CMP_CONST,
    "movzx edi, dil",
    "movzx esi, sil"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp2,
    KCOV_CMP_SIZE2 | KCOV_CMP_CONST,
    "movzx edi, di",
    "movzx esi, si"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp4,
    KCOV_CMP_SIZE4 | KCOV_CMP_CONST,
    "mov edi, edi",
    "mov esi, esi"
);
trace_cmp_callback!(
    __sanitizer_cov_trace_const_cmp8,
    KCOV_CMP_SIZE8 | KCOV_CMP_CONST
);

#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_cov_trace_switch() {
    core::arch::naked_asm!(
        "mov rdx, [rsp]",
        "jmp {}",
        sym record_switch,
    );
}

#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
extern "C" fn record_pc(pc: usize) {
    if load_usize_relaxed(&ACTIVE_KCOV_TASKS) == 0 {
        return;
    }
    // CPU-local state is not usable before OSTD initialization.
    if load_bool_relaxed(&crate::IN_BOOTSTRAP_CONTEXT)
        || !InterruptLevel::current().is_task_context()
    {
        return;
    }
    let Some(task) = Task::current() else {
        return;
    };
    if task.kcov.state() != (STATE_TRACE_PC | IN_SYSCALL) {
        return;
    }
    // Never spin in a callback. A nested invocation while mutating an
    // attachment is ignored, and IRQ handlers never contribute to task coverage.
    let Some(slot) = task.kcov.slot.try_lock() else {
        return;
    };
    if let Some(attachment) = slot.as_ref()
        && attachment.mode == KcovMode::TracePc
    {
        attachment.buffer.record(pc);
    }
}

#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
extern "C" fn record_cmp(arg1: u64, arg2: u64, cmp_type: u64, ip: usize) {
    if load_usize_relaxed(&ACTIVE_KCOV_CMP_TASKS) == 0 {
        return;
    }
    if load_bool_relaxed(&crate::IN_BOOTSTRAP_CONTEXT)
        || !InterruptLevel::current().is_task_context()
    {
        return;
    }
    let Some(task) = Task::current() else {
        return;
    };
    if task.kcov.state() != (STATE_TRACE_CMP | IN_SYSCALL) {
        return;
    }
    let Some(slot) = task.kcov.slot.try_lock() else {
        return;
    };
    if let Some(attachment) = slot.as_ref()
        && attachment.mode == KcovMode::TraceCmp
    {
        let _ = attachment
            .buffer
            .record_cmp(cmp_type, arg1, arg2, ip as u64);
    }
}

#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
extern "C" fn record_switch(val: u64, cases: *const u64, ip: usize) {
    if load_usize_relaxed(&ACTIVE_KCOV_CMP_TASKS) == 0 || cases.is_null() {
        return;
    }
    if load_bool_relaxed(&crate::IN_BOOTSTRAP_CONTEXT)
        || !InterruptLevel::current().is_task_context()
    {
        return;
    }
    let Some(task) = Task::current() else {
        return;
    };
    if task.kcov.state() != (STATE_TRACE_CMP | IN_SYSCALL) {
        return;
    }
    let Some(slot) = task.kcov.slot.try_lock() else {
        return;
    };
    let Some(attachment) = slot.as_ref() else {
        return;
    };
    if attachment.mode != KcovMode::TraceCmp {
        return;
    }
    // SAFETY: LLVM SanitizerCoverage generates `cases` as a static `u64` array
    // `[num_cases, val_bits, case_0, ..., case_{num_cases - 1}]`.
    let (num_cases, val_bits) = unsafe { (cases.read(), cases.add(1).read()) };
    let cmp_type = match val_bits {
        8 => KCOV_CMP_SIZE1 | KCOV_CMP_CONST,
        16 => KCOV_CMP_SIZE2 | KCOV_CMP_CONST,
        32 => KCOV_CMP_SIZE4 | KCOV_CMP_CONST,
        64 => KCOV_CMP_SIZE8 | KCOV_CMP_CONST,
        _ => return,
    };
    let max_cases = num_cases.min(attachment.buffer.entries as u64);
    for i in 0..max_cases {
        // SAFETY: `i < num_cases`, so `2 + i` is within the compiler-emitted table.
        let case_val = unsafe { cases.add(2 + i as usize).read() };
        if !attachment
            .buffer
            .record_cmp(cmp_type, case_val, val, ip as u64)
        {
            break;
        }
    }
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::{mm::FrameAllocOptions, prelude::*};

    #[ktest]
    fn shared_count_is_bounded() {
        let frame: UFrame = FrameAllocOptions::new().alloc_frame().unwrap().into();
        let buffer = KcovBuffer::new(alloc::vec![frame.clone()], 3).unwrap();
        buffer.record(0x1234);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 1);
        assert_eq!(frame.read_once::<usize>(WORD_SIZE).unwrap(), 0x1234);
        buffer.record(0x5678);
        buffer.record(0x9abc);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), 2);
        frame.write_once(0, &usize::MAX).unwrap();
        buffer.record(0xdead);
        assert_eq!(frame.read_once::<usize>(0).unwrap(), usize::MAX);
        frame.write_once(0, &0usize).unwrap();
        buffer.record(0xbeef);
        assert_eq!(frame.read_once::<usize>(WORD_SIZE).unwrap(), 0xbeef);
    }

    #[ktest]
    fn records_across_page_boundary() {
        let frames: Vec<UFrame> = (0..2)
            .map(|_| FrameAllocOptions::new().alloc_frame().unwrap().into())
            .collect();
        frames[0].write_once(0, &(WORDS_PER_PAGE - 1)).unwrap();
        let buffer = KcovBuffer::new(frames.clone(), WORDS_PER_PAGE + 1).unwrap();
        buffer.record(0xcafe);
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
}
