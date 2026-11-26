// SPDX-License-Identifier: MPL-2.0

//! Panic support.

use crate::early_println;

extern crate gimli;

/// The default panic handler for OSTD based kernels.
///
/// The user can override it by defining their own panic handler with the macro
/// `#[ostd::panic_handler]`.
#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
#[linkage = "weak"]
// SAFETY: The name does not collide with other symbols.
#[unsafe(no_mangle)]
pub fn __ostd_panic_handler(info: &core::panic::PanicInfo) -> ! {
    let _irq_guard = crate::irq::disable_local();

    crate::cpu_local_cell! {
        static IN_PANIC: bool = false;
    }

    if IN_PANIC.load() {
        early_println!("The panic handler panicked {:#?}", info);
        abort();
    }

    IN_PANIC.store(true);

    early_println!("Non-resettable panic! {:#?}", info);

    print_stack_trace();
    abort();
}

/// Aborts the system.
///
/// This function will first attempt to power off the system. If that fails, it will halt all CPUs.
#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
pub fn abort() -> ! {
    // TODO: The main purpose of powering off here is to allow QEMU to exit. Otherwise, the CI may
    // freeze after panicking. However, this is unnecessary and may prevent debugging on a real
    // machine (i.e., the message will disappear afterward).
    crate::power::poweroff(crate::power::ExitCode::Failure);
}

/// A guard that aborts the system if dropped.
///
/// This is useful to ensure that certain objects will not be dropped during
/// panic handling.
#[derive(Debug)]
pub(crate) struct PanicGuard {
    _private: (),
}

impl Drop for PanicGuard {
    fn drop(&mut self) {
        early_println!("Panicked in `PanicGuard`, aborting the system");
        abort();
    }
}

impl PanicGuard {
    /// Creates a panic guard that aborts the system if dropped.
    pub(crate) fn new() -> Self {
        PanicGuard { _private: () }
    }

    /// Finishes panic guarding by forgetting the guard.
    ///
    /// After the panic guarding finishes, it no longer aborts the system
    /// when panic happens.
    pub(crate) fn forget(self) {
        core::mem::forget(self);
    }
}

pub use unwinding::panic::{begin_panic, catch_unwind};

/// Global lock serializing stack-trace output across CPUs.
static BACKTRACE_PRINT_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());

/// Prints the stack trace of the current thread to the console.
///
/// The printing procedure is protected by a spin lock to prevent interleaving.
#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
pub fn print_stack_trace() {
    let _lock = BACKTRACE_PRINT_LOCK.lock();
    print_stack_trace_with(crate::console::early_print);
}

/// Prints the stack trace using the lock-free emergency serial console.
///
/// Uses a non-blocking lock attempt so a KASAN fault occurring inside an active
/// backtrace still prints instead of deadlocking.
#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
#[sanitize(address = "off")]
pub(crate) fn print_stack_trace_emergency() {
    let _lock = BACKTRACE_PRINT_LOCK.try_lock();
    print_stack_trace_with(crate::console::emergency_print_args);
}

#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
fn print_stack_trace_with(print_fn: fn(core::fmt::Arguments)) {
    use core::ffi::c_void;

    use gimli::Register;
    use unwinding::abi::{
        _Unwind_Backtrace, _Unwind_FindEnclosingFunction, _Unwind_GetGR, _Unwind_GetIP,
        UnwindContext, UnwindReasonCode,
    };

    print_fn(format_args!("Printing stack trace:\n"));

    struct CallbackData {
        counter: usize,
        print_fn: fn(core::fmt::Arguments),
    }
    #[cfg_attr(
        all(feature = "kasan", target_arch = "x86_64"),
        sanitize(address = "off")
    )]
    extern "C" fn callback(unwind_ctx: &UnwindContext<'_>, arg: *mut c_void) -> UnwindReasonCode {
        let data = unsafe { &mut *(arg as *mut CallbackData) };
        let print_fn = data.print_fn;
        data.counter += 1;
        let pc = _Unwind_GetIP(unwind_ctx);
        if pc > 0 {
            let fde_initial_address = _Unwind_FindEnclosingFunction(pc as *mut c_void) as usize;
            print_fn(format_args!(
                "{:4}: fn {:#18x} - pc {:#18x} / registers:\n",
                data.counter, fde_initial_address, pc,
            ));
        }
        // Print the first 8 general registers for any architecture. The register number follows
        // the DWARF standard.
        for i in 0..8u16 {
            let reg_name = cfg_select! {
                target_arch = "x86_64" => gimli::X86_64::register_name(Register(i)),
                target_arch = "riscv64" => gimli::RiscV::register_name(Register(i)),
                target_arch = "loongarch64" => gimli::LoongArch::register_name(Register(i)),
                target_arch = "aarch64" => gimli::AArch64::register_name(Register(i)),
                _ => None,
            };
            let reg_val = _Unwind_GetGR(unwind_ctx, i as i32);
            if i.is_multiple_of(4) {
                print_fn(format_args!("\n    "));
            }
            print_fn(format_args!(
                " {} {:#18x};",
                reg_name.unwrap_or("unknown"),
                reg_val
            ));
        }
        print_fn(format_args!("\n\n"));
        UnwindReasonCode::NO_REASON
    }

    let mut data = CallbackData {
        counter: 0,
        print_fn,
    };
    _Unwind_Backtrace(callback, &mut data as *mut _ as _);
}
