// SPDX-License-Identifier: MPL-2.0

//! Console output.

use core::fmt::{Arguments, Write};

use crate::arch::serial::SERIAL_PORT;

pub mod uart_ns16650a;

/// Returns whether a fatal diagnostic report currently owns the emergency console.
///
/// Normal console and logger paths should suppress output while this returns
/// `true` so peer CPUs do not interleave bytes with the report.
#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
#[inline]
pub fn is_report_in_progress() -> bool {
    #[cfg(all(feature = "kasan", target_arch = "x86_64"))]
    {
        crate::mm::kasan::is_reporting()
    }
    #[cfg(not(all(feature = "kasan", target_arch = "x86_64")))]
    {
        false
    }
}

/// Prints formatted arguments to the console.
#[cfg_attr(
    all(feature = "kasan", target_arch = "x86_64"),
    sanitize(address = "off")
)]
pub fn early_print(args: Arguments) {
    if is_report_in_progress() {
        return;
    }

    let Some(serial) = SERIAL_PORT.get() else {
        return;
    };

    #[cfg(target_arch = "x86_64")]
    crate::arch::if_tdx_enabled!({
        // Hold the lock to prevent the logs from interleaving.
        let _guard = serial.lock();
        tdx_guest::print(args);
    } else {
        serial.lock().write_fmt(args).unwrap();
    });
    #[cfg(not(target_arch = "x86_64"))]
    serial.lock().write_fmt(args).unwrap();
}

/// Lock-free COM1 emergency writer used for fatal KASAN reports.
///
/// Bypasses `SERIAL_PORT`'s spinlock so faults occurring while a console lock
/// is held still emit a complete report without deadlocking.
#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
struct RawCom1Writer;

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
impl RawCom1Writer {
    const COM1_DATA_PORT: u16 = 0x3F8;
    const COM1_LSR_PORT: u16 = Self::COM1_DATA_PORT + 5;
    const LSR_TX_HOLDING_EMPTY: u8 = 0x20;
    const TX_READY_POLL_LIMIT: usize = 100_000;

    #[sanitize(address = "off")]
    fn write_byte(byte: u8) {
        for _ in 0..Self::TX_READY_POLL_LIMIT {
            let lsr: u8;
            // SAFETY: Reading the legacy COM1 Line Status Register (port 0x3FD)
            // has no memory side effects; `SERIAL_PORT` already probed COM1.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") Self::COM1_LSR_PORT,
                    out("al") lsr,
                    options(nomem, nostack, preserves_flags),
                );
            }
            if (lsr & Self::LSR_TX_HOLDING_EMPTY) != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: Writing a byte to the legacy COM1 transmit holding register
        // (port 0x3F8) is safe when reporting a fatal fault with local IRQs off.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") Self::COM1_DATA_PORT,
                in("al") byte,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
impl Write for RawCom1Writer {
    #[sanitize(address = "off")]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                Self::write_byte(b'\r');
            }
            Self::write_byte(byte);
        }
        Ok(())
    }
}

/// Prints formatted arguments directly to COM1 without acquiring console locks.
#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
#[sanitize(address = "off")]
pub(crate) fn emergency_print_args(args: Arguments) {
    if SERIAL_PORT.get().is_none() {
        return;
    }

    crate::arch::if_tdx_enabled!({
        tdx_guest::print(args);
    } else {
        let _ = RawCom1Writer.write_fmt(args);
    });
}

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
macro_rules! emergency_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::emergency_print_args(format_args!($fmt $(, $($arg)+)?))
    }
}

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
macro_rules! emergency_println {
    () => {
        $crate::console::emergency_print_args(format_args!("\n"))
    };
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::emergency_print_args(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    }
}

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
pub(crate) use {emergency_print, emergency_println};

/// Prints to the console.
#[macro_export]
macro_rules! early_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!($fmt $(, $($arg)+)?))
    }
}

/// Prints to the console with a newline.
#[macro_export]
macro_rules! early_println {
    () => { $crate::early_print!("\n") };
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    }
}
