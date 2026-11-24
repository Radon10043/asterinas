// SPDX-License-Identifier: MPL-2.0

//! Console output.

use core::fmt::{Arguments, Write};

use crate::arch::serial::SERIAL_PORT;

pub mod uart_ns16650a;

/// Returns whether a fatal KASAN report currently owns the emergency serial port.
#[inline]
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
pub fn is_report_in_progress() -> bool {
    #[cfg(feature = "kasan")]
    {
        crate::mm::kasan::is_reporting()
    }
    #[cfg(not(feature = "kasan"))]
    {
        false
    }
}

/// Prints formatted arguments to the console.
#[cfg_attr(feature = "kasan", sanitize(address = "off"))]
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

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
struct RawCom1Writer;

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
impl RawCom1Writer {
    #[sanitize(address = "off")]
    fn send_byte(byte: u8) {
        const COM1_DATA: u16 = 0x3F8;
        const COM1_LSR: u16 = 0x3FD;
        const LSR_THRE: u8 = 0x20;
        for _ in 0..100_000 {
            let lsr: u8;
            // SAFETY: Reads legacy COM1 status register during emergency output.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") COM1_LSR,
                    out("al") lsr,
                    options(nomem, nostack)
                );
            }
            if lsr == u8::MAX {
                return;
            }
            if (lsr & LSR_THRE) != 0 {
                break;
            }
        }
        // SAFETY: Writes a single character to COM1 TX FIFO during emergency output.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") COM1_DATA,
                in("al") byte,
                options(nomem, nostack)
            );
        }
    }
}

#[cfg(all(feature = "kasan", target_arch = "x86_64"))]
impl Write for RawCom1Writer {
    #[sanitize(address = "off")]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if b == b'\n' {
                Self::send_byte(b'\r');
            }
            Self::send_byte(b);
        }
        Ok(())
    }
}

/// Prints formatted arguments to the console, bypassing contended locks if needed.
#[cfg(feature = "kasan")]
#[sanitize(address = "off")]
pub(crate) fn force_early_print(args: Arguments) {
    if let Some(serial) = SERIAL_PORT.get() {
        let mut guard = None;
        for _ in 0..100_000 {
            if let Some(g) = serial.try_lock() {
                guard = Some(g);
                break;
            }
            core::hint::spin_loop();
        }

        #[cfg(target_arch = "x86_64")]
        crate::arch::if_tdx_enabled!({
            let _guard = guard;
            tdx_guest::print(args);
            return;
        } else {
            if let Some(mut g) = guard {
                let _ = g.write_fmt(args);
                return;
            }
        });
        #[cfg(not(target_arch = "x86_64"))]
        if let Some(mut g) = guard {
            let _ = g.write_fmt(args);
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    crate::arch::if_tdx_enabled!({
        tdx_guest::print(args);
    } else {
        let _ = RawCom1Writer.write_fmt(args);
    });
}

/// Prints to the console, bypassing contended serial locks if needed.
#[cfg(feature = "kasan")]
#[doc(hidden)]
#[macro_export]
macro_rules! force_early_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::force_early_print(format_args!($fmt $(, $($arg)+)?))
    }
}

/// Prints to the console with a newline, bypassing contended serial locks if needed.
#[cfg(feature = "kasan")]
#[doc(hidden)]
#[macro_export]
macro_rules! force_early_println {
    () => { $crate::force_early_print!("\n") };
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::force_early_print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    }
}

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
