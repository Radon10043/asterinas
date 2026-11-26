// SPDX-License-Identifier: MPL-2.0

//! KASAN violation classification and diagnostic reporting.
//!
//! Mirrors Linux's `mm/kasan/report.c` and `mm/kasan/report_generic.c`.

use core::sync::atomic::AtomicUsize;

use super::{
    AccessType, KASAN_ALLOCA_LEFT, KASAN_ALLOCA_RIGHT, KASAN_GRANULE_MASK, KASAN_GRANULE_SIZE,
    KASAN_PAGE_FREE, KASAN_PAGE_REDZONE, KASAN_SHADOW_END, KASAN_SHADOW_INIT, KASAN_SHADOW_START,
    KASAN_SLAB_FREE, KASAN_SLAB_REDZONE, addr_has_metadata, align_down, cmpxchg_usize,
    disable_for_report, mem_to_shadow, shadow, shadow_to_mem,
};
use crate::{
    mm::{PAGE_SIZE, kspace},
    util::id_set::Id,
};

const SHADOW_BYTES_PER_ROW: usize = 16;
const SHADOW_ROWS_AROUND_ADDR: usize = 2;
const NO_REPORTING_CPU: usize = usize::MAX;

static REPORTING_CPU: AtomicUsize = AtomicUsize::new(NO_REPORTING_CPU);

/// Locates the first inaccessible byte within `[addr .. addr + size)`.
///
/// Mirrors Linux's `kasan_find_first_bad_addr()` in `mm/kasan/report_generic.c`.
#[sanitize(address = "off")]
pub(super) fn find_first_bad_addr(addr: usize, size: usize) -> usize {
    if size == 0 || addr > usize::MAX - size || !addr_has_metadata(addr) {
        return addr;
    }

    let mut cur = addr;
    let end = addr + size;
    while cur < end {
        // SAFETY: `cur` is within `[addr .. addr + size)` and has mapped shadow.
        let raw = unsafe { shadow::shadow_byte(cur) };
        if raw != KASAN_SHADOW_INIT {
            let s = raw as i8;
            let gran_off = cur & KASAN_GRANULE_MASK;
            let rem_in_gran = KASAN_GRANULE_SIZE - gran_off;
            let chunk = rem_in_gran.min(end - cur);
            let last = (gran_off + chunk - 1) as i8;
            if s <= 0 || last >= s {
                let bad_off = if s > 0 && (gran_off as i8) < s {
                    s as usize - gran_off
                } else {
                    0
                };
                return cur + bad_off;
            }
            cur += chunk;
        } else {
            let next_gran = align_down(cur, KASAN_GRANULE_SIZE).saturating_add(KASAN_GRANULE_SIZE);
            cur = next_gran.min(end);
        }
    }
    addr
}

/// Classifies an access outside the kernel address range, mirroring Linux's
/// `get_wild_bug_type()`.
#[sanitize(address = "off")]
const fn get_wild_bug_type(addr: usize) -> &'static str {
    if addr < PAGE_SIZE {
        "null-ptr-deref"
    } else if addr <= kspace::MAX_USERSPACE_VADDR {
        "user-memory-access"
    } else {
        "wild-memory-access"
    }
}

/// Classifies a violation from the shadow byte at `bad_addr`, mirroring Linux's
/// `get_shadow_bug_type()` in `mm/kasan/report_generic.c`.
#[sanitize(address = "off")]
fn get_shadow_bug_type(bad_addr: usize) -> &'static str {
    // SAFETY: Caller verified `addr_has_metadata(bad_addr)`.
    let mut shadow_val = unsafe { shadow::shadow_byte(bad_addr) };

    const KASAN_GRANULE_LIMIT: u8 = KASAN_GRANULE_SIZE as u8;

    // For a partial-granule out-of-bounds access (shadow byte 1..=7), inspect
    // the immediately following shadow byte to distinguish OOB from UAF.
    if (1..KASAN_GRANULE_LIMIT).contains(&shadow_val) {
        let next_shadow = mem_to_shadow(bad_addr) + 1;
        if next_shadow < KASAN_SHADOW_END {
            // SAFETY: `next_shadow` lies inside `[KASAN_SHADOW_START, KASAN_SHADOW_END)`.
            let next_val = unsafe { *(next_shadow as *const u8) };
            if next_val != KASAN_SHADOW_INIT {
                shadow_val = next_val;
            }
        }
    }

    match shadow_val {
        0..KASAN_GRANULE_LIMIT => "out-of-bounds",
        KASAN_SLAB_REDZONE | KASAN_PAGE_REDZONE => "slab-out-of-bounds",
        KASAN_SLAB_FREE => "slab-use-after-free",
        KASAN_PAGE_FREE => "use-after-free",
        KASAN_ALLOCA_LEFT | KASAN_ALLOCA_RIGHT => "alloca-out-of-bounds",
        _ => "unknown-crash",
    }
}

#[sanitize(address = "off")]
fn get_bug_type(addr: usize, bad_addr: usize) -> &'static str {
    if !addr_has_metadata(addr) || !addr_has_metadata(bad_addr) {
        return get_wild_bug_type(addr);
    }
    get_shadow_bug_type(bad_addr)
}

#[sanitize(address = "off")]
fn acquire_report_slot_or_halt(addr: usize, pc: usize) {
    crate::arch::irq::disable_local();
    let cpu_tag = crate::arch::cpu::local::get_base() as usize;

    match cmpxchg_usize(&REPORTING_CPU, NO_REPORTING_CPU, cpu_tag) {
        Ok(_) => {
            // Disable nested KASAN checks before formatting or unwinding.
            disable_for_report();
        }
        Err(owner) if owner == cpu_tag => {
            crate::early_println!(
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

/// Prints a Linux-style shadow memory window around `addr`.
#[sanitize(address = "off")]
fn print_shadow_for_address(addr: usize) {
    if !addr_has_metadata(addr) {
        return;
    }

    let bad_shadow = mem_to_shadow(addr);
    let center_row = align_down(bad_shadow, SHADOW_BYTES_PER_ROW);
    let start_row = center_row
        .saturating_sub(SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW)
        .max(KASAN_SHADOW_START);
    let end_row = center_row
        .saturating_add((SHADOW_ROWS_AROUND_ADDR + 1) * SHADOW_BYTES_PER_ROW)
        .min(KASAN_SHADOW_END);

    crate::early_println!("Memory state around the buggy address:");
    let mut row = start_row;
    while row < end_row {
        let marker = if row == center_row { ">" } else { " " };
        crate::early_print!("{}{:#018x}:", marker, shadow_to_mem(row));
        for col in 0..SHADOW_BYTES_PER_ROW {
            let shadow_addr = row + col;
            // SAFETY: `[start_row .. end_row)` lies within `[KASAN_SHADOW_START, KASAN_SHADOW_END)`.
            let byte = unsafe { *(shadow_addr as *const u8) };
            if shadow_addr == bad_shadow {
                crate::early_print!(" [{:02x}]", byte);
            } else {
                crate::early_print!(" {:02x}", byte);
            }
        }
        crate::early_println!();
        row += SHADOW_BYTES_PER_ROW;
    }
}

/// Reports a poisoned or invalid memory access and aborts the kernel.
#[sanitize(address = "off")]
pub(super) fn report_access_error(addr: usize, size: usize, access: AccessType, pc: usize) -> ! {
    acquire_report_slot_or_halt(addr, pc);
    let bad_addr = find_first_bad_addr(addr, size);
    let bug_type = get_bug_type(addr, bad_addr);
    let op_desc = match access {
        AccessType::Read => "Read",
        AccessType::Write => "Write",
    };
    let cpu_id = crate::cpu::CpuId::current_racy().as_usize();

    crate::early_println!("\n==================================================================");
    crate::early_println!("BUG: KASAN: {} in {:#x}", bug_type, pc);
    crate::early_println!(
        "{} of size {} at addr {:#x} by CPU {}",
        op_desc,
        size,
        bad_addr,
        cpu_id
    );
    if pc != 0 {
        crate::early_println!("KASAN: pc {:#x}", pc);
    }
    crate::panic::print_stack_trace();
    print_shadow_for_address(bad_addr);
    crate::early_println!("==================================================================");
    crate::panic::abort();
}
