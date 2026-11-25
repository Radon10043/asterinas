// SPDX-License-Identifier: MPL-2.0

//! Support for the code coverage feature of OSDK.
//!
//! For more information about the code coverage feature (`cargo osdk run --coverage`),
//! check out the OSDK reference manual.

use alloc::vec::Vec;

use spin::Once;

use crate::{arch::irq::disable_local_and_halt, power::ExitCode};

/// A hook that is invoked when the system exits to dump the code coverage data.
pub(crate) fn on_system_exit(code: ExitCode) -> ! {
    static COVERAGE_DATA: Once<Vec<u8>> = Once::new();

    let coverage = COVERAGE_DATA.call_once(|| {
        let mut coverage = Vec::new();
        // SAFETY: `call_once` guarantees that this function will not be called concurrently by
        // multiple threads.
        unsafe { minicov::capture_coverage(&mut coverage).unwrap() };
        coverage
    });

    let status = match code {
        ExitCode::Success => "success",
        ExitCode::Failure => "failure",
    };
    crate::early_println!(
        "#### Coverage: {:p} {} {}",
        coverage.as_ptr(),
        coverage.len(),
        status
    );

    // OSDK pauses the VM and copies this immutable buffer before terminating QEMU.
    disable_local_and_halt();
}
