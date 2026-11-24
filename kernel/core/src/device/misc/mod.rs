// SPDX-License-Identifier: MPL-2.0

//! Misc devices.
//!
//! Includes major-10 misc devices and dynamically allocated character devices.

use device_id::MajorId;
use spin::Once;

use super::registry::char::{MajorIdOwner, acquire_major};

mod hwrng;
#[cfg(feature = "kcov")]
mod kcov;
#[cfg(all(target_arch = "x86_64", feature = "cvm_guest"))]
pub(crate) mod tdxguest;

static MISC_MAJOR: Once<MajorIdOwner> = Once::new();

pub(super) fn init_in_first_kthread() {
    MISC_MAJOR.call_once(|| acquire_major(MajorId::new(10)).unwrap());

    hwrng::init_in_first_kthread();
    #[cfg(feature = "kcov")]
    kcov::init_in_first_kthread();

    #[cfg(target_arch = "x86_64")]
    ostd::if_tdx_enabled!({
        tdxguest::init().unwrap();
    });
}
