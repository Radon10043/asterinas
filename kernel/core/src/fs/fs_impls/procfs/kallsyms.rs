// SPDX-License-Identifier: MPL-2.0

//! Kernel text-boundary symbols at `/proc/kallsyms` for KCOV.
//!
//! Exposes `_stext`, `__stext`, and `_etext` to root so KCOV consumers can
//! validate and symbolize recorded kernel program counters against the
//! matching kernel ELF.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/kallsyms`.
pub(super) struct KallsymsFileOps;

impl KallsymsFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Restrict kernel text addresses to root.
        ProcFile::new(Self, parent, mkmod!(u+r))
    }
}

impl ProcFileOps for KallsymsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let range = ostd::mm::kernel_text_range();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{:016x} T _stext", range.start)?;
        writeln!(printer, "{:016x} T __stext", range.start)?;
        writeln!(printer, "{:016x} T _etext", range.end)?;
        Ok(printer.bytes_written())
    }
}
