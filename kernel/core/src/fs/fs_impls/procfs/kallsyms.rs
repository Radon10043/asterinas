// SPDX-License-Identifier: MPL-2.0

//! Text-boundary symbols for interpreting KCOV PCs in the matching kernel ELF.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

pub(super) struct KallsymsFileOps;

impl KallsymsFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        // Coverage kernels expose addresses only to the root test executor.
        ProcFile::new(Self, parent, mkmod!(u+r))
    }
}

impl ProcFileOps for KallsymsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let range = ostd::kcov::kernel_text_range();
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "{:016x} T _stext", range.start)?;
        writeln!(printer, "{:016x} T __stext", range.start)?;
        writeln!(printer, "{:016x} T _etext", range.end)?;
        Ok(printer.bytes_written())
    }
}
