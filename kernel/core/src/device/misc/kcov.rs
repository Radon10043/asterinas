// SPDX-License-Identifier: MPL-2.0

//! Per-task kernel PC and comparison coverage through `/dev/kcov`.

use device_id::{DeviceId, MinorId};
use ostd::kcov::{KcovBuffer, KcovMode};

use crate::{
    device::{
        Device, DeviceType,
        registry::char::{self, MajorIdOwner},
    },
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{MappableObject, PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::{
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    thread::Thread,
    util::ioctl::RawIoctl,
    vm::{
        page_cache::{Vmo, VmoCommitError, VmoMapMode, VmoOptions},
        vmar::FileMmapRequest,
    },
};

// Linux's 64-bit ABI. INIT_TRACE encodes _IOR('c', 1, unsigned long), but
// takes the number of entries by value, not a pointer to an output value.
const KCOV_INIT_TRACE: u32 = 0x8008_6301;
const KCOV_ENABLE: u32 = 0x6364;
const KCOV_DISABLE: u32 = 0x6365;
const KCOV_TRACE_PC: usize = 0;
const KCOV_TRACE_CMP: usize = 1;
const MAX_ENTRIES: usize = 4 << 20;

struct KcovDevice {
    // Keep ownership for as long as this device is registered.
    major: MajorIdOwner,
}

impl Device for KcovDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(self.major.get(), MinorId::new(0))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsNodeMeta> {
        Some(DevtmpfsNodeMeta::new("kcov").unwrap())
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let thread = Thread::current().ok_or_else(|| errno!(EPERM))?;
        if !thread
            .as_posix_thread()
            .is_some_and(|thread| thread.credentials().euid().is_root())
        {
            return Err(errno!(EPERM, "KCOV is restricted to root"));
        }

        Ok(Box::new(KcovFile {
            buffer: Mutex::new(None),
        }))
    }
}

struct KcovFile {
    buffer: Mutex<Option<(Arc<Vmo>, Arc<KcovBuffer>)>>,
}

impl KcovFile {
    fn init_trace(&self, entries: usize) -> Result<()> {
        if !(2..=MAX_ENTRIES).contains(&entries) {
            return Err(errno!(EINVAL, "invalid KCOV buffer size"));
        }

        let mut buffer = self.buffer.lock();
        if buffer.is_some() {
            return Err(errno!(EBUSY, "the KCOV buffer is already initialized"));
        }

        // VmoOptions::new creates a nonresizable anonymous VMO. Eagerly commit
        // zeroed, independently allocated pages before publishing the buffer.
        let vmo = VmoOptions::new(entries * size_of::<u64>()).alloc()?;
        let mut frames = Vec::with_capacity(vmo.size() / PAGE_SIZE);
        for offset in (0..vmo.size()).step_by(PAGE_SIZE) {
            let (page, _) = match vmo.try_commit_page(offset, VmoMapMode::SharedRead) {
                Ok(page) => page,
                Err(VmoCommitError::Err(err)) => return Err(err),
                Err(VmoCommitError::NeedIo { .. } | VmoCommitError::WaitUntilInit { .. }) => {
                    // A fresh anonymous VMO has neither a backend nor an
                    // asynchronous initializer.
                    return Err(errno!(EIO, "anonymous KCOV page is not ready"));
                }
            };
            frames.push(page.into());
        }
        let runtime_buffer = KcovBuffer::new(frames, entries)?;
        *buffer = Some((vmo, runtime_buffer));
        Ok(())
    }
}

impl Pollable for KcovFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        mask & (IoEvents::IN | IoEvents::OUT)
    }
}

impl FileOps for KcovFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        Err(errno!(EINVAL, "KCOV does not support reading"))
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        Err(errno!(EINVAL, "KCOV does not support writing"))
    }
}

impl PerOpenFileOps for KcovFile {
    fn check_seekable(&self) -> Result<()> {
        Err(errno!(ESPIPE, "KCOV does not support seeking"))
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, _path: &Path, raw_ioctl: RawIoctl) -> Result<i32> {
        match raw_ioctl.cmd() {
            KCOV_INIT_TRACE => self.init_trace(raw_ioctl.arg())?,
            KCOV_ENABLE => {
                let mode = match raw_ioctl.arg() {
                    KCOV_TRACE_PC => KcovMode::TracePc,
                    KCOV_TRACE_CMP => KcovMode::TraceCmp,
                    _ => return Err(errno!(EINVAL, "unsupported KCOV mode")),
                };
                let buffer = self.buffer.lock();
                let (_, runtime_buffer) = buffer
                    .as_ref()
                    .ok_or_else(|| errno!(EINVAL, "the KCOV buffer is not initialized"))?;
                if !runtime_buffer.enable(mode) {
                    return Err(errno!(EBUSY, "a KCOV session is already enabled"));
                }
            }
            KCOV_DISABLE => {
                if raw_ioctl.arg() != 0 {
                    return Err(errno!(EINVAL, "unsupported KCOV disable argument"));
                }
                let buffer = self.buffer.lock();
                let (_, runtime_buffer) = buffer
                    .as_ref()
                    .ok_or_else(|| errno!(EINVAL, "the KCOV buffer is not initialized"))?;
                if !runtime_buffer.disable() {
                    return Err(errno!(EINVAL, "the caller does not own this KCOV session"));
                }
            }
            _ => return Err(errno!(ENOTTY, "unsupported KCOV ioctl")),
        }
        Ok(0)
    }

    fn mappable(&self, request: FileMmapRequest) -> Result<MappableObject<'_>> {
        let buffer = self.buffer.lock();
        let (vmo, _) = buffer
            .as_ref()
            .ok_or_else(|| errno!(EINVAL, "the KCOV buffer is not initialized"))?;
        if !request.is_shared() || request.offset() != 0 || request.size() != vmo.size() {
            return Err(errno!(
                EINVAL,
                "KCOV requires a complete shared mapping at offset zero"
            ));
        }
        Ok(MappableObject::Vmo(vmo.clone()))
    }
}

pub(super) fn init_in_first_kthread() {
    let device = Arc::new(KcovDevice {
        major: char::allocate_major().unwrap(),
    });
    char::register(device).unwrap();
}
