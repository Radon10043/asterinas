// SPDX-License-Identifier: MPL-2.0

//! Per-task kernel PC and comparison coverage through `/dev/kcov`.
//!
//! Follows Linux's KCOV ABI (`KCOV_INIT_TRACE`, `mmap`, `KCOV_ENABLE`,
//! `KCOV_DISABLE`) and exposes `/dev/kcov` as a privileged character device
//! (mode `0600`, requiring `CAP_SYS_ADMIN`) because Asterinas does not yet
//! implement `debugfs`.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.18/source/kernel/kcov.c>.

use device_id::{DeviceId, MinorId};
use ostd::{
    kcov::{KcovBuffer, KcovError, KcovMode},
    mm::FrameAllocOptions,
    task::Task,
};

use crate::{
    device::{
        Device, DeviceType,
        registry::char::{self, MajorIdOwner},
    },
    dispatch_ioctl,
    events::IoEvents,
    fs::{
        devtmpfs::DevtmpfsNodeMeta,
        file::{Mappable, MappableObject, MappedObject, PerOpenFileOps, StatusFlags},
        vfs::{inode::FileOps, path::Path},
    },
    prelude::*,
    process::{
        UserNamespace,
        credentials::capabilities::CapSet,
        posix_thread::AsPosixThread,
        signal::{PollHandle, Pollable},
    },
    security::lsm::hooks as lsm_hooks,
    util::ioctl::RawIoctl,
    vm::vmar::{FileMmapRequest, MapHandle},
};

const KCOV_TRACE_PC: usize = 0;
const KCOV_TRACE_CMP: usize = 1;

// Minimum buffer holds word 0 (count) plus at least one entry.
// Upper bound matches Linux's `INT_MAX / sizeof(unsigned long)`.
const MIN_ENTRIES: usize = 2;
const MAX_ENTRIES: usize = (i32::MAX as usize) / size_of::<usize>();

struct KcovDevice {
    // Keep ownership of the allocated major ID for as long as the device is registered.
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
        // Default devtmpfs mode is `u+rw` (`0600`), matching Linux's debugfs `kcov` mode.
        Some(DevtmpfsNodeMeta::new("kcov").unwrap())
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let task = Task::current().ok_or_else(|| errno!(EPERM, "KCOV requires a user task"))?;
        let posix_thread = task
            .as_posix_thread()
            .ok_or_else(|| errno!(EPERM, "KCOV requires a user task"))?;
        lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
            UserNamespace::get_init_singleton().as_ref(),
            posix_thread,
            CapSet::SYS_ADMIN,
        ))?;

        Ok(Box::new(KcovFile {
            state: Mutex::new(KcovFileState::Uninitialized),
        }))
    }
}

enum KcovFileState {
    /// Freshly opened descriptor before `KCOV_INIT_TRACE`.
    Uninitialized,
    /// `KCOV_INIT_TRACE` configured `nr_entries` words; awaiting `mmap`.
    Initialized { nr_entries: usize },
    /// Backing frames are allocated and ready to be enabled.
    Mapped { buffer: Arc<KcovBuffer> },
}

struct KcovFile {
    state: Mutex<KcovFileState>,
}

impl KcovFile {
    fn init_trace(&self, nr_entries: usize) -> Result<()> {
        let mut state = self.state.lock();
        if !matches!(*state, KcovFileState::Uninitialized) {
            return Err(errno!(EBUSY, "the KCOV buffer is already initialized"));
        }
        if !(MIN_ENTRIES..=MAX_ENTRIES).contains(&nr_entries) {
            return Err(errno!(EINVAL, "invalid KCOV buffer size"));
        }

        *state = KcovFileState::Initialized { nr_entries };
        Ok(())
    }

    fn mapped_buffer(&self) -> Result<Arc<KcovBuffer>> {
        let state = self.state.lock();
        match &*state {
            KcovFileState::Mapped { buffer } => Ok(buffer.clone()),
            KcovFileState::Uninitialized | KcovFileState::Initialized { .. } => Err(errno!(
                EINVAL,
                "the KCOV buffer is not initialized and mapped"
            )),
        }
    }

    fn check_map_size(nr_entries: usize, map_size: usize) -> Result<()> {
        let expected_size = nr_entries
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| errno!(EINVAL, "invalid KCOV mapping size"))?;
        if map_size != expected_size {
            return Err(errno!(EINVAL, "invalid KCOV mapping size"));
        }
        Ok(())
    }

    fn alloc_buffer(nr_entries: usize, map_size: usize) -> Result<Arc<KcovBuffer>> {
        let page_count = map_size / PAGE_SIZE;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(page_count)
            .map_err(|_| errno!(ENOMEM, "failed to allocate KCOV frame list"))?;
        for _ in 0..page_count {
            frames.push(FrameAllocOptions::new().alloc_frame()?.into());
        }
        Ok(KcovBuffer::new(frames, nr_entries)?)
    }

    fn get_or_alloc_buffer(&self, map_size: usize) -> Result<Arc<KcovBuffer>> {
        let nr_entries = {
            let state = self.state.lock();
            match &*state {
                KcovFileState::Uninitialized => {
                    return Err(errno!(EINVAL, "the KCOV buffer is not initialized"));
                }
                KcovFileState::Initialized { nr_entries } => {
                    Self::check_map_size(*nr_entries, map_size)?;
                    *nr_entries
                }
                KcovFileState::Mapped { buffer } => {
                    Self::check_map_size(buffer.nr_entries(), map_size)?;
                    if buffer.is_active() {
                        return Err(errno!(EINVAL, "cannot map an active KCOV buffer"));
                    }
                    return Ok(buffer.clone());
                }
            }
        };

        // Allocate the zeroed backing frames outside the mutex, matching
        // Linux's `kcov_mmap`, and discard them if another `mmap` won the race.
        let candidate = Self::alloc_buffer(nr_entries, map_size)?;
        let (result, discarded) = {
            let mut state = self.state.lock();
            match &*state {
                KcovFileState::Initialized { .. } => {
                    *state = KcovFileState::Mapped {
                        buffer: candidate.clone(),
                    };
                    (Ok(candidate), None)
                }
                KcovFileState::Mapped { buffer } => {
                    let result = if buffer.is_active() {
                        Err(errno!(EINVAL, "cannot map an active KCOV buffer"))
                    } else {
                        Ok(buffer.clone())
                    };
                    (result, Some(candidate))
                }
                KcovFileState::Uninitialized => {
                    unreachable!("KCOV state cannot return to Uninitialized")
                }
            }
        };
        drop(discarded);
        result
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
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            cmd @ InitTrace => {
                self.init_trace(cmd.get())?;
                Ok(0)
            }
            cmd @ Enable => {
                let buffer = self.mapped_buffer()?;
                let mode = match cmd.get() {
                    KCOV_TRACE_PC => KcovMode::TracePc,
                    KCOV_TRACE_CMP => KcovMode::TraceCmp,
                    _ => return Err(errno!(EINVAL, "unsupported KCOV mode")),
                };
                buffer.enable(mode).map_err(|err| match err {
                    KcovError::TaskAlreadyAttached => {
                        errno!(EBUSY, "a KCOV session is already enabled for this task")
                    }
                    KcovError::BufferAlreadyActive => {
                        errno!(EINVAL, "the KCOV buffer is already enabled")
                    }
                    KcovError::NotInTaskContext | KcovError::NotAttached => {
                        errno!(EINVAL, "KCOV cannot be enabled in this context")
                    }
                })?;
                Ok(0)
            }
            cmd @ Disable => {
                if cmd.get() != 0 {
                    return Err(errno!(EINVAL, "unsupported KCOV disable argument"));
                }
                let buffer = self.mapped_buffer()?;
                buffer
                    .disable()
                    .map_err(|_| errno!(EINVAL, "the caller does not own this KCOV session"))?;
                Ok(0)
            }
            _ => Err(errno!(ENOTTY, "unsupported KCOV ioctl")),
        })
    }

    fn mappable(&self, request: FileMmapRequest) -> Result<MappableObject<'_>> {
        if !request.is_shared() {
            return Err(errno!(EINVAL, "KCOV requires a shared mapping"));
        }
        Ok(MappableObject::Device(self as &dyn Mappable))
    }
}

impl Mappable for KcovFile {
    fn map(&self, offset: usize, mut handle: MapHandle) -> Result<Box<dyn MappedObject>> {
        if offset != 0 {
            return Err(errno!(EINVAL, "KCOV mapping offset must be zero"));
        }

        let buffer = self.get_or_alloc_buffer(handle.size())?;
        for (page_index, frame) in buffer.frames().iter().enumerate() {
            handle.map_frame(page_index * PAGE_SIZE, frame.clone());
        }

        Ok(Box::new(KcovMappedObject { buffer }))
    }
}

/// VM-facing view of a mapped KCOV buffer, retaining its backing frames across
/// `close`, `fork`, and partial `munmap`.
///
/// All frames are mapped eagerly in [`KcovFile::map`], so the default
/// [`MappedObject::handle_page_fault`] implementation (returning `EFAULT`) is
/// retained.
#[derive(Debug)]
struct KcovMappedObject {
    buffer: Arc<KcovBuffer>,
}

impl MappedObject for KcovMappedObject {
    fn dup_at_offset(&self, _offset: usize) -> Box<dyn MappedObject> {
        Box::new(Self {
            buffer: self.buffer.clone(),
        })
    }
}

pub(super) fn init_in_first_kthread() {
    let device = Arc::new(KcovDevice {
        major: char::allocate_major().unwrap(),
    });
    char::register(device).unwrap();
}

mod ioctl_defs {
    use crate::{
        ioc,
        util::ioctl::{InData, OutData, PassByVal},
    };

    // Reference: <https://elixir.bootlin.com/linux/v6.18/source/include/uapi/linux/kcov.h>

    // Linux encodes `KCOV_INIT_TRACE` with `_IOR('c', 1, unsigned long)` while
    // passing the buffer entry count directly by value.
    pub(super) type InitTrace = ioc!(KCOV_INIT_TRACE, b'c', 1, OutData<usize, PassByVal>);
    // Linux defines `KCOV_ENABLE` as `_IO('c', 100)` (`0x6364`) and `KCOV_DISABLE`
    // as `_IO('c', 101)` (`0x6365`), leaving the direction and size bits zero
    // while still passing a `usize` argument by value, so legacy encoding is required.
    pub(super) type Enable    = ioc!(KCOV_ENABLE,     0x6364,  InData<usize, PassByVal>);
    pub(super) type Disable   = ioc!(KCOV_DISABLE,    0x6365,  InData<usize, PassByVal>);
}
