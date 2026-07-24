#![no_std]

//! Userspace facade for the stable GinkgoOS syscall ABI and structured IPC codec.
//!
//! The raw syscall entry point and the safe wrappers in this crate target the
//! x86-64 GinkgoOS ABI. Calls which let the kernel write memory use borrowed
//! slices or private fixed-layout output blocks so those buffers remain valid
//! for the duration of the syscall.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("ginkgo-userspace supports only the x86_64 GinkgoOS syscall ABI");

extern crate alloc;

mod window_transport;

use core::mem::MaybeUninit;
use core::ptr::NonNull;

pub use ginkgo_ipc::{decode_structured, encode_structured, StructuredMessageError};
pub use ginkgo_sysapi::*;
pub use ginkgo_window as window;
pub use window_transport::*;

/// Result type used by ergonomic syscall wrappers.
pub type SyscallResult<T> = Result<T, Status>;

/// Invokes one syscall using the Linux x86-64 syscall register convention.
///
/// `number` is placed in `rax`; the six arguments are placed in `rdi`, `rsi`,
/// `rdx`, `r10`, `r8`, and `r9`. The signed value returned in `rax` is returned
/// unchanged. The kernel ABI requires it to be a sign-extended [`Status`].
///
/// # Safety
///
/// A syscall can terminate the process, mutate process state, and dereference
/// user addresses encoded in its arguments. Every address and length must obey
/// the selected syscall's ABI for the entire duration of the call.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn raw_syscall6(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let result: u64;

    // SAFETY: The caller upholds the syscall-specific argument contract. The
    // register assignments and clobbers are those defined by the x86-64 ABI.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number as u64 => result,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            in("r8") arg4,
            in("r9") arg5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    result as i64
}

/// Yields the current process's remaining scheduler time slice.
#[inline]
pub fn process_yield() -> SyscallResult<()> {
    // SAFETY: ProcessYield has no pointer arguments.
    status_result(unsafe { raw_syscall6(SyscallNumber::ProcessYield, 0, 0, 0, 0, 0, 0) })
}

/// Returns nanoseconds elapsed on the kernel's monotonic clock.
#[inline]
pub fn monotonic_time_ns() -> SyscallResult<u64> {
    let mut output = MonotonicTimeOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ClockGetMonotonic,
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.now_ns)
}

/// Returns one coherent system-and-caller memory accounting checkpoint.
#[inline]
pub fn memory_get_info() -> SyscallResult<MemoryInfo> {
    let mut output = MemoryInfo::default();
    // SAFETY: output is writable and remains alive until the syscall returns;
    // version and size exactly identify the fixed ABI layout.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::MemoryGetInfo,
            mut_pointer_address(&mut output),
            u64::from(MemoryInfo::SIZE),
            u64::from(MEMORY_INFO_VERSION),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Fills `output` with unpredictable bytes through an explicit random capability.
#[inline]
pub fn random_fill(source: Handle, output: &mut [u8]) -> SyscallResult<()> {
    // SAFETY: output remains writable for the duration of the syscall.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::RandomFill,
            u64::from(source.raw()),
            mut_slice_address(output),
            output.len() as u64,
            0,
            0,
            0,
        )
    })
}

/// Creates a process from an executable file capability.
///
/// `args_blob` contains zero or more NUL-terminated UTF-8 arguments. Creation
/// transfers or duplicates `startup_handles` atomically according to each
/// disposition. The combined arguments and opaque configuration data are
/// bounded by [`PROCESS_MAX_STARTUP_BYTES`].
pub fn process_create(
    executable: Handle,
    args_blob: &[u8],
    startup_handles: &[HandleDisposition],
    config: &[u8],
) -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    let args = process_create_args(executable, args_blob, startup_handles, config, &mut output)?;

    // SAFETY: args and output remain valid, and all three borrowed input slices
    // remain readable until the syscall returns. Empty slices use address zero.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ProcessCreate,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Creates a process with caller-selected memory ceilings. The kernel rejects
/// every ceiling above the RAM-derived launch default.
pub fn process_create_with_policy(
    executable: Handle,
    args_blob: &[u8],
    startup_handles: &[HandleDisposition],
    config: &[u8],
    policy: &ProcessMemoryPolicy,
) -> SyscallResult<Handle> {
    if policy.version != PROCESS_MEMORY_POLICY_VERSION || policy.size != ProcessMemoryPolicy::SIZE {
        return Err(Status::InvalidArgument);
    }
    let mut output = HandleOutput::default();
    let base = process_create_args(executable, args_blob, startup_handles, config, &mut output)?;
    let args = ProcessCreateArgs2 {
        executable: base.executable,
        reserved: base.reserved,
        args_address: base.args_address,
        args_length: base.args_length,
        startup_handles_address: base.startup_handles_address,
        startup_handle_count: base.startup_handle_count,
        config_address: base.config_address,
        config_length: base.config_length,
        output_address: base.output_address,
        version: ProcessCreateArgs2::VERSION,
        size: ProcessCreateArgs2::SIZE,
        policy_address: pointer_address(policy),
    };
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ProcessCreate2,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Reads stable state, termination, and fault information for a process.
pub fn process_get_info(process: Handle) -> SyscallResult<ProcessInfo> {
    let mut output = ProcessInfo::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ProcessGetInfo,
            u64::from(process.raw()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Requests termination of a process through a capability with `TERMINATE` rights.
pub fn process_terminate(process: Handle) -> SyscallResult<()> {
    // SAFETY: ProcessTerminate receives only an integer handle value.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::ProcessTerminate,
            u64::from(process.raw()),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Requests a bounded orderly machine power transition through explicit authority.
pub fn system_power_request(
    power: Handle,
    action: SystemPowerAction,
    flags: SystemPowerFlags,
) -> SyscallResult<()> {
    // SAFETY: SystemPowerRequest receives only integer values.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::SystemPowerRequest,
            u64::from(power.raw()),
            action as u64,
            u64::from(flags.bits()),
            0,
            0,
            0,
        )
    })
}

/// Cancels a request while it remains in its confirmation interval.
pub fn system_power_cancel(power: Handle) -> SyscallResult<()> {
    // SAFETY: SystemPowerCancel receives only an integer handle value.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::SystemPowerCancel,
            u64::from(power.raw()),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Returns current orderly-shutdown progress and any terminal failure.
pub fn system_power_get_info(power: Handle) -> SyscallResult<SystemPowerInfo> {
    let mut output = SystemPowerInfo::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::SystemPowerGetInfo,
            u64::from(power.raw()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Waits for a process to terminate and returns its final information.
pub fn process_wait(process: Handle, deadline_ns: i64) -> SyscallResult<ProcessInfo> {
    let mut item = [WaitItem::new(process, Signals::TERMINATED)];
    wait_many(&mut item, deadline_ns)?;
    process_get_info(process)
}

/// Returns the calling application's private data-directory capability.
pub fn application_get_data_directory() -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ApplicationGetDataDirectory,
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Creates or opens private application data through an installation-authority root.
pub fn application_data_create(root: Handle, app_id: &str) -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    let args = application_data_create_args(root, app_id, &mut output);
    // SAFETY: args and output remain valid, and app_id remains readable until
    // the syscall returns. An empty app ID uses address zero.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ApplicationDataCreate,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Terminates the current process with `exit_code`.
///
/// This function returns only if the kernel rejects the request. The returned
/// status is not collapsed or translated.
#[inline]
pub fn process_exit(exit_code: i32) -> Status {
    // SAFETY: ProcessExit has no pointer arguments. Cast through i64 so a
    // negative exit code is sign-extended in the argument register.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ProcessExit,
            (i64::from(exit_code)) as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    decode_status(raw)
}

/// Writes bytes to the kernel's initial bounded serial debug sink.
///
/// The kernel defines and enforces the maximum accepted length. This wrapper
/// passes the complete slice address and length without truncating it.
#[inline]
pub fn debug_write(bytes: &[u8]) -> SyscallResult<()> {
    let (address, length) = debug_write_args(bytes);
    // SAFETY: bytes remains readable for the duration of the call, and an
    // empty slice is represented by address zero and length zero.
    status_result(unsafe { raw_syscall6(SyscallNumber::DebugWrite, address, length, 0, 0, 0, 0) })
}

/// Queues interleaved 44.1 kHz signed 16-bit little-endian stereo PCM.
///
/// The kernel accepts frame-aligned writes up to 16 KiB. `ShouldWait` means the
/// bounded hardware queue is full; yield and retry the complete slice.
#[inline]
pub fn audio_write(pcm: &[u8]) -> SyscallResult<()> {
    let address = slice_address(pcm);
    let length = pcm.len() as u64;
    // SAFETY: pcm remains readable for the duration of the syscall.
    status_result(unsafe { raw_syscall6(SyscallNumber::AudioWrite, address, length, 0, 0, 0, 0) })
}

/// Opens or creates one file relative to a filesystem root or directory capability.
pub fn filesystem_open(
    anchor: Handle,
    name: &str,
    flags: FilesystemOpenFlags,
) -> SyscallResult<Handle> {
    let args = filesystem_open_args(name, flags);
    let mut output = HandleOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemOpen,
            u64::from(anchor.raw()),
            pointer_address(&args),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Reads at most 16 KiB from a file at an explicit offset.
pub fn filesystem_read(file: Handle, offset: u64, output: &mut [u8]) -> SyscallResult<usize> {
    let mut result = FilesystemReadOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemRead,
            u64::from(file.raw()),
            offset,
            mut_slice_address(output),
            output.len() as u64,
            mut_pointer_address(&mut result),
            0,
        )
    };
    status_result(raw)?;
    usize::try_from(result.count).map_err(|_| Status::OutOfRange)
}

/// Writes at most 16 KiB to a file at an explicit offset.
pub fn filesystem_write(file: Handle, offset: u64, input: &[u8]) -> SyscallResult<usize> {
    let mut result = FilesystemReadOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemWrite,
            u64::from(file.raw()),
            offset,
            slice_address(input),
            input.len() as u64,
            mut_pointer_address(&mut result),
            0,
        )
    };
    status_result(raw)?;
    usize::try_from(result.count).map_err(|_| Status::OutOfRange)
}

pub fn filesystem_stat(file: Handle) -> SyscallResult<FilesystemStat> {
    let mut output = FilesystemStat::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemStat,
            u64::from(file.raw()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Reads one directory entry at `cookie`. `EndOfDirectory` ends iteration.
pub fn filesystem_read_directory(
    root: Handle,
    cookie: u64,
) -> SyscallResult<FilesystemDirectoryEntry> {
    let mut output = FilesystemDirectoryEntry::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemReadDirectory,
            u64::from(root.raw()),
            cookie,
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

pub fn filesystem_truncate(file: Handle, length: u64) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemTruncate,
            u64::from(file.raw()),
            length,
            0,
            0,
            0,
            0,
        )
    })
}

pub fn filesystem_unlink(root: Handle, name: &str) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemUnlink,
            u64::from(root.raw()),
            slice_address(name.as_bytes()),
            name.len() as u64,
            0,
            0,
            0,
        )
    })
}

/// Opens a directory relative to a filesystem root or directory capability.
pub fn filesystem_open_directory(anchor: Handle, path: &str) -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    let args = filesystem_open_directory_args(anchor, path, &mut output);
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemOpenDirectory,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Creates a directory at a relative UTF-8 path beneath `anchor`.
pub fn filesystem_create_directory(anchor: Handle, path: &str) -> SyscallResult<()> {
    let args = filesystem_create_directory_args(anchor, path);
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemCreateDirectory,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Removes an empty directory at a relative UTF-8 path beneath `anchor`.
pub fn filesystem_remove_directory(anchor: Handle, path: &str) -> SyscallResult<()> {
    let args = filesystem_remove_directory_args(anchor, path);
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemRemoveDirectory,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Renames or moves one relative path, optionally replacing the destination atomically.
pub fn filesystem_rename(
    source_anchor: Handle,
    source_path: &str,
    destination_anchor: Handle,
    destination_path: &str,
    flags: FilesystemRenameFlags,
) -> SyscallResult<()> {
    let args = filesystem_rename_args(
        source_anchor,
        source_path,
        destination_anchor,
        destination_path,
        flags,
    );
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemRename,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Flushes pending data and metadata for a file, directory, or filesystem-root capability.
pub fn filesystem_sync(handle: Handle) -> SyscallResult<()> {
    let args = filesystem_sync_args(handle);
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemSync,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Returns capacity and stable limit information for the filesystem containing `anchor`.
pub fn filesystem_get_info(anchor: Handle) -> SyscallResult<FilesystemInfo> {
    let mut output = FilesystemInfo::default();
    let args = filesystem_get_info_args(anchor, &mut output);
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemGetInfo,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Returns rich metadata for a relative UTF-8 path beneath `anchor`.
pub fn filesystem_get_metadata(anchor: Handle, path: &str) -> SyscallResult<FilesystemMetadata> {
    let mut output = FilesystemMetadata::default();
    let args = filesystem_get_metadata_args(anchor, path, &mut output);
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemGetMetadata,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Reads one rich entry from a directory capability. `EndOfDirectory` ends iteration.
pub fn filesystem_read_directory2(
    directory: Handle,
    cookie: u64,
) -> SyscallResult<FilesystemDirectoryEntry2> {
    let mut output = FilesystemDirectoryEntry2::default();
    let args = filesystem_read_directory2_args(directory, cookie, &mut output);
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::FilesystemReadDirectory2,
            pointer_address(&args),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output)
}

/// Closes a process-local handle.
#[inline]
pub fn handle_close(handle: Handle) -> SyscallResult<()> {
    // SAFETY: HandleClose receives only an integer handle value.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::HandleClose,
            u64::from(handle.raw()),
            0,
            0,
            0,
            0,
            0,
        )
    })
}

/// Duplicates `handle` with the requested subset of its current rights.
#[inline]
pub fn handle_duplicate(handle: Handle, rights: Rights) -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::HandleDuplicate,
            u64::from(handle.raw()),
            u64::from(rights.bits()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Waits until one requested signal is pending or `deadline_ns` is reached.
///
/// The kernel updates every item's `pending` field before returning success or
/// [`Status::TimedOut`]. On success it returns the first ready item's index.
#[inline]
pub fn wait_many(items: &mut [WaitItem], deadline_ns: i64) -> SyscallResult<usize> {
    let args = WaitManyArgs {
        items_address: mut_slice_address(items),
        item_count: items.len() as u64,
        deadline_ns,
    };
    let mut output = WaitManyOutput::default();

    // SAFETY: args and output remain valid for the call, and items describes a
    // writable slice whose address is zero exactly when its length is zero.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::WaitMany,
            pointer_address(&args),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;

    let ready_index = output.ready_index as usize;
    assert!(
        ready_index < items.len(),
        "kernel returned an invalid wait-many index"
    );
    Ok(ready_index)
}

/// Creates a connected channel pair.
#[inline]
pub fn channel_create() -> SyscallResult<(Handle, Handle)> {
    let mut output = ChannelCreateOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ChannelCreate,
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok((output.first, output.second))
}

/// Writes bytes and rights-attenuating handle dispositions to a channel.
///
/// Moved handles are consumed only if the entire write succeeds.
#[inline]
pub fn channel_write(
    channel: Handle,
    bytes: &[u8],
    dispositions: &[HandleDisposition],
) -> SyscallResult<()> {
    let args = channel_write_args(bytes, dispositions);
    // SAFETY: args and both borrowed slices remain readable until the syscall
    // returns. Empty slices are represented by address zero.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::ChannelWrite,
            u64::from(channel.raw()),
            pointer_address(&args),
            0,
            0,
            0,
            0,
        )
    })
}

/// Reads one channel message into caller-owned buffers.
///
/// On success, the first `message.handle_count` entries of `handles` have been
/// initialized by the kernel and may be read with [`MaybeUninit::assume_init`].
/// On failure, callers must treat every entry as uninitialized. In particular,
/// [`Status::BufferTooSmall`] leaves the message queued and reports no partial
/// handles through this wrapper.
#[inline]
pub fn channel_read(
    channel: Handle,
    bytes: &mut [u8],
    handles: &mut [MaybeUninit<ReceivedHandle>],
) -> SyscallResult<MessageInfo> {
    let mut output = ChannelReadOutput::default();
    let args = channel_read_args(bytes, handles, &mut output);

    // SAFETY: args and output remain valid, and the two output slices remain
    // writable until the syscall returns. Empty slices use address zero.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::ChannelRead,
            u64::from(channel.raw()),
            pointer_address(&args),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;

    assert!(
        output.message.byte_count as usize <= bytes.len(),
        "kernel returned a channel byte count larger than the buffer"
    );
    assert!(
        usize::from(output.message.handle_count) <= handles.len(),
        "kernel returned a channel handle count larger than the buffer"
    );
    Ok(output.message)
}

/// Creates a shared-memory object of exactly `size` bytes.
#[inline]
pub fn shared_memory_create(size: u64) -> SyscallResult<Handle> {
    let mut output = HandleOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::SharedMemoryCreate,
            size,
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.handle)
}

/// Returns the shared-memory object's size in bytes.
#[inline]
pub fn shared_memory_get_size(handle: Handle) -> SyscallResult<u64> {
    let mut output = SharedMemorySizeOutput::default();
    // SAFETY: output is writable and remains alive until the syscall returns.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::SharedMemoryGetSize,
            u64::from(handle.raw()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(output.size)
}

/// Maps a range of a shared-memory object into the current address space.
///
/// `requested_address` is a hint unless [`MapFlags::FIXED`] is set. With
/// `FIXED`, the requested range must be free or the kernel returns
/// [`Status::AlreadyMapped`].
///
/// # Safety
///
/// The caller must ensure the resulting mapping does not violate Rust aliasing
/// rules and must not use references into it after it is unmapped. Executable
/// or fixed-address mappings may impose additional process invariants.
#[inline]
pub unsafe fn shared_memory_map(
    handle: Handle,
    offset: u64,
    length: usize,
    requested_address: Option<NonNull<u8>>,
    protection: MapProtection,
    flags: MapFlags,
) -> SyscallResult<NonNull<u8>> {
    let args = SharedMemoryMapArgs {
        address: requested_address.map_or(0, |address| pointer_address(address.as_ptr())),
        offset,
        length: length as u64,
        protection,
        flags,
    };
    let mut output = SharedMemoryMapOutput::default();

    // SAFETY: The caller accepts the mapping's memory-safety obligations. The
    // fixed-layout argument and output blocks remain valid for this call.
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::SharedMemoryMap,
            u64::from(handle.raw()),
            pointer_address(&args),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    Ok(NonNull::new(output.address as usize as *mut u8)
        .expect("kernel returned a null address for a successful mapping"))
}

/// Maps an eager private snapshot of a file range.
///
/// The source offset must be page aligned. The range must fit in the file. The
/// final page is zero-filled after the requested bytes. Closing `file` after a
/// successful call does not invalidate later [`virtual_commit`] calls. Unlinking
/// the mapped file invalidates its retained generation identity; recommit may then
/// fail, and replacement at the same path is not treated as the original file.
///
/// # Safety
///
/// The caller must uphold Rust aliasing rules for the returned memory.
pub unsafe fn virtual_map_file(
    file: Handle,
    offset: u64,
    length: usize,
    requested_address: Option<NonNull<u8>>,
    protection: MapProtection,
    flags: MapFlags,
) -> SyscallResult<NonNull<u8>> {
    let args = VirtualMapFileArgs {
        address: requested_address.map_or(0, |address| pointer_address(address.as_ptr())),
        offset,
        length: length as u64,
        protection,
        flags,
    };
    let mut output = VirtualMapFileOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::VirtualMapFile,
            u64::from(file.raw()),
            pointer_address(&args),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    NonNull::new(output.address as usize as *mut u8).ok_or(Status::InvalidAddress)
}

/// Recommits decommitted file-backed pages from the original file range.
pub unsafe fn virtual_commit(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::VirtualCommit,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Releases file-backed frames while preserving their mapping and backing identity.
pub unsafe fn virtual_decommit(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::VirtualDecommit,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Changes protection on a page-granular file-backed subrange.
pub unsafe fn virtual_protect(
    address: NonNull<u8>,
    length: usize,
    protection: MapProtection,
) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::VirtualProtect,
            pointer_address(address.as_ptr()),
            length as u64,
            u64::from(protection.bits()),
            0,
            0,
            0,
        )
    })
}

/// Removes a page-granular file-backed subrange.
pub unsafe fn virtual_unmap(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::VirtualUnmap,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Maps eager, zero-filled private memory into the current process.
///
/// `length` must be nonzero and is rounded up to a whole-page mapping.
///
/// # Safety
///
/// The caller must uphold Rust aliasing rules for the returned memory.
#[inline]
pub unsafe fn anonymous_map(
    length: usize,
    protection: MapProtection,
) -> SyscallResult<NonNull<u8>> {
    let mut output = AnonymousMapOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousMap,
            length as u64,
            u64::from(protection.bits()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    NonNull::new(output.address as usize as *mut u8).ok_or(Status::InvalidAddress)
}

/// Reserves private anonymous address space without allocating physical frames.
///
/// `length` must be nonzero and is rounded up to a whole-page reservation. The
/// reservation's protection is applied when pages are committed and may be
/// changed with [`anonymous_protect`] before or after commitment.
///
/// # Safety
///
/// The caller must uphold Rust aliasing rules for any subsequently committed memory.
#[inline]
pub unsafe fn anonymous_reserve(
    length: usize,
    protection: MapProtection,
) -> SyscallResult<NonNull<u8>> {
    let mut output = AnonymousReserveOutput::default();
    let raw = unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousReserve,
            length as u64,
            u64::from(protection.bits()),
            mut_pointer_address(&mut output),
            0,
            0,
            0,
        )
    };
    status_result(raw)?;
    NonNull::new(output.address as usize as *mut u8).ok_or(Status::InvalidAddress)
}

/// Eagerly commits zero-filled physical pages into an anonymous reservation.
///
/// `address` must be page aligned. `length` must be nonzero and is rounded up;
/// every intersecting page must currently be reserved and uncommitted.
///
/// # Safety
///
/// The caller must uphold Rust aliasing rules for the newly accessible memory.
#[inline]
pub unsafe fn anonymous_commit(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousCommit,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Releases committed pages while preserving their anonymous reservation.
///
/// `address` must be page aligned and `length` is rounded up. Already-decommitted
/// pages in the range are accepted, making this operation idempotent.
///
/// # Safety
///
/// No pointer or reference into the range may be used unless it is committed again.
#[inline]
pub unsafe fn anonymous_decommit(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousDecommit,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Changes permissions on a page-granular private anonymous subrange.
///
/// `address` must be page aligned and nonzero `length` is rounded up, so every
/// page intersecting the requested byte range receives the new protection.
///
/// # Safety
///
/// The caller must ensure existing references and executable code obey the new permissions.
#[inline]
pub unsafe fn anonymous_protect(
    address: NonNull<u8>,
    length: usize,
    protection: MapProtection,
) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousProtect,
            pointer_address(address.as_ptr()),
            length as u64,
            u64::from(protection.bits()),
            0,
            0,
            0,
        )
    })
}

/// Removes a page-granular private anonymous subrange and its reservation.
///
/// `address` must be page aligned and nonzero `length` is rounded up, so every
/// page intersecting the requested byte range is removed.
///
/// # Safety
///
/// No pointer or reference into the mapping may be used after success.
#[inline]
pub unsafe fn anonymous_unmap(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::AnonymousUnmap,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

/// Unmaps an exact shared-memory range from the current process.
///
/// # Safety
///
/// No pointer or reference into the mapping may be used after success.
#[inline]
pub unsafe fn shared_memory_unmap(address: NonNull<u8>, length: usize) -> SyscallResult<()> {
    // SAFETY: The caller upholds the mapped-range and post-unmap obligations.
    status_result(unsafe {
        raw_syscall6(
            SyscallNumber::SharedMemoryUnmap,
            pointer_address(address.as_ptr()),
            length as u64,
            0,
            0,
            0,
            0,
        )
    })
}

#[inline]
fn decode_status(raw: i64) -> Status {
    Status::from_raw(raw).expect("kernel returned a value outside the stable Status ABI")
}

#[inline]
fn status_result(raw: i64) -> SyscallResult<()> {
    match decode_status(raw) {
        Status::Ok => Ok(()),
        status => Err(status),
    }
}

#[inline]
fn pointer_address<T>(pointer: *const T) -> u64 {
    pointer as usize as u64
}

#[inline]
fn mut_pointer_address<T>(value: &mut T) -> u64 {
    pointer_address(core::ptr::from_mut(value))
}

#[inline]
fn slice_address<T>(slice: &[T]) -> u64 {
    if slice.is_empty() {
        0
    } else {
        pointer_address(slice.as_ptr())
    }
}

#[inline]
fn mut_slice_address<T>(slice: &mut [T]) -> u64 {
    if slice.is_empty() {
        0
    } else {
        pointer_address(slice.as_mut_ptr())
    }
}

fn debug_write_args(bytes: &[u8]) -> (u64, u64) {
    (slice_address(bytes), bytes.len() as u64)
}

fn filesystem_open_args(name: &str, flags: FilesystemOpenFlags) -> FilesystemOpenArgs {
    FilesystemOpenArgs {
        name_address: slice_address(name.as_bytes()),
        name_length: name.len() as u64,
        flags,
        reserved: 0,
    }
}

fn application_data_create_args(
    root: Handle,
    app_id: &str,
    output: &mut HandleOutput,
) -> ApplicationDataCreateArgs {
    ApplicationDataCreateArgs {
        root,
        reserved: 0,
        app_id_address: slice_address(app_id.as_bytes()),
        app_id_length: app_id.len() as u64,
        output_address: mut_pointer_address(output),
    }
}

fn filesystem_open_directory_args(
    anchor: Handle,
    path: &str,
    output: &mut HandleOutput,
) -> FilesystemOpenDirectoryArgs {
    FilesystemOpenDirectoryArgs {
        anchor,
        reserved: 0,
        path_address: slice_address(path.as_bytes()),
        path_length: path.len() as u64,
        output_address: mut_pointer_address(output),
    }
}

fn filesystem_create_directory_args(anchor: Handle, path: &str) -> FilesystemCreateDirectoryArgs {
    FilesystemCreateDirectoryArgs {
        anchor,
        reserved: 0,
        path_address: slice_address(path.as_bytes()),
        path_length: path.len() as u64,
    }
}

fn filesystem_remove_directory_args(anchor: Handle, path: &str) -> FilesystemRemoveDirectoryArgs {
    FilesystemRemoveDirectoryArgs {
        anchor,
        reserved: 0,
        path_address: slice_address(path.as_bytes()),
        path_length: path.len() as u64,
    }
}

fn filesystem_rename_args(
    source_anchor: Handle,
    source_path: &str,
    destination_anchor: Handle,
    destination_path: &str,
    flags: FilesystemRenameFlags,
) -> FilesystemRenameArgs {
    FilesystemRenameArgs {
        source_anchor,
        destination_anchor,
        source_path_address: slice_address(source_path.as_bytes()),
        source_path_length: source_path.len() as u64,
        destination_path_address: slice_address(destination_path.as_bytes()),
        destination_path_length: destination_path.len() as u64,
        flags,
        reserved: 0,
    }
}

fn filesystem_sync_args(handle: Handle) -> FilesystemSyncArgs {
    FilesystemSyncArgs {
        handle,
        reserved: 0,
    }
}

fn filesystem_get_info_args(anchor: Handle, output: &mut FilesystemInfo) -> FilesystemGetInfoArgs {
    FilesystemGetInfoArgs {
        anchor,
        reserved: 0,
        output_address: mut_pointer_address(output),
    }
}

fn filesystem_get_metadata_args(
    anchor: Handle,
    path: &str,
    output: &mut FilesystemMetadata,
) -> FilesystemGetMetadataArgs {
    FilesystemGetMetadataArgs {
        anchor,
        reserved: 0,
        path_address: slice_address(path.as_bytes()),
        path_length: path.len() as u64,
        output_address: mut_pointer_address(output),
    }
}

fn filesystem_read_directory2_args(
    directory: Handle,
    cookie: u64,
    output: &mut FilesystemDirectoryEntry2,
) -> FilesystemReadDirectory2Args {
    FilesystemReadDirectory2Args {
        directory,
        reserved: 0,
        cookie,
        output_address: mut_pointer_address(output),
    }
}

fn channel_write_args(bytes: &[u8], dispositions: &[HandleDisposition]) -> ChannelWriteArgs {
    ChannelWriteArgs {
        bytes_address: slice_address(bytes),
        byte_count: bytes.len() as u64,
        dispositions_address: slice_address(dispositions),
        disposition_count: dispositions.len() as u64,
        flags: 0,
        reserved: 0,
    }
}

fn process_create_args(
    executable: Handle,
    args_blob: &[u8],
    startup_handles: &[HandleDisposition],
    config: &[u8],
    output: &mut HandleOutput,
) -> SyscallResult<ProcessCreateArgs> {
    let argument_count = args_blob.iter().filter(|byte| **byte == 0).count();
    if (!args_blob.is_empty() && args_blob.last() != Some(&0))
        || core::str::from_utf8(args_blob).is_err()
    {
        return Err(Status::InvalidArgument);
    }
    if argument_count > PROCESS_MAX_ARGS
        || startup_handles.len() > PROCESS_MAX_STARTUP_HANDLES
        || args_blob
            .len()
            .checked_add(config.len())
            .is_none_or(|length| length > PROCESS_MAX_STARTUP_BYTES)
    {
        return Err(Status::ResourceLimit);
    }

    Ok(ProcessCreateArgs {
        executable,
        reserved: 0,
        args_address: slice_address(args_blob),
        args_length: args_blob.len() as u64,
        startup_handles_address: slice_address(startup_handles),
        startup_handle_count: startup_handles.len() as u64,
        config_address: slice_address(config),
        config_length: config.len() as u64,
        output_address: mut_pointer_address(output),
    })
}

fn channel_read_args(
    bytes: &mut [u8],
    handles: &mut [MaybeUninit<ReceivedHandle>],
    output: &mut ChannelReadOutput,
) -> ChannelReadArgs {
    ChannelReadArgs {
        bytes_address: mut_slice_address(bytes),
        byte_capacity: bytes.len() as u64,
        handles_address: mut_slice_address(handles),
        handle_capacity: handles.len() as u64,
        output_address: mut_pointer_address(output),
        flags: 0,
        reserved: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_results_preserve_every_error() {
        assert_eq!(status_result(Status::Ok.raw().into()), Ok(()));
        for status in [
            Status::InvalidHandle,
            Status::WrongObjectType,
            Status::AccessDenied,
            Status::InvalidRights,
            Status::DuplicateHandle,
            Status::MessageTooLarge,
            Status::HandleTableFull,
            Status::ShouldWait,
            Status::PeerClosed,
            Status::BufferTooSmall,
            Status::InvalidMessage,
            Status::CyclicTransfer,
            Status::OutOfMemory,
            Status::InvalidArgument,
            Status::InvalidAddress,
            Status::OutOfRange,
            Status::AlreadyMapped,
            Status::UnknownSyscall,
            Status::NotFound,
            Status::EndOfDirectory,
            Status::Io,
            Status::TimedOut,
            Status::ResourceLimit,
            Status::NotDirectory,
            Status::IsDirectory,
            Status::DirectoryNotEmpty,
            Status::AlreadyExists,
            Status::CrossDevice,
        ] {
            assert_eq!(status_result(status.raw().into()), Err(status));
        }
    }

    #[test]
    fn debug_write_arguments_preserve_the_slice() {
        let bytes = b"serial smoke test";
        let (address, length) = debug_write_args(bytes);

        assert_eq!(address, pointer_address(bytes.as_ptr()));
        assert_eq!(length, bytes.len() as u64);

        let (empty_address, empty_length) = debug_write_args(&[]);
        assert_eq!(empty_address, 0);
        assert_eq!(empty_length, 0);
    }

    #[test]
    fn empty_slices_use_the_null_user_address() {
        let bytes: [u8; 0] = [];
        let dispositions: [HandleDisposition; 0] = [];
        let args = channel_write_args(&bytes, &dispositions);

        assert_eq!(args.bytes_address, 0);
        assert_eq!(args.byte_count, 0);
        assert_eq!(args.dispositions_address, 0);
        assert_eq!(args.disposition_count, 0);
    }

    #[test]
    fn write_arguments_retain_nonempty_slice_addresses_and_lengths() {
        let bytes = [1_u8, 2, 3];
        let dispositions = [HandleDisposition::move_handle(
            Handle::from_raw(7),
            Rights::READ,
        )];
        let args = channel_write_args(&bytes, &dispositions);

        assert_eq!(args.bytes_address, pointer_address(bytes.as_ptr()));
        assert_eq!(args.byte_count, 3);
        assert_eq!(
            args.dispositions_address,
            pointer_address(dispositions.as_ptr())
        );
        assert_eq!(args.disposition_count, 1);
        assert_eq!(args.flags, 0);
        assert_eq!(args.reserved, 0);
    }

    #[test]
    fn application_data_create_arguments_retain_root_app_id_and_output() {
        let root = Handle::from_raw(37);
        let app_id = "org.ginkgo.example";
        let mut output = HandleOutput::default();
        let output_address = mut_pointer_address(&mut output);

        let args = application_data_create_args(root, app_id, &mut output);

        assert_eq!(args.root, root);
        assert_eq!(args.reserved, 0);
        assert_eq!(args.app_id_address, pointer_address(app_id.as_ptr()));
        assert_eq!(args.app_id_length, app_id.len() as u64);
        assert_eq!(args.output_address, output_address);

        let empty = application_data_create_args(root, "", &mut output);
        assert_eq!(empty.app_id_address, 0);
        assert_eq!(empty.app_id_length, 0);
    }

    #[test]
    fn filesystem_path_arguments_retain_anchors_paths_flags_and_outputs() {
        let anchor = Handle::from_raw(41);
        let destination_anchor = Handle::from_raw(42);
        let path = "parent/child";
        let destination = "archive/child";

        let open = filesystem_open_args(path, FilesystemOpenFlags::READ);
        assert_eq!(open.name_address, pointer_address(path.as_ptr()));
        assert_eq!(open.name_length, path.len() as u64);
        assert_eq!(open.flags, FilesystemOpenFlags::READ);
        assert_eq!(open.reserved, 0);

        let mut handle_output = HandleOutput::default();
        let handle_output_address = mut_pointer_address(&mut handle_output);
        let open_directory = filesystem_open_directory_args(anchor, path, &mut handle_output);
        assert_eq!(open_directory.anchor, anchor);
        assert_eq!(open_directory.reserved, 0);
        assert_eq!(open_directory.path_address, pointer_address(path.as_ptr()));
        assert_eq!(open_directory.path_length, path.len() as u64);
        assert_eq!(open_directory.output_address, handle_output_address);

        let create = filesystem_create_directory_args(anchor, path);
        assert_eq!(create.anchor, anchor);
        assert_eq!(create.reserved, 0);
        assert_eq!(create.path_address, pointer_address(path.as_ptr()));
        assert_eq!(create.path_length, path.len() as u64);

        let remove = filesystem_remove_directory_args(anchor, path);
        assert_eq!(remove.anchor, anchor);
        assert_eq!(remove.reserved, 0);
        assert_eq!(remove.path_address, pointer_address(path.as_ptr()));
        assert_eq!(remove.path_length, path.len() as u64);

        let rename = filesystem_rename_args(
            anchor,
            path,
            destination_anchor,
            destination,
            FilesystemRenameFlags::REPLACE,
        );
        assert_eq!(rename.source_anchor, anchor);
        assert_eq!(rename.destination_anchor, destination_anchor);
        assert_eq!(rename.source_path_address, pointer_address(path.as_ptr()));
        assert_eq!(rename.source_path_length, path.len() as u64);
        assert_eq!(
            rename.destination_path_address,
            pointer_address(destination.as_ptr())
        );
        assert_eq!(rename.destination_path_length, destination.len() as u64);
        assert_eq!(rename.flags, FilesystemRenameFlags::REPLACE);
        assert_eq!(rename.reserved, 0);

        let no_replace = filesystem_rename_args(
            anchor,
            path,
            destination_anchor,
            destination,
            FilesystemRenameFlags::empty(),
        );
        assert!(no_replace.flags.is_empty());
    }

    #[test]
    fn filesystem_non_path_arguments_retain_handles_cookies_and_outputs() {
        let anchor = Handle::from_raw(51);
        let sync = filesystem_sync_args(anchor);
        assert_eq!(sync.handle, anchor);
        assert_eq!(sync.reserved, 0);

        let mut info = FilesystemInfo::default();
        let info_address = mut_pointer_address(&mut info);
        let get_info = filesystem_get_info_args(anchor, &mut info);
        assert_eq!(get_info.anchor, anchor);
        assert_eq!(get_info.reserved, 0);
        assert_eq!(get_info.output_address, info_address);

        let path = "nested/file";
        let mut metadata = FilesystemMetadata::default();
        let metadata_address = mut_pointer_address(&mut metadata);
        let get_metadata = filesystem_get_metadata_args(anchor, path, &mut metadata);
        assert_eq!(get_metadata.anchor, anchor);
        assert_eq!(get_metadata.reserved, 0);
        assert_eq!(get_metadata.path_address, pointer_address(path.as_ptr()));
        assert_eq!(get_metadata.path_length, path.len() as u64);
        assert_eq!(get_metadata.output_address, metadata_address);

        let mut entry = FilesystemDirectoryEntry2::default();
        let entry_address = mut_pointer_address(&mut entry);
        let read_directory = filesystem_read_directory2_args(anchor, 99, &mut entry);
        assert_eq!(read_directory.directory, anchor);
        assert_eq!(read_directory.reserved, 0);
        assert_eq!(read_directory.cookie, 99);
        assert_eq!(read_directory.output_address, entry_address);
    }

    #[test]
    fn empty_filesystem_paths_use_null_addresses() {
        let anchor = Handle::from_raw(61);
        let mut output = HandleOutput::default();
        let open = filesystem_open_args("", FilesystemOpenFlags::empty());
        let open_directory = filesystem_open_directory_args(anchor, "", &mut output);
        let create = filesystem_create_directory_args(anchor, "");
        let remove = filesystem_remove_directory_args(anchor, "");
        let rename = filesystem_rename_args(anchor, "", anchor, "", FilesystemRenameFlags::empty());

        assert_eq!(open.name_address, 0);
        assert_eq!(open.name_length, 0);
        assert_eq!(open_directory.path_address, 0);
        assert_eq!(open_directory.path_length, 0);
        assert_eq!(create.path_address, 0);
        assert_eq!(create.path_length, 0);
        assert_eq!(remove.path_address, 0);
        assert_eq!(remove.path_length, 0);
        assert_eq!(rename.source_path_address, 0);
        assert_eq!(rename.source_path_length, 0);
        assert_eq!(rename.destination_path_address, 0);
        assert_eq!(rename.destination_path_length, 0);
    }

    #[test]
    fn process_create_arguments_retain_all_borrowed_inputs() {
        let arguments = b"program\0--flag\0";
        let handles = [HandleDisposition::duplicate(
            Handle::from_raw(9),
            Rights::READ,
        )];
        let config = b"mode=test";
        let mut output = HandleOutput::default();
        let output_address = mut_pointer_address(&mut output);

        let args = process_create_args(
            Handle::from_raw(7),
            arguments,
            &handles,
            config,
            &mut output,
        )
        .unwrap();

        assert_eq!(args.executable, Handle::from_raw(7));
        assert_eq!(args.reserved, 0);
        assert_eq!(args.args_address, pointer_address(arguments.as_ptr()));
        assert_eq!(args.args_length, arguments.len() as u64);
        assert_eq!(
            args.startup_handles_address,
            pointer_address(handles.as_ptr())
        );
        assert_eq!(args.startup_handle_count, 1);
        assert_eq!(args.config_address, pointer_address(config.as_ptr()));
        assert_eq!(args.config_length, config.len() as u64);
        assert_eq!(args.output_address, output_address);
    }

    #[test]
    fn process_create_rejects_invalid_or_unbounded_startup_data() {
        let mut output = HandleOutput::default();
        assert_eq!(
            process_create_args(Handle::from_raw(1), b"unterminated", &[], &[], &mut output),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            process_create_args(Handle::from_raw(1), &[0xff, 0], &[], &[], &mut output),
            Err(Status::InvalidArgument)
        );

        let too_many_arguments = [0_u8; PROCESS_MAX_ARGS + 1];
        assert_eq!(
            process_create_args(
                Handle::from_raw(1),
                &too_many_arguments,
                &[],
                &[],
                &mut output,
            ),
            Err(Status::ResourceLimit)
        );

        let too_many_handles =
            [HandleDisposition::move_handle(Handle::from_raw(2), Rights::TRANSFER);
                PROCESS_MAX_STARTUP_HANDLES + 1];
        assert_eq!(
            process_create_args(
                Handle::from_raw(1),
                &[],
                &too_many_handles,
                &[],
                &mut output,
            ),
            Err(Status::ResourceLimit)
        );

        let oversized = [0_u8; PROCESS_MAX_STARTUP_BYTES + 1];
        assert_eq!(
            process_create_args(Handle::from_raw(1), &[], &[], &oversized, &mut output),
            Err(Status::ResourceLimit)
        );
    }

    #[test]
    fn empty_process_create_inputs_use_null_addresses() {
        let mut output = HandleOutput::default();
        let args = process_create_args(Handle::from_raw(1), &[], &[], &[], &mut output).unwrap();

        assert_eq!(args.args_address, 0);
        assert_eq!(args.startup_handles_address, 0);
        assert_eq!(args.config_address, 0);
        assert_ne!(args.output_address, 0);
    }

    #[test]
    fn read_arguments_use_writable_buffers_and_private_output() {
        let mut bytes = [0_u8; 8];
        let mut handles = [MaybeUninit::<ReceivedHandle>::uninit(); 2];
        let mut output = ChannelReadOutput::default();
        let bytes_address = pointer_address(bytes.as_mut_ptr());
        let handles_address = pointer_address(handles.as_mut_ptr());
        let output_address = pointer_address(core::ptr::from_mut(&mut output));

        let args = channel_read_args(&mut bytes, &mut handles, &mut output);

        assert_eq!(args.bytes_address, bytes_address);
        assert_eq!(args.byte_capacity, 8);
        assert_eq!(args.handles_address, handles_address);
        assert_eq!(args.handle_capacity, 2);
        assert_eq!(args.output_address, output_address);
        assert_eq!(args.flags, 0);
        assert_eq!(args.reserved, 0);
    }

    #[test]
    fn empty_read_buffers_use_null_addresses_but_not_a_null_output() {
        let mut bytes: [u8; 0] = [];
        let mut handles: [MaybeUninit<ReceivedHandle>; 0] = [];
        let mut output = ChannelReadOutput::default();
        let args = channel_read_args(&mut bytes, &mut handles, &mut output);

        assert_eq!(args.bytes_address, 0);
        assert_eq!(args.handles_address, 0);
        assert_ne!(args.output_address, 0);
    }
}
