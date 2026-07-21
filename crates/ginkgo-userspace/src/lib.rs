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
/// The kernel updates every item's `pending` field before a successful return
/// and returns the first ready item's index.
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

/// Unmaps an exact virtual-address range from the current process.
///
/// # Safety
///
/// `address..address + length` must describe a live userspace mapping, and no
/// references or pointers into that range may be used after a successful call.
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
