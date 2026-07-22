#![no_std]

//! Stable, fixed-layout syscall and IPC types shared by the GinkgoOS kernel and userspace.
//!
//! The syscall ABI is currently x86-64 only. System calls use the Linux x86-64
//! register convention: `rax` contains a [`SyscallNumber`], arguments are passed
//! in `rdi`, `rsi`, `rdx`, `r10`, `r8`, and `r9`, and `rax` returns a signed
//! [`Status`] value. Structures passed across the boundary contain integer user
//! addresses rather than Rust pointers.

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Maximum byte payload accepted by one channel message.
pub const CHANNEL_MAX_BYTES: usize = 16 * 1024;
/// Maximum number of handles accepted by one channel message.
pub const CHANNEL_MAX_HANDLES: usize = 16;
/// Serialized size of [`RpcHeader`].
pub const RPC_HEADER_SIZE: usize = core::mem::size_of::<RpcHeader>();
/// A wait deadline which never expires.
pub const DEADLINE_INFINITE: i64 = i64::MAX;

/// Stable syscall numbers. Existing discriminants must never be changed or reused.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SyscallNumber {
    ProcessYield = 0,
    ProcessExit = 1,
    HandleClose = 2,
    HandleDuplicate = 3,
    WaitMany = 4,
    ChannelCreate = 5,
    ChannelWrite = 6,
    ChannelRead = 7,
    SharedMemoryCreate = 8,
    SharedMemoryGetSize = 9,
    SharedMemoryMap = 10,
    SharedMemoryUnmap = 11,
    DebugWrite = 12,
    FilesystemOpen = 13,
    FilesystemRead = 14,
    FilesystemWrite = 15,
    FilesystemStat = 16,
    FilesystemReadDirectory = 17,
    FilesystemTruncate = 18,
    FilesystemUnlink = 19,
}

/// An opaque process-local reference to a kernel object.
#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    FromBytes,
    Hash,
    Immutable,
    IntoBytes,
    KnownLayout,
    Ord,
    PartialEq,
    PartialOrd,
)]
pub struct Handle(u32);

impl Handle {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

bitflags! {
    /// Authority carried by a handle. Rights may only be preserved or reduced.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct Rights: u32 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const WAIT      = 1 << 2;
        const SIGNAL    = 1 << 3;
        const DUPLICATE = 1 << 4;
        const TRANSFER  = 1 << 5;
        const MAP       = 1 << 6;
        const MANAGE    = 1 << 7;
    }
}

bitflags! {
    /// Level-triggered state reported by a waitable kernel object.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct Signals: u32 {
        const READABLE    = 1 << 0;
        const WRITABLE    = 1 << 1;
        const PEER_CLOSED = 1 << 2;
        const SIGNALED    = 1 << 3;
    }
}

bitflags! {
    /// Userspace-defined metadata for an RPC message.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct RpcFlags: u32 {
        const RESPONSE = 1 << 0;
        const ERROR    = 1 << 1;
        const ONE_WAY  = 1 << 2;
    }
}

bitflags! {
    /// Access and creation behavior for [`SyscallNumber::FilesystemOpen`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct FilesystemOpenFlags: u32 {
        const READ     = 1 << 0;
        const WRITE    = 1 << 1;
        const CREATE   = 1 << 2;
        const TRUNCATE = 1 << 3;
    }
}

bitflags! {
    /// Access permitted through a shared-memory mapping.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MapProtection: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXECUTE = 1 << 2;
    }
}

bitflags! {
    /// Placement behavior for a shared-memory mapping.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct MapFlags: u32 {
        /// Map exactly at `SharedMemoryMapArgs::address` and fail if occupied.
        const FIXED = 1 << 0;
    }
}

/// Stable object-kind identifier returned with received handles.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType {
    Channel = 1,
    SharedMemory = 2,
    Window = 3,
    FilesystemRoot = 4,
    File = 5,
}

/// Stable syscall status values. Additional detail is returned in output structs.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ok = 0,
    InvalidHandle = -1,
    WrongObjectType = -2,
    AccessDenied = -3,
    InvalidRights = -4,
    DuplicateHandle = -5,
    MessageTooLarge = -6,
    HandleTableFull = -7,
    ShouldWait = -8,
    PeerClosed = -9,
    BufferTooSmall = -10,
    InvalidMessage = -11,
    CyclicTransfer = -12,
    OutOfMemory = -13,
    InvalidArgument = -14,
    InvalidAddress = -15,
    OutOfRange = -16,
    AlreadyMapped = -17,
    UnknownSyscall = -18,
    NotFound = -19,
    EndOfDirectory = -20,
    Io = -21,
}

impl Status {
    /// Converts a raw, sign-extended syscall return value to a known status.
    pub const fn from_raw(raw: i64) -> Option<Self> {
        Some(match raw {
            0 => Self::Ok,
            -1 => Self::InvalidHandle,
            -2 => Self::WrongObjectType,
            -3 => Self::AccessDenied,
            -4 => Self::InvalidRights,
            -5 => Self::DuplicateHandle,
            -6 => Self::MessageTooLarge,
            -7 => Self::HandleTableFull,
            -8 => Self::ShouldWait,
            -9 => Self::PeerClosed,
            -10 => Self::BufferTooSmall,
            -11 => Self::InvalidMessage,
            -12 => Self::CyclicTransfer,
            -13 => Self::OutOfMemory,
            -14 => Self::InvalidArgument,
            -15 => Self::InvalidAddress,
            -16 => Self::OutOfRange,
            -17 => Self::AlreadyMapped,
            -18 => Self::UnknownSyscall,
            -19 => Self::NotFound,
            -20 => Self::EndOfDirectory,
            -21 => Self::Io,
            _ => return None,
        })
    }

    pub const fn raw(self) -> i32 {
        self as i32
    }
}

/// Fixed-layout sizes of one complete channel message.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct MessageInfo {
    pub byte_count: u32,
    pub handle_count: u16,
    pub reserved: u16,
}

impl MessageInfo {
    pub const fn new(byte_count: u32, handle_count: u16) -> Self {
        Self {
            byte_count,
            handle_count,
            reserved: 0,
        }
    }
}

/// One object in a wait-many request. The kernel writes `pending` before returning.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitItem {
    pub handle: Handle,
    pub wait_for: Signals,
    pub pending: Signals,
}

impl WaitItem {
    pub const fn new(handle: Handle, wait_for: Signals) -> Self {
        Self {
            handle,
            wait_for,
            pending: Signals::empty(),
        }
    }
}

/// Argument block for [`SyscallNumber::WaitMany`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitManyArgs {
    /// Address of a writable array of [`WaitItem`] values, or zero when empty.
    pub items_address: u64,
    pub item_count: u64,
    /// Absolute monotonic deadline in nanoseconds, or [`DEADLINE_INFINITE`].
    pub deadline_ns: i64,
}

/// Output block for [`SyscallNumber::WaitMany`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitManyOutput {
    pub ready_index: u64,
}

/// Output block for syscalls that create one handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleOutput {
    pub handle: Handle,
    pub reserved: u32,
}

impl Default for HandleOutput {
    fn default() -> Self {
        Self {
            handle: Handle::INVALID,
            reserved: 0,
        }
    }
}

/// How a handle is transferred in a channel write.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispositionOperation {
    /// Remove the handle from the sender if the entire write succeeds.
    Move = 0,
    /// Create a duplicate for the receiver and retain the sender's handle.
    Duplicate = 1,
}

/// One rights-attenuating handle operation in a channel write.
///
/// `rights` must be a subset of the source handle's rights. A move requires
/// `Rights::TRANSFER`; a duplicate requires `Rights::DUPLICATE`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleDisposition {
    pub handle: Handle,
    pub operation: DispositionOperation,
    pub rights: Rights,
    pub reserved: u32,
}

impl HandleDisposition {
    pub const fn move_handle(handle: Handle, rights: Rights) -> Self {
        Self {
            handle,
            operation: DispositionOperation::Move,
            rights,
            reserved: 0,
        }
    }

    pub const fn duplicate(handle: Handle, rights: Rights) -> Self {
        Self {
            handle,
            operation: DispositionOperation::Duplicate,
            rights,
            reserved: 0,
        }
    }
}

/// Metadata for one handle received from a channel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedHandle {
    pub handle: Handle,
    pub rights: Rights,
    pub object_type: ObjectType,
    pub reserved: u32,
}

/// Output block for [`SyscallNumber::ChannelCreate`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelCreateOutput {
    pub first: Handle,
    pub second: Handle,
}

impl Default for ChannelCreateOutput {
    fn default() -> Self {
        Self {
            first: Handle::INVALID,
            second: Handle::INVALID,
        }
    }
}

/// Argument block for [`SyscallNumber::ChannelWrite`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelWriteArgs {
    /// Address of `byte_count` readable bytes, or zero when the count is zero.
    pub bytes_address: u64,
    pub byte_count: u64,
    /// Address of `disposition_count` readable [`HandleDisposition`] values.
    pub dispositions_address: u64,
    pub disposition_count: u64,
    /// Reserved for future channel-write options; must currently be zero.
    pub flags: u32,
    pub reserved: u32,
}

/// Argument block for [`SyscallNumber::ChannelRead`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelReadArgs {
    /// Address of `byte_capacity` writable bytes, or zero when the capacity is zero.
    pub bytes_address: u64,
    pub byte_capacity: u64,
    /// Address of `handle_capacity` writable [`ReceivedHandle`] values.
    pub handles_address: u64,
    pub handle_capacity: u64,
    /// Address of a writable [`ChannelReadOutput`].
    pub output_address: u64,
    /// Reserved for future channel-read options; must currently be zero.
    pub flags: u32,
    pub reserved: u32,
}

/// Output block for [`SyscallNumber::ChannelRead`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelReadOutput {
    pub message: MessageInfo,
}

/// Output block for [`SyscallNumber::SharedMemoryGetSize`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedMemorySizeOutput {
    pub size: u64,
}

/// Argument block for [`SyscallNumber::SharedMemoryMap`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryMapArgs {
    /// Requested address, or zero to let the kernel choose when not `FIXED`.
    pub address: u64,
    pub offset: u64,
    pub length: u64,
    pub protection: MapProtection,
    pub flags: MapFlags,
}

/// Output block for [`SyscallNumber::SharedMemoryMap`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedMemoryMapOutput {
    pub address: u64,
}

/// Maximum UTF-8 bytes in one filesystem path component.
pub const FILESYSTEM_NAME_MAX: usize = 252;
/// Maximum bytes transferred by one filesystem read syscall.
pub const FILESYSTEM_READ_MAX_BYTES: usize = 16 * 1024;

/// Argument block for [`SyscallNumber::FilesystemOpen`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemOpenArgs {
    pub name_address: u64,
    pub name_length: u64,
    pub flags: FilesystemOpenFlags,
    pub reserved: u32,
}

/// Output block for [`SyscallNumber::FilesystemRead`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemReadOutput {
    pub count: u64,
}

/// Stable file metadata returned by [`SyscallNumber::FilesystemStat`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemStat {
    pub length: u64,
    pub reserved: [u64; 2],
}

/// One root-directory entry returned by [`SyscallNumber::FilesystemReadDirectory`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemDirectoryEntry {
    pub next_cookie: u64,
    pub length: u64,
    pub name_length: u16,
    pub reserved: [u8; 6],
    pub name: [u8; FILESYSTEM_NAME_MAX],
}

impl Default for FilesystemDirectoryEntry {
    fn default() -> Self {
        Self {
            next_cookie: 0,
            length: 0,
            name_length: 0,
            reserved: [0; 6],
            name: [0; FILESYSTEM_NAME_MAX],
        }
    }
}

/// Zerocopy RPC envelope followed immediately by a postcard payload.
///
/// All fields are little-endian on GinkgoOS's current x86-64 ABI. Protocols
/// must version their `protocol_id`/`method_id` contracts before supporting
/// architectures with a different native endianness.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct RpcHeader {
    pub transaction_id: u64,
    pub protocol_id: u32,
    pub method_id: u32,
    pub flags: u32,
    pub payload_length: u32,
}

impl RpcHeader {
    pub const fn new(
        transaction_id: u64,
        protocol_id: u32,
        method_id: u32,
        flags: RpcFlags,
    ) -> Self {
        Self {
            transaction_id,
            protocol_id,
            method_id,
            flags: flags.bits(),
            payload_length: 0,
        }
    }

    pub const fn rpc_flags(self) -> RpcFlags {
        RpcFlags::from_bits_retain(self.flags)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Handle>() == 4);
    assert!(core::mem::size_of::<Rights>() == 4);
    assert!(core::mem::size_of::<Signals>() == 4);
    assert!(core::mem::size_of::<MessageInfo>() == 8);
    assert!(core::mem::size_of::<WaitItem>() == 12);
    assert!(core::mem::size_of::<WaitManyArgs>() == 24);
    assert!(core::mem::size_of::<WaitManyOutput>() == 8);
    assert!(core::mem::size_of::<HandleOutput>() == 8);
    assert!(core::mem::size_of::<HandleDisposition>() == 16);
    assert!(core::mem::size_of::<ReceivedHandle>() == 16);
    assert!(core::mem::size_of::<ChannelCreateOutput>() == 8);
    assert!(core::mem::size_of::<ChannelWriteArgs>() == 40);
    assert!(core::mem::size_of::<ChannelReadArgs>() == 48);
    assert!(core::mem::size_of::<ChannelReadOutput>() == 8);
    assert!(core::mem::size_of::<SharedMemorySizeOutput>() == 8);
    assert!(core::mem::size_of::<SharedMemoryMapArgs>() == 32);
    assert!(core::mem::size_of::<SharedMemoryMapOutput>() == 8);
    assert!(core::mem::size_of::<FilesystemOpenArgs>() == 24);
    assert!(core::mem::size_of::<FilesystemReadOutput>() == 8);
    assert!(core::mem::size_of::<FilesystemStat>() == 24);
    assert!(core::mem::size_of::<FilesystemDirectoryEntry>() == 280);
    assert!(RPC_HEADER_SIZE == 24);
};

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn syscall_discriminants_are_stable() {
        assert_eq!(SyscallNumber::ProcessYield as u64, 0);
        assert_eq!(SyscallNumber::ProcessExit as u64, 1);
        assert_eq!(SyscallNumber::HandleClose as u64, 2);
        assert_eq!(SyscallNumber::HandleDuplicate as u64, 3);
        assert_eq!(SyscallNumber::WaitMany as u64, 4);
        assert_eq!(SyscallNumber::ChannelCreate as u64, 5);
        assert_eq!(SyscallNumber::ChannelWrite as u64, 6);
        assert_eq!(SyscallNumber::ChannelRead as u64, 7);
        assert_eq!(SyscallNumber::SharedMemoryCreate as u64, 8);
        assert_eq!(SyscallNumber::SharedMemoryGetSize as u64, 9);
        assert_eq!(SyscallNumber::SharedMemoryMap as u64, 10);
        assert_eq!(SyscallNumber::SharedMemoryUnmap as u64, 11);
        assert_eq!(SyscallNumber::DebugWrite as u64, 12);
        assert_eq!(SyscallNumber::FilesystemOpen as u64, 13);
        assert_eq!(SyscallNumber::FilesystemRead as u64, 14);
        assert_eq!(SyscallNumber::FilesystemWrite as u64, 15);
        assert_eq!(SyscallNumber::FilesystemStat as u64, 16);
        assert_eq!(SyscallNumber::FilesystemReadDirectory as u64, 17);
        assert_eq!(SyscallNumber::FilesystemTruncate as u64, 18);
        assert_eq!(SyscallNumber::FilesystemUnlink as u64, 19);
    }

    #[test]
    fn status_discriminants_are_stable_and_round_trip() {
        let statuses = [
            Status::Ok,
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
        ];

        for (index, status) in statuses.into_iter().enumerate() {
            let expected = -(index as i32);
            assert_eq!(status.raw(), expected);
            assert_eq!(Status::from_raw(i64::from(expected)), Some(status));
        }
        assert_eq!(Status::from_raw(1), None);
        assert_eq!(Status::from_raw(i64::from(i32::MIN)), None);
    }

    #[test]
    fn operation_and_object_discriminants_are_stable() {
        assert_eq!(DispositionOperation::Move as u32, 0);
        assert_eq!(DispositionOperation::Duplicate as u32, 1);
        assert_eq!(ObjectType::Channel as u32, 1);
        assert_eq!(ObjectType::SharedMemory as u32, 2);
        assert_eq!(ObjectType::Window as u32, 3);
        assert_eq!(ObjectType::FilesystemRoot as u32, 4);
        assert_eq!(ObjectType::File as u32, 5);
    }

    #[test]
    fn argument_blocks_have_stable_layouts() {
        assert_eq!(size_of::<WaitManyArgs>(), 24);
        assert_eq!(offset_of!(WaitManyArgs, deadline_ns), 16);

        assert_eq!(size_of::<ChannelWriteArgs>(), 40);
        assert_eq!(align_of::<ChannelWriteArgs>(), 8);
        assert_eq!(offset_of!(ChannelWriteArgs, bytes_address), 0);
        assert_eq!(offset_of!(ChannelWriteArgs, dispositions_address), 16);
        assert_eq!(offset_of!(ChannelWriteArgs, flags), 32);

        assert_eq!(size_of::<ChannelReadArgs>(), 48);
        assert_eq!(align_of::<ChannelReadArgs>(), 8);
        assert_eq!(offset_of!(ChannelReadArgs, handles_address), 16);
        assert_eq!(offset_of!(ChannelReadArgs, output_address), 32);
        assert_eq!(offset_of!(ChannelReadArgs, flags), 40);

        assert_eq!(size_of::<SharedMemoryMapArgs>(), 32);
        assert_eq!(offset_of!(SharedMemoryMapArgs, protection), 24);
        assert_eq!(offset_of!(SharedMemoryMapArgs, flags), 28);

        assert_eq!(size_of::<FilesystemOpenArgs>(), 24);
        assert_eq!(offset_of!(FilesystemOpenArgs, flags), 16);
        assert_eq!(size_of::<FilesystemDirectoryEntry>(), 280);
        assert_eq!(offset_of!(FilesystemDirectoryEntry, name), 24);
    }

    #[test]
    fn channel_handle_records_have_stable_layouts() {
        assert_eq!(size_of::<HandleDisposition>(), 16);
        assert_eq!(offset_of!(HandleDisposition, operation), 4);
        assert_eq!(offset_of!(HandleDisposition, rights), 8);
        assert_eq!(size_of::<ReceivedHandle>(), 16);
        assert_eq!(offset_of!(ReceivedHandle, object_type), 8);
    }

    #[test]
    fn mapping_bits_are_stable() {
        assert_eq!(MapProtection::READ.bits(), 1);
        assert_eq!(MapProtection::WRITE.bits(), 2);
        assert_eq!(MapProtection::EXECUTE.bits(), 4);
        assert_eq!(MapFlags::FIXED.bits(), 1);
        assert_eq!(FilesystemOpenFlags::READ.bits(), 1);
        assert_eq!(FilesystemOpenFlags::WRITE.bits(), 2);
        assert_eq!(FilesystemOpenFlags::CREATE.bits(), 4);
        assert_eq!(FilesystemOpenFlags::TRUNCATE.bits(), 8);
    }
}
