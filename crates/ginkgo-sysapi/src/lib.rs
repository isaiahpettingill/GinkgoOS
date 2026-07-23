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
/// Maximum random bytes returned by one bounded syscall.
pub const RANDOM_MAX_BYTES: usize = 4096;
/// Maximum number of NUL-terminated arguments in a process startup blob.
pub const PROCESS_MAX_ARGS: usize = 32;
/// Maximum combined byte length of process arguments and configuration data.
pub const PROCESS_MAX_STARTUP_BYTES: usize = 16 * 1024;
/// Maximum number of handles transferred during process creation.
pub const PROCESS_MAX_STARTUP_HANDLES: usize = 16;
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
    /// Queues interleaved 44.1 kHz signed 16-bit little-endian stereo PCM.
    AudioWrite = 20,
    /// Reads the kernel's monotonic nanosecond clock.
    ClockGetMonotonic = 21,
    /// Fills a writable buffer through a random-source capability.
    RandomFill = 22,
    /// Creates a process from an executable file capability.
    ProcessCreate = 23,
    /// Reads stable status information through a process capability.
    ProcessGetInfo = 24,
    /// Requests termination through a process capability.
    ProcessTerminate = 25,
    /// Returns the calling application's private data-directory capability.
    ApplicationGetDataDirectory = 26,
    FilesystemOpenDirectory = 27,
    FilesystemCreateDirectory = 28,
    FilesystemRemoveDirectory = 29,
    FilesystemRename = 30,
    FilesystemSync = 31,
    FilesystemGetInfo = 32,
    FilesystemGetMetadata = 33,
    FilesystemReadDirectory2 = 34,
    /// Creates or opens an application's private data directory during installation.
    ApplicationDataCreate = 35,
    /// Requests an orderly power-off or reboot through a system-power capability.
    SystemPowerRequest = 36,
    /// Cancels a power request before irreversible synchronization begins.
    SystemPowerCancel = 37,
    /// Reads progress and failure information through a system-power capability.
    SystemPowerGetInfo = 38,
    /// Maps eager zero-filled private memory; length is rounded up to whole pages.
    AnonymousMap = 39,
    /// Removes an aligned anonymous range; length is rounded up to whole pages.
    AnonymousUnmap = 40,
    /// Protects an aligned anonymous range, rounding length up and enforcing W^X.
    AnonymousProtect = 41,
    /// Reserves page-rounded anonymous space without allocating frames or quota.
    AnonymousReserve = 42,
    /// Commits zero-filled pages at an aligned address, rounding length up.
    AnonymousCommit = 43,
    /// Decommits an aligned page-rounded range while preserving its reservation.
    AnonymousDecommit = 44,
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
        const INSPECT   = 1 << 8;
        const TERMINATE = 1 << 9;
        const EXECUTE   = 1 << 10;
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
        const TERMINATED  = 1 << 4;
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
        const EXECUTE  = 1 << 4;
    }
}

bitflags! {
    /// Rename behavior for [`SyscallNumber::FilesystemRename`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct FilesystemRenameFlags: u32 {
        /// Atomically replace an existing destination. Empty flags require no replacement.
        const REPLACE = 1 << 0;
    }
}

bitflags! {
    /// Stable filesystem properties returned in [`FilesystemInfo::flags`].
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct FilesystemInfoFlags: u32 {
        const READ_ONLY = 1 << 0;
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

/// Requested terminal machine state.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPowerAction {
    PowerOff = 1,
    Reboot = 2,
}

impl SystemPowerAction {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::PowerOff),
            2 => Some(Self::Reboot),
            _ => None,
        }
    }
}

/// Observable phase of the bounded orderly-shutdown state machine.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPowerState {
    Idle = 0,
    Requested = 1,
    Quiescing = 2,
    Synchronizing = 3,
    Committing = 4,
    Canceled = 5,
    Failed = 6,
}

impl SystemPowerState {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Idle),
            1 => Some(Self::Requested),
            2 => Some(Self::Quiescing),
            3 => Some(Self::Synchronizing),
            4 => Some(Self::Committing),
            5 => Some(Self::Canceled),
            6 => Some(Self::Failed),
            _ => None,
        }
    }
}

bitflags! {
    /// Policy selected by the authorized requester.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct SystemPowerFlags: u32 {
        /// Continue to firmware after bounded process/device failures.
        const FORCE = 1 << 0;
    }
}

/// Stable progress record returned by [`SyscallNumber::SystemPowerGetInfo`].
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq,
)]
pub struct SystemPowerInfo {
    pub state: u32,
    pub action: u32,
    pub flags: u32,
    /// A [`Status`] value, or zero when no failure has occurred.
    pub failure_status: i32,
    pub sequence: u64,
    pub deadline_ns: u64,
}

impl SystemPowerInfo {
    pub const fn power_state(self) -> Option<SystemPowerState> {
        SystemPowerState::from_raw(self.state)
    }

    pub const fn power_action(self) -> Option<SystemPowerAction> {
        SystemPowerAction::from_raw(self.action)
    }

    pub const fn power_flags(self) -> SystemPowerFlags {
        SystemPowerFlags::from_bits_retain(self.flags)
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
    RandomSource = 6,
    Process = 7,
    ApplicationData = 8,
    Directory = 9,
    SystemPower = 10,
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
    TimedOut = -22,
    ResourceLimit = -23,
    NotDirectory = -24,
    IsDirectory = -25,
    DirectoryNotEmpty = -26,
    AlreadyExists = -27,
    CrossDevice = -28,
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
            -22 => Self::TimedOut,
            -23 => Self::ResourceLimit,
            -24 => Self::NotDirectory,
            -25 => Self::IsDirectory,
            -26 => Self::DirectoryNotEmpty,
            -27 => Self::AlreadyExists,
            -28 => Self::CrossDevice,
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
///
/// `ready_index` is defined only when the syscall returns [`Status::Ok`]. The
/// kernel still updates every [`WaitItem::pending`] field when it returns
/// [`Status::TimedOut`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitManyOutput {
    pub ready_index: u64,
}

/// Output block for [`SyscallNumber::ClockGetMonotonic`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MonotonicTimeOutput {
    pub now_ns: u64,
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

/// Externally visible lifecycle state of a process capability.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Running = 0,
    Terminated = 1,
}

impl ProcessState {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Running),
            1 => Some(Self::Terminated),
            _ => None,
        }
    }
}

/// Why a process reached [`ProcessState::Terminated`].
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTerminationCause {
    None = 0,
    Exited = 1,
    Terminated = 2,
    Faulted = 3,
}

impl ProcessTerminationCause {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Exited),
            2 => Some(Self::Terminated),
            3 => Some(Self::Faulted),
            _ => None,
        }
    }
}

/// Stable classification of a process-ending userspace fault.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessFault {
    None = 0,
    PageFault = 1,
    GeneralProtection = 2,
    InvalidOpcode = 3,
    InvalidUserContext = 4,
    ResourceLimit = 5,
    Other = 6,
    OutOfMemory = 7,
}

impl ProcessFault {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::PageFault),
            2 => Some(Self::GeneralProtection),
            3 => Some(Self::InvalidOpcode),
            4 => Some(Self::InvalidUserContext),
            5 => Some(Self::ResourceLimit),
            6 => Some(Self::Other),
            7 => Some(Self::OutOfMemory),
            _ => None,
        }
    }
}

/// Argument block for [`SyscallNumber::ProcessCreate`].
///
/// `args_address..args_length` is a blob of NUL-terminated UTF-8 arguments.
/// The blob contains at most [`PROCESS_MAX_ARGS`] arguments. The combined
/// `args_length` and `config_length` is at most
/// [`PROCESS_MAX_STARTUP_BYTES`], and `startup_handle_count` is at most
/// [`PROCESS_MAX_STARTUP_HANDLES`]. Handle dispositions are committed only if
/// process creation succeeds completely.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessCreateArgs {
    pub executable: Handle,
    pub reserved: u32,
    pub args_address: u64,
    pub args_length: u64,
    pub startup_handles_address: u64,
    pub startup_handle_count: u64,
    pub config_address: u64,
    pub config_length: u64,
    /// Address of a writable [`HandleOutput`] receiving the process capability.
    pub output_address: u64,
}

/// Stable process information returned by [`SyscallNumber::ProcessGetInfo`].
///
/// The discriminated fields intentionally use raw integers: a kernel copying a
/// future discriminant into an older userspace binary must not create an invalid
/// Rust enum value. Use the accessors to interpret values known to this ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProcessInfo {
    pub state: u32,
    pub cause: u32,
    pub exit_code: i32,
    pub fault: u32,
    pub fault_code: u64,
    pub fault_address: u64,
}

impl ProcessInfo {
    pub const fn process_state(self) -> Option<ProcessState> {
        ProcessState::from_raw(self.state)
    }

    pub const fn termination_cause(self) -> Option<ProcessTerminationCause> {
        ProcessTerminationCause::from_raw(self.cause)
    }

    pub const fn process_fault(self) -> Option<ProcessFault> {
        ProcessFault::from_raw(self.fault)
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

/// Output block for mapping syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SharedMemoryMapOutput {
    pub address: u64,
}

/// Output block for [`SyscallNumber::AnonymousMap`].
pub type AnonymousMapOutput = SharedMemoryMapOutput;
/// Output block for [`SyscallNumber::AnonymousReserve`].
pub type AnonymousReserveOutput = SharedMemoryMapOutput;

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

/// Stable filesystem object kind used by metadata and directory enumeration.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemEntryKind {
    File = 1,
    Directory = 2,
}

impl FilesystemEntryKind {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::File),
            2 => Some(Self::Directory),
            _ => None,
        }
    }
}

/// Argument block for [`SyscallNumber::FilesystemOpenDirectory`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemOpenDirectoryArgs {
    pub anchor: Handle,
    pub reserved: u32,
    pub path_address: u64,
    pub path_length: u64,
    /// Address of a writable [`HandleOutput`].
    pub output_address: u64,
}

/// Argument block for [`SyscallNumber::FilesystemCreateDirectory`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemCreateDirectoryArgs {
    pub anchor: Handle,
    pub reserved: u32,
    pub path_address: u64,
    pub path_length: u64,
}

/// Argument block for [`SyscallNumber::FilesystemRemoveDirectory`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemRemoveDirectoryArgs {
    pub anchor: Handle,
    pub reserved: u32,
    pub path_address: u64,
    pub path_length: u64,
}

/// Argument block for [`SyscallNumber::FilesystemRename`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemRenameArgs {
    pub source_anchor: Handle,
    pub destination_anchor: Handle,
    pub source_path_address: u64,
    pub source_path_length: u64,
    pub destination_path_address: u64,
    pub destination_path_length: u64,
    pub flags: FilesystemRenameFlags,
    pub reserved: u32,
}

/// Argument block for [`SyscallNumber::FilesystemSync`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemSyncArgs {
    pub handle: Handle,
    pub reserved: u32,
}

/// Argument block for [`SyscallNumber::FilesystemGetInfo`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemGetInfoArgs {
    pub anchor: Handle,
    pub reserved: u32,
    /// Address of a writable [`FilesystemInfo`].
    pub output_address: u64,
}

/// Stable filesystem capacity and limit information.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemInfo {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub block_size: u32,
    pub max_name_length: u32,
    pub max_path_depth: u32,
    pub flags: u32,
    pub reserved: [u64; 3],
}

impl FilesystemInfo {
    pub const fn filesystem_flags(self) -> FilesystemInfoFlags {
        FilesystemInfoFlags::from_bits_retain(self.flags)
    }
}

/// Argument block for [`SyscallNumber::FilesystemGetMetadata`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemGetMetadataArgs {
    pub anchor: Handle,
    pub reserved: u32,
    pub path_address: u64,
    pub path_length: u64,
    /// Address of a writable [`FilesystemMetadata`].
    pub output_address: u64,
}

/// Stable metadata for one filesystem object.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilesystemMetadata {
    pub kind: u32,
    pub mode: u32,
    pub size: u64,
    pub stable_id: u64,
    pub ctime_ns: u64,
    pub mtime_ns: u64,
    pub uid: u32,
    pub gid: u32,
    pub policy: u32,
    pub reserved: [u32; 3],
}

impl FilesystemMetadata {
    pub const fn entry_kind(self) -> Option<FilesystemEntryKind> {
        FilesystemEntryKind::from_raw(self.kind)
    }
}

/// Argument block for [`SyscallNumber::FilesystemReadDirectory2`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemReadDirectory2Args {
    pub directory: Handle,
    pub reserved: u32,
    pub cookie: u64,
    /// Address of a writable [`FilesystemDirectoryEntry2`].
    pub output_address: u64,
}

/// Argument block for [`SyscallNumber::ApplicationDataCreate`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationDataCreateArgs {
    /// Filesystem-root capability carrying installation authority.
    pub root: Handle,
    pub reserved: u32,
    pub app_id_address: u64,
    pub app_id_length: u64,
    /// Address of a writable [`HandleOutput`].
    pub output_address: u64,
}

/// One rich directory entry returned by [`SyscallNumber::FilesystemReadDirectory2`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemDirectoryEntry2 {
    pub next_cookie: u64,
    pub size: u64,
    pub stable_id: u64,
    pub kind: u32,
    pub name_length: u16,
    pub reserved: [u8; 6],
    pub name: [u8; FILESYSTEM_NAME_MAX],
}

impl FilesystemDirectoryEntry2 {
    pub const fn entry_kind(self) -> Option<FilesystemEntryKind> {
        FilesystemEntryKind::from_raw(self.kind)
    }
}

impl Default for FilesystemDirectoryEntry2 {
    fn default() -> Self {
        Self {
            next_cookie: 0,
            size: 0,
            stable_id: 0,
            kind: 0,
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
    assert!(core::mem::size_of::<MonotonicTimeOutput>() == 8);
    assert!(core::mem::size_of::<HandleOutput>() == 8);
    assert!(core::mem::size_of::<HandleDisposition>() == 16);
    assert!(core::mem::size_of::<ProcessCreateArgs>() == 64);
    assert!(core::mem::size_of::<ProcessInfo>() == 32);
    assert!(core::mem::size_of::<SystemPowerInfo>() == 32);
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
    assert!(core::mem::size_of::<FilesystemOpenDirectoryArgs>() == 32);
    assert!(core::mem::size_of::<FilesystemCreateDirectoryArgs>() == 24);
    assert!(core::mem::size_of::<FilesystemRemoveDirectoryArgs>() == 24);
    assert!(core::mem::size_of::<FilesystemRenameArgs>() == 48);
    assert!(core::mem::size_of::<FilesystemSyncArgs>() == 8);
    assert!(core::mem::size_of::<FilesystemGetInfoArgs>() == 16);
    assert!(core::mem::size_of::<FilesystemInfo>() == 64);
    assert!(core::mem::size_of::<FilesystemGetMetadataArgs>() == 32);
    assert!(core::mem::size_of::<FilesystemMetadata>() == 64);
    assert!(core::mem::size_of::<FilesystemReadDirectory2Args>() == 24);
    assert!(core::mem::size_of::<ApplicationDataCreateArgs>() == 32);
    assert!(core::mem::size_of::<FilesystemDirectoryEntry2>() == 288);
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
        assert_eq!(SyscallNumber::AudioWrite as u64, 20);
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
        assert_eq!(SyscallNumber::ClockGetMonotonic as u64, 21);
        assert_eq!(SyscallNumber::RandomFill as u64, 22);
        assert_eq!(SyscallNumber::ProcessCreate as u64, 23);
        assert_eq!(SyscallNumber::ProcessGetInfo as u64, 24);
        assert_eq!(SyscallNumber::ProcessTerminate as u64, 25);
        assert_eq!(SyscallNumber::ApplicationGetDataDirectory as u64, 26);
        assert_eq!(SyscallNumber::FilesystemOpenDirectory as u64, 27);
        assert_eq!(SyscallNumber::FilesystemCreateDirectory as u64, 28);
        assert_eq!(SyscallNumber::FilesystemRemoveDirectory as u64, 29);
        assert_eq!(SyscallNumber::FilesystemRename as u64, 30);
        assert_eq!(SyscallNumber::FilesystemSync as u64, 31);
        assert_eq!(SyscallNumber::FilesystemGetInfo as u64, 32);
        assert_eq!(SyscallNumber::FilesystemGetMetadata as u64, 33);
        assert_eq!(SyscallNumber::FilesystemReadDirectory2 as u64, 34);
        assert_eq!(SyscallNumber::ApplicationDataCreate as u64, 35);
        assert_eq!(SyscallNumber::SystemPowerRequest as u64, 36);
        assert_eq!(SyscallNumber::SystemPowerCancel as u64, 37);
        assert_eq!(SyscallNumber::SystemPowerGetInfo as u64, 38);
        assert_eq!(SyscallNumber::AnonymousMap as u64, 39);
        assert_eq!(SyscallNumber::AnonymousUnmap as u64, 40);
        assert_eq!(SyscallNumber::AnonymousProtect as u64, 41);
        assert_eq!(SyscallNumber::AnonymousReserve as u64, 42);
        assert_eq!(SyscallNumber::AnonymousCommit as u64, 43);
        assert_eq!(SyscallNumber::AnonymousDecommit as u64, 44);
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
            Status::TimedOut,
            Status::ResourceLimit,
            Status::NotDirectory,
            Status::IsDirectory,
            Status::DirectoryNotEmpty,
            Status::AlreadyExists,
            Status::CrossDevice,
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
    fn wait_deadline_sentinel_is_stable() {
        assert_eq!(DEADLINE_INFINITE, i64::MAX);
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
        assert_eq!(ObjectType::RandomSource as u32, 6);
        assert_eq!(ObjectType::Process as u32, 7);
        assert_eq!(ObjectType::ApplicationData as u32, 8);
        assert_eq!(ObjectType::Directory as u32, 9);
        assert_eq!(FilesystemEntryKind::File as u32, 1);
        assert_eq!(FilesystemEntryKind::Directory as u32, 2);
        assert_eq!(
            FilesystemEntryKind::from_raw(1),
            Some(FilesystemEntryKind::File)
        );
        assert_eq!(
            FilesystemEntryKind::from_raw(2),
            Some(FilesystemEntryKind::Directory)
        );
        assert_eq!(FilesystemEntryKind::from_raw(0), None);

        assert_eq!(ProcessState::Running as u32, 0);
        assert_eq!(ProcessState::Terminated as u32, 1);
        assert_eq!(ProcessTerminationCause::None as u32, 0);
        assert_eq!(ProcessTerminationCause::Exited as u32, 1);
        assert_eq!(ProcessTerminationCause::Terminated as u32, 2);
        assert_eq!(ProcessTerminationCause::Faulted as u32, 3);
        assert_eq!(ProcessFault::None as u32, 0);
        assert_eq!(ProcessFault::PageFault as u32, 1);
        assert_eq!(ProcessFault::GeneralProtection as u32, 2);
        assert_eq!(ProcessFault::InvalidOpcode as u32, 3);
        assert_eq!(ProcessFault::InvalidUserContext as u32, 4);
        assert_eq!(ProcessFault::ResourceLimit as u32, 5);
        assert_eq!(ProcessFault::Other as u32, 6);
        assert_eq!(ProcessFault::OutOfMemory as u32, 7);
    }

    #[test]
    fn argument_blocks_have_stable_layouts() {
        assert_eq!(size_of::<WaitManyArgs>(), 24);
        assert_eq!(offset_of!(WaitManyArgs, deadline_ns), 16);
        assert_eq!(size_of::<MonotonicTimeOutput>(), 8);
        assert_eq!(offset_of!(MonotonicTimeOutput, now_ns), 0);

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

        assert_eq!(size_of::<ProcessCreateArgs>(), 64);
        assert_eq!(align_of::<ProcessCreateArgs>(), 8);
        assert_eq!(offset_of!(ProcessCreateArgs, executable), 0);
        assert_eq!(offset_of!(ProcessCreateArgs, args_address), 8);
        assert_eq!(offset_of!(ProcessCreateArgs, args_length), 16);
        assert_eq!(offset_of!(ProcessCreateArgs, startup_handles_address), 24);
        assert_eq!(offset_of!(ProcessCreateArgs, startup_handle_count), 32);
        assert_eq!(offset_of!(ProcessCreateArgs, config_address), 40);
        assert_eq!(offset_of!(ProcessCreateArgs, config_length), 48);
        assert_eq!(offset_of!(ProcessCreateArgs, output_address), 56);

        assert_eq!(size_of::<ProcessInfo>(), 32);
        assert_eq!(align_of::<ProcessInfo>(), 8);
        assert_eq!(offset_of!(ProcessInfo, state), 0);
        assert_eq!(offset_of!(ProcessInfo, cause), 4);
        assert_eq!(offset_of!(ProcessInfo, exit_code), 8);
        assert_eq!(offset_of!(ProcessInfo, fault), 12);
        assert_eq!(offset_of!(ProcessInfo, fault_code), 16);
        assert_eq!(offset_of!(ProcessInfo, fault_address), 24);

        assert_eq!(size_of::<FilesystemDirectoryEntry>(), 280);
        assert_eq!(offset_of!(FilesystemDirectoryEntry, name), 24);

        assert_eq!(size_of::<FilesystemOpenDirectoryArgs>(), 32);
        assert_eq!(align_of::<FilesystemOpenDirectoryArgs>(), 8);
        assert_eq!(offset_of!(FilesystemOpenDirectoryArgs, anchor), 0);
        assert_eq!(offset_of!(FilesystemOpenDirectoryArgs, path_address), 8);
        assert_eq!(offset_of!(FilesystemOpenDirectoryArgs, path_length), 16);
        assert_eq!(offset_of!(FilesystemOpenDirectoryArgs, output_address), 24);

        assert_eq!(size_of::<FilesystemCreateDirectoryArgs>(), 24);
        assert_eq!(offset_of!(FilesystemCreateDirectoryArgs, path_address), 8);
        assert_eq!(offset_of!(FilesystemCreateDirectoryArgs, path_length), 16);
        assert_eq!(size_of::<FilesystemRemoveDirectoryArgs>(), 24);
        assert_eq!(offset_of!(FilesystemRemoveDirectoryArgs, path_address), 8);
        assert_eq!(offset_of!(FilesystemRemoveDirectoryArgs, path_length), 16);

        assert_eq!(size_of::<FilesystemRenameArgs>(), 48);
        assert_eq!(align_of::<FilesystemRenameArgs>(), 8);
        assert_eq!(offset_of!(FilesystemRenameArgs, source_anchor), 0);
        assert_eq!(offset_of!(FilesystemRenameArgs, destination_anchor), 4);
        assert_eq!(offset_of!(FilesystemRenameArgs, source_path_address), 8);
        assert_eq!(offset_of!(FilesystemRenameArgs, source_path_length), 16);
        assert_eq!(
            offset_of!(FilesystemRenameArgs, destination_path_address),
            24
        );
        assert_eq!(
            offset_of!(FilesystemRenameArgs, destination_path_length),
            32
        );
        assert_eq!(offset_of!(FilesystemRenameArgs, flags), 40);
        assert_eq!(offset_of!(FilesystemRenameArgs, reserved), 44);

        assert_eq!(size_of::<FilesystemSyncArgs>(), 8);
        assert_eq!(offset_of!(FilesystemSyncArgs, handle), 0);
        assert_eq!(offset_of!(FilesystemSyncArgs, reserved), 4);

        assert_eq!(size_of::<FilesystemGetInfoArgs>(), 16);
        assert_eq!(offset_of!(FilesystemGetInfoArgs, anchor), 0);
        assert_eq!(offset_of!(FilesystemGetInfoArgs, output_address), 8);
        assert_eq!(size_of::<FilesystemInfo>(), 64);
        assert_eq!(offset_of!(FilesystemInfo, total_bytes), 0);
        assert_eq!(offset_of!(FilesystemInfo, free_bytes), 8);
        assert_eq!(offset_of!(FilesystemInfo, available_bytes), 16);
        assert_eq!(offset_of!(FilesystemInfo, block_size), 24);
        assert_eq!(offset_of!(FilesystemInfo, max_name_length), 28);
        assert_eq!(offset_of!(FilesystemInfo, max_path_depth), 32);
        assert_eq!(offset_of!(FilesystemInfo, flags), 36);
        assert_eq!(offset_of!(FilesystemInfo, reserved), 40);

        assert_eq!(size_of::<FilesystemGetMetadataArgs>(), 32);
        assert_eq!(offset_of!(FilesystemGetMetadataArgs, anchor), 0);
        assert_eq!(offset_of!(FilesystemGetMetadataArgs, path_address), 8);
        assert_eq!(offset_of!(FilesystemGetMetadataArgs, path_length), 16);
        assert_eq!(offset_of!(FilesystemGetMetadataArgs, output_address), 24);
        assert_eq!(size_of::<FilesystemMetadata>(), 64);
        assert_eq!(offset_of!(FilesystemMetadata, kind), 0);
        assert_eq!(offset_of!(FilesystemMetadata, mode), 4);
        assert_eq!(offset_of!(FilesystemMetadata, size), 8);
        assert_eq!(offset_of!(FilesystemMetadata, stable_id), 16);
        assert_eq!(offset_of!(FilesystemMetadata, ctime_ns), 24);
        assert_eq!(offset_of!(FilesystemMetadata, mtime_ns), 32);
        assert_eq!(offset_of!(FilesystemMetadata, uid), 40);
        assert_eq!(offset_of!(FilesystemMetadata, gid), 44);
        assert_eq!(offset_of!(FilesystemMetadata, policy), 48);
        assert_eq!(offset_of!(FilesystemMetadata, reserved), 52);

        assert_eq!(size_of::<FilesystemReadDirectory2Args>(), 24);
        assert_eq!(offset_of!(FilesystemReadDirectory2Args, directory), 0);
        assert_eq!(offset_of!(FilesystemReadDirectory2Args, cookie), 8);
        assert_eq!(offset_of!(FilesystemReadDirectory2Args, output_address), 16);
        assert_eq!(size_of::<ApplicationDataCreateArgs>(), 32);
        assert_eq!(align_of::<ApplicationDataCreateArgs>(), 8);
        assert_eq!(offset_of!(ApplicationDataCreateArgs, root), 0);
        assert_eq!(offset_of!(ApplicationDataCreateArgs, reserved), 4);
        assert_eq!(offset_of!(ApplicationDataCreateArgs, app_id_address), 8);
        assert_eq!(offset_of!(ApplicationDataCreateArgs, app_id_length), 16);
        assert_eq!(offset_of!(ApplicationDataCreateArgs, output_address), 24);

        assert_eq!(size_of::<FilesystemDirectoryEntry2>(), 288);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, next_cookie), 0);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, size), 8);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, stable_id), 16);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, kind), 24);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, name_length), 28);
        assert_eq!(offset_of!(FilesystemDirectoryEntry2, name), 36);
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
        assert_eq!(FilesystemOpenFlags::EXECUTE.bits(), 16);
        assert_eq!(FilesystemRenameFlags::empty().bits(), 0);
        assert_eq!(FilesystemRenameFlags::REPLACE.bits(), 1);
        assert_eq!(FilesystemInfoFlags::READ_ONLY.bits(), 1);
        assert_eq!(Rights::INSPECT.bits(), 1 << 8);
        assert_eq!(Rights::TERMINATE.bits(), 1 << 9);
        assert_eq!(Rights::EXECUTE.bits(), 1 << 10);
        assert_eq!(Signals::TERMINATED.bits(), 1 << 4);
    }

    #[test]
    fn process_startup_bounds_are_stable() {
        assert_eq!(PROCESS_MAX_ARGS, 32);
        assert_eq!(PROCESS_MAX_STARTUP_BYTES, 16 * 1024);
        assert_eq!(PROCESS_MAX_STARTUP_HANDLES, 16);
    }

    #[test]
    fn process_info_raw_discriminants_are_checked() {
        let info = ProcessInfo {
            state: ProcessState::Terminated as u32,
            cause: ProcessTerminationCause::Faulted as u32,
            fault: ProcessFault::PageFault as u32,
            ..ProcessInfo::default()
        };
        assert_eq!(info.process_state(), Some(ProcessState::Terminated));
        assert_eq!(
            info.termination_cause(),
            Some(ProcessTerminationCause::Faulted)
        );
        assert_eq!(info.process_fault(), Some(ProcessFault::PageFault));

        let unknown = ProcessInfo {
            state: u32::MAX,
            cause: u32::MAX,
            fault: u32::MAX,
            ..ProcessInfo::default()
        };
        assert_eq!(unknown.process_state(), None);
        assert_eq!(unknown.termination_cause(), None);
        assert_eq!(unknown.process_fault(), None);
    }
}
