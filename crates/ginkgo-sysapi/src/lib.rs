#![no_std]

//! Fixed-layout types shared by the GinkgoOS kernel and userspace.

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Maximum byte payload accepted by one channel message.
pub const CHANNEL_MAX_BYTES: usize = 16 * 1024;
/// Maximum number of handles accepted by one channel message.
pub const CHANNEL_MAX_HANDLES: usize = 16;
/// Serialized size of [`RpcHeader`].
pub const RPC_HEADER_SIZE: usize = core::mem::size_of::<RpcHeader>();

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

/// Stable object-kind identifier returned by handle inspection.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType {
    Channel = 1,
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

/// One object in a wait-many request.
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

const _: () = assert!(RPC_HEADER_SIZE == 24);
