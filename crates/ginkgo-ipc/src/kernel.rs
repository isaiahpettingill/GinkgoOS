//! Capability handles for channels, shared memory, and protected windows.
//!
//! [`HandleTable`] is the process-local boundary for kernel objects. Channels
//! preserve datagram boundaries and may atomically move handles between tables;
//! duplicated and transferred shared-memory/window handles retain object identity.
//! Operations are intentionally nonblocking so they can be used by the current
//! cooperative scheduler; a future syscall layer can block around exposed object
//! signals without changing these semantics.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::mem;

use ginkgo_sysapi::{
    Handle, MessageInfo, ObjectType, Rights, Signals, Status, WaitItem, CHANNEL_MAX_BYTES,
    CHANNEL_MAX_HANDLES,
};
use spinning_top::Spinlock;

/// Maximum number of complete messages queued in either direction.
pub const CHANNEL_QUEUE_CAPACITY: usize = 64;
/// Maximum number of live or vacant slots retained by one handle table.
pub const HANDLE_TABLE_CAPACITY: usize = 4096;
/// Default number of equal shared-memory slots owned by [`HandleTable::window_create`].
pub const WINDOW_BUFFER_COUNT: usize = 2;

const HANDLE_INDEX_BITS: u32 = 12;
const HANDLE_INDEX_MASK: u32 = (1 << HANDLE_INDEX_BITS) - 1;
const HANDLE_GENERATION_MASK: u32 = (1 << (32 - HANDLE_INDEX_BITS)) - 1;

// Serializes queue-edge additions while cycle detection traverses other channel
// states. Reads and endpoint teardown only remove edges and need no graph lock.
static CHANNEL_GRAPH_LOCK: Spinlock<()> = Spinlock::new(());

const CHANNEL_DEFAULT_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits()
        | Rights::WRITE.bits()
        | Rights::WAIT.bits()
        | Rights::DUPLICATE.bits()
        | Rights::TRANSFER.bits(),
);
const SHARED_MEMORY_DEFAULT_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits()
        | Rights::WRITE.bits()
        | Rights::DUPLICATE.bits()
        | Rights::TRANSFER.bits()
        | Rights::MANAGE.bits(),
);
const WINDOW_CLIENT_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits()
        | Rights::WRITE.bits()
        | Rights::WAIT.bits()
        | Rights::DUPLICATE.bits()
        | Rights::TRANSFER.bits(),
);
const WINDOW_MANAGER_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits()
        | Rights::WAIT.bits()
        | Rights::DUPLICATE.bits()
        | Rights::TRANSFER.bits()
        | Rights::MANAGE.bits(),
);

fn handle_from_parts(index: usize, generation: u32) -> Handle {
    debug_assert!(index < HANDLE_TABLE_CAPACITY);
    debug_assert!(generation != 0 && generation <= HANDLE_GENERATION_MASK);
    Handle::from_raw((generation << HANDLE_INDEX_BITS) | index as u32)
}

fn handle_parts(handle: Handle) -> Option<(usize, u32)> {
    let raw = handle.raw();
    let generation = raw >> HANDLE_INDEX_BITS;
    let index = (raw & HANDLE_INDEX_MASK) as usize;
    (raw != 0 && generation != 0).then_some((index, generation))
}

/// A kernel-object or handle-table operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    InvalidHandle,
    WrongObjectType,
    AccessDenied,
    InvalidRights,
    DuplicateHandle,
    CyclicTransfer,
    MessageTooLarge,
    HandleTableFull,
    InvalidMessage,
    OutOfMemory,
    /// The operation would block: a read queue is empty or a write queue is full.
    ShouldWait,
    PeerClosed,
    /// The message remains queued and can be retried with larger buffers.
    BufferTooSmall(MessageInfo),
}

impl IpcError {
    /// Converts the kernel's detailed error into its stable syscall status.
    pub const fn status(self) -> Status {
        match self {
            Self::InvalidHandle => Status::InvalidHandle,
            Self::WrongObjectType => Status::WrongObjectType,
            Self::AccessDenied => Status::AccessDenied,
            Self::InvalidRights => Status::InvalidRights,
            Self::DuplicateHandle => Status::DuplicateHandle,
            Self::CyclicTransfer => Status::CyclicTransfer,
            Self::MessageTooLarge => Status::MessageTooLarge,
            Self::HandleTableFull => Status::HandleTableFull,
            Self::InvalidMessage => Status::InvalidMessage,
            Self::OutOfMemory => Status::OutOfMemory,
            Self::ShouldWait => Status::ShouldWait,
            Self::PeerClosed => Status::PeerClosed,
            Self::BufferTooSmall(_) => Status::BufferTooSmall,
        }
    }
}

#[derive(Clone)]
struct HandleEntry {
    object: Arc<KernelObject>,
    rights: Rights,
}

struct HandleSlot {
    generation: u32,
    entry: Option<HandleEntry>,
}

impl HandleSlot {
    const fn vacant() -> Self {
        Self {
            generation: 1,
            entry: None,
        }
    }

    fn advance_generation(&mut self) {
        // Retire a slot rather than wrapping and allowing an ancient raw handle
        // to become valid again. Capacity is replenished from never-used slots.
        if self.generation == HANDLE_GENERATION_MASK {
            self.generation = 0;
        } else {
            self.generation += 1;
        }
    }
}

enum KernelObject {
    Channel(ChannelEndpoint),
    SharedMemory(SharedMemoryObject),
    Window(WindowEndpoint),
}

struct SharedMemoryObject {
    bytes: Spinlock<Box<[u8]>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowRole {
    Client,
    Manager,
}

struct WindowEndpoint {
    state: Arc<Spinlock<WindowState>>,
    role: WindowRole,
}

impl WindowEndpoint {
    fn signals(&self) -> Signals {
        let state = self.state.lock();
        match self.role {
            WindowRole::Client => {
                let mut signals = Signals::empty();
                if state.release.is_some() {
                    signals |= Signals::READABLE;
                }
                if !state.manager_open {
                    signals |= Signals::PEER_CLOSED;
                }
                if !state.retired
                    && state.manager_open
                    && state.release.is_none()
                    && state.pending.is_none()
                    && state
                        .buffers
                        .iter()
                        .any(|buffer| matches!(buffer, WindowBufferState::ClientOwned))
                {
                    signals |= Signals::WRITABLE;
                }
                signals
            }
            WindowRole::Manager => {
                let mut signals = Signals::empty();
                if state.pending.is_some() {
                    signals |= Signals::READABLE;
                }
                if !state.client_open {
                    signals |= Signals::PEER_CLOSED;
                }
                signals
            }
        }
    }
}

struct WindowState {
    shared_memory: Arc<KernelObject>,
    buffer_len: usize,
    generation: u64,
    buffers: Box<[WindowBufferState]>,
    pending: Option<WindowPresentation>,
    displayed: Option<WindowPresentation>,
    release: Option<WindowRelease>,
    next_serial: u64,
    retired: bool,
    client_open: bool,
    manager_open: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowBufferState {
    ClientOwned,
    Pending,
    Displayed,
    Released,
}

impl Drop for WindowEndpoint {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        match self.role {
            WindowRole::Client => state.client_open = false,
            WindowRole::Manager => state.manager_open = false,
        }
    }
}

struct ChannelEndpoint {
    state: Arc<Spinlock<ChannelState>>,
    side: usize,
}

impl ChannelEndpoint {
    fn signals(&self) -> Signals {
        let state = self.state.lock();
        let peer = 1 - self.side;
        let mut signals = Signals::empty();
        if !state.queues[self.side].is_empty() {
            signals |= Signals::READABLE;
        }
        if !state.open[peer] {
            signals |= Signals::PEER_CLOSED;
        } else if state.queues[peer].len() < CHANNEL_QUEUE_CAPACITY {
            signals |= Signals::WRITABLE;
        }
        signals
    }
}

impl Drop for ChannelEndpoint {
    fn drop(&mut self) {
        let discarded = {
            let mut state = self.state.lock();
            state.open[self.side] = false;
            // No endpoint can consume messages queued for this side. Move them
            // out before dropping their object references to avoid recursively
            // taking this channel's spinlock.
            mem::take(&mut state.queues[self.side])
        };
        drop(discarded);
    }
}

struct ChannelState {
    open: [bool; 2],
    queues: [VecDeque<KernelMessage>; 2],
}

struct KernelMessage {
    bytes: Box<[u8]>,
    handles: Box<[HandleEntry]>,
}

/// A handle moved by a channel write and the rights installed at the receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleDisposition {
    pub handle: Handle,
    pub rights: Rights,
}

impl HandleDisposition {
    pub const fn new(handle: Handle, rights: Rights) -> Self {
        Self { handle, rights }
    }
}

/// Identity assigned to one pending or displayed window submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPresentation {
    pub buffer_index: u32,
    /// Stable generation of the window's shared surface pool.
    pub generation: u64,
    pub presentation_serial: u64,
}

/// Notification that a formerly displayed buffer is client-owned again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowRelease {
    pub buffer_index: u32,
    /// Stable generation of the window's shared surface pool.
    pub generation: u64,
    /// Serial of the presentation whose buffer was released.
    pub presentation_serial: u64,
}

/// A process-local capability table.
///
/// The table owns every object referenced by its handles. Dropping or closing
/// the last handle to a channel endpoint reports peer closure to the other end.
pub struct HandleTable {
    slots: Vec<HandleSlot>,
}

impl HandleTable {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.entry.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Creates zero-filled, heap-backed shared memory.
    pub fn shared_memory_create(&mut self, size: usize) -> Result<Handle, IpcError> {
        if size == 0 {
            return Err(IpcError::InvalidMessage);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| IpcError::OutOfMemory)?;
        bytes.resize(size, 0);
        let object = Arc::new(KernelObject::SharedMemory(SharedMemoryObject {
            bytes: Spinlock::new(bytes.into_boxed_slice()),
        }));
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, SHARED_MEMORY_DEFAULT_RIGHTS))
    }

    /// Returns the immutable allocation length of a shared-memory object.
    pub fn shared_memory_len(&self, handle: Handle) -> Result<usize, IpcError> {
        let object = self.object_with_rights(handle, Rights::READ)?;
        let len = shared_memory_object(&object)?.bytes.lock().len();
        Ok(len)
    }

    /// Copies a checked range out of shared memory.
    pub fn shared_memory_read(
        &self,
        handle: Handle,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError> {
        let object = self.object_with_rights(handle, Rights::READ)?;
        let memory = shared_memory_object(&object)?;
        let bytes = memory.bytes.lock();
        let range = checked_range(offset, output.len(), bytes.len())?;
        output.copy_from_slice(&bytes[range]);
        Ok(())
    }

    /// Copies bytes into a checked shared-memory range.
    ///
    /// Window lifecycle protection does not revoke writable shared-memory aliases:
    /// any holder of one can still mutate pending or displayed surface bytes. The
    /// window capabilities protect submission/manager authority and ownership
    /// transitions, not application writes through fake revocable mappings.
    pub fn shared_memory_write(
        &self,
        handle: Handle,
        offset: usize,
        input: &[u8],
    ) -> Result<(), IpcError> {
        let object = self.object_with_rights(handle, Rights::WRITE)?;
        let memory = shared_memory_object(&object)?;
        let mut bytes = memory.bytes.lock();
        let range = checked_range(offset, input.len(), bytes.len())?;
        bytes[range].copy_from_slice(input);
        Ok(())
    }

    /// Creates a generation-1 window over two equal shared-memory buffers.
    pub fn window_create(&mut self, shared_memory: Handle) -> Result<(Handle, Handle), IpcError> {
        self.window_create_with_generation_and_buffer_count(
            shared_memory,
            1,
            WINDOW_BUFFER_COUNT as u32,
        )
    }

    /// Creates protected client and manager capabilities over equal surface buffers.
    ///
    /// `generation` must be nonzero, `buffer_count` must be at least two, and the
    /// shared-memory allocation must divide into that many nonempty equal slots.
    /// Creation requires [`Rights::MANAGE`] on the memory object. Writable memory
    /// aliases remain writable; window protection covers capability authority and
    /// lifecycle ownership, not revocation of application memory access.
    pub fn window_create_with_generation_and_buffer_count(
        &mut self,
        shared_memory: Handle,
        generation: u64,
        buffer_count: u32,
    ) -> Result<(Handle, Handle), IpcError> {
        let memory = self.object_with_rights(shared_memory, Rights::MANAGE)?;
        let buffer_count = usize::try_from(buffer_count).map_err(|_| IpcError::InvalidMessage)?;
        if generation == 0 || buffer_count < 2 {
            return Err(IpcError::InvalidMessage);
        }
        let memory_len = shared_memory_object(&memory)?.bytes.lock().len();
        if memory_len < buffer_count || memory_len % buffer_count != 0 {
            return Err(IpcError::InvalidMessage);
        }
        let buffer_len = memory_len / buffer_count;

        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(buffer_count)
            .map_err(|_| IpcError::OutOfMemory)?;
        buffers.resize(buffer_count, WindowBufferState::ClientOwned);
        let slots = self.reserve_slots(2)?;
        let state = Arc::new(Spinlock::new(WindowState {
            shared_memory: memory,
            buffer_len,
            generation,
            buffers: buffers.into_boxed_slice(),
            pending: None,
            displayed: None,
            release: None,
            next_serial: 1,
            retired: false,
            client_open: true,
            manager_open: true,
        }));
        let client = Arc::new(KernelObject::Window(WindowEndpoint {
            state: Arc::clone(&state),
            role: WindowRole::Client,
        }));
        let manager = Arc::new(KernelObject::Window(WindowEndpoint {
            state,
            role: WindowRole::Manager,
        }));
        let client = self.insert_reserved(slots[0], client, WINDOW_CLIENT_RIGHTS);
        let manager = self.insert_reserved(slots[1], manager, WINDOW_MANAGER_RIGHTS);
        Ok((client, manager))
    }

    /// Returns the byte length of each of a window's equal buffers.
    pub fn window_buffer_len(&self, window: Handle) -> Result<usize, IpcError> {
        let object = self.object_with_rights(window, Rights::READ)?;
        let endpoint = window_endpoint(&object)?;
        let buffer_len = endpoint.state.lock().buffer_len;
        Ok(buffer_len)
    }

    /// Returns the number of buffers in a window's surface pool.
    pub fn window_buffer_count(&self, window: Handle) -> Result<usize, IpcError> {
        let object = self.object_with_rights(window, Rights::READ)?;
        let endpoint = window_endpoint(&object)?;
        let buffer_count = endpoint.state.lock().buffers.len();
        Ok(buffer_count)
    }

    /// Submits one client-owned buffer from the current stable pool generation.
    ///
    /// An unread release is a presentation barrier and returns `ShouldWait`, so a
    /// normally accepted submission always has release capacity at completion.
    pub fn window_present(
        &self,
        client: Handle,
        buffer_index: u32,
        generation: u64,
    ) -> Result<WindowPresentation, IpcError> {
        let object = self.object_with_rights(client, Rights::WRITE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Client)?;
        let mut state = endpoint.state.lock();
        if state.release.is_some() {
            return Err(IpcError::ShouldWait);
        }
        if !state.manager_open {
            return Err(IpcError::PeerClosed);
        }
        if state.retired {
            return Err(IpcError::InvalidMessage);
        }
        if state.pending.is_some() {
            return Err(IpcError::ShouldWait);
        }

        let index = usize::try_from(buffer_index).map_err(|_| IpcError::InvalidMessage)?;
        if generation != state.generation {
            return Err(IpcError::InvalidMessage);
        }
        let Some(buffer) = state.buffers.get(index) else {
            return Err(IpcError::InvalidMessage);
        };
        if *buffer != WindowBufferState::ClientOwned {
            return Err(IpcError::InvalidMessage);
        }
        let next_serial = state
            .next_serial
            .checked_add(1)
            .ok_or(IpcError::InvalidMessage)?;
        let presentation = WindowPresentation {
            buffer_index,
            generation,
            presentation_serial: state.next_serial,
        };
        state.next_serial = next_serial;
        state.buffers[index] = WindowBufferState::Pending;
        state.pending = Some(presentation);
        Ok(presentation)
    }

    /// Reads one release event and transfers that slot back to client ownership.
    ///
    /// At most one event exists per window. Until it is read, the released slot
    /// is not client-owned and cannot contribute [`Signals::WRITABLE`].
    pub fn window_read_release(&self, client: Handle) -> Result<WindowRelease, IpcError> {
        let object = self.object_with_rights(client, Rights::READ)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Client)?;
        let mut state = endpoint.state.lock();
        let Some(release) = state.release else {
            return if state.manager_open {
                Err(IpcError::ShouldWait)
            } else {
                Err(IpcError::PeerClosed)
            };
        };
        let index = usize::try_from(release.buffer_index).map_err(|_| IpcError::InvalidMessage)?;
        if state.buffers.get(index) != Some(&WindowBufferState::Released) {
            return Err(IpcError::InvalidMessage);
        }
        state.release = None;
        state.buffers[index] = WindowBufferState::ClientOwned;
        Ok(release)
    }

    /// Returns the current pending presentation to a privileged manager.
    pub fn window_manager_pending(&self, manager: Handle) -> Result<WindowPresentation, IpcError> {
        let object = self.object_with_rights(manager, Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let state = endpoint.state.lock();
        if let Some(pending) = state.pending {
            Ok(pending)
        } else if state.client_open {
            Err(IpcError::ShouldWait)
        } else {
            Err(IpcError::PeerClosed)
        }
    }

    /// Returns the currently displayed presentation, if the first frame completed.
    pub fn window_manager_displayed(
        &self,
        manager: Handle,
    ) -> Result<Option<WindowPresentation>, IpcError> {
        let object = self.object_with_rights(manager, Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let displayed = endpoint.state.lock().displayed;
        Ok(displayed)
    }

    /// Copies a checked range from the pending buffer without changing ownership.
    pub fn window_manager_copy_pending(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError> {
        let object = self.object_with_rights(manager, Rights::READ | Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let state = endpoint.state.lock();
        if state.pending != Some(presentation) {
            return Err(IpcError::InvalidMessage);
        }
        copy_window_buffer(&state, presentation, offset, output)
    }

    /// Copies a checked range from the retained displayed buffer.
    ///
    /// The expected presentation must still be displayed. Copying never changes
    /// pending/displayed ownership or release events.
    pub fn window_manager_copy_displayed(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), IpcError> {
        let object = self.object_with_rights(manager, Rights::READ | Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let state = endpoint.state.lock();
        if state.displayed != Some(presentation) {
            return Err(IpcError::InvalidMessage);
        }
        copy_window_buffer(&state, presentation, offset, output)
    }

    /// Reports composition completion for the current pending presentation.
    ///
    /// A failed completion leaves pending/displayed ownership and release events
    /// unchanged so the manager may retry. A successful completion displays the
    /// pending buffer and releases the previously displayed buffer, if any.
    pub fn window_manager_complete(
        &self,
        manager: Handle,
        presentation: WindowPresentation,
        successful: bool,
    ) -> Result<(), IpcError> {
        let object = self.object_with_rights(manager, Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let mut state = endpoint.state.lock();
        if state.pending != Some(presentation) {
            return Err(IpcError::InvalidMessage);
        }
        if !successful {
            return Ok(());
        }

        let displayed_index =
            usize::try_from(presentation.buffer_index).map_err(|_| IpcError::InvalidMessage)?;
        if state.buffers.get(displayed_index) != Some(&WindowBufferState::Pending) {
            return Err(IpcError::InvalidMessage);
        }

        let release = if let Some(previous) = state.displayed {
            if state.release.is_some() {
                return Err(IpcError::ShouldWait);
            }
            let released_index =
                usize::try_from(previous.buffer_index).map_err(|_| IpcError::InvalidMessage)?;
            if state.buffers.get(released_index) != Some(&WindowBufferState::Displayed) {
                return Err(IpcError::InvalidMessage);
            }
            Some((
                released_index,
                WindowRelease {
                    buffer_index: previous.buffer_index,
                    generation: previous.generation,
                    presentation_serial: previous.presentation_serial,
                },
            ))
        } else {
            None
        };

        if let Some((released_index, release)) = release {
            state.buffers[released_index] = WindowBufferState::Released;
            state.release = Some(release);
        }
        state.buffers[displayed_index] = WindowBufferState::Displayed;
        state.pending = None;
        state.displayed = Some(presentation);
        Ok(())
    }

    /// Retires a surface pool after pending composition has drained.
    ///
    /// Retirement rejects new presentations but preserves release reads. If a
    /// displayed buffer exists, it becomes released and exactly one release event
    /// is made readable. An occupied release slot or pending presentation causes
    /// `ShouldWait` without changing ownership.
    pub fn window_manager_retire(&self, manager: Handle) -> Result<(), IpcError> {
        let object = self.object_with_rights(manager, Rights::MANAGE)?;
        let endpoint = window_endpoint_for_role(&object, WindowRole::Manager)?;
        let mut state = endpoint.state.lock();
        if state.retired {
            return Ok(());
        }
        if state.pending.is_some() || (state.displayed.is_some() && state.release.is_some()) {
            return Err(IpcError::ShouldWait);
        }

        let release = if let Some(displayed) = state.displayed {
            let index =
                usize::try_from(displayed.buffer_index).map_err(|_| IpcError::InvalidMessage)?;
            if state.buffers.get(index) != Some(&WindowBufferState::Displayed) {
                return Err(IpcError::InvalidMessage);
            }
            Some((
                index,
                WindowRelease {
                    buffer_index: displayed.buffer_index,
                    generation: displayed.generation,
                    presentation_serial: displayed.presentation_serial,
                },
            ))
        } else {
            None
        };

        if let Some((index, release)) = release {
            state.buffers[index] = WindowBufferState::Released;
            state.release = Some(release);
            state.displayed = None;
        }
        state.retired = true;
        Ok(())
    }

    /// Creates both ends of a channel in this table.
    pub fn channel_create(&mut self) -> Result<(Handle, Handle), IpcError> {
        let slots = self.reserve_slots(2)?;
        let [left, right] = new_channel_objects();
        let left = self.insert_reserved(slots[0], left, CHANNEL_DEFAULT_RIGHTS);
        let right = self.insert_reserved(slots[1], right, CHANNEL_DEFAULT_RIGHTS);
        Ok((left, right))
    }

    /// Writes one complete message and atomically moves all attached handles,
    /// preserving their current rights at the receiver.
    ///
    /// On any error, including a full queue or closed peer, every source handle
    /// remains valid in this table and no message is queued.
    pub fn channel_write(
        &mut self,
        channel: Handle,
        bytes: &[u8],
        handles: &[Handle],
    ) -> Result<(), IpcError> {
        if bytes.len() > CHANNEL_MAX_BYTES || handles.len() > CHANNEL_MAX_HANDLES {
            return Err(IpcError::MessageTooLarge);
        }

        let dispositions = handles
            .iter()
            .copied()
            .map(|handle| {
                self.handle_rights(handle)
                    .map(|rights| HandleDisposition::new(handle, rights))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.channel_write_with_dispositions(channel, bytes, &dispositions)
    }

    /// Writes one complete message and atomically moves handles with attenuated rights.
    ///
    /// Every requested rights set must be a subset of its source handle's rights,
    /// every source must carry [`Rights::TRANSFER`], and a source handle may occur
    /// only once. On any error, all source handles remain valid and no message is
    /// queued.
    pub fn channel_write_with_dispositions(
        &mut self,
        channel: Handle,
        bytes: &[u8],
        dispositions: &[HandleDisposition],
    ) -> Result<(), IpcError> {
        if bytes.len() > CHANNEL_MAX_BYTES || dispositions.len() > CHANNEL_MAX_HANDLES {
            return Err(IpcError::MessageTooLarge);
        }

        let channel_object = self.object_with_rights(channel, Rights::WRITE)?;
        let endpoint = channel_endpoint(&channel_object)?;

        let mut transfers = Vec::with_capacity(dispositions.len());
        for (position, disposition) in dispositions.iter().copied().enumerate() {
            if dispositions[..position]
                .iter()
                .any(|prior| prior.handle == disposition.handle)
            {
                return Err(IpcError::DuplicateHandle);
            }
            let (index, _) = self.validated_slot(disposition.handle)?;
            let entry = self.slots[index]
                .entry
                .as_ref()
                .ok_or(IpcError::InvalidHandle)?;
            if !entry.rights.contains(Rights::TRANSFER) {
                return Err(IpcError::AccessDenied);
            }
            if !entry.rights.contains(disposition.rights) {
                return Err(IpcError::InvalidRights);
            }
            transfers.push((index, disposition.rights));
        }

        // Allocate all message storage before the commit point. The kernel's
        // allocator is currently infallible, so no operation below can fail
        // after handles start moving out of the sender.
        let message_bytes = bytes.to_vec().into_boxed_slice();
        let mut message_handles = Vec::with_capacity(dispositions.len());

        let _graph = CHANNEL_GRAPH_LOCK.lock();
        let mut state = endpoint.state.lock();
        let peer = 1 - endpoint.side;
        if !state.open[peer] {
            return Err(IpcError::PeerClosed);
        }
        if state.queues[peer].len() == CHANNEL_QUEUE_CAPACITY {
            return Err(IpcError::ShouldWait);
        }

        let mut visited = Vec::new();
        for &(index, _) in &transfers {
            let entry = self.slots[index]
                .entry
                .as_ref()
                .expect("validated transfer slot became vacant");
            if object_reaches_channel(&entry.object, &endpoint.state, &mut visited) {
                return Err(IpcError::CyclicTransfer);
            }
        }

        for (index, destination_rights) in transfers {
            let mut entry = self.slots[index]
                .entry
                .take()
                .expect("validated transfer slot became vacant");
            self.slots[index].advance_generation();
            entry.rights = destination_rights;
            message_handles.push(entry);
        }
        state.queues[peer].push_back(KernelMessage {
            bytes: message_bytes,
            handles: message_handles.into_boxed_slice(),
        });
        Ok(())
    }

    /// Reads and removes one complete message.
    ///
    /// If either output is too small, the message remains queued. Handles are
    /// assigned fresh process-local values only after all output and table-space
    /// checks have succeeded.
    pub fn channel_read(
        &mut self,
        channel: Handle,
        bytes_out: &mut [u8],
        handles_out: &mut [Handle],
    ) -> Result<MessageInfo, IpcError> {
        let channel_object = self.object_with_rights(channel, Rights::READ)?;
        let endpoint = channel_endpoint(&channel_object)?;
        let mut state = endpoint.state.lock();

        let Some(message) = state.queues[endpoint.side].front() else {
            return if state.open[1 - endpoint.side] {
                Err(IpcError::ShouldWait)
            } else {
                Err(IpcError::PeerClosed)
            };
        };
        let byte_count = message.bytes.len();
        let handle_count = message.handles.len();
        let info = MessageInfo::new(byte_count as u32, handle_count as u16);
        if bytes_out.len() < byte_count || handles_out.len() < handle_count {
            return Err(IpcError::BufferTooSmall(info));
        }

        let destination_slots = self.reserve_slots(handle_count)?;
        let message = state.queues[endpoint.side]
            .pop_front()
            .expect("front message disappeared while channel was locked");
        bytes_out[..byte_count].copy_from_slice(&message.bytes);
        for ((entry, slot), output) in message
            .handles
            .into_vec()
            .into_iter()
            .zip(destination_slots)
            .zip(handles_out.iter_mut())
        {
            *output = self.insert_reserved(slot, entry.object, entry.rights);
        }
        Ok(info)
    }

    /// Closes a handle. Other aliases created by duplication remain valid.
    pub fn handle_close(&mut self, handle: Handle) -> Result<(), IpcError> {
        let (index, _) = self.validated_slot(handle)?;
        let entry = self.slots[index]
            .entry
            .take()
            .ok_or(IpcError::InvalidHandle)?;
        self.slots[index].advance_generation();
        drop(entry);
        Ok(())
    }

    /// Creates an alias with equal or fewer rights.
    pub fn handle_duplicate(&mut self, handle: Handle, rights: Rights) -> Result<Handle, IpcError> {
        let entry = self.entry(handle)?;
        if !entry.rights.contains(Rights::DUPLICATE) {
            return Err(IpcError::AccessDenied);
        }
        if !entry.rights.contains(rights) {
            return Err(IpcError::InvalidRights);
        }
        let object = Arc::clone(&entry.object);
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, rights))
    }

    pub fn handle_rights(&self, handle: Handle) -> Result<Rights, IpcError> {
        Ok(self.entry(handle)?.rights)
    }

    pub fn object_type(&self, handle: Handle) -> Result<ObjectType, IpcError> {
        match self.entry(handle)?.object.as_ref() {
            KernelObject::Channel(_) => Ok(ObjectType::Channel),
            KernelObject::SharedMemory(_) => Ok(ObjectType::SharedMemory),
            KernelObject::Window(_) => Ok(ObjectType::Window),
        }
    }

    /// Returns current level-triggered signals without blocking.
    pub fn object_signals(&self, handle: Handle) -> Result<Signals, IpcError> {
        let object = self.object_with_rights(handle, Rights::WAIT)?;
        match object.as_ref() {
            KernelObject::Channel(endpoint) => Ok(endpoint.signals()),
            KernelObject::SharedMemory(_) => Ok(Signals::empty()),
            KernelObject::Window(endpoint) => Ok(endpoint.signals()),
        }
    }

    /// Scans wait items in order and returns the first ready index.
    ///
    /// This is the nonblocking core of a future `object_wait_many` syscall. A
    /// cooperative task can call it once per scheduler step; a stackful scheduler
    /// can use the same signals to register and block a thread.
    pub fn poll_wait_many(&self, items: &mut [WaitItem]) -> Result<Option<usize>, IpcError> {
        let mut ready = None;
        for (index, item) in items.iter_mut().enumerate() {
            item.pending = self.object_signals(item.handle)?;
            if ready.is_none() && item.pending.intersects(item.wait_for) {
                ready = Some(index);
            }
        }
        Ok(ready)
    }

    fn entry(&self, handle: Handle) -> Result<&HandleEntry, IpcError> {
        let (index, _) = self.validated_slot(handle)?;
        self.slots[index]
            .entry
            .as_ref()
            .ok_or(IpcError::InvalidHandle)
    }

    fn object_with_rights(
        &self,
        handle: Handle,
        required: Rights,
    ) -> Result<Arc<KernelObject>, IpcError> {
        let entry = self.entry(handle)?;
        if !entry.rights.contains(required) {
            return Err(IpcError::AccessDenied);
        }
        Ok(Arc::clone(&entry.object))
    }

    fn validated_slot(&self, handle: Handle) -> Result<(usize, u32), IpcError> {
        let (index, generation) = handle_parts(handle).ok_or(IpcError::InvalidHandle)?;
        let slot = self.slots.get(index).ok_or(IpcError::InvalidHandle)?;
        if slot.generation != generation || slot.entry.is_none() {
            return Err(IpcError::InvalidHandle);
        }
        Ok((index, generation))
    }

    fn reserve_slots(&mut self, count: usize) -> Result<Vec<usize>, IpcError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let vacant = self
            .slots
            .iter()
            .filter(|slot| slot.entry.is_none() && slot.generation != 0)
            .count();
        let available = vacant + HANDLE_TABLE_CAPACITY.saturating_sub(self.slots.len());
        if count > available {
            return Err(IpcError::HandleTableFull);
        }

        let mut reserved = Vec::with_capacity(count);
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.entry.is_none() && slot.generation != 0 {
                reserved.push(index);
                if reserved.len() == count {
                    return Ok(reserved);
                }
            }
        }
        while reserved.len() < count {
            let index = self.slots.len();
            self.slots.push(HandleSlot::vacant());
            reserved.push(index);
        }
        Ok(reserved)
    }

    fn insert_reserved(
        &mut self,
        index: usize,
        object: Arc<KernelObject>,
        rights: Rights,
    ) -> Handle {
        let slot = &mut self.slots[index];
        debug_assert!(slot.entry.is_none());
        slot.entry = Some(HandleEntry { object, rights });
        handle_from_parts(index, slot.generation)
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates one channel endpoint in each of two process-local handle tables.
pub fn channel_create_between(
    left_table: &mut HandleTable,
    right_table: &mut HandleTable,
) -> Result<(Handle, Handle), IpcError> {
    let left_slot = left_table.reserve_slots(1)?[0];
    let right_slot = right_table.reserve_slots(1)?[0];
    let [left, right] = new_channel_objects();
    let left = left_table.insert_reserved(left_slot, left, CHANNEL_DEFAULT_RIGHTS);
    let right = right_table.insert_reserved(right_slot, right, CHANNEL_DEFAULT_RIGHTS);
    Ok((left, right))
}

fn new_channel_objects() -> [Arc<KernelObject>; 2] {
    let state = Arc::new(Spinlock::new(ChannelState {
        open: [true, true],
        queues: [VecDeque::new(), VecDeque::new()],
    }));
    [
        Arc::new(KernelObject::Channel(ChannelEndpoint {
            state: Arc::clone(&state),
            side: 0,
        })),
        Arc::new(KernelObject::Channel(ChannelEndpoint { state, side: 1 })),
    ]
}

fn channel_endpoint(object: &Arc<KernelObject>) -> Result<&ChannelEndpoint, IpcError> {
    match object.as_ref() {
        KernelObject::Channel(endpoint) => Ok(endpoint),
        KernelObject::SharedMemory(_) | KernelObject::Window(_) => Err(IpcError::WrongObjectType),
    }
}

fn shared_memory_object(object: &Arc<KernelObject>) -> Result<&SharedMemoryObject, IpcError> {
    match object.as_ref() {
        KernelObject::SharedMemory(memory) => Ok(memory),
        KernelObject::Channel(_) | KernelObject::Window(_) => Err(IpcError::WrongObjectType),
    }
}

fn window_endpoint(object: &Arc<KernelObject>) -> Result<&WindowEndpoint, IpcError> {
    match object.as_ref() {
        KernelObject::Window(endpoint) => Ok(endpoint),
        KernelObject::Channel(_) | KernelObject::SharedMemory(_) => Err(IpcError::WrongObjectType),
    }
}

fn window_endpoint_for_role(
    object: &Arc<KernelObject>,
    role: WindowRole,
) -> Result<&WindowEndpoint, IpcError> {
    let endpoint = window_endpoint(object)?;
    if endpoint.role != role {
        return Err(IpcError::AccessDenied);
    }
    Ok(endpoint)
}

fn checked_range(
    offset: usize,
    length: usize,
    allocation_len: usize,
) -> Result<core::ops::Range<usize>, IpcError> {
    let end = offset.checked_add(length).ok_or(IpcError::InvalidMessage)?;
    if end > allocation_len {
        return Err(IpcError::InvalidMessage);
    }
    Ok(offset..end)
}

fn copy_window_buffer(
    state: &WindowState,
    presentation: WindowPresentation,
    offset: usize,
    output: &mut [u8],
) -> Result<(), IpcError> {
    if presentation.generation != state.generation {
        return Err(IpcError::InvalidMessage);
    }
    let relative = checked_range(offset, output.len(), state.buffer_len)?;
    let index = usize::try_from(presentation.buffer_index).map_err(|_| IpcError::InvalidMessage)?;
    if index >= state.buffers.len() {
        return Err(IpcError::InvalidMessage);
    }
    let buffer_start = index
        .checked_mul(state.buffer_len)
        .ok_or(IpcError::InvalidMessage)?;
    let start = buffer_start
        .checked_add(relative.start)
        .ok_or(IpcError::InvalidMessage)?;
    let end = buffer_start
        .checked_add(relative.end)
        .ok_or(IpcError::InvalidMessage)?;
    let memory = shared_memory_object(&state.shared_memory)
        .expect("window referenced a non-shared-memory object");
    let bytes = memory.bytes.lock();
    output.copy_from_slice(&bytes[start..end]);
    Ok(())
}

fn object_reaches_channel(
    object: &Arc<KernelObject>,
    destination: &Arc<Spinlock<ChannelState>>,
    visited: &mut Vec<usize>,
) -> bool {
    let KernelObject::Channel(endpoint) = object.as_ref() else {
        return false;
    };
    let mut pending = Vec::from([Arc::clone(&endpoint.state)]);

    while let Some(candidate) = pending.pop() {
        if Arc::ptr_eq(&candidate, destination) {
            return true;
        }

        let identity = Arc::as_ptr(&candidate) as usize;
        if visited.contains(&identity) {
            continue;
        }
        visited.push(identity);

        // Clone outgoing state references while holding exactly one channel
        // lock, then continue iteratively. This keeps traversal bounded by heap
        // capacity rather than kernel stack depth and avoids nested lock order.
        let outgoing = {
            let state = candidate.lock();
            let mut outgoing = Vec::new();
            for queue in &state.queues {
                for message in queue {
                    for entry in &message.handles {
                        if let KernelObject::Channel(endpoint) = entry.object.as_ref() {
                            outgoing.push(Arc::clone(&endpoint.state));
                        }
                    }
                }
            }
            outgoing
        };
        pending.extend(outgoing);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_memory_checks_ranges_and_shares_bytes_across_aliases_and_transfer() {
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        assert_eq!(
            sender.shared_memory_create(0),
            Err(IpcError::InvalidMessage)
        );

        let memory = sender.shared_memory_create(8).unwrap();
        assert_eq!(sender.object_type(memory), Ok(ObjectType::SharedMemory));
        assert_eq!(sender.shared_memory_len(memory), Ok(8));
        let memory_rights = sender.handle_rights(memory).unwrap();
        assert!(memory_rights.contains(Rights::READ | Rights::WRITE | Rights::MANAGE));
        assert!(!memory_rights.contains(Rights::MAP));

        let mut bytes = [0xff; 8];
        sender.shared_memory_read(memory, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 8]);
        sender
            .shared_memory_write(memory, 2, &[1, 2, 3, 4])
            .unwrap();

        let alias_rights = Rights::READ | Rights::WRITE | Rights::TRANSFER;
        let alias = sender.handle_duplicate(memory, alias_rights).unwrap();
        sender.shared_memory_write(alias, 4, &[9, 8]).unwrap();
        sender.shared_memory_read(memory, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0, 0, 1, 2, 9, 8, 0, 0]);

        assert_eq!(
            sender.shared_memory_write(memory, 7, &[1, 2]),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            sender.shared_memory_read(memory, usize::MAX, &mut [0; 1]),
            Err(IpcError::InvalidMessage)
        );
        sender.shared_memory_read(memory, 8, &mut []).unwrap();
        sender.shared_memory_write(memory, 8, &[]).unwrap();

        let (send, receive) = channel_create_between(&mut sender, &mut receiver).unwrap();
        sender
            .channel_write_with_dispositions(
                send,
                &[],
                &[HandleDisposition::new(alias, Rights::READ)],
            )
            .unwrap();
        assert_eq!(sender.object_type(alias), Err(IpcError::InvalidHandle));
        let mut transferred = [Handle::INVALID; 1];
        receiver
            .channel_read(receive, &mut [], &mut transferred)
            .unwrap();
        let transferred = transferred[0];
        assert_eq!(
            receiver.object_type(transferred),
            Ok(ObjectType::SharedMemory)
        );
        assert_eq!(receiver.handle_rights(transferred), Ok(Rights::READ));

        sender.shared_memory_write(memory, 0, &[7, 6]).unwrap();
        receiver
            .shared_memory_read(transferred, 0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [7, 6, 1, 2, 9, 8, 0, 0]);
        assert_eq!(
            receiver.shared_memory_write(transferred, 0, &[0]),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            sender.shared_memory_read(send, 0, &mut []),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(IpcError::OutOfMemory.status(), Status::OutOfMemory);
    }

    #[test]
    fn window_capabilities_have_stable_types_protected_roles_and_checked_backing() {
        assert_eq!(ObjectType::Channel as u32, 1);
        assert_eq!(ObjectType::SharedMemory as u32, 2);
        assert_eq!(ObjectType::Window as u32, 3);

        let mut table = HandleTable::new();
        let one_byte = table.shared_memory_create(1).unwrap();
        assert_eq!(table.window_create(one_byte), Err(IpcError::InvalidMessage));
        let odd = table.shared_memory_create(3).unwrap();
        assert_eq!(table.window_create(odd), Err(IpcError::InvalidMessage));

        let memory = table.shared_memory_create(8).unwrap();
        let read_only = table.handle_duplicate(memory, Rights::READ).unwrap();
        assert_eq!(table.window_create(read_only), Err(IpcError::AccessDenied));
        let (client, manager) = table.window_create(memory).unwrap();

        assert_eq!(table.object_type(client), Ok(ObjectType::Window));
        assert_eq!(table.object_type(manager), Ok(ObjectType::Window));
        assert_eq!(table.window_buffer_len(client), Ok(4));
        assert_eq!(table.window_buffer_len(manager), Ok(4));
        assert_eq!(table.window_buffer_count(client), Ok(2));
        assert_eq!(table.window_buffer_count(manager), Ok(2));
        assert_eq!(table.handle_rights(client), Ok(WINDOW_CLIENT_RIGHTS));
        assert_eq!(table.handle_rights(manager), Ok(WINDOW_MANAGER_RIGHTS));
        assert!(!WINDOW_CLIENT_RIGHTS.contains(Rights::MANAGE));
        assert!(!WINDOW_MANAGER_RIGHTS.contains(Rights::WRITE));

        assert_eq!(
            table.window_manager_pending(client),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.window_present(manager, 0, 1),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.shared_memory_len(client),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.window_buffer_len(memory),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(table.window_create(manager), Err(IpcError::WrongObjectType));

        let (channel, _) = table.channel_create().unwrap();
        assert_eq!(
            table.window_present(channel, 0, 1),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.channel_read(client, &mut [], &mut []),
            Err(IpcError::WrongObjectType)
        );
    }

    #[test]
    fn window_three_buffer_pool_reuses_generation_and_bounds_release_ownership() {
        let mut table = HandleTable::new();
        let memory = table.shared_memory_create(12).unwrap();
        assert_eq!(
            table.window_create_with_generation_and_buffer_count(memory, 0, 3),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            table.window_create_with_generation_and_buffer_count(memory, 7, 1),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            table.window_create_with_generation_and_buffer_count(memory, 7, 5),
            Err(IpcError::InvalidMessage)
        );

        let (client, manager) = table
            .window_create_with_generation_and_buffer_count(memory, 7, 3)
            .unwrap();
        assert_eq!(table.window_buffer_count(client), Ok(3));
        assert_eq!(table.window_buffer_len(client), Ok(4));

        let first = table.window_present(client, 0, 7).unwrap();
        table.window_manager_complete(manager, first, true).unwrap();
        let second = table.window_present(client, 1, 7).unwrap();
        table
            .window_manager_complete(manager, second, true)
            .unwrap();

        let signals = table.object_signals(client).unwrap();
        assert!(signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.window_present(client, 2, 7),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            table.window_manager_retire(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.window_manager_displayed(manager), Ok(Some(second)));

        assert_eq!(
            table.window_read_release(client).unwrap(),
            WindowRelease {
                buffer_index: 0,
                generation: 7,
                presentation_serial: first.presentation_serial,
            }
        );
        assert_eq!(table.window_read_release(client), Err(IpcError::ShouldWait));
        let signals = table.object_signals(client).unwrap();
        assert!(!signals.contains(Signals::READABLE));
        assert!(signals.contains(Signals::WRITABLE));

        let third = table.window_present(client, 2, 7).unwrap();
        let signals = table.object_signals(client).unwrap();
        assert!(!signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        table.window_manager_complete(manager, third, true).unwrap();
        assert_eq!(
            table.window_manager_pending(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.window_manager_displayed(manager), Ok(Some(third)));
        let signals = table.object_signals(client).unwrap();
        assert!(signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.window_present(client, 0, 7),
            Err(IpcError::ShouldWait)
        );
        let second_release = table.window_read_release(client).unwrap();
        assert_eq!(
            second_release,
            WindowRelease {
                buffer_index: 1,
                generation: 7,
                presentation_serial: second.presentation_serial,
            }
        );

        assert!(table
            .object_signals(client)
            .unwrap()
            .contains(Signals::WRITABLE));
        let fourth = table.window_present(client, 1, 7).unwrap();
        assert_eq!(first.presentation_serial, 1);
        assert_eq!(second.presentation_serial, 2);
        assert_eq!(third.presentation_serial, 3);
        assert_eq!(fourth.presentation_serial, 4);
        assert_eq!(fourth.generation, 7);
    }

    #[test]
    fn window_retirement_is_atomic_and_drains_the_displayed_release() {
        let mut table = HandleTable::new();
        let memory = table.shared_memory_create(8).unwrap();
        let (client, manager) = table
            .window_create_with_generation_and_buffer_count(memory, 11, 2)
            .unwrap();
        let presentation = table.window_present(client, 0, 11).unwrap();

        assert_eq!(
            table.window_manager_retire(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.window_manager_pending(manager), Ok(presentation));
        assert_eq!(table.window_manager_displayed(manager), Ok(None));
        assert_eq!(table.window_read_release(client), Err(IpcError::ShouldWait));
        let signals = table.object_signals(client).unwrap();
        assert!(!signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));

        table
            .window_manager_complete(manager, presentation, false)
            .unwrap();
        assert_eq!(
            table.window_manager_retire(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.window_manager_pending(manager), Ok(presentation));

        table
            .window_manager_complete(manager, presentation, true)
            .unwrap();
        table.window_manager_retire(manager).unwrap();
        assert_eq!(table.window_manager_displayed(manager), Ok(None));
        assert_eq!(
            table.window_manager_copy_displayed(manager, presentation, 0, &mut [0; 1]),
            Err(IpcError::InvalidMessage)
        );
        let signals = table.object_signals(client).unwrap();
        assert!(signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.window_present(client, 1, 11),
            Err(IpcError::ShouldWait)
        );

        assert_eq!(
            table.window_read_release(client).unwrap(),
            WindowRelease {
                buffer_index: 0,
                generation: 11,
                presentation_serial: presentation.presentation_serial,
            }
        );
        let signals = table.object_signals(client).unwrap();
        assert!(!signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.window_present(client, 0, 11),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(table.window_read_release(client), Err(IpcError::ShouldWait));
        table.window_manager_retire(manager).unwrap();
    }

    #[test]
    fn window_final_role_closure_signals_peers_without_alias_false_positives() {
        let mut table = HandleTable::new();
        let memory = table.shared_memory_create(16).unwrap();
        let (client, manager) = table.window_create(memory).unwrap();
        let manager_alias = table
            .handle_duplicate(manager, WINDOW_MANAGER_RIGHTS)
            .unwrap();
        table.window_present(client, 0, 1).unwrap();

        table.handle_close(manager).unwrap();
        assert!(!table
            .object_signals(client)
            .unwrap()
            .contains(Signals::PEER_CLOSED));
        table.handle_close(manager_alias).unwrap();
        let client_signals = table.object_signals(client).unwrap();
        assert!(client_signals.contains(Signals::PEER_CLOSED));
        assert!(!client_signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.window_present(client, 1, 1),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(table.window_read_release(client), Err(IpcError::PeerClosed));

        let (client, manager) = table.window_create(memory).unwrap();
        let client_alias = table
            .handle_duplicate(client, WINDOW_CLIENT_RIGHTS)
            .unwrap();
        let pending = table.window_present(client, 0, 1).unwrap();
        table.handle_close(client).unwrap();
        assert!(!table
            .object_signals(manager)
            .unwrap()
            .contains(Signals::PEER_CLOSED));
        table.handle_close(client_alias).unwrap();
        let manager_signals = table.object_signals(manager).unwrap();
        assert!(manager_signals.contains(Signals::PEER_CLOSED));
        assert!(manager_signals.contains(Signals::READABLE));
        assert_eq!(table.window_manager_pending(manager), Ok(pending));
        table
            .window_manager_complete(manager, pending, true)
            .unwrap();
        let manager_signals = table.object_signals(manager).unwrap();
        assert!(manager_signals.contains(Signals::PEER_CLOSED));
        assert!(!manager_signals.contains(Signals::READABLE));
    }

    #[test]
    fn window_two_buffer_lifecycle_is_atomic_and_signal_driven_across_transfer() {
        let mut manager_table = HandleTable::new();
        let mut client_table = HandleTable::new();
        let memory = manager_table.shared_memory_create(8).unwrap();
        manager_table
            .shared_memory_write(memory, 0, &[1, 2, 3, 4])
            .unwrap();
        manager_table
            .shared_memory_write(memory, 4, &[5, 6, 7, 8])
            .unwrap();
        let (client, manager) = manager_table.window_create(memory).unwrap();
        let (send, receive) =
            channel_create_between(&mut manager_table, &mut client_table).unwrap();
        manager_table
            .channel_write(send, b"window", &[client])
            .unwrap();
        assert!(!manager_table
            .object_signals(manager)
            .unwrap()
            .contains(Signals::PEER_CLOSED));
        let mut transferred = [Handle::INVALID; 1];
        client_table
            .channel_read(receive, &mut [0; 6], &mut transferred)
            .unwrap();
        let client = transferred[0];
        assert_eq!(client_table.object_type(client), Ok(ObjectType::Window));
        assert_eq!(client_table.handle_rights(client), Ok(WINDOW_CLIENT_RIGHTS));
        assert!(!manager_table
            .object_signals(manager)
            .unwrap()
            .contains(Signals::PEER_CLOSED));

        let signals = client_table.object_signals(client).unwrap();
        assert!(signals.contains(Signals::WRITABLE));
        assert!(!signals.contains(Signals::READABLE));
        assert_eq!(
            client_table.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            manager_table.window_manager_pending(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(manager_table.window_manager_displayed(manager), Ok(None));

        assert_eq!(
            client_table.window_present(client, 0, 2),
            Err(IpcError::InvalidMessage)
        );
        let first = client_table.window_present(client, 0, 1).unwrap();
        assert_eq!(
            first,
            WindowPresentation {
                buffer_index: 0,
                generation: 1,
                presentation_serial: 1,
            }
        );
        assert_eq!(
            client_table.window_present(client, 1, 1),
            Err(IpcError::ShouldWait)
        );
        let client_signals = client_table.object_signals(client).unwrap();
        assert!(!client_signals.contains(Signals::WRITABLE));
        assert!(!client_signals.contains(Signals::READABLE));
        assert!(manager_table
            .object_signals(manager)
            .unwrap()
            .contains(Signals::READABLE));
        assert_eq!(manager_table.window_manager_pending(manager), Ok(first));

        let mut copied = [0; 4];
        assert_eq!(
            manager_table.window_manager_copy_displayed(manager, first, 0, &mut copied),
            Err(IpcError::InvalidMessage)
        );
        manager_table
            .window_manager_copy_pending(manager, first, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4]);
        assert_eq!(
            manager_table.window_manager_copy_pending(manager, first, 3, &mut [0; 2]),
            Err(IpcError::InvalidMessage)
        );
        let stale_serial = WindowPresentation {
            presentation_serial: first.presentation_serial + 1,
            ..first
        };
        let stale_index = WindowPresentation {
            buffer_index: 1,
            ..first
        };
        assert_eq!(
            manager_table.window_manager_copy_pending(manager, stale_serial, 0, &mut copied),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            manager_table.window_manager_complete(manager, stale_index, true),
            Err(IpcError::InvalidMessage)
        );

        manager_table
            .window_manager_complete(manager, first, false)
            .unwrap();
        assert_eq!(manager_table.window_manager_pending(manager), Ok(first));
        assert_eq!(manager_table.window_manager_displayed(manager), Ok(None));
        assert_eq!(
            client_table.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert!(!client_table
            .object_signals(client)
            .unwrap()
            .contains(Signals::WRITABLE));

        manager_table
            .window_manager_complete(manager, first, true)
            .unwrap();
        assert_eq!(
            manager_table.window_manager_pending(manager),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            manager_table.window_manager_displayed(manager),
            Ok(Some(first))
        );
        assert!(client_table
            .object_signals(client)
            .unwrap()
            .contains(Signals::WRITABLE));
        assert_eq!(
            client_table.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            client_table.window_present(client, 0, 1),
            Err(IpcError::InvalidMessage)
        );

        let second = client_table.window_present(client, 1, 1).unwrap();
        assert_eq!(second.generation, 1);
        assert_eq!(second.presentation_serial, 2);
        manager_table
            .window_manager_copy_pending(manager, second, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, [5, 6, 7, 8]);
        copied.fill(0);
        manager_table
            .window_manager_copy_displayed(manager, first, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4]);
        assert_eq!(
            manager_table.window_manager_copy_displayed(manager, stale_serial, 0, &mut copied),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            manager_table.window_manager_copy_displayed(manager, first, 4, &mut [0; 1]),
            Err(IpcError::InvalidMessage)
        );
        manager_table
            .window_manager_complete(manager, second, false)
            .unwrap();
        assert_eq!(manager_table.window_manager_pending(manager), Ok(second));
        assert_eq!(
            manager_table.window_manager_displayed(manager),
            Ok(Some(first))
        );
        assert_eq!(
            client_table.window_read_release(client),
            Err(IpcError::ShouldWait)
        );
        assert!(!client_table
            .object_signals(client)
            .unwrap()
            .contains(Signals::WRITABLE));

        manager_table
            .window_manager_complete(manager, second, true)
            .unwrap();
        assert_eq!(
            manager_table.window_manager_displayed(manager),
            Ok(Some(second))
        );
        assert_eq!(
            manager_table.window_manager_copy_displayed(manager, first, 0, &mut copied),
            Err(IpcError::InvalidMessage)
        );
        manager_table
            .window_manager_copy_displayed(manager, second, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, [5, 6, 7, 8]);
        let signals = client_table.object_signals(client).unwrap();
        assert!(signals.contains(Signals::READABLE));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            client_table.window_present(client, 0, 1),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            client_table.window_present(client, 0, 2),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(
            client_table.window_present(client, WINDOW_BUFFER_COUNT as u32, 1),
            Err(IpcError::ShouldWait)
        );

        let first_release = client_table.window_read_release(client).unwrap();
        assert_eq!(
            first_release,
            WindowRelease {
                buffer_index: 0,
                generation: 1,
                presentation_serial: first.presentation_serial,
            }
        );
        let signals = client_table.object_signals(client).unwrap();
        assert!(!signals.contains(Signals::READABLE));
        assert!(signals.contains(Signals::WRITABLE));

        let third = client_table
            .window_present(client, first_release.buffer_index, first_release.generation)
            .unwrap();
        assert_eq!(third.buffer_index, 0);
        assert_eq!(third.generation, 1);
        assert_eq!(third.presentation_serial, 3);
        assert_eq!(
            manager_table.window_manager_complete(manager, second, true),
            Err(IpcError::InvalidMessage)
        );
        manager_table
            .window_manager_complete(manager, third, true)
            .unwrap();
        manager_table
            .window_manager_copy_displayed(manager, third, 0, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4]);
        assert_eq!(
            manager_table.window_manager_copy_displayed(manager, second, 0, &mut copied),
            Err(IpcError::InvalidMessage)
        );
        assert_eq!(
            client_table.window_present(client, 0, 1),
            Err(IpcError::ShouldWait)
        );
        assert!(!client_table
            .object_signals(client)
            .unwrap()
            .contains(Signals::WRITABLE));
        let second_release = client_table.window_read_release(client).unwrap();
        assert_eq!(
            second_release,
            WindowRelease {
                buffer_index: 1,
                generation: 1,
                presentation_serial: second.presentation_serial,
            }
        );

        let fourth = client_table
            .window_present(
                client,
                second_release.buffer_index,
                second_release.generation,
            )
            .unwrap();
        assert_eq!(fourth.buffer_index, 1);
        assert_eq!(fourth.generation, 1);
        assert_eq!(fourth.presentation_serial, 4);
    }

    #[test]
    fn preserves_message_boundaries_and_order() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        table.channel_write(left, b"first", &[]).unwrap();
        table.channel_write(left, b"second", &[]).unwrap();

        let mut bytes = [0; 16];
        let first = table.channel_read(right, &mut bytes, &mut []).unwrap();
        assert_eq!(first, MessageInfo::new(5, 0));
        assert_eq!(&bytes[..first.byte_count as usize], b"first");

        let second = table.channel_read(right, &mut bytes, &mut []).unwrap();
        assert_eq!(&bytes[..second.byte_count as usize], b"second");
        assert_eq!(
            table.channel_read(right, &mut bytes, &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn enforces_bounded_queues_and_reports_writability() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        for sequence in 0..CHANNEL_QUEUE_CAPACITY {
            table.channel_write(left, &[sequence as u8], &[]).unwrap();
        }
        assert_eq!(
            table.channel_write(left, b"full", &[]),
            Err(IpcError::ShouldWait)
        );
        assert!(!table
            .object_signals(left)
            .unwrap()
            .contains(Signals::WRITABLE));
        assert!(table
            .object_signals(right)
            .unwrap()
            .contains(Signals::READABLE));

        table.channel_read(right, &mut [0], &mut []).unwrap();
        assert!(table
            .object_signals(left)
            .unwrap()
            .contains(Signals::WRITABLE));
    }

    #[test]
    fn leaves_a_message_queued_when_outputs_are_too_small() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        table.channel_write(left, b"payload", &[]).unwrap();

        let required = MessageInfo::new(7, 0);
        assert_eq!(
            table.channel_read(right, &mut [0; 3], &mut []),
            Err(IpcError::BufferTooSmall(required))
        );
        let mut bytes = [0; 7];
        assert_eq!(
            table.channel_read(right, &mut bytes, &mut []).unwrap(),
            required
        );
        assert_eq!(&bytes, b"payload");
    }

    #[test]
    fn atomically_moves_handles_between_process_tables() {
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let (send, receive) = channel_create_between(&mut sender, &mut receiver).unwrap();
        let (transferred, retained_peer) = sender.channel_create().unwrap();
        let transferred_rights = sender.handle_rights(transferred).unwrap();

        sender
            .channel_write(send, b"endpoint", &[transferred])
            .unwrap();
        assert_eq!(
            sender.object_type(transferred),
            Err(IpcError::InvalidHandle)
        );

        let mut bytes = [0; 8];
        let mut handles = [Handle::INVALID; 1];
        let info = receiver
            .channel_read(receive, &mut bytes, &mut handles)
            .unwrap();
        assert_eq!(info, MessageInfo::new(8, 1));
        assert_eq!(receiver.object_type(handles[0]), Ok(ObjectType::Channel));
        assert_eq!(receiver.handle_rights(handles[0]), Ok(transferred_rights));

        sender
            .channel_write(retained_peer, b"cross-table", &[])
            .unwrap();
        let mut payload = [0; 11];
        receiver
            .channel_read(handles[0], &mut payload, &mut [])
            .unwrap();
        assert_eq!(&payload, b"cross-table");
    }

    #[test]
    fn transfer_dispositions_install_attenuated_receiver_rights() {
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let (send, receive) = channel_create_between(&mut sender, &mut receiver).unwrap();
        let (transferred, retained_peer) = sender.channel_create().unwrap();
        let destination_rights = Rights::READ | Rights::WAIT;

        sender
            .channel_write_with_dispositions(
                send,
                b"attenuated",
                &[HandleDisposition::new(transferred, destination_rights)],
            )
            .unwrap();
        assert_eq!(
            sender.handle_rights(transferred),
            Err(IpcError::InvalidHandle)
        );

        let mut bytes = [0; 10];
        let mut handles = [Handle::INVALID; 1];
        receiver
            .channel_read(receive, &mut bytes, &mut handles)
            .unwrap();
        assert_eq!(&bytes, b"attenuated");
        assert_eq!(receiver.handle_rights(handles[0]), Ok(destination_rights));
        assert_eq!(
            receiver.channel_write(handles[0], b"denied", &[]),
            Err(IpcError::AccessDenied)
        );

        sender
            .channel_write(retained_peer, b"readable", &[])
            .unwrap();
        assert!(receiver
            .object_signals(handles[0])
            .unwrap()
            .contains(Signals::READABLE));
        let mut payload = [0; 8];
        receiver
            .channel_read(handles[0], &mut payload, &mut [])
            .unwrap();
        assert_eq!(&payload, b"readable");
    }

    #[test]
    fn rejects_rights_escalation_and_sources_without_transfer_rights_atomically() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        let original_rights = table.handle_rights(candidate).unwrap();

        assert_eq!(
            table.channel_write_with_dispositions(
                left,
                b"escalated",
                &[HandleDisposition::new(
                    candidate,
                    original_rights | Rights::MANAGE,
                )],
            ),
            Err(IpcError::InvalidRights)
        );
        assert_eq!(table.handle_rights(candidate), Ok(original_rights));
        assert_eq!(
            table.channel_read(right, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );

        let non_transferable = table
            .handle_duplicate(candidate, Rights::READ | Rights::WAIT)
            .unwrap();
        assert_eq!(
            table.channel_write_with_dispositions(
                left,
                b"no transfer",
                &[HandleDisposition::new(non_transferable, Rights::READ)],
            ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.handle_rights(non_transferable),
            Ok(Rights::READ | Rights::WAIT)
        );
        assert_eq!(
            table.channel_read(right, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn rejects_duplicate_dispositions_without_consuming_or_queueing() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        let original_rights = table.handle_rights(candidate).unwrap();

        assert_eq!(
            table.channel_write_with_dispositions(
                left,
                b"duplicate",
                &[
                    HandleDisposition::new(candidate, Rights::READ),
                    HandleDisposition::new(candidate, Rights::WAIT),
                ],
            ),
            Err(IpcError::DuplicateHandle)
        );
        assert_eq!(table.handle_rights(candidate), Ok(original_rights));
        assert_eq!(
            table.channel_read(right, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn full_queue_rejects_dispositions_without_consuming_or_queueing() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        let original_rights = table.handle_rights(candidate).unwrap();
        for sequence in 0..CHANNEL_QUEUE_CAPACITY {
            table.channel_write(left, &[sequence as u8], &[]).unwrap();
        }

        assert_eq!(
            table.channel_write_with_dispositions(
                left,
                b"full",
                &[HandleDisposition::new(candidate, Rights::READ)],
            ),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.handle_rights(candidate), Ok(original_rights));

        let mut byte = [0; 1];
        for sequence in 0..CHANNEL_QUEUE_CAPACITY {
            let info = table.channel_read(right, &mut byte, &mut []).unwrap();
            assert_eq!(info, MessageInfo::new(1, 0));
            assert_eq!(byte[0], sequence as u8);
        }
        assert_eq!(
            table.channel_read(right, &mut byte, &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn closed_queue_rejects_dispositions_without_consuming_or_queueing() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        let original_rights = table.handle_rights(candidate).unwrap();
        let (state, peer) = {
            let object = table.object_with_rights(left, Rights::WRITE).unwrap();
            let endpoint = channel_endpoint(&object).unwrap();
            (Arc::clone(&endpoint.state), 1 - endpoint.side)
        };
        table.handle_close(right).unwrap();

        assert_eq!(
            table.channel_write_with_dispositions(
                left,
                b"closed",
                &[HandleDisposition::new(candidate, Rights::READ)],
            ),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(table.handle_rights(candidate), Ok(original_rights));
        let state = state.lock();
        assert!(!state.open[peer]);
        assert!(state.queues[peer].is_empty());
    }

    #[test]
    fn rejects_transfers_that_would_create_channel_ownership_cycles() {
        let mut table = HandleTable::new();
        let (first_left, first_right) = table.channel_create().unwrap();
        let (second_left, second_right) = table.channel_create().unwrap();

        table
            .channel_write(first_left, b"first to second", &[second_left])
            .unwrap();
        assert_eq!(
            table.channel_write(second_right, b"second to first", &[first_right]),
            Err(IpcError::CyclicTransfer)
        );
        assert_eq!(table.object_type(first_right), Ok(ObjectType::Channel));
        assert_eq!(IpcError::CyclicTransfer.status(), Status::CyclicTransfer);

        let mut handles = [Handle::INVALID; 1];
        table
            .channel_read(first_right, &mut [0; 15], &mut handles)
            .unwrap();
        assert_eq!(table.object_type(handles[0]), Ok(ObjectType::Channel));
    }

    #[test]
    fn failed_write_does_not_consume_transferred_handles() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        for _ in 0..CHANNEL_QUEUE_CAPACITY {
            table.channel_write(left, &[], &[]).unwrap();
        }

        assert_eq!(
            table.channel_write(left, &[], &[candidate]),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.object_type(candidate), Ok(ObjectType::Channel));
        assert_eq!(
            table.channel_write(left, &[], &[candidate, candidate]),
            Err(IpcError::DuplicateHandle)
        );
        assert_eq!(table.object_type(candidate), Ok(ObjectType::Channel));
        assert!(table
            .object_signals(right)
            .unwrap()
            .contains(Signals::READABLE));
    }

    #[test]
    fn reports_peer_closure_after_the_last_alias_is_closed() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        let alias = table
            .handle_duplicate(right, CHANNEL_DEFAULT_RIGHTS)
            .unwrap();
        table.handle_close(right).unwrap();
        assert!(!table
            .object_signals(left)
            .unwrap()
            .contains(Signals::PEER_CLOSED));

        table.handle_close(alias).unwrap();
        let signals = table.object_signals(left).unwrap();
        assert!(signals.contains(Signals::PEER_CLOSED));
        assert!(!signals.contains(Signals::WRITABLE));
        assert_eq!(
            table.channel_write(left, b"lost", &[]),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(
            table.channel_read(left, &mut [], &mut []),
            Err(IpcError::PeerClosed)
        );
    }

    #[test]
    fn duplication_can_only_reduce_rights() {
        let mut table = HandleTable::new();
        let (left, _) = table.channel_create().unwrap();
        let read_only = table
            .handle_duplicate(left, Rights::READ | Rights::WAIT)
            .unwrap();
        assert_eq!(
            table.channel_write(read_only, b"denied", &[]),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.handle_duplicate(read_only, Rights::READ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.handle_duplicate(left, CHANNEL_DEFAULT_RIGHTS | Rights::MANAGE),
            Err(IpcError::InvalidRights)
        );
    }

    #[test]
    fn stale_integer_handles_do_not_revalidate_after_slot_reuse() {
        let mut table = HandleTable::new();
        let (left, right) = table.channel_create().unwrap();
        table.handle_close(left).unwrap();
        let (replacement, _) = table.channel_create().unwrap();

        assert_ne!(left, replacement);
        assert_eq!(table.object_signals(left), Err(IpcError::InvalidHandle));
        assert_eq!(table.object_type(replacement), Ok(ObjectType::Channel));
        table.handle_close(right).unwrap();
    }

    #[test]
    fn retires_slots_before_generation_values_can_wrap() {
        let mut slot = HandleSlot {
            generation: HANDLE_GENERATION_MASK,
            entry: None,
        };
        slot.advance_generation();
        assert_eq!(slot.generation, 0);

        let mut table = HandleTable {
            slots: alloc::vec![slot],
        };
        let reserved = table.reserve_slots(1).unwrap();
        assert_eq!(reserved, alloc::vec![1]);
    }

    #[test]
    fn wait_many_reports_pending_signals_and_first_ready_item() {
        let mut table = HandleTable::new();
        let (first, first_peer) = table.channel_create().unwrap();
        let (second, second_peer) = table.channel_create().unwrap();
        table.channel_write(second_peer, b"ready", &[]).unwrap();

        let mut items = [
            WaitItem::new(first, Signals::READABLE),
            WaitItem::new(second, Signals::READABLE | Signals::PEER_CLOSED),
        ];
        assert_eq!(table.poll_wait_many(&mut items).unwrap(), Some(1));
        assert!(!items[0].pending.contains(Signals::READABLE));
        assert!(items[1].pending.contains(Signals::READABLE));

        table.handle_close(first_peer).unwrap();
        items[0].wait_for = Signals::PEER_CLOSED;
        assert_eq!(table.poll_wait_many(&mut items).unwrap(), Some(0));
    }
}
