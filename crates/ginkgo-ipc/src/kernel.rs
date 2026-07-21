//! Capability handles and bounded asynchronous channels.
//!
//! [`HandleTable`] is the process-local boundary for kernel objects. Channels
//! preserve datagram boundaries and may atomically move handles between tables.
//! Operations are intentionally nonblocking so they can be used by the current
//! cooperative scheduler; a future syscall layer can block around the exposed
//! object signals without changing channel semantics.

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

/// A channel or handle-table operation failure.
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

    /// Creates both ends of a channel in this table.
    pub fn channel_create(&mut self) -> Result<(Handle, Handle), IpcError> {
        let slots = self.reserve_slots(2)?;
        let [left, right] = new_channel_objects();
        let left = self.insert_reserved(slots[0], left, CHANNEL_DEFAULT_RIGHTS);
        let right = self.insert_reserved(slots[1], right, CHANNEL_DEFAULT_RIGHTS);
        Ok((left, right))
    }

    /// Writes one complete message and atomically moves all attached handles.
    ///
    /// On any error, including a full queue or closed peer, every source handle
    /// remains valid in this table.
    pub fn channel_write(
        &mut self,
        channel: Handle,
        bytes: &[u8],
        handles: &[Handle],
    ) -> Result<(), IpcError> {
        if bytes.len() > CHANNEL_MAX_BYTES || handles.len() > CHANNEL_MAX_HANDLES {
            return Err(IpcError::MessageTooLarge);
        }

        let channel_object = self.object_with_rights(channel, Rights::WRITE)?;
        let endpoint = channel_endpoint(&channel_object)?;

        let mut transfer_slots = Vec::with_capacity(handles.len());
        for (position, handle) in handles.iter().copied().enumerate() {
            if handles[..position].contains(&handle) {
                return Err(IpcError::DuplicateHandle);
            }
            let (index, _) = self.validated_slot(handle)?;
            let entry = self.slots[index]
                .entry
                .as_ref()
                .ok_or(IpcError::InvalidHandle)?;
            if !entry.rights.contains(Rights::TRANSFER) {
                return Err(IpcError::AccessDenied);
            }
            transfer_slots.push(index);
        }

        // Allocate all message storage before the commit point. The kernel's
        // allocator is currently infallible, so no operation below can fail
        // after handles start moving out of the sender.
        let message_bytes = bytes.to_vec().into_boxed_slice();
        let mut message_handles = Vec::with_capacity(handles.len());

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
        for &index in &transfer_slots {
            let entry = self.slots[index]
                .entry
                .as_ref()
                .expect("validated transfer slot became vacant");
            if object_reaches_channel(&entry.object, &endpoint.state, &mut visited) {
                return Err(IpcError::CyclicTransfer);
            }
        }

        for index in transfer_slots {
            let entry = self.slots[index]
                .entry
                .take()
                .expect("validated transfer slot became vacant");
            self.slots[index].advance_generation();
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
        }
    }

    /// Returns current level-triggered signals without blocking.
    pub fn object_signals(&self, handle: Handle) -> Result<Signals, IpcError> {
        let object = self.object_with_rights(handle, Rights::WAIT)?;
        match object.as_ref() {
            KernelObject::Channel(endpoint) => Ok(endpoint.signals()),
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
    }
}

fn object_reaches_channel(
    object: &Arc<KernelObject>,
    destination: &Arc<Spinlock<ChannelState>>,
    visited: &mut Vec<usize>,
) -> bool {
    let KernelObject::Channel(endpoint) = object.as_ref();
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
                        let KernelObject::Channel(endpoint) = entry.object.as_ref();
                        outgoing.push(Arc::clone(&endpoint.state));
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
