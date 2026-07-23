//! Capability handles for channels, shared memory, and protected windows.
//!
//! [`HandleTable`] is the process-local boundary for kernel objects. Channels
//! preserve datagram boundaries and may atomically move handles between tables;
//! duplicated and transferred shared-memory/window handles retain object identity.
//! Operations are intentionally nonblocking so they can be used by the current
//! cooperative scheduler; a future syscall layer can block around exposed object
//! signals without changing these semantics.

use alloc::{
    alloc::{alloc_zeroed, dealloc, Layout},
    collections::VecDeque,
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{
    mem,
    ptr::NonNull,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};

use ginkgo_filesystem::{DirectoryHandle, FileHandle};
use ginkgo_sysapi::{
    Handle, MessageInfo, ObjectType, ProcessFault, ProcessInfo, ProcessState,
    ProcessTerminationCause, Rights, Signals, Status, WaitItem, CHANNEL_MAX_BYTES,
    CHANNEL_MAX_HANDLES,
};
use spinning_top::Spinlock;

/// Maximum number of complete messages queued in either direction.
pub const CHANNEL_QUEUE_CAPACITY: usize = 64;
/// Maximum number of live or vacant slots retained by one handle table.
pub const HANDLE_TABLE_CAPACITY: usize = 256;
/// Required allocation and mapping alignment for shared-memory backing.
pub const SHARED_MEMORY_PAGE_SIZE: usize = 4096;
/// Default number of equal shared-memory slots owned by [`HandleTable::window_create`].
pub const WINDOW_BUFFER_COUNT: usize = 2;
/// Maximum UTF-8 byte length of an application-data scope identifier.
pub const APPLICATION_DATA_MAX_APP_ID_LEN: usize = 127;

const HANDLE_INDEX_BITS: u32 = 12;
const HANDLE_INDEX_MASK: u32 = (1 << HANDLE_INDEX_BITS) - 1;
const HANDLE_GENERATION_MASK: u32 = (1 << (32 - HANDLE_INDEX_BITS)) - 1;

// Serializes queue-edge additions while cycle detection traverses other channel
// states. Reads and endpoint teardown only remove edges and need no graph lock.
static CHANNEL_GRAPH_LOCK: Spinlock<()> = Spinlock::new(());

static SHARED_MEMORY_LIVE_OBJECTS: AtomicUsize = AtomicUsize::new(0);
static SHARED_MEMORY_LOGICAL_BYTES: AtomicUsize = AtomicUsize::new(0);
static SHARED_MEMORY_MAPPED_ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static SHARED_MEMORY_CUMULATIVE_CREATIONS: AtomicUsize = AtomicUsize::new(0);
static SHARED_MEMORY_CUMULATIVE_DROPS: AtomicUsize = AtomicUsize::new(0);

/// Global shared-memory backing allocation diagnostics.
///
/// Byte totals describe currently live backing allocations. Cumulative totals
/// increase monotonically for each successfully allocated and subsequently dropped
/// backing, including allocations whose enclosing handle creation later fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryBackingStats {
    pub live_objects: usize,
    pub logical_bytes: usize,
    pub mapped_allocated_bytes: usize,
    pub cumulative_creations: usize,
    pub cumulative_drops: usize,
}

/// Returns a point-in-time snapshot of global shared-memory backing diagnostics.
pub fn shared_memory_backing_stats() -> SharedMemoryBackingStats {
    SharedMemoryBackingStats {
        live_objects: SHARED_MEMORY_LIVE_OBJECTS.load(Ordering::Relaxed),
        logical_bytes: SHARED_MEMORY_LOGICAL_BYTES.load(Ordering::Relaxed),
        mapped_allocated_bytes: SHARED_MEMORY_MAPPED_ALLOCATED_BYTES.load(Ordering::Relaxed),
        cumulative_creations: SHARED_MEMORY_CUMULATIVE_CREATIONS.load(Ordering::Relaxed),
        cumulative_drops: SHARED_MEMORY_CUMULATIVE_DROPS.load(Ordering::Relaxed),
    }
}

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
        | Rights::MAP.bits()
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
const PROCESS_DEFAULT_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::WAIT.bits()
        | Rights::INSPECT.bits()
        | Rights::TERMINATE.bits()
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
    Process(ProcessControl),
    ApplicationData(ApplicationDataScope),
    FilesystemRoot,
    Directory(DirectoryHandle),
    File(FileHandle),
    RandomSource,
}

/// An owned, cloneable application-data namespace scope.
///
/// Clones share immutable validated identifier storage and remain valid after the
/// originating handle is closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationDataScope {
    app_id: Arc<String>,
}

impl ApplicationDataScope {
    pub fn app_id(&self) -> &str {
        self.app_id.as_str()
    }
}

impl AsRef<str> for ApplicationDataScope {
    fn as_ref(&self) -> &str {
        self.app_id()
    }
}

/// Scheduler-facing ownership of a waitable process object's persistent state.
///
/// This control is independent of the scheduler's process representation. The
/// scheduler retains a clone while a process is live, records exactly one terminal
/// outcome, and may then drop its clone; handle-owned clones continue to provide
/// inspection and terminal signals until the final handle is closed.
#[derive(Clone)]
pub struct ProcessControl {
    state: Arc<Spinlock<ProcessControlState>>,
}

#[derive(Clone, Copy)]
struct ProcessControlState {
    info: ProcessInfo,
    terminate_requested: bool,
}

impl ProcessControl {
    /// Creates running process state without installing a handle.
    pub fn new() -> Result<Self, IpcError> {
        let info = ProcessInfo {
            state: ProcessState::Running as u32,
            cause: ProcessTerminationCause::None as u32,
            exit_code: 0,
            fault: ProcessFault::None as u32,
            fault_code: 0,
            fault_address: 0,
        };
        let state = Arc::try_new(Spinlock::new(ProcessControlState {
            info,
            terminate_requested: false,
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
        Ok(Self { state })
    }

    /// Returns the stable public process snapshot without requiring a handle.
    pub fn info(&self) -> ProcessInfo {
        self.state.lock().info
    }

    /// Reports whether a holder of `TERMINATE` has requested scheduler teardown.
    pub fn terminate_requested(&self) -> bool {
        self.state.lock().terminate_requested
    }

    /// Records normal process exit unless another terminal outcome won the race.
    pub fn mark_exited(&self, exit_code: i32) -> bool {
        self.mark_terminal(ProcessInfo {
            state: ProcessState::Terminated as u32,
            cause: ProcessTerminationCause::Exited as u32,
            exit_code,
            fault: ProcessFault::None as u32,
            fault_code: 0,
            fault_address: 0,
        })
    }

    /// Records a structured userspace fault unless the process is already terminal.
    ///
    /// `ProcessFault::None` is not a fault and is rejected without changing state.
    /// A zero `fault_address` represents an unavailable or inapplicable address.
    pub fn mark_faulted(&self, fault: ProcessFault, fault_code: u64, fault_address: u64) -> bool {
        if fault == ProcessFault::None {
            return false;
        }
        self.mark_terminal(ProcessInfo {
            state: ProcessState::Terminated as u32,
            cause: ProcessTerminationCause::Faulted as u32,
            exit_code: 0,
            fault: fault as u32,
            fault_code,
            fault_address,
        })
    }

    /// Records scheduler acknowledgement of external termination.
    pub fn mark_terminated(&self) -> bool {
        self.mark_terminal(ProcessInfo {
            state: ProcessState::Terminated as u32,
            cause: ProcessTerminationCause::Terminated as u32,
            exit_code: 0,
            fault: ProcessFault::None as u32,
            fault_code: 0,
            fault_address: 0,
        })
    }

    fn request_terminate(&self) -> bool {
        let mut state = self.state.lock();
        if state.info.state == ProcessState::Terminated as u32 {
            return false;
        }
        state.terminate_requested = true;
        true
    }

    fn signals(&self) -> Signals {
        if self.state.lock().info.state == ProcessState::Terminated as u32 {
            Signals::TERMINATED
        } else {
            Signals::empty()
        }
    }

    fn mark_terminal(&self, info: ProcessInfo) -> bool {
        let mut state = self.state.lock();
        if state.info.state == ProcessState::Terminated as u32 {
            return false;
        }
        state.info = info;
        true
    }
}

struct SharedMemoryObject {
    backing: SharedMemoryBacking,
    access: Spinlock<()>,
}

struct SharedMemoryBacking {
    base: NonNull<u8>,
    logical_len: usize,
    layout: Layout,
}

impl SharedMemoryBacking {
    fn new(logical_len: usize) -> Result<Self, IpcError> {
        let mapped_len = logical_len
            .checked_add(SHARED_MEMORY_PAGE_SIZE - 1)
            .ok_or(IpcError::InvalidMessage)?
            & !(SHARED_MEMORY_PAGE_SIZE - 1);
        let layout = Layout::from_size_align(mapped_len, SHARED_MEMORY_PAGE_SIZE)
            .map_err(|_| IpcError::InvalidMessage)?;
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(IpcError::OutOfMemory)?;

        SHARED_MEMORY_LIVE_OBJECTS.fetch_add(1, Ordering::Relaxed);
        SHARED_MEMORY_LOGICAL_BYTES.fetch_add(logical_len, Ordering::Relaxed);
        SHARED_MEMORY_MAPPED_ALLOCATED_BYTES.fetch_add(mapped_len, Ordering::Relaxed);
        SHARED_MEMORY_CUMULATIVE_CREATIONS.fetch_add(1, Ordering::Relaxed);

        Ok(Self {
            base,
            logical_len,
            layout,
        })
    }

    fn mapped_len(&self) -> usize {
        self.layout.size()
    }
}

// SAFETY: the allocation address and lengths are immutable. All safe byte access
// is serialized by SharedMemoryObject::access; raw mapping users must provide the
// external synchronization documented by SharedMemoryMappingLease.
unsafe impl Send for SharedMemoryBacking {}
unsafe impl Sync for SharedMemoryBacking {}

impl Drop for SharedMemoryBacking {
    fn drop(&mut self) {
        unsafe { dealloc(self.base.as_ptr(), self.layout) };
        SHARED_MEMORY_LIVE_OBJECTS.fetch_sub(1, Ordering::Relaxed);
        SHARED_MEMORY_LOGICAL_BYTES.fetch_sub(self.logical_len, Ordering::Relaxed);
        SHARED_MEMORY_MAPPED_ALLOCATED_BYTES.fetch_sub(self.mapped_len(), Ordering::Relaxed);
        SHARED_MEMORY_CUMULATIVE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
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
    buffers: Vec<WindowBufferState>,
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
    bytes: Vec<u8>,
    handles: Vec<HandleEntry>,
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

/// Kernel-internal channel handle operation, independent of the syscall ABI layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleOperation {
    Move,
    Duplicate,
}

/// One atomic move or duplicate operation attached to a channel write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleOperationDisposition {
    pub handle: Handle,
    pub operation: HandleOperation,
    pub rights: Rights,
}

impl HandleOperationDisposition {
    pub const fn move_handle(handle: Handle, rights: Rights) -> Self {
        Self {
            handle,
            operation: HandleOperation::Move,
            rights,
        }
    }

    pub const fn duplicate(handle: Handle, rights: Rights) -> Self {
        Self {
            handle,
            operation: HandleOperation::Duplicate,
            rights,
        }
    }
}

/// Page-aligned kernel backing metadata retained by a mapping lease.
///
/// Direct mapped access aliases kernel read/write APIs and all writable aliases;
/// mapping code must provide external synchronization and enforce the requested
/// userspace protections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedMemoryMappingInfo {
    /// Immutable base address of the page-aligned kernel allocation.
    pub base: *const u8,
    /// API-visible byte length used by read/write and window subdivision.
    pub logical_len: usize,
    /// Page-rounded allocation length available to a real mapping implementation.
    pub mapped_len: usize,
}

/// Access requested by an owning shared-memory mapping lease.
///
/// Executable mappings are intentionally unsupported and cannot be represented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedMemoryMappingAccess {
    ReadOnly,
    ReadWrite,
}

impl SharedMemoryMappingAccess {
    const fn required_rights(self) -> Rights {
        match self {
            Self::ReadOnly => Rights::MAP.union(Rights::READ),
            Self::ReadWrite => Rights::MAP.union(Rights::READ).union(Rights::WRITE),
        }
    }
}

/// Owns a reference to shared-memory backing prepared for a future process mapping.
///
/// The lease keeps the allocation alive across source handle close or transfer. It
/// does not itself install a userspace mapping; process code must enforce address
/// placement, effective rights, and coherency with every writable alias.
#[derive(Clone)]
pub struct SharedMemoryMappingLease {
    _object: Arc<KernelObject>,
    info: SharedMemoryMappingInfo,
    effective_rights: Rights,
}

impl SharedMemoryMappingLease {
    pub const fn info(&self) -> SharedMemoryMappingInfo {
        self.info
    }

    pub const fn effective_rights(&self) -> Rights {
        self.effective_rights
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

    /// Creates running process control state and installs its default capability.
    ///
    /// The returned [`ProcessControl`] is retained by the scheduler independently
    /// of the handle. Closing the handle does not request or cause termination.
    pub fn process_create(&mut self) -> Result<(Handle, ProcessControl), IpcError> {
        let process = ProcessControl::new()?;
        let handle = self.process_install(&process)?;
        Ok((handle, process))
    }

    /// Installs a default-rights handle for existing process control state.
    pub fn process_install(&mut self, process: &ProcessControl) -> Result<Handle, IpcError> {
        let object = Arc::try_new(KernelObject::Process(process.clone()))
            .map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, PROCESS_DEFAULT_RIGHTS))
    }

    /// Returns persistent process status. The handle must carry [`Rights::INSPECT`].
    pub fn process_info(&self, handle: Handle) -> Result<ProcessInfo, IpcError> {
        let object = self.object_with_rights(handle, Rights::INSPECT)?;
        Ok(process_control(&object)?.info())
    }

    /// Requests external process termination through a [`Rights::TERMINATE`] handle.
    ///
    /// This only records a request. The scheduler remains responsible for stopping
    /// the process and calling [`ProcessControl::mark_terminated`]. Requests made
    /// after a terminal outcome are harmless no-ops.
    pub fn process_terminate(&self, handle: Handle) -> Result<(), IpcError> {
        let object = self.object_with_rights(handle, Rights::TERMINATE)?;
        process_control(&object)?.request_terminate();
        Ok(())
    }

    /// Creates a non-transferable capability authorizing kernel random bytes.
    pub fn random_source_create(&mut self) -> Result<Handle, IpcError> {
        let object = Arc::try_new(KernelObject::RandomSource).map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, Rights::READ))
    }

    pub fn random_source(&self, handle: Handle) -> Result<(), IpcError> {
        let object = self.object_with_rights(handle, Rights::READ)?;
        match object.as_ref() {
            KernelObject::RandomSource => Ok(()),
            _ => Err(IpcError::WrongObjectType),
        }
    }

    /// Creates a transferable application-private data identity capability.
    ///
    /// The identifier is independently validated against the lowercase registry
    /// grammar and copied into bounded immutable storage.
    pub fn application_data_create(&mut self, app_id: &str) -> Result<Handle, IpcError> {
        if !valid_application_data_app_id(app_id) {
            return Err(IpcError::InvalidMessage);
        }
        let mut owned_app_id = String::new();
        owned_app_id
            .try_reserve_exact(app_id.len())
            .map_err(|_| IpcError::OutOfMemory)?;
        owned_app_id.push_str(app_id);
        let app_id = Arc::try_new(owned_app_id).map_err(|_| IpcError::OutOfMemory)?;
        let object = Arc::try_new(KernelObject::ApplicationData(ApplicationDataScope {
            app_id,
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, Rights::READ | Rights::TRANSFER))
    }

    /// Returns an owned clone of an application-data scope after checking rights.
    pub fn application_data_scope(
        &self,
        handle: Handle,
        required_rights: Rights,
    ) -> Result<ApplicationDataScope, IpcError> {
        let object = self.object_with_rights(handle, required_rights | Rights::READ)?;
        match object.as_ref() {
            KernelObject::ApplicationData(scope) => Ok(scope.clone()),
            _ => Err(IpcError::WrongObjectType),
        }
    }

    /// Creates a non-transferable read/write capability for the filesystem root namespace.
    pub fn filesystem_root_create(&mut self) -> Result<Handle, IpcError> {
        self.filesystem_root_create_with_rights(Rights::READ | Rights::WRITE)
    }

    /// Creates a filesystem-root capability with explicitly bounded namespace access.
    ///
    /// `rights` must be a nonempty subset of `READ | WRITE | EXECUTE`. Root handles
    /// intentionally carry neither `DUPLICATE` nor `TRANSFER` authority.
    pub fn filesystem_root_create_with_rights(
        &mut self,
        rights: Rights,
    ) -> Result<Handle, IpcError> {
        let allowed = Rights::READ | Rights::WRITE | Rights::EXECUTE;
        if rights.is_empty() || !allowed.contains(rights) {
            return Err(IpcError::InvalidRights);
        }
        let object =
            Arc::try_new(KernelObject::FilesystemRoot).map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, rights))
    }

    /// Creates a scoped directory capability with explicitly bounded authority.
    ///
    /// `rights` must be a nonempty subset of `READ | WRITE | DUPLICATE | TRANSFER`.
    /// Read and write authorize directory operations; duplicate and transfer authorize
    /// delegation and may be attenuated independently.
    pub fn filesystem_directory_create(
        &mut self,
        directory: DirectoryHandle,
        rights: Rights,
    ) -> Result<Handle, IpcError> {
        let allowed = Rights::READ | Rights::WRITE | Rights::DUPLICATE | Rights::TRANSFER;
        if rights.is_empty() || !allowed.contains(rights) {
            return Err(IpcError::InvalidRights);
        }
        let object =
            Arc::try_new(KernelObject::Directory(directory)).map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, rights))
    }

    /// Returns a scoped filesystem directory after checking all requested rights.
    pub fn filesystem_directory(
        &self,
        handle: Handle,
        required_rights: Rights,
    ) -> Result<DirectoryHandle, IpcError> {
        let object = self.object_with_rights(handle, required_rights)?;
        match object.as_ref() {
            KernelObject::Directory(directory) => Ok(*directory),
            _ => Err(IpcError::WrongObjectType),
        }
    }

    /// Creates a process-local file capability with bounded data or execution access.
    ///
    /// `DUPLICATE` and `TRANSFER` may accompany ordinary read/write access. Execution
    /// requires read access and is mutually exclusive with write access, preventing a
    /// writable executable capability from being created.
    pub fn filesystem_file_create(
        &mut self,
        file: FileHandle,
        rights: Rights,
    ) -> Result<Handle, IpcError> {
        let allowed =
            Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::DUPLICATE | Rights::TRANSFER;
        let has_data_access = rights.intersects(Rights::READ | Rights::WRITE);
        let invalid_execute = rights.contains(Rights::EXECUTE)
            && (!rights.contains(Rights::READ) || rights.contains(Rights::WRITE));
        if rights.is_empty() || !allowed.contains(rights) || !has_data_access || invalid_execute {
            return Err(IpcError::InvalidRights);
        }
        let object = Arc::try_new(KernelObject::File(file)).map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, rights))
    }

    pub fn filesystem_root(&self, handle: Handle, rights: Rights) -> Result<(), IpcError> {
        let object = self.object_with_rights(handle, rights)?;
        match object.as_ref() {
            KernelObject::FilesystemRoot => Ok(()),
            _ => Err(IpcError::WrongObjectType),
        }
    }

    pub fn filesystem_file(&self, handle: Handle, rights: Rights) -> Result<FileHandle, IpcError> {
        let object = self.object_with_rights(handle, rights)?;
        match object.as_ref() {
            KernelObject::File(file) => Ok(*file),
            _ => Err(IpcError::WrongObjectType),
        }
    }

    /// Creates zero-filled, heap-backed shared memory.
    pub fn shared_memory_create(&mut self, size: usize) -> Result<Handle, IpcError> {
        if size == 0 {
            return Err(IpcError::InvalidMessage);
        }

        let backing = SharedMemoryBacking::new(size)?;
        let object = Arc::try_new(KernelObject::SharedMemory(SharedMemoryObject {
            backing,
            access: Spinlock::new(()),
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
        let slot = self.reserve_slots(1)?[0];
        Ok(self.insert_reserved(slot, object, SHARED_MEMORY_DEFAULT_RIGHTS))
    }

    /// Returns the immutable allocation length of a shared-memory object.
    pub fn shared_memory_len(&self, handle: Handle) -> Result<usize, IpcError> {
        let object = self.object_with_rights(handle, Rights::READ)?;
        Ok(shared_memory_object(&object)?.backing.logical_len)
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
        let _access = memory.access.lock();
        let range = checked_range(offset, output.len(), memory.backing.logical_len)?;
        let bytes = unsafe {
            slice::from_raw_parts(memory.backing.base.as_ptr(), memory.backing.logical_len)
        };
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
        let _access = memory.access.lock();
        let range = checked_range(offset, input.len(), memory.backing.logical_len)?;
        let bytes = unsafe {
            slice::from_raw_parts_mut(memory.backing.base.as_ptr(), memory.backing.logical_len)
        };
        bytes[range].copy_from_slice(input);
        Ok(())
    }

    /// Acquires an owning lease for a future process mapping.
    ///
    /// Read-only access requires `MAP | READ`; writable access requires
    /// `MAP | READ | WRITE`. Executable leases are unsupported. This does not
    /// install a userspace mapping; the returned lease only retains the object and
    /// records the maximum effective rights authorized by this request.
    pub fn shared_memory_mapping_lease(
        &self,
        handle: Handle,
        access: SharedMemoryMappingAccess,
    ) -> Result<SharedMemoryMappingLease, IpcError> {
        let effective_rights = access.required_rights();
        let object = self.object_with_rights(handle, effective_rights)?;
        let backing = &shared_memory_object(&object)?.backing;
        let info = SharedMemoryMappingInfo {
            base: backing.base.as_ptr().cast_const(),
            logical_len: backing.logical_len,
            mapped_len: backing.mapped_len(),
        };
        Ok(SharedMemoryMappingLease {
            _object: object,
            info,
            effective_rights,
        })
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
        let memory_len = shared_memory_object(&memory)?.backing.logical_len;
        if memory_len < buffer_count || memory_len % buffer_count != 0 {
            return Err(IpcError::InvalidMessage);
        }
        let buffer_len = memory_len / buffer_count;

        let mut buffers = try_vec_with_capacity(buffer_count)?;
        buffers.resize(buffer_count, WindowBufferState::ClientOwned);
        let slots = self.reserve_slots(2)?;
        let state = Arc::try_new(Spinlock::new(WindowState {
            shared_memory: memory,
            buffer_len,
            generation,
            buffers,
            pending: None,
            displayed: None,
            release: None,
            next_serial: 1,
            retired: false,
            client_open: true,
            manager_open: true,
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
        let client = Arc::try_new(KernelObject::Window(WindowEndpoint {
            state: Arc::clone(&state),
            role: WindowRole::Client,
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
        let manager = Arc::try_new(KernelObject::Window(WindowEndpoint {
            state,
            role: WindowRole::Manager,
        }))
        .map_err(|_| IpcError::OutOfMemory)?;
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
        let [left, right] = new_channel_objects()?;
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

        let mut dispositions = try_vec_with_capacity(handles.len())?;
        for handle in handles.iter().copied() {
            dispositions.push(HandleDisposition::new(handle, self.handle_rights(handle)?));
        }
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
        let mut operations = try_vec_with_capacity(dispositions.len())?;
        for disposition in dispositions {
            operations.push(HandleOperationDisposition::move_handle(
                disposition.handle,
                disposition.rights,
            ));
        }
        self.channel_write_with_handle_operations(channel, bytes, &operations)
    }

    /// Writes one message with an atomic ordered mix of moves and duplicates.
    ///
    /// A move requires [`Rights::TRANSFER`] and consumes its source only after every
    /// validation succeeds. A duplicate requires [`Rights::DUPLICATE`] and retains
    /// its source. Destination rights must be subsets, source handles must be unique,
    /// and every failure leaves all originals valid with no message queued.
    pub fn channel_write_with_handle_operations(
        &mut self,
        channel: Handle,
        bytes: &[u8],
        dispositions: &[HandleOperationDisposition],
    ) -> Result<(), IpcError> {
        self.channel_write_with_handle_operations_impl(channel, bytes, dispositions, &mut || Ok(()))
    }

    fn channel_write_with_handle_operations_impl<F>(
        &mut self,
        channel: Handle,
        bytes: &[u8],
        dispositions: &[HandleOperationDisposition],
        graph_allocation_hook: &mut F,
    ) -> Result<(), IpcError>
    where
        F: FnMut() -> Result<(), IpcError>,
    {
        enum PreparedHandle {
            Move { index: usize, rights: Rights },
            Duplicate(HandleEntry),
        }

        if bytes.len() > CHANNEL_MAX_BYTES || dispositions.len() > CHANNEL_MAX_HANDLES {
            return Err(IpcError::MessageTooLarge);
        }

        let channel_object = self.object_with_rights(channel, Rights::WRITE)?;
        let endpoint = channel_endpoint(&channel_object)?;

        let mut prepared = try_vec_with_capacity(dispositions.len())?;
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
            let required = match disposition.operation {
                HandleOperation::Move => Rights::TRANSFER,
                HandleOperation::Duplicate => Rights::DUPLICATE,
            };
            if !entry.rights.contains(required) {
                return Err(IpcError::AccessDenied);
            }
            if !entry.rights.contains(disposition.rights) {
                return Err(IpcError::InvalidRights);
            }
            match disposition.operation {
                HandleOperation::Move => prepared.push(PreparedHandle::Move {
                    index,
                    rights: disposition.rights,
                }),
                HandleOperation::Duplicate => {
                    prepared.push(PreparedHandle::Duplicate(HandleEntry {
                        object: Arc::clone(&entry.object),
                        rights: disposition.rights,
                    }))
                }
            }
        }

        // Allocate all message storage before the commit point, so no operation
        // below can fail after move handles start leaving the sender.
        let mut message_bytes = try_vec_with_capacity(bytes.len())?;
        message_bytes.extend_from_slice(bytes);
        let mut message_handles = try_vec_with_capacity(dispositions.len())?;

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
        for handle in &prepared {
            let object = match handle {
                PreparedHandle::Move { index, .. } => {
                    &self.slots[*index]
                        .entry
                        .as_ref()
                        .expect("validated move slot became vacant")
                        .object
                }
                PreparedHandle::Duplicate(entry) => &entry.object,
            };
            if object_reaches_channel(object, &endpoint.state, &mut visited, graph_allocation_hook)?
            {
                return Err(IpcError::CyclicTransfer);
            }
        }

        for handle in prepared {
            let entry = match handle {
                PreparedHandle::Move { index, rights } => {
                    let mut entry = self.slots[index]
                        .entry
                        .take()
                        .expect("validated move slot became vacant");
                    self.slots[index].advance_generation();
                    entry.rights = rights;
                    entry
                }
                PreparedHandle::Duplicate(entry) => entry,
            };
            message_handles.push(entry);
        }
        state.queues[peer].push_back(KernelMessage {
            bytes: message_bytes,
            handles: message_handles,
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
            KernelObject::RandomSource => Ok(ObjectType::RandomSource),
            KernelObject::Window(_) => Ok(ObjectType::Window),
            KernelObject::Process(_) => Ok(ObjectType::Process),
            KernelObject::ApplicationData(_) => Ok(ObjectType::ApplicationData),
            KernelObject::FilesystemRoot => Ok(ObjectType::FilesystemRoot),
            KernelObject::Directory(_) => Ok(ObjectType::Directory),
            KernelObject::File(_) => Ok(ObjectType::File),
        }
    }

    /// Returns current level-triggered signals without blocking.
    pub fn object_signals(&self, handle: Handle) -> Result<Signals, IpcError> {
        let object = self.object_with_rights(handle, Rights::WAIT)?;
        match object.as_ref() {
            KernelObject::Channel(endpoint) => Ok(endpoint.signals()),
            KernelObject::SharedMemory(_) | KernelObject::RandomSource => Ok(Signals::empty()),
            KernelObject::Window(endpoint) => Ok(endpoint.signals()),
            KernelObject::Process(process) => Ok(process.signals()),
            KernelObject::ApplicationData(_)
            | KernelObject::FilesystemRoot
            | KernelObject::Directory(_)
            | KernelObject::File(_) => Ok(Signals::empty()),
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

        let mut reserved = try_vec_with_capacity(count)?;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.entry.is_none() && slot.generation != 0 {
                reserved.push(index);
                if reserved.len() == count {
                    return Ok(reserved);
                }
            }
        }
        let new_slot_count = count - reserved.len();
        self.slots
            .try_reserve_exact(new_slot_count)
            .map_err(|_| IpcError::OutOfMemory)?;
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

/// Atomically applies an ordered batch of moves and duplicates between handle tables.
///
/// Every source handle must occur at most once. Moves require [`Rights::TRANSFER`],
/// duplicates require [`Rights::DUPLICATE`], and destination rights must be subsets
/// of the source rights. All validation and allocation, including reservation of
/// every destination slot, completes before any source or destination entry changes.
/// On error both tables are unchanged. Returned destination-local handles correspond
/// one-for-one with `dispositions` in the same order.
pub fn handle_transfer_batch_between(
    source_table: &mut HandleTable,
    destination_table: &mut HandleTable,
    dispositions: &[HandleOperationDisposition],
) -> Result<Vec<Handle>, IpcError> {
    enum PreparedHandle {
        Move { index: usize, rights: Rights },
        Duplicate(HandleEntry),
    }

    let mut prepared = try_vec_with_capacity(dispositions.len())?;
    for (position, disposition) in dispositions.iter().copied().enumerate() {
        if dispositions[..position]
            .iter()
            .any(|prior| prior.handle == disposition.handle)
        {
            return Err(IpcError::DuplicateHandle);
        }

        let (index, _) = source_table.validated_slot(disposition.handle)?;
        let entry = source_table.slots[index]
            .entry
            .as_ref()
            .ok_or(IpcError::InvalidHandle)?;
        let required = match disposition.operation {
            HandleOperation::Move => Rights::TRANSFER,
            HandleOperation::Duplicate => Rights::DUPLICATE,
        };
        if !entry.rights.contains(required) {
            return Err(IpcError::AccessDenied);
        }
        if !entry.rights.contains(disposition.rights) {
            return Err(IpcError::InvalidRights);
        }

        match disposition.operation {
            HandleOperation::Move => prepared.push(PreparedHandle::Move {
                index,
                rights: disposition.rights,
            }),
            HandleOperation::Duplicate => prepared.push(PreparedHandle::Duplicate(HandleEntry {
                object: Arc::clone(&entry.object),
                rights: disposition.rights,
            })),
        }
    }

    // Allocate the result before reserving destination slots. Once reservation
    // succeeds, the commit below only moves values into known-vacant entries.
    let mut destination_handles = try_vec_with_capacity(dispositions.len())?;
    let destination_slots = destination_table.reserve_slots(dispositions.len())?;
    for (prepared, destination_index) in prepared.into_iter().zip(destination_slots) {
        let entry = match prepared {
            PreparedHandle::Move { index, rights } => {
                let mut entry = source_table.slots[index]
                    .entry
                    .take()
                    .expect("validated cross-table move slot became vacant");
                source_table.slots[index].advance_generation();
                entry.rights = rights;
                entry
            }
            PreparedHandle::Duplicate(entry) => entry,
        };
        destination_table.slots[destination_index].entry = Some(entry);
        destination_handles.push(handle_from_parts(
            destination_index,
            destination_table.slots[destination_index].generation,
        ));
    }
    Ok(destination_handles)
}

/// Atomically moves one capability between process-local handle tables.
///
/// The source must carry `TRANSFER`, and `rights` must be a subset of its current
/// rights. Destination capacity is reserved before the source is consumed, so any
/// reported error leaves both tables unchanged.
pub fn handle_move_between(
    source_table: &mut HandleTable,
    destination_table: &mut HandleTable,
    source_handle: Handle,
    rights: Rights,
) -> Result<Handle, IpcError> {
    let mut handles = handle_transfer_batch_between(
        source_table,
        destination_table,
        &[HandleOperationDisposition::move_handle(
            source_handle,
            rights,
        )],
    )?;
    Ok(handles
        .pop()
        .expect("one successful cross-table disposition returned no handle"))
}

/// Creates one channel endpoint in each of two process-local handle tables.
pub fn channel_create_between(
    left_table: &mut HandleTable,
    right_table: &mut HandleTable,
) -> Result<(Handle, Handle), IpcError> {
    let left_slot = left_table.reserve_slots(1)?[0];
    let right_slot = right_table.reserve_slots(1)?[0];
    let [left, right] = new_channel_objects()?;
    let left = left_table.insert_reserved(left_slot, left, CHANNEL_DEFAULT_RIGHTS);
    let right = right_table.insert_reserved(right_slot, right, CHANNEL_DEFAULT_RIGHTS);
    Ok((left, right))
}

fn new_channel_objects() -> Result<[Arc<KernelObject>; 2], IpcError> {
    let mut left_queue = VecDeque::new();
    left_queue
        .try_reserve_exact(CHANNEL_QUEUE_CAPACITY)
        .map_err(|_| IpcError::OutOfMemory)?;
    let mut right_queue = VecDeque::new();
    right_queue
        .try_reserve_exact(CHANNEL_QUEUE_CAPACITY)
        .map_err(|_| IpcError::OutOfMemory)?;
    let state = Arc::try_new(Spinlock::new(ChannelState {
        open: [true, true],
        queues: [left_queue, right_queue],
    }))
    .map_err(|_| IpcError::OutOfMemory)?;
    let left = Arc::try_new(KernelObject::Channel(ChannelEndpoint {
        state: Arc::clone(&state),
        side: 0,
    }))
    .map_err(|_| IpcError::OutOfMemory)?;
    let right = Arc::try_new(KernelObject::Channel(ChannelEndpoint { state, side: 1 }))
        .map_err(|_| IpcError::OutOfMemory)?;
    Ok([left, right])
}

fn channel_endpoint(object: &Arc<KernelObject>) -> Result<&ChannelEndpoint, IpcError> {
    match object.as_ref() {
        KernelObject::Channel(endpoint) => Ok(endpoint),
        KernelObject::SharedMemory(_)
        | KernelObject::RandomSource
        | KernelObject::Window(_)
        | KernelObject::Process(_)
        | KernelObject::ApplicationData(_)
        | KernelObject::FilesystemRoot
        | KernelObject::Directory(_)
        | KernelObject::File(_) => Err(IpcError::WrongObjectType),
    }
}

fn shared_memory_object(object: &Arc<KernelObject>) -> Result<&SharedMemoryObject, IpcError> {
    match object.as_ref() {
        KernelObject::SharedMemory(memory) => Ok(memory),
        KernelObject::Channel(_)
        | KernelObject::RandomSource
        | KernelObject::Window(_)
        | KernelObject::Process(_)
        | KernelObject::ApplicationData(_)
        | KernelObject::FilesystemRoot
        | KernelObject::Directory(_)
        | KernelObject::File(_) => Err(IpcError::WrongObjectType),
    }
}

fn window_endpoint(object: &Arc<KernelObject>) -> Result<&WindowEndpoint, IpcError> {
    match object.as_ref() {
        KernelObject::Window(endpoint) => Ok(endpoint),
        KernelObject::Channel(_)
        | KernelObject::SharedMemory(_)
        | KernelObject::RandomSource
        | KernelObject::Process(_)
        | KernelObject::ApplicationData(_)
        | KernelObject::FilesystemRoot
        | KernelObject::Directory(_)
        | KernelObject::File(_) => Err(IpcError::WrongObjectType),
    }
}

fn process_control(object: &Arc<KernelObject>) -> Result<&ProcessControl, IpcError> {
    match object.as_ref() {
        KernelObject::Process(process) => Ok(process),
        KernelObject::Channel(_)
        | KernelObject::SharedMemory(_)
        | KernelObject::RandomSource
        | KernelObject::Window(_)
        | KernelObject::ApplicationData(_)
        | KernelObject::FilesystemRoot
        | KernelObject::Directory(_)
        | KernelObject::File(_) => Err(IpcError::WrongObjectType),
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

fn valid_application_data_app_id(app_id: &str) -> bool {
    !app_id.is_empty()
        && app_id.len() <= APPLICATION_DATA_MAX_APP_ID_LEN
        && app_id.split('.').all(|component| {
            !component.is_empty()
                && component.as_bytes()[0].is_ascii_lowercase()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !component.ends_with('-')
        })
}

fn try_vec_with_capacity<T>(capacity: usize) -> Result<Vec<T>, IpcError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| IpcError::OutOfMemory)?;
    Ok(values)
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
    let _access = memory.access.lock();
    let bytes =
        unsafe { slice::from_raw_parts(memory.backing.base.as_ptr(), memory.backing.logical_len) };
    output.copy_from_slice(&bytes[start..end]);
    Ok(())
}

fn object_reaches_channel<F>(
    object: &Arc<KernelObject>,
    destination: &Arc<Spinlock<ChannelState>>,
    visited: &mut Vec<usize>,
    allocation_hook: &mut F,
) -> Result<bool, IpcError>
where
    F: FnMut() -> Result<(), IpcError>,
{
    let KernelObject::Channel(endpoint) = object.as_ref() else {
        return Ok(false);
    };
    allocation_hook()?;
    let mut pending = try_vec_with_capacity(1)?;
    pending.push(Arc::clone(&endpoint.state));

    while let Some(candidate) = pending.pop() {
        if Arc::ptr_eq(&candidate, destination) {
            return Ok(true);
        }

        let identity = Arc::as_ptr(&candidate) as usize;
        if visited.contains(&identity) {
            continue;
        }
        allocation_hook()?;
        visited.try_reserve(1).map_err(|_| IpcError::OutOfMemory)?;
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
                            allocation_hook()?;
                            outgoing.try_reserve(1).map_err(|_| IpcError::OutOfMemory)?;
                            outgoing.push(Arc::clone(&endpoint.state));
                        }
                    }
                }
            }
            outgoing
        };
        if !outgoing.is_empty() {
            allocation_hook()?;
            pending
                .try_reserve(outgoing.len())
                .map_err(|_| IpcError::OutOfMemory)?;
            pending.extend(outgoing);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    static SHARED_MEMORY_TEST_LOCK: Spinlock<()> = Spinlock::new(());

    #[test]
    fn process_default_rights_and_operations_are_independently_gated() {
        let mut table = HandleTable::new();
        let (process, control) = table.process_create().unwrap();
        assert_eq!(table.object_type(process), Ok(ObjectType::Process));
        assert_eq!(table.handle_rights(process), Ok(PROCESS_DEFAULT_RIGHTS));
        assert_eq!(
            PROCESS_DEFAULT_RIGHTS,
            Rights::WAIT
                | Rights::INSPECT
                | Rights::TERMINATE
                | Rights::DUPLICATE
                | Rights::TRANSFER
        );
        assert_eq!(control.info().process_state(), Some(ProcessState::Running));
        assert_eq!(
            control.info().termination_cause(),
            Some(ProcessTerminationCause::None)
        );

        let inspect = table.handle_duplicate(process, Rights::INSPECT).unwrap();
        assert_eq!(table.process_info(inspect), Ok(control.info()));
        assert_eq!(table.object_signals(inspect), Err(IpcError::AccessDenied));
        assert_eq!(
            table.process_terminate(inspect),
            Err(IpcError::AccessDenied)
        );

        let wait = table.handle_duplicate(process, Rights::WAIT).unwrap();
        assert_eq!(table.object_signals(wait), Ok(Signals::empty()));
        assert_eq!(table.process_info(wait), Err(IpcError::AccessDenied));
        assert_eq!(table.process_terminate(wait), Err(IpcError::AccessDenied));

        let terminate = table.handle_duplicate(process, Rights::TERMINATE).unwrap();
        assert_eq!(table.process_info(terminate), Err(IpcError::AccessDenied));
        assert_eq!(table.object_signals(terminate), Err(IpcError::AccessDenied));
        table.process_terminate(terminate).unwrap();
        assert!(control.terminate_requested());
        assert_eq!(control.info().process_state(), Some(ProcessState::Running));
        assert_eq!(table.object_signals(process), Ok(Signals::empty()));

        let (channel, _) = table.channel_create().unwrap();
        assert_eq!(table.process_info(channel), Err(IpcError::AccessDenied));
        assert_eq!(
            table.process_terminate(channel),
            Err(IpcError::AccessDenied)
        );
        let channel_with_process_rights = table
            .handle_duplicate(channel, Rights::WAIT | Rights::INSPECT | Rights::TERMINATE)
            .unwrap_err();
        assert_eq!(channel_with_process_rights, IpcError::InvalidRights);
    }

    #[test]
    fn process_terminal_outcomes_publish_structured_info_and_signal_once() {
        let mut table = HandleTable::new();

        let (exited, exited_control) = table.process_create().unwrap();
        assert!(exited_control.mark_exited(-17));
        assert_eq!(
            table.process_info(exited).unwrap(),
            ProcessInfo {
                state: ProcessState::Terminated as u32,
                cause: ProcessTerminationCause::Exited as u32,
                exit_code: -17,
                fault: ProcessFault::None as u32,
                fault_code: 0,
                fault_address: 0,
            }
        );
        assert_eq!(table.object_signals(exited), Ok(Signals::TERMINATED));
        assert!(!exited_control.mark_terminated());

        let (faulted, faulted_control) = table.process_create().unwrap();
        assert!(!faulted_control.mark_faulted(ProcessFault::None, 1, 2));
        assert!(faulted_control.mark_faulted(ProcessFault::PageFault, 0b101, 0xdead_beef));
        let fault = table.process_info(faulted).unwrap();
        assert_eq!(fault.process_state(), Some(ProcessState::Terminated));
        assert_eq!(
            fault.termination_cause(),
            Some(ProcessTerminationCause::Faulted)
        );
        assert_eq!(fault.process_fault(), Some(ProcessFault::PageFault));
        assert_eq!(fault.exit_code, 0);
        assert_eq!(fault.fault_code, 0b101);
        assert_eq!(fault.fault_address, 0xdead_beef);
        assert_eq!(table.object_signals(faulted), Ok(Signals::TERMINATED));

        let (terminated, terminated_control) = table.process_create().unwrap();
        table.process_terminate(terminated).unwrap();
        assert!(terminated_control.terminate_requested());
        assert_eq!(table.object_signals(terminated), Ok(Signals::empty()));
        assert!(terminated_control.mark_terminated());
        let info = table.process_info(terminated).unwrap();
        assert_eq!(info.process_state(), Some(ProcessState::Terminated));
        assert_eq!(
            info.termination_cause(),
            Some(ProcessTerminationCause::Terminated)
        );
        assert_eq!(info.process_fault(), Some(ProcessFault::None));
        assert_eq!(table.object_signals(terminated), Ok(Signals::TERMINATED));
        table.process_terminate(terminated).unwrap();
        assert!(terminated_control.terminate_requested());
    }

    #[test]
    fn process_aliases_and_channel_operations_share_one_lifecycle() {
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let (process, control) = sender.process_create().unwrap();
        let moved = sender
            .handle_duplicate(process, PROCESS_DEFAULT_RIGHTS)
            .unwrap();
        let (send, receive) = channel_create_between(&mut sender, &mut receiver).unwrap();
        let received_rights = Rights::WAIT | Rights::INSPECT;
        sender
            .channel_write_with_handle_operations(
                send,
                b"processes",
                &[
                    HandleOperationDisposition::duplicate(process, received_rights),
                    HandleOperationDisposition::move_handle(moved, received_rights),
                ],
            )
            .unwrap();
        assert_eq!(sender.object_type(process), Ok(ObjectType::Process));
        assert_eq!(sender.object_type(moved), Err(IpcError::InvalidHandle));

        let mut bytes = [0; 9];
        let mut handles = [Handle::INVALID; 2];
        receiver
            .channel_read(receive, &mut bytes, &mut handles)
            .unwrap();
        assert_eq!(&bytes, b"processes");
        for handle in handles {
            assert_eq!(receiver.object_type(handle), Ok(ObjectType::Process));
            assert_eq!(receiver.handle_rights(handle), Ok(received_rights));
            assert_eq!(receiver.process_info(handle), Ok(control.info()));
        }

        assert!(control.mark_exited(23));
        assert_eq!(sender.process_info(process).unwrap().exit_code, 23);
        for handle in handles {
            assert_eq!(receiver.process_info(handle).unwrap().exit_code, 23);
            assert_eq!(receiver.object_signals(handle), Ok(Signals::TERMINATED));
        }
    }

    #[test]
    fn process_info_persists_after_scheduler_control_is_retired() {
        let mut table = HandleTable::new();
        let (process, control) = table.process_create().unwrap();
        assert!(control.mark_faulted(ProcessFault::InvalidOpcode, 6, 0));
        drop(control);

        let info = table.process_info(process).unwrap();
        assert_eq!(info.process_state(), Some(ProcessState::Terminated));
        assert_eq!(
            info.termination_cause(),
            Some(ProcessTerminationCause::Faulted)
        );
        assert_eq!(info.process_fault(), Some(ProcessFault::InvalidOpcode));
        assert_eq!(info.fault_code, 6);
        assert_eq!(table.object_signals(process), Ok(Signals::TERMINATED));
    }

    #[test]
    fn closing_the_last_process_handle_does_not_request_or_cause_termination() {
        let control = ProcessControl::new().unwrap();
        {
            let mut table = HandleTable::new();
            let first = table.process_install(&control).unwrap();
            let second = table.process_install(&control).unwrap();
            table.handle_close(first).unwrap();
            table.handle_close(second).unwrap();
            assert!(table.is_empty());
        }

        assert!(!control.terminate_requested());
        assert_eq!(control.info().process_state(), Some(ProcessState::Running));
        assert_eq!(
            control.info().termination_cause(),
            Some(ProcessTerminationCause::None)
        );
        assert!(control.mark_exited(0));
        assert_eq!(
            control.info().process_state(),
            Some(ProcessState::Terminated)
        );
    }

    #[test]
    fn shared_memory_backing_is_page_aligned_rounded_zeroed_and_map_gated() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
        let mut table = HandleTable::new();
        let one_byte = table.shared_memory_create(1).unwrap();
        let exact_page = table.shared_memory_create(SHARED_MEMORY_PAGE_SIZE).unwrap();
        let over_page = table
            .shared_memory_create(SHARED_MEMORY_PAGE_SIZE + 1)
            .unwrap();

        for (handle, logical_len, mapped_len) in [
            (one_byte, 1, SHARED_MEMORY_PAGE_SIZE),
            (exact_page, SHARED_MEMORY_PAGE_SIZE, SHARED_MEMORY_PAGE_SIZE),
            (
                over_page,
                SHARED_MEMORY_PAGE_SIZE + 1,
                SHARED_MEMORY_PAGE_SIZE * 2,
            ),
        ] {
            let lease = table
                .shared_memory_mapping_lease(handle, SharedMemoryMappingAccess::ReadOnly)
                .unwrap();
            assert_eq!(lease.effective_rights(), Rights::MAP | Rights::READ);
            let info = lease.info();
            assert_eq!(info.base as usize % SHARED_MEMORY_PAGE_SIZE, 0);
            assert_eq!(info.logical_len, logical_len);
            assert_eq!(info.mapped_len, mapped_len);
            assert_eq!(info.mapped_len % SHARED_MEMORY_PAGE_SIZE, 0);
            assert_eq!(table.shared_memory_len(handle), Ok(logical_len));

            let storage = unsafe { slice::from_raw_parts(info.base, info.mapped_len) };
            assert!(storage.iter().all(|byte| *byte == 0));
            assert!(storage[info.logical_len..].iter().all(|byte| *byte == 0));
        }

        let writable = table
            .shared_memory_mapping_lease(one_byte, SharedMemoryMappingAccess::ReadWrite)
            .unwrap();
        assert_eq!(
            writable.effective_rights(),
            Rights::MAP | Rights::READ | Rights::WRITE
        );

        let map_only = table.handle_duplicate(one_byte, Rights::MAP).unwrap();
        assert!(matches!(
            table.shared_memory_mapping_lease(map_only, SharedMemoryMappingAccess::ReadOnly),
            Err(IpcError::AccessDenied)
        ));
        let read_only = table.handle_duplicate(one_byte, Rights::READ).unwrap();
        assert!(matches!(
            table.shared_memory_mapping_lease(read_only, SharedMemoryMappingAccess::ReadOnly),
            Err(IpcError::AccessDenied)
        ));
        let mapped_read = table
            .handle_duplicate(one_byte, Rights::MAP | Rights::READ)
            .unwrap();
        let read_lease = table
            .shared_memory_mapping_lease(mapped_read, SharedMemoryMappingAccess::ReadOnly)
            .unwrap();
        assert_eq!(read_lease.effective_rights(), Rights::MAP | Rights::READ);
        assert!(matches!(
            table.shared_memory_mapping_lease(mapped_read, SharedMemoryMappingAccess::ReadWrite),
            Err(IpcError::AccessDenied)
        ));
    }

    #[test]
    fn shared_memory_mapping_lease_keeps_backing_alive_after_handle_close() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
        let baseline = shared_memory_backing_stats();
        let mut table = HandleTable::new();
        let memory = table.shared_memory_create(8).unwrap();
        assert_eq!(
            shared_memory_backing_stats(),
            SharedMemoryBackingStats {
                live_objects: baseline.live_objects + 1,
                logical_bytes: baseline.logical_bytes + 8,
                mapped_allocated_bytes: baseline.mapped_allocated_bytes + SHARED_MEMORY_PAGE_SIZE,
                cumulative_creations: baseline.cumulative_creations + 1,
                cumulative_drops: baseline.cumulative_drops,
            }
        );
        table.shared_memory_write(memory, 0, b"retained").unwrap();
        let lease = table
            .shared_memory_mapping_lease(memory, SharedMemoryMappingAccess::ReadWrite)
            .unwrap();
        let stored_lease = lease.clone();
        let info = lease.info();

        table.handle_close(memory).unwrap();
        assert_eq!(table.object_type(memory), Err(IpcError::InvalidHandle));
        assert_eq!(
            shared_memory_backing_stats(),
            SharedMemoryBackingStats {
                live_objects: baseline.live_objects + 1,
                logical_bytes: baseline.logical_bytes + 8,
                mapped_allocated_bytes: baseline.mapped_allocated_bytes + SHARED_MEMORY_PAGE_SIZE,
                cumulative_creations: baseline.cumulative_creations + 1,
                cumulative_drops: baseline.cumulative_drops,
            }
        );
        assert_eq!(stored_lease.info(), info);
        assert_eq!(
            stored_lease.effective_rights(),
            Rights::MAP | Rights::READ | Rights::WRITE
        );
        let bytes = unsafe { slice::from_raw_parts(info.base, info.logical_len) };
        assert_eq!(bytes, b"retained");
        drop(lease);
        assert_eq!(stored_lease.info(), info);
        assert_eq!(
            shared_memory_backing_stats().cumulative_drops,
            baseline.cumulative_drops
        );
        drop(stored_lease);
        assert_eq!(
            shared_memory_backing_stats(),
            SharedMemoryBackingStats {
                cumulative_creations: baseline.cumulative_creations + 1,
                cumulative_drops: baseline.cumulative_drops + 1,
                ..baseline
            }
        );
    }

    #[test]
    fn shared_memory_checks_ranges_and_shares_bytes_across_aliases_and_transfer() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
        assert!(memory_rights.contains(Rights::READ | Rights::WRITE | Rights::MAP | Rights::MANAGE));

        let mut bytes = [0xff; 8];
        sender.shared_memory_read(memory, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 8]);
        sender
            .shared_memory_write(memory, 2, &[1, 2, 3, 4])
            .unwrap();

        let alias_rights = Rights::READ | Rights::WRITE | Rights::TRANSFER;
        let alias = sender.handle_duplicate(memory, alias_rights).unwrap();
        assert!(matches!(
            sender.shared_memory_mapping_lease(alias, SharedMemoryMappingAccess::ReadOnly),
            Err(IpcError::AccessDenied)
        ));
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
        assert!(matches!(
            receiver.shared_memory_mapping_lease(transferred, SharedMemoryMappingAccess::ReadOnly),
            Err(IpcError::AccessDenied)
        ));

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
    fn application_data_capabilities_own_validated_scopes_with_exact_rights() {
        let mut table = HandleTable::new();
        let mut supplied_id = String::from("tools.paint-2");
        let application_data = table.application_data_create(&supplied_id).unwrap();
        supplied_id.clear();

        assert_eq!(
            table.object_type(application_data),
            Ok(ObjectType::ApplicationData)
        );
        assert_eq!(
            table.handle_rights(application_data),
            Ok(Rights::READ | Rights::TRANSFER)
        );
        let scope = table
            .application_data_scope(application_data, Rights::READ)
            .unwrap();
        assert_eq!(scope.app_id(), "tools.paint-2");
        assert_eq!(scope.as_ref(), "tools.paint-2");
        for rights in [Rights::WRITE, Rights::EXECUTE] {
            assert_eq!(
                table.application_data_scope(application_data, rights),
                Err(IpcError::AccessDenied)
            );
        }

        let retained = table
            .application_data_scope(application_data, Rights::READ)
            .unwrap();
        table.handle_close(application_data).unwrap();
        assert_eq!(retained.app_id(), "tools.paint-2");
    }

    #[test]
    fn application_data_scopes_are_independent_and_transfer_with_attenuation() {
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();
        let alpha = source.application_data_create("alpha.editor").unwrap();
        let beta = source.application_data_create("beta.editor").unwrap();
        let alpha_scope = source.application_data_scope(alpha, Rights::READ).unwrap();
        let beta_scope = source.application_data_scope(beta, Rights::READ).unwrap();
        assert_ne!(alpha_scope, beta_scope);
        assert_eq!(alpha_scope.app_id(), "alpha.editor");
        assert_eq!(beta_scope.app_id(), "beta.editor");

        assert_eq!(
            source.handle_duplicate(alpha, Rights::READ),
            Err(IpcError::AccessDenied)
        );
        let moved = handle_move_between(&mut source, &mut destination, alpha, Rights::READ)
            .expect("application-data identity should move with attenuation");
        assert_eq!(source.object_type(alpha), Err(IpcError::InvalidHandle));
        assert_eq!(destination.handle_rights(moved), Ok(Rights::READ));
        assert_eq!(
            destination
                .application_data_scope(moved, Rights::READ)
                .unwrap()
                .app_id(),
            "alpha.editor"
        );
        assert_eq!(
            handle_move_between(&mut destination, &mut source, moved, Rights::READ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(source.object_type(beta), Ok(ObjectType::ApplicationData));

        let root = source.filesystem_root_create().unwrap();
        assert_eq!(
            source.application_data_scope(root, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
    }

    #[test]
    fn application_data_creation_rejects_invalid_or_unbounded_app_ids() {
        let mut table = HandleTable::new();
        let maximum = "a".repeat(APPLICATION_DATA_MAX_APP_ID_LEN);
        let maximum_handle = table.application_data_create(&maximum).unwrap();
        assert_eq!(
            table
                .application_data_scope(maximum_handle, Rights::READ)
                .unwrap()
                .app_id(),
            maximum
        );

        let oversized = "a".repeat(APPLICATION_DATA_MAX_APP_ID_LEN + 1);
        for app_id in [
            "",
            ".alpha",
            "alpha.",
            "alpha..beta",
            "Alpha",
            "alpha_Beta",
            "alpha-beta-",
            "-alpha",
            "alpha/beta",
            "alpha\\beta",
            "alpha:beta",
            "alpha beta",
            "alpha\0beta",
            "álpha",
            oversized.as_str(),
        ] {
            assert_eq!(
                table.application_data_create(app_id),
                Err(IpcError::InvalidMessage),
                "accepted invalid application ID {app_id:?}"
            );
        }
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn filesystem_directory_creation_reports_type_and_enforces_bounded_rights() {
        let mut filesystem = ginkgo_filesystem::RedoxFs::new().unwrap();
        let root = filesystem.root_directory().unwrap();
        let directory = filesystem.create_directory_at(root, "scoped").unwrap();
        let mut table = HandleTable::new();

        for rights in [
            Rights::READ,
            Rights::WRITE,
            Rights::DUPLICATE,
            Rights::TRANSFER,
            Rights::READ | Rights::WRITE,
            Rights::READ | Rights::DUPLICATE | Rights::TRANSFER,
            Rights::READ | Rights::WRITE | Rights::DUPLICATE | Rights::TRANSFER,
        ] {
            let handle = table
                .filesystem_directory_create(directory, rights)
                .unwrap();
            assert_eq!(table.object_type(handle), Ok(ObjectType::Directory));
            assert_eq!(table.handle_rights(handle), Ok(rights));
            assert_eq!(table.filesystem_directory(handle, rights), Ok(directory));
        }

        let read_only = table
            .filesystem_directory_create(directory, Rights::READ)
            .unwrap();
        assert_eq!(
            table.filesystem_directory(read_only, Rights::WRITE),
            Err(IpcError::AccessDenied)
        );
        for rights in [
            Rights::empty(),
            Rights::WAIT,
            Rights::EXECUTE,
            Rights::READ | Rights::WAIT,
            Rights::WRITE | Rights::MANAGE,
        ] {
            assert_eq!(
                table.filesystem_directory_create(directory, rights),
                Err(IpcError::InvalidRights)
            );
        }
    }

    #[test]
    fn filesystem_directory_delegation_attenuates_and_transfers_as_a_graph_leaf() {
        let mut filesystem = ginkgo_filesystem::RedoxFs::new().unwrap();
        let root = filesystem.root_directory().unwrap();
        let directory = filesystem.create_directory_at(root, "delegated").unwrap();
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();
        let full_rights = Rights::READ | Rights::WRITE | Rights::DUPLICATE | Rights::TRANSFER;
        let parent = source
            .filesystem_directory_create(directory, full_rights)
            .unwrap();
        let delegated = source
            .handle_duplicate(parent, Rights::READ | Rights::TRANSFER)
            .unwrap();
        assert_eq!(source.handle_rights(parent), Ok(full_rights));
        assert_eq!(
            source.handle_rights(delegated),
            Ok(Rights::READ | Rights::TRANSFER)
        );

        let (send, receive) = channel_create_between(&mut source, &mut destination).unwrap();
        source
            .channel_write_with_dispositions(
                send,
                b"directory",
                &[HandleDisposition::new(delegated, Rights::READ)],
            )
            .unwrap();
        assert_eq!(source.object_type(delegated), Err(IpcError::InvalidHandle));
        assert_eq!(source.object_type(parent), Ok(ObjectType::Directory));

        let mut bytes = [0; 9];
        let mut handles = [Handle::INVALID; 1];
        destination
            .channel_read(receive, &mut bytes, &mut handles)
            .unwrap();
        assert_eq!(&bytes, b"directory");
        let received = handles[0];
        assert_eq!(destination.object_type(received), Ok(ObjectType::Directory));
        assert_eq!(destination.handle_rights(received), Ok(Rights::READ));
        let received_directory = destination
            .filesystem_directory(received, Rights::READ)
            .unwrap();
        assert_eq!(received_directory, directory);
        assert!(filesystem
            .list_directory(received_directory)
            .unwrap()
            .is_empty());
        assert_eq!(
            destination.handle_duplicate(received, Rights::READ),
            Err(IpcError::AccessDenied)
        );
    }

    #[test]
    fn filesystem_directory_access_rejects_other_object_kinds() {
        let mut filesystem = ginkgo_filesystem::RedoxFs::new().unwrap();
        let directory = filesystem.root_directory().unwrap();
        let file = filesystem.create_file_at(directory, "file").unwrap();
        let mut table = HandleTable::new();
        let directory_handle = table
            .filesystem_directory_create(directory, Rights::READ)
            .unwrap();
        let root_handle = table.filesystem_root_create().unwrap();
        let file_handle = table.filesystem_file_create(file, Rights::READ).unwrap();
        let application_data = table.application_data_create("directory.test").unwrap();

        assert_eq!(
            table.filesystem_directory(root_handle, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.filesystem_directory(file_handle, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.filesystem_directory(application_data, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.filesystem_root(directory_handle, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.filesystem_file(directory_handle, Rights::READ),
            Err(IpcError::WrongObjectType)
        );
        assert_eq!(
            table.object_type(root_handle),
            Ok(ObjectType::FilesystemRoot)
        );
        assert_eq!(
            table.object_type(application_data),
            Ok(ObjectType::ApplicationData)
        );
    }

    #[test]
    fn filesystem_root_creation_bounds_explicit_rights_and_preserves_default() {
        let mut table = HandleTable::new();
        let default_root = table.filesystem_root_create().unwrap();
        assert_eq!(
            table.handle_rights(default_root),
            Ok(Rights::READ | Rights::WRITE)
        );
        assert_eq!(
            table.object_type(default_root),
            Ok(ObjectType::FilesystemRoot)
        );
        assert_eq!(
            table.filesystem_root(default_root, Rights::READ | Rights::WRITE),
            Ok(())
        );
        assert_eq!(
            table.filesystem_root(default_root, Rights::EXECUTE),
            Err(IpcError::AccessDenied)
        );
        let mut destination = HandleTable::new();
        assert_eq!(
            handle_move_between(&mut table, &mut destination, default_root, Rights::READ,),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.object_type(default_root),
            Ok(ObjectType::FilesystemRoot)
        );
        assert!(destination.is_empty());

        for rights in [
            Rights::READ,
            Rights::WRITE,
            Rights::EXECUTE,
            Rights::READ | Rights::EXECUTE,
            Rights::READ | Rights::WRITE | Rights::EXECUTE,
        ] {
            let root = table.filesystem_root_create_with_rights(rights).unwrap();
            assert_eq!(table.handle_rights(root), Ok(rights));
            assert_eq!(table.filesystem_root(root, rights), Ok(()));
            assert_eq!(
                table.handle_duplicate(root, rights),
                Err(IpcError::AccessDenied)
            );
        }

        for rights in [
            Rights::empty(),
            Rights::DUPLICATE,
            Rights::TRANSFER,
            Rights::READ | Rights::DUPLICATE,
            Rights::EXECUTE | Rights::TRANSFER,
            Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::WAIT,
        ] {
            assert_eq!(
                table.filesystem_root_create_with_rights(rights),
                Err(IpcError::InvalidRights)
            );
        }
    }

    #[test]
    fn filesystem_file_creation_supports_read_only_executable_transfer() {
        let mut filesystem = ginkgo_filesystem::RedoxFs::new().unwrap();
        let file = filesystem.create("/ipc-executable-rights").unwrap();
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();

        for rights in [
            Rights::READ,
            Rights::WRITE,
            Rights::READ | Rights::WRITE,
            Rights::READ | Rights::DUPLICATE,
            Rights::WRITE | Rights::TRANSFER,
        ] {
            let handle = source.filesystem_file_create(file, rights).unwrap();
            assert_eq!(source.handle_rights(handle), Ok(rights));
            assert_eq!(source.filesystem_file(handle, rights), Ok(file));
            assert_eq!(source.object_type(handle), Ok(ObjectType::File));
        }

        let executable_rights =
            Rights::READ | Rights::EXECUTE | Rights::DUPLICATE | Rights::TRANSFER;
        let executable = source
            .filesystem_file_create(file, executable_rights)
            .unwrap();
        assert_eq!(source.handle_rights(executable), Ok(executable_rights));
        assert_eq!(
            source.filesystem_file(executable, Rights::READ | Rights::EXECUTE),
            Ok(file)
        );
        assert_eq!(
            source.filesystem_file(executable, Rights::WRITE),
            Err(IpcError::AccessDenied)
        );

        let transferred_source = source
            .handle_duplicate(
                executable,
                Rights::READ | Rights::EXECUTE | Rights::TRANSFER,
            )
            .unwrap();
        let transferred = handle_move_between(
            &mut source,
            &mut destination,
            transferred_source,
            Rights::READ | Rights::EXECUTE,
        )
        .unwrap();
        assert_eq!(
            source.object_type(transferred_source),
            Err(IpcError::InvalidHandle)
        );
        assert_eq!(destination.object_type(transferred), Ok(ObjectType::File));
        assert_eq!(
            destination.handle_rights(transferred),
            Ok(Rights::READ | Rights::EXECUTE)
        );
        assert_eq!(
            destination.filesystem_file(transferred, Rights::EXECUTE),
            Ok(file)
        );
        assert_eq!(source.object_type(executable), Ok(ObjectType::File));
    }

    #[test]
    fn filesystem_file_creation_rejects_invalid_and_writable_execute_rights() {
        let mut filesystem = ginkgo_filesystem::RedoxFs::new().unwrap();
        let file = filesystem.create("/ipc-invalid-execute-rights").unwrap();
        let mut table = HandleTable::new();

        for rights in [
            Rights::empty(),
            Rights::DUPLICATE,
            Rights::TRANSFER,
            Rights::DUPLICATE | Rights::TRANSFER,
            Rights::EXECUTE,
            Rights::EXECUTE | Rights::DUPLICATE | Rights::TRANSFER,
            Rights::WRITE | Rights::EXECUTE,
            Rights::READ | Rights::WRITE | Rights::EXECUTE,
            Rights::READ | Rights::EXECUTE | Rights::WAIT,
        ] {
            assert_eq!(
                table.filesystem_file_create(file, rights),
                Err(IpcError::InvalidRights)
            );
        }
        assert!(table.is_empty());
    }

    #[test]
    fn random_source_is_read_only_nontransferable_authority() {
        let mut table = HandleTable::new();
        let source = table.random_source_create().unwrap();
        assert_eq!(table.object_type(source), Ok(ObjectType::RandomSource));
        assert_eq!(table.handle_rights(source), Ok(Rights::READ));
        assert_eq!(table.random_source(source), Ok(()));
        assert_eq!(
            table.handle_duplicate(source, Rights::READ),
            Err(IpcError::AccessDenied)
        );
    }

    #[test]
    fn window_capabilities_have_stable_types_protected_roles_and_checked_backing() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
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
    fn injected_graph_allocation_failure_is_atomic() {
        assert!(matches!(
            try_vec_with_capacity::<u8>(usize::MAX),
            Err(IpcError::OutOfMemory)
        ));

        let mut table = HandleTable::new();
        let (send, receive) = table.channel_create().unwrap();
        let (candidate, _) = table.channel_create().unwrap();
        let candidate_rights = table.handle_rights(candidate).unwrap();
        let disposition = [HandleOperationDisposition::move_handle(
            candidate,
            Rights::READ,
        )];
        let mut fail_graph_allocation = || Err(IpcError::OutOfMemory);

        assert_eq!(
            table.channel_write_with_handle_operations_impl(
                send,
                b"oom",
                &disposition,
                &mut fail_graph_allocation,
            ),
            Err(IpcError::OutOfMemory)
        );
        assert_eq!(table.handle_rights(candidate), Ok(candidate_rights));
        assert_eq!(
            table.channel_read(receive, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn mixed_channel_operations_move_duplicate_and_preserve_exact_rights() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
        let mut sender = HandleTable::new();
        let mut receiver = HandleTable::new();
        let (send, receive) = channel_create_between(&mut sender, &mut receiver).unwrap();
        let memory = sender.shared_memory_create(8).unwrap();
        sender.shared_memory_write(memory, 0, b"shared!!").unwrap();
        let lease = sender
            .shared_memory_mapping_lease(memory, SharedMemoryMappingAccess::ReadWrite)
            .unwrap();
        let duplicate_source = sender
            .handle_duplicate(memory, Rights::READ | Rights::DUPLICATE)
            .unwrap();
        let duplicate_source_rights = sender.handle_rights(duplicate_source).unwrap();

        sender
            .channel_write_with_handle_operations(
                send,
                b"mixed",
                &[
                    HandleOperationDisposition::duplicate(duplicate_source, Rights::READ),
                    HandleOperationDisposition::move_handle(memory, Rights::READ | Rights::MAP),
                ],
            )
            .unwrap();
        assert_eq!(sender.object_type(memory), Err(IpcError::InvalidHandle));
        assert_eq!(
            sender.handle_rights(duplicate_source),
            Ok(duplicate_source_rights)
        );
        let lease_bytes =
            unsafe { slice::from_raw_parts(lease.info().base, lease.info().logical_len) };
        assert_eq!(lease_bytes, b"shared!!");

        let mut bytes = [0; 5];
        let mut handles = [Handle::INVALID; 2];
        assert_eq!(
            receiver
                .channel_read(receive, &mut bytes, &mut handles)
                .unwrap(),
            MessageInfo::new(5, 2)
        );
        assert_eq!(&bytes, b"mixed");
        assert_eq!(receiver.handle_rights(handles[0]), Ok(Rights::READ));
        assert_eq!(
            receiver.handle_rights(handles[1]),
            Ok(Rights::READ | Rights::MAP)
        );
        assert_eq!(
            receiver.object_type(handles[0]),
            Ok(ObjectType::SharedMemory)
        );
        assert_eq!(
            receiver.object_type(handles[1]),
            Ok(ObjectType::SharedMemory)
        );
        let received_lease = receiver
            .shared_memory_mapping_lease(handles[1], SharedMemoryMappingAccess::ReadOnly)
            .unwrap();
        assert_eq!(received_lease.info(), lease.info());
    }

    #[test]
    fn mixed_channel_operation_validation_is_atomic() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
        let mut table = HandleTable::new();
        let (send, receive) = table.channel_create().unwrap();
        let move_candidate = table.shared_memory_create(8).unwrap();
        let source = table.shared_memory_create(8).unwrap();
        let no_duplicate = table
            .handle_duplicate(source, Rights::READ | Rights::TRANSFER)
            .unwrap();
        let no_transfer = table
            .handle_duplicate(source, Rights::READ | Rights::DUPLICATE)
            .unwrap();
        let move_rights = table.handle_rights(move_candidate).unwrap();

        assert_eq!(
            table.channel_write_with_handle_operations(
                send,
                b"denied",
                &[
                    HandleOperationDisposition::move_handle(move_candidate, Rights::READ),
                    HandleOperationDisposition::duplicate(no_duplicate, Rights::READ),
                ],
            ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(table.handle_rights(move_candidate), Ok(move_rights));
        assert_eq!(
            table.channel_read(receive, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );

        assert_eq!(
            table.channel_write_with_handle_operations(
                send,
                b"no transfer",
                &[HandleOperationDisposition::move_handle(
                    no_transfer,
                    Rights::READ,
                )],
            ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            table.channel_write_with_handle_operations(
                send,
                b"escalated",
                &[HandleOperationDisposition::duplicate(
                    no_transfer,
                    Rights::READ | Rights::WRITE,
                )],
            ),
            Err(IpcError::InvalidRights)
        );
        assert_eq!(
            table.channel_write_with_handle_operations(
                send,
                b"duplicate source",
                &[
                    HandleOperationDisposition::duplicate(no_transfer, Rights::READ),
                    HandleOperationDisposition::move_handle(no_transfer, Rights::READ),
                ],
            ),
            Err(IpcError::DuplicateHandle)
        );
        assert_eq!(
            table.handle_rights(no_transfer),
            Ok(Rights::READ | Rights::DUPLICATE)
        );
        assert_eq!(
            table.channel_write_with_handle_operations(
                send,
                b"cycle",
                &[HandleOperationDisposition::duplicate(receive, Rights::READ)],
            ),
            Err(IpcError::CyclicTransfer)
        );
        assert_eq!(table.object_type(receive), Ok(ObjectType::Channel));
        assert_eq!(
            table.channel_read(receive, &mut [], &mut []),
            Err(IpcError::ShouldWait)
        );
    }

    #[test]
    fn mixed_channel_operations_are_atomic_for_full_and_closed_queues() {
        let _shared_memory_test = SHARED_MEMORY_TEST_LOCK.lock();
        let mut table = HandleTable::new();
        let (send, receive) = table.channel_create().unwrap();
        let move_source = table.shared_memory_create(8).unwrap();
        let duplicate_base = table.shared_memory_create(8).unwrap();
        let duplicate_source = table
            .handle_duplicate(duplicate_base, Rights::READ | Rights::DUPLICATE)
            .unwrap();
        let move_rights = table.handle_rights(move_source).unwrap();
        let duplicate_rights = table.handle_rights(duplicate_source).unwrap();
        for sequence in 0..CHANNEL_QUEUE_CAPACITY {
            table.channel_write(send, &[sequence as u8], &[]).unwrap();
        }

        let operations = [
            HandleOperationDisposition::move_handle(move_source, Rights::READ),
            HandleOperationDisposition::duplicate(duplicate_source, Rights::READ),
        ];
        assert_eq!(
            table.channel_write_with_handle_operations(send, b"full", &operations),
            Err(IpcError::ShouldWait)
        );
        assert_eq!(table.handle_rights(move_source), Ok(move_rights));
        assert_eq!(table.handle_rights(duplicate_source), Ok(duplicate_rights));
        let mut byte = [0; 1];
        for sequence in 0..CHANNEL_QUEUE_CAPACITY {
            assert_eq!(
                table.channel_read(receive, &mut byte, &mut []).unwrap(),
                MessageInfo::new(1, 0)
            );
            assert_eq!(byte[0], sequence as u8);
        }
        assert_eq!(
            table.channel_read(receive, &mut byte, &mut []),
            Err(IpcError::ShouldWait)
        );

        let (closed_send, closed_receive) = table.channel_create().unwrap();
        table.handle_close(closed_receive).unwrap();
        assert_eq!(
            table.channel_write_with_handle_operations(closed_send, b"closed", &operations),
            Err(IpcError::PeerClosed)
        );
        assert_eq!(table.handle_rights(move_source), Ok(move_rights));
        assert_eq!(table.handle_rights(duplicate_source), Ok(duplicate_rights));
    }

    #[test]
    fn direct_cross_table_move_attenuates_rights_and_invalidates_the_source() {
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();
        let (endpoint, peer) = source.channel_create().unwrap();
        let destination_rights = Rights::READ | Rights::WRITE | Rights::WAIT;

        let moved =
            handle_move_between(&mut source, &mut destination, endpoint, destination_rights)
                .unwrap();
        assert_eq!(source.handle_rights(endpoint), Err(IpcError::InvalidHandle));
        assert_eq!(destination.handle_rights(moved), Ok(destination_rights));
        source.channel_write(peer, b"hello", &[]).unwrap();
        let mut bytes = [0; 5];
        let info = destination
            .channel_read(moved, &mut bytes, &mut [])
            .unwrap();
        assert_eq!(info.byte_count, 5);
        assert_eq!(&bytes, b"hello");

        let (without_transfer, _) = source.channel_create().unwrap();
        let without_transfer = source
            .handle_duplicate(
                without_transfer,
                Rights::READ | Rights::WRITE | Rights::WAIT,
            )
            .unwrap();
        assert_eq!(
            handle_move_between(
                &mut source,
                &mut destination,
                without_transfer,
                Rights::READ,
            ),
            Err(IpcError::AccessDenied)
        );
        assert_eq!(
            source.handle_rights(without_transfer),
            Ok(Rights::READ | Rights::WRITE | Rights::WAIT)
        );
    }

    #[test]
    fn cross_table_batch_mixes_moves_and_duplicates_in_disposition_order() {
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();
        let (process, control) = source.process_create().unwrap();
        let memory = source.shared_memory_create(8).unwrap();
        source.shared_memory_write(memory, 0, b"retained").unwrap();
        let (channel, peer) = source.channel_create().unwrap();
        let process_rights = Rights::WAIT | Rights::INSPECT;
        let memory_rights = Rights::READ;
        let channel_rights = Rights::READ | Rights::WAIT;

        let handles = handle_transfer_batch_between(
            &mut source,
            &mut destination,
            &[
                HandleOperationDisposition::duplicate(process, process_rights),
                HandleOperationDisposition::move_handle(memory, memory_rights),
                HandleOperationDisposition::duplicate(channel, channel_rights),
            ],
        )
        .unwrap();
        assert_eq!(handles.len(), 3);
        assert_eq!(destination.object_type(handles[0]), Ok(ObjectType::Process));
        assert_eq!(
            destination.object_type(handles[1]),
            Ok(ObjectType::SharedMemory)
        );
        assert_eq!(destination.object_type(handles[2]), Ok(ObjectType::Channel));
        assert_eq!(destination.handle_rights(handles[0]), Ok(process_rights));
        assert_eq!(destination.handle_rights(handles[1]), Ok(memory_rights));
        assert_eq!(destination.handle_rights(handles[2]), Ok(channel_rights));

        assert_eq!(source.object_type(process), Ok(ObjectType::Process));
        assert_eq!(source.object_type(memory), Err(IpcError::InvalidHandle));
        assert_eq!(source.object_type(channel), Ok(ObjectType::Channel));
        assert!(control.mark_exited(31));
        assert_eq!(destination.process_info(handles[0]).unwrap().exit_code, 31);
        assert_eq!(
            destination.object_signals(handles[0]),
            Ok(Signals::TERMINATED)
        );

        let mut stored = [0; 8];
        destination
            .shared_memory_read(handles[1], 0, &mut stored)
            .unwrap();
        assert_eq!(&stored, b"retained");
        source.channel_write(peer, b"alias", &[]).unwrap();
        let mut message = [0; 5];
        destination
            .channel_read(handles[2], &mut message, &mut [])
            .unwrap();
        assert_eq!(&message, b"alias");
    }

    #[test]
    fn cross_table_batch_validation_errors_leave_both_tables_unchanged() {
        {
            let mut source = HandleTable::new();
            let mut destination = HandleTable::new();
            let (process, _) = source.process_create().unwrap();
            let sentinel = destination.random_source_create().unwrap();
            let source_len = source.len();
            let destination_len = destination.len();
            assert_eq!(
                handle_transfer_batch_between(
                    &mut source,
                    &mut destination,
                    &[
                        HandleOperationDisposition::move_handle(process, Rights::INSPECT),
                        HandleOperationDisposition::duplicate(
                            Handle::from_raw(u32::MAX),
                            Rights::empty(),
                        ),
                    ],
                ),
                Err(IpcError::InvalidHandle)
            );
            assert_eq!(source.len(), source_len);
            assert_eq!(destination.len(), destination_len);
            assert_eq!(source.handle_rights(process), Ok(PROCESS_DEFAULT_RIGHTS));
            assert_eq!(
                destination.object_type(sentinel),
                Ok(ObjectType::RandomSource)
            );
        }

        {
            let mut source = HandleTable::new();
            let mut destination = HandleTable::new();
            let (process, _) = source.process_create().unwrap();
            let sentinel = destination.random_source_create().unwrap();
            assert_eq!(
                handle_transfer_batch_between(
                    &mut source,
                    &mut destination,
                    &[
                        HandleOperationDisposition::move_handle(process, Rights::INSPECT),
                        HandleOperationDisposition::duplicate(process, Rights::WAIT),
                    ],
                ),
                Err(IpcError::DuplicateHandle)
            );
            assert_eq!(source.handle_rights(process), Ok(PROCESS_DEFAULT_RIGHTS));
            assert_eq!(source.len(), 1);
            assert_eq!(destination.len(), 1);
            assert_eq!(
                destination.object_type(sentinel),
                Ok(ObjectType::RandomSource)
            );
        }

        {
            let mut source = HandleTable::new();
            let mut destination = HandleTable::new();
            let (process, _) = source.process_create().unwrap();
            let sentinel = destination.random_source_create().unwrap();
            assert_eq!(
                handle_transfer_batch_between(
                    &mut source,
                    &mut destination,
                    &[HandleOperationDisposition::duplicate(
                        process,
                        PROCESS_DEFAULT_RIGHTS | Rights::READ,
                    )],
                ),
                Err(IpcError::InvalidRights)
            );
            assert_eq!(source.handle_rights(process), Ok(PROCESS_DEFAULT_RIGHTS));
            assert_eq!(source.len(), 1);
            assert_eq!(destination.len(), 1);
            assert_eq!(
                destination.object_type(sentinel),
                Ok(ObjectType::RandomSource)
            );
        }

        {
            let mut source = HandleTable::new();
            let mut destination = HandleTable::new();
            let (process, _) = source.process_create().unwrap();
            let no_transfer = source
                .handle_duplicate(process, Rights::WAIT | Rights::INSPECT | Rights::DUPLICATE)
                .unwrap();
            let no_duplicate = source
                .handle_duplicate(process, Rights::WAIT | Rights::INSPECT | Rights::TRANSFER)
                .unwrap();
            let sentinel = destination.random_source_create().unwrap();
            assert_eq!(
                handle_transfer_batch_between(
                    &mut source,
                    &mut destination,
                    &[HandleOperationDisposition::move_handle(
                        no_transfer,
                        Rights::INSPECT,
                    )],
                ),
                Err(IpcError::AccessDenied)
            );
            assert_eq!(
                handle_transfer_batch_between(
                    &mut source,
                    &mut destination,
                    &[HandleOperationDisposition::duplicate(
                        no_duplicate,
                        Rights::INSPECT,
                    )],
                ),
                Err(IpcError::AccessDenied)
            );
            assert_eq!(
                source.handle_rights(no_transfer),
                Ok(Rights::WAIT | Rights::INSPECT | Rights::DUPLICATE)
            );
            assert_eq!(
                source.handle_rights(no_duplicate),
                Ok(Rights::WAIT | Rights::INSPECT | Rights::TRANSFER)
            );
            assert_eq!(source.len(), 3);
            assert_eq!(destination.len(), 1);
            assert_eq!(
                destination.object_type(sentinel),
                Ok(ObjectType::RandomSource)
            );
        }
    }

    #[test]
    fn cross_table_batch_destination_exhaustion_rolls_back_every_operation() {
        let mut source = HandleTable::new();
        let mut destination = HandleTable::new();
        let (process, _) = source.process_create().unwrap();
        let memory = source.shared_memory_create(4).unwrap();
        let process_rights = source.handle_rights(process).unwrap();
        let memory_rights = source.handle_rights(memory).unwrap();
        let mut first_destination = Handle::INVALID;
        for index in 0..(HANDLE_TABLE_CAPACITY - 1) {
            let handle = destination.random_source_create().unwrap();
            if index == 0 {
                first_destination = handle;
            }
        }
        assert_eq!(destination.len(), HANDLE_TABLE_CAPACITY - 1);

        assert_eq!(
            handle_transfer_batch_between(
                &mut source,
                &mut destination,
                &[
                    HandleOperationDisposition::move_handle(process, Rights::INSPECT),
                    HandleOperationDisposition::duplicate(memory, Rights::READ),
                ],
            ),
            Err(IpcError::HandleTableFull)
        );
        assert_eq!(source.handle_rights(process), Ok(process_rights));
        assert_eq!(source.handle_rights(memory), Ok(memory_rights));
        assert_eq!(source.len(), 2);
        assert_eq!(destination.len(), HANDLE_TABLE_CAPACITY - 1);
        assert_eq!(
            destination.object_type(first_destination),
            Ok(ObjectType::RandomSource)
        );
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
