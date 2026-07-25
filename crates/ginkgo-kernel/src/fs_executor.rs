//! Fixed-capacity filesystem execution on one stackful fiber.
//!
//! The stackless scheduler owns [`FsJob`] values and generation-tagged [`FsJobId`]s. It never
//! receives a filesystem reference. The pinned fiber is the sole owner of the production
//! [`OwnedFilesystem`] and executes one RedoxFS operation at a time. Runtime storage waits suspend
//! that fiber through `storage`; [`FsExecutor::poll_step`] resumes it at most once.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    marker::PhantomPinned,
    pin::Pin,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU8, Ordering},
};

use ginkgo_filesystem::{
    DirectoryEntry, DirectoryHandle, FileHandle, FileInfo, FilesystemInfo, FsError, NodeMetadata,
    RedoxFs, RenameMode,
};

use crate::{
    async_block::BlockPriority,
    block::Volume,
    fiber::{self, Fiber, FiberFault, FiberOutcome, FixedStack, ResumeError},
    storage::{StorageDiagnostics, StorageDisk, StorageError},
    writeback::{DrainReport, WriteBackDisk, WriteBackMetrics, WriteBackProgress, WriteBackStatus},
};

/// Filesystem type exclusively owned by the executor fiber.
pub type OwnedFilesystem = RedoxFs<WriteBackDisk<Volume<StorageDisk>>>;

pub const FS_JOB_CAPACITY: usize = 32;
pub const FS_RESERVED_KERNEL_JOBS: usize = 4;
pub const FS_NORMAL_JOB_CAPACITY: usize = FS_JOB_CAPACITY - FS_RESERVED_KERNEL_JOBS;
pub const FS_MAX_PATH_BYTES: usize = 4096;
pub const FS_MAX_CHUNK_BYTES: usize = redoxfs::BLOCK_SIZE as usize;
pub const FS_MAX_DIRECTORY_ENTRIES: usize = 256;
pub const FS_MAX_DIRECTORY_RESULT_BYTES: usize = 64 * 1024;
pub const FS_MAX_LOG_APPEND_BYTES: usize = redoxfs::BLOCK_SIZE as usize;
pub const FS_MAX_LOG_FILE_BYTES: u64 = 64 * 1024;
pub const FS_MAX_ELF_BYTES: usize = 32 * 1024 * 1024;
pub const FS_MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
pub const FS_MAX_VM_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
pub const FS_MAX_DRAIN_STEPS: usize = 4096;

const MAILBOX_IDLE: u8 = 0;
const MAILBOX_RUNNING: u8 = 1;
const MAILBOX_COMPLETE: u8 = 2;
const FIBER_FAULT_NO_WORK: usize = 1;
const FIBER_FAULT_YIELD: usize = 2;
const FIBER_FAULT_RESULT_MISSING: usize = 3;

static ACTIVE_WORK: AtomicPtr<FiberWork> = AtomicPtr::new(ptr::null_mut());
static ACTIVE_MAILBOX: AtomicPtr<AtomicU8> = AtomicPtr::new(ptr::null_mut());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsJobId {
    index: u16,
    generation: u32,
}

impl FsJobId {
    pub const fn index(self) -> usize {
        self.index as usize
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// A directory capability or the filesystem root. Root jobs accept either a relative path or an
/// absolute path with one leading slash. Handle-scoped jobs accept only relative paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsDirectory {
    Root,
    Handle(DirectoryHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSnapshotRange {
    pub file: FileHandle,
    pub offset: u64,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WholeFileKind {
    Elf,
    Registry,
    VmSnapshot,
}

impl WholeFileKind {
    pub const fn maximum(self) -> usize {
        match self {
            Self::Elf => FS_MAX_ELF_BYTES,
            Self::Registry => FS_MAX_REGISTRY_BYTES,
            Self::VmSnapshot => FS_MAX_VM_SNAPSHOT_BYTES,
        }
    }
}

/// Fully owned filesystem work. Paths and payload bytes are copied into owned `String`/`Vec`
/// values before enqueue; no variant carries a user pointer.
#[derive(Debug)]
pub enum FsJob {
    RootDirectory,
    OpenFile {
        directory: FsDirectory,
        path: String,
    },
    OpenFileOptions {
        directory: FsDirectory,
        path: String,
        create: bool,
        truncate: bool,
    },
    CreateFile {
        directory: FsDirectory,
        path: String,
    },
    OpenDirectory {
        directory: FsDirectory,
        path: String,
    },
    CreateDirectory {
        directory: FsDirectory,
        path: String,
    },
    ReadChunk {
        file: FileHandle,
        offset: u64,
        length: usize,
    },
    WriteChunk {
        file: FileHandle,
        offset: u64,
        data: Vec<u8>,
    },
    Stat {
        file: FileHandle,
    },
    FileMetadata {
        file: FileHandle,
    },
    DirectoryMetadata {
        directory: DirectoryHandle,
    },
    MetadataAt {
        directory: FsDirectory,
        path: String,
    },
    ListDirectory {
        directory: FsDirectory,
    },
    FilesystemInfo,
    Truncate {
        file: FileHandle,
        length: u64,
    },
    Unlink {
        directory: FsDirectory,
        path: String,
    },
    RemoveDirectory {
        directory: FsDirectory,
        path: String,
    },
    Mkdir {
        directory: FsDirectory,
        path: String,
    },
    Rename {
        source_directory: FsDirectory,
        source_path: String,
        destination_directory: FsDirectory,
        destination_path: String,
        mode: RenameMode,
    },
    Checkpoint,
    CheckpointAndWait {
        max_writeback_steps: usize,
    },
    WaitDurable {
        ticket: u64,
        max_writeback_steps: usize,
    },
    WritebackStep,
    RetryWritebackStep,
    AppendBoundedLog {
        path: String,
        data: Vec<u8>,
        limit: u64,
    },
    ReplaceFile {
        path: String,
        data: Vec<u8>,
    },
    SetupApplicationDataDirectory {
        application_id: String,
    },
    OpenApplicationDataDirectory {
        application_id: String,
    },
    PrepareProgramLaunch {
        executable_path: String,
        application_id: String,
        maximum: usize,
    },
    ReadWholeFile {
        directory: FsDirectory,
        path: String,
        kind: WholeFileKind,
        maximum: usize,
    },
    ReadWholeFileHandle {
        file: FileHandle,
        kind: WholeFileKind,
        maximum: usize,
    },
    ReadFileSnapshot {
        file: FileHandle,
        offset: u64,
        length: usize,
    },
    ReadFileSnapshots {
        ranges: Vec<FileSnapshotRange>,
    },
    Quiesce,
    Resume,
    ShutdownDrain {
        max_writeback_steps: usize,
        shutdown_storage: bool,
    },
    ActivateAsyncStorage {
        destination_apic_id: u8,
    },
    StorageDiagnostics,
    WritebackDiagnostics,
    #[cfg(test)]
    TestYield {
        yields: usize,
        shutdown_priority: bool,
    },
}

impl FsJob {
    fn priority(&self) -> JobPriority {
        match self {
            Self::ShutdownDrain { .. } | Self::Quiesce | Self::CheckpointAndWait { .. } => {
                JobPriority::Shutdown
            }
            Self::Checkpoint
            | Self::WaitDurable { .. }
            | Self::WritebackStep
            | Self::RetryWritebackStep
            | Self::Resume
            | Self::ActivateAsyncStorage { .. }
            | Self::StorageDiagnostics
            | Self::WritebackDiagnostics => JobPriority::Kernel,
            #[cfg(test)]
            Self::TestYield {
                shutdown_priority: true,
                ..
            } => JobPriority::Shutdown,
            _ => JobPriority::Normal,
        }
    }

    fn block_priority(&self) -> BlockPriority {
        match self {
            Self::WritebackStep | Self::RetryWritebackStep => BlockPriority::Background,
            Self::Checkpoint
            | Self::CheckpointAndWait { .. }
            | Self::WaitDurable { .. }
            | Self::Quiesce
            | Self::ShutdownDrain { .. } => BlockPriority::Normal,
            _ => BlockPriority::Latency,
        }
    }

    fn validate(&self) -> Result<(), FsExecutorError> {
        match self {
            Self::OpenFile { path, .. }
            | Self::OpenFileOptions { path, .. }
            | Self::CreateFile { path, .. }
            | Self::OpenDirectory { path, .. }
            | Self::CreateDirectory { path, .. }
            | Self::MetadataAt { path, .. }
            | Self::Unlink { path, .. }
            | Self::RemoveDirectory { path, .. }
            | Self::Mkdir { path, .. } => validate_path(path),
            Self::Rename {
                source_path,
                destination_path,
                ..
            } => {
                validate_path(source_path)?;
                validate_path(destination_path)
            }
            Self::ReadChunk { length, .. } if *length > FS_MAX_CHUNK_BYTES => {
                Err(FsExecutorError::PayloadTooLarge)
            }
            Self::WriteChunk { data, .. } if data.len() > FS_MAX_CHUNK_BYTES => {
                Err(FsExecutorError::PayloadTooLarge)
            }
            Self::CheckpointAndWait {
                max_writeback_steps,
            }
            | Self::WaitDurable {
                max_writeback_steps,
                ..
            }
            | Self::ShutdownDrain {
                max_writeback_steps,
                ..
            } if *max_writeback_steps > FS_MAX_DRAIN_STEPS => Err(FsExecutorError::PayloadTooLarge),
            Self::AppendBoundedLog { path, data, limit } => {
                validate_path(path)?;
                if data.len() > FS_MAX_LOG_APPEND_BYTES || *limit > FS_MAX_LOG_FILE_BYTES {
                    return Err(FsExecutorError::PayloadTooLarge);
                }
                Ok(())
            }
            Self::ReplaceFile { path, data } => {
                validate_path(path)?;
                if data.len() > FS_MAX_LOG_APPEND_BYTES {
                    return Err(FsExecutorError::PayloadTooLarge);
                }
                Ok(())
            }
            Self::SetupApplicationDataDirectory { application_id }
            | Self::OpenApplicationDataDirectory { application_id } => {
                validate_path(application_id)
            }
            Self::PrepareProgramLaunch {
                executable_path,
                application_id,
                maximum,
            } => {
                validate_path(executable_path)?;
                validate_path(application_id)?;
                if *maximum > WholeFileKind::Elf.maximum() {
                    return Err(FsExecutorError::PayloadTooLarge);
                }
                Ok(())
            }
            Self::ReadWholeFile {
                path,
                kind,
                maximum,
                ..
            } => {
                validate_path(path)?;
                if *maximum > kind.maximum() {
                    return Err(FsExecutorError::PayloadTooLarge);
                }
                Ok(())
            }
            Self::ReadWholeFileHandle { kind, maximum, .. } => {
                if *maximum > kind.maximum() {
                    Err(FsExecutorError::PayloadTooLarge)
                } else {
                    Ok(())
                }
            }
            Self::ReadFileSnapshot { length, .. } if *length > FS_MAX_VM_SNAPSHOT_BYTES => {
                Err(FsExecutorError::PayloadTooLarge)
            }
            Self::ReadFileSnapshots { ranges } => {
                let total = ranges.iter().try_fold(0usize, |total, range| {
                    total
                        .checked_add(range.length)
                        .ok_or(FsExecutorError::PayloadTooLarge)
                })?;
                if total > FS_MAX_VM_SNAPSHOT_BYTES {
                    Err(FsExecutorError::PayloadTooLarge)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum FsResult {
    Unit,
    File(FileHandle),
    OpenedFile {
        file: FileHandle,
        created: bool,
        directory: FsDirectory,
        path: String,
    },
    Directory(DirectoryHandle),
    Bytes(Vec<u8>),
    FileSnapshot {
        bytes: Vec<u8>,
        file_length: u64,
    },
    FileSnapshots(Vec<(FileSnapshotRange, Vec<u8>)>),
    ProgramLaunch {
        image: Vec<u8>,
        application_data: DirectoryHandle,
    },
    Count(usize),
    FileInfo(FileInfo),
    Metadata(NodeMetadata),
    DirectoryEntries(Vec<DirectoryEntry>),
    FilesystemInfo(FilesystemInfo),
    Durability(DurabilityResult),
    Writeback(WriteBackProgress),
    Drain(DrainReport),
    StorageDiagnostics(StorageDiagnostics),
    WritebackDiagnostics {
        status: WriteBackStatus,
        metrics: WriteBackMetrics,
    },
    AsyncStorageActivated {
        writeback_newly_enabled: bool,
    },
}

impl FsResult {
    fn payload_size(&self) -> usize {
        match self {
            Self::Bytes(bytes) | Self::FileSnapshot { bytes, .. } => bytes.len(),
            Self::FileSnapshots(snapshots) => snapshots.iter().map(|(_, bytes)| bytes.len()).sum(),
            Self::ProgramLaunch { image, .. } => image.len(),
            Self::DirectoryEntries(entries) => entries
                .iter()
                .map(|entry| entry.name.len() + core::mem::size_of::<DirectoryEntry>())
                .sum(),
            _ => core::mem::size_of_val(self),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurabilityResult {
    pub ticket: u64,
    pub durable_sequence: u64,
    pub steps: usize,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsExecutorError {
    Filesystem(FsError),
    Storage(StorageError),
    Writeback(i32),
    QueueFull,
    ReservedCapacity,
    PayloadTooLarge,
    ResultTooLarge,
    AllocationFailed,
    Canceled,
    ExecutorStarted,
    UnknownJob,
    NotComplete,
    Fiber(ResumeError),
    FiberFault(FiberFault),
    Internal,
}

impl From<FsError> for FsExecutorError {
    fn from(error: FsError) -> Self {
        Self::Filesystem(error)
    }
}

impl From<StorageError> for FsExecutorError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Debug)]
pub struct EnqueueError {
    pub error: FsExecutorError,
    pub job: FsJob,
}

#[derive(Debug)]
pub struct FsCompletion {
    pub id: FsJobId,
    pub result: Result<FsResult, FsExecutorError>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsExecutorDiagnostics {
    pub queued: usize,
    pub active: usize,
    pub high_water: usize,
    pub completed: u64,
    pub errors: u64,
    pub cancel_draining: usize,
    pub fiber_yields: u64,
    pub max_result_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollStep {
    Idle,
    Yielded(FsJobId),
    Completed(FsJobId),
    Faulted(FsJobId, FsExecutorError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobPriority {
    Normal,
    Kernel,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Queued,
    Active,
    Complete,
}

struct JobSlot {
    generation: u32,
    state: SlotState,
    priority: JobPriority,
    canceled: bool,
    job: Option<FsJob>,
    completion: Option<Result<FsResult, FsExecutorError>>,
}

impl JobSlot {
    const fn empty() -> Self {
        Self {
            generation: 1,
            state: SlotState::Free,
            priority: JobPriority::Normal,
            canceled: false,
            job: None,
            completion: None,
        }
    }
}

struct ReadyQueue {
    entries: [Option<FsJobId>; FS_JOB_CAPACITY],
    head: usize,
    len: usize,
}

impl ReadyQueue {
    const fn new() -> Self {
        Self {
            entries: [None; FS_JOB_CAPACITY],
            head: 0,
            len: 0,
        }
    }

    fn push(&mut self, id: FsJobId) -> Result<(), FsExecutorError> {
        if self.len == FS_JOB_CAPACITY {
            return Err(FsExecutorError::QueueFull);
        }
        let tail = (self.head + self.len) % FS_JOB_CAPACITY;
        self.entries[tail] = Some(id);
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<FsJobId> {
        if self.len == 0 {
            return None;
        }
        let id = self.entries[self.head].take();
        self.head = (self.head + 1) % FS_JOB_CAPACITY;
        self.len -= 1;
        id
    }

    fn remove(&mut self, id: FsJobId) -> bool {
        let Some(offset) = (0..self.len)
            .find(|offset| self.entries[(self.head + offset) % FS_JOB_CAPACITY] == Some(id))
        else {
            return false;
        };
        for index in offset..self.len - 1 {
            let from = (self.head + index + 1) % FS_JOB_CAPACITY;
            let to = (self.head + index) % FS_JOB_CAPACITY;
            self.entries[to] = self.entries[from];
        }
        let tail = (self.head + self.len - 1) % FS_JOB_CAPACITY;
        self.entries[tail] = None;
        self.len -= 1;
        true
    }
}

struct SchedulerState {
    slots: [JobSlot; FS_JOB_CAPACITY],
    normal_ready: ReadyQueue,
    kernel_ready: ReadyQueue,
    shutdown_ready: ReadyQueue,
    active: Option<FsJobId>,
    normal_in_use: usize,
    diagnostics: FsExecutorDiagnostics,
}

impl SchedulerState {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| JobSlot::empty()),
            normal_ready: ReadyQueue::new(),
            kernel_ready: ReadyQueue::new(),
            shutdown_ready: ReadyQueue::new(),
            active: None,
            normal_in_use: 0,
            diagnostics: FsExecutorDiagnostics::default(),
        }
    }

    fn enqueue(&mut self, job: FsJob) -> Result<FsJobId, EnqueueError> {
        if let Err(error) = job.validate() {
            return Err(EnqueueError { error, job });
        }
        let priority = job.priority();
        if priority == JobPriority::Normal && self.normal_in_use == FS_NORMAL_JOB_CAPACITY {
            return Err(EnqueueError {
                error: FsExecutorError::ReservedCapacity,
                job,
            });
        }
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.state == SlotState::Free)
        else {
            return Err(EnqueueError {
                error: FsExecutorError::QueueFull,
                job,
            });
        };
        let id = FsJobId {
            index: index as u16,
            generation: self.slots[index].generation,
        };
        let queue = match priority {
            JobPriority::Normal => &mut self.normal_ready,
            JobPriority::Kernel => &mut self.kernel_ready,
            JobPriority::Shutdown => &mut self.shutdown_ready,
        };
        if let Err(error) = queue.push(id) {
            return Err(EnqueueError { error, job });
        }
        let slot = &mut self.slots[index];
        slot.state = SlotState::Queued;
        slot.priority = priority;
        slot.canceled = false;
        slot.job = Some(job);
        slot.completion = None;
        if priority == JobPriority::Normal {
            self.normal_in_use += 1;
        }
        self.diagnostics.queued += 1;
        self.diagnostics.high_water = self
            .diagnostics
            .high_water
            .max(self.diagnostics.queued + self.diagnostics.active);
        Ok(id)
    }

    fn next(&mut self) -> Option<(FsJobId, FsJob)> {
        let id = self
            .shutdown_ready
            .pop()
            .or_else(|| self.kernel_ready.pop())
            .or_else(|| self.normal_ready.pop())?;
        let slot = &mut self.slots[id.index()];
        if slot.generation != id.generation || slot.state != SlotState::Queued {
            return self.next();
        }
        let job = slot.job.take()?;
        slot.state = SlotState::Active;
        self.active = Some(id);
        self.diagnostics.queued -= 1;
        self.diagnostics.active = 1;
        Some((id, job))
    }

    fn finish(&mut self, id: FsJobId, mut result: Result<FsResult, FsExecutorError>) {
        let slot = &mut self.slots[id.index()];
        debug_assert_eq!(slot.generation, id.generation);
        debug_assert_eq!(slot.state, SlotState::Active);
        if slot.canceled {
            result = Err(FsExecutorError::Canceled);
            self.diagnostics.cancel_draining = self.diagnostics.cancel_draining.saturating_sub(1);
        }
        if result.is_err() {
            self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
        }
        if let Ok(value) = &result {
            self.diagnostics.max_result_size =
                self.diagnostics.max_result_size.max(value.payload_size());
        }
        slot.completion = Some(result);
        slot.state = SlotState::Complete;
        self.active = None;
        self.diagnostics.active = 0;
        self.diagnostics.completed = self.diagnostics.completed.saturating_add(1);
    }

    fn cancel(&mut self, id: FsJobId) -> Result<(), FsExecutorError> {
        let slot = self.slot_mut(id)?;
        match slot.state {
            SlotState::Queued => {
                let priority = slot.priority;
                let removed = match priority {
                    JobPriority::Normal => self.normal_ready.remove(id),
                    JobPriority::Kernel => self.kernel_ready.remove(id),
                    JobPriority::Shutdown => self.shutdown_ready.remove(id),
                };
                if !removed {
                    return Err(FsExecutorError::Internal);
                }
                let slot = &mut self.slots[id.index()];
                slot.job = None;
                slot.completion = Some(Err(FsExecutorError::Canceled));
                slot.state = SlotState::Complete;
                self.diagnostics.queued -= 1;
                self.diagnostics.completed = self.diagnostics.completed.saturating_add(1);
                self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
                Ok(())
            }
            SlotState::Active => {
                if !slot.canceled {
                    slot.canceled = true;
                    self.diagnostics.cancel_draining += 1;
                }
                Ok(())
            }
            SlotState::Complete => Err(FsExecutorError::NotComplete),
            SlotState::Free => Err(FsExecutorError::UnknownJob),
        }
    }

    fn take_completion(&mut self, id: FsJobId) -> Result<FsCompletion, FsExecutorError> {
        let slot = self.slot_mut(id)?;
        if slot.state != SlotState::Complete {
            return Err(FsExecutorError::NotComplete);
        }
        let result = slot.completion.take().ok_or(FsExecutorError::Internal)?;
        let priority = slot.priority;
        slot.state = SlotState::Free;
        slot.canceled = false;
        slot.generation = next_generation(slot.generation);
        if priority == JobPriority::Normal {
            self.normal_in_use = self.normal_in_use.saturating_sub(1);
        }
        Ok(FsCompletion { id, result })
    }

    fn slot_mut(&mut self, id: FsJobId) -> Result<&mut JobSlot, FsExecutorError> {
        let slot = self
            .slots
            .get_mut(id.index())
            .ok_or(FsExecutorError::UnknownJob)?;
        if slot.generation != id.generation || slot.state == SlotState::Free {
            return Err(FsExecutorError::UnknownJob);
        }
        Ok(slot)
    }
}

struct FiberWork {
    filesystem: Option<OwnedFilesystem>,
    job: Option<FsJob>,
    result: Option<Result<FsResult, FsExecutorError>>,
}

impl FiberWork {
    fn new(filesystem: OwnedFilesystem) -> Self {
        Self {
            filesystem: Some(filesystem),
            job: None,
            result: None,
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self {
            filesystem: None,
            job: None,
            result: None,
        }
    }

    fn run(&mut self) {
        let result = match self.job.take() {
            Some(job) => {
                let priority = job.block_priority();
                if let Some(filesystem) = self.filesystem.as_mut() {
                    storage_disk_mut(filesystem).set_request_priority(priority);
                    let result = execute_job(Some(filesystem), job);
                    storage_disk_mut(filesystem).set_request_priority(BlockPriority::Latency);
                    result
                } else {
                    execute_job(None, job)
                }
            }
            None => Err(FsExecutorError::Internal),
        };
        self.result = Some(result);
    }
}

/// Fixed-capacity executor. Pin this value before enqueueing or polling it. The supplied stack must
/// remain pinned for the executor's lifetime.
pub struct FsExecutor<'stack, const STACK_SIZE: usize> {
    scheduler: SchedulerState,
    work: FiberWork,
    mailbox: AtomicU8,
    fiber: Fiber<'stack, STACK_SIZE>,
    started: bool,
    _pinned: PhantomPinned,
}

impl<'stack, const STACK_SIZE: usize> FsExecutor<'stack, STACK_SIZE> {
    pub fn new(
        filesystem: OwnedFilesystem,
        stack: Pin<&'stack mut FixedStack<STACK_SIZE>>,
    ) -> Self {
        Self {
            scheduler: SchedulerState::new(),
            work: FiberWork::new(filesystem),
            mailbox: AtomicU8::new(MAILBOX_IDLE),
            fiber: Fiber::new(stack, filesystem_fiber_entry),
            started: false,
            _pinned: PhantomPinned,
        }
    }

    #[cfg(test)]
    fn new_test(stack: Pin<&'stack mut FixedStack<STACK_SIZE>>) -> Self {
        Self {
            scheduler: SchedulerState::new(),
            work: FiberWork::test(),
            mailbox: AtomicU8::new(MAILBOX_IDLE),
            fiber: Fiber::new(stack, filesystem_fiber_entry),
            started: false,
            _pinned: PhantomPinned,
        }
    }

    /// Enables runtime storage before the fiber starts. After the first `poll_step`, use the
    /// `ActivateAsyncStorage` control job instead.
    pub fn activate_async_before_start(
        &mut self,
        destination_apic_id: u8,
    ) -> Result<bool, FsExecutorError> {
        if self.started {
            return Err(FsExecutorError::ExecutorStarted);
        }
        activate_async(
            self.work
                .filesystem
                .as_mut()
                .ok_or(FsExecutorError::Internal)?,
            destination_apic_id,
        )
    }

    pub fn storage_diagnostics_before_start(&self) -> Result<StorageDiagnostics, FsExecutorError> {
        if self.started {
            return Err(FsExecutorError::ExecutorStarted);
        }
        let filesystem = self
            .work
            .filesystem
            .as_ref()
            .ok_or(FsExecutorError::Internal)?;
        Ok(storage_disk(filesystem).diagnostics())
    }

    pub fn writeback_diagnostics_before_start(
        &self,
    ) -> Result<(WriteBackStatus, WriteBackMetrics), FsExecutorError> {
        if self.started {
            return Err(FsExecutorError::ExecutorStarted);
        }
        let disk = self
            .work
            .filesystem
            .as_ref()
            .ok_or(FsExecutorError::Internal)?
            .disk();
        Ok((disk.status(), disk.metrics()))
    }

    pub fn enqueue(self: Pin<&mut Self>, job: FsJob) -> Result<FsJobId, EnqueueError> {
        unsafe { self.get_unchecked_mut() }.scheduler.enqueue(job)
    }

    pub fn cancel(self: Pin<&mut Self>, id: FsJobId) -> Result<(), FsExecutorError> {
        unsafe { self.get_unchecked_mut() }.scheduler.cancel(id)
    }

    pub fn take_completion(
        self: Pin<&mut Self>,
        id: FsJobId,
    ) -> Result<FsCompletion, FsExecutorError> {
        unsafe { self.get_unchecked_mut() }
            .scheduler
            .take_completion(id)
    }

    pub fn diagnostics(&self) -> FsExecutorDiagnostics {
        self.scheduler.diagnostics
    }

    /// Starts or advances at most one job and resumes the filesystem fiber at most once.
    pub fn poll_step(self: Pin<&mut Self>) -> PollStep {
        let this = unsafe { self.get_unchecked_mut() };
        this.started = true;

        if this.scheduler.active.is_none() {
            let Some((id, job)) = this.scheduler.next() else {
                return PollStep::Idle;
            };
            debug_assert!(this.work.job.is_none());
            debug_assert!(this.work.result.is_none());
            this.work.job = Some(job);
            this.mailbox.store(MAILBOX_RUNNING, Ordering::Release);
            this.scheduler.active = Some(id);
        }

        let id = this.scheduler.active.expect("active job disappeared");
        ACTIVE_WORK.store(ptr::from_mut(&mut this.work), Ordering::Release);
        ACTIVE_MAILBOX.store(ptr::from_ref(&this.mailbox).cast_mut(), Ordering::Release);
        let outcome = unsafe { Pin::new_unchecked(&mut this.fiber) }.resume();
        match outcome {
            Ok(FiberOutcome::Yielded) => {
                this.scheduler.diagnostics.fiber_yields =
                    this.scheduler.diagnostics.fiber_yields.saturating_add(1);
                if this.mailbox.load(Ordering::Acquire) == MAILBOX_COMPLETE {
                    let result = this
                        .work
                        .result
                        .take()
                        .unwrap_or(Err(FsExecutorError::Internal));
                    this.mailbox.store(MAILBOX_IDLE, Ordering::Release);
                    this.scheduler.finish(id, result);
                    PollStep::Completed(id)
                } else {
                    PollStep::Yielded(id)
                }
            }
            Ok(FiberOutcome::Complete) => {
                let error = FsExecutorError::FiberFault(FiberFault::new(FIBER_FAULT_NO_WORK));
                this.scheduler.finish(id, Err(error));
                PollStep::Faulted(id, error)
            }
            Ok(FiberOutcome::Faulted(fault)) => {
                let error = FsExecutorError::FiberFault(fault);
                this.scheduler.finish(id, Err(error));
                PollStep::Faulted(id, error)
            }
            Err(error) => {
                let error = FsExecutorError::Fiber(error);
                this.scheduler.finish(id, Err(error));
                PollStep::Faulted(id, error)
            }
        }
    }
}

fn filesystem_fiber_entry(_: &mut fiber::FiberContext) -> fiber::FiberResult {
    loop {
        let work = ACTIVE_WORK.load(Ordering::Acquire);
        let mailbox = ACTIVE_MAILBOX.load(Ordering::Acquire);
        if work.is_null() || mailbox.is_null() {
            return Err(FiberFault::new(FIBER_FAULT_NO_WORK));
        }
        if unsafe { (*mailbox).load(Ordering::Acquire) } != MAILBOX_RUNNING {
            return Err(FiberFault::new(FIBER_FAULT_NO_WORK));
        }
        unsafe { (*work).run() };
        if unsafe { (*work).result.is_none() } {
            return Err(FiberFault::new(FIBER_FAULT_RESULT_MISSING));
        }
        unsafe { (*mailbox).store(MAILBOX_COMPLETE, Ordering::Release) };
        fiber::yield_now().map_err(|_| FiberFault::new(FIBER_FAULT_YIELD))?;
    }
}

fn execute_job(
    filesystem: Option<&mut OwnedFilesystem>,
    job: FsJob,
) -> Result<FsResult, FsExecutorError> {
    #[cfg(test)]
    if let FsJob::TestYield { yields, .. } = job {
        let mut progress = 0;
        while progress < yields {
            progress += 1;
            fiber::yield_now().map_err(map_yield_error)?;
        }
        return Ok(FsResult::Count(progress));
    }

    let filesystem = filesystem.ok_or(FsExecutorError::Internal)?;
    match job {
        FsJob::RootDirectory => filesystem
            .root_directory()
            .map(FsResult::Directory)
            .map_err(Into::into),
        FsJob::OpenFile { directory, path } => {
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            filesystem
                .open_file_at(directory, path)
                .map(FsResult::File)
                .map_err(Into::into)
        }
        FsJob::OpenFileOptions {
            directory,
            path,
            create,
            truncate,
        } => {
            let (anchor, relative_path) = directory_and_path(filesystem, directory, &path)?;
            let (file, created) = match filesystem.open_file_at(anchor, relative_path) {
                Ok(file) => (file, false),
                Err(FsError::NotFound) if create => {
                    (filesystem.create_file_at(anchor, relative_path)?, true)
                }
                Err(error) => return Err(error.into()),
            };
            if truncate {
                if let Err(error) = filesystem.truncate(file, 0) {
                    if created {
                        let _ = remove_file_path(filesystem, anchor, relative_path);
                    }
                    return Err(error.into());
                }
            }
            Ok(FsResult::OpenedFile {
                file,
                created,
                directory,
                path,
            })
        }
        FsJob::CreateFile { directory, path } => {
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            filesystem
                .create_file_at(directory, path)
                .map(FsResult::File)
                .map_err(Into::into)
        }
        FsJob::OpenDirectory { directory, path } => {
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            filesystem
                .open_directory_at(directory, path)
                .map(FsResult::Directory)
                .map_err(Into::into)
        }
        FsJob::CreateDirectory { directory, path } | FsJob::Mkdir { directory, path } => {
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            filesystem
                .create_directory_at(directory, path)
                .map(FsResult::Directory)
                .map_err(Into::into)
        }
        FsJob::ReadChunk {
            file,
            offset,
            length,
        } => {
            let mut bytes = try_zeroed(length)?;
            let count = filesystem.read(file, offset, &mut bytes)?;
            bytes.truncate(count);
            Ok(FsResult::Bytes(bytes))
        }
        FsJob::WriteChunk { file, offset, data } => filesystem
            .write(file, offset, &data)
            .map(FsResult::Count)
            .map_err(Into::into),
        FsJob::Stat { file } => filesystem
            .stat(file)
            .map(FsResult::FileInfo)
            .map_err(Into::into),
        FsJob::FileMetadata { file } => filesystem
            .file_metadata(file)
            .map(FsResult::Metadata)
            .map_err(Into::into),
        FsJob::DirectoryMetadata { directory } => filesystem
            .directory_metadata(directory)
            .map(FsResult::Metadata)
            .map_err(Into::into),
        FsJob::MetadataAt { directory, path } => {
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            match filesystem.open_file_at(directory, path) {
                Ok(file) => filesystem
                    .file_metadata(file)
                    .map(FsResult::Metadata)
                    .map_err(Into::into),
                Err(FsError::IsDirectory) => {
                    let directory = filesystem.open_directory_at(directory, path)?;
                    filesystem
                        .directory_metadata(directory)
                        .map(FsResult::Metadata)
                        .map_err(Into::into)
                }
                Err(error) => Err(error.into()),
            }
        }
        FsJob::ListDirectory { directory } => {
            let directory = directory_handle(filesystem, directory)?;
            let entries = filesystem.list_directory(directory)?;
            let result_bytes = entries.iter().try_fold(0_usize, |total, entry| {
                total
                    .checked_add(entry.name.len() + core::mem::size_of::<DirectoryEntry>())
                    .ok_or(FsExecutorError::ResultTooLarge)
            })?;
            if entries.len() > FS_MAX_DIRECTORY_ENTRIES
                || result_bytes > FS_MAX_DIRECTORY_RESULT_BYTES
            {
                return Err(FsExecutorError::ResultTooLarge);
            }
            Ok(FsResult::DirectoryEntries(entries))
        }
        FsJob::FilesystemInfo => filesystem
            .filesystem_info()
            .map(FsResult::FilesystemInfo)
            .map_err(Into::into),
        FsJob::Truncate { file, length } => filesystem
            .truncate(file, length)
            .map(|()| FsResult::Unit)
            .map_err(Into::into),
        FsJob::Unlink { directory, path } => {
            let (parent, name) = parent_and_name(filesystem, directory, &path)?;
            filesystem.remove_file_at(parent, name)?;
            Ok(FsResult::Unit)
        }
        FsJob::RemoveDirectory { directory, path } => {
            let (parent, name) = parent_and_name(filesystem, directory, &path)?;
            filesystem.remove_directory_at(parent, name)?;
            Ok(FsResult::Unit)
        }
        FsJob::Rename {
            source_directory,
            source_path,
            destination_directory,
            destination_path,
            mode,
        } => {
            let (source_directory, source_path) =
                directory_and_path(filesystem, source_directory, &source_path)?;
            let (destination_directory, destination_path) =
                directory_and_path(filesystem, destination_directory, &destination_path)?;
            filesystem.rename_at(
                source_directory,
                source_path,
                destination_directory,
                destination_path,
                mode,
            )?;
            Ok(FsResult::Unit)
        }
        FsJob::Checkpoint => filesystem
            .sync_ticket()
            .map(|ticket| {
                FsResult::Durability(DurabilityResult {
                    ticket,
                    durable_sequence: filesystem.durable_flush_sequence(),
                    steps: 0,
                    complete: filesystem.is_ticket_durable(ticket),
                })
            })
            .map_err(Into::into),
        FsJob::CheckpointAndWait {
            max_writeback_steps,
        } => {
            let ticket = filesystem.sync_ticket()?;
            wait_durable(filesystem, ticket, max_writeback_steps).map(FsResult::Durability)
        }
        FsJob::WaitDurable {
            ticket,
            max_writeback_steps,
        } => wait_durable(filesystem, ticket, max_writeback_steps).map(FsResult::Durability),
        FsJob::WritebackStep => filesystem
            .disk_mut()
            .writeback_step()
            .map(FsResult::Writeback)
            .map_err(map_writeback_error),
        FsJob::RetryWritebackStep => filesystem
            .disk_mut()
            .retry_writeback_step()
            .map(FsResult::Writeback)
            .map_err(map_writeback_error),
        FsJob::AppendBoundedLog { path, data, limit } => {
            let root = filesystem.root_directory()?;
            let path = root_path(&path)?;
            let file = match filesystem.open_file_at(root, path) {
                Ok(file) => file,
                Err(FsError::NotFound) => filesystem.create_file_at(root, path)?,
                Err(error) => return Err(error.into()),
            };
            let length = filesystem.stat(file)?.len;
            let incoming =
                u64::try_from(data.len()).map_err(|_| FsExecutorError::PayloadTooLarge)?;
            let reset =
                length >= limit || length.checked_add(incoming).is_none_or(|end| end > limit);
            if reset {
                filesystem.truncate(file, 0)?;
            }
            let offset = if reset { 0 } else { length };
            let count = filesystem.write(file, offset, &data)?;
            Ok(FsResult::Count(count))
        }
        FsJob::ReplaceFile { path, data } => {
            let root = filesystem.root_directory()?;
            let path = root_path(&path)?;
            let file = match filesystem.open_file_at(root, path) {
                Ok(file) => file,
                Err(FsError::NotFound) => filesystem.create_file_at(root, path)?,
                Err(error) => return Err(error.into()),
            };
            filesystem.truncate(file, 0)?;
            let count = filesystem.write(file, 0, &data)?;
            Ok(FsResult::Count(count))
        }
        FsJob::SetupApplicationDataDirectory { application_id } => {
            let root = filesystem.root_directory()?;
            let appdata = match filesystem.open_directory_at(root, "appdata") {
                Ok(directory) => directory,
                Err(FsError::NotFound) => filesystem.create_directory_at(root, "appdata")?,
                Err(error) => return Err(error.into()),
            };
            let directory = match filesystem.open_directory_at(appdata, &application_id) {
                Ok(directory) => directory,
                Err(FsError::NotFound) => {
                    filesystem.create_directory_at(appdata, &application_id)?
                }
                Err(error) => return Err(error.into()),
            };
            Ok(FsResult::Directory(directory))
        }
        FsJob::PrepareProgramLaunch {
            executable_path,
            application_id,
            maximum,
        } => {
            let root = filesystem.root_directory()?;
            let executable_path = root_path(&executable_path)?;
            let file = filesystem.open_file_at(root, executable_path)?;
            let image = read_whole_file(filesystem, file, maximum)?;
            let appdata = match filesystem.open_directory_at(root, "appdata") {
                Ok(directory) => directory,
                Err(FsError::NotFound) => filesystem.create_directory_at(root, "appdata")?,
                Err(error) => return Err(error.into()),
            };
            let application_data = match filesystem.open_directory_at(appdata, &application_id) {
                Ok(directory) => directory,
                Err(FsError::NotFound) => {
                    filesystem.create_directory_at(appdata, &application_id)?
                }
                Err(error) => return Err(error.into()),
            };
            Ok(FsResult::ProgramLaunch {
                image,
                application_data,
            })
        }
        FsJob::ReadWholeFileHandle {
            file,
            kind: _,
            maximum,
        } => read_whole_file(filesystem, file, maximum).map(FsResult::Bytes),
        FsJob::OpenApplicationDataDirectory { application_id } => {
            let root = filesystem.root_directory()?;
            let appdata = filesystem.open_directory_at(root, "appdata")?;
            filesystem
                .open_directory_at(appdata, &application_id)
                .map(FsResult::Directory)
                .map_err(Into::into)
        }
        FsJob::ReadWholeFile {
            directory,
            path,
            kind,
            maximum,
        } => {
            if maximum > kind.maximum() {
                return Err(FsExecutorError::PayloadTooLarge);
            }
            let (directory, path) = directory_and_path(filesystem, directory, &path)?;
            let file = filesystem.open_file_at(directory, path)?;
            read_whole_file(filesystem, file, maximum).map(FsResult::Bytes)
        }
        FsJob::ReadFileSnapshot {
            file,
            offset,
            length,
        } => {
            let file_length = filesystem.stat(file)?.len;
            let end = offset
                .checked_add(length as u64)
                .ok_or(FsExecutorError::ResultTooLarge)?;
            if end > file_length {
                return Err(FsExecutorError::ResultTooLarge);
            }
            let mut bytes = try_zeroed(length)?;
            if filesystem.read(file, offset, &mut bytes)? != length {
                return Err(FsExecutorError::Filesystem(FsError::Io));
            }
            Ok(FsResult::FileSnapshot { bytes, file_length })
        }
        FsJob::ReadFileSnapshots { ranges } => {
            let mut snapshots = Vec::new();
            snapshots
                .try_reserve_exact(ranges.len())
                .map_err(|_| FsExecutorError::AllocationFailed)?;
            for range in ranges {
                let mut bytes = try_zeroed(range.length)?;
                if filesystem.read(range.file, range.offset, &mut bytes)? != range.length {
                    return Err(FsExecutorError::Filesystem(FsError::Io));
                }
                snapshots.push((range, bytes));
            }
            Ok(FsResult::FileSnapshots(snapshots))
        }
        FsJob::Quiesce => filesystem
            .disk_mut()
            .quiesce()
            .map(|ticket| {
                FsResult::Durability(DurabilityResult {
                    ticket,
                    durable_sequence: filesystem.durable_flush_sequence(),
                    steps: 0,
                    complete: filesystem.is_ticket_durable(ticket),
                })
            })
            .map_err(map_writeback_error),
        FsJob::Resume => filesystem
            .disk_mut()
            .resume_after_quiesce()
            .map(|()| FsResult::Unit)
            .map_err(map_writeback_error),
        FsJob::ShutdownDrain {
            max_writeback_steps,
            shutdown_storage,
        } => {
            let report = filesystem
                .disk_mut()
                .shutdown_drain(max_writeback_steps)
                .map_err(map_writeback_error)?;
            if report.complete && shutdown_storage {
                storage_disk_mut(filesystem).shutdown()?;
            }
            Ok(FsResult::Drain(report))
        }
        FsJob::ActivateAsyncStorage {
            destination_apic_id,
        } => activate_async(filesystem, destination_apic_id).map(|writeback_newly_enabled| {
            FsResult::AsyncStorageActivated {
                writeback_newly_enabled,
            }
        }),
        FsJob::StorageDiagnostics => Ok(FsResult::StorageDiagnostics(
            storage_disk(filesystem).diagnostics(),
        )),
        FsJob::WritebackDiagnostics => Ok(FsResult::WritebackDiagnostics {
            status: filesystem.disk().status(),
            metrics: filesystem.disk().metrics(),
        }),
        #[cfg(test)]
        FsJob::TestYield { .. } => unreachable!(),
    }
}

fn validate_path(path: &str) -> Result<(), FsExecutorError> {
    if path.is_empty() || path.len() > FS_MAX_PATH_BYTES {
        return Err(FsExecutorError::PayloadTooLarge);
    }
    Ok(())
}

fn root_path(path: &str) -> Result<&str, FsExecutorError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return Err(FsExecutorError::Filesystem(FsError::InvalidName));
    }
    Ok(path)
}

fn directory_handle(
    filesystem: &mut OwnedFilesystem,
    directory: FsDirectory,
) -> Result<DirectoryHandle, FsExecutorError> {
    match directory {
        FsDirectory::Root => filesystem.root_directory().map_err(Into::into),
        FsDirectory::Handle(directory) => Ok(directory),
    }
}

fn directory_and_path<'a>(
    filesystem: &mut OwnedFilesystem,
    directory: FsDirectory,
    path: &'a str,
) -> Result<(DirectoryHandle, &'a str), FsExecutorError> {
    let directory_handle = directory_handle(filesystem, directory)?;
    let path = match directory {
        FsDirectory::Root => root_path(path)?,
        FsDirectory::Handle(_) => path,
    };
    Ok((directory_handle, path))
}

fn parent_and_name<'a>(
    filesystem: &mut OwnedFilesystem,
    directory: FsDirectory,
    path: &'a str,
) -> Result<(DirectoryHandle, &'a str), FsExecutorError> {
    let (directory, path) = directory_and_path(filesystem, directory, path)?;
    match path.rsplit_once('/') {
        Some((parent_path, name)) => {
            let parent = filesystem.open_directory_at(directory, parent_path)?;
            Ok((parent, name))
        }
        None => Ok((directory, path)),
    }
}

fn remove_file_path(
    filesystem: &mut OwnedFilesystem,
    directory: DirectoryHandle,
    path: &str,
) -> Result<(), FsError> {
    let (parent, name) = match path.rsplit_once('/') {
        Some((parent_path, name)) => (filesystem.open_directory_at(directory, parent_path)?, name),
        None => (directory, path),
    };
    filesystem.remove_file_at(parent, name)
}

fn try_zeroed(length: usize) -> Result<Vec<u8>, FsExecutorError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| FsExecutorError::AllocationFailed)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn read_whole_file(
    filesystem: &mut OwnedFilesystem,
    file: FileHandle,
    maximum: usize,
) -> Result<Vec<u8>, FsExecutorError> {
    let length =
        usize::try_from(filesystem.stat(file)?.len).map_err(|_| FsExecutorError::ResultTooLarge)?;
    if length > maximum {
        return Err(FsExecutorError::ResultTooLarge);
    }
    let mut bytes = try_zeroed(length)?;
    if filesystem.read(file, 0, &mut bytes)? != length {
        return Err(FsExecutorError::Filesystem(FsError::Io));
    }
    Ok(bytes)
}

fn wait_durable(
    filesystem: &mut OwnedFilesystem,
    ticket: u64,
    max_steps: usize,
) -> Result<DurabilityResult, FsExecutorError> {
    let mut steps = 0;
    while !filesystem.is_ticket_durable(ticket) && steps < max_steps {
        match filesystem
            .disk_mut()
            .writeback_step()
            .map_err(map_writeback_error)?
        {
            WriteBackProgress::Idle => break,
            WriteBackProgress::WroteBlock { .. } | WriteBackProgress::Flushed { .. } => {
                steps += 1;
            }
        }
    }
    Ok(DurabilityResult {
        ticket,
        durable_sequence: filesystem.durable_flush_sequence(),
        steps,
        complete: filesystem.is_ticket_durable(ticket),
    })
}

fn storage_disk(filesystem: &OwnedFilesystem) -> &StorageDisk {
    filesystem.disk().inner().device()
}

fn storage_disk_mut(filesystem: &mut OwnedFilesystem) -> &mut StorageDisk {
    filesystem.disk_mut().inner_mut().device_mut()
}

fn activate_async(
    filesystem: &mut OwnedFilesystem,
    destination_apic_id: u8,
) -> Result<bool, FsExecutorError> {
    storage_disk_mut(filesystem).activate_async(destination_apic_id)?;
    Ok(filesystem.disk_mut().enable_async_writeback())
}

fn map_writeback_error(error: syscall::error::Error) -> FsExecutorError {
    FsExecutorError::Writeback(error.errno)
}

#[cfg(test)]
fn map_yield_error(_: fiber::YieldError) -> FsExecutorError {
    FsExecutorError::Internal
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const TEST_STACK_SIZE: usize = 64 * 1024;
    static FIBER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        FIBER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn normal_job() -> FsJob {
        FsJob::TestYield {
            yields: 0,
            shutdown_priority: false,
        }
    }

    fn run_to_completion<const SIZE: usize>(
        mut executor: Pin<&mut FsExecutor<'_, SIZE>>,
        id: FsJobId,
    ) {
        for _ in 0..16 {
            match executor.as_mut().poll_step() {
                PollStep::Completed(completed) => {
                    assert_eq!(completed, id);
                    return;
                }
                PollStep::Yielded(active) => assert_eq!(active, id),
                other => panic!("unexpected poll result: {other:?}"),
            }
        }
        panic!("job did not complete");
    }

    #[test]
    fn fs_executor_queue_bounds_and_generation_reuse() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let mut first = None;
        for index in 0..FS_NORMAL_JOB_CAPACITY {
            let id = executor.as_mut().enqueue(normal_job()).unwrap();
            if index == 0 {
                first = Some(id);
            }
        }
        assert_eq!(
            executor.as_mut().enqueue(normal_job()).unwrap_err().error,
            FsExecutorError::ReservedCapacity
        );
        for _ in 0..FS_RESERVED_KERNEL_JOBS {
            executor
                .as_mut()
                .enqueue(FsJob::WritebackDiagnostics)
                .unwrap();
        }
        assert_eq!(
            executor
                .as_mut()
                .enqueue(FsJob::WritebackDiagnostics)
                .unwrap_err()
                .error,
            FsExecutorError::QueueFull
        );

        let first = first.unwrap();
        executor.as_mut().cancel(first).unwrap();
        let completion = executor.as_mut().take_completion(first).unwrap();
        assert_eq!(completion.result.unwrap_err(), FsExecutorError::Canceled);
        let replacement = executor.as_mut().enqueue(normal_job()).unwrap();
        assert_eq!(replacement.index(), first.index());
        assert_ne!(replacement.generation(), first.generation());
        assert_eq!(
            executor.as_mut().take_completion(first).unwrap_err(),
            FsExecutorError::UnknownJob
        );
    }

    #[test]
    fn fs_executor_keeps_one_active_job() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let first = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 2,
                shutdown_priority: false,
            })
            .unwrap();
        let second = executor.as_mut().enqueue(normal_job()).unwrap();

        assert_eq!(executor.as_mut().poll_step(), PollStep::Yielded(first));
        assert_eq!(executor.diagnostics().active, 1);
        assert_eq!(executor.as_mut().poll_step(), PollStep::Yielded(first));
        assert_eq!(executor.diagnostics().active, 1);
        assert_eq!(executor.as_mut().poll_step(), PollStep::Completed(first));
        assert_eq!(executor.diagnostics().active, 0);
        assert_eq!(
            executor.as_mut().take_completion(second).unwrap_err(),
            FsExecutorError::NotComplete
        );
    }

    #[test]
    fn fs_executor_completion_is_owned_exactly_once() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let id = executor.as_mut().enqueue(normal_job()).unwrap();
        run_to_completion(executor.as_mut(), id);
        assert!(matches!(
            executor.as_mut().take_completion(id).unwrap().result,
            Ok(FsResult::Count(0))
        ));
        assert_eq!(
            executor.as_mut().take_completion(id).unwrap_err(),
            FsExecutorError::UnknownJob
        );
    }

    #[test]
    fn fs_executor_cancellation_before_and_after_start() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);

        let queued = executor.as_mut().enqueue(normal_job()).unwrap();
        executor.as_mut().cancel(queued).unwrap();
        assert_eq!(
            executor
                .as_mut()
                .take_completion(queued)
                .unwrap()
                .result
                .unwrap_err(),
            FsExecutorError::Canceled
        );

        let active = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 1,
                shutdown_priority: false,
            })
            .unwrap();
        assert_eq!(executor.as_mut().poll_step(), PollStep::Yielded(active));
        executor.as_mut().cancel(active).unwrap();
        assert_eq!(executor.diagnostics().cancel_draining, 1);
        assert_eq!(executor.as_mut().poll_step(), PollStep::Completed(active));
        assert_eq!(executor.diagnostics().cancel_draining, 0);
        assert_eq!(
            executor
                .as_mut()
                .take_completion(active)
                .unwrap()
                .result
                .unwrap_err(),
            FsExecutorError::Canceled
        );
    }

    #[test]
    fn fs_executor_fiber_yields_preserve_transaction_progress() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let id = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 3,
                shutdown_priority: false,
            })
            .unwrap();
        run_to_completion(executor.as_mut(), id);
        let completion = executor.as_mut().take_completion(id).unwrap();
        assert!(matches!(completion.result, Ok(FsResult::Count(3))));
        assert_eq!(executor.diagnostics().fiber_yields, 4);
    }

    #[test]
    fn delayed_filesystem_job_yields_between_sibling_and_process_turns() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let delayed = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 3,
                shutdown_priority: false,
            })
            .unwrap();
        let mut sibling_thread_turns = 0;
        let mut other_process_turns = 0;
        while executor.as_mut().poll_step() != PollStep::Completed(delayed) {
            sibling_thread_turns += 1;
            other_process_turns += 1;
        }
        assert_eq!(sibling_thread_turns, 3);
        assert_eq!(other_process_turns, 3);
        assert!(matches!(
            executor.as_mut().take_completion(delayed).unwrap().result,
            Ok(FsResult::Count(3))
        ));
    }

    #[test]
    fn shutdown_completion_is_hidden_until_the_exact_final_step() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let shutdown = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 2,
                shutdown_priority: true,
            })
            .unwrap();
        assert_eq!(executor.as_mut().poll_step(), PollStep::Yielded(shutdown));
        assert_eq!(
            executor.as_mut().take_completion(shutdown).unwrap_err(),
            FsExecutorError::NotComplete
        );
        assert_eq!(executor.as_mut().poll_step(), PollStep::Yielded(shutdown));
        assert_eq!(
            executor.as_mut().take_completion(shutdown).unwrap_err(),
            FsExecutorError::NotComplete
        );
        assert_eq!(executor.as_mut().poll_step(), PollStep::Completed(shutdown));
        assert!(matches!(
            executor.as_mut().take_completion(shutdown).unwrap().result,
            Ok(FsResult::Count(2))
        ));
    }

    #[test]
    fn fs_executor_shutdown_job_has_priority() {
        let _guard = test_lock();
        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let executor = FsExecutor::new_test(stack.as_mut());
        let mut executor = core::pin::pin!(executor);
        let normal = executor.as_mut().enqueue(normal_job()).unwrap();
        let shutdown = executor
            .as_mut()
            .enqueue(FsJob::TestYield {
                yields: 0,
                shutdown_priority: true,
            })
            .unwrap();
        assert_eq!(executor.as_mut().poll_step(), PollStep::Completed(shutdown));
        assert_eq!(
            executor.as_mut().take_completion(normal).unwrap_err(),
            FsExecutorError::NotComplete
        );
    }
}
