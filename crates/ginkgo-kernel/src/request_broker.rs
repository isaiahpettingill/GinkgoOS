//! Concrete request ownership and IPC completion integration.
//!
//! Syscall code prepares every buffer while it still has access to the owning
//! [`Process`](crate::process::Process), then transfers the resulting values to
//! [`RequestBroker`]. The broker stores addresses only as integers and never
//! dereferences user memory. Worker, completion, action, cancellation, deadline,
//! and lifecycle paths use only storage reserved at construction or transferred
//! during submission.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use ginkgo_filesystem::{DirectoryHandle, FileHandle};
use ginkgo_ipc::{IpcError, RequestControl, SharedMemoryRequestLease};
use ginkgo_sysapi::{
    RequestBufferFlags, RequestCompletionMode, RequestDiagnostics, RequestFlags, RequestInfo,
    RequestOperation, RequestResultFlags, RequestState, Rights, Status, DEADLINE_INFINITE,
    REQUEST_DIAGNOSTICS_VERSION, REQUEST_INFO_VERSION, REQUEST_MAX_BUFFERS,
};

use crate::{
    paging::address_space::PinnedUserPage,
    request::{
        DeferredCompletion, RequestAction, RequestDevice, RequestDispatch, RequestError, RequestId,
        RequestLimits, RequestOwner, RequestResourceState, RequestResources, RequestRuntime,
        RequestRuntimeDiagnostics, RequestSubmission, RequestTarget, RequestWorkerBudget,
        RequestWorkerReport,
    },
};

/// A generation-protected file capability retained independently of a process handle.
#[derive(Debug, Eq, PartialEq)]
pub struct FileCapabilityLease {
    file: FileHandle,
}

impl FileCapabilityLease {
    pub const fn new(file: FileHandle) -> Self {
        Self { file }
    }

    pub const fn file(&self) -> &FileHandle {
        &self.file
    }
}

impl From<FileHandle> for FileCapabilityLease {
    fn from(file: FileHandle) -> Self {
        Self::new(file)
    }
}

/// Prepared target authority held for the full request resource lifetime.
#[derive(Debug, Eq, PartialEq)]
pub enum PreparedRequestTarget {
    None,
    File(FileCapabilityLease),
    /// Copied directory authority; `None` selects the filesystem root.
    Directory {
        directory: Option<DirectoryHandle>,
        is_root: bool,
        rights: Rights,
    },
    FilesystemSync,
}

impl PreparedRequestTarget {
    pub const fn file(&self) -> Option<&FileHandle> {
        match self {
            Self::File(lease) => Some(lease.file()),
            Self::None | Self::Directory { .. } | Self::FilesystemSync => None,
        }
    }

    pub const fn directory(&self) -> Option<(Option<DirectoryHandle>, bool, Rights)> {
        match self {
            Self::Directory {
                directory,
                is_root,
                rights,
            } => Some((*directory, *is_root, *rights)),
            Self::None | Self::File(_) | Self::FilesystemSync => None,
        }
    }

    fn validate(
        &self,
        operation: RequestOperation,
        target: RequestTarget,
    ) -> Result<(), BrokerError> {
        let valid = match (operation, self) {
            (RequestOperation::Nop, Self::None) => target == RequestTarget(0),
            (RequestOperation::AudioWrite | RequestOperation::Synthetic, Self::None) => {
                target != RequestTarget(0)
            }
            (
                RequestOperation::FilesystemRead | RequestOperation::FilesystemWrite,
                Self::File(lease),
            ) => target == file_request_target(lease.file),
            (
                RequestOperation::FilesystemOpen,
                Self::Directory {
                    directory, rights, ..
                },
            ) => rights.contains(Rights::READ) && target == directory_request_target(*directory),
            (RequestOperation::FilesystemSync, Self::FilesystemSync) => target != RequestTarget(0),
            _ => false,
        };
        valid.then_some(()).ok_or(BrokerError::ActionMismatch)
    }
}

/// Scalar operation metadata retained inline by [`RequestRuntime`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerPayload {
    pub operation_argument: u64,
    pub user_data: u64,
    pub request_flags: RequestFlags,
}

/// One buffer fully copied, validated, pinned, or leased by syscall preparation.
///
/// `user_address` is retained only so syscall/process integration can copy a
/// completed output back through `Process`. The broker never treats it as a pointer.
pub enum PreparedRequestBuffer {
    Copied {
        flags: RequestBufferFlags,
        user_address: u64,
        bytes: Vec<u8>,
    },
    Pinned {
        flags: RequestBufferFlags,
        owner_process_id: u64,
        pages: Vec<PinnedUserPage>,
    },
    SharedMemory {
        flags: RequestBufferFlags,
        lease: SharedMemoryRequestLease,
    },
}

impl PreparedRequestBuffer {
    pub const fn flags(&self) -> RequestBufferFlags {
        match self {
            Self::Copied { flags, .. }
            | Self::Pinned { flags, .. }
            | Self::SharedMemory { flags, .. } => *flags,
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            Self::Copied { bytes, .. } => bytes.len(),
            Self::Pinned { pages, .. } => pages
                .iter()
                .fold(0usize, |total, page| total.saturating_add(page.byte_length)),
            Self::SharedMemory { lease, .. } => lease.len(),
        }
    }
}

/// A request whose target, scalars, buffers, pins, and leases are ready to own.
pub struct PreparedBrokerRequest {
    pub owner: RequestOwner,
    pub target: RequestTarget,
    pub target_lease: PreparedRequestTarget,
    pub device: Option<RequestDevice>,
    pub operation: RequestOperation,
    pub completion_mode: RequestCompletionMode,
    pub payload: BrokerPayload,
    pub deadline_ns: Option<u64>,
    pub buffers: Vec<PreparedRequestBuffer>,
}

impl PreparedBrokerRequest {
    /// Computes the bounded resource charge represented by the prepared buffers.
    pub fn resources(&self) -> Result<RequestResources, BrokerError> {
        self.target_lease.validate(self.operation, self.target)?;
        if self.buffers.len() > REQUEST_MAX_BUFFERS {
            return Err(BrokerError::TooManyBuffers);
        }

        let mut resources = RequestResources::default();
        for buffer in &self.buffers {
            match buffer {
                PreparedRequestBuffer::Copied { bytes, .. } => {
                    resources.copied_bytes = resources
                        .copied_bytes
                        .checked_add(bytes.len())
                        .ok_or(BrokerError::ResourceOverflow)?;
                }
                PreparedRequestBuffer::Pinned {
                    owner_process_id,
                    pages,
                    ..
                } => {
                    if *owner_process_id != self.owner.process_id {
                        return Err(BrokerError::PinnedPageOwnerMismatch);
                    }
                    resources.pinned_pages = resources
                        .pinned_pages
                        .checked_add(pages.len())
                        .ok_or(BrokerError::ResourceOverflow)?;
                }
                PreparedRequestBuffer::SharedMemory { lease, .. } => {
                    resources.shared_bytes = resources
                        .shared_bytes
                        .checked_add(lease.len())
                        .ok_or(BrokerError::ResourceOverflow)?;
                }
            }
        }
        self.total_requested_bytes()?;
        checked_public_deadline(self.deadline_ns)?;
        Ok(resources)
    }

    /// Returns the total byte span described by all prepared request buffers.
    pub fn total_requested_bytes(&self) -> Result<u64, BrokerError> {
        self.buffers.iter().try_fold(0u64, |total, buffer| {
            let length = match buffer {
                PreparedRequestBuffer::Copied { bytes, .. } => {
                    u64::try_from(bytes.len()).map_err(|_| BrokerError::ResourceOverflow)?
                }
                PreparedRequestBuffer::Pinned { pages, .. } => {
                    pages.iter().try_fold(0u64, |buffer_total, page| {
                        let length = u64::try_from(page.byte_length)
                            .map_err(|_| BrokerError::ResourceOverflow)?;
                        buffer_total
                            .checked_add(length)
                            .ok_or(BrokerError::ResourceOverflow)
                    })?
                }
                PreparedRequestBuffer::SharedMemory { lease, .. } => {
                    u64::try_from(lease.len()).map_err(|_| BrokerError::ResourceOverflow)?
                }
            };
            total
                .checked_add(length)
                .ok_or(BrokerError::ResourceOverflow)
        })
    }

    fn submission(
        &self,
    ) -> Result<RequestSubmission<RequestOperation, BrokerPayload>, BrokerError> {
        Ok(RequestSubmission {
            owner: self.owner,
            target: self.target,
            device: self.device,
            operation: self.operation,
            service_payload: self.payload,
            deadline_ns: self.deadline_ns,
            resources: self.resources()?,
        })
    }
}

/// Submission result used by syscall code to install or wait on the control.
pub struct BrokerSubmission {
    pub id: RequestId,
    pub control: RequestControl,
    pub completion_mode: RequestCompletionMode,
}

impl fmt::Debug for BrokerSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerSubmission")
            .field("id", &self.id)
            .field("completion_mode", &self.completion_mode)
            .finish_non_exhaustive()
    }
}

/// A failed single submission, including the still-owned prepared resources.
pub struct BrokerSubmitFailure {
    pub error: BrokerError,
    pub request: PreparedBrokerRequest,
}

impl fmt::Debug for BrokerSubmitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerSubmitFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// A failed atomic batch, including every still-owned prepared request.
pub struct BrokerBatchSubmitFailure {
    pub error: BrokerError,
    pub requests: Vec<PreparedBrokerRequest>,
}

impl fmt::Debug for BrokerBatchSubmitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerBatchSubmitFailure")
            .field("error", &self.error)
            .field("request_count", &self.requests.len())
            .finish()
    }
}

/// Completion details not represented by the generic scheduling runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerCompletion {
    pub id: RequestId,
    pub status: Status,
    pub device_released: bool,
    pub bytes_transferred: u64,
    pub result_flags: RequestResultFlags,
}

/// Resources transferred out after the runtime emits its release action.
///
/// The receiver must copy writable copied buffers through the owning `Process`,
/// unpin each `Pinned` buffer from its recorded owner process, and then drop all
/// copied storage and shared-memory leases. Taking a release acknowledges the
/// runtime action, so this value is returned at most once for an ID.
pub struct ReleasedBrokerResources {
    pub id: RequestId,
    pub owner: RequestOwner,
    pub buffers: Vec<PreparedRequestBuffer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Runtime(RequestError),
    Control(IpcError),
    OutOfMemory,
    TooManyBuffers,
    ResourceOverflow,
    InvalidDeadline,
    PinnedPageOwnerMismatch,
    InvalidRequest,
    ReleaseNotDispatched,
    ResourcesAlreadyTaken,
    ActionMismatch,
}

impl From<RequestError> for BrokerError {
    fn from(error: RequestError) -> Self {
        Self::Runtime(error)
    }
}

impl From<IpcError> for BrokerError {
    fn from(error: IpcError) -> Self {
        Self::Control(error)
    }
}

#[derive(Clone, Copy)]
struct CompletionResult {
    bytes_transferred: u64,
    result_flags: RequestResultFlags,
}

struct BrokerEntry {
    id: RequestId,
    owner: RequestOwner,
    target: RequestTarget,
    target_lease: PreparedRequestTarget,
    control: RequestControl,
    info: RequestInfo,
    completion_mode: RequestCompletionMode,
    buffers: Option<Vec<PreparedRequestBuffer>>,
    service_offset: u64,
    durability_ticket: Option<u64>,
    total_requested_bytes: u64,
    completion_result: Option<CompletionResult>,
    terminal_publication_attempted: bool,
    release_dispatched: bool,
}

struct BrokerSlot {
    generation: u32,
    retired: bool,
    entry: Option<BrokerEntry>,
}

impl BrokerSlot {
    const fn vacant() -> Self {
        Self {
            generation: 1,
            retired: false,
            entry: None,
        }
    }
}

/// Fixed-capacity owner around the generic request runtime.
pub struct RequestBroker {
    runtime: RequestRuntime<RequestOperation, BrokerPayload>,
    slots: Vec<BrokerSlot>,
    published_bytes: u64,
}

impl RequestBroker {
    pub fn try_new() -> Result<Self, BrokerError> {
        Self::try_new_with_limits(RequestLimits::default_policy())
    }

    pub fn try_new_with_limits(limits: RequestLimits) -> Result<Self, BrokerError> {
        let runtime = RequestRuntime::try_new_with_limits(limits)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.system_capacity)
            .map_err(|_| BrokerError::OutOfMemory)?;
        for _ in 0..limits.system_capacity {
            slots.push(BrokerSlot::vacant());
        }
        Ok(Self {
            runtime,
            slots,
            published_bytes: 0,
        })
    }

    pub const fn limits(&self) -> RequestLimits {
        self.runtime.limits()
    }

    pub const fn is_accepting(&self) -> bool {
        self.runtime.is_accepting()
    }

    /// Submits one request without transferring prepared resources on failure.
    pub fn submit(
        &mut self,
        request: PreparedBrokerRequest,
        now_ns: u64,
    ) -> Result<BrokerSubmission, BrokerSubmitFailure> {
        let slot_index = match self.next_vacant_slot() {
            Some(index) => index,
            None => {
                return Err(BrokerSubmitFailure {
                    error: BrokerError::Runtime(RequestError::SystemFull),
                    request,
                });
            }
        };
        let expected_id = self.expected_id(slot_index);
        let submission = match request.submission() {
            Ok(submission) => submission,
            Err(error) => return Err(BrokerSubmitFailure { error, request }),
        };
        let info = match initial_info(&request, now_ns) {
            Ok(info) => info,
            Err(error) => return Err(BrokerSubmitFailure { error, request }),
        };
        let control = match RequestControl::new(expected_id.raw(), info) {
            Ok(control) => control,
            Err(error) => {
                return Err(BrokerSubmitFailure {
                    error: BrokerError::Control(error),
                    request,
                });
            }
        };
        let id = match self.runtime.submit(submission, now_ns) {
            Ok(id) => id,
            Err(error) => {
                return Err(BrokerSubmitFailure {
                    error: BrokerError::Runtime(error),
                    request,
                });
            }
        };
        debug_assert_eq!(id, expected_id);
        let result = BrokerSubmission {
            id,
            control: control.clone(),
            completion_mode: request.completion_mode,
        };
        self.install(slot_index, id, control, info, request);
        Ok(result)
    }

    /// Prepares controls first, then commits the complete runtime batch atomically.
    /// No request or resource is transferred on error.
    pub fn submit_batch(
        &mut self,
        requests: Vec<PreparedBrokerRequest>,
        now_ns: u64,
    ) -> Result<Vec<BrokerSubmission>, BrokerBatchSubmitFailure> {
        if requests.is_empty() {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::Runtime(RequestError::EmptyBatch),
                requests,
            });
        }
        if requests.len() > self.runtime.limits().max_batch {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::Runtime(RequestError::BatchTooLarge),
                requests,
            });
        }

        let mut slot_indices = Vec::new();
        if slot_indices.try_reserve_exact(requests.len()).is_err() {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::OutOfMemory,
                requests,
            });
        }
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.entry.is_none() && !slot.retired {
                slot_indices.push(index);
                if slot_indices.len() == requests.len() {
                    break;
                }
            }
        }
        if slot_indices.len() != requests.len() {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::Runtime(RequestError::SystemFull),
                requests,
            });
        }

        let mut submissions = Vec::new();
        let mut controls = Vec::new();
        let mut infos = Vec::new();
        let mut ids = Vec::new();
        if submissions.try_reserve_exact(requests.len()).is_err()
            || controls.try_reserve_exact(requests.len()).is_err()
            || infos.try_reserve_exact(requests.len()).is_err()
            || ids.try_reserve_exact(requests.len()).is_err()
        {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::OutOfMemory,
                requests,
            });
        }

        for (request, slot_index) in requests.iter().zip(slot_indices.iter().copied()) {
            let submission = match request.submission() {
                Ok(submission) => submission,
                Err(error) => return Err(BrokerBatchSubmitFailure { error, requests }),
            };
            let info = match initial_info(request, now_ns) {
                Ok(info) => info,
                Err(error) => return Err(BrokerBatchSubmitFailure { error, requests }),
            };
            let id = self.expected_id(slot_index);
            let control = match RequestControl::new(id.raw(), info) {
                Ok(control) => control,
                Err(error) => {
                    return Err(BrokerBatchSubmitFailure {
                        error: BrokerError::Control(error),
                        requests,
                    });
                }
            };
            submissions.push(submission);
            controls.push(control);
            infos.push(info);
            ids.push(id);
        }

        let mut runtime_ids = Vec::new();
        let mut results = Vec::new();
        if runtime_ids.try_reserve_exact(requests.len()).is_err()
            || results.try_reserve_exact(requests.len()).is_err()
        {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::OutOfMemory,
                requests,
            });
        }
        runtime_ids.resize(requests.len(), RequestId::INVALID);
        if let Err(error) = self
            .runtime
            .submit_batch(&submissions, &mut runtime_ids, now_ns)
        {
            return Err(BrokerBatchSubmitFailure {
                error: BrokerError::Runtime(error),
                requests,
            });
        }
        debug_assert_eq!(runtime_ids, ids);

        for ((((request, control), info), id), slot_index) in requests
            .into_iter()
            .zip(controls.into_iter())
            .zip(infos.into_iter())
            .zip(runtime_ids.into_iter())
            .zip(slot_indices.into_iter())
        {
            results.push(BrokerSubmission {
                id,
                control: control.clone(),
                completion_mode: request.completion_mode,
            });
            self.install(slot_index, id, control, info, request);
        }
        Ok(results)
    }

    pub fn control(&self, id: RequestId) -> Option<&RequestControl> {
        self.entry(id).map(|entry| &entry.control)
    }

    pub fn info(&self, id: RequestId) -> Option<RequestInfo> {
        self.entry(id).map(|entry| entry.info)
    }

    pub fn completion_mode(&self, id: RequestId) -> Option<RequestCompletionMode> {
        self.entry(id).map(|entry| entry.completion_mode)
    }

    pub fn target(&self, id: RequestId) -> Option<RequestTarget> {
        self.entry(id).map(|entry| entry.target)
    }

    pub fn prepared_target(&self, id: RequestId) -> Option<&PreparedRequestTarget> {
        self.entry(id).map(|entry| &entry.target_lease)
    }

    /// Borrows the retained file target used by filesystem chunk workers.
    pub fn file_target(&self, id: RequestId) -> Option<&FileHandle> {
        self.entry(id).and_then(|entry| entry.target_lease.file())
    }

    /// Returns the retained directory authority used by filesystem-open workers.
    pub fn directory_target(
        &self,
        id: RequestId,
    ) -> Option<(Option<DirectoryHandle>, bool, Rights)> {
        self.entry(id)
            .and_then(|entry| entry.target_lease.directory())
    }

    pub fn service_offset(&self, id: RequestId) -> Option<u64> {
        self.entry(id).map(|entry| entry.service_offset)
    }

    pub fn durability_ticket(&self, id: RequestId) -> Option<Option<u64>> {
        self.entry(id).map(|entry| entry.durability_ticket)
    }

    pub fn set_durability_ticket(&mut self, id: RequestId, ticket: u64) -> Result<(), BrokerError> {
        let entry = self.entry_mut(id).ok_or(BrokerError::InvalidRequest)?;
        match entry.durability_ticket {
            Some(existing) if existing != ticket => Err(BrokerError::ActionMismatch),
            Some(_) => Ok(()),
            None => {
                entry.durability_ticket = Some(ticket);
                Ok(())
            }
        }
    }

    pub fn total_requested_bytes(&self, id: RequestId) -> Option<u64> {
        self.entry(id).map(|entry| entry.total_requested_bytes)
    }

    /// Advances bounded service progress and returns the new absolute offset.
    pub fn advance_service_offset(
        &mut self,
        id: RequestId,
        bytes: u64,
    ) -> Result<u64, BrokerError> {
        let snapshot = self
            .runtime
            .snapshot(id)
            .ok_or(BrokerError::InvalidRequest)?;
        if snapshot.state != RequestState::Active
            || snapshot.resource_state != RequestResourceState::KernelOwned
        {
            return Err(BrokerError::Runtime(RequestError::InvalidState));
        }
        let entry = self.entry_mut(id).ok_or(BrokerError::InvalidRequest)?;
        let offset = entry
            .service_offset
            .checked_add(bytes)
            .ok_or(BrokerError::ResourceOverflow)?;
        if offset > entry.total_requested_bytes {
            return Err(BrokerError::ResourceOverflow);
        }
        entry.service_offset = offset;
        Ok(offset)
    }

    pub fn owner(&self, id: RequestId) -> Option<RequestOwner> {
        self.entry(id).map(|entry| entry.owner)
    }

    pub fn buffers(&self, id: RequestId) -> Option<&[PreparedRequestBuffer]> {
        self.entry(id).and_then(|entry| entry.buffers.as_deref())
    }

    pub fn buffers_mut(&mut self, id: RequestId) -> Option<&mut [PreparedRequestBuffer]> {
        self.entry_mut(id)
            .and_then(|entry| entry.buffers.as_deref_mut())
    }

    /// Selects one fair runtime dispatch and updates broker-visible metadata.
    pub fn next_dispatch(
        &mut self,
        now_ns: u64,
    ) -> Option<RequestDispatch<RequestOperation, BrokerPayload>> {
        let dispatch = self.runtime.next_dispatch(now_ns)?;
        self.synchronize_info(dispatch.id);
        Some(dispatch)
    }

    /// Yields one kernel-owned chunked request to the back of its target FIFO.
    pub fn requeue_active(&mut self, id: RequestId) -> Result<(), BrokerError> {
        self.runtime.requeue_active(id)?;
        self.synchronize_info(id);
        Ok(())
    }

    pub fn mark_device_owned(&mut self, id: RequestId) -> Result<(), BrokerError> {
        self.runtime.mark_device_owned(id)?;
        Ok(())
    }

    /// Records one bounded completion without allocating.
    pub fn record_completion(&mut self, completion: BrokerCompletion) -> Result<(), BrokerError> {
        let retain_result = self
            .runtime
            .snapshot(completion.id)
            .is_some_and(|snapshot| !state_is_terminal(snapshot.state));
        self.runtime.record_completion(DeferredCompletion {
            id: completion.id,
            status: completion.status,
            device_released: completion.device_released,
        })?;
        if retain_result {
            if let Some(entry) = self.entry_mut(completion.id) {
                if entry.completion_result.is_none() {
                    entry.completion_result = Some(CompletionResult {
                        bytes_transferred: completion.bytes_transferred,
                        result_flags: completion.result_flags,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn run_worker(&mut self, now_ns: u64, budget: RequestWorkerBudget) -> RequestWorkerReport {
        let report = self.runtime.run_worker(now_ns, budget);
        self.synchronize_all_info();
        report
    }

    pub fn cancel(&mut self, id: RequestId, now_ns: u64) -> Result<(), BrokerError> {
        self.runtime.cancel(id, now_ns)?;
        if let Some(entry) = self.entry(id) {
            entry.control.request_cancellation();
        }
        self.synchronize_info(id);
        Ok(())
    }

    pub fn acknowledge_cancel(
        &mut self,
        id: RequestId,
        now_ns: u64,
        device_stopped: bool,
    ) -> Result<(), BrokerError> {
        self.runtime
            .acknowledge_cancel(id, now_ns, device_stopped)?;
        self.synchronize_info(id);
        Ok(())
    }

    pub fn acknowledge_drain(&mut self, id: RequestId) -> Result<(), BrokerError> {
        self.runtime.acknowledge_drain(id)?;
        Ok(())
    }

    pub fn terminate_thread(&mut self, owner: RequestOwner, now_ns: u64) -> usize {
        let affected = self.runtime.terminate_thread(owner, now_ns);
        self.synchronize_all_info();
        affected
    }

    pub fn terminate_process(&mut self, process_id: u64, now_ns: u64) -> usize {
        let affected = self.runtime.terminate_process(process_id, now_ns);
        self.synchronize_all_info();
        affected
    }

    pub fn remove_device(
        &mut self,
        device: RequestDevice,
        now_ns: u64,
        ownership_stopped: bool,
    ) -> usize {
        let affected = self
            .runtime
            .remove_device(device, now_ns, ownership_stopped);
        self.synchronize_all_info();
        affected
    }

    pub fn reset_device(&mut self, device: RequestDevice, now_ns: u64) -> usize {
        let affected = self.runtime.reset_device(device, now_ns);
        self.synchronize_all_info();
        affected
    }

    pub fn begin_shutdown(&mut self, now_ns: u64) -> usize {
        let affected = self.runtime.begin_shutdown(now_ns);
        self.synchronize_all_info();
        affected
    }

    pub fn resume_after_shutdown_cancel(&mut self) {
        self.runtime.resume_after_shutdown_cancel();
    }

    /// Pops one runtime action.
    ///
    /// Terminal actions update `RequestInfo` and publish the `RequestControl` before
    /// being returned. Release actions make [`Self::take_external_resources`] legal.
    pub fn pop_action(&mut self) -> Result<Option<RequestAction>, BrokerError> {
        let Some(action) = self.runtime.next_action() else {
            return Ok(None);
        };
        match action {
            RequestAction::PublishTerminal {
                id,
                state,
                status,
                completed_at_ns,
            } => {
                self.publish_terminal(id, state, status, completed_at_ns)?;
            }
            RequestAction::ReleaseResources {
                id,
                owner,
                resources,
            } => {
                let snapshot = self
                    .runtime
                    .snapshot(id)
                    .ok_or(BrokerError::InvalidRequest)?;
                let entry = self.entry_mut(id).ok_or(BrokerError::InvalidRequest)?;
                if entry.owner != owner || snapshot.resources != resources {
                    return Err(BrokerError::ActionMismatch);
                }
                entry.release_dispatched = true;
            }
            RequestAction::CancelDevice { .. } => {}
        }
        Ok(Some(action))
    }

    /// Updates terminal metadata and attempts IPC publication exactly once.
    pub fn publish_terminal(
        &mut self,
        id: RequestId,
        state: RequestState,
        status: Status,
        completed_at_ns: u64,
    ) -> Result<bool, BrokerError> {
        let snapshot = self
            .runtime
            .snapshot(id)
            .ok_or(BrokerError::InvalidRequest)?;
        if snapshot.state != state
            || snapshot.status != status
            || snapshot.completed_at_ns != Some(completed_at_ns)
            || !state_is_terminal(state)
        {
            return Err(BrokerError::ActionMismatch);
        }
        self.synchronize_info(id);
        let (published, bytes_transferred) = {
            let entry = self.entry_mut(id).ok_or(BrokerError::InvalidRequest)?;
            if entry.terminal_publication_attempted {
                return Ok(false);
            }
            entry.terminal_publication_attempted = true;
            (
                entry.control.publish_terminal(entry.info),
                entry.info.bytes_transferred,
            )
        };
        if published {
            self.published_bytes = self.published_bytes.saturating_add(bytes_transferred);
        }
        Ok(published)
    }

    /// Transfers all external resources after a release action and acknowledges it.
    pub fn take_external_resources(
        &mut self,
        id: RequestId,
    ) -> Result<ReleasedBrokerResources, BrokerError> {
        let (owner, release_dispatched, has_buffers) = self
            .entry(id)
            .map(|entry| {
                (
                    entry.owner,
                    entry.release_dispatched,
                    entry.buffers.is_some(),
                )
            })
            .ok_or(BrokerError::InvalidRequest)?;
        if !release_dispatched {
            return Err(BrokerError::ReleaseNotDispatched);
        }
        if !has_buffers {
            return Err(BrokerError::ResourcesAlreadyTaken);
        }

        self.runtime.acknowledge_resource_release(id)?;
        let buffers = self
            .entry_mut(id)
            .and_then(|entry| entry.buffers.take())
            .ok_or(BrokerError::ResourcesAlreadyTaken)?;
        let released = ReleasedBrokerResources { id, owner, buffers };
        self.retire_entry_if_runtime_did(id);
        Ok(released)
    }

    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.runtime.next_deadline_ns()
    }

    pub fn is_system_drained(&self) -> bool {
        self.runtime.is_system_drained()
    }

    pub fn is_process_drained(&self, process_id: u64) -> bool {
        self.runtime.is_process_drained(process_id)
    }

    pub fn is_thread_drained(&self, owner: RequestOwner) -> bool {
        self.runtime.is_thread_drained(owner)
    }

    /// Maps internal bounded counters to the stable public diagnostics ABI.
    pub fn diagnostics(&self) -> RequestDiagnostics {
        let runtime = self.runtime.diagnostics();
        RequestDiagnostics {
            version: REQUEST_DIAGNOSTICS_VERSION,
            size: RequestDiagnostics::SIZE,
            queue_depth: usize_to_u64(runtime.queued_requests),
            peak_queue_depth: usize_to_u64(runtime.peak_queued_requests),
            active_requests: usize_to_u64(runtime.active_requests),
            completed_requests: runtime.terminal_publications,
            total_service_latency_ns: runtime.cumulative_service_latency_ns,
            maximum_service_latency_ns: runtime.maximum_service_latency_ns,
            total_wait_latency_ns: runtime.cumulative_queue_latency_ns,
            maximum_wait_latency_ns: runtime.maximum_queue_latency_ns,
            deadline_misses: runtime.timeouts,
            cancellations: runtime.cancellation_requests,
            bytes_transferred: self.published_bytes,
            errors: runtime.failures,
            rejected_requests: rejected_requests(runtime),
            dropped_completions: runtime.rejected_completion_queue_full,
            peak_active_requests: usize_to_u64(runtime.peak_active_requests),
        }
    }

    fn install(
        &mut self,
        slot_index: usize,
        id: RequestId,
        control: RequestControl,
        info: RequestInfo,
        request: PreparedBrokerRequest,
    ) {
        debug_assert!(self.slots[slot_index].entry.is_none());
        let total_requested_bytes = request
            .total_requested_bytes()
            .expect("installed request was validated before runtime submission");
        self.slots[slot_index].entry = Some(BrokerEntry {
            id,
            owner: request.owner,
            target: request.target,
            target_lease: request.target_lease,
            control,
            info,
            completion_mode: request.completion_mode,
            buffers: Some(request.buffers),
            service_offset: 0,
            durability_ticket: None,
            total_requested_bytes,
            completion_result: None,
            terminal_publication_attempted: false,
            release_dispatched: false,
        });
    }

    fn next_vacant_slot(&self) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.entry.is_none() && !slot.retired)
    }

    fn expected_id(&self, slot_index: usize) -> RequestId {
        let generation = self.slots[slot_index].generation;
        RequestId::from_raw((u64::from(generation) << 32) | (slot_index as u64 + 1))
    }

    fn entry(&self, id: RequestId) -> Option<&BrokerEntry> {
        let index = id_slot_index(id)?;
        let slot = self.slots.get(index)?;
        (slot.generation == id.generation())
            .then_some(slot.entry.as_ref())
            .flatten()
            .filter(|entry| entry.id == id)
    }

    fn entry_mut(&mut self, id: RequestId) -> Option<&mut BrokerEntry> {
        let index = id_slot_index(id)?;
        let slot = self.slots.get_mut(index)?;
        (slot.generation == id.generation())
            .then_some(slot.entry.as_mut())
            .flatten()
            .filter(|entry| entry.id == id)
    }

    fn synchronize_info(&mut self, id: RequestId) {
        let Some(snapshot) = self.runtime.snapshot(id) else {
            return;
        };
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.info.state = snapshot.state as u32;
        entry.info.result = snapshot.status as i32;
        entry.info.started_ns = snapshot.started_at_ns.unwrap_or(0);
        entry.info.completed_ns = snapshot.completed_at_ns.unwrap_or(0);
        entry.info.result_flags = 0;
        entry.info.bytes_transferred = 0;
        if state_is_terminal(snapshot.state) {
            if let Some(result) = entry.completion_result {
                entry.info.bytes_transferred = result.bytes_transferred;
                entry.info.result_flags = result.result_flags.bits();
            }
            let mut flags = RequestResultFlags::from_bits_retain(entry.info.result_flags);
            if snapshot.cancellation_acknowledged {
                flags |= RequestResultFlags::CANCEL_ACKNOWLEDGED;
            }
            if snapshot.state == RequestState::TimedOut {
                flags |= RequestResultFlags::DEADLINE_EXPIRED;
            }
            entry.info.result_flags = flags.bits();
        }
    }

    fn synchronize_all_info(&mut self) {
        for index in 0..self.slots.len() {
            let Some(id) = self.slots[index].entry.as_ref().map(|entry| entry.id) else {
                continue;
            };
            self.synchronize_info(id);
        }
    }

    fn retire_entry_if_runtime_did(&mut self, id: RequestId) {
        if self.runtime.snapshot(id).is_some() {
            return;
        }
        let Some(index) = id_slot_index(id) else {
            return;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return;
        };
        if slot.generation != id.generation()
            || slot.entry.as_ref().is_none_or(|entry| entry.id != id)
        {
            return;
        }
        slot.entry = None;
        match slot.generation.checked_add(1) {
            Some(generation) => slot.generation = generation,
            None => slot.retired = true,
        }
    }
}

fn initial_info(
    request: &PreparedBrokerRequest,
    submitted_ns: u64,
) -> Result<RequestInfo, BrokerError> {
    Ok(RequestInfo {
        version: REQUEST_INFO_VERSION,
        size: RequestInfo::SIZE,
        state: RequestState::Pending as u32,
        operation: request.operation as u32,
        request_flags: request.payload.request_flags.bits(),
        result_flags: 0,
        result: Status::ShouldWait as i32,
        reserved: 0,
        bytes_transferred: 0,
        deadline_ns: checked_public_deadline(request.deadline_ns)?,
        submitted_ns,
        started_ns: 0,
        completed_ns: 0,
        user_data: request.payload.user_data,
    })
}

fn checked_public_deadline(deadline_ns: Option<u64>) -> Result<i64, BrokerError> {
    match deadline_ns {
        None => Ok(DEADLINE_INFINITE),
        Some(deadline) => {
            let deadline = i64::try_from(deadline).map_err(|_| BrokerError::InvalidDeadline)?;
            if deadline == DEADLINE_INFINITE {
                Err(BrokerError::InvalidDeadline)
            } else {
                Ok(deadline)
            }
        }
    }
}

fn file_request_target(file: FileHandle) -> RequestTarget {
    RequestTarget((u64::from(file.generation()) << 32) | u64::from(file.node_id()))
}

fn directory_request_target(directory: Option<DirectoryHandle>) -> RequestTarget {
    match directory {
        Some(directory) => RequestTarget(
            (u64::from(directory.generation()) << 32) | u64::from(directory.node_id()),
        ),
        None => RequestTarget(u64::MAX),
    }
}

fn id_slot_index(id: RequestId) -> Option<usize> {
    if !id.is_valid() {
        return None;
    }
    let encoded = id.raw() as u32;
    (encoded != 0).then_some((encoded - 1) as usize)
}

const fn state_is_terminal(state: RequestState) -> bool {
    matches!(
        state,
        RequestState::Completed
            | RequestState::TimedOut
            | RequestState::Canceled
            | RequestState::Failed
            | RequestState::OwnerTerminated
    )
}

const fn usize_to_u64(value: usize) -> u64 {
    if value > u64::MAX as usize {
        u64::MAX
    } else {
        value as u64
    }
}

fn rejected_requests(diagnostics: RequestRuntimeDiagnostics) -> u64 {
    diagnostics
        .rejected_quiescing
        .saturating_add(diagnostics.rejected_system_full)
        .saturating_add(diagnostics.rejected_owner_limit)
        .saturating_add(diagnostics.rejected_target_limit)
        .saturating_add(diagnostics.rejected_copied_bytes)
        .saturating_add(diagnostics.rejected_pinned_pages)
        .saturating_add(diagnostics.rejected_shared_bytes)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use ginkgo_filesystem::RedoxFs;
    use ginkgo_ipc::HandleTable;

    use crate::paging::address_space::{UserAccess, UserPagePermissions};

    use super::*;

    fn limits(capacity: usize) -> RequestLimits {
        RequestLimits {
            system_capacity: capacity,
            per_owner_requests: capacity,
            per_target_requests: capacity,
            max_batch: capacity.min(crate::request::REQUEST_MAX_BATCH),
            copied_bytes_per_request: 64,
            copied_bytes_per_owner: 128,
            copied_bytes_system: 256,
            pinned_pages_per_request: 4,
            pinned_pages_per_owner: 8,
            pinned_pages_system: 16,
            shared_bytes_per_request: 256,
            shared_bytes_per_owner: 512,
            shared_bytes_system: 1024,
            deferred_completion_capacity: capacity.max(1),
        }
    }

    fn broker(capacity: usize) -> RequestBroker {
        RequestBroker::try_new_with_limits(limits(capacity)).unwrap()
    }

    fn prepared(process: u64, thread: u64, target: u64) -> PreparedBrokerRequest {
        PreparedBrokerRequest {
            owner: RequestOwner::new(process, thread),
            target: RequestTarget(target),
            target_lease: PreparedRequestTarget::None,
            device: Some(RequestDevice(target as u32)),
            operation: RequestOperation::Synthetic,
            completion_mode: RequestCompletionMode::Handle,
            payload: BrokerPayload {
                operation_argument: 0x1234,
                user_data: 0x5678,
                request_flags: RequestFlags::ORDERED,
            },
            deadline_ns: None,
            buffers: vec![PreparedRequestBuffer::Copied {
                flags: RequestBufferFlags::READ | RequestBufferFlags::WRITE,
                user_address: 0x4000,
                bytes: vec![1, 2, 3, 4],
            }],
        }
    }

    fn prepared_open(
        process: u64,
        thread: u64,
        directory: Option<DirectoryHandle>,
        is_root: bool,
        rights: Rights,
    ) -> PreparedBrokerRequest {
        let mut request = prepared(process, thread, directory_request_target(directory).0);
        request.target_lease = PreparedRequestTarget::Directory {
            directory,
            is_root,
            rights,
        };
        request.device = None;
        request.operation = RequestOperation::FilesystemOpen;
        request.buffers[0] = PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::READ,
            user_address: 0x4000,
            bytes: vec![b'f', b'i', b'l', b'e'],
        };
        request
    }

    fn complete(broker: &mut RequestBroker, id: RequestId, now_ns: u64, bytes_transferred: u64) {
        broker
            .record_completion(BrokerCompletion {
                id,
                status: Status::Ok,
                device_released: true,
                bytes_transferred,
                result_flags: RequestResultFlags::empty(),
            })
            .unwrap();
        assert_eq!(
            broker
                .run_worker(now_ns, RequestWorkerBudget::DEFAULT)
                .completions,
            1
        );
    }

    fn pop_until_release(broker: &mut RequestBroker, id: RequestId) {
        loop {
            match broker.pop_action().unwrap() {
                Some(RequestAction::ReleaseResources { id: action_id, .. }) if action_id == id => {
                    return;
                }
                Some(_) => {}
                None => panic!("missing release action"),
            }
        }
    }

    #[test]
    fn submit_owns_prepared_buffers_control_and_metadata() {
        let mut broker = broker(2);
        let mut request = prepared(1, 2, 9);
        request.buffers.push(PreparedRequestBuffer::Pinned {
            flags: RequestBufferFlags::WRITE,
            owner_process_id: 1,
            pages: vec![PinnedUserPage {
                virtual_start: 0x8000,
                physical_start: 0x18000,
                page_offset: 0,
                byte_length: 16,
                permissions: UserPagePermissions::READ_WRITE,
                access: UserAccess::Write,
            }],
        });
        let submission = broker.submit(request, 10).unwrap();

        assert_eq!(submission.control.request_id(), submission.id.raw());
        assert_eq!(broker.target(submission.id), Some(RequestTarget(9)));
        assert_eq!(broker.buffers(submission.id).unwrap().len(), 2);
        assert_eq!(broker.total_requested_bytes(submission.id), Some(20));
        assert_eq!(
            broker.info(submission.id).unwrap().request_state(),
            Some(RequestState::Pending)
        );
        let dispatch = broker.next_dispatch(12).unwrap();
        assert_eq!(dispatch.id, submission.id);
        assert_eq!(dispatch.service_payload.operation_argument, 0x1234);
        assert_eq!(dispatch.resources.pinned_pages, 1);
    }

    #[test]
    fn repeated_chunk_requeue_is_fair_and_preserves_checked_progress() {
        let mut broker = broker(2);
        let first = broker.submit(prepared(1, 1, 7), 0).unwrap();
        let second = broker.submit(prepared(2, 1, 7), 0).unwrap();

        assert_eq!(broker.next_dispatch(1).unwrap().id, first.id);
        assert_eq!(broker.total_requested_bytes(first.id), Some(4));
        assert_eq!(broker.service_offset(first.id), Some(0));
        assert_eq!(broker.advance_service_offset(first.id, 1), Ok(1));
        broker.requeue_active(first.id).unwrap();
        assert_eq!(
            broker.info(first.id).unwrap().request_state(),
            Some(RequestState::Pending)
        );
        assert_eq!(
            broker.advance_service_offset(first.id, 1),
            Err(BrokerError::Runtime(RequestError::InvalidState))
        );

        assert_eq!(broker.next_dispatch(2).unwrap().id, second.id);
        assert_eq!(broker.advance_service_offset(second.id, 2), Ok(2));
        broker.requeue_active(second.id).unwrap();
        assert_eq!(broker.next_dispatch(3).unwrap().id, first.id);
        assert_eq!(broker.advance_service_offset(first.id, 3), Ok(4));
        assert_eq!(
            broker.advance_service_offset(first.id, 1),
            Err(BrokerError::ResourceOverflow)
        );
        assert_eq!(broker.service_offset(first.id), Some(4));
        assert_eq!(broker.info(first.id).unwrap().started_ns, 1);
    }

    #[test]
    fn deadline_and_cancel_can_finish_between_broker_chunks() {
        let mut deadline_broker = broker(1);
        let mut request = prepared(1, 1, 1);
        request.deadline_ns = Some(10);
        let deadline = deadline_broker.submit(request, 0).unwrap();
        deadline_broker.next_dispatch(1).unwrap();
        deadline_broker
            .advance_service_offset(deadline.id, 1)
            .unwrap();
        deadline_broker.requeue_active(deadline.id).unwrap();
        deadline_broker.run_worker(10, RequestWorkerBudget::DEFAULT);
        assert_eq!(
            deadline_broker.info(deadline.id).unwrap().request_state(),
            Some(RequestState::TimedOut)
        );
        assert_eq!(deadline_broker.service_offset(deadline.id), Some(1));

        let mut cancel_broker = broker(1);
        let cancel = cancel_broker.submit(prepared(1, 1, 1), 0).unwrap();
        cancel_broker.next_dispatch(1).unwrap();
        cancel_broker.advance_service_offset(cancel.id, 2).unwrap();
        cancel_broker.requeue_active(cancel.id).unwrap();
        cancel_broker.cancel(cancel.id, 2).unwrap();
        assert_eq!(
            cancel_broker.info(cancel.id).unwrap().request_state(),
            Some(RequestState::Canceled)
        );
        assert_eq!(cancel_broker.service_offset(cancel.id), Some(2));
    }

    #[test]
    fn target_lease_must_match_filesystem_operation_and_target() {
        let mut broker = broker(1);
        let mut request = prepared(1, 1, 7);
        request.operation = RequestOperation::FilesystemRead;
        let failure = broker.submit(request, 0).unwrap_err();
        assert_eq!(failure.error, BrokerError::ActionMismatch);

        let mut sync = prepared(1, 1, 7);
        sync.operation = RequestOperation::FilesystemSync;
        sync.target_lease = PreparedRequestTarget::FilesystemSync;
        sync.buffers.clear();
        assert!(broker.submit(sync, 0).is_ok());
    }

    #[test]
    fn filesystem_open_requires_matching_directory_target_with_read_rights() {
        let mut filesystem = RedoxFs::new().unwrap();
        let root = filesystem.root_directory().unwrap();
        let directory = filesystem
            .create_directory_at(root, "request-open-target")
            .unwrap();

        let mut missing_target = prepared(1, 1, directory_request_target(Some(directory)).0);
        missing_target.operation = RequestOperation::FilesystemOpen;
        assert_eq!(missing_target.resources(), Err(BrokerError::ActionMismatch));

        let no_read = prepared_open(1, 1, Some(directory), false, Rights::WRITE);
        assert_eq!(no_read.resources(), Err(BrokerError::ActionMismatch));

        let mut mismatched = prepared_open(1, 1, Some(directory), false, Rights::READ);
        mismatched.target = RequestTarget(u64::MAX);
        assert_eq!(mismatched.resources(), Err(BrokerError::ActionMismatch));

        let wrong_operation = PreparedBrokerRequest {
            operation: RequestOperation::Synthetic,
            ..prepared_open(1, 1, Some(directory), false, Rights::READ | Rights::WRITE)
        };
        assert_eq!(
            wrong_operation.resources(),
            Err(BrokerError::ActionMismatch)
        );

        assert!(prepared_open(1, 1, Some(directory), false, Rights::READ)
            .resources()
            .is_ok());
        assert!(
            prepared_open(1, 1, None, true, Rights::READ | Rights::WRITE)
                .resources()
                .is_ok()
        );
    }

    #[test]
    fn directory_target_survives_source_handle_close_until_release() {
        let mut filesystem = RedoxFs::new().unwrap();
        let root = filesystem.root_directory().unwrap();
        let directory = filesystem
            .create_directory_at(root, "request-directory-target-lease")
            .unwrap();
        let rights = Rights::READ | Rights::WRITE;
        let mut handles = HandleTable::new();
        let handle = handles
            .filesystem_directory_create(directory, rights)
            .unwrap();
        let retained_directory = handles.filesystem_directory(handle, Rights::READ).unwrap();

        let request = prepared_open(1, 1, Some(retained_directory), false, rights);
        let mut broker = broker(1);
        let submission = broker.submit(request, 0).unwrap();
        handles.handle_close(handle).unwrap();

        assert_eq!(
            broker.directory_target(submission.id),
            Some((Some(directory), false, rights))
        );
        broker.cancel(submission.id, 1).unwrap();
        pop_until_release(&mut broker, submission.id);
        assert_eq!(
            broker.directory_target(submission.id),
            Some((Some(directory), false, rights))
        );
        broker.take_external_resources(submission.id).unwrap();
        assert_eq!(broker.directory_target(submission.id), None);
    }

    #[test]
    fn file_target_lease_survives_source_handle_close_until_release() {
        let mut filesystem = RedoxFs::new().unwrap();
        let file = filesystem.create("/request-target-lease").unwrap();
        let mut handles = HandleTable::new();
        let handle = handles.filesystem_file_create(file, Rights::READ).unwrap();
        let leased_file = handles.filesystem_file(handle, Rights::READ).unwrap();

        let mut request = prepared(1, 1, file_request_target(file).0);
        request.operation = RequestOperation::FilesystemRead;
        request.target_lease = PreparedRequestTarget::File(FileCapabilityLease::new(leased_file));
        request.buffers[0] = PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::WRITE,
            user_address: 0x4000,
            bytes: vec![0; 4],
        };
        let mut broker = broker(1);
        let submission = broker.submit(request, 0).unwrap();
        handles.handle_close(handle).unwrap();

        assert_eq!(broker.file_target(submission.id), Some(&file));
        broker.cancel(submission.id, 1).unwrap();
        pop_until_release(&mut broker, submission.id);
        assert_eq!(broker.file_target(submission.id), Some(&file));
        broker.take_external_resources(submission.id).unwrap();
        assert_eq!(broker.file_target(submission.id), None);
    }

    #[test]
    fn terminal_action_publishes_waitable_control_once() {
        let mut broker = broker(1);
        let submission = broker.submit(prepared(1, 1, 1), 5).unwrap();
        broker.next_dispatch(6).unwrap();
        complete(&mut broker, submission.id, 20, 4);

        let action = broker.pop_action().unwrap().unwrap();
        assert!(matches!(action, RequestAction::PublishTerminal { .. }));
        let info = submission.control.info();
        assert_eq!(info.request_state(), Some(RequestState::Completed));
        assert_eq!(info.bytes_transferred, 4);
        assert!(!broker
            .publish_terminal(submission.id, RequestState::Completed, Status::Ok, 20)
            .unwrap());
    }

    #[test]
    fn pending_cancellation_is_terminal_and_releasable() {
        let mut broker = broker(1);
        let submission = broker.submit(prepared(1, 1, 1), 0).unwrap();
        broker.cancel(submission.id, 5).unwrap();
        pop_until_release(&mut broker, submission.id);

        assert_eq!(
            submission.control.info().request_state(),
            Some(RequestState::Canceled)
        );
        let released = broker.take_external_resources(submission.id).unwrap();
        assert_eq!(released.buffers.len(), 1);
        assert!(broker.is_system_drained());
    }

    #[test]
    fn timed_out_device_owned_resources_wait_for_late_drain() {
        let mut broker = broker(1);
        let mut request = prepared(1, 1, 1);
        request.deadline_ns = Some(10);
        let submission = broker.submit(request, 0).unwrap();
        broker.next_dispatch(1).unwrap();
        broker.mark_device_owned(submission.id).unwrap();
        assert_eq!(
            broker
                .run_worker(10, RequestWorkerBudget::DEFAULT)
                .deadlines,
            1
        );

        while broker.pop_action().unwrap().is_some() {}
        assert_eq!(
            submission.control.info().request_state(),
            Some(RequestState::TimedOut)
        );
        assert_eq!(
            broker.take_external_resources(submission.id).err(),
            Some(BrokerError::ReleaseNotDispatched)
        );

        broker
            .record_completion(BrokerCompletion {
                id: submission.id,
                status: Status::Canceled,
                device_released: true,
                bytes_transferred: 0,
                result_flags: RequestResultFlags::empty(),
            })
            .unwrap();
        broker.run_worker(20, RequestWorkerBudget::DEFAULT);
        pop_until_release(&mut broker, submission.id);
        assert_eq!(
            broker
                .take_external_resources(submission.id)
                .unwrap()
                .buffers
                .len(),
            1
        );
    }

    #[test]
    fn owner_process_termination_publishes_and_releases_pending_work() {
        let mut broker = broker(2);
        let first = broker.submit(prepared(7, 1, 1), 0).unwrap();
        let second = broker.submit(prepared(7, 2, 2), 0).unwrap();
        assert_eq!(broker.terminate_process(7, 8), 2);

        let mut releases = Vec::new();
        while let Some(action) = broker.pop_action().unwrap() {
            if let RequestAction::ReleaseResources { id, .. } = action {
                releases.push(id);
            }
        }
        assert_eq!(
            first.control.info().request_state(),
            Some(RequestState::OwnerTerminated)
        );
        assert_eq!(
            second.control.info().request_state(),
            Some(RequestState::OwnerTerminated)
        );
        for id in releases {
            broker.take_external_resources(id).unwrap();
        }
        assert!(broker.is_process_drained(7));
    }

    #[test]
    fn external_resources_can_be_taken_only_once() {
        let mut broker = broker(1);
        let submission = broker.submit(prepared(1, 1, 1), 0).unwrap();
        broker.next_dispatch(1).unwrap();
        complete(&mut broker, submission.id, 2, 4);
        pop_until_release(&mut broker, submission.id);

        broker.take_external_resources(submission.id).unwrap();
        assert_eq!(
            broker.take_external_resources(submission.id).err(),
            Some(BrokerError::InvalidRequest)
        );
    }

    #[test]
    fn diagnostics_map_runtime_latency_counts_and_bytes() {
        let mut broker = broker(1);
        let submission = broker.submit(prepared(1, 1, 1), 10).unwrap();
        broker.next_dispatch(15).unwrap();
        complete(&mut broker, submission.id, 25, 3);
        pop_until_release(&mut broker, submission.id);

        let diagnostics = broker.diagnostics();
        assert_eq!(diagnostics.version, REQUEST_DIAGNOSTICS_VERSION);
        assert_eq!(diagnostics.completed_requests, 1);
        assert_eq!(diagnostics.bytes_transferred, 3);
        assert_eq!(diagnostics.total_wait_latency_ns, 5);
        assert_eq!(diagnostics.total_service_latency_ns, 10);
    }

    #[test]
    fn retired_ids_are_stale_after_slot_reuse() {
        let mut broker = broker(1);
        let old = broker.submit(prepared(1, 1, 1), 0).unwrap().id;
        broker.cancel(old, 1).unwrap();
        pop_until_release(&mut broker, old);
        broker.take_external_resources(old).unwrap();

        let new = broker.submit(prepared(1, 1, 1), 2).unwrap().id;
        assert_ne!(old, new);
        assert_eq!(
            broker.cancel(old, 3).err(),
            Some(BrokerError::Runtime(RequestError::InvalidRequest))
        );
        assert!(broker.info(old).is_none());
        assert!(broker.info(new).is_some());
    }

    #[test]
    fn batch_submission_is_atomic_when_runtime_rejects_it() {
        let mut broker = broker(2);
        let mut first = prepared(1, 1, 1);
        let mut second = prepared(1, 1, 2);
        first.buffers[0] = PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::READ,
            user_address: 0x1000,
            bytes: vec![0; 65],
        };
        second.buffers[0] = PreparedRequestBuffer::Copied {
            flags: RequestBufferFlags::READ,
            user_address: 0x2000,
            bytes: vec![0; 65],
        };
        let failure = broker.submit_batch(vec![first, second], 0).unwrap_err();
        assert_eq!(
            failure.error,
            BrokerError::Runtime(RequestError::CopiedBytesLimit)
        );
        assert_eq!(failure.requests.len(), 2);
        assert!(broker.is_system_drained());
    }
}
