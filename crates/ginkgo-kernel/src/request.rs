//! Boot-preallocated asynchronous kernel request scheduling and completion.
//!
//! The runtime owns request identity, queueing, deadlines, logical outcomes, and
//! resource-drain bookkeeping. It deliberately does not own process page-pin or
//! IPC completion objects. Instead, it emits bounded [`RequestAction`] values for
//! the integration layer to publish terminal state, ask a device to cancel, and
//! release the request's external resource leases.
//!
//! Submission may allocate while constructing caller-owned request metadata, but
//! [`RequestRuntime::try_new_with_limits`] reserves all runtime storage. Completion,
//! cancellation, deadline, lifecycle, action, and dispatch paths do not grow a
//! collection after construction.

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};

use ginkgo_sysapi::{RequestState, Status};

/// Default number of live requests retained system-wide.
pub const REQUEST_SYSTEM_CAPACITY: usize = 1024;
/// Default number of requests retained for one process owner.
pub const REQUESTS_PER_OWNER_LIMIT: usize = 64;
/// Default number of requests retained for one target object.
pub const REQUESTS_PER_TARGET_LIMIT: usize = 32;
/// Maximum requests accepted by one atomic batch.
pub const REQUEST_MAX_BATCH: usize = 16;
/// Maximum copied input bytes retained by one request.
pub const REQUEST_COPIED_BYTES_LIMIT: usize = 16 * 1024;
/// Maximum copied input bytes retained for one owner.
pub const REQUEST_COPIED_BYTES_PER_OWNER: usize = 256 * 1024;
/// Maximum copied input bytes retained system-wide.
pub const REQUEST_COPIED_BYTES_SYSTEM: usize = 4 * 1024 * 1024;
/// Maximum pinned pages retained by one request.
pub const REQUEST_PINNED_PAGES_LIMIT: usize = 64;
/// Maximum pinned pages retained for one owner.
pub const REQUEST_PINNED_PAGES_PER_OWNER: usize = 256;
/// Maximum pinned pages retained system-wide.
pub const REQUEST_PINNED_PAGES_SYSTEM: usize = 4096;
/// Maximum shared-memory bytes retained by one request.
pub const REQUEST_SHARED_BYTES_LIMIT: usize = 1024 * 1024;
/// Maximum shared-memory bytes retained for one owner.
pub const REQUEST_SHARED_BYTES_PER_OWNER: usize = 4 * 1024 * 1024;
/// Maximum shared-memory bytes retained system-wide.
pub const REQUEST_SHARED_BYTES_SYSTEM: usize = 32 * 1024 * 1024;
/// Default deferred completion records retained until worker context drains them.
pub const REQUEST_DEFERRED_COMPLETION_CAPACITY: usize = 1024;
/// Default number of completion records handled by one worker call.
pub const REQUEST_COMPLETION_WORK_BUDGET: usize = 32;
/// Default number of expired deadlines handled by one worker call.
pub const REQUEST_DEADLINE_WORK_BUDGET: usize = 32;

const REQUEST_INDEX_BITS: u32 = 32;
const REQUEST_INDEX_MASK: u64 = u32::MAX as u64;
const ACTIONS_PER_REQUEST: usize = 3;

/// Stable generation-tagged identity used by workers and device completion records.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(u64);

impl RequestId {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.generation() != 0 && self.encoded_index() != 0
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> REQUEST_INDEX_BITS) as u32
    }

    const fn encoded_index(self) -> u32 {
        (self.0 & REQUEST_INDEX_MASK) as u32
    }

    const fn index(self) -> Option<usize> {
        let encoded = self.encoded_index();
        if encoded == 0 {
            None
        } else {
            Some((encoded - 1) as usize)
        }
    }

    fn from_parts(index: usize, generation: u32) -> Self {
        debug_assert!(generation != 0);
        debug_assert!(index < u32::MAX as usize);
        Self((u64::from(generation) << REQUEST_INDEX_BITS) | (index as u64 + 1))
    }
}

/// Process and thread that own request lifecycle and resource charges.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestOwner {
    pub process_id: u64,
    pub thread_id: u64,
}

impl RequestOwner {
    pub const fn new(process_id: u64, thread_id: u64) -> Self {
        Self {
            process_id,
            thread_id,
        }
    }
}

/// Opaque identity used to serialize requests against one target object.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestTarget(pub u64);

/// Opaque identity for the device or service that may own request resources.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestDevice(pub u32);

/// Bounded external resources retained by a request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestResources {
    pub copied_bytes: usize,
    pub pinned_pages: usize,
    pub shared_bytes: usize,
}

impl RequestResources {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            copied_bytes: self.copied_bytes.checked_add(other.copied_bytes)?,
            pinned_pages: self.pinned_pages.checked_add(other.pinned_pages)?,
            shared_bytes: self.shared_bytes.checked_add(other.shared_bytes)?,
        })
    }

    fn saturating_add(self, other: Self) -> Self {
        Self {
            copied_bytes: self.copied_bytes.saturating_add(other.copied_bytes),
            pinned_pages: self.pinned_pages.saturating_add(other.pinned_pages),
            shared_bytes: self.shared_bytes.saturating_add(other.shared_bytes),
        }
    }
}

/// Submission metadata copied and validated before publication to this runtime.
///
/// `O` identifies the operation and `P` carries service-specific scalar metadata.
/// Both stay abstract and [`Copy`] so this scheduler can serve unrelated kernel
/// subsystems without owning their buffers or allocating operation objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestSubmission<O: Copy, P: Copy> {
    pub owner: RequestOwner,
    pub target: RequestTarget,
    pub device: Option<RequestDevice>,
    pub operation: O,
    pub service_payload: P,
    pub deadline_ns: Option<u64>,
    pub resources: RequestResources,
}

/// Limits whose complete backing storage is reserved by runtime construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLimits {
    pub system_capacity: usize,
    pub per_owner_requests: usize,
    pub per_target_requests: usize,
    pub max_batch: usize,
    pub copied_bytes_per_request: usize,
    pub copied_bytes_per_owner: usize,
    pub copied_bytes_system: usize,
    pub pinned_pages_per_request: usize,
    pub pinned_pages_per_owner: usize,
    pub pinned_pages_system: usize,
    pub shared_bytes_per_request: usize,
    pub shared_bytes_per_owner: usize,
    pub shared_bytes_system: usize,
    pub deferred_completion_capacity: usize,
}

impl RequestLimits {
    pub const fn default_policy() -> Self {
        Self {
            system_capacity: REQUEST_SYSTEM_CAPACITY,
            per_owner_requests: REQUESTS_PER_OWNER_LIMIT,
            per_target_requests: REQUESTS_PER_TARGET_LIMIT,
            max_batch: REQUEST_MAX_BATCH,
            copied_bytes_per_request: REQUEST_COPIED_BYTES_LIMIT,
            copied_bytes_per_owner: REQUEST_COPIED_BYTES_PER_OWNER,
            copied_bytes_system: REQUEST_COPIED_BYTES_SYSTEM,
            pinned_pages_per_request: REQUEST_PINNED_PAGES_LIMIT,
            pinned_pages_per_owner: REQUEST_PINNED_PAGES_PER_OWNER,
            pinned_pages_system: REQUEST_PINNED_PAGES_SYSTEM,
            shared_bytes_per_request: REQUEST_SHARED_BYTES_LIMIT,
            shared_bytes_per_owner: REQUEST_SHARED_BYTES_PER_OWNER,
            shared_bytes_system: REQUEST_SHARED_BYTES_SYSTEM,
            deferred_completion_capacity: REQUEST_DEFERRED_COMPLETION_CAPACITY,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.system_capacity != 0
            && self.system_capacity < u32::MAX as usize
            && self.per_owner_requests != 0
            && self.per_owner_requests <= self.system_capacity
            && self.per_target_requests != 0
            && self.per_target_requests <= self.system_capacity
            && self.max_batch != 0
            && self.max_batch <= self.system_capacity
            && self.max_batch <= REQUEST_MAX_BATCH
            && self.copied_bytes_per_request <= self.copied_bytes_per_owner
            && self.copied_bytes_per_owner <= self.copied_bytes_system
            && self.pinned_pages_per_request <= self.pinned_pages_per_owner
            && self.pinned_pages_per_owner <= self.pinned_pages_system
            && self.shared_bytes_per_request <= self.shared_bytes_per_owner
            && self.shared_bytes_per_owner <= self.shared_bytes_system
            && self.deferred_completion_capacity != 0
    }
}

/// Runtime construction or request operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    InvalidLimits,
    OutOfMemory,
    Quiescing,
    EmptyBatch,
    BatchTooLarge,
    OutputTooSmall,
    SystemFull,
    OwnerLimit,
    TargetLimit,
    CopiedBytesLimit,
    PinnedPagesLimit,
    SharedBytesLimit,
    CompletionQueueFull,
    InvalidRequest,
    InvalidState,
    ReleaseNotDispatched,
}

/// Ownership of external resources, independent of the public logical result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestResourceState {
    KernelOwned,
    DeviceOwned,
    DrainPending,
    ReleasePending,
    Released,
}

/// Why a request needs service or device cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCancelReason {
    Explicit,
    Deadline,
    OwnerThreadTerminated,
    OwnerProcessTerminated,
    Shutdown,
}

/// Bounded work emitted to the kernel integration layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestAction {
    /// Publish this final logical result to the waitable completion object once.
    PublishTerminal {
        id: RequestId,
        state: RequestState,
        status: Status,
        completed_at_ns: u64,
    },
    /// Ask the service or device to cancel or drain one active request.
    CancelDevice {
        id: RequestId,
        device: Option<RequestDevice>,
        reason: RequestCancelReason,
    },
    /// Drop page pins, copied storage, shared leases, and target leases once.
    ReleaseResources {
        id: RequestId,
        owner: RequestOwner,
        resources: RequestResources,
    },
}

/// Request selected from a fair target rotation for service submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestDispatch<O: Copy, P: Copy> {
    pub id: RequestId,
    pub owner: RequestOwner,
    pub target: RequestTarget,
    pub device: Option<RequestDevice>,
    pub operation: O,
    pub service_payload: P,
    pub deadline_ns: Option<u64>,
    pub resources: RequestResources,
}

/// One completion copied from a bounded interrupt/deferred device record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferredCompletion {
    pub id: RequestId,
    pub status: Status,
    /// The device can no longer access request-owned pages when this is true.
    pub device_released: bool,
}

/// Bounded work allowed during one completion/deadline worker turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestWorkerBudget {
    pub completions: usize,
    pub deadlines: usize,
}

impl RequestWorkerBudget {
    pub const DEFAULT: Self = Self {
        completions: REQUEST_COMPLETION_WORK_BUDGET,
        deadlines: REQUEST_DEADLINE_WORK_BUDGET,
    };
}

/// Work performed by one bounded worker turn.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestWorkerReport {
    pub completions: usize,
    pub deadlines: usize,
    pub completion_budget_exhausted: bool,
    pub deadline_budget_exhausted: bool,
}

/// Publicly useful request state retained while the runtime slot remains live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestSnapshot<O: Copy, P: Copy> {
    pub id: RequestId,
    pub owner: RequestOwner,
    pub target: RequestTarget,
    pub device: Option<RequestDevice>,
    pub operation: O,
    pub service_payload: P,
    pub state: RequestState,
    pub resource_state: RequestResourceState,
    pub status: Status,
    pub deadline_ns: Option<u64>,
    pub submitted_at_ns: u64,
    pub started_at_ns: Option<u64>,
    pub completed_at_ns: Option<u64>,
    pub cancellation_requested: bool,
    pub cancellation_acknowledged: bool,
    pub terminal_publication_dispatched: bool,
    pub resource_release_dispatched: bool,
    pub resources: RequestResources,
}

/// Saturating lifetime counters and current bounded usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestRuntimeDiagnostics {
    pub live_requests: usize,
    pub peak_live_requests: usize,
    pub queued_requests: usize,
    pub peak_queued_requests: usize,
    pub active_requests: usize,
    pub peak_active_requests: usize,
    pub copied_bytes: usize,
    pub peak_copied_bytes: usize,
    pub pinned_pages: usize,
    pub peak_pinned_pages: usize,
    pub shared_bytes: usize,
    pub peak_shared_bytes: usize,
    pub deferred_completions: usize,
    pub peak_deferred_completions: usize,
    pub submissions: u64,
    pub batch_submissions: u64,
    pub batch_rollbacks: u64,
    pub dispatches: u64,
    pub completions: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub cancellation_requests: u64,
    pub cancellation_acknowledgements: u64,
    pub cancellation_lost_races: u64,
    pub owner_thread_terminations: u64,
    pub owner_process_terminations: u64,
    pub device_removals: u64,
    pub device_resets: u64,
    pub shutdowns: u64,
    pub rejected_quiescing: u64,
    pub rejected_system_full: u64,
    pub rejected_owner_limit: u64,
    pub rejected_target_limit: u64,
    pub rejected_copied_bytes: u64,
    pub rejected_pinned_pages: u64,
    pub rejected_shared_bytes: u64,
    pub rejected_completion_queue_full: u64,
    pub stale_completions: u64,
    pub duplicate_completions: u64,
    pub late_completions: u64,
    pub terminal_publications: u64,
    pub resource_release_actions: u64,
    pub resource_release_acknowledgements: u64,
    pub completion_budget_exhaustions: u64,
    pub deadline_budget_exhaustions: u64,
    pub maximum_queue_latency_ns: u64,
    pub cumulative_queue_latency_ns: u64,
    pub queue_latency_samples: u64,
    pub maximum_service_latency_ns: u64,
    pub cumulative_service_latency_ns: u64,
    pub service_latency_samples: u64,
}

#[derive(Clone, Copy, Debug)]
struct DeadlineEntry {
    deadline_ns: u64,
    id: RequestId,
}

impl DeadlineEntry {
    const fn ordering_key(self) -> (u64, u64) {
        (self.deadline_ns, self.id.raw())
    }
}

#[derive(Debug)]
struct TargetQueue {
    target: Option<RequestTarget>,
    active: Option<RequestId>,
    queued: VecDeque<RequestId>,
}

impl TargetQueue {
    fn try_vacant(capacity: usize) -> Result<Self, RequestError> {
        let mut queued = VecDeque::new();
        queued
            .try_reserve_exact(capacity)
            .map_err(|_| RequestError::OutOfMemory)?;
        Ok(Self {
            target: None,
            active: None,
            queued,
        })
    }

    fn is_idle(&self) -> bool {
        self.active.is_none() && self.queued.is_empty()
    }
}

struct RequestSlot<O: Copy, P: Copy> {
    generation: u32,
    retired: bool,
    request: Option<KernelRequest<O, P>>,
}

impl<O: Copy, P: Copy> RequestSlot<O, P> {
    const fn vacant() -> Self {
        Self {
            generation: 1,
            retired: false,
            request: None,
        }
    }
}

struct KernelRequest<O: Copy, P: Copy> {
    id: RequestId,
    owner: RequestOwner,
    target: RequestTarget,
    device: Option<RequestDevice>,
    operation: O,
    service_payload: P,
    state: RequestState,
    resource_state: RequestResourceState,
    status: Status,
    deadline_ns: Option<u64>,
    deadline_heap_index: Option<usize>,
    submitted_at_ns: u64,
    started_at_ns: Option<u64>,
    completed_at_ns: Option<u64>,
    resources: RequestResources,
    cancellation_requested: bool,
    cancellation_acknowledged: bool,
    cancel_action_queued: bool,
    cancel_action_dispatched: bool,
    terminal_action_queued: bool,
    terminal_publication_dispatched: bool,
    release_action_queued: bool,
    resource_release_dispatched: bool,
}

impl<O: Copy, P: Copy> KernelRequest<O, P> {
    fn snapshot(&self) -> RequestSnapshot<O, P> {
        RequestSnapshot {
            id: self.id,
            owner: self.owner,
            target: self.target,
            device: self.device,
            operation: self.operation,
            service_payload: self.service_payload,
            state: self.state,
            resource_state: self.resource_state,
            status: self.status,
            deadline_ns: self.deadline_ns,
            submitted_at_ns: self.submitted_at_ns,
            started_at_ns: self.started_at_ns,
            completed_at_ns: self.completed_at_ns,
            cancellation_requested: self.cancellation_requested,
            cancellation_acknowledged: self.cancellation_acknowledged,
            terminal_publication_dispatched: self.terminal_publication_dispatched,
            resource_release_dispatched: self.resource_release_dispatched,
            resources: self.resources,
        }
    }
}

/// Fixed-capacity request scheduler and exactly-once completion arbiter.
///
/// Operation and service payload values are retained inline in preallocated slots.
pub struct RequestRuntime<O: Copy, P: Copy> {
    limits: RequestLimits,
    slots: Vec<RequestSlot<O, P>>,
    targets: Vec<TargetQueue>,
    target_cursor: usize,
    deadlines: Vec<DeadlineEntry>,
    deferred_completions: VecDeque<DeferredCompletion>,
    actions: VecDeque<RequestAction>,
    accepting: bool,
    diagnostics: RequestRuntimeDiagnostics,
}

impl<O: Copy, P: Copy> RequestRuntime<O, P> {
    /// Reserves the default system capacity and every worker-path queue.
    pub fn try_new() -> Result<Self, RequestError> {
        Self::try_new_with_limits(RequestLimits::default_policy())
    }

    /// Reserves all storage needed by the supplied bounded policy.
    pub fn try_new_with_limits(limits: RequestLimits) -> Result<Self, RequestError> {
        if !limits.is_valid() {
            return Err(RequestError::InvalidLimits);
        }

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.system_capacity)
            .map_err(|_| RequestError::OutOfMemory)?;
        for _ in 0..limits.system_capacity {
            slots.push(RequestSlot::vacant());
        }

        let mut targets = Vec::new();
        targets
            .try_reserve_exact(limits.system_capacity)
            .map_err(|_| RequestError::OutOfMemory)?;
        for _ in 0..limits.system_capacity {
            targets.push(TargetQueue::try_vacant(limits.per_target_requests)?);
        }

        let mut deadlines = Vec::new();
        deadlines
            .try_reserve_exact(limits.system_capacity)
            .map_err(|_| RequestError::OutOfMemory)?;

        let mut deferred_completions = VecDeque::new();
        deferred_completions
            .try_reserve_exact(limits.deferred_completion_capacity)
            .map_err(|_| RequestError::OutOfMemory)?;

        let action_capacity = limits
            .system_capacity
            .checked_mul(ACTIONS_PER_REQUEST)
            .ok_or(RequestError::InvalidLimits)?;
        let mut actions = VecDeque::new();
        actions
            .try_reserve_exact(action_capacity)
            .map_err(|_| RequestError::OutOfMemory)?;

        Ok(Self {
            limits,
            slots,
            targets,
            target_cursor: 0,
            deadlines,
            deferred_completions,
            actions,
            accepting: true,
            diagnostics: RequestRuntimeDiagnostics::default(),
        })
    }

    pub const fn limits(&self) -> RequestLimits {
        self.limits
    }

    pub const fn is_accepting(&self) -> bool {
        self.accepting
    }

    pub fn diagnostics(&self) -> RequestRuntimeDiagnostics {
        let mut diagnostics = self.diagnostics;
        diagnostics.deferred_completions = self.deferred_completions.len();
        diagnostics
    }

    pub fn snapshot(&self, id: RequestId) -> Option<RequestSnapshot<O, P>> {
        self.request(id).map(KernelRequest::snapshot)
    }

    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.deadlines.first().map(|entry| entry.deadline_ns)
    }

    pub fn is_system_drained(&self) -> bool {
        self.diagnostics.live_requests == 0
    }

    pub fn is_process_drained(&self, process_id: u64) -> bool {
        !self.slots.iter().any(|slot| {
            slot.request
                .as_ref()
                .is_some_and(|request| request.owner.process_id == process_id)
        })
    }

    pub fn is_thread_drained(&self, owner: RequestOwner) -> bool {
        !self.slots.iter().any(|slot| {
            slot.request
                .as_ref()
                .is_some_and(|request| request.owner == owner)
        })
    }

    /// Atomically submits one already-copied and validated request.
    pub fn submit(
        &mut self,
        submission: RequestSubmission<O, P>,
        now_ns: u64,
    ) -> Result<RequestId, RequestError> {
        let mut output = [RequestId::INVALID; 1];
        self.submit_batch(core::slice::from_ref(&submission), &mut output, now_ns)?;
        Ok(output[0])
    }

    /// Preflights and atomically commits a bounded request batch.
    ///
    /// On any error no slot, queue, deadline, generation, or accounting value changes.
    pub fn submit_batch(
        &mut self,
        submissions: &[RequestSubmission<O, P>],
        output: &mut [RequestId],
        now_ns: u64,
    ) -> Result<(), RequestError> {
        if submissions.is_empty() {
            return Err(RequestError::EmptyBatch);
        }
        if submissions.len() > self.limits.max_batch {
            return Err(RequestError::BatchTooLarge);
        }
        if output.len() < submissions.len() {
            return Err(RequestError::OutputTooSmall);
        }
        if !self.accepting {
            self.diagnostics.rejected_quiescing =
                self.diagnostics.rejected_quiescing.saturating_add(1);
            self.diagnostics.batch_rollbacks = self.diagnostics.batch_rollbacks.saturating_add(1);
            return Err(RequestError::Quiescing);
        }

        if let Err(error) = self.preflight_batch(submissions) {
            self.record_rejection(error);
            self.diagnostics.batch_rollbacks = self.diagnostics.batch_rollbacks.saturating_add(1);
            return Err(error);
        }

        for (index, submission) in submissions.iter().copied().enumerate() {
            let slot_index = self
                .slots
                .iter()
                .position(|slot| slot.request.is_none() && !slot.retired)
                .expect("batch slot count was preflighted");
            let generation = self.slots[slot_index].generation;
            let id = RequestId::from_parts(slot_index, generation);
            let target_index = self
                .target_index_or_vacant(submission.target)
                .expect("batch target count was preflighted");
            if self.targets[target_index].target.is_none() {
                self.targets[target_index].target = Some(submission.target);
            }

            self.slots[slot_index].request = Some(KernelRequest {
                id,
                owner: submission.owner,
                target: submission.target,
                device: submission.device,
                operation: submission.operation,
                service_payload: submission.service_payload,
                state: RequestState::Pending,
                resource_state: RequestResourceState::KernelOwned,
                status: Status::ShouldWait,
                deadline_ns: submission.deadline_ns,
                deadline_heap_index: None,
                submitted_at_ns: now_ns,
                started_at_ns: None,
                completed_at_ns: None,
                resources: submission.resources,
                cancellation_requested: false,
                cancellation_acknowledged: false,
                cancel_action_queued: false,
                cancel_action_dispatched: false,
                terminal_action_queued: false,
                terminal_publication_dispatched: false,
                release_action_queued: false,
                resource_release_dispatched: false,
            });
            self.targets[target_index].queued.push_back(id);
            if let Some(deadline_ns) = submission.deadline_ns {
                self.push_deadline(DeadlineEntry { deadline_ns, id });
            }
            output[index] = id;
            self.charge_submission(submission.resources);
        }

        self.diagnostics.submissions = self
            .diagnostics
            .submissions
            .saturating_add(submissions.len() as u64);
        if submissions.len() > 1 {
            self.diagnostics.batch_submissions =
                self.diagnostics.batch_submissions.saturating_add(1);
        }
        Ok(())
    }

    /// Selects one target in round-robin order and starts its FIFO head.
    pub fn next_dispatch(&mut self, now_ns: u64) -> Option<RequestDispatch<O, P>> {
        if self.targets.is_empty() {
            return None;
        }
        for _ in 0..self.targets.len() {
            let index = self.target_cursor;
            self.target_cursor = (self.target_cursor + 1) % self.targets.len();
            if self.targets[index].active.is_some() {
                continue;
            }
            let Some(id) = self.targets[index].queued.pop_front() else {
                self.release_idle_target(index);
                continue;
            };
            let Some(slot_index) = self.valid_request_index(id) else {
                continue;
            };
            let request = self.slots[slot_index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            if request.state != RequestState::Pending {
                continue;
            }
            request.state = RequestState::Active;
            let first_dispatch = request.started_at_ns.is_none();
            if first_dispatch {
                request.started_at_ns = Some(now_ns);
            }
            self.targets[index].active = Some(id);
            self.diagnostics.queued_requests = self.diagnostics.queued_requests.saturating_sub(1);
            self.diagnostics.active_requests = self.diagnostics.active_requests.saturating_add(1);
            self.diagnostics.peak_active_requests = self
                .diagnostics
                .peak_active_requests
                .max(self.diagnostics.active_requests);
            self.diagnostics.dispatches = self.diagnostics.dispatches.saturating_add(1);
            if first_dispatch {
                let latency = now_ns.saturating_sub(request.submitted_at_ns);
                self.diagnostics.maximum_queue_latency_ns =
                    self.diagnostics.maximum_queue_latency_ns.max(latency);
                self.diagnostics.cumulative_queue_latency_ns = self
                    .diagnostics
                    .cumulative_queue_latency_ns
                    .saturating_add(latency);
                self.diagnostics.queue_latency_samples =
                    self.diagnostics.queue_latency_samples.saturating_add(1);
            }
            return Some(RequestDispatch {
                id,
                owner: request.owner,
                target: request.target,
                device: request.device,
                operation: request.operation,
                service_payload: request.service_payload,
                deadline_ns: request.deadline_ns,
                resources: request.resources,
            });
        }
        None
    }

    /// Yields an active kernel-owned request to the back of its target FIFO.
    ///
    /// The original deadline and first-start timestamp stay armed. All target queues
    /// reserve their limit at construction, so this transition does not allocate.
    pub fn requeue_active(&mut self, id: RequestId) -> Result<(), RequestError> {
        let slot_index = self
            .valid_request_index(id)
            .ok_or(RequestError::InvalidRequest)?;
        let target = {
            let request = self.slots[slot_index]
                .request
                .as_ref()
                .expect("validated request disappeared");
            if request.state != RequestState::Active
                || request.resource_state != RequestResourceState::KernelOwned
            {
                return Err(RequestError::InvalidState);
            }
            request.target
        };
        let target_index = self
            .target_index(target)
            .ok_or(RequestError::InvalidState)?;
        if self.targets[target_index].active != Some(id) {
            return Err(RequestError::InvalidState);
        }

        self.slots[slot_index]
            .request
            .as_mut()
            .expect("validated request disappeared")
            .state = RequestState::Pending;
        self.targets[target_index].active = None;
        debug_assert!(self.targets[target_index].queued.len() < self.limits.per_target_requests);
        self.targets[target_index].queued.push_back(id);
        self.diagnostics.active_requests = self.diagnostics.active_requests.saturating_sub(1);
        self.diagnostics.queued_requests = self.diagnostics.queued_requests.saturating_add(1);
        self.diagnostics.peak_queued_requests = self
            .diagnostics
            .peak_queued_requests
            .max(self.diagnostics.queued_requests);
        Ok(())
    }

    /// Marks that an active request's service or device can access retained resources.
    pub fn mark_device_owned(&mut self, id: RequestId) -> Result<(), RequestError> {
        let request = self.request_mut(id).ok_or(RequestError::InvalidRequest)?;
        if !matches!(
            request.state,
            RequestState::Active | RequestState::CancelPending
        ) || request.resource_state != RequestResourceState::KernelOwned
        {
            return Err(RequestError::InvalidState);
        }
        request.resource_state = RequestResourceState::DeviceOwned;
        Ok(())
    }

    /// Records completion without allocation; worker context applies it later.
    pub fn record_completion(
        &mut self,
        completion: DeferredCompletion,
    ) -> Result<(), RequestError> {
        if self.deferred_completions.len() >= self.limits.deferred_completion_capacity {
            self.diagnostics.rejected_completion_queue_full = self
                .diagnostics
                .rejected_completion_queue_full
                .saturating_add(1);
            return Err(RequestError::CompletionQueueFull);
        }
        self.deferred_completions.push_back(completion);
        self.diagnostics.peak_deferred_completions = self
            .diagnostics
            .peak_deferred_completions
            .max(self.deferred_completions.len());
        Ok(())
    }

    /// Drains completions before inclusive deadlines, within explicit budgets.
    ///
    /// Deadlines are skipped while an older recorded completion remains queued. This
    /// guarantees that a completion already visible to the runtime wins over an equal
    /// inclusive deadline even when the completion budget is exhausted.
    pub fn run_worker(&mut self, now_ns: u64, budget: RequestWorkerBudget) -> RequestWorkerReport {
        let mut report = RequestWorkerReport::default();
        while report.completions < budget.completions {
            let Some(completion) = self.deferred_completions.pop_front() else {
                break;
            };
            report.completions += 1;
            self.apply_completion(completion, now_ns);
        }
        if !self.deferred_completions.is_empty() {
            report.completion_budget_exhausted = true;
            self.diagnostics.completion_budget_exhaustions = self
                .diagnostics
                .completion_budget_exhaustions
                .saturating_add(1);
            return report;
        }

        while report.deadlines < budget.deadlines {
            let Some(entry) = self.deadlines.first().copied() else {
                break;
            };
            if entry.deadline_ns > now_ns {
                break;
            }
            self.remove_deadline_at(0);
            report.deadlines += 1;
            self.apply_timeout(entry.id, now_ns);
        }
        if self
            .deadlines
            .first()
            .is_some_and(|entry| entry.deadline_ns <= now_ns)
        {
            report.deadline_budget_exhausted = true;
            self.diagnostics.deadline_budget_exhaustions = self
                .diagnostics
                .deadline_budget_exhaustions
                .saturating_add(1);
        }
        report
    }

    /// Requests cancellation. Pending requests acknowledge immediately; active
    /// requests wait for [`Self::acknowledge_cancel`] or normal completion.
    pub fn cancel(&mut self, id: RequestId, now_ns: u64) -> Result<(), RequestError> {
        self.request_cancel(id, RequestCancelReason::Explicit, now_ns)
    }

    /// Acknowledges cancellation and optionally proves that device ownership ended.
    pub fn acknowledge_cancel(
        &mut self,
        id: RequestId,
        now_ns: u64,
        device_stopped: bool,
    ) -> Result<(), RequestError> {
        let index = self
            .valid_request_index(id)
            .ok_or(RequestError::InvalidRequest)?;
        {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            if !request.cancellation_requested {
                return Err(RequestError::InvalidState);
            }
            if !request.cancellation_acknowledged {
                request.cancellation_acknowledged = true;
                self.diagnostics.cancellation_acknowledgements = self
                    .diagnostics
                    .cancellation_acknowledgements
                    .saturating_add(1);
            }
            if device_stopped
                && matches!(
                    request.resource_state,
                    RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
                )
            {
                request.resource_state = RequestResourceState::KernelOwned;
            }
        }

        if self
            .request(id)
            .is_some_and(|request| request.state == RequestState::CancelPending)
        {
            self.finish_terminal(id, RequestState::Canceled, Status::Canceled, now_ns);
        } else {
            self.queue_release_if_possible(id);
        }
        Ok(())
    }

    /// Proves that a late completion, reset, or bus-master stop ended device access.
    pub fn acknowledge_drain(&mut self, id: RequestId) -> Result<(), RequestError> {
        let request = self.request_mut(id).ok_or(RequestError::InvalidRequest)?;
        if !matches!(
            request.resource_state,
            RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
        ) {
            return Err(RequestError::InvalidState);
        }
        request.resource_state = RequestResourceState::KernelOwned;
        self.release_target_if_safe(id);
        self.queue_release_if_possible(id);
        Ok(())
    }

    /// Marks all requests owned by one thread as owner-terminated.
    pub fn terminate_thread(&mut self, owner: RequestOwner, now_ns: u64) -> usize {
        self.diagnostics.owner_thread_terminations =
            self.diagnostics.owner_thread_terminations.saturating_add(1);
        self.terminate_matching(
            |request| request.owner == owner,
            RequestCancelReason::OwnerThreadTerminated,
            now_ns,
        )
    }

    /// Marks all requests owned by one process as owner-terminated.
    pub fn terminate_process(&mut self, process_id: u64, now_ns: u64) -> usize {
        self.diagnostics.owner_process_terminations = self
            .diagnostics
            .owner_process_terminations
            .saturating_add(1);
        self.terminate_matching(
            |request| request.owner.process_id == process_id,
            RequestCancelReason::OwnerProcessTerminated,
            now_ns,
        )
    }

    /// Fails requests for a removed device. Resources are releasable immediately
    /// only when the caller has already stopped DMA or bus mastering.
    pub fn remove_device(
        &mut self,
        device: RequestDevice,
        now_ns: u64,
        ownership_stopped: bool,
    ) -> usize {
        self.diagnostics.device_removals = self.diagnostics.device_removals.saturating_add(1);
        self.fail_device(device, now_ns, ownership_stopped)
    }

    /// Fails requests for a reset device after reset has stopped old DMA ownership.
    pub fn reset_device(&mut self, device: RequestDevice, now_ns: u64) -> usize {
        self.diagnostics.device_resets = self.diagnostics.device_resets.saturating_add(1);
        self.fail_device(device, now_ns, true)
    }

    /// Rejects new work, cancels queued work, and asks active work to drain.
    pub fn begin_shutdown(&mut self, now_ns: u64) -> usize {
        self.accepting = false;
        self.diagnostics.shutdowns = self.diagnostics.shutdowns.saturating_add(1);
        let mut affected = 0usize;
        for index in 0..self.slots.len() {
            let Some(id) = self.slots[index].request.as_ref().map(|request| request.id) else {
                continue;
            };
            if self
                .request(id)
                .is_some_and(|request| !is_terminal(request.state))
            {
                if self
                    .request_cancel(id, RequestCancelReason::Shutdown, now_ns)
                    .is_ok()
                {
                    affected += 1;
                }
            }
        }
        affected
    }

    /// Reopens submission after an orderly shutdown request was canceled.
    /// Canceled requests are not resurrected.
    pub fn resume_after_shutdown_cancel(&mut self) {
        self.accepting = true;
    }

    /// Pops one preallocated integration action.
    pub fn next_action(&mut self) -> Option<RequestAction> {
        let action = self.actions.pop_front()?;
        let id = match action {
            RequestAction::PublishTerminal { id, .. }
            | RequestAction::CancelDevice { id, .. }
            | RequestAction::ReleaseResources { id, .. } => id,
        };
        if let Some(request) = self.request_mut(id) {
            match action {
                RequestAction::PublishTerminal { .. } => {
                    request.terminal_action_queued = false;
                    request.terminal_publication_dispatched = true;
                    self.diagnostics.terminal_publications =
                        self.diagnostics.terminal_publications.saturating_add(1);
                }
                RequestAction::CancelDevice { .. } => {
                    request.cancel_action_queued = false;
                    request.cancel_action_dispatched = true;
                }
                RequestAction::ReleaseResources { .. } => {
                    request.release_action_queued = false;
                    request.resource_release_dispatched = true;
                    self.diagnostics.resource_release_actions =
                        self.diagnostics.resource_release_actions.saturating_add(1);
                }
            }
        }
        self.try_retire(id);
        Some(action)
    }

    /// Confirms that the integration layer performed one emitted release action.
    pub fn acknowledge_resource_release(&mut self, id: RequestId) -> Result<(), RequestError> {
        let resources = {
            let request = self.request_mut(id).ok_or(RequestError::InvalidRequest)?;
            if !request.resource_release_dispatched {
                return Err(RequestError::ReleaseNotDispatched);
            }
            if request.resource_state == RequestResourceState::Released {
                return Err(RequestError::InvalidState);
            }
            request.resource_state = RequestResourceState::Released;
            request.resources
        };
        self.uncharge_resources(resources);
        self.diagnostics.resource_release_acknowledgements = self
            .diagnostics
            .resource_release_acknowledgements
            .saturating_add(1);
        self.try_retire(id);
        Ok(())
    }

    fn preflight_batch(&self, submissions: &[RequestSubmission<O, P>]) -> Result<(), RequestError> {
        let vacant_slots = self
            .slots
            .iter()
            .filter(|slot| slot.request.is_none() && !slot.retired)
            .count();
        if submissions.len() > vacant_slots
            || self
                .diagnostics
                .live_requests
                .checked_add(submissions.len())
                .is_none_or(|count| count > self.limits.system_capacity)
        {
            return Err(RequestError::SystemFull);
        }

        let mut batch_resources = RequestResources::default();
        for submission in submissions {
            if submission.resources.copied_bytes > self.limits.copied_bytes_per_request {
                return Err(RequestError::CopiedBytesLimit);
            }
            if submission.resources.pinned_pages > self.limits.pinned_pages_per_request {
                return Err(RequestError::PinnedPagesLimit);
            }
            if submission.resources.shared_bytes > self.limits.shared_bytes_per_request {
                return Err(RequestError::SharedBytesLimit);
            }
            batch_resources = batch_resources
                .checked_add(submission.resources)
                .ok_or(RequestError::SystemFull)?;
        }

        let system_resources = RequestResources {
            copied_bytes: self.diagnostics.copied_bytes,
            pinned_pages: self.diagnostics.pinned_pages,
            shared_bytes: self.diagnostics.shared_bytes,
        }
        .checked_add(batch_resources)
        .ok_or(RequestError::SystemFull)?;
        if system_resources.copied_bytes > self.limits.copied_bytes_system {
            return Err(RequestError::CopiedBytesLimit);
        }
        if system_resources.pinned_pages > self.limits.pinned_pages_system {
            return Err(RequestError::PinnedPagesLimit);
        }
        if system_resources.shared_bytes > self.limits.shared_bytes_system {
            return Err(RequestError::SharedBytesLimit);
        }

        for (batch_index, submission) in submissions.iter().enumerate() {
            if submissions[..batch_index]
                .iter()
                .any(|previous| previous.owner == submission.owner)
            {
                continue;
            }
            let (existing_count, existing_resources) = self.owner_usage(submission.owner);
            let mut batch_count = 0usize;
            let mut owner_resources = existing_resources;
            for candidate in submissions
                .iter()
                .filter(|candidate| candidate.owner == submission.owner)
            {
                batch_count = batch_count.saturating_add(1);
                owner_resources = owner_resources
                    .checked_add(candidate.resources)
                    .ok_or(RequestError::OwnerLimit)?;
            }
            if existing_count.saturating_add(batch_count) > self.limits.per_owner_requests {
                return Err(RequestError::OwnerLimit);
            }
            if owner_resources.copied_bytes > self.limits.copied_bytes_per_owner {
                return Err(RequestError::CopiedBytesLimit);
            }
            if owner_resources.pinned_pages > self.limits.pinned_pages_per_owner {
                return Err(RequestError::PinnedPagesLimit);
            }
            if owner_resources.shared_bytes > self.limits.shared_bytes_per_owner {
                return Err(RequestError::SharedBytesLimit);
            }
        }

        let mut new_targets = 0usize;
        for (batch_index, submission) in submissions.iter().enumerate() {
            if submissions[..batch_index]
                .iter()
                .any(|previous| previous.target == submission.target)
            {
                continue;
            }
            let existing = self.target_request_count(submission.target);
            let batch = submissions
                .iter()
                .filter(|candidate| candidate.target == submission.target)
                .count();
            if existing.saturating_add(batch) > self.limits.per_target_requests {
                return Err(RequestError::TargetLimit);
            }
            if self.target_index(submission.target).is_none() {
                new_targets += 1;
            }
        }
        let vacant_targets = self
            .targets
            .iter()
            .filter(|target| target.target.is_none())
            .count();
        if new_targets > vacant_targets {
            return Err(RequestError::SystemFull);
        }
        Ok(())
    }

    fn owner_usage(&self, owner: RequestOwner) -> (usize, RequestResources) {
        self.slots
            .iter()
            .filter_map(|slot| slot.request.as_ref())
            .fold(
                (0usize, RequestResources::default()),
                |(count, resources), request| {
                    if request.owner == owner {
                        let charged = if request.resource_state == RequestResourceState::Released {
                            RequestResources::default()
                        } else {
                            request.resources
                        };
                        (count.saturating_add(1), resources.saturating_add(charged))
                    } else {
                        (count, resources)
                    }
                },
            )
    }

    fn target_request_count(&self, target: RequestTarget) -> usize {
        self.slots
            .iter()
            .filter_map(|slot| slot.request.as_ref())
            .filter(|request| request.target == target)
            .count()
    }

    fn target_index(&self, target: RequestTarget) -> Option<usize> {
        self.targets
            .iter()
            .position(|queue| queue.target == Some(target))
    }

    fn target_index_or_vacant(&self, target: RequestTarget) -> Option<usize> {
        self.target_index(target)
            .or_else(|| self.targets.iter().position(|queue| queue.target.is_none()))
    }

    fn charge_submission(&mut self, resources: RequestResources) {
        self.diagnostics.live_requests = self.diagnostics.live_requests.saturating_add(1);
        self.diagnostics.peak_live_requests = self
            .diagnostics
            .peak_live_requests
            .max(self.diagnostics.live_requests);
        self.diagnostics.queued_requests = self.diagnostics.queued_requests.saturating_add(1);
        self.diagnostics.peak_queued_requests = self
            .diagnostics
            .peak_queued_requests
            .max(self.diagnostics.queued_requests);
        self.diagnostics.copied_bytes = self
            .diagnostics
            .copied_bytes
            .saturating_add(resources.copied_bytes);
        self.diagnostics.peak_copied_bytes = self
            .diagnostics
            .peak_copied_bytes
            .max(self.diagnostics.copied_bytes);
        self.diagnostics.pinned_pages = self
            .diagnostics
            .pinned_pages
            .saturating_add(resources.pinned_pages);
        self.diagnostics.peak_pinned_pages = self
            .diagnostics
            .peak_pinned_pages
            .max(self.diagnostics.pinned_pages);
        self.diagnostics.shared_bytes = self
            .diagnostics
            .shared_bytes
            .saturating_add(resources.shared_bytes);
        self.diagnostics.peak_shared_bytes = self
            .diagnostics
            .peak_shared_bytes
            .max(self.diagnostics.shared_bytes);
    }

    fn uncharge_resources(&mut self, resources: RequestResources) {
        self.diagnostics.copied_bytes = self
            .diagnostics
            .copied_bytes
            .saturating_sub(resources.copied_bytes);
        self.diagnostics.pinned_pages = self
            .diagnostics
            .pinned_pages
            .saturating_sub(resources.pinned_pages);
        self.diagnostics.shared_bytes = self
            .diagnostics
            .shared_bytes
            .saturating_sub(resources.shared_bytes);
    }

    fn record_rejection(&mut self, error: RequestError) {
        match error {
            RequestError::SystemFull => {
                self.diagnostics.rejected_system_full =
                    self.diagnostics.rejected_system_full.saturating_add(1);
            }
            RequestError::OwnerLimit => {
                self.diagnostics.rejected_owner_limit =
                    self.diagnostics.rejected_owner_limit.saturating_add(1);
            }
            RequestError::TargetLimit => {
                self.diagnostics.rejected_target_limit =
                    self.diagnostics.rejected_target_limit.saturating_add(1);
            }
            RequestError::CopiedBytesLimit => {
                self.diagnostics.rejected_copied_bytes =
                    self.diagnostics.rejected_copied_bytes.saturating_add(1);
            }
            RequestError::PinnedPagesLimit => {
                self.diagnostics.rejected_pinned_pages =
                    self.diagnostics.rejected_pinned_pages.saturating_add(1);
            }
            RequestError::SharedBytesLimit => {
                self.diagnostics.rejected_shared_bytes =
                    self.diagnostics.rejected_shared_bytes.saturating_add(1);
            }
            _ => {}
        }
    }

    fn request(&self, id: RequestId) -> Option<&KernelRequest<O, P>> {
        let index = self.valid_request_index(id)?;
        self.slots[index].request.as_ref()
    }

    fn request_mut(&mut self, id: RequestId) -> Option<&mut KernelRequest<O, P>> {
        let index = self.valid_request_index(id)?;
        self.slots[index].request.as_mut()
    }

    fn valid_request_index(&self, id: RequestId) -> Option<usize> {
        let index = id.index()?;
        let slot = self.slots.get(index)?;
        (id.is_valid()
            && !slot.retired
            && slot.generation == id.generation()
            && slot
                .request
                .as_ref()
                .is_some_and(|request| request.id == id))
        .then_some(index)
    }

    fn apply_completion(&mut self, completion: DeferredCompletion, now_ns: u64) {
        let Some(index) = self.valid_request_index(completion.id) else {
            self.diagnostics.stale_completions =
                self.diagnostics.stale_completions.saturating_add(1);
            return;
        };
        let state = self.slots[index]
            .request
            .as_ref()
            .expect("validated request disappeared")
            .state;
        if is_terminal(state) {
            if matches!(state, RequestState::Completed | RequestState::Failed) {
                self.diagnostics.duplicate_completions =
                    self.diagnostics.duplicate_completions.saturating_add(1);
            } else {
                self.diagnostics.late_completions =
                    self.diagnostics.late_completions.saturating_add(1);
            }
            if completion.device_released {
                let request = self.slots[index]
                    .request
                    .as_mut()
                    .expect("validated request disappeared");
                if matches!(
                    request.resource_state,
                    RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
                ) {
                    request.resource_state = RequestResourceState::KernelOwned;
                }
                self.release_target_if_safe(completion.id);
                self.queue_release_if_possible(completion.id);
            }
            return;
        }

        if state == RequestState::CancelPending {
            self.remove_cancel_action(completion.id);
            self.diagnostics.cancellation_lost_races =
                self.diagnostics.cancellation_lost_races.saturating_add(1);
        }
        {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            request.state = RequestState::Completing;
            if completion.device_released
                && matches!(
                    request.resource_state,
                    RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
                )
            {
                request.resource_state = RequestResourceState::KernelOwned;
            } else if request.resource_state == RequestResourceState::DeviceOwned {
                request.resource_state = RequestResourceState::DrainPending;
            }
        }
        let terminal = if completion.status == Status::Ok {
            RequestState::Completed
        } else {
            RequestState::Failed
        };
        self.finish_terminal(completion.id, terminal, completion.status, now_ns);
    }

    fn apply_timeout(&mut self, id: RequestId, now_ns: u64) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let needs_cancel = {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            request.deadline_heap_index = None;
            if is_terminal(request.state) {
                return;
            }
            let needs_cancel = request.started_at_ns.is_some();
            request.cancellation_requested |= needs_cancel;
            needs_cancel
        };
        if needs_cancel {
            self.queue_cancel_action(id, RequestCancelReason::Deadline);
        }
        self.finish_terminal(id, RequestState::TimedOut, Status::TimedOut, now_ns);
    }

    fn request_cancel(
        &mut self,
        id: RequestId,
        reason: RequestCancelReason,
        now_ns: u64,
    ) -> Result<(), RequestError> {
        let index = self
            .valid_request_index(id)
            .ok_or(RequestError::InvalidRequest)?;
        let state = self.slots[index]
            .request
            .as_ref()
            .expect("validated request disappeared")
            .state;
        if is_terminal(state) {
            return Err(RequestError::InvalidState);
        }
        if state == RequestState::CancelPending {
            return Ok(());
        }
        self.diagnostics.cancellation_requests =
            self.diagnostics.cancellation_requests.saturating_add(1);
        {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            request.cancellation_requested = true;
        }
        if state == RequestState::Pending {
            {
                let request = self.slots[index]
                    .request
                    .as_mut()
                    .expect("validated request disappeared");
                request.cancellation_acknowledged = true;
            }
            self.diagnostics.cancellation_acknowledgements = self
                .diagnostics
                .cancellation_acknowledgements
                .saturating_add(1);
            self.finish_terminal(id, RequestState::Canceled, Status::Canceled, now_ns);
            return Ok(());
        }

        {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            request.state = RequestState::CancelPending;
        }
        self.queue_cancel_action(id, reason);
        Ok(())
    }

    fn terminate_matching<F>(
        &mut self,
        mut matches: F,
        reason: RequestCancelReason,
        now_ns: u64,
    ) -> usize
    where
        F: FnMut(&KernelRequest<O, P>) -> bool,
    {
        let mut affected = 0usize;
        for index in 0..self.slots.len() {
            let Some((id, state)) = self.slots[index]
                .request
                .as_ref()
                .filter(|request| matches(request) && !is_terminal(request.state))
                .map(|request| (request.id, request.state))
            else {
                continue;
            };
            affected += 1;
            {
                let request = self.slots[index]
                    .request
                    .as_mut()
                    .expect("matched request disappeared");
                request.cancellation_requested = true;
            }
            if state != RequestState::Pending {
                self.queue_cancel_action(id, reason);
            } else {
                let request = self.slots[index]
                    .request
                    .as_mut()
                    .expect("matched request disappeared");
                request.cancellation_acknowledged = true;
                self.diagnostics.cancellation_acknowledgements = self
                    .diagnostics
                    .cancellation_acknowledgements
                    .saturating_add(1);
            }
            self.finish_terminal(id, RequestState::OwnerTerminated, Status::Canceled, now_ns);
        }
        affected
    }

    fn fail_device(
        &mut self,
        device: RequestDevice,
        now_ns: u64,
        ownership_stopped: bool,
    ) -> usize {
        let mut affected = 0usize;
        for index in 0..self.slots.len() {
            let Some((id, terminal, draining)) = self.slots[index]
                .request
                .as_ref()
                .filter(|request| request.device == Some(device))
                .map(|request| {
                    (
                        request.id,
                        is_terminal(request.state),
                        matches!(
                            request.resource_state,
                            RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
                        ),
                    )
                })
            else {
                continue;
            };
            if terminal && !draining {
                continue;
            }

            affected += 1;
            self.remove_cancel_action(id);
            if ownership_stopped && draining {
                self.slots[index]
                    .request
                    .as_mut()
                    .expect("matched request disappeared")
                    .resource_state = RequestResourceState::KernelOwned;
            }
            if terminal {
                self.release_target_if_safe(id);
                self.queue_release_if_possible(id);
            } else {
                self.finish_terminal(id, RequestState::Failed, Status::Io, now_ns);
            }
        }
        affected
    }

    fn finish_terminal(&mut self, id: RequestId, state: RequestState, status: Status, now_ns: u64) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        if self.slots[index]
            .request
            .as_ref()
            .is_some_and(|request| is_terminal(request.state))
        {
            return;
        }
        self.remove_request_from_pending_queue(id);
        self.remove_request_deadline(id);
        {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            request.state = state;
            request.status = status;
            request.completed_at_ns = Some(now_ns);
            if request.resource_state == RequestResourceState::DeviceOwned {
                request.resource_state = RequestResourceState::DrainPending;
            }
        }
        match state {
            RequestState::Completed => {
                self.diagnostics.completions = self.diagnostics.completions.saturating_add(1);
            }
            RequestState::TimedOut => {
                self.diagnostics.timeouts = self.diagnostics.timeouts.saturating_add(1);
            }
            RequestState::Failed => {
                self.diagnostics.failures = self.diagnostics.failures.saturating_add(1);
            }
            _ => {}
        }
        if let Some(started_at_ns) = self.request(id).and_then(|request| request.started_at_ns) {
            let latency = now_ns.saturating_sub(started_at_ns);
            self.diagnostics.maximum_service_latency_ns =
                self.diagnostics.maximum_service_latency_ns.max(latency);
            self.diagnostics.cumulative_service_latency_ns = self
                .diagnostics
                .cumulative_service_latency_ns
                .saturating_add(latency);
            self.diagnostics.service_latency_samples =
                self.diagnostics.service_latency_samples.saturating_add(1);
        }
        self.queue_terminal_action(id);
        self.release_target_if_safe(id);
        self.queue_release_if_possible(id);
    }

    fn remove_request_from_pending_queue(&mut self, id: RequestId) {
        let Some(target) = self.request(id).map(|request| request.target) else {
            return;
        };
        let Some(index) = self.target_index(target) else {
            return;
        };
        let before = self.targets[index].queued.len();
        self.targets[index].queued.retain(|queued| *queued != id);
        if self.targets[index].queued.len() != before {
            self.diagnostics.queued_requests = self.diagnostics.queued_requests.saturating_sub(1);
        }
        self.release_idle_target(index);
    }

    fn release_target_if_safe(&mut self, id: RequestId) {
        let Some(request) = self.request(id) else {
            return;
        };
        if !is_terminal(request.state)
            || matches!(
                request.resource_state,
                RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
            )
        {
            return;
        }
        let target = request.target;
        let was_started = request.started_at_ns.is_some();
        let Some(index) = self.target_index(target) else {
            return;
        };
        if self.targets[index].active == Some(id) {
            self.targets[index].active = None;
            if was_started {
                self.diagnostics.active_requests =
                    self.diagnostics.active_requests.saturating_sub(1);
            }
        }
        self.release_idle_target(index);
    }

    fn release_idle_target(&mut self, index: usize) {
        if self.targets[index].is_idle() {
            self.targets[index].target = None;
        }
    }

    fn queue_terminal_action(&mut self, id: RequestId) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let action = {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            if request.terminal_action_queued || request.terminal_publication_dispatched {
                return;
            }
            request.terminal_action_queued = true;
            RequestAction::PublishTerminal {
                id,
                state: request.state,
                status: request.status,
                completed_at_ns: request.completed_at_ns.unwrap_or(request.submitted_at_ns),
            }
        };
        self.push_action(action);
    }

    fn queue_cancel_action(&mut self, id: RequestId, reason: RequestCancelReason) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let action = {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            if request.cancel_action_queued || request.cancel_action_dispatched {
                return;
            }
            request.cancel_action_queued = true;
            RequestAction::CancelDevice {
                id,
                device: request.device,
                reason,
            }
        };
        self.push_action(action);
    }

    fn queue_release_if_possible(&mut self, id: RequestId) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let action = {
            let request = self.slots[index]
                .request
                .as_mut()
                .expect("validated request disappeared");
            if !is_terminal(request.state)
                || request.resource_state != RequestResourceState::KernelOwned
                || request.release_action_queued
                || request.resource_release_dispatched
            {
                return;
            }
            request.resource_state = RequestResourceState::ReleasePending;
            request.release_action_queued = true;
            RequestAction::ReleaseResources {
                id,
                owner: request.owner,
                resources: request.resources,
            }
        };
        self.push_action(action);
    }

    fn push_action(&mut self, action: RequestAction) {
        debug_assert!(self.actions.len() < self.actions.capacity());
        self.actions.push_back(action);
    }

    fn remove_cancel_action(&mut self, id: RequestId) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let queued = self.slots[index]
            .request
            .as_ref()
            .is_some_and(|request| request.cancel_action_queued);
        if !queued {
            return;
        }
        self.actions.retain(|action| {
            !matches!(action, RequestAction::CancelDevice { id: action_id, .. } if *action_id == id)
        });
        if let Some(request) = self.slots[index].request.as_mut() {
            request.cancel_action_queued = false;
        }
    }

    fn try_retire(&mut self, id: RequestId) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let retire = self.slots[index].request.as_ref().is_some_and(|request| {
            is_terminal(request.state)
                && request.terminal_publication_dispatched
                && request.resource_state == RequestResourceState::Released
                && !request.cancel_action_queued
                && !request.terminal_action_queued
                && !request.release_action_queued
        });
        if !retire {
            return;
        }
        let request = self.slots[index]
            .request
            .take()
            .expect("retiring request disappeared");
        self.remove_request_deadline(id);
        self.release_target_after_retirement(&request);
        self.diagnostics.live_requests = self.diagnostics.live_requests.saturating_sub(1);
        self.slots[index].generation = match self.slots[index].generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                self.slots[index].retired = true;
                self.slots[index].generation
            }
        };
    }

    fn release_target_after_retirement(&mut self, request: &KernelRequest<O, P>) {
        let Some(index) = self.target_index(request.target) else {
            return;
        };
        if self.targets[index].active == Some(request.id) {
            self.targets[index].active = None;
            if request.started_at_ns.is_some() {
                self.diagnostics.active_requests =
                    self.diagnostics.active_requests.saturating_sub(1);
            }
        }
        self.targets[index]
            .queued
            .retain(|queued| *queued != request.id);
        self.release_idle_target(index);
    }

    fn push_deadline(&mut self, entry: DeadlineEntry) {
        debug_assert!(self.deadlines.len() < self.limits.system_capacity);
        let index = self.deadlines.len();
        self.deadlines.push(entry);
        self.set_deadline_heap_index(index);
        self.sift_deadline_up(index);
    }

    fn remove_request_deadline(&mut self, id: RequestId) {
        let Some(index) = self.valid_request_index(id) else {
            return;
        };
        let heap_index = self.slots[index]
            .request
            .as_ref()
            .and_then(|request| request.deadline_heap_index);
        if let Some(heap_index) = heap_index {
            self.remove_deadline_at(heap_index);
        }
    }

    fn remove_deadline_at(&mut self, index: usize) -> DeadlineEntry {
        let removed = self.deadlines.swap_remove(index);
        if let Some(request) = self.request_mut(removed.id) {
            request.deadline_heap_index = None;
        }
        if index < self.deadlines.len() {
            self.set_deadline_heap_index(index);
            if index > 0
                && self.deadlines[index].ordering_key()
                    < self.deadlines[(index - 1) / 2].ordering_key()
            {
                self.sift_deadline_up(index);
            } else {
                self.sift_deadline_down(index);
            }
        }
        removed
    }

    fn sift_deadline_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.deadlines[parent].ordering_key() <= self.deadlines[index].ordering_key() {
                break;
            }
            self.swap_deadlines(parent, index);
            index = parent;
        }
    }

    fn sift_deadline_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.deadlines.len() {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.deadlines.len()
                && self.deadlines[right].ordering_key() < self.deadlines[left].ordering_key()
            {
                right
            } else {
                left
            };
            if self.deadlines[index].ordering_key() <= self.deadlines[smallest].ordering_key() {
                break;
            }
            self.swap_deadlines(index, smallest);
            index = smallest;
        }
    }

    fn swap_deadlines(&mut self, left: usize, right: usize) {
        self.deadlines.swap(left, right);
        self.set_deadline_heap_index(left);
        self.set_deadline_heap_index(right);
    }

    fn set_deadline_heap_index(&mut self, heap_index: usize) {
        let id = self.deadlines[heap_index].id;
        if let Some(request) = self.request_mut(id) {
            request.deadline_heap_index = Some(heap_index);
        }
    }

    #[cfg(test)]
    fn set_generation_for_test(&mut self, index: usize, generation: u32) {
        assert_ne!(generation, 0);
        assert!(self.slots[index].request.is_none());
        self.slots[index].generation = generation;
        self.slots[index].retired = false;
    }
}

const fn is_terminal(state: RequestState) -> bool {
    matches!(
        state,
        RequestState::Completed
            | RequestState::TimedOut
            | RequestState::Canceled
            | RequestState::Failed
            | RequestState::OwnerTerminated
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cmp;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestOperation {
        Nop,
        Read,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestPayload {
        cookie: u64,
    }

    type TestRuntime = RequestRuntime<TestOperation, TestPayload>;

    fn limits(capacity: usize) -> RequestLimits {
        RequestLimits {
            system_capacity: capacity,
            per_owner_requests: capacity,
            per_target_requests: capacity,
            max_batch: cmp::min(capacity, REQUEST_MAX_BATCH),
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

    fn runtime(capacity: usize) -> TestRuntime {
        TestRuntime::try_new_with_limits(limits(capacity)).unwrap()
    }

    fn owner(process: u64, thread: u64) -> RequestOwner {
        RequestOwner::new(process, thread)
    }

    fn submission(
        owner: RequestOwner,
        target: u64,
    ) -> RequestSubmission<TestOperation, TestPayload> {
        RequestSubmission {
            owner,
            target: RequestTarget(target),
            device: Some(RequestDevice(target as u32)),
            operation: TestOperation::Nop,
            service_payload: TestPayload { cookie: target },
            deadline_ns: None,
            resources: RequestResources {
                copied_bytes: 8,
                pinned_pages: 1,
                shared_bytes: 16,
            },
        }
    }

    fn complete(runtime: &mut TestRuntime, id: RequestId, now_ns: u64) {
        runtime
            .record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        let report = runtime.run_worker(now_ns, RequestWorkerBudget::DEFAULT);
        assert_eq!(report.completions, 1);
    }

    fn collect_actions(runtime: &mut TestRuntime) -> Vec<RequestAction> {
        let mut actions = Vec::new();
        while let Some(action) = runtime.next_action() {
            actions.push(action);
        }
        actions
    }

    fn finish_releases(runtime: &mut TestRuntime, actions: &[RequestAction]) {
        for action in actions {
            if let RequestAction::ReleaseResources { id, .. } = action {
                runtime.acknowledge_resource_release(*id).unwrap();
            }
        }
    }

    #[test]
    fn abstract_operation_and_service_payload_round_trip() {
        let mut runtime = runtime(1);
        let mut request = submission(owner(1, 1), 10);
        request.operation = TestOperation::Read;
        request.service_payload = TestPayload {
            cookie: 0xfeed_beef,
        };
        let id = runtime.submit(request, 0).unwrap();

        let snapshot = runtime.snapshot(id).unwrap();
        assert_eq!(snapshot.operation, TestOperation::Read);
        assert_eq!(snapshot.service_payload.cookie, 0xfeed_beef);
        let dispatch = runtime.next_dispatch(1).unwrap();
        assert_eq!(dispatch.operation, TestOperation::Read);
        assert_eq!(dispatch.service_payload.cookie, 0xfeed_beef);
    }

    #[test]
    fn completion_before_inclusive_deadline_wins() {
        let mut runtime = runtime(2);
        let mut request = submission(owner(1, 1), 10);
        request.deadline_ns = Some(50);
        let id = runtime.submit(request, 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(id).unwrap();
        runtime
            .record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();

        let report = runtime.run_worker(
            50,
            RequestWorkerBudget {
                completions: 1,
                deadlines: 1,
            },
        );
        assert_eq!(report.completions, 1);
        assert_eq!(report.deadlines, 0);
        assert_eq!(runtime.snapshot(id).unwrap().state, RequestState::Completed);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RaceEvent {
        Complete,
        CancelAck,
        Timeout,
        OwnerThread,
        DeviceRemoval,
    }

    fn apply_race_event(runtime: &mut TestRuntime, id: RequestId, event: RaceEvent, now_ns: u64) {
        match event {
            RaceEvent::Complete => {
                let _ = runtime.record_completion(DeferredCompletion {
                    id,
                    status: Status::Ok,
                    device_released: true,
                });
                runtime.run_worker(now_ns, RequestWorkerBudget::DEFAULT);
            }
            RaceEvent::CancelAck => {
                let _ = runtime.cancel(id, now_ns);
                let _ = runtime.acknowledge_cancel(id, now_ns, true);
            }
            RaceEvent::Timeout => runtime.apply_timeout(id, now_ns),
            RaceEvent::OwnerThread => {
                runtime.terminate_thread(owner(1, 1), now_ns);
            }
            RaceEvent::DeviceRemoval => {
                runtime.remove_device(RequestDevice(10), now_ns, true);
            }
        }
    }

    #[test]
    fn every_ordered_terminal_race_publishes_and_releases_exactly_once() {
        const EVENTS: [RaceEvent; 5] = [
            RaceEvent::Complete,
            RaceEvent::CancelAck,
            RaceEvent::Timeout,
            RaceEvent::OwnerThread,
            RaceEvent::DeviceRemoval,
        ];

        for first in EVENTS {
            for second in EVENTS {
                let mut runtime = runtime(1);
                let id = runtime.submit(submission(owner(1, 1), 10), 0).unwrap();
                runtime.next_dispatch(1).unwrap();
                runtime.mark_device_owned(id).unwrap();
                apply_race_event(&mut runtime, id, first, 10);
                apply_race_event(&mut runtime, id, second, 10);

                let expected = match first {
                    RaceEvent::Complete => RequestState::Completed,
                    RaceEvent::CancelAck => RequestState::Canceled,
                    RaceEvent::Timeout => RequestState::TimedOut,
                    RaceEvent::OwnerThread => RequestState::OwnerTerminated,
                    RaceEvent::DeviceRemoval => RequestState::Failed,
                };
                assert_eq!(runtime.snapshot(id).unwrap().state, expected);

                if runtime.snapshot(id).is_some_and(|snapshot| {
                    matches!(
                        snapshot.resource_state,
                        RequestResourceState::DeviceOwned | RequestResourceState::DrainPending
                    )
                }) {
                    runtime.acknowledge_drain(id).unwrap();
                }
                let actions = collect_actions(&mut runtime);
                assert_eq!(
                    actions
                        .iter()
                        .filter(|action| matches!(action, RequestAction::PublishTerminal { .. }))
                        .count(),
                    1,
                    "terminal publication for {first:?} then {second:?}"
                );
                assert_eq!(
                    actions
                        .iter()
                        .filter(|action| matches!(action, RequestAction::ReleaseResources { .. }))
                        .count(),
                    1,
                    "resource release for {first:?} then {second:?}"
                );
                finish_releases(&mut runtime, &actions);
                assert!(runtime.is_system_drained());
            }
        }
    }

    #[test]
    fn completion_can_win_after_cancel_request_but_before_acknowledgement() {
        let mut runtime = runtime(1);
        let id = runtime.submit(submission(owner(1, 1), 10), 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(id).unwrap();
        runtime.cancel(id, 2).unwrap();

        complete(&mut runtime, id, 3);
        let snapshot = runtime.snapshot(id).unwrap();
        assert_eq!(snapshot.state, RequestState::Completed);
        assert!(snapshot.cancellation_requested);
        assert!(!snapshot.cancellation_acknowledged);
        assert_eq!(runtime.diagnostics().cancellation_lost_races, 1);
        assert_eq!(runtime.acknowledge_cancel(id, 4, true), Ok(()));
        assert_eq!(runtime.snapshot(id).unwrap().state, RequestState::Completed);
    }

    #[test]
    fn stale_generation_reuse_and_duplicate_completion_are_rejected() {
        let mut runtime = runtime(1);
        let stale = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        complete(&mut runtime, stale, 2);
        runtime
            .record_completion(DeferredCompletion {
                id: stale,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        runtime.run_worker(3, RequestWorkerBudget::DEFAULT);
        assert_eq!(runtime.diagnostics().duplicate_completions, 1);
        let actions = collect_actions(&mut runtime);
        finish_releases(&mut runtime, &actions);

        let current = runtime.submit(submission(owner(1, 1), 1), 4).unwrap();
        assert_ne!(stale, current);
        runtime
            .record_completion(DeferredCompletion {
                id: stale,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        runtime.run_worker(5, RequestWorkerBudget::DEFAULT);
        assert_eq!(runtime.diagnostics().stale_completions, 1);
        assert_eq!(runtime.cancel(stale, 5), Err(RequestError::InvalidRequest));
        assert_eq!(
            runtime.acknowledge_cancel(stale, 5, true),
            Err(RequestError::InvalidRequest)
        );
        assert_eq!(
            runtime.acknowledge_drain(stale),
            Err(RequestError::InvalidRequest)
        );
        assert_eq!(
            runtime.snapshot(current).unwrap().state,
            RequestState::Pending
        );
    }

    #[test]
    fn generation_wrap_retires_slot() {
        let mut runtime = runtime(1);
        runtime.set_generation_for_test(0, u32::MAX);
        let id = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        runtime.cancel(id, 1).unwrap();
        let actions = collect_actions(&mut runtime);
        finish_releases(&mut runtime, &actions);
        assert_eq!(
            runtime.submit(submission(owner(1, 1), 1), 2),
            Err(RequestError::SystemFull)
        );
    }

    #[test]
    fn system_owner_target_and_resource_limits_are_atomic() {
        let mut policy = limits(3);
        policy.per_owner_requests = 2;
        policy.per_target_requests = 1;
        let mut runtime = TestRuntime::try_new_with_limits(policy).unwrap();
        runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        assert_eq!(
            runtime.submit(submission(owner(2, 1), 1), 0),
            Err(RequestError::TargetLimit)
        );
        runtime.submit(submission(owner(1, 1), 2), 0).unwrap();
        assert_eq!(
            runtime.submit(submission(owner(1, 1), 3), 0),
            Err(RequestError::OwnerLimit)
        );
        assert_eq!(runtime.diagnostics().live_requests, 2);

        let mut too_large = submission(owner(2, 1), 3);
        too_large.resources.copied_bytes = policy.copied_bytes_per_request + 1;
        assert_eq!(
            runtime.submit(too_large, 0),
            Err(RequestError::CopiedBytesLimit)
        );
        too_large.resources.copied_bytes = 0;
        too_large.resources.pinned_pages = policy.pinned_pages_per_request + 1;
        assert_eq!(
            runtime.submit(too_large, 0),
            Err(RequestError::PinnedPagesLimit)
        );
        too_large.resources.pinned_pages = 0;
        too_large.resources.shared_bytes = policy.shared_bytes_per_request + 1;
        assert_eq!(
            runtime.submit(too_large, 0),
            Err(RequestError::SharedBytesLimit)
        );
        assert_eq!(runtime.diagnostics().live_requests, 2);
    }

    #[test]
    fn aggregate_owner_and_system_resource_charges_are_enforced() {
        let mut owner_runtime = runtime(4);
        let mut first = submission(owner(1, 1), 1);
        first.resources.pinned_pages = 4;
        first.resources.shared_bytes = 256;
        let mut second = submission(owner(1, 1), 2);
        second.resources.pinned_pages = 4;
        second.resources.shared_bytes = 256;
        owner_runtime.submit(first, 0).unwrap();
        owner_runtime.submit(second, 0).unwrap();

        let mut pinned_over = submission(owner(1, 1), 3);
        pinned_over.resources.pinned_pages = 1;
        pinned_over.resources.shared_bytes = 0;
        assert_eq!(
            owner_runtime.submit(pinned_over, 0),
            Err(RequestError::PinnedPagesLimit)
        );
        let mut shared_over = submission(owner(1, 1), 3);
        shared_over.resources.pinned_pages = 0;
        shared_over.resources.shared_bytes = 1;
        assert_eq!(
            owner_runtime.submit(shared_over, 0),
            Err(RequestError::SharedBytesLimit)
        );

        let mut system_runtime = runtime(5);
        for process in 1..=4 {
            let mut request = submission(owner(process, 1), process);
            request.resources.copied_bytes = 64;
            request.resources.pinned_pages = 0;
            request.resources.shared_bytes = 0;
            system_runtime.submit(request, 0).unwrap();
        }
        let mut system_over = submission(owner(5, 1), 5);
        system_over.resources.copied_bytes = 1;
        system_over.resources.pinned_pages = 0;
        system_over.resources.shared_bytes = 0;
        assert_eq!(
            system_runtime.submit(system_over, 0),
            Err(RequestError::CopiedBytesLimit)
        );
    }

    #[test]
    fn batch_preflight_rolls_back_every_member() {
        let mut policy = limits(4);
        policy.per_target_requests = 1;
        let mut runtime = TestRuntime::try_new_with_limits(policy).unwrap();
        let batch = [submission(owner(1, 1), 1), submission(owner(1, 1), 1)];
        let mut output = [RequestId::INVALID; 2];
        assert_eq!(
            runtime.submit_batch(&batch, &mut output, 0),
            Err(RequestError::TargetLimit)
        );
        assert_eq!(output, [RequestId::INVALID; 2]);
        assert_eq!(runtime.diagnostics().live_requests, 0);
        assert_eq!(runtime.diagnostics().queued_requests, 0);
        assert_eq!(runtime.next_deadline_ns(), None);
        assert_eq!(runtime.diagnostics().batch_rollbacks, 1);
    }

    #[test]
    fn target_fifo_and_fair_rotation_are_preserved() {
        let mut runtime = runtime(6);
        let a1 = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let a2 = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let b1 = runtime.submit(submission(owner(2, 1), 2), 0).unwrap();
        let b2 = runtime.submit(submission(owner(2, 1), 2), 0).unwrap();

        assert_eq!(runtime.next_dispatch(1).unwrap().id, a1);
        assert_eq!(runtime.next_dispatch(1).unwrap().id, b1);
        assert_eq!(runtime.next_dispatch(1), None);

        complete(&mut runtime, a1, 2);
        complete(&mut runtime, b1, 2);
        assert_eq!(runtime.next_dispatch(3).unwrap().id, a2);
        assert_eq!(runtime.next_dispatch(3).unwrap().id, b2);
    }

    #[test]
    fn repeated_chunk_requeue_rotates_at_the_back_of_one_target_fifo() {
        let mut runtime = runtime(3);
        let first = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let second = runtime.submit(submission(owner(2, 1), 1), 0).unwrap();
        let other_target = runtime.submit(submission(owner(3, 1), 2), 0).unwrap();

        assert_eq!(runtime.next_dispatch(1).unwrap().id, first);
        assert_eq!(runtime.next_dispatch(1).unwrap().id, other_target);
        runtime.requeue_active(first).unwrap();
        assert_eq!(runtime.next_dispatch(2).unwrap().id, second);
        runtime.requeue_active(second).unwrap();
        assert_eq!(runtime.next_dispatch(3).unwrap().id, first);
        runtime.requeue_active(first).unwrap();
        assert_eq!(runtime.next_dispatch(4).unwrap().id, second);

        let diagnostics = runtime.diagnostics();
        assert_eq!(diagnostics.active_requests, 2);
        assert_eq!(diagnostics.queued_requests, 1);
        assert_eq!(diagnostics.dispatches, 5);
        assert_eq!(diagnostics.queue_latency_samples, 3);
        assert_eq!(runtime.snapshot(first).unwrap().started_at_ns, Some(1));
    }

    #[test]
    fn deadline_and_cancel_can_win_while_a_chunked_request_is_requeued() {
        let mut deadline_runtime = runtime(1);
        let mut deadline_request = submission(owner(1, 1), 1);
        deadline_request.deadline_ns = Some(10);
        let deadline_id = deadline_runtime.submit(deadline_request, 0).unwrap();
        deadline_runtime.next_dispatch(1).unwrap();
        deadline_runtime.requeue_active(deadline_id).unwrap();
        assert_eq!(deadline_runtime.next_deadline_ns(), Some(10));
        deadline_runtime.run_worker(10, RequestWorkerBudget::DEFAULT);
        assert_eq!(
            deadline_runtime.snapshot(deadline_id).unwrap().state,
            RequestState::TimedOut
        );
        assert_eq!(deadline_runtime.diagnostics().active_requests, 0);
        assert_eq!(deadline_runtime.diagnostics().queued_requests, 0);

        let mut cancel_runtime = runtime(1);
        let cancel_id = cancel_runtime
            .submit(submission(owner(1, 1), 1), 0)
            .unwrap();
        cancel_runtime.next_dispatch(1).unwrap();
        cancel_runtime.requeue_active(cancel_id).unwrap();
        cancel_runtime.cancel(cancel_id, 2).unwrap();
        let snapshot = cancel_runtime.snapshot(cancel_id).unwrap();
        assert_eq!(snapshot.state, RequestState::Canceled);
        assert!(snapshot.cancellation_acknowledged);
        assert_eq!(cancel_runtime.diagnostics().active_requests, 0);
        assert_eq!(cancel_runtime.diagnostics().queued_requests, 0);
    }

    #[test]
    fn requeue_rejects_non_active_or_device_owned_requests() {
        let mut runtime = runtime(2);
        let pending = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        assert_eq!(
            runtime.requeue_active(pending),
            Err(RequestError::InvalidState)
        );
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(pending).unwrap();
        assert_eq!(
            runtime.requeue_active(pending),
            Err(RequestError::InvalidState)
        );
    }

    #[test]
    fn timeout_publishes_while_device_ownership_delays_release() {
        let mut runtime = runtime(1);
        let mut request = submission(owner(1, 1), 1);
        request.deadline_ns = Some(10);
        let id = runtime.submit(request, 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(id).unwrap();
        runtime.run_worker(10, RequestWorkerBudget::DEFAULT);

        let snapshot = runtime.snapshot(id).unwrap();
        assert_eq!(snapshot.state, RequestState::TimedOut);
        assert_eq!(snapshot.resource_state, RequestResourceState::DrainPending);
        assert!(snapshot.cancellation_requested);
        let first_actions = collect_actions(&mut runtime);
        assert!(first_actions.iter().any(|action| {
            matches!(
                action,
                RequestAction::CancelDevice {
                    id: action_id,
                    reason: RequestCancelReason::Deadline,
                    ..
                } if *action_id == id
            )
        }));
        assert_eq!(
            first_actions
                .iter()
                .filter(|action| matches!(action, RequestAction::PublishTerminal { .. }))
                .count(),
            1
        );
        assert!(!first_actions
            .iter()
            .any(|action| matches!(action, RequestAction::ReleaseResources { .. })));

        runtime
            .record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        runtime.run_worker(20, RequestWorkerBudget::DEFAULT);
        assert_eq!(runtime.snapshot(id).unwrap().state, RequestState::TimedOut);
        let release = collect_actions(&mut runtime);
        assert_eq!(
            release
                .iter()
                .filter(|action| matches!(action, RequestAction::ReleaseResources { .. }))
                .count(),
            1
        );
        finish_releases(&mut runtime, &release);
        assert!(runtime.is_system_drained());
        assert_eq!(runtime.diagnostics().late_completions, 1);
    }

    #[test]
    fn reset_releases_a_timed_out_device_owned_request() {
        let mut runtime = runtime(1);
        let mut request = submission(owner(1, 1), 7);
        request.deadline_ns = Some(10);
        let id = runtime.submit(request, 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(id).unwrap();
        runtime.run_worker(10, RequestWorkerBudget::DEFAULT);
        assert_eq!(
            runtime.snapshot(id).unwrap().resource_state,
            RequestResourceState::DrainPending
        );

        assert_eq!(runtime.reset_device(RequestDevice(7), 11), 1);
        assert_eq!(runtime.snapshot(id).unwrap().state, RequestState::TimedOut);
        assert_eq!(
            runtime.snapshot(id).unwrap().resource_state,
            RequestResourceState::ReleasePending
        );
        let actions = collect_actions(&mut runtime);
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, RequestAction::PublishTerminal { .. }))
                .count(),
            1
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, RequestAction::ReleaseResources { .. }))
                .count(),
            1
        );
        finish_releases(&mut runtime, &actions);
        assert!(runtime.is_system_drained());
    }

    #[test]
    fn resource_release_requires_one_action_and_one_acknowledgement() {
        let mut runtime = runtime(1);
        let id = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        runtime.cancel(id, 1).unwrap();
        assert_eq!(
            runtime.acknowledge_resource_release(id),
            Err(RequestError::ReleaseNotDispatched)
        );
        let actions = collect_actions(&mut runtime);
        let releases = actions
            .iter()
            .filter(|action| matches!(action, RequestAction::ReleaseResources { .. }))
            .count();
        assert_eq!(releases, 1);
        finish_releases(&mut runtime, &actions);
        assert_eq!(
            runtime.acknowledge_resource_release(id),
            Err(RequestError::InvalidRequest)
        );
        assert_eq!(runtime.diagnostics().resource_release_actions, 1);
        assert_eq!(runtime.diagnostics().resource_release_acknowledgements, 1);
    }

    #[test]
    fn worker_budgets_bound_completions_and_preserve_deadline_precedence() {
        let mut runtime = runtime(4);
        let mut ids = [RequestId::INVALID; 3];
        for (index, slot) in ids.iter_mut().enumerate() {
            let mut request = submission(owner(index as u64 + 1, 1), index as u64 + 1);
            request.deadline_ns = Some(10);
            *slot = runtime.submit(request, 0).unwrap();
            runtime.next_dispatch(1).unwrap();
            runtime
                .record_completion(DeferredCompletion {
                    id: *slot,
                    status: Status::Ok,
                    device_released: true,
                })
                .unwrap();
        }

        let first = runtime.run_worker(
            10,
            RequestWorkerBudget {
                completions: 1,
                deadlines: 1,
            },
        );
        assert_eq!(first.completions, 1);
        assert_eq!(first.deadlines, 0);
        assert!(first.completion_budget_exhausted);
        assert_eq!(
            runtime.snapshot(ids[0]).unwrap().state,
            RequestState::Completed
        );
        assert_eq!(
            runtime.snapshot(ids[1]).unwrap().state,
            RequestState::Active
        );

        let second = runtime.run_worker(
            10,
            RequestWorkerBudget {
                completions: 2,
                deadlines: 1,
            },
        );
        assert_eq!(second.completions, 2);
        assert_eq!(second.deadlines, 0);
        assert!(ids.iter().all(|id| {
            runtime
                .snapshot(*id)
                .is_some_and(|snapshot| snapshot.state == RequestState::Completed)
        }));
        assert_eq!(runtime.diagnostics().completion_budget_exhaustions, 1);
    }

    #[test]
    fn deadline_budget_is_bounded() {
        let mut runtime = runtime(3);
        let mut ids = [RequestId::INVALID; 3];
        for (index, id) in ids.iter_mut().enumerate() {
            let mut request = submission(owner(index as u64 + 1, 1), index as u64 + 1);
            request.deadline_ns = Some(5);
            *id = runtime.submit(request, 0).unwrap();
        }
        let first = runtime.run_worker(
            5,
            RequestWorkerBudget {
                completions: 0,
                deadlines: 1,
            },
        );
        assert_eq!(first.deadlines, 1);
        assert!(first.deadline_budget_exhausted);
        assert_eq!(
            ids.iter()
                .filter(|id| runtime.snapshot(**id).unwrap().state == RequestState::TimedOut)
                .count(),
            1
        );
        let second = runtime.run_worker(
            5,
            RequestWorkerBudget {
                completions: 0,
                deadlines: 2,
            },
        );
        assert_eq!(second.deadlines, 2);
        assert_eq!(runtime.diagnostics().deadline_budget_exhaustions, 1);
    }

    #[test]
    fn process_termination_selects_every_thread_of_only_that_process() {
        let mut runtime = runtime(3);
        let first = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let second = runtime.submit(submission(owner(1, 2), 2), 0).unwrap();
        let other = runtime.submit(submission(owner(2, 1), 3), 0).unwrap();

        assert_eq!(runtime.terminate_process(1, 5), 2);
        assert_eq!(
            runtime.snapshot(first).unwrap().state,
            RequestState::OwnerTerminated
        );
        assert_eq!(
            runtime.snapshot(second).unwrap().state,
            RequestState::OwnerTerminated
        );
        assert_eq!(
            runtime.snapshot(other).unwrap().state,
            RequestState::Pending
        );
        assert!(!runtime.is_process_drained(1));

        let actions = collect_actions(&mut runtime);
        finish_releases(&mut runtime, &actions);
        assert!(runtime.is_process_drained(1));
        assert!(!runtime.is_system_drained());
    }

    #[test]
    fn owner_device_and_shutdown_paths_quiesce_and_drain() {
        let mut runtime = runtime(4);
        let pending = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let active = runtime.submit(submission(owner(2, 1), 2), 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.mark_device_owned(active).unwrap();

        assert_eq!(runtime.terminate_thread(owner(1, 1), 2), 1);
        assert_eq!(
            runtime.snapshot(pending).unwrap().state,
            RequestState::OwnerTerminated
        );
        assert_eq!(runtime.begin_shutdown(3), 1);
        assert!(!runtime.is_accepting());
        assert_eq!(
            runtime.snapshot(active).unwrap().state,
            RequestState::CancelPending
        );
        assert_eq!(
            runtime.submit(submission(owner(3, 1), 3), 4),
            Err(RequestError::Quiescing)
        );
        runtime.reset_device(RequestDevice(2), 5);
        assert_eq!(
            runtime.snapshot(active).unwrap().state,
            RequestState::Failed
        );
        runtime.resume_after_shutdown_cancel();
        assert!(runtime.is_accepting());
    }

    #[test]
    fn shutdown_stops_admission_and_drains_pending_and_active_work() {
        let mut runtime = runtime(2);
        let pending = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        let active = runtime.submit(submission(owner(2, 1), 2), 0).unwrap();
        assert_eq!(runtime.next_dispatch(1).unwrap().id, pending);
        runtime.mark_device_owned(pending).unwrap();

        assert_eq!(runtime.begin_shutdown(2), 2);
        assert_eq!(
            runtime.snapshot(pending).unwrap().state,
            RequestState::CancelPending
        );
        assert_eq!(
            runtime.snapshot(active).unwrap().state,
            RequestState::Canceled
        );
        assert_eq!(
            runtime.submit(submission(owner(3, 1), 3), 3),
            Err(RequestError::Quiescing)
        );
        runtime.acknowledge_cancel(pending, 4, true).unwrap();

        let actions = collect_actions(&mut runtime);
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, RequestAction::PublishTerminal { .. }))
                .count(),
            2
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, RequestAction::ReleaseResources { .. }))
                .count(),
            2
        );
        finish_releases(&mut runtime, &actions);
        assert!(runtime.is_system_drained());
    }

    #[test]
    fn deferred_completion_queue_is_strictly_bounded() {
        let mut policy = limits(2);
        policy.deferred_completion_capacity = 1;
        let mut runtime = TestRuntime::try_new_with_limits(policy).unwrap();
        let id = runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        runtime
            .record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        assert_eq!(
            runtime.record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            }),
            Err(RequestError::CompletionQueueFull)
        );
        assert_eq!(runtime.diagnostics().rejected_completion_queue_full, 1);
    }

    #[test]
    fn runtime_paths_keep_every_preallocated_collection_capacity() {
        let mut runtime = runtime(2);
        let slot_capacity = runtime.slots.capacity();
        let target_capacity = runtime.targets.capacity();
        let deadline_capacity = runtime.deadlines.capacity();
        let completion_capacity = runtime.deferred_completions.capacity();
        let action_capacity = runtime.actions.capacity();
        let target_queue_capacities = [
            runtime.targets[0].queued.capacity(),
            runtime.targets[1].queued.capacity(),
        ];

        let mut request = submission(owner(1, 1), 1);
        request.deadline_ns = Some(10);
        let id = runtime.submit(request, 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        runtime.requeue_active(id).unwrap();
        runtime.next_dispatch(2).unwrap();
        runtime.mark_device_owned(id).unwrap();
        runtime.cancel(id, 3).unwrap();
        runtime
            .record_completion(DeferredCompletion {
                id,
                status: Status::Ok,
                device_released: true,
            })
            .unwrap();
        runtime.run_worker(10, RequestWorkerBudget::DEFAULT);
        let actions = collect_actions(&mut runtime);
        finish_releases(&mut runtime, &actions);

        assert_eq!(runtime.slots.capacity(), slot_capacity);
        assert_eq!(runtime.targets.capacity(), target_capacity);
        assert_eq!(runtime.deadlines.capacity(), deadline_capacity);
        assert_eq!(runtime.deferred_completions.capacity(), completion_capacity);
        assert_eq!(runtime.actions.capacity(), action_capacity);
        assert_eq!(
            [
                runtime.targets[0].queued.capacity(),
                runtime.targets[1].queued.capacity(),
            ],
            target_queue_capacities
        );
    }

    #[test]
    fn diagnostics_saturate() {
        let mut runtime = runtime(1);
        runtime.diagnostics.submissions = u64::MAX;
        runtime.diagnostics.completions = u64::MAX;
        runtime.submit(submission(owner(1, 1), 1), 0).unwrap();
        runtime.next_dispatch(1).unwrap();
        complete(&mut runtime, RequestId::from_parts(0, 1), 2);
        assert_eq!(runtime.diagnostics().submissions, u64::MAX);
        assert_eq!(runtime.diagnostics().completions, u64::MAX);
    }
}
