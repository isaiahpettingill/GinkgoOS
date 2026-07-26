//! Fixed-capacity asynchronous block request scheduling.
//!
//! [`AsyncBlockQueue`] reserves every request slot, device slot, and priority queue in
//! [`AsyncBlockQueue::try_new`]. Submission copies bounded DMA metadata into those tables.
//! Dispatch and completion never grow a collection. A timed-out or cancelled in-flight request
//! keeps its DMA and bounce-buffer ownership until hardware completes it or a reset/removal epoch
//! proves that the old device can no longer access the memory.

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use core::{cmp::min, task::Poll};

pub const SECTOR_SIZE: u32 = 512;
pub const MAX_DMA_SEGMENTS: usize = 32;
pub const MAX_CHILDREN: usize = 64;
pub const DEFAULT_CHILD_BYTES: u32 = 4096;
pub const MAX_REQUEST_BYTES: u32 = DEFAULT_CHILD_BYTES * MAX_CHILDREN as u32;

const INDEX_BITS: u32 = 32;
const INDEX_MASK: u64 = u32::MAX as u64;
const PRIORITY_COUNT: usize = 3;

/// A generation-tagged request-table identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockRequestId(u64);

impl BlockRequestId {
    pub const INVALID: Self = Self(0);

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> INDEX_BITS) as u32
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.generation() != 0 && self.encoded_index() != 0
    }

    const fn encoded_index(self) -> u32 {
        (self.0 & INDEX_MASK) as u32
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
        debug_assert!(index < u32::MAX as usize);
        debug_assert_ne!(generation, 0);
        Self((u64::from(generation) << INDEX_BITS) | (index as u64 + 1))
    }
}

/// A generation-tagged registered device identity.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockDeviceId(u64);

impl BlockDeviceId {
    pub const INVALID: Self = Self(0);

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn generation(self) -> u32 {
        (self.0 >> INDEX_BITS) as u32
    }

    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.generation() != 0 && self.encoded_index() != 0
    }

    const fn encoded_index(self) -> u32 {
        (self.0 & INDEX_MASK) as u32
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
        debug_assert!(index < u32::MAX as usize);
        debug_assert_ne!(generation, 0);
        Self((u64::from(generation) << INDEX_BITS) | (index as u64 + 1))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockOperation {
    Read,
    Write,
    Flush,
    /// An ordering and durability fence. Drivers may implement this as a native barrier or flush.
    Barrier,
}

impl BlockOperation {
    const fn transfers_data(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    const fn is_fence(self) -> bool {
        matches!(self, Self::Flush | Self::Barrier)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockPriority {
    Latency,
    Normal,
    Background,
}

impl BlockPriority {
    const fn index(self) -> usize {
        match self {
            Self::Latency => 0,
            Self::Normal => 1,
            Self::Background => 2,
        }
    }

    const fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Latency,
            1 => Self::Normal,
            _ => Self::Background,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DmaSegment {
    pub physical_address: u64,
    pub length: u32,
}

impl DmaSegment {
    const EMPTY: Self = Self {
        physical_address: 0,
        length: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaAddressMode {
    Bits32,
    Bits64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaConstraints {
    pub address_mode: DmaAddressMode,
    pub address_alignment: u32,
    pub max_segments: u8,
    pub max_segment_len: u32,
}

impl DmaConstraints {
    pub const fn dma32() -> Self {
        Self {
            address_mode: DmaAddressMode::Bits32,
            address_alignment: 1,
            max_segments: MAX_DMA_SEGMENTS as u8,
            max_segment_len: u32::MAX,
        }
    }

    pub const fn dma64() -> Self {
        Self {
            address_mode: DmaAddressMode::Bits64,
            address_alignment: 1,
            max_segments: MAX_DMA_SEGMENTS as u8,
            max_segment_len: u32::MAX,
        }
    }

    const fn is_valid(self) -> bool {
        self.address_alignment != 0
            && self.address_alignment.is_power_of_two()
            && self.max_segments != 0
            && self.max_segments as usize <= MAX_DMA_SEGMENTS
            && self.max_segment_len != 0
    }
}

/// Ownership token from a bounded bounce-buffer pool.
///
/// The queue treats the token as opaque ownership and returns it in [`RequestCompletion`]. The
/// pool can use `pool_index` plus `generation` to reject stale returns.
#[derive(Debug, Eq, PartialEq)]
pub struct BounceBufferLease {
    pub pool_index: u16,
    pub generation: u32,
    pub physical_address: u64,
    pub capacity: u32,
    pub used: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BufferKind {
    Segments,
    Bounce,
}

/// Bounded, owned DMA metadata for one parent request.
#[derive(Debug, Eq, PartialEq)]
pub struct BlockBuffer {
    byte_len: u32,
    segments: [DmaSegment; MAX_DMA_SEGMENTS],
    segment_count: u8,
    kind: BufferKind,
    bounce: Option<BounceBufferLease>,
}

impl BlockBuffer {
    /// Creates a buffer backed by physical ranges covered by a direct-DMA lease.
    ///
    /// # Safety
    ///
    /// The caller must hold exclusive ownership of every physical range in `segments` for the
    /// lifetime of the returned buffer. Those ranges must remain pinned and DMA-accessible, and
    /// must not be released, remapped, reused, or accessed in a way that conflicts with device DMA.
    /// After the buffer is submitted successfully, these requirements continue until the request
    /// completion is taken. A failed submission returns the request and therefore the buffer's
    /// ownership to the caller.
    pub unsafe fn from_dma_segments(
        byte_len: u32,
        segments: &[DmaSegment],
    ) -> Result<Self, BufferError> {
        if byte_len == 0 {
            return Err(BufferError::Empty);
        }
        if segments.is_empty() || segments.len() > MAX_DMA_SEGMENTS {
            return Err(BufferError::SegmentCount);
        }
        let mut total = 0_u64;
        let mut owned = [DmaSegment::EMPTY; MAX_DMA_SEGMENTS];
        for (index, segment) in segments.iter().copied().enumerate() {
            if segment.length == 0 {
                return Err(BufferError::EmptySegment);
            }
            segment
                .physical_address
                .checked_add(u64::from(segment.length) - 1)
                .ok_or(BufferError::AddressOverflow)?;
            total = total
                .checked_add(u64::from(segment.length))
                .ok_or(BufferError::LengthOverflow)?;
            owned[index] = segment;
        }
        if total != u64::from(byte_len) {
            return Err(BufferError::LengthMismatch);
        }
        Ok(Self {
            byte_len,
            segments: owned,
            segment_count: segments.len() as u8,
            kind: BufferKind::Segments,
            bounce: None,
        })
    }

    pub fn from_bounce(lease: BounceBufferLease) -> Result<Self, BufferError> {
        if lease.generation == 0 || lease.capacity == 0 || lease.used == 0 {
            return Err(BufferError::InvalidBounceLease);
        }
        if lease.used > lease.capacity {
            return Err(BufferError::InvalidBounceLease);
        }
        lease
            .physical_address
            .checked_add(u64::from(lease.used) - 1)
            .ok_or(BufferError::AddressOverflow)?;
        let mut segments = [DmaSegment::EMPTY; MAX_DMA_SEGMENTS];
        segments[0] = DmaSegment {
            physical_address: lease.physical_address,
            length: lease.used,
        };
        Ok(Self {
            byte_len: lease.used,
            segments,
            segment_count: 1,
            kind: BufferKind::Bounce,
            bounce: Some(lease),
        })
    }

    pub const fn byte_len(&self) -> u32 {
        self.byte_len
    }

    pub fn segments(&self) -> &[DmaSegment] {
        &self.segments[..usize::from(self.segment_count)]
    }

    pub const fn is_bounce(&self) -> bool {
        matches!(self.kind, BufferKind::Bounce)
    }

    /// Reports whether this buffer can be submitted directly or must be copied into a
    /// driver-owned bounce buffer that satisfies `constraints`.
    pub fn dma_disposition(&self, constraints: DmaConstraints) -> DmaDisposition {
        match self.validate_for(constraints) {
            Ok(()) => DmaDisposition::Direct,
            Err(error) => DmaDisposition::BounceRequired(error),
        }
    }

    fn validate_for(&self, constraints: DmaConstraints) -> Result<(), DmaError> {
        if usize::from(self.segment_count) > usize::from(constraints.max_segments) {
            return Err(DmaError::TooManySegments);
        }
        for segment in self.segments() {
            if segment.length > constraints.max_segment_len {
                return Err(DmaError::SegmentTooLong);
            }
            if segment.physical_address % u64::from(constraints.address_alignment) != 0 {
                return Err(DmaError::MisalignedAddress);
            }
            let end = segment
                .physical_address
                .checked_add(u64::from(segment.length) - 1)
                .ok_or(DmaError::AddressOverflow)?;
            if constraints.address_mode == DmaAddressMode::Bits32 && end > u64::from(u32::MAX) {
                return Err(DmaError::AddressOutsideDmaWindow);
            }
        }
        Ok(())
    }

    fn slice(
        &self,
        offset: u32,
        length: u32,
    ) -> Result<([DmaSegment; MAX_DMA_SEGMENTS], u8), DmaError> {
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= self.byte_len)
            .ok_or(DmaError::SliceOutOfBounds)?;
        let mut result = [DmaSegment::EMPTY; MAX_DMA_SEGMENTS];
        let mut result_count = 0_usize;
        let mut segment_start = 0_u32;
        for segment in self.segments() {
            let segment_end = segment_start
                .checked_add(segment.length)
                .ok_or(DmaError::AddressOverflow)?;
            let overlap_start = segment_start.max(offset);
            let overlap_end = segment_end.min(end);
            if overlap_start < overlap_end {
                if result_count == MAX_DMA_SEGMENTS {
                    return Err(DmaError::TooManySegments);
                }
                let within_segment = overlap_start - segment_start;
                result[result_count] = DmaSegment {
                    physical_address: segment
                        .physical_address
                        .checked_add(u64::from(within_segment))
                        .ok_or(DmaError::AddressOverflow)?,
                    length: overlap_end - overlap_start,
                };
                result_count += 1;
            }
            segment_start = segment_end;
            if segment_start >= end {
                break;
            }
        }
        if result_count == 0 {
            return Err(DmaError::SliceOutOfBounds);
        }
        Ok((result, result_count as u8))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferError {
    Empty,
    SegmentCount,
    EmptySegment,
    LengthMismatch,
    LengthOverflow,
    AddressOverflow,
    InvalidBounceLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaError {
    TooManySegments,
    SegmentTooLong,
    MisalignedAddress,
    AddressOutsideDmaWindow,
    AddressOverflow,
    SliceOutOfBounds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaDisposition {
    Direct,
    BounceRequired(DmaError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    pub max_request_bytes: u32,
    pub child_bytes: u32,
    pub priority_weights: [u8; PRIORITY_COUNT],
    pub background_aging_ns: u64,
    pub background_progress_interval: u32,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_request_bytes: MAX_REQUEST_BYTES,
            child_bytes: DEFAULT_CHILD_BYTES,
            priority_weights: [8, 4, 1],
            background_aging_ns: 50_000_000,
            background_progress_interval: 12,
        }
    }
}

impl QueueConfig {
    const fn is_valid(self) -> bool {
        self.max_request_bytes != 0
            && self.max_request_bytes <= MAX_REQUEST_BYTES
            && self.max_request_bytes % SECTOR_SIZE == 0
            && self.child_bytes != 0
            && self.child_bytes % SECTOR_SIZE == 0
            && self.child_bytes <= self.max_request_bytes
            && self.priority_weights[0] != 0
            && self.priority_weights[1] != 0
            && self.priority_weights[2] != 0
            && self.background_progress_interval != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockDeviceConfig {
    pub capacity_sectors: u64,
    pub queue_depth: u16,
    pub supports_flush: bool,
    pub dma: DmaConstraints,
}

impl BlockDeviceConfig {
    const fn is_valid(self) -> bool {
        self.capacity_sectors != 0 && self.queue_depth != 0 && self.dma.is_valid()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueBuildError {
    InvalidCapacity,
    CapacityTooLarge,
    InvalidConfiguration,
    OutOfMemory,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RequestSpec {
    pub device: BlockDeviceId,
    pub operation: BlockOperation,
    pub lba: u64,
    pub buffer: Option<BlockBuffer>,
    pub priority: BlockPriority,
    /// Absolute monotonic deadline. `None` means no deadline.
    pub deadline_ns: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    Quiescing,
    QueueFull,
    InvalidDevice,
    DeviceRemoved,
    InvalidOperationBuffer,
    InvalidLength,
    RequestTooLarge,
    TooManyChildren,
    OutOfBounds,
    AddressOverflow,
    DeadlineExpired,
    /// The caller must replace direct SG metadata with a valid bounded bounce lease.
    BounceRequired(DmaError),
    /// A supplied bounce lease itself violates the device DMA constraints.
    Dma(DmaError),
    SequenceExhausted,
    OrderingEpochExhausted,
}

/// A failed submission returns the complete request, including bounce ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct SubmitFailure {
    pub error: SubmitError,
    pub request: RequestSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestOutcome {
    Success,
    Cancelled,
    TimedOut,
    IoError,
    Unsupported,
    DeviceReset,
    DeviceRemoved,
    ForcedShutdown,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RequestCompletion {
    pub id: BlockRequestId,
    pub outcome: RequestOutcome,
    pub bytes_completed: u32,
    pub bounce: Option<BounceBufferLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPoll {
    Unknown,
    Queued,
    InFlight,
    CancelPending,
    Complete(RequestOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelResult {
    Unknown,
    AlreadyComplete,
    CancelledBeforeDispatch,
    PendingHardware,
    AlreadyPending,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimeoutReport {
    pub completed_without_dma: usize,
    pub waiting_for_hardware: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceLifecycleError {
    InvalidDevice,
    DeviceRemoved,
    EpochExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRegisterError {
    InvalidConfiguration,
    NoDeviceSlot,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardwareStatus {
    Success,
    IoError,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDisposition {
    Accepted,
    DuplicateRejected,
    StaleRejected,
}

/// Opaque command ownership checked on completion and cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchToken {
    request_id: BlockRequestId,
    device_id: BlockDeviceId,
    device_epoch: u32,
    child_index: u16,
    serial: u64,
    shutdown_flush: bool,
}

impl DispatchToken {
    pub const fn request_id(self) -> BlockRequestId {
        self.request_id
    }

    pub const fn device_id(self) -> BlockDeviceId {
        self.device_id
    }

    pub const fn device_epoch(self) -> u32 {
        self.device_epoch
    }

    pub const fn child_index(self) -> u16 {
        self.child_index
    }

    pub const fn is_shutdown_flush(self) -> bool {
        self.shutdown_flush
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchCommand {
    pub token: DispatchToken,
    pub operation: BlockOperation,
    pub lba: u64,
    pub byte_len: u32,
    pub priority: BlockPriority,
    /// Requests before a fence share its epoch; requests after it use the next epoch.
    pub ordering_epoch: u64,
    segments: [DmaSegment; MAX_DMA_SEGMENTS],
    segment_count: u8,
}

impl DispatchCommand {
    pub fn segments(&self) -> &[DmaSegment] {
        &self.segments[..usize::from(self.segment_count)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverCompletion {
    pub token: DispatchToken,
    pub status: HardwareStatus,
}

/// Poll-style contract implemented by interrupt-backed block drivers.
///
/// `poll_ready` and `poll_completion` run in task/worker context. An ISR should only acknowledge
/// hardware and make that worker runnable. Once `submit` accepts a command, the driver must report
/// its token exactly once, unless a successful reset/removal has stopped DMA and the queue has been
/// notified through `reset_device`/`remove_device`. Returning `Pending` must not spin indefinitely.
/// If `submit` returns `Err`, it must not have retained the command or started DMA; this lets
/// [`run_device_worker`] safely finish the rejected command as an I/O error.
pub trait AsyncBlockDevice {
    type Error;

    fn config(&self) -> BlockDeviceConfig;

    fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>>;

    fn submit(&mut self, command: &DispatchCommand) -> Result<(), Self::Error>;

    fn poll_completion(&mut self) -> Poll<Result<DriverCompletion, Self::Error>>;

    /// Requests best-effort cancellation. Ownership remains with hardware until completion/reset.
    fn request_cancel(&mut self, token: DispatchToken) -> Result<(), Self::Error>;

    /// Completes only after old-epoch DMA has stopped.
    fn poll_reset(&mut self) -> Poll<Result<(), Self::Error>>;
}

/// Maximum driver operations performed by one [`run_device_worker`] call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceWorkerBudget {
    pub completions: usize,
    pub cancellations: usize,
    pub submissions: usize,
}

/// Work completed by one bounded device-worker call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceWorkerReport {
    pub completion_polls: usize,
    pub accepted_completions: usize,
    pub duplicate_completions: usize,
    pub stale_completions: usize,
    pub cancellation_polls: usize,
    pub cancellations_requested: usize,
    pub readiness_polls: usize,
    pub commands_submitted: usize,
    pub rejected_commands: usize,
    pub timeouts: TimeoutReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceWorkerOperation {
    PollCompletion,
    RequestCancel,
    PollReady,
    Submit,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeviceWorkerError<E> {
    pub operation: DeviceWorkerOperation,
    pub error: E,
    pub token: Option<DispatchToken>,
    pub report: DeviceWorkerReport,
}

/// Polls one driver without allocation or unbounded draining.
///
/// Each budget field limits calls to its matching driver operation. Completions run first so a
/// completion already visible to the driver wins over a queued cancellation. Deadline expiry and
/// queue scans remain bounded by capacities fixed in [`AsyncBlockQueue::try_new`]. DMA ownership
/// remains with the queue until completion or a reset/removal epoch proves that hardware stopped.
pub fn run_device_worker<D: AsyncBlockDevice + ?Sized>(
    queue: &mut AsyncBlockQueue,
    device: BlockDeviceId,
    driver: &mut D,
    now_ns: u64,
    budget: DeviceWorkerBudget,
) -> Result<DeviceWorkerReport, DeviceWorkerError<D::Error>> {
    let mut report = DeviceWorkerReport::default();

    for _ in 0..budget.completions {
        report.completion_polls += 1;
        let completion = match driver.poll_completion() {
            Poll::Pending => break,
            Poll::Ready(Ok(completion)) => completion,
            Poll::Ready(Err(error)) => {
                return Err(DeviceWorkerError {
                    operation: DeviceWorkerOperation::PollCompletion,
                    error,
                    token: None,
                    report,
                });
            }
        };
        match queue.complete_at(completion.token, completion.status, now_ns) {
            CompletionDisposition::Accepted => report.accepted_completions += 1,
            CompletionDisposition::DuplicateRejected => report.duplicate_completions += 1,
            CompletionDisposition::StaleRejected => report.stale_completions += 1,
        }
    }

    report.timeouts = queue.expire_deadlines(now_ns);

    for _ in 0..budget.cancellations {
        report.cancellation_polls += 1;
        let Some(token) = queue.poll_cancel(device) else {
            break;
        };
        if let Err(error) = driver.request_cancel(token) {
            return Err(DeviceWorkerError {
                operation: DeviceWorkerOperation::RequestCancel,
                error,
                token: Some(token),
                report,
            });
        }
        report.cancellations_requested += 1;
    }

    for _ in 0..budget.submissions {
        report.readiness_polls += 1;
        match driver.poll_ready() {
            Poll::Pending => break,
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => {
                return Err(DeviceWorkerError {
                    operation: DeviceWorkerOperation::PollReady,
                    error,
                    token: None,
                    report,
                });
            }
        }
        let Some(command) = queue.dispatch_one(device, now_ns) else {
            break;
        };
        if let Err(error) = driver.submit(&command) {
            let disposition = queue.complete_at(command.token, HardwareStatus::IoError, now_ns);
            debug_assert_eq!(disposition, CompletionDisposition::Accepted);
            report.rejected_commands += 1;
            return Err(DeviceWorkerError {
                operation: DeviceWorkerOperation::Submit,
                error,
                token: Some(command.token),
                report,
            });
        }
        report.commands_submitted += 1;
    }

    Ok(report)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockDiagnostics {
    pub submissions: u64,
    pub rejected_submissions: u64,
    pub dispatches: u64,
    pub background_dispatches: u64,
    pub aged_background_dispatches: u64,
    pub terminal_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub transferred_bytes: u64,
    pub io_errors: u64,
    pub unsupported_operations: u64,
    pub cancellations: u64,
    pub timeouts: u64,
    pub resets: u64,
    pub removals: u64,
    pub stale_completions: u64,
    pub duplicate_completions: u64,
    pub shutdown_flushes: u64,
    pub shutdown_flush_failures: u64,
    pub queue_high_water: usize,
    pub in_flight_high_water: usize,
    pub max_queue_wait_ns: u64,
    pub service_latency_samples: u64,
    pub total_service_latency_ns: u64,
    pub max_service_latency_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticSnapshot {
    pub counters: BlockDiagnostics,
    pub live_requests: usize,
    pub queued_requests: usize,
    pub in_flight_commands: usize,
    pub registered_devices: usize,
    pub shutdown: ShutdownState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownState {
    Running,
    Quiescing,
    Drained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Queued,
    Active,
    Terminal,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildState {
    Pending,
    InFlight { serial: u64, cancel_notified: bool },
    Done,
}

#[derive(Debug)]
struct RequestSlot {
    generation: u32,
    state: SlotState,
    device: BlockDeviceId,
    operation: BlockOperation,
    lba: u64,
    buffer: Option<BlockBuffer>,
    priority: BlockPriority,
    deadline_ns: Option<u64>,
    sequence: u64,
    ordering_epoch: u64,
    enqueued_at_ns: u64,
    first_dispatched_at_ns: Option<u64>,
    child_count: u16,
    next_child: u16,
    children: [ChildState; MAX_CHILDREN],
    in_flight: u16,
    queued_entry: bool,
    pending_outcome: Option<RequestOutcome>,
    terminal_outcome: Option<RequestOutcome>,
    bytes_completed: u32,
}

impl RequestSlot {
    fn vacant(generation: u32) -> Self {
        Self {
            generation,
            state: SlotState::Free,
            device: BlockDeviceId::INVALID,
            operation: BlockOperation::Read,
            lba: 0,
            buffer: None,
            priority: BlockPriority::Normal,
            deadline_ns: None,
            sequence: 0,
            ordering_epoch: 0,
            enqueued_at_ns: 0,
            first_dispatched_at_ns: None,
            child_count: 0,
            next_child: 0,
            children: [ChildState::Pending; MAX_CHILDREN],
            in_flight: 0,
            queued_entry: false,
            pending_outcome: None,
            terminal_outcome: None,
            bytes_completed: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueEntry {
    id: BlockRequestId,
    enqueued_at_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownFlushState {
    None,
    Pending,
    InFlight { serial: u64 },
    Done,
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct DeviceSlot {
    generation: u32,
    epoch: u32,
    ever_registered: bool,
    present: bool,
    config: BlockDeviceConfig,
    in_flight: u16,
    next_sequence: u64,
    next_ordering_epoch: u64,
    next_serial: u64,
    credits: [u16; PRIORITY_COUNT],
    fair_cursor: usize,
    non_background_dispatches: u32,
    shutdown_flush: ShutdownFlushState,
}

impl DeviceSlot {
    const EMPTY_CONFIG: BlockDeviceConfig = BlockDeviceConfig {
        capacity_sectors: 0,
        queue_depth: 0,
        supports_flush: false,
        dma: DmaConstraints::dma64(),
    };

    const fn empty() -> Self {
        Self {
            generation: 1,
            epoch: 1,
            ever_registered: false,
            present: false,
            config: Self::EMPTY_CONFIG,
            in_flight: 0,
            next_sequence: 1,
            next_ordering_epoch: 1,
            next_serial: 1,
            credits: [0; PRIORITY_COUNT],
            fair_cursor: 0,
            non_background_dispatches: 0,
            shutdown_flush: ShutdownFlushState::None,
        }
    }
}

/// Fixed-capacity multi-device block scheduler.
pub struct AsyncBlockQueue {
    config: QueueConfig,
    slots: Vec<RequestSlot>,
    devices: Vec<DeviceSlot>,
    queues: [VecDeque<QueueEntry>; PRIORITY_COUNT],
    live_requests: usize,
    queued_requests: usize,
    in_flight_commands: usize,
    registered_devices: usize,
    shutdown: ShutdownState,
    diagnostics: BlockDiagnostics,
}

impl AsyncBlockQueue {
    pub fn try_new(
        request_capacity: usize,
        device_capacity: usize,
        config: QueueConfig,
    ) -> Result<Self, QueueBuildError> {
        if request_capacity == 0 || device_capacity == 0 {
            return Err(QueueBuildError::InvalidCapacity);
        }
        if request_capacity >= u32::MAX as usize || device_capacity >= u32::MAX as usize {
            return Err(QueueBuildError::CapacityTooLarge);
        }
        if !config.is_valid() {
            return Err(QueueBuildError::InvalidConfiguration);
        }

        let mut slots = Vec::new();
        slots
            .try_reserve_exact(request_capacity)
            .map_err(|_| QueueBuildError::OutOfMemory)?;
        for _ in 0..request_capacity {
            slots.push(RequestSlot::vacant(1));
        }

        let mut devices = Vec::new();
        devices
            .try_reserve_exact(device_capacity)
            .map_err(|_| QueueBuildError::OutOfMemory)?;
        for _ in 0..device_capacity {
            devices.push(DeviceSlot::empty());
        }

        let mut queues: [VecDeque<QueueEntry>; PRIORITY_COUNT] =
            core::array::from_fn(|_| VecDeque::new());
        for queue in &mut queues {
            queue
                .try_reserve_exact(request_capacity)
                .map_err(|_| QueueBuildError::OutOfMemory)?;
        }

        Ok(Self {
            config,
            slots,
            devices,
            queues,
            live_requests: 0,
            queued_requests: 0,
            in_flight_commands: 0,
            registered_devices: 0,
            shutdown: ShutdownState::Running,
            diagnostics: BlockDiagnostics::default(),
        })
    }

    pub const fn request_capacity(&self) -> usize {
        self.slots.len()
    }

    pub const fn device_capacity(&self) -> usize {
        self.devices.len()
    }

    pub fn register_device(
        &mut self,
        config: BlockDeviceConfig,
    ) -> Result<BlockDeviceId, DeviceRegisterError> {
        if !config.is_valid() {
            return Err(DeviceRegisterError::InvalidConfiguration);
        }
        let index = self
            .devices
            .iter()
            .position(|device| !device.present)
            .ok_or(DeviceRegisterError::NoDeviceSlot)?;
        let device = &mut self.devices[index];
        if device.ever_registered {
            device.generation = device
                .generation
                .checked_add(1)
                .ok_or(DeviceRegisterError::GenerationExhausted)?;
        }
        device.ever_registered = true;
        device.present = true;
        device.epoch = 1;
        device.config = config;
        device.in_flight = 0;
        device.next_sequence = 1;
        device.next_ordering_epoch = 1;
        device.next_serial = 1;
        device.credits = [0; PRIORITY_COUNT];
        device.fair_cursor = 0;
        device.non_background_dispatches = 0;
        device.shutdown_flush = if self.shutdown == ShutdownState::Quiescing {
            ShutdownFlushState::Pending
        } else {
            ShutdownFlushState::None
        };
        self.registered_devices += 1;
        Ok(BlockDeviceId::from_parts(index, device.generation))
    }

    pub fn device_epoch(&self, id: BlockDeviceId) -> Option<u32> {
        self.device_index(id).map(|index| self.devices[index].epoch)
    }

    pub fn submit(
        &mut self,
        now_ns: u64,
        request: RequestSpec,
    ) -> Result<BlockRequestId, SubmitFailure> {
        let validation = self.validate_submission(now_ns, &request);
        let (device_index, child_count) = match validation {
            Ok(value) => value,
            Err(error) => {
                self.diagnostics.rejected_submissions =
                    self.diagnostics.rejected_submissions.saturating_add(1);
                return Err(SubmitFailure { error, request });
            }
        };
        let slot_index = match self
            .slots
            .iter()
            .position(|slot| slot.state == SlotState::Free)
        {
            Some(index) => index,
            None => {
                self.diagnostics.rejected_submissions =
                    self.diagnostics.rejected_submissions.saturating_add(1);
                return Err(SubmitFailure {
                    error: SubmitError::QueueFull,
                    request,
                });
            }
        };
        let sequence = self.devices[device_index].next_sequence;
        let next_sequence = match sequence.checked_add(1) {
            Some(value) => value,
            None => {
                self.diagnostics.rejected_submissions =
                    self.diagnostics.rejected_submissions.saturating_add(1);
                return Err(SubmitFailure {
                    error: SubmitError::SequenceExhausted,
                    request,
                });
            }
        };
        let ordering_epoch = self.devices[device_index].next_ordering_epoch;
        let next_ordering_epoch = if request.operation.is_fence() {
            match ordering_epoch.checked_add(1) {
                Some(value) => value,
                None => {
                    self.diagnostics.rejected_submissions =
                        self.diagnostics.rejected_submissions.saturating_add(1);
                    return Err(SubmitFailure {
                        error: SubmitError::OrderingEpochExhausted,
                        request,
                    });
                }
            }
        } else {
            ordering_epoch
        };
        self.devices[device_index].next_sequence = next_sequence;
        self.devices[device_index].next_ordering_epoch = next_ordering_epoch;

        let generation = self.slots[slot_index].generation;
        let id = BlockRequestId::from_parts(slot_index, generation);
        let slot = &mut self.slots[slot_index];
        slot.state = SlotState::Queued;
        slot.device = request.device;
        slot.operation = request.operation;
        slot.lba = request.lba;
        slot.buffer = request.buffer;
        slot.priority = request.priority;
        slot.deadline_ns = request.deadline_ns;
        slot.sequence = sequence;
        slot.ordering_epoch = ordering_epoch;
        slot.enqueued_at_ns = now_ns;
        slot.first_dispatched_at_ns = None;
        slot.child_count = child_count;
        slot.next_child = 0;
        slot.children.fill(ChildState::Pending);
        slot.in_flight = 0;
        slot.queued_entry = false;
        slot.pending_outcome = None;
        slot.terminal_outcome = None;
        slot.bytes_completed = 0;
        self.enqueue(slot_index, now_ns);
        self.live_requests += 1;
        self.diagnostics.submissions = self.diagnostics.submissions.saturating_add(1);
        self.diagnostics.queue_high_water =
            self.diagnostics.queue_high_water.max(self.queued_requests);
        Ok(id)
    }

    fn validate_submission(
        &self,
        now_ns: u64,
        request: &RequestSpec,
    ) -> Result<(usize, u16), SubmitError> {
        if self.shutdown != ShutdownState::Running {
            return Err(SubmitError::Quiescing);
        }
        let device_index = request
            .device
            .index()
            .filter(|index| *index < self.devices.len())
            .ok_or(SubmitError::InvalidDevice)?;
        let device = &self.devices[device_index];
        if device.generation != request.device.generation() {
            return Err(SubmitError::InvalidDevice);
        }
        if !device.present {
            return Err(SubmitError::DeviceRemoved);
        }
        if request
            .deadline_ns
            .is_some_and(|deadline| deadline <= now_ns)
        {
            return Err(SubmitError::DeadlineExpired);
        }

        if request.operation.transfers_data() {
            let buffer = request
                .buffer
                .as_ref()
                .ok_or(SubmitError::InvalidOperationBuffer)?;
            let byte_len = buffer.byte_len();
            if byte_len == 0 || byte_len % SECTOR_SIZE != 0 {
                return Err(SubmitError::InvalidLength);
            }
            if byte_len > self.config.max_request_bytes {
                return Err(SubmitError::RequestTooLarge);
            }
            if let Err(error) = buffer.validate_for(device.config.dma) {
                return Err(if buffer.is_bounce() {
                    SubmitError::Dma(error)
                } else {
                    SubmitError::BounceRequired(error)
                });
            }
            let sectors = u64::from(byte_len / SECTOR_SIZE);
            let end = request
                .lba
                .checked_add(sectors)
                .ok_or(SubmitError::AddressOverflow)?;
            if end > device.config.capacity_sectors {
                return Err(SubmitError::OutOfBounds);
            }
            let children = byte_len.div_ceil(self.config.child_bytes);
            if children == 0 || children as usize > MAX_CHILDREN {
                return Err(SubmitError::TooManyChildren);
            }
            Ok((device_index, children as u16))
        } else {
            if request.buffer.is_some() || request.lba != 0 {
                return Err(SubmitError::InvalidOperationBuffer);
            }
            Ok((device_index, 1))
        }
    }

    pub fn poll_request(&self, id: BlockRequestId) -> RequestPoll {
        let Some(index) = self.request_index(id) else {
            return RequestPoll::Unknown;
        };
        let slot = &self.slots[index];
        match slot.state {
            SlotState::Queued if slot.pending_outcome.is_some() => RequestPoll::CancelPending,
            SlotState::Queued => RequestPoll::Queued,
            SlotState::Active if slot.pending_outcome.is_some() => RequestPoll::CancelPending,
            SlotState::Active => RequestPoll::InFlight,
            SlotState::Terminal => RequestPoll::Complete(
                slot.terminal_outcome
                    .expect("terminal request has an outcome"),
            ),
            SlotState::Free | SlotState::Retired => RequestPoll::Unknown,
        }
    }

    pub fn cancel(&mut self, id: BlockRequestId) -> CancelResult {
        let Some(index) = self.request_index(id) else {
            return CancelResult::Unknown;
        };
        match self.slots[index].state {
            SlotState::Terminal => CancelResult::AlreadyComplete,
            SlotState::Free | SlotState::Retired => CancelResult::Unknown,
            SlotState::Queued | SlotState::Active => {
                if self.slots[index].pending_outcome.is_some() {
                    return CancelResult::AlreadyPending;
                }
                self.diagnostics.cancellations = self.diagnostics.cancellations.saturating_add(1);
                self.abort_request(index, RequestOutcome::Cancelled);
                if self.slots[index].state == SlotState::Terminal {
                    CancelResult::CancelledBeforeDispatch
                } else {
                    CancelResult::PendingHardware
                }
            }
        }
    }

    pub fn expire_deadlines(&mut self, now_ns: u64) -> TimeoutReport {
        let mut report = TimeoutReport::default();
        for index in 0..self.slots.len() {
            let should_expire = matches!(
                self.slots[index].state,
                SlotState::Queued | SlotState::Active
            ) && self.slots[index].pending_outcome.is_none()
                && self.slots[index]
                    .deadline_ns
                    .is_some_and(|deadline| deadline <= now_ns);
            if !should_expire {
                continue;
            }
            let had_dma = self.slots[index].in_flight != 0;
            self.diagnostics.timeouts = self.diagnostics.timeouts.saturating_add(1);
            self.abort_request(index, RequestOutcome::TimedOut);
            if had_dma {
                report.waiting_for_hardware += 1;
            } else {
                report.completed_without_dma += 1;
            }
        }
        report
    }

    /// Returns each in-flight token needing a best-effort hardware cancellation once.
    pub fn poll_cancel(&mut self, device: BlockDeviceId) -> Option<DispatchToken> {
        let device_index = self.device_index(device)?;
        let epoch = self.devices[device_index].epoch;
        for slot_index in 0..self.slots.len() {
            let slot = &mut self.slots[slot_index];
            if slot.device != device || slot.pending_outcome.is_none() {
                continue;
            }
            let id = BlockRequestId::from_parts(slot_index, slot.generation);
            for child_index in 0..usize::from(slot.next_child) {
                if let ChildState::InFlight {
                    serial,
                    cancel_notified: false,
                } = slot.children[child_index]
                {
                    slot.children[child_index] = ChildState::InFlight {
                        serial,
                        cancel_notified: true,
                    };
                    return Some(DispatchToken {
                        request_id: id,
                        device_id: device,
                        device_epoch: epoch,
                        child_index: child_index as u16,
                        serial,
                        shutdown_flush: false,
                    });
                }
            }
        }
        None
    }

    /// Selects one command for a specific device according to weighted fair priority policy.
    pub fn dispatch_one(&mut self, device: BlockDeviceId, now_ns: u64) -> Option<DispatchCommand> {
        self.expire_deadlines(now_ns);
        let device_index = self.device_index(device)?;
        if self.devices[device_index].in_flight >= self.devices[device_index].config.queue_depth {
            return None;
        }

        let selected = self.select_request(device_index, now_ns);
        if let Some(slot_index) = selected {
            return self.dispatch_request(device_index, slot_index, now_ns);
        }
        self.dispatch_shutdown_flush(device_index)
    }

    fn select_request(&mut self, device_index: usize, now_ns: u64) -> Option<usize> {
        let force_background = self.devices[device_index].non_background_dispatches
            >= self.config.background_progress_interval;
        if let Some(index) =
            self.take_eligible(device_index, BlockPriority::Background, now_ns, true)
        {
            self.diagnostics.aged_background_dispatches = self
                .diagnostics
                .aged_background_dispatches
                .saturating_add(1);
            return Some(index);
        }
        if force_background {
            if let Some(index) =
                self.take_eligible(device_index, BlockPriority::Background, now_ns, false)
            {
                return Some(index);
            }
        }

        for _ in 0..PRIORITY_COUNT * 2 {
            if self.devices[device_index].credits == [0; PRIORITY_COUNT] {
                for priority in 0..PRIORITY_COUNT {
                    self.devices[device_index].credits[priority] =
                        u16::from(self.config.priority_weights[priority]);
                }
            }
            let priority_index = self.devices[device_index].fair_cursor;
            self.devices[device_index].fair_cursor = (priority_index + 1) % PRIORITY_COUNT;
            if self.devices[device_index].credits[priority_index] == 0 {
                continue;
            }
            let priority = BlockPriority::from_index(priority_index);
            if let Some(index) = self.take_eligible(device_index, priority, now_ns, false) {
                self.devices[device_index].credits[priority_index] -= 1;
                return Some(index);
            }
            self.devices[device_index].credits[priority_index] = 0;
        }
        None
    }

    fn take_eligible(
        &mut self,
        device_index: usize,
        priority: BlockPriority,
        now_ns: u64,
        require_aged: bool,
    ) -> Option<usize> {
        let queue_index = priority.index();
        let count = self.queues[queue_index].len();
        for _ in 0..count {
            let entry = self.queues[queue_index]
                .pop_front()
                .expect("queue length was sampled");
            let candidate = self.request_index(entry.id).filter(|index| {
                let slot = &self.slots[*index];
                slot.queued_entry
                    && slot.device.index() == Some(device_index)
                    && slot.priority == priority
                    && (!require_aged
                        || now_ns.saturating_sub(entry.enqueued_at_ns)
                            >= self.config.background_aging_ns)
                    && self.is_dispatchable(*index, device_index)
            });
            if let Some(index) = candidate {
                self.slots[index].queued_entry = false;
                self.queued_requests = self.queued_requests.saturating_sub(1);
                return Some(index);
            }
            self.queues[queue_index].push_back(entry);
        }
        None
    }

    fn is_dispatchable(&self, slot_index: usize, device_index: usize) -> bool {
        let slot = &self.slots[slot_index];
        if !matches!(slot.state, SlotState::Queued | SlotState::Active)
            || slot.pending_outcome.is_some()
            || slot.next_child >= slot.child_count
            || !self.devices[device_index].present
        {
            return false;
        }
        if slot.operation.is_fence() {
            !self.slots.iter().any(|other| {
                other.device == slot.device
                    && other.sequence < slot.sequence
                    && matches!(other.state, SlotState::Queued | SlotState::Active)
            })
        } else {
            !self.slots.iter().any(|other| {
                other.device == slot.device
                    && other.ordering_epoch < slot.ordering_epoch
                    && other.operation.is_fence()
                    && matches!(other.state, SlotState::Queued | SlotState::Active)
            })
        }
    }

    fn dispatch_request(
        &mut self,
        device_index: usize,
        slot_index: usize,
        now_ns: u64,
    ) -> Option<DispatchCommand> {
        let child_index = self.slots[slot_index].next_child;
        let offset = u32::from(child_index).checked_mul(self.config.child_bytes)?;
        let byte_len = if self.slots[slot_index].operation.transfers_data() {
            min(
                self.config.child_bytes,
                self.slots[slot_index]
                    .buffer
                    .as_ref()?
                    .byte_len()
                    .checked_sub(offset)?,
            )
        } else {
            0
        };
        let (segments, segment_count) = if byte_len == 0 {
            ([DmaSegment::EMPTY; MAX_DMA_SEGMENTS], 0)
        } else {
            self.slots[slot_index]
                .buffer
                .as_ref()?
                .slice(offset, byte_len)
                .ok()?
        };
        let serial = self.devices[device_index].next_serial;
        self.devices[device_index].next_serial = next_nonzero_u64(serial);
        let device_id = self.slots[slot_index].device;
        let request_id = BlockRequestId::from_parts(slot_index, self.slots[slot_index].generation);
        let token = DispatchToken {
            request_id,
            device_id,
            device_epoch: self.devices[device_index].epoch,
            child_index,
            serial,
            shutdown_flush: false,
        };
        let lba = self.slots[slot_index]
            .lba
            .checked_add(u64::from(offset / SECTOR_SIZE))?;
        let priority = self.slots[slot_index].priority;
        let operation = self.slots[slot_index].operation;
        let ordering_epoch = self.slots[slot_index].ordering_epoch;
        let queue_wait = now_ns.saturating_sub(self.slots[slot_index].enqueued_at_ns);

        let slot = &mut self.slots[slot_index];
        slot.state = SlotState::Active;
        if slot.first_dispatched_at_ns.is_none() {
            slot.first_dispatched_at_ns = Some(now_ns);
        }
        slot.children[usize::from(child_index)] = ChildState::InFlight {
            serial,
            cancel_notified: false,
        };
        slot.next_child += 1;
        slot.in_flight += 1;
        let requeue = slot.next_child < slot.child_count;
        self.devices[device_index].in_flight += 1;
        self.in_flight_commands += 1;
        self.diagnostics.dispatches = self.diagnostics.dispatches.saturating_add(1);
        self.diagnostics.in_flight_high_water = self
            .diagnostics
            .in_flight_high_water
            .max(self.in_flight_commands);
        self.diagnostics.max_queue_wait_ns = self.diagnostics.max_queue_wait_ns.max(queue_wait);
        if priority == BlockPriority::Background {
            self.devices[device_index].non_background_dispatches = 0;
            self.diagnostics.background_dispatches =
                self.diagnostics.background_dispatches.saturating_add(1);
        } else {
            self.devices[device_index].non_background_dispatches = self.devices[device_index]
                .non_background_dispatches
                .saturating_add(1);
        }
        if requeue {
            self.enqueue(slot_index, now_ns);
        }

        Some(DispatchCommand {
            token,
            operation,
            lba,
            byte_len,
            priority,
            ordering_epoch,
            segments,
            segment_count,
        })
    }

    fn dispatch_shutdown_flush(&mut self, device_index: usize) -> Option<DispatchCommand> {
        if self.shutdown != ShutdownState::Quiescing
            || self.devices[device_index].shutdown_flush != ShutdownFlushState::Pending
            || self.devices[device_index].in_flight != 0
            || self.slots.iter().any(|slot| {
                slot.device.index() == Some(device_index)
                    && matches!(slot.state, SlotState::Queued | SlotState::Active)
            })
        {
            return None;
        }
        let serial = self.devices[device_index].next_serial;
        self.devices[device_index].next_serial = next_nonzero_u64(serial);
        self.devices[device_index].shutdown_flush = ShutdownFlushState::InFlight { serial };
        self.devices[device_index].in_flight += 1;
        self.in_flight_commands += 1;
        self.diagnostics.dispatches = self.diagnostics.dispatches.saturating_add(1);
        self.diagnostics.shutdown_flushes = self.diagnostics.shutdown_flushes.saturating_add(1);
        self.diagnostics.in_flight_high_water = self
            .diagnostics
            .in_flight_high_water
            .max(self.in_flight_commands);
        let device_id =
            BlockDeviceId::from_parts(device_index, self.devices[device_index].generation);
        Some(DispatchCommand {
            token: DispatchToken {
                request_id: BlockRequestId::INVALID,
                device_id,
                device_epoch: self.devices[device_index].epoch,
                child_index: 0,
                serial,
                shutdown_flush: true,
            },
            operation: BlockOperation::Flush,
            lba: 0,
            byte_len: 0,
            priority: BlockPriority::Latency,
            ordering_epoch: self.devices[device_index].next_ordering_epoch,
            segments: [DmaSegment::EMPTY; MAX_DMA_SEGMENTS],
            segment_count: 0,
        })
    }

    pub fn complete(
        &mut self,
        token: DispatchToken,
        status: HardwareStatus,
    ) -> CompletionDisposition {
        self.complete_observed(token, status, None)
    }

    /// Completes a command and records service latency against the worker's monotonic clock.
    pub fn complete_at(
        &mut self,
        token: DispatchToken,
        status: HardwareStatus,
        now_ns: u64,
    ) -> CompletionDisposition {
        self.complete_observed(token, status, Some(now_ns))
    }

    fn complete_observed(
        &mut self,
        token: DispatchToken,
        status: HardwareStatus,
        now_ns: Option<u64>,
    ) -> CompletionDisposition {
        let Some(device_index) = token
            .device_id
            .index()
            .filter(|index| *index < self.devices.len())
        else {
            return self.reject_stale_completion();
        };
        let device = &self.devices[device_index];
        if !device.present
            || device.generation != token.device_id.generation()
            || device.epoch != token.device_epoch
        {
            return self.reject_stale_completion();
        }
        if token.shutdown_flush {
            return self.complete_shutdown_flush(device_index, token, status);
        }
        let Some(slot_index) = self.request_index(token.request_id) else {
            return self.reject_stale_completion();
        };
        if self.slots[slot_index].device != token.device_id
            || usize::from(token.child_index) >= MAX_CHILDREN
        {
            return self.reject_stale_completion();
        }
        match self.slots[slot_index].children[usize::from(token.child_index)] {
            ChildState::Done => return self.reject_duplicate_completion(),
            ChildState::Pending => return self.reject_stale_completion(),
            ChildState::InFlight { serial, .. } if serial != token.serial => {
                return self.reject_stale_completion();
            }
            ChildState::InFlight { .. } => {}
        }

        self.slots[slot_index].children[usize::from(token.child_index)] = ChildState::Done;
        self.slots[slot_index].in_flight = self.slots[slot_index].in_flight.saturating_sub(1);
        self.devices[device_index].in_flight =
            self.devices[device_index].in_flight.saturating_sub(1);
        self.in_flight_commands = self.in_flight_commands.saturating_sub(1);

        if status == HardwareStatus::Success {
            let offset = u32::from(token.child_index).saturating_mul(self.config.child_bytes);
            let child_len = self.slots[slot_index]
                .buffer
                .as_ref()
                .map(|buffer| {
                    min(
                        self.config.child_bytes,
                        buffer.byte_len().saturating_sub(offset),
                    )
                })
                .unwrap_or(0);
            self.slots[slot_index].bytes_completed = self.slots[slot_index]
                .bytes_completed
                .saturating_add(child_len);
            self.diagnostics.transferred_bytes = self
                .diagnostics
                .transferred_bytes
                .saturating_add(u64::from(child_len));
        } else if self.slots[slot_index].pending_outcome.is_none() {
            self.slots[slot_index].pending_outcome = Some(match status {
                HardwareStatus::Success => RequestOutcome::Success,
                HardwareStatus::IoError => RequestOutcome::IoError,
                HardwareStatus::Unsupported => RequestOutcome::Unsupported,
            });
            self.remove_queued_entry(slot_index);
        }

        let ready_to_finish = self.slots[slot_index].in_flight == 0
            && (self.slots[slot_index].pending_outcome.is_some()
                || self.slots[slot_index].next_child == self.slots[slot_index].child_count);
        if ready_to_finish {
            let outcome = self.slots[slot_index]
                .pending_outcome
                .unwrap_or(RequestOutcome::Success);
            self.mark_terminal_at(slot_index, outcome, now_ns);
        }
        self.update_shutdown_state();
        CompletionDisposition::Accepted
    }

    fn complete_shutdown_flush(
        &mut self,
        device_index: usize,
        token: DispatchToken,
        status: HardwareStatus,
    ) -> CompletionDisposition {
        match self.devices[device_index].shutdown_flush {
            ShutdownFlushState::Done | ShutdownFlushState::Failed => {
                return self.reject_duplicate_completion();
            }
            ShutdownFlushState::InFlight { serial } if serial == token.serial => {}
            _ => return self.reject_stale_completion(),
        }
        self.devices[device_index].in_flight =
            self.devices[device_index].in_flight.saturating_sub(1);
        self.in_flight_commands = self.in_flight_commands.saturating_sub(1);
        self.devices[device_index].shutdown_flush = if status == HardwareStatus::Success {
            ShutdownFlushState::Done
        } else {
            self.diagnostics.shutdown_flush_failures =
                self.diagnostics.shutdown_flush_failures.saturating_add(1);
            ShutdownFlushState::Failed
        };
        self.update_shutdown_state();
        CompletionDisposition::Accepted
    }

    pub fn take_completion(&mut self, id: BlockRequestId) -> Option<RequestCompletion> {
        let index = self.request_index(id)?;
        if self.slots[index].state != SlotState::Terminal {
            return None;
        }
        let outcome = self.slots[index].terminal_outcome?;
        let bounce = self.slots[index]
            .buffer
            .as_mut()
            .and_then(|buffer| buffer.bounce.take());
        let completion = RequestCompletion {
            id,
            outcome,
            bytes_completed: self.slots[index].bytes_completed,
            bounce,
        };
        let generation = self.slots[index].generation;
        self.live_requests = self.live_requests.saturating_sub(1);
        self.slots[index] = if let Some(next_generation) = generation.checked_add(1) {
            RequestSlot::vacant(next_generation)
        } else {
            let mut retired = RequestSlot::vacant(generation);
            retired.state = SlotState::Retired;
            retired
        };
        Some(completion)
    }

    pub fn reset_device(&mut self, device: BlockDeviceId) -> Result<(), DeviceLifecycleError> {
        let device_index = self
            .device_index(device)
            .ok_or(DeviceLifecycleError::InvalidDevice)?;
        let new_epoch = self.devices[device_index]
            .epoch
            .checked_add(1)
            .ok_or(DeviceLifecycleError::EpochExhausted)?;
        self.devices[device_index].epoch = new_epoch;
        self.devices[device_index].in_flight = 0;
        self.devices[device_index].credits = [0; PRIORITY_COUNT];
        self.devices[device_index].shutdown_flush = if self.shutdown == ShutdownState::Quiescing {
            ShutdownFlushState::Failed
        } else {
            ShutdownFlushState::None
        };
        self.fail_device_requests(device, RequestOutcome::DeviceReset);
        self.recount_in_flight();
        self.diagnostics.resets = self.diagnostics.resets.saturating_add(1);
        self.update_shutdown_state();
        Ok(())
    }

    pub fn remove_device(&mut self, device: BlockDeviceId) -> Result<(), DeviceLifecycleError> {
        let device_index = self
            .device_index(device)
            .ok_or(DeviceLifecycleError::InvalidDevice)?;
        let new_epoch = self.devices[device_index]
            .epoch
            .checked_add(1)
            .ok_or(DeviceLifecycleError::EpochExhausted)?;
        self.devices[device_index].epoch = new_epoch;
        self.devices[device_index].present = false;
        self.devices[device_index].in_flight = 0;
        self.devices[device_index].shutdown_flush = ShutdownFlushState::Failed;
        self.registered_devices = self.registered_devices.saturating_sub(1);
        self.fail_device_requests(device, RequestOutcome::DeviceRemoved);
        self.recount_in_flight();
        self.diagnostics.removals = self.diagnostics.removals.saturating_add(1);
        self.update_shutdown_state();
        Ok(())
    }

    pub fn begin_shutdown(&mut self) {
        if self.shutdown != ShutdownState::Running {
            return;
        }
        self.shutdown = ShutdownState::Quiescing;
        for device in &mut self.devices {
            if device.present {
                device.shutdown_flush = if device.config.supports_flush {
                    ShutdownFlushState::Pending
                } else {
                    ShutdownFlushState::Done
                };
            }
        }
        self.update_shutdown_state();
    }

    /// Stops all old-epoch DMA by changing every device epoch, then fails outstanding requests.
    /// Platform code must stop bus mastering before calling this method.
    pub fn force_shutdown(&mut self) {
        self.shutdown = ShutdownState::Quiescing;
        for device_index in 0..self.devices.len() {
            if !self.devices[device_index].present {
                continue;
            }
            self.devices[device_index].epoch =
                self.devices[device_index].epoch.saturating_add(1).max(1);
            self.devices[device_index].in_flight = 0;
            self.devices[device_index].shutdown_flush = ShutdownFlushState::Failed;
            let device =
                BlockDeviceId::from_parts(device_index, self.devices[device_index].generation);
            self.fail_device_requests(device, RequestOutcome::ForcedShutdown);
        }
        self.recount_in_flight();
        self.update_shutdown_state();
    }

    pub const fn shutdown_state(&self) -> ShutdownState {
        self.shutdown
    }

    pub fn diagnostics(&self) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            counters: self.diagnostics,
            live_requests: self.live_requests,
            queued_requests: self.queued_requests,
            in_flight_commands: self.in_flight_commands,
            registered_devices: self.registered_devices,
            shutdown: self.shutdown,
        }
    }

    fn abort_request(&mut self, index: usize, outcome: RequestOutcome) {
        self.slots[index].pending_outcome = Some(outcome);
        self.remove_queued_entry(index);
        if self.slots[index].in_flight == 0 {
            self.mark_terminal(index, outcome);
        }
    }

    fn mark_terminal(&mut self, index: usize, outcome: RequestOutcome) {
        self.mark_terminal_at(index, outcome, None);
    }

    fn mark_terminal_at(&mut self, index: usize, outcome: RequestOutcome, now_ns: Option<u64>) {
        self.remove_queued_entry(index);
        if self.slots[index].state == SlotState::Terminal {
            return;
        }
        self.slots[index].state = SlotState::Terminal;
        self.slots[index].terminal_outcome = Some(outcome);
        self.diagnostics.terminal_requests = self.diagnostics.terminal_requests.saturating_add(1);
        if outcome == RequestOutcome::Success {
            self.diagnostics.successful_requests =
                self.diagnostics.successful_requests.saturating_add(1);
        } else {
            self.diagnostics.failed_requests = self.diagnostics.failed_requests.saturating_add(1);
            if outcome == RequestOutcome::IoError {
                self.diagnostics.io_errors = self.diagnostics.io_errors.saturating_add(1);
            } else if outcome == RequestOutcome::Unsupported {
                self.diagnostics.unsupported_operations =
                    self.diagnostics.unsupported_operations.saturating_add(1);
            }
        }
        if let (Some(start), Some(end)) = (self.slots[index].first_dispatched_at_ns, now_ns) {
            let latency = end.saturating_sub(start);
            self.diagnostics.service_latency_samples =
                self.diagnostics.service_latency_samples.saturating_add(1);
            self.diagnostics.total_service_latency_ns = self
                .diagnostics
                .total_service_latency_ns
                .saturating_add(latency);
            self.diagnostics.max_service_latency_ns =
                self.diagnostics.max_service_latency_ns.max(latency);
        }
        self.update_shutdown_state();
    }

    fn fail_device_requests(&mut self, device: BlockDeviceId, outcome: RequestOutcome) {
        for index in 0..self.slots.len() {
            if self.slots[index].device == device
                && matches!(
                    self.slots[index].state,
                    SlotState::Queued | SlotState::Active
                )
            {
                let terminal_outcome = self.slots[index].pending_outcome.unwrap_or(outcome);
                self.slots[index].in_flight = 0;
                self.slots[index].pending_outcome = Some(terminal_outcome);
                self.mark_terminal(index, terminal_outcome);
            }
        }
    }

    fn enqueue(&mut self, slot_index: usize, now_ns: u64) {
        debug_assert!(!self.slots[slot_index].queued_entry);
        let id = BlockRequestId::from_parts(slot_index, self.slots[slot_index].generation);
        let priority = self.slots[slot_index].priority;
        self.queues[priority.index()].push_back(QueueEntry {
            id,
            enqueued_at_ns: now_ns,
        });
        self.slots[slot_index].queued_entry = true;
        self.slots[slot_index].enqueued_at_ns = now_ns;
        self.queued_requests += 1;
        self.diagnostics.queue_high_water =
            self.diagnostics.queue_high_water.max(self.queued_requests);
    }

    fn remove_queued_entry(&mut self, slot_index: usize) {
        if !self.slots[slot_index].queued_entry {
            return;
        }
        let id = BlockRequestId::from_parts(slot_index, self.slots[slot_index].generation);
        let priority = self.slots[slot_index].priority;
        self.queues[priority.index()].retain(|entry| entry.id != id);
        self.slots[slot_index].queued_entry = false;
        self.queued_requests = self.queued_requests.saturating_sub(1);
    }

    fn request_index(&self, id: BlockRequestId) -> Option<usize> {
        let index = id.index()?;
        let slot = self.slots.get(index)?;
        if slot.generation == id.generation()
            && !matches!(slot.state, SlotState::Free | SlotState::Retired)
        {
            Some(index)
        } else {
            None
        }
    }

    fn device_index(&self, id: BlockDeviceId) -> Option<usize> {
        let index = id.index()?;
        let device = self.devices.get(index)?;
        if device.present && device.generation == id.generation() {
            Some(index)
        } else {
            None
        }
    }

    fn reject_stale_completion(&mut self) -> CompletionDisposition {
        self.diagnostics.stale_completions = self.diagnostics.stale_completions.saturating_add(1);
        CompletionDisposition::StaleRejected
    }

    fn reject_duplicate_completion(&mut self) -> CompletionDisposition {
        self.diagnostics.duplicate_completions =
            self.diagnostics.duplicate_completions.saturating_add(1);
        CompletionDisposition::DuplicateRejected
    }

    fn recount_in_flight(&mut self) {
        self.in_flight_commands = self
            .devices
            .iter()
            .map(|device| usize::from(device.in_flight))
            .sum();
    }

    fn update_shutdown_state(&mut self) {
        if self.shutdown != ShutdownState::Quiescing {
            return;
        }
        let active_requests = self
            .slots
            .iter()
            .any(|slot| matches!(slot.state, SlotState::Queued | SlotState::Active));
        let device_work = self.devices.iter().any(|device| {
            device.present
                && matches!(
                    device.shutdown_flush,
                    ShutdownFlushState::Pending | ShutdownFlushState::InFlight { .. }
                )
        });
        if !active_requests && !device_work && self.in_flight_commands == 0 {
            self.shutdown = ShutdownState::Drained;
        }
    }
}

const fn next_nonzero_u64(value: u64) -> u64 {
    match value.checked_add(1) {
        Some(next) => next,
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn device_config(depth: u16, dma: DmaConstraints) -> BlockDeviceConfig {
        BlockDeviceConfig {
            capacity_sectors: 4096,
            queue_depth: depth,
            supports_flush: true,
            dma,
        }
    }

    fn queue(capacity: usize, depth: u16) -> (AsyncBlockQueue, BlockDeviceId) {
        let mut queue = AsyncBlockQueue::try_new(capacity, 2, QueueConfig::default()).unwrap();
        let device = queue
            .register_device(device_config(depth, DmaConstraints::dma64()))
            .unwrap();
        (queue, device)
    }

    fn transfer(
        device: BlockDeviceId,
        operation: BlockOperation,
        lba: u64,
        bytes: u32,
        address: u64,
        priority: BlockPriority,
        deadline_ns: Option<u64>,
    ) -> RequestSpec {
        RequestSpec {
            device,
            operation,
            lba,
            buffer: Some(
                // SAFETY: Tests use distinct, fixed physical ranges as owned DMA fixtures and keep
                // them reserved until each request completion is taken.
                unsafe {
                    BlockBuffer::from_dma_segments(
                        bytes,
                        &[DmaSegment {
                            physical_address: address,
                            length: bytes,
                        }],
                    )
                }
                .unwrap(),
            ),
            priority,
            deadline_ns,
        }
    }

    fn fence(device: BlockDeviceId, operation: BlockOperation) -> RequestSpec {
        RequestSpec {
            device,
            operation,
            lba: 0,
            buffer: None,
            priority: BlockPriority::Latency,
            deadline_ns: None,
        }
    }

    #[test]
    fn diagnostics_record_bytes_outcomes_and_service_latency() {
        let (mut queue, device) = queue(1, 1);
        let success = queue
            .submit(
                10,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 20).unwrap();
        assert_eq!(
            queue.complete_at(command.token, HardwareStatus::Success, 50),
            CompletionDisposition::Accepted
        );
        queue.take_completion(success).unwrap();

        let failed = queue
            .submit(
                55,
                transfer(
                    device,
                    BlockOperation::Read,
                    1,
                    512,
                    0x2000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 60).unwrap();
        queue.complete_at(command.token, HardwareStatus::IoError, 80);
        queue.take_completion(failed).unwrap();

        let unsupported = queue
            .submit(
                85,
                transfer(
                    device,
                    BlockOperation::Write,
                    2,
                    512,
                    0x3000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 90).unwrap();
        queue.complete_at(command.token, HardwareStatus::Unsupported, 100);
        queue.take_completion(unsupported).unwrap();

        let diagnostics = queue.diagnostics().counters;
        assert_eq!(diagnostics.transferred_bytes, 512);
        assert_eq!(diagnostics.io_errors, 1);
        assert_eq!(diagnostics.unsupported_operations, 1);
        assert_eq!(diagnostics.service_latency_samples, 3);
        assert_eq!(diagnostics.total_service_latency_ns, 60);
        assert_eq!(diagnostics.max_service_latency_ns, 30);
    }

    #[test]
    fn saturation_is_fixed_and_generation_tags_change_on_reuse() {
        let (mut queue, device) = queue(2, 1);
        let first = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    1,
                    512,
                    0x2000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let failure = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    2,
                    512,
                    0x3000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap_err();
        assert_eq!(failure.error, SubmitError::QueueFull);

        let command = queue.dispatch_one(device, 1).unwrap();
        assert_eq!(command.token.request_id(), first);
        assert_eq!(
            queue.complete(command.token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(
            queue.take_completion(first).unwrap().outcome,
            RequestOutcome::Success
        );
        let replacement = queue
            .submit(
                2,
                transfer(
                    device,
                    BlockOperation::Read,
                    3,
                    512,
                    0x4000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        assert_ne!(replacement, first);
        assert_eq!(replacement.generation(), first.generation() + 1);
    }

    #[test]
    fn parent_transfer_larger_than_four_kib_is_split_without_allocation() {
        let (mut queue, device) = queue(2, 3);
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    10,
                    12 * 1024,
                    0x20_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        let third = queue.dispatch_one(device, 3).unwrap();
        assert_eq!([first.byte_len, second.byte_len, third.byte_len], [4096; 3]);
        assert_eq!([first.lba, second.lba, third.lba], [10, 18, 26]);
        assert_eq!(first.segments()[0].physical_address, 0x20_000);
        assert_eq!(second.segments()[0].physical_address, 0x21_000);
        assert_eq!(third.segments()[0].physical_address, 0x22_000);
        assert!(queue.dispatch_one(device, 4).is_none());
        queue.complete(second.token, HardwareStatus::Success);
        queue.complete(first.token, HardwareStatus::Success);
        queue.complete(third.token, HardwareStatus::Success);
        let completion = queue.take_completion(id).unwrap();
        assert_eq!(completion.outcome, RequestOutcome::Success);
        assert_eq!(completion.bytes_completed, 12 * 1024);
    }

    #[test]
    fn sixteen_kib_child_spans_four_dma_segments() {
        let config = QueueConfig {
            max_request_bytes: 16 * 1024,
            child_bytes: 16 * 1024,
            ..QueueConfig::default()
        };
        let mut queue = AsyncBlockQueue::try_new(1, 1, config).unwrap();
        let device = queue
            .register_device(device_config(1, DmaConstraints::dma64()))
            .unwrap();
        let segments = [
            DmaSegment {
                physical_address: 0x10_000,
                length: 4096,
            },
            DmaSegment {
                physical_address: 0x30_000,
                length: 4096,
            },
            DmaSegment {
                physical_address: 0x50_000,
                length: 4096,
            },
            DmaSegment {
                physical_address: 0x70_000,
                length: 4096,
            },
        ];
        let id = queue
            .submit(
                0,
                RequestSpec {
                    device,
                    operation: BlockOperation::Read,
                    lba: 8,
                    buffer: Some(
                        // SAFETY: These fixed, non-overlapping ranges remain owned by this test
                        // until the request completion is taken.
                        unsafe { BlockBuffer::from_dma_segments(16 * 1024, &segments) }.unwrap(),
                    ),
                    priority: BlockPriority::Normal,
                    deadline_ns: None,
                },
            )
            .unwrap();

        let command = queue.dispatch_one(device, 1).unwrap();
        assert_eq!(command.byte_len, 16 * 1024);
        assert_eq!(command.segments(), &segments);
        assert!(queue.dispatch_one(device, 2).is_none());
        assert_eq!(
            queue.complete(command.token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(
            queue.take_completion(id).unwrap().bytes_completed,
            16 * 1024
        );

        let invalid = QueueConfig {
            max_request_bytes: 16 * 1024,
            child_bytes: 16 * 1024 + SECTOR_SIZE,
            ..QueueConfig::default()
        };
        assert!(matches!(
            AsyncBlockQueue::try_new(1, 1, invalid),
            Err(QueueBuildError::InvalidConfiguration)
        ));
    }

    #[test]
    fn larger_parent_still_splits_with_sixteen_kib_children() {
        let config = QueueConfig {
            max_request_bytes: 48 * 1024,
            child_bytes: 16 * 1024,
            ..QueueConfig::default()
        };
        let mut queue = AsyncBlockQueue::try_new(1, 1, config).unwrap();
        let device = queue
            .register_device(device_config(3, DmaConstraints::dma64()))
            .unwrap();
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    32,
                    40 * 1024,
                    0x10_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();

        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        let third = queue.dispatch_one(device, 3).unwrap();
        assert_eq!(
            [first.byte_len, second.byte_len, third.byte_len],
            [16 * 1024, 16 * 1024, 8 * 1024]
        );
        assert_eq!([first.lba, second.lba, third.lba], [32, 64, 96]);
        assert_eq!(first.segments()[0].physical_address, 0x10_000);
        assert_eq!(second.segments()[0].physical_address, 0x14_000);
        assert_eq!(third.segments()[0].physical_address, 0x18_000);
        queue.complete(first.token, HardwareStatus::Success);
        queue.complete(second.token, HardwareStatus::Success);
        queue.complete(third.token, HardwareStatus::Success);
        assert_eq!(
            queue.take_completion(id).unwrap().bytes_completed,
            40 * 1024
        );
    }

    #[test]
    fn child_completions_may_arrive_in_reverse_order() {
        let config = QueueConfig {
            max_request_bytes: 48 * 1024,
            child_bytes: 16 * 1024,
            ..QueueConfig::default()
        };
        let mut queue = AsyncBlockQueue::try_new(1, 1, config).unwrap();
        let device = queue
            .register_device(device_config(3, DmaConstraints::dma64()))
            .unwrap();
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    48 * 1024,
                    0x20_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        let third = queue.dispatch_one(device, 3).unwrap();

        assert_eq!(
            queue.complete(third.token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(queue.poll_request(id), RequestPoll::InFlight);
        assert_eq!(
            queue.complete(second.token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(queue.poll_request(id), RequestPoll::InFlight);
        assert_eq!(
            queue.complete(first.token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(
            queue.poll_request(id),
            RequestPoll::Complete(RequestOutcome::Success)
        );
        assert_eq!(
            queue.take_completion(id).unwrap().bytes_completed,
            48 * 1024
        );
    }

    #[test]
    fn one_parent_can_have_multiple_children_in_flight() {
        let (mut queue, device) = queue(1, 2);
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    12 * 1024,
                    0x40_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();

        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        assert_eq!(first.token.request_id(), id);
        assert_eq!(second.token.request_id(), id);
        assert_eq!(
            [first.token.child_index(), second.token.child_index()],
            [0, 1]
        );
        assert_eq!(queue.diagnostics().in_flight_commands, 2);
        assert!(queue.dispatch_one(device, 3).is_none());

        queue.complete(second.token, HardwareStatus::Success);
        let third = queue.dispatch_one(device, 4).unwrap();
        assert_eq!(third.token.request_id(), id);
        assert_eq!(third.token.child_index(), 2);
        queue.complete(third.token, HardwareStatus::Success);
        assert_eq!(queue.poll_request(id), RequestPoll::InFlight);
        queue.complete(first.token, HardwareStatus::Success);
        assert_eq!(
            queue.take_completion(id).unwrap().bytes_completed,
            12 * 1024
        );
    }

    #[test]
    fn sg_validation_covers_shape_alignment_and_dma_address_width() {
        assert_eq!(
            // SAFETY: This deliberately invalid test fixture is never submitted for DMA.
            unsafe {
                BlockBuffer::from_dma_segments(
                    1024,
                    &[DmaSegment {
                        physical_address: 0x1000,
                        length: 512,
                    }],
                )
            }
            .unwrap_err(),
            BufferError::LengthMismatch
        );

        let crossing = u64::from(u32::MAX) - 255;
        // SAFETY: The fixed physical range is an owned DMA fixture and is not submitted or reused.
        let crossing_buffer = unsafe {
            BlockBuffer::from_dma_segments(
                512,
                &[DmaSegment {
                    physical_address: crossing,
                    length: 512,
                }],
            )
        }
        .unwrap();
        assert_eq!(
            crossing_buffer.dma_disposition(DmaConstraints::dma32()),
            DmaDisposition::BounceRequired(DmaError::AddressOutsideDmaWindow)
        );
        assert_eq!(
            crossing_buffer.dma_disposition(DmaConstraints::dma64()),
            DmaDisposition::Direct
        );

        let mut queue = AsyncBlockQueue::try_new(4, 2, QueueConfig::default()).unwrap();
        let dma32 = queue
            .register_device(device_config(1, DmaConstraints::dma32()))
            .unwrap();
        let dma64 = queue
            .register_device(device_config(1, DmaConstraints::dma64()))
            .unwrap();
        assert_eq!(
            queue
                .submit(
                    0,
                    transfer(
                        dma32,
                        BlockOperation::Write,
                        0,
                        512,
                        crossing,
                        BlockPriority::Normal,
                        None,
                    ),
                )
                .unwrap_err()
                .error,
            SubmitError::BounceRequired(DmaError::AddressOutsideDmaWindow)
        );
        assert!(queue
            .submit(
                0,
                transfer(
                    dma64,
                    BlockOperation::Write,
                    0,
                    512,
                    crossing,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .is_ok());
        assert!(queue
            .submit(
                0,
                RequestSpec {
                    device: dma32,
                    operation: BlockOperation::Write,
                    lba: 1,
                    buffer: Some(
                        BlockBuffer::from_bounce(BounceBufferLease {
                            pool_index: 1,
                            generation: 1,
                            physical_address: 0x8000,
                            capacity: 512,
                            used: 512,
                        })
                        .unwrap(),
                    ),
                    priority: BlockPriority::Normal,
                    deadline_ns: None,
                },
            )
            .is_ok());

        let aligned = DmaConstraints {
            address_alignment: 4096,
            ..DmaConstraints::dma64()
        };
        let mut aligned_queue = AsyncBlockQueue::try_new(1, 1, QueueConfig::default()).unwrap();
        let aligned_device = aligned_queue
            .register_device(device_config(1, aligned))
            .unwrap();
        assert_eq!(
            aligned_queue
                .submit(
                    0,
                    transfer(
                        aligned_device,
                        BlockOperation::Read,
                        0,
                        512,
                        0x1100,
                        BlockPriority::Normal,
                        None,
                    ),
                )
                .unwrap_err()
                .error,
            SubmitError::BounceRequired(DmaError::MisalignedAddress)
        );
    }

    #[test]
    fn device_queue_depth_allows_bounded_in_flight_concurrency() {
        let (mut queue, device) = queue(4, 2);
        for lba in 0..3 {
            queue
                .submit(
                    0,
                    transfer(
                        device,
                        BlockOperation::Read,
                        lba,
                        512,
                        0x1000 + lba * 0x1000,
                        BlockPriority::Normal,
                        None,
                    ),
                )
                .unwrap();
        }
        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        assert!(queue.dispatch_one(device, 3).is_none());
        queue.complete(first.token, HardwareStatus::Success);
        assert!(queue.dispatch_one(device, 4).is_some());
        assert_eq!(queue.diagnostics().counters.in_flight_high_water, 2);
        queue.complete(second.token, HardwareStatus::Success);
    }

    #[test]
    fn weighted_fairness_ages_background_and_guarantees_progress() {
        let mut config = QueueConfig::default();
        config.priority_weights = [8, 4, 1];
        config.background_aging_ns = 100;
        config.background_progress_interval = 3;
        let mut queue = AsyncBlockQueue::try_new(8, 1, config).unwrap();
        let device = queue
            .register_device(device_config(1, DmaConstraints::dma64()))
            .unwrap();
        for lba in 0..6 {
            queue
                .submit(
                    0,
                    transfer(
                        device,
                        BlockOperation::Read,
                        lba,
                        512,
                        0x1000 + lba * 0x1000,
                        BlockPriority::Latency,
                        None,
                    ),
                )
                .unwrap();
        }
        let background = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    20,
                    512,
                    0x10_000,
                    BlockPriority::Background,
                    None,
                ),
            )
            .unwrap();

        let mut background_position = None;
        for position in 0..4 {
            let command = queue.dispatch_one(device, 1).unwrap();
            if command.token.request_id() == background {
                background_position = Some(position);
            }
            queue.complete(command.token, HardwareStatus::Success);
        }
        assert!(background_position.is_some_and(|position| position <= 3));

        let aged = queue
            .submit(
                10,
                transfer(
                    device,
                    BlockOperation::Write,
                    30,
                    512,
                    0x20_000,
                    BlockPriority::Background,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 111).unwrap();
        assert_eq!(command.token.request_id(), aged);
        assert!(queue.diagnostics().counters.aged_background_dispatches >= 1);
    }

    #[test]
    fn barrier_and_flush_epochs_block_later_work_until_completion() {
        let (mut queue, device) = queue(7, 3);
        let write_before = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    0,
                    8192,
                    0x10_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let barrier = queue
            .submit(0, fence(device, BlockOperation::Barrier))
            .unwrap();
        let write_after = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    32,
                    512,
                    0x30_000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();
        let flush = queue
            .submit(0, fence(device, BlockOperation::Flush))
            .unwrap();
        let read_after = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    40,
                    512,
                    0x40_000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();

        let first = queue.dispatch_one(device, 1).unwrap();
        let second = queue.dispatch_one(device, 2).unwrap();
        assert_eq!(first.token.request_id(), write_before);
        assert_eq!(second.token.request_id(), write_before);
        assert_eq!(first.ordering_epoch, 1);
        assert_eq!(second.ordering_epoch, 1);
        assert!(queue.dispatch_one(device, 3).is_none());
        queue.complete(first.token, HardwareStatus::Success);
        assert!(queue.dispatch_one(device, 4).is_none());
        queue.complete(second.token, HardwareStatus::Success);
        let barrier_command = queue.dispatch_one(device, 5).unwrap();
        assert_eq!(barrier_command.token.request_id(), barrier);
        assert_eq!(barrier_command.operation, BlockOperation::Barrier);
        assert_eq!(barrier_command.ordering_epoch, 1);
        assert!(queue.dispatch_one(device, 6).is_none());
        queue.complete(barrier_command.token, HardwareStatus::Success);
        let after_command = queue.dispatch_one(device, 7).unwrap();
        assert_eq!(after_command.token.request_id(), write_after);
        assert_eq!(after_command.ordering_epoch, 2);
        assert!(queue.dispatch_one(device, 8).is_none());
        queue.complete(after_command.token, HardwareStatus::Success);

        let flush_command = queue.dispatch_one(device, 9).unwrap();
        assert_eq!(flush_command.token.request_id(), flush);
        assert_eq!(flush_command.operation, BlockOperation::Flush);
        assert_eq!(flush_command.ordering_epoch, 2);
        assert!(queue.dispatch_one(device, 10).is_none());
        queue.complete(flush_command.token, HardwareStatus::Success);

        let read_command = queue.dispatch_one(device, 11).unwrap();
        assert_eq!(read_command.token.request_id(), read_after);
        assert_eq!(read_command.ordering_epoch, 3);
    }

    #[test]
    fn timeout_and_cancel_races_keep_bounce_owned_until_hardware_stops() {
        let (mut queue, device) = queue(3, 2);
        let bounce = BounceBufferLease {
            pool_index: 7,
            generation: 3,
            physical_address: 0x40_000,
            capacity: 4096,
            used: 4096,
        };
        let timed = queue
            .submit(
                0,
                RequestSpec {
                    device,
                    operation: BlockOperation::Read,
                    lba: 0,
                    buffer: Some(BlockBuffer::from_bounce(bounce).unwrap()),
                    priority: BlockPriority::Latency,
                    deadline_ns: Some(10),
                },
            )
            .unwrap();
        let command = queue.dispatch_one(device, 1).unwrap();
        let report = queue.expire_deadlines(10);
        assert_eq!(report.waiting_for_hardware, 1);
        assert_eq!(queue.poll_request(timed), RequestPoll::CancelPending);
        assert!(queue.take_completion(timed).is_none());
        assert_eq!(queue.poll_cancel(device), Some(command.token));
        assert!(queue.poll_cancel(device).is_none());
        queue.complete(command.token, HardwareStatus::Success);
        let completion = queue.take_completion(timed).unwrap();
        assert_eq!(completion.outcome, RequestOutcome::TimedOut);
        assert_eq!(completion.bounce.unwrap().pool_index, 7);

        let cancelled = queue
            .submit(
                20,
                transfer(
                    device,
                    BlockOperation::Write,
                    8,
                    512,
                    0x50_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 21).unwrap();
        assert_eq!(queue.cancel(cancelled), CancelResult::PendingHardware);
        queue.complete(command.token, HardwareStatus::IoError);
        assert_eq!(
            queue.take_completion(cancelled).unwrap().outcome,
            RequestOutcome::Cancelled
        );
    }

    #[test]
    fn timeout_outcome_survives_device_reset() {
        let (mut queue, device) = queue(1, 1);
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x60_000,
                    BlockPriority::Latency,
                    Some(10),
                ),
            )
            .unwrap();
        let token = queue.dispatch_one(device, 1).unwrap().token;

        assert_eq!(queue.expire_deadlines(10).waiting_for_hardware, 1);
        queue.reset_device(device).unwrap();

        assert_eq!(
            queue.take_completion(id).unwrap().outcome,
            RequestOutcome::TimedOut
        );
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::StaleRejected
        );
    }

    #[test]
    fn cancel_outcome_survives_device_removal() {
        let (mut queue, device) = queue(1, 1);
        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    0,
                    512,
                    0x70_000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let token = queue.dispatch_one(device, 1).unwrap().token;

        assert_eq!(queue.cancel(id), CancelResult::PendingHardware);
        queue.remove_device(device).unwrap();

        assert_eq!(
            queue.take_completion(id).unwrap().outcome,
            RequestOutcome::Cancelled
        );
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::StaleRejected
        );
    }

    #[test]
    fn reset_and_removal_change_epochs_and_fail_owned_requests() {
        let (mut queue, device) = queue(4, 2);
        let first = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let token = queue.dispatch_one(device, 1).unwrap().token;
        let old_epoch = token.device_epoch();
        queue.reset_device(device).unwrap();
        assert_ne!(queue.device_epoch(device).unwrap(), old_epoch);
        assert_eq!(
            queue.take_completion(first).unwrap().outcome,
            RequestOutcome::DeviceReset
        );
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::StaleRejected
        );

        let second = queue
            .submit(
                2,
                transfer(
                    device,
                    BlockOperation::Write,
                    1,
                    512,
                    0x2000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        queue.remove_device(device).unwrap();
        assert_eq!(
            queue.take_completion(second).unwrap().outcome,
            RequestOutcome::DeviceRemoved
        );
        let replacement = queue
            .register_device(device_config(1, DmaConstraints::dma64()))
            .unwrap();
        assert_ne!(replacement, device);
    }

    #[test]
    fn duplicate_and_stale_completions_never_complete_a_reused_slot() {
        let (mut queue, device) = queue(1, 1);
        let old = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let token = queue.dispatch_one(device, 1).unwrap().token;
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::Accepted
        );
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::DuplicateRejected
        );
        queue.take_completion(old).unwrap();
        let replacement = queue
            .submit(
                2,
                transfer(
                    device,
                    BlockOperation::Read,
                    1,
                    512,
                    0x2000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        assert_ne!(replacement, old);
        assert_eq!(
            queue.complete(token, HardwareStatus::Success),
            CompletionDisposition::StaleRejected
        );
        assert_eq!(queue.poll_request(replacement), RequestPoll::Queued);
    }

    #[test]
    fn shutdown_quiesces_submissions_drains_and_flushes_each_device() {
        let (mut queue, device) = queue(1, 1);
        let request = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Write,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        queue.begin_shutdown();
        assert_eq!(queue.shutdown_state(), ShutdownState::Quiescing);
        assert_eq!(
            queue
                .submit(
                    1,
                    transfer(
                        device,
                        BlockOperation::Read,
                        1,
                        512,
                        0x2000,
                        BlockPriority::Normal,
                        None,
                    ),
                )
                .unwrap_err()
                .error,
            SubmitError::Quiescing
        );

        let write = queue.dispatch_one(device, 2).unwrap();
        queue.complete(write.token, HardwareStatus::Success);
        assert_eq!(
            queue.poll_request(request),
            RequestPoll::Complete(RequestOutcome::Success)
        );
        let flush = queue.dispatch_one(device, 3).unwrap();
        assert!(flush.token.is_shutdown_flush());
        assert_eq!(flush.operation, BlockOperation::Flush);
        assert_eq!(queue.shutdown_state(), ShutdownState::Quiescing);
        queue.complete(flush.token, HardwareStatus::Success);
        assert_eq!(queue.shutdown_state(), ShutdownState::Drained);
        assert_eq!(queue.diagnostics().counters.shutdown_flushes, 1);
    }

    #[test]
    fn shutdown_skips_flush_for_devices_without_flush_support() {
        let mut queue = AsyncBlockQueue::try_new(1, 1, QueueConfig::default()).unwrap();
        let mut config = device_config(1, DmaConstraints::dma64());
        config.supports_flush = false;
        let device = queue.register_device(config).unwrap();

        queue.begin_shutdown();

        assert_eq!(queue.shutdown_state(), ShutdownState::Drained);
        assert!(queue.dispatch_one(device, 0).is_none());
        assert_eq!(queue.diagnostics().counters.shutdown_flushes, 0);
    }

    #[test]
    fn two_registered_devices_have_independent_slots_and_limits() {
        let mut queue = AsyncBlockQueue::try_new(4, 2, QueueConfig::default()).unwrap();
        let first_device = queue
            .register_device(device_config(1, DmaConstraints::dma64()))
            .unwrap();
        let second_device = queue
            .register_device(device_config(2, DmaConstraints::dma64()))
            .unwrap();
        let first = queue
            .submit(
                0,
                transfer(
                    first_device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let second = queue
            .submit(
                0,
                transfer(
                    second_device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x2000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        assert_eq!(
            queue
                .dispatch_one(first_device, 1)
                .unwrap()
                .token
                .request_id(),
            first
        );
        assert_eq!(
            queue
                .dispatch_one(second_device, 1)
                .unwrap()
                .token
                .request_id(),
            second
        );
        assert_eq!(queue.diagnostics().registered_devices, 2);
    }

    #[test]
    fn construction_preallocates_every_steady_state_collection() {
        let (mut queue, device) = queue(3, 2);
        let slot_capacity = queue.slots.capacity();
        let device_capacity = queue.devices.capacity();
        let queue_capacities =
            core::array::from_fn::<_, PRIORITY_COUNT, _>(|index| queue.queues[index].capacity());

        let expired = queue
            .submit(
                10,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    Some(10),
                ),
            )
            .unwrap_err();
        assert_eq!(expired.error, SubmitError::DeadlineExpired);

        let id = queue
            .submit(
                10,
                transfer(
                    device,
                    BlockOperation::Write,
                    1,
                    8192,
                    0x2000,
                    BlockPriority::Background,
                    Some(100),
                ),
            )
            .unwrap();
        let first = queue.dispatch_one(device, 11).unwrap();
        let second = queue.dispatch_one(device, 12).unwrap();
        queue.complete(first.token, HardwareStatus::Success);
        queue.complete(second.token, HardwareStatus::Success);
        assert_eq!(
            queue.take_completion(id).unwrap().outcome,
            RequestOutcome::Success
        );

        assert_eq!(queue.slots.capacity(), slot_capacity);
        assert_eq!(queue.devices.capacity(), device_capacity);
        assert_eq!(
            core::array::from_fn::<_, PRIORITY_COUNT, _>(|index| queue.queues[index].capacity()),
            queue_capacities
        );
    }

    struct FakeAsyncDriver {
        config: BlockDeviceConfig,
        ready: bool,
        completion: Option<DriverCompletion>,
        cancelled: Option<DispatchToken>,
        reset_complete: bool,
    }

    impl AsyncBlockDevice for FakeAsyncDriver {
        type Error = ();

        fn config(&self) -> BlockDeviceConfig {
            self.config
        }

        fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>> {
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn submit(&mut self, command: &DispatchCommand) -> Result<(), Self::Error> {
            if !self.ready || self.completion.is_some() {
                return Err(());
            }
            self.ready = false;
            self.completion = Some(DriverCompletion {
                token: command.token,
                status: HardwareStatus::Success,
            });
            Ok(())
        }

        fn poll_completion(&mut self) -> Poll<Result<DriverCompletion, Self::Error>> {
            match self.completion.take() {
                Some(completion) => {
                    self.ready = true;
                    Poll::Ready(Ok(completion))
                }
                None => Poll::Pending,
            }
        }

        fn request_cancel(&mut self, token: DispatchToken) -> Result<(), Self::Error> {
            self.cancelled = Some(token);
            Ok(())
        }

        fn poll_reset(&mut self) -> Poll<Result<(), Self::Error>> {
            if self.reset_complete {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn device_worker_bounds_each_work_class_without_growing_queue_storage() {
        let (mut queue, device) = queue(2, 1);
        let slot_capacity = queue.slots.capacity();
        let device_capacity = queue.devices.capacity();
        let queue_capacities =
            core::array::from_fn::<_, PRIORITY_COUNT, _>(|index| queue.queues[index].capacity());
        let mut driver = FakeAsyncDriver {
            config: device_config(1, DmaConstraints::dma64()),
            ready: true,
            completion: None,
            cancelled: None,
            reset_complete: false,
        };
        let first = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();
        let second = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    1,
                    512,
                    0x2000,
                    BlockPriority::Normal,
                    None,
                ),
            )
            .unwrap();

        let submitted = run_device_worker(
            &mut queue,
            device,
            &mut driver,
            1,
            DeviceWorkerBudget {
                completions: 0,
                cancellations: 0,
                submissions: 1,
            },
        )
        .unwrap();
        assert_eq!(submitted.readiness_polls, 1);
        assert_eq!(submitted.commands_submitted, 1);
        assert_eq!(queue.cancel(first), CancelResult::PendingHardware);

        let cancelled = run_device_worker(
            &mut queue,
            device,
            &mut driver,
            2,
            DeviceWorkerBudget {
                completions: 0,
                cancellations: 1,
                submissions: 0,
            },
        )
        .unwrap();
        assert_eq!(cancelled.cancellation_polls, 1);
        assert_eq!(cancelled.cancellations_requested, 1);
        assert!(driver.cancelled.is_some());

        let completed_and_submitted = run_device_worker(
            &mut queue,
            device,
            &mut driver,
            3,
            DeviceWorkerBudget {
                completions: 1,
                cancellations: 0,
                submissions: 1,
            },
        )
        .unwrap();
        assert_eq!(completed_and_submitted.completion_polls, 1);
        assert_eq!(completed_and_submitted.accepted_completions, 1);
        assert_eq!(completed_and_submitted.commands_submitted, 1);
        assert_eq!(
            queue.take_completion(first).unwrap().outcome,
            RequestOutcome::Cancelled
        );

        let completed = run_device_worker(
            &mut queue,
            device,
            &mut driver,
            4,
            DeviceWorkerBudget {
                completions: 1,
                cancellations: 0,
                submissions: 0,
            },
        )
        .unwrap();
        assert_eq!(completed.accepted_completions, 1);
        assert_eq!(
            queue.take_completion(second).unwrap().outcome,
            RequestOutcome::Success
        );
        assert_eq!(queue.slots.capacity(), slot_capacity);
        assert_eq!(queue.devices.capacity(), device_capacity);
        assert_eq!(
            core::array::from_fn::<_, PRIORITY_COUNT, _>(|index| queue.queues[index].capacity()),
            queue_capacities
        );
    }

    #[test]
    fn poll_style_device_contract_drives_completion_and_cancel() {
        let (mut queue, device) = queue(2, 1);
        let mut driver = FakeAsyncDriver {
            config: device_config(1, DmaConstraints::dma64()),
            ready: false,
            completion: None,
            cancelled: None,
            reset_complete: false,
        };
        assert_eq!(driver.config().queue_depth, 1);
        assert_eq!(driver.poll_ready(), Poll::Pending);
        driver.ready = true;
        assert_eq!(driver.poll_ready(), Poll::Ready(Ok(())));

        let id = queue
            .submit(
                0,
                transfer(
                    device,
                    BlockOperation::Read,
                    0,
                    512,
                    0x1000,
                    BlockPriority::Latency,
                    None,
                ),
            )
            .unwrap();
        let command = queue.dispatch_one(device, 1).unwrap();
        driver.submit(&command).unwrap();
        assert_eq!(queue.cancel(id), CancelResult::PendingHardware);
        let cancel = queue.poll_cancel(device).unwrap();
        driver.request_cancel(cancel).unwrap();
        assert_eq!(driver.cancelled, Some(command.token));

        let completion = match driver.poll_completion() {
            Poll::Ready(Ok(completion)) => completion,
            other => panic!("unexpected completion state: {other:?}"),
        };
        assert_eq!(
            queue.complete(completion.token, completion.status),
            CompletionDisposition::Accepted
        );
        assert_eq!(
            queue.take_completion(id).unwrap().outcome,
            RequestOutcome::Cancelled
        );
        assert_eq!(driver.poll_reset(), Poll::Pending);
        driver.reset_complete = true;
        assert_eq!(driver.poll_reset(), Poll::Ready(Ok(())));
    }

    #[test]
    fn segmented_child_slices_preserve_exact_ranges() {
        // SAFETY: The fixed, non-overlapping physical ranges are owned by this test fixture and
        // remain reserved for the lifetime of the buffer.
        let buffer = unsafe {
            BlockBuffer::from_dma_segments(
                4096,
                &[
                    DmaSegment {
                        physical_address: 0x1000,
                        length: 1024,
                    },
                    DmaSegment {
                        physical_address: 0x8000,
                        length: 3072,
                    },
                ],
            )
        }
        .unwrap();
        let (segments, count) = buffer.slice(512, 2048).unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            &segments[..2],
            &[
                DmaSegment {
                    physical_address: 0x1200,
                    length: 512,
                },
                DmaSegment {
                    physical_address: 0x8000,
                    length: 1536,
                },
            ]
        );
        let _ = vec![segments[0], segments[1]];
    }
}
