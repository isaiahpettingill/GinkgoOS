//! Bootstrap and fiber-aware runtime storage over virtio-blk or AHCI.
//!
//! Construction reserves the async scheduler and a fixed DMA32 bounce pool. Bootstrap I/O uses
//! the drivers' bounded synchronous paths. After [`StorageDisk::activate_async`], every synchronous
//! [`BlockDevice`] call is adapted to bounded async requests and suspends only its calling fiber
//! while hardware owns a request.

use core::{arch::asm, ptr, task::Poll};

use crate::{
    ahci::{AhciDiagnostics, AhciDisk, AhciError},
    async_block::{
        run_device_worker, AsyncBlockDevice, AsyncBlockQueue, BlockBuffer, BlockDeviceConfig,
        BlockDeviceId, BlockOperation, BlockPriority, BlockRequestId, BounceBufferLease,
        BufferError, DeviceLifecycleError, DeviceRegisterError, DeviceWorkerBudget,
        DeviceWorkerOperation, DiagnosticSnapshot, DmaSegment, QueueBuildError, QueueConfig,
        RequestCompletion, RequestOutcome, RequestPoll, RequestSpec, ShutdownState, SubmitError,
    },
    block::{BlockDevice, SECTOR_SIZE},
    fiber::{self, YieldError},
    memory::{
        FrameAllocatorError, UsableFrameAllocator, VirtAddr, DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    },
    paging::ActivePageTable,
    virtio_blk::{VirtioBlk, VirtioBlkDiagnostics, VirtioBlkError},
};

/// Number of stable DMA32 pages reserved for runtime storage I/O.
pub const STORAGE_BOUNCE_PAGES: usize = 8;
/// Number of parent requests reserved in the async queue.
pub const STORAGE_REQUEST_CAPACITY: usize = STORAGE_BOUNCE_PAGES;
/// Default deadline for one runtime request, shutdown flush, or reset proof.
pub const DEFAULT_STORAGE_IO_TIMEOUT_NS: u64 = 5_000_000_000;

const BOUNCE_BYTES: usize = PAGE_SIZE as usize;
const MAX_RUNTIME_TRANSFER_BYTES: usize = STORAGE_BOUNCE_PAGES * BOUNCE_BYTES;
const VIRTIO_CHILD_BYTES: usize = 2 * BOUNCE_BYTES;
const AHCI_CHILD_BYTES: usize = 4 * BOUNCE_BYTES;
const WORKER_BUDGET: DeviceWorkerBudget = DeviceWorkerBudget {
    completions: STORAGE_REQUEST_CAPACITY,
    cancellations: STORAGE_REQUEST_CAPACITY,
    submissions: STORAGE_REQUEST_CAPACITY,
};

/// The selected hardware transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDriverKind {
    Virtio,
    Ahci,
}

/// Whether calls use bootstrap polling or interrupt-backed fiber suspension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageMode {
    Bootstrap,
    Runtime,
}

/// Driver errors normalized across the preferred virtio and fallback AHCI paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDriverError {
    Virtio(VirtioBlkError),
    Ahci(AhciError),
}

impl From<VirtioBlkError> for StorageDriverError {
    fn from(value: VirtioBlkError) -> Self {
        Self::Virtio(value)
    }
}

impl From<AhciError> for StorageDriverError {
    fn from(value: AhciError) -> Self {
        Self::Ahci(value)
    }
}

/// Errors returned by storage construction, mode changes, and I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// Neither preferred transport could be initialized.
    NoDevice {
        virtio: VirtioBlkError,
        ahci: AhciError,
    },
    Driver(StorageDriverError),
    FrameAllocator(FrameAllocatorError),
    OutOfDma32Frames,
    AddressOverflow,
    InvalidTscFrequency,
    InvalidTimeout,
    QueueBuild(QueueBuildError),
    DeviceRegister(DeviceRegisterError),
    Buffer(BufferError),
    Submit(SubmitError),
    Lifecycle(DeviceLifecycleError),
    Worker {
        operation: DeviceWorkerOperation,
        driver: StorageDriverError,
    },
    Misaligned,
    OutOfBounds,
    BouncePoolExhausted,
    BounceOwnership,
    RecoveryRequired,
    UnexpectedCompletion,
    RequestFailed(RequestOutcome),
    ResetTimedOut,
    ShutdownTimedOut,
    /// Runtime I/O was called without an active filesystem fiber.
    OutsideActiveFiber,
    Yield(YieldError),
}

impl From<StorageDriverError> for StorageError {
    fn from(value: StorageDriverError) -> Self {
        Self::Driver(value)
    }
}

impl From<FrameAllocatorError> for StorageError {
    fn from(value: FrameAllocatorError) -> Self {
        Self::FrameAllocator(value)
    }
}

impl From<QueueBuildError> for StorageError {
    fn from(value: QueueBuildError) -> Self {
        Self::QueueBuild(value)
    }
}

impl From<DeviceRegisterError> for StorageError {
    fn from(value: DeviceRegisterError) -> Self {
        Self::DeviceRegister(value)
    }
}

impl From<BufferError> for StorageError {
    fn from(value: BufferError) -> Self {
        Self::Buffer(value)
    }
}

impl From<DeviceLifecycleError> for StorageError {
    fn from(value: DeviceLifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

/// The owned hardware driver selected during initialization.
pub enum StorageDriver {
    Virtio(VirtioBlk),
    Ahci(AhciDisk),
}

impl StorageDriver {
    pub const fn kind(&self) -> StorageDriverKind {
        match self {
            Self::Virtio(_) => StorageDriverKind::Virtio,
            Self::Ahci(_) => StorageDriverKind::Ahci,
        }
    }

    pub fn diagnostics(&self) -> StorageDriverDiagnostics {
        match self {
            Self::Virtio(driver) => StorageDriverDiagnostics::Virtio(driver.diagnostics()),
            Self::Ahci(driver) => StorageDriverDiagnostics::Ahci(driver.diagnostics()),
        }
    }

    fn enable_interrupts(&mut self, destination_apic_id: u8) -> Result<(), StorageDriverError> {
        match self {
            Self::Virtio(driver) => driver
                .enable_msix(destination_apic_id)
                .map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver
                .enable_msi(destination_apic_id)
                .map_err(StorageDriverError::Ahci),
        }
    }

    fn bootstrap_read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), StorageDriverError> {
        match self {
            Self::Virtio(driver) => driver
                .read_sectors(lba, buffer)
                .map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver
                .read_sectors(lba, buffer)
                .map_err(StorageDriverError::Ahci),
        }
    }

    fn bootstrap_write(&mut self, lba: u64, buffer: &[u8]) -> Result<(), StorageDriverError> {
        match self {
            Self::Virtio(driver) => driver
                .write_sectors(lba, buffer)
                .map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver
                .write_sectors(lba, buffer)
                .map_err(StorageDriverError::Ahci),
        }
    }

    fn bootstrap_flush(&mut self) -> Result<(), StorageDriverError> {
        match self {
            Self::Virtio(driver) => driver.flush().map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver.flush().map_err(StorageDriverError::Ahci),
        }
    }

    fn runtime_flush_needed(&self) -> bool {
        AsyncBlockDevice::config(self).supports_flush
    }
}

impl AsyncBlockDevice for StorageDriver {
    type Error = StorageDriverError;

    fn config(&self) -> BlockDeviceConfig {
        match self {
            Self::Virtio(driver) => AsyncBlockDevice::config(driver),
            Self::Ahci(driver) => AsyncBlockDevice::config(driver),
        }
    }

    fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Virtio(driver) => driver
                .poll_ready()
                .map(|result| result.map_err(StorageDriverError::Virtio)),
            Self::Ahci(driver) => driver
                .poll_ready()
                .map(|result| result.map_err(StorageDriverError::Ahci)),
        }
    }

    fn submit(&mut self, command: &crate::async_block::DispatchCommand) -> Result<(), Self::Error> {
        match self {
            Self::Virtio(driver) => driver.submit(command).map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver.submit(command).map_err(StorageDriverError::Ahci),
        }
    }

    fn poll_completion(
        &mut self,
    ) -> Poll<Result<crate::async_block::DriverCompletion, Self::Error>> {
        match self {
            Self::Virtio(driver) => driver
                .poll_completion()
                .map(|result| result.map_err(StorageDriverError::Virtio)),
            Self::Ahci(driver) => driver
                .poll_completion()
                .map(|result| result.map_err(StorageDriverError::Ahci)),
        }
    }

    fn request_cancel(
        &mut self,
        token: crate::async_block::DispatchToken,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Virtio(driver) => driver
                .request_cancel(token)
                .map_err(StorageDriverError::Virtio),
            Self::Ahci(driver) => driver
                .request_cancel(token)
                .map_err(StorageDriverError::Ahci),
        }
    }

    fn poll_reset(&mut self) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Virtio(driver) => driver
                .poll_reset()
                .map(|result| result.map_err(StorageDriverError::Virtio)),
            Self::Ahci(driver) => driver
                .poll_reset()
                .map(|result| result.map_err(StorageDriverError::Ahci)),
        }
    }
}

/// Transport-specific diagnostics included in [`StorageDiagnostics`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDriverDiagnostics {
    Virtio(VirtioBlkDiagnostics),
    Ahci(AhciDiagnostics),
}

/// One combined snapshot of adapter, queue, and hardware-driver state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageDiagnostics {
    pub mode: StorageMode,
    pub driver: StorageDriverDiagnostics,
    pub queue: DiagnosticSnapshot,
    pub bounce_available: usize,
    pub bounce_in_flight: usize,
    pub bounce_quarantined: usize,
    pub tsc_frequency_hz: u64,
    pub io_timeout_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StorageClock {
    frequency_hz: u64,
    epoch: u64,
}

impl StorageClock {
    fn new(frequency_hz: u64) -> Result<Self, StorageError> {
        if frequency_hz == 0 {
            return Err(StorageError::InvalidTscFrequency);
        }
        Ok(Self {
            frequency_hz,
            epoch: ordered_tsc(),
        })
    }

    fn now_ns(self) -> u64 {
        ticks_to_nanoseconds(ordered_tsc().saturating_sub(self.epoch), self.frequency_hz)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BounceState {
    Available,
    Leased {
        generation: u32,
    },
    Submitted {
        generation: u32,
        request: BlockRequestId,
    },
    Quarantined {
        generation: u32,
        request: BlockRequestId,
    },
}

#[derive(Clone, Copy, Debug)]
struct BouncePage {
    physical_address: u64,
    pointer: *mut u8,
    next_generation: u32,
    state: BounceState,
}

impl BouncePage {
    const EMPTY: Self = Self {
        physical_address: 0,
        pointer: ptr::null_mut(),
        next_generation: 1,
        state: BounceState::Quarantined {
            generation: 0,
            request: BlockRequestId::INVALID,
        },
    };
}

#[derive(Debug)]
struct BouncePool {
    pages: [BouncePage; STORAGE_BOUNCE_PAGES],
}

impl BouncePool {
    fn from_dma32_run(physical_base: u64, hhdm_offset: u64) -> Result<Self, StorageError> {
        let byte_len = (STORAGE_BOUNCE_PAGES as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(StorageError::AddressOverflow)?;
        let physical_end = physical_base
            .checked_add(byte_len)
            .ok_or(StorageError::AddressOverflow)?;
        if physical_end > DMA_32BIT_ADDRESS_LIMIT {
            return Err(StorageError::AddressOverflow);
        }

        let mut pages = [BouncePage::EMPTY; STORAGE_BOUNCE_PAGES];
        for (index, page) in pages.iter_mut().enumerate() {
            let offset = (index as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(StorageError::AddressOverflow)?;
            let physical_address = physical_base
                .checked_add(offset)
                .ok_or(StorageError::AddressOverflow)?;
            let virtual_address = hhdm_offset
                .checked_add(physical_address)
                .ok_or(StorageError::AddressOverflow)?;
            VirtAddr::try_new(virtual_address).map_err(|_| StorageError::AddressOverflow)?;
            let pointer = usize::try_from(virtual_address)
                .map_err(|_| StorageError::AddressOverflow)? as *mut u8;
            // SAFETY: Each page is newly allocated, exclusively owned, and covered by the HHDM.
            unsafe { ptr::write_bytes(pointer, 0, BOUNCE_BYTES) };
            *page = BouncePage {
                physical_address,
                pointer,
                next_generation: 1,
                state: BounceState::Available,
            };
        }
        Ok(Self { pages })
    }

    #[cfg(test)]
    fn model(physical_base: u64) -> Self {
        let mut pages = [BouncePage::EMPTY; STORAGE_BOUNCE_PAGES];
        for (index, page) in pages.iter_mut().enumerate() {
            *page = BouncePage {
                physical_address: physical_base + index as u64 * PAGE_SIZE,
                pointer: ptr::null_mut(),
                next_generation: 1,
                state: BounceState::Available,
            };
        }
        Self { pages }
    }

    fn acquire(&mut self, used: usize) -> Result<(usize, u32, BounceBufferLease), StorageError> {
        if used == 0 || used > BOUNCE_BYTES {
            return Err(StorageError::BounceOwnership);
        }
        let index = self
            .pages
            .iter()
            .position(|page| page.state == BounceState::Available)
            .ok_or(StorageError::BouncePoolExhausted)?;
        let page = &mut self.pages[index];
        let generation = page.next_generation;
        page.next_generation = next_generation(generation);
        page.state = BounceState::Leased { generation };
        Ok((
            index,
            generation,
            BounceBufferLease {
                pool_index: index as u16,
                generation,
                physical_address: page.physical_address,
                capacity: BOUNCE_BYTES as u32,
                used: used as u32,
            },
        ))
    }

    fn mark_submitted(
        &mut self,
        index: usize,
        generation: u32,
        request: BlockRequestId,
    ) -> Result<(), StorageError> {
        let page = self
            .pages
            .get_mut(index)
            .ok_or(StorageError::BounceOwnership)?;
        if !matches!(page.state, BounceState::Leased { generation: owner } if owner == generation) {
            return Err(StorageError::BounceOwnership);
        }
        page.state = BounceState::Submitted {
            generation,
            request,
        };
        Ok(())
    }

    fn release_unsubmitted(&mut self, index: usize, generation: u32) -> Result<(), StorageError> {
        let page = self
            .pages
            .get_mut(index)
            .ok_or(StorageError::BounceOwnership)?;
        if !matches!(page.state, BounceState::Leased { generation: owner } if owner == generation) {
            return Err(StorageError::BounceOwnership);
        }
        page.state = BounceState::Available;
        Ok(())
    }

    fn validate_submitted(
        &self,
        request: BlockRequestId,
        index: usize,
        generation: u32,
    ) -> Result<(), StorageError> {
        let page = self.pages.get(index).ok_or(StorageError::BounceOwnership)?;
        if page.state
            != (BounceState::Submitted {
                generation,
                request,
            })
        {
            return Err(StorageError::BounceOwnership);
        }
        Ok(())
    }

    fn release_submitted(
        &mut self,
        request: BlockRequestId,
        index: usize,
        generation: u32,
    ) -> Result<(), StorageError> {
        self.validate_submitted(request, index, generation)?;
        self.pages[index].state = BounceState::Available;
        Ok(())
    }

    fn release_after_dma_stopped(
        &mut self,
        request: BlockRequestId,
        index: usize,
        generation: u32,
    ) -> Result<(), StorageError> {
        let page = self
            .pages
            .get_mut(index)
            .ok_or(StorageError::BounceOwnership)?;
        let owned = matches!(
            page.state,
            BounceState::Submitted {
                generation: owner_generation,
                request: owner_request,
            } | BounceState::Quarantined {
                generation: owner_generation,
                request: owner_request,
            } if owner_generation == generation && owner_request == request
        );
        if !owned {
            return Err(StorageError::BounceOwnership);
        }
        page.state = BounceState::Available;
        Ok(())
    }

    #[cfg(test)]
    fn validate_return(
        &self,
        request: BlockRequestId,
        lease: &BounceBufferLease,
    ) -> Result<usize, StorageError> {
        let index = usize::from(lease.pool_index);
        let page = self.pages.get(index).ok_or(StorageError::BounceOwnership)?;
        let expected = BounceState::Submitted {
            generation: lease.generation,
            request,
        };
        if page.state != expected
            || page.physical_address != lease.physical_address
            || lease.capacity != BOUNCE_BYTES as u32
            || lease.used == 0
            || lease.used > lease.capacity
        {
            return Err(StorageError::BounceOwnership);
        }
        Ok(index)
    }

    #[cfg(test)]
    fn release_return(
        &mut self,
        request: BlockRequestId,
        lease: BounceBufferLease,
    ) -> Result<usize, StorageError> {
        let index = self.validate_return(request, &lease)?;
        self.pages[index].state = BounceState::Available;
        Ok(index)
    }

    fn quarantine_request(&mut self, request: BlockRequestId) {
        for page in &mut self.pages {
            if let BounceState::Submitted {
                generation,
                request: owner,
            } = page.state
            {
                if owner == request {
                    page.state = BounceState::Quarantined {
                        generation,
                        request,
                    };
                }
            }
        }
    }

    fn copy_into(&self, index: usize, source: &[u8]) -> Result<(), StorageError> {
        let page = self.pages.get(index).ok_or(StorageError::BounceOwnership)?;
        if source.len() > BOUNCE_BYTES || page.pointer.is_null() {
            return Err(StorageError::BounceOwnership);
        }
        // SAFETY: A leased page is exclusively owned by this adapter before submission.
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), page.pointer, source.len()) };
        Ok(())
    }

    fn copy_out(&self, index: usize, destination: &mut [u8]) -> Result<(), StorageError> {
        let page = self.pages.get(index).ok_or(StorageError::BounceOwnership)?;
        if destination.len() > BOUNCE_BYTES || page.pointer.is_null() {
            return Err(StorageError::BounceOwnership);
        }
        // SAFETY: Driver completion acquired device writes and the page remains exclusively owned.
        unsafe {
            ptr::copy_nonoverlapping(page.pointer, destination.as_mut_ptr(), destination.len())
        };
        Ok(())
    }

    fn counts(&self) -> (usize, usize, usize) {
        let mut available = 0;
        let mut in_flight = 0;
        let mut quarantined = 0;
        for page in &self.pages {
            match page.state {
                BounceState::Available => available += 1,
                BounceState::Leased { .. } | BounceState::Submitted { .. } => in_flight += 1,
                BounceState::Quarantined { .. } => quarantined += 1,
            }
        }
        (available, in_flight, quarantined)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingBouncePage {
    index: usize,
    generation: u32,
    used: usize,
}

impl PendingBouncePage {
    const EMPTY: Self = Self {
        index: 0,
        generation: 0,
        used: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTransfer {
    request: BlockRequestId,
    pages: [PendingBouncePage; STORAGE_BOUNCE_PAGES],
    page_count: usize,
    byte_len: usize,
}

/// Production storage adapter used as a synchronous disk by partition and filesystem code.
pub struct StorageDisk {
    driver: StorageDriver,
    mode: StorageMode,
    queue: AsyncBlockQueue,
    device: BlockDeviceId,
    bounce: BouncePool,
    clock: StorageClock,
    io_timeout_ns: u64,
    request_priority: BlockPriority,
    pending_transfer: Option<PendingTransfer>,
}

impl StorageDisk {
    /// Initializes virtio-blk when present, otherwise AHCI, and reserves all runtime resources.
    ///
    /// # Safety
    ///
    /// The caller must satisfy the initialization safety contracts of [`VirtioBlk::initialize`]
    /// and [`AhciDisk::initialize`]. The page table's HHDM must remain valid for this object's
    /// lifetime. The selected PCI function and the reserved frames must remain exclusively owned.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        tsc_frequency_hz: u64,
    ) -> Result<Self, StorageError> {
        unsafe {
            Self::initialize_with_timeout(
                page_table,
                frames,
                tsc_frequency_hz,
                DEFAULT_STORAGE_IO_TIMEOUT_NS,
            )
        }
    }

    /// Initializes storage with an explicit per-operation timeout.
    ///
    /// # Safety
    ///
    /// The requirements are the same as [`StorageDisk::initialize`].
    pub unsafe fn initialize_with_timeout(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        tsc_frequency_hz: u64,
        io_timeout_ns: u64,
    ) -> Result<Self, StorageError> {
        let clock = StorageClock::new(tsc_frequency_hz)?;
        if io_timeout_ns == 0 {
            return Err(StorageError::InvalidTimeout);
        }

        let driver = match unsafe { VirtioBlk::initialize(page_table, frames) } {
            Ok(driver) => StorageDriver::Virtio(driver),
            Err(virtio) => match unsafe { AhciDisk::initialize(page_table, frames) } {
                Ok(driver) => StorageDriver::Ahci(driver),
                Err(ahci) => return Err(StorageError::NoDevice { virtio, ahci }),
            },
        };

        let child_bytes = match driver {
            StorageDriver::Virtio(_) => VIRTIO_CHILD_BYTES,
            StorageDriver::Ahci(_) => AHCI_CHILD_BYTES,
        };
        let mut queue = AsyncBlockQueue::try_new(
            STORAGE_REQUEST_CAPACITY,
            1,
            QueueConfig {
                max_request_bytes: MAX_RUNTIME_TRANSFER_BYTES as u32,
                child_bytes: child_bytes as u32,
                ..QueueConfig::default()
            },
        )?;
        let device = queue.register_device(driver.config())?;

        let frames = frames
            .allocate_contiguous_frames_below(STORAGE_BOUNCE_PAGES, DMA_32BIT_ADDRESS_LIMIT)?
            .ok_or(StorageError::OutOfDma32Frames)?;
        let physical_base = frames
            .first()
            .map(|frame| frame.start_address().as_u64())
            .ok_or(StorageError::OutOfDma32Frames)?;
        let bounce = BouncePool::from_dma32_run(physical_base, page_table.hhdm_offset().as_u64())?;

        Ok(Self {
            driver,
            mode: StorageMode::Bootstrap,
            queue,
            device,
            bounce,
            clock,
            io_timeout_ns,
            request_priority: BlockPriority::Latency,
            pending_transfer: None,
        })
    }

    pub const fn mode(&self) -> StorageMode {
        self.mode
    }

    pub const fn driver_kind(&self) -> StorageDriverKind {
        self.driver.kind()
    }

    pub fn driver(&self) -> &StorageDriver {
        &self.driver
    }

    /// Exposes the selected driver only during bootstrap diagnostics and smoke tests.
    /// Runtime filesystem code must use the executor-owned `StorageDisk` interface.
    pub fn driver_mut(&mut self) -> &mut StorageDriver {
        &mut self.driver
    }

    /// Selects the priority used by subsequent runtime block requests.
    pub fn set_request_priority(&mut self, priority: BlockPriority) {
        self.request_priority = priority;
    }

    pub fn diagnostics(&self) -> StorageDiagnostics {
        let (bounce_available, bounce_in_flight, bounce_quarantined) = self.bounce.counts();
        StorageDiagnostics {
            mode: self.mode,
            driver: self.driver.diagnostics(),
            queue: self.queue.diagnostics(),
            bounce_available,
            bounce_in_flight,
            bounce_quarantined,
            tsc_frequency_hz: self.clock.frequency_hz,
            io_timeout_ns: self.io_timeout_ns,
        }
    }

    /// Enables the selected driver's interrupt mode and permanently leaves bootstrap mode.
    pub fn activate_async(&mut self, destination_apic_id: u8) -> Result<(), StorageError> {
        if self.mode == StorageMode::Runtime {
            return Ok(());
        }
        if self.pending_transfer.is_some() {
            return Err(StorageError::RecoveryRequired);
        }
        self.driver.enable_interrupts(destination_apic_id)?;
        commit_runtime_mode(&mut self.mode);
        Ok(())
    }

    /// Stops accepting new queue submissions and schedules a final flush.
    pub fn begin_shutdown(&mut self) {
        self.queue.begin_shutdown();
    }

    pub const fn shutdown_state(&self) -> ShutdownState {
        self.queue.shutdown_state()
    }

    /// Drains runtime requests and the final flush without busy polling.
    pub fn shutdown(&mut self) -> Result<(), StorageError> {
        match self.mode {
            StorageMode::Bootstrap => self.driver.bootstrap_flush().map_err(StorageError::from),
            StorageMode::Runtime => {
                require_active_fiber()?;
                if self.pending_transfer.is_some() {
                    return Err(StorageError::RecoveryRequired);
                }
                self.queue.begin_shutdown();
                let deadline = deadline_after(self.clock.now_ns(), self.io_timeout_ns);
                loop {
                    if self.queue.shutdown_state() == ShutdownState::Drained {
                        return Ok(());
                    }
                    let now = self.clock.now_ns();
                    if now >= deadline {
                        self.reset_driver_and_offline_queue()?;
                        return Err(StorageError::ShutdownTimedOut);
                    }
                    if let Err(error) = self.run_worker(now) {
                        self.reset_driver_and_offline_queue()?;
                        return Err(error);
                    }
                    if self.queue.shutdown_state() != ShutdownState::Drained {
                        yield_runtime()?;
                    }
                }
            }
        }
    }

    /// Stops driver DMA, offlines the terminal driver, and returns retained bounce ownership.
    pub fn reset(&mut self) -> Result<(), StorageError> {
        require_active_fiber()?;
        self.reset_driver_and_offline_queue()?;
        self.reap_pending_after_reset()
    }

    /// Marks all requests failed after platform code has independently stopped bus mastering.
    ///
    /// # Safety
    ///
    /// The caller must prove that the selected device can no longer DMA before calling this hook.
    pub unsafe fn force_shutdown_after_dma_stopped(&mut self) -> Result<(), StorageError> {
        self.queue.force_shutdown();
        self.reap_pending_after_dma_stopped()
    }

    fn run_worker(&mut self, now_ns: u64) -> Result<(), StorageError> {
        run_device_worker(
            &mut self.queue,
            self.device,
            &mut self.driver,
            now_ns,
            WORKER_BUDGET,
        )
        .map(|_| ())
        .map_err(|error| StorageError::Worker {
            operation: error.operation,
            driver: error.error,
        })
    }

    fn reset_driver_and_offline_queue(&mut self) -> Result<(), StorageError> {
        let deadline = deadline_after(self.clock.now_ns(), self.io_timeout_ns);
        loop {
            match self.driver.poll_reset() {
                Poll::Ready(Ok(())) => {
                    self.queue.remove_device(self.device)?;
                    return Ok(());
                }
                Poll::Ready(Err(error)) => {
                    self.quarantine_pending_transfer();
                    return Err(StorageError::Driver(error));
                }
                Poll::Pending => {
                    if self.clock.now_ns() >= deadline {
                        self.quarantine_pending_transfer();
                        return Err(StorageError::ResetTimedOut);
                    }
                    yield_runtime()?;
                }
            }
        }
    }

    fn quarantine_pending_transfer(&mut self) {
        if let Some(pending) = self.pending_transfer {
            self.bounce.quarantine_request(pending.request);
        }
    }

    fn release_pending_pages(&mut self, pending: PendingTransfer) -> Result<(), StorageError> {
        for page in &pending.pages[..pending.page_count] {
            self.bounce
                .release_submitted(pending.request, page.index, page.generation)?;
        }
        Ok(())
    }

    fn reap_pending_after_reset(&mut self) -> Result<(), StorageError> {
        let Some(pending) = self.pending_transfer else {
            return Ok(());
        };
        let completion = self
            .queue
            .take_completion(pending.request)
            .ok_or(StorageError::UnexpectedCompletion)?;
        if completion.id != pending.request || completion.bounce.is_some() {
            self.quarantine_pending_transfer();
            return Err(StorageError::UnexpectedCompletion);
        }
        self.pending_transfer = None;
        self.release_pending_pages(pending)
    }

    fn reap_pending_after_dma_stopped(&mut self) -> Result<(), StorageError> {
        let Some(pending) = self.pending_transfer else {
            return Ok(());
        };
        let completion = self
            .queue
            .take_completion(pending.request)
            .ok_or(StorageError::UnexpectedCompletion)?;
        if completion.id != pending.request || completion.bounce.is_some() {
            return Err(StorageError::UnexpectedCompletion);
        }
        for page in &pending.pages[..pending.page_count] {
            self.bounce
                .release_after_dma_stopped(pending.request, page.index, page.generation)?;
        }
        self.pending_transfer = None;
        Ok(())
    }

    fn finish_completion(
        &mut self,
        completion: RequestCompletion,
        read_destination: Option<&mut [u8]>,
    ) -> Result<(), StorageError> {
        let Some(pending) = self.pending_transfer else {
            return Err(StorageError::UnexpectedCompletion);
        };
        if pending.request != completion.id || completion.bounce.is_some() {
            self.quarantine_pending_transfer();
            return Err(StorageError::UnexpectedCompletion);
        }

        for page in &pending.pages[..pending.page_count] {
            if let Err(error) =
                self.bounce
                    .validate_submitted(pending.request, page.index, page.generation)
            {
                self.quarantine_pending_transfer();
                return Err(error);
            }
        }

        let result = if completion.outcome != RequestOutcome::Success {
            Err(StorageError::RequestFailed(completion.outcome))
        } else if completion.bytes_completed != pending.byte_len as u32 {
            Err(StorageError::UnexpectedCompletion)
        } else {
            Ok(())
        };

        if result.is_ok() {
            if let Some(destination) = read_destination {
                if destination.len() != pending.byte_len {
                    self.pending_transfer = None;
                    self.release_pending_pages(pending)?;
                    return Err(StorageError::UnexpectedCompletion);
                }
                let mut offset = 0;
                for page in &pending.pages[..pending.page_count] {
                    let end = offset + page.used;
                    if let Err(error) = self
                        .bounce
                        .copy_out(page.index, &mut destination[offset..end])
                    {
                        self.quarantine_pending_transfer();
                        return Err(error);
                    }
                    offset = end;
                }
            }
        }

        self.pending_transfer = None;
        self.release_pending_pages(pending)?;
        result
    }

    fn submit_runtime_request(
        &mut self,
        operation: BlockOperation,
        lba: u64,
        write_source: Option<&[u8]>,
        read_destination: Option<&mut [u8]>,
    ) -> Result<(), StorageError> {
        if self.pending_transfer.is_some() {
            return Err(StorageError::RecoveryRequired);
        }

        let byte_len = write_source
            .map(|source| source.len())
            .or_else(|| {
                read_destination
                    .as_ref()
                    .map(|destination| destination.len())
            })
            .unwrap_or(0);
        if byte_len > MAX_RUNTIME_TRANSFER_BYTES {
            return Err(StorageError::BouncePoolExhausted);
        }

        let mut pages = [PendingBouncePage::EMPTY; STORAGE_BOUNCE_PAGES];
        let mut segments = [DmaSegment::default(); STORAGE_BOUNCE_PAGES];
        let page_count = byte_len.div_ceil(BOUNCE_BYTES);
        for page_offset in 0..page_count {
            let start = page_offset * BOUNCE_BYTES;
            let used = (byte_len - start).min(BOUNCE_BYTES);
            let (index, generation, lease) = match self.bounce.acquire(used) {
                Ok(owner) => owner,
                Err(error) => {
                    for page in &pages[..page_offset] {
                        let _ = self.bounce.release_unsubmitted(page.index, page.generation);
                    }
                    return Err(error);
                }
            };
            if let Some(source) = write_source {
                if let Err(error) = self.bounce.copy_into(index, &source[start..start + used]) {
                    let _ = self.bounce.release_unsubmitted(index, generation);
                    for page in &pages[..page_offset] {
                        let _ = self.bounce.release_unsubmitted(page.index, page.generation);
                    }
                    return Err(error);
                }
            }
            pages[page_offset] = PendingBouncePage {
                index,
                generation,
                used,
            };
            segments[page_offset] = DmaSegment {
                physical_address: lease.physical_address,
                length: used as u32,
            };
        }
        let buffer = if byte_len == 0 {
            None
        } else {
            match unsafe {
                BlockBuffer::from_dma_segments(byte_len as u32, &segments[..page_count])
            } {
                Ok(buffer) => Some(buffer),
                Err(error) => {
                    for page in &pages[..page_count] {
                        self.bounce
                            .release_unsubmitted(page.index, page.generation)?;
                    }
                    return Err(StorageError::Buffer(error));
                }
            }
        };

        let now = self.clock.now_ns();
        let request = RequestSpec {
            device: self.device,
            operation,
            lba,
            buffer,
            priority: self.request_priority,
            deadline_ns: Some(deadline_after(now, self.io_timeout_ns)),
        };
        let id = match self.queue.submit(now, request) {
            Ok(id) => id,
            Err(failure) => {
                for page in &pages[..page_count] {
                    self.bounce
                        .release_unsubmitted(page.index, page.generation)?;
                }
                return Err(StorageError::Submit(failure.error));
            }
        };
        for page in &pages[..page_count] {
            self.bounce
                .mark_submitted(page.index, page.generation, id)?;
        }
        self.pending_transfer = Some(PendingTransfer {
            request: id,
            pages,
            page_count,
            byte_len,
        });

        let mut read_destination = read_destination;
        loop {
            let worker = self.run_worker(self.clock.now_ns());
            if let Some(completion) = self.queue.take_completion(id) {
                return self.finish_completion(completion, read_destination.take());
            }
            if let Err(error) = worker {
                match self.reset_driver_and_offline_queue() {
                    Ok(()) => {
                        let completion = self
                            .queue
                            .take_completion(id)
                            .ok_or(StorageError::UnexpectedCompletion)?;
                        self.finish_completion(completion, None)?;
                        return Err(error);
                    }
                    Err(reset_error) => return Err(reset_error),
                }
            }
            if self.queue.poll_request(id) == RequestPoll::CancelPending {
                self.reset_driver_and_offline_queue()?;
                let completion = self
                    .queue
                    .take_completion(id)
                    .ok_or(StorageError::UnexpectedCompletion)?;
                return self.finish_completion(completion, None);
            }
            yield_runtime()?;
        }
    }

    fn runtime_read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), StorageError> {
        require_active_fiber()?;
        validate_transfer(self.capacity_sectors(), lba, buffer.len())?;
        let mut offset = 0;
        while let Some(chunk) = next_chunk(buffer.len(), offset) {
            let chunk_lba = lba
                .checked_add((chunk.offset / SECTOR_SIZE) as u64)
                .ok_or(StorageError::AddressOverflow)?;
            self.submit_runtime_request(
                BlockOperation::Read,
                chunk_lba,
                None,
                Some(&mut buffer[chunk.offset..chunk.offset + chunk.len]),
            )?;
            offset += chunk.len;
        }
        Ok(())
    }

    fn runtime_write(&mut self, lba: u64, buffer: &[u8]) -> Result<(), StorageError> {
        require_active_fiber()?;
        validate_transfer(self.capacity_sectors(), lba, buffer.len())?;
        let mut offset = 0;
        while let Some(chunk) = next_chunk(buffer.len(), offset) {
            let chunk_lba = lba
                .checked_add((chunk.offset / SECTOR_SIZE) as u64)
                .ok_or(StorageError::AddressOverflow)?;
            self.submit_runtime_request(
                BlockOperation::Write,
                chunk_lba,
                Some(&buffer[chunk.offset..chunk.offset + chunk.len]),
                None,
            )?;
            offset += chunk.len;
        }
        Ok(())
    }

    fn runtime_flush(&mut self) -> Result<(), StorageError> {
        require_active_fiber()?;
        if !self.driver.runtime_flush_needed() {
            return Ok(());
        }
        self.submit_runtime_request(BlockOperation::Flush, 0, None, None)
    }
}

impl BlockDevice for StorageDisk {
    type Error = StorageError;

    fn capacity_sectors(&self) -> u64 {
        match &self.driver {
            StorageDriver::Virtio(driver) => driver.capacity_sectors(),
            StorageDriver::Ahci(driver) => driver.capacity_sectors(),
        }
    }

    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        match self.mode {
            StorageMode::Bootstrap => self
                .driver
                .bootstrap_read(lba, buffer)
                .map_err(StorageError::from),
            StorageMode::Runtime => self.runtime_read(lba, buffer),
        }
    }

    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        match self.mode {
            StorageMode::Bootstrap => self
                .driver
                .bootstrap_write(lba, buffer)
                .map_err(StorageError::from),
            StorageMode::Runtime => self.runtime_write(lba, buffer),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        match self.mode {
            StorageMode::Bootstrap => self.driver.bootstrap_flush().map_err(StorageError::from),
            StorageMode::Runtime => self.runtime_flush(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Chunk {
    offset: usize,
    len: usize,
}

fn next_chunk(total: usize, offset: usize) -> Option<Chunk> {
    if offset >= total {
        return None;
    }
    Some(Chunk {
        offset,
        len: (total - offset).min(MAX_RUNTIME_TRANSFER_BYTES),
    })
}

fn validate_transfer(capacity: u64, lba: u64, byte_len: usize) -> Result<(), StorageError> {
    if byte_len % SECTOR_SIZE != 0 {
        return Err(StorageError::Misaligned);
    }
    let sectors =
        u64::try_from(byte_len / SECTOR_SIZE).map_err(|_| StorageError::AddressOverflow)?;
    let end = lba
        .checked_add(sectors)
        .ok_or(StorageError::AddressOverflow)?;
    if end > capacity {
        return Err(StorageError::OutOfBounds);
    }
    Ok(())
}

fn commit_runtime_mode(mode: &mut StorageMode) {
    *mode = StorageMode::Runtime;
}

fn require_active_fiber() -> Result<(), StorageError> {
    match fiber::yield_now() {
        Ok(()) => Ok(()),
        Err(YieldError::OutsideFiber) => Err(StorageError::OutsideActiveFiber),
        Err(error) => Err(StorageError::Yield(error)),
    }
}

fn yield_runtime() -> Result<(), StorageError> {
    require_active_fiber()
}

fn deadline_after(now_ns: u64, timeout_ns: u64) -> u64 {
    now_ns.saturating_add(timeout_ns)
}

fn ticks_to_nanoseconds(ticks: u64, frequency_hz: u64) -> u64 {
    if frequency_hz == 0 {
        return u64::MAX;
    }
    let nanoseconds = u128::from(ticks)
        .saturating_mul(1_000_000_000)
        .checked_div(u128::from(frequency_hz))
        .unwrap_or(u128::from(u64::MAX));
    nanoseconds.min(u128::from(u64::MAX)) as u64
}

fn ordered_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let low: u32;
        let high: u32;
        // SAFETY: LFENCE/RDTSC only read architectural timing state.
        unsafe {
            asm!(
                "lfence",
                "rdtsc",
                out("eax") low,
                out("edx") high,
                options(nostack),
            );
        }
        u64::from(low) | (u64::from(high) << 32)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

const fn next_generation(generation: u32) -> u32 {
    match generation.checked_add(1) {
        Some(0) | None => 1,
        Some(next) => next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_at_runtime_transfer_boundaries_without_overlap() {
        assert_eq!(next_chunk(0, 0), None);
        let total = MAX_RUNTIME_TRANSFER_BYTES + SECTOR_SIZE;
        assert_eq!(
            next_chunk(total, 0),
            Some(Chunk {
                offset: 0,
                len: MAX_RUNTIME_TRANSFER_BYTES,
            })
        );
        assert_eq!(
            next_chunk(total, MAX_RUNTIME_TRANSFER_BYTES),
            Some(Chunk {
                offset: MAX_RUNTIME_TRANSFER_BYTES,
                len: SECTOR_SIZE,
            })
        );
        assert_eq!(next_chunk(total, total), None);
    }

    #[test]
    fn bounce_page_is_not_reused_until_matching_completion() {
        let mut pool = BouncePool::model(0x20_0000);
        let (index, generation, lease) = pool.acquire(SECTOR_SIZE).unwrap();
        let request = BlockRequestId::from_raw((1_u64 << 32) | 1);
        pool.mark_submitted(index, generation, request).unwrap();

        assert_eq!(
            pool.pages[index].state,
            BounceState::Submitted {
                generation,
                request
            }
        );
        let wrong = BlockRequestId::from_raw((1_u64 << 32) | 2);
        assert_eq!(
            pool.validate_return(wrong, &lease),
            Err(StorageError::BounceOwnership)
        );
        assert_eq!(
            pool.pages[index].state,
            BounceState::Submitted {
                generation,
                request
            }
        );

        assert_eq!(pool.release_return(request, lease), Ok(index));
        assert_eq!(pool.pages[index].state, BounceState::Available);
    }

    #[test]
    fn submitted_batch_pages_release_only_for_the_matching_parent() {
        let mut pool = BouncePool::model(0x20_0000);
        let request = BlockRequestId::from_raw((1_u64 << 32) | 1);
        let wrong = BlockRequestId::from_raw((1_u64 << 32) | 2);
        let mut owners = [(0, 0); 3];
        for owner in &mut owners {
            let (index, generation, _) = pool.acquire(BOUNCE_BYTES).unwrap();
            pool.mark_submitted(index, generation, request).unwrap();
            *owner = (index, generation);
        }

        for (index, generation) in owners {
            assert_eq!(
                pool.release_submitted(wrong, index, generation),
                Err(StorageError::BounceOwnership)
            );
            assert_eq!(pool.release_submitted(request, index, generation), Ok(()));
        }
        assert_eq!(pool.counts(), (STORAGE_BOUNCE_PAGES, 0, 0));
    }

    #[test]
    fn quarantine_retains_ownership_until_external_dma_stop_proof() {
        let mut pool = BouncePool::model(0x20_0000);
        let request = BlockRequestId::from_raw((1_u64 << 32) | 1);
        let mut owners = [(0, 0); 3];
        for owner in &mut owners {
            let (index, generation, _) = pool.acquire(BOUNCE_BYTES).unwrap();
            pool.mark_submitted(index, generation, request).unwrap();
            *owner = (index, generation);
        }

        pool.quarantine_request(request);
        assert_eq!(pool.counts(), (STORAGE_BOUNCE_PAGES - 3, 0, 3));
        for (index, generation) in owners {
            pool.release_after_dma_stopped(request, index, generation)
                .unwrap();
        }
        assert_eq!(pool.counts(), (STORAGE_BOUNCE_PAGES, 0, 0));
    }

    #[test]
    fn bounce_copies_only_the_requested_chunk() {
        let mut backing = [0xa5_u8; BOUNCE_BYTES];
        let source = [0x5a_u8; SECTOR_SIZE];
        let mut destination = [0_u8; SECTOR_SIZE];
        let mut pool = BouncePool::model(0x20_0000);
        pool.pages[0].pointer = backing.as_mut_ptr();
        let (index, _, _) = pool.acquire(SECTOR_SIZE).unwrap();

        pool.copy_into(index, &source).unwrap();
        assert_eq!(&backing[..SECTOR_SIZE], &source);
        assert!(backing[SECTOR_SIZE..].iter().all(|byte| *byte == 0xa5));

        pool.copy_out(index, &mut destination).unwrap();
        assert_eq!(destination, source);
    }

    #[test]
    fn runtime_mode_transition_is_permanent_and_idempotent() {
        let mut mode = StorageMode::Bootstrap;
        commit_runtime_mode(&mut mode);
        assert_eq!(mode, StorageMode::Runtime);
        commit_runtime_mode(&mut mode);
        assert_eq!(mode, StorageMode::Runtime);
    }

    #[test]
    fn tsc_deadline_conversion_saturates_safely() {
        assert_eq!(
            ticks_to_nanoseconds(3_000_000_000, 3_000_000_000),
            1_000_000_000
        );
        assert_eq!(ticks_to_nanoseconds(1, 0), u64::MAX);
        assert_eq!(deadline_after(7, 11), 18);
        assert_eq!(deadline_after(u64::MAX - 2, 10), u64::MAX);
    }

    #[test]
    fn runtime_entry_rejects_calls_outside_a_fiber() {
        assert_eq!(
            require_active_fiber(),
            Err(StorageError::OutsideActiveFiber)
        );
    }

    #[test]
    fn transfer_validation_checks_alignment_and_capacity() {
        assert_eq!(validate_transfer(10, 9, SECTOR_SIZE), Ok(()));
        assert_eq!(validate_transfer(10, 10, 0), Ok(()));
        assert_eq!(
            validate_transfer(10, 10, SECTOR_SIZE),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(validate_transfer(10, 0, 1), Err(StorageError::Misaligned));
    }
}
