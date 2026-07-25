//! Fixed-capacity transitional PCI virtio-blk support.
//!
//! Bootstrap callers may use the synchronous [`BlockDevice`] API before MSI-X is
//! enabled. The asynchronous path owns a bounded set of descriptor blocks, keeps
//! exact dispatch tokens until hardware returns each chain, and drains used-ring
//! entries in device-selected order. The assembly ISR only records a pending bit;
//! all queue work remains in deferred task context.

use core::{
    hint::spin_loop,
    ptr,
    sync::atomic::{fence, Ordering},
    task::Poll,
};

use crate::{
    arch::{take_virtio_blk_interrupt_pending, VIRTIO_BLK_VECTOR},
    async_block::{
        AsyncBlockDevice, BlockDeviceConfig, BlockOperation, DispatchCommand, DispatchToken,
        DmaAddressMode, DmaConstraints, DmaSegment, DriverCompletion, HardwareStatus,
    },
    block::{BlockDevice, SECTOR_SIZE},
    io::{IoError, MmioRegion, PortRegion},
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageTableFlags},
    pci::{PciBar, PciConfig, PciDevice, PciError, PciMsixCapability},
};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_BLK_TRANSITIONAL_DEVICE_ID: u16 = 0x1001;
const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
const PCI_BAR0: u8 = 0x10;
const LEGACY_IO_BYTES: u16 = 0x20;

const REG_HOST_FEATURES: u16 = 0x00;
const REG_GUEST_FEATURES: u16 = 0x04;
const REG_QUEUE_PFN: u16 = 0x08;
const REG_QUEUE_SIZE: u16 = 0x0c;
const REG_QUEUE_SELECT: u16 = 0x0e;
const REG_QUEUE_NOTIFY: u16 = 0x10;
const REG_DEVICE_STATUS: u16 = 0x12;
const REG_ISR_STATUS: u16 = 0x13;
const REG_MSIX_CONFIG_VECTOR: u16 = 0x14;
const REG_MSIX_QUEUE_VECTOR: u16 = 0x16;
const REG_CONFIG_WITHOUT_MSIX: u16 = 0x14;
const REG_CONFIG_WITH_MSIX: u16 = 0x18;
const CONFIG_CAPACITY_LOW: u16 = 0;
const CONFIG_CAPACITY_HIGH: u16 = 4;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
const STATUS_FAILED: u8 = 128;
const READY_STATUS: u8 = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;

const VIRTIO_BLK_F_RO: u32 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;
const SUPPORTED_FEATURES: u32 = VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
const DESCRIPTOR_BYTES: usize = 16;
const USED_ELEMENT_BYTES: usize = 8;
const MAX_QUEUE_SIZE: u16 = 256;
const MAX_SG_SEGMENTS: usize = 8;
const DESCRIPTORS_PER_SLOT: u16 = (MAX_SG_SEGMENTS as u16) + 2;
const MAX_SLOTS: usize = 16;
const INVALID_SLOT: u8 = u8::MAX;
const QUEUE_INDEX: u16 = 0;

const POLL_LIMIT: usize = 1_000_000;
const INTERRUPT_WATCHDOG_POLLS: u16 = 64;
const REQUEST_HEADER_BYTES: usize = 16;
const REQUEST_STATUS_OFFSET: usize = 16;
const REQUEST_STRIDE: usize = 32;

const MSIX_NO_VECTOR: u16 = u16::MAX;
const MSIX_TABLE_ENTRY_BYTES: u64 = 16;
const MSIX_ENTRY_ADDRESS_LOW: usize = 0;
const MSIX_ENTRY_ADDRESS_HIGH: usize = 4;
const MSIX_ENTRY_DATA: usize = 8;
const MSIX_ENTRY_VECTOR_CONTROL: usize = 12;
const MSIX_VECTOR_MASKED: u32 = 1;
const MSI_ADDRESS_BASE: u32 = 0xfee0_0000;
const MAX_MSIX_BAR_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioBlkError {
    Pci(PciError),
    Io(IoError),
    Mapping(MapError),
    FrameAllocator(FrameAllocatorError),
    DeviceNotPresent,
    InvalidIoBar,
    InvalidMsixTable,
    MsixUnavailable,
    MsixRejected,
    InvalidQueueSize,
    InvalidQueueLayout,
    UnsupportedDmaAddress,
    AddressOverflow,
    OutOfFrames,
    FeatureNegotiationFailed,
    ReadOnly,
    Misaligned,
    OutOfBounds,
    TimedOut,
    Busy,
    QueueFull,
    AsyncNotEnabled,
    TooManySegments,
    InvalidRequest,
    GenerationExhausted,
    CompletionQueueFull,
    DeviceNeedsReset,
    DeviceReset,
    DeviceFailed,
    DeviceIo,
    UnsupportedRequest,
    InvalidDeviceStatus(u8),
    InvalidUsedRing,
    InvalidDescriptorChain,
}

impl From<PciError> for VirtioBlkError {
    fn from(value: PciError) -> Self {
        Self::Pci(value)
    }
}

impl From<IoError> for VirtioBlkError {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

impl From<MapError> for VirtioBlkError {
    fn from(value: MapError) -> Self {
        Self::Mapping(value)
    }
}

impl From<FrameAllocatorError> for VirtioBlkError {
    fn from(value: FrameAllocatorError) -> Self {
        Self::FrameAllocator(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioBlkDiagnostics {
    pub async_enabled: bool,
    pub msix_enabled: bool,
    pub interrupts: u64,
    pub watchdog_polls: u64,
    pub submissions: u64,
    pub completions: u64,
    pub in_flight: u16,
    pub in_flight_high_water: u16,
    pub invalid_used_ids: u64,
    pub errors: u64,
    pub resets: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueueLayout {
    descriptors: usize,
    available: usize,
    used: usize,
    bytes: usize,
    pages: usize,
}

impl QueueLayout {
    fn new(size: u16) -> Result<Self, VirtioBlkError> {
        if size < DESCRIPTORS_PER_SLOT || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
            return Err(VirtioBlkError::InvalidQueueSize);
        }
        let size = usize::from(size);
        let descriptors = 0;
        let descriptor_bytes = size
            .checked_mul(DESCRIPTOR_BYTES)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let available = descriptor_bytes;
        let available_bytes = 6_usize
            .checked_add(size.checked_mul(2).ok_or(VirtioBlkError::AddressOverflow)?)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let used = align_up(
            available
                .checked_add(available_bytes)
                .ok_or(VirtioBlkError::AddressOverflow)?,
            PAGE_SIZE as usize,
        )?;
        let used_bytes = 6_usize
            .checked_add(
                size.checked_mul(USED_ELEMENT_BYTES)
                    .ok_or(VirtioBlkError::AddressOverflow)?,
            )
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let bytes = used
            .checked_add(used_bytes)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let pages = bytes
            .checked_add(PAGE_SIZE as usize - 1)
            .ok_or(VirtioBlkError::AddressOverflow)?
            / PAGE_SIZE as usize;
        Ok(Self {
            descriptors,
            available,
            used,
            bytes,
            pages,
        })
    }
}

struct DmaRegion {
    physical: u64,
    pointer: *mut u8,
    len: usize,
}

impl DmaRegion {
    fn allocate_contiguous(
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
        pages: usize,
        max_address_exclusive: Option<u64>,
    ) -> Result<Self, VirtioBlkError> {
        let allocated = match max_address_exclusive {
            Some(limit) => frames.allocate_contiguous_frames_below(pages, limit)?,
            None => frames.allocate_contiguous_frames(pages)?,
        }
        .ok_or(VirtioBlkError::OutOfFrames)?;
        let physical = allocated
            .first()
            .ok_or(VirtioBlkError::AddressOverflow)?
            .start_address()
            .as_u64();
        let len = pages
            .checked_mul(PAGE_SIZE as usize)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        physical
            .checked_add(u64::try_from(len).map_err(|_| VirtioBlkError::AddressOverflow)? - 1)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let virtual_address = hhdm_offset
            .checked_add(physical)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        VirtAddr::try_new(virtual_address).map_err(|_| VirtioBlkError::AddressOverflow)?;
        let pointer = usize::try_from(virtual_address)
            .map_err(|_| VirtioBlkError::AddressOverflow)? as *mut u8;
        unsafe { ptr::write_bytes(pointer, 0, len) };
        Ok(Self {
            physical,
            pointer,
            len,
        })
    }

    fn checked(
        &self,
        offset: usize,
        width: usize,
        alignment: usize,
    ) -> Result<*mut u8, VirtioBlkError> {
        if alignment == 0 || offset % alignment != 0 {
            return Err(VirtioBlkError::InvalidQueueLayout);
        }
        offset
            .checked_add(width)
            .filter(|end| *end <= self.len)
            .ok_or(VirtioBlkError::InvalidQueueLayout)?;
        Ok(unsafe { self.pointer.add(offset) })
    }

    fn read_u8(&self, offset: usize) -> Result<u8, VirtioBlkError> {
        let pointer = self.checked(offset, 1, 1)?;
        Ok(unsafe { ptr::read_volatile(pointer) })
    }

    fn read_u16(&self, offset: usize) -> Result<u16, VirtioBlkError> {
        let pointer = self.checked(offset, 2, 2)?.cast::<u16>();
        Ok(u16::from_le(unsafe { ptr::read_volatile(pointer) }))
    }

    fn read_u32(&self, offset: usize) -> Result<u32, VirtioBlkError> {
        let pointer = self.checked(offset, 4, 4)?.cast::<u32>();
        Ok(u32::from_le(unsafe { ptr::read_volatile(pointer) }))
    }

    fn write_u8(&self, offset: usize, value: u8) -> Result<(), VirtioBlkError> {
        let pointer = self.checked(offset, 1, 1)?;
        unsafe { ptr::write_volatile(pointer, value) };
        Ok(())
    }

    fn write_u16(&self, offset: usize, value: u16) -> Result<(), VirtioBlkError> {
        let pointer = self.checked(offset, 2, 2)?.cast::<u16>();
        unsafe { ptr::write_volatile(pointer, value.to_le()) };
        Ok(())
    }

    fn write_u32(&self, offset: usize, value: u32) -> Result<(), VirtioBlkError> {
        let pointer = self.checked(offset, 4, 4)?.cast::<u32>();
        unsafe { ptr::write_volatile(pointer, value.to_le()) };
        Ok(())
    }

    fn write_u64(&self, offset: usize, value: u64) -> Result<(), VirtioBlkError> {
        let pointer = self.checked(offset, 8, 8)?.cast::<u64>();
        unsafe { ptr::write_volatile(pointer, value.to_le()) };
        Ok(())
    }

    fn copy_from(&self, offset: usize, source: &[u8]) -> Result<(), VirtioBlkError> {
        let destination = self.checked(offset, source.len(), 1)?;
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len()) };
        Ok(())
    }

    fn copy_to(&self, offset: usize, destination: &mut [u8]) -> Result<(), VirtioBlkError> {
        let source = self.checked(offset, destination.len(), 1)?;
        unsafe { ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len()) };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    InFlight,
    CancelPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestSlot<T: Copy> {
    state: SlotState,
    generation: u32,
    token: Option<T>,
    synchronous: bool,
    operation: BlockOperation,
    byte_len: u32,
    expected_used_len: u32,
}

impl<T: Copy + Eq> RequestSlot<T> {
    const fn empty() -> Self {
        Self {
            state: SlotState::Free,
            generation: 0,
            token: None,
            synchronous: false,
            operation: BlockOperation::Flush,
            byte_len: 0,
            expected_used_len: 0,
        }
    }

    fn start(
        &mut self,
        token: Option<T>,
        synchronous: bool,
        operation: BlockOperation,
        byte_len: u32,
        expected_used_len: u32,
    ) -> Result<(), VirtioBlkError> {
        if self.state != SlotState::Free {
            return Err(VirtioBlkError::Busy);
        }
        let generation = self.generation.wrapping_add(1);
        if generation == 0 {
            return Err(VirtioBlkError::GenerationExhausted);
        }
        self.generation = generation;
        self.token = token;
        self.synchronous = synchronous;
        self.operation = operation;
        self.byte_len = byte_len;
        self.expected_used_len = expected_used_len;
        self.state = SlotState::InFlight;
        Ok(())
    }

    fn request_cancel(&mut self, token: T) -> bool {
        if self.token == Some(token) && self.state != SlotState::Free {
            self.state = SlotState::CancelPending;
            true
        } else {
            false
        }
    }

    fn cancel_synchronous(&mut self) {
        if self.synchronous && self.state != SlotState::Free {
            self.state = SlotState::CancelPending;
        }
    }

    fn release(&mut self) {
        self.state = SlotState::Free;
        self.token = None;
        self.synchronous = false;
        self.operation = BlockOperation::Flush;
        self.byte_len = 0;
        self.expected_used_len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetState {
    Running,
    WaitingForZero,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorPlan {
    request_type: u32,
    data_count: u8,
    device_writes_data: bool,
    descriptor_count: u8,
    expected_used_len: u32,
}

impl DescriptorPlan {
    #[cfg(test)]
    fn chain_indices(self, slot: usize) -> [u16; DESCRIPTORS_PER_SLOT as usize] {
        let mut indices = [u16::MAX; DESCRIPTORS_PER_SLOT as usize];
        let head = descriptor_head(slot);
        indices[0] = head;
        for index in 0..usize::from(self.data_count) {
            indices[index + 1] = head + 1 + index as u16;
        }
        indices[usize::from(self.descriptor_count) - 1] = head + DESCRIPTORS_PER_SLOT - 1;
        indices
    }
}

/// One exclusively owned transitional virtio-blk PCI function.
pub struct VirtioBlk {
    io: PortRegion,
    queue: DmaRegion,
    requests: DmaRegion,
    bootstrap_data: DmaRegion,
    msix_table: Option<MmioRegion>,
    msix_capability: Option<PciMsixCapability>,
    pci_device: PciDevice,
    layout: QueueLayout,
    queue_size: u16,
    slot_count: u16,
    slots: [RequestSlot<DispatchToken>; MAX_SLOTS],
    head_to_slot: [u8; MAX_QUEUE_SIZE as usize],
    completions: [Option<DriverCompletion>; MAX_SLOTS],
    completion_head: u8,
    completion_tail: u8,
    completion_count: u8,
    capacity_sectors: u64,
    read_only: bool,
    flush_supported: bool,
    available_index: u16,
    used_index: u16,
    watchdog_countdown: u16,
    sync_completion: Option<Result<(), VirtioBlkError>>,
    reset_state: ResetState,
    terminal_error: Option<VirtioBlkError>,
    diagnostics: VirtioBlkDiagnostics,
}

impl VirtioBlk {
    /// Discovers and initializes the first QEMU transitional virtio-blk device.
    ///
    /// The active page table is needed only to map an optional MSI-X table. Queue,
    /// request, status, and bootstrap data DMA are allocated below 4 GiB.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own PCI configuration mechanism #1, the
    /// discovered function, the active page table, and its BARs. The HHDM in
    /// `page_table` must coherently map allocator frames for this object's life.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, VirtioBlkError> {
        let mut pci = unsafe { PciConfig::new()? };
        let device = find_device(&mut pci)?.ok_or(VirtioBlkError::DeviceNotPresent)?;
        let bar = pci.read_u32(device.address, PCI_BAR0)?;
        let base = io_bar_base(bar)?;

        let msix_capability = pci.find_msix_capability(device)?;
        if let Some(capability) = msix_capability {
            pci.set_msix_control(device, capability, false, true)?;
        }

        let command = pci.read_u16(device.address, 0x04)?;
        pci.write_u16(
            device.address,
            0x04,
            command | PCI_COMMAND_IO_SPACE | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER,
        )?;
        let identity = pci.read_u32(device.address, 0x00)?;
        if identity as u16 != VIRTIO_VENDOR_ID
            || (identity >> 16) as u16 != VIRTIO_BLK_TRANSITIONAL_DEVICE_ID
        {
            return Err(VirtioBlkError::DeviceNotPresent);
        }

        let msix_table = if let Some(capability) = msix_capability {
            let table_bar = pci.probe_bar(device, capability.table_bar)?;
            validate_msix_table(capability, table_bar)?;
            let mut table = unsafe { map_msix_bar(page_table, frames, table_bar)? };
            table.write_u32(
                capability.table_offset as usize + MSIX_ENTRY_VECTOR_CONTROL,
                MSIX_VECTOR_MASKED,
            )?;
            Some(table)
        } else {
            None
        };
        fence(Ordering::Release);

        let mut io = unsafe { PortRegion::new(base, LEGACY_IO_BYTES) }
            .ok_or(VirtioBlkError::InvalidIoBar)?;
        io.write_u8(REG_DEVICE_STATUS, 0)?;
        if io.read_u8(REG_DEVICE_STATUS)? != 0 {
            return Err(VirtioBlkError::DeviceReset);
        }
        write_status(&mut io, STATUS_ACKNOWLEDGE)?;
        write_status(&mut io, STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;

        let host_features = io.read_u32(REG_HOST_FEATURES)?;
        let negotiated = host_features & SUPPORTED_FEATURES;
        io.write_u32(REG_GUEST_FEATURES, negotiated)?;
        let feature_status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
        write_status(&mut io, feature_status)?;
        if io.read_u8(REG_DEVICE_STATUS)? & STATUS_FEATURES_OK == 0 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::FeatureNegotiationFailed);
        }

        io.write_u16(REG_QUEUE_SELECT, QUEUE_INDEX)?;
        if io.read_u32(REG_QUEUE_PFN)? != 0 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::InvalidQueueLayout);
        }
        let queue_size = io.read_u16(REG_QUEUE_SIZE)?;
        let layout = QueueLayout::new(queue_size)?;
        let slot_count = slot_count_for_queue(queue_size)?;

        let hhdm_offset = page_table.hhdm_offset().as_u64();
        let queue = DmaRegion::allocate_contiguous(
            frames,
            hhdm_offset,
            layout.pages,
            Some(DMA_32BIT_ADDRESS_LIMIT),
        )?;
        if queue.physical & (PAGE_SIZE - 1) != 0 || queue.physical >> 12 > u64::from(u32::MAX) {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::UnsupportedDmaAddress);
        }
        let requests =
            DmaRegion::allocate_contiguous(frames, hhdm_offset, 1, Some(DMA_32BIT_ADDRESS_LIMIT))?;
        let bootstrap_data =
            DmaRegion::allocate_contiguous(frames, hhdm_offset, 1, Some(DMA_32BIT_ADDRESS_LIMIT))?;

        io.write_u32(REG_QUEUE_PFN, (queue.physical >> 12) as u32)?;
        if io.read_u32(REG_QUEUE_PFN)? != (queue.physical >> 12) as u32 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::InvalidQueueLayout);
        }

        let config_base = transitional_config_base(false);
        let capacity_low = io.read_u32(config_base + CONFIG_CAPACITY_LOW)?;
        let capacity_high = io.read_u32(config_base + CONFIG_CAPACITY_HIGH)?;
        let capacity_sectors = u64::from(capacity_low) | (u64::from(capacity_high) << 32);
        let used_index = queue.read_u16(layout.used + 2)?;
        let available_index = queue.read_u16(layout.available + 2)?;
        if used_index != 0 || available_index != 0 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::InvalidUsedRing);
        }

        let mut head_to_slot = [INVALID_SLOT; MAX_QUEUE_SIZE as usize];
        for slot in 0..usize::from(slot_count) {
            head_to_slot[usize::from(descriptor_head(slot))] = slot as u8;
        }

        write_status(&mut io, READY_STATUS)?;
        validate_operational_status(io.read_u8(REG_DEVICE_STATUS)?, READY_STATUS)?;

        Ok(Self {
            io,
            queue,
            requests,
            bootstrap_data,
            msix_table,
            msix_capability,
            pci_device: device,
            layout,
            queue_size,
            slot_count,
            slots: [RequestSlot::empty(); MAX_SLOTS],
            head_to_slot,
            completions: [None; MAX_SLOTS],
            completion_head: 0,
            completion_tail: 0,
            completion_count: 0,
            capacity_sectors,
            read_only: host_features & VIRTIO_BLK_F_RO != 0,
            flush_supported: negotiated & VIRTIO_BLK_F_FLUSH != 0,
            available_index,
            used_index,
            watchdog_countdown: INTERRUPT_WATCHDOG_POLLS,
            sync_completion: None,
            reset_state: ResetState::Running,
            terminal_error: None,
            diagnostics: VirtioBlkDiagnostics::default(),
        })
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub const fn capacity_bytes(&self) -> Option<u64> {
        self.capacity_sectors.checked_mul(SECTOR_SIZE as u64)
    }

    pub fn diagnostics(&self) -> VirtioBlkDiagnostics {
        self.diagnostics
    }

    /// Programs MSI-X table entry zero for the dedicated virtio-blk vector.
    ///
    /// Enabling MSI-X inserts two legacy transport registers at `0x14` and moves
    /// device-specific configuration from `0x14` to `0x18`. Capacity is cached
    /// before this transition, and all later accesses use the shifted layout.
    pub fn enable_msix(&mut self, destination_apic_id: u8) -> Result<(), VirtioBlkError> {
        self.ensure_running()?;
        if self.diagnostics.msix_enabled {
            return Ok(());
        }
        if self.msix_capability.is_none() || self.msix_table.is_none() {
            return Err(self.reject(VirtioBlkError::MsixUnavailable));
        }

        let result = self.enable_msix_inner(destination_apic_id);
        if let Err(error) = result {
            if let (Some(capability), Some(table)) =
                (self.msix_capability, self.msix_table.as_mut())
            {
                let _ = table.write_u32(
                    capability.table_offset as usize + MSIX_ENTRY_VECTOR_CONTROL,
                    MSIX_VECTOR_MASKED,
                );
                if let Ok(mut pci) = unsafe { PciConfig::new() } {
                    let _ = pci.set_msix_control(self.pci_device, capability, false, true);
                }
            }
            self.diagnostics.msix_enabled = false;
            self.diagnostics.async_enabled = false;
            return Err(self.reject(error));
        }
        self.diagnostics.msix_enabled = true;
        self.diagnostics.async_enabled = true;
        self.watchdog_countdown = INTERRUPT_WATCHDOG_POLLS;
        Ok(())
    }

    fn enable_msix_inner(&mut self, destination_apic_id: u8) -> Result<(), VirtioBlkError> {
        let capability = self
            .msix_capability
            .ok_or(VirtioBlkError::MsixUnavailable)?;
        let table_offset = capability.table_offset as usize;
        let table = self
            .msix_table
            .as_mut()
            .ok_or(VirtioBlkError::MsixUnavailable)?;
        table.write_u32(table_offset + MSIX_ENTRY_VECTOR_CONTROL, MSIX_VECTOR_MASKED)?;
        table.write_u32(
            table_offset + MSIX_ENTRY_ADDRESS_LOW,
            MSI_ADDRESS_BASE | (u32::from(destination_apic_id) << 12),
        )?;
        table.write_u32(table_offset + MSIX_ENTRY_ADDRESS_HIGH, 0)?;
        table.write_u32(table_offset + MSIX_ENTRY_DATA, u32::from(VIRTIO_BLK_VECTOR))?;
        fence(Ordering::Release);

        let mut pci = unsafe { PciConfig::new()? };
        pci.set_msix_control(self.pci_device, capability, true, true)?;

        self.io.write_u16(REG_MSIX_CONFIG_VECTOR, MSIX_NO_VECTOR)?;
        self.io.write_u16(REG_QUEUE_SELECT, QUEUE_INDEX)?;
        self.io.write_u16(REG_MSIX_QUEUE_VECTOR, 0)?;
        if self.io.read_u16(REG_MSIX_CONFIG_VECTOR)? != MSIX_NO_VECTOR
            || self.io.read_u16(REG_MSIX_QUEUE_VECTOR)? != 0
        {
            return Err(VirtioBlkError::MsixRejected);
        }

        table.write_u32(table_offset + MSIX_ENTRY_VECTOR_CONTROL, 0)?;
        fence(Ordering::Release);
        pci.set_msix_control(self.pci_device, capability, true, false)?;
        let _ = self.io.read_u8(REG_ISR_STATUS)?;
        Ok(())
    }

    pub fn read_sectors(
        &mut self,
        first_sector: u64,
        buffer: &mut [u8],
    ) -> Result<(), VirtioBlkError> {
        self.ensure_bootstrap_mode()?;
        let range = transfer_range(first_sector, buffer.len(), self.capacity_sectors)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks_mut(PAGE_SIZE as usize) {
            let segment = DmaSegment {
                physical_address: self.bootstrap_data.physical,
                length: chunk.len() as u32,
            };
            self.submit_synchronous(BlockOperation::Read, sector, chunk.len() as u32, &[segment])?;
            self.bootstrap_data.copy_to(0, chunk)?;
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    pub fn write_sectors(
        &mut self,
        first_sector: u64,
        buffer: &[u8],
    ) -> Result<(), VirtioBlkError> {
        self.ensure_bootstrap_mode()?;
        if self.read_only && !buffer.is_empty() {
            return Err(self.reject(VirtioBlkError::ReadOnly));
        }
        let range = transfer_range(first_sector, buffer.len(), self.capacity_sectors)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks(PAGE_SIZE as usize) {
            self.bootstrap_data.copy_from(0, chunk)?;
            let segment = DmaSegment {
                physical_address: self.bootstrap_data.physical,
                length: chunk.len() as u32,
            };
            self.submit_synchronous(
                BlockOperation::Write,
                sector,
                chunk.len() as u32,
                &[segment],
            )?;
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), VirtioBlkError> {
        self.ensure_bootstrap_mode()?;
        if !self.flush_supported {
            return Ok(());
        }
        self.submit_synchronous(BlockOperation::Flush, 0, 0, &[])
    }

    fn submit_synchronous(
        &mut self,
        operation: BlockOperation,
        sector: u64,
        byte_len: u32,
        segments: &[DmaSegment],
    ) -> Result<(), VirtioBlkError> {
        self.drain_used_ring()?;
        if self.diagnostics.in_flight != 0 {
            return Err(self.reject(VirtioBlkError::Busy));
        }
        self.sync_completion = None;
        let plan = descriptor_plan(operation, byte_len, segments.len())?;
        validate_segments(segments, byte_len)?;
        let slot = self.prepare_slot(None, true, operation, sector, byte_len, segments, plan)?;
        self.publish_slot(slot)?;

        for _ in 0..POLL_LIMIT {
            if let Some(completion) = self.sync_completion.take() {
                return completion;
            }
            if let Err(error) = self.drain_used_ring() {
                self.slots[slot].cancel_synchronous();
                return Err(error);
            }
            if let Some(completion) = self.sync_completion.take() {
                return completion;
            }
            spin_loop();
        }
        self.slots[slot].cancel_synchronous();
        self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
        Err(VirtioBlkError::TimedOut)
    }

    fn submit_async(&mut self, command: &DispatchCommand) -> Result<(), VirtioBlkError> {
        self.ensure_async_mode()?;
        let plan = match descriptor_plan(
            command.operation,
            command.byte_len,
            command.segments().len(),
        ) {
            Ok(plan) => plan,
            Err(error) => return Err(self.reject(error)),
        };
        if self.read_only && command.operation == BlockOperation::Write {
            return Err(self.reject(VirtioBlkError::ReadOnly));
        }
        if matches!(
            command.operation,
            BlockOperation::Read | BlockOperation::Write
        ) {
            if let Err(error) = transfer_range(
                command.lba,
                command.byte_len as usize,
                self.capacity_sectors,
            ) {
                return Err(self.reject(error));
            }
        }
        if let Err(error) = validate_segments(command.segments(), command.byte_len) {
            return Err(self.reject(error));
        }
        if usize::from(self.completion_count) + usize::from(self.diagnostics.in_flight)
            >= usize::from(self.slot_count)
        {
            return Err(self.reject(VirtioBlkError::QueueFull));
        }

        if matches!(
            command.operation,
            BlockOperation::Flush | BlockOperation::Barrier
        ) && !self.flush_supported
        {
            self.diagnostics.submissions = self.diagnostics.submissions.saturating_add(1);
            self.diagnostics.completions = self.diagnostics.completions.saturating_add(1);
            self.push_completion(DriverCompletion {
                token: command.token,
                status: HardwareStatus::Success,
            })?;
            return Ok(());
        }

        let slot = self.prepare_slot(
            Some(command.token),
            false,
            command.operation,
            command.lba,
            command.byte_len,
            command.segments(),
            plan,
        )?;
        self.publish_slot(slot)
    }

    fn prepare_slot(
        &mut self,
        token: Option<DispatchToken>,
        synchronous: bool,
        operation: BlockOperation,
        sector: u64,
        byte_len: u32,
        segments: &[DmaSegment],
        plan: DescriptorPlan,
    ) -> Result<usize, VirtioBlkError> {
        let Some(slot) = self.slots[..usize::from(self.slot_count)]
            .iter()
            .position(|slot| slot.state == SlotState::Free)
        else {
            return Err(VirtioBlkError::QueueFull);
        };

        self.write_slot_chain(slot, sector, segments, plan)?;
        self.slots[slot].start(
            token,
            synchronous,
            operation,
            byte_len,
            plan.expected_used_len,
        )?;
        Ok(slot)
    }

    fn write_slot_chain(
        &self,
        slot: usize,
        sector: u64,
        segments: &[DmaSegment],
        plan: DescriptorPlan,
    ) -> Result<(), VirtioBlkError> {
        let request_offset = request_offset(slot)?;
        self.requests.write_u32(request_offset, plan.request_type)?;
        self.requests.write_u32(request_offset + 4, 0)?;
        self.requests.write_u64(request_offset + 8, sector)?;
        self.requests
            .write_u8(request_offset + REQUEST_STATUS_OFFSET, 0xff)?;

        let head = descriptor_head(slot);
        let status_descriptor = head + DESCRIPTORS_PER_SLOT - 1;
        let first_after_header = if segments.is_empty() {
            status_descriptor
        } else {
            head + 1
        };
        self.write_descriptor(
            head,
            self.requests.physical + request_offset as u64,
            REQUEST_HEADER_BYTES as u32,
            DESC_F_NEXT,
            first_after_header,
        )?;

        for (index, segment) in segments.iter().copied().enumerate() {
            let descriptor = head + 1 + index as u16;
            let next = if index + 1 == segments.len() {
                status_descriptor
            } else {
                descriptor + 1
            };
            self.write_descriptor(
                descriptor,
                segment.physical_address,
                segment.length,
                DESC_F_NEXT
                    | if plan.device_writes_data {
                        DESC_F_WRITE
                    } else {
                        0
                    },
                next,
            )?;
        }

        self.write_descriptor(
            status_descriptor,
            self.requests.physical + request_offset as u64 + REQUEST_STATUS_OFFSET as u64,
            1,
            DESC_F_WRITE,
            0,
        )
    }

    fn publish_slot(&mut self, slot: usize) -> Result<(), VirtioBlkError> {
        let available_slot = usize::from(self.available_index % self.queue_size);
        if let Err(error) = self.queue.write_u16(
            self.layout.available + 4 + available_slot * 2,
            descriptor_head(slot),
        ) {
            self.slots[slot].release();
            return Err(error);
        }
        fence(Ordering::Release);
        let next_available = self.available_index.wrapping_add(1);
        if let Err(error) = self
            .queue
            .write_u16(self.layout.available + 2, next_available)
        {
            self.slots[slot].release();
            return Err(error);
        }
        self.available_index = next_available;
        self.diagnostics.submissions = self.diagnostics.submissions.saturating_add(1);
        self.diagnostics.in_flight = self.diagnostics.in_flight.saturating_add(1);
        self.diagnostics.in_flight_high_water = self
            .diagnostics
            .in_flight_high_water
            .max(self.diagnostics.in_flight);
        fence(Ordering::Release);

        if let Err(error) = self.io.write_u16(REG_QUEUE_NOTIFY, QUEUE_INDEX) {
            let _ = self.fatal(error.into());
            // The available index is visible to the device. Retain ownership and
            // report acceptance; the worker will observe the terminal error.
        }
        Ok(())
    }

    fn drain_used_ring(&mut self) -> Result<(), VirtioBlkError> {
        let status = match self.io.read_u8(REG_DEVICE_STATUS) {
            Ok(status) => status,
            Err(error) => return Err(self.fatal(error.into())),
        };
        if let Err(error) = validate_operational_status(status, READY_STATUS) {
            return Err(self.fatal(error));
        }

        fence(Ordering::Acquire);
        let observed = match self.queue.read_u16(self.layout.used + 2) {
            Ok(index) => index,
            Err(error) => return Err(self.fatal(error)),
        };
        let pending = match used_index_distance(self.used_index, observed, self.queue_size) {
            Ok(pending) => pending,
            Err(error) => return Err(self.fatal(error)),
        };
        if pending > self.diagnostics.in_flight {
            return Err(self.fatal(VirtioBlkError::InvalidUsedRing));
        }

        fence(Ordering::Acquire);
        for _ in 0..pending {
            let used_slot = usize::from(self.used_index % self.queue_size);
            let element = self.layout.used + 4 + used_slot * USED_ELEMENT_BYTES;
            let id = match self.queue.read_u32(element) {
                Ok(id) => id,
                Err(error) => return Err(self.fatal(error)),
            };
            let length = match self.queue.read_u32(element + 4) {
                Ok(length) => length,
                Err(error) => return Err(self.fatal(error)),
            };
            let slot =
                match mapped_slot_for_used(&self.head_to_slot, &self.slots, self.slot_count, id) {
                    Ok(slot) => slot,
                    Err(error) => {
                        self.diagnostics.invalid_used_ids =
                            self.diagnostics.invalid_used_ids.saturating_add(1);
                        return Err(self.fatal(error));
                    }
                };
            if length != self.slots[slot].expected_used_len {
                return Err(self.fatal(VirtioBlkError::InvalidUsedRing));
            }

            let status_offset = request_offset(slot)? + REQUEST_STATUS_OFFSET;
            let request_status = match self.requests.read_u8(status_offset) {
                Ok(status) => status,
                Err(error) => return Err(self.fatal(error)),
            };
            let hardware_status = match request_status {
                VIRTIO_BLK_S_OK => HardwareStatus::Success,
                VIRTIO_BLK_S_IOERR => {
                    self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
                    HardwareStatus::IoError
                }
                VIRTIO_BLK_S_UNSUPP => {
                    self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
                    HardwareStatus::Unsupported
                }
                value => return Err(self.fatal(VirtioBlkError::InvalidDeviceStatus(value))),
            };

            self.used_index = self.used_index.wrapping_add(1);
            self.complete_slot(slot, hardware_status)?;
        }
        Ok(())
    }

    fn complete_slot(
        &mut self,
        slot_index: usize,
        hardware_status: HardwareStatus,
    ) -> Result<(), VirtioBlkError> {
        let slot = self.slots[slot_index];
        if slot.synchronous {
            if slot.state != SlotState::CancelPending {
                self.sync_completion = Some(match hardware_status {
                    HardwareStatus::Success => Ok(()),
                    HardwareStatus::IoError => Err(VirtioBlkError::DeviceIo),
                    HardwareStatus::Unsupported => Err(VirtioBlkError::UnsupportedRequest),
                });
            }
        } else {
            let token = slot
                .token
                .ok_or_else(|| self.fatal(VirtioBlkError::InvalidUsedRing))?;
            self.push_completion(DriverCompletion {
                token,
                status: hardware_status,
            })?;
        }
        self.slots[slot_index].release();
        self.diagnostics.in_flight = self.diagnostics.in_flight.saturating_sub(1);
        self.diagnostics.completions = self.diagnostics.completions.saturating_add(1);
        Ok(())
    }

    fn poll_completion_inner(&mut self) -> Poll<Result<DriverCompletion, VirtioBlkError>> {
        if let Some(completion) = self.pop_completion() {
            return Poll::Ready(Ok(completion));
        }
        if let Some(error) = self.terminal_error {
            return Poll::Ready(Err(error));
        }
        if self.reset_state != ResetState::Running {
            return Poll::Ready(Err(VirtioBlkError::DeviceReset));
        }

        let interrupted = take_virtio_blk_interrupt_pending();
        let should_drain = if interrupted {
            self.diagnostics.interrupts = self.diagnostics.interrupts.saturating_add(1);
            self.watchdog_countdown = INTERRUPT_WATCHDOG_POLLS;
            if let Err(error) = self.io.read_u8(REG_ISR_STATUS) {
                return Poll::Ready(Err(self.fatal(error.into())));
            }
            fence(Ordering::Acquire);
            true
        } else if self.diagnostics.in_flight == 0 {
            false
        } else if self.watchdog_countdown > 1 {
            self.watchdog_countdown -= 1;
            false
        } else {
            self.watchdog_countdown = INTERRUPT_WATCHDOG_POLLS;
            self.diagnostics.watchdog_polls = self.diagnostics.watchdog_polls.saturating_add(1);
            true
        };

        if should_drain {
            if let Err(error) = self.drain_used_ring() {
                return Poll::Ready(Err(error));
            }
        }
        match self.pop_completion() {
            Some(completion) => Poll::Ready(Ok(completion)),
            None => Poll::Pending,
        }
    }

    fn push_completion(&mut self, completion: DriverCompletion) -> Result<(), VirtioBlkError> {
        if usize::from(self.completion_count) >= usize::from(self.slot_count) {
            return Err(self.fatal(VirtioBlkError::CompletionQueueFull));
        }
        let index = usize::from(self.completion_tail);
        self.completions[index] = Some(completion);
        self.completion_tail =
            ((usize::from(self.completion_tail) + 1) % usize::from(self.slot_count)) as u8;
        self.completion_count += 1;
        Ok(())
    }

    fn pop_completion(&mut self) -> Option<DriverCompletion> {
        if self.completion_count == 0 {
            return None;
        }
        let index = usize::from(self.completion_head);
        let completion = self.completions[index].take();
        self.completion_head =
            ((usize::from(self.completion_head) + 1) % usize::from(self.slot_count)) as u8;
        self.completion_count -= 1;
        completion
    }

    fn request_cancel_inner(&mut self, token: DispatchToken) -> Result<(), VirtioBlkError> {
        self.ensure_async_mode()?;
        for slot in &mut self.slots[..usize::from(self.slot_count)] {
            if slot.request_cancel(token) {
                return Ok(());
            }
        }
        // Completion may already be in the bounded FIFO. Cancellation remains a
        // logical request and never fabricates a hardware completion.
        Ok(())
    }

    fn poll_reset_inner(&mut self) -> Poll<Result<(), VirtioBlkError>> {
        if self.reset_state == ResetState::Complete {
            return Poll::Ready(Ok(()));
        }
        if self.reset_state == ResetState::Running {
            self.diagnostics.resets = self.diagnostics.resets.saturating_add(1);
            if let Some(capability) = self.msix_capability {
                if let Some(table) = self.msix_table.as_mut() {
                    let _ = table.write_u32(
                        capability.table_offset as usize + MSIX_ENTRY_VECTOR_CONTROL,
                        MSIX_VECTOR_MASKED,
                    );
                    fence(Ordering::Release);
                }
            }
            if let Err(error) = self.io.write_u8(REG_DEVICE_STATUS, 0) {
                return Poll::Ready(Err(self.reject(error.into())));
            }
            self.reset_state = ResetState::WaitingForZero;
        }

        let observed = match self.io.read_u8(REG_DEVICE_STATUS) {
            Ok(observed) => observed,
            Err(error) => return Poll::Ready(Err(self.reject(error.into()))),
        };
        if observed == u8::MAX {
            return Poll::Ready(Err(self.reject(VirtioBlkError::DeviceNotPresent)));
        }
        if observed != 0 {
            return Poll::Pending;
        }

        fence(Ordering::Acquire);
        release_slots_after_verified_reset(&mut self.slots, self.slot_count, observed);
        self.diagnostics.in_flight = 0;
        self.completions.fill(None);
        self.completion_head = 0;
        self.completion_tail = 0;
        self.completion_count = 0;
        self.sync_completion = None;
        self.terminal_error = Some(VirtioBlkError::DeviceReset);
        self.reset_state = ResetState::Complete;
        self.diagnostics.async_enabled = false;

        if let Some(capability) = self.msix_capability {
            match unsafe { PciConfig::new() } {
                Ok(mut pci) => {
                    if let Err(error) =
                        pci.set_msix_control(self.pci_device, capability, false, true)
                    {
                        return Poll::Ready(Err(self.reject(error.into())));
                    }
                    self.diagnostics.msix_enabled = false;
                }
                Err(error) => return Poll::Ready(Err(self.reject(error.into()))),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn write_descriptor(
        &self,
        index: u16,
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    ) -> Result<(), VirtioBlkError> {
        if index >= self.queue_size || (flags & DESC_F_NEXT != 0 && next >= self.queue_size) {
            return Err(VirtioBlkError::InvalidDescriptorChain);
        }
        let offset = self.layout.descriptors + usize::from(index) * DESCRIPTOR_BYTES;
        self.queue.write_u64(offset, address)?;
        self.queue.write_u32(offset + 8, length)?;
        self.queue.write_u16(offset + 12, flags)?;
        self.queue.write_u16(offset + 14, next)
    }

    fn ensure_running(&self) -> Result<(), VirtioBlkError> {
        if self.reset_state != ResetState::Running {
            return Err(VirtioBlkError::DeviceReset);
        }
        match self.terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn ensure_bootstrap_mode(&mut self) -> Result<(), VirtioBlkError> {
        self.ensure_running()?;
        if self.diagnostics.async_enabled {
            return Err(self.reject(VirtioBlkError::Busy));
        }
        Ok(())
    }

    fn ensure_async_mode(&mut self) -> Result<(), VirtioBlkError> {
        self.ensure_running()?;
        if !self.diagnostics.async_enabled || !self.diagnostics.msix_enabled {
            return Err(self.reject(VirtioBlkError::AsyncNotEnabled));
        }
        Ok(())
    }

    fn reject(&mut self, error: VirtioBlkError) -> VirtioBlkError {
        self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
        error
    }

    fn fatal(&mut self, error: VirtioBlkError) -> VirtioBlkError {
        self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
        if self.terminal_error.is_none() {
            self.terminal_error = Some(error);
            if let Ok(status) = self.io.read_u8(REG_DEVICE_STATUS) {
                if status != u8::MAX && status != 0 {
                    let _ = self.io.write_u8(REG_DEVICE_STATUS, status | STATUS_FAILED);
                }
            }
        }
        error
    }
}

impl AsyncBlockDevice for VirtioBlk {
    type Error = VirtioBlkError;

    fn config(&self) -> BlockDeviceConfig {
        BlockDeviceConfig {
            capacity_sectors: self.capacity_sectors,
            queue_depth: self.slot_count,
            supports_flush: self.flush_supported,
            dma: DmaConstraints {
                address_mode: DmaAddressMode::Bits64,
                address_alignment: 1,
                max_segments: MAX_SG_SEGMENTS as u8,
                max_segment_len: u32::MAX,
            },
        }
    }

    fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>> {
        if let Err(error) = self.ensure_async_mode() {
            return Poll::Ready(Err(error));
        }
        if usize::from(self.completion_count) + usize::from(self.diagnostics.in_flight)
            >= usize::from(self.slot_count)
        {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn submit(&mut self, command: &DispatchCommand) -> Result<(), Self::Error> {
        self.submit_async(command)
    }

    fn poll_completion(&mut self) -> Poll<Result<DriverCompletion, Self::Error>> {
        self.poll_completion_inner()
    }

    fn request_cancel(&mut self, token: DispatchToken) -> Result<(), Self::Error> {
        self.request_cancel_inner(token)
    }

    fn poll_reset(&mut self) -> Poll<Result<(), Self::Error>> {
        self.poll_reset_inner()
    }
}

impl Drop for VirtioBlk {
    fn drop(&mut self) {
        if let (Some(capability), Some(table)) = (self.msix_capability, self.msix_table.as_mut()) {
            let _ = table.write_u32(
                capability.table_offset as usize + MSIX_ENTRY_VECTOR_CONTROL,
                MSIX_VECTOR_MASKED,
            );
            fence(Ordering::Release);
        }
        let _ = self.io.write_u8(REG_DEVICE_STATUS, 0);
        // Frames come from a monotonic allocator and are not returned here. No
        // slot is logically released unless poll_reset observed status zero.
    }
}

impl BlockDevice for VirtioBlk {
    type Error = VirtioBlkError;

    fn capacity_sectors(&self) -> u64 {
        VirtioBlk::capacity_sectors(self)
    }

    fn read_sectors(&mut self, first_sector: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        VirtioBlk::read_sectors(self, first_sector, buffer)
    }

    fn write_sectors(&mut self, first_sector: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        VirtioBlk::write_sectors(self, first_sector, buffer)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        VirtioBlk::flush(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferRange {
    first_sector: u64,
    sector_count: u64,
}

fn descriptor_plan(
    operation: BlockOperation,
    byte_len: u32,
    segment_count: usize,
) -> Result<DescriptorPlan, VirtioBlkError> {
    if segment_count > MAX_SG_SEGMENTS {
        return Err(VirtioBlkError::TooManySegments);
    }
    match operation {
        BlockOperation::Read | BlockOperation::Write => {
            if byte_len == 0 || byte_len as usize % SECTOR_SIZE != 0 || segment_count == 0 {
                return Err(VirtioBlkError::InvalidRequest);
            }
            let device_writes_data = operation == BlockOperation::Read;
            let expected_used_len = if device_writes_data {
                byte_len
                    .checked_add(1)
                    .ok_or(VirtioBlkError::AddressOverflow)?
            } else {
                1
            };
            Ok(DescriptorPlan {
                request_type: if device_writes_data {
                    VIRTIO_BLK_T_IN
                } else {
                    VIRTIO_BLK_T_OUT
                },
                data_count: segment_count as u8,
                device_writes_data,
                descriptor_count: segment_count as u8 + 2,
                expected_used_len,
            })
        }
        BlockOperation::Flush | BlockOperation::Barrier => {
            if byte_len != 0 || segment_count != 0 {
                return Err(VirtioBlkError::InvalidRequest);
            }
            Ok(DescriptorPlan {
                request_type: VIRTIO_BLK_T_FLUSH,
                data_count: 0,
                device_writes_data: false,
                descriptor_count: 2,
                expected_used_len: 1,
            })
        }
    }
}

fn validate_segments(segments: &[DmaSegment], byte_len: u32) -> Result<(), VirtioBlkError> {
    if segments.len() > MAX_SG_SEGMENTS {
        return Err(VirtioBlkError::TooManySegments);
    }
    let mut total = 0_u64;
    for segment in segments {
        if segment.length == 0 {
            return Err(VirtioBlkError::InvalidRequest);
        }
        segment
            .physical_address
            .checked_add(u64::from(segment.length) - 1)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        total = total
            .checked_add(u64::from(segment.length))
            .ok_or(VirtioBlkError::AddressOverflow)?;
    }
    if total != u64::from(byte_len) {
        return Err(VirtioBlkError::InvalidRequest);
    }
    Ok(())
}

fn slot_count_for_queue(queue_size: u16) -> Result<u16, VirtioBlkError> {
    if queue_size < DESCRIPTORS_PER_SLOT {
        return Err(VirtioBlkError::InvalidQueueSize);
    }
    Ok((queue_size / DESCRIPTORS_PER_SLOT).min(MAX_SLOTS as u16))
}

const fn descriptor_head(slot: usize) -> u16 {
    slot as u16 * DESCRIPTORS_PER_SLOT
}

fn request_offset(slot: usize) -> Result<usize, VirtioBlkError> {
    let offset = slot
        .checked_mul(REQUEST_STRIDE)
        .ok_or(VirtioBlkError::AddressOverflow)?;
    if offset + REQUEST_STRIDE > PAGE_SIZE as usize {
        return Err(VirtioBlkError::InvalidQueueLayout);
    }
    Ok(offset)
}

fn mapped_slot_for_used<T: Copy + Eq>(
    head_to_slot: &[u8; MAX_QUEUE_SIZE as usize],
    slots: &[RequestSlot<T>; MAX_SLOTS],
    slot_count: u16,
    id: u32,
) -> Result<usize, VirtioBlkError> {
    let id = usize::try_from(id).map_err(|_| VirtioBlkError::InvalidUsedRing)?;
    let mapped = head_to_slot
        .get(id)
        .copied()
        .ok_or(VirtioBlkError::InvalidUsedRing)?;
    if mapped == INVALID_SLOT || u16::from(mapped) >= slot_count {
        return Err(VirtioBlkError::InvalidUsedRing);
    }
    let slot = usize::from(mapped);
    if slots[slot].state == SlotState::Free || usize::from(descriptor_head(slot)) != id {
        return Err(VirtioBlkError::InvalidUsedRing);
    }
    Ok(slot)
}

fn used_index_distance(
    consumed: u16,
    observed: u16,
    queue_size: u16,
) -> Result<u16, VirtioBlkError> {
    let distance = observed.wrapping_sub(consumed);
    if distance > queue_size {
        Err(VirtioBlkError::InvalidUsedRing)
    } else {
        Ok(distance)
    }
}

fn release_slots_after_verified_reset<T: Copy + Eq>(
    slots: &mut [RequestSlot<T>; MAX_SLOTS],
    slot_count: u16,
    observed_status: u8,
) -> bool {
    if observed_status != 0 {
        return false;
    }
    for slot in &mut slots[..usize::from(slot_count)] {
        slot.release();
    }
    true
}

fn transfer_range(
    first_sector: u64,
    byte_len: usize,
    capacity_sectors: u64,
) -> Result<TransferRange, VirtioBlkError> {
    if byte_len % SECTOR_SIZE != 0 {
        return Err(VirtioBlkError::Misaligned);
    }
    let sector_count =
        u64::try_from(byte_len).map_err(|_| VirtioBlkError::AddressOverflow)? / SECTOR_SIZE as u64;
    let end = first_sector
        .checked_add(sector_count)
        .ok_or(VirtioBlkError::AddressOverflow)?;
    if end > capacity_sectors {
        return Err(VirtioBlkError::OutOfBounds);
    }
    Ok(TransferRange {
        first_sector,
        sector_count,
    })
}

fn align_up(value: usize, alignment: usize) -> Result<usize, VirtioBlkError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(VirtioBlkError::InvalidQueueLayout);
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(VirtioBlkError::AddressOverflow)
}

fn io_bar_base(raw: u32) -> Result<u16, VirtioBlkError> {
    if raw & 1 == 0 {
        return Err(VirtioBlkError::InvalidIoBar);
    }
    let address = raw & 0xffff_fffc;
    let base = u16::try_from(address).map_err(|_| VirtioBlkError::InvalidIoBar)?;
    if base == 0 || u32::from(base) + u32::from(LEGACY_IO_BYTES) > u32::from(u16::MAX) + 1 {
        return Err(VirtioBlkError::InvalidIoBar);
    }
    Ok(base)
}

const fn transitional_config_base(msix_enabled: bool) -> u16 {
    if msix_enabled {
        REG_CONFIG_WITH_MSIX
    } else {
        REG_CONFIG_WITHOUT_MSIX
    }
}

fn validate_operational_status(status: u8, required: u8) -> Result<(), VirtioBlkError> {
    if status == u8::MAX {
        return Err(VirtioBlkError::DeviceNotPresent);
    }
    if status == 0 {
        return Err(VirtioBlkError::DeviceReset);
    }
    if status & STATUS_FAILED != 0 {
        return Err(VirtioBlkError::DeviceFailed);
    }
    if status & STATUS_DEVICE_NEEDS_RESET != 0 {
        return Err(VirtioBlkError::DeviceNeedsReset);
    }
    if status & required != required {
        return Err(VirtioBlkError::DeviceReset);
    }
    Ok(())
}

fn write_status(io: &mut PortRegion, status: u8) -> Result<(), VirtioBlkError> {
    io.write_u8(REG_DEVICE_STATUS, status)?;
    let observed = io.read_u8(REG_DEVICE_STATUS)?;
    if observed == u8::MAX {
        return Err(VirtioBlkError::DeviceNotPresent);
    }
    if observed & status != status {
        return Err(VirtioBlkError::DeviceReset);
    }
    Ok(())
}

fn validate_msix_table(capability: PciMsixCapability, bar: PciBar) -> Result<(), VirtioBlkError> {
    if capability.table_size == 0 || bar.size == 0 || bar.size > MAX_MSIX_BAR_SIZE {
        return Err(VirtioBlkError::InvalidMsixTable);
    }
    let end = u64::from(capability.table_offset)
        .checked_add(MSIX_TABLE_ENTRY_BYTES)
        .ok_or(VirtioBlkError::AddressOverflow)?;
    if end > bar.size {
        return Err(VirtioBlkError::InvalidMsixTable);
    }
    Ok(())
}

unsafe fn map_msix_bar(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    bar: PciBar,
) -> Result<MmioRegion, VirtioBlkError> {
    if bar.size == 0 || bar.size > MAX_MSIX_BAR_SIZE {
        return Err(VirtioBlkError::InvalidMsixTable);
    }
    let physical_page = bar.physical_address & !(PAGE_SIZE - 1);
    let page_offset = bar.physical_address - physical_page;
    let mapped_length = page_offset
        .checked_add(bar.size)
        .and_then(|length| length.checked_add(PAGE_SIZE - 1))
        .map(|length| length & !(PAGE_SIZE - 1))
        .ok_or(VirtioBlkError::AddressOverflow)?;
    let candidates = [
        0xffff_ac00_0000_0000_u64,
        0xffff_ad00_0000_0000,
        0xffff_ae00_0000_0000,
        0xffff_af00_0000_0000,
    ];
    let mut chosen = None;
    'candidate: for base in candidates {
        let mut offset = 0;
        while offset < mapped_length {
            let address = VirtAddr::try_new(
                base.checked_add(offset)
                    .ok_or(VirtioBlkError::AddressOverflow)?,
            )
            .map_err(|_| VirtioBlkError::AddressOverflow)?;
            if page_table.translate_addr(address).is_some() {
                continue 'candidate;
            }
            offset += PAGE_SIZE;
        }
        chosen = Some(base);
        break;
    }
    let virtual_base = chosen.ok_or(VirtioBlkError::InvalidMsixTable)?;
    let flags = PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    let mut offset = 0;
    while offset < mapped_length {
        let physical = PhysAddr::try_new(
            physical_page
                .checked_add(offset)
                .ok_or(VirtioBlkError::AddressOverflow)?,
        )
        .map_err(|_| VirtioBlkError::AddressOverflow)?;
        let frame = PhysFrame::from_start_address(physical)
            .map_err(|_| VirtioBlkError::InvalidMsixTable)?;
        let virtual_address = VirtAddr::try_new(
            virtual_base
                .checked_add(offset)
                .ok_or(VirtioBlkError::AddressOverflow)?,
        )
        .map_err(|_| VirtioBlkError::AddressOverflow)?;
        let page = VirtPage::from_start_address(virtual_address)
            .map_err(|_| VirtioBlkError::InvalidMsixTable)?;
        unsafe { page_table.map_4k(page, frame, flags, frames)? };
        offset += PAGE_SIZE;
    }
    let address = virtual_base
        .checked_add(page_offset)
        .ok_or(VirtioBlkError::AddressOverflow)?;
    let pointer = usize::try_from(address).map_err(|_| VirtioBlkError::AddressOverflow)? as *mut u8;
    let length = usize::try_from(bar.size).map_err(|_| VirtioBlkError::AddressOverflow)?;
    unsafe { MmioRegion::from_raw_parts(pointer, length) }.ok_or(VirtioBlkError::InvalidMsixTable)
}

fn find_device(pci: &mut PciConfig) -> Result<Option<PciDevice>, VirtioBlkError> {
    for bus in 0_u16..=255 {
        for device in 0_u8..32 {
            for function in 0_u8..8 {
                let address = crate::pci::PciAddress::new(bus as u8, device, function)
                    .ok_or(VirtioBlkError::DeviceNotPresent)?;
                let Some(candidate) = pci.device(address)? else {
                    if function == 0 {
                        break;
                    }
                    continue;
                };
                if candidate.vendor_id == VIRTIO_VENDOR_ID
                    && candidate.device_id == VIRTIO_BLK_TRANSITIONAL_DEVICE_ID
                {
                    return Ok(Some(candidate));
                }
                if function == 0 && candidate.header_type & 0x80 == 0 {
                    break;
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_layout_matches_legacy_split_ring_rules() {
        let layout = QueueLayout::new(128).unwrap();
        assert_eq!(layout.descriptors, 0);
        assert_eq!(layout.available, 2048);
        assert_eq!(layout.used, 4096);
        assert_eq!(layout.bytes, 5126);
        assert_eq!(layout.pages, 2);
        assert_eq!(slot_count_for_queue(128), Ok(12));
    }

    #[test]
    fn queue_layout_rejects_sizes_without_one_full_slot() {
        assert_eq!(QueueLayout::new(8), Err(VirtioBlkError::InvalidQueueSize));
        assert_eq!(QueueLayout::new(7), Err(VirtioBlkError::InvalidQueueSize));
        assert_eq!(QueueLayout::new(512), Err(VirtioBlkError::InvalidQueueSize));
        assert_eq!(slot_count_for_queue(16), Ok(1));
        assert_eq!(slot_count_for_queue(32), Ok(3));
    }

    #[test]
    fn descriptor_plans_validate_operations_and_used_lengths() {
        let read = descriptor_plan(BlockOperation::Read, 4096, 8).unwrap();
        assert_eq!(read.data_count, 8);
        assert!(read.device_writes_data);
        assert_eq!(read.descriptor_count, 10);
        assert_eq!(read.expected_used_len, 4097);

        let write = descriptor_plan(BlockOperation::Write, 4096, 2).unwrap();
        assert!(!write.device_writes_data);
        assert_eq!(write.expected_used_len, 1);

        let flush = descriptor_plan(BlockOperation::Flush, 0, 0).unwrap();
        assert_eq!(flush.descriptor_count, 2);
        assert_eq!(flush.expected_used_len, 1);
        assert_eq!(
            descriptor_plan(BlockOperation::Read, 512, 9),
            Err(VirtioBlkError::TooManySegments)
        );
        assert_eq!(
            descriptor_plan(BlockOperation::Write, 513, 1),
            Err(VirtioBlkError::InvalidRequest)
        );
    }

    #[test]
    fn multi_sg_chain_stays_inside_its_fixed_descriptor_block() {
        let plan = descriptor_plan(BlockOperation::Read, 4096, 8).unwrap();
        assert_eq!(plan.chain_indices(0), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            plan.chain_indices(1),
            [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
        );
        let flush = descriptor_plan(BlockOperation::Flush, 0, 0).unwrap();
        assert_eq!(flush.chain_indices(2)[..2], [20, 29]);
    }

    #[test]
    fn head_mapping_accepts_out_of_order_used_completions() {
        let mut slots = [RequestSlot::<u64>::empty(); MAX_SLOTS];
        let mut heads = [INVALID_SLOT; MAX_QUEUE_SIZE as usize];
        for slot in 0..2 {
            heads[usize::from(descriptor_head(slot))] = slot as u8;
        }
        slots[0]
            .start(Some(11), false, BlockOperation::Read, 512, 513)
            .unwrap();
        slots[1]
            .start(Some(22), false, BlockOperation::Write, 512, 1)
            .unwrap();

        assert_eq!(mapped_slot_for_used(&heads, &slots, 2, 10), Ok(1));
        slots[1].release();
        assert_eq!(mapped_slot_for_used(&heads, &slots, 2, 0), Ok(0));
        slots[0].release();
        assert_eq!(
            mapped_slot_for_used(&heads, &slots, 2, 10),
            Err(VirtioBlkError::InvalidUsedRing)
        );
    }

    #[test]
    fn used_index_distance_handles_wrap_and_rejects_impossible_jumps() {
        assert_eq!(used_index_distance(u16::MAX - 1, 1, 128), Ok(3));
        assert_eq!(used_index_distance(42, 42, 128), Ok(0));
        assert_eq!(
            used_index_distance(0, 129, 128),
            Err(VirtioBlkError::InvalidUsedRing)
        );
    }

    #[test]
    fn cancellation_is_exact_and_does_not_release_ownership() {
        let mut slot = RequestSlot::<u64>::empty();
        slot.start(Some(7), false, BlockOperation::Read, 512, 513)
            .unwrap();
        assert!(!slot.request_cancel(8));
        assert!(slot.request_cancel(7));
        assert_eq!(slot.state, SlotState::CancelPending);
        assert_eq!(slot.token, Some(7));
        let first_generation = slot.generation;
        slot.release();
        slot.start(Some(9), false, BlockOperation::Read, 512, 513)
            .unwrap();
        assert!(slot.generation > first_generation);
        assert!(!slot.request_cancel(7));
        assert_eq!(slot.token, Some(9));
    }

    #[test]
    fn reset_releases_slots_only_after_status_zero_is_observed() {
        let mut slots = [RequestSlot::<u64>::empty(); MAX_SLOTS];
        slots[0]
            .start(Some(1), false, BlockOperation::Read, 512, 513)
            .unwrap();
        assert!(!release_slots_after_verified_reset(
            &mut slots,
            1,
            READY_STATUS
        ));
        assert_eq!(slots[0].state, SlotState::InFlight);
        assert!(release_slots_after_verified_reset(&mut slots, 1, 0));
        assert_eq!(slots[0].state, SlotState::Free);
    }

    #[test]
    fn transitional_configuration_base_shifts_for_msix() {
        assert_eq!(transitional_config_base(false), 0x14);
        assert_eq!(transitional_config_base(true), 0x18);
    }

    #[test]
    fn transfer_range_accepts_edge_and_rejects_invalid_ranges() {
        assert_eq!(
            transfer_range(8, 1024, 10),
            Ok(TransferRange {
                first_sector: 8,
                sector_count: 2,
            })
        );
        assert_eq!(
            transfer_range(0, SECTOR_SIZE - 1, 10),
            Err(VirtioBlkError::Misaligned)
        );
        assert_eq!(
            transfer_range(9, 2 * SECTOR_SIZE, 10),
            Err(VirtioBlkError::OutOfBounds)
        );
        assert_eq!(
            transfer_range(u64::MAX, SECTOR_SIZE, u64::MAX),
            Err(VirtioBlkError::AddressOverflow)
        );
    }

    #[test]
    fn io_bar_validation_masks_flags_and_checks_port_space() {
        assert_eq!(io_bar_base(0xc001), Ok(0xc000));
        assert_eq!(io_bar_base(0xc000), Err(VirtioBlkError::InvalidIoBar));
        assert_eq!(io_bar_base(1), Err(VirtioBlkError::InvalidIoBar));
        assert_eq!(io_bar_base(0x1_0001), Err(VirtioBlkError::InvalidIoBar));
        assert_eq!(io_bar_base(0xfff1), Err(VirtioBlkError::InvalidIoBar));
    }

    #[test]
    fn device_status_reports_reset_failure_and_disappearance() {
        assert_eq!(
            validate_operational_status(READY_STATUS, READY_STATUS),
            Ok(())
        );
        assert_eq!(
            validate_operational_status(0, READY_STATUS),
            Err(VirtioBlkError::DeviceReset)
        );
        assert_eq!(
            validate_operational_status(READY_STATUS | STATUS_DEVICE_NEEDS_RESET, READY_STATUS),
            Err(VirtioBlkError::DeviceNeedsReset)
        );
        assert_eq!(
            validate_operational_status(READY_STATUS | STATUS_FAILED, READY_STATUS),
            Err(VirtioBlkError::DeviceFailed)
        );
        assert_eq!(
            validate_operational_status(u8::MAX, READY_STATUS),
            Err(VirtioBlkError::DeviceNotPresent)
        );
    }
}
