//! Bounded-polling virtio-blk support for the transitional legacy PCI interface.
//!
//! This driver targets QEMU `virtio-blk-pci,disable-modern=on`. It deliberately
//! negotiates no ring extensions, submits one request at a time, and never
//! reuses DMA memory after a timeout or malformed device response.

use core::{
    hint::spin_loop,
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

use crate::{
    block::{BlockDevice, SECTOR_SIZE},
    io::{IoError, PortRegion},
    memory::{FrameAllocatorError, UsableFrameAllocator, VirtAddr, PAGE_SIZE},
    pci::{PciConfig, PciDevice, PciError},
};

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_BLK_TRANSITIONAL_DEVICE_ID: u16 = 0x1001;
const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
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
const REG_CONFIG_CAPACITY_LOW: u16 = 0x14;
const REG_CONFIG_CAPACITY_HIGH: u16 = 0x18;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
const STATUS_FAILED: u8 = 128;

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
const DESC_HEADER: u16 = 0;
const DESC_DATA: u16 = 1;
const DESC_STATUS: u16 = 2;
const DESCRIPTORS_USED: u16 = 3;
const DESCRIPTOR_BYTES: usize = 16;
const USED_ELEMENT_BYTES: usize = 8;

const MAX_QUEUE_SIZE: u16 = 256;
const POLL_LIMIT: usize = 1_000_000;
const QUEUE_INDEX: u16 = 0;
const REQUEST_HEADER_OFFSET: usize = 0;
const REQUEST_STATUS_OFFSET: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioBlkError {
    Pci(PciError),
    Io(IoError),
    FrameAllocator(FrameAllocatorError),
    DeviceNotPresent,
    InvalidIoBar,
    InvalidQueueSize,
    InvalidQueueLayout,
    NonContiguousDma,
    UnsupportedDmaAddress,
    AddressOverflow,
    OutOfFrames,
    FeatureNegotiationFailed,
    ReadOnly,
    Misaligned,
    OutOfBounds,
    TimedOut,
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

impl From<FrameAllocatorError> for VirtioBlkError {
    fn from(value: FrameAllocatorError) -> Self {
        Self::FrameAllocator(value)
    }
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
        if size < DESCRIPTORS_USED || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
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
    ) -> Result<Self, VirtioBlkError> {
        if pages == 0 {
            return Err(VirtioBlkError::AddressOverflow);
        }
        let mut physical = None;
        let mut expected = 0_u64;
        for index in 0..pages {
            let frame = frames
                .allocate_frame()?
                .ok_or(VirtioBlkError::OutOfFrames)?;
            let address = frame.start_address().as_u64();
            if index == 0 {
                physical = Some(address);
                expected = address;
            }
            if address != expected {
                return Err(VirtioBlkError::NonContiguousDma);
            }
            expected = expected
                .checked_add(PAGE_SIZE)
                .ok_or(VirtioBlkError::AddressOverflow)?;
        }
        let physical = physical.ok_or(VirtioBlkError::OutOfFrames)?;
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
        // SAFETY: The caller guarantees that the HHDM covers allocator frames.
        // These freshly allocated, physically contiguous frames are exclusively
        // owned by this DMA region and remain allocated for the driver's life.
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
        // SAFETY: The checked range is within this exclusively owned allocation.
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

/// One exclusively owned transitional virtio-blk PCI function.
pub struct VirtioBlk {
    io: PortRegion,
    queue: DmaRegion,
    request: DmaRegion,
    data: DmaRegion,
    layout: QueueLayout,
    queue_size: u16,
    capacity_sectors: u64,
    read_only: bool,
    flush_supported: bool,
    available_index: u16,
    used_index: u16,
    terminal_error: Option<VirtioBlkError>,
}

impl VirtioBlk {
    /// Discovers and initializes the first QEMU transitional virtio-blk device.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own PCI configuration mechanism #1, the
    /// discovered function and its BAR0 I/O ports. It must guarantee that the
    /// supplied HHDM offset maps every allocated frame coherently and for the
    /// lifetime of this object. No other driver may use the device or frames.
    pub unsafe fn initialize(
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<Self, VirtioBlkError> {
        let mut pci = unsafe { PciConfig::new()? };
        let device = find_device(&mut pci)?.ok_or(VirtioBlkError::DeviceNotPresent)?;
        let bar = pci.read_u32(device.address, PCI_BAR0)?;
        let base = io_bar_base(bar)?;
        let command = pci.read_u16(device.address, 0x04)?;
        pci.write_u16(
            device.address,
            0x04,
            command | PCI_COMMAND_IO_SPACE | PCI_COMMAND_BUS_MASTER,
        )?;
        let identity = pci.read_u32(device.address, 0x00)?;
        if identity as u16 != VIRTIO_VENDOR_ID
            || (identity >> 16) as u16 != VIRTIO_BLK_TRANSITIONAL_DEVICE_ID
        {
            return Err(VirtioBlkError::DeviceNotPresent);
        }
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
        let queue = DmaRegion::allocate_contiguous(frames, hhdm_offset, layout.pages)?;
        if queue.physical & (PAGE_SIZE - 1) != 0 || queue.physical >> 12 > u64::from(u32::MAX) {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::UnsupportedDmaAddress);
        }
        let request = DmaRegion::allocate_contiguous(frames, hhdm_offset, 1)?;
        let data = DmaRegion::allocate_contiguous(frames, hhdm_offset, 1)?;
        io.write_u32(REG_QUEUE_PFN, (queue.physical >> 12) as u32)?;
        if io.read_u32(REG_QUEUE_PFN)? != (queue.physical >> 12) as u32 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::InvalidQueueLayout);
        }

        let capacity_low = io.read_u32(REG_CONFIG_CAPACITY_LOW)?;
        let capacity_high = io.read_u32(REG_CONFIG_CAPACITY_HIGH)?;
        let capacity_sectors = u64::from(capacity_low) | (u64::from(capacity_high) << 32);
        let used_index = queue.read_u16(layout.used + 2)?;
        let available_index = queue.read_u16(layout.available + 2)?;
        if used_index != 0 || available_index != 0 {
            let _ = io.write_u8(REG_DEVICE_STATUS, feature_status | STATUS_FAILED);
            return Err(VirtioBlkError::InvalidUsedRing);
        }

        let ready_status = feature_status | STATUS_DRIVER_OK;
        write_status(&mut io, ready_status)?;
        validate_operational_status(io.read_u8(REG_DEVICE_STATUS)?, ready_status)?;

        Ok(Self {
            io,
            queue,
            request,
            data,
            layout,
            queue_size,
            capacity_sectors,
            read_only: host_features & VIRTIO_BLK_F_RO != 0,
            flush_supported: negotiated & VIRTIO_BLK_F_FLUSH != 0,
            available_index,
            used_index,
            terminal_error: None,
        })
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    pub const fn capacity_bytes(&self) -> Option<u64> {
        self.capacity_sectors.checked_mul(SECTOR_SIZE as u64)
    }

    pub fn read_sectors(
        &mut self,
        first_sector: u64,
        buffer: &mut [u8],
    ) -> Result<(), VirtioBlkError> {
        self.ensure_live()?;
        let range = transfer_range(first_sector, buffer.len(), self.capacity_sectors)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks_mut(PAGE_SIZE as usize) {
            self.request_data(VIRTIO_BLK_T_IN, sector, chunk, true)?;
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    pub fn write_sectors(
        &mut self,
        first_sector: u64,
        buffer: &[u8],
    ) -> Result<(), VirtioBlkError> {
        self.ensure_live()?;
        if self.read_only && !buffer.is_empty() {
            return Err(VirtioBlkError::ReadOnly);
        }
        let range = transfer_range(first_sector, buffer.len(), self.capacity_sectors)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks(PAGE_SIZE as usize) {
            self.data.copy_from(0, chunk)?;
            self.submit(VIRTIO_BLK_T_OUT, sector, chunk.len(), false)?;
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), VirtioBlkError> {
        self.ensure_live()?;
        if !self.flush_supported {
            return Ok(());
        }
        self.submit(VIRTIO_BLK_T_FLUSH, 0, 0, false)
    }

    fn request_data(
        &mut self,
        request_type: u32,
        sector: u64,
        buffer: &mut [u8],
        device_writes: bool,
    ) -> Result<(), VirtioBlkError> {
        self.submit(request_type, sector, buffer.len(), device_writes)?;
        if device_writes {
            self.data.copy_to(0, buffer)?;
        }
        Ok(())
    }

    fn submit(
        &mut self,
        request_type: u32,
        sector: u64,
        data_len: usize,
        device_writes: bool,
    ) -> Result<(), VirtioBlkError> {
        self.ensure_live()?;
        if data_len > PAGE_SIZE as usize || data_len % SECTOR_SIZE != 0 {
            return Err(VirtioBlkError::Misaligned);
        }
        let has_data = data_len != 0;
        let writable_len = if has_data && device_writes {
            data_len
                .checked_add(1)
                .ok_or(VirtioBlkError::AddressOverflow)?
        } else {
            1
        };

        self.request
            .write_u32(REQUEST_HEADER_OFFSET, request_type)?;
        self.request.write_u32(REQUEST_HEADER_OFFSET + 4, 0)?;
        self.request.write_u64(REQUEST_HEADER_OFFSET + 8, sector)?;
        self.request.write_u8(REQUEST_STATUS_OFFSET, 0xff)?;

        let header_next = if has_data { DESC_DATA } else { DESC_STATUS };
        self.write_descriptor(
            DESC_HEADER,
            self.request.physical + REQUEST_HEADER_OFFSET as u64,
            16,
            DESC_F_NEXT,
            header_next,
        )?;
        if has_data {
            self.write_descriptor(
                DESC_DATA,
                self.data.physical,
                u32::try_from(data_len).map_err(|_| VirtioBlkError::AddressOverflow)?,
                DESC_F_NEXT | if device_writes { DESC_F_WRITE } else { 0 },
                DESC_STATUS,
            )?;
        } else {
            self.clear_descriptor(DESC_DATA)?;
        }
        self.write_descriptor(
            DESC_STATUS,
            self.request.physical + REQUEST_STATUS_OFFSET as u64,
            1,
            DESC_F_WRITE,
            0,
        )?;
        validate_descriptor_plan(has_data, device_writes, data_len)?;

        let slot = usize::from(self.available_index % self.queue_size);
        self.queue
            .write_u16(self.layout.available + 4 + slot * 2, DESC_HEADER)?;
        compiler_fence(Ordering::Release);
        self.available_index = self.available_index.wrapping_add(1);
        self.queue
            .write_u16(self.layout.available + 2, self.available_index)?;
        compiler_fence(Ordering::Release);
        self.io.write_u16(REG_QUEUE_NOTIFY, QUEUE_INDEX)?;

        let expected_used = self.used_index.wrapping_add(1);
        for _ in 0..POLL_LIMIT {
            let status = self
                .io
                .read_u8(REG_DEVICE_STATUS)
                .map_err(|error| self.poison(error.into()))?;
            if let Err(error) = validate_operational_status(
                status,
                STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            ) {
                return Err(self.poison(error));
            }
            compiler_fence(Ordering::Acquire);
            let observed = self
                .queue
                .read_u16(self.layout.used + 2)
                .map_err(|error| self.poison(error))?;
            if observed == self.used_index {
                spin_loop();
                continue;
            }
            if observed != expected_used {
                return Err(self.poison(VirtioBlkError::InvalidUsedRing));
            }
            compiler_fence(Ordering::Acquire);
            let used_slot = usize::from(self.used_index % self.queue_size);
            let element = self.layout.used + 4 + used_slot * USED_ELEMENT_BYTES;
            let id = self
                .queue
                .read_u32(element)
                .map_err(|error| self.poison(error))?;
            let length = self
                .queue
                .read_u32(element + 4)
                .map_err(|error| self.poison(error))?;
            validate_used_element(id, length, writable_len).map_err(|error| self.poison(error))?;
            self.used_index = expected_used;
            let request_status = self
                .request
                .read_u8(REQUEST_STATUS_OFFSET)
                .map_err(|error| self.poison(error))?;
            return match request_status {
                VIRTIO_BLK_S_OK => Ok(()),
                VIRTIO_BLK_S_IOERR => Err(VirtioBlkError::DeviceIo),
                VIRTIO_BLK_S_UNSUPP => Err(VirtioBlkError::UnsupportedRequest),
                value => Err(self.poison(VirtioBlkError::InvalidDeviceStatus(value))),
            };
        }
        Err(self.poison(VirtioBlkError::TimedOut))
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

    fn clear_descriptor(&self, index: u16) -> Result<(), VirtioBlkError> {
        self.write_descriptor(index, 0, 0, 0, 0)
    }

    fn ensure_live(&self) -> Result<(), VirtioBlkError> {
        match self.terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn poison(&mut self, error: VirtioBlkError) -> VirtioBlkError {
        if self.terminal_error.is_none() {
            self.terminal_error = Some(error);
            if let Ok(status) = self.io.read_u8(REG_DEVICE_STATUS) {
                if status != u8::MAX {
                    let _ = self.io.write_u8(REG_DEVICE_STATUS, status | STATUS_FAILED);
                }
            }
        }
        error
    }
}

impl Drop for VirtioBlk {
    fn drop(&mut self) {
        // Reset tells the device to stop touching queue memory. Allocator frames
        // are monotonic and intentionally remain unavailable after this object.
        let _ = self.io.write_u8(REG_DEVICE_STATUS, 0);
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

fn validate_descriptor_plan(
    has_data: bool,
    device_writes: bool,
    data_len: usize,
) -> Result<(), VirtioBlkError> {
    if has_data != (data_len != 0)
        || data_len > PAGE_SIZE as usize
        || data_len % SECTOR_SIZE != 0
        || (!has_data && device_writes)
    {
        return Err(VirtioBlkError::InvalidDescriptorChain);
    }
    Ok(())
}

fn validate_used_element(id: u32, length: u32, writable_len: usize) -> Result<(), VirtioBlkError> {
    if id != u32::from(DESC_HEADER)
        || usize::try_from(length).map_err(|_| VirtioBlkError::InvalidUsedRing)? != writable_len
    {
        return Err(VirtioBlkError::InvalidUsedRing);
    }
    Ok(())
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
    }

    #[test]
    fn queue_layout_rejects_unsafe_sizes() {
        assert_eq!(QueueLayout::new(2), Err(VirtioBlkError::InvalidQueueSize));
        assert_eq!(QueueLayout::new(7), Err(VirtioBlkError::InvalidQueueSize));
        assert_eq!(QueueLayout::new(512), Err(VirtioBlkError::InvalidQueueSize));
    }

    #[test]
    fn transfer_range_accepts_edge_and_empty_requests() {
        assert_eq!(
            transfer_range(8, 1024, 10),
            Ok(TransferRange {
                first_sector: 8,
                sector_count: 2,
            })
        );
        assert_eq!(
            transfer_range(10, 0, 10),
            Ok(TransferRange {
                first_sector: 10,
                sector_count: 0,
            })
        );
    }

    #[test]
    fn transfer_range_rejects_alignment_overflow_and_bounds() {
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
        let ready = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
        assert_eq!(validate_operational_status(ready, ready), Ok(()));
        assert_eq!(
            validate_operational_status(0, ready),
            Err(VirtioBlkError::DeviceReset)
        );
        assert_eq!(
            validate_operational_status(ready | STATUS_DEVICE_NEEDS_RESET, ready),
            Err(VirtioBlkError::DeviceNeedsReset)
        );
        assert_eq!(
            validate_operational_status(ready | STATUS_FAILED, ready),
            Err(VirtioBlkError::DeviceFailed)
        );
        assert_eq!(
            validate_operational_status(u8::MAX, ready),
            Err(VirtioBlkError::DeviceNotPresent)
        );
    }

    #[test]
    fn used_element_must_match_head_and_writable_length() {
        assert_eq!(validate_used_element(0, 513, 513), Ok(()));
        assert_eq!(
            validate_used_element(1, 513, 513),
            Err(VirtioBlkError::InvalidUsedRing)
        );
        assert_eq!(
            validate_used_element(0, 512, 513),
            Err(VirtioBlkError::InvalidUsedRing)
        );
    }

    #[test]
    fn descriptor_plan_is_bounded_and_sector_aligned() {
        assert_eq!(validate_descriptor_plan(true, true, 4096), Ok(()));
        assert_eq!(validate_descriptor_plan(false, false, 0), Ok(()));
        assert_eq!(
            validate_descriptor_plan(true, false, 513),
            Err(VirtioBlkError::InvalidDescriptorChain)
        );
        assert_eq!(
            validate_descriptor_plan(false, true, 0),
            Err(VirtioBlkError::InvalidDescriptorChain)
        );
    }
}
