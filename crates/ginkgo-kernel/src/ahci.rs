//! Bounded-polling AHCI 1.0 SATA block-device support.
//!
//! The driver deliberately owns one controller port, uses command slot zero, and
//! transfers at most one 4 KiB DMA page per command. Interrupts remain disabled;
//! every hardware wait has a fixed iteration limit.

use core::{
    hint::spin_loop,
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

use crate::{
    block::{BlockDevice, SECTOR_SIZE},
    io::{IoError, MmioRegion},
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageTableFlags},
    pci::{PciBar, PciConfig, PciError},
};

const AHCI_CLASS: u8 = 0x01;
const AHCI_SUBCLASS: u8 = 0x06;
const AHCI_INTERFACE: u8 = 0x01;
const AHCI_BAR: u8 = 5;
const MIN_ABAR_SIZE: u64 = 0x180;
const MAX_ABAR_SIZE: u64 = 16 * 1024 * 1024;
const POLL_LIMIT: usize = 1_000_000;

const REG_CAP: usize = 0x00;
const REG_GHC: usize = 0x04;
const REG_IS: usize = 0x08;
const REG_PI: usize = 0x0c;
const REG_VS: usize = 0x10;
const REG_CAP2: usize = 0x24;
const REG_BOHC: usize = 0x28;
const GHC_AE: u32 = 1 << 31;
const CAP_S64A: u32 = 1 << 31;
const CAP2_BOH: u32 = 1;
const BOHC_BOS: u32 = 1;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_OOC: u32 = 1 << 3;
const BOHC_BB: u32 = 1 << 4;

const PORT_BASE: usize = 0x100;
const PORT_STRIDE: usize = 0x80;
const PORT_CLB: usize = 0x00;
const PORT_FB: usize = 0x08;
const PORT_IS: usize = 0x10;
const PORT_IE: usize = 0x14;
const PORT_CMD: usize = 0x18;
const PORT_TFD: usize = 0x20;
const PORT_SIG: usize = 0x24;
const PORT_SSTS: usize = 0x28;
const PORT_SERR: usize = 0x30;
const PORT_SACT: usize = 0x34;
const PORT_CI: usize = 0x38;
const PORT_CMD_ST: u32 = 1;
const PORT_CMD_FRE: u32 = 1 << 4;
const PORT_CMD_FR: u32 = 1 << 14;
const PORT_CMD_CR: u32 = 1 << 15;
const PORT_IS_TFES: u32 = 1 << 30;
const PORT_IS_ERROR_MASK: u32 = 0x7d00_0000;
const SATA_SIGNATURE: u32 = 0x0000_0101;
const SSTS_DET_PRESENT: u32 = 3;
const SSTS_IPM_ACTIVE: u32 = 1;

const ATA_STATUS_ERR: u8 = 1;
const ATA_STATUS_DRQ: u8 = 1 << 3;
const ATA_STATUS_DF: u8 = 1 << 5;
const ATA_STATUS_BSY: u8 = 1 << 7;
const ATA_IDENTIFY_DEVICE: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const FIS_TYPE_REG_H2D: u8 = 0x27;
const FIS_COMMAND: u8 = 1 << 7;
const LBA_MODE: u8 = 1 << 6;

const COMMAND_TABLE_PRDT: usize = 128;
const COMMAND_SLOT: u32 = 1;
const MAX_TRANSFER_BYTES: usize = PAGE_SIZE as usize;
const MAX_TRANSFER_SECTORS: u16 = (MAX_TRANSFER_BYTES / SECTOR_SIZE) as u16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciError {
    Pci(PciError),
    Io(IoError),
    Mapping(MapError),
    FrameAllocator(FrameAllocatorError),
    ControllerNotFound,
    InvalidBar,
    UnsupportedAhciVersion,
    BiosHandoffTimedOut,
    NoSataPort,
    EngineTimedOut,
    CommandTimedOut,
    PortRemoved,
    UnsupportedDevice,
    InvalidCapacity,
    UnsupportedDmaAddress,
    AddressOverflow,
    OutOfFrames,
    Misaligned,
    OutOfBounds,
    InvalidTransfer,
    TaskFileError { status: u8, error: u8 },
    CommandSlotBusy,
    InterfaceError(u32),
    DeviceUnavailable,
}

impl From<PciError> for AhciError {
    fn from(value: PciError) -> Self {
        Self::Pci(value)
    }
}

impl From<IoError> for AhciError {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}

impl From<MapError> for AhciError {
    fn from(value: MapError) -> Self {
        Self::Mapping(value)
    }
}

impl From<FrameAllocatorError> for AhciError {
    fn from(value: FrameAllocatorError) -> Self {
        Self::FrameAllocator(value)
    }
}

struct DmaPage {
    physical: u64,
    pointer: *mut u8,
}

impl DmaPage {
    fn allocate(
        frames: &mut UsableFrameAllocator<'_>,
        hhdm: u64,
        supports_64_bit: bool,
    ) -> Result<Self, AhciError> {
        let frame = if supports_64_bit {
            frames.allocate_frame()?
        } else {
            frames.allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)?
        }
        .ok_or(AhciError::OutOfFrames)?;
        let physical = frame.start_address().as_u64();
        let virtual_address = hhdm
            .checked_add(physical)
            .ok_or(AhciError::AddressOverflow)?;
        VirtAddr::try_new(virtual_address).map_err(|_| AhciError::AddressOverflow)?;
        let pointer =
            usize::try_from(virtual_address).map_err(|_| AhciError::AddressOverflow)? as *mut u8;
        // SAFETY: This newly allocated frame is exclusively owned and the
        // initialization contract guarantees that the HHDM covers it.
        unsafe { ptr::write_bytes(pointer, 0, PAGE_SIZE as usize) };
        Ok(Self { physical, pointer })
    }

    fn clear(&self) {
        // SAFETY: Callers clear pages only while no command is outstanding.
        unsafe { ptr::write_bytes(self.pointer, 0, PAGE_SIZE as usize) };
    }

    fn check(&self, offset: usize, length: usize, alignment: usize) -> Result<*mut u8, AhciError> {
        if alignment == 0 || offset % alignment != 0 {
            return Err(AhciError::AddressOverflow);
        }
        offset
            .checked_add(length)
            .filter(|end| *end <= PAGE_SIZE as usize)
            .ok_or(AhciError::AddressOverflow)?;
        // SAFETY: The complete range was checked against this page.
        Ok(unsafe { self.pointer.add(offset) })
    }

    fn write_u32(&self, offset: usize, value: u32) -> Result<(), AhciError> {
        let pointer = self.check(offset, 4, 4)?.cast::<u32>();
        // SAFETY: Bounds, alignment, and exclusive ownership were checked.
        unsafe { ptr::write_volatile(pointer, value) };
        Ok(())
    }

    fn read_u16(&self, word: usize) -> Result<u16, AhciError> {
        let offset = word.checked_mul(2).ok_or(AhciError::AddressOverflow)?;
        let pointer = self.check(offset, 2, 2)?.cast::<u16>();
        // SAFETY: Bounds and alignment were checked; command completion precedes this read.
        Ok(unsafe { ptr::read_volatile(pointer) })
    }

    fn copy_from(&self, source: &[u8]) -> Result<(), AhciError> {
        self.check(0, source.len(), 1)?;
        // SAFETY: The destination range is in this exclusively owned DMA page.
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), self.pointer, source.len()) };
        Ok(())
    }

    fn copy_to(&self, destination: &mut [u8]) -> Result<(), AhciError> {
        self.check(0, destination.len(), 1)?;
        // SAFETY: The source range is in this page and command completion has acquired DMA writes.
        unsafe {
            ptr::copy_nonoverlapping(self.pointer, destination.as_mut_ptr(), destination.len())
        };
        Ok(())
    }
}

/// An exclusively owned AHCI controller port containing one 512-byte-sector SATA disk.
pub struct AhciDisk {
    mmio: MmioRegion,
    port: usize,
    command_list: DmaPage,
    received_fis: DmaPage,
    command_table: DmaPage,
    data: DmaPage,
    capacity: u64,
    flush_supported: bool,
    unavailable: bool,
}

impl AhciDisk {
    /// Discovers the first PCI AHCI controller and claims its first active SATA port.
    ///
    /// # Safety
    ///
    /// The caller must provide exclusive ownership of PCI configuration mechanism
    /// #1, the selected controller and fixed MMIO mapping, the active page tables,
    /// and the allocator. The active page table's HHDM must coherently map every
    /// frame returned by `frames`. No firmware, interrupt handler, or other driver
    /// may access the controller after BIOS/OS ownership transfer completes.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, AhciError> {
        let mut pci = unsafe { PciConfig::new()? };
        let device = pci
            .find_first(AHCI_CLASS, AHCI_SUBCLASS, Some(AHCI_INTERFACE))?
            .ok_or(AhciError::ControllerNotFound)?;
        let bar = pci.probe_bar(device, AHCI_BAR)?;
        pci.enable_memory_and_bus_mastering(device)?;
        let mut mmio = unsafe { map_abar(page_table, frames, bar)? };

        let version = mmio.read_u32(REG_VS)?;
        if version >> 16 == 0 {
            return Err(AhciError::UnsupportedAhciVersion);
        }
        bios_handoff(&mut mmio)?;
        let ghc = mmio.read_u32(REG_GHC)?;
        mmio.write_u32(REG_GHC, ghc | GHC_AE)?;

        let capabilities = mmio.read_u32(REG_CAP)?;
        let port_count = usize::from((capabilities & 0x1f) as u8) + 1;
        let implemented = mmio.read_u32(REG_PI)?;
        let port = first_active_sata_port(&mut mmio, port_count, implemented)?;
        let port_base = port_offset(port)?;
        if port_base
            .checked_add(PORT_STRIDE)
            .filter(|end| *end <= mmio.len())
            .is_none()
        {
            return Err(AhciError::InvalidBar);
        }

        stop_engine(&mut mmio, port_base)?;
        mmio.write_u32(port_base + PORT_IE, 0)?;
        mmio.write_u32(port_base + PORT_IS, u32::MAX)?;
        mmio.write_u32(port_base + PORT_SERR, u32::MAX)?;

        let supports_64_bit = capabilities & CAP_S64A != 0;
        let hhdm = page_table.hhdm_offset().as_u64();
        let command_list = DmaPage::allocate(frames, hhdm, supports_64_bit)?;
        let received_fis = DmaPage::allocate(frames, hhdm, supports_64_bit)?;
        let command_table = DmaPage::allocate(frames, hhdm, supports_64_bit)?;
        let data = DmaPage::allocate(frames, hhdm, supports_64_bit)?;

        program_dma_base(&mut mmio, port_base, PORT_CLB, command_list.physical)?;
        program_dma_base(&mut mmio, port_base, PORT_FB, received_fis.physical)?;
        compiler_fence(Ordering::Release);
        start_engine(&mut mmio, port_base)?;

        let mut disk = Self {
            mmio,
            port,
            command_list,
            received_fis,
            command_table,
            data,
            capacity: 0,
            flush_supported: false,
            unavailable: false,
        };
        disk.identify()?;
        Ok(disk)
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    pub const fn flush_supported(&self) -> bool {
        self.flush_supported
    }

    pub fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), AhciError> {
        let range = transfer_range(lba, buffer.len(), self.capacity)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks_mut(MAX_TRANSFER_BYTES) {
            let count =
                u16::try_from(chunk.len() / SECTOR_SIZE).map_err(|_| AhciError::InvalidTransfer)?;
            self.issue(ATA_READ_DMA_EXT, sector, count, chunk.len(), false)?;
            self.data.copy_to(chunk)?;
            sector = sector
                .checked_add(u64::from(count))
                .ok_or(AhciError::AddressOverflow)?;
        }
        Ok(())
    }

    pub fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), AhciError> {
        let range = transfer_range(lba, buffer.len(), self.capacity)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks(MAX_TRANSFER_BYTES) {
            let count =
                u16::try_from(chunk.len() / SECTOR_SIZE).map_err(|_| AhciError::InvalidTransfer)?;
            self.data.copy_from(chunk)?;
            compiler_fence(Ordering::Release);
            self.issue(ATA_WRITE_DMA_EXT, sector, count, chunk.len(), true)?;
            sector = sector
                .checked_add(u64::from(count))
                .ok_or(AhciError::AddressOverflow)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), AhciError> {
        if self.unavailable {
            return Err(AhciError::DeviceUnavailable);
        }
        if self.flush_supported {
            self.issue(ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)?;
        }
        Ok(())
    }

    fn identify(&mut self) -> Result<(), AhciError> {
        self.issue(ATA_IDENTIFY_DEVICE, 0, 0, SECTOR_SIZE, false)?;
        let command_sets = self.data.read_u16(83)?;
        if command_sets & (1 << 10) == 0 {
            return Err(AhciError::UnsupportedDevice);
        }
        let mut capacity = 0_u64;
        for word in (100..=103).rev() {
            capacity = (capacity << 16) | u64::from(self.data.read_u16(word)?);
        }
        // ATA LBA48 task-file fields contain 48 bits, so larger/reserved identify
        // values are rejected rather than silently truncated.
        if capacity == 0 || capacity > (1_u64 << 48) {
            return Err(AhciError::InvalidCapacity);
        }
        self.capacity = capacity;
        self.flush_supported = command_sets & (1 << 13) != 0;
        Ok(())
    }

    fn issue(
        &mut self,
        command: u8,
        lba: u64,
        sectors: u16,
        byte_len: usize,
        write: bool,
    ) -> Result<(), AhciError> {
        if self.unavailable {
            return Err(AhciError::DeviceUnavailable);
        }
        if lba >= (1_u64 << 48) || sectors > MAX_TRANSFER_SECTORS {
            return Err(AhciError::InvalidTransfer);
        }
        let expected = usize::from(sectors)
            .checked_mul(SECTOR_SIZE)
            .ok_or(AhciError::AddressOverflow)?;
        if byte_len != 0 && byte_len != expected && command != ATA_IDENTIFY_DEVICE {
            return Err(AhciError::InvalidTransfer);
        }
        if command == ATA_IDENTIFY_DEVICE && byte_len != SECTOR_SIZE {
            return Err(AhciError::InvalidTransfer);
        }

        let base = port_offset(self.port)?;
        if let Err(error) = validate_port(&mut self.mmio, base) {
            self.unavailable = true;
            return Err(error);
        }
        wait_tfd_idle(&mut self.mmio, base).map_err(|error| {
            if matches!(error, AhciError::CommandTimedOut | AhciError::PortRemoved) {
                self.unavailable = true;
            }
            error
        })?;
        if self.mmio.read_u32(base + PORT_CI)? & COMMAND_SLOT != 0
            || self.mmio.read_u32(base + PORT_SACT)? & COMMAND_SLOT != 0
        {
            self.unavailable = true;
            return Err(AhciError::CommandSlotBusy);
        }

        self.command_list.clear();
        self.command_table.clear();
        let fis = command_fis(command, lba, sectors);
        // SAFETY: The command table is exclusively owned and no command is active.
        unsafe { ptr::copy_nonoverlapping(fis.as_ptr(), self.command_table.pointer, fis.len()) };

        let prdt_count = if byte_len == 0 { 0_u16 } else { 1_u16 };
        if byte_len != 0 {
            let dbc = prdt_dbc(byte_len)?;
            self.command_table
                .write_u32(COMMAND_TABLE_PRDT, self.data.physical as u32)?;
            self.command_table
                .write_u32(COMMAND_TABLE_PRDT + 4, (self.data.physical >> 32) as u32)?;
            self.command_table.write_u32(COMMAND_TABLE_PRDT + 8, 0)?;
            self.command_table.write_u32(COMMAND_TABLE_PRDT + 12, dbc)?;
        }
        let mut header = 5_u32 | (u32::from(prdt_count) << 16);
        if write {
            header |= 1 << 6;
        }
        self.command_list.write_u32(0, header)?;
        self.command_list.write_u32(4, 0)?;
        self.command_list
            .write_u32(8, self.command_table.physical as u32)?;
        self.command_list
            .write_u32(12, (self.command_table.physical >> 32) as u32)?;

        self.mmio.write_u32(base + PORT_IS, u32::MAX)?;
        self.mmio.write_u32(base + PORT_SERR, u32::MAX)?;
        compiler_fence(Ordering::Release);
        self.mmio.write_u32(base + PORT_CI, COMMAND_SLOT)?;

        for _ in 0..POLL_LIMIT {
            if let Err(error) = validate_port(&mut self.mmio, base) {
                self.unavailable = true;
                return Err(error);
            }
            let interrupt = self.mmio.read_u32(base + PORT_IS)?;
            if interrupt & PORT_IS_TFES != 0 {
                let error = self.task_file_error(base)?;
                self.mmio.write_u32(base + PORT_IS, interrupt)?;
                return Err(error);
            }
            if interrupt & PORT_IS_ERROR_MASK != 0 {
                self.unavailable = true;
                self.mmio.write_u32(base + PORT_IS, interrupt)?;
                return Err(AhciError::InterfaceError(interrupt & PORT_IS_ERROR_MASK));
            }
            if self.mmio.read_u32(base + PORT_CI)? & COMMAND_SLOT == 0 {
                compiler_fence(Ordering::Acquire);
                validate_port(&mut self.mmio, base).map_err(|error| {
                    self.unavailable = true;
                    error
                })?;
                let task_file = self.mmio.read_u32(base + PORT_TFD)?;
                let status = task_file as u8;
                if status & (ATA_STATUS_ERR | ATA_STATUS_DF | ATA_STATUS_BSY | ATA_STATUS_DRQ) != 0
                {
                    return Err(AhciError::TaskFileError {
                        status,
                        error: (task_file >> 8) as u8,
                    });
                }
                self.mmio.write_u32(base + PORT_IS, interrupt)?;
                let global = self.mmio.read_u32(REG_IS)?;
                if global & (1_u32 << self.port) != 0 {
                    self.mmio.write_u32(REG_IS, 1_u32 << self.port)?;
                }
                return Ok(());
            }
            spin_loop();
        }
        self.unavailable = true;
        Err(AhciError::CommandTimedOut)
    }

    fn task_file_error(&mut self, base: usize) -> Result<AhciError, AhciError> {
        validate_port(&mut self.mmio, base)?;
        let task_file = self.mmio.read_u32(base + PORT_TFD)?;
        Ok(AhciError::TaskFileError {
            status: task_file as u8,
            error: (task_file >> 8) as u8,
        })
    }
}

impl Drop for AhciDisk {
    fn drop(&mut self) {
        if let Ok(base) = port_offset(self.port) {
            let _ = self.mmio.write_u32(base + PORT_IE, 0);
            let _ = stop_engine(&mut self.mmio, base);
        }
        compiler_fence(Ordering::SeqCst);
        // The monotonic allocator intentionally cannot reuse these pages. Keeping
        // their ownership represented here prevents conceptual reuse after a timeout.
        let _ = (self.received_fis.physical, self.command_list.physical);
    }
}

impl BlockDevice for AhciDisk {
    type Error = AhciError;

    fn capacity_sectors(&self) -> u64 {
        AhciDisk::capacity_sectors(self)
    }

    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        AhciDisk::read_sectors(self, lba, buffer)
    }

    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        AhciDisk::write_sectors(self, lba, buffer)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        AhciDisk::flush(self)
    }
}

fn bios_handoff(mmio: &mut MmioRegion) -> Result<(), AhciError> {
    if mmio.len() < REG_BOHC + 4 || mmio.read_u32(REG_CAP2)? & CAP2_BOH == 0 {
        return Ok(());
    }
    let ownership = mmio.read_u32(REG_BOHC)?;
    mmio.write_u32(REG_BOHC, (ownership | BOHC_OOS) & !BOHC_OOC)?;
    for _ in 0..POLL_LIMIT {
        let status = mmio.read_u32(REG_BOHC)?;
        if status & (BOHC_BOS | BOHC_BB) == 0 {
            if status & BOHC_OOC != 0 {
                mmio.write_u32(REG_BOHC, status | BOHC_OOC)?;
            }
            return Ok(());
        }
        spin_loop();
    }
    Err(AhciError::BiosHandoffTimedOut)
}

fn first_active_sata_port(
    mmio: &mut MmioRegion,
    port_count: usize,
    implemented: u32,
) -> Result<usize, AhciError> {
    for port in 0..port_count.min(32) {
        if implemented & (1_u32 << port) == 0 {
            continue;
        }
        let base = port_offset(port)?;
        if base
            .checked_add(PORT_STRIDE)
            .filter(|end| *end <= mmio.len())
            .is_none()
        {
            return Err(AhciError::InvalidBar);
        }
        let ssts = mmio.read_u32(base + PORT_SSTS)?;
        let det = ssts & 0xf;
        let ipm = (ssts >> 8) & 0xf;
        if det == SSTS_DET_PRESENT
            && ipm == SSTS_IPM_ACTIVE
            && mmio.read_u32(base + PORT_SIG)? == SATA_SIGNATURE
        {
            return Ok(port);
        }
    }
    Err(AhciError::NoSataPort)
}

fn validate_port(mmio: &mut MmioRegion, base: usize) -> Result<(), AhciError> {
    let ssts = mmio.read_u32(base + PORT_SSTS)?;
    if ssts == u32::MAX {
        return Err(AhciError::PortRemoved);
    }
    if ssts & 0xf != SSTS_DET_PRESENT || (ssts >> 8) & 0xf != SSTS_IPM_ACTIVE {
        return Err(AhciError::PortRemoved);
    }
    if mmio.read_u32(base + PORT_SIG)? != SATA_SIGNATURE {
        return Err(AhciError::UnsupportedDevice);
    }
    Ok(())
}

fn wait_tfd_idle(mmio: &mut MmioRegion, base: usize) -> Result<(), AhciError> {
    for _ in 0..POLL_LIMIT {
        validate_port(mmio, base)?;
        let task_file = mmio.read_u32(base + PORT_TFD)?;
        let status = task_file as u8;
        if status != u8::MAX && status & (ATA_STATUS_BSY | ATA_STATUS_DRQ) == 0 {
            if status & (ATA_STATUS_ERR | ATA_STATUS_DF) != 0 {
                return Err(AhciError::TaskFileError {
                    status,
                    error: (task_file >> 8) as u8,
                });
            }
            return Ok(());
        }
        spin_loop();
    }
    Err(AhciError::CommandTimedOut)
}

fn stop_engine(mmio: &mut MmioRegion, base: usize) -> Result<(), AhciError> {
    let command = mmio.read_u32(base + PORT_CMD)?;
    mmio.write_u32(base + PORT_CMD, command & !PORT_CMD_ST)?;
    wait_register_clear(mmio, base + PORT_CMD, PORT_CMD_CR)?;
    let command = mmio.read_u32(base + PORT_CMD)?;
    mmio.write_u32(base + PORT_CMD, command & !PORT_CMD_FRE)?;
    wait_register_clear(mmio, base + PORT_CMD, PORT_CMD_FR)
}

fn start_engine(mmio: &mut MmioRegion, base: usize) -> Result<(), AhciError> {
    wait_register_clear(mmio, base + PORT_CMD, PORT_CMD_CR | PORT_CMD_FR)?;
    let command = mmio.read_u32(base + PORT_CMD)?;
    mmio.write_u32(base + PORT_CMD, command | PORT_CMD_FRE | PORT_CMD_ST)?;
    Ok(())
}

fn wait_register_clear(mmio: &mut MmioRegion, register: usize, mask: u32) -> Result<(), AhciError> {
    for _ in 0..POLL_LIMIT {
        if mmio.read_u32(register)? & mask == 0 {
            return Ok(());
        }
        spin_loop();
    }
    Err(AhciError::EngineTimedOut)
}

fn program_dma_base(
    mmio: &mut MmioRegion,
    port_base: usize,
    register: usize,
    physical: u64,
) -> Result<(), AhciError> {
    mmio.write_u32(port_base + register, physical as u32)?;
    mmio.write_u32(port_base + register + 4, (physical >> 32) as u32)?;
    Ok(())
}

fn port_offset(port: usize) -> Result<usize, AhciError> {
    PORT_BASE
        .checked_add(
            port.checked_mul(PORT_STRIDE)
                .ok_or(AhciError::AddressOverflow)?,
        )
        .ok_or(AhciError::AddressOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferRange {
    first_sector: u64,
    sector_count: u64,
}

fn transfer_range(
    first_sector: u64,
    byte_len: usize,
    capacity: u64,
) -> Result<TransferRange, AhciError> {
    if byte_len % SECTOR_SIZE != 0 {
        return Err(AhciError::Misaligned);
    }
    let sector_count =
        u64::try_from(byte_len).map_err(|_| AhciError::AddressOverflow)? / SECTOR_SIZE as u64;
    let end = first_sector
        .checked_add(sector_count)
        .ok_or(AhciError::AddressOverflow)?;
    if end > capacity {
        return Err(AhciError::OutOfBounds);
    }
    Ok(TransferRange {
        first_sector,
        sector_count,
    })
}

fn command_fis(command: u8, lba: u64, sectors: u16) -> [u8; 20] {
    let mut fis = [0_u8; 20];
    fis[0] = FIS_TYPE_REG_H2D;
    fis[1] = FIS_COMMAND;
    fis[2] = command;
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    if command == ATA_READ_DMA_EXT || command == ATA_WRITE_DMA_EXT {
        fis[7] = LBA_MODE;
    }
    fis[8] = (lba >> 24) as u8;
    fis[9] = (lba >> 32) as u8;
    fis[10] = (lba >> 40) as u8;
    fis[12] = sectors as u8;
    fis[13] = (sectors >> 8) as u8;
    fis
}

fn prdt_dbc(byte_len: usize) -> Result<u32, AhciError> {
    if byte_len == 0 || byte_len > MAX_TRANSFER_BYTES {
        return Err(AhciError::InvalidTransfer);
    }
    Ok(u32::try_from(byte_len - 1).map_err(|_| AhciError::AddressOverflow)?)
}

unsafe fn map_abar(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    bar: PciBar,
) -> Result<MmioRegion, AhciError> {
    if bar.size < MIN_ABAR_SIZE || bar.size > MAX_ABAR_SIZE {
        return Err(AhciError::InvalidBar);
    }
    let physical_page = bar.physical_address & !(PAGE_SIZE - 1);
    let page_offset = bar.physical_address - physical_page;
    let mapped_length = page_offset
        .checked_add(bar.size)
        .and_then(|length| length.checked_add(PAGE_SIZE - 1))
        .map(|length| length & !(PAGE_SIZE - 1))
        .ok_or(AhciError::AddressOverflow)?;
    let candidates = [
        0xffff_a800_0000_0000_u64,
        0xffff_a900_0000_0000,
        0xffff_aa00_0000_0000,
        0xffff_ab00_0000_0000,
    ];
    let mut chosen = None;
    'candidate: for base in candidates {
        let mut offset = 0;
        while offset < mapped_length {
            let address =
                VirtAddr::try_new(base.checked_add(offset).ok_or(AhciError::AddressOverflow)?)
                    .map_err(|_| AhciError::AddressOverflow)?;
            if page_table.translate_addr(address).is_some() {
                continue 'candidate;
            }
            offset += PAGE_SIZE;
        }
        chosen = Some(base);
        break;
    }
    let virtual_base = chosen.ok_or(AhciError::InvalidBar)?;
    let flags = PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    let mut offset = 0;
    while offset < mapped_length {
        let physical = PhysAddr::try_new(
            physical_page
                .checked_add(offset)
                .ok_or(AhciError::AddressOverflow)?,
        )
        .map_err(|_| AhciError::AddressOverflow)?;
        let frame = PhysFrame::from_start_address(physical).map_err(|_| AhciError::InvalidBar)?;
        let virtual_address = VirtAddr::try_new(
            virtual_base
                .checked_add(offset)
                .ok_or(AhciError::AddressOverflow)?,
        )
        .map_err(|_| AhciError::AddressOverflow)?;
        let page =
            VirtPage::from_start_address(virtual_address).map_err(|_| AhciError::InvalidBar)?;
        unsafe { page_table.map_4k(page, frame, flags, frames)? };
        offset += PAGE_SIZE;
    }
    let address = virtual_base
        .checked_add(page_offset)
        .ok_or(AhciError::AddressOverflow)?;
    let pointer = usize::try_from(address).map_err(|_| AhciError::AddressOverflow)? as *mut u8;
    let length = usize::try_from(bar.size).map_err(|_| AhciError::AddressOverflow)?;
    // SAFETY: The complete, exclusively claimed ABAR was mapped uncached above.
    unsafe { MmioRegion::from_raw_parts(pointer, length) }.ok_or(AhciError::InvalidBar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fis_encodes_lba48_and_count() {
        let fis = command_fis(ATA_READ_DMA_EXT, 0x1234_5678_9abc, 0x0800);
        assert_eq!(fis[0], FIS_TYPE_REG_H2D);
        assert_eq!(fis[1], FIS_COMMAND);
        assert_eq!(fis[2], ATA_READ_DMA_EXT);
        assert_eq!(&fis[4..=6], &[0xbc, 0x9a, 0x78]);
        assert_eq!(fis[7], LBA_MODE);
        assert_eq!(&fis[8..=10], &[0x56, 0x34, 0x12]);
        assert_eq!(&fis[12..=13], &[0x00, 0x08]);
    }

    #[test]
    fn prdt_dbc_is_zero_based_and_page_bounded() {
        assert_eq!(prdt_dbc(1), Ok(0));
        assert_eq!(prdt_dbc(4096), Ok(4095));
        assert_eq!(prdt_dbc(0), Err(AhciError::InvalidTransfer));
        assert_eq!(prdt_dbc(4097), Err(AhciError::InvalidTransfer));
    }

    #[test]
    fn transfer_range_checks_alignment_overflow_and_capacity() {
        assert_eq!(
            transfer_range(7, 1024, 10),
            Ok(TransferRange {
                first_sector: 7,
                sector_count: 2
            })
        );
        assert_eq!(transfer_range(0, 1, 10), Err(AhciError::Misaligned));
        assert_eq!(transfer_range(9, 1024, 10), Err(AhciError::OutOfBounds));
        assert_eq!(
            transfer_range(u64::MAX, 512, u64::MAX),
            Err(AhciError::AddressOverflow)
        );
        assert_eq!(
            transfer_range(10, 0, 10),
            Ok(TransferRange {
                first_sector: 10,
                sector_count: 0
            })
        );
    }
}
