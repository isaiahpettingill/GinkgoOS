//! Fixed-capacity AHCI SATA block-device support.
//!
//! Bootstrap callers may use the synchronous [`BlockDevice`] API before MSI is
//! enabled. The asynchronous path uses NCQ when the controller and disk support
//! it, keeps one command table and exact dispatch token per usable command slot,
//! and performs all completion and reset work in deferred task context. The ISR
//! only sets the coalescing pending bit in `arch`.

use core::{
    cmp::min,
    hint::spin_loop,
    ptr,
    sync::atomic::{compiler_fence, fence, Ordering},
    task::Poll,
};

use crate::{
    arch::{
        register_ahci_port_ie, take_ahci_interrupt_pending, unregister_ahci_port_ie,
        AhciInterruptRegisterError, AHCI_VECTOR,
    },
    async_block::{
        AsyncBlockDevice, BlockDeviceConfig, BlockOperation, DispatchCommand, DispatchToken,
        DmaAddressMode, DmaConstraints, DmaSegment, DriverCompletion, HardwareStatus,
        MAX_DMA_SEGMENTS,
    },
    block::{BlockDevice, SECTOR_SIZE},
    io::{IoError, MmioRegion},
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageTableFlags},
    pci::{PciBar, PciConfig, PciDevice, PciError},
};

const AHCI_CLASS: u8 = 0x01;
const AHCI_SUBCLASS: u8 = 0x06;
const AHCI_INTERFACE: u8 = 0x01;
const AHCI_BAR: u8 = 5;
const MIN_ABAR_SIZE: u64 = 0x180;
const MAX_ABAR_SIZE: u64 = 16 * 1024 * 1024;
const POLL_LIMIT: usize = 1_000_000;
const INTERRUPT_WATCHDOG_POLLS: u16 = 64;
const RESET_WATCHDOG_POLLS: u16 = 4096;

const REG_CAP: usize = 0x00;
const REG_GHC: usize = 0x04;
const REG_IS: usize = 0x08;
const REG_PI: usize = 0x0c;
const REG_VS: usize = 0x10;
const REG_CAP2: usize = 0x24;
const REG_BOHC: usize = 0x28;
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;
const CAP_S64A: u32 = 1 << 31;
const CAP_SNCQ: u32 = 1 << 30;
const CAP_NCS_SHIFT: u32 = 8;
const CAP_NCS_MASK: u32 = 0x1f << CAP_NCS_SHIFT;
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
const PORT_IS_DHRS: u32 = 1;
const PORT_IS_SDBS: u32 = 1 << 3;
const PORT_IS_DPS: u32 = 1 << 5;
const PORT_IS_PCS: u32 = 1 << 6;
const PORT_IS_PRCS: u32 = 1 << 22;
const PORT_IS_TFES: u32 = 1 << 30;
const PORT_IS_ERROR_MASK: u32 = 0x7d00_0000;
const PORT_INTERRUPT_MASK: u32 =
    PORT_IS_DHRS | PORT_IS_SDBS | PORT_IS_DPS | PORT_IS_PCS | PORT_IS_PRCS | PORT_IS_ERROR_MASK;
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
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;
const ATA_WRITE_FPDMA_QUEUED: u8 = 0x61;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const FIS_TYPE_REG_H2D: u8 = 0x27;
const FIS_COMMAND: u8 = 1 << 7;
const LBA_MODE: u8 = 1 << 6;

const COMMAND_TABLE_PRDT: usize = 128;
const COMMAND_HEADER_BYTES: usize = 32;
const COMMAND_FIS_DWORDS: u32 = 5;
const COMMAND_HEADER_WRITE: u32 = 1 << 6;
const MAX_SLOTS: usize = 32;
const MAX_PRDT_ENTRIES: usize = 32;
const PRDT_ENTRY_BYTES: usize = 16;
const PRDT_MAX_BYTES: u32 = 4 * 1024 * 1024;
const BOOTSTRAP_TRANSFER_BYTES: usize = PAGE_SIZE as usize;
const BOOTSTRAP_TRANSFER_SECTORS: u32 = (BOOTSTRAP_TRANSFER_BYTES / SECTOR_SIZE) as u32;
const MAX_ATA_SECTORS: u32 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciError {
    Pci(PciError),
    Io(IoError),
    InterruptRegistration(AhciInterruptRegisterError),
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
    AsyncModeActive,
    AsyncNotEnabled,
    QueueFull,
    CompletionQueueFull,
    InvalidRequest,
    TooManyPrdtEntries,
    DeviceReset,
    DmaStopUnproved,
    Quarantined,
}

impl From<PciError> for AhciError {
    fn from(value: PciError) -> Self {
        Self::Pci(value)
    }
}

impl From<AhciInterruptRegisterError> for AhciError {
    fn from(value: AhciInterruptRegisterError) -> Self {
        Self::InterruptRegistration(value)
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
        validate_dma_range(physical, PAGE_SIZE as u32, supports_64_bit)?;
        let virtual_address = hhdm
            .checked_add(physical)
            .ok_or(AhciError::AddressOverflow)?;
        VirtAddr::try_new(virtual_address).map_err(|_| AhciError::AddressOverflow)?;
        let pointer =
            usize::try_from(virtual_address).map_err(|_| AhciError::AddressOverflow)? as *mut u8;
        // SAFETY: This newly allocated frame is exclusively owned and the HHDM covers it.
        unsafe { ptr::write_bytes(pointer, 0, PAGE_SIZE as usize) };
        Ok(Self { physical, pointer })
    }

    fn clear(&self) {
        // SAFETY: Callers clear a table only while its command slot is not active.
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
        // SAFETY: Bounds were checked and command completion acquired DMA writes.
        Ok(unsafe { ptr::read_volatile(pointer) })
    }

    fn copy_from(&self, source: &[u8]) -> Result<(), AhciError> {
        self.check(0, source.len(), 1)?;
        // SAFETY: The destination is in this exclusively owned DMA page.
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), self.pointer, source.len()) };
        Ok(())
    }

    fn copy_to(&self, destination: &mut [u8]) -> Result<(), AhciError> {
        self.check(0, destination.len(), 1)?;
        // SAFETY: Completion acquired device writes before this copy.
        unsafe {
            ptr::copy_nonoverlapping(self.pointer, destination.as_mut_ptr(), destination.len())
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ControllerCaps {
    command_slots: u8,
    supports_64_bit: bool,
    supports_ncq: bool,
}

impl ControllerCaps {
    const fn parse(cap: u32) -> Self {
        Self {
            command_slots: (((cap & CAP_NCS_MASK) >> CAP_NCS_SHIFT) + 1) as u8,
            supports_64_bit: cap & CAP_S64A != 0,
            supports_ncq: cap & CAP_SNCQ != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdentifyInfo {
    queue_depth: u8,
    ncq_supported: bool,
    flush_supported: bool,
    capacity: u64,
}

fn parse_identify(words: &[u16; 256]) -> Result<IdentifyInfo, AhciError> {
    if words[83] & (1 << 10) == 0 {
        return Err(AhciError::UnsupportedDevice);
    }
    let capacity = u64::from(words[100])
        | (u64::from(words[101]) << 16)
        | (u64::from(words[102]) << 32)
        | (u64::from(words[103]) << 48);
    if capacity == 0 || capacity > (1_u64 << 48) {
        return Err(AhciError::InvalidCapacity);
    }
    Ok(IdentifyInfo {
        queue_depth: ((words[75] & 0x1f) + 1) as u8,
        ncq_supported: words[76] & (1 << 8) != 0,
        flush_supported: words[83] & (1 << 12) != 0,
        capacity,
    })
}

const fn effective_queue_depth(controller: u8, device: u8, ncq: bool) -> u8 {
    if ncq {
        min_u8(min_u8(controller, device), MAX_SLOTS as u8)
    } else {
        1
    }
}

const fn min_u8(left: u8, right: u8) -> u8 {
    if left < right {
        left
    } else {
        right
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Free,
    Active,
    Quarantined,
}

#[derive(Clone, Copy, Debug)]
struct CommandSlot {
    state: SlotState,
    token: Option<DispatchToken>,
    operation: BlockOperation,
    byte_len: u32,
}

impl CommandSlot {
    const EMPTY: Self = Self {
        state: SlotState::Free,
        token: None,
        operation: BlockOperation::Read,
        byte_len: 0,
    };

    fn activate(&mut self, token: DispatchToken, operation: BlockOperation, byte_len: u32) {
        self.state = SlotState::Active;
        self.token = Some(token);
        self.operation = operation;
        self.byte_len = byte_len;
    }

    fn release(&mut self) {
        *self = Self::EMPTY;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetState {
    Running,
    StopRequested,
    WaitingForCr,
    WaitingForFr,
    Complete,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetProofState {
    WaitingForCr,
    WaitingForFr,
    Proved,
}

fn advance_reset_proof(state: ResetProofState, command: u32) -> (ResetProofState, bool) {
    match state {
        ResetProofState::WaitingForCr if command & PORT_CMD_CR == 0 => {
            (ResetProofState::WaitingForFr, false)
        }
        ResetProofState::WaitingForCr => (state, false),
        ResetProofState::WaitingForFr if command & (PORT_CMD_CR | PORT_CMD_FR) == 0 => {
            (ResetProofState::Proved, true)
        }
        ResetProofState::WaitingForFr => (state, false),
        ResetProofState::Proved => (state, true),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AhciDiagnostics {
    pub controller_queue_depth: u8,
    pub device_queue_depth: u8,
    pub negotiated_queue_depth: u8,
    pub ncq_supported: bool,
    pub ncq_enabled: bool,
    pub dma_64_bit: bool,
    pub flush_supported: bool,
    pub async_enabled: bool,
    pub msi_enabled: bool,
    pub interrupts: u64,
    pub watchdog_polls: u64,
    pub submissions: u64,
    pub completions: u64,
    pub in_flight: u8,
    pub slot_high_water: u8,
    pub prdt_high_water: u8,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub resets: u64,
    pub dma_stop_proofs: u64,
    pub dma_stop_failures: u64,
    pub quarantines: u64,
    pub removal_events: u64,
}

/// An exclusively owned AHCI controller port containing one 512-byte-sector SATA disk.
pub struct AhciDisk {
    mmio: MmioRegion,
    pci_device: PciDevice,
    port: usize,
    port_ie_address: u64,
    command_list: DmaPage,
    received_fis: DmaPage,
    command_tables: [Option<DmaPage>; MAX_SLOTS],
    bootstrap_data: DmaPage,
    capacity: u64,
    flush_supported: bool,
    supports_64_bit: bool,
    ncq_enabled: bool,
    slot_count: u8,
    slots: [CommandSlot; MAX_SLOTS],
    issued_mask: u32,
    exclusive_command: bool,
    completions: [Option<DriverCompletion>; MAX_SLOTS],
    completion_head: u8,
    completion_tail: u8,
    completion_count: u8,
    watchdog_countdown: u16,
    reset_watchdog: u16,
    reset_state: ResetState,
    unavailable: bool,
    diagnostics: AhciDiagnostics,
}

impl AhciDisk {
    /// Discovers the first PCI AHCI controller and claims its first active SATA port.
    ///
    /// # Safety
    ///
    /// The caller must provide exclusive ownership of PCI configuration mechanism
    /// #1, the selected controller and fixed MMIO mapping, the active page tables,
    /// and the allocator. The HHDM must coherently map every returned frame. No
    /// firmware, interrupt handler, or other driver may access the controller after
    /// BIOS/OS ownership transfer completes.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, AhciError> {
        let mut pci = unsafe { PciConfig::new()? };
        let device = pci
            .find_first(AHCI_CLASS, AHCI_SUBCLASS, Some(AHCI_INTERFACE))?
            .ok_or(AhciError::ControllerNotFound)?;
        match pci.disable_msi(device) {
            Ok(()) | Err(PciError::MsiCapabilityNotPresent) => {}
            Err(error) => return Err(error.into()),
        }
        let bar = pci.probe_bar(device, AHCI_BAR)?;
        pci.enable_memory_and_bus_mastering(device)?;
        let mut mmio = unsafe { map_abar(page_table, frames, bar)? };

        let version = mmio.read_u32(REG_VS)?;
        if version >> 16 == 0 {
            return Err(AhciError::UnsupportedAhciVersion);
        }
        bios_handoff(&mut mmio)?;
        let ghc = mmio.read_u32(REG_GHC)?;
        mmio.write_u32(REG_GHC, (ghc | GHC_AE) & !GHC_IE)?;

        let capabilities = mmio.read_u32(REG_CAP)?;
        let controller = ControllerCaps::parse(capabilities);
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

        let port_ie_address = mmio.u32_address(port_base + PORT_IE)?;
        stop_engine(&mut mmio, port_base)?;
        mmio.write_u32(port_base + PORT_IE, 0)?;
        mmio.write_u32(port_base + PORT_IS, u32::MAX)?;
        mmio.write_u32(port_base + PORT_SERR, u32::MAX)?;

        let hhdm = page_table.hhdm_offset().as_u64();
        let command_list = DmaPage::allocate(frames, hhdm, controller.supports_64_bit)?;
        let received_fis = DmaPage::allocate(frames, hhdm, controller.supports_64_bit)?;
        let bootstrap_data = DmaPage::allocate(frames, hhdm, controller.supports_64_bit)?;
        let mut command_tables: [Option<DmaPage>; MAX_SLOTS] = core::array::from_fn(|_| None);
        command_tables[0] = Some(DmaPage::allocate(frames, hhdm, controller.supports_64_bit)?);

        program_dma_base(&mut mmio, port_base, PORT_CLB, command_list.physical)?;
        program_dma_base(&mut mmio, port_base, PORT_FB, received_fis.physical)?;
        compiler_fence(Ordering::Release);
        start_engine(&mut mmio, port_base)?;

        let mut disk = Self {
            mmio,
            pci_device: device,
            port,
            port_ie_address,
            command_list,
            received_fis,
            command_tables,
            bootstrap_data,
            capacity: 0,
            flush_supported: false,
            supports_64_bit: controller.supports_64_bit,
            ncq_enabled: false,
            slot_count: 1,
            slots: [CommandSlot::EMPTY; MAX_SLOTS],
            issued_mask: 0,
            exclusive_command: false,
            completions: [None; MAX_SLOTS],
            completion_head: 0,
            completion_tail: 0,
            completion_count: 0,
            watchdog_countdown: INTERRUPT_WATCHDOG_POLLS,
            reset_watchdog: 0,
            reset_state: ResetState::Running,
            unavailable: false,
            diagnostics: AhciDiagnostics {
                controller_queue_depth: controller.command_slots,
                dma_64_bit: controller.supports_64_bit,
                ..AhciDiagnostics::default()
            },
        };
        let identify = disk.identify()?;
        disk.ncq_enabled = controller.supports_ncq && identify.ncq_supported;
        disk.slot_count = effective_queue_depth(
            controller.command_slots,
            identify.queue_depth,
            disk.ncq_enabled,
        );
        disk.diagnostics.device_queue_depth = identify.queue_depth;
        disk.diagnostics.negotiated_queue_depth = disk.slot_count;
        disk.diagnostics.ncq_supported = identify.ncq_supported;
        disk.diagnostics.ncq_enabled = disk.ncq_enabled;
        disk.diagnostics.flush_supported = identify.flush_supported;

        for table in disk.command_tables[1..usize::from(disk.slot_count)].iter_mut() {
            *table = Some(DmaPage::allocate(frames, hhdm, controller.supports_64_bit)?);
        }
        Ok(disk)
    }

    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    pub const fn flush_supported(&self) -> bool {
        self.flush_supported
    }

    pub const fn diagnostics(&self) -> AhciDiagnostics {
        self.diagnostics
    }

    /// Enables the dedicated AHCI MSI after CPU/IDT initialization is complete.
    pub fn enable_msi(&mut self, destination_apic_id: u8) -> Result<(), AhciError> {
        self.ensure_bootstrap_mode()?;
        let base = port_offset(self.port)?;
        if self.issued_mask != 0 {
            return Err(self.reject(AhciError::CommandSlotBusy));
        }
        self.mask_interrupts(base)?;
        self.acknowledge_interrupts(base)?;
        let mut pci = unsafe { PciConfig::new()? };
        unsafe { register_ahci_port_ie(self.port_ie_address)? };
        fence(Ordering::SeqCst);
        let mut msi_configured = false;
        let enabled = (|| {
            pci.configure_msi(self.pci_device, destination_apic_id, AHCI_VECTOR)?;
            msi_configured = true;
            self.mmio.write_u32(base + PORT_IE, PORT_INTERRUPT_MASK)?;
            let ghc = self.mmio.read_u32(REG_GHC)?;
            self.mmio.write_u32(REG_GHC, ghc | GHC_AE | GHC_IE)?;
            let _ = self.mmio.read_u32(REG_GHC)?;
            Ok::<(), AhciError>(())
        })();
        if let Err(error) = enabled {
            let _ = self.mask_interrupts(base);
            if let Ok(ghc) = self.mmio.read_u32(REG_GHC) {
                let _ = self.mmio.write_u32(REG_GHC, ghc & !GHC_IE);
            }
            let delivery_disabled = !msi_configured || pci.disable_msi(self.pci_device).is_ok();
            if delivery_disabled {
                let _ = unsafe { unregister_ahci_port_ie(self.port_ie_address) };
            }
            return Err(error);
        }
        fence(Ordering::SeqCst);
        self.diagnostics.msi_enabled = true;
        self.diagnostics.async_enabled = true;
        Ok(())
    }

    pub fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), AhciError> {
        self.ensure_bootstrap_mode()?;
        let range = transfer_range(lba, buffer.len(), self.capacity)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks_mut(BOOTSTRAP_TRANSFER_BYTES) {
            let count =
                u32::try_from(chunk.len() / SECTOR_SIZE).map_err(|_| AhciError::InvalidTransfer)?;
            self.issue_bootstrap(ATA_READ_DMA_EXT, sector, count, chunk.len(), false)?;
            self.bootstrap_data.copy_to(chunk)?;
            sector = sector
                .checked_add(u64::from(count))
                .ok_or(AhciError::AddressOverflow)?;
        }
        Ok(())
    }

    pub fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), AhciError> {
        self.ensure_bootstrap_mode()?;
        let range = transfer_range(lba, buffer.len(), self.capacity)?;
        let mut sector = range.first_sector;
        for chunk in buffer.chunks(BOOTSTRAP_TRANSFER_BYTES) {
            let count =
                u32::try_from(chunk.len() / SECTOR_SIZE).map_err(|_| AhciError::InvalidTransfer)?;
            self.bootstrap_data.copy_from(chunk)?;
            compiler_fence(Ordering::Release);
            self.issue_bootstrap(ATA_WRITE_DMA_EXT, sector, count, chunk.len(), true)?;
            sector = sector
                .checked_add(u64::from(count))
                .ok_or(AhciError::AddressOverflow)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), AhciError> {
        self.ensure_bootstrap_mode()?;
        if self.flush_supported {
            self.issue_bootstrap(ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)?;
        }
        Ok(())
    }

    fn identify(&mut self) -> Result<IdentifyInfo, AhciError> {
        self.issue_bootstrap(ATA_IDENTIFY_DEVICE, 0, 0, SECTOR_SIZE, false)?;
        let mut words = [0_u16; 256];
        for (word, value) in words.iter_mut().enumerate() {
            *value = self.bootstrap_data.read_u16(word)?;
        }
        let identify = parse_identify(&words)?;
        self.capacity = identify.capacity;
        self.flush_supported = identify.flush_supported;
        Ok(identify)
    }

    fn issue_bootstrap(
        &mut self,
        command: u8,
        lba: u64,
        sectors: u32,
        byte_len: usize,
        write: bool,
    ) -> Result<(), AhciError> {
        self.ensure_bootstrap_mode()?;
        if lba >= (1_u64 << 48) || sectors > BOOTSTRAP_TRANSFER_SECTORS {
            return Err(AhciError::InvalidTransfer);
        }
        let expected = usize::try_from(sectors)
            .map_err(|_| AhciError::AddressOverflow)?
            .checked_mul(SECTOR_SIZE)
            .ok_or(AhciError::AddressOverflow)?;
        if command == ATA_IDENTIFY_DEVICE {
            if byte_len != SECTOR_SIZE {
                return Err(AhciError::InvalidTransfer);
            }
        } else if byte_len != 0 && byte_len != expected {
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
        if self.mmio.read_u32(base + PORT_CI)? & 1 != 0
            || self.mmio.read_u32(base + PORT_SACT)? & 1 != 0
        {
            self.unavailable = true;
            return Err(AhciError::CommandSlotBusy);
        }

        self.command_list.clear();
        let table = self.command_tables[0]
            .as_ref()
            .ok_or(AhciError::DeviceUnavailable)?;
        table.clear();
        let fis = command_fis(command, lba, sectors)?;
        copy_fis(table, &fis)?;
        let prdt_count = if byte_len == 0 {
            0
        } else {
            let plan = build_prdt(
                &[DmaSegment {
                    physical_address: self.bootstrap_data.physical,
                    length: u32::try_from(byte_len).map_err(|_| AhciError::AddressOverflow)?,
                }],
                u32::try_from(byte_len).map_err(|_| AhciError::AddressOverflow)?,
                self.supports_64_bit,
            )?;
            write_prdt(table, &plan)?;
            plan.count
        };
        write_command_header(&self.command_list, 0, table.physical, prdt_count, write)?;

        self.mmio.write_u32(base + PORT_IS, u32::MAX)?;
        self.mmio.write_u32(base + PORT_SERR, u32::MAX)?;
        compiler_fence(Ordering::Release);
        self.mmio.write_u32(base + PORT_CI, 1)?;

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
            if self.mmio.read_u32(base + PORT_CI)? & 1 == 0 {
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

    fn submit_async(&mut self, command: &DispatchCommand) -> Result<(), AhciError> {
        self.ensure_async_mode()?;
        let (ata_command, write, exclusive) = match command.operation {
            BlockOperation::Read => (
                if self.ncq_enabled {
                    ATA_READ_FPDMA_QUEUED
                } else {
                    ATA_READ_DMA_EXT
                },
                false,
                false,
            ),
            BlockOperation::Write => (
                if self.ncq_enabled {
                    ATA_WRITE_FPDMA_QUEUED
                } else {
                    ATA_WRITE_DMA_EXT
                },
                true,
                false,
            ),
            BlockOperation::Flush | BlockOperation::Barrier if self.flush_supported => {
                (ATA_FLUSH_CACHE_EXT, false, true)
            }
            BlockOperation::Flush | BlockOperation::Barrier => {
                return Err(self.reject(AhciError::UnsupportedDevice));
            }
        };
        if exclusive
            && (self.issued_mask != 0 || command.byte_len != 0 || !command.segments().is_empty())
        {
            return Err(self.reject(AhciError::InvalidRequest));
        }
        if !exclusive && self.exclusive_command {
            return Err(self.reject(AhciError::QueueFull));
        }
        let byte_len = command.byte_len;
        let sectors = if exclusive {
            0
        } else {
            if byte_len == 0 || byte_len as usize % SECTOR_SIZE != 0 {
                return Err(self.reject(AhciError::InvalidRequest));
            }
            byte_len / SECTOR_SIZE as u32
        };
        if sectors > MAX_ATA_SECTORS || command.lba >= (1_u64 << 48) {
            return Err(self.reject(AhciError::InvalidTransfer));
        }
        transfer_range(command.lba, byte_len as usize, self.capacity)?;
        let plan = if exclusive {
            PrdtPlan::EMPTY
        } else {
            build_prdt(command.segments(), byte_len, self.supports_64_bit)?
        };
        let slot = self
            .find_free_slot()
            .ok_or_else(|| self.reject(AhciError::QueueFull))?;
        let tag = slot as u8;
        let fis = if self.ncq_enabled && !exclusive {
            ncq_fis(ata_command, command.lba, sectors, tag)?
        } else {
            command_fis(ata_command, command.lba, sectors)?
        };
        if self.command_tables[slot].is_none() {
            return Err(self.reject(AhciError::DeviceUnavailable));
        }
        let table = self.command_tables[slot]
            .as_ref()
            .ok_or(AhciError::DeviceUnavailable)?;
        table.clear();
        copy_fis(table, &fis)?;
        write_prdt(table, &plan)?;
        write_command_header(&self.command_list, slot, table.physical, plan.count, write)?;

        let base = port_offset(self.port)?;
        validate_port(&mut self.mmio, base).map_err(|error| {
            self.note_removal(error);
            error
        })?;
        let mask = 1_u32 << slot;
        let hardware_active =
            self.mmio.read_u32(base + PORT_CI)? | self.mmio.read_u32(base + PORT_SACT)?;
        if hardware_active & mask != 0 {
            return Err(self.reject(AhciError::CommandSlotBusy));
        }

        self.slots[slot].activate(command.token, command.operation, byte_len);
        self.issued_mask |= mask;
        self.exclusive_command = exclusive;
        self.diagnostics.submissions = self.diagnostics.submissions.saturating_add(1);
        self.diagnostics.in_flight = self.diagnostics.in_flight.saturating_add(1);
        self.diagnostics.slot_high_water = self
            .diagnostics
            .slot_high_water
            .max(self.diagnostics.in_flight);
        self.diagnostics.prdt_high_water = self.diagnostics.prdt_high_water.max(plan.count);
        compiler_fence(Ordering::Release);
        let issue = (|| {
            if self.ncq_enabled && !exclusive {
                self.mmio.write_u32(base + PORT_SACT, mask)?;
                compiler_fence(Ordering::Release);
            }
            self.mmio.write_u32(base + PORT_CI, mask)?;
            Ok::<(), IoError>(())
        })();
        if let Err(error) = issue {
            self.reject(error.into());
            self.start_reset();
        }
        Ok(())
    }

    fn find_free_slot(&self) -> Option<usize> {
        (0..usize::from(self.slot_count)).find(|slot| self.slots[*slot].state == SlotState::Free)
    }

    fn drain_completions(&mut self) -> Result<(), AhciError> {
        let base = port_offset(self.port)?;
        if let Err(error) = validate_port(&mut self.mmio, base) {
            self.note_removal(error);
            return Err(error);
        }
        let interrupt = self.mmio.read_u32(base + PORT_IS)?;
        if interrupt != 0 {
            self.mmio.write_u32(base + PORT_IS, interrupt)?;
        }
        let global = self.mmio.read_u32(REG_IS)?;
        let port_bit = 1_u32 << self.port;
        if global & port_bit != 0 {
            self.mmio.write_u32(REG_IS, port_bit)?;
        }
        if interrupt & PORT_IS_ERROR_MASK != 0 {
            self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
            self.start_reset();
            if interrupt & PORT_IS_TFES != 0 {
                return Err(self.task_file_error(base)?);
            }
            return Err(AhciError::InterfaceError(interrupt & PORT_IS_ERROR_MASK));
        }

        let sact = self.mmio.read_u32(base + PORT_SACT)?;
        let ci = self.mmio.read_u32(base + PORT_CI)?;
        let completed = completed_slots(self.issued_mask, sact, ci);
        if completed == 0 {
            return self.rearm_interrupts(base);
        }
        fence(Ordering::Acquire);
        for slot in 0..usize::from(self.slot_count) {
            let mask = 1_u32 << slot;
            if completed & mask == 0 {
                continue;
            }
            let command_slot = self.slots[slot];
            let token = command_slot.token.ok_or(AhciError::InvalidRequest)?;
            self.push_completion(DriverCompletion {
                token,
                status: HardwareStatus::Success,
            })?;
            match command_slot.operation {
                BlockOperation::Read => {
                    self.diagnostics.bytes_read = self
                        .diagnostics
                        .bytes_read
                        .saturating_add(u64::from(command_slot.byte_len));
                }
                BlockOperation::Write => {
                    self.diagnostics.bytes_written = self
                        .diagnostics
                        .bytes_written
                        .saturating_add(u64::from(command_slot.byte_len));
                }
                BlockOperation::Flush | BlockOperation::Barrier => {}
            }
            self.slots[slot].release();
            self.issued_mask &= !mask;
            self.diagnostics.in_flight = self.diagnostics.in_flight.saturating_sub(1);
            self.diagnostics.completions = self.diagnostics.completions.saturating_add(1);
        }
        if self.issued_mask == 0 {
            self.exclusive_command = false;
        }
        self.rearm_interrupts(base)
    }

    fn mask_interrupts(&mut self, base: usize) -> Result<(), AhciError> {
        self.mmio.write_u32(base + PORT_IE, 0)?;
        let _ = self.mmio.read_u32(base + PORT_IE)?;
        Ok(())
    }

    fn rearm_interrupts(&mut self, base: usize) -> Result<(), AhciError> {
        if self.reset_state != ResetState::Running
            || !self.diagnostics.async_enabled
            || !self.diagnostics.msi_enabled
        {
            return Ok(());
        }
        fence(Ordering::Release);
        let rearmed = (|| {
            self.mmio.write_u32(base + PORT_IE, PORT_INTERRUPT_MASK)?;
            let enabled = self.mmio.read_u32(base + PORT_IE)?;
            if enabled & PORT_INTERRUPT_MASK != PORT_INTERRUPT_MASK {
                return Err(AhciError::DeviceUnavailable);
            }
            Ok(())
        })();
        if rearmed.is_err() {
            self.start_reset();
        }
        rearmed
    }

    fn acknowledge_interrupts(&mut self, base: usize) -> Result<(), AhciError> {
        let interrupt = self.mmio.read_u32(base + PORT_IS)?;
        if interrupt != 0 {
            self.mmio.write_u32(base + PORT_IS, interrupt)?;
        }
        let port_bit = 1_u32 << self.port;
        let global = self.mmio.read_u32(REG_IS)?;
        if global & port_bit != 0 {
            self.mmio.write_u32(REG_IS, port_bit)?;
        }
        Ok(())
    }

    fn push_completion(&mut self, completion: DriverCompletion) -> Result<(), AhciError> {
        if usize::from(self.completion_count) >= usize::from(self.slot_count) {
            self.start_reset();
            return Err(self.reject(AhciError::CompletionQueueFull));
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

    fn poll_completion_inner(&mut self) -> Poll<Result<DriverCompletion, AhciError>> {
        if self.reset_state != ResetState::Running {
            if let Some(completion) = self.pop_completion() {
                return Poll::Ready(Ok(completion));
            }
            return Poll::Ready(Err(if self.reset_state == ResetState::Quarantined {
                AhciError::Quarantined
            } else {
                AhciError::DeviceReset
            }));
        }
        if let Err(error) = self.ensure_async_mode() {
            return Poll::Ready(Err(error));
        }

        let interrupted = take_ahci_interrupt_pending();
        let should_drain = if interrupted {
            self.diagnostics.interrupts = self.diagnostics.interrupts.saturating_add(1);
            self.watchdog_countdown = INTERRUPT_WATCHDOG_POLLS;
            true
        } else if self.issued_mask == 0 {
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
            if let Err(error) = self.drain_completions() {
                return Poll::Ready(Err(error));
            }
        }
        match self.pop_completion() {
            Some(completion) => Poll::Ready(Ok(completion)),
            None => Poll::Pending,
        }
    }

    fn request_cancel_inner(&mut self, token: DispatchToken) -> Result<(), AhciError> {
        self.ensure_async_mode()?;
        if self.slots[..usize::from(self.slot_count)]
            .iter()
            .any(|slot| slot.state == SlotState::Active && slot.token == Some(token))
        {
            self.start_reset();
        }
        Ok(())
    }

    fn start_reset(&mut self) {
        if self.reset_state == ResetState::Running {
            self.reset_state = ResetState::StopRequested;
            self.reset_watchdog = RESET_WATCHDOG_POLLS;
            self.diagnostics.resets = self.diagnostics.resets.saturating_add(1);
            if let Ok(base) = port_offset(self.port) {
                let _ = self.mask_interrupts(base);
            }
        }
    }

    fn poll_reset_inner(&mut self) -> Poll<Result<(), AhciError>> {
        if self.reset_state == ResetState::Complete {
            return Poll::Ready(Ok(()));
        }
        if self.reset_state == ResetState::Quarantined {
            return Poll::Ready(Err(AhciError::DmaStopUnproved));
        }
        if self.reset_state == ResetState::Running {
            self.start_reset();
        }
        let base = match port_offset(self.port) {
            Ok(base) => base,
            Err(error) => return Poll::Ready(Err(self.quarantine(error))),
        };
        if self.reset_watchdog == 0 {
            return Poll::Ready(Err(self.quarantine(AhciError::DmaStopUnproved)));
        }
        self.reset_watchdog -= 1;

        match self.reset_state {
            ResetState::StopRequested => {
                if let Err(error) = self.mask_interrupts(base) {
                    return Poll::Ready(Err(self.quarantine(error.into())));
                }
                if let Ok(mut pci) = unsafe { PciConfig::new() } {
                    let _ = pci.disable_msi(self.pci_device);
                }
                self.diagnostics.msi_enabled = false;
                let command = match self.mmio.read_u32(base + PORT_CMD) {
                    Ok(command) if command != u32::MAX => command,
                    Ok(_) => return Poll::Ready(Err(self.quarantine(AhciError::PortRemoved))),
                    Err(error) => return Poll::Ready(Err(self.quarantine(error.into()))),
                };
                if let Err(error) = self.mmio.write_u32(base + PORT_CMD, command & !PORT_CMD_ST) {
                    return Poll::Ready(Err(self.quarantine(error.into())));
                }
                self.reset_state = ResetState::WaitingForCr;
                Poll::Pending
            }
            ResetState::WaitingForCr => {
                let command = match self.mmio.read_u32(base + PORT_CMD) {
                    Ok(command) if command != u32::MAX => command,
                    Ok(_) => return Poll::Ready(Err(self.quarantine(AhciError::PortRemoved))),
                    Err(error) => return Poll::Ready(Err(self.quarantine(error.into()))),
                };
                let (proof, _) = advance_reset_proof(ResetProofState::WaitingForCr, command);
                if proof == ResetProofState::WaitingForFr {
                    if let Err(error) = self
                        .mmio
                        .write_u32(base + PORT_CMD, command & !PORT_CMD_FRE)
                    {
                        return Poll::Ready(Err(self.quarantine(error.into())));
                    }
                    self.reset_state = ResetState::WaitingForFr;
                }
                Poll::Pending
            }
            ResetState::WaitingForFr => {
                let command = match self.mmio.read_u32(base + PORT_CMD) {
                    Ok(command) if command != u32::MAX => command,
                    Ok(_) => return Poll::Ready(Err(self.quarantine(AhciError::PortRemoved))),
                    Err(error) => return Poll::Ready(Err(self.quarantine(error.into()))),
                };
                let (_, proved) = advance_reset_proof(ResetProofState::WaitingForFr, command);
                if !proved {
                    return Poll::Pending;
                }
                fence(Ordering::Acquire);
                self.release_after_dma_stop_proof();
                self.reset_state = ResetState::Complete;
                self.unavailable = true;
                self.diagnostics.async_enabled = false;
                self.diagnostics.dma_stop_proofs =
                    self.diagnostics.dma_stop_proofs.saturating_add(1);
                Poll::Ready(Ok(()))
            }
            ResetState::Running | ResetState::Complete | ResetState::Quarantined => unreachable!(),
        }
    }

    fn release_after_dma_stop_proof(&mut self) {
        for slot in &mut self.slots[..usize::from(self.slot_count)] {
            slot.release();
        }
        self.issued_mask = 0;
        self.exclusive_command = false;
        self.completions.fill(None);
        self.completion_head = 0;
        self.completion_tail = 0;
        self.completion_count = 0;
        self.diagnostics.in_flight = 0;
    }

    fn quarantine(&mut self, cause: AhciError) -> AhciError {
        if self.reset_state != ResetState::Quarantined {
            if let Ok(mut pci) = unsafe { PciConfig::new() } {
                let _ = pci.disable_msi(self.pci_device);
                let _ = pci.set_bus_mastering(self.pci_device, false);
            }
            for slot in &mut self.slots[..usize::from(self.slot_count)] {
                if slot.state == SlotState::Active {
                    slot.state = SlotState::Quarantined;
                }
            }
            self.reset_state = ResetState::Quarantined;
            self.unavailable = true;
            self.diagnostics.async_enabled = false;
            self.diagnostics.msi_enabled = false;
            self.diagnostics.dma_stop_failures =
                self.diagnostics.dma_stop_failures.saturating_add(1);
            self.diagnostics.quarantines = self.diagnostics.quarantines.saturating_add(1);
        }
        self.reject(cause)
    }

    fn note_removal(&mut self, error: AhciError) {
        if matches!(error, AhciError::PortRemoved | AhciError::UnsupportedDevice) {
            self.diagnostics.removal_events = self.diagnostics.removal_events.saturating_add(1);
        }
        self.start_reset();
    }

    fn task_file_error(&mut self, base: usize) -> Result<AhciError, AhciError> {
        let task_file = self.mmio.read_u32(base + PORT_TFD)?;
        Ok(AhciError::TaskFileError {
            status: task_file as u8,
            error: (task_file >> 8) as u8,
        })
    }

    fn ensure_bootstrap_mode(&mut self) -> Result<(), AhciError> {
        if self.unavailable {
            return Err(AhciError::DeviceUnavailable);
        }
        if self.diagnostics.async_enabled || self.diagnostics.msi_enabled {
            return Err(self.reject(AhciError::AsyncModeActive));
        }
        if self.reset_state != ResetState::Running {
            return Err(AhciError::DeviceReset);
        }
        Ok(())
    }

    fn ensure_async_mode(&mut self) -> Result<(), AhciError> {
        if self.reset_state != ResetState::Running {
            return Err(AhciError::DeviceReset);
        }
        if self.unavailable {
            return Err(AhciError::DeviceUnavailable);
        }
        if !self.diagnostics.async_enabled || !self.diagnostics.msi_enabled {
            return Err(self.reject(AhciError::AsyncNotEnabled));
        }
        Ok(())
    }

    fn reject(&mut self, error: AhciError) -> AhciError {
        self.diagnostics.errors = self.diagnostics.errors.saturating_add(1);
        error
    }
}

impl AsyncBlockDevice for AhciDisk {
    type Error = AhciError;

    fn config(&self) -> BlockDeviceConfig {
        BlockDeviceConfig {
            capacity_sectors: self.capacity,
            queue_depth: u16::from(self.slot_count),
            supports_flush: self.flush_supported,
            dma: DmaConstraints {
                address_mode: if self.supports_64_bit {
                    DmaAddressMode::Bits64
                } else {
                    DmaAddressMode::Bits32
                },
                address_alignment: 1,
                max_segments: MAX_DMA_SEGMENTS as u8,
                max_segment_len: PRDT_MAX_BYTES,
            },
        }
    }

    fn poll_ready(&mut self) -> Poll<Result<(), Self::Error>> {
        if let Err(error) = self.ensure_async_mode() {
            return Poll::Ready(Err(error));
        }
        if self.exclusive_command
            || usize::from(self.diagnostics.in_flight) + usize::from(self.completion_count)
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

impl Drop for AhciDisk {
    fn drop(&mut self) {
        if let Ok(base) = port_offset(self.port) {
            let _ = self.mask_interrupts(base);
            if stop_engine(&mut self.mmio, base).is_err() {
                if let Ok(mut pci) = unsafe { PciConfig::new() } {
                    let _ = pci.set_bus_mastering(self.pci_device, false);
                }
            }
        }
        if let Ok(mut pci) = unsafe { PciConfig::new() } {
            if pci.disable_msi(self.pci_device).is_ok() {
                let _ = unsafe { unregister_ahci_port_ie(self.port_ie_address) };
            }
        }
        compiler_fence(Ordering::SeqCst);
        // The monotonic allocator does not reuse these frames. Active tokens are
        // never logically released here if stopping DMA could not be proved.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrdtEntry {
    physical_address: u64,
    length: u32,
}

impl PrdtEntry {
    const EMPTY: Self = Self {
        physical_address: 0,
        length: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrdtPlan {
    entries: [PrdtEntry; MAX_PRDT_ENTRIES],
    count: u8,
}

impl PrdtPlan {
    const EMPTY: Self = Self {
        entries: [PrdtEntry::EMPTY; MAX_PRDT_ENTRIES],
        count: 0,
    };
}

fn build_prdt(
    segments: &[DmaSegment],
    byte_len: u32,
    supports_64_bit: bool,
) -> Result<PrdtPlan, AhciError> {
    if byte_len == 0 {
        return if segments.is_empty() {
            Ok(PrdtPlan::EMPTY)
        } else {
            Err(AhciError::InvalidRequest)
        };
    }
    if segments.is_empty() || segments.len() > MAX_DMA_SEGMENTS {
        return Err(AhciError::InvalidRequest);
    }
    let mut plan = PrdtPlan::EMPTY;
    let mut total = 0_u64;
    for segment in segments {
        if segment.length == 0 {
            return Err(AhciError::InvalidRequest);
        }
        validate_dma_range(segment.physical_address, segment.length, supports_64_bit)?;
        total = total
            .checked_add(u64::from(segment.length))
            .ok_or(AhciError::AddressOverflow)?;
        let mut address = segment.physical_address;
        let mut remaining = segment.length;
        while remaining != 0 {
            if usize::from(plan.count) == MAX_PRDT_ENTRIES {
                return Err(AhciError::TooManyPrdtEntries);
            }
            let length = min(remaining, PRDT_MAX_BYTES);
            plan.entries[usize::from(plan.count)] = PrdtEntry {
                physical_address: address,
                length,
            };
            plan.count += 1;
            remaining -= length;
            address = address
                .checked_add(u64::from(length))
                .ok_or(AhciError::AddressOverflow)?;
        }
    }
    if total != u64::from(byte_len) {
        return Err(AhciError::InvalidRequest);
    }
    Ok(plan)
}

fn validate_dma_range(address: u64, length: u32, supports_64_bit: bool) -> Result<u64, AhciError> {
    if length == 0 {
        return Err(AhciError::InvalidTransfer);
    }
    let inclusive_end = address
        .checked_add(u64::from(length) - 1)
        .ok_or(AhciError::AddressOverflow)?;
    if !supports_64_bit && inclusive_end >= DMA_32BIT_ADDRESS_LIMIT {
        return Err(AhciError::UnsupportedDmaAddress);
    }
    Ok(inclusive_end)
}

fn prdt_dbc(byte_len: u32) -> Result<u32, AhciError> {
    if byte_len == 0 || byte_len > PRDT_MAX_BYTES {
        return Err(AhciError::InvalidTransfer);
    }
    Ok(byte_len - 1)
}

fn write_prdt(table: &DmaPage, plan: &PrdtPlan) -> Result<(), AhciError> {
    for (index, entry) in plan.entries[..usize::from(plan.count)].iter().enumerate() {
        let offset = COMMAND_TABLE_PRDT + index * PRDT_ENTRY_BYTES;
        table.write_u32(offset, entry.physical_address as u32)?;
        table.write_u32(offset + 4, (entry.physical_address >> 32) as u32)?;
        table.write_u32(offset + 8, 0)?;
        table.write_u32(offset + 12, prdt_dbc(entry.length)?)?;
    }
    Ok(())
}

fn write_command_header(
    command_list: &DmaPage,
    slot: usize,
    table_physical: u64,
    prdt_count: u8,
    write: bool,
) -> Result<(), AhciError> {
    if slot >= MAX_SLOTS || usize::from(prdt_count) > MAX_PRDT_ENTRIES {
        return Err(AhciError::InvalidRequest);
    }
    let offset = slot
        .checked_mul(COMMAND_HEADER_BYTES)
        .ok_or(AhciError::AddressOverflow)?;
    let mut flags = COMMAND_FIS_DWORDS | (u32::from(prdt_count) << 16);
    if write {
        flags |= COMMAND_HEADER_WRITE;
    }
    command_list.write_u32(offset, flags)?;
    command_list.write_u32(offset + 4, 0)?;
    command_list.write_u32(offset + 8, table_physical as u32)?;
    command_list.write_u32(offset + 12, (table_physical >> 32) as u32)?;
    command_list.write_u32(offset + 16, 0)?;
    command_list.write_u32(offset + 20, 0)?;
    command_list.write_u32(offset + 24, 0)?;
    command_list.write_u32(offset + 28, 0)
}

fn copy_fis(table: &DmaPage, fis: &[u8; 20]) -> Result<(), AhciError> {
    table.check(0, fis.len(), 1)?;
    // SAFETY: The table is exclusively owned by an inactive command slot.
    unsafe { ptr::copy_nonoverlapping(fis.as_ptr(), table.pointer, fis.len()) };
    Ok(())
}

fn command_fis(command: u8, lba: u64, sectors: u32) -> Result<[u8; 20], AhciError> {
    let count = ata_sector_count(sectors)?;
    let mut fis = [0_u8; 20];
    fis[0] = FIS_TYPE_REG_H2D;
    fis[1] = FIS_COMMAND;
    fis[2] = command;
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    if matches!(
        command,
        ATA_READ_DMA_EXT | ATA_WRITE_DMA_EXT | ATA_FLUSH_CACHE_EXT
    ) {
        fis[7] = LBA_MODE;
    }
    fis[8] = (lba >> 24) as u8;
    fis[9] = (lba >> 32) as u8;
    fis[10] = (lba >> 40) as u8;
    fis[12] = count as u8;
    fis[13] = (count >> 8) as u8;
    Ok(fis)
}

fn ncq_fis(command: u8, lba: u64, sectors: u32, tag: u8) -> Result<[u8; 20], AhciError> {
    if !matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED) || tag >= MAX_SLOTS as u8
    {
        return Err(AhciError::InvalidRequest);
    }
    let count = ata_sector_count(sectors)?;
    let mut fis = [0_u8; 20];
    fis[0] = FIS_TYPE_REG_H2D;
    fis[1] = FIS_COMMAND;
    fis[2] = command;
    fis[3] = count as u8;
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    fis[7] = LBA_MODE;
    fis[8] = (lba >> 24) as u8;
    fis[9] = (lba >> 32) as u8;
    fis[10] = (lba >> 40) as u8;
    fis[11] = (count >> 8) as u8;
    fis[12] = tag << 3;
    Ok(fis)
}

fn ata_sector_count(sectors: u32) -> Result<u16, AhciError> {
    if sectors > MAX_ATA_SECTORS {
        return Err(AhciError::InvalidTransfer);
    }
    Ok(if sectors == MAX_ATA_SECTORS {
        0
    } else {
        sectors as u16
    })
}

const fn completed_slots(issued: u32, sact: u32, ci: u32) -> u32 {
    issued & !(sact | ci)
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
    fn cap_parses_queue_depth_dma_width_and_ncq() {
        assert_eq!(
            ControllerCaps::parse(CAP_S64A | CAP_SNCQ | (17 << CAP_NCS_SHIFT)),
            ControllerCaps {
                command_slots: 18,
                supports_64_bit: true,
                supports_ncq: true,
            }
        );
        assert_eq!(ControllerCaps::parse(0).command_slots, 1);
        let no_ncq = ControllerCaps::parse(31 << CAP_NCS_SHIFT);
        assert!(!no_ncq.supports_64_bit);
        assert!(!no_ncq.supports_ncq);
    }

    #[test]
    fn identify_parses_depth_ncq_flush_and_capacity() {
        let mut words = [0_u16; 256];
        words[75] = 15;
        words[76] = 1 << 8;
        words[83] = (1 << 10) | (1 << 12);
        words[100] = 0x9abc;
        words[101] = 0x5678;
        words[102] = 0x1234;
        let info = parse_identify(&words).unwrap();
        assert_eq!(info.queue_depth, 16);
        assert!(info.ncq_supported);
        assert!(info.flush_supported);
        assert_eq!(info.capacity, 0x1234_5678_9abc);
        assert_eq!(effective_queue_depth(32, info.queue_depth, true), 16);
        assert_eq!(effective_queue_depth(32, info.queue_depth, false), 1);
    }

    #[test]
    fn ncq_fis_encodes_features_lba_and_tag() {
        let fis = ncq_fis(ATA_READ_FPDMA_QUEUED, 0x1234_5678_9abc, 0x0800, 19).unwrap();
        assert_eq!(&fis[0..4], &[FIS_TYPE_REG_H2D, FIS_COMMAND, 0x60, 0x00]);
        assert_eq!(&fis[4..=6], &[0xbc, 0x9a, 0x78]);
        assert_eq!(fis[7], LBA_MODE);
        assert_eq!(&fis[8..=11], &[0x56, 0x34, 0x12, 0x08]);
        assert_eq!(fis[12], 19 << 3);
        let write = ncq_fis(ATA_WRITE_FPDMA_QUEUED, 7, 1, 31).unwrap();
        assert_eq!(write[2], ATA_WRITE_FPDMA_QUEUED);
        assert_eq!(write[3], 1);
        assert_eq!(write[12], 31 << 3);
    }

    #[test]
    fn prdt_splits_at_four_mib_and_sets_zero_based_dbc() {
        let segment = DmaSegment {
            physical_address: 0x20_0000,
            length: PRDT_MAX_BYTES + 512,
        };
        let plan = build_prdt(&[segment], segment.length, true).unwrap();
        assert_eq!(plan.count, 2);
        assert_eq!(
            plan.entries[0],
            PrdtEntry {
                physical_address: 0x20_0000,
                length: PRDT_MAX_BYTES,
            }
        );
        assert_eq!(plan.entries[1].physical_address, 0x60_0000);
        assert_eq!(plan.entries[1].length, 512);
        assert_eq!(prdt_dbc(1), Ok(0));
        assert_eq!(prdt_dbc(PRDT_MAX_BYTES), Ok(PRDT_MAX_BYTES - 1));
        assert_eq!(prdt_dbc(0), Err(AhciError::InvalidTransfer));
        assert_eq!(
            prdt_dbc(PRDT_MAX_BYTES + 1),
            Err(AhciError::InvalidTransfer)
        );
    }

    #[test]
    fn prdt_rejects_more_than_32_entries() {
        let segment = DmaSegment {
            physical_address: 0x1000,
            length: PRDT_MAX_BYTES,
        };
        let segments = [segment; MAX_PRDT_ENTRIES];
        let total = PRDT_MAX_BYTES * MAX_PRDT_ENTRIES as u32;
        assert_eq!(build_prdt(&segments, total, true).unwrap().count, 32);
        let oversized = DmaSegment {
            physical_address: 0x1000,
            length: PRDT_MAX_BYTES + 1,
        };
        let mut too_many = segments;
        too_many[0] = oversized;
        assert_eq!(
            build_prdt(&too_many, total + 1, true),
            Err(AhciError::TooManyPrdtEntries)
        );
    }

    #[test]
    fn dma32_checks_the_inclusive_end() {
        assert_eq!(
            validate_dma_range(u64::from(u32::MAX), 1, false),
            Ok(u64::from(u32::MAX))
        );
        assert_eq!(
            validate_dma_range(u64::from(u32::MAX), 2, false),
            Err(AhciError::UnsupportedDmaAddress)
        );
        assert_eq!(
            validate_dma_range(u64::MAX, 2, true),
            Err(AhciError::AddressOverflow)
        );
    }

    #[test]
    fn slots_complete_out_of_order_from_sact_and_ci() {
        let issued = 0b10111;
        assert_eq!(completed_slots(issued, 0b10001, 0), 0b00110);
        assert_eq!(completed_slots(issued, 0b00100, 0b10000), 0b00011);
        assert_eq!(completed_slots(issued, 0, 0), issued);
    }

    #[test]
    fn reset_proof_never_releases_before_cr_then_fr_stop() {
        let (state, release) =
            advance_reset_proof(ResetProofState::WaitingForCr, PORT_CMD_CR | PORT_CMD_FR);
        assert_eq!(state, ResetProofState::WaitingForCr);
        assert!(!release);
        let (state, release) = advance_reset_proof(state, PORT_CMD_FR);
        assert_eq!(state, ResetProofState::WaitingForFr);
        assert!(!release);
        let (state, release) = advance_reset_proof(state, PORT_CMD_FR);
        assert_eq!(state, ResetProofState::WaitingForFr);
        assert!(!release);
        let (state, release) = advance_reset_proof(state, 0);
        assert_eq!(state, ResetProofState::Proved);
        assert!(release);
    }

    #[test]
    fn transfer_range_checks_alignment_overflow_and_capacity() {
        assert_eq!(
            transfer_range(7, 1024, 10),
            Ok(TransferRange {
                first_sector: 7,
                sector_count: 2,
            })
        );
        assert_eq!(transfer_range(0, 1, 10), Err(AhciError::Misaligned));
        assert_eq!(transfer_range(9, 1024, 10), Err(AhciError::OutOfBounds));
        assert_eq!(
            transfer_range(u64::MAX, 512, u64::MAX),
            Err(AhciError::AddressOverflow)
        );
    }
}
