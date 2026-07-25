//! Legacy PCI configuration-space discovery for x86_64.
//!
//! This module uses PCI configuration mechanism #1 (`0xcf8`/`0xcfc`) to find
//! devices by class, configure their memory BARs, and safely walk conventional
//! capability lists. MSI configuration is deliberately limited to one fixed,
//! edge-triggered vector addressed to one xAPIC ID.

use crate::io::{IoError, PortRegion};

const CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
const CONFIG_PORT_COUNT: u16 = 8;
const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
const CAPABILITY_POINTER: u8 = 0x34;
const CARDBUS_CAPABILITY_POINTER: u8 = 0x14;
const CAPABILITY_MIN_OFFSET: u8 = 0x40;
const CAPABILITY_MAX_OFFSET: u8 = 0xfc;
const CAPABILITY_SLOT_COUNT: usize = 48;
const MSI_CAPABILITY_ID: u8 = 0x05;
const MSI_ENABLE: u16 = 1;
const MSI_MULTIPLE_MESSAGE_ENABLE: u16 = 0b111 << 4;
const MSI_64_BIT_CAPABLE: u16 = 1 << 7;
const MSI_PER_VECTOR_MASKING_CAPABLE: u16 = 1 << 8;
const MSI_ADDRESS_BASE: u32 = 0xfee0_0000;
const MSIX_CAPABILITY_ID: u8 = 0x11;
const MSIX_TABLE_SIZE: u16 = 0x07ff;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_WRITABLE_CONTROL: u16 = MSIX_FUNCTION_MASK | MSIX_ENABLE;
const MSIX_TABLE_ENTRY_SIZE: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciError {
    Io(IoError),
    DeviceNotPresent,
    CommandStateMismatch,
    InvalidRegister,
    InvalidBar,
    UnsupportedIoBar,
    BarSizeOverflow,
    MalformedCapabilityList,
    MsiCapabilityNotPresent,
    InvalidMsiVector,
}

impl From<IoError> for PciError {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Self> {
        if device < 32 && function < 8 {
            Some(Self {
                bus,
                device,
                function,
            })
        } else {
            None
        }
    }

    fn mechanism_one_address(self, register: u8) -> Result<u32, PciError> {
        if register & 3 != 0 || register > 0xfc {
            return Err(PciError::InvalidRegister);
        }
        Ok(0x8000_0000
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device) << 11)
            | (u32::from(self.function) << 8)
            | u32::from(register))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciBar {
    pub physical_address: u64,
    pub size: u64,
    pub is_64_bit: bool,
    pub prefetchable: bool,
}

/// The locations described by a conventional PCI MSI-X capability.
///
/// BAR indices identify configuration-space BARs; offsets are relative to the
/// corresponding BAR. This module does not probe or map either BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciMsixCapability {
    pub capability_offset: u8,
    pub table_size: u16,
    pub table_bar: u8,
    pub table_offset: u32,
    pub pba_bar: u8,
    pub pba_offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    pub header_type: u8,
}

/// Exclusive access to PCI configuration mechanism #1.
///
/// Only one instance may exist because every transaction shares the address
/// latch at `0xcf8`.
pub struct PciConfig {
    ports: PortRegion,
}

impl PciConfig {
    /// Claims the mechanism #1 ports.
    ///
    /// # Safety
    ///
    /// The caller must run at an I/O privilege level that permits port I/O and
    /// must ensure no other code accesses PCI mechanism #1 while this value is
    /// alive.
    pub unsafe fn new() -> Result<Self, PciError> {
        let ports = PortRegion::new(CONFIG_ADDRESS_PORT, CONFIG_PORT_COUNT)
            .ok_or(PciError::InvalidRegister)?;
        Ok(Self { ports })
    }

    pub fn read_u32(&mut self, address: PciAddress, register: u8) -> Result<u32, PciError> {
        self.ports
            .write_u32(0, address.mechanism_one_address(register)?)?;
        Ok(self.ports.read_u32(4)?)
    }

    pub fn write_u32(
        &mut self,
        address: PciAddress,
        register: u8,
        value: u32,
    ) -> Result<(), PciError> {
        self.ports
            .write_u32(0, address.mechanism_one_address(register)?)?;
        self.ports.write_u32(4, value)?;
        Ok(())
    }

    pub fn read_u16(&mut self, address: PciAddress, register: u8) -> Result<u16, PciError> {
        if register & 1 != 0 || register > 0xfe {
            return Err(PciError::InvalidRegister);
        }
        let aligned = register & !3;
        let shift = u32::from(register & 2) * 8;
        Ok((self.read_u32(address, aligned)? >> shift) as u16)
    }

    pub fn write_u16(
        &mut self,
        address: PciAddress,
        register: u8,
        value: u16,
    ) -> Result<(), PciError> {
        if register & 1 != 0 || register > 0xfe {
            return Err(PciError::InvalidRegister);
        }
        self.ports
            .write_u32(0, address.mechanism_one_address(register & !3)?)?;
        self.ports.write_u16(4 + u16::from(register & 2), value)?;
        Ok(())
    }

    fn read_u8(&mut self, address: PciAddress, register: u8) -> Result<u8, PciError> {
        let aligned = register & !3;
        let shift = u32::from(register & 3) * 8;
        Ok((self.read_u32(address, aligned)? >> shift) as u8)
    }

    pub fn device(&mut self, address: PciAddress) -> Result<Option<PciDevice>, PciError> {
        let id = self.read_u32(address, 0x00)?;
        let vendor_id = id as u16;
        if vendor_id == 0xffff {
            return Ok(None);
        }
        let class = self.read_u32(address, 0x08)?;
        let header = self.read_u32(address, 0x0c)?;
        Ok(Some(PciDevice {
            address,
            vendor_id,
            device_id: (id >> 16) as u16,
            revision: class as u8,
            programming_interface: (class >> 8) as u8,
            subclass: (class >> 16) as u8,
            class: (class >> 24) as u8,
            header_type: (header >> 16) as u8,
        }))
    }

    /// Finds the first device matching a class tuple in deterministic
    /// bus/device/function order.
    ///
    /// Function zero determines whether functions 1 through 7 are scanned, as
    /// required for PCI multifunction devices.
    pub fn find_first(
        &mut self,
        class: u8,
        subclass: u8,
        programming_interface: Option<u8>,
    ) -> Result<Option<PciDevice>, PciError> {
        for bus in 0_u16..=255 {
            for device in 0_u8..32 {
                let function_zero = PciAddress {
                    bus: bus as u8,
                    device,
                    function: 0,
                };
                let Some(first) = self.device(function_zero)? else {
                    continue;
                };
                if device_matches(first, class, subclass, programming_interface) {
                    return Ok(Some(first));
                }

                for function in 1..function_count(first.header_type) {
                    let address = PciAddress {
                        bus: bus as u8,
                        device,
                        function,
                    };
                    let Some(candidate) = self.device(address)? else {
                        continue;
                    };
                    if device_matches(candidate, class, subclass, programming_interface) {
                        return Ok(Some(candidate));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Finds the first xHCI controller.
    pub fn find_xhci(&mut self) -> Result<Option<PciDevice>, PciError> {
        self.find_first(0x0c, 0x03, Some(0x30))
    }

    /// Probes a memory BAR and restores every configuration register it changes.
    ///
    /// BAR indices are validated against the device's PCI header type. Memory
    /// decoding is temporarily disabled while the BAR size mask is read.
    pub fn probe_bar(&mut self, device: PciDevice, index: u8) -> Result<PciBar, PciError> {
        let (register, has_upper_register) = memory_bar_register(device.header_type, index)?;

        // An upper half is not independently probeable as a BAR.
        if index > 0 {
            let previous = self.read_u32(device.address, register - 4)?;
            if is_64_bit_memory_bar(previous) {
                return Err(PciError::InvalidBar);
            }
        }

        let command = self.read_u16(device.address, 0x04)?;
        self.write_u16(device.address, 0x04, command & !COMMAND_MEMORY_SPACE)?;

        let result = self.probe_bar_inner(device.address, register, has_upper_register);

        // Restore decode state even when probing found an invalid BAR.
        let restore = self.write_u16(device.address, 0x04, command);
        match (result, restore) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(bar), Ok(())) => Ok(bar),
        }
    }

    /// Compatibility wrapper for probing BAR0.
    pub fn probe_bar0(&mut self, device: PciDevice) -> Result<PciBar, PciError> {
        self.probe_bar(device, 0)
    }

    fn probe_bar_inner(
        &mut self,
        address: PciAddress,
        register: u8,
        has_upper_register: bool,
    ) -> Result<PciBar, PciError> {
        let low = self.read_u32(address, register)?;
        if low & 1 != 0 {
            return Err(PciError::UnsupportedIoBar);
        }

        let kind = (low >> 1) & 3;
        if kind != 0 && kind != 2 {
            return Err(PciError::InvalidBar);
        }
        let is_64_bit = kind == 2;
        if is_64_bit && !has_upper_register {
            return Err(PciError::InvalidBar);
        }
        let high = if is_64_bit {
            self.read_u32(address, register + 4)?
        } else {
            0
        };

        self.write_u32(address, register, u32::MAX)?;
        if is_64_bit {
            if let Err(error) = self.write_u32(address, register + 4, u32::MAX) {
                let restore_high = self.write_u32(address, register + 4, high);
                let restore_low = self.write_u32(address, register, low);
                restore_high?;
                restore_low?;
                return Err(error);
            }
        }
        let mask_low_result = self.read_u32(address, register);
        let mask_high_result = if is_64_bit {
            self.read_u32(address, register + 4)
        } else {
            Ok(0)
        };

        // BAR contents must be restored before interpreting a failed read.
        let restore_high = if is_64_bit {
            self.write_u32(address, register + 4, high)
        } else {
            Ok(())
        };
        let restore_low = self.write_u32(address, register, low);
        let mask_low = mask_low_result?;
        let mask_high = mask_high_result?;
        restore_high?;
        restore_low?;

        let physical_address = if is_64_bit {
            (u64::from(high) << 32) | u64::from(low & 0xffff_fff0)
        } else {
            u64::from(low & 0xffff_fff0)
        };
        let size = memory_bar_size(mask_low, mask_high, is_64_bit)?;
        if size == 0 || !size.is_power_of_two() || physical_address & (size - 1) != 0 {
            return Err(PciError::InvalidBar);
        }

        Ok(PciBar {
            physical_address,
            size,
            is_64_bit,
            prefetchable: low & (1 << 3) != 0,
        })
    }

    /// Enables or disables PCI bus mastering without changing other command bits.
    ///
    /// The requested state is read back from the command register so a device
    /// that rejects the update is reported to the caller.
    pub fn set_bus_mastering(&mut self, device: PciDevice, enabled: bool) -> Result<(), PciError> {
        let command = self.read_u16(device.address, 0x04)?;
        let updated = command_with_bus_mastering(command, enabled);
        if updated != command {
            self.write_u16(device.address, 0x04, updated)?;
        }
        let readback = self.read_u16(device.address, 0x04)?;
        if bus_mastering_matches(readback, enabled) {
            Ok(())
        } else {
            Err(PciError::CommandStateMismatch)
        }
    }

    pub fn enable_memory_and_bus_mastering(&mut self, device: PciDevice) -> Result<(), PciError> {
        let command = self.read_u16(device.address, 0x04)?;
        self.write_u16(device.address, 0x04, command | COMMAND_MEMORY_SPACE)?;
        self.set_bus_mastering(device, true)
    }

    /// Finds a conventional PCI capability while bounding and validating the list.
    ///
    /// Every pointer must name an aligned dword in `0x40..=0xfc`. Cycles,
    /// overlong chains, unsupported header layouts, and a set capabilities-status
    /// bit with a null head are reported as malformed instead of being followed.
    pub fn find_capability(
        &mut self,
        device: PciDevice,
        capability_id: u8,
    ) -> Result<Option<u8>, PciError> {
        let status = self.read_u16(device.address, 0x06)?;
        if status & STATUS_CAPABILITIES_LIST == 0 {
            return Ok(None);
        }
        let pointer_register = match device.header_type & 0x7f {
            0 | 1 => CAPABILITY_POINTER,
            2 => CARDBUS_CAPABILITY_POINTER,
            _ => return Err(PciError::MalformedCapabilityList),
        };
        let first = self.read_u8(device.address, pointer_register)?;
        find_capability_in_list(first, capability_id, |offset| {
            self.read_u32(device.address, offset)
        })
    }

    /// Finds and parses the conventional MSI-X capability for `device`.
    ///
    /// The capability must fit in conventional configuration space. Both BIRs
    /// must name BARs present in the device's header layout, and the complete
    /// table and pending-bit array must fit in 32-bit BAR-relative arithmetic.
    /// Overlapping structures in one BAR are rejected. The BARs are not probed
    /// or mapped by this method.
    pub fn find_msix_capability(
        &mut self,
        device: PciDevice,
    ) -> Result<Option<PciMsixCapability>, PciError> {
        let Some(capability_offset) = self.find_capability(device, MSIX_CAPABILITY_ID)? else {
            return Ok(None);
        };
        let registers = msix_registers(capability_offset)?;
        let control = self.read_u16(device.address, registers.control)?;
        let table = self.read_u32(device.address, registers.table)?;
        let pba = self.read_u32(device.address, registers.pba)?;
        parse_msix_capability(device.header_type, capability_offset, control, table, pba).map(Some)
    }

    /// Updates MSI-X enable and function-mask state without changing other bits.
    ///
    /// If the enable state changes, the function mask is asserted first. Thus a
    /// failed final write leaves the function masked. Read-only table-size bits
    /// and reserved control bits are copied from the value read from hardware.
    /// Callers must initialize and mask individual table entries before asking
    /// for an enabled, unmasked function.
    pub fn set_msix_control(
        &mut self,
        device: PciDevice,
        capability: PciMsixCapability,
        enabled: bool,
        function_masked: bool,
    ) -> Result<(), PciError> {
        let registers = msix_registers(capability.capability_offset)?;
        let header = self.read_u32(device.address, capability.capability_offset)?;
        if header as u8 != MSIX_CAPABILITY_ID {
            return Err(PciError::MalformedCapabilityList);
        }

        let control = self.read_u16(device.address, registers.control)?;
        let (transition, final_control) = msix_control_values(control, enabled, function_masked);
        if let Some(masked_control) = transition {
            self.write_u16(device.address, registers.control, masked_control)?;
        }
        self.write_u16(device.address, registers.control, final_control)
    }

    /// Disables conventional MSI for `device` without changing other control bits.
    ///
    /// If the capability supports per-vector masking, every vector is masked
    /// before MSI is disabled. A failed final write therefore leaves interrupts
    /// masked.
    pub fn disable_msi(&mut self, device: PciDevice) -> Result<(), PciError> {
        let capability = self
            .find_capability(device, MSI_CAPABILITY_ID)?
            .ok_or(PciError::MsiCapabilityNotPresent)?;
        let control_register = msi_control_register(capability)?;
        let control = self.read_u16(device.address, control_register)?;
        let registers = msi_registers(capability, control)?;

        if let Some(mask_bits) = registers.mask_bits {
            self.write_u32(device.address, mask_bits, u32::MAX)?;
        }
        self.write_u16(
            device.address,
            control_register,
            msi_disabled_control(control),
        )
    }

    /// Programs one fixed, edge-triggered MSI message for `device`.
    ///
    /// `destination_apic_id` is the eight-bit xAPIC ID and `vector` must be in
    /// `0x20..=0xfe`. Multiple-message enable is cleared even if the capability
    /// advertises more vectors. The capability is disabled before its address and
    /// data are changed and enabled only after all writes succeed.
    pub fn configure_msi(
        &mut self,
        device: PciDevice,
        destination_apic_id: u8,
        vector: u8,
    ) -> Result<(), PciError> {
        if !(0x20..=0xfe).contains(&vector) {
            return Err(PciError::InvalidMsiVector);
        }
        let capability = self
            .find_capability(device, MSI_CAPABILITY_ID)?
            .ok_or(PciError::MsiCapabilityNotPresent)?;
        let control_register = msi_control_register(capability)?;
        let control = self.read_u16(device.address, control_register)?;
        let registers = msi_registers(capability, control)?;
        let disabled_control = control & !(MSI_ENABLE | MSI_MULTIPLE_MESSAGE_ENABLE);

        self.write_u16(device.address, control_register, disabled_control)?;
        self.write_u32(
            device.address,
            registers.address_low,
            MSI_ADDRESS_BASE | (u32::from(destination_apic_id) << 12),
        )?;
        if let Some(address_high) = registers.address_high {
            self.write_u32(device.address, address_high, 0)?;
        }
        self.write_u16(device.address, registers.message_data, u16::from(vector))?;
        if let Some(mask_bits) = registers.mask_bits {
            let current_mask = self.read_u32(device.address, mask_bits)?;
            self.write_u32(
                device.address,
                mask_bits,
                msi_mask_with_vector_zero_enabled(current_mask),
            )?;
        }
        self.write_u16(
            device.address,
            control_register,
            disabled_control | MSI_ENABLE,
        )
    }
}

fn find_capability_in_list<F>(
    first: u8,
    capability_id: u8,
    mut read: F,
) -> Result<Option<u8>, PciError>
where
    F: FnMut(u8) -> Result<u32, PciError>,
{
    if first == 0 {
        return Err(PciError::MalformedCapabilityList);
    }

    let mut visited = 0_u64;
    let mut pointer = first;
    for _ in 0..CAPABILITY_SLOT_COUNT {
        if pointer < CAPABILITY_MIN_OFFSET || pointer > CAPABILITY_MAX_OFFSET || pointer & 3 != 0 {
            return Err(PciError::MalformedCapabilityList);
        }
        let slot = usize::from((pointer - CAPABILITY_MIN_OFFSET) / 4);
        let bit = 1_u64 << slot;
        if visited & bit != 0 {
            return Err(PciError::MalformedCapabilityList);
        }
        visited |= bit;

        let header = read(pointer)?;
        if header as u8 == capability_id {
            return Ok(Some(pointer));
        }
        pointer = (header >> 8) as u8;
        if pointer == 0 {
            return Ok(None);
        }
    }
    Err(PciError::MalformedCapabilityList)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsixRegisters {
    control: u8,
    table: u8,
    pba: u8,
}

fn msix_registers(capability: u8) -> Result<MsixRegisters, PciError> {
    if capability < CAPABILITY_MIN_OFFSET || capability & 3 != 0 {
        return Err(PciError::MalformedCapabilityList);
    }
    let control = capability
        .checked_add(2)
        .filter(|offset| *offset <= 0xfe)
        .ok_or(PciError::MalformedCapabilityList)?;
    let table = capability
        .checked_add(4)
        .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET)
        .ok_or(PciError::MalformedCapabilityList)?;
    let pba = capability
        .checked_add(8)
        .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET)
        .ok_or(PciError::MalformedCapabilityList)?;
    Ok(MsixRegisters {
        control,
        table,
        pba,
    })
}

fn parse_msix_capability(
    header_type: u8,
    capability_offset: u8,
    control: u16,
    table: u32,
    pba: u32,
) -> Result<PciMsixCapability, PciError> {
    msix_registers(capability_offset)?;

    let table_size = (control & MSIX_TABLE_SIZE) + 1;
    let table_bytes = u32::from(table_size) * MSIX_TABLE_ENTRY_SIZE;
    let pba_bytes = ((u32::from(table_size) + 63) / 64) * 8;
    let (table_bar, table_offset, table_end) = msix_region(header_type, table, table_bytes)?;
    let (pba_bar, pba_offset, pba_end) = msix_region(header_type, pba, pba_bytes)?;

    if table_bar == pba_bar && table_offset <= pba_end && pba_offset <= table_end {
        return Err(PciError::MalformedCapabilityList);
    }

    Ok(PciMsixCapability {
        capability_offset,
        table_size,
        table_bar,
        table_offset,
        pba_bar,
        pba_offset,
    })
}

fn msix_region(header_type: u8, value: u32, size: u32) -> Result<(u8, u32, u32), PciError> {
    let bar = (value & 0b111) as u8;
    memory_bar_register(header_type, bar)?;
    let offset = value & !0b111;
    let end = offset
        .checked_add(size - 1)
        .ok_or(PciError::MalformedCapabilityList)?;
    Ok((bar, offset, end))
}

fn msix_control_values(control: u16, enabled: bool, function_masked: bool) -> (Option<u16>, u16) {
    let preserved = control & !MSIX_WRITABLE_CONTROL;
    let final_control = preserved
        | if enabled { MSIX_ENABLE } else { 0 }
        | if function_masked {
            MSIX_FUNCTION_MASK
        } else {
            0
        };
    let enable_changes = control & MSIX_ENABLE != final_control & MSIX_ENABLE;
    let transition = enable_changes.then_some(control | MSIX_FUNCTION_MASK);
    (transition, final_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MsiRegisters {
    address_low: u8,
    address_high: Option<u8>,
    message_data: u8,
    mask_bits: Option<u8>,
}

fn msi_control_register(capability: u8) -> Result<u8, PciError> {
    capability
        .checked_add(2)
        .filter(|offset| *offset <= 0xfe)
        .ok_or(PciError::MalformedCapabilityList)
}

fn msi_registers(capability: u8, control: u16) -> Result<MsiRegisters, PciError> {
    let address_low = capability
        .checked_add(4)
        .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET)
        .ok_or(PciError::MalformedCapabilityList)?;
    let is_64_bit = control & MSI_64_BIT_CAPABLE != 0;
    let address_high = is_64_bit
        .then(|| capability.checked_add(8))
        .flatten()
        .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET);
    if is_64_bit && address_high.is_none() {
        return Err(PciError::MalformedCapabilityList);
    }
    let message_data = capability
        .checked_add(if is_64_bit { 12 } else { 8 })
        .filter(|offset| *offset <= 0xfe)
        .ok_or(PciError::MalformedCapabilityList)?;
    let mask_bits = if control & MSI_PER_VECTOR_MASKING_CAPABLE != 0 {
        let mask_bits = capability
            .checked_add(if is_64_bit { 16 } else { 12 })
            .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET)
            .ok_or(PciError::MalformedCapabilityList)?;
        capability
            .checked_add(if is_64_bit { 20 } else { 16 })
            .filter(|offset| *offset <= CAPABILITY_MAX_OFFSET)
            .ok_or(PciError::MalformedCapabilityList)?;
        Some(mask_bits)
    } else {
        None
    };
    Ok(MsiRegisters {
        address_low,
        address_high,
        message_data,
        mask_bits,
    })
}

fn command_with_bus_mastering(command: u16, enabled: bool) -> u16 {
    if enabled {
        command | COMMAND_BUS_MASTER
    } else {
        command & !COMMAND_BUS_MASTER
    }
}

fn bus_mastering_matches(command: u16, enabled: bool) -> bool {
    (command & COMMAND_BUS_MASTER != 0) == enabled
}

fn msi_disabled_control(control: u16) -> u16 {
    control & !MSI_ENABLE
}

const fn msi_mask_with_vector_zero_enabled(mask: u32) -> u32 {
    mask & !1
}

fn device_matches(
    device: PciDevice,
    class: u8,
    subclass: u8,
    programming_interface: Option<u8>,
) -> bool {
    device.class == class
        && device.subclass == subclass
        && programming_interface.is_none_or(|interface| device.programming_interface == interface)
}

fn function_count(header_type: u8) -> u8 {
    if header_type & 0x80 != 0 {
        8
    } else {
        1
    }
}

fn memory_bar_register(header_type: u8, index: u8) -> Result<(u8, bool), PciError> {
    let count = match header_type & 0x7f {
        0 => 6,
        1 => 2,
        _ => return Err(PciError::InvalidBar),
    };
    if index >= count {
        return Err(PciError::InvalidBar);
    }

    Ok((0x10 + index * 4, index + 1 < count))
}

fn is_64_bit_memory_bar(value: u32) -> bool {
    value & 1 == 0 && (value >> 1) & 3 == 2
}

fn memory_bar_size(mask_low: u32, mask_high: u32, is_64_bit: bool) -> Result<u64, PciError> {
    if is_64_bit {
        let mask = (u64::from(mask_high) << 32) | u64::from(mask_low & 0xffff_fff0);
        if mask == 0 {
            return Err(PciError::InvalidBar);
        }
        (!mask).checked_add(1).ok_or(PciError::BarSizeOverflow)
    } else {
        let mask = mask_low & 0xffff_fff0;
        if mask == 0 {
            return Err(PciError::InvalidBar);
        }
        Ok(u64::from((!mask).wrapping_add(1)))
    }
}

/// Discovers and claims the first xHCI controller.
///
/// # Safety
///
/// The caller must have exclusive ownership of PCI mechanism #1 and must not
/// race another PCI enumerator or driver.
pub unsafe fn claim_xhci() -> Result<(PciDevice, PciBar), PciError> {
    let mut config = PciConfig::new()?;
    let device = config.find_xhci()?.ok_or(PciError::DeviceNotPresent)?;
    let bar = config.probe_bar0(device)?;
    config.enable_memory_and_bus_mastering(device)?;
    Ok((device, bar))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_one_address_encodes_bdf_and_register() {
        let address = PciAddress::new(0xab, 0x1c, 7).unwrap();
        assert_eq!(address.mechanism_one_address(0x3c), Ok(0x80ab_e73c));
        assert_eq!(
            address.mechanism_one_address(0x3d),
            Err(PciError::InvalidRegister)
        );
    }

    #[test]
    fn bdf_validation_rejects_out_of_range_fields() {
        assert!(PciAddress::new(0, 31, 7).is_some());
        assert!(PciAddress::new(0, 32, 0).is_none());
        assert!(PciAddress::new(0, 0, 8).is_none());
    }

    fn test_device(header_type: u8, class: u8, subclass: u8, interface: u8) -> PciDevice {
        PciDevice {
            address: PciAddress::new(0, 0, 0).unwrap(),
            vendor_id: 0x1234,
            device_id: 0x5678,
            revision: 0,
            class,
            subclass,
            programming_interface: interface,
            header_type,
        }
    }

    #[test]
    fn class_matching_can_ignore_or_require_programming_interface() {
        let audio = test_device(0, 0x04, 0x03, 0x80);
        assert!(device_matches(audio, 0x04, 0x03, None));
        assert!(device_matches(audio, 0x04, 0x03, Some(0x80)));
        assert!(!device_matches(audio, 0x04, 0x03, Some(0x00)));
        assert!(!device_matches(audio, 0x04, 0x01, None));
    }

    #[test]
    fn multifunction_bit_controls_function_scan_count() {
        assert_eq!(function_count(0x00), 1);
        assert_eq!(function_count(0x01), 1);
        assert_eq!(function_count(0x80), 8);
        assert_eq!(function_count(0x81), 8);
    }

    #[test]
    fn bar_registers_follow_header_layout() {
        assert_eq!(memory_bar_register(0x00, 0), Ok((0x10, true)));
        assert_eq!(memory_bar_register(0x80, 5), Ok((0x24, false)));
        assert_eq!(memory_bar_register(0x01, 1), Ok((0x14, false)));
        assert_eq!(memory_bar_register(0x01, 2), Err(PciError::InvalidBar));
        assert_eq!(memory_bar_register(0x02, 0), Err(PciError::InvalidBar));
    }

    #[test]
    fn memory_bar_type_recognizes_only_64_bit_memory_bars() {
        assert!(is_64_bit_memory_bar(0x0000_0004));
        assert!(is_64_bit_memory_bar(0x1234_500c));
        assert!(!is_64_bit_memory_bar(0x0000_0000));
        assert!(!is_64_bit_memory_bar(0x0000_0001));
    }

    #[test]
    fn bar_size_masks_use_the_correct_address_width() {
        assert_eq!(memory_bar_size(0xffff_c000, 0, false), Ok(0x4000));
        assert_eq!(
            memory_bar_size(0xff00_0000, 0xffff_ffff, true),
            Ok(0x0100_0000)
        );
        assert_eq!(memory_bar_size(0, 0, false), Err(PciError::InvalidBar));
        assert_eq!(memory_bar_size(0, 0, true), Err(PciError::InvalidBar));
    }

    fn capability_search(
        first: u8,
        entries: &[(u8, u8, u8)],
        id: u8,
    ) -> Result<Option<u8>, PciError> {
        find_capability_in_list(first, id, |offset| {
            entries
                .iter()
                .find(|entry| entry.0 == offset)
                .map(|entry| u32::from(entry.1) | (u32::from(entry.2) << 8))
                .ok_or(PciError::MalformedCapabilityList)
        })
    }

    #[test]
    fn bus_mastering_updates_only_its_command_bit() {
        let command = 0xa5a3;
        assert_eq!(
            command_with_bus_mastering(command, true),
            command | COMMAND_BUS_MASTER
        );
        assert_eq!(
            command_with_bus_mastering(command | COMMAND_BUS_MASTER, false),
            command
        );
        assert!(bus_mastering_matches(command | COMMAND_BUS_MASTER, true));
        assert!(bus_mastering_matches(command, false));
        assert!(!bus_mastering_matches(command, true));
    }

    #[test]
    fn capability_search_finds_entries_and_terminates_at_a_null_link() {
        let entries = [(0x40, 0x01, 0x4c), (0x4c, MSI_CAPABILITY_ID, 0)];
        assert_eq!(
            capability_search(0x40, &entries, MSI_CAPABILITY_ID),
            Ok(Some(0x4c))
        );
        assert_eq!(capability_search(0x40, &entries, 0x11), Ok(None));
    }

    #[test]
    fn capability_search_rejects_null_unaligned_out_of_range_and_cyclic_lists() {
        assert_eq!(
            capability_search(0, &[], MSI_CAPABILITY_ID),
            Err(PciError::MalformedCapabilityList)
        );
        for invalid in [0x3c, 0x41, 0xfd] {
            assert_eq!(
                capability_search(invalid, &[], MSI_CAPABILITY_ID),
                Err(PciError::MalformedCapabilityList)
            );
        }
        let cycle = [(0x40, 0x01, 0x48), (0x48, 0x02, 0x40)];
        assert_eq!(
            capability_search(0x40, &cycle, MSI_CAPABILITY_ID),
            Err(PciError::MalformedCapabilityList)
        );
        let malformed_link = [(0x40, 0x01, 0x42)];
        assert_eq!(
            capability_search(0x40, &malformed_link, MSI_CAPABILITY_ID),
            Err(PciError::MalformedCapabilityList)
        );
    }

    #[test]
    fn msix_parser_extracts_layout_and_decodes_table_size() {
        assert_eq!(
            parse_msix_capability(0x80, 0x40, 7, 0x0000_2002, 0x0000_3005),
            Ok(PciMsixCapability {
                capability_offset: 0x40,
                table_size: 8,
                table_bar: 2,
                table_offset: 0x2000,
                pba_bar: 5,
                pba_offset: 0x3000,
            })
        );
        assert_eq!(
            parse_msix_capability(0, 0xf4, MSIX_TABLE_SIZE, 0x0000_0000, 0x0000_8000)
                .unwrap()
                .table_size,
            2048
        );
    }

    #[test]
    fn msix_parser_rejects_incomplete_capabilities_and_invalid_birs() {
        assert_eq!(
            parse_msix_capability(0, 0xf8, 0, 0, 0x1000),
            Err(PciError::MalformedCapabilityList)
        );
        for (header_type, table) in [(0x00, 6), (0x01, 2), (0x02, 0)] {
            assert_eq!(
                parse_msix_capability(header_type, 0x40, 0, table, 0x1000),
                Err(PciError::InvalidBar)
            );
        }
    }

    #[test]
    fn msix_parser_checks_region_arithmetic_and_overlap() {
        assert!(parse_msix_capability(0, 0x40, 0, 0xffff_fff0, 0x1001).is_ok());
        assert_eq!(
            parse_msix_capability(0, 0x40, 0, 0xffff_fff8, 0x1001),
            Err(PciError::MalformedCapabilityList)
        );
        assert_eq!(
            parse_msix_capability(0, 0x40, 64, 0x1000, 0xffff_fff8),
            Err(PciError::MalformedCapabilityList)
        );
        assert_eq!(
            parse_msix_capability(0, 0x40, 3, 0x1000, 0x1020),
            Err(PciError::MalformedCapabilityList)
        );
    }

    #[test]
    fn msix_control_masks_transitions_and_preserves_other_bits() {
        let preserved = 0x2a55;
        assert_eq!(
            msix_control_values(preserved, true, false),
            (
                Some(preserved | MSIX_FUNCTION_MASK),
                preserved | MSIX_ENABLE
            )
        );

        let enabled = preserved | MSIX_ENABLE;
        assert_eq!(
            msix_control_values(enabled, false, false),
            (Some(enabled | MSIX_FUNCTION_MASK), preserved)
        );
        assert_eq!(
            msix_control_values(enabled, true, true),
            (None, enabled | MSIX_FUNCTION_MASK)
        );
    }

    #[test]
    fn msi_layout_accepts_complete_32_and_64_bit_capabilities_only() {
        assert_eq!(
            msi_registers(0x40, 0),
            Ok(MsiRegisters {
                address_low: 0x44,
                address_high: None,
                message_data: 0x48,
                mask_bits: None,
            })
        );
        assert_eq!(
            msi_registers(0x40, MSI_64_BIT_CAPABLE),
            Ok(MsiRegisters {
                address_low: 0x44,
                address_high: Some(0x48),
                message_data: 0x4c,
                mask_bits: None,
            })
        );
        assert_eq!(
            msi_registers(0xf8, 0),
            Err(PciError::MalformedCapabilityList)
        );
        assert_eq!(
            msi_registers(0xf4, MSI_64_BIT_CAPABLE),
            Err(PciError::MalformedCapabilityList)
        );
    }

    #[test]
    fn msi_layout_locates_complete_per_vector_mask_registers() {
        assert_eq!(
            msi_registers(0x40, MSI_PER_VECTOR_MASKING_CAPABLE)
                .unwrap()
                .mask_bits,
            Some(0x4c)
        );
        assert_eq!(
            msi_registers(0x40, MSI_64_BIT_CAPABLE | MSI_PER_VECTOR_MASKING_CAPABLE)
                .unwrap()
                .mask_bits,
            Some(0x50)
        );
        assert_eq!(
            msi_registers(0xf0, MSI_PER_VECTOR_MASKING_CAPABLE),
            Err(PciError::MalformedCapabilityList)
        );
        assert_eq!(
            msi_registers(0xec, MSI_64_BIT_CAPABLE | MSI_PER_VECTOR_MASKING_CAPABLE),
            Err(PciError::MalformedCapabilityList)
        );
    }

    #[test]
    fn disabling_msi_preserves_all_other_control_bits() {
        let control = 0xa5f1;
        assert_eq!(msi_disabled_control(control), control & !MSI_ENABLE);
    }

    #[test]
    fn enabling_one_msi_message_unmasks_only_vector_zero() {
        assert_eq!(msi_mask_with_vector_zero_enabled(u32::MAX), u32::MAX - 1);
        assert_eq!(msi_mask_with_vector_zero_enabled(0xa5a5_5a5b), 0xa5a5_5a5a);
    }
}
