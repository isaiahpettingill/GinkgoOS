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
const MSI_ADDRESS_BASE: u32 = 0xfee0_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciError {
    Io(IoError),
    DeviceNotPresent,
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

    pub fn enable_memory_and_bus_mastering(&mut self, device: PciDevice) -> Result<(), PciError> {
        let command = self.read_u16(device.address, 0x04)?;
        self.write_u16(
            device.address,
            0x04,
            command | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER,
        )
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
        let control_register = capability
            .checked_add(2)
            .ok_or(PciError::MalformedCapabilityList)?;
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
struct MsiRegisters {
    address_low: u8,
    address_high: Option<u8>,
    message_data: u8,
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
    Ok(MsiRegisters {
        address_low,
        address_high,
        message_data,
    })
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
    fn msi_layout_accepts_complete_32_and_64_bit_capabilities_only() {
        assert_eq!(
            msi_registers(0x40, 0),
            Ok(MsiRegisters {
                address_low: 0x44,
                address_high: None,
                message_data: 0x48,
            })
        );
        assert_eq!(
            msi_registers(0x40, MSI_64_BIT_CAPABLE),
            Ok(MsiRegisters {
                address_low: 0x44,
                address_high: Some(0x48),
                message_data: 0x4c,
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
}
