//! Legacy PCI configuration-space discovery for x86_64.
//!
//! This module uses PCI configuration mechanism #1 (`0xcf8`/`0xcfc`).  It is
//! intentionally small: GinkgoOS currently needs it only to claim an xHCI
//! controller before a more general PCI subsystem exists.

use crate::io::{IoError, PortRegion};

const CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
const CONFIG_PORT_COUNT: u16 = 8;
const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciError {
    Io(IoError),
    DeviceNotPresent,
    InvalidRegister,
    InvalidBar,
    UnsupportedIoBar,
    BarSizeOverflow,
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

    /// Finds the first xHCI controller, correctly limiting single-function
    /// devices to function zero while scanning all functions of multifunction
    /// devices.
    pub fn find_xhci(&mut self) -> Result<Option<PciDevice>, PciError> {
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
                if first.class == 0x0c
                    && first.subclass == 0x03
                    && first.programming_interface == 0x30
                {
                    return Ok(Some(first));
                }

                if first.header_type & 0x80 == 0 {
                    continue;
                }
                for function in 1_u8..8 {
                    let address = PciAddress {
                        bus: bus as u8,
                        device,
                        function,
                    };
                    let Some(candidate) = self.device(address)? else {
                        continue;
                    };
                    if candidate.class == 0x0c
                        && candidate.subclass == 0x03
                        && candidate.programming_interface == 0x30
                    {
                        return Ok(Some(candidate));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Probes BAR0 and restores every configuration register it changes.
    /// Memory decoding is temporarily disabled while the BAR size mask is read.
    pub fn probe_bar0(&mut self, device: PciDevice) -> Result<PciBar, PciError> {
        if device.header_type & 0x7f != 0 {
            return Err(PciError::InvalidBar);
        }

        let command = self.read_u16(device.address, 0x04)?;
        self.write_u16(device.address, 0x04, command & !COMMAND_MEMORY_SPACE)?;

        let result = self.probe_bar0_inner(device.address);

        // Restore decode state even when probing found an invalid BAR.
        let restore = self.write_u16(device.address, 0x04, command);
        match (result, restore) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(bar), Ok(())) => Ok(bar),
        }
    }

    fn probe_bar0_inner(&mut self, address: PciAddress) -> Result<PciBar, PciError> {
        let low = self.read_u32(address, 0x10)?;
        if low == 0 || low == u32::MAX {
            return Err(PciError::InvalidBar);
        }
        if low & 1 != 0 {
            return Err(PciError::UnsupportedIoBar);
        }

        let kind = (low >> 1) & 3;
        if kind != 0 && kind != 2 {
            return Err(PciError::InvalidBar);
        }
        let is_64_bit = kind == 2;
        let high = if is_64_bit {
            self.read_u32(address, 0x14)?
        } else {
            0
        };

        self.write_u32(address, 0x10, u32::MAX)?;
        if is_64_bit {
            if let Err(error) = self.write_u32(address, 0x14, u32::MAX) {
                if let Err(restore_error) = self.write_u32(address, 0x10, low) {
                    return Err(restore_error);
                }
                return Err(error);
            }
        }
        let mask_low_result = self.read_u32(address, 0x10);
        let mask_high_result = if is_64_bit {
            self.read_u32(address, 0x14)
        } else {
            Ok(0)
        };

        // BAR contents must be restored before interpreting a failed read.
        let restore_low = self.write_u32(address, 0x10, low);
        let restore_high = if is_64_bit {
            self.write_u32(address, 0x14, high)
        } else {
            Ok(())
        };
        let mask_low = mask_low_result?;
        let mask_high = mask_high_result?;
        restore_low?;
        restore_high?;

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

    #[test]
    fn bar_size_masks_use_the_correct_address_width() {
        assert_eq!(memory_bar_size(0xffff_c000, 0, false), Ok(0x4000));
        assert_eq!(
            memory_bar_size(0xff00_0000, 0xffff_ffff, true),
            Ok(0x0100_0000)
        );
    }
}
