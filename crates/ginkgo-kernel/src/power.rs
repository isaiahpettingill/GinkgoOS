//! ACPI-backed machine reset and S5 soft-off.

extern crate alloc;

use acpi::{
    address::{AddressSpace, GenericAddress},
    aml::{namespace::AmlName, object::Object, Interpreter},
    registers::FixedRegisters,
    sdt::{fadt::Fadt, SdtHeader},
    AcpiTables, Handle, Handler, PhysicalMapping,
};
use alloc::{sync::Arc, vec};
use core::{
    mem,
    ptr::{self, NonNull},
    slice,
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
};
use x86_64::instructions::port::Port;

static NEXT_AML_MUTEX: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerError {
    MissingRsdp,
    InvalidAddress,
    Acpi,
    MissingFadt,
    MissingSleepState,
    UnsupportedAddressSpace,
    UnsupportedAccessWidth,
    ResetUnsupported,
}

#[derive(Clone)]
struct AcpiHandler {
    hhdm_offset: u64,
    tsc_frequency: u64,
}

impl AcpiHandler {
    fn virtual_address(&self, physical_address: usize) -> Option<usize> {
        usize::try_from(self.hhdm_offset)
            .ok()?
            .checked_add(physical_address)
    }

    fn pci_config_address(address: acpi::PciAddress, offset: u16) -> Option<u32> {
        (address.segment() == 0 && offset < 256).then(|| {
            0x8000_0000
                | (u32::from(address.bus()) << 16)
                | (u32::from(address.device()) << 11)
                | (u32::from(address.function()) << 8)
                | (u32::from(offset) & 0xfc)
        })
    }

    fn read_pci_config(&self, address: acpi::PciAddress, offset: u16) -> u32 {
        let Some(config_address) = Self::pci_config_address(address, offset) else {
            return u32::MAX;
        };
        unsafe {
            Port::<u32>::new(0xcf8).write(config_address);
            Port::<u32>::new(0xcfc).read()
        }
    }

    fn write_pci_config(&self, address: acpi::PciAddress, offset: u16, value: u32) {
        let Some(config_address) = Self::pci_config_address(address, offset) else {
            return;
        };
        unsafe {
            Port::<u32>::new(0xcf8).write(config_address);
            Port::<u32>::new(0xcfc).write(value);
        }
    }

    fn spin_ns(&self, duration_ns: u64) {
        if duration_ns == 0 || self.tsc_frequency == 0 {
            return;
        }
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let ticks = self
            .tsc_frequency
            .saturating_mul(duration_ns)
            .saturating_div(1_000_000_000);
        while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}

impl Handler for AcpiHandler {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        let virtual_address = self
            .virtual_address(physical_address)
            .expect("ACPI physical mapping address must fit the HHDM");
        let virtual_start = NonNull::new(virtual_address as *mut T)
            .expect("ACPI physical mapping cannot produce a null virtual address");
        PhysicalMapping {
            physical_start: physical_address,
            virtual_start,
            region_length: size,
            mapped_length: size,
            handler: self.clone(),
        }
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {}

    fn read_u8(&self, address: usize) -> u8 {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::read_volatile(address as *const u8) }
    }

    fn read_u16(&self, address: usize) -> u16 {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::read_volatile(address as *const u16) }
    }

    fn read_u32(&self, address: usize) -> u32 {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::read_volatile(address as *const u32) }
    }

    fn read_u64(&self, address: usize) -> u64 {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::read_volatile(address as *const u64) }
    }

    fn write_u8(&self, address: usize, value: u8) {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::write_volatile(address as *mut u8, value) }
    }

    fn write_u16(&self, address: usize, value: u16) {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::write_volatile(address as *mut u16, value) }
    }

    fn write_u32(&self, address: usize, value: u32) {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::write_volatile(address as *mut u32, value) }
    }

    fn write_u64(&self, address: usize, value: u64) {
        let address = self
            .virtual_address(address)
            .expect("ACPI memory address must fit HHDM");
        unsafe { ptr::write_volatile(address as *mut u64, value) }
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        unsafe { Port::<u8>::new(port).read() }
    }

    fn read_io_u16(&self, port: u16) -> u16 {
        unsafe { Port::<u16>::new(port).read() }
    }

    fn read_io_u32(&self, port: u16) -> u32 {
        unsafe { Port::<u32>::new(port).read() }
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        unsafe { Port::<u8>::new(port).write(value) }
    }

    fn write_io_u16(&self, port: u16, value: u16) {
        unsafe { Port::<u16>::new(port).write(value) }
    }

    fn write_io_u32(&self, port: u16, value: u32) {
        unsafe { Port::<u32>::new(port).write(value) }
    }

    fn read_pci_u8(&self, address: acpi::PciAddress, offset: u16) -> u8 {
        (self.read_pci_config(address, offset) >> (u32::from(offset & 3) * 8)) as u8
    }

    fn read_pci_u16(&self, address: acpi::PciAddress, offset: u16) -> u16 {
        (self.read_pci_config(address, offset) >> (u32::from(offset & 2) * 8)) as u16
    }

    fn read_pci_u32(&self, address: acpi::PciAddress, offset: u16) -> u32 {
        self.read_pci_config(address, offset)
    }

    fn write_pci_u8(&self, address: acpi::PciAddress, offset: u16, value: u8) {
        let shift = u32::from(offset & 3) * 8;
        let current = self.read_pci_config(address, offset);
        self.write_pci_config(
            address,
            offset,
            (current & !(0xff << shift)) | (u32::from(value) << shift),
        );
    }

    fn write_pci_u16(&self, address: acpi::PciAddress, offset: u16, value: u16) {
        let shift = u32::from(offset & 2) * 8;
        let current = self.read_pci_config(address, offset);
        self.write_pci_config(
            address,
            offset,
            (current & !(0xffff << shift)) | (u32::from(value) << shift),
        );
    }

    fn write_pci_u32(&self, address: acpi::PciAddress, offset: u16, value: u32) {
        self.write_pci_config(address, offset, value);
    }

    fn nanos_since_boot(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
            .saturating_mul(1_000_000_000)
            .saturating_div(self.tsc_frequency.max(1))
    }

    fn stall(&self, microseconds: u64) {
        self.spin_ns(microseconds.saturating_mul(1_000));
    }

    fn sleep(&self, milliseconds: u64) {
        self.spin_ns(milliseconds.saturating_mul(1_000_000));
    }

    fn create_mutex(&self) -> Handle {
        Handle(NEXT_AML_MUTEX.fetch_add(1, Ordering::Relaxed))
    }

    fn acquire(&self, _mutex: Handle, _timeout: u16) -> Result<(), acpi::aml::AmlError> {
        Ok(())
    }

    fn release(&self, _mutex: Handle) {}
}

pub struct AcpiPower {
    handler: AcpiHandler,
    pm1a_control: GenericAddress,
    pm1b_control: Option<GenericAddress>,
    sleep_type_a: u8,
    sleep_type_b: u8,
    reset_register: Option<GenericAddress>,
    reset_value: u8,
    smi_command_port: u32,
    acpi_enable: u8,
}

impl AcpiPower {
    /// Discovers reset and S5 information from the firmware ACPI namespace.
    ///
    /// `rsdp_address` is the virtual pointer returned by Limine.
    pub unsafe fn discover(
        rsdp_address: *mut u8,
        hhdm_offset: u64,
        tsc_frequency: u64,
    ) -> Result<Self, PowerError> {
        let rsdp_virtual = rsdp_address as usize;
        if rsdp_virtual == 0 {
            return Err(PowerError::MissingRsdp);
        }
        let hhdm = usize::try_from(hhdm_offset).map_err(|_| PowerError::InvalidAddress)?;
        let rsdp_physical = rsdp_virtual
            .checked_sub(hhdm)
            .ok_or(PowerError::InvalidAddress)?;
        let handler = AcpiHandler {
            hhdm_offset,
            tsc_frequency,
        };
        let tables = unsafe { AcpiTables::from_rsdp(handler.clone(), rsdp_physical) }
            .map_err(|_| PowerError::Acpi)?;
        let fadt = tables.find_table::<Fadt>().ok_or(PowerError::MissingFadt)?;
        fadt.validate().map_err(|_| PowerError::Acpi)?;

        let pm1a_control = fadt.pm1a_control_block().map_err(|_| PowerError::Acpi)?;
        let pm1b_control = fadt.pm1b_control_block().map_err(|_| PowerError::Acpi)?;
        validate_control_register(pm1a_control)?;
        if let Some(pm1b) = pm1b_control {
            validate_control_register(pm1b)?;
        }

        let registers =
            Arc::new(FixedRegisters::new(&fadt, handler.clone()).map_err(|_| PowerError::Acpi)?);
        let dsdt = tables.dsdt().map_err(|_| PowerError::Acpi)?;
        let interpreter = Interpreter::new(handler.clone(), dsdt.revision, registers, None);
        load_aml_table(&handler, &interpreter, dsdt.phys_address, dsdt.length)?;
        for ssdt in tables.ssdts() {
            load_aml_table(&handler, &interpreter, ssdt.phys_address, ssdt.length)?;
        }
        let s5 = interpreter
            .evaluate(
                AmlName::from_str("\\_S5").map_err(|_| PowerError::MissingSleepState)?,
                vec![],
            )
            .map_err(|_| PowerError::MissingSleepState)?;
        let Object::Package(package) = &*s5 else {
            return Err(PowerError::MissingSleepState);
        };
        let sleep_type_a = package
            .first()
            .ok_or(PowerError::MissingSleepState)?
            .as_integer()
            .map_err(|_| PowerError::MissingSleepState)? as u8;
        let sleep_type_b = package
            .get(1)
            .ok_or(PowerError::MissingSleepState)?
            .as_integer()
            .map_err(|_| PowerError::MissingSleepState)? as u8;
        if sleep_type_a > 7 || sleep_type_b > 7 {
            return Err(PowerError::MissingSleepState);
        }

        let flags = fadt.flags;
        let reset_register = if flags.supports_system_reset_via_fadt() {
            Some(fadt.reset_register().map_err(|_| PowerError::Acpi)?)
        } else {
            None
        };
        if let Some(reset) = reset_register {
            validate_gas(reset)?;
        }

        Ok(Self {
            handler,
            pm1a_control,
            pm1b_control,
            sleep_type_a,
            sleep_type_b,
            reset_register,
            reset_value: fadt.reset_value,
            smi_command_port: fadt.smi_cmd_port,
            acpi_enable: fadt.acpi_enable,
        })
    }

    pub const fn supports_power_off(&self) -> bool {
        true
    }

    pub const fn supports_reboot(&self) -> bool {
        self.reset_register.is_some()
    }

    pub const fn sleep_types(&self) -> (u8, u8) {
        (self.sleep_type_a, self.sleep_type_b)
    }

    pub const fn control_addresses(&self) -> (u64, Option<u64>) {
        (
            self.pm1a_control.address,
            match self.pm1b_control {
                Some(register) => Some(register.address),
                None => None,
            },
        )
    }

    pub fn power_off(&self) -> Result<(), PowerError> {
        self.ensure_acpi_mode()?;
        write_sleep_control(&self.handler, self.pm1a_control, self.sleep_type_a)?;
        if let Some(pm1b) = self.pm1b_control {
            write_sleep_control(&self.handler, pm1b, self.sleep_type_b)?;
        }
        Ok(())
    }

    pub fn reboot(&self) -> Result<(), PowerError> {
        let reset = self.reset_register.ok_or(PowerError::ResetUnsupported)?;
        write_gas(&self.handler, reset, u64::from(self.reset_value))
    }

    fn ensure_acpi_mode(&self) -> Result<(), PowerError> {
        if read_gas(&self.handler, self.pm1a_control)? & 1 != 0 {
            return Ok(());
        }
        let port = u16::try_from(self.smi_command_port).map_err(|_| PowerError::InvalidAddress)?;
        if port == 0 || self.acpi_enable == 0 {
            return Err(PowerError::Acpi);
        }
        self.handler.write_io_u8(port, self.acpi_enable);
        for _ in 0..30_000 {
            if read_gas(&self.handler, self.pm1a_control)? & 1 != 0 {
                return Ok(());
            }
            self.handler.stall(100);
        }
        Err(PowerError::Acpi)
    }
}

fn load_aml_table(
    handler: &AcpiHandler,
    interpreter: &Interpreter<AcpiHandler>,
    physical_address: usize,
    length: u32,
) -> Result<(), PowerError> {
    let length = usize::try_from(length).map_err(|_| PowerError::InvalidAddress)?;
    if length < mem::size_of::<SdtHeader>() {
        return Err(PowerError::Acpi);
    }
    let mapping = unsafe { handler.map_physical_region::<SdtHeader>(physical_address, length) };
    let aml = unsafe {
        slice::from_raw_parts(
            mapping
                .virtual_start
                .as_ptr()
                .cast::<u8>()
                .add(mem::size_of::<SdtHeader>()),
            length - mem::size_of::<SdtHeader>(),
        )
    };
    interpreter.load_table(aml).map_err(|_| PowerError::Acpi)
}

fn validate_control_register(register: GenericAddress) -> Result<(), PowerError> {
    validate_gas(register)?;
    if register.bit_width < 16 || register.bit_offset != 0 {
        return Err(PowerError::UnsupportedAccessWidth);
    }
    Ok(())
}

fn validate_gas(register: GenericAddress) -> Result<(), PowerError> {
    if register.address == 0 || register.bit_offset != 0 {
        return Err(PowerError::InvalidAddress);
    }
    let access_bytes = match register.bit_width {
        8 => 1_u64,
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err(PowerError::UnsupportedAccessWidth),
    };
    let declared_access_bytes = match register.access_size {
        0 => access_bytes,
        1 => 1,
        2 => 2,
        3 => 4,
        4 => 8,
        _ => return Err(PowerError::UnsupportedAccessWidth),
    };
    if declared_access_bytes != access_bytes || register.address % access_bytes != 0 {
        return Err(PowerError::UnsupportedAccessWidth);
    }
    match register.address_space {
        AddressSpace::SystemMemory => Ok(()),
        AddressSpace::SystemIo
            if access_bytes <= 4
                && register
                    .address
                    .checked_add(access_bytes - 1)
                    .is_some_and(|end| end <= u64::from(u16::MAX)) =>
        {
            Ok(())
        }
        AddressSpace::SystemIo if access_bytes > 4 => Err(PowerError::UnsupportedAccessWidth),
        AddressSpace::SystemIo => Err(PowerError::InvalidAddress),
        _ => Err(PowerError::UnsupportedAddressSpace),
    }
}

fn read_gas(handler: &AcpiHandler, register: GenericAddress) -> Result<u64, PowerError> {
    validate_gas(register)?;
    let address = usize::try_from(register.address).map_err(|_| PowerError::InvalidAddress)?;
    Ok(match (register.address_space, register.bit_width) {
        (AddressSpace::SystemMemory, 8) => handler.read_u8(address).into(),
        (AddressSpace::SystemMemory, 16) => handler.read_u16(address).into(),
        (AddressSpace::SystemMemory, 32) => handler.read_u32(address).into(),
        (AddressSpace::SystemMemory, 64) => handler.read_u64(address),
        (AddressSpace::SystemIo, 8) => handler.read_io_u8(address as u16).into(),
        (AddressSpace::SystemIo, 16) => handler.read_io_u16(address as u16).into(),
        (AddressSpace::SystemIo, 32) => handler.read_io_u32(address as u16).into(),
        _ => return Err(PowerError::UnsupportedAccessWidth),
    })
}

fn write_gas(
    handler: &AcpiHandler,
    register: GenericAddress,
    value: u64,
) -> Result<(), PowerError> {
    validate_gas(register)?;
    let address = usize::try_from(register.address).map_err(|_| PowerError::InvalidAddress)?;
    match (register.address_space, register.bit_width) {
        (AddressSpace::SystemMemory, 8) => handler.write_u8(address, value as u8),
        (AddressSpace::SystemMemory, 16) => handler.write_u16(address, value as u16),
        (AddressSpace::SystemMemory, 32) => handler.write_u32(address, value as u32),
        (AddressSpace::SystemMemory, 64) => handler.write_u64(address, value),
        (AddressSpace::SystemIo, 8) => handler.write_io_u8(address as u16, value as u8),
        (AddressSpace::SystemIo, 16) => handler.write_io_u16(address as u16, value as u16),
        (AddressSpace::SystemIo, 32) => handler.write_io_u32(address as u16, value as u32),
        _ => return Err(PowerError::UnsupportedAccessWidth),
    }
    Ok(())
}

fn write_sleep_control(
    handler: &AcpiHandler,
    register: GenericAddress,
    sleep_type: u8,
) -> Result<(), PowerError> {
    let current = read_gas(handler, register)?;
    let value = (current & !((0b111_u64 << 10) | (1_u64 << 13)))
        | (u64::from(sleep_type) << 10)
        | (1_u64 << 13);
    write_gas(handler, register, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gas(
        address_space: AddressSpace,
        address: u64,
        bit_width: u8,
        access_size: u8,
    ) -> GenericAddress {
        GenericAddress {
            address_space,
            bit_width,
            bit_offset: 0,
            access_size,
            address,
        }
    }

    #[test]
    fn gas_validation_requires_safe_matching_accesses() {
        assert_eq!(
            validate_gas(gas(AddressSpace::SystemIo, 0x404, 16, 0)),
            Ok(())
        );
        assert_eq!(
            validate_gas(gas(AddressSpace::SystemMemory, 0x1000, 32, 3)),
            Ok(())
        );
        assert_eq!(
            validate_gas(gas(AddressSpace::SystemMemory, 0x1000, 32, 2)),
            Err(PowerError::UnsupportedAccessWidth)
        );
        assert_eq!(
            validate_gas(gas(AddressSpace::SystemMemory, 0x1001, 32, 3)),
            Err(PowerError::UnsupportedAccessWidth)
        );
        assert_eq!(
            validate_gas(gas(AddressSpace::SystemIo, u64::from(u16::MAX), 16, 2)),
            Err(PowerError::UnsupportedAccessWidth)
        );
    }
}
