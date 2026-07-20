//! Checked x86 port-I/O and memory-mapped-I/O capabilities.
//!
//! Constructing either region is unsafe because the caller must establish that
//! the represented hardware resource is valid and exclusively owned. Once a
//! region exists, individual accesses are range- and alignment-checked.

use core::{
    arch::asm,
    mem::{align_of, size_of},
    ptr::{self, NonNull},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoError {
    OutOfRange,
    AddressOverflow,
    Misaligned,
    DeviceNotPresent,
}

/// An exclusively owned range in the x86 I/O-port address space.
///
/// `count` is measured in port-address bytes. Typed accesses must fit entirely
/// within both this range and the 16-bit x86 port-address space.
pub struct PortRegion {
    base: u16,
    count: u16,
}

impl PortRegion {
    /// Creates a port-I/O capability.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this range belongs to a device that accepts
    /// the requested access widths, that no other live capability aliases it,
    /// and that the code executes with sufficient I/O privilege.
    pub const unsafe fn new(base: u16, count: u16) -> Option<Self> {
        if count == 0 || (base as u32) + (count as u32) > (u16::MAX as u32) + 1 {
            None
        } else {
            Some(Self { base, count })
        }
    }

    pub const fn base(&self) -> u16 {
        self.base
    }

    pub const fn count(&self) -> u16 {
        self.count
    }

    pub fn read_u8(&mut self, offset: u16) -> Result<u8, IoError> {
        let port = self.checked_port(offset, size_of::<u8>())?;
        let value: u8;

        // SAFETY: `new` establishes ownership and I/O privilege; the checked
        // port lies within the declared range and `in` does not touch the stack.
        unsafe {
            asm!(
                "in al, dx",
                in("dx") port,
                lateout("al") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(value)
    }

    pub fn read_u16(&mut self, offset: u16) -> Result<u16, IoError> {
        let port = self.checked_port(offset, size_of::<u16>())?;
        let value: u16;

        // SAFETY: See `read_u8`; this access additionally passed the u16 width
        // check performed by `checked_port`.
        unsafe {
            asm!(
                "in ax, dx",
                in("dx") port,
                lateout("ax") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(value)
    }

    pub fn read_u32(&mut self, offset: u16) -> Result<u32, IoError> {
        let port = self.checked_port(offset, size_of::<u32>())?;
        let value: u32;

        // SAFETY: See `read_u8`; this access additionally passed the u32 width
        // check performed by `checked_port`.
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") port,
                lateout("eax") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(value)
    }

    pub fn write_u8(&mut self, offset: u16, value: u8) -> Result<(), IoError> {
        let port = self.checked_port(offset, size_of::<u8>())?;

        // SAFETY: `new` establishes ownership and I/O privilege; the checked
        // port lies within the declared range and `out` does not touch the stack.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(())
    }

    pub fn write_u16(&mut self, offset: u16, value: u16) -> Result<(), IoError> {
        let port = self.checked_port(offset, size_of::<u16>())?;

        // SAFETY: See `write_u8`; this access additionally passed the u16 width
        // check performed by `checked_port`.
        unsafe {
            asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(())
    }

    pub fn write_u32(&mut self, offset: u16, value: u32) -> Result<(), IoError> {
        let port = self.checked_port(offset, size_of::<u32>())?;

        // SAFETY: See `write_u8`; this access additionally passed the u32 width
        // check performed by `checked_port`.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nostack, preserves_flags),
            );
        }
        Ok(())
    }

    fn checked_port(&self, offset: u16, width: usize) -> Result<u16, IoError> {
        let offset = u32::from(offset);
        let width = u32::try_from(width).map_err(|_| IoError::AddressOverflow)?;
        let relative_end = offset
            .checked_add(width)
            .ok_or(IoError::AddressOverflow)?;

        if relative_end > u32::from(self.count) {
            return Err(IoError::OutOfRange);
        }

        let absolute_end = u32::from(self.base)
            .checked_add(relative_end)
            .ok_or(IoError::AddressOverflow)?;
        if absolute_end > u32::from(u16::MAX) + 1 {
            return Err(IoError::AddressOverflow);
        }

        self.base
            .checked_add(offset as u16)
            .ok_or(IoError::AddressOverflow)
    }
}

/// An exclusively owned, virtually mapped MMIO byte range.
/// A nonblocking 16550-compatible serial device backed by an I/O-port range.
pub struct SerialPort {
    ports: PortRegion,
}

impl SerialPort {
    pub const COM1_BASE: u16 = 0x3f8;

    /// Claims and initializes a 16550-compatible serial port.
    ///
    /// # Safety
    ///
    /// The caller must ensure exclusive ownership of the eight ports beginning
    /// at `base` and that a compatible UART is present there.
    pub unsafe fn new(base: u16) -> Option<Self> {
        let ports = PortRegion::new(base, 8)?;
        let mut serial = Self { ports };
        serial.initialize().ok()?;
        Some(serial)
    }

    pub fn try_read(&mut self) -> Result<Option<u8>, IoError> {
        if self.ports.read_u8(5)? & 1 == 0 {
            return Ok(None);
        }
        self.ports.read_u8(0).map(Some)
    }

    pub fn try_write(&mut self, byte: u8) -> Result<bool, IoError> {
        if self.ports.read_u8(5)? & (1 << 5) == 0 {
            return Ok(false);
        }
        self.ports.write_u8(0, byte)?;
        Ok(true)
    }

    /// Writes every byte that the UART can accept immediately and returns the
    /// number written. It never spins waiting for the device.
    pub fn write_available(&mut self, bytes: &[u8]) -> Result<usize, IoError> {
        let mut written = 0;
        for &byte in bytes {
            if !self.try_write(byte)? {
                break;
            }
            written += 1;
        }
        Ok(written)
    }

    fn initialize(&mut self) -> Result<(), IoError> {
        self.ports.write_u8(1, 0x00)?;
        self.ports.write_u8(3, 0x80)?;
        self.ports.write_u8(0, 0x03)?;
        self.ports.write_u8(1, 0x00)?;
        self.ports.write_u8(3, 0x03)?;
        self.ports.write_u8(2, 0xc7)?;

        // Probe the UART in loopback mode so an absent legacy port (which
        // commonly reads as 0xff) is not mistaken for a stream of input.
        self.ports.write_u8(4, 0x1e)?;
        self.ports.write_u8(0, 0xae)?;
        if self.ports.read_u8(0)? != 0xae {
            return Err(IoError::DeviceNotPresent);
        }
        self.ports.write_u8(4, 0x0f)?;
        Ok(())
    }
}

pub struct MmioRegion {
    base: NonNull<u8>,
    len: usize,
}

impl MmioRegion {
    /// Creates an MMIO capability over `base..base + len`.
    ///
    /// # Safety
    ///
    /// The complete range must remain mapped for this value's lifetime with
    /// device-appropriate page attributes. It must be valid for volatile reads
    /// and writes, and no other Rust reference or live `MmioRegion` may alias
    /// the range. Creating this value does not map a physical address.
    pub unsafe fn from_raw_parts(base: *mut u8, len: usize) -> Option<Self> {
        let base = NonNull::new(base)?;
        if len == 0 || (base.as_ptr() as usize).checked_add(len).is_none() {
            return None;
        }
        Some(Self { base, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn read_u8(&mut self, offset: usize) -> Result<u8, IoError> {
        self.read(offset)
    }

    pub fn read_u16(&mut self, offset: usize) -> Result<u16, IoError> {
        self.read(offset)
    }

    pub fn read_u32(&mut self, offset: usize) -> Result<u32, IoError> {
        self.read(offset)
    }

    pub fn read_u64(&mut self, offset: usize) -> Result<u64, IoError> {
        self.read(offset)
    }

    pub fn write_u8(&mut self, offset: usize, value: u8) -> Result<(), IoError> {
        self.write(offset, value)
    }

    pub fn write_u16(&mut self, offset: usize, value: u16) -> Result<(), IoError> {
        self.write(offset, value)
    }

    pub fn write_u32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        self.write(offset, value)
    }

    pub fn write_u64(&mut self, offset: usize, value: u64) -> Result<(), IoError> {
        self.write(offset, value)
    }

    fn read<T: Copy>(&mut self, offset: usize) -> Result<T, IoError> {
        let pointer = self.checked_pointer::<T>(offset)?;

        // SAFETY: Construction guarantees a valid MMIO mapping and exclusive
        // ownership. `checked_pointer` verifies range and alignment for `T`.
        Ok(unsafe { ptr::read_volatile(pointer.cast_const()) })
    }

    fn write<T>(&mut self, offset: usize, value: T) -> Result<(), IoError> {
        let pointer = self.checked_pointer::<T>(offset)?;

        // SAFETY: Construction guarantees a valid MMIO mapping and exclusive
        // ownership. `checked_pointer` verifies range and alignment for `T`.
        unsafe { ptr::write_volatile(pointer, value) };
        Ok(())
    }

    fn checked_pointer<T>(&self, offset: usize) -> Result<*mut T, IoError> {
        let end = offset
            .checked_add(size_of::<T>())
            .ok_or(IoError::AddressOverflow)?;
        if end > self.len {
            return Err(IoError::OutOfRange);
        }

        let address = (self.base.as_ptr() as usize)
            .checked_add(offset)
            .ok_or(IoError::AddressOverflow)?;
        if address % align_of::<T>() != 0 {
            return Err(IoError::Misaligned);
        }

        // SAFETY: The constructor's contract makes the whole byte range valid,
        // and the range check above proves that this `T` lies inside it.
        Ok(unsafe { self.base.as_ptr().add(offset).cast::<T>() })
    }
}
