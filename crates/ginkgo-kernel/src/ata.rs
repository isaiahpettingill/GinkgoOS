//! Legacy ATA PIO support for the primary-channel master disk.

use core::hint::spin_loop;

use redoxfs::{Disk, BLOCK_SIZE};
use syscall::error::{Error, Result as SyscallResult, EINVAL, EIO};

use crate::io::{IoError, PortRegion};

const PRIMARY_COMMAND_BASE: u16 = 0x1f0;
const PRIMARY_COMMAND_LEN: u16 = 8;
const PRIMARY_CONTROL_BASE: u16 = 0x3f6;
const PRIMARY_CONTROL_LEN: u16 = 1;

const REG_DATA: u16 = 0;
const REG_ERROR: u16 = 1;
const REG_SECTOR_COUNT: u16 = 2;
const REG_LBA_LOW: u16 = 3;
const REG_LBA_MID: u16 = 4;
const REG_LBA_HIGH: u16 = 5;
const REG_DRIVE: u16 = 6;
const REG_STATUS_COMMAND: u16 = 7;

const STATUS_ERROR: u8 = 1 << 0;
const STATUS_DATA_REQUEST: u8 = 1 << 3;
const STATUS_DEVICE_FAULT: u8 = 1 << 5;
const STATUS_BUSY: u8 = 1 << 7;

const CONTROL_DISABLE_INTERRUPTS: u8 = 1 << 1;
const DRIVE_MASTER: u8 = 0xa0;
const DRIVE_MASTER_LBA: u8 = 0xe0;

const COMMAND_READ_SECTORS: u8 = 0x20;
const COMMAND_WRITE_SECTORS: u8 = 0x30;
const COMMAND_CACHE_FLUSH: u8 = 0xe7;
const COMMAND_IDENTIFY: u8 = 0xec;

const SECTOR_SIZE: usize = 512;
const WORDS_PER_SECTOR: usize = SECTOR_SIZE / 2;
const LBA28_SECTOR_LIMIT: u64 = 1 << 28;
const POLL_LIMIT: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtaError {
    Io(IoError),
    InvalidPortRegion,
    DeviceNotPresent,
    UnsupportedDevice,
    InvalidCapacity,
    TimedOut,
    DeviceFault,
    DeviceError(u8),
    Misaligned,
    AddressOverflow,
    OutOfBounds,
}

impl From<IoError> for AtaError {
    fn from(error: IoError) -> Self {
        Self::Io(error)
    }
}

/// An exclusively owned legacy primary-channel ATA master using LBA28 PIO.
pub struct AtaPioDisk {
    command: PortRegion,
    control: PortRegion,
    sectors: u32,
    flush_supported: bool,
}

impl AtaPioDisk {
    /// Claims and identifies the legacy primary-channel master disk.
    ///
    /// The disk is expected at the standard PC-compatible ports used by QEMU's
    /// `pc` machine. Interrupts are disabled on the channel because this driver
    /// completes every command by bounded polling.
    ///
    /// # Safety
    ///
    /// The caller must have sufficient privilege for x86 port I/O and must
    /// guarantee exclusive access to ports `0x1f0..=0x1f7` and `0x3f6` for the
    /// lifetime of the returned disk. No interrupt handler or other driver may
    /// issue commands to the same ATA channel concurrently.
    pub unsafe fn primary_master() -> Result<Self, AtaError> {
        let command = unsafe { PortRegion::new(PRIMARY_COMMAND_BASE, PRIMARY_COMMAND_LEN) }
            .ok_or(AtaError::InvalidPortRegion)?;
        let control = unsafe { PortRegion::new(PRIMARY_CONTROL_BASE, PRIMARY_CONTROL_LEN) }
            .ok_or(AtaError::InvalidPortRegion)?;
        let mut disk = Self {
            command,
            control,
            sectors: 0,
            flush_supported: false,
        };

        disk.control.write_u8(0, CONTROL_DISABLE_INTERRUPTS)?;
        disk.command.write_u8(REG_DRIVE, DRIVE_MASTER)?;
        disk.io_delay()?;
        disk.wait_not_busy()?;

        disk.command.write_u8(REG_SECTOR_COUNT, 0)?;
        disk.command.write_u8(REG_LBA_LOW, 0)?;
        disk.command.write_u8(REG_LBA_MID, 0)?;
        disk.command.write_u8(REG_LBA_HIGH, 0)?;
        disk.command
            .write_u8(REG_STATUS_COMMAND, COMMAND_IDENTIFY)?;

        let initial_status = disk.command.read_u8(REG_STATUS_COMMAND)?;
        if initial_status == 0 || initial_status == u8::MAX {
            return Err(AtaError::DeviceNotPresent);
        }

        disk.wait_not_busy()?;
        let signature_mid = disk.command.read_u8(REG_LBA_MID)?;
        let signature_high = disk.command.read_u8(REG_LBA_HIGH)?;
        if signature_mid != 0 || signature_high != 0 {
            return Err(AtaError::UnsupportedDevice);
        }
        disk.wait_for_data()?;

        let mut identify = [0_u16; WORDS_PER_SECTOR];
        for word in &mut identify {
            *word = disk.command.read_u16(REG_DATA)?;
        }
        disk.wait_for_completion()?;

        if identify[49] & (1 << 9) == 0 {
            return Err(AtaError::UnsupportedDevice);
        }

        let reported_sectors = u64::from(identify[60]) | (u64::from(identify[61]) << 16);
        let usable_sectors = reported_sectors.min(LBA28_SECTOR_LIMIT);
        if usable_sectors == 0 {
            return Err(AtaError::InvalidCapacity);
        }

        disk.sectors = usable_sectors as u32;
        disk.flush_supported = identify[82] & (1 << 12) != 0;
        Ok(disk)
    }

    /// Returns whether the first RedoxFS block is entirely zeroed.
    pub fn is_blank(&mut self) -> Result<bool, AtaError> {
        let mut sector = [0_u8; SECTOR_SIZE];
        for lba in 0..(BLOCK_SIZE as usize / SECTOR_SIZE) {
            self.read_sector(lba as u32, &mut sector)?;
            if sector.iter().any(|byte| *byte != 0) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn read_sector(&mut self, lba: u32, buffer: &mut [u8]) -> Result<(), AtaError> {
        debug_assert_eq!(buffer.len(), SECTOR_SIZE);
        self.issue_lba28(lba, COMMAND_READ_SECTORS)?;
        self.wait_for_data()?;

        for (bytes, _) in buffer.chunks_exact_mut(2).zip(0..WORDS_PER_SECTOR) {
            bytes.copy_from_slice(&self.command.read_u16(REG_DATA)?.to_le_bytes());
        }

        self.wait_for_completion()
    }

    fn write_sector(&mut self, lba: u32, buffer: &[u8]) -> Result<(), AtaError> {
        debug_assert_eq!(buffer.len(), SECTOR_SIZE);
        self.issue_lba28(lba, COMMAND_WRITE_SECTORS)?;
        self.wait_for_data()?;

        for bytes in buffer.chunks_exact(2) {
            self.command
                .write_u16(REG_DATA, u16::from_le_bytes([bytes[0], bytes[1]]))?;
        }

        self.wait_for_completion()
    }

    fn issue_lba28(&mut self, lba: u32, command: u8) -> Result<(), AtaError> {
        debug_assert!(u64::from(lba) < LBA28_SECTOR_LIMIT);
        self.wait_not_busy()?;
        self.command
            .write_u8(REG_DRIVE, DRIVE_MASTER_LBA | ((lba >> 24) as u8 & 0x0f))?;
        self.io_delay()?;
        self.wait_not_busy()?;
        self.command.write_u8(REG_SECTOR_COUNT, 1)?;
        self.command.write_u8(REG_LBA_LOW, lba as u8)?;
        self.command.write_u8(REG_LBA_MID, (lba >> 8) as u8)?;
        self.command.write_u8(REG_LBA_HIGH, (lba >> 16) as u8)?;
        self.command.write_u8(REG_STATUS_COMMAND, command)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), AtaError> {
        if !self.flush_supported {
            return Ok(());
        }

        self.wait_not_busy()?;
        self.command
            .write_u8(REG_STATUS_COMMAND, COMMAND_CACHE_FLUSH)?;
        self.wait_for_completion()
    }

    fn io_delay(&mut self) -> Result<(), AtaError> {
        // Four alternate-status reads provide the ATA-required 400 ns delay
        // without acknowledging a pending interrupt.
        for _ in 0..4 {
            self.control.read_u8(0)?;
        }
        Ok(())
    }

    fn wait_not_busy(&mut self) -> Result<u8, AtaError> {
        for _ in 0..POLL_LIMIT {
            let status = self.command.read_u8(REG_STATUS_COMMAND)?;
            if status == 0 || status == u8::MAX {
                return Err(AtaError::DeviceNotPresent);
            }
            if status & STATUS_BUSY == 0 {
                if status & STATUS_DEVICE_FAULT != 0 {
                    return Err(AtaError::DeviceFault);
                }
                return Ok(status);
            }
            spin_loop();
        }
        Err(AtaError::TimedOut)
    }

    fn wait_for_data(&mut self) -> Result<(), AtaError> {
        for _ in 0..POLL_LIMIT {
            let status = self.command.read_u8(REG_STATUS_COMMAND)?;
            if status == 0 || status == u8::MAX {
                return Err(AtaError::DeviceNotPresent);
            }
            if status & STATUS_BUSY == 0 {
                self.check_command_error(status)?;
                if status & STATUS_DATA_REQUEST != 0 {
                    return Ok(());
                }
            }
            spin_loop();
        }
        Err(AtaError::TimedOut)
    }

    fn wait_for_completion(&mut self) -> Result<(), AtaError> {
        let status = self.wait_not_busy()?;
        self.check_command_error(status)
    }

    fn check_command_error(&mut self, status: u8) -> Result<(), AtaError> {
        if status & STATUS_DEVICE_FAULT != 0 {
            return Err(AtaError::DeviceFault);
        }
        if status & STATUS_ERROR != 0 {
            return Err(AtaError::DeviceError(self.command.read_u8(REG_ERROR)?));
        }
        Ok(())
    }
}

impl Disk for AtaPioDisk {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> SyscallResult<usize> {
        let range = transfer_range(block, buffer.len(), self.sectors).map_err(disk_error)?;
        let mut lba = range.first_sector;
        for sector in buffer.chunks_exact_mut(SECTOR_SIZE) {
            self.read_sector(lba, sector).map_err(disk_error)?;
            lba += 1;
        }
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> SyscallResult<usize> {
        let range = transfer_range(block, buffer.len(), self.sectors).map_err(disk_error)?;
        let mut lba = range.first_sector;
        for sector in buffer.chunks_exact(SECTOR_SIZE) {
            self.write_sector(lba, sector).map_err(disk_error)?;
            lba += 1;
        }
        if !buffer.is_empty() {
            self.flush().map_err(disk_error)?;
        }
        Ok(buffer.len())
    }

    fn size(&mut self) -> SyscallResult<u64> {
        Ok(u64::from(self.sectors) * SECTOR_SIZE as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferRange {
    first_sector: u32,
    sector_count: u32,
}

fn transfer_range(
    block: u64,
    byte_len: usize,
    capacity_sectors: u32,
) -> Result<TransferRange, AtaError> {
    if byte_len % SECTOR_SIZE != 0 {
        return Err(AtaError::Misaligned);
    }

    let byte_offset = block
        .checked_mul(BLOCK_SIZE)
        .ok_or(AtaError::AddressOverflow)?;
    if byte_offset % SECTOR_SIZE as u64 != 0 {
        return Err(AtaError::Misaligned);
    }

    let first_sector = byte_offset / SECTOR_SIZE as u64;
    let sector_count =
        u64::try_from(byte_len).map_err(|_| AtaError::AddressOverflow)? / SECTOR_SIZE as u64;
    let end_sector = first_sector
        .checked_add(sector_count)
        .ok_or(AtaError::AddressOverflow)?;
    if end_sector > u64::from(capacity_sectors) || end_sector > LBA28_SECTOR_LIMIT {
        return Err(AtaError::OutOfBounds);
    }

    Ok(TransferRange {
        first_sector: u32::try_from(first_sector).map_err(|_| AtaError::OutOfBounds)?,
        sector_count: u32::try_from(sector_count).map_err(|_| AtaError::OutOfBounds)?,
    })
}

fn disk_error(error: AtaError) -> Error {
    match error {
        AtaError::Misaligned | AtaError::AddressOverflow | AtaError::OutOfBounds => {
            Error::new(EINVAL)
        }
        _ => Error::new(EIO),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_converts_redoxfs_blocks_to_ata_sectors() {
        assert_eq!(
            transfer_range(3, 2 * SECTOR_SIZE, 100),
            Ok(TransferRange {
                first_sector: 24,
                sector_count: 2,
            })
        );
    }

    #[test]
    fn range_rejects_non_sector_sized_buffers() {
        assert_eq!(
            transfer_range(0, SECTOR_SIZE - 1, 100),
            Err(AtaError::Misaligned)
        );
    }

    #[test]
    fn range_rejects_block_offset_overflow() {
        assert_eq!(
            transfer_range(u64::MAX, 0, u32::MAX),
            Err(AtaError::AddressOverflow)
        );
    }

    #[test]
    fn range_rejects_capacity_overrun() {
        assert_eq!(
            transfer_range(1, SECTOR_SIZE, 8),
            Err(AtaError::OutOfBounds)
        );
    }

    #[test]
    fn empty_range_at_capacity_is_valid() {
        assert_eq!(
            transfer_range(1, 0, 8),
            Ok(TransferRange {
                first_sector: 8,
                sector_count: 0,
            })
        );
    }
}
