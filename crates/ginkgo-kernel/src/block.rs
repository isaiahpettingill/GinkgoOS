//! Common synchronous block-device and partition-volume support.
//!
//! Drivers implement [`BlockDevice`] with bounded, polling-based operations.
//! [`Volume::discover`] then selects a GPT or legacy MBR partition, or exposes an
//! unpartitioned disk as a whole, and adapts it to [`redoxfs::Disk`].

use core::cmp::min;

use redoxfs::{Disk, BLOCK_SIZE};
use syscall::error::{Error as SyscallError, Result as SyscallResult, EINVAL, EIO};

/// The logical sector size supported by this abstraction.
pub const SECTOR_SIZE: usize = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_MIN_HEADER_SIZE: usize = 92;
const GPT_MIN_ENTRY_SIZE: u32 = 128;
const GPT_MAX_ENTRY_SIZE: u32 = 4096;
const GPT_MAX_ENTRY_COUNT: u32 = 16_384;
const MBR_PARTITION_OFFSET: usize = 446;
const MBR_PARTITION_SIZE: usize = 16;
const MBR_PARTITION_COUNT: usize = 4;

/// A synchronous, sector-addressed device whose operations finish after bounded polling.
///
/// Buffers contain one or more complete 512-byte sectors. Implementations must reject
/// transfers beyond `capacity_sectors()` and must return rather than poll indefinitely.
pub trait BlockDevice {
    /// Driver-specific errors returned without loss of detail.
    type Error;

    /// Returns the number of addressable 512-byte sectors.
    fn capacity_sectors(&self) -> u64;

    /// Reads complete sectors beginning at `lba` into `buffer`.
    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;

    /// Writes complete sectors beginning at `lba` from `buffer`.
    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error>;

    /// Makes previously completed writes durable when the hardware has a write cache.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// The reason a GPT was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GptError {
    MissingHeader,
    InvalidHeaderSize,
    InvalidHeaderCrc,
    InvalidHeaderRange,
    InvalidEntryLayout,
    InvalidEntryArrayCrc,
    InvalidPartitionRange,
}

/// Errors from discovering or accessing a volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeError<E> {
    Device(E),
    EmptyDevice,
    Misaligned,
    AddressOverflow,
    OutOfBounds,
    InvalidGpt(GptError),
    InvalidMbr,
    NoUsablePartition,
}

impl<E> From<E> for VolumeError<E> {
    fn from(error: E) -> Self {
        Self::Device(error)
    }
}

/// An owned, bounds-checked sector range on a block device.
pub struct Volume<D> {
    device: D,
    start_lba: u64,
    sector_count: u64,
}

/// Synonym emphasizing that [`Volume`] may represent a partition.
pub type Partition<D> = Volume<D>;

impl<D: BlockDevice> Volume<D> {
    /// Discovers a usable volume using GPT first, then legacy MBR.
    ///
    /// A protective MBR requires a valid GPT. A disk with neither a GPT signature nor
    /// an MBR signature is treated as an unpartitioned whole-disk volume. GPT selection
    /// is deterministic: the lowest-index non-empty usable entry is chosen.
    pub fn discover(mut device: D) -> Result<Self, VolumeError<D::Error>> {
        let capacity = device.capacity_sectors();
        if capacity == 0 {
            return Err(VolumeError::EmptyDevice);
        }

        let mut mbr = [0_u8; SECTOR_SIZE];
        device
            .read_sectors(0, &mut mbr)
            .map_err(VolumeError::Device)?;
        let mbr_signed = mbr[510] == 0x55 && mbr[511] == 0xaa;
        let protective = mbr_signed && mbr_has_protective_partition(&mbr);

        let mut gpt_header = [0_u8; SECTOR_SIZE];
        let has_gpt_signature = if capacity > 1 {
            device
                .read_sectors(1, &mut gpt_header)
                .map_err(VolumeError::Device)?;
            &gpt_header[..GPT_SIGNATURE.len()] == GPT_SIGNATURE
        } else {
            false
        };

        if has_gpt_signature {
            let range = parse_gpt(&mut device, capacity, &gpt_header)?;
            return Self::from_validated_range(device, range.0, range.1);
        }
        if protective {
            return Err(VolumeError::InvalidGpt(GptError::MissingHeader));
        }
        if mbr_signed {
            if let Some((start, count)) = parse_mbr(&mbr, capacity)? {
                return Self::from_validated_range(device, start, count);
            }
            if mbr_partition_entries_blank(&mbr) {
                return Self::whole_disk(device);
            }
            return Err(VolumeError::NoUsablePartition);
        }

        Self::whole_disk(device)
    }

    /// Creates a view spanning the entire device.
    pub fn whole_disk(device: D) -> Result<Self, VolumeError<D::Error>> {
        let capacity = device.capacity_sectors();
        if capacity == 0 {
            return Err(VolumeError::EmptyDevice);
        }
        if capacity > u64::MAX / SECTOR_SIZE as u64 {
            return Err(VolumeError::AddressOverflow);
        }
        Ok(Self {
            device,
            start_lba: 0,
            sector_count: capacity,
        })
    }

    /// Creates an explicitly bounded partition view.
    pub fn from_range(
        device: D,
        start_lba: u64,
        sector_count: u64,
    ) -> Result<Self, VolumeError<D::Error>> {
        Self::from_validated_range(device, start_lba, sector_count)
    }

    fn from_validated_range(
        device: D,
        start_lba: u64,
        sector_count: u64,
    ) -> Result<Self, VolumeError<D::Error>> {
        if sector_count == 0 {
            return Err(VolumeError::OutOfBounds);
        }
        if sector_count > u64::MAX / SECTOR_SIZE as u64 {
            return Err(VolumeError::AddressOverflow);
        }
        let end = start_lba
            .checked_add(sector_count)
            .ok_or(VolumeError::AddressOverflow)?;
        if end > device.capacity_sectors() {
            return Err(VolumeError::OutOfBounds);
        }
        Ok(Self {
            device,
            start_lba,
            sector_count,
        })
    }

    pub const fn start_lba(&self) -> u64 {
        self.start_lba
    }

    pub const fn sector_count(&self) -> u64 {
        self.sector_count
    }

    pub const fn capacity_bytes(&self) -> u64 {
        self.sector_count * SECTOR_SIZE as u64
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn into_inner(self) -> D {
        self.device
    }

    /// Reads complete sectors relative to the beginning of this volume.
    pub fn read_sectors(
        &mut self,
        relative_lba: u64,
        buffer: &mut [u8],
    ) -> Result<(), VolumeError<D::Error>> {
        let absolute = self.checked_transfer(relative_lba, buffer.len())?;
        self.device
            .read_sectors(absolute, buffer)
            .map_err(VolumeError::Device)
    }

    /// Writes complete sectors relative to the beginning of this volume.
    pub fn write_sectors(
        &mut self,
        relative_lba: u64,
        buffer: &[u8],
    ) -> Result<(), VolumeError<D::Error>> {
        let absolute = self.checked_transfer(relative_lba, buffer.len())?;
        self.device
            .write_sectors(absolute, buffer)
            .map_err(VolumeError::Device)
    }

    pub fn flush(&mut self) -> Result<(), VolumeError<D::Error>> {
        self.device.flush().map_err(VolumeError::Device)
    }

    fn checked_transfer(
        &self,
        relative_lba: u64,
        byte_len: usize,
    ) -> Result<u64, VolumeError<D::Error>> {
        if byte_len % SECTOR_SIZE != 0 {
            return Err(VolumeError::Misaligned);
        }
        let sectors =
            u64::try_from(byte_len / SECTOR_SIZE).map_err(|_| VolumeError::AddressOverflow)?;
        let relative_end = relative_lba
            .checked_add(sectors)
            .ok_or(VolumeError::AddressOverflow)?;
        if relative_end > self.sector_count {
            return Err(VolumeError::OutOfBounds);
        }
        self.start_lba
            .checked_add(relative_lba)
            .ok_or(VolumeError::AddressOverflow)
    }
}

impl<D: BlockDevice> Disk for Volume<D> {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> SyscallResult<usize> {
        let relative_lba = redox_lba::<D::Error>(block).map_err(syscall_error)?;
        self.read_sectors(relative_lba, buffer)
            .map_err(syscall_error)?;
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> SyscallResult<usize> {
        let relative_lba = redox_lba::<D::Error>(block).map_err(syscall_error)?;
        self.write_sectors(relative_lba, buffer)
            .map_err(syscall_error)?;
        if !buffer.is_empty() {
            self.flush().map_err(syscall_error)?;
        }
        Ok(buffer.len())
    }

    fn size(&mut self) -> SyscallResult<u64> {
        Ok(self.capacity_bytes())
    }
}

fn redox_lba<E>(block: u64) -> Result<u64, VolumeError<E>> {
    let byte_offset = block
        .checked_mul(BLOCK_SIZE)
        .ok_or(VolumeError::AddressOverflow)?;
    if byte_offset % SECTOR_SIZE as u64 != 0 {
        return Err(VolumeError::Misaligned);
    }
    Ok(byte_offset / SECTOR_SIZE as u64)
}

fn syscall_error<E>(error: VolumeError<E>) -> SyscallError {
    match error {
        VolumeError::Misaligned | VolumeError::AddressOverflow | VolumeError::OutOfBounds => {
            SyscallError::new(EINVAL)
        }
        _ => SyscallError::new(EIO),
    }
}

fn parse_gpt<D: BlockDevice>(
    device: &mut D,
    capacity: u64,
    header: &[u8; SECTOR_SIZE],
) -> Result<(u64, u64), VolumeError<D::Error>> {
    let header_size = le_u32(header, 12) as usize;
    if !(GPT_MIN_HEADER_SIZE..=SECTOR_SIZE).contains(&header_size) {
        return Err(VolumeError::InvalidGpt(GptError::InvalidHeaderSize));
    }

    let expected_header_crc = le_u32(header, 16);
    let mut crc = Crc32::new();
    crc.update(&header[..16]);
    crc.update(&[0; 4]);
    crc.update(&header[20..header_size]);
    if crc.finish() != expected_header_crc {
        return Err(VolumeError::InvalidGpt(GptError::InvalidHeaderCrc));
    }

    let current_lba = le_u64(header, 24);
    let backup_lba = le_u64(header, 32);
    let first_usable = le_u64(header, 40);
    let last_usable = le_u64(header, 48);
    if current_lba != 1
        || backup_lba >= capacity
        || backup_lba == current_lba
        || first_usable > last_usable
        || first_usable >= capacity
        || last_usable >= capacity
        || (first_usable..=last_usable).contains(&current_lba)
        || (first_usable..=last_usable).contains(&backup_lba)
    {
        return Err(VolumeError::InvalidGpt(GptError::InvalidHeaderRange));
    }

    let entries_lba = le_u64(header, 72);
    let entry_count = le_u32(header, 80);
    let entry_size = le_u32(header, 84);
    if entry_count == 0
        || entry_count > GPT_MAX_ENTRY_COUNT
        || !(GPT_MIN_ENTRY_SIZE..=GPT_MAX_ENTRY_SIZE).contains(&entry_size)
        || entry_size % 8 != 0
    {
        return Err(VolumeError::InvalidGpt(GptError::InvalidEntryLayout));
    }
    let entries_bytes = u64::from(entry_count)
        .checked_mul(u64::from(entry_size))
        .ok_or(VolumeError::InvalidGpt(GptError::InvalidEntryLayout))?;
    let entries_sectors = entries_bytes
        .checked_add(SECTOR_SIZE as u64 - 1)
        .ok_or(VolumeError::InvalidGpt(GptError::InvalidEntryLayout))?
        / SECTOR_SIZE as u64;
    let entries_end = entries_lba
        .checked_add(entries_sectors)
        .ok_or(VolumeError::InvalidGpt(GptError::InvalidEntryLayout))?;
    if entries_lba < 2
        || entries_end > first_usable
        || entries_end > capacity
        || (entries_lba..entries_end).contains(&current_lba)
        || (entries_lba..entries_end).contains(&backup_lba)
        || ranges_overlap(entries_lba, entries_end, first_usable, last_usable + 1)
    {
        return Err(VolumeError::InvalidGpt(GptError::InvalidEntryLayout));
    }

    let expected_entries_crc = le_u32(header, 88);
    let mut entry_crc = Crc32::new();
    let mut remaining = entries_bytes;
    let mut lba = entries_lba;
    let mut sector = [0_u8; SECTOR_SIZE];
    while remaining != 0 {
        device
            .read_sectors(lba, &mut sector)
            .map_err(VolumeError::Device)?;
        let used = min(remaining, SECTOR_SIZE as u64) as usize;
        entry_crc.update(&sector[..used]);
        remaining -= used as u64;
        lba += 1;
    }
    if entry_crc.finish() != expected_entries_crc {
        return Err(VolumeError::InvalidGpt(GptError::InvalidEntryArrayCrc));
    }

    let mut selected = None;
    for index in 0..entry_count {
        let offset = u64::from(index) * u64::from(entry_size);
        let mut prefix = [0_u8; 48];
        read_bytes(device, entries_lba, offset, &mut prefix)?;
        if prefix[..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let first = le_u64(&prefix, 32);
        let last = le_u64(&prefix, 40);
        if first < first_usable || last > last_usable || first > last {
            return Err(VolumeError::InvalidGpt(GptError::InvalidPartitionRange));
        }
        if selected.is_none() {
            selected = Some((first, last - first + 1));
        }
    }
    selected.ok_or(VolumeError::NoUsablePartition)
}

fn read_bytes<D: BlockDevice>(
    device: &mut D,
    base_lba: u64,
    byte_offset: u64,
    output: &mut [u8],
) -> Result<(), VolumeError<D::Error>> {
    let mut copied = 0;
    while copied < output.len() {
        let absolute_offset = byte_offset
            .checked_add(copied as u64)
            .ok_or(VolumeError::AddressOverflow)?;
        let sector_offset = (absolute_offset % SECTOR_SIZE as u64) as usize;
        let lba = base_lba
            .checked_add(absolute_offset / SECTOR_SIZE as u64)
            .ok_or(VolumeError::AddressOverflow)?;
        let mut sector = [0_u8; SECTOR_SIZE];
        device
            .read_sectors(lba, &mut sector)
            .map_err(VolumeError::Device)?;
        let count = min(output.len() - copied, SECTOR_SIZE - sector_offset);
        output[copied..copied + count]
            .copy_from_slice(&sector[sector_offset..sector_offset + count]);
        copied += count;
    }
    Ok(())
}

fn parse_mbr<E>(
    mbr: &[u8; SECTOR_SIZE],
    capacity: u64,
) -> Result<Option<(u64, u64)>, VolumeError<E>> {
    let mut selected = None;
    for index in 0..MBR_PARTITION_COUNT {
        let offset = MBR_PARTITION_OFFSET + index * MBR_PARTITION_SIZE;
        let kind = mbr[offset + 4];
        let start = u64::from(le_u32(mbr, offset + 8));
        let count = u64::from(le_u32(mbr, offset + 12));
        if kind == 0 || count == 0 || kind == 0xee || is_extended_mbr_type(kind) {
            continue;
        }
        let end = start.checked_add(count).ok_or(VolumeError::InvalidMbr)?;
        if start == 0 || end > capacity {
            return Err(VolumeError::InvalidMbr);
        }
        if selected.is_none() {
            selected = Some((start, count));
        }
    }
    Ok(selected)
}

fn mbr_has_protective_partition(mbr: &[u8; SECTOR_SIZE]) -> bool {
    (0..MBR_PARTITION_COUNT).any(|index| {
        let offset = MBR_PARTITION_OFFSET + index * MBR_PARTITION_SIZE;
        mbr[offset + 4] == 0xee && le_u32(mbr, offset + 12) != 0
    })
}

fn mbr_partition_entries_blank(mbr: &[u8; SECTOR_SIZE]) -> bool {
    mbr[MBR_PARTITION_OFFSET..MBR_PARTITION_OFFSET + MBR_PARTITION_COUNT * MBR_PARTITION_SIZE]
        .iter()
        .all(|byte| *byte == 0)
}

const fn is_extended_mbr_type(kind: u8) -> bool {
    matches!(kind, 0x05 | 0x0f | 0x85)
}

const fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

struct Crc32(u32);

impl Crc32 {
    const fn new() -> Self {
        Self(u32::MAX)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = 0_u32.wrapping_sub(self.0 & 1);
                self.0 = (self.0 >> 1) ^ (0xedb8_8320 & mask);
            }
        }
    }

    const fn finish(self) -> u32 {
        !self.0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeError {
        Read,
        Write,
        Flush,
        Contract,
    }

    struct FakeDisk {
        data: Vec<u8>,
        fail_read: bool,
        fail_write: bool,
        fail_flush: bool,
        flushes: usize,
    }

    impl FakeDisk {
        fn zeroed(sectors: usize) -> Self {
            Self {
                data: vec![0; sectors * SECTOR_SIZE],
                fail_read: false,
                fail_write: false,
                fail_flush: false,
                flushes: 0,
            }
        }

        fn sector_mut(&mut self, lba: usize) -> &mut [u8] {
            &mut self.data[lba * SECTOR_SIZE..(lba + 1) * SECTOR_SIZE]
        }
    }

    impl BlockDevice for FakeDisk {
        type Error = FakeError;

        fn capacity_sectors(&self) -> u64 {
            (self.data.len() / SECTOR_SIZE) as u64
        }

        fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(FakeError::Read);
            }
            if buffer.len() % SECTOR_SIZE != 0 {
                return Err(FakeError::Contract);
            }
            let start = usize::try_from(lba).map_err(|_| FakeError::Contract)? * SECTOR_SIZE;
            let end = start.checked_add(buffer.len()).ok_or(FakeError::Contract)?;
            let source = self.data.get(start..end).ok_or(FakeError::Contract)?;
            buffer.copy_from_slice(source);
            Ok(())
        }

        fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write {
                return Err(FakeError::Write);
            }
            if buffer.len() % SECTOR_SIZE != 0 {
                return Err(FakeError::Contract);
            }
            let start = usize::try_from(lba).map_err(|_| FakeError::Contract)? * SECTOR_SIZE;
            let end = start.checked_add(buffer.len()).ok_or(FakeError::Contract)?;
            let target = self.data.get_mut(start..end).ok_or(FakeError::Contract)?;
            target.copy_from_slice(buffer);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            self.flushes += 1;
            if self.fail_flush {
                Err(FakeError::Flush)
            } else {
                Ok(())
            }
        }
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = Crc32::new();
        crc.update(bytes);
        crc.finish()
    }

    fn make_gpt(partitions: &[(u64, u64)]) -> FakeDisk {
        let mut disk = FakeDisk::zeroed(128);
        {
            let mbr = disk.sector_mut(0);
            mbr[510] = 0x55;
            mbr[511] = 0xaa;
            mbr[MBR_PARTITION_OFFSET + 4] = 0xee;
            put_u32(mbr, MBR_PARTITION_OFFSET + 8, 1);
            put_u32(mbr, MBR_PARTITION_OFFSET + 12, 127);
        }

        let mut entries = [0_u8; 4 * 128];
        for (index, (first, last)) in partitions.iter().enumerate() {
            let offset = index * 128;
            entries[offset] = (index + 1) as u8;
            put_u64(&mut entries, offset + 32, *first);
            put_u64(&mut entries, offset + 40, *last);
        }
        disk.sector_mut(2).copy_from_slice(&entries);

        let entries_crc = crc32(&entries);
        let header = disk.sector_mut(1);
        header[..8].copy_from_slice(GPT_SIGNATURE);
        put_u32(header, 8, 0x0001_0000);
        put_u32(header, 12, GPT_MIN_HEADER_SIZE as u32);
        put_u64(header, 24, 1);
        put_u64(header, 32, 127);
        put_u64(header, 40, 34);
        put_u64(header, 48, 126);
        put_u64(header, 72, 2);
        put_u32(header, 80, 4);
        put_u32(header, 84, 128);
        put_u32(header, 88, entries_crc);
        let header_crc = crc32(&header[..GPT_MIN_HEADER_SIZE]);
        put_u32(header, 16, header_crc);
        disk
    }

    fn make_mbr(start: u32, count: u32, kind: u8) -> FakeDisk {
        let mut disk = FakeDisk::zeroed(64);
        let mbr = disk.sector_mut(0);
        mbr[510] = 0x55;
        mbr[511] = 0xaa;
        mbr[MBR_PARTITION_OFFSET + 4] = kind;
        put_u32(mbr, MBR_PARTITION_OFFSET + 8, start);
        put_u32(mbr, MBR_PARTITION_OFFSET + 12, count);
        disk
    }

    #[test]
    fn whole_disk_is_selected_without_partition_table() {
        let volume = Volume::discover(FakeDisk::zeroed(16)).unwrap();
        assert_eq!(volume.start_lba(), 0);
        assert_eq!(volume.sector_count(), 16);
    }

    #[test]
    fn explicit_partition_enforces_alignment_and_bounds() {
        let mut volume = Volume::from_range(FakeDisk::zeroed(16), 4, 3).unwrap();
        assert_eq!(
            volume.read_sectors(0, &mut [0; 1]),
            Err(VolumeError::Misaligned)
        );
        assert_eq!(
            volume.read_sectors(3, &mut [0; SECTOR_SIZE]),
            Err(VolumeError::OutOfBounds)
        );
        assert!(volume.read_sectors(3, &mut []).is_ok());
    }

    #[test]
    fn partition_io_is_relative_and_does_not_escape() {
        let mut volume = Volume::from_range(FakeDisk::zeroed(12), 5, 2).unwrap();
        volume.write_sectors(1, &[0xa5; SECTOR_SIZE]).unwrap();
        assert_eq!(volume.device().data[6 * SECTOR_SIZE], 0xa5);
        assert_eq!(volume.device().data[4 * SECTOR_SIZE], 0);
    }

    #[test]
    fn valid_gpt_selects_first_non_empty_partition() {
        let volume = Volume::discover(make_gpt(&[(40, 47), (60, 70)])).unwrap();
        assert_eq!((volume.start_lba(), volume.sector_count()), (40, 8));
    }

    #[test]
    fn gpt_entry_array_crc_is_required() {
        let mut disk = make_gpt(&[(40, 47)]);
        disk.sector_mut(2)[100] ^= 1;
        assert!(matches!(
            Volume::discover(disk),
            Err(VolumeError::InvalidGpt(GptError::InvalidEntryArrayCrc))
        ));
    }

    #[test]
    fn gpt_header_crc_is_required() {
        let mut disk = make_gpt(&[(40, 47)]);
        disk.sector_mut(1)[40] ^= 1;
        assert!(matches!(
            Volume::discover(disk),
            Err(VolumeError::InvalidGpt(GptError::InvalidHeaderCrc))
        ));
    }

    #[test]
    fn gpt_rejects_invalid_entry_layout_and_partition_range() {
        let mut bad_layout = make_gpt(&[(40, 47)]);
        put_u32(bad_layout.sector_mut(1), 84, 64);
        put_u32(bad_layout.sector_mut(1), 16, 0);
        let crc = crc32(&bad_layout.sector_mut(1)[..GPT_MIN_HEADER_SIZE]);
        put_u32(bad_layout.sector_mut(1), 16, crc);
        assert!(matches!(
            Volume::discover(bad_layout),
            Err(VolumeError::InvalidGpt(GptError::InvalidEntryLayout))
        ));

        let bad_range = make_gpt(&[(20, 47)]);
        assert!(matches!(
            Volume::discover(bad_range),
            Err(VolumeError::InvalidGpt(GptError::InvalidPartitionRange))
        ));
    }

    #[test]
    fn protective_mbr_without_gpt_is_not_used_as_legacy_mbr() {
        assert!(matches!(
            Volume::discover(make_mbr(1, 63, 0xee)),
            Err(VolumeError::InvalidGpt(GptError::MissingHeader))
        ));
    }

    #[test]
    fn legacy_mbr_partition_is_selected_and_checked() {
        let volume = Volume::discover(make_mbr(8, 20, 0x83)).unwrap();
        assert_eq!((volume.start_lba(), volume.sector_count()), (8, 20));
        assert!(matches!(
            Volume::discover(make_mbr(60, 10, 0x83)),
            Err(VolumeError::InvalidMbr)
        ));
    }

    #[test]
    fn device_errors_propagate_from_discovery_and_io() {
        let mut unreadable = FakeDisk::zeroed(8);
        unreadable.fail_read = true;
        assert!(matches!(
            Volume::discover(unreadable),
            Err(VolumeError::Device(FakeError::Read))
        ));

        let mut volume = Volume::whole_disk(FakeDisk::zeroed(8)).unwrap();
        volume.device_mut().fail_write = true;
        assert_eq!(
            volume.write_sectors(0, &[0; SECTOR_SIZE]),
            Err(VolumeError::Device(FakeError::Write))
        );
    }

    #[test]
    fn redoxfs_write_flushes_and_propagates_flush_failure() {
        let mut volume = Volume::whole_disk(FakeDisk::zeroed(32)).unwrap();
        unsafe { Disk::write_at(&mut volume, 0, &[7; SECTOR_SIZE]).unwrap() };
        assert_eq!(volume.device().flushes, 1);

        volume.device_mut().fail_flush = true;
        let result = unsafe { Disk::write_at(&mut volume, 0, &[8; SECTOR_SIZE]) };
        assert_eq!(result.unwrap_err().errno, EIO);
        assert_eq!(volume.device().flushes, 2);
    }

    #[test]
    fn redoxfs_access_checks_partition_boundary() {
        let mut volume = Volume::from_range(FakeDisk::zeroed(32), 8, 8).unwrap();
        let result = unsafe { Disk::read_at(&mut volume, 1, &mut [0; SECTOR_SIZE]) };
        assert_eq!(result.unwrap_err().errno, EINVAL);
        assert_eq!(Disk::size(&mut volume).unwrap(), 8 * SECTOR_SIZE as u64);
    }

    #[test]
    fn crc32_matches_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
