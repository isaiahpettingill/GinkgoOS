//! Strict ELF64 loader planning for Ginkgo x86-64 executables.
//!
//! The Ginkgo executable profile accepts only little-endian ELF64 `ET_EXEC`
//! files for x86-64. It uses only nonempty `PT_LOAD` headers, requires readable
//! segments with at least 4 KiB power-of-two alignment, enforces W^X, rejects
//! page overlap and zero/noncanonical/higher-half mappings, and requires the
//! entry point to lie in an executable segment. Program headers and total load
//! pages are capped for the kernel's fixed-allocation, no-demand-paging model;
//! other program-header types are ignored rather than interpreted.
//!
//! Parsing is dependency-free and never indexes untrusted input without a
//! preceding bounds check. Loading is expressed as a page callback so callers
//! can use `AddressSpace::map_zeroed_user_4k`, then initialize the returned
//! owned frame through the HHDM even when the final mapping is read/execute.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::{max, min};

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_PROGRAM_HEADERS: usize = 128;
/// Maximum pages mapped from all `PT_LOAD` segments: 64 MiB at 4 KiB/page.
///
/// The current kernel eagerly allocates every image page from a monotonic frame
/// allocator and cannot reclaim it. Keeping one executable below one eighth of
/// the standard 512 MiB development machine prevents a malformed image from
/// consuming nearly all boot memory before stacks and page tables are created.
pub const MAX_TOTAL_LOAD_PAGES: u64 = 16_384;
pub const USER_ADDRESS_END: u64 = 0x0000_8000_0000_0000;

const ELF_HEADER_SIZE: u16 = 64;
const PROGRAM_HEADER_SIZE: u16 = 56;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u32 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const VALID_SEGMENT_FLAGS: u32 = PF_R | PF_W | PF_X;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentPermissions {
    pub writable: bool,
    pub executable: bool,
}

impl SegmentPermissions {
    pub const fn is_writable(self) -> bool {
        self.writable
    }

    pub const fn is_executable(self) -> bool {
        self.executable
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedSegment {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub file_size: u64,
    pub page_start: u64,
    pub page_count: u64,
    pub permissions: SegmentPermissions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    pub entry: u64,
    pub segments: Vec<LoadedSegment>,
}

/// A fully validated ELF image that has not yet modified an address space.
pub struct ParsedElf<'a> {
    file: &'a [u8],
    entry: u64,
    total_load_pages: u64,
    segments: Vec<LoadSegment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LoadSegment {
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    page_start: u64,
    page_end: u64,
    permissions: SegmentPermissions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    Truncated { offset: u64, size: usize },
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEndian(u8),
    UnsupportedIdentVersion(u8),
    UnsupportedType(u16),
    UnsupportedMachine(u16),
    UnsupportedVersion(u32),
    InvalidHeaderSize(u16),
    InvalidProgramHeaderSize(u16),
    MissingProgramHeaders,
    TooManyProgramHeaders(u16),
    ProgramHeaderTableBeforeHeader(u64),
    ProgramHeaderTableOverflow,
    ProgramHeaderTableOutOfBounds,
    AllocationFailed,
    NoLoadSegments,
    EmptyLoadSegment { index: u16 },
    FileSizeExceedsMemorySize { index: u16 },
    FileRangeOverflow { index: u16 },
    FileRangeOutOfBounds { index: u16 },
    VirtualRangeOverflow { index: u16 },
    InvalidUserRange { index: u16 },
    InvalidAlignment { index: u16, alignment: u64 },
    IncongruentAlignment { index: u16 },
    UnknownSegmentFlags { index: u16, flags: u32 },
    UnreadableLoadSegment { index: u16 },
    WritableExecutableSegment { index: u16 },
    OverlappingLoadPages { first: u16, second: u16 },
    TooManyLoadPages { pages: u64, maximum: u64 },
    InvalidEntry(u64),
    EntryNotExecutable(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError<E> {
    Elf(ElfError),
    Page(E),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedRangeError {
    AddressOverflow,
    InvalidUserRange { start: u64, length: u64 },
}

impl<E> From<ElfError> for LoadError<E> {
    fn from(error: ElfError) -> Self {
        Self::Elf(error)
    }
}

/// Parses and validates an ELF64 little-endian x86-64 `ET_EXEC` image.
pub fn parse(file: &[u8]) -> Result<ParsedElf<'_>, ElfError> {
    let reader = Reader::new(file);
    let ident = reader.bytes::<16>(0)?;
    if ident[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::BadMagic);
    }
    if ident[4] != ELFCLASS64 {
        return Err(ElfError::UnsupportedClass(ident[4]));
    }
    if ident[5] != ELFDATA2LSB {
        return Err(ElfError::UnsupportedEndian(ident[5]));
    }
    if ident[6] != EV_CURRENT as u8 {
        return Err(ElfError::UnsupportedIdentVersion(ident[6]));
    }

    let elf_type = reader.u16(16)?;
    if elf_type != ET_EXEC {
        return Err(ElfError::UnsupportedType(elf_type));
    }
    let machine = reader.u16(18)?;
    if machine != EM_X86_64 {
        return Err(ElfError::UnsupportedMachine(machine));
    }
    let version = reader.u32(20)?;
    if version != EV_CURRENT {
        return Err(ElfError::UnsupportedVersion(version));
    }

    let entry = reader.u64(24)?;
    let program_header_offset = reader.u64(32)?;
    let header_size = reader.u16(52)?;
    if header_size != ELF_HEADER_SIZE {
        return Err(ElfError::InvalidHeaderSize(header_size));
    }
    let program_header_size = reader.u16(54)?;
    if program_header_size != PROGRAM_HEADER_SIZE {
        return Err(ElfError::InvalidProgramHeaderSize(program_header_size));
    }
    let program_header_count = reader.u16(56)?;
    if program_header_count == 0 {
        return Err(ElfError::MissingProgramHeaders);
    }
    if usize::from(program_header_count) > MAX_PROGRAM_HEADERS {
        return Err(ElfError::TooManyProgramHeaders(program_header_count));
    }
    if program_header_offset < u64::from(ELF_HEADER_SIZE) {
        return Err(ElfError::ProgramHeaderTableBeforeHeader(
            program_header_offset,
        ));
    }

    let table_size = u64::from(program_header_size)
        .checked_mul(u64::from(program_header_count))
        .ok_or(ElfError::ProgramHeaderTableOverflow)?;
    let table_end = program_header_offset
        .checked_add(table_size)
        .ok_or(ElfError::ProgramHeaderTableOverflow)?;
    if table_end > usize_to_u64(file.len())? {
        return Err(ElfError::ProgramHeaderTableOutOfBounds);
    }

    let mut segments: Vec<LoadSegment> = Vec::new();
    segments
        .try_reserve_exact(usize::from(program_header_count))
        .map_err(|_| ElfError::AllocationFailed)?;
    let mut segment_indexes = Vec::new();
    segment_indexes
        .try_reserve_exact(usize::from(program_header_count))
        .map_err(|_| ElfError::AllocationFailed)?;
    let mut total_load_pages = 0u64;

    for index in 0..program_header_count {
        let offset = program_header_offset
            .checked_add(u64::from(index) * u64::from(program_header_size))
            .ok_or(ElfError::ProgramHeaderTableOverflow)?;
        if reader.u32(offset)? != PT_LOAD {
            continue;
        }

        let flags = reader.u32(offset + 4)?;
        let file_offset = reader.u64(offset + 8)?;
        let virtual_address = reader.u64(offset + 16)?;
        let file_size = reader.u64(offset + 32)?;
        let memory_size = reader.u64(offset + 40)?;
        let alignment = reader.u64(offset + 48)?;

        if memory_size == 0 {
            return Err(ElfError::EmptyLoadSegment { index });
        }
        if file_size > memory_size {
            return Err(ElfError::FileSizeExceedsMemorySize { index });
        }
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or(ElfError::FileRangeOverflow { index })?;
        if file_end > usize_to_u64(file.len())? {
            return Err(ElfError::FileRangeOutOfBounds { index });
        }
        let virtual_end = virtual_address
            .checked_add(memory_size)
            .ok_or(ElfError::VirtualRangeOverflow { index })?;
        if virtual_address < PAGE_SIZE || virtual_end > USER_ADDRESS_END {
            return Err(ElfError::InvalidUserRange { index });
        }
        if alignment < PAGE_SIZE || !alignment.is_power_of_two() {
            return Err(ElfError::InvalidAlignment { index, alignment });
        }
        if virtual_address % alignment != file_offset % alignment {
            return Err(ElfError::IncongruentAlignment { index });
        }
        if flags & !VALID_SEGMENT_FLAGS != 0 {
            return Err(ElfError::UnknownSegmentFlags { index, flags });
        }
        if flags & PF_R == 0 {
            // x86-64 user mappings are always readable; accepting this would
            // silently grant a permission absent from the ELF segment.
            return Err(ElfError::UnreadableLoadSegment { index });
        }
        let writable = flags & PF_W != 0;
        let executable = flags & PF_X != 0;
        if writable && executable {
            return Err(ElfError::WritableExecutableSegment { index });
        }

        let page_start = align_down(virtual_address);
        let page_end = align_up(virtual_end).ok_or(ElfError::VirtualRangeOverflow { index })?;
        let page_count = (page_end - page_start) / PAGE_SIZE;
        total_load_pages =
            total_load_pages
                .checked_add(page_count)
                .ok_or(ElfError::TooManyLoadPages {
                    pages: u64::MAX,
                    maximum: MAX_TOTAL_LOAD_PAGES,
                })?;
        if total_load_pages > MAX_TOTAL_LOAD_PAGES {
            return Err(ElfError::TooManyLoadPages {
                pages: total_load_pages,
                maximum: MAX_TOTAL_LOAD_PAGES,
            });
        }
        for (other_position, other) in segments.iter().enumerate() {
            if ranges_overlap(page_start, page_end, other.page_start, other.page_end) {
                return Err(ElfError::OverlappingLoadPages {
                    first: segment_indexes[other_position],
                    second: index,
                });
            }
        }

        segments.push(LoadSegment {
            file_offset,
            virtual_address,
            file_size,
            memory_size,
            page_start,
            page_end,
            permissions: SegmentPermissions {
                writable,
                executable,
            },
        });
        segment_indexes.push(index);
    }

    if segments.is_empty() {
        return Err(ElfError::NoLoadSegments);
    }
    if entry < PAGE_SIZE || entry >= USER_ADDRESS_END {
        return Err(ElfError::InvalidEntry(entry));
    }
    if !segments.iter().any(|segment| {
        segment.permissions.executable
            && entry >= segment.virtual_address
            && entry < segment.virtual_address + segment.memory_size
    }) {
        return Err(ElfError::EntryNotExecutable(entry));
    }

    Ok(ParsedElf {
        file,
        entry,
        total_load_pages,
        segments,
    })
}

impl<'a> ParsedElf<'a> {
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub const fn total_load_pages(&self) -> u64 {
        self.total_load_pages
    }

    /// Checks whether mapped image pages overlap a reserved user virtual range.
    ///
    /// The nonempty reserved range must lie entirely in the nonzero canonical
    /// lower half. Both it and the load segments are compared at page
    /// granularity, so an unaligned stack or guard range reserves every page it
    /// touches. An empty range never overlaps and does not inspect `start`.
    /// Call this after parsing and before consuming the image with `load_with`.
    pub fn overlaps_reserved_range(
        &self,
        start: u64,
        length: u64,
    ) -> Result<bool, ReservedRangeError> {
        if length == 0 {
            return Ok(false);
        }
        let end = start
            .checked_add(length)
            .ok_or(ReservedRangeError::AddressOverflow)?;
        if start < PAGE_SIZE || end > USER_ADDRESS_END {
            return Err(ReservedRangeError::InvalidUserRange { start, length });
        }
        let page_start = align_down(start);
        let page_end = align_up(end).ok_or(ReservedRangeError::AddressOverflow)?;
        Ok(self.segments.iter().any(|segment| {
            ranges_overlap(page_start, page_end, segment.page_start, segment.page_end)
        }))
    }

    /// Loads validated pages through an address-space integration callback.
    ///
    /// Each callback invocation receives a page-aligned, nonzero lower-half
    /// user address, final W^X permissions, and a complete zero-initialized
    /// 4 KiB page containing any file-backed bytes. The callback should:
    ///
    /// 1. call `AddressSpace::map_zeroed_user_4k` with equivalent permissions;
    /// 2. use its returned owned frame plus the HHDM to copy `contents` into
    ///    that frame (copying only nonzero spans is also valid).
    ///
    /// Initializing through the owned frame is necessary for final RX pages:
    /// `AddressSpace::copy_to_user` intentionally requires an active, writable
    /// destination. All ELF validation and `LoadedImage` metadata allocation
    /// complete before the first callback, so only page integration can fail
    /// after mappings begin. If the callback fails, pages accepted by earlier
    /// invocations remain
    /// mapped and owned by the address space.
    pub fn load_with<F, E>(self, mut load_page: F) -> Result<LoadedImage, LoadError<E>>
    where
        F: FnMut(u64, SegmentPermissions, &[u8; PAGE_SIZE as usize]) -> Result<(), E>,
    {
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(self.segments.len())
            .map_err(|_| LoadError::Elf(ElfError::AllocationFailed))?;
        for segment in &self.segments {
            metadata.push(LoadedSegment {
                virtual_address: segment.virtual_address,
                memory_size: segment.memory_size,
                file_size: segment.file_size,
                page_start: segment.page_start,
                page_count: (segment.page_end - segment.page_start) / PAGE_SIZE,
                permissions: segment.permissions,
            });
        }
        let loaded = LoadedImage {
            entry: self.entry,
            segments: metadata,
        };

        for segment in &self.segments {
            let file_virtual_end = segment
                .virtual_address
                .checked_add(segment.file_size)
                .expect("validated ELF file range");
            let mut page_address = segment.page_start;
            while page_address < segment.page_end {
                let mut contents = [0u8; PAGE_SIZE as usize];
                let page_end = page_address + PAGE_SIZE;
                let copy_start = max(page_address, segment.virtual_address);
                let copy_end = min(page_end, file_virtual_end);
                if copy_start < copy_end {
                    let source_start = segment.file_offset + (copy_start - segment.virtual_address);
                    let copy_length = copy_end - copy_start;
                    let destination_start = copy_start - page_address;
                    let source_start = source_start as usize;
                    let source_end = source_start + copy_length as usize;
                    let destination_start = destination_start as usize;
                    let destination_end = destination_start + copy_length as usize;
                    contents[destination_start..destination_end]
                        .copy_from_slice(&self.file[source_start..source_end]);
                }
                load_page(page_address, segment.permissions, &contents).map_err(LoadError::Page)?;
                page_address += PAGE_SIZE;
            }
        }

        Ok(loaded)
    }
}

/// Parses and loads an ELF image using the same callback contract as
/// [`ParsedElf::load_with`].
pub fn load_with<F, E>(file: &[u8], load_page: F) -> Result<LoadedImage, LoadError<E>>
where
    F: FnMut(u64, SegmentPermissions, &[u8; PAGE_SIZE as usize]) -> Result<(), E>,
{
    parse(file)?.load_with(load_page)
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn bytes<const N: usize>(&self, offset: u64) -> Result<[u8; N], ElfError> {
        let start = usize::try_from(offset).map_err(|_| ElfError::Truncated { offset, size: N })?;
        let end = start
            .checked_add(N)
            .ok_or(ElfError::Truncated { offset, size: N })?;
        let source = self
            .bytes
            .get(start..end)
            .ok_or(ElfError::Truncated { offset, size: N })?;
        let mut result = [0; N];
        result.copy_from_slice(source);
        Ok(result)
    }

    fn u16(&self, offset: u64) -> Result<u16, ElfError> {
        Ok(u16::from_le_bytes(self.bytes::<2>(offset)?))
    }

    fn u32(&self, offset: u64) -> Result<u32, ElfError> {
        Ok(u32::from_le_bytes(self.bytes::<4>(offset)?))
    }

    fn u64(&self, offset: u64) -> Result<u64, ElfError> {
        Ok(u64::from_le_bytes(self.bytes::<8>(offset)?))
    }
}

fn usize_to_u64(value: usize) -> Result<u64, ElfError> {
    u64::try_from(value).map_err(|_| ElfError::ProgramHeaderTableOutOfBounds)
}

const fn align_down(address: u64) -> u64 {
    address & !(PAGE_SIZE - 1)
}

fn align_up(address: u64) -> Option<u64> {
    address
        .checked_add(PAGE_SIZE - 1)
        .map(|value| align_down(value))
}

const fn ranges_overlap(
    first_start: u64,
    first_end: u64,
    second_start: u64,
    second_end: u64,
) -> bool {
    first_start < second_end && second_start < first_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const HEADER: usize = ELF_HEADER_SIZE as usize;
    const PHDR: usize = PROGRAM_HEADER_SIZE as usize;

    #[derive(Clone, Copy)]
    struct ProgramHeader {
        kind: u32,
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    }

    impl ProgramHeader {
        const fn load(
            flags: u32,
            offset: u64,
            virtual_address: u64,
            file_size: u64,
            memory_size: u64,
        ) -> Self {
            Self {
                kind: PT_LOAD,
                flags,
                offset,
                virtual_address,
                file_size,
                memory_size,
                alignment: PAGE_SIZE,
            }
        }
    }

    fn fixture(entry: u64, headers: &[ProgramHeader]) -> Vec<u8> {
        let mut length = HEADER + PHDR * headers.len();
        for header in headers {
            if let Some(end) = header.offset.checked_add(header.file_size) {
                if let Ok(end) = usize::try_from(end) {
                    length = length.max(end);
                }
            }
        }
        let mut file = vec![0u8; length];
        file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        file[4] = ELFCLASS64;
        file[5] = ELFDATA2LSB;
        file[6] = EV_CURRENT as u8;
        put_u16(&mut file, 16, ET_EXEC);
        put_u16(&mut file, 18, EM_X86_64);
        put_u32(&mut file, 20, EV_CURRENT);
        put_u64(&mut file, 24, entry);
        put_u64(&mut file, 32, HEADER as u64);
        put_u16(&mut file, 52, ELF_HEADER_SIZE);
        put_u16(&mut file, 54, PROGRAM_HEADER_SIZE);
        put_u16(&mut file, 56, headers.len() as u16);

        for (index, header) in headers.iter().enumerate() {
            let base = HEADER + index * PHDR;
            put_u32(&mut file, base, header.kind);
            put_u32(&mut file, base + 4, header.flags);
            put_u64(&mut file, base + 8, header.offset);
            put_u64(&mut file, base + 16, header.virtual_address);
            put_u64(&mut file, base + 32, header.file_size);
            put_u64(&mut file, base + 40, header.memory_size);
            put_u64(&mut file, base + 48, header.alignment);
        }
        file
    }

    fn one_load() -> Vec<u8> {
        let mut file = fixture(
            0x401000,
            &[ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 4, 4)],
        );
        file[0x1000..0x1004].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
        file
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn loads_valid_rx_and_rw_bss_segments() {
        let mut file = fixture(
            0x401001,
            &[
                ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 4, 4),
                ProgramHeader::load(PF_R | PF_W, 0x2000, 0x403000, 3, 0x1100),
            ],
        );
        file[0x1000..0x1004].copy_from_slice(&[1, 2, 3, 4]);
        file[0x2000..0x2003].copy_from_slice(&[5, 6, 7]);

        let mut pages = Vec::new();
        let loaded = load_with(&file, |address, permissions, contents| {
            pages.push((address, permissions, *contents));
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(loaded.entry, 0x401001);
        assert_eq!(loaded.segments.len(), 2);
        assert_eq!(loaded.segments[1].page_count, 2);
        assert_eq!(pages.len() as u64, parse(&file).unwrap().total_load_pages());
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].0, 0x401000);
        assert_eq!(&pages[0].2[..4], &[1, 2, 3, 4]);
        assert!(pages[0].2[4..].iter().all(|byte| *byte == 0));
        assert_eq!(pages[1].0, 0x403000);
        assert_eq!(&pages[1].2[..3], &[5, 6, 7]);
        assert!(pages[1].2[3..].iter().all(|byte| *byte == 0));
        assert_eq!(pages[2].0, 0x404000);
        assert!(pages[2].2.iter().all(|byte| *byte == 0));
        assert_eq!(
            pages[0].1,
            SegmentPermissions {
                writable: false,
                executable: true
            }
        );
        assert_eq!(
            pages[1].1,
            SegmentPermissions {
                writable: true,
                executable: false
            }
        );
    }

    #[test]
    fn copies_an_unaligned_congruent_segment_across_pages() {
        let mut file = fixture(
            0x401123,
            &[ProgramHeader::load(
                PF_R | PF_X,
                0x1123,
                0x401123,
                0x1000,
                0x1000,
            )],
        );
        for (index, byte) in file[0x1123..0x2123].iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let mut pages = Vec::new();
        load_with(&file, |address, _, contents| {
            pages.push((address, *contents));
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(pages.len(), 2);
        assert!(pages[0].1[..0x123].iter().all(|byte| *byte == 0));
        assert_eq!(&pages[0].1[0x123..0x127], &[0, 1, 2, 3]);
        assert_eq!(&pages[1].1[..4], &[0xdd, 0xde, 0xdf, 0xe0]);
        assert!(pages[1].1[0x123..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_truncation_and_ident_fields() {
        assert!(matches!(parse(&[]), Err(ElfError::Truncated { .. })));

        let mut file = one_load();
        file[0] = 0;
        assert_eq!(parse(&file).err(), Some(ElfError::BadMagic));
        file = one_load();
        file[4] = 1;
        assert_eq!(parse(&file).err(), Some(ElfError::UnsupportedClass(1)));
        file = one_load();
        file[5] = 2;
        assert_eq!(parse(&file).err(), Some(ElfError::UnsupportedEndian(2)));
        file = one_load();
        file[6] = 0;
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::UnsupportedIdentVersion(0))
        );
    }

    #[test]
    fn rejects_wrong_type_machine_and_version() {
        let mut file = one_load();
        put_u16(&mut file, 16, 3);
        assert_eq!(parse(&file).err(), Some(ElfError::UnsupportedType(3)));
        file = one_load();
        put_u16(&mut file, 18, 3);
        assert_eq!(parse(&file).err(), Some(ElfError::UnsupportedMachine(3)));
        file = one_load();
        put_u32(&mut file, 20, 0);
        assert_eq!(parse(&file).err(), Some(ElfError::UnsupportedVersion(0)));
    }

    #[test]
    fn rejects_invalid_header_and_program_header_tables() {
        let mut file = one_load();
        put_u16(&mut file, 52, 63);
        assert_eq!(parse(&file).err(), Some(ElfError::InvalidHeaderSize(63)));
        file = one_load();
        put_u16(&mut file, 54, 55);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::InvalidProgramHeaderSize(55))
        );
        file = one_load();
        put_u16(&mut file, 56, 0);
        assert_eq!(parse(&file).err(), Some(ElfError::MissingProgramHeaders));
        file = one_load();
        put_u16(&mut file, 56, MAX_PROGRAM_HEADERS as u16 + 1);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::TooManyProgramHeaders(129))
        );
        file = one_load();
        put_u64(&mut file, 32, 1);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::ProgramHeaderTableBeforeHeader(1))
        );
        file = one_load();
        put_u64(&mut file, 32, u64::MAX - 20);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::ProgramHeaderTableOverflow)
        );
        file = one_load();
        let file_length = file.len() as u64;
        put_u64(&mut file, 32, file_length);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::ProgramHeaderTableOutOfBounds)
        );
    }

    #[test]
    fn ignores_non_load_headers_but_requires_a_load_segment() {
        let mut header = ProgramHeader::load(PF_R, 0x1000, 0x401000, 1, 1);
        header.kind = 4;
        let file = fixture(0x401000, &[header]);
        assert_eq!(parse(&file).err(), Some(ElfError::NoLoadSegments));
    }

    #[test]
    fn rejects_bad_file_and_virtual_ranges() {
        let file = fixture(
            0x401000,
            &[ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 2, 1)],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::FileSizeExceedsMemorySize { index: 0 })
        );

        let mut file = one_load();
        put_u64(&mut file, HEADER + 8, u64::MAX - 1);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::FileRangeOverflow { index: 0 })
        );
        file = one_load();
        let file_length = file.len() as u64;
        put_u64(&mut file, HEADER + 8, file_length);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::FileRangeOutOfBounds { index: 0 })
        );
        file = one_load();
        put_u64(&mut file, HEADER + 16, u64::MAX - 1);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::VirtualRangeOverflow { index: 0 })
        );
    }

    #[test]
    fn rejects_zero_page_noncanonical_and_higher_half_ranges() {
        let file = fixture(0x1000, &[ProgramHeader::load(PF_R | PF_X, 0, 0, 1, 1)]);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::InvalidUserRange { index: 0 })
        );

        for address in [USER_ADDRESS_END, 0xffff_8000_0000_0000] {
            let file = fixture(
                address,
                &[ProgramHeader::load(PF_R | PF_X, 0x1000, address, 1, 1)],
            );
            assert_eq!(
                parse(&file).err(),
                Some(ElfError::InvalidUserRange { index: 0 })
            );
        }
    }

    #[test]
    fn rejects_invalid_or_incongruent_alignment() {
        let mut header = ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 1, 1);
        header.alignment = 24;
        let file = fixture(0x401000, &[header]);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::InvalidAlignment {
                index: 0,
                alignment: 24
            })
        );

        header.alignment = PAGE_SIZE;
        header.virtual_address += 1;
        let file = fixture(header.virtual_address, &[header]);
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::IncongruentAlignment { index: 0 })
        );
    }

    #[test]
    fn checks_reserved_ranges_against_mapped_pages() {
        let file = one_load();
        let parsed = parse(&file).unwrap();

        assert!(parsed.overlaps_reserved_range(0x401000, 1).unwrap());
        assert!(parsed.overlaps_reserved_range(0x400fff, 2).unwrap());
        assert!(!parsed.overlaps_reserved_range(0x402000, PAGE_SIZE).unwrap());
        assert!(!parsed.overlaps_reserved_range(u64::MAX, 0).unwrap());
        assert_eq!(
            parsed.overlaps_reserved_range(0, PAGE_SIZE),
            Err(ReservedRangeError::InvalidUserRange {
                start: 0,
                length: PAGE_SIZE
            })
        );
        assert_eq!(
            parsed.overlaps_reserved_range(u64::MAX - 1, PAGE_SIZE),
            Err(ReservedRangeError::AddressOverflow)
        );
    }

    #[test]
    fn rejects_oversized_total_load_page_count() {
        let pages = MAX_TOTAL_LOAD_PAGES + 1;
        let file = fixture(
            0x401000,
            &[ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                1,
                pages * PAGE_SIZE,
            )],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::TooManyLoadPages {
                pages,
                maximum: MAX_TOTAL_LOAD_PAGES
            })
        );
    }

    #[test]
    fn rejects_overlapping_load_pages() {
        let file = fixture(
            0x401000,
            &[
                ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 1, 1),
                ProgramHeader::load(PF_R | PF_W, 0x2800, 0x401800, 1, 1),
            ],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::OverlappingLoadPages {
                first: 0,
                second: 1
            })
        );
    }

    #[test]
    fn rejects_unsafe_or_unrepresentable_permissions() {
        let file = fixture(
            0x401000,
            &[ProgramHeader::load(
                PF_R | PF_W | PF_X,
                0x1000,
                0x401000,
                1,
                1,
            )],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::WritableExecutableSegment { index: 0 })
        );

        let file = fixture(
            0x401000,
            &[ProgramHeader::load(PF_X, 0x1000, 0x401000, 1, 1)],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::UnreadableLoadSegment { index: 0 })
        );

        let file = fixture(
            0x401000,
            &[ProgramHeader::load(PF_R | 8, 0x1000, 0x401000, 1, 1)],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::UnknownSegmentFlags {
                index: 0,
                flags: PF_R | 8
            })
        );
    }

    #[test]
    fn requires_entry_inside_an_executable_segment() {
        let file = fixture(
            0x403000,
            &[ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 1, 1)],
        );
        assert_eq!(
            parse(&file).err(),
            Some(ElfError::EntryNotExecutable(0x403000))
        );

        let file = fixture(
            0,
            &[ProgramHeader::load(PF_R | PF_X, 0x1000, 0x401000, 1, 1)],
        );
        assert_eq!(parse(&file).err(), Some(ElfError::InvalidEntry(0)));
    }

    #[test]
    fn validates_everything_before_loading_and_propagates_page_errors() {
        let mut calls = 0;
        let malformed = &one_load()[..HEADER];
        let error = load_with(malformed, |_, _, _| {
            calls += 1;
            Ok::<_, u8>(())
        })
        .unwrap_err();
        assert!(matches!(error, LoadError::Elf(_)));
        assert_eq!(calls, 0);

        let pages = MAX_TOTAL_LOAD_PAGES + 1;
        let oversized = fixture(
            0x401000,
            &[ProgramHeader::load(
                PF_R | PF_X,
                0x1000,
                0x401000,
                1,
                pages * PAGE_SIZE,
            )],
        );
        let error = load_with(&oversized, |_, _, _| {
            calls += 1;
            Ok::<_, u8>(())
        })
        .unwrap_err();
        assert_eq!(
            error,
            LoadError::Elf(ElfError::TooManyLoadPages {
                pages,
                maximum: MAX_TOTAL_LOAD_PAGES
            })
        );
        assert_eq!(calls, 0);

        let error = load_with(&one_load(), |_, _, _| Err::<(), _>(7u8)).unwrap_err();
        assert_eq!(error, LoadError::Page(7));
    }
}
