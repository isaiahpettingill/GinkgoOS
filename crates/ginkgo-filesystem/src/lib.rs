#![no_std]

//! GinkgoOS adapter for the RedoxFS transaction engine.
//!
//! The filesystem uses the upstream RedoxFS on-disk format over a mutable
//! memory-backed block device. A build script formats the seed image with the
//! same adapted `no_std` RedoxFS core used by the kernel.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use redoxfs::{Disk, FileSystem, Node, TreePtr, BLOCK_SIZE};
use syscall::error::{Error, EEXIST, EINVAL, EIO, ENOENT, ENOSPC};

const SEED_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/redoxfs.img"));
static NEXT_FILESYSTEM_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandle {
    filesystem_id: u64,
    node_id: u32,
    generation: u32,
}

impl FileHandle {
    pub const fn node_id(self) -> u32 {
        self.node_id
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileInfo {
    pub len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    InvalidName,
    AlreadyExists,
    NotFound,
    NoSpace,
    InvalidHandle,
    OffsetOverflow,
    Io,
}

/// A mutable memory disk containing a RedoxFS image.
pub struct MemoryDisk {
    data: Vec<u8>,
}

impl MemoryDisk {
    fn from_seed() -> Self {
        Self {
            data: SEED_IMAGE.to_vec(),
        }
    }

    pub fn zeroed(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Disk for MemoryDisk {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> syscall::error::Result<usize> {
        let range = disk_range(block, buffer.len(), self.data.len())?;
        buffer.copy_from_slice(&self.data[range]);
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> syscall::error::Result<usize> {
        let range = disk_range(block, buffer.len(), self.data.len())?;
        self.data[range].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn size(&mut self) -> syscall::error::Result<u64> {
        Ok(self.data.len() as u64)
    }
}

/// A RedoxFS instance over an owned block device.
pub struct RedoxFs<D: Disk = MemoryDisk> {
    filesystem_id: u64,
    generations: BTreeMap<u32, u32>,
    inner: FileSystem<D>,
}

impl RedoxFs<MemoryDisk> {
    pub fn new() -> Result<Self, FsError> {
        Self::open_disk(MemoryDisk::from_seed())
    }
}

impl<D: Disk> RedoxFs<D> {
    pub fn open_disk(disk: D) -> Result<Self, FsError> {
        let inner = FileSystem::open(disk, None, Some(0), false).map_err(map_error)?;
        Ok(Self::from_inner(inner))
    }

    pub fn format_disk(disk: D) -> Result<Self, FsError> {
        let inner = FileSystem::create(disk, 0, 0).map_err(map_error)?;
        Ok(Self::from_inner(inner))
    }

    fn from_inner(inner: FileSystem<D>) -> Self {
        let filesystem_id = NEXT_FILESYSTEM_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            filesystem_id,
            generations: BTreeMap::new(),
            inner,
        }
    }

    pub fn into_disk(self) -> D {
        self.inner.disk
    }

    pub fn image_size(&mut self) -> Result<u64, FsError> {
        self.inner.disk.size().map_err(map_error)
    }

    pub fn file_count(&mut self) -> Result<usize, FsError> {
        Ok(self.list_root()?.len())
    }

    pub fn list_root(&mut self) -> Result<Vec<DirectoryEntry>, FsError> {
        let mut directory = Vec::new();
        self.inner
            .tx(|tx| tx.child_nodes(TreePtr::root(), &mut directory))
            .map_err(map_error)?;

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(directory.len())
            .map_err(|_| FsError::NoSpace)?;
        for entry in directory {
            let name = entry.name().ok_or(FsError::Io)?;
            let node = self
                .inner
                .tx(|tx| tx.read_tree(entry.node_ptr()))
                .map_err(map_error)?;
            if !node.data().is_dir() {
                entries.push(DirectoryEntry {
                    name: String::from(name),
                    len: node.data().size(),
                });
            }
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    pub fn create(&mut self, path: &str) -> Result<FileHandle, FsError> {
        let name = parse_name(path)?;
        let node = self
            .inner
            .tx(|tx| tx.create_node(TreePtr::root(), name, Node::MODE_FILE | 0o644, 0, 0))
            .map_err(map_error)?;
        let generation = *self.generations.entry(node.id()).or_insert(1);
        Ok(FileHandle {
            filesystem_id: self.filesystem_id,
            node_id: node.id(),
            generation,
        })
    }

    pub fn open(&mut self, path: &str) -> Result<FileHandle, FsError> {
        let name = parse_name(path)?;
        let node = self
            .inner
            .tx(|tx| tx.find_node(TreePtr::root(), name))
            .map_err(map_error)?;
        if node.data().is_dir() {
            return Err(FsError::InvalidHandle);
        }
        let generation = *self.generations.entry(node.id()).or_insert(1);
        Ok(FileHandle {
            filesystem_id: self.filesystem_id,
            node_id: node.id(),
            generation,
        })
    }

    pub fn read(
        &mut self,
        file: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        let node = self.validate_handle(file)?;
        self.inner
            .tx(|tx| tx.read_node(node, offset, output, 0, 0))
            .map_err(handle_error)
    }

    pub fn write(&mut self, file: FileHandle, offset: u64, input: &[u8]) -> Result<usize, FsError> {
        offset
            .checked_add(input.len() as u64)
            .ok_or(FsError::OffsetOverflow)?;
        let node = self.validate_handle(file)?;
        self.inner
            .tx(|tx| tx.write_node(node, offset, input, 0, 0))
            .map_err(handle_error)
    }

    pub fn truncate(&mut self, file: FileHandle, len: u64) -> Result<(), FsError> {
        let node = self.validate_handle(file)?;
        self.inner
            .tx(|tx| tx.truncate_node(node, len, 0, 0))
            .map_err(handle_error)
    }

    pub fn stat(&mut self, file: FileHandle) -> Result<FileInfo, FsError> {
        let pointer = self.validate_handle(file)?;
        let node = self
            .inner
            .tx(|tx| tx.read_tree(pointer))
            .map_err(handle_error)?;
        Ok(FileInfo {
            len: node.data().size(),
        })
    }

    pub fn remove(&mut self, file: FileHandle) -> Result<(), FsError> {
        let node = self.validate_handle(file)?;
        self.inner
            .tx(|tx| {
                let mut entries = Vec::new();
                tx.child_nodes(TreePtr::root(), &mut entries)?;
                let entry = entries
                    .iter()
                    .find(|entry| entry.node_ptr().id() == node.id())
                    .ok_or_else(|| Error::new(ENOENT))?;
                let name = entry.name().ok_or_else(|| Error::new(EIO))?;
                tx.remove_node(TreePtr::root(), name, Node::MODE_FILE)?;
                Ok(())
            })
            .map_err(handle_error)?;
        let generation = self.generations.entry(file.node_id).or_insert(1);
        *generation = next_generation(*generation);
        Ok(())
    }

    fn validate_handle(&self, file: FileHandle) -> Result<TreePtr<Node>, FsError> {
        if file.filesystem_id != self.filesystem_id
            || self.generations.get(&file.node_id) != Some(&file.generation)
        {
            return Err(FsError::InvalidHandle);
        }
        Ok(TreePtr::new(file.node_id))
    }
}

const fn next_generation(generation: u32) -> u32 {
    let next = generation.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

fn parse_name(path: &str) -> Result<&str, FsError> {
    let name = path.strip_prefix('/').ok_or(FsError::InvalidName)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.contains('/')
        || name.contains(':')
    {
        return Err(FsError::InvalidName);
    }
    if name.len() > redoxfs::DIR_ENTRY_MAX_LENGTH {
        return Err(FsError::InvalidName);
    }
    Ok(name)
}

fn disk_range(
    block: u64,
    length: usize,
    disk_length: usize,
) -> syscall::error::Result<core::ops::Range<usize>> {
    let offset = block
        .checked_mul(BLOCK_SIZE)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| Error::new(EIO))?;
    let end = offset.checked_add(length).ok_or_else(|| Error::new(EIO))?;
    if end > disk_length {
        return Err(Error::new(EIO));
    }
    Ok(offset..end)
}

fn handle_error(error: Error) -> FsError {
    if error.errno == ENOENT {
        FsError::InvalidHandle
    } else {
        map_error(error)
    }
}

fn map_error(error: Error) -> FsError {
    match error.errno {
        EINVAL => FsError::InvalidName,
        EEXIST => FsError::AlreadyExists,
        ENOENT => FsError::NotFound,
        ENOSPC => FsError::NoSpace,
        _ => FsError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_read_and_reopen() {
        let mut fs = RedoxFs::new().unwrap();
        let file = fs.create("/hello").unwrap();
        assert_eq!(fs.write(file, 2, b"redoxfs").unwrap(), 7);
        assert_eq!(fs.open("/hello").unwrap(), file);
        assert_eq!(fs.stat(file).unwrap(), FileInfo { len: 9 });

        let mut output = [0xff; 16];
        let count = fs.read(file, 0, &mut output).unwrap();
        assert_eq!(count, 9);
        assert_eq!(&output[..count], b"\0\0redoxfs");
    }

    #[test]
    fn truncate_and_remove_are_transactional() {
        let mut fs = RedoxFs::new().unwrap();
        let file = fs.create("/data").unwrap();
        fs.write(file, 0, b"abcdefgh").unwrap();
        fs.truncate(file, 3).unwrap();
        fs.truncate(file, 6).unwrap();

        let mut output = [0xff; 6];
        fs.read(file, 0, &mut output).unwrap();
        assert_eq!(&output, b"abc\0\0\0");

        fs.remove(file).unwrap();
        assert_eq!(fs.stat(file), Err(FsError::InvalidHandle));
        assert_eq!(fs.open("/data"), Err(FsError::NotFound));

        let replacement = fs.create("/replacement").unwrap();
        assert_eq!(replacement.node_id(), file.node_id());
        assert_ne!(replacement.generation(), file.generation());
        assert_eq!(fs.write(file, 0, b"stale"), Err(FsError::InvalidHandle));
    }

    #[test]
    fn rejects_handles_from_another_filesystem() {
        let mut first = RedoxFs::new().unwrap();
        let mut second = RedoxFs::new().unwrap();
        let file = first.create("/first").unwrap();

        assert_eq!(second.stat(file), Err(FsError::InvalidHandle));
        assert_eq!(
            second.write(file, 0, b"wrong disk"),
            Err(FsError::InvalidHandle)
        );
    }

    #[test]
    fn persists_files_when_a_disk_is_reopened() {
        let disk = MemoryDisk::zeroed(2 * 1024 * 1024);
        let mut fs = RedoxFs::format_disk(disk).unwrap();
        let file = fs.create("/persistent").unwrap();
        fs.write(file, 0, b"survives reboot").unwrap();

        let disk = fs.into_disk();
        let mut reopened = RedoxFs::open_disk(disk).unwrap();
        let file = reopened.open("/persistent").unwrap();
        let mut bytes = [0; 15];
        assert_eq!(reopened.read(file, 0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"survives reboot");
    }

    #[test]
    fn lists_root_files_in_lexical_order() {
        let mut fs = RedoxFs::new().unwrap();
        fs.create("/zeta").unwrap();
        fs.create("/alpha").unwrap();
        let entries = fs.list_root().unwrap();
        assert_eq!(entries[0].name, "alpha");
        assert_eq!(entries[1].name, "zeta");
    }

    #[test]
    fn validates_flat_kernel_paths() {
        let mut fs = RedoxFs::new().unwrap();
        assert_eq!(fs.create("relative"), Err(FsError::InvalidName));
        assert_eq!(fs.create("/"), Err(FsError::InvalidName));
        assert_eq!(fs.create("/a/b"), Err(FsError::InvalidName));
        fs.create("/one").unwrap();
        assert_eq!(fs.create("/one"), Err(FsError::AlreadyExists));
        assert_eq!(fs.file_count().unwrap(), 1);
    }
}
