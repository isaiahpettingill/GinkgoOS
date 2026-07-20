//! GinkgoOS adapter for the RedoxFS transaction engine.
//!
//! The filesystem uses the upstream RedoxFS on-disk format over a mutable
//! memory-backed block device. A build script formats the seed image with the
//! same adapted `no_std` RedoxFS core used by the kernel.

use alloc::vec::Vec;

use redoxfs::{Disk, FileSystem, Node, TreePtr, BLOCK_SIZE};
use syscall::error::{Error, EEXIST, EINVAL, EIO, ENOENT, ENOSPC};

const SEED_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/redoxfs.img"));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandle {
    node_id: u32,
}

impl FileHandle {
    pub const fn node_id(self) -> u32 {
        self.node_id
    }

    fn node_ptr(self) -> TreePtr<Node> {
        TreePtr::new(self.node_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileInfo {
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

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Disk for MemoryDisk {
    unsafe fn read_at(
        &mut self,
        block: u64,
        buffer: &mut [u8],
    ) -> syscall::error::Result<usize> {
        let range = disk_range(block, buffer.len(), self.data.len())?;
        buffer.copy_from_slice(&self.data[range]);
        Ok(buffer.len())
    }

    unsafe fn write_at(
        &mut self,
        block: u64,
        buffer: &[u8],
    ) -> syscall::error::Result<usize> {
        let range = disk_range(block, buffer.len(), self.data.len())?;
        self.data[range].copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn size(&mut self) -> syscall::error::Result<u64> {
        Ok(self.data.len() as u64)
    }
}

/// A RedoxFS instance backed by kernel memory.
pub struct RedoxFs {
    inner: FileSystem<MemoryDisk>,
}

impl RedoxFs {
    pub fn new() -> Result<Self, FsError> {
        let disk = MemoryDisk::from_seed();
        let inner = FileSystem::open(disk, None, Some(0), false).map_err(map_error)?;
        Ok(Self { inner })
    }

    pub fn image_size(&mut self) -> Result<u64, FsError> {
        self.inner.disk.size().map_err(map_error)
    }

    pub fn file_count(&mut self) -> Result<usize, FsError> {
        let mut entries = Vec::new();
        self.inner
            .tx(|tx| tx.child_nodes(TreePtr::root(), &mut entries))
            .map_err(map_error)?;
        Ok(entries.len())
    }

    pub fn create(&mut self, path: &str) -> Result<FileHandle, FsError> {
        let name = parse_name(path)?;
        let node = self
            .inner
            .tx(|tx| {
                tx.create_node(
                    TreePtr::root(),
                    name,
                    Node::MODE_FILE | 0o644,
                    0,
                    0,
                )
            })
            .map_err(map_error)?;
        Ok(FileHandle {
            node_id: node.id(),
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
        Ok(FileHandle {
            node_id: node.id(),
        })
    }

    pub fn read(
        &mut self,
        file: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        self.inner
            .tx(|tx| tx.read_node(file.node_ptr(), offset, output, 0, 0))
            .map_err(handle_error)
    }

    pub fn write(
        &mut self,
        file: FileHandle,
        offset: u64,
        input: &[u8],
    ) -> Result<usize, FsError> {
        offset
            .checked_add(input.len() as u64)
            .ok_or(FsError::OffsetOverflow)?;
        self.inner
            .tx(|tx| tx.write_node(file.node_ptr(), offset, input, 0, 0))
            .map_err(handle_error)
    }

    pub fn truncate(&mut self, file: FileHandle, len: u64) -> Result<(), FsError> {
        self.inner
            .tx(|tx| tx.truncate_node(file.node_ptr(), len, 0, 0))
            .map_err(handle_error)
    }

    pub fn stat(&mut self, file: FileHandle) -> Result<FileInfo, FsError> {
        let node = self
            .inner
            .tx(|tx| tx.read_tree(file.node_ptr()))
            .map_err(handle_error)?;
        Ok(FileInfo {
            len: node.data().size(),
        })
    }

    pub fn remove(&mut self, file: FileHandle) -> Result<(), FsError> {
        self.inner
            .tx(|tx| {
                let mut entries = Vec::new();
                tx.child_nodes(TreePtr::root(), &mut entries)?;
                let entry = entries
                    .iter()
                    .find(|entry| entry.node_ptr().id() == file.node_id)
                    .ok_or_else(|| Error::new(ENOENT))?;
                let name = entry.name().ok_or_else(|| Error::new(EIO))?;
                tx.remove_node(TreePtr::root(), name, Node::MODE_FILE)?;
                Ok(())
            })
            .map_err(handle_error)
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
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(EIO))?;
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
