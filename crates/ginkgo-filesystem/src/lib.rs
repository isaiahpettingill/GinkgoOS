#![no_std]

//! Capability-oriented GinkgoOS adapter for the RedoxFS transaction engine.
//!
//! Paths accepted by directory-scoped methods are relative, contain at most
//! [`MAX_TRAVERSAL_DEPTH`] components, and never interpret `.`, `..`, empty
//! components, drive prefixes, or symlinks. This makes a [`DirectoryHandle`] a
//! namespace boundary rather than an ambient-current-directory convenience.
//!
//! RedoxFS exposes creation and modification times, Unix mode, uid, and gid;
//! these are retained in [`NodeMetadata`]. `policy` is reserved for a future
//! GinkgoOS access-policy identifier and is currently always zero. RedoxFS does
//! not expose birth-time distinct from ctime or a device-cache flush operation.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use redoxfs::{
    BlockAddr, BlockMeta, Disk, FileSystem, Node, Transaction, TreeData, TreePtr, BLOCK_SIZE,
};
use syscall::error::{
    Error, EEXIST, EINVAL, EIO, EISDIR, ELOOP, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY,
};

const SEED_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/redoxfs.img"));
static NEXT_FILESYSTEM_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of components in any directory-scoped path.
pub const MAX_TRAVERSAL_DEPTH: usize = 32;

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

/// A generation-protected directory capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryHandle {
    filesystem_id: u64,
    node_id: u32,
    generation: u32,
}

impl DirectoryHandle {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: u64,
    pub nanoseconds: u32,
}

/// Metadata supplied directly by RedoxFS, except for reserved `policy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeMetadata {
    pub kind: NodeKind,
    pub size: u64,
    /// Stable RedoxFS tree-node identity within this filesystem image.
    pub identity: u64,
    /// RedoxFS type and Unix permission bits.
    pub mode: u16,
    /// Reserved GinkgoOS policy identifier; currently zero.
    pub policy: u32,
    pub uid: u32,
    pub gid: u32,
    pub ctime: Timestamp,
    pub mtime: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    /// Compatibility alias for `metadata.size`.
    pub len: u64,
    pub metadata: NodeMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameMode {
    NoReplace,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemInfo {
    pub capacity_bytes: u64,
    /// `None` explicitly means that the backing filesystem cannot report free
    /// space. RedoxFS currently provides this value, so this adapter returns
    /// `Some` unless arithmetic overflows.
    pub free_bytes: Option<u64>,
    pub block_size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    InvalidName,
    TraversalTooDeep,
    AlreadyExists,
    NotFound,
    NoSpace,
    InvalidHandle,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    WouldCycle,
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

    /// Exposes the owned backing disk for explicit device-cache synchronization.
    pub fn disk_mut(&mut self) -> &mut D {
        &mut self.inner.disk
    }

    pub fn image_size(&mut self) -> Result<u64, FsError> {
        self.inner.disk.size().map_err(map_error)
    }

    /// Grows the filesystem to the current backing-device size.
    ///
    /// Existing data and allocation state are preserved. Shrinking is never
    /// attempted, and a device whose size is unchanged is a no-op.
    pub fn grow_to_disk(&mut self) -> Result<bool, FsError> {
        let disk_size = self.inner.disk.size().map_err(map_error)?;
        let filesystem_offset = self
            .inner
            .block
            .checked_mul(BLOCK_SIZE)
            .ok_or(FsError::OffsetOverflow)?;
        let available = disk_size
            .checked_sub(filesystem_offset)
            .ok_or(FsError::OffsetOverflow)?;
        let new_size = available / BLOCK_SIZE * BLOCK_SIZE;
        let old_size = self.inner.header.size();
        if new_size <= old_size {
            return Ok(false);
        }

        let old_blocks = old_size / BLOCK_SIZE;
        let new_blocks = new_size / BLOCK_SIZE;
        let old_allocator = self.inner.allocator().clone();
        // SAFETY: each address is newly exposed by growth beyond the old
        // filesystem boundary, is block-aligned, and cannot overlap an existing
        // allocation. RedoxFS's resize utility uses the same allocator operation.
        unsafe {
            let allocator = self.inner.allocator_mut();
            for index in old_blocks..new_blocks {
                allocator.deallocate(BlockAddr::new(index, BlockMeta::default()));
            }
        }
        let result = self.inner.tx(|transaction| {
            transaction.header.size = new_size.into();
            transaction.header_changed = true;
            transaction.sync(true)
        });
        if let Err(error) = result {
            // Do not let callers allocate beyond the old durable boundary after
            // a failed resize. A later remount will select the newest valid
            // RedoxFS header if the device failed after partially persisting.
            unsafe {
                *self.inner.allocator_mut() = old_allocator;
            }
            return Err(map_error(error));
        }
        Ok(true)
    }

    pub fn filesystem_info(&mut self) -> Result<FilesystemInfo, FsError> {
        let capacity_bytes = self.inner.header.size();
        let free_bytes = self.inner.allocator().free().checked_mul(BLOCK_SIZE);
        Ok(FilesystemInfo {
            capacity_bytes,
            free_bytes,
            block_size: BLOCK_SIZE,
        })
    }

    /// Forces RedoxFS to checkpoint pending allocator state and write a fresh
    /// header. Transactions are already committed before adapter methods
    /// return. The RedoxFS `Disk` trait has no hardware-cache flush primitive.
    pub fn sync(&mut self) -> Result<(), FsError> {
        self.inner.cleanup().map_err(map_error)
    }

    pub fn root_directory(&mut self) -> Result<DirectoryHandle, FsError> {
        let root = self
            .inner
            .tx(|tx| tx.read_tree(TreePtr::<Node>::root()))
            .map_err(map_error)?;
        if !root.data().is_dir() {
            return Err(FsError::Io);
        }
        Ok(self.directory_handle(root.id()))
    }

    pub fn file_count(&mut self) -> Result<usize, FsError> {
        Ok(self.list_root()?.len())
    }

    /// Legacy absolute-root enumeration. Directories remain filtered out for
    /// compatibility; use [`Self::list_directory`] for the hierarchical API.
    pub fn list_root(&mut self) -> Result<Vec<DirectoryEntry>, FsError> {
        let root = self.root_directory()?;
        let mut entries = self.list_directory(root)?;
        entries.retain(|entry| entry.metadata.kind == NodeKind::File);
        Ok(entries)
    }

    /// Legacy absolute-root create, delegated to the scoped implementation.
    pub fn create(&mut self, path: &str) -> Result<FileHandle, FsError> {
        let relative = parse_absolute(path)?;
        let root = self.root_directory()?;
        self.create_file_at(root, relative)
    }

    /// Legacy absolute-root open, delegated to the scoped implementation.
    pub fn open(&mut self, path: &str) -> Result<FileHandle, FsError> {
        let relative = parse_absolute(path)?;
        let root = self.root_directory()?;
        self.open_file_at(root, relative)
    }

    pub fn open_file_at(
        &mut self,
        directory: DirectoryHandle,
        path: &str,
    ) -> Result<FileHandle, FsError> {
        let components = parse_relative(path)?;
        let start = self.validate_directory_identity(directory)?;
        let node = self
            .inner
            .tx(|tx| resolve_path(tx, start, &components))
            .map_err(map_error)?;
        if node.data().is_dir() {
            return Err(FsError::IsDirectory);
        }
        if !is_regular_file(node.data()) {
            return Err(FsError::Io);
        }
        Ok(self.file_handle(node.id()))
    }

    pub fn create_file_at(
        &mut self,
        directory: DirectoryHandle,
        path: &str,
    ) -> Result<FileHandle, FsError> {
        let components = parse_relative(path)?;
        let start = self.validate_directory_identity(directory)?;
        let node = self
            .inner
            .tx(|tx| {
                let (parent, name) = resolve_parent(tx, start, &components)?;
                tx.create_node(parent, name, Node::MODE_FILE | 0o644, 0, 0)
            })
            .map_err(map_error)?;
        Ok(self.file_handle(node.id()))
    }

    pub fn open_directory_at(
        &mut self,
        directory: DirectoryHandle,
        path: &str,
    ) -> Result<DirectoryHandle, FsError> {
        let components = parse_relative(path)?;
        let start = self.validate_directory_identity(directory)?;
        let node = self
            .inner
            .tx(|tx| resolve_path(tx, start, &components))
            .map_err(map_error)?;
        if !node.data().is_dir() {
            return Err(FsError::NotDirectory);
        }
        Ok(self.directory_handle(node.id()))
    }

    pub fn create_directory_at(
        &mut self,
        directory: DirectoryHandle,
        path: &str,
    ) -> Result<DirectoryHandle, FsError> {
        let components = parse_relative(path)?;
        let start = self.validate_directory_identity(directory)?;
        let node = self
            .inner
            .tx(|tx| {
                let (parent, name) = resolve_parent(tx, start, &components)?;
                tx.create_node(parent, name, Node::MODE_DIR | 0o755, 0, 0)
            })
            .map_err(map_error)?;
        Ok(self.directory_handle(node.id()))
    }

    pub fn list_directory(
        &mut self,
        directory: DirectoryHandle,
    ) -> Result<Vec<DirectoryEntry>, FsError> {
        let pointer = self.validate_directory_identity(directory)?;
        let nodes = self
            .inner
            .tx(|tx| {
                ensure_directory(tx, pointer)?;
                let mut entries = Vec::new();
                tx.child_nodes(pointer, &mut entries)?;
                let mut nodes = Vec::new();
                nodes
                    .try_reserve_exact(entries.len())
                    .map_err(|_| Error::new(ENOSPC))?;
                for entry in entries {
                    let name = entry.name().ok_or_else(|| Error::new(EIO))?;
                    let node = tx.read_tree(entry.node_ptr())?;
                    if !node.data().is_dir() && !is_regular_file(node.data()) {
                        return Err(Error::new(EIO));
                    }
                    nodes.push((String::from(name), node));
                }
                Ok(nodes)
            })
            .map_err(map_error)?;

        let mut entries = Vec::new();
        entries
            .try_reserve_exact(nodes.len())
            .map_err(|_| FsError::NoSpace)?;
        for (name, node) in nodes {
            let metadata = node_metadata(&node);
            entries.push(DirectoryEntry {
                name,
                len: metadata.size,
                metadata,
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    pub fn read(
        &mut self,
        file: FileHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, FsError> {
        let node = self.validate_file_identity(file)?;
        self.inner
            .tx(|tx| {
                ensure_file(tx, node)?;
                tx.read_node(node, offset, output, 0, 0)
            })
            .map_err(handle_error)
    }

    pub fn write(&mut self, file: FileHandle, offset: u64, input: &[u8]) -> Result<usize, FsError> {
        offset
            .checked_add(input.len() as u64)
            .ok_or(FsError::OffsetOverflow)?;
        let node = self.validate_file_identity(file)?;
        self.inner
            .tx(|tx| {
                ensure_file(tx, node)?;
                tx.write_node(node, offset, input, 0, 0)
            })
            .map_err(handle_error)
    }

    pub fn truncate(&mut self, file: FileHandle, len: u64) -> Result<(), FsError> {
        let node = self.validate_file_identity(file)?;
        self.inner
            .tx(|tx| {
                ensure_file(tx, node)?;
                tx.truncate_node(node, len, 0, 0)
            })
            .map_err(handle_error)
    }

    pub fn stat(&mut self, file: FileHandle) -> Result<FileInfo, FsError> {
        Ok(FileInfo {
            len: self.file_metadata(file)?.size,
        })
    }

    pub fn file_metadata(&mut self, file: FileHandle) -> Result<NodeMetadata, FsError> {
        let pointer = self.validate_file_identity(file)?;
        let node = self
            .inner
            .tx(|tx| {
                let node = tx.read_tree(pointer)?;
                if node.data().is_dir() {
                    return Err(Error::new(EISDIR));
                }
                if !is_regular_file(node.data()) {
                    return Err(Error::new(EIO));
                }
                Ok(node)
            })
            .map_err(handle_error)?;
        Ok(node_metadata(&node))
    }

    pub fn directory_metadata(
        &mut self,
        directory: DirectoryHandle,
    ) -> Result<NodeMetadata, FsError> {
        let pointer = self.validate_directory_identity(directory)?;
        let node = self
            .inner
            .tx(|tx| {
                let node = tx.read_tree(pointer)?;
                if !node.data().is_dir() {
                    return Err(Error::new(ENOTDIR));
                }
                Ok(node)
            })
            .map_err(handle_error)?;
        Ok(node_metadata(&node))
    }

    pub fn remove_file_at(&mut self, parent: DirectoryHandle, name: &str) -> Result<(), FsError> {
        validate_component(name)?;
        let parent = self.validate_directory_identity(parent)?;
        let removed = self
            .inner
            .tx(|tx| {
                ensure_directory(tx, parent)?;
                let node = tx.find_node(parent, name)?;
                if node.data().is_dir() {
                    return Err(Error::new(EISDIR));
                }
                if !is_regular_file(node.data()) {
                    return Err(Error::new(EIO));
                }
                let id = node.id();
                tx.remove_node(parent, name, Node::MODE_FILE)?;
                Ok(id)
            })
            .map_err(map_error)?;
        self.invalidate_node(removed);
        Ok(())
    }

    pub fn remove_directory_at(
        &mut self,
        parent: DirectoryHandle,
        name: &str,
    ) -> Result<(), FsError> {
        validate_component(name)?;
        let parent = self.validate_directory_identity(parent)?;
        let removed = self
            .inner
            .tx(|tx| {
                ensure_directory(tx, parent)?;
                let node = tx.find_node(parent, name)?;
                if !node.data().is_dir() {
                    return Err(Error::new(ENOTDIR));
                }
                let id = node.id();
                tx.remove_node(parent, name, Node::MODE_DIR)?;
                Ok(id)
            })
            .map_err(map_error)?;
        self.invalidate_node(removed);
        Ok(())
    }

    /// Rename or move a node. Resolution, cycle/type checks, replacement, and
    /// relinking all occur in one RedoxFS transaction.
    pub fn rename_at(
        &mut self,
        source_directory: DirectoryHandle,
        source_path: &str,
        destination_directory: DirectoryHandle,
        destination_path: &str,
        mode: RenameMode,
    ) -> Result<(), FsError> {
        let source_components = parse_relative(source_path)?;
        let destination_components = parse_relative(destination_path)?;
        let source_start = self.validate_directory_identity(source_directory)?;
        let destination_start = self.validate_directory_identity(destination_directory)?;

        let replaced = self
            .inner
            .tx(|tx| {
                let (source_parent, source_name) =
                    resolve_parent(tx, source_start, &source_components)?;
                let (destination_parent, destination_name) =
                    resolve_parent(tx, destination_start, &destination_components)?;
                let source = tx.find_node(source_parent, source_name)?;
                if !source.data().is_dir() && !is_regular_file(source.data()) {
                    return Err(Error::new(EIO));
                }
                let destination = match tx.find_node(destination_parent, destination_name) {
                    Ok(node) => Some(node),
                    Err(error) if error.errno == ENOENT => None,
                    Err(error) => return Err(error),
                };

                if destination
                    .as_ref()
                    .is_some_and(|node| node.id() == source.id())
                {
                    return Ok(None);
                }
                if mode == RenameMode::NoReplace && destination.is_some() {
                    return Err(Error::new(EEXIST));
                }
                if let Some(destination) = destination.as_ref() {
                    if !destination.data().is_dir() && !is_regular_file(destination.data()) {
                        return Err(Error::new(EIO));
                    }
                    if source.data().is_dir() && !destination.data().is_dir() {
                        return Err(Error::new(ENOTDIR));
                    }
                    if !source.data().is_dir() && destination.data().is_dir() {
                        return Err(Error::new(EISDIR));
                    }
                }
                if source.data().is_dir()
                    && directory_contains(tx, source.ptr(), destination_parent)?
                {
                    return Err(Error::new(ELOOP));
                }

                let replaced = destination.map(|node| node.id());
                match mode {
                    RenameMode::NoReplace => tx.rename_node_no_replace(
                        source_parent,
                        source_name,
                        destination_parent,
                        destination_name,
                    )?,
                    RenameMode::Replace => tx.rename_node(
                        source_parent,
                        source_name,
                        destination_parent,
                        destination_name,
                    )?,
                }
                Ok(replaced)
            })
            .map_err(map_error)?;

        if let Some(node_id) = replaced {
            self.invalidate_node(node_id);
        }
        Ok(())
    }

    /// Atomically replace a file with another file by rename. Both path
    /// resolution and the replacement happen in one RedoxFS transaction.
    pub fn atomic_replace_file_at(
        &mut self,
        source_directory: DirectoryHandle,
        source_path: &str,
        destination_directory: DirectoryHandle,
        destination_path: &str,
    ) -> Result<(), FsError> {
        let source_components = parse_relative(source_path)?;
        let destination_components = parse_relative(destination_path)?;
        let source_start = self.validate_directory_identity(source_directory)?;
        let destination_start = self.validate_directory_identity(destination_directory)?;

        let replaced = self
            .inner
            .tx(|tx| {
                let (source_parent, source_name) =
                    resolve_parent(tx, source_start, &source_components)?;
                let (destination_parent, destination_name) =
                    resolve_parent(tx, destination_start, &destination_components)?;
                let source = tx.find_node(source_parent, source_name)?;
                if source.data().is_dir() {
                    return Err(Error::new(EISDIR));
                }
                if !is_regular_file(source.data()) {
                    return Err(Error::new(EIO));
                }
                let destination = match tx.find_node(destination_parent, destination_name) {
                    Ok(node) => {
                        if node.data().is_dir() {
                            return Err(Error::new(EISDIR));
                        }
                        if !is_regular_file(node.data()) {
                            return Err(Error::new(EIO));
                        }
                        if node.id() == source.id() {
                            return Ok(None);
                        }
                        Some(node.id())
                    }
                    Err(error) if error.errno == ENOENT => None,
                    Err(error) => return Err(error),
                };
                tx.rename_node(
                    source_parent,
                    source_name,
                    destination_parent,
                    destination_name,
                )?;
                Ok(destination)
            })
            .map_err(map_error)?;

        if let Some(node_id) = replaced {
            self.invalidate_node(node_id);
        }
        Ok(())
    }

    /// Legacy root-file unlink by handle.
    pub fn remove(&mut self, file: FileHandle) -> Result<(), FsError> {
        let node = self.validate_file_identity(file)?;
        let name = self
            .inner
            .tx(|tx| {
                ensure_file(tx, node)?;
                let mut entries = Vec::new();
                tx.child_nodes(TreePtr::root(), &mut entries)?;
                let entry = entries
                    .iter()
                    .find(|entry| entry.node_ptr().id() == node.id())
                    .ok_or_else(|| Error::new(ENOENT))?;
                entry
                    .name()
                    .map(String::from)
                    .ok_or_else(|| Error::new(EIO))
            })
            .map_err(handle_error)?;
        let root = self.root_directory()?;
        self.remove_file_at(root, &name)
    }

    fn file_handle(&mut self, node_id: u32) -> FileHandle {
        let generation = self.generation_for(node_id);
        FileHandle {
            filesystem_id: self.filesystem_id,
            node_id,
            generation,
        }
    }

    fn directory_handle(&mut self, node_id: u32) -> DirectoryHandle {
        let generation = self.generation_for(node_id);
        DirectoryHandle {
            filesystem_id: self.filesystem_id,
            node_id,
            generation,
        }
    }

    fn generation_for(&mut self, node_id: u32) -> u32 {
        *self.generations.entry(node_id).or_insert(1)
    }

    fn invalidate_node(&mut self, node_id: u32) {
        let generation = self.generations.entry(node_id).or_insert(1);
        *generation = next_generation(*generation);
    }

    fn validate_file_identity(&self, file: FileHandle) -> Result<TreePtr<Node>, FsError> {
        self.validate_identity(file.filesystem_id, file.node_id, file.generation)
    }

    fn validate_directory_identity(
        &self,
        directory: DirectoryHandle,
    ) -> Result<TreePtr<Node>, FsError> {
        self.validate_identity(
            directory.filesystem_id,
            directory.node_id,
            directory.generation,
        )
    }

    fn validate_identity(
        &self,
        filesystem_id: u64,
        node_id: u32,
        generation: u32,
    ) -> Result<TreePtr<Node>, FsError> {
        if filesystem_id != self.filesystem_id
            || self.generations.get(&node_id) != Some(&generation)
        {
            return Err(FsError::InvalidHandle);
        }
        Ok(TreePtr::new(node_id))
    }
}

fn resolve_path<D: Disk>(
    tx: &mut Transaction<D>,
    start: TreePtr<Node>,
    components: &[&str],
) -> syscall::error::Result<TreeData<Node>> {
    let mut current = ensure_directory(tx, start)?;
    for (index, component) in components.iter().enumerate() {
        let child = tx.find_node(current.ptr(), component)?;
        if index + 1 < components.len() && !child.data().is_dir() {
            return Err(Error::new(ENOTDIR));
        }
        current = child;
    }
    Ok(current)
}

fn resolve_parent<'a, D: Disk>(
    tx: &mut Transaction<D>,
    start: TreePtr<Node>,
    components: &'a [&'a str],
) -> syscall::error::Result<(TreePtr<Node>, &'a str)> {
    let (name, parents) = components.split_last().ok_or_else(|| Error::new(EINVAL))?;
    let parent = if parents.is_empty() {
        ensure_directory(tx, start)?.ptr()
    } else {
        let node = resolve_path(tx, start, parents)?;
        if !node.data().is_dir() {
            return Err(Error::new(ENOTDIR));
        }
        node.ptr()
    };
    Ok((parent, name))
}

fn ensure_directory<D: Disk>(
    tx: &mut Transaction<D>,
    pointer: TreePtr<Node>,
) -> syscall::error::Result<TreeData<Node>> {
    let node = tx.read_tree(pointer)?;
    if !node.data().is_dir() {
        return Err(Error::new(ENOTDIR));
    }
    Ok(node)
}

fn ensure_file<D: Disk>(
    tx: &mut Transaction<D>,
    pointer: TreePtr<Node>,
) -> syscall::error::Result<TreeData<Node>> {
    let node = tx.read_tree(pointer)?;
    if node.data().is_dir() {
        return Err(Error::new(EISDIR));
    }
    if !is_regular_file(node.data()) {
        return Err(Error::new(EIO));
    }
    Ok(node)
}

fn is_regular_file(node: &Node) -> bool {
    node.mode() & Node::MODE_TYPE == Node::MODE_FILE
}

fn directory_contains<D: Disk>(
    tx: &mut Transaction<D>,
    directory: TreePtr<Node>,
    sought: TreePtr<Node>,
) -> syscall::error::Result<bool> {
    let mut pending = vec![directory];
    while let Some(current) = pending.pop() {
        if current.id() == sought.id() {
            return Ok(true);
        }
        let mut entries = Vec::new();
        tx.child_nodes(current, &mut entries)?;
        for entry in entries {
            let child = tx.read_tree(entry.node_ptr())?;
            if child.data().is_dir() {
                pending.push(child.ptr());
            }
        }
    }
    Ok(false)
}

fn node_metadata(node: &TreeData<Node>) -> NodeMetadata {
    let (ctime_seconds, ctime_nanoseconds) = node.data().ctime();
    let (mtime_seconds, mtime_nanoseconds) = node.data().mtime();
    NodeMetadata {
        kind: if node.data().is_dir() {
            NodeKind::Directory
        } else {
            NodeKind::File
        },
        size: node.data().size(),
        identity: u64::from(node.id()),
        mode: node.data().mode(),
        policy: 0,
        uid: node.data().uid(),
        gid: node.data().gid(),
        ctime: Timestamp {
            seconds: ctime_seconds,
            nanoseconds: ctime_nanoseconds,
        },
        mtime: Timestamp {
            seconds: mtime_seconds,
            nanoseconds: mtime_nanoseconds,
        },
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

fn parse_absolute(path: &str) -> Result<&str, FsError> {
    path.strip_prefix('/').ok_or(FsError::InvalidName)
}

fn parse_relative(path: &str) -> Result<Vec<&str>, FsError> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return Err(FsError::InvalidName);
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        validate_component(component)?;
        if components.len() == MAX_TRAVERSAL_DEPTH {
            return Err(FsError::TraversalTooDeep);
        }
        components.push(component);
    }
    Ok(components)
}

fn validate_component(component: &str) -> Result<(), FsError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.as_bytes().contains(&0)
        || component.contains(':')
        || component.contains('\\')
        || component.len() > redoxfs::DIR_ENTRY_MAX_LENGTH
    {
        return Err(FsError::InvalidName);
    }
    Ok(())
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
        ENOTDIR => FsError::NotDirectory,
        EISDIR => FsError::IsDirectory,
        ENOTEMPTY => FsError::DirectoryNotEmpty,
        ELOOP => FsError::WouldCycle,
        _ => FsError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

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
    fn builds_and_reopens_a_deep_hierarchy() {
        let disk = MemoryDisk::zeroed(8 * 1024 * 1024);
        let mut fs = RedoxFs::format_disk(disk).unwrap();
        let root = fs.root_directory().unwrap();
        let mut current = root;
        for depth in 0..MAX_TRAVERSAL_DEPTH {
            current = fs
                .create_directory_at(current, &format!("level{depth}"))
                .unwrap();
        }
        let file = fs.create_file_at(current, "leaf").unwrap();
        fs.write(file, 0, b"persistent tree").unwrap();
        fs.sync().unwrap();

        let disk = fs.into_disk();
        let mut reopened = RedoxFs::open_disk(disk).unwrap();
        let root = reopened.root_directory().unwrap();
        let mut path = String::new();
        for depth in 0..MAX_TRAVERSAL_DEPTH {
            if depth != 0 {
                path.push('/');
            }
            path.push_str(&format!("level{depth}"));
        }
        let directory = reopened.open_directory_at(root, &path).unwrap();
        let file = reopened.open_file_at(directory, "leaf").unwrap();
        let mut bytes = [0; 15];
        reopened.read(file, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"persistent tree");
    }

    #[test]
    fn rejects_unsafe_traversal_and_excessive_depth() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        for path in [
            "",
            "/absolute",
            "\\absolute",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "a//b",
            "a/",
            "a:b",
            "a\\b",
            "a\0b",
        ] {
            assert_eq!(
                fs.open_file_at(root, path),
                Err(FsError::InvalidName),
                "{path:?}"
            );
        }
        let long = "x".repeat(redoxfs::DIR_ENTRY_MAX_LENGTH + 1);
        assert_eq!(fs.create_file_at(root, &long), Err(FsError::InvalidName));
        let too_deep = (0..=MAX_TRAVERSAL_DEPTH)
            .map(|_| "x")
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            fs.open_file_at(root, &too_deep),
            Err(FsError::TraversalTooDeep)
        );
    }

    #[test]
    fn directory_capability_is_scoped_to_its_subtree() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        let delegated = fs.create_directory_at(root, "delegated").unwrap();
        let secret = fs.create_file_at(root, "secret").unwrap();
        fs.write(secret, 0, b"hidden").unwrap();
        assert_eq!(fs.open_file_at(delegated, "secret"), Err(FsError::NotFound));
        assert_eq!(
            fs.open_file_at(delegated, "../secret"),
            Err(FsError::InvalidName)
        );
    }

    #[test]
    fn stale_and_cross_filesystem_handles_are_rejected() {
        let mut first = RedoxFs::new().unwrap();
        let mut second = RedoxFs::new().unwrap();
        let root = first.root_directory().unwrap();
        let directory = first.create_directory_at(root, "gone").unwrap();
        first.remove_directory_at(root, "gone").unwrap();
        assert_eq!(first.list_directory(directory), Err(FsError::InvalidHandle));
        assert_eq!(second.list_directory(root), Err(FsError::InvalidHandle));

        let file = first.create_file_at(root, "old").unwrap();
        first.remove_file_at(root, "old").unwrap();
        let replacement = first.create_file_at(root, "new").unwrap();
        assert_eq!(replacement.node_id(), file.node_id());
        assert_ne!(replacement.generation(), file.generation());
        assert_eq!(first.stat(file), Err(FsError::InvalidHandle));
        assert_eq!(second.stat(replacement), Err(FsError::InvalidHandle));
    }

    #[test]
    fn rename_move_no_replace_and_replace_are_atomic() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        let left = fs.create_directory_at(root, "left").unwrap();
        let right = fs.create_directory_at(root, "right").unwrap();
        let source = fs.create_file_at(left, "source").unwrap();
        fs.write(source, 0, b"source").unwrap();
        let target = fs.create_file_at(right, "target").unwrap();
        fs.write(target, 0, b"target").unwrap();

        assert_eq!(
            fs.rename_at(left, "source", right, "target", RenameMode::NoReplace),
            Err(FsError::AlreadyExists)
        );
        assert_eq!(fs.open_file_at(left, "source").unwrap(), source);
        assert_eq!(fs.open_file_at(right, "target").unwrap(), target);

        fs.rename_at(left, "source", right, "target", RenameMode::Replace)
            .unwrap();
        assert_eq!(fs.open_file_at(left, "source"), Err(FsError::NotFound));
        assert_eq!(fs.open_file_at(right, "target").unwrap(), source);
        assert_eq!(fs.stat(target), Err(FsError::InvalidHandle));
    }

    #[test]
    fn atomic_file_replacement_invalidates_only_replaced_file() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        let live = fs.create_file_at(root, "live").unwrap();
        fs.write(live, 0, b"old").unwrap();
        let staged = fs.create_file_at(root, "staged").unwrap();
        fs.write(staged, 0, b"new").unwrap();
        fs.atomic_replace_file_at(root, "staged", root, "live")
            .unwrap();

        assert_eq!(fs.stat(live), Err(FsError::InvalidHandle));
        assert_eq!(fs.open_file_at(root, "staged"), Err(FsError::NotFound));
        assert_eq!(fs.open_file_at(root, "live").unwrap(), staged);
        let mut bytes = [0; 3];
        fs.read(staged, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"new");
    }

    #[test]
    fn refuses_nonempty_rmdir_and_directory_cycles() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        let parent = fs.create_directory_at(root, "parent").unwrap();
        let child = fs.create_directory_at(parent, "child").unwrap();
        fs.create_file_at(child, "file").unwrap();
        assert_eq!(
            fs.remove_directory_at(parent, "child"),
            Err(FsError::DirectoryNotEmpty)
        );
        assert_eq!(
            fs.rename_at(root, "parent", child, "cycle", RenameMode::NoReplace),
            Err(FsError::WouldCycle)
        );
        assert!(fs.open_directory_at(root, "parent/child").is_ok());
    }

    #[test]
    fn listing_contains_kind_identity_permissions_and_times() {
        let mut fs = RedoxFs::new().unwrap();
        let root = fs.root_directory().unwrap();
        let file = fs.create_file_at(root, "file").unwrap();
        fs.write(file, 0, b"data").unwrap();
        fs.create_directory_at(root, "directory").unwrap();
        let entries = fs.list_directory(root).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].metadata.kind, NodeKind::Directory);
        assert_eq!(entries[1].metadata.kind, NodeKind::File);
        assert_eq!(entries[1].metadata.identity, u64::from(file.node_id()));
        assert_eq!(entries[1].metadata.size, 4);
        assert_eq!(entries[1].metadata.policy, 0);
        assert_eq!(entries[1].metadata.mode & Node::MODE_PERM, 0o644);
        assert_eq!(entries[1].metadata.ctime.seconds, 0);
        assert_eq!(entries[1].metadata.mtime.seconds, 0);

        let info = fs.filesystem_info().unwrap();
        assert_eq!(info.block_size, BLOCK_SIZE);
        assert!(info.free_bytes.is_some());
        assert!(info.free_bytes.unwrap() < info.capacity_bytes);
    }

    #[test]
    fn grows_to_an_expanded_backing_disk_without_losing_data() {
        let disk = MemoryDisk::zeroed(8 * 1024 * 1024);
        let mut fs = RedoxFs::format_disk(disk).unwrap();
        let file = fs.create("/preserved").unwrap();
        fs.write(file, 0, b"before growth").unwrap();
        fs.sync().unwrap();
        let old_info = fs.filesystem_info().unwrap();

        let mut disk = fs.into_disk();
        disk.data.resize(16 * 1024 * 1024, 0);
        let mut fs = RedoxFs::open_disk(disk).unwrap();
        assert!(fs.grow_to_disk().unwrap());
        let new_info = fs.filesystem_info().unwrap();
        assert!(new_info.capacity_bytes > old_info.capacity_bytes);
        assert!(new_info.free_bytes.unwrap() > old_info.free_bytes.unwrap());
        assert!(!fs.grow_to_disk().unwrap());

        let file = fs.open("/preserved").unwrap();
        let mut bytes = [0_u8; 13];
        assert_eq!(fs.read(file, 0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(&bytes, b"before growth");
    }

    #[test]
    fn legacy_absolute_root_methods_delegate() {
        let mut fs = RedoxFs::new().unwrap();
        assert_eq!(fs.create("relative"), Err(FsError::InvalidName));
        assert_eq!(fs.create("/"), Err(FsError::InvalidName));
        let root = fs.root_directory().unwrap();
        fs.create_directory_at(root, "nested").unwrap();
        let file = fs.create("/nested/file").unwrap();
        assert_eq!(fs.open("/nested/file").unwrap(), file);
        assert!(fs.list_root().unwrap().is_empty());
    }
}
