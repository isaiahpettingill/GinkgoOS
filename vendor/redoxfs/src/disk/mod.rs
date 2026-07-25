use syscall::error::Result;

#[cfg(feature = "std")]
pub use self::cache::DiskCache;
#[cfg(feature = "std")]
pub use self::file::DiskFile;
#[cfg(feature = "std")]
pub use self::io::DiskIo;
#[cfg(feature = "std")]
pub use self::memory::DiskMemory;
#[cfg(feature = "std")]
pub use self::sparse::DiskSparse;

#[cfg(feature = "std")]
mod cache;
#[cfg(feature = "std")]
mod file;
#[cfg(feature = "std")]
mod io;
#[cfg(feature = "std")]
mod memory;
#[cfg(feature = "std")]
mod sparse;

/// A disk
pub trait Disk {
    /// Read blocks from disk
    ///
    /// # Safety
    /// Unsafe to discourage use, use filesystem wrappers instead
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize>;

    /// Write blocks from disk
    ///
    /// # Safety
    /// Unsafe to discourage use, use filesystem wrappers instead
    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize>;

    /// Make completed writes durable when the backing device has a volatile cache.
    /// Memory and ordinary host-file adapters may use the default no-op.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Sequence requested by the latest successful flush.
    /// Synchronous disks may use the default sequence zero.
    fn requested_flush_sequence(&self) -> u64 {
        0
    }

    /// Latest flush sequence known to be durable.
    /// Synchronous disks may use the default sequence zero.
    fn durable_flush_sequence(&self) -> u64 {
        0
    }

    /// Get size of disk in bytes
    fn size(&mut self) -> Result<u64>;
}
