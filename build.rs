use std::{env, fs, path::PathBuf};

use redoxfs::{Disk, FileSystem, BLOCK_SIZE};
use syscall::error::{Error, Result, EIO};

const IMAGE_SIZE: usize = 2 * 1024 * 1024;

struct ImageDisk {
    data: Vec<u8>,
}

impl ImageDisk {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }
}

impl Disk for ImageDisk {
    unsafe fn read_at(&mut self, block: u64, buffer: &mut [u8]) -> Result<usize> {
        let offset = block
            .checked_mul(BLOCK_SIZE)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::new(EIO))?;
        let end = offset
            .checked_add(buffer.len())
            .ok_or_else(|| Error::new(EIO))?;
        let source = self.data.get(offset..end).ok_or_else(|| Error::new(EIO))?;
        buffer.copy_from_slice(source);
        Ok(buffer.len())
    }

    unsafe fn write_at(&mut self, block: u64, buffer: &[u8]) -> Result<usize> {
        let offset = block
            .checked_mul(BLOCK_SIZE)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::new(EIO))?;
        let end = offset
            .checked_add(buffer.len())
            .ok_or_else(|| Error::new(EIO))?;
        let destination = self
            .data
            .get_mut(offset..end)
            .ok_or_else(|| Error::new(EIO))?;
        destination.copy_from_slice(buffer);
        Ok(buffer.len())
    }

    fn size(&mut self) -> Result<u64> {
        Ok(self.data.len() as u64)
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let disk = ImageDisk::new(IMAGE_SIZE);
    let filesystem = FileSystem::create(disk, 0, 0)
        .expect("failed to format the embedded RedoxFS seed image");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is missing"))
        .join("redoxfs.img");
    fs::write(output, filesystem.disk.data).expect("failed to write RedoxFS seed image");
}
