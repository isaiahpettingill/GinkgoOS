#![no_std]
#![feature(allocator_api)]

extern crate alloc;

pub mod ahci;
pub mod arch;
pub mod ata;
pub mod audio;
pub mod block;
pub mod compositor;
pub mod desktop_runtime;
pub mod elf;
pub mod entropy;
pub mod input;
pub mod io;
pub mod limine;
pub mod local_apic;
pub mod memory;
pub mod paging;
pub mod pci;
pub mod power;
pub mod process;
pub mod shared_memory;
pub mod syscall;
pub mod task;
pub mod trust;
pub mod usb;
pub mod virtio_blk;
