#![no_std]

use core::{alloc::Layout, panic::PanicInfo};

use ginkgo_userspace::{
    anonymous_map, anonymous_unmap, debug_write, process_exit, process_yield, MapProtection,
};
use spinning_top::RawSpinlock;
use talc::{
    base::{binning::Binning, Talc},
    source::Source,
    TalcLock,
};

const HEAP_GROWTH_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
struct ProcessHeapSource;

unsafe impl Source for ProcessHeapSource {
    fn acquire<B: Binning>(
        talc: &mut Talc<Self, B>,
        layout: Layout,
    ) -> Result<(), ()> {
        let requested = layout
            .size()
            .checked_add(HEAP_GROWTH_BYTES - 1)
            .map(|size| size.max(HEAP_GROWTH_BYTES) / HEAP_GROWTH_BYTES * HEAP_GROWTH_BYTES)
            .ok_or(())?;
        let mapping = unsafe {
            anonymous_map(
                requested,
                MapProtection::READ | MapProtection::WRITE,
            )
        }
        .map_err(|_| ())?;
        if unsafe { talc.claim(mapping.as_ptr(), requested) }.is_none() {
            let _ = unsafe { anonymous_unmap(mapping, requested) };
            return Err(());
        }
        Ok(())
    }
}

#[global_allocator]
static ALLOCATOR: TalcLock<RawSpinlock, ProcessHeapSource> =
    TalcLock::new(ProcessHeapSource);

/// Defines the assembly entry shim expected by the GinkgoOS ELF loader.
///
/// The supplied function must have the signature `extern "C" fn(u64, u64, u64, u64) -> !`.
/// The fourth argument is the process's non-transferable random-source capability.
#[macro_export]
macro_rules! entry {
    ($entry:path) => {
        core::arch::global_asm!(
            r#"
            .pushsection .text._start,"ax",@progbits
            .global _start
            .type _start,@function
        _start:
            call {entry}
            ud2
            .size _start, . - _start
            .popsection
            "#,
            entry = sym $entry,
        );
    };
}

/// Terminates the current process and yields forever if the kernel rejects exit.
pub fn exit(code: i32) -> ! {
    let _ = process_exit(code);
    loop {
        let _ = process_yield();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let _ = debug_write(b"userspace: panic\n");
    exit(127)
}
