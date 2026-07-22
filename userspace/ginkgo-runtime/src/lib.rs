#![no_std]

use core::panic::PanicInfo;

use ginkgo_userspace::{debug_write, process_exit, process_yield};
use spinning_top::RawSpinlock;
use talc::{source::Claim, TalcLock};

/// Static heap shared by production userspace executables.
pub const HEAP_SIZE: usize = 2 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: TalcLock<RawSpinlock, Claim> = TalcLock::new(unsafe {
    #[link_section = ".bss.userspace_heap"]
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    Claim::array(&raw mut HEAP)
});

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
