//! Static bootstrap heap used by `alloc` and kernel services.

use spinning_top::RawSpinlock;
use talc::{source::Claim, TalcLock};

pub const HEAP_SIZE: usize = 4 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: TalcLock<RawSpinlock, Claim> = TalcLock::new(unsafe {
    #[link_section = ".bootstrap_heap"]
    static mut HEAP: [u8; HEAP_SIZE] = [0xa5; HEAP_SIZE];
    Claim::array(&raw mut HEAP)
});
