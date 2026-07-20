//! Static bootstrap heap used by `alloc` and RedoxFS.

use spinning_top::RawSpinlock;
use talc::{source::Claim, TalcLock};

const HEAP_SIZE: usize = 4 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: TalcLock<RawSpinlock, Claim> = TalcLock::new(unsafe {
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    Claim::array(&raw mut HEAP)
});
