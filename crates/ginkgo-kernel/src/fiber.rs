//! Fixed-capacity, stackful fibers for the single-core x86_64 kernel.
//!
//! A [`Fiber`] borrows a caller-owned, pinned [`FixedStack`]. This keeps stack
//! allocation out of the fiber implementation and lets boot code reserve stacks
//! before the heap exists. [`StackBounds`] exposes the downward-growing stack's
//! usable range; a future mapper can reserve the page immediately below `bottom`
//! as a guard page.
//!
//! Context switches do not unwind. Code may call [`yield_now`] (or
//! [`FiberContext::yield_now`]) at any depth and all intervening stack frames stay
//! live until the fiber is resumed. Fiber entry functions must return errors as
//! [`FiberFault`] values. Panics are not caught and must abort in the kernel.
//!
//! # Interrupt and thread safety
//!
//! The kernel target rejects `resume` and `yield_now` while interrupts are
//! enabled. The active-fiber marker remains set until the assembly switch has
//! completely returned to the caller, so no interrupt can observe a partly
//! switched context as idle. Host targets use the same marker to reject overlap
//! from another thread. This is a single-core primitive, not a thread scheduler.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::ptr::{addr_of, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(not(target_arch = "x86_64"))]
compile_error!("ginkgo-kernel fibers are implemented only for x86_64");

/// Smallest usable fiber stack. Real filesystem work should normally use more.
pub const MIN_STACK_SIZE: usize = 4096;

/// Alignment used by preallocated stacks so their lower bound is page-aligned.
pub const FIBER_STACK_ALIGNMENT: usize = 4096;

const INITIAL_FRAME_SIZE: usize = 48;
const INVALID_SWITCH_FAULT: FiberFault = FiberFault::new(usize::MAX);

/// The usable byte range of a downward-growing fiber stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackBounds {
    bottom: usize,
    top: usize,
}

impl StackBounds {
    /// Lowest usable address, inclusive.
    pub const fn bottom(self) -> usize {
        self.bottom
    }

    /// Highest usable address, exclusive. The initial stack pointer is below it.
    pub const fn top(self) -> usize {
        self.top
    }

    pub const fn len(self) -> usize {
        self.top - self.bottom
    }

    pub const fn is_empty(self) -> bool {
        self.bottom == self.top
    }

    pub const fn contains(self, address: usize) -> bool {
        address >= self.bottom && address < self.top
    }
}

/// A page-aligned, fixed-capacity stack that can be reserved before heap setup.
///
/// Pin this value before passing it to [`Fiber::new`]. For kernel use it can live
/// in static boot storage. `SIZE` should normally be a multiple of 4096 so both
/// exposed bounds are page-aligned.
#[repr(C, align(4096))]
pub struct FixedStack<const SIZE: usize> {
    bytes: [MaybeUninit<u8>; SIZE],
    _pinned: PhantomPinned,
}

impl<const SIZE: usize> FixedStack<SIZE> {
    pub const fn new() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); SIZE],
            _pinned: PhantomPinned,
        }
    }

    pub const fn capacity(&self) -> usize {
        SIZE
    }

    pub fn bounds(self: Pin<&Self>) -> StackBounds {
        let bottom = self.get_ref().bytes.as_ptr() as usize;
        StackBounds {
            bottom,
            top: bottom + SIZE,
        }
    }

    fn bottom_mut(self: Pin<&mut Self>) -> *mut u8 {
        // The byte array does not move when accessed through its pinned owner.
        unsafe { self.get_unchecked_mut().bytes.as_mut_ptr().cast::<u8>() }
    }
}

impl<const SIZE: usize> Default for FixedStack<SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

/// An explicit failure returned by a fiber entry function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FiberFault {
    code: usize,
}

impl FiberFault {
    pub const fn new(code: usize) -> Self {
        Self { code }
    }

    pub const fn code(self) -> usize {
        self.code
    }
}

pub type FiberResult = Result<(), FiberFault>;
pub type FiberEntry = fn(&mut FiberContext) -> FiberResult;

/// Current lifecycle state. Terminal states never transition again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FiberState {
    Ready,
    Running,
    Yielded,
    Complete,
    Faulted(FiberFault),
}

/// One event produced by a successful call to [`Fiber::resume`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FiberOutcome {
    Yielded,
    Complete,
    Faulted(FiberFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeError {
    /// A fiber is already active on this core (including this same fiber).
    NestedResume,
    AlreadyComplete,
    AlreadyFaulted(FiberFault),
    StackTooSmall {
        provided: usize,
        minimum: usize,
    },
    /// Kernel context switching requires interrupts to remain disabled.
    InterruptsEnabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YieldError {
    OutsideFiber,
    NotRunning,
    /// Kernel context switching requires interrupts to remain disabled.
    InterruptsEnabled,
}

/// Capability passed to the entry function. It can be threaded through code that
/// prefers an explicit context; deep synchronous code may call [`yield_now`]
/// directly instead.
pub struct FiberContext {
    _private: (),
}

impl FiberContext {
    pub fn yield_now(&mut self) -> Result<(), YieldError> {
        yield_now()
    }
}

/// The saved register set.
///
/// The first seven words are `rsp`, `rbx`, `rbp`, and `r12..r15`. Windows also
/// requires `rdi`, `rsi`, and `xmm6..xmm15` to survive an `extern "C"` call, so
/// storage for those registers is always present and the Windows switch saves it.
#[repr(C, align(16))]
struct Context {
    words: [usize; 7],
    windows_gprs: [usize; 2],
    windows_xmm: [[u8; 16]; 10],
}

impl Context {
    const ZERO: Self = Self {
        words: [0; 7],
        windows_gprs: [0; 2],
        windows_xmm: [[0; 16]; 10],
    };
}

struct FiberCore {
    caller_context: Context,
    fiber_context: Context,
    entry: FiberEntry,
    state: FiberState,
    initialized: bool,
}

/// A pinned stackful fiber backed by a caller-owned [`FixedStack`].
///
/// Pin the `Fiber` before its first resume. A yielded fiber may be resumed any
/// number of times, but completion or fault is returned exactly once; later
/// resumes return the matching `ResumeError`.
pub struct Fiber<'stack, const STACK_SIZE: usize> {
    stack: Pin<&'stack mut FixedStack<STACK_SIZE>>,
    core: UnsafeCell<FiberCore>,
    _single_core: PhantomData<*mut ()>,
    _pinned: PhantomPinned,
}

impl<'stack, const STACK_SIZE: usize> Fiber<'stack, STACK_SIZE> {
    pub fn new(stack: Pin<&'stack mut FixedStack<STACK_SIZE>>, entry: FiberEntry) -> Self {
        Self {
            stack,
            core: UnsafeCell::new(FiberCore {
                caller_context: Context::ZERO,
                fiber_context: Context::ZERO,
                entry,
                state: FiberState::Ready,
                initialized: false,
            }),
            _single_core: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    pub fn state(&self) -> FiberState {
        // Safe callers cannot inspect the fiber while `resume` holds its mutable pin.
        unsafe { (*self.core.get()).state }
    }

    pub fn stack_bounds(&self) -> StackBounds {
        self.stack.as_ref().bounds()
    }

    /// Runs until the fiber yields, completes, or reports a fault.
    ///
    /// On the kernel target this returns `InterruptsEnabled` instead of entering
    /// the small non-preemptible assembly switch window with interrupts enabled.
    pub fn resume(self: Pin<&mut Self>) -> Result<FiberOutcome, ResumeError> {
        if !ACTIVE_FIBER.load(Ordering::Acquire).is_null() {
            return Err(ResumeError::NestedResume);
        }

        let this = unsafe { self.get_unchecked_mut() };
        let core = this.core.get();

        match unsafe { (*core).state } {
            FiberState::Complete => return Err(ResumeError::AlreadyComplete),
            FiberState::Faulted(fault) => return Err(ResumeError::AlreadyFaulted(fault)),
            FiberState::Running => return Err(ResumeError::NestedResume),
            FiberState::Ready | FiberState::Yielded => {}
        }

        let bounds = this.stack.as_ref().bounds();
        let aligned_top = bounds.top() & !15;
        let usable = aligned_top.saturating_sub(bounds.bottom());
        if usable < MIN_STACK_SIZE || usable < INITIAL_FRAME_SIZE {
            return Err(ResumeError::StackTooSmall {
                provided: usable,
                minimum: MIN_STACK_SIZE,
            });
        }
        if interrupts_enabled() {
            return Err(ResumeError::InterruptsEnabled);
        }

        if unsafe { !(*core).initialized } {
            unsafe {
                initialize_context(core, this.stack.as_mut().bottom_mut(), aligned_top);
            }
        }

        if ACTIVE_FIBER
            .compare_exchange(null_mut(), core, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ResumeError::NestedResume);
        }

        unsafe {
            (*core).state = FiberState::Running;
            ginkgo_fiber_context_switch(
                addr_of_mut!((*core).caller_context),
                addr_of!((*core).fiber_context),
            );
        }

        let active_was_self = ACTIVE_FIBER
            .compare_exchange(core, null_mut(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        debug_assert!(active_was_self);

        match unsafe { (*core).state } {
            FiberState::Yielded => Ok(FiberOutcome::Yielded),
            FiberState::Complete => Ok(FiberOutcome::Complete),
            FiberState::Faulted(fault) => Ok(FiberOutcome::Faulted(fault)),
            FiberState::Ready | FiberState::Running => {
                unsafe {
                    (*core).state = FiberState::Faulted(INVALID_SWITCH_FAULT);
                }
                Ok(FiberOutcome::Faulted(INVALID_SWITCH_FAULT))
            }
        }
    }
}

static ACTIVE_FIBER: AtomicPtr<FiberCore> = AtomicPtr::new(null_mut());

/// Suspends the active fiber without unwinding any synchronous call frames.
pub fn yield_now() -> Result<(), YieldError> {
    let core = ACTIVE_FIBER.load(Ordering::Acquire);
    if core.is_null() {
        return Err(YieldError::OutsideFiber);
    }
    if interrupts_enabled() {
        return Err(YieldError::InterruptsEnabled);
    }
    if unsafe { (*core).state } != FiberState::Running {
        return Err(YieldError::NotRunning);
    }

    unsafe {
        (*core).state = FiberState::Yielded;
        ginkgo_fiber_context_switch(
            addr_of_mut!((*core).fiber_context),
            addr_of!((*core).caller_context),
        );
    }

    if ACTIVE_FIBER.load(Ordering::Acquire) != core
        || unsafe { (*core).state } != FiberState::Running
    {
        return Err(YieldError::NotRunning);
    }
    Ok(())
}

unsafe fn initialize_context(core: *mut FiberCore, bottom: *mut u8, aligned_top: usize) {
    debug_assert!(aligned_top >= bottom as usize + INITIAL_FRAME_SIZE);

    // `ret` consumes the trampoline address. The remaining 40 bytes provide a
    // fake return address plus the 32-byte Windows shadow space. SysV enters with
    // the same required `rsp % 16 == 8` alignment.
    let initial_rsp = aligned_top - INITIAL_FRAME_SIZE;
    unsafe {
        (initial_rsp as *mut usize).write(fiber_entry_trampoline as *const () as usize);
        ((initial_rsp + 8) as *mut usize).write(fiber_returned as *const () as usize);
        (*core).fiber_context.words[0] = initial_rsp;
        (*core).initialized = true;
    }
}

extern "C" fn fiber_entry_trampoline() -> ! {
    let core = ACTIVE_FIBER.load(Ordering::Acquire);
    if core.is_null() {
        fiber_returned()
    }

    let entry = unsafe { (*core).entry };
    let mut context = FiberContext { _private: () };
    let terminal_state = match entry(&mut context) {
        Ok(()) => FiberState::Complete,
        Err(fault) => FiberState::Faulted(fault),
    };

    unsafe {
        // Entry is reached only from Running, and terminal fibers cannot resume,
        // so this terminal publication occurs once.
        (*core).state = terminal_state;
        ginkgo_fiber_context_switch(
            addr_of_mut!((*core).fiber_context),
            addr_of!((*core).caller_context),
        );
    }
    fiber_returned()
}

extern "C" fn fiber_returned() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "none")]
fn interrupts_enabled() -> bool {
    let flags: usize;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(preserves_flags),
        );
    }
    flags & (1 << 9) != 0
}

#[cfg(not(target_os = "none"))]
const fn interrupts_enabled() -> bool {
    false
}

unsafe extern "C" {
    fn ginkgo_fiber_context_switch(from: *mut Context, to: *const Context);
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
global_asm!(
    r#"
    .text
    .globl ginkgo_fiber_context_switch
    .p2align 4
 ginkgo_fiber_context_switch:
    mov [rcx + 0], rsp
    mov [rcx + 8], rbx
    mov [rcx + 16], rbp
    mov [rcx + 24], r12
    mov [rcx + 32], r13
    mov [rcx + 40], r14
    mov [rcx + 48], r15
    mov [rcx + 56], rdi
    mov [rcx + 64], rsi
    movdqu [rcx + 72], xmm6
    movdqu [rcx + 88], xmm7
    movdqu [rcx + 104], xmm8
    movdqu [rcx + 120], xmm9
    movdqu [rcx + 136], xmm10
    movdqu [rcx + 152], xmm11
    movdqu [rcx + 168], xmm12
    movdqu [rcx + 184], xmm13
    movdqu [rcx + 200], xmm14
    movdqu [rcx + 216], xmm15

    mov rsp, [rdx + 0]
    mov rbx, [rdx + 8]
    mov rbp, [rdx + 16]
    mov r12, [rdx + 24]
    mov r13, [rdx + 32]
    mov r14, [rdx + 40]
    mov r15, [rdx + 48]
    mov rdi, [rdx + 56]
    mov rsi, [rdx + 64]
    movdqu xmm6, [rdx + 72]
    movdqu xmm7, [rdx + 88]
    movdqu xmm8, [rdx + 104]
    movdqu xmm9, [rdx + 120]
    movdqu xmm10, [rdx + 136]
    movdqu xmm11, [rdx + 152]
    movdqu xmm12, [rdx + 168]
    movdqu xmm13, [rdx + 184]
    movdqu xmm14, [rdx + 200]
    movdqu xmm15, [rdx + 216]
    ret
"#
);

#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
global_asm!(
    r#"
    .text
    .globl ginkgo_fiber_context_switch
    .type ginkgo_fiber_context_switch,@function
    .p2align 4
 ginkgo_fiber_context_switch:
    mov [rdi + 0], rsp
    mov [rdi + 8], rbx
    mov [rdi + 16], rbp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    mov rsp, [rsi + 0]
    mov rbx, [rsi + 8]
    mov rbp, [rsi + 16]
    mov r12, [rsi + 24]
    mov r13, [rsi + 32]
    mov r14, [rsi + 40]
    mov r15, [rsi + 48]
    ret
    .size ginkgo_fiber_context_switch, .-ginkgo_fiber_context_switch
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const TEST_STACK_SIZE: usize = 64 * 1024;
    const LOCAL_WORDS: usize = 32;

    static FIBER_PHASE: AtomicUsize = AtomicUsize::new(0);
    static HOST_PHASE: AtomicUsize = AtomicUsize::new(0);
    static NESTED_RESULT: AtomicUsize = AtomicUsize::new(0);
    static ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FAULT_ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn must_not_run(_: &mut FiberContext) -> FiberResult {
        NESTED_RESULT.store(2, Ordering::SeqCst);
        Ok(())
    }

    fn yielding_entry(context: &mut FiberContext) -> FiberResult {
        ENTRY_COUNT.fetch_add(1, Ordering::SeqCst);

        {
            let mut nested_stack = core::pin::pin!(FixedStack::<MIN_STACK_SIZE>::new());
            let nested = Fiber::new(nested_stack.as_mut(), must_not_run);
            let mut nested = core::pin::pin!(nested);
            let rejected = nested.as_mut().resume() == Err(ResumeError::NestedResume);
            NESTED_RESULT.store(rejected as usize, Ordering::SeqCst);
        }

        let mut locals = [0usize; LOCAL_WORDS];
        for (index, value) in locals.iter_mut().enumerate() {
            *value = 0x1000 + index;
        }

        for round in 1..=3 {
            for (index, value) in locals.iter().enumerate() {
                let observed = unsafe { core::ptr::read_volatile(value) };
                if observed != round * 0x1000 + index {
                    return Err(FiberFault::new(10 + round));
                }
            }

            FIBER_PHASE.store(round, Ordering::SeqCst);
            context
                .yield_now()
                .map_err(|_| FiberFault::new(20 + round))?;

            if HOST_PHASE.load(Ordering::SeqCst) != round {
                return Err(FiberFault::new(30 + round));
            }
            for value in &mut locals {
                unsafe {
                    core::ptr::write_volatile(value, value.wrapping_add(0x1000));
                }
            }
        }

        Ok(())
    }

    fn faulting_entry(_: &mut FiberContext) -> FiberResult {
        FAULT_ENTRY_COUNT.fetch_add(1, Ordering::SeqCst);
        Err(FiberFault::new(77))
    }

    #[test]
    fn fiber_switching_and_state_publication() {
        FIBER_PHASE.store(0, Ordering::SeqCst);
        HOST_PHASE.store(0, Ordering::SeqCst);
        NESTED_RESULT.store(0, Ordering::SeqCst);
        ENTRY_COUNT.store(0, Ordering::SeqCst);
        FAULT_ENTRY_COUNT.store(0, Ordering::SeqCst);

        assert_eq!(yield_now(), Err(YieldError::OutsideFiber));

        let mut stack = core::pin::pin!(FixedStack::<TEST_STACK_SIZE>::new());
        let fiber = Fiber::new(stack.as_mut(), yielding_entry);
        let mut fiber = core::pin::pin!(fiber);

        let bounds = fiber.as_ref().stack_bounds();
        assert_eq!(bounds.len(), TEST_STACK_SIZE);
        assert_eq!(bounds.bottom() % FIBER_STACK_ALIGNMENT, 0);

        let mut unrelated_host_local = 40usize;
        for round in 1..=3 {
            assert_eq!(fiber.as_mut().resume(), Ok(FiberOutcome::Yielded));
            assert_eq!(fiber.as_ref().state(), FiberState::Yielded);
            assert_eq!(FIBER_PHASE.load(Ordering::SeqCst), round);

            unrelated_host_local += round;
            HOST_PHASE.store(round, Ordering::SeqCst);
        }
        assert_eq!(unrelated_host_local, 46);
        assert_eq!(NESTED_RESULT.load(Ordering::SeqCst), 1);

        assert_eq!(fiber.as_mut().resume(), Ok(FiberOutcome::Complete));
        assert_eq!(fiber.as_ref().state(), FiberState::Complete);
        assert_eq!(ENTRY_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(fiber.as_mut().resume(), Err(ResumeError::AlreadyComplete));
        assert_eq!(ENTRY_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(yield_now(), Err(YieldError::OutsideFiber));

        let mut fault_stack = core::pin::pin!(FixedStack::<MIN_STACK_SIZE>::new());
        let fault_fiber = Fiber::new(fault_stack.as_mut(), faulting_entry);
        let mut fault_fiber = core::pin::pin!(fault_fiber);
        let fault = FiberFault::new(77);

        assert_eq!(
            fault_fiber.as_mut().resume(),
            Ok(FiberOutcome::Faulted(fault))
        );
        assert_eq!(fault_fiber.as_ref().state(), FiberState::Faulted(fault));
        assert_eq!(FAULT_ENTRY_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(
            fault_fiber.as_mut().resume(),
            Err(ResumeError::AlreadyFaulted(fault))
        );
        assert_eq!(FAULT_ENTRY_COUNT.load(Ordering::SeqCst), 1);
    }
}
