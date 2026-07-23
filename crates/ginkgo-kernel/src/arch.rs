//! x86-64 privilege separation, `SYSCALL` entry, and ring-3 preemption foundation.
//!
//! This module allocates no stacks and chooses no process-specific syscall ABI.
//! Integration must create one [`CpuPrivilegeState`] per CPU, provide five
//! distinct mapped kernel stacks,
//! call [`initialize_cpu`] on that CPU, and later call [`enter_user`] with a
//! scheduler-owned [`UserContext`]. [`capture_syscall_and_yield`] is a stateless
//! dispatcher for the model where every syscall returns to the scheduler.
//!
//! # Current interrupt assumptions
//!
//! Kernel Rust normally runs with interrupts disabled. [`idle_until_interrupt`]
//! is the sole supported CPL0 site that briefly executes `STI; HLT; CLI` to wait
//! for an external interrupt, normally an armed timer. Validated user contexts
//! require IF, while `IA32_FMASK`
//! clears IF, TF, DF, NT, and AC atomically on every syscall.
//! Synchronous user exceptions and the local APIC preemption interrupt are
//! contained on TSS RSP0. The preemption path captures the complete user context,
//! acknowledges the APIC, and returns [`KernelExit::Preempted`] to the suspended
//! scheduler continuation. A timer arriving at the CPL0 idle site preserves the
//! interrupted register state, acknowledges EOI, and returns to the idle `CLI`.
//! The dedicated xHCI MSI entry similarly preserves interrupted state at CPL0 or
//! CPL3, records one coalescing pending bit, acknowledges EOI without entering
//! Rust or relying on GS, and returns directly. #DF, NMI, and #MC use dedicated
//! IST1/IST2/IST3 stacks and always fail-stop without accessing GS. Other external
//! interrupts, nested kernel entries, and enabling IF elsewhere in kernel Rust
//! remain unsupported.
//!
//! # Fault-handling limitation
//!
//! User-triggerable synchronous exceptions are returned as
//! [`KernelExit::Fault`]. Double faults, NMI, machine check, kernel-mode faults,
//! faults without an active user context, and unsupported vectors halt the CPU.
//! There is no resume-from-fault path, IRQ handling, recoverable NMI/MCE policy,
//! stack-overflow detection, or nested-entry accounting. Context validation
//! prevents non-canonical IRET control state, but cannot prove mappings
//! are present or correctly executable/writable. Successful [`initialize_cpu`]
//! guarantees CPU NX support and enables EFER.NXE; address-space code can use
//! [`validate_no_execute_requirement`] before accepting `NO_EXECUTE` mappings.
//!
//! [`UserContext`] owns a 64-byte-aligned extended-state area. XSAVE-capable CPUs
//! preserve enabled x87/SSE/AVX state across syscall, fault, preemption, and process
//! switches; legacy CPUs fall back to FXSAVE. AVX2 uses the preserved AVX state,
//! while system images retain an x86-64 plus x87/SSE/SSE2 target baseline.
//! Debug-register, FS-base, and user GS-base state remain unsupported. User GS
//! is reset to zero on every scheduler entry; GS is per-CPU state in the kernel.

use core::{
    arch::{asm, global_asm},
    mem::{offset_of, size_of},
    ptr,
    sync::atomic::{AtomicU64, AtomicU8, Ordering},
};

use crate::local_apic::{PREEMPTION_VECTOR, SPURIOUS_VECTOR};

pub const KERNEL_CODE_SELECTOR: u16 = 1 << 3;
pub const KERNEL_DATA_SELECTOR: u16 = 2 << 3;
pub const USER_DATA_SELECTOR: u16 = (3 << 3) | 3;
pub const USER_CODE_SELECTOR: u16 = (4 << 3) | 3;
pub const TSS_SELECTOR: u16 = 5 << 3;

const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;
const RFLAGS_RESUME: u64 = 1 << 16;
const USER_RFLAGS_REQUIRED: u64 = (1 << 1) | RFLAGS_INTERRUPT_ENABLE;
pub const USER_RFLAGS_DEFAULT: u64 = USER_RFLAGS_REQUIRED;
const USER_RFLAGS_ALLOWED: u64 = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 4)
    | (1 << 6)
    | (1 << 7)
    | (1 << 9)
    | (1 << 11)
    | RFLAGS_RESUME;

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
const IA32_GS_BASE: u32 = 0xc000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

const EFER_SYSTEM_CALL_EXTENSIONS: u64 = 1;
const EFER_NO_EXECUTE_ENABLE: u64 = 1 << 11;
const EXTENDED_FEATURES_LEAF: u32 = 0x8000_0001;
const CPUID_SYSCALL_SYSRET: u32 = 1 << 11;
const CPUID_NO_EXECUTE: u32 = 1 << 20;
const CPUID_FPU: u32 = 1 << 0;
const CPUID_XSAVE: u32 = 1 << 26;
const CPUID_AVX: u32 = 1 << 28;
const CPUID_FXSR: u32 = 1 << 24;
const CPUID_SSE: u32 = 1 << 25;
const CPUID_SSE2: u32 = 1 << 26;
const CR0_MONITOR_COPROCESSOR: u64 = 1 << 1;
const CR0_EMULATION: u64 = 1 << 2;
const CR0_TASK_SWITCHED: u64 = 1 << 3;
const CR0_NUMERIC_ERROR: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_SMAP: u64 = 1 << 21;
const CPUID_SMAP: u32 = 1 << 20;
const FXSAVE_SIZE: usize = 4096;

const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_AVX: u64 = 1 << 2;
const FXSAVE_FCW_OFFSET: usize = 0;
const FXSAVE_MXCSR_OFFSET: usize = 24;
const INITIAL_FCW: u16 = 0x037f;
const INITIAL_MXCSR: u32 = 0x1f80;
const SUPPORTED_MXCSR_BITS: u32 = 0x0000_ffbf;
const FMASK_VALUE: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | RFLAGS_RESUME | (1 << 18); // TF, IF, DF, NT, RF, AC
const STAR_VALUE: u64 =
    ((((USER_DATA_SELECTOR & !3) - 8) as u64) << 48) | ((KERNEL_CODE_SELECTOR as u64) << 32);

const _: () = assert!(star_selector_layout_is_valid(STAR_VALUE));

const GDT_ENTRY_COUNT: usize = 7;
const IDT_ENTRY_COUNT: usize = 256;
const DIVIDE_ERROR_VECTOR: usize = 0;
const DEBUG_VECTOR: usize = 1;
const NMI_VECTOR: usize = 2;
const BREAKPOINT_VECTOR: usize = 3;
const OVERFLOW_VECTOR: usize = 4;
const BOUND_RANGE_VECTOR: usize = 5;
const INVALID_OPCODE_VECTOR: usize = 6;
const DEVICE_NOT_AVAILABLE_VECTOR: usize = 7;
const DOUBLE_FAULT_VECTOR: usize = 8;
const INVALID_TSS_VECTOR: usize = 10;
const SEGMENT_NOT_PRESENT_VECTOR: usize = 11;
const STACK_SEGMENT_VECTOR: usize = 12;
const GENERAL_PROTECTION_VECTOR: usize = 13;
const PAGE_FAULT_VECTOR: usize = 14;
const X87_FLOATING_POINT_VECTOR: usize = 16;
const ALIGNMENT_CHECK_VECTOR: usize = 17;
const MACHINE_CHECK_VECTOR: usize = 18;
const SIMD_FLOATING_POINT_VECTOR: usize = 19;
const VIRTUALIZATION_VECTOR: usize = 20;
const CONTROL_PROTECTION_VECTOR: usize = 21;
const HYPERVISOR_INJECTION_VECTOR: usize = 28;
const VMM_COMMUNICATION_VECTOR: usize = 29;
const SECURITY_EXCEPTION_VECTOR: usize = 30;
/// Dedicated fixed xHCI MSI vector installed by the CPU IDT initialization.
pub const XHCI_VECTOR: u8 = 0x41;
const INTERRUPT_GATE_PRESENT_RING0: u8 = 0x8e;
const INTERRUPT_GATE_PRESENT_RING3: u8 = 0xee;
const DOUBLE_FAULT_IST_INDEX: u8 = 1;
const NMI_IST_INDEX: u8 = 2;
const MACHINE_CHECK_IST_INDEX: u8 = 3;
const KERNEL_EXIT_FAULT: u64 = 3;
const KERNEL_EXIT_PREEMPTED: u64 = 4;
const USER_CONTEXT_GPR_QWORDS: usize = offset_of!(UserContext, rip) / size_of::<u64>();
const USER_CONTEXT_QWORDS: usize = size_of::<UserContext>() / size_of::<u64>();

// These symbols are accessed directly by the xHCI assembly entry. They are
// process-global because this interrupt layer currently supports only the BSP.
#[no_mangle]
static GINKGO_XHCI_INTERRUPT_PENDING: AtomicU8 = AtomicU8::new(0);
#[no_mangle]
static GINKGO_EXTERNAL_INTERRUPT_EOI: AtomicU64 = AtomicU64::new(0);

/// Consumes the coalescing xHCI interrupt-pending flag.
///
/// The assembly ISR sets this flag before acknowledging the local APIC. Multiple
/// interrupts before one call intentionally coalesce into a single `true` result.
pub fn take_xhci_interrupt_pending() -> bool {
    GINKGO_XHCI_INTERRUPT_PENDING.swap(0, Ordering::AcqRel) != 0
}

/// Aligned extended state area. XSAVE-capable CPUs preserve enabled AVX state;
/// older CPUs use the architectural legacy prefix through FXSAVE.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FxState {
    bytes: [u8; FXSAVE_SIZE],
}

impl FxState {
    pub const fn initial() -> Self {
        let mut bytes = [0; FXSAVE_SIZE];
        bytes[FXSAVE_FCW_OFFSET] = INITIAL_FCW as u8;
        bytes[FXSAVE_FCW_OFFSET + 1] = (INITIAL_FCW >> 8) as u8;
        bytes[FXSAVE_MXCSR_OFFSET] = INITIAL_MXCSR as u8;
        bytes[FXSAVE_MXCSR_OFFSET + 1] = (INITIAL_MXCSR >> 8) as u8;
        bytes[FXSAVE_MXCSR_OFFSET + 2] = (INITIAL_MXCSR >> 16) as u8;
        bytes[FXSAVE_MXCSR_OFFSET + 3] = (INITIAL_MXCSR >> 24) as u8;
        Self { bytes }
    }

    pub const fn control_word(&self) -> u16 {
        u16::from_le_bytes([
            self.bytes[FXSAVE_FCW_OFFSET],
            self.bytes[FXSAVE_FCW_OFFSET + 1],
        ])
    }

    pub const fn mxcsr(&self) -> u32 {
        u32::from_le_bytes([
            self.bytes[FXSAVE_MXCSR_OFFSET],
            self.bytes[FXSAVE_MXCSR_OFFSET + 1],
            self.bytes[FXSAVE_MXCSR_OFFSET + 2],
            self.bytes[FXSAVE_MXCSR_OFFSET + 3],
        ])
    }

    const fn is_valid(&self) -> bool {
        self.mxcsr() & !SUPPORTED_MXCSR_BITS == 0
    }
}

impl Default for FxState {
    fn default() -> Self {
        Self::initial()
    }
}

/// General-purpose, IRET-visible, and x87/SSE state for one user thread.
///
/// All general-purpose registers are preserved by the IRET return path. After a
/// `SYSCALL`, `rcx` and `r11` naturally contain the architectural syscall-clobbered
/// values (the return RIP and pre-syscall RFLAGS); after an interrupt they retain
/// the ordinary user register values from the interrupted instruction. `rip` and
/// `rflags` are always the authoritative control state. `fx_state` is eagerly
/// switched with XSAVE64/XRSTOR64 when available and FXSAVE64/FXRSTOR64 otherwise.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserContext {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub fx_state: FxState,
}

impl UserContext {
    pub const fn new(rip: u64, rsp: u64) -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip,
            rsp,
            rflags: USER_RFLAGS_DEFAULT,
            fx_state: FxState::initial(),
        }
    }

    /// Sets the conventional RAX syscall result consumed by the next entry.
    ///
    /// With [`capture_syscall_and_yield`], the scheduler inspects the captured
    /// frame, computes the result, calls this method, and passes the same context
    /// to [`enter_user`] again. The first user instruction then observes `value`
    /// in RAX.
    pub fn set_syscall_return(&mut self, value: u64) {
        self.rax = value;
    }

    pub const fn validate(&self) -> Result<(), ContextValidationError> {
        if !is_user_canonical_address(self.rip) || self.rip == 0 {
            return Err(ContextValidationError::InvalidInstructionPointer);
        }
        if !is_user_canonical_address(self.rsp) || self.rsp == 0 {
            return Err(ContextValidationError::InvalidStackPointer);
        }
        if self.rflags & USER_RFLAGS_REQUIRED != USER_RFLAGS_REQUIRED
            || self.rflags & !USER_RFLAGS_ALLOWED != 0
        {
            return Err(ContextValidationError::InvalidFlags);
        }
        if !self.fx_state.is_valid() {
            return Err(ContextValidationError::InvalidFloatingPointState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextValidationError {
    InvalidInstructionPointer,
    InvalidStackPointer,
    InvalidFlags,
    InvalidFloatingPointState,
}

/// Action selected by the syscall dispatcher.
///
/// `ResumeUser` is honored only if the possibly modified context passes a fresh
/// validation immediately before `IRETQ`. Invalid state is converted to
/// `ExitToKernel` and returned to [`enter_user`] instead.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAction {
    ResumeUser = 0,
    YieldToKernel = 1,
    ExitToKernel = 2,
}

/// A contained ring-3 exception captured before returning to the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFaultFrame {
    pub vector: u64,
    pub error_code: u64,
    /// CR2 for a page fault; other contained exceptions have no fault address.
    pub fault_address: Option<u64>,
}

/// Kernel-side result of a completed [`enter_user`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelExit {
    YieldToKernel,
    ExitToKernel,
    Fault(UserFaultFrame),
    /// The local APIC timer captured this runnable context asynchronously.
    Preempted,
}

/// Dispatcher invoked on the protected per-CPU syscall stack.
///
/// The callback may inspect and modify all fields, then choose whether to
/// resume this frame or return control to the kernel scheduler.
pub type SyscallDispatcher = extern "C" fn(&mut UserContext) -> DispatchAction;

/// Stateless dispatcher for scheduler-mediated syscalls.
///
/// The entry assembly copies the syscall frame back into the `UserContext`
/// supplied to [`enter_user`] after this callback returns `YieldToKernel`. No
/// global process pointer is needed. The scheduler may then decode arguments,
/// update the frame (including with [`UserContext::set_syscall_return`]), and
/// call [`enter_user`] again.
pub extern "C" fn capture_syscall_and_yield(_context: &mut UserContext) -> DispatchAction {
    DispatchAction::YieldToKernel
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuCapabilities {
    pub syscall_sysret: bool,
    pub no_execute: bool,
    pub fxsave_sse: bool,
    pub smap: bool,
    pub xsave: bool,
    pub avx: bool,
    /// Physical-address width reported by CPUID and capped by the active paging implementation.
    pub physical_address_bits: u8,
    /// Linear-address width reported by CPUID. The current four-level kernel deliberately
    /// continues to use only the low 48 bits until it implements LA57 page tables.
    pub linear_address_bits: u8,
}

impl CpuCapabilities {
    const fn from_cpuid(
        maximum_extended_leaf: u32,
        extended_edx: u32,
        maximum_standard_leaf: u32,
        standard_ecx: u32,
        standard_edx: u32,
        structured_ebx: u32,
        address_widths_eax: u32,
    ) -> Self {
        let has_extended_features = maximum_extended_leaf >= EXTENDED_FEATURES_LEAF;
        let (physical_address_bits, linear_address_bits) =
            if maximum_extended_leaf >= ADDRESS_WIDTHS_LEAF {
                validated_address_widths(address_widths_eax as u8, (address_widths_eax >> 8) as u8)
            } else {
                (
                    DEFAULT_PHYSICAL_ADDRESS_BITS,
                    FOUR_LEVEL_LINEAR_ADDRESS_BITS,
                )
            };
        Self {
            syscall_sysret: has_extended_features && extended_edx & CPUID_SYSCALL_SYSRET != 0,
            no_execute: has_extended_features && extended_edx & CPUID_NO_EXECUTE != 0,
            fxsave_sse: standard_edx & (CPUID_FPU | CPUID_FXSR | CPUID_SSE | CPUID_SSE2)
                == (CPUID_FPU | CPUID_FXSR | CPUID_SSE | CPUID_SSE2),
            smap: maximum_standard_leaf >= 7 && structured_ebx & CPUID_SMAP != 0,
            xsave: standard_ecx & CPUID_XSAVE != 0,
            avx: standard_ecx & (CPUID_XSAVE | CPUID_AVX) == (CPUID_XSAVE | CPUID_AVX),
            physical_address_bits,
            linear_address_bits,
        }
    }
}

/// The x86-64 page-table implementation represents at most 52 physical bits.
pub const MAX_PHYSICAL_ADDRESS_BITS: u8 = 52;
/// Four-level page tables make bits 0 through 47 canonical; LA57 is not enabled.
pub const FOUR_LEVEL_LINEAR_ADDRESS_BITS: u8 = 48;
const DEFAULT_PHYSICAL_ADDRESS_BITS: u8 = 36;
const ADDRESS_WIDTHS_LEAF: u32 = 0x8000_0008;

const fn validated_address_widths(physical: u8, linear: u8) -> (u8, u8) {
    let physical = if physical >= 12 && physical <= MAX_PHYSICAL_ADDRESS_BITS {
        physical
    } else {
        DEFAULT_PHYSICAL_ADDRESS_BITS
    };
    let linear = if linear >= FOUR_LEVEL_LINEAR_ADDRESS_BITS && linear <= 57 {
        linear
    } else {
        FOUR_LEVEL_LINEAR_ADDRESS_BITS
    };
    (physical, linear)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoExecuteError {
    Unsupported,
}

/// Validates an address-space request to use a `NO_EXECUTE` page-table bit.
///
/// This is pure so page-table policy can be tested independently. Runtime code
/// should pass [`cpu_capabilities`] from the CPU that will activate the mapping.
pub const fn validate_no_execute_requirement(
    no_execute_requested: bool,
    capabilities: CpuCapabilities,
) -> Result<(), NoExecuteError> {
    if no_execute_requested && !capabilities.no_execute {
        Err(NoExecuteError::Unsupported)
    } else {
        Ok(())
    }
}

/// Enables the architectural no-execute page-table bit before early kernel
/// subsystems install non-executable mappings.
///
/// # Safety
///
/// The caller must run at CPL0 on the current CPU and must ensure that every
/// existing page-table entry has a valid reserved-bit encoding once NXE is set.
pub unsafe fn enable_no_execute() -> Result<(), NoExecuteError> {
    validate_no_execute_requirement(true, cpu_capabilities())?;
    unsafe { write_msr(IA32_EFER, read_msr(IA32_EFER) | EFER_NO_EXECUTE_ENABLE) };
    Ok(())
}

/// External-interrupt resources installed into one CPU's entry state.
///
/// A zero EOI address disables maskable external-interrupt entries and is used
/// by the legacy [`initialize_cpu`] wrapper. A configured address must be the
/// permanently mapped, supervisor-only virtual address returned by
/// [`crate::local_apic::LocalApicTimer::eoi_register_address`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalInterruptState {
    pub local_apic_eoi: u64,
}

impl ExternalInterruptState {
    pub const DISABLED: Self = Self { local_apic_eoi: 0 };

    pub const fn local_apic(local_apic_eoi: u64) -> Self {
        Self { local_apic_eoi }
    }

    const fn validate(self) -> Result<(), InitializeError> {
        if self.local_apic_eoi == 0 {
            return Ok(());
        }
        if !is_canonical_address(self.local_apic_eoi)
            || self.local_apic_eoi < 0xffff_8000_0000_0000
            || self.local_apic_eoi & 3 != 0
        {
            return Err(InitializeError::InvalidInterruptEoiAddress);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitializeError {
    InterruptsEnabled,
    SyscallUnsupported,
    NoExecuteUnsupported,
    FloatingPointUnsupported,
    ExtendedStateTooLarge(u32),
    InvalidStackTop,
    SharedStackTop,
    InvalidInterruptEoiAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterUserError {
    InvalidContext(ContextValidationError),
}

/// Failure to enter the interrupt-driven idle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleError {
    /// The caller already had IF set, which would violate the kernel entry model.
    InterruptsEnabled,
    /// Privileged `STI`/`HLT`/`CLI` execution is unavailable in a hosted build.
    UnsupportedEnvironment,
}

/// Sleeps until a supported local-APIC interrupt arrives.
///
/// This is the only supported site at which kernel code temporarily enables
/// maskable interrupts. The caller must have initialized the current CPU with
/// [`initialize_cpu_with_external_interrupts`] and normally arms its local APIC
/// timer first. If no interrupt is capable of arriving, the CPU may remain halted
/// forever.
///
/// The function first verifies that IF is clear. On bare metal, `STI; HLT` is a
/// lost-wakeup-safe pair because interrupt recognition is inhibited until after
/// the instruction following `STI` begins. A CPL0 timer or xHCI interrupt
/// acknowledges the APIC and IRETs to the following `CLI`, so this function
/// always returns to its caller with IF clear. Other CPL0 interrupt sites remain
/// unsupported.
pub fn idle_until_interrupt() -> Result<(), IdleError> {
    if interrupts_enabled() {
        return Err(IdleError::InterruptsEnabled);
    }

    #[cfg(target_os = "none")]
    unsafe {
        asm!("sti", "hlt", "cli", options(nostack, preserves_flags));
        Ok(())
    }

    #[cfg(not(target_os = "none"))]
    {
        Err(IdleError::UnsupportedEnvironment)
    }
}

/// Top addresses of five caller-owned, downward-growing kernel stacks.
///
/// RSP0 receives contained CPL3 exceptions. Dedicated IST1, IST2, and IST3
/// stacks fail-stop double fault, NMI, and machine check even during a
/// SWAPGS/IRET window. `syscall` is used by LSTAR. All five extents must be
/// disjoint, not merely have distinct top addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivilegeStackTops {
    pub rsp0: u64,
    pub double_fault: u64,
    pub nmi: u64,
    pub machine_check: u64,
    pub syscall: u64,
}

impl PrivilegeStackTops {
    const fn validate(self) -> Result<(), InitializeError> {
        let tops = [
            self.rsp0,
            self.double_fault,
            self.nmi,
            self.machine_check,
            self.syscall,
        ];
        let mut index = 0;
        while index < tops.len() {
            if !valid_kernel_stack_top(tops[index]) {
                return Err(InitializeError::InvalidStackTop);
            }
            let mut other = index + 1;
            while other < tops.len() {
                if tops[index] == tops[other] {
                    return Err(InitializeError::SharedStackTop);
                }
                other += 1;
            }
            index += 1;
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    const fn interrupt_gate(handler: u64, ist: u8, type_attributes: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x7,
            type_attributes,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    #[cfg(all(test, not(target_os = "none")))]
    const fn handler(self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_middle as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }
}

#[repr(C, align(16))]
struct InterruptDescriptorTable {
    entries: [IdtEntry; IDT_ENTRY_COUNT],
}

impl InterruptDescriptorTable {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); IDT_ENTRY_COUNT],
        }
    }
}

#[derive(Clone, Copy)]
struct ExceptionGate {
    vector: usize,
    handler: u64,
    ist: u8,
    type_attributes: u8,
}

impl ExceptionGate {
    const fn ring0(vector: usize, handler: u64) -> Self {
        Self {
            vector,
            handler,
            ist: 0,
            type_attributes: INTERRUPT_GATE_PRESENT_RING0,
        }
    }

    const fn ring3(vector: usize, handler: u64) -> Self {
        Self {
            vector,
            handler,
            ist: 0,
            type_attributes: INTERRUPT_GATE_PRESENT_RING3,
        }
    }

    const fn fail_stop(vector: usize, handler: u64, ist: u8) -> Self {
        Self {
            vector,
            handler,
            ist,
            type_attributes: INTERRUPT_GATE_PRESENT_RING0,
        }
    }
}

fn exception_idt(fail_stop: u64, gates: &[ExceptionGate]) -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();
    for entry in &mut idt.entries {
        *entry = IdtEntry::interrupt_gate(fail_stop, 0, INTERRUPT_GATE_PRESENT_RING0);
    }
    for gate in gates {
        idt.entries[gate.vector] =
            IdtEntry::interrupt_gate(gate.handler, gate.ist, gate.type_attributes);
    }
    idt
}

/// CPU-local descriptor tables, IDT, and entry bookkeeping.
///
/// Construct this in static storage with [`CpuPrivilegeState::new`]. Passing it
/// to [`initialize_cpu`] permanently lends its address to the processor through
/// GDTR, IDTR, TR, and `IA32_GS_BASE`; it must never be moved or aliased mutably
/// after initialization.
#[repr(C, align(16))]
pub struct CpuPrivilegeState {
    syscall: SyscallCpuState,
    kernel_fx_state: FxState,
    gdt: [u64; GDT_ENTRY_COUNT],
    tss: TaskStateSegment,
    idt: InterruptDescriptorTable,
}

impl CpuPrivilegeState {
    pub const fn new() -> Self {
        Self {
            syscall: SyscallCpuState::new(),
            kernel_fx_state: FxState::initial(),
            gdt: [0; GDT_ENTRY_COUNT],
            tss: TaskStateSegment::new(),
            idt: InterruptDescriptorTable::new(),
        }
    }
}

impl Default for CpuPrivilegeState {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
struct SyscallCpuState {
    syscall_stack_top: u64,
    kernel_rsp: u64,
    user_rsp: u64,
    dispatcher: u64,
    active_context: u64,
    fault_valid: u64,
    fault_vector: u64,
    fault_error_code: u64,
    fault_address: u64,
    interrupt_eoi: u64,
    user_copy_fixup: u64,
    smap_enabled: u64,
    xsave_enabled: u64,
    xsave_mask_low: u64,
    xsave_mask_high: u64,
}

impl SyscallCpuState {
    const fn new() -> Self {
        Self {
            syscall_stack_top: 0,
            kernel_rsp: 0,
            user_rsp: 0,
            dispatcher: 0,
            active_context: 0,
            fault_valid: 0,
            fault_vector: 0,
            fault_error_code: 0,
            fault_address: 0,
            interrupt_eoi: 0,
            user_copy_fixup: 0,
            smap_enabled: 0,
            xsave_enabled: 0,
            xsave_mask_low: 0,
            xsave_mask_high: 0,
        }
    }
}

#[repr(C, packed)]
struct TaskStateSegment {
    reserved_1: u32,
    rsp: [u64; 3],
    reserved_2: u64,
    ist: [u64; 7],
    reserved_3: u64,
    reserved_4: u16,
    io_map_base: u16,
}

impl TaskStateSegment {
    const fn new() -> Self {
        Self {
            reserved_1: 0,
            rsp: [0; 3],
            reserved_2: 0,
            ist: [0; 7],
            reserved_3: 0,
            reserved_4: 0,
            io_map_base: size_of::<Self>() as u16,
        }
    }

    unsafe fn set_stack_tops(&mut self, stacks: PrivilegeStackTops) {
        let this = self as *mut Self;
        unsafe {
            ptr::addr_of_mut!((*this).rsp[0]).write_unaligned(stacks.rsp0);
            ptr::addr_of_mut!((*this).ist[0]).write_unaligned(stacks.double_fault);
            ptr::addr_of_mut!((*this).ist[1]).write_unaligned(stacks.nmi);
            ptr::addr_of_mut!((*this).ist[2]).write_unaligned(stacks.machine_check);
        }
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

/// Stack words normalized by each exception stub after the saved GPR block.
/// RSP/SS are present because containment proceeds only when saved CS has RPL3.
#[repr(C)]
struct NormalizedExceptionFrame {
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

const fn exception_pushes_error_code(vector: usize) -> bool {
    vector == 8
        || vector == 10
        || vector == 11
        || vector == 12
        || vector == 13
        || vector == 14
        || vector == 17
        || vector == 21
        || vector == 29
        || vector == 30
}

const _: () = {
    assert!(!exception_pushes_error_code(DIVIDE_ERROR_VECTOR));
    assert!(!exception_pushes_error_code(DEBUG_VECTOR));
    assert!(!exception_pushes_error_code(BREAKPOINT_VECTOR));
    assert!(!exception_pushes_error_code(OVERFLOW_VECTOR));
    assert!(!exception_pushes_error_code(BOUND_RANGE_VECTOR));
    assert!(!exception_pushes_error_code(INVALID_OPCODE_VECTOR));
    assert!(!exception_pushes_error_code(DEVICE_NOT_AVAILABLE_VECTOR));
    assert!(!exception_pushes_error_code(X87_FLOATING_POINT_VECTOR));
    assert!(!exception_pushes_error_code(SIMD_FLOATING_POINT_VECTOR));
    assert!(!exception_pushes_error_code(VIRTUALIZATION_VECTOR));
    assert!(!exception_pushes_error_code(HYPERVISOR_INJECTION_VECTOR));
    assert!(exception_pushes_error_code(DOUBLE_FAULT_VECTOR));
    assert!(exception_pushes_error_code(INVALID_TSS_VECTOR));
    assert!(exception_pushes_error_code(SEGMENT_NOT_PRESENT_VECTOR));
    assert!(exception_pushes_error_code(STACK_SEGMENT_VECTOR));
    assert!(exception_pushes_error_code(GENERAL_PROTECTION_VECTOR));
    assert!(exception_pushes_error_code(PAGE_FAULT_VECTOR));
    assert!(exception_pushes_error_code(ALIGNMENT_CHECK_VECTOR));
    assert!(exception_pushes_error_code(CONTROL_PROTECTION_VECTOR));
    assert!(exception_pushes_error_code(VMM_COMMUNICATION_VECTOR));
    assert!(exception_pushes_error_code(SECURITY_EXCEPTION_VECTOR));
};

const fn star_selector_layout_is_valid(star: u64) -> bool {
    let syscall_cs = ((star >> 32) as u16) & !3;
    let sysret_base = ((star >> 48) as u16) & !3;
    syscall_cs == KERNEL_CODE_SELECTOR
        && syscall_cs + 8 == KERNEL_DATA_SELECTOR
        && ((sysret_base + 8) | 3) == USER_DATA_SELECTOR
        && ((sysret_base + 16) | 3) == USER_CODE_SELECTOR
}

/// Returns whether `address` is canonical under the kernel's current four-level
/// (48-bit virtual-address) contract.
pub const fn is_canonical_address(address: u64) -> bool {
    let sign = (address >> 47) & 1;
    let upper = address >> 48;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

/// Returns whether `address` is in the lower canonical user half.
pub const fn is_user_canonical_address(address: u64) -> bool {
    is_canonical_address(address) && address < (1_u64 << 47)
}

const fn valid_kernel_stack_top(address: u64) -> bool {
    address != 0 && address & 0xf == 0 && is_canonical_address(address)
}

/// Installs GDT/TSS/IDT, enables EFER.SCE/NXE, configures eager FXSAVE, and
/// configures `SYSCALL` without an active external-interrupt controller.
///
/// Success is also the capability boundary for address-space setup: both
/// `SYSCALL/SYSRET`, execute-disable, FXSAVE, SSE, and SSE2 have been verified
/// by CPUID. EFER.NXE and CR4.OSFXSR/OSXMMEXCPT are active before return;
/// CR4.OSXSAVE is preserved rather than forcibly disabling hardware features.
///
/// # Safety
///
/// - This function must execute once on the CPU represented by `state`, at CPL0,
///   with interrupts disabled and long mode/four-level paging already active.
/// - `state` must be unique to this CPU and remain mapped, writable, and at the
///   same virtual address forever.
/// - Each supplied top must belong to a distinct, writable, supervisor-only,
///   downward-growing stack with enough committed space for its entry class.
///   The top addresses alone cannot prove stack extent or non-overlap.
/// - The dispatcher must obey the C ABI, must not unwind, and must not enable
///   interrupts under the current single-entry assumptions.
/// - No pre-existing code may depend on the old GDT, IDT, TR, GS base, kernel
///   GS base, or syscall MSRs after this call.
pub unsafe fn initialize_cpu(
    state: &'static mut CpuPrivilegeState,
    stacks: PrivilegeStackTops,
    dispatcher: SyscallDispatcher,
) -> Result<(), InitializeError> {
    unsafe {
        initialize_cpu_with_external_interrupts(
            state,
            stacks,
            dispatcher,
            ExternalInterruptState::DISABLED,
        )
    }
}

/// Installs the privilege foundation and local-APIC external-interrupt EOI target.
///
/// This is the interrupt-capable form of [`initialize_cpu`]. In addition to that
/// function's safety contract, `external.local_apic_eoi` must remain mapped,
/// writable, supervisor-only, and uncached in every user address space activated
/// on this CPU. Kernel code must keep IF clear; only validated ring-3 contexts
/// run with maskable interrupts enabled.
pub unsafe fn initialize_cpu_with_external_interrupts(
    state: &'static mut CpuPrivilegeState,
    stacks: PrivilegeStackTops,
    dispatcher: SyscallDispatcher,
    external: ExternalInterruptState,
) -> Result<(), InitializeError> {
    if interrupts_enabled() {
        return Err(InitializeError::InterruptsEnabled);
    }
    let capabilities = cpu_capabilities();
    if !capabilities.syscall_sysret {
        return Err(InitializeError::SyscallUnsupported);
    }
    if validate_no_execute_requirement(true, capabilities).is_err() {
        return Err(InitializeError::NoExecuteUnsupported);
    }
    if !capabilities.fxsave_sse {
        return Err(InitializeError::FloatingPointUnsupported);
    }
    stacks.validate()?;
    external.validate()?;
    let xsave_mask = unsafe { configure_extended_state(capabilities)? };

    state.syscall.xsave_enabled = u64::from(xsave_mask.is_some());
    state.syscall.xsave_mask_low = xsave_mask.unwrap_or(0) as u32 as u64;
    state.syscall.xsave_mask_high = xsave_mask.unwrap_or(0) >> 32;
    state.syscall.syscall_stack_top = stacks.syscall;
    state.syscall.dispatcher = dispatcher as usize as u64;
    state.syscall.interrupt_eoi = external.local_apic_eoi;
    GINKGO_XHCI_INTERRUPT_PENDING.store(0, Ordering::Relaxed);
    GINKGO_EXTERNAL_INTERRUPT_EOI.store(external.local_apic_eoi, Ordering::Release);
    unsafe { state.tss.set_stack_tops(stacks) };

    let tss_base = ptr::addr_of!(state.tss) as u64;
    let (tss_low, tss_high) = tss_descriptor(tss_base, (size_of::<TaskStateSegment>() - 1) as u32);
    state.gdt = gdt(tss_low, tss_high);
    let fail_stop = ginkgo_x86_exception_fail_stop as *const () as usize as u64;
    state.idt = exception_idt(
        fail_stop,
        &[
            ExceptionGate::ring0(
                DIVIDE_ERROR_VECTOR,
                ginkgo_x86_exception_divide_error as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                DEBUG_VECTOR,
                ginkgo_x86_exception_debug as *const () as usize as u64,
            ),
            ExceptionGate::fail_stop(NMI_VECTOR, fail_stop, NMI_IST_INDEX),
            ExceptionGate::ring3(
                BREAKPOINT_VECTOR,
                ginkgo_x86_exception_breakpoint as *const () as usize as u64,
            ),
            ExceptionGate::ring3(
                OVERFLOW_VECTOR,
                ginkgo_x86_exception_overflow as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                BOUND_RANGE_VECTOR,
                ginkgo_x86_exception_bound_range as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                INVALID_OPCODE_VECTOR,
                ginkgo_x86_exception_invalid_opcode as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                DEVICE_NOT_AVAILABLE_VECTOR,
                ginkgo_x86_exception_device_not_available as *const () as usize as u64,
            ),
            ExceptionGate::fail_stop(DOUBLE_FAULT_VECTOR, fail_stop, DOUBLE_FAULT_IST_INDEX),
            ExceptionGate::ring0(
                INVALID_TSS_VECTOR,
                ginkgo_x86_exception_invalid_tss as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                SEGMENT_NOT_PRESENT_VECTOR,
                ginkgo_x86_exception_segment_not_present as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                STACK_SEGMENT_VECTOR,
                ginkgo_x86_exception_stack_segment as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                GENERAL_PROTECTION_VECTOR,
                ginkgo_x86_exception_general_protection as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                PAGE_FAULT_VECTOR,
                ginkgo_x86_exception_page_fault as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                X87_FLOATING_POINT_VECTOR,
                ginkgo_x86_exception_x87_floating_point as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                ALIGNMENT_CHECK_VECTOR,
                ginkgo_x86_exception_alignment_check as *const () as usize as u64,
            ),
            ExceptionGate::fail_stop(MACHINE_CHECK_VECTOR, fail_stop, MACHINE_CHECK_IST_INDEX),
            ExceptionGate::ring0(
                SIMD_FLOATING_POINT_VECTOR,
                ginkgo_x86_exception_simd_floating_point as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                VIRTUALIZATION_VECTOR,
                ginkgo_x86_exception_virtualization as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                CONTROL_PROTECTION_VECTOR,
                ginkgo_x86_exception_control_protection as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                HYPERVISOR_INJECTION_VECTOR,
                ginkgo_x86_exception_hypervisor_injection as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                VMM_COMMUNICATION_VECTOR,
                ginkgo_x86_exception_vmm_communication as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                SECURITY_EXCEPTION_VECTOR,
                ginkgo_x86_exception_security as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                usize::from(PREEMPTION_VECTOR),
                ginkgo_x86_timer_interrupt as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                usize::from(XHCI_VECTOR),
                ginkgo_x86_xhci_interrupt as *const () as usize as u64,
            ),
            ExceptionGate::ring0(
                usize::from(SPURIOUS_VECTOR),
                ginkgo_x86_spurious_interrupt as *const () as usize as u64,
            ),
        ],
    );

    let gdtr = DescriptorTablePointer {
        limit: (size_of::<[u64; GDT_ENTRY_COUNT]>() - 1) as u16,
        base: ptr::addr_of!(state.gdt) as u64,
    };
    let idtr = DescriptorTablePointer {
        limit: (size_of::<InterruptDescriptorTable>() - 1) as u16,
        base: ptr::addr_of!(state.idt) as u64,
    };
    unsafe {
        load_gdt_and_tss(&gdtr);
        load_idt(&idtr);
    };

    let state_address = state as *mut CpuPrivilegeState as u64;
    state.syscall.smap_enabled = u64::from(capabilities.smap);
    unsafe {
        write_msr(IA32_GS_BASE, state_address);
        write_msr(IA32_KERNEL_GS_BASE, 0);
        write_msr(IA32_STAR, STAR_VALUE);
        write_msr(
            IA32_LSTAR,
            ginkgo_x86_syscall_entry as *const () as usize as u64,
        );
        write_msr(IA32_FMASK, FMASK_VALUE);
        write_msr(
            IA32_EFER,
            read_msr(IA32_EFER) | EFER_SYSTEM_CALL_EXTENSIONS | EFER_NO_EXECUTE_ENABLE,
        );
        if capabilities.smap {
            asm!("clac", options(nomem, nostack, preserves_flags));
            let mut cr4: u64;
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            asm!("mov cr4, {}", in(reg) (cr4 | CR4_SMAP), options(nomem, nostack, preserves_flags));
        }
    }
    Ok(())
}

/// Enters a validated user context and returns only when its dispatcher yields
/// or exits to the scheduler.
///
/// # Safety
///
/// The current CPU must have been initialized by [`initialize_cpu`], the kernel
/// caller must have IF clear, `context` must stay exclusively borrowed for the whole
/// user run, and its user mappings (including the stack and instruction pages)
/// must remain valid. If the caller has switched CR3, that address space must
/// also retain supervisor-only mappings for this entry text, the per-CPU state,
/// the syscall stack, and `context`; SYSCALL does not switch page tables. The
/// assembly preserves the kernel ABI's callee-saved GPRs, eagerly switches the
/// complete enabled x87/SSE/AVX image, and restores the exact kernel stack before
/// this function returns.
pub unsafe fn enter_user(context: &mut UserContext) -> Result<KernelExit, EnterUserError> {
    context.validate().map_err(EnterUserError::InvalidContext)?;

    // Do not leak a previous thread's user GS base across scheduler entries.
    // During kernel execution GS_BASE is per-CPU and KERNEL_GS_BASE is the value
    // that SWAPGS will install immediately before IRETQ.
    unsafe { write_msr(IA32_KERNEL_GS_BASE, 0) };
    let action = unsafe { ginkgo_x86_enter_user(context) };
    Ok(match action {
        action if action == DispatchAction::YieldToKernel as u64 => KernelExit::YieldToKernel,
        action if action == DispatchAction::ExitToKernel as u64 => KernelExit::ExitToKernel,
        KERNEL_EXIT_FAULT => {
            let Some(fault) = (unsafe { take_user_fault() }) else {
                fail_stop();
            };
            KernelExit::Fault(fault)
        }
        KERNEL_EXIT_PREEMPTED => KernelExit::Preempted,
        _ => fail_stop(),
    })
}

/// Takes the contained user-fault record from the current CPU's GS state.
///
/// This is consumed internally by [`enter_user`] and returned as
/// [`KernelExit::Fault`], keeping process ownership in the scheduler rather than
/// in a global exception handler.
unsafe fn take_user_fault() -> Option<UserFaultFrame> {
    let valid: u64;
    let vector: u64;
    let error_code: u64;
    let address: u64;
    unsafe {
        asm!(
            "mov {valid}, qword ptr gs:[{fault_valid}]",
            "mov {vector}, qword ptr gs:[{fault_vector}]",
            "mov {error_code}, qword ptr gs:[{fault_error_code}]",
            "mov {address}, qword ptr gs:[{fault_address}]",
            "mov qword ptr gs:[{fault_valid}], 0",
            valid = out(reg) valid,
            vector = out(reg) vector,
            error_code = out(reg) error_code,
            address = out(reg) address,
            fault_valid = const STATE_FAULT_VALID,
            fault_vector = const STATE_FAULT_VECTOR,
            fault_error_code = const STATE_FAULT_ERROR_CODE,
            fault_address = const STATE_FAULT_ADDRESS,
            options(nostack, preserves_flags),
        );
    }
    if valid == 0 {
        None
    } else {
        Some(user_fault_frame(vector, error_code, address))
    }
}

const fn user_fault_frame(vector: u64, error_code: u64, fault_address: u64) -> UserFaultFrame {
    UserFaultFrame {
        vector,
        error_code,
        fault_address: if vector == PAGE_FAULT_VECTOR as u64 {
            Some(fault_address)
        } else {
            None
        },
    }
}

fn fail_stop() -> ! {
    unsafe {
        asm!("cli", "2:", "hlt", "jmp 2b", options(noreturn));
    }
}

const fn rflags_interrupts_enabled(rflags: u64) -> bool {
    rflags & RFLAGS_INTERRUPT_ENABLE != 0
}

fn interrupts_enabled() -> bool {
    let rflags: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
    }
    rflags_interrupts_enabled(rflags)
}

/// Reports the CPU features required by this privilege foundation.
pub fn cpu_capabilities() -> CpuCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        let maximum_standard = core::arch::x86_64::__cpuid(0).eax;
        let maximum = core::arch::x86_64::__cpuid(0x8000_0000).eax;
        let extended_edx = if maximum >= EXTENDED_FEATURES_LEAF {
            core::arch::x86_64::__cpuid(EXTENDED_FEATURES_LEAF).edx
        } else {
            0
        };
        let address_widths_eax = if maximum >= ADDRESS_WIDTHS_LEAF {
            core::arch::x86_64::__cpuid(ADDRESS_WIDTHS_LEAF).eax
        } else {
            0
        };
        let standard = core::arch::x86_64::__cpuid(1);
        let standard_ecx = standard.ecx;
        let standard_edx = standard.edx;
        let structured_ebx = if maximum_standard >= 7 {
            core::arch::x86_64::__cpuid_count(7, 0).ebx
        } else {
            0
        };
        CpuCapabilities::from_cpuid(
            maximum,
            extended_edx,
            maximum_standard,
            standard_ecx,
            standard_edx,
            structured_ebx,
            address_widths_eax,
        )
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        CpuCapabilities::from_cpuid(0, 0, 0, 0, 0, 0, 0)
    }
}

const fn fxsave_cr0(current: u64) -> u64 {
    (current | CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR) & !(CR0_EMULATION | CR0_TASK_SWITCHED)
}

const fn fxsave_cr4(current: u64, xsave: bool) -> u64 {
    let required = CR4_OSFXSR | CR4_OSXMMEXCPT;
    if xsave {
        current | required | CR4_OSXSAVE
    } else {
        current | required
    }
}

unsafe fn configure_extended_state(
    capabilities: CpuCapabilities,
) -> Result<Option<u64>, InitializeError> {
    let mut cr0: u64;
    let mut cr4: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr0 = fxsave_cr0(cr0);
    cr4 = fxsave_cr4(cr4, capabilities.xsave);
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }

    let xsave_mask = if capabilities.xsave {
        let mask = XCR0_X87 | XCR0_SSE | if capabilities.avx { XCR0_AVX } else { 0 };
        unsafe {
            asm!(
                "xsetbv",
                in("ecx") 0_u32,
                in("eax") mask as u32,
                in("edx") (mask >> 32) as u32,
                options(nostack),
            );
        }
        let required = core::arch::x86_64::__cpuid_count(0x0d, 0).ebx;
        if required as usize > FXSAVE_SIZE {
            return Err(InitializeError::ExtendedStateTooLarge(required));
        }
        Some(mask)
    } else {
        None
    };

    let mxcsr = INITIAL_MXCSR;
    unsafe {
        asm!(
            "fninit",
            "ldmxcsr [{}]",
            in(reg) &mxcsr,
            options(readonly, preserves_flags),
        );
    }
    Ok(xsave_mask)
}

unsafe fn load_gdt_and_tss(gdtr: &DescriptorTablePointer) {
    unsafe {
        asm!(
            "lgdt [{gdtr}]",
            "push {kernel_code}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {kernel_data}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov eax, 0",
            "mov fs, ax",
            "mov gs, ax",
            "mov ax, {tss}",
            "ltr ax",
            gdtr = in(reg) gdtr,
            kernel_code = const KERNEL_CODE_SELECTOR,
            kernel_data = const KERNEL_DATA_SELECTOR,
            tss = const TSS_SELECTOR,
            lateout("rax") _,
            options(preserves_flags),
        );
    }
}

unsafe fn load_idt(idtr: &DescriptorTablePointer) {
    unsafe {
        asm!("lidt [{idtr}]", idtr = in(reg) idtr, options(readonly, nostack, preserves_flags));
    }
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    u64::from(low) | (u64::from(high) << 32)
}

unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

const fn gdt(tss_low: u64, tss_high: u64) -> [u64; GDT_ENTRY_COUNT] {
    [
        0,
        0x00af_9a00_0000_ffff, // Ring 0, executable, readable, long mode.
        0x00cf_9200_0000_ffff, // Ring 0 data.
        0x00cf_f200_0000_ffff, // Ring 3 data; must precede user code for SYSRET.
        0x00af_fa00_0000_ffff, // Ring 3, executable, readable, long mode.
        tss_low,
        tss_high,
    ]
}

const fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let low = ((limit & 0xffff) as u64)
        | ((base & 0x00ff_ffff) << 16)
        | (0x9_u64 << 40) // Available 64-bit TSS.
        | (1_u64 << 47) // Present.
        | ((((limit >> 16) & 0xf) as u64) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

const STATE_KERNEL_FX: usize = offset_of!(CpuPrivilegeState, kernel_fx_state);
const STATE_SYSCALL_STACK_TOP: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, syscall_stack_top);
const STATE_KERNEL_RSP: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, kernel_rsp);
const STATE_USER_RSP: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, user_rsp);
const STATE_DISPATCHER: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, dispatcher);
const STATE_ACTIVE_CONTEXT: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, active_context);
const STATE_FAULT_VALID: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, fault_valid);
const STATE_FAULT_VECTOR: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, fault_vector);
const STATE_FAULT_ERROR_CODE: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, fault_error_code);
const STATE_FAULT_ADDRESS: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, fault_address);
const STATE_INTERRUPT_EOI: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, interrupt_eoi);
const STATE_USER_COPY_FIXUP: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, user_copy_fixup);
const STATE_SMAP_ENABLED: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, smap_enabled);
const STATE_XSAVE_ENABLED: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, xsave_enabled);
const STATE_XSAVE_MASK_LOW: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, xsave_mask_low);
const STATE_XSAVE_MASK_HIGH: usize =
    offset_of!(CpuPrivilegeState, syscall) + offset_of!(SyscallCpuState, xsave_mask_high);

const EXCEPTION_SAVED_GPRS_SIZE: usize = USER_CONTEXT_GPR_QWORDS * size_of::<u64>();
const EXCEPTION_VECTOR_OFFSET: usize =
    EXCEPTION_SAVED_GPRS_SIZE + offset_of!(NormalizedExceptionFrame, vector);
const EXCEPTION_ERROR_CODE_OFFSET: usize =
    EXCEPTION_SAVED_GPRS_SIZE + offset_of!(NormalizedExceptionFrame, error_code);
const EXCEPTION_RIP_OFFSET: usize =
    EXCEPTION_SAVED_GPRS_SIZE + offset_of!(NormalizedExceptionFrame, rip);
const EXCEPTION_RFLAGS_OFFSET: usize =
    EXCEPTION_SAVED_GPRS_SIZE + offset_of!(NormalizedExceptionFrame, rflags);
const EXCEPTION_RSP_OFFSET: usize =
    EXCEPTION_SAVED_GPRS_SIZE + offset_of!(NormalizedExceptionFrame, rsp);
const NORMALIZED_EXCEPTION_CS_OFFSET: usize = offset_of!(NormalizedExceptionFrame, cs);
const KERNEL_EXCEPTION_RIP_OFFSET: usize = offset_of!(NormalizedExceptionFrame, rip);

/// Copies a validated range while recovering a page fault as `false`.
///
/// # Safety
/// Both ranges must be valid for `length`; exactly one range may refer to the
/// active userspace address space. Interrupts must remain disabled.
pub unsafe fn copy_user_bytes(destination: *mut u8, source: *const u8, length: usize) -> bool {
    if length == 0 {
        return true;
    }
    unsafe { ginkgo_x86_copy_user(destination, source, length) == 0 }
}

extern "C" {
    fn ginkgo_x86_copy_user(destination: *mut u8, source: *const u8, length: usize) -> u64;
    fn ginkgo_x86_syscall_entry();
    fn ginkgo_x86_enter_user(context: *mut UserContext) -> u64;
    fn ginkgo_x86_exception_fail_stop();
    fn ginkgo_x86_exception_divide_error();
    fn ginkgo_x86_exception_debug();
    fn ginkgo_x86_exception_breakpoint();
    fn ginkgo_x86_exception_overflow();
    fn ginkgo_x86_exception_bound_range();
    fn ginkgo_x86_exception_invalid_opcode();
    fn ginkgo_x86_exception_device_not_available();
    fn ginkgo_x86_exception_invalid_tss();
    fn ginkgo_x86_exception_segment_not_present();
    fn ginkgo_x86_exception_stack_segment();
    fn ginkgo_x86_exception_general_protection();
    fn ginkgo_x86_exception_page_fault();
    fn ginkgo_x86_exception_x87_floating_point();
    fn ginkgo_x86_exception_alignment_check();
    fn ginkgo_x86_exception_simd_floating_point();
    fn ginkgo_x86_exception_virtualization();
    fn ginkgo_x86_exception_control_protection();
    fn ginkgo_x86_exception_hypervisor_injection();
    fn ginkgo_x86_exception_vmm_communication();
    fn ginkgo_x86_exception_security();
    fn ginkgo_x86_timer_interrupt();
    fn ginkgo_x86_xhci_interrupt();
    fn ginkgo_x86_spurious_interrupt();
}

/// Assembly's final guard against a dispatcher attempting an unsafe user IRET.
#[no_mangle]
extern "C" fn ginkgo_x86_validate_user_context(context: *const UserContext) -> u64 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: The entry assembly passes its live, naturally aligned frame.
    u64::from(unsafe { &*context }.validate().is_ok())
}

global_asm!(
    r#"
    .text
    .global ginkgo_x86_enter_user
    .global ginkgo_x86_copy_user
    .global ginkgo_x86_syscall_entry
    .global ginkgo_x86_exception_fail_stop
    .global ginkgo_x86_exception_divide_error
    .global ginkgo_x86_exception_debug
    .global ginkgo_x86_exception_breakpoint
    .global ginkgo_x86_exception_overflow
    .global ginkgo_x86_exception_bound_range
    .global ginkgo_x86_exception_invalid_opcode
    .global ginkgo_x86_exception_device_not_available
    .global ginkgo_x86_exception_invalid_tss
    .global ginkgo_x86_exception_segment_not_present
    .global ginkgo_x86_exception_stack_segment
    .global ginkgo_x86_exception_general_protection
    .global ginkgo_x86_exception_page_fault
    .global ginkgo_x86_exception_x87_floating_point
    .global ginkgo_x86_exception_alignment_check
    .global ginkgo_x86_exception_simd_floating_point
    .global ginkgo_x86_exception_virtualization
    .global ginkgo_x86_exception_control_protection
    .global ginkgo_x86_exception_hypervisor_injection
    .global ginkgo_x86_exception_vmm_communication
    .global ginkgo_x86_exception_security
    .global ginkgo_x86_timer_interrupt
    .global ginkgo_x86_xhci_interrupt
    .global ginkgo_x86_spurious_interrupt

// Fault-contained copy used after page-table validation. The page-fault handler
// redirects to the local failure label and clears AC before any Rust resumes.
ginkgo_x86_copy_user:
    leaq .Lginkgo_user_copy_fault(%rip), %rax
    movq %rax, %gs:{state_user_copy_fixup}
    cmpq $0, %gs:{state_smap_enabled}
    je .Lginkgo_user_copy_access
    stac
.Lginkgo_user_copy_access:
    movq %rdx, %rcx
    cld
    rep movsb
    cmpq $0, %gs:{state_smap_enabled}
    je .Lginkgo_user_copy_success
    clac
.Lginkgo_user_copy_success:
    movq $0, %gs:{state_user_copy_fixup}
    xorl %eax, %eax
    retq
.Lginkgo_user_copy_fault:
    movl $1, %eax
    retq

// Unsupported vectors, NMI, #DF, and #MC use this through IDT-selected stacks.
// This path is safe in every SWAPGS state: it never reads memory or GS.
ginkgo_x86_exception_fail_stop:
.Lginkgo_fail_stop:
    cli
.Lginkgo_halted:
    hlt
    jmp .Lginkgo_halted

// A local-APIC spurious interrupt has no in-service bit and requires no EOI.
// It touches neither GS nor interrupted register state and is valid from CPL0/3.
ginkgo_x86_spurious_interrupt:
    iretq

// The xHCI MSI may interrupt CPL0 idle or CPL3. RIP-relative globals avoid GS,
// whose active base differs across privilege levels. Preserve the sole scratch
// register, publish a coalescing byte, acknowledge the APIC, and return directly.
ginkgo_x86_xhci_interrupt:
    pushq %rax
    movb $1, GINKGO_XHCI_INTERRUPT_PENDING(%rip)
    movq GINKGO_EXTERNAL_INTERRUPT_EOI(%rip), %rax
    testq %rax, %rax
    jz .Lginkgo_fail_stop
    movl $0, (%rax)
    popq %rax
    iretq

// The timer is the only external interrupt that drives scheduler preemption. It
// either wakes idle_until_interrupt at CPL0 or preempts an active user at CPL3.
ginkgo_x86_timer_interrupt:
    pushq $0
    pushq ${preemption_vector}
    testb $3, {normalized_exception_cs}(%rsp)
    jnz .Lginkgo_timer_from_user

    // CPL0 entry retains kernel GS. Preserve the only scratch register, issue
    // EOI, discard the two software-normalization words, and return to the CLI
    // immediately following idle_until_interrupt's HLT. IRET restores RFLAGS.
    pushq %rax
    movq %gs:{state_interrupt_eoi}, %rax
    testq %rax, %rax
    jz .Lginkgo_fail_stop
    movl $0, (%rax)
    popq %rax
    addq $16, %rsp
    iretq

.Lginkgo_timer_from_user:
    swapgs
    cmpq $0, %gs:{state_smap_enabled}
    je .Lginkgo_timer_ac_clear
    clac
.Lginkgo_timer_ac_clear:
    cmpq $0, %gs:{state_active_context}
    je .Lginkgo_fail_stop

    // Save GPRs in exact UserContext field order at the new stack top.
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    cld
    movq %gs:{state_active_context}, %rdi
    movq %rsp, %rsi
    movq ${context_gpr_qwords}, %rcx
    rep movsq

    // RDI now points at UserContext.rip. The CPL transition guarantees RSP/SS.
    movq {exception_rip}(%rsp), %rax
    movq %rax, 0(%rdi)
    movq {exception_rsp}(%rsp), %rax
    movq %rax, 8(%rdi)
    movq {exception_rflags}(%rsp), %rax
    movq %rax, 16(%rdi)

    movq %gs:{state_active_context}, %rax
    cmpq $0, %gs:{state_xsave_enabled}
    je .Lginkgo_timer_fxsave_user
    movl %gs:{state_xsave_mask_low}, %eax
    movl %gs:{state_xsave_mask_high}, %edx
    movq %gs:{state_active_context}, %rcx
    xsave64 {ctx_fx_state}(%rcx)
    xrstor64 %gs:{state_kernel_fx}
    jmp .Lginkgo_timer_fx_ready
.Lginkgo_timer_fxsave_user:
    fxsave64 {ctx_fx_state}(%rax)
    fxrstor64 %gs:{state_kernel_fx}
.Lginkgo_timer_fx_ready:

    // All user registers are captured, so RAX is scratch for the MMIO EOI.
    movq %gs:{state_interrupt_eoi}, %rax
    testq %rax, %rax
    jz .Lginkgo_fail_stop
    movl $0, (%rax)

    movq ${preempted_action}, %rax
    jmp .Lginkgo_restore_kernel

// No-error-code exceptions synthesize zero before pushing their vector.
ginkgo_x86_exception_divide_error:
    pushq $0
    pushq ${divide_error_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_debug:
    pushq $0
    pushq ${debug_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_breakpoint:
    pushq $0
    pushq ${breakpoint_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_overflow:
    pushq $0
    pushq ${overflow_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_bound_range:
    pushq $0
    pushq ${bound_range_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_invalid_opcode:
    pushq $0
    pushq ${invalid_opcode_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_device_not_available:
    pushq $0
    pushq ${device_not_available_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_x87_floating_point:
    pushq $0
    pushq ${x87_floating_point_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_simd_floating_point:
    pushq $0
    pushq ${simd_floating_point_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_virtualization:
    pushq $0
    pushq ${virtualization_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_hypervisor_injection:
    pushq $0
    pushq ${hypervisor_injection_vector}
    jmp .Lginkgo_exception_common

// Error-code exceptions already have the error word at the hardware stack top.
ginkgo_x86_exception_invalid_tss:
    pushq ${invalid_tss_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_segment_not_present:
    pushq ${segment_not_present_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_stack_segment:
    pushq ${stack_segment_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_general_protection:
    pushq ${general_protection_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_page_fault:
    pushq ${page_fault_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_alignment_check:
    pushq ${alignment_check_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_control_protection:
    pushq ${control_protection_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_vmm_communication:
    pushq ${vmm_communication_vector}
    jmp .Lginkgo_exception_common

ginkgo_x86_exception_security:
    pushq ${security_exception_vector}

.Lginkgo_exception_common:
    // Kernel page faults are recoverable only while the explicit user-copy
    // fixup is armed. All other kernel faults fail stop.
    testb $3, {normalized_exception_cs}(%rsp)
    jnz .Lginkgo_exception_from_user
    cmpq ${page_fault_vector}, 0(%rsp)
    jne .Lginkgo_fail_stop
    cmpq $0, %gs:{state_user_copy_fixup}
    je .Lginkgo_fail_stop
    movq %gs:{state_user_copy_fixup}, %rax
    movq $0, %gs:{state_user_copy_fixup}
    movq %rax, {kernel_exception_rip}(%rsp)
    cmpq $0, %gs:{state_smap_enabled}
    je .Lginkgo_user_copy_fault_return
    clac
.Lginkgo_user_copy_fault_return:
    addq $16, %rsp
    iretq

.Lginkgo_exception_from_user:
    swapgs
    cmpq $0, %gs:{state_smap_enabled}
    je .Lginkgo_exception_ac_clear
    clac
.Lginkgo_exception_ac_clear:
    cmpq $0, %gs:{state_active_context}
    je .Lginkgo_fail_stop

    // Save GPRs in exact UserContext field order at the new stack top.
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    cld
    movq %gs:{state_active_context}, %rdi
    movq %rsp, %rsi
    movq ${context_gpr_qwords}, %rcx
    rep movsq

    // REP leaves RDI at UserContext.rip. Complete the control-state fields from
    // the privilege-transition frame; user RSP/SS exist because saved CS was RPL3.
    movq {exception_rip}(%rsp), %rax
    movq %rax, 0(%rdi)
    movq {exception_rsp}(%rsp), %rax
    movq %rax, 8(%rdi)
    movq {exception_rflags}(%rsp), %rax
    movq %rax, 16(%rdi)

    movq {exception_vector}(%rsp), %r8
    cmpq ${device_not_available_vector}, %r8
    jne .Lginkgo_fx_fault_ready
    clts
.Lginkgo_fx_fault_ready:
    movq %gs:{state_active_context}, %rax
    cmpq $0, %gs:{state_xsave_enabled}
    je .Lginkgo_exception_fxsave_user
    movl %gs:{state_xsave_mask_low}, %eax
    movl %gs:{state_xsave_mask_high}, %edx
    movq %gs:{state_active_context}, %rcx
    xsave64 {ctx_fx_state}(%rcx)
    xrstor64 %gs:{state_kernel_fx}
    jmp .Lginkgo_exception_fx_ready
.Lginkgo_exception_fxsave_user:
    fxsave64 {ctx_fx_state}(%rax)
    fxrstor64 %gs:{state_kernel_fx}
.Lginkgo_exception_fx_ready:

    movq {exception_error_code}(%rsp), %r9
    movq %r8, %gs:{state_fault_vector}
    movq %r9, %gs:{state_fault_error_code}
    movq $0, %gs:{state_fault_address}
    cmpq ${page_fault_vector}, %r8
    jne .Lginkgo_fault_record_ready
    movq %cr2, %rax
    movq %rax, %gs:{state_fault_address}

.Lginkgo_fault_record_ready:
    // Publish valid last, then abandon the TSS stack and return to enter_user's
    // suspended scheduler continuation with kernel GS still active.
    movq $1, %gs:{state_fault_valid}
    movq ${fault_action}, %rax
    jmp .Lginkgo_restore_kernel

// u64 ginkgo_x86_enter_user(UserContext *context)
// Save every kernel callee-saved GPR on the scheduler's stack. The saved RSP is
// the continuation used by a later YieldToKernel/ExitToKernel syscall.
ginkgo_x86_enter_user:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %gs:{state_kernel_rsp}
    movq %rdi, %gs:{state_active_context}
    movq $0, %gs:{state_fault_valid}

    // Rust validates before this call, then this final assembly-side check makes
    // first entry obey the same safe-IRET rule as syscall resumption.
    subq $8, %rsp
    callq ginkgo_x86_validate_user_context
    addq $8, %rsp
    testq %rax, %rax
    jz .Lginkgo_first_entry_invalid

    movq %gs:{state_active_context}, %rdx
    jmp .Lginkgo_restore_user

.Lginkgo_first_entry_invalid:
    movq ${exit_action}, %rax
    jmp .Lginkgo_restore_kernel

// LSTAR target. SYSCALL leaves the untrusted user RSP active, so the first
// instructions swap in kernel GS, save that RSP without dereferencing it, and
// replace it with the protected per-CPU stack. No push/call occurs beforehand.
ginkgo_x86_syscall_entry:
    swapgs
    movq %rsp, %gs:{state_user_rsp}
    movq %gs:{state_syscall_stack_top}, %rsp
    subq ${context_size}, %rsp

    movq %rax, {ctx_rax}(%rsp)
    movq %rbx, {ctx_rbx}(%rsp)
    movq %rcx, {ctx_rcx}(%rsp)
    movq %rdx, {ctx_rdx}(%rsp)
    movq %rsi, {ctx_rsi}(%rsp)
    movq %rdi, {ctx_rdi}(%rsp)
    movq %rbp, {ctx_rbp}(%rsp)
    movq %r8, {ctx_r8}(%rsp)
    movq %r9, {ctx_r9}(%rsp)
    movq %r10, {ctx_r10}(%rsp)
    movq %r11, {ctx_r11}(%rsp)
    movq %r12, {ctx_r12}(%rsp)
    movq %r13, {ctx_r13}(%rsp)
    movq %r14, {ctx_r14}(%rsp)
    movq %r15, {ctx_r15}(%rsp)
    movq %rcx, {ctx_rip}(%rsp)
    movq %r11, {ctx_rflags}(%rsp)
    movq %gs:{state_user_rsp}, %rax
    movq %rax, {ctx_rsp}(%rsp)
    cmpq $0, %gs:{state_xsave_enabled}
    je .Lginkgo_syscall_fxsave_user
    movl %gs:{state_xsave_mask_low}, %eax
    movl %gs:{state_xsave_mask_high}, %edx
    xsave64 {ctx_fx_state}(%rsp)
    xrstor64 %gs:{state_kernel_fx}
    jmp .Lginkgo_syscall_fx_ready
.Lginkgo_syscall_fxsave_user:
    fxsave64 {ctx_fx_state}(%rsp)
    fxrstor64 %gs:{state_kernel_fx}
.Lginkgo_syscall_fx_ready:

    cld
    movq %rsp, %rdi
    callq *%gs:{state_dispatcher}
    testq %rax, %rax
    jnz .Lginkgo_return_kernel

    movq %rsp, %rdi
    callq ginkgo_x86_validate_user_context
    testq %rax, %rax
    jnz .Lginkgo_resume_syscall

    movq ${exit_action}, %rax
    jmp .Lginkgo_return_kernel

.Lginkgo_resume_syscall:
    movq %rsp, %rdx

// RDX points at the validated frame. IRETQ, unlike SYSRETQ, preserves arbitrary
// interrupted RCX/R11 values. FXSAVE state is consumed before the IRET frame
// overwrites the top 40 bytes of a syscall-stack-resident temporary context.
.Lginkgo_restore_user:
    cmpq $0, %gs:{state_xsave_enabled}
    je .Lginkgo_restore_user_fxsave
    movq %rdx, %r8
    movl %gs:{state_xsave_mask_low}, %eax
    movl %gs:{state_xsave_mask_high}, %edx
    xsave64 %gs:{state_kernel_fx}
    xrstor64 {ctx_fx_state}(%r8)
    movq %r8, %rdx
    jmp .Lginkgo_restore_user_fx_ready
.Lginkgo_restore_user_fxsave:
    fxsave64 %gs:{state_kernel_fx}
    fxrstor64 {ctx_fx_state}(%rdx)
.Lginkgo_restore_user_fx_ready:

    // Build a trusted CPL3 hardware frame at the protected syscall stack top.
    movq %gs:{state_syscall_stack_top}, %rsp
    pushq ${user_data_selector}
    pushq {ctx_rsp}(%rdx)
    pushq {ctx_rflags}(%rdx)
    pushq ${user_code_selector}
    pushq {ctx_rip}(%rdx)

    // RDX remains the frame pointer until the final load. No memory access may
    // follow its restoration.
    movq {ctx_rax}(%rdx), %rax
    movq {ctx_rbx}(%rdx), %rbx
    movq {ctx_rcx}(%rdx), %rcx
    movq {ctx_rsi}(%rdx), %rsi
    movq {ctx_rdi}(%rdx), %rdi
    movq {ctx_rbp}(%rdx), %rbp
    movq {ctx_r8}(%rdx), %r8
    movq {ctx_r9}(%rdx), %r9
    movq {ctx_r10}(%rdx), %r10
    movq {ctx_r11}(%rdx), %r11
    movq {ctx_r12}(%rdx), %r12
    movq {ctx_r13}(%rdx), %r13
    movq {ctx_r14}(%rdx), %r14
    movq {ctx_r15}(%rdx), %r15
    movq {ctx_rdx}(%rdx), %rdx
    swapgs
    iretq

// Keep the latest user frame in scheduler-owned storage, then restore the
// exact kernel continuation and its callee-saved register set. Kernel GS stays
// active because this path does not return to userspace.
.Lginkgo_return_kernel:
    movq %rax, %r8
    movq %gs:{state_active_context}, %rdi
    movq %rsp, %rsi
    movq ${context_qwords}, %rcx
    cld
    rep movsq
    movq %r8, %rax

.Lginkgo_restore_kernel:
    movq $0, %gs:{state_active_context}
    movq %gs:{state_kernel_rsp}, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
"#,
    state_kernel_fx = const STATE_KERNEL_FX,
    state_syscall_stack_top = const STATE_SYSCALL_STACK_TOP,
    state_kernel_rsp = const STATE_KERNEL_RSP,
    state_user_rsp = const STATE_USER_RSP,
    state_dispatcher = const STATE_DISPATCHER,
    state_active_context = const STATE_ACTIVE_CONTEXT,
    state_fault_valid = const STATE_FAULT_VALID,
    state_fault_vector = const STATE_FAULT_VECTOR,
    state_fault_error_code = const STATE_FAULT_ERROR_CODE,
    state_fault_address = const STATE_FAULT_ADDRESS,
    state_interrupt_eoi = const STATE_INTERRUPT_EOI,
    state_user_copy_fixup = const STATE_USER_COPY_FIXUP,
    state_smap_enabled = const STATE_SMAP_ENABLED,
    state_xsave_enabled = const STATE_XSAVE_ENABLED,
    state_xsave_mask_low = const STATE_XSAVE_MASK_LOW,
    state_xsave_mask_high = const STATE_XSAVE_MASK_HIGH,
    preemption_vector = const PREEMPTION_VECTOR,
    divide_error_vector = const DIVIDE_ERROR_VECTOR,
    debug_vector = const DEBUG_VECTOR,
    breakpoint_vector = const BREAKPOINT_VECTOR,
    overflow_vector = const OVERFLOW_VECTOR,
    bound_range_vector = const BOUND_RANGE_VECTOR,
    invalid_opcode_vector = const INVALID_OPCODE_VECTOR,
    device_not_available_vector = const DEVICE_NOT_AVAILABLE_VECTOR,
    invalid_tss_vector = const INVALID_TSS_VECTOR,
    segment_not_present_vector = const SEGMENT_NOT_PRESENT_VECTOR,
    stack_segment_vector = const STACK_SEGMENT_VECTOR,
    general_protection_vector = const GENERAL_PROTECTION_VECTOR,
    page_fault_vector = const PAGE_FAULT_VECTOR,
    x87_floating_point_vector = const X87_FLOATING_POINT_VECTOR,
    alignment_check_vector = const ALIGNMENT_CHECK_VECTOR,
    simd_floating_point_vector = const SIMD_FLOATING_POINT_VECTOR,
    virtualization_vector = const VIRTUALIZATION_VECTOR,
    control_protection_vector = const CONTROL_PROTECTION_VECTOR,
    hypervisor_injection_vector = const HYPERVISOR_INJECTION_VECTOR,
    vmm_communication_vector = const VMM_COMMUNICATION_VECTOR,
    security_exception_vector = const SECURITY_EXCEPTION_VECTOR,
    normalized_exception_cs = const NORMALIZED_EXCEPTION_CS_OFFSET,
    kernel_exception_rip = const KERNEL_EXCEPTION_RIP_OFFSET,
    exception_vector = const EXCEPTION_VECTOR_OFFSET,
    exception_error_code = const EXCEPTION_ERROR_CODE_OFFSET,
    exception_rip = const EXCEPTION_RIP_OFFSET,
    exception_rflags = const EXCEPTION_RFLAGS_OFFSET,
    exception_rsp = const EXCEPTION_RSP_OFFSET,
    context_gpr_qwords = const USER_CONTEXT_GPR_QWORDS,
    context_size = const size_of::<UserContext>(),
    context_qwords = const USER_CONTEXT_QWORDS,
    exit_action = const DispatchAction::ExitToKernel as u64,
    fault_action = const KERNEL_EXIT_FAULT,
    preempted_action = const KERNEL_EXIT_PREEMPTED,
    user_data_selector = const USER_DATA_SELECTOR,
    user_code_selector = const USER_CODE_SELECTOR,
    ctx_rax = const offset_of!(UserContext, rax),
    ctx_rbx = const offset_of!(UserContext, rbx),
    ctx_rcx = const offset_of!(UserContext, rcx),
    ctx_rdx = const offset_of!(UserContext, rdx),
    ctx_rsi = const offset_of!(UserContext, rsi),
    ctx_rdi = const offset_of!(UserContext, rdi),
    ctx_rbp = const offset_of!(UserContext, rbp),
    ctx_r8 = const offset_of!(UserContext, r8),
    ctx_r9 = const offset_of!(UserContext, r9),
    ctx_r10 = const offset_of!(UserContext, r10),
    ctx_r11 = const offset_of!(UserContext, r11),
    ctx_r12 = const offset_of!(UserContext, r12),
    ctx_r13 = const offset_of!(UserContext, r13),
    ctx_r14 = const offset_of!(UserContext, r14),
    ctx_r15 = const offset_of!(UserContext, r15),
    ctx_rip = const offset_of!(UserContext, rip),
    ctx_rsp = const offset_of!(UserContext, rsp),
    ctx_rflags = const offset_of!(UserContext, rflags),
    ctx_fx_state = const offset_of!(UserContext, fx_state),
    options(att_syntax),
);

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_syscall_and_sysret_rules() {
        assert!(star_selector_layout_is_valid(STAR_VALUE));
        assert_eq!(KERNEL_CODE_SELECTOR, 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR, 0x10);
        assert_eq!(USER_DATA_SELECTOR, 0x1b);
        assert_eq!(USER_CODE_SELECTOR, 0x23);
        assert_eq!(TSS_SELECTOR, 0x28);

        let syscall_cs = ((STAR_VALUE >> 32) as u16) & !3;
        let sysret_base = ((STAR_VALUE >> 48) as u16) & !3;
        assert_eq!(syscall_cs, KERNEL_CODE_SELECTOR);
        assert_eq!(syscall_cs + 8, KERNEL_DATA_SELECTOR);
        assert_eq!((sysret_base + 8) | 3, USER_DATA_SELECTOR);
        assert_eq!((sysret_base + 16) | 3, USER_CODE_SELECTOR);
    }

    #[test]
    fn first_entry_context_is_iret_safe_and_interruptible() {
        let context = UserContext::new(0x4000_1000, 0x7fff_ffff_f000);
        assert_eq!(context.rflags, USER_RFLAGS_DEFAULT);
        assert_eq!(context.validate(), Ok(()));
        assert!(star_selector_layout_is_valid(STAR_VALUE));
    }

    #[test]
    fn extended_capabilities_gate_no_execute_requests() {
        let absent = CpuCapabilities::from_cpuid(0x8000_0000, u32::MAX, 0, 0, 0, 0, 0);
        assert_eq!(
            absent,
            CpuCapabilities {
                syscall_sysret: false,
                no_execute: false,
                fxsave_sse: false,
                smap: false,
                xsave: false,
                avx: false,
                physical_address_bits: DEFAULT_PHYSICAL_ADDRESS_BITS,
                linear_address_bits: FOUR_LEVEL_LINEAR_ADDRESS_BITS,
            }
        );

        let syscall_only = CpuCapabilities::from_cpuid(
            EXTENDED_FEATURES_LEAF,
            CPUID_SYSCALL_SYSRET,
            7,
            0,
            CPUID_FPU | CPUID_FXSR | CPUID_SSE | CPUID_SSE2,
            0,
            0,
        );
        assert!(syscall_only.syscall_sysret);
        assert!(!syscall_only.no_execute);
        assert_eq!(
            validate_no_execute_requirement(true, syscall_only),
            Err(NoExecuteError::Unsupported)
        );
        assert_eq!(validate_no_execute_requirement(false, syscall_only), Ok(()));

        let complete = CpuCapabilities::from_cpuid(
            EXTENDED_FEATURES_LEAF,
            CPUID_SYSCALL_SYSRET | CPUID_NO_EXECUTE,
            7,
            CPUID_XSAVE | CPUID_AVX,
            CPUID_FPU | CPUID_FXSR | CPUID_SSE | CPUID_SSE2,
            CPUID_SMAP,
            0,
        );
        assert!(complete.syscall_sysret);
        assert!(complete.no_execute);
        assert!(complete.fxsave_sse);
        assert!(complete.smap);
        assert!(complete.xsave);
        assert!(complete.avx);
        let missing_sse2 = CpuCapabilities::from_cpuid(
            EXTENDED_FEATURES_LEAF,
            CPUID_SYSCALL_SYSRET | CPUID_NO_EXECUTE,
            7,
            0,
            CPUID_FPU | CPUID_FXSR | CPUID_SSE,
            0,
            0,
        );
        assert!(!missing_sse2.fxsave_sse);
        assert_eq!(validate_no_execute_requirement(true, complete), Ok(()));
        assert_eq!(
            EFER_SYSTEM_CALL_EXTENSIONS | EFER_NO_EXECUTE_ENABLE,
            (1 << 0) | (1 << 11)
        );
    }

    #[test]
    fn cpuid_address_widths_are_validated_and_preserved() {
        let widths =
            CpuCapabilities::from_cpuid(ADDRESS_WIDTHS_LEAF, 0, 0, 0, 0, 0, 52 | (57 << 8));
        assert_eq!(widths.physical_address_bits, 52);
        assert_eq!(widths.linear_address_bits, 57);

        let malformed =
            CpuCapabilities::from_cpuid(ADDRESS_WIDTHS_LEAF, 0, 0, 0, 0, 0, 53 | (47 << 8));
        assert_eq!(
            malformed.physical_address_bits,
            DEFAULT_PHYSICAL_ADDRESS_BITS
        );
        assert_eq!(
            malformed.linear_address_bits,
            FOUR_LEVEL_LINEAR_ADDRESS_BITS
        );
    }

    #[test]
    fn capture_dispatcher_yields_and_scheduler_sets_rax_result() {
        let mut context = UserContext::new(0x4000_1000, 0x7fff_ffff_f000);
        context.rax = 0x1234;
        assert_eq!(
            capture_syscall_and_yield(&mut context),
            DispatchAction::YieldToKernel
        );
        assert_eq!(context.rax, 0x1234);

        context.set_syscall_return(0xfeed_face);
        assert_eq!(context.rax, 0xfeed_face);
        assert_eq!(context.validate(), Ok(()));
    }

    #[test]
    fn context_layout_matches_assembly_contract() {
        assert_eq!(size_of::<FxState>(), FXSAVE_SIZE);
        assert_eq!(core::mem::align_of::<FxState>(), 64);
        assert_eq!(size_of::<UserContext>(), 4288);
        assert_eq!(core::mem::align_of::<UserContext>(), 64);
        assert_eq!(offset_of!(UserContext, rax), 0);
        assert_eq!(offset_of!(UserContext, rdx), 3 * 8);
        assert_eq!(offset_of!(UserContext, r15), 14 * 8);
        assert_eq!(offset_of!(UserContext, rip), 15 * 8);
        assert_eq!(offset_of!(UserContext, rsp), 16 * 8);
        assert_eq!(offset_of!(UserContext, rflags), 17 * 8);
        assert_eq!(offset_of!(UserContext, fx_state), 24 * 8);
        assert_eq!(USER_CONTEXT_QWORDS, 536);

        assert_eq!(STATE_SYSCALL_STACK_TOP, 0);
        assert_eq!(STATE_KERNEL_RSP, 8);
        assert_eq!(STATE_USER_RSP, 16);
        assert_eq!(STATE_DISPATCHER, 24);
        assert_eq!(STATE_ACTIVE_CONTEXT, 32);
        assert_eq!(STATE_FAULT_VALID, 40);
        assert_eq!(STATE_FAULT_VECTOR, 48);
        assert_eq!(STATE_FAULT_ERROR_CODE, 56);
        assert_eq!(STATE_FAULT_ADDRESS, 64);
        assert_eq!(STATE_INTERRUPT_EOI, 72);
        assert_eq!(STATE_USER_COPY_FIXUP, 80);
        assert_eq!(STATE_SMAP_ENABLED, 88);
        assert_eq!(STATE_XSAVE_ENABLED, 96);
        assert_eq!(STATE_XSAVE_MASK_LOW, 104);
        assert_eq!(STATE_XSAVE_MASK_HIGH, 112);
        assert_eq!(STATE_KERNEL_FX, 128);
        assert_eq!(STATE_KERNEL_FX % 64, 0);
    }

    #[test]
    fn initial_fxsave_image_is_valid_and_rejects_reserved_mxcsr_bits() {
        assert_eq!(
            fxsave_cr0(CR0_EMULATION | CR0_TASK_SWITCHED),
            CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR
        );
        let cr4 = fxsave_cr4(0, true);
        assert_ne!(cr4 & CR4_OSXSAVE, 0);
        assert_eq!(
            cr4 & (CR4_OSFXSR | CR4_OSXMMEXCPT),
            CR4_OSFXSR | CR4_OSXMMEXCPT
        );

        let state = FxState::initial();
        assert_eq!(state.control_word(), INITIAL_FCW);
        assert_eq!(state.mxcsr(), INITIAL_MXCSR);
        assert!(state.is_valid());

        let mut context = UserContext::new(0x4000_1000, 0x7fff_ffff_f000);
        context.fx_state.bytes[FXSAVE_MXCSR_OFFSET + 3] = 0x80;
        assert_eq!(
            context.validate(),
            Err(ContextValidationError::InvalidFloatingPointState)
        );
    }

    #[test]
    fn idt_gate_layout_and_required_vectors_are_correct() {
        assert_eq!(size_of::<IdtEntry>(), 16);
        assert_eq!(offset_of!(IdtEntry, offset_low), 0);
        assert_eq!(offset_of!(IdtEntry, selector), 2);
        assert_eq!(offset_of!(IdtEntry, ist), 4);
        assert_eq!(offset_of!(IdtEntry, type_attributes), 5);
        assert_eq!(offset_of!(IdtEntry, offset_middle), 6);
        assert_eq!(offset_of!(IdtEntry, offset_high), 8);
        assert_eq!(offset_of!(IdtEntry, reserved), 12);
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
        assert_eq!(size_of::<InterruptDescriptorTable>(), 16 * IDT_ENTRY_COUNT);

        let fail_stop = 0xffff_8000_0000_1000;
        let contained = 0xffff_8000_0000_2000;
        let timer = 0xffff_8000_0000_3000;
        let xhci = 0xffff_8000_0000_4000;
        let spurious = 0xffff_8000_0000_5000;
        let gates = [
            ExceptionGate::ring0(DIVIDE_ERROR_VECTOR, contained),
            ExceptionGate::ring0(DEBUG_VECTOR, contained),
            ExceptionGate::fail_stop(NMI_VECTOR, fail_stop, NMI_IST_INDEX),
            ExceptionGate::ring3(BREAKPOINT_VECTOR, contained),
            ExceptionGate::ring3(OVERFLOW_VECTOR, contained),
            ExceptionGate::ring0(BOUND_RANGE_VECTOR, contained),
            ExceptionGate::ring0(INVALID_OPCODE_VECTOR, contained),
            ExceptionGate::ring0(DEVICE_NOT_AVAILABLE_VECTOR, contained),
            ExceptionGate::fail_stop(DOUBLE_FAULT_VECTOR, fail_stop, DOUBLE_FAULT_IST_INDEX),
            ExceptionGate::ring0(INVALID_TSS_VECTOR, contained),
            ExceptionGate::ring0(SEGMENT_NOT_PRESENT_VECTOR, contained),
            ExceptionGate::ring0(STACK_SEGMENT_VECTOR, contained),
            ExceptionGate::ring0(GENERAL_PROTECTION_VECTOR, contained),
            ExceptionGate::ring0(PAGE_FAULT_VECTOR, contained),
            ExceptionGate::ring0(X87_FLOATING_POINT_VECTOR, contained),
            ExceptionGate::ring0(ALIGNMENT_CHECK_VECTOR, contained),
            ExceptionGate::fail_stop(MACHINE_CHECK_VECTOR, fail_stop, MACHINE_CHECK_IST_INDEX),
            ExceptionGate::ring0(SIMD_FLOATING_POINT_VECTOR, contained),
            ExceptionGate::ring0(VIRTUALIZATION_VECTOR, contained),
            ExceptionGate::ring0(CONTROL_PROTECTION_VECTOR, contained),
            ExceptionGate::ring0(HYPERVISOR_INJECTION_VECTOR, contained),
            ExceptionGate::ring0(VMM_COMMUNICATION_VECTOR, contained),
            ExceptionGate::ring0(SECURITY_EXCEPTION_VECTOR, contained),
            ExceptionGate::ring0(usize::from(PREEMPTION_VECTOR), timer),
            ExceptionGate::ring0(usize::from(XHCI_VECTOR), xhci),
            ExceptionGate::ring0(usize::from(SPURIOUS_VECTOR), spurious),
        ];
        let idt = exception_idt(fail_stop, &gates);

        for vector in [
            DIVIDE_ERROR_VECTOR,
            DEBUG_VECTOR,
            BOUND_RANGE_VECTOR,
            INVALID_OPCODE_VECTOR,
            DEVICE_NOT_AVAILABLE_VECTOR,
            INVALID_TSS_VECTOR,
            SEGMENT_NOT_PRESENT_VECTOR,
            STACK_SEGMENT_VECTOR,
            GENERAL_PROTECTION_VECTOR,
            PAGE_FAULT_VECTOR,
            X87_FLOATING_POINT_VECTOR,
            ALIGNMENT_CHECK_VECTOR,
            SIMD_FLOATING_POINT_VECTOR,
            VIRTUALIZATION_VECTOR,
            CONTROL_PROTECTION_VECTOR,
            HYPERVISOR_INJECTION_VECTOR,
            VMM_COMMUNICATION_VECTOR,
            SECURITY_EXCEPTION_VECTOR,
        ] {
            let gate = idt.entries[vector];
            assert_eq!(gate.handler(), contained);
            assert_eq!(gate.ist, 0);
            assert_eq!(gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
        }
        for vector in [BREAKPOINT_VECTOR, OVERFLOW_VECTOR] {
            assert_eq!(idt.entries[vector].handler(), contained);
            assert_eq!(
                idt.entries[vector].type_attributes,
                INTERRUPT_GATE_PRESENT_RING3
            );
        }
        for (vector, ist) in [
            (DOUBLE_FAULT_VECTOR, DOUBLE_FAULT_IST_INDEX),
            (NMI_VECTOR, NMI_IST_INDEX),
            (MACHINE_CHECK_VECTOR, MACHINE_CHECK_IST_INDEX),
        ] {
            let gate = idt.entries[vector];
            assert_eq!(gate.handler(), fail_stop);
            assert_eq!(gate.ist, ist);
            assert_eq!(gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
        }
        for gate in &idt.entries {
            assert_eq!(gate.selector, KERNEL_CODE_SELECTOR);
            assert_eq!(gate.reserved, 0);
        }
        assert_eq!(idt.entries[9].handler(), fail_stop);
        let timer_gate = idt.entries[usize::from(PREEMPTION_VECTOR)];
        assert_eq!(timer_gate.handler(), timer);
        assert_eq!(timer_gate.ist, 0);
        assert_eq!(timer_gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
        let xhci_gate = idt.entries[usize::from(XHCI_VECTOR)];
        assert_eq!(xhci_gate.handler(), xhci);
        assert_eq!(xhci_gate.ist, 0);
        assert_eq!(xhci_gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
        let spurious_gate = idt.entries[usize::from(SPURIOUS_VECTOR)];
        assert_eq!(spurious_gate.handler(), spurious);
        assert_eq!(spurious_gate.ist, 0);
        assert_eq!(spurious_gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
    }

    #[test]
    fn normalized_exception_frame_offsets_match_hardware_order() {
        for vector in [
            DIVIDE_ERROR_VECTOR,
            DEBUG_VECTOR,
            BREAKPOINT_VECTOR,
            OVERFLOW_VECTOR,
            BOUND_RANGE_VECTOR,
            INVALID_OPCODE_VECTOR,
            DEVICE_NOT_AVAILABLE_VECTOR,
            X87_FLOATING_POINT_VECTOR,
            SIMD_FLOATING_POINT_VECTOR,
            VIRTUALIZATION_VECTOR,
            HYPERVISOR_INJECTION_VECTOR,
        ] {
            assert!(!exception_pushes_error_code(vector));
        }
        for vector in [
            DOUBLE_FAULT_VECTOR,
            INVALID_TSS_VECTOR,
            SEGMENT_NOT_PRESENT_VECTOR,
            STACK_SEGMENT_VECTOR,
            GENERAL_PROTECTION_VECTOR,
            PAGE_FAULT_VECTOR,
            ALIGNMENT_CHECK_VECTOR,
            CONTROL_PROTECTION_VECTOR,
            VMM_COMMUNICATION_VECTOR,
            SECURITY_EXCEPTION_VECTOR,
        ] {
            assert!(exception_pushes_error_code(vector));
        }

        assert_eq!(USER_CONTEXT_GPR_QWORDS, 15);
        assert_eq!(EXCEPTION_SAVED_GPRS_SIZE, 120);
        assert_eq!(size_of::<NormalizedExceptionFrame>(), 56);
        assert_eq!(offset_of!(NormalizedExceptionFrame, vector), 0);
        assert_eq!(offset_of!(NormalizedExceptionFrame, error_code), 8);
        assert_eq!(offset_of!(NormalizedExceptionFrame, rip), 16);
        assert_eq!(offset_of!(NormalizedExceptionFrame, cs), 24);
        assert_eq!(offset_of!(NormalizedExceptionFrame, rflags), 32);
        assert_eq!(offset_of!(NormalizedExceptionFrame, rsp), 40);
        assert_eq!(offset_of!(NormalizedExceptionFrame, ss), 48);

        assert_eq!(NORMALIZED_EXCEPTION_CS_OFFSET, 24);
        assert_eq!(EXCEPTION_VECTOR_OFFSET, 120);
        assert_eq!(EXCEPTION_ERROR_CODE_OFFSET, 128);
        assert_eq!(EXCEPTION_RIP_OFFSET, 136);
        assert_eq!(EXCEPTION_RFLAGS_OFFSET, 152);
        assert_eq!(EXCEPTION_RSP_OFFSET, 160);
    }

    #[test]
    fn user_fault_frame_exposes_cr2_only_for_page_faults() {
        let page_fault = user_fault_frame(PAGE_FAULT_VECTOR as u64, 0b101, 0x1234_5000);
        assert_eq!(
            KernelExit::Fault(page_fault),
            KernelExit::Fault(UserFaultFrame {
                vector: 14,
                error_code: 0b101,
                fault_address: Some(0x1234_5000),
            })
        );

        let invalid_opcode = user_fault_frame(INVALID_OPCODE_VECTOR as u64, 0, 0xdead_beef);
        assert_eq!(invalid_opcode.fault_address, None);
    }

    #[test]
    fn tss_layout_and_descriptor_are_architectural() {
        assert_eq!(size_of::<TaskStateSegment>(), 104);
        assert_eq!(offset_of!(TaskStateSegment, rsp), 4);
        assert_eq!(offset_of!(TaskStateSegment, ist), 36);
        assert_eq!(offset_of!(TaskStateSegment, io_map_base), 102);

        let stacks = PrivilegeStackTops {
            rsp0: 0xffff_8000_0001_0000,
            double_fault: 0xffff_8000_0002_0000,
            nmi: 0xffff_8000_0003_0000,
            machine_check: 0xffff_8000_0004_0000,
            syscall: 0xffff_8000_0005_0000,
        };
        let mut tss = TaskStateSegment::new();
        unsafe { tss.set_stack_tops(stacks) };
        let tss_ptr = &raw const tss;
        assert_eq!(
            unsafe { ptr::addr_of!((*tss_ptr).rsp[0]).read_unaligned() },
            stacks.rsp0
        );
        assert_eq!(
            unsafe { ptr::addr_of!((*tss_ptr).ist[0]).read_unaligned() },
            stacks.double_fault
        );
        assert_eq!(
            unsafe { ptr::addr_of!((*tss_ptr).ist[1]).read_unaligned() },
            stacks.nmi
        );
        assert_eq!(
            unsafe { ptr::addr_of!((*tss_ptr).ist[2]).read_unaligned() },
            stacks.machine_check
        );

        let base = 0xffff_8000_1234_5000;
        let (low, high) = tss_descriptor(base, 103);
        assert_eq!(low & 0xffff, 103);
        assert_eq!((low >> 40) & 0xf, 0x9);
        assert_eq!((low >> 47) & 1, 1);
        assert_eq!(high, base >> 32);
    }

    #[test]
    fn idle_entry_requires_interrupts_disabled() {
        assert!(!rflags_interrupts_enabled(0));
        assert!(!rflags_interrupts_enabled(1 << 1));
        assert!(rflags_interrupts_enabled(RFLAGS_INTERRUPT_ENABLE));
        assert!(rflags_interrupts_enabled(u64::MAX));
        assert_eq!(RFLAGS_INTERRUPT_ENABLE, 0x200);

        #[cfg(not(target_os = "none"))]
        assert!(matches!(
            idle_until_interrupt(),
            Err(IdleError::InterruptsEnabled | IdleError::UnsupportedEnvironment)
        ));
    }

    #[test]
    fn canonical_address_checks_cover_both_halves_and_hole() {
        assert!(is_canonical_address(0));
        assert!(is_canonical_address(0x0000_7fff_ffff_ffff));
        assert!(is_canonical_address(0xffff_8000_0000_0000));
        assert!(is_canonical_address(u64::MAX));
        assert!(!is_canonical_address(0x0000_8000_0000_0000));
        assert!(!is_canonical_address(0xffff_7fff_ffff_ffff));

        assert!(is_user_canonical_address(0x0000_7fff_ffff_ffff));
        assert!(!is_user_canonical_address(0xffff_8000_0000_0000));
    }

    #[test]
    fn context_validation_rejects_unsafe_iret_state_and_requires_if() {
        let valid = UserContext::new(0x4000_1000, 0x7fff_ffff_f000);
        assert_eq!(valid.validate(), Ok(()));

        let mut context = valid;
        context.rip = 0xffff_8000_0000_0000;
        assert_eq!(
            context.validate(),
            Err(ContextValidationError::InvalidInstructionPointer)
        );

        context = valid;
        context.rsp = 0x0000_8000_0000_0000;
        assert_eq!(
            context.validate(),
            Err(ContextValidationError::InvalidStackPointer)
        );

        assert_eq!(USER_RFLAGS_REQUIRED, 0x202);
        assert_eq!(USER_RFLAGS_DEFAULT, 0x202);
        assert_eq!(USER_RFLAGS_ALLOWED, 0x1_0ad7);

        context = valid;
        context.rflags |= RFLAGS_RESUME;
        assert_eq!(context.validate(), Ok(()));

        context = valid;
        context.rflags &= !(1 << 9);
        assert_eq!(
            context.validate(),
            Err(ContextValidationError::InvalidFlags)
        );

        for forbidden in [1 << 8, 1 << 10, 3 << 12, 1 << 14, 1 << 17, 1 << 18] {
            context = valid;
            context.rflags |= forbidden;
            assert_eq!(
                context.validate(),
                Err(ContextValidationError::InvalidFlags)
            );
        }

        context = valid;
        context.rflags = 0;
        assert_eq!(
            context.validate(),
            Err(ContextValidationError::InvalidFlags)
        );
    }

    #[test]
    fn xhci_pending_flag_coalesces_and_is_consumed() {
        GINKGO_XHCI_INTERRUPT_PENDING.store(0, Ordering::Relaxed);
        assert!(!take_xhci_interrupt_pending());
        GINKGO_XHCI_INTERRUPT_PENDING.store(1, Ordering::Release);
        GINKGO_XHCI_INTERRUPT_PENDING.store(1, Ordering::Release);
        assert!(take_xhci_interrupt_pending());
        assert!(!take_xhci_interrupt_pending());
    }

    #[test]
    fn external_interrupt_state_accepts_disabled_or_canonical_eoi_only() {
        assert_eq!(ExternalInterruptState::DISABLED.validate(), Ok(()));
        assert_eq!(
            ExternalInterruptState::local_apic(0xffff_f700_0000_00b0).validate(),
            Ok(())
        );
        for invalid in [
            0x0000_8000_0000_00b0,
            0x0000_0000_fee0_00b0,
            0xffff_f700_0000_00b1,
        ] {
            assert_eq!(
                ExternalInterruptState::local_apic(invalid).validate(),
                Err(InitializeError::InvalidInterruptEoiAddress)
            );
        }
    }

    #[test]
    fn stack_tops_must_be_canonical_aligned_and_distinct() {
        let valid = PrivilegeStackTops {
            rsp0: 0xffff_8000_0001_0000,
            double_fault: 0xffff_8000_0002_0000,
            nmi: 0xffff_8000_0003_0000,
            machine_check: 0xffff_8000_0004_0000,
            syscall: 0xffff_8000_0005_0000,
        };
        assert_eq!(valid.validate(), Ok(()));

        assert_eq!(
            PrivilegeStackTops {
                syscall: valid.rsp0,
                ..valid
            }
            .validate(),
            Err(InitializeError::SharedStackTop)
        );
        assert_eq!(
            PrivilegeStackTops {
                syscall: valid.syscall + 1,
                ..valid
            }
            .validate(),
            Err(InitializeError::InvalidStackTop)
        );
    }
}
