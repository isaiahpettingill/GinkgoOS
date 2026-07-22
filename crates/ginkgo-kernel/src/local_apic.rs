//! Bootstrap-processor local APIC timer and TSC-backed monotonic clock.
//!
//! This module deliberately implements only the xAPIC MMIO mode needed by the
//! first single-core preemptive scheduler. It discovers the bootstrap local APIC
//! through `IA32_APIC_BASE`, maps one uncached supervisor page into the shared
//! kernel half, calibrates the APIC one-shot timer against Limine's TSC frequency,
//! and exposes its xAPIC ID plus the EOI register address required by external
//! interrupt entries in [`crate::arch`]. x2APIC, I/O APIC routing, SMP, and
//! general kernel-mode interrupt dispatch are outside this layer.
//!
//! The mapping must be created before any [`crate::paging::address_space::AddressSpace`]
//! is created. User address spaces copy the kernel P4 half at construction time,
//! and the timer interrupt must be able to acknowledge the APIC under every user
//! CR3.

use core::{arch::asm, ptr::NonNull};

use crate::{
    memory::UsableFrameAllocator,
    paging::{ActivePageTable, MapError},
};
#[cfg(target_os = "none")]
use crate::{
    memory::{PhysAddr, PhysFrame, VirtAddr, VirtPage},
    paging::PageTableFlags,
};

#[cfg(target_os = "none")]
const IA32_APIC_BASE: u32 = 0x1b;
#[cfg(any(target_os = "none", test))]
const APIC_BASE_ENABLE: u64 = 1 << 11;
#[cfg(any(target_os = "none", test))]
const APIC_BASE_X2APIC: u64 = 1 << 10;
#[cfg(any(target_os = "none", test))]
const APIC_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_os = "none")]
const CPUID_APIC: u32 = 1 << 9;

#[cfg(any(target_os = "none", test))]
const APIC_ID: usize = 0x020;
#[cfg(any(target_os = "none", test))]
const APIC_TPR: usize = 0x080;
const APIC_EOI: usize = 0x0b0;
#[cfg(any(target_os = "none", test))]
const APIC_SVR: usize = 0x0f0;
const APIC_LVT_TIMER: usize = 0x320;
const APIC_INITIAL_COUNT: usize = 0x380;
#[cfg(any(target_os = "none", test))]
const APIC_CURRENT_COUNT: usize = 0x390;
#[cfg(any(target_os = "none", test))]
const APIC_DIVIDE_CONFIGURATION: usize = 0x3e0;

#[cfg(any(target_os = "none", test))]
const APIC_SOFTWARE_ENABLE: u32 = 1 << 8;
const APIC_LVT_MASKED: u32 = 1 << 16;
#[cfg(any(target_os = "none", test))]
const APIC_DIVIDE_BY_16: u32 = 0b0011;
#[cfg(any(target_os = "none", test))]
const CALIBRATION_NANOSECONDS: u64 = 10_000_000;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// IDT vector programmed into the local APIC one-shot timer.
pub const PREEMPTION_VECTOR: u8 = 0x40;
/// IDT vector selected by the local APIC spurious-interrupt register.
pub const SPURIOUS_VECTOR: u8 = 0xff;

// These are intentionally in the kernel canonical half and use separate P4
// regions from the executable's conventional ffffffff... mapping. Selection is
// dynamic because Limine is free to choose its HHDM address on every boot.
#[cfg(target_os = "none")]
const MMIO_MAPPING_CANDIDATES: [u64; 8] = [
    0xffff_f700_0000_0000,
    0xffff_f600_0000_0000,
    0xffff_f500_0000_0000,
    0xffff_f400_0000_0000,
    0xffff_f300_0000_0000,
    0xffff_f200_0000_0000,
    0xffff_f100_0000_0000,
    0xffff_f000_0000_0000,
];

/// Failure while discovering, mapping, calibrating, or programming the BSP APIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalApicError {
    /// Privileged APIC initialization is unavailable in a hosted build.
    UnsupportedEnvironment,
    /// Limine did not provide a usable nonzero TSC frequency.
    InvalidTscFrequency,
    /// CPUID reports no local APIC.
    LocalApicUnsupported,
    /// The boot environment left x2APIC enabled; this implementation needs xAPIC MMIO.
    X2ApicUnsupported,
    /// `IA32_APIC_BASE` did not contain an enabled, aligned physical base.
    InvalidPhysicalBase,
    /// None of the reserved kernel virtual candidates was unused.
    NoVirtualAddress,
    /// The page-table operation needed to map the APIC failed.
    Paging(MapError),
    /// The APIC timer did not decrement during calibration.
    TimerNotCounting,
    /// A requested one-shot duration cannot be represented by the 32-bit counter.
    DurationOutOfRange,
}

impl From<MapError> for LocalApicError {
    fn from(value: MapError) -> Self {
        Self::Paging(value)
    }
}

/// A single-core monotonic clock derived from the architectural timestamp counter.
///
/// `frequency` is the best-effort counter frequency reported by Limine. The
/// returned nanoseconds are relative to construction and do not represent wall
/// clock time. TSC wraparound is not handled because a 64-bit TSC cannot wrap in
/// a practical kernel lifetime at contemporary frequencies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonotonicClock {
    frequency: u64,
    epoch: u64,
}

impl MonotonicClock {
    /// Constructs a clock whose zero is the current ordered TSC reading.
    pub fn new(frequency: u64) -> Result<Self, LocalApicError> {
        if frequency == 0 {
            return Err(LocalApicError::InvalidTscFrequency);
        }
        Ok(Self {
            frequency,
            epoch: ordered_tsc(),
        })
    }

    /// Returns the timestamp-counter frequency in hertz.
    pub const fn frequency(&self) -> u64 {
        self.frequency
    }

    /// Returns elapsed monotonic nanoseconds since this clock was constructed.
    pub fn now_ns(&self) -> u64 {
        nanoseconds_for_ticks(ordered_tsc().saturating_sub(self.epoch), self.frequency)
    }
}

/// Mapped and calibrated bootstrap local APIC one-shot timer.
///
/// All methods assume single-CPU ownership. The interrupt entry acknowledges the
/// timer by writing to [`Self::eoi_register_address`], so this value and its page
/// mapping must remain valid for the lifetime of the initialized CPU privilege
/// state.
pub struct LocalApicTimer {
    mmio_base: NonNull<u8>,
    ticks_per_second: u64,
    clock: MonotonicClock,
    id: u8,
}

impl LocalApicTimer {
    /// Maps, configures, and calibrates the bootstrap processor's xAPIC timer.
    ///
    /// The caller must run at CPL0 with interrupts disabled, while `page_table`
    /// is active and exclusively mutable. Limine base revision 5 or newer must
    /// have left the legacy PIC and I/O APIC routes masked. This must run before
    /// constructing any user address space so the new kernel mapping is inherited
    /// by every process CR3.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        allocator: &mut UsableFrameAllocator<'_>,
        tsc_frequency: u64,
    ) -> Result<Self, LocalApicError> {
        if tsc_frequency == 0 {
            return Err(LocalApicError::InvalidTscFrequency);
        }

        #[cfg(not(target_os = "none"))]
        {
            let _ = (page_table, allocator);
            return Err(LocalApicError::UnsupportedEnvironment);
        }

        #[cfg(target_os = "none")]
        {
            if core::arch::x86_64::__cpuid(1).edx & CPUID_APIC == 0 {
                return Err(LocalApicError::LocalApicUnsupported);
            }
            let apic_base = unsafe { read_msr(IA32_APIC_BASE) };
            if apic_base & APIC_BASE_X2APIC != 0 {
                return Err(LocalApicError::X2ApicUnsupported);
            }
            if apic_base & APIC_BASE_ENABLE == 0 {
                return Err(LocalApicError::InvalidPhysicalBase);
            }
            let physical_base = apic_base & APIC_BASE_ADDRESS_MASK;
            let physical = PhysAddr::try_new(physical_base)
                .map_err(|_| LocalApicError::InvalidPhysicalBase)?;
            let frame = PhysFrame::from_start_address(physical)
                .map_err(|_| LocalApicError::InvalidPhysicalBase)?;

            let virtual_base = MMIO_MAPPING_CANDIDATES
                .into_iter()
                .find_map(|candidate| {
                    let address = VirtAddr::try_new(candidate).ok()?;
                    page_table
                        .translate_addr(address)
                        .is_none()
                        .then_some(address)
                })
                .ok_or(LocalApicError::NoVirtualAddress)?;
            let page = VirtPage::from_start_address(virtual_base)
                .map_err(|_| LocalApicError::NoVirtualAddress)?;
            let flags = PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::WRITE_THROUGH
                | PageTableFlags::NO_CACHE;
            unsafe { page_table.map_4k(page, frame, flags, allocator)? };

            let mmio_base = NonNull::new(virtual_base.as_mut_ptr::<u8>())
                .ok_or(LocalApicError::NoVirtualAddress)?;
            let clock = MonotonicClock::new(tsc_frequency)?;
            let mut timer = Self {
                mmio_base,
                ticks_per_second: 0,
                clock,
                id: 0,
            };
            timer.id = (unsafe { timer.read(APIC_ID) } >> 24) as u8;
            unsafe { timer.configure_and_calibrate(tsc_frequency)? };
            Ok(timer)
        }
    }

    /// Returns the eight-bit xAPIC ID used as an MSI destination.
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Returns the calibrated post-divider APIC timer frequency in hertz.
    pub const fn ticks_per_second(&self) -> u64 {
        self.ticks_per_second
    }

    /// Returns the monotonic clock used to calibrate this timer.
    pub const fn clock(&self) -> &MonotonicClock {
        &self.clock
    }

    /// Returns the mapped virtual address of the write-only local APIC EOI register.
    pub fn eoi_register_address(&self) -> u64 {
        self.mmio_base.as_ptr() as usize as u64 + APIC_EOI as u64
    }

    /// Arms a one-shot preemption interrupt after `duration_ns` nanoseconds.
    ///
    /// Kernel code must keep IF clear. The interrupt becomes deliverable only
    /// after the architecture return path restores a validated ring-3 RFLAGS.
    pub fn arm_one_shot(&mut self, duration_ns: u64) -> Result<(), LocalApicError> {
        let count = timer_count_for_duration(self.ticks_per_second, duration_ns)?;
        unsafe {
            self.write(APIC_LVT_TIMER, u32::from(PREEMPTION_VECTOR));
            self.write(APIC_INITIAL_COUNT, count);
        }
        Ok(())
    }

    /// Masks and clears the one-shot counter.
    ///
    /// This cannot retract a timer interrupt that has already reached the local
    /// APIC IRR. Such an interrupt is safe and may cause one short later quantum.
    pub fn disarm(&mut self) {
        unsafe {
            self.write(
                APIC_LVT_TIMER,
                APIC_LVT_MASKED | u32::from(PREEMPTION_VECTOR),
            );
            self.write(APIC_INITIAL_COUNT, 0);
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn configure_and_calibrate(&mut self, tsc_frequency: u64) -> Result<(), LocalApicError> {
        unsafe {
            self.write(APIC_TPR, 0);
            let svr = self.read(APIC_SVR);
            self.write(
                APIC_SVR,
                (svr & !0xff) | APIC_SOFTWARE_ENABLE | u32::from(SPURIOUS_VECTOR),
            );
            self.write(APIC_DIVIDE_CONFIGURATION, APIC_DIVIDE_BY_16);
            self.write(
                APIC_LVT_TIMER,
                APIC_LVT_MASKED | u32::from(PREEMPTION_VECTOR),
            );
            self.write(APIC_INITIAL_COUNT, u32::MAX);
        }

        let start = ordered_tsc();
        let calibration_ticks =
            ticks_for_nanoseconds(tsc_frequency, CALIBRATION_NANOSECONDS).max(1);
        while ordered_tsc().saturating_sub(start) < calibration_ticks {
            core::hint::spin_loop();
        }
        let end = ordered_tsc();
        let current = unsafe { self.read(APIC_CURRENT_COUNT) };
        self.disarm();

        let elapsed_apic = u64::from(u32::MAX - current);
        let elapsed_tsc = end.saturating_sub(start);
        self.ticks_per_second = calibrated_frequency(elapsed_apic, elapsed_tsc, tsc_frequency)
            .ok_or(LocalApicError::TimerNotCounting)?;
        Ok(())
    }

    #[cfg(target_os = "none")]
    unsafe fn read(&self, offset: usize) -> u32 {
        unsafe {
            self.mmio_base
                .as_ptr()
                .add(offset)
                .cast::<u32>()
                .read_volatile()
        }
    }

    unsafe fn write(&mut self, offset: usize, value: u32) {
        unsafe {
            self.mmio_base
                .as_ptr()
                .add(offset)
                .cast::<u32>()
                .write_volatile(value)
        }
    }
}

#[cfg(any(target_os = "none", test))]
fn ticks_for_nanoseconds(frequency: u64, nanoseconds: u64) -> u64 {
    ((u128::from(frequency) * u128::from(nanoseconds)) / u128::from(NANOSECONDS_PER_SECOND))
        .min(u128::from(u64::MAX)) as u64
}

fn nanoseconds_for_ticks(ticks: u64, frequency: u64) -> u64 {
    if frequency == 0 {
        return u64::MAX;
    }
    ((u128::from(ticks) * u128::from(NANOSECONDS_PER_SECOND)) / u128::from(frequency))
        .min(u128::from(u64::MAX)) as u64
}

fn timer_count_for_duration(
    ticks_per_second: u64,
    duration_ns: u64,
) -> Result<u32, LocalApicError> {
    if ticks_per_second == 0 || duration_ns == 0 {
        return Err(LocalApicError::DurationOutOfRange);
    }
    let numerator = u128::from(ticks_per_second) * u128::from(duration_ns);
    let count = numerator.div_ceil(u128::from(NANOSECONDS_PER_SECOND));
    if count == 0 || count > u128::from(u32::MAX) {
        return Err(LocalApicError::DurationOutOfRange);
    }
    Ok(count as u32)
}

#[cfg(any(target_os = "none", test))]
fn calibrated_frequency(elapsed_apic: u64, elapsed_tsc: u64, tsc_frequency: u64) -> Option<u64> {
    if elapsed_apic == 0 || elapsed_tsc == 0 || tsc_frequency == 0 {
        return None;
    }
    let frequency =
        (u128::from(elapsed_apic) * u128::from(tsc_frequency)) / u128::from(elapsed_tsc);
    u64::try_from(frequency)
        .ok()
        .filter(|frequency| *frequency != 0)
}

fn ordered_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let low: u32;
        let high: u32;
        unsafe {
            asm!(
                "lfence",
                "rdtsc",
                out("eax") low,
                out("edx") high,
                options(nostack),
            );
        }
        u64::from(low) | (u64::from(high) << 32)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[cfg(target_os = "none")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architectural_registers_and_vectors_are_non_overlapping() {
        assert_eq!(PREEMPTION_VECTOR, 0x40);
        assert_eq!(SPURIOUS_VECTOR, 0xff);
        assert!(PREEMPTION_VECTOR >= 32);
        assert_ne!(PREEMPTION_VECTOR, SPURIOUS_VECTOR);
        assert_eq!(APIC_ID, 0x20);
        assert_eq!(APIC_TPR, 0x80);
        assert_eq!(APIC_EOI, 0xb0);
        assert_eq!(APIC_SVR, 0xf0);
        assert_eq!(APIC_LVT_TIMER, 0x320);
        assert_eq!(APIC_INITIAL_COUNT, 0x380);
        assert_eq!(APIC_CURRENT_COUNT, 0x390);
        assert_eq!(APIC_DIVIDE_CONFIGURATION, 0x3e0);
        assert_eq!(APIC_SOFTWARE_ENABLE, 1 << 8);
        assert_eq!(APIC_DIVIDE_BY_16, 0b0011);
        assert_eq!(CALIBRATION_NANOSECONDS, 10_000_000);
    }

    #[test]
    fn clock_conversion_uses_wide_arithmetic_and_saturates() {
        assert_eq!(ticks_for_nanoseconds(1_000_000_000, 1), 1);
        assert_eq!(ticks_for_nanoseconds(3_000_000_000, 10_000_000), 30_000_000);
        assert_eq!(nanoseconds_for_ticks(30_000_000, 3_000_000_000), 10_000_000);
        assert_eq!(nanoseconds_for_ticks(u64::MAX, 1), u64::MAX);
        assert_eq!(nanoseconds_for_ticks(1, 0), u64::MAX);
    }

    #[test]
    fn one_shot_count_rounds_up_and_rejects_unrepresentable_requests() {
        assert_eq!(timer_count_for_duration(100, 1), Ok(1));
        assert_eq!(
            timer_count_for_duration(100_000_000, 10_000_000),
            Ok(1_000_000)
        );
        assert_eq!(
            timer_count_for_duration(0, 10_000_000),
            Err(LocalApicError::DurationOutOfRange)
        );
        assert_eq!(
            timer_count_for_duration(100, 0),
            Err(LocalApicError::DurationOutOfRange)
        );
        assert_eq!(
            timer_count_for_duration(u64::MAX, u64::MAX),
            Err(LocalApicError::DurationOutOfRange)
        );
    }

    #[test]
    fn calibration_scales_apic_ticks_by_measured_tsc_interval() {
        assert_eq!(
            calibrated_frequency(1_000_000, 30_000_000, 3_000_000_000),
            Some(100_000_000)
        );
        assert_eq!(calibrated_frequency(0, 1, 1), None);
        assert_eq!(calibrated_frequency(1, 0, 1), None);
        assert_eq!(calibrated_frequency(1, 1, 0), None);
    }

    #[test]
    fn monotonic_clock_rejects_zero_frequency() {
        assert_eq!(
            MonotonicClock::new(0),
            Err(LocalApicError::InvalidTscFrequency)
        );
        let clock = MonotonicClock::new(1_000_000_000).unwrap();
        assert_eq!(clock.frequency(), 1_000_000_000);
        assert!(clock.now_ns() < u64::MAX);
    }

    #[test]
    fn apic_base_mask_preserves_the_architectural_page_address() {
        let value = 0x0000_0000_fee0_0000 | APIC_BASE_ENABLE;
        assert_eq!(value & APIC_BASE_ADDRESS_MASK, 0xfee0_0000);
        assert_eq!(value & APIC_BASE_ENABLE, APIC_BASE_ENABLE);
        assert_eq!(value & APIC_BASE_X2APIC, 0);
    }
}
