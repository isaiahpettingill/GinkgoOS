#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use ginkgo_userspace::{
    anonymous_map, debug_write, monotonic_time_ns, process_yield, thread_create, thread_exit,
    thread_join, thread_set_scheduling_class, thread_sleep_until, thread_wake, MapProtection,
    ThreadSchedulingClass, ThreadState, DEADLINE_INFINITE,
};

static STARTED: AtomicU64 = AtomicU64::new(0);
static FINISHED: AtomicU64 = AtomicU64::new(0);

const STACK_SIZE: u64 = 256 * 1024;
const TLS_SIZE: usize = 4096;

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(_arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> ! {
    let tls_one = map_tls(0x1111_2222_3333_4444);
    let tls_two = map_tls(0xaaaa_bbbb_cccc_dddd);
    let first = must(thread_create(
        worker as *const () as usize as u64,
        0,
        STACK_SIZE,
        tls_one,
    ));
    let second = must(thread_create(
        worker as *const () as usize as u64,
        1,
        STACK_SIZE,
        tls_two,
    ));
    must(thread_set_scheduling_class(
        second,
        ThreadSchedulingClass::Background,
    ));

    while STARTED.load(Ordering::Acquire) != 0b11 {
        must(process_yield());
    }
    must(thread_wake(first));
    must(thread_wake(second));

    let first_info = must(thread_join(first, DEADLINE_INFINITE));
    let second_info = must(thread_join(second, DEADLINE_INFINITE));
    if first_info.state != ThreadState::Exited as u32
        || second_info.state != ThreadState::Exited as u32
        || first_info.exit_code != 10
        || second_info.exit_code != 11
        || first_info.preemption_count == 0
        || second_info.preemption_count == 0
        || FINISHED.load(Ordering::Acquire) != 0b11
    {
        fail(b"ginkgo-thread-smoke: invalid join result\n");
    }
    let _ = debug_write(b"ginkgo-thread-smoke: PASS\n");
    ginkgo_runtime::exit(0)
}

fn map_tls(marker: u64) -> u64 {
    let mapping =
        must(unsafe { anonymous_map(TLS_SIZE, MapProtection::READ | MapProtection::WRITE) });
    unsafe { mapping.as_ptr().cast::<u64>().write(marker) };
    mapping.as_ptr() as usize as u64
}

extern "C" fn worker(index: u64) -> ! {
    let bit = 1u64 << index;
    let expected_tls = if index == 0 {
        0x1111_2222_3333_4444u64
    } else {
        0xaaaa_bbbb_cccc_ddddu64
    };
    let observed_tls: u64;
    unsafe {
        core::arch::asm!(
            "mov {value}, qword ptr fs:[0]",
            value = out(reg) observed_tls,
            options(nostack, preserves_flags),
        );
    }
    if observed_tls != expected_tls {
        fail(b"ginkgo-thread-smoke: TLS isolation failed\n");
    }
    STARTED.fetch_or(bit, Ordering::Release);
    for _ in 0..20_000_000 {
        core::hint::spin_loop();
    }
    unsafe {
        core::arch::asm!(
            "movq xmm15, {value}",
            value = in(reg) expected_tls,
            options(nostack, preserves_flags),
        );
    }

    let deadline = must(monotonic_time_ns()).saturating_add(50_000_000);
    must(thread_sleep_until(deadline as i64));
    for _ in 0..128 {
        must(process_yield());
    }
    let observed_after: u64;
    let observed_simd: u64;
    unsafe {
        core::arch::asm!(
            "mov {tls}, qword ptr fs:[0]",
            "movq {simd}, xmm15",
            tls = out(reg) observed_after,
            simd = out(reg) observed_simd,
            options(nostack, preserves_flags),
        );
    }
    if observed_after != expected_tls {
        fail(b"ginkgo-thread-smoke: TLS changed after preemption\n");
    }
    if observed_simd != expected_tls {
        fail(b"ginkgo-thread-smoke: SIMD isolation failed\n");
    }
    FINISHED.fetch_or(bit, Ordering::Release);
    let _ = thread_exit(10 + index as i32);
    loop {
        let _ = process_yield();
    }
}

fn must<T>(result: Result<T, ginkgo_userspace::Status>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => fail(b"ginkgo-thread-smoke: syscall failed\n"),
    }
}

fn fail(message: &[u8]) -> ! {
    let _ = debug_write(message);
    ginkgo_runtime::exit(1)
}
