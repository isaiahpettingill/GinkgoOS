#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use ginkgo_userspace::{
    anonymous_map, audio_write, channel_create, channel_read, channel_write, debug_write,
    filesystem_open, filesystem_sync, filesystem_write, handle_close, monotonic_time_ns,
    process_yield, storage_get_diagnostics, thread_create, thread_current, thread_exit,
    thread_get_scheduling_info,
    thread_join, thread_set_scheduling_class, thread_set_scheduling_class_with_authority,
    thread_sleep_until, thread_wake, FilesystemOpenFlags, Handle, MapProtection, Signals, Status,
    StorageDiagnostics, ThreadId, ThreadSchedulingClass, ThreadState, WaitItem, DEADLINE_INFINITE,
    FILESYSTEM_IO_MAX_BYTES,
};

static STARTED: AtomicU64 = AtomicU64::new(0);
static FINISHED: AtomicU64 = AtomicU64::new(0);

static WORKLOAD_START: AtomicU64 = AtomicU64::new(0);
static WORKLOAD_GATE: AtomicU64 = AtomicU64::new(0);
static WORKER_FAILURE: AtomicU64 = AtomicU64::new(0);
static RENDER_FRAMES: AtomicU64 = AtomicU64::new(0);
static RENDER_MISSES: AtomicU64 = AtomicU64::new(0);
static RENDER_MAX_LATE_NS: AtomicU64 = AtomicU64::new(0);
static AUDIO_PERIODS: AtomicU64 = AtomicU64::new(0);
static AUDIO_UNDERRUNS: AtomicU64 = AtomicU64::new(0);
static AUDIO_MISSES: AtomicU64 = AtomicU64::new(0);
static AUDIO_MAX_LATE_NS: AtomicU64 = AtomicU64::new(0);
static INPUT_EVENTS: AtomicU64 = AtomicU64::new(0);
static INPUT_MAX_LATENCY_NS: AtomicU64 = AtomicU64::new(0);
static BACKGROUND_BYTES: AtomicU64 = AtomicU64::new(0);
static HOG_STOP: AtomicU64 = AtomicU64::new(0);
static HOG_TICKS: AtomicU64 = AtomicU64::new(0);

static DONATION_LOW2: AtomicU64 = AtomicU64::new(0);
static DONATION_LOW1: AtomicU64 = AtomicU64::new(0);
static DONATION_MAIN: AtomicU64 = AtomicU64::new(0);
static DONATION_GATE: AtomicU64 = AtomicU64::new(0);
static DONATION_ACTIVE: AtomicU64 = AtomicU64::new(0);
static DONATION_OBSERVE: AtomicU64 = AtomicU64::new(0);
static DONATION_LOW1_JOINING: AtomicU64 = AtomicU64::new(0);
static DONATION_SEEN: AtomicU64 = AtomicU64::new(0);
static DONATION_DEMOTION_CHECK: AtomicU64 = AtomicU64::new(0);
static DONATION_OBSERVER_OK: AtomicU64 = AtomicU64::new(0);

const STACK_SIZE: u64 = 256 * 1024;
const TLS_SIZE: usize = 4096;
const FRAME_PERIOD_NS: u64 = 16_666_667;
const FRAME_COUNT: u64 = 180;
const AUDIO_PERIOD_NS: u64 = 10_000_000;
const AUDIO_PERIOD_COUNT: u64 = 300;
const AUDIO_CHUNK_BYTES: usize = 441 * 2 * 2;
const INPUT_PERIOD_NS: u64 = 20_000_000;
const INPUT_EVENT_COUNT: u64 = 100;
const FILE_BYTES: u64 = 1024 * 1024;
const FILE_CHUNK_BYTES: usize = FILESYSTEM_IO_MAX_BYTES;
const SILENT_AUDIO: [u8; AUDIO_CHUNK_BYTES] = [0; AUDIO_CHUNK_BYTES];
const FILE_CHUNK: [u8; FILE_CHUNK_BYTES] = [0x35; FILE_CHUNK_BYTES];


ginkgo_runtime::entry6!(process_main);

extern "C" fn process_main(
    arg0: u64,
    _arg1: u64,
    _arg2: u64,
    _arg3: u64,
    arg4: u64,
    _arg5: u64,
) -> ! {
    run_isolation_phase();

    if arg0 > u32::MAX as u64 || arg4 > u32::MAX as u64 {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL invalid launch handle\n");
    }
    let filesystem_root = Handle::from_raw(arg0 as u32);
    let scheduling_authority = Handle::from_raw(arg4 as u32);
    if !filesystem_root.is_valid() || !scheduling_authority.is_valid() {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL missing launch capability\n");
    }

    let main_thread = scheduler_must(
        thread_current(),
        b"ginkgo-scheduler-smoke: FAIL get current thread\n",
    );
    run_admission_checks(main_thread, scheduling_authority);
    let metrics = run_overload(filesystem_root, scheduling_authority);
    run_donation_checks(main_thread, scheduling_authority);

    let _ = debug_write(b"ginkgo-scheduler-smoke: donation PASS\n");
    let storage = scheduler_must(
        storage_get_diagnostics(),
        b"ginkgo-scheduler-smoke: FAIL storage diagnostics\n",
    );
    print_storage_metrics(storage);
    validate_storage_diagnostics(storage);
    print_metrics(metrics);
    let _ = debug_write(b"ginkgo-scheduler-smoke: PASS\n");
    let _ = debug_write(b"ginkgo-thread-smoke: PASS\n");
    ginkgo_runtime::exit(0)
}

fn run_isolation_phase() {
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
}

fn run_admission_checks(main_thread: ThreadId, authority: Handle) {
    for class in [
        ThreadSchedulingClass::Critical,
        ThreadSchedulingClass::Audio,
        ThreadSchedulingClass::Interactive,
    ] {
        if thread_set_scheduling_class(main_thread, class) != Err(Status::AccessDenied) {
            fail_scheduler(b"ginkgo-scheduler-smoke: FAIL privileged class admitted directly\n");
        }
    }

    scheduler_must(
        thread_set_scheduling_class_with_authority(
            main_thread,
            ThreadSchedulingClass::Interactive,
            authority,
        ),
        b"ginkgo-scheduler-smoke: FAIL delegated Interactive rejected\n",
    );
    scheduler_must(
        thread_set_scheduling_class_with_authority(
            main_thread,
            ThreadSchedulingClass::Audio,
            authority,
        ),
        b"ginkgo-scheduler-smoke: FAIL delegated Audio rejected\n",
    );
    scheduler_must(
        thread_set_scheduling_class(main_thread, ThreadSchedulingClass::Normal),
        b"ginkgo-scheduler-smoke: FAIL admission demotion rejected\n",
    );
    let info = scheduler_must(
        thread_get_scheduling_info(main_thread),
        b"ginkgo-scheduler-smoke: FAIL admission info unavailable\n",
    );
    if info.base_class != ThreadSchedulingClass::Normal as u32
        || info.effective_class != ThreadSchedulingClass::Normal as u32
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL admission left stale promotion\n");
    }

    let _ = debug_write(b"ginkgo-scheduler-smoke: admission PASS\n");
}

#[derive(Clone, Copy)]
struct Metrics {
    frames: u64,
    frame_misses: u64,
    frame_max_late_ns: u64,
    audio_periods: u64,
    audio_underruns: u64,
    audio_misses: u64,
    audio_max_late_ns: u64,
    input_events: u64,
    input_max_latency_ns: u64,
    background_bytes: u64,
    hog_ticks: u64,
}

fn run_overload(filesystem_root: Handle, authority: Handle) -> Metrics {
    let (input_sender, input_receiver) = scheduler_must(
        channel_create(),
        b"ginkgo-scheduler-smoke: FAIL input channel create\n",
    );
    let render = create_scheduler_thread(
        render_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL render thread create\n",
    );
    let audio = create_scheduler_thread(
        audio_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL audio thread create\n",
    );
    let input = create_scheduler_thread(
        input_worker,
        u64::from(input_receiver.raw()),
        b"ginkgo-scheduler-smoke: FAIL input thread create\n",
    );
    let hog_one = create_scheduler_thread(
        hog_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL first hog thread create\n",
    );
    let hog_two = create_scheduler_thread(
        hog_worker,
        1,
        b"ginkgo-scheduler-smoke: FAIL second hog thread create\n",
    );
    let background = create_scheduler_thread(
        background_worker,
        u64::from(filesystem_root.raw()),
        b"ginkgo-scheduler-smoke: FAIL background thread create\n",
    );

    scheduler_must(
        thread_set_scheduling_class_with_authority(
            render,
            ThreadSchedulingClass::Interactive,
            authority,
        ),
        b"ginkgo-scheduler-smoke: FAIL render delegation\n",
    );
    scheduler_must(
        thread_set_scheduling_class_with_authority(audio, ThreadSchedulingClass::Audio, authority),
        b"ginkgo-scheduler-smoke: FAIL audio delegation\n",
    );
    set_scheduler_class(input, ThreadSchedulingClass::Normal);
    set_scheduler_class(hog_one, ThreadSchedulingClass::Normal);
    set_scheduler_class(hog_two, ThreadSchedulingClass::Normal);
    set_scheduler_class(background, ThreadSchedulingClass::Background);

    let start = scheduler_must(
        monotonic_time_ns(),
        b"ginkgo-scheduler-smoke: FAIL workload clock\n",
    )
    .saturating_add(100_000_000);
    WORKLOAD_START.store(start, Ordering::Release);
    WORKLOAD_GATE.store(1, Ordering::Release);

    send_input_events(input_sender, start);

    join_scheduler_thread(render, 20, b"ginkgo-scheduler-smoke: FAIL render join\n");
    join_scheduler_thread(audio, 21, b"ginkgo-scheduler-smoke: FAIL audio join\n");
    join_scheduler_thread(input, 22, b"ginkgo-scheduler-smoke: FAIL input join\n");

    HOG_STOP.store(1, Ordering::Release);
    join_scheduler_thread(
        hog_one,
        23,
        b"ginkgo-scheduler-smoke: FAIL first hog join\n",
    );
    join_scheduler_thread(
        hog_two,
        24,
        b"ginkgo-scheduler-smoke: FAIL second hog join\n",
    );
    join_scheduler_thread(
        background,
        25,
        b"ginkgo-scheduler-smoke: FAIL background join\n",
    );

    scheduler_must(
        handle_close(input_sender),
        b"ginkgo-scheduler-smoke: FAIL input sender close\n",
    );
    scheduler_must(
        handle_close(input_receiver),
        b"ginkgo-scheduler-smoke: FAIL input receiver close\n",
    );

    if WORKER_FAILURE.load(Ordering::Acquire) != 0 {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL overload worker error\n");
    }

    let metrics = Metrics {
        frames: RENDER_FRAMES.load(Ordering::Acquire),
        frame_misses: RENDER_MISSES.load(Ordering::Acquire),
        frame_max_late_ns: RENDER_MAX_LATE_NS.load(Ordering::Acquire),
        audio_periods: AUDIO_PERIODS.load(Ordering::Acquire),
        audio_underruns: AUDIO_UNDERRUNS.load(Ordering::Acquire),
        audio_misses: AUDIO_MISSES.load(Ordering::Acquire),
        audio_max_late_ns: AUDIO_MAX_LATE_NS.load(Ordering::Acquire),
        input_events: INPUT_EVENTS.load(Ordering::Acquire),
        input_max_latency_ns: INPUT_MAX_LATENCY_NS.load(Ordering::Acquire),
        background_bytes: BACKGROUND_BYTES.load(Ordering::Acquire),
        hog_ticks: HOG_TICKS.load(Ordering::Acquire),
    };
    if metrics.frames != FRAME_COUNT
        || metrics.audio_periods < AUDIO_PERIOD_COUNT
        || metrics.input_events != INPUT_EVENT_COUNT
        || metrics.background_bytes < FILE_BYTES
        || metrics.hog_ticks == 0
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL structural workload result\n");
    }
    metrics
}

fn send_input_events(sender: Handle, start: u64) {
    for sequence in 0..INPUT_EVENT_COUNT {
        let deadline = start.saturating_add(sequence.saturating_mul(INPUT_PERIOD_NS));
        scheduler_must(
            thread_sleep_until(deadline as i64),
            b"ginkgo-scheduler-smoke: FAIL input send sleep\n",
        );
        loop {
            if WORKER_FAILURE.load(Ordering::Acquire) != 0 {
                fail_scheduler(b"ginkgo-scheduler-smoke: FAIL worker during input send\n");
            }
            let sent_at = scheduler_must(
                monotonic_time_ns(),
                b"ginkgo-scheduler-smoke: FAIL input send clock\n",
            );
            let mut message = [0u8; 16];
            message[..8].copy_from_slice(&sequence.to_le_bytes());
            message[8..].copy_from_slice(&sent_at.to_le_bytes());
            match channel_write(sender, &message, &[]) {
                Ok(()) => break,
                Err(Status::ShouldWait) => scheduler_must(
                    process_yield(),
                    b"ginkgo-scheduler-smoke: FAIL input send yield\n",
                ),
                Err(_) => fail_scheduler(b"ginkgo-scheduler-smoke: FAIL input channel write\n"),
            }
        }
    }
}

extern "C" fn render_worker(_argument: u64) -> ! {
    wait_for_workload_start();
    let start = WORKLOAD_START.load(Ordering::Acquire);
    let mut misses = 0u64;
    let mut maximum_lateness = 0u64;
    for frame in 1..=FRAME_COUNT {
        let deadline = start.saturating_add(frame.saturating_mul(FRAME_PERIOD_NS));
        worker_must(
            thread_sleep_until(deadline as i64),
            b"ginkgo-scheduler-smoke: FAIL render sleep\n",
            20,
        );
        let now = worker_must(
            monotonic_time_ns(),
            b"ginkgo-scheduler-smoke: FAIL render clock\n",
            20,
        );
        let lateness = now.saturating_sub(deadline);
        maximum_lateness = maximum_lateness.max(lateness);
        if lateness > FRAME_PERIOD_NS {
            misses = misses.saturating_add(1);
        }
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }
        RENDER_FRAMES.store(frame, Ordering::Release);
    }
    RENDER_MISSES.store(misses, Ordering::Release);
    RENDER_MAX_LATE_NS.store(maximum_lateness, Ordering::Release);
    exit_thread(20)
}

extern "C" fn audio_worker(_argument: u64) -> ! {
    wait_for_workload_start();
    let start = WORKLOAD_START.load(Ordering::Acquire);
    let mut underruns = 0u64;
    let mut misses = 0u64;
    let mut maximum_lateness = 0u64;
    for period in 1..=AUDIO_PERIOD_COUNT {
        let deadline = start.saturating_add(period.saturating_mul(AUDIO_PERIOD_NS));
        worker_must(
            thread_sleep_until(deadline as i64),
            b"ginkgo-scheduler-smoke: FAIL audio sleep\n",
            21,
        );
        let now = worker_must(
            monotonic_time_ns(),
            b"ginkgo-scheduler-smoke: FAIL audio clock\n",
            21,
        );
        let lateness = now.saturating_sub(deadline);
        maximum_lateness = maximum_lateness.max(lateness);
        if lateness > AUDIO_PERIOD_NS {
            misses = misses.saturating_add(1);
        }
        loop {
            match audio_write(&SILENT_AUDIO) {
                Ok(()) => break,
                Err(Status::ShouldWait) => {
                    underruns = underruns.saturating_add(1);
                    worker_must(
                        process_yield(),
                        b"ginkgo-scheduler-smoke: FAIL audio retry yield\n",
                        21,
                    );
                }
                Err(_) => worker_fail(b"ginkgo-scheduler-smoke: FAIL audio write\n", 21),
            }
        }
        AUDIO_PERIODS.store(period, Ordering::Release);
    }
    AUDIO_UNDERRUNS.store(underruns, Ordering::Release);
    AUDIO_MISSES.store(misses, Ordering::Release);
    AUDIO_MAX_LATE_NS.store(maximum_lateness, Ordering::Release);
    exit_thread(21)
}

extern "C" fn input_worker(argument: u64) -> ! {
    wait_for_workload_start();
    let receiver = Handle::from_raw(argument as u32);
    let mut maximum_latency = 0u64;
    for expected_sequence in 0..INPUT_EVENT_COUNT {
        let mut items = [WaitItem::new(receiver, Signals::READABLE)];
        let ready = worker_must(
            ginkgo_userspace::wait_many(&mut items, DEADLINE_INFINITE),
            b"ginkgo-scheduler-smoke: FAIL input wait_many\n",
            22,
        );
        if ready != 0 || !items[0].pending.contains(Signals::READABLE) {
            worker_fail(b"ginkgo-scheduler-smoke: FAIL input wake signal\n", 22);
        }
        let mut message = [0u8; 16];
        let info = worker_must(
            channel_read(receiver, &mut message, &mut []),
            b"ginkgo-scheduler-smoke: FAIL input channel read\n",
            22,
        );
        if info.byte_count != message.len() as u32 || info.handle_count != 0 {
            worker_fail(
                b"ginkgo-scheduler-smoke: FAIL input malformed message\n",
                22,
            );
        }
        let mut sequence_bytes = [0u8; 8];
        let mut timestamp_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&message[..8]);
        timestamp_bytes.copy_from_slice(&message[8..]);
        let sequence = u64::from_le_bytes(sequence_bytes);
        let sent_at = u64::from_le_bytes(timestamp_bytes);
        let dispatched_at = worker_must(
            monotonic_time_ns(),
            b"ginkgo-scheduler-smoke: FAIL input dispatch clock\n",
            22,
        );
        if sequence != expected_sequence || sent_at > dispatched_at {
            worker_fail(
                b"ginkgo-scheduler-smoke: FAIL input order or timestamp\n",
                22,
            );
        }
        maximum_latency = maximum_latency.max(dispatched_at - sent_at);
        INPUT_EVENTS.store(expected_sequence + 1, Ordering::Release);
    }
    INPUT_MAX_LATENCY_NS.store(maximum_latency, Ordering::Release);
    exit_thread(22)
}

extern "C" fn hog_worker(index: u64) -> ! {
    wait_for_workload_start();
    while HOG_STOP.load(Ordering::Acquire) == 0 {
        for _ in 0..4096 {
            core::hint::spin_loop();
        }
        HOG_TICKS.fetch_add(1, Ordering::Relaxed);
    }
    exit_thread(23 + index as i32)
}





extern "C" fn background_worker(argument: u64) -> ! {
    wait_for_workload_start();
    let root = Handle::from_raw(argument as u32);
    let flags =
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE;
    let file = loop {
        match filesystem_open(root, "ginkgo-scheduler-overload.bin", flags) {
            Ok(file) => break file,
            Err(Status::ShouldWait) => worker_must(
                process_yield(),
                b"ginkgo-scheduler-smoke: FAIL background open yield\n",
                25,
            ),
            Err(_) => worker_fail(b"ginkgo-scheduler-smoke: FAIL background open\n", 25),
        }
    };

    let mut offset = 0u64;
    while offset < FILE_BYTES {
        let remaining = (FILE_BYTES - offset) as usize;
        let amount = remaining.min(FILE_CHUNK.len());
        match filesystem_write(file, offset, &FILE_CHUNK[..amount]) {
            Ok(0) => worker_fail(b"ginkgo-scheduler-smoke: FAIL background zero write\n", 25),
            Ok(written) => {
                offset = offset.saturating_add(written as u64);
                BACKGROUND_BYTES.store(offset, Ordering::Release);
            }
            Err(Status::ShouldWait) => worker_must(
                process_yield(),
                b"ginkgo-scheduler-smoke: FAIL background write yield\n",
                25,
            ),
            Err(_) => worker_fail(b"ginkgo-scheduler-smoke: FAIL background write\n", 25),
        }
    }
    loop {
        match filesystem_sync(file) {
            Ok(()) => break,
            Err(Status::ShouldWait) => worker_must(
                process_yield(),
                b"ginkgo-scheduler-smoke: FAIL background sync yield\n",
                25,
            ),
            Err(_) => worker_fail(b"ginkgo-scheduler-smoke: FAIL background sync\n", 25),
        }
    }
    worker_must(
        handle_close(file),
        b"ginkgo-scheduler-smoke: FAIL background close\n",
        25,
    );
    exit_thread(25)
}

fn run_donation_checks(main_thread: ThreadId, authority: Handle) {
    DONATION_MAIN.store(main_thread.0, Ordering::Release);
    let low2 = create_scheduler_thread(
        donation_low2_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL low2 thread create\n",
    );
    DONATION_LOW2.store(low2.0, Ordering::Release);
    let low1 = create_scheduler_thread(
        donation_low1_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL low1 thread create\n",
    );
    DONATION_LOW1.store(low1.0, Ordering::Release);
    let observer = create_scheduler_thread(
        donation_observer_worker,
        0,
        b"ginkgo-scheduler-smoke: FAIL observer thread create\n",
    );

    set_scheduler_class(low2, ThreadSchedulingClass::Background);
    set_scheduler_class(low1, ThreadSchedulingClass::Background);
    scheduler_must(
        thread_set_scheduling_class_with_authority(
            observer,
            ThreadSchedulingClass::Audio,
            authority,
        ),
        b"ginkgo-scheduler-smoke: FAIL observer delegation\n",
    );
    DONATION_GATE.store(1, Ordering::Release);
    DONATION_ACTIVE.store(1, Ordering::Release);
    while DONATION_LOW1_JOINING.load(Ordering::Acquire) == 0 {
        scheduler_must(
            process_yield(),
            b"ginkgo-scheduler-smoke: FAIL low1 join wait yield\n",
        );
    }
    loop {
        let low1_info = scheduler_must(
            thread_get_scheduling_info(low1),
            b"ginkgo-scheduler-smoke: FAIL low1 blocked info\n",
        );
        if low1_info.state == ThreadState::Blocked as u32 {
            break;
        }
        scheduler_must(
            process_yield(),
            b"ginkgo-scheduler-smoke: FAIL low1 blocked wait yield\n",
        );
    }

    scheduler_must(
        thread_set_scheduling_class_with_authority(
            main_thread,
            ThreadSchedulingClass::Interactive,
            authority,
        ),
        b"ginkgo-scheduler-smoke: FAIL donation main delegation\n",
    );
    let timeout = scheduler_must(
        monotonic_time_ns(),
        b"ginkgo-scheduler-smoke: FAIL finite join clock\n",
    )
    .saturating_add(50_000_000);
    if thread_join(low1, timeout as i64) != Err(Status::TimedOut) {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL finite join did not time out\n");
    }
    let low1_unwound = scheduler_must(
        thread_get_scheduling_info(low1),
        b"ginkgo-scheduler-smoke: FAIL timeout low1 info\n",
    );
    let low2_unwound = scheduler_must(
        thread_get_scheduling_info(low2),
        b"ginkgo-scheduler-smoke: FAIL timeout low2 info\n",
    );
    if low1_unwound.base_class != ThreadSchedulingClass::Background as u32
        || low1_unwound.effective_class != ThreadSchedulingClass::Background as u32
        || low2_unwound.base_class != ThreadSchedulingClass::Background as u32
        || low2_unwound.effective_class != ThreadSchedulingClass::Background as u32
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL finite join left stale donation\n");
    }

    DONATION_OBSERVE.store(1, Ordering::Release);
    join_scheduler_thread(
        low1,
        31,
        b"ginkgo-scheduler-smoke: FAIL nested donation join\n",
    );

    scheduler_must(
        thread_set_scheduling_class(main_thread, ThreadSchedulingClass::Normal),
        b"ginkgo-scheduler-smoke: FAIL donation demotion\n",
    );
    scheduler_must(
        thread_set_scheduling_class(observer, ThreadSchedulingClass::Normal),
        b"ginkgo-scheduler-smoke: FAIL observer demotion\n",
    );
    let main_info = scheduler_must(
        thread_get_scheduling_info(main_thread),
        b"ginkgo-scheduler-smoke: FAIL demoted main info\n",
    );
    let observer_info = scheduler_must(
        thread_get_scheduling_info(observer),
        b"ginkgo-scheduler-smoke: FAIL demotion observer info\n",
    );
    if main_info.base_class != ThreadSchedulingClass::Normal as u32
        || main_info.effective_class != ThreadSchedulingClass::Normal as u32
        || observer_info.base_class != ThreadSchedulingClass::Normal as u32
        || observer_info.effective_class != ThreadSchedulingClass::Normal as u32
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL stale donation after demotion\n");
    }
    DONATION_DEMOTION_CHECK.store(1, Ordering::Release);
    join_scheduler_thread(
        observer,
        32,
        b"ginkgo-scheduler-smoke: FAIL donation observer join\n",
    );
    if DONATION_SEEN.load(Ordering::Acquire) != 1
        || DONATION_OBSERVER_OK.load(Ordering::Acquire) != 1
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL donation not observed\n");
    }
}

extern "C" fn donation_low2_worker(_argument: u64) -> ! {
    wait_for_atomic(&DONATION_GATE);
    while DONATION_SEEN.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    if DONATION_SEEN.load(Ordering::Acquire) != 1 {
        worker_fail(
            b"ginkgo-scheduler-smoke: FAIL donation observer unavailable\n",
            30,
        );
    }
    for _ in 0..20_000_000 {
        core::hint::spin_loop();
    }
    exit_thread(30)
}

extern "C" fn donation_low1_worker(_argument: u64) -> ! {
    wait_for_atomic(&DONATION_GATE);
    let low2 = ThreadId(DONATION_LOW2.load(Ordering::Acquire));
    wait_for_atomic(&DONATION_ACTIVE);
    DONATION_LOW1_JOINING.store(1, Ordering::Release);
    let low2_info = worker_must(
        thread_join(low2, DEADLINE_INFINITE),
        b"ginkgo-scheduler-smoke: FAIL low1 joining low2\n",
        31,
    );
    if low2_info.state != ThreadState::Exited as u32 || low2_info.exit_code != 30 {
        worker_fail(b"ginkgo-scheduler-smoke: FAIL low2 exit result\n", 31);
    }
    exit_thread(31)
}

extern "C" fn donation_observer_worker(_argument: u64) -> ! {
    wait_for_atomic(&DONATION_GATE);
    wait_for_atomic(&DONATION_OBSERVE);
    let low1 = ThreadId(DONATION_LOW1.load(Ordering::Acquire));
    let low2 = ThreadId(DONATION_LOW2.load(Ordering::Acquire));
    let deadline = worker_must(
        monotonic_time_ns(),
        b"ginkgo-scheduler-smoke: FAIL observer clock\n",
        32,
    )
    .saturating_add(10_000_000_000);
    loop {
        let low1_info = worker_must(
            thread_get_scheduling_info(low1),
            b"ginkgo-scheduler-smoke: FAIL observer low1 info\n",
            32,
        );
        let low2_info = worker_must(
            thread_get_scheduling_info(low2),
            b"ginkgo-scheduler-smoke: FAIL observer low2 info\n",
            32,
        );
        if low1_info.state == ThreadState::Blocked as u32
            && low1_info.effective_class == ThreadSchedulingClass::Interactive as u32
            && low2_info.effective_class == ThreadSchedulingClass::Interactive as u32
        {
            DONATION_SEEN.store(1, Ordering::Release);
            break;
        }
        let now = worker_must(
            monotonic_time_ns(),
            b"ginkgo-scheduler-smoke: FAIL observer polling clock\n",
            32,
        );
        if now >= deadline {
            DONATION_SEEN.store(2, Ordering::Release);
            worker_fail(
                b"ginkgo-scheduler-smoke: FAIL nested donation timeout\n",
                32,
            );
        }
        worker_must(
            process_yield(),
            b"ginkgo-scheduler-smoke: FAIL observer yield\n",
            32,
        );
    }

    wait_for_atomic(&DONATION_DEMOTION_CHECK);
    let main = ThreadId(DONATION_MAIN.load(Ordering::Acquire));
    let own = worker_must(
        thread_current(),
        b"ginkgo-scheduler-smoke: FAIL observer current thread\n",
        32,
    );
    let main_info = worker_must(
        thread_get_scheduling_info(main),
        b"ginkgo-scheduler-smoke: FAIL observer main info\n",
        32,
    );
    let own_info = worker_must(
        thread_get_scheduling_info(own),
        b"ginkgo-scheduler-smoke: FAIL observer own info\n",
        32,
    );
    if main_info.base_class != ThreadSchedulingClass::Normal as u32
        || main_info.effective_class != ThreadSchedulingClass::Normal as u32
        || own_info.base_class != ThreadSchedulingClass::Normal as u32
        || own_info.effective_class != ThreadSchedulingClass::Normal as u32
    {
        worker_fail(
            b"ginkgo-scheduler-smoke: FAIL observer found stale promotion\n",
            32,
        );
    }
    DONATION_OBSERVER_OK.store(1, Ordering::Release);
    exit_thread(32)
}

fn wait_for_workload_start() {
    wait_for_atomic(&WORKLOAD_GATE);
}

fn wait_for_atomic(value: &AtomicU64) {
    while value.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
}

fn create_scheduler_thread(
    entry: extern "C" fn(u64) -> !,
    argument: u64,
    message: &'static [u8],
) -> ThreadId {
    scheduler_must(
        thread_create(entry as *const () as usize as u64, argument, STACK_SIZE, 0),
        message,
    )
}

fn set_scheduler_class(thread: ThreadId, class: ThreadSchedulingClass) {
    scheduler_must(
        thread_set_scheduling_class(thread, class),
        b"ginkgo-scheduler-smoke: FAIL scheduling class assignment\n",
    );
}

fn join_scheduler_thread(thread: ThreadId, exit_code: i32, message: &'static [u8]) {
    let info = scheduler_must(thread_join(thread, DEADLINE_INFINITE), message);
    if info.state != ThreadState::Exited as u32 || info.exit_code != exit_code {
        fail_scheduler(message);
    }
}

fn worker_must<T>(result: Result<T, Status>, message: &'static [u8], code: i32) -> T {
    match result {
        Ok(value) => value,
        Err(_) => worker_fail(message, code),
    }
}

fn worker_fail(message: &'static [u8], code: i32) -> ! {
    WORKER_FAILURE.store(code as u64, Ordering::Release);
    let _ = debug_write(message);
    exit_thread(code + 64)
}

fn exit_thread(code: i32) -> ! {
    let _ = thread_exit(code);
    loop {
        let _ = process_yield();
    }
}

fn scheduler_must<T>(result: Result<T, Status>, message: &'static [u8]) -> T {
    match result {
        Ok(value) => value,
        Err(_) => fail_scheduler(message),
    }
}

fn validate_storage_diagnostics(metrics: StorageDiagnostics) {
    if metrics.mode != 1
        || metrics.in_flight_high_water < 2
        || metrics.failed_requests != 0
        || metrics.io_errors != 0
        || metrics.unsupported_operations != 0
        || metrics.bounce_in_flight != 0
        || metrics.bounce_quarantined != 0
        || metrics.bytes_transferred == 0
        || metrics.requested_write_sequence != metrics.durable_write_sequence
    {
        fail_scheduler(b"ginkgo-scheduler-smoke: FAIL storage diagnostics invariant\n");
    }
}

fn print_storage_metrics(metrics: StorageDiagnostics) {
    let mut line = OutputLine::new();
    line.push(b"ginkgo-scheduler-smoke: storage");
    line.push(b" driver=");
    line.push_u64(u64::from(metrics.driver));
    line.push(b" queue_hwm=");
    line.push_u64(metrics.queue_high_water);
    line.push(b" in_flight_hwm=");
    line.push_u64(metrics.in_flight_high_water);
    line.push(b" bytes=");
    line.push_u64(metrics.bytes_transferred);
    line.push(b" failures=");
    line.push_u64(metrics.failed_requests);
    line.push(b" io_errors=");
    line.push_u64(metrics.io_errors);
    line.push(b" bounce_in_flight=");
    line.push_u64(metrics.bounce_in_flight);
    line.push(b" bounce_quarantined=");
    line.push_u64(metrics.bounce_quarantined);
    line.push(b" cache_hits=");
    line.push_u64(metrics.cache_read_hits);
    line.push(b" cache_misses=");
    line.push_u64(metrics.cache_read_misses);
    line.push(b" writeback_bytes=");
    line.push_u64(metrics.bytes_written_back);
    line.push(b" requested=");
    line.push_u64(metrics.requested_write_sequence);
    line.push(b" durable=");
    line.push_u64(metrics.durable_write_sequence);
    line.push(b"\n");
    let _ = debug_write(line.as_bytes());
}

fn print_metrics(metrics: Metrics) {
    let mut line = OutputLine::new();
    line.push(b"ginkgo-scheduler-smoke: metrics frames=");
    line.push_u64(metrics.frames);
    line.push(b" frame_misses=");
    line.push_u64(metrics.frame_misses);
    line.push(b" frame_max_late_ns=");
    line.push_u64(metrics.frame_max_late_ns);
    line.push(b" audio_periods=");
    line.push_u64(metrics.audio_periods);
    line.push(b" audio_underruns=");
    line.push_u64(metrics.audio_underruns);
    line.push(b" audio_misses=");
    line.push_u64(metrics.audio_misses);
    line.push(b" audio_max_late_ns=");
    line.push_u64(metrics.audio_max_late_ns);
    line.push(b" input_events=");
    line.push_u64(metrics.input_events);
    line.push(b" input_max_latency_ns=");
    line.push_u64(metrics.input_max_latency_ns);
    line.push(b" background_bytes=");
    line.push_u64(metrics.background_bytes);
    line.push(b" hog_ticks=");
    line.push_u64(metrics.hog_ticks);
    line.push(b"\n");
    let _ = debug_write(line.as_bytes());
}

struct OutputLine {
    bytes: [u8; 512],
    length: usize,
}

impl OutputLine {
    const fn new() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.length.saturating_add(bytes.len()) > self.bytes.len() {
            fail_scheduler(b"ginkgo-scheduler-smoke: FAIL metrics buffer overflow\n");
        }
        let end = self.length + bytes.len();
        self.bytes[self.length..end].copy_from_slice(bytes);
        self.length = end;
    }

    fn push_u64(&mut self, mut value: u64) {
        if value == 0 {
            self.push(b"0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut count = 0usize;
        while value != 0 {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
        }
        while count != 0 {
            count -= 1;
            self.push(&digits[count..count + 1]);
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
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

fn must<T>(result: Result<T, Status>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => fail(b"ginkgo-thread-smoke: syscall failed\n"),
    }
}

fn fail_scheduler(message: &[u8]) -> ! {
    let _ = debug_write(message);
    ginkgo_runtime::exit(1)
}

fn fail(message: &[u8]) -> ! {
    let _ = debug_write(message);
    ginkgo_runtime::exit(1)
}
