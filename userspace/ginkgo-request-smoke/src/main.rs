#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use ginkgo_userspace::{
    anonymous_map, anonymous_unmap, debug_write, handle_close, monotonic_time_ns, process_yield,
    request_cancel, request_get_diagnostics, request_get_info, request_submit,
    request_submit_batch, shared_memory_create, shared_memory_map, shared_memory_unmap,
    thread_create, thread_exit, thread_join, wait_many, Handle, MapFlags, MapProtection,
    RequestBuffer, RequestBufferFlags, RequestBufferKind, RequestCompletionMode,
    RequestDiagnostics, RequestFlags, RequestInfo, RequestOperation, RequestResultFlags,
    RequestState, RequestSubmitArgs, RequestSubmitOutput, Signals, Status, ThreadState, WaitItem,
    DEADLINE_INFINITE, REQUEST_SUBMIT_ARGS_VERSION,
};

const PAGE_SIZE: usize = 4096;
const STACK_SIZE: u64 = 256 * 1024;
const PRESSURE_SYNTHETIC_COUNT: usize = 64;
const SYNTHETIC_RESET_MODE: u64 = 1 << 63;
const SYNTHETIC_REMOVE_MODE: u64 = 1 << 62;

static OWNER_REQUEST_HANDLE: AtomicU32 = AtomicU32::new(0);

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(root_raw: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> ! {
    let root = u32::try_from(root_raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
        .unwrap_or_else(|| fail(b"missing filesystem root"));

    for _ in 0..64 {
        must(process_yield(), b"boot log drain yield");
    }

    run_immediate();
    marker(b"ginkgo-request-smoke: immediate PASS\n");

    run_shared_memory();
    marker(b"ginkgo-request-smoke: buffers PASS\n");

    run_pinned_cancel();
    run_deadline();
    run_device_faults();
    run_pressure(root);
    marker(b"ginkgo-request-smoke: cancel PASS\n");

    run_atomic_batch();
    run_owner_termination();
    marker(b"ginkgo-request-smoke: lifecycle PASS\n");

    for _ in 0..4 {
        must(process_yield(), b"final drain yield");
    }
    let diagnostics = must(request_get_diagnostics(), b"request diagnostics");
    print_diagnostics(&diagnostics);
    check_diagnostics(&diagnostics);
    marker(b"ginkgo-request-smoke: PASS\n");
    ginkgo_runtime::exit(0)
}

fn run_immediate() {
    let nop = must(
        request_submit(
            Handle::INVALID,
            RequestOperation::Nop,
            RequestCompletionMode::InlineOnly,
            RequestFlags::empty(),
            &[],
            0,
            DEADLINE_INFINITE,
            0x1000,
        ),
        b"inline Nop",
    );
    if nop.request.is_valid()
        || nop.request_state() != Some(RequestState::Completed)
        || nop.result_status() != Some(Status::Ok)
        || nop.bytes_transferred != 0
    {
        fail(b"inline Nop output");
    }

    let mut copied = [0_u8; 513];
    let descriptor = memory_buffer(
        RequestBufferKind::Copy,
        RequestBufferFlags::WRITE,
        copied.as_mut_ptr() as u64,
        copied.len(),
    );
    let blocked = must(
        request_submit(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Block,
            RequestFlags::empty(),
            core::slice::from_ref(&descriptor),
            0,
            DEADLINE_INFINITE,
            0x1001,
        ),
        b"blocking Synthetic",
    );
    must(process_yield(), b"blocking copy release yield");
    if blocked.request.is_valid()
        || blocked.request_state() != Some(RequestState::Completed)
        || blocked.result_status() != Some(Status::Ok)
        || blocked.bytes_transferred != copied.len() as u64
        || copied.iter().any(|byte| *byte != 0xa5)
    {
        fail(b"blocking Synthetic result");
    }

    let output = submit_synthetic_handle(0, DEADLINE_INFINITE, 0x1002, &[]);
    let info = wait_terminal(output.request);
    if info.request_state() != Some(RequestState::Completed)
        || info.operation() != Some(RequestOperation::Synthetic)
        || info.result_status() != Some(Status::Ok)
        || info.user_data != 0x1002
    {
        fail(b"handle Synthetic info");
    }
    close(output.request, b"close immediate request");
}

fn run_shared_memory() {
    let shared = must(
        shared_memory_create(PAGE_SIZE as u64),
        b"shared memory create",
    );
    let mapping = must(
        unsafe {
            shared_memory_map(
                shared,
                0,
                PAGE_SIZE,
                None,
                MapProtection::READ | MapProtection::WRITE,
                MapFlags::empty(),
            )
        },
        b"shared memory map",
    );
    for offset in 0..PAGE_SIZE {
        unsafe { mapping.as_ptr().add(offset).write_volatile(0) };
    }
    let descriptor = RequestBuffer {
        kind: RequestBufferKind::SharedMemory as u32,
        flags: RequestBufferFlags::WRITE.bits(),
        address: 0,
        length: PAGE_SIZE as u64,
        handle: shared,
        reserved: 0,
        offset: 0,
    };
    let output = submit_synthetic_handle(
        0,
        DEADLINE_INFINITE,
        0x2000,
        core::slice::from_ref(&descriptor),
    );
    close(shared, b"close shared source handle");
    let info = wait_terminal(output.request);
    if info.request_state() != Some(RequestState::Completed)
        || info.result_status() != Some(Status::Ok)
        || info.bytes_transferred != PAGE_SIZE as u64
    {
        fail(b"shared request info");
    }
    for offset in 0..PAGE_SIZE {
        if unsafe { mapping.as_ptr().add(offset).read_volatile() } != 0xa5 {
            fail(b"shared mapped bytes");
        }
    }
    close(output.request, b"close shared request");
    must(
        unsafe { shared_memory_unmap(mapping, PAGE_SIZE) },
        b"shared memory unmap",
    );
}

fn run_pinned_cancel() {
    let length = PAGE_SIZE * 3;
    let mapping = must(
        unsafe { anonymous_map(length, MapProtection::READ | MapProtection::WRITE) },
        b"pinned mapping",
    );
    for page in 0..3 {
        unsafe {
            mapping
                .as_ptr()
                .add(page * PAGE_SIZE)
                .write_volatile(page as u8)
        };
    }
    let descriptor = memory_buffer(
        RequestBufferKind::Pinned,
        RequestBufferFlags::WRITE,
        mapping.as_ptr() as u64,
        length,
    );
    let output = submit_synthetic_handle(
        1,
        DEADLINE_INFINITE,
        0x3000,
        core::slice::from_ref(&descriptor),
    );
    if unsafe { anonymous_unmap(mapping, length) } != Err(Status::ShouldWait) {
        fail(b"pinned overlap unmap status");
    }
    must(request_cancel(output.request), b"pinned request cancel");
    let info = wait_terminal(output.request);
    if info.request_state() != Some(RequestState::Canceled)
        || info.result_status() != Some(Status::Canceled)
        || !info
            .result_flags()
            .contains(RequestResultFlags::CANCEL_ACKNOWLEDGED)
    {
        fail(b"pinned cancellation result");
    }
    close(output.request, b"close pinned request");
    must(
        unsafe { anonymous_unmap(mapping, length) },
        b"pinned mapping unmap after cancel",
    );
}

fn run_deadline() {
    let now = must(monotonic_time_ns(), b"deadline clock");
    let deadline = now
        .checked_add(10_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .unwrap_or_else(|| fail(b"deadline range"));
    let output = submit_synthetic_handle(1, deadline, 0x3001, &[]);
    let info = wait_terminal(output.request);
    if info.request_state() != Some(RequestState::TimedOut)
        || info.result_status() != Some(Status::TimedOut)
        || !info
            .result_flags()
            .contains(RequestResultFlags::DEADLINE_EXPIRED)
    {
        fail(b"deadline terminal result");
    }
    close(output.request, b"close deadline request");
}

fn run_device_faults() {
    for (mode, user_data) in [
        (SYNTHETIC_RESET_MODE, 0x3100),
        (SYNTHETIC_REMOVE_MODE, 0x3101),
    ] {
        let output = submit_synthetic_handle(mode | user_data, DEADLINE_INFINITE, user_data, &[]);
        let info = wait_terminal(output.request);
        if info.request_state() != Some(RequestState::Failed)
            || info.result_status() != Some(Status::Io)
            || info.user_data != user_data
        {
            fail(b"device fault result");
        }
        close(output.request, b"close device fault request");
    }
}

fn run_pressure(_root: Handle) {
    let mut handles = [Handle::INVALID; PRESSURE_SYNTHETIC_COUNT];
    for (index, handle) in handles.iter_mut().enumerate() {
        let selector = index as u64 + 1;
        *handle = submit_synthetic_handle(selector, DEADLINE_INFINITE, 0x4000 + index as u64, &[])
            .request;
    }

    let rejected = [
        request_args(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Handle,
            65,
            DEADLINE_INFINITE,
            0x6000,
        ),
        request_args(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Handle,
            66,
            DEADLINE_INFINITE,
            0x6001,
        ),
    ];
    let mut rejected_outputs = [RequestSubmitOutput::default(); 2];
    if request_submit_batch(&rejected, &mut rejected_outputs) != Err(Status::ResourceLimit)
        || rejected_outputs
            .iter()
            .any(|output| output.request.is_valid())
    {
        fail(b"pressure owner limit rejection");
    }

    for handle in handles {
        must(request_cancel(handle), b"cancel pressure Synthetic");
        let info = wait_terminal(handle);
        if info.request_state() != Some(RequestState::Canceled)
            || info.result_status() != Some(Status::Canceled)
            || !info
                .result_flags()
                .contains(RequestResultFlags::CANCEL_ACKNOWLEDGED)
        {
            fail(b"pressure Synthetic result");
        }
        close(handle, b"close pressure request");
    }
}

fn run_atomic_batch() {
    let submissions = [
        request_args(
            Handle::INVALID,
            RequestOperation::Nop,
            RequestCompletionMode::InlineOnly,
            0,
            DEADLINE_INFINITE,
            0x7000,
        ),
        request_args(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Handle,
            0,
            DEADLINE_INFINITE,
            0x7001,
        ),
        request_args(
            Handle::INVALID,
            RequestOperation::Nop,
            RequestCompletionMode::InlineOnly,
            0,
            DEADLINE_INFINITE,
            0x7002,
        ),
        request_args(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Handle,
            0,
            DEADLINE_INFINITE,
            0x7003,
        ),
    ];
    let mut outputs = [RequestSubmitOutput::default(); 4];
    must(
        request_submit_batch(&submissions, &mut outputs),
        b"mixed atomic batch",
    );
    for index in [0, 2] {
        if outputs[index].request.is_valid()
            || outputs[index].request_state() != Some(RequestState::Completed)
            || outputs[index].result_status() != Some(Status::Ok)
        {
            fail(b"batch Nop output");
        }
    }
    for index in [1, 3] {
        if !outputs[index].request.is_valid() {
            fail(b"batch Synthetic handle");
        }
        let info = wait_terminal(outputs[index].request);
        if info.request_state() != Some(RequestState::Completed)
            || info.result_status() != Some(Status::Ok)
            || info.user_data != submissions[index].user_data
        {
            fail(b"batch Synthetic result");
        }
        close(outputs[index].request, b"close batch request");
    }
}

fn run_owner_termination() {
    OWNER_REQUEST_HANDLE.store(0, Ordering::Release);
    let tls = must(
        unsafe { anonymous_map(PAGE_SIZE, MapProtection::READ | MapProtection::WRITE) },
        b"owner TLS map",
    );
    let thread = must(
        thread_create(
            owner_worker as *const () as usize as u64,
            0,
            STACK_SIZE,
            tls.as_ptr() as u64,
        ),
        b"owner thread create",
    );
    let raw = loop {
        let raw = OWNER_REQUEST_HANDLE.load(Ordering::Acquire);
        if raw != 0 {
            break raw;
        }
        must(process_yield(), b"owner handle yield");
    };
    if raw == u32::MAX {
        fail(b"owner thread submit");
    }
    let request = Handle::from_raw(raw);
    let info = wait_terminal(request);
    if info.request_state() != Some(RequestState::OwnerTerminated)
        || info.result_status() != Some(Status::Canceled)
        || info.user_data != 0x8000
    {
        fail(b"owner termination result");
    }
    close(request, b"close owner request");
    let joined = must(thread_join(thread, DEADLINE_INFINITE), b"owner thread join");
    if joined.state != ThreadState::Exited as u32 || joined.exit_code != 42 {
        fail(b"owner thread join result");
    }
    must(
        unsafe { anonymous_unmap(tls, PAGE_SIZE) },
        b"owner TLS unmap",
    );
}

extern "C" fn owner_worker(_argument: u64) -> ! {
    match request_submit(
        Handle::INVALID,
        RequestOperation::Synthetic,
        RequestCompletionMode::Handle,
        RequestFlags::empty(),
        &[],
        1,
        DEADLINE_INFINITE,
        0x8000,
    ) {
        Ok(output) if output.request.is_valid() => {
            OWNER_REQUEST_HANDLE.store(output.request.raw(), Ordering::Release);
            let _ = thread_exit(42);
        }
        _ => {
            OWNER_REQUEST_HANDLE.store(u32::MAX, Ordering::Release);
            let _ = thread_exit(1);
        }
    }
    loop {
        let _ = process_yield();
    }
}

fn submit_synthetic_handle(
    operation_argument: u64,
    deadline_ns: i64,
    user_data: u64,
    buffers: &[RequestBuffer],
) -> RequestSubmitOutput {
    let output = must(
        request_submit(
            Handle::INVALID,
            RequestOperation::Synthetic,
            RequestCompletionMode::Handle,
            RequestFlags::empty(),
            buffers,
            operation_argument,
            deadline_ns,
            user_data,
        ),
        b"Synthetic handle submit",
    );
    if !output.request.is_valid() {
        fail(b"Synthetic handle output");
    }
    output
}

fn wait_terminal(handle: Handle) -> RequestInfo {
    let mut items = [WaitItem::new(handle, Signals::SIGNALED)];
    let ready = must(
        wait_many(&mut items, DEADLINE_INFINITE),
        b"request wait_many",
    );
    if ready != 0 || !items[0].pending.contains(Signals::SIGNALED) {
        fail(b"request signal result");
    }
    must(request_get_info(handle), b"RequestGetInfo")
}

fn memory_buffer(
    kind: RequestBufferKind,
    flags: RequestBufferFlags,
    address: u64,
    length: usize,
) -> RequestBuffer {
    RequestBuffer {
        kind: kind as u32,
        flags: flags.bits(),
        address,
        length: length as u64,
        handle: Handle::INVALID,
        reserved: 0,
        offset: 0,
    }
}

fn request_args(
    target: Handle,
    operation: RequestOperation,
    completion_mode: RequestCompletionMode,
    operation_argument: u64,
    deadline_ns: i64,
    user_data: u64,
) -> RequestSubmitArgs {
    RequestSubmitArgs {
        version: REQUEST_SUBMIT_ARGS_VERSION,
        size: RequestSubmitArgs::SIZE,
        target,
        operation: operation as u32,
        completion_mode: completion_mode as u32,
        flags: RequestFlags::empty().bits(),
        buffers_address: 0,
        buffer_count: 0,
        reserved: 0,
        operation_argument,
        deadline_ns,
        user_data,
    }
}

fn check_diagnostics(diagnostics: &RequestDiagnostics) {
    if diagnostics.queue_depth != 0
        || diagnostics.active_requests != 0
        || diagnostics.peak_queue_depth < 2
        || diagnostics.peak_active_requests < 64
        || diagnostics.completed_requests < 74
        || diagnostics.deadline_misses < 1
        || diagnostics.cancellations < 65
        || diagnostics.bytes_transferred < 4609
        || diagnostics.errors != 2
        || diagnostics.rejected_requests < 1
        || diagnostics.dropped_completions != 0
    {
        fail(b"diagnostic bounds");
    }
}

fn print_diagnostics(diagnostics: &RequestDiagnostics) {
    let mut line = Line::new();
    line.text(b"ginkgo-request-smoke: diagnostics queue=");
    line.number(diagnostics.queue_depth);
    line.text(b" peak=");
    line.number(diagnostics.peak_queue_depth);
    line.text(b" active=");
    line.number(diagnostics.active_requests);
    line.text(b" peak_active=");
    line.number(diagnostics.peak_active_requests);
    line.text(b" completed=");
    line.number(diagnostics.completed_requests);
    line.text(b" deadline_misses=");
    line.number(diagnostics.deadline_misses);
    line.text(b" cancellations=");
    line.number(diagnostics.cancellations);
    line.text(b" bytes=");
    line.number(diagnostics.bytes_transferred);
    line.text(b" errors=");
    line.number(diagnostics.errors);
    line.text(b" rejected=");
    line.number(diagnostics.rejected_requests);
    line.text(b" dropped=");
    line.number(diagnostics.dropped_completions);
    line.text(b"\n");
    marker(line.as_bytes());
}

struct Line {
    bytes: [u8; 384],
    length: usize,
}

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; 384],
            length: 0,
        }
    }

    fn text(&mut self, text: &[u8]) {
        let end = self
            .length
            .checked_add(text.len())
            .unwrap_or_else(|| fail(b"line overflow"));
        if end > self.bytes.len() {
            fail(b"line overflow");
        }
        self.bytes[self.length..end].copy_from_slice(text);
        self.length = end;
    }

    fn number(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.text(&digits[start..]);
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

fn close(handle: Handle, stage: &'static [u8]) {
    must(handle_close(handle), stage);
}

fn must<T>(result: Result<T, Status>, stage: &'static [u8]) -> T {
    result.unwrap_or_else(|_| fail(stage))
}

fn marker(bytes: &[u8]) {
    if debug_write(bytes).is_err() {
        ginkgo_runtime::exit(1);
    }
}

fn fail(stage: &'static [u8]) -> ! {
    let _ = debug_write(b"ginkgo-request-smoke: FAIL ");
    let _ = debug_write(stage);
    let _ = debug_write(b"\n");
    ginkgo_runtime::exit(1)
}
