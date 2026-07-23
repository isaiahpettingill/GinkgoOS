#![no_std]
#![no_main]

use core::{mem::MaybeUninit, slice};

use ginkgo_userspace::{
    application_data_create, application_get_data_directory, channel_create, channel_read,
    channel_write, debug_write, filesystem_open, handle_close, handle_duplicate, process_create,
    process_get_info, process_terminate, process_wait, system_power_request, wait_many,
    FilesystemOpenFlags, Handle, HandleDisposition, ProcessFault, ProcessState,
    ProcessTerminationCause, ReceivedHandle, Rights, Signals, Status, SystemPowerAction,
    SystemPowerFlags, WaitItem, DEADLINE_INFINITE,
};

const MAGIC: u32 = u32::from_le_bytes(*b"GKSP");
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 64;
const EXECUTABLE_PATH: &str = "system/process-capability-smoke.elf";
const MALFORMED_PATH: &str = "system/process-capability-malformed.elf";
const CHANNEL_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits() | Rights::WAIT.bits());
const CHILD_MESSAGE: &[u8] = b"startup-ok";
const WAITING_MESSAGE: &[u8] = b"waiting";
const CHILD_CONFIG: &[u8] = b"\0cfg\0";

struct Startup<'a> {
    bytes: &'a [u8],
    argc: usize,
    argv_offset: usize,
    config_offset: usize,
    config_length: usize,
    handles_offset: usize,
    handle_count: usize,
}

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(block_address: u64, block_length: u64, zero0: u64, zero1: u64) -> ! {
    if block_length == 0 && zero0 == 0 && zero1 == 0 {
        let root = u32::try_from(block_address)
            .ok()
            .map(Handle::from_raw)
            .filter(|handle| handle.is_valid())
            .unwrap_or_else(|| fail(b"parent root"));
        run_parent(root);
    }
    let startup = match unsafe { Startup::parse(block_address, block_length, zero0, zero1) } {
        Some(startup) => startup,
        None => fail(b"startup block"),
    };
    match startup.argument(1) {
        Some(b"exit") => run_exit_child(&startup),
        Some(b"fault") => run_fault_child(),
        Some(b"wait") => run_wait_child(&startup),
        _ => fail(b"startup mode"),
    }
}

impl<'a> Startup<'a> {
    unsafe fn parse(address: u64, length: u64, zero0: u64, zero1: u64) -> Option<Self> {
        let length = usize::try_from(length).ok()?;
        if address == 0 || length < HEADER_SIZE || length > 16 * 1024 || zero0 != 0 || zero1 != 0 {
            return None;
        }
        let bytes = unsafe { slice::from_raw_parts(address as *const u8, length) };
        if read_u32(bytes, 0)? != MAGIC
            || read_u16(bytes, 4)? != VERSION
            || usize::from(read_u16(bytes, 6)?) != HEADER_SIZE
            || usize::try_from(read_u32(bytes, 8)?).ok()? != length
            || bytes[44..HEADER_SIZE].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let startup = Self {
            bytes,
            argc: usize::try_from(read_u32(bytes, 12)?).ok()?,
            argv_offset: usize::try_from(read_u32(bytes, 16)?).ok()?,
            config_offset: usize::try_from(read_u32(bytes, 28)?).ok()?,
            config_length: usize::try_from(read_u32(bytes, 32)?).ok()?,
            handles_offset: usize::try_from(read_u32(bytes, 36)?).ok()?,
            handle_count: usize::try_from(read_u32(bytes, 40)?).ok()?,
        };
        checked_range(startup.argv_offset, startup.argc.checked_mul(4)?, length)?;
        checked_range(startup.config_offset, startup.config_length, length)?;
        checked_range(
            startup.handles_offset,
            startup.handle_count.checked_mul(4)?,
            length,
        )?;
        for index in 0..startup.argc {
            startup.argument(index)?;
        }
        Some(startup)
    }

    fn argument(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.argc {
            return None;
        }
        let offset = usize::try_from(read_u32(self.bytes, self.argv_offset + index * 4)?).ok()?;
        let rest = self.bytes.get(offset..)?;
        let length = rest.iter().position(|byte| *byte == 0)?;
        Some(&rest[..length])
    }

    fn config(&self) -> &'a [u8] {
        &self.bytes[self.config_offset..self.config_offset + self.config_length]
    }

    fn handle(&self, index: usize) -> Option<Handle> {
        if index >= self.handle_count {
            return None;
        }
        let handle = Handle::from_raw(read_u32(self.bytes, self.handles_offset + index * 4)?);
        handle.is_valid().then_some(handle)
    }
}

fn run_parent(root: Handle) -> ! {
    trace(b"parent entered\n");
    if system_power_request(
        Handle::INVALID,
        SystemPowerAction::PowerOff,
        SystemPowerFlags::empty(),
    ) != Err(Status::InvalidHandle)
    {
        fail(b"invalid system power handle");
    }
    if system_power_request(root, SystemPowerAction::PowerOff, SystemPowerFlags::empty())
        != Err(Status::AccessDenied)
    {
        fail(b"unauthorized system power");
    }
    let executable = filesystem_open(
        root,
        EXECUTABLE_PATH,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    )
    .unwrap_or_else(|_| fail(b"open executable"));

    trace(b"normal\n");
    normal_exit_case(root, executable);
    trace(b"fault\n");
    fault_case(executable);
    trace(b"termination\n");
    termination_case(executable);
    trace(b"malformed\n");
    malformed_atomic_case(root);
    trace(b"unauthorized\n");
    unauthorized_case(executable);
    trace(b"parent exiting\n");

    close(executable, b"close executable");
    close(root, b"close root");
    ginkgo_runtime::exit(0)
}

fn normal_exit_case(root: Handle, executable: Handle) {
    let (parent_channel, child_channel) =
        channel_create().unwrap_or_else(|_| fail(b"normal channel create"));
    let application_data = application_data_create(root, "process-smoke")
        .unwrap_or_else(|_| fail(b"normal application data create"));
    let dispositions = [
        HandleDisposition::move_handle(child_channel, CHANNEL_RIGHTS),
        HandleDisposition::move_handle(application_data, Rights::READ),
    ];
    let process = match process_create(
        executable,
        b"smoke\0exit\0alpha\0",
        &dispositions,
        CHILD_CONFIG,
    ) {
        Ok(process) => process,
        Err(status) => fail_status(b"normal create", status),
    };
    let info = process_wait(process, DEADLINE_INFINITE).unwrap_or_else(|_| fail(b"normal wait"));
    if info.process_state() != Some(ProcessState::Terminated)
        || info.termination_cause() != Some(ProcessTerminationCause::Exited)
        || info.exit_code != 37
        || info.process_fault() != Some(ProcessFault::None)
    {
        fail(b"normal status");
    }
    let inspected = process_get_info(process).unwrap_or_else(|_| fail(b"normal inspect"));
    if inspected != info {
        fail(b"normal stable info");
    }
    let mut message = [0_u8; 16];
    let mut handles: [MaybeUninit<ReceivedHandle>; 0] = [];
    let received = channel_read(parent_channel, &mut message, &mut handles)
        .unwrap_or_else(|_| fail(b"normal channel read"));
    if received.byte_count as usize != CHILD_MESSAGE.len()
        || received.handle_count != 0
        || &message[..CHILD_MESSAGE.len()] != CHILD_MESSAGE
    {
        fail(b"normal child message");
    }
    close(process, b"close normal process");
    close(parent_channel, b"close normal channel");
}

fn fault_case(executable: Handle) {
    let process = process_create(executable, b"smoke\0fault\0", &[], &[])
        .unwrap_or_else(|_| fail(b"fault create"));
    let info = process_wait(process, DEADLINE_INFINITE).unwrap_or_else(|_| fail(b"fault wait"));
    if info.process_state() != Some(ProcessState::Terminated)
        || info.termination_cause() != Some(ProcessTerminationCause::Faulted)
        || info.process_fault() != Some(ProcessFault::InvalidOpcode)
    {
        fail(b"fault status");
    }
    close(process, b"close fault process");
}

fn termination_case(executable: Handle) {
    let (parent_channel, child_channel) =
        channel_create().unwrap_or_else(|_| fail(b"termination channel create"));
    let dispositions = [HandleDisposition::move_handle(
        child_channel,
        CHANNEL_RIGHTS,
    )];
    let process = process_create(executable, b"smoke\0wait\0", &dispositions, &[])
        .unwrap_or_else(|_| fail(b"termination create"));
    let mut items = [WaitItem::new(parent_channel, Signals::READABLE)];
    wait_many(&mut items, DEADLINE_INFINITE)
        .unwrap_or_else(|_| fail(b"termination readiness wait"));
    let mut message = [0_u8; 7];
    let mut handles: [MaybeUninit<ReceivedHandle>; 0] = [];
    let received = channel_read(parent_channel, &mut message, &mut handles)
        .unwrap_or_else(|_| fail(b"termination readiness read"));
    if received.byte_count != 7 || received.handle_count != 0 || &message != WAITING_MESSAGE {
        fail(b"termination readiness message");
    }
    process_terminate(process).unwrap_or_else(|_| fail(b"termination request"));
    let info =
        process_wait(process, DEADLINE_INFINITE).unwrap_or_else(|_| fail(b"termination wait"));
    if info.process_state() != Some(ProcessState::Terminated)
        || info.termination_cause() != Some(ProcessTerminationCause::Terminated)
    {
        fail(b"termination status");
    }
    close(process, b"close terminated process");
    close(parent_channel, b"close termination channel");
}

fn malformed_atomic_case(root: Handle) {
    let malformed = filesystem_open(
        root,
        MALFORMED_PATH,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    )
    .unwrap_or_else(|_| fail(b"open malformed"));
    let (peer, moved) = channel_create().unwrap_or_else(|_| fail(b"malformed channel create"));
    let dispositions = [HandleDisposition::move_handle(moved, CHANNEL_RIGHTS)];
    if process_create(malformed, b"smoke\0exit\0", &dispositions, &[])
        != Err(Status::InvalidArgument)
    {
        fail(b"malformed status");
    }
    channel_write(moved, b"retained", &[]).unwrap_or_else(|_| fail(b"malformed consumed handle"));
    let mut message = [0_u8; 8];
    let mut handles: [MaybeUninit<ReceivedHandle>; 0] = [];
    let received = channel_read(peer, &mut message, &mut handles)
        .unwrap_or_else(|_| fail(b"malformed atomic read"));
    if received.byte_count != 8 || &message != b"retained" {
        fail(b"malformed atomic message");
    }
    close(moved, b"close retained channel");
    close(peer, b"close malformed peer");
    close(malformed, b"close malformed file");
}

fn unauthorized_case(executable: Handle) {
    let read_only = handle_duplicate(executable, Rights::READ)
        .unwrap_or_else(|_| fail(b"attenuate executable"));
    if process_create(read_only, b"smoke\0exit\0", &[], &[]) != Err(Status::AccessDenied) {
        fail(b"unauthorized launch status");
    }
    close(read_only, b"close attenuated file");
}

fn run_exit_child(startup: &Startup<'_>) -> ! {
    if startup.argc != 3
        || startup.argument(0) != Some(b"smoke")
        || startup.argument(1) != Some(b"exit")
        || startup.argument(2) != Some(b"alpha")
        || startup.config() != CHILD_CONFIG
        || startup.handle_count != 2
    {
        fail(b"exit child startup");
    }
    let channel = startup
        .handle(0)
        .unwrap_or_else(|| fail(b"exit child channel"));
    let application_data = startup
        .handle(1)
        .unwrap_or_else(|| fail(b"exit child application data"));
    let directory =
        application_get_data_directory().unwrap_or_else(|_| fail(b"exit child data directory"));
    channel_write(channel, CHILD_MESSAGE, &[]).unwrap_or_else(|_| fail(b"exit child write"));
    close(directory, b"exit child close data directory");
    close(application_data, b"exit child close application data");
    close(channel, b"exit child close channel");
    ginkgo_runtime::exit(37)
}

fn run_fault_child() -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn run_wait_child(startup: &Startup<'_>) -> ! {
    if startup.argc != 2 || startup.config() != b"" || startup.handle_count != 1 {
        fail(b"wait child startup");
    }
    let channel = startup
        .handle(0)
        .unwrap_or_else(|| fail(b"wait child channel"));
    channel_write(channel, WAITING_MESSAGE, &[]).unwrap_or_else(|_| fail(b"wait child readiness"));
    let mut items = [WaitItem::new(channel, Signals::READABLE)];
    let _ = wait_many(&mut items, DEADLINE_INFINITE);
    fail(b"wait child resumed");
}

fn close(handle: Handle, stage: &'static [u8]) {
    handle_close(handle).unwrap_or_else(|_| fail(stage));
}

fn trace(stage: &'static [u8]) {
    let _ = debug_write(b"ginkgo-process-capability-smoke: ");
    let _ = debug_write(stage);
}

fn fail_status(stage: &'static [u8], status: Status) -> ! {
    let detail: &'static [u8] = match status {
        Status::InvalidHandle => b" invalid-handle",
        Status::WrongObjectType => b" wrong-object-type",
        Status::AccessDenied => b" access-denied",
        Status::InvalidRights => b" invalid-rights",
        Status::HandleTableFull => b" handle-table-full",
        Status::OutOfMemory => b" out-of-memory",
        Status::InvalidArgument => b" invalid-argument",
        Status::InvalidAddress => b" invalid-address",
        Status::Io => b" io",
        Status::ResourceLimit => b" resource-limit",
        _ => b" other",
    };
    let _ = debug_write(b"ginkgo-process-capability-smoke: status");
    let _ = debug_write(detail);
    let _ = debug_write(b"\n");
    fail(stage)
}

fn fail(stage: &'static [u8]) -> ! {
    let _ = debug_write(b"ginkgo-process-capability-smoke: FAIL ");
    let _ = debug_write(stage);
    let _ = debug_write(b"\n");
    ginkgo_runtime::exit(1)
}

fn checked_range(offset: usize, length: usize, total: usize) -> Option<()> {
    (offset <= total && length <= total - offset).then_some(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
