#![no_std]
#![no_main]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use core::{mem::MaybeUninit, slice, str};

use ginkgo_terminal_protocol::{decode_console_message, encode_console_message, ConsoleMessage};
use ginkgo_userspace::{
    channel_read, channel_write, filesystem_create_directory, filesystem_get_metadata,
    filesystem_open, filesystem_open_directory, filesystem_read, filesystem_read_directory2,
    filesystem_remove_directory, filesystem_rename, filesystem_stat, filesystem_sync,
    filesystem_truncate, filesystem_unlink, filesystem_write, handle_close, monotonic_time_ns,
    process_yield, random_fill, wait_many, FilesystemEntryKind, FilesystemMetadata,
    FilesystemOpenFlags, FilesystemRenameFlags, Handle, ReceivedHandle, Signals, Status, WaitItem,
    CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES, DEADLINE_INFINITE, FILESYSTEM_IO_MAX_BYTES,
    RANDOM_MAX_BYTES,
};
use wasmi::{
    Caller, Config, EnforcedLimits, Engine, Error, Extern, Linker, Memory, Module, StackLimits,
    Store, StoreLimits, StoreLimitsBuilder,
};

const STARTUP_MAGIC: u32 = u32::from_le_bytes(*b"GKSP");
const STARTUP_VERSION: u16 = 1;
const STARTUP_HEADER_SIZE: usize = 64;
const WASI_MODULES: &[&str] = &["wasi_snapshot_preview1", "wasi_unstable"];
const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
const EXECUTION_FUEL: u64 = 500_000_000;
const MAX_LINEAR_MEMORY_BYTES: usize = 256 * 1024 * 1024;
const MAX_TABLE_ELEMENTS: usize = 64 * 1024;
const MODULE_HANDLE: usize = 0;
const CONSOLE_HANDLE: usize = 1;
const PREOPEN_HANDLE: usize = 2;
const RANDOM_HANDLE: usize = 3;
const PREOPEN_FD: i32 = 3;
const FIRST_FILE_FD: i32 = 4;
const MAX_OPEN_FILES: usize = 32;
const MAX_IOVECS: usize = 1024;
const MAX_POLL_SUBSCRIPTIONS: usize = 128;
const WASI_SUBSCRIPTION_SIZE: usize = 48;
const WASI_EVENT_SIZE: usize = 32;

const EVENTTYPE_CLOCK: u8 = 0;
const EVENTTYPE_FD_READ: u8 = 1;
const EVENTTYPE_FD_WRITE: u8 = 2;
const SUBCLOCKFLAG_ABSTIME: u16 = 1;

const ERRNO_SUCCESS: i32 = 0;
const ERRNO_ACCES: i32 = 2;
const ERRNO_AGAIN: i32 = 6;
const ERRNO_BADF: i32 = 8;
const ERRNO_EXIST: i32 = 20;
const ERRNO_FAULT: i32 = 21;
const ERRNO_ILSEQ: i32 = 25;
const ERRNO_INVAL: i32 = 28;
const ERRNO_IO: i32 = 29;
const ERRNO_ISDIR: i32 = 31;
const ERRNO_MFILE: i32 = 33;
const ERRNO_NAMETOOLONG: i32 = 37;
const ERRNO_NOENT: i32 = 44;
const ERRNO_NOMEM: i32 = 48;
const ERRNO_NOSPC: i32 = 51;
const ERRNO_NOSYS: i32 = 52;
const ERRNO_NOTDIR: i32 = 54;
const ERRNO_NOTEMPTY: i32 = 55;
const ERRNO_NOTSUP: i32 = 58;
const ERRNO_OVERFLOW: i32 = 61;
const ERRNO_RANGE: i32 = 68;
const ERRNO_XDEV: i32 = 75;
const ERRNO_NOTCAPABLE: i32 = 76;

const FILETYPE_CHARACTER_DEVICE: u8 = 2;
const FILETYPE_DIRECTORY: u8 = 3;
const FILETYPE_REGULAR_FILE: u8 = 4;

const RIGHT_FD_DATASYNC: u64 = 1 << 0;
const RIGHT_FD_READ: u64 = 1 << 1;
const RIGHT_FD_SEEK: u64 = 1 << 2;
const RIGHT_FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
const RIGHT_FD_SYNC: u64 = 1 << 4;
const RIGHT_FD_TELL: u64 = 1 << 5;
const RIGHT_FD_WRITE: u64 = 1 << 6;
const RIGHT_FD_ADVISE: u64 = 1 << 7;
const RIGHT_PATH_CREATE_DIRECTORY: u64 = 1 << 9;
const RIGHT_PATH_CREATE_FILE: u64 = 1 << 10;
const RIGHT_PATH_OPEN: u64 = 1 << 13;
const RIGHT_FD_READDIR: u64 = 1 << 14;
const RIGHT_PATH_RENAME_SOURCE: u64 = 1 << 16;
const RIGHT_PATH_RENAME_TARGET: u64 = 1 << 17;
const RIGHT_PATH_FILESTAT_GET: u64 = 1 << 18;
const RIGHT_PATH_FILESTAT_SET_SIZE: u64 = 1 << 19;
const RIGHT_FD_FILESTAT_GET: u64 = 1 << 21;
const RIGHT_FD_FILESTAT_SET_SIZE: u64 = 1 << 22;
const RIGHT_PATH_REMOVE_DIRECTORY: u64 = 1 << 25;
const RIGHT_PATH_UNLINK_FILE: u64 = 1 << 26;
const RIGHT_POLL_FD_READWRITE: u64 = 1 << 27;
const FILE_RIGHTS: u64 = RIGHT_FD_DATASYNC
    | RIGHT_FD_READ
    | RIGHT_FD_SEEK
    | RIGHT_FD_FDSTAT_SET_FLAGS
    | RIGHT_FD_SYNC
    | RIGHT_FD_TELL
    | RIGHT_FD_WRITE
    | RIGHT_FD_ADVISE
    | RIGHT_FD_FILESTAT_GET
    | RIGHT_FD_FILESTAT_SET_SIZE
    | RIGHT_POLL_FD_READWRITE;
const DIRECTORY_RIGHTS: u64 = RIGHT_FD_FDSTAT_SET_FLAGS
    | RIGHT_FD_SYNC
    | RIGHT_FD_ADVISE
    | RIGHT_PATH_CREATE_DIRECTORY
    | RIGHT_PATH_CREATE_FILE
    | RIGHT_PATH_OPEN
    | RIGHT_FD_READDIR
    | RIGHT_PATH_RENAME_SOURCE
    | RIGHT_PATH_RENAME_TARGET
    | RIGHT_PATH_FILESTAT_GET
    | RIGHT_PATH_FILESTAT_SET_SIZE
    | RIGHT_FD_FILESTAT_GET
    | RIGHT_PATH_REMOVE_DIRECTORY
    | RIGHT_PATH_UNLINK_FILE
    | RIGHT_POLL_FD_READWRITE;

const FDFLAG_APPEND: u16 = 1 << 0;
const FDFLAG_NONBLOCK: u16 = 1 << 2;
const SUPPORTED_FDFLAGS: u16 = FDFLAG_APPEND | FDFLAG_NONBLOCK;

const OFLAG_CREAT: u16 = 1 << 0;
const OFLAG_DIRECTORY: u16 = 1 << 1;
const OFLAG_EXCL: u16 = 1 << 2;
const OFLAG_TRUNC: u16 = 1 << 3;

struct Startup<'a> {
    bytes: &'a [u8],
    argc: usize,
    argv_offset: usize,
    handles_offset: usize,
    handle_count: usize,
}

struct OpenFile {
    handle: Handle,
    offset: u64,
    rights: u64,
    inheriting_rights: u64,
    flags: u16,
    filetype: u8,
}

#[derive(Clone, Copy)]
struct PollSubscription {
    userdata: u64,
    kind: PollSubscriptionKind,
}

#[derive(Clone, Copy)]
enum PollSubscriptionKind {
    Clock { deadline: u64 },
    FdRead { fd: i32 },
    FdWrite { fd: i32 },
}

struct WasiState {
    arguments: Vec<Vec<u8>>,
    console: Handle,
    preopen: Option<Handle>,
    random: Option<Handle>,
    stdio_open: [bool; 3],
    stdio_rights: [u64; 3],
    stdin_buffer: Vec<u8>,
    stdin_cursor: usize,
    preopen_rights: u64,
    preopen_inheriting_rights: u64,
    preopen_flags: u16,
    files: [Option<OpenFile>; MAX_OPEN_FILES],
    limits: StoreLimits,
}

impl Drop for WasiState {
    fn drop(&mut self) {
        if let Some(preopen) = self.preopen.take() {
            let _ = handle_close(preopen);
        }
        if let Some(random) = self.random.take() {
            let _ = handle_close(random);
        }
        for entry in &mut self.files {
            if let Some(file) = entry.take() {
                let _ = handle_close(file.handle);
            }
        }
    }
}

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(address: u64, length: u64, zero0: u64, zero1: u64) -> ! {
    let startup = match unsafe { Startup::parse(address, length, zero0, zero1) } {
        Some(startup) => startup,
        None => exit_error(Handle::INVALID, "invalid WASM runtime startup block", 126),
    };
    let module_file = match startup.handle(MODULE_HANDLE) {
        Some(handle) => handle,
        None => exit_error(Handle::INVALID, "missing WASM module handle", 126),
    };
    let console = startup.handle(CONSOLE_HANDLE).unwrap_or(Handle::INVALID);
    let preopen = startup.handle(PREOPEN_HANDLE);
    let random = startup.handle(RANDOM_HANDLE);
    let arguments = match startup.arguments() {
        Some(arguments) => arguments,
        None => {
            let _ = handle_close(module_file);
            close_optional(preopen);
            close_optional(random);
            exit_error(console, "invalid WASI arguments", 126)
        }
    };
    let module_result = read_module(module_file);
    let _ = handle_close(module_file);
    let module_bytes = match module_result {
        Ok(bytes) => bytes,
        Err(message) => {
            close_optional(preopen);
            close_optional(random);
            exit_error(console, message, 126)
        }
    };

    let code = match run_module(&module_bytes, arguments, console, preopen, random) {
        Ok(code) => code,
        Err(message) => exit_error(console, &message, 126),
    };
    send_console(console, ConsoleMessage::Exit(code));
    let _ = handle_close(console);
    ginkgo_runtime::exit(code)
}

impl<'a> Startup<'a> {
    unsafe fn parse(address: u64, length: u64, zero0: u64, zero1: u64) -> Option<Self> {
        let length = usize::try_from(length).ok()?;
        if address == 0
            || length < STARTUP_HEADER_SIZE
            || length > 16 * 1024
            || zero0 != 0
            || zero1 != 0
        {
            return None;
        }
        let bytes = unsafe { slice::from_raw_parts(address as *const u8, length) };
        if read_u32(bytes, 0)? != STARTUP_MAGIC
            || read_u16(bytes, 4)? != STARTUP_VERSION
            || usize::from(read_u16(bytes, 6)?) != STARTUP_HEADER_SIZE
            || usize::try_from(read_u32(bytes, 8)?).ok()? != length
            || bytes[44..STARTUP_HEADER_SIZE].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let startup = Self {
            bytes,
            argc: usize::try_from(read_u32(bytes, 12)?).ok()?,
            argv_offset: usize::try_from(read_u32(bytes, 16)?).ok()?,
            handles_offset: usize::try_from(read_u32(bytes, 36)?).ok()?,
            handle_count: usize::try_from(read_u32(bytes, 40)?).ok()?,
        };
        checked_range(startup.argv_offset, startup.argc.checked_mul(4)?, length)?;
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

    fn arguments(&self) -> Option<Vec<Vec<u8>>> {
        let mut arguments = Vec::with_capacity(self.argc);
        for index in 0..self.argc {
            let argument = self.argument(index)?;
            str::from_utf8(argument).ok()?;
            let mut nul_terminated = Vec::with_capacity(argument.len() + 1);
            nul_terminated.extend_from_slice(argument);
            nul_terminated.push(0);
            arguments.push(nul_terminated);
        }
        Some(arguments)
    }

    fn handle(&self, index: usize) -> Option<Handle> {
        if index >= self.handle_count {
            return None;
        }
        let handle = Handle::from_raw(read_u32(self.bytes, self.handles_offset + index * 4)?);
        handle.is_valid().then_some(handle)
    }
}

fn read_module(file: Handle) -> Result<Vec<u8>, &'static str> {
    let length = usize::try_from(
        filesystem_stat(file)
            .map_err(|_| "cannot stat WASM module")?
            .length,
    )
    .map_err(|_| "WASM module is too large")?;
    if length == 0 || length > MAX_MODULE_BYTES {
        return Err("WASM module size is outside the runtime limit");
    }
    let mut bytes = vec![0; length];
    let mut offset = 0;
    while offset < length {
        let chunk_end = offset.saturating_add(FILESYSTEM_IO_MAX_BYTES).min(length);
        let count = filesystem_read(file, offset as u64, &mut bytes[offset..chunk_end])
            .map_err(|_| "cannot read WASM module")?;
        if count == 0 {
            return Err("WASM module ended before its recorded length");
        }
        offset += count;
    }
    Ok(bytes)
}

fn run_module(
    bytes: &[u8],
    arguments: Vec<Vec<u8>>,
    console: Handle,
    preopen: Option<Handle>,
    random: Option<Handle>,
) -> Result<i32, String> {
    let mut config = Config::default();
    let stack_limits = match StackLimits::new(1024, 64 * 1024, 1024) {
        Ok(limits) => limits,
        Err(error) => {
            close_optional(preopen);
            close_optional(random);
            return Err(format!("invalid WASM stack limits: {error}"));
        }
    };
    config
        .set_stack_limits(stack_limits)
        .enforced_limits(EnforcedLimits::default())
        .consume_fuel(true)
        .wasm_memory64(false)
        .wasm_multi_memory(false)
        .wasm_custom_page_sizes(false)
        .wasm_tail_call(false);
    let engine = Engine::new(&config);
    let limits = StoreLimitsBuilder::new()
        .memory_size(MAX_LINEAR_MEMORY_BYTES)
        .table_elements(MAX_TABLE_ELEMENTS)
        .instances(1)
        .memories(1)
        .tables(1)
        .build();
    let mut store = Store::new(
        &engine,
        WasiState {
            arguments,
            console,
            preopen,
            random,
            stdio_open: [true; 3],
            stdio_rights: [
                RIGHT_FD_READ
                    | RIGHT_FD_FDSTAT_SET_FLAGS
                    | RIGHT_FD_FILESTAT_GET
                    | RIGHT_POLL_FD_READWRITE,
                RIGHT_FD_WRITE
                    | RIGHT_FD_FDSTAT_SET_FLAGS
                    | RIGHT_FD_FILESTAT_GET
                    | RIGHT_POLL_FD_READWRITE,
                RIGHT_FD_WRITE
                    | RIGHT_FD_FDSTAT_SET_FLAGS
                    | RIGHT_FD_FILESTAT_GET
                    | RIGHT_POLL_FD_READWRITE,
            ],
            stdin_buffer: Vec::new(),
            stdin_cursor: 0,
            preopen_rights: DIRECTORY_RIGHTS,
            preopen_inheriting_rights: FILE_RIGHTS | DIRECTORY_RIGHTS,
            preopen_flags: 0,
            files: core::array::from_fn(|_| None),
            limits,
        },
    );
    let module =
        Module::new(&engine, bytes).map_err(|error| format!("invalid WASM module: {error}"))?;
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(EXECUTION_FUEL)
        .map_err(|error| format!("cannot set WASM fuel: {error}"))?;
    let mut linker = Linker::new(&engine);
    register_wasi(&mut linker).map_err(|error| format!("cannot register WASIp1: {error}"))?;
    let instance = linker
        .instantiate(&mut store, &module)
        .and_then(|instance| instance.start(&mut store))
        .map_err(|error| format!("cannot instantiate WASM module: {error}"))?;
    let start = instance
        .get_typed_func::<(), ()>(&store, "_start")
        .map_err(|error| format!("WASIp1 module has no command _start export: {error}"))?;
    match start.call(&mut store, ()) {
        Ok(()) => Ok(0),
        Err(error) => {
            if let Some(code) = error.i32_exit_status() {
                Ok(code)
            } else if error.as_trap_code().is_some() {
                Err(format!("WASM trapped: {error}"))
            } else {
                Err(format!("WASM execution failed: {error}"))
            }
        }
    }
}

fn register_wasi(linker: &mut Linker<WasiState>) -> Result<(), wasmi::errors::LinkerError> {
    for module in WASI_MODULES {
        register_wasi_module(linker, module)?;
    }
    Ok(())
}

fn register_wasi_module(
    linker: &mut Linker<WasiState>,
    module: &str,
) -> Result<(), wasmi::errors::LinkerError> {
    linker.func_wrap(module, "args_sizes_get", wasi_args_sizes_get)?;
    linker.func_wrap(module, "args_get", wasi_args_get)?;
    linker.func_wrap(module, "environ_sizes_get", wasi_environ_sizes_get)?;
    linker.func_wrap(module, "environ_get", wasi_environ_get)?;
    linker.func_wrap(module, "fd_write", wasi_fd_write)?;
    linker.func_wrap(module, "fd_read", wasi_fd_read)?;
    linker.func_wrap(module, "fd_close", wasi_fd_close)?;
    linker.func_wrap(module, "fd_fdstat_set_flags", wasi_fd_fdstat_set_flags)?;
    linker.func_wrap(module, "fd_fdstat_set_rights", wasi_fd_fdstat_set_rights)?;
    linker.func_wrap(module, "fd_fdstat_get", wasi_fd_fdstat_get)?;
    linker.func_wrap(module, "fd_prestat_get", wasi_fd_prestat_get)?;
    linker.func_wrap(module, "fd_prestat_dir_name", wasi_fd_prestat_dir_name)?;
    linker.func_wrap(module, "fd_seek", wasi_fd_seek)?;
    linker.func_wrap(module, "fd_tell", wasi_fd_tell)?;
    linker.func_wrap(module, "fd_pread", wasi_fd_pread)?;
    linker.func_wrap(module, "fd_pwrite", wasi_fd_pwrite)?;
    linker.func_wrap(module, "fd_filestat_get", wasi_fd_filestat_get)?;
    linker.func_wrap(module, "fd_filestat_set_size", wasi_fd_filestat_set_size)?;
    linker.func_wrap(module, "fd_sync", wasi_fd_sync)?;
    linker.func_wrap(module, "fd_datasync", wasi_fd_datasync)?;
    linker.func_wrap(module, "fd_advise", wasi_fd_advise)?;
    linker.func_wrap(module, "fd_readdir", wasi_fd_readdir)?;
    linker.func_wrap(module, "path_filestat_get", wasi_path_filestat_get)?;
    linker.func_wrap(module, "path_open", wasi_path_open)?;
    linker.func_wrap(module, "path_create_directory", wasi_path_create_directory)?;
    linker.func_wrap(module, "path_remove_directory", wasi_path_remove_directory)?;
    linker.func_wrap(module, "path_unlink_file", wasi_path_unlink_file)?;
    linker.func_wrap(module, "path_rename", wasi_path_rename)?;
    linker.func_wrap(module, "clock_res_get", wasi_clock_res_get)?;
    linker.func_wrap(module, "clock_time_get", wasi_clock_time_get)?;
    linker.func_wrap(module, "random_get", wasi_random_get)?;
    linker.func_wrap(module, "poll_oneoff", wasi_poll_oneoff)?;
    linker.func_wrap(module, "sched_yield", wasi_sched_yield)?;
    linker.func_wrap(module, "proc_exit", wasi_proc_exit)?;
    Ok(())
}

fn wasi_args_sizes_get(mut caller: Caller<'_, WasiState>, argc: i32, size: i32) -> i32 {
    let count = caller.data().arguments.len();
    let bytes = caller.data().arguments.iter().map(Vec::len).sum::<usize>();
    if write_u32_guest(&mut caller, argc, count as u32).is_err()
        || write_u32_guest(&mut caller, size, bytes as u32).is_err()
    {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_args_get(mut caller: Caller<'_, WasiState>, argv: i32, buffer: i32) -> i32 {
    let arguments = caller.data().arguments.clone();
    let argv = match guest_offset(argv) {
        Some(offset) => offset,
        None => return ERRNO_FAULT,
    };
    let mut cursor = match guest_offset(buffer) {
        Some(offset) => offset,
        None => return ERRNO_FAULT,
    };
    let argument_bytes = arguments.iter().map(Vec::len).sum::<usize>();
    if read_guest(
        &caller,
        argv,
        match arguments.len().checked_mul(4) {
            Some(length) => length,
            None => return ERRNO_FAULT,
        },
    )
    .is_err()
        || read_guest(&caller, cursor, argument_bytes).is_err()
    {
        return ERRNO_FAULT;
    }
    for (index, argument) in arguments.iter().enumerate() {
        let pointer = match u32::try_from(cursor) {
            Ok(pointer) => pointer,
            Err(_) => return ERRNO_FAULT,
        };
        if write_guest(&mut caller, argv + index * 4, &pointer.to_le_bytes()).is_err()
            || write_guest(&mut caller, cursor, argument).is_err()
        {
            return ERRNO_FAULT;
        }
        cursor += argument.len();
    }
    ERRNO_SUCCESS
}

fn wasi_environ_sizes_get(mut caller: Caller<'_, WasiState>, count: i32, size: i32) -> i32 {
    if write_u32_guest(&mut caller, count, 0).is_err()
        || write_u32_guest(&mut caller, size, 0).is_err()
    {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_environ_get(_caller: Caller<'_, WasiState>, _environ: i32, _buffer: i32) -> i32 {
    ERRNO_SUCCESS
}

fn wasi_fd_write(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    iovs: i32,
    count: i32,
    written: i32,
) -> i32 {
    let vectors = match guest_iovecs(&caller, iovs, count) {
        Ok(vectors) => vectors,
        Err(errno) => return errno,
    };
    if validate_guest_output(&caller, written, 4).is_err() {
        return ERRNO_FAULT;
    }

    if fd == 1 || fd == 2 {
        if !caller.data().stdio_open[fd as usize] {
            return ERRNO_BADF;
        }
        if caller.data().stdio_rights[fd as usize] & RIGHT_FD_WRITE == 0 {
            return ERRNO_NOTCAPABLE;
        }
        let mut output = Vec::new();
        for &(pointer, length) in &vectors {
            let bytes = match read_guest(&caller, pointer, length) {
                Ok(bytes) => bytes,
                Err(errno) => return errno,
            };
            if output
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > CHANNEL_MAX_BYTES / 2)
            {
                return ERRNO_INVAL;
            }
            output.extend_from_slice(bytes);
        }
        let amount = output.len() as u32;
        let message = if fd == 2 {
            ConsoleMessage::Error(output)
        } else {
            ConsoleMessage::Output(output)
        };
        send_console(caller.data().console, message);
        return if write_u32_guest(&mut caller, written, amount).is_ok() {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    let (handle, mut offset, flags) = match open_file(&caller, fd) {
        Ok(file) if file.filetype == FILETYPE_REGULAR_FILE => {
            if file.rights & RIGHT_FD_WRITE == 0 {
                return ERRNO_NOTCAPABLE;
            }
            (file.handle, file.offset, file.flags)
        }
        Ok(_) => return ERRNO_ISDIR,
        Err(errno) => return errno,
    };
    if flags & FDFLAG_APPEND != 0 {
        offset = match filesystem_stat(handle) {
            Ok(stat) => stat.length,
            Err(status) => return status_to_errno(status),
        };
    }

    let mut total = 0_usize;
    for &(pointer, length) in &vectors {
        let mut consumed = 0;
        while consumed < length {
            let amount = (length - consumed).min(FILESYSTEM_IO_MAX_BYTES);
            let bytes = match read_guest(&caller, pointer + consumed, amount) {
                Ok(bytes) => bytes,
                Err(errno) => return errno,
            };
            let count = match filesystem_write(handle, offset, bytes) {
                Ok(count) => count,
                Err(_status) if total != 0 => break,
                Err(status) => return status_to_errno(status),
            };
            total += count;
            offset = match offset.checked_add(count as u64) {
                Some(offset) => offset,
                None => return ERRNO_OVERFLOW,
            };
            consumed += count;
            if count < amount {
                break;
            }
        }
        if consumed < length {
            break;
        }
    }
    if let Ok(file) = open_file_mut(&mut caller, fd) {
        file.offset = offset;
    }
    if write_u32_guest(&mut caller, written, total as u32).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_read(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    iovs: i32,
    count: i32,
    read: i32,
) -> i32 {
    let vectors = match guest_iovecs(&caller, iovs, count) {
        Ok(vectors) => vectors,
        Err(errno) => return errno,
    };
    if validate_guest_output(&caller, read, 4).is_err() {
        return ERRNO_FAULT;
    }

    if fd == 0 {
        if !caller.data().stdio_open[0] {
            return ERRNO_BADF;
        }
        if caller.data().stdio_rights[0] & RIGHT_FD_READ == 0 {
            return ERRNO_NOTCAPABLE;
        }
        if vectors.iter().all(|(_, length)| *length == 0) {
            return if write_u32_guest(&mut caller, read, 0).is_ok() {
                ERRNO_SUCCESS
            } else {
                ERRNO_FAULT
            };
        }
        let (input, mut cursor) = if caller.data().stdin_cursor < caller.data().stdin_buffer.len() {
            let cursor = caller.data().stdin_cursor;
            (core::mem::take(&mut caller.data_mut().stdin_buffer), cursor)
        } else {
            caller.data_mut().stdin_buffer.clear();
            caller.data_mut().stdin_cursor = 0;
            match receive_input(caller.data().console) {
                Ok(Some(input)) => (input, 0),
                Ok(None) => return ERRNO_AGAIN,
                Err(status) => return status_to_errno(status),
            }
        };
        let start = cursor;
        for &(pointer, length) in &vectors {
            let amount = length.min(input.len().saturating_sub(cursor));
            if write_guest(&mut caller, pointer, &input[cursor..cursor + amount]).is_err() {
                caller.data_mut().stdin_buffer = input;
                caller.data_mut().stdin_cursor = cursor;
                return ERRNO_FAULT;
            }
            cursor += amount;
            if cursor == input.len() {
                break;
            }
        }
        if cursor < input.len() {
            caller.data_mut().stdin_buffer = input;
            caller.data_mut().stdin_cursor = cursor;
        } else {
            caller.data_mut().stdin_buffer.clear();
            caller.data_mut().stdin_cursor = 0;
        }
        return if write_u32_guest(&mut caller, read, (cursor - start) as u32).is_ok() {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    let (handle, mut offset) = match open_file(&caller, fd) {
        Ok(file) if file.filetype == FILETYPE_REGULAR_FILE => {
            if file.rights & RIGHT_FD_READ == 0 {
                return ERRNO_NOTCAPABLE;
            }
            (file.handle, file.offset)
        }
        Ok(_) => return ERRNO_ISDIR,
        Err(errno) => return errno,
    };
    let memory = match memory(&caller) {
        Ok(memory) => memory,
        Err(errno) => return errno,
    };
    let mut total = 0_usize;
    'vectors: for &(pointer, length) in &vectors {
        let mut filled = 0;
        while filled < length {
            let amount = (length - filled).min(FILESYSTEM_IO_MAX_BYTES);
            let target = match memory
                .data_mut(&mut caller)
                .get_mut(pointer + filled..pointer + filled + amount)
            {
                Some(target) => target,
                None => return ERRNO_FAULT,
            };
            let count = match filesystem_read(handle, offset, target) {
                Ok(count) => count,
                Err(_status) if total != 0 => break 'vectors,
                Err(status) => return status_to_errno(status),
            };
            total += count;
            offset = match offset.checked_add(count as u64) {
                Some(offset) => offset,
                None => return ERRNO_OVERFLOW,
            };
            filled += count;
            if count < amount {
                break 'vectors;
            }
        }
    }
    if let Ok(file) = open_file_mut(&mut caller, fd) {
        file.offset = offset;
    }
    if write_u32_guest(&mut caller, read, total as u32).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_close(mut caller: Caller<'_, WasiState>, fd: i32) -> i32 {
    if (0..=2).contains(&fd) {
        let was_open = core::mem::replace(&mut caller.data_mut().stdio_open[fd as usize], false);
        if fd == 0 && was_open {
            caller.data_mut().stdin_buffer.clear();
            caller.data_mut().stdin_cursor = 0;
        }
        return if was_open { ERRNO_SUCCESS } else { ERRNO_BADF };
    }
    if fd == PREOPEN_FD {
        return match caller.data_mut().preopen.take() {
            Some(handle) => status_result(handle_close(handle)),
            None => ERRNO_BADF,
        };
    }
    let slot = match file_slot(fd) {
        Some(slot) => slot,
        None => return ERRNO_BADF,
    };
    match caller.data_mut().files[slot].take() {
        Some(file) => status_result(handle_close(file.handle)),
        None => ERRNO_BADF,
    }
}

fn wasi_fd_fdstat_set_flags(mut caller: Caller<'_, WasiState>, fd: i32, flags: i32) -> i32 {
    let flags = match u16::try_from(flags) {
        Ok(flags) if flags & !SUPPORTED_FDFLAGS == 0 => flags,
        _ => return ERRNO_NOTSUP,
    };
    if (0..=2).contains(&fd) {
        if !caller.data().stdio_open[fd as usize] {
            return ERRNO_BADF;
        }
        if caller.data().stdio_rights[fd as usize] & RIGHT_FD_FDSTAT_SET_FLAGS == 0 {
            return ERRNO_NOTCAPABLE;
        }
        return if flags & !FDFLAG_NONBLOCK == 0 {
            ERRNO_SUCCESS
        } else {
            ERRNO_NOTSUP
        };
    }
    if fd == PREOPEN_FD {
        if caller.data().preopen.is_none() {
            return ERRNO_BADF;
        }
        if caller.data().preopen_rights & RIGHT_FD_FDSTAT_SET_FLAGS == 0 {
            return ERRNO_NOTCAPABLE;
        }
        if flags & FDFLAG_APPEND != 0 {
            return ERRNO_ISDIR;
        }
        caller.data_mut().preopen_flags = flags;
        return ERRNO_SUCCESS;
    }
    let file = match open_file_mut(&mut caller, fd) {
        Ok(file) => file,
        Err(errno) => return errno,
    };
    if file.rights & RIGHT_FD_FDSTAT_SET_FLAGS == 0 {
        return ERRNO_NOTCAPABLE;
    }
    if file.filetype == FILETYPE_DIRECTORY && flags & FDFLAG_APPEND != 0 {
        return ERRNO_ISDIR;
    }
    file.flags = flags;
    ERRNO_SUCCESS
}

fn wasi_fd_fdstat_set_rights(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    rights_base: i64,
    rights_inheriting: i64,
) -> i32 {
    let rights_base = rights_base as u64;
    let rights_inheriting = rights_inheriting as u64;
    if (0..=2).contains(&fd) {
        if !caller.data().stdio_open[fd as usize] {
            return ERRNO_BADF;
        }
        let current = caller.data().stdio_rights[fd as usize];
        if rights_base & !current != 0 || rights_inheriting != 0 {
            return ERRNO_NOTCAPABLE;
        }
        caller.data_mut().stdio_rights[fd as usize] = rights_base;
        return ERRNO_SUCCESS;
    }
    if fd == PREOPEN_FD {
        if caller.data().preopen.is_none() {
            return ERRNO_BADF;
        }
        if rights_base & !caller.data().preopen_rights != 0
            || rights_inheriting & !caller.data().preopen_inheriting_rights != 0
        {
            return ERRNO_NOTCAPABLE;
        }
        caller.data_mut().preopen_rights = rights_base;
        caller.data_mut().preopen_inheriting_rights = rights_inheriting;
        return ERRNO_SUCCESS;
    }
    let file = match open_file_mut(&mut caller, fd) {
        Ok(file) => file,
        Err(errno) => return errno,
    };
    if rights_base & !file.rights != 0 || rights_inheriting & !file.inheriting_rights != 0 {
        return ERRNO_NOTCAPABLE;
    }
    file.rights = rights_base;
    file.inheriting_rights = rights_inheriting;
    ERRNO_SUCCESS
}

fn wasi_fd_fdstat_get(mut caller: Caller<'_, WasiState>, fd: i32, output: i32) -> i32 {
    let (filetype, flags, rights, inheriting) = if (0..=2).contains(&fd) {
        if !caller.data().stdio_open[fd as usize] {
            return ERRNO_BADF;
        }
        (
            FILETYPE_CHARACTER_DEVICE,
            FDFLAG_NONBLOCK,
            caller.data().stdio_rights[fd as usize],
            0,
        )
    } else if fd == PREOPEN_FD {
        if caller.data().preopen.is_none() {
            return ERRNO_BADF;
        }
        (
            FILETYPE_DIRECTORY,
            caller.data().preopen_flags,
            caller.data().preopen_rights,
            caller.data().preopen_inheriting_rights,
        )
    } else {
        match open_file(&caller, fd) {
            Ok(file) => (
                file.filetype,
                file.flags,
                file.rights,
                file.inheriting_rights,
            ),
            Err(errno) => return errno,
        }
    };
    let mut stat = [0_u8; 24];
    stat[0] = filetype;
    stat[2..4].copy_from_slice(&flags.to_le_bytes());
    stat[8..16].copy_from_slice(&rights.to_le_bytes());
    stat[16..24].copy_from_slice(&inheriting.to_le_bytes());
    write_guest_result(&mut caller, output, &stat)
}

fn wasi_fd_prestat_get(mut caller: Caller<'_, WasiState>, fd: i32, output: i32) -> i32 {
    if fd != PREOPEN_FD || caller.data().preopen.is_none() {
        return ERRNO_BADF;
    }
    let mut prestat = [0_u8; 8];
    prestat[4..8].copy_from_slice(&1_u32.to_le_bytes());
    write_guest_result(&mut caller, output, &prestat)
}

fn wasi_fd_prestat_dir_name(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    path: i32,
    path_length: i32,
) -> i32 {
    if fd != PREOPEN_FD || caller.data().preopen.is_none() {
        return ERRNO_BADF;
    }
    let length = path_length as u32 as usize;
    if length < 1 {
        return ERRNO_NAMETOOLONG;
    }
    if validate_guest_output(&caller, path, length).is_err() {
        return ERRNO_FAULT;
    }
    match guest_offset(path).and_then(|offset| write_guest(&mut caller, offset, b"/").ok()) {
        Some(()) => ERRNO_SUCCESS,
        None => ERRNO_FAULT,
    }
}

fn wasi_fd_seek(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    delta: i64,
    whence: i32,
    output: i32,
) -> i32 {
    if validate_guest_output(&caller, output, 8).is_err() {
        return ERRNO_FAULT;
    }
    let file = match open_file(&caller, fd) {
        Ok(file) if file.filetype == FILETYPE_REGULAR_FILE => file,
        Ok(_) => return ERRNO_NOTSUP,
        Err(errno) => return errno,
    };
    if file.rights & RIGHT_FD_SEEK == 0 {
        return ERRNO_NOTCAPABLE;
    }
    let base = match whence {
        0 => 0,
        1 => file.offset,
        2 => match filesystem_stat(file.handle) {
            Ok(stat) => stat.length,
            Err(status) => return status_to_errno(status),
        },
        _ => return ERRNO_INVAL,
    };
    let offset = i128::from(base) + i128::from(delta);
    let offset = match u64::try_from(offset) {
        Ok(offset) => offset,
        Err(_) => return ERRNO_INVAL,
    };
    match open_file_mut(&mut caller, fd) {
        Ok(file) => file.offset = offset,
        Err(errno) => return errno,
    }
    if write_u64_guest(&mut caller, output, offset).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_tell(mut caller: Caller<'_, WasiState>, fd: i32, output: i32) -> i32 {
    if validate_guest_output(&caller, output, 8).is_err() {
        return ERRNO_FAULT;
    }
    let offset = match open_file(&caller, fd) {
        Ok(file) if file.filetype != FILETYPE_REGULAR_FILE => return ERRNO_NOTSUP,
        Ok(file) if file.rights & RIGHT_FD_TELL == 0 => return ERRNO_NOTCAPABLE,
        Ok(file) => file.offset,
        Err(errno) => return errno,
    };
    if write_u64_guest(&mut caller, output, offset).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_pread(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    iovs: i32,
    count: i32,
    offset: i64,
    read: i32,
) -> i32 {
    let vectors = match guest_iovecs(&caller, iovs, count) {
        Ok(vectors) => vectors,
        Err(errno) => return errno,
    };
    if validate_guest_output(&caller, read, 4).is_err() {
        return ERRNO_FAULT;
    }
    let handle = match open_file(&caller, fd) {
        Ok(file) if file.filetype != FILETYPE_REGULAR_FILE => return ERRNO_ISDIR,
        Ok(file) if file.rights & RIGHT_FD_READ == 0 => return ERRNO_NOTCAPABLE,
        Ok(file) => file.handle,
        Err(errno) => return errno,
    };
    let memory = match memory(&caller) {
        Ok(memory) => memory,
        Err(errno) => return errno,
    };
    let mut offset = offset as u64;
    let mut total = 0_usize;
    'vectors: for &(pointer, length) in &vectors {
        let mut filled = 0;
        while filled < length {
            let amount = (length - filled).min(FILESYSTEM_IO_MAX_BYTES);
            let target = match memory
                .data_mut(&mut caller)
                .get_mut(pointer + filled..pointer + filled + amount)
            {
                Some(target) => target,
                None => return ERRNO_FAULT,
            };
            let count = match filesystem_read(handle, offset, target) {
                Ok(count) => count,
                Err(_) if total != 0 => break 'vectors,
                Err(status) => return status_to_errno(status),
            };
            total += count;
            offset = match offset.checked_add(count as u64) {
                Some(offset) => offset,
                None => return ERRNO_OVERFLOW,
            };
            filled += count;
            if count < amount {
                break 'vectors;
            }
        }
    }
    if write_u32_guest(&mut caller, read, total as u32).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_pwrite(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    iovs: i32,
    count: i32,
    offset: i64,
    written: i32,
) -> i32 {
    let vectors = match guest_iovecs(&caller, iovs, count) {
        Ok(vectors) => vectors,
        Err(errno) => return errno,
    };
    if validate_guest_output(&caller, written, 4).is_err() {
        return ERRNO_FAULT;
    }
    let handle = match open_file(&caller, fd) {
        Ok(file) if file.filetype != FILETYPE_REGULAR_FILE => return ERRNO_ISDIR,
        Ok(file) if file.rights & RIGHT_FD_WRITE == 0 => return ERRNO_NOTCAPABLE,
        Ok(file) if file.flags & FDFLAG_APPEND != 0 => return ERRNO_NOTSUP,
        Ok(file) => file.handle,
        Err(errno) => return errno,
    };
    let mut offset = offset as u64;
    let mut total = 0_usize;
    'vectors: for &(pointer, length) in &vectors {
        let mut consumed = 0;
        while consumed < length {
            let amount = (length - consumed).min(FILESYSTEM_IO_MAX_BYTES);
            let bytes = match read_guest(&caller, pointer + consumed, amount) {
                Ok(bytes) => bytes,
                Err(errno) => return errno,
            };
            let count = match filesystem_write(handle, offset, bytes) {
                Ok(count) => count,
                Err(_) if total != 0 => break 'vectors,
                Err(status) => return status_to_errno(status),
            };
            total += count;
            offset = match offset.checked_add(count as u64) {
                Some(offset) => offset,
                None => return ERRNO_OVERFLOW,
            };
            consumed += count;
            if count < amount {
                break 'vectors;
            }
        }
    }
    if write_u32_guest(&mut caller, written, total as u32).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_fd_filestat_get(mut caller: Caller<'_, WasiState>, fd: i32, output: i32) -> i32 {
    if (0..=2).contains(&fd) {
        if !caller.data().stdio_open[fd as usize] {
            return ERRNO_BADF;
        }
        if caller.data().stdio_rights[fd as usize] & RIGHT_FD_FILESTAT_GET == 0 {
            return ERRNO_NOTCAPABLE;
        }
        return write_guest_result(
            &mut caller,
            output,
            &wasi_fd_filestat(FILETYPE_CHARACTER_DEVICE, 0),
        );
    }
    let (handle, filetype) = match fd_handle_with_right(&caller, fd, RIGHT_FD_FILESTAT_GET) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    let size = match filesystem_stat(handle) {
        Ok(stat) => stat.length,
        Err(status) => return status_to_errno(status),
    };
    write_guest_result(&mut caller, output, &wasi_fd_filestat(filetype, size))
}

fn wasi_fd_filestat_set_size(caller: Caller<'_, WasiState>, fd: i32, size: i64) -> i32 {
    let (handle, filetype) = match fd_handle_with_right(&caller, fd, RIGHT_FD_FILESTAT_SET_SIZE) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    if filetype != FILETYPE_REGULAR_FILE {
        return ERRNO_ISDIR;
    }
    status_result(filesystem_truncate(handle, size as u64))
}

fn wasi_fd_sync(caller: Caller<'_, WasiState>, fd: i32) -> i32 {
    let (handle, _) = match fd_handle_with_right(&caller, fd, RIGHT_FD_SYNC) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    status_result(filesystem_sync(handle))
}

fn wasi_fd_datasync(caller: Caller<'_, WasiState>, fd: i32) -> i32 {
    let (handle, filetype) = match fd_handle_with_right(&caller, fd, RIGHT_FD_DATASYNC) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    if filetype != FILETYPE_REGULAR_FILE {
        return ERRNO_ISDIR;
    }
    status_result(filesystem_sync(handle))
}

fn wasi_fd_advise(
    caller: Caller<'_, WasiState>,
    fd: i32,
    offset: i64,
    length: i64,
    advice: i32,
) -> i32 {
    if !(0..=5).contains(&advice) || (offset as u64).checked_add(length as u64).is_none() {
        return ERRNO_INVAL;
    }
    let (_, filetype) = match fd_handle_with_right(&caller, fd, RIGHT_FD_ADVISE) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    if filetype != FILETYPE_REGULAR_FILE {
        return ERRNO_ISDIR;
    }
    ERRNO_SUCCESS
}

fn wasi_fd_readdir(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    buffer: i32,
    buffer_length: i32,
    cookie: i64,
    used: i32,
) -> i32 {
    let buffer_length = buffer_length as u32 as usize;
    if validate_guest_output(&caller, buffer, buffer_length).is_err()
        || validate_guest_output(&caller, used, 4).is_err()
    {
        return ERRNO_FAULT;
    }
    let (directory, filetype) = match fd_handle_with_right(&caller, fd, RIGHT_FD_READDIR) {
        Ok(descriptor) => descriptor,
        Err(errno) => return errno,
    };
    if filetype != FILETYPE_DIRECTORY {
        return ERRNO_NOTDIR;
    }
    let base = match guest_offset(buffer) {
        Some(base) => base,
        None => return ERRNO_FAULT,
    };
    let mut cookie = cookie as u64;
    let mut cursor = 0_usize;
    while cursor < buffer_length {
        let entry = match filesystem_read_directory2(directory, cookie) {
            Ok(entry) => entry,
            Err(Status::EndOfDirectory) => break,
            Err(status) => return status_to_errno(status),
        };
        let name_length = usize::from(entry.name_length).min(entry.name.len());
        let mut dirent = [0_u8; 24];
        dirent[0..8].copy_from_slice(&entry.next_cookie.to_le_bytes());
        dirent[8..16].copy_from_slice(&entry.stable_id.to_le_bytes());
        dirent[16..20].copy_from_slice(&(name_length as u32).to_le_bytes());
        dirent[20] = wasi_filetype(entry.entry_kind());

        let header_count = dirent.len().min(buffer_length - cursor);
        if write_guest(&mut caller, base + cursor, &dirent[..header_count]).is_err() {
            return ERRNO_FAULT;
        }
        cursor += header_count;
        if header_count < dirent.len() {
            break;
        }
        let name_count = name_length.min(buffer_length - cursor);
        if write_guest(&mut caller, base + cursor, &entry.name[..name_count]).is_err() {
            return ERRNO_FAULT;
        }
        cursor += name_count;
        if name_count < name_length {
            break;
        }
        cookie = entry.next_cookie;
    }
    if write_u32_guest(&mut caller, used, cursor as u32).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_path_filestat_get(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    lookup_flags: i32,
    path: i32,
    path_length: i32,
    output: i32,
) -> i32 {
    if lookup_flags as u32 & !1 != 0 {
        return ERRNO_INVAL;
    }
    let path = match guest_path(&caller, path, path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let anchor = match directory_anchor(&caller, fd, RIGHT_PATH_FILESTAT_GET) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    let metadata = match filesystem_get_metadata(anchor, &path) {
        Ok(metadata) => metadata,
        Err(status) => return status_to_errno(status),
    };
    let stat = wasi_filestat(metadata);
    write_guest_result(&mut caller, output, &stat)
}

#[allow(clippy::too_many_arguments)]
fn wasi_path_open(
    mut caller: Caller<'_, WasiState>,
    fd: i32,
    lookup_flags: i32,
    path: i32,
    path_length: i32,
    oflags: i32,
    rights_base: i64,
    rights_inheriting: i64,
    fdflags: i32,
    output: i32,
) -> i32 {
    if lookup_flags as u32 & !1 != 0 {
        return ERRNO_INVAL;
    }
    let oflags = match u16::try_from(oflags) {
        Ok(flags) if flags & !(OFLAG_CREAT | OFLAG_DIRECTORY | OFLAG_EXCL | OFLAG_TRUNC) == 0 => {
            flags
        }
        _ => return ERRNO_INVAL,
    };
    if oflags & OFLAG_EXCL != 0 {
        return ERRNO_NOTSUP;
    }
    let fdflags = match u16::try_from(fdflags) {
        Ok(flags) if flags & !SUPPORTED_FDFLAGS == 0 => flags,
        _ => return ERRNO_NOTSUP,
    };
    if validate_guest_output(&caller, output, 4).is_err() {
        return ERRNO_FAULT;
    }
    let path = match guest_path(&caller, path, path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let mut needed_directory_right = RIGHT_PATH_OPEN;
    if oflags & OFLAG_CREAT != 0 {
        needed_directory_right |= RIGHT_PATH_CREATE_FILE;
    }
    if oflags & OFLAG_TRUNC != 0 {
        needed_directory_right |= RIGHT_PATH_FILESTAT_SET_SIZE;
    }
    let anchor = match directory_anchor(&caller, fd, needed_directory_right) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    let slot = match caller.data().files.iter().position(Option::is_none) {
        Some(slot) => slot,
        None => return ERRNO_MFILE,
    };
    let requested_rights = rights_base as u64;
    let requested_inheriting = rights_inheriting as u64;
    let parent_inheriting = match directory_inheriting_rights(&caller, fd) {
        Ok(rights) => rights,
        Err(errno) => return errno,
    };

    let (handle, filetype, granted_rights, granted_inheriting) = if oflags & OFLAG_DIRECTORY != 0 {
        if oflags & (OFLAG_CREAT | OFLAG_TRUNC) != 0 || fdflags & FDFLAG_APPEND != 0 {
            return ERRNO_INVAL;
        }
        let granted_rights = requested_rights & parent_inheriting & DIRECTORY_RIGHTS;
        let granted_inheriting =
            requested_inheriting & parent_inheriting & (FILE_RIGHTS | DIRECTORY_RIGHTS);
        let handle = match filesystem_open_directory(anchor, &path) {
            Ok(handle) => handle,
            Err(status) => return status_to_errno(status),
        };
        (
            handle,
            FILETYPE_DIRECTORY,
            granted_rights,
            granted_inheriting,
        )
    } else {
        let granted_rights = requested_rights & parent_inheriting & FILE_RIGHTS;
        let mut flags = FilesystemOpenFlags::empty();
        if granted_rights & RIGHT_FD_READ != 0 {
            flags |= FilesystemOpenFlags::READ;
        }
        if granted_rights & (RIGHT_FD_WRITE | RIGHT_FD_FILESTAT_SET_SIZE) != 0 {
            flags |= FilesystemOpenFlags::WRITE;
        }
        if flags.is_empty() {
            flags |= FilesystemOpenFlags::READ;
        }
        if oflags & OFLAG_CREAT != 0 {
            if granted_rights & RIGHT_FD_WRITE == 0 {
                return ERRNO_NOTCAPABLE;
            }
            flags |= FilesystemOpenFlags::CREATE;
        }
        if oflags & OFLAG_TRUNC != 0 {
            if granted_rights & RIGHT_FD_WRITE == 0 {
                return ERRNO_NOTCAPABLE;
            }
            flags |= FilesystemOpenFlags::TRUNCATE;
        }
        let handle = match filesystem_open(anchor, &path, flags) {
            Ok(handle) => handle,
            Err(status) => return status_to_errno(status),
        };
        (handle, FILETYPE_REGULAR_FILE, granted_rights, 0)
    };

    caller.data_mut().files[slot] = Some(OpenFile {
        handle,
        offset: 0,
        rights: granted_rights,
        inheriting_rights: granted_inheriting,
        flags: fdflags,
        filetype,
    });
    let guest_fd = FIRST_FILE_FD + slot as i32;
    if write_u32_guest(&mut caller, output, guest_fd as u32).is_err() {
        if let Some(file) = caller.data_mut().files[slot].take() {
            let _ = handle_close(file.handle);
        }
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_path_create_directory(
    caller: Caller<'_, WasiState>,
    fd: i32,
    path: i32,
    path_length: i32,
) -> i32 {
    let path = match guest_path(&caller, path, path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let anchor = match directory_anchor(&caller, fd, RIGHT_PATH_CREATE_DIRECTORY) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    status_result(filesystem_create_directory(anchor, &path))
}

fn wasi_path_remove_directory(
    caller: Caller<'_, WasiState>,
    fd: i32,
    path: i32,
    path_length: i32,
) -> i32 {
    let path = match guest_path(&caller, path, path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let anchor = match directory_anchor(&caller, fd, RIGHT_PATH_REMOVE_DIRECTORY) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    status_result(filesystem_remove_directory(anchor, &path))
}

fn wasi_path_unlink_file(
    caller: Caller<'_, WasiState>,
    fd: i32,
    path: i32,
    path_length: i32,
) -> i32 {
    let path = match guest_path(&caller, path, path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let anchor = match directory_anchor(&caller, fd, RIGHT_PATH_UNLINK_FILE) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    status_result(filesystem_unlink(anchor, &path))
}

#[allow(clippy::too_many_arguments)]
fn wasi_path_rename(
    caller: Caller<'_, WasiState>,
    old_fd: i32,
    old_path: i32,
    old_path_length: i32,
    new_fd: i32,
    new_path: i32,
    new_path_length: i32,
) -> i32 {
    let old_path = match guest_path(&caller, old_path, old_path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let new_path = match guest_path(&caller, new_path, new_path_length) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    let old_anchor = match directory_anchor(&caller, old_fd, RIGHT_PATH_RENAME_SOURCE) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    let new_anchor = match directory_anchor(&caller, new_fd, RIGHT_PATH_RENAME_TARGET) {
        Ok(anchor) => anchor,
        Err(errno) => return errno,
    };
    status_result(filesystem_rename(
        old_anchor,
        &old_path,
        new_anchor,
        &new_path,
        FilesystemRenameFlags::REPLACE,
    ))
}

fn wasi_clock_res_get(mut caller: Caller<'_, WasiState>, clock: i32, output: i32) -> i32 {
    if clock != 1 {
        return ERRNO_NOSYS;
    }
    if write_u64_guest(&mut caller, output, 1).is_err() {
        ERRNO_FAULT
    } else {
        ERRNO_SUCCESS
    }
}

fn wasi_clock_time_get(
    mut caller: Caller<'_, WasiState>,
    clock: i32,
    _precision: i64,
    output: i32,
) -> i32 {
    if clock != 1 {
        return ERRNO_NOSYS;
    }
    let time = match monotonic_time_ns() {
        Ok(time) => time,
        Err(_) => return ERRNO_IO,
    };
    match guest_offset(output)
        .and_then(|offset| write_guest(&mut caller, offset, &time.to_le_bytes()).ok())
    {
        Some(()) => ERRNO_SUCCESS,
        None => ERRNO_FAULT,
    }
}

fn wasi_poll_oneoff(
    mut caller: Caller<'_, WasiState>,
    subscriptions: i32,
    events: i32,
    subscription_count: i32,
    event_count: i32,
) -> i32 {
    let subscription_count = subscription_count as u32 as usize;
    if subscription_count == 0 || subscription_count > MAX_POLL_SUBSCRIPTIONS {
        return ERRNO_INVAL;
    }
    let subscriptions_length = match subscription_count.checked_mul(WASI_SUBSCRIPTION_SIZE) {
        Some(length) => length,
        None => return ERRNO_INVAL,
    };
    let events_length = match subscription_count.checked_mul(WASI_EVENT_SIZE) {
        Some(length) => length,
        None => return ERRNO_INVAL,
    };
    let subscriptions_offset = match guest_offset(subscriptions) {
        Some(offset) => offset,
        None => return ERRNO_FAULT,
    };
    if read_guest(&caller, subscriptions_offset, subscriptions_length).is_err()
        || validate_guest_output(&caller, events, events_length).is_err()
        || validate_guest_output(&caller, event_count, 4).is_err()
    {
        return ERRNO_FAULT;
    }
    let start = match monotonic_time_ns() {
        Ok(time) => time,
        Err(status) => return status_to_errno(status),
    };
    let mut parsed = Vec::with_capacity(subscription_count);
    for index in 0..subscription_count {
        let offset = subscriptions_offset + index * WASI_SUBSCRIPTION_SIZE;
        let bytes = match read_guest(&caller, offset, WASI_SUBSCRIPTION_SIZE) {
            Ok(bytes) => bytes,
            Err(errno) => return errno,
        };
        let userdata = match read_u64(bytes, 0) {
            Some(userdata) => userdata,
            None => return ERRNO_FAULT,
        };
        let kind = match bytes[8] {
            EVENTTYPE_CLOCK => {
                if read_u32(bytes, 16) != Some(1) {
                    return ERRNO_INVAL;
                }
                let timeout = match read_u64(bytes, 24) {
                    Some(timeout) => timeout,
                    None => return ERRNO_FAULT,
                };
                let flags = match read_u16(bytes, 40) {
                    Some(flags) if flags & !SUBCLOCKFLAG_ABSTIME == 0 => flags,
                    Some(_) => return ERRNO_INVAL,
                    None => return ERRNO_FAULT,
                };
                let deadline = if flags & SUBCLOCKFLAG_ABSTIME != 0 {
                    timeout
                } else {
                    start.saturating_add(timeout)
                };
                PollSubscriptionKind::Clock { deadline }
            }
            EVENTTYPE_FD_READ => {
                let fd = match read_u32(bytes, 16) {
                    Some(fd) => fd as i32,
                    None => return ERRNO_FAULT,
                };
                PollSubscriptionKind::FdRead { fd }
            }
            EVENTTYPE_FD_WRITE => {
                let fd = match read_u32(bytes, 16) {
                    Some(fd) => fd as i32,
                    None => return ERRNO_FAULT,
                };
                PollSubscriptionKind::FdWrite { fd }
            }
            _ => return ERRNO_INVAL,
        };
        parsed.push(PollSubscription { userdata, kind });
    }

    let mut console_pending = Signals::empty();
    let mut stdin_error = None;
    loop {
        let now = match monotonic_time_ns() {
            Ok(time) => time,
            Err(status) => return status_to_errno(status),
        };
        let ready = collect_poll_events(&caller, &parsed, now, console_pending, stdin_error);
        if !ready.is_empty() {
            let wait_signals = poll_console_wait_signals(&caller, &parsed);
            let console = caller.data().console;
            if console_pending.is_empty() && !wait_signals.is_empty() && console.is_valid() {
                let mut item = [WaitItem::new(console, wait_signals | Signals::PEER_CLOSED)];
                match wait_many(&mut item, now.min(DEADLINE_INFINITE as u64) as i64) {
                    Ok(_) => {
                        console_pending = item[0].pending;
                        stdin_error = None;
                        if console_pending.contains(Signals::READABLE)
                            && caller.data().stdin_cursor >= caller.data().stdin_buffer.len()
                        {
                            match receive_input(console) {
                                Ok(Some(input)) => {
                                    caller.data_mut().stdin_buffer = input;
                                    caller.data_mut().stdin_cursor = 0;
                                }
                                Ok(None) => console_pending.remove(Signals::READABLE),
                                Err(Status::PeerClosed) => console_pending |= Signals::PEER_CLOSED,
                                Err(status) => stdin_error = Some(status_to_errno(status)),
                            }
                        }
                        continue;
                    }
                    Err(Status::TimedOut) => {}
                    Err(status) => return status_to_errno(status),
                }
            }
            let event_offset = match guest_offset(events) {
                Some(offset) => offset,
                None => return ERRNO_FAULT,
            };
            for (index, event) in ready.iter().enumerate() {
                if write_guest(&mut caller, event_offset + index * WASI_EVENT_SIZE, event).is_err()
                {
                    return ERRNO_FAULT;
                }
            }
            return if write_u32_guest(&mut caller, event_count, ready.len() as u32).is_ok() {
                ERRNO_SUCCESS
            } else {
                ERRNO_FAULT
            };
        }

        let deadline = parsed
            .iter()
            .filter_map(|subscription| match subscription.kind {
                PollSubscriptionKind::Clock { deadline } => Some(deadline),
                _ => None,
            })
            .min();
        let wait_signals = poll_console_wait_signals(&caller, &parsed);
        let console = caller.data().console;
        if !console.is_valid() {
            if deadline.is_none() {
                return ERRNO_BADF;
            }
            let _ = process_yield();
            console_pending = Signals::empty();
            stdin_error = None;
            continue;
        }
        let wait_for = if wait_signals.is_empty() {
            Signals::READABLE | Signals::PEER_CLOSED
        } else {
            wait_signals | Signals::PEER_CLOSED
        };
        let mut item = [WaitItem::new(console, wait_for)];
        let deadline_ns = deadline
            .map(|deadline| deadline.min(DEADLINE_INFINITE as u64) as i64)
            .unwrap_or(DEADLINE_INFINITE);
        match wait_many(&mut item, deadline_ns) {
            Ok(_) => console_pending = item[0].pending,
            Err(Status::TimedOut) => console_pending = Signals::empty(),
            Err(status) => return status_to_errno(status),
        }
        stdin_error = None;
        if console_pending.contains(Signals::READABLE)
            && caller.data().stdin_cursor >= caller.data().stdin_buffer.len()
        {
            match receive_input(console) {
                Ok(Some(input)) => {
                    caller.data_mut().stdin_buffer = input;
                    caller.data_mut().stdin_cursor = 0;
                }
                Ok(None) => console_pending.remove(Signals::READABLE),
                Err(Status::PeerClosed) => console_pending |= Signals::PEER_CLOSED,
                Err(status) => stdin_error = Some(status_to_errno(status)),
            }
        }
    }
}

fn collect_poll_events(
    caller: &Caller<'_, WasiState>,
    subscriptions: &[PollSubscription],
    now: u64,
    console_pending: Signals,
    stdin_error: Option<i32>,
) -> Vec<[u8; WASI_EVENT_SIZE]> {
    let mut events = Vec::new();
    for subscription in subscriptions {
        let result = match subscription.kind {
            PollSubscriptionKind::Clock { deadline } if now >= deadline => {
                Some((ERRNO_SUCCESS, EVENTTYPE_CLOCK, 0, 0))
            }
            PollSubscriptionKind::Clock { .. } => None,
            PollSubscriptionKind::FdRead { fd } => {
                poll_fd_event(caller, fd, EVENTTYPE_FD_READ, console_pending, stdin_error)
            }
            PollSubscriptionKind::FdWrite { fd } => {
                poll_fd_event(caller, fd, EVENTTYPE_FD_WRITE, console_pending, None)
            }
        };
        if let Some((errno, event_type, nbytes, flags)) = result {
            events.push(wasi_event(
                subscription.userdata,
                errno,
                event_type,
                nbytes,
                flags,
            ));
        }
    }
    events
}

fn poll_fd_event(
    caller: &Caller<'_, WasiState>,
    fd: i32,
    event_type: u8,
    console_pending: Signals,
    stdin_error: Option<i32>,
) -> Option<(i32, u8, u64, u16)> {
    if (0..=2).contains(&fd) {
        if !caller.data().stdio_open[fd as usize] {
            return Some((ERRNO_BADF, event_type, 0, 0));
        }
        let needed_right = if event_type == EVENTTYPE_FD_READ {
            RIGHT_FD_READ
        } else {
            RIGHT_FD_WRITE
        };
        let rights = caller.data().stdio_rights[fd as usize];
        if rights & RIGHT_POLL_FD_READWRITE == 0 || rights & needed_right == 0 {
            return Some((ERRNO_NOTCAPABLE, event_type, 0, 0));
        }
        if !caller.data().console.is_valid() {
            return Some((ERRNO_BADF, event_type, 0, 0));
        }
        if event_type == EVENTTYPE_FD_READ {
            if let Some(errno) = stdin_error {
                return Some((errno, event_type, 0, 0));
            }
            let buffered = caller
                .data()
                .stdin_buffer
                .len()
                .saturating_sub(caller.data().stdin_cursor);
            if buffered != 0 {
                return Some((ERRNO_SUCCESS, event_type, buffered as u64, 0));
            }
        }
        if console_pending.contains(Signals::PEER_CLOSED) {
            return Some((ERRNO_SUCCESS, event_type, 0, 1));
        }
        let signal = if event_type == EVENTTYPE_FD_READ {
            Signals::READABLE
        } else {
            Signals::WRITABLE
        };
        return console_pending
            .contains(signal)
            .then_some((ERRNO_SUCCESS, event_type, 0, 0));
    }

    let (handle, filetype, rights, offset) = if fd == PREOPEN_FD {
        match caller.data().preopen {
            Some(handle) => (handle, FILETYPE_DIRECTORY, caller.data().preopen_rights, 0),
            None => return Some((ERRNO_BADF, event_type, 0, 0)),
        }
    } else {
        match open_file(caller, fd) {
            Ok(file) => (file.handle, file.filetype, file.rights, file.offset),
            Err(_) => return Some((ERRNO_BADF, event_type, 0, 0)),
        }
    };
    if rights & RIGHT_POLL_FD_READWRITE == 0 {
        return Some((ERRNO_NOTCAPABLE, event_type, 0, 0));
    }
    let nbytes = if event_type == EVENTTYPE_FD_READ && filetype == FILETYPE_REGULAR_FILE {
        match filesystem_stat(handle) {
            Ok(stat) => stat.length.saturating_sub(offset),
            Err(status) => return Some((status_to_errno(status), event_type, 0, 0)),
        }
    } else {
        0
    };
    Some((ERRNO_SUCCESS, event_type, nbytes, 0))
}

fn poll_console_wait_signals(
    caller: &Caller<'_, WasiState>,
    subscriptions: &[PollSubscription],
) -> Signals {
    let mut signals = Signals::empty();
    for subscription in subscriptions {
        let (fd, event_type) = match subscription.kind {
            PollSubscriptionKind::FdRead { fd } => (fd, EVENTTYPE_FD_READ),
            PollSubscriptionKind::FdWrite { fd } => (fd, EVENTTYPE_FD_WRITE),
            PollSubscriptionKind::Clock { .. } => continue,
        };
        if !(0..=2).contains(&fd) || !caller.data().stdio_open[fd as usize] {
            continue;
        }
        let needed_right = if event_type == EVENTTYPE_FD_READ {
            RIGHT_FD_READ
        } else {
            RIGHT_FD_WRITE
        };
        let rights = caller.data().stdio_rights[fd as usize];
        if rights & RIGHT_POLL_FD_READWRITE == 0 || rights & needed_right == 0 {
            continue;
        }
        signals |= if event_type == EVENTTYPE_FD_READ {
            Signals::READABLE
        } else {
            Signals::WRITABLE
        };
    }
    signals
}

fn wasi_event(userdata: u64, errno: i32, event_type: u8, nbytes: u64, flags: u16) -> [u8; 32] {
    let mut event = [0_u8; WASI_EVENT_SIZE];
    event[0..8].copy_from_slice(&userdata.to_le_bytes());
    event[8..10].copy_from_slice(&(errno as u16).to_le_bytes());
    event[10] = event_type;
    event[16..24].copy_from_slice(&nbytes.to_le_bytes());
    event[24..26].copy_from_slice(&flags.to_le_bytes());
    event
}

fn wasi_random_get(mut caller: Caller<'_, WasiState>, buffer: i32, length: i32) -> i32 {
    let length = length as u32 as usize;
    if validate_guest_output(&caller, buffer, length).is_err() {
        return ERRNO_FAULT;
    }
    let source = match caller.data().random {
        Some(source) => source,
        None => return ERRNO_NOTCAPABLE,
    };
    let memory = match memory(&caller) {
        Ok(memory) => memory,
        Err(errno) => return errno,
    };
    let base = match guest_offset(buffer) {
        Some(base) => base,
        None => return ERRNO_FAULT,
    };
    let mut filled = 0;
    while filled < length {
        let amount = (length - filled).min(RANDOM_MAX_BYTES);
        let target = match memory
            .data_mut(&mut caller)
            .get_mut(base + filled..base + filled + amount)
        {
            Some(target) => target,
            None => return ERRNO_FAULT,
        };
        if let Err(status) = random_fill(source, target) {
            return status_to_errno(status);
        }
        filled += amount;
    }
    ERRNO_SUCCESS
}

fn wasi_sched_yield(_caller: Caller<'_, WasiState>) -> i32 {
    let _ = process_yield();
    ERRNO_SUCCESS
}

fn wasi_proc_exit(_caller: Caller<'_, WasiState>, status: i32) -> Result<(), Error> {
    Err(Error::i32_exit(status))
}

fn memory(caller: &Caller<'_, WasiState>) -> Result<Memory, i32> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(ERRNO_FAULT)
}

fn read_guest<'a>(
    caller: &'a Caller<'_, WasiState>,
    offset: usize,
    length: usize,
) -> Result<&'a [u8], i32> {
    memory(caller)?
        .data(caller)
        .get(offset..offset.checked_add(length).ok_or(ERRNO_FAULT)?)
        .ok_or(ERRNO_FAULT)
}

fn write_guest(caller: &mut Caller<'_, WasiState>, offset: usize, bytes: &[u8]) -> Result<(), i32> {
    let memory = memory(caller)?;
    let end = offset.checked_add(bytes.len()).ok_or(ERRNO_FAULT)?;
    let target = memory
        .data_mut(caller)
        .get_mut(offset..end)
        .ok_or(ERRNO_FAULT)?;
    target.copy_from_slice(bytes);
    Ok(())
}

fn read_u32_guest(caller: &Caller<'_, WasiState>, offset: usize) -> Result<u32, i32> {
    let bytes: [u8; 4] = read_guest(caller, offset, 4)?
        .try_into()
        .map_err(|_| ERRNO_FAULT)?;
    Ok(u32::from_le_bytes(bytes))
}

fn write_u32_guest(caller: &mut Caller<'_, WasiState>, offset: i32, value: u32) -> Result<(), i32> {
    write_guest(
        caller,
        guest_offset(offset).ok_or(ERRNO_FAULT)?,
        &value.to_le_bytes(),
    )
}

fn write_u64_guest(caller: &mut Caller<'_, WasiState>, offset: i32, value: u64) -> Result<(), i32> {
    write_guest(
        caller,
        guest_offset(offset).ok_or(ERRNO_FAULT)?,
        &value.to_le_bytes(),
    )
}

fn write_guest_result(caller: &mut Caller<'_, WasiState>, offset: i32, bytes: &[u8]) -> i32 {
    match guest_offset(offset).and_then(|offset| write_guest(caller, offset, bytes).ok()) {
        Some(()) => ERRNO_SUCCESS,
        None => ERRNO_FAULT,
    }
}

fn validate_guest_output(
    caller: &Caller<'_, WasiState>,
    offset: i32,
    length: usize,
) -> Result<(), i32> {
    read_guest(caller, guest_offset(offset).ok_or(ERRNO_FAULT)?, length).map(|_| ())
}

fn guest_iovecs(
    caller: &Caller<'_, WasiState>,
    iovs: i32,
    count: i32,
) -> Result<Vec<(usize, usize)>, i32> {
    let count = usize::try_from(count).map_err(|_| ERRNO_INVAL)?;
    if count > MAX_IOVECS {
        return Err(ERRNO_INVAL);
    }
    let base = guest_offset(iovs).ok_or(ERRNO_FAULT)?;
    read_guest(caller, base, count.checked_mul(8).ok_or(ERRNO_FAULT)?)?;
    let mut vectors = Vec::with_capacity(count);
    for index in 0..count {
        let offset = base + index * 8;
        let pointer = read_u32_guest(caller, offset)? as usize;
        let length = read_u32_guest(caller, offset + 4)? as usize;
        read_guest(caller, pointer, length)?;
        vectors.push((pointer, length));
    }
    Ok(vectors)
}

fn guest_path(caller: &Caller<'_, WasiState>, pointer: i32, length: i32) -> Result<String, i32> {
    let bytes = read_guest(
        caller,
        guest_offset(pointer).ok_or(ERRNO_FAULT)?,
        length as u32 as usize,
    )?;
    if bytes.is_empty() {
        return Err(ERRNO_NOENT);
    }
    if bytes[0] == b'/' || bytes.iter().any(|byte| *byte == 0 || *byte == b'\\') {
        return Err(ERRNO_NOTCAPABLE);
    }
    if bytes
        .split(|byte| *byte == b'/')
        .any(|component| component == b"..")
    {
        return Err(ERRNO_NOTCAPABLE);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ERRNO_ILSEQ)
}

fn file_slot(fd: i32) -> Option<usize> {
    let slot = usize::try_from(fd.checked_sub(FIRST_FILE_FD)?).ok()?;
    (slot < MAX_OPEN_FILES).then_some(slot)
}

fn open_file<'a>(caller: &'a Caller<'_, WasiState>, fd: i32) -> Result<&'a OpenFile, i32> {
    caller
        .data()
        .files
        .get(file_slot(fd).ok_or(ERRNO_BADF)?)
        .and_then(Option::as_ref)
        .ok_or(ERRNO_BADF)
}

fn open_file_mut<'a>(
    caller: &'a mut Caller<'_, WasiState>,
    fd: i32,
) -> Result<&'a mut OpenFile, i32> {
    caller
        .data_mut()
        .files
        .get_mut(file_slot(fd).ok_or(ERRNO_BADF)?)
        .and_then(Option::as_mut)
        .ok_or(ERRNO_BADF)
}

fn directory_anchor(caller: &Caller<'_, WasiState>, fd: i32, right: u64) -> Result<Handle, i32> {
    if fd == PREOPEN_FD {
        let handle = caller.data().preopen.ok_or(ERRNO_BADF)?;
        if caller.data().preopen_rights & right != right {
            return Err(ERRNO_NOTCAPABLE);
        }
        return Ok(handle);
    }
    let directory = open_file(caller, fd)?;
    if directory.filetype != FILETYPE_DIRECTORY {
        return Err(ERRNO_NOTDIR);
    }
    if directory.rights & right != right {
        return Err(ERRNO_NOTCAPABLE);
    }
    Ok(directory.handle)
}

fn directory_inheriting_rights(caller: &Caller<'_, WasiState>, fd: i32) -> Result<u64, i32> {
    if fd == PREOPEN_FD {
        caller.data().preopen.ok_or(ERRNO_BADF)?;
        return Ok(caller.data().preopen_inheriting_rights);
    }
    let directory = open_file(caller, fd)?;
    if directory.filetype != FILETYPE_DIRECTORY {
        return Err(ERRNO_NOTDIR);
    }
    Ok(directory.inheriting_rights)
}

fn fd_handle_with_right(
    caller: &Caller<'_, WasiState>,
    fd: i32,
    right: u64,
) -> Result<(Handle, u8), i32> {
    if fd == PREOPEN_FD {
        let handle = caller.data().preopen.ok_or(ERRNO_BADF)?;
        if caller.data().preopen_rights & right == 0 {
            return Err(ERRNO_NOTCAPABLE);
        }
        return Ok((handle, FILETYPE_DIRECTORY));
    }
    let file = open_file(caller, fd)?;
    if file.rights & right == 0 {
        return Err(ERRNO_NOTCAPABLE);
    }
    Ok((file.handle, file.filetype))
}

fn wasi_filetype(kind: Option<FilesystemEntryKind>) -> u8 {
    match kind {
        Some(FilesystemEntryKind::File) => FILETYPE_REGULAR_FILE,
        Some(FilesystemEntryKind::Directory) => FILETYPE_DIRECTORY,
        None => 0,
    }
}

fn wasi_fd_filestat(filetype: u8, size: u64) -> [u8; 64] {
    let mut stat = [0_u8; 64];
    stat[16] = filetype;
    stat[24..32].copy_from_slice(&1_u64.to_le_bytes());
    stat[32..40].copy_from_slice(&size.to_le_bytes());
    stat
}

fn wasi_filestat(metadata: FilesystemMetadata) -> [u8; 64] {
    let mut stat = [0_u8; 64];
    stat[8..16].copy_from_slice(&metadata.stable_id.to_le_bytes());
    stat[16] = wasi_filetype(metadata.entry_kind());
    stat[24..32].copy_from_slice(&1_u64.to_le_bytes());
    stat[32..40].copy_from_slice(&metadata.size.to_le_bytes());
    stat[48..56].copy_from_slice(&metadata.mtime_ns.to_le_bytes());
    stat[56..64].copy_from_slice(&metadata.ctime_ns.to_le_bytes());
    stat
}

fn status_result(result: Result<(), Status>) -> i32 {
    match result {
        Ok(()) => ERRNO_SUCCESS,
        Err(status) => status_to_errno(status),
    }
}

fn status_to_errno(status: Status) -> i32 {
    match status {
        Status::Ok => ERRNO_SUCCESS,
        Status::InvalidHandle | Status::WrongObjectType => ERRNO_BADF,
        Status::AccessDenied => ERRNO_ACCES,
        Status::InvalidRights => ERRNO_NOTCAPABLE,
        Status::ShouldWait => ERRNO_AGAIN,
        Status::InvalidArgument | Status::InvalidMessage | Status::DuplicateHandle => ERRNO_INVAL,
        Status::InvalidAddress => ERRNO_FAULT,
        Status::OutOfRange | Status::BufferTooSmall => ERRNO_RANGE,
        Status::NotFound => ERRNO_NOENT,
        Status::OutOfMemory => ERRNO_NOMEM,
        Status::HandleTableFull | Status::ResourceLimit => ERRNO_MFILE,
        Status::MessageTooLarge => ERRNO_NOSPC,
        Status::NotDirectory => ERRNO_NOTDIR,
        Status::IsDirectory => ERRNO_ISDIR,
        Status::DirectoryNotEmpty => ERRNO_NOTEMPTY,
        Status::AlreadyExists => ERRNO_EXIST,
        Status::CrossDevice => ERRNO_XDEV,
        Status::UnknownSyscall => ERRNO_NOSYS,
        Status::Io
        | Status::TimedOut
        | Status::Canceled
        | Status::PeerClosed
        | Status::EndOfDirectory
        | Status::AlreadyMapped
        | Status::CyclicTransfer => ERRNO_IO,
    }
}

fn guest_offset(value: i32) -> Option<usize> {
    usize::try_from(value as u32).ok()
}

fn receive_input(console: Handle) -> Result<Option<Vec<u8>>, Status> {
    if !console.is_valid() {
        return Err(Status::InvalidHandle);
    }
    let mut bytes = vec![0; CHANNEL_MAX_BYTES];
    let mut handles = [MaybeUninit::<ReceivedHandle>::uninit(); CHANNEL_MAX_HANDLES];
    let info = match channel_read(console, &mut bytes, &mut handles) {
        Ok(info) => info,
        Err(Status::ShouldWait) => return Ok(None),
        Err(status) => return Err(status),
    };
    for handle in handles.iter().take(info.handle_count as usize) {
        let _ = handle_close(unsafe { handle.assume_init() }.handle);
    }
    if info.handle_count != 0 {
        return Err(Status::InvalidMessage);
    }
    bytes.truncate(info.byte_count as usize);
    match decode_console_message(&bytes, 0) {
        Ok(ConsoleMessage::Input(input)) => Ok(Some(input)),
        _ => Err(Status::InvalidMessage),
    }
}

fn send_console(console: Handle, message: ConsoleMessage) {
    if !console.is_valid() {
        return;
    }
    let Ok(bytes) = encode_console_message(&message) else {
        return;
    };
    loop {
        match channel_write(console, &bytes, &[]) {
            Ok(()) => return,
            Err(Status::ShouldWait) => {
                let _ = process_yield();
            }
            Err(_) => return,
        }
    }
}

fn exit_error(console: Handle, message: &str, code: i32) -> ! {
    send_console(console, ConsoleMessage::Error(message.as_bytes().to_vec()));
    send_console(console, ConsoleMessage::Exit(code));
    if console.is_valid() {
        let _ = handle_close(console);
    }
    ginkgo_runtime::exit(code)
}

fn close_optional(handle: Option<Handle>) {
    if let Some(handle) = handle {
        let _ = handle_close(handle);
    }
}

fn checked_range(offset: usize, length: usize, total: usize) -> Option<()> {
    (offset.checked_add(length)? <= total).then_some(())
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

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
