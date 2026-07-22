extern crate alloc;

use alloc::{
    collections::VecDeque,
    format,
    rc::Rc,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::cell::RefCell;

use ginkgo_app_package::{
    sha256, ExecutableGeneration, InstalledRegistry, Package, Provenance, Sha256, MAX_REGISTRY_LEN,
};
use ginkgo_terminal_protocol::ConsoleMessage;
use ginkgo_userspace::{
    channel_create, filesystem_create_directory, filesystem_get_info, filesystem_get_metadata,
    filesystem_open, filesystem_open_directory, filesystem_read, filesystem_read_directory,
    filesystem_read_directory2, filesystem_remove_directory, filesystem_rename, filesystem_stat,
    filesystem_sync, filesystem_truncate, filesystem_unlink, filesystem_write, handle_close,
    process_create, process_get_info, process_terminate, process_wait, process_yield,
    FilesystemEntryKind, FilesystemInfoFlags, FilesystemMetadata, FilesystemOpenFlags,
    FilesystemRenameFlags, Handle, ProcessFault, ProcessInfo, ProcessState,
    ProcessTerminationCause, Status, DEADLINE_INFINITE, PROCESS_MAX_ARGS,
    PROCESS_MAX_STARTUP_BYTES,
};
use rhai::{Array, Dynamic, Engine, ImmutableString, Map, INT};

use crate::{
    keyboard::{BACKSPACE, CANCEL, CLEAR, ENTER, HISTORY_NEXT, HISTORY_PREVIOUS},
    transport::PendingSend,
};

const MAX_LINE_BYTES: usize = 4096;
const MAX_HISTORY: usize = 64;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 256;
const MAX_PENDING_MESSAGES: usize = 128;
const MAX_CHILDREN: usize = 8;
const MAX_JOBS: usize = 32;
const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const FILE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_INSTALL_PACKAGE_BYTES: usize = 1024 * 1024;
const INSTALLED_REGISTRY_PATH: &str = "installed-apps.gki";
const STAGED_REGISTRY_PATH: &str = "installed-apps.gki.new";
const PROTECTED_SYSTEM_IDS: &[&str] = &["desktop", "files", "terminal", "minimal-client"];

pub struct ChildStream {
    pub app_id: String,
    pub endpoint: Handle,
}

pub struct HeadlessJob {
    pub id: INT,
    pub process: Handle,
}

pub struct HostState {
    filesystem: Handle,
    desktop: Handle,
    shell_endpoint: Handle,
    pub pending: VecDeque<PendingSend>,
    pub children: Vec<ChildStream>,
    pub jobs: Vec<HeadlessJob>,
    next_job_id: INT,
}

impl HostState {
    fn emit(&mut self, message: ConsoleMessage) {
        if self.pending.len() >= MAX_PENDING_MESSAGES {
            return;
        }
        if let Ok(send) = PendingSend::console(self.shell_endpoint, &message) {
            self.pending.push_back(send);
        }
    }

    fn output(&mut self, text: String) {
        self.emit(ConsoleMessage::Output(bounded_output(text)));
    }

    fn error(&mut self, text: String) {
        self.emit(ConsoleMessage::Error(bounded_output(text)));
    }

    fn spawn(&mut self, path: &str, arguments: Array) -> INT {
        if self.jobs.len() >= MAX_JOBS || self.next_job_id == INT::MAX {
            self.error(String::from("spawn_elf: terminal job limit reached"));
            return -1;
        }
        let arguments = match argument_strings(arguments) {
            Ok(arguments) => arguments,
            Err(error) => {
                self.error(format!("spawn_elf: {}", error));
                return -1;
            }
        };
        let blob = match encode_arguments(path, &arguments) {
            Ok(blob) => blob,
            Err(error) => {
                self.error(format!("spawn_elf: {}", error));
                return -1;
            }
        };
        let process = match create_headless_process(self.filesystem, path, &blob) {
            Ok(process) => process,
            Err(error) => {
                self.error(format!("spawn_elf: {:?}", error));
                return -1;
            }
        };
        let id = self.next_job_id;
        self.next_job_id += 1;
        self.jobs.push(HeadlessJob { id, process });
        id
    }

    fn job_process(&self, id: INT) -> Option<Handle> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.process)
    }

    fn close_job(&mut self, id: INT) -> bool {
        let Some(index) = self.jobs.iter().position(|job| job.id == id) else {
            return false;
        };
        if handle_close(self.jobs[index].process).is_err() {
            return false;
        }
        self.jobs.remove(index);
        true
    }

    fn launch(&mut self, app_id: String) -> bool {
        if self.children.len() >= MAX_CHILDREN || self.pending.len() >= MAX_PENDING_MESSAGES {
            self.error(String::from("run: terminal launch limit reached"));
            return false;
        }
        let (terminal_endpoint, child_endpoint) = match channel_create() {
            Ok(pair) => pair,
            Err(error) => {
                self.error(format!("run: channel creation failed: {:?}", error));
                return false;
            }
        };
        let request = match PendingSend::launch(self.desktop, app_id.clone(), child_endpoint) {
            Ok(request) => request,
            Err(()) => {
                let _ = handle_close(terminal_endpoint);
                let _ = handle_close(child_endpoint);
                self.error(String::from("run: launch request was too large"));
                return false;
            }
        };
        self.pending.push_back(request);
        self.children.push(ChildStream {
            app_id,
            endpoint: terminal_endpoint,
        });
        true
    }
}

pub struct Shell {
    engine: Engine,
    host: Rc<RefCell<HostState>>,
    line: String,
    history: VecDeque<String>,
    history_position: Option<usize>,
}

impl Shell {
    pub fn new(filesystem: Handle, desktop: Handle, shell_endpoint: Handle) -> Self {
        let host = Rc::new(RefCell::new(HostState {
            filesystem,
            desktop,
            shell_endpoint,
            pending: VecDeque::new(),
            children: Vec::new(),
            jobs: Vec::new(),
            next_job_id: 1,
        }));
        let mut engine = Engine::new();
        engine.set_max_operations(100_000);
        engine.set_max_call_levels(32);
        engine.set_max_expr_depths(64, 32);
        engine.set_max_string_size(MAX_FILE_BYTES);
        engine.set_max_array_size(4096);
        engine.set_max_map_size(1024);
        register_functions(&mut engine, host.clone());
        Self {
            engine,
            host,
            line: String::new(),
            history: VecDeque::new(),
            history_position: None,
        }
    }

    pub fn host(&self) -> Rc<RefCell<HostState>> {
        self.host.clone()
    }

    pub fn current_line(&self) -> &str {
        &self.line
    }

    pub fn accept(&mut self, bytes: &[u8]) -> bool {
        let mut changed = false;
        for byte in bytes.iter().copied() {
            match byte {
                ENTER => {
                    self.execute_line();
                    changed = true;
                }
                BACKSPACE => {
                    changed |= self.line.pop().is_some();
                    self.history_position = None;
                }
                CLEAR => {
                    self.host
                        .borrow_mut()
                        .emit(ConsoleMessage::Output(vec![CLEAR]));
                    changed = true;
                }
                CANCEL => {
                    self.line.clear();
                    self.history_position = None;
                    self.host.borrow_mut().error(String::from("^C"));
                    changed = true;
                }
                HISTORY_PREVIOUS => changed |= self.recall_previous(),
                HISTORY_NEXT => changed |= self.recall_next(),
                0x20..=0x7e if self.line.len() < MAX_LINE_BYTES => {
                    self.line.push(byte as char);
                    self.history_position = None;
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    fn execute_line(&mut self) {
        let source = core::mem::take(&mut self.line);
        self.history_position = None;
        self.host
            .borrow_mut()
            .emit(ConsoleMessage::Output(format!("> {}", source).into_bytes()));
        if source.trim().is_empty() {
            return;
        }
        if self.history.back().map(String::as_str) != Some(source.as_str()) {
            if self.history.len() == MAX_HISTORY {
                self.history.pop_front();
            }
            self.history.push_back(source.clone());
        }

        let script = if let Some(path) = source_command(&source) {
            match read_text(self.host.borrow().filesystem, path) {
                Ok(script) => script,
                Err(error) => {
                    self.host
                        .borrow_mut()
                        .error(format!("source: {}: {:?}", path, error));
                    return;
                }
            }
        } else {
            source
        };

        match self.engine.eval::<Dynamic>(&script) {
            Ok(value) if !value.is_unit() => self.host.borrow_mut().output(value.to_string()),
            Ok(_) => {}
            Err(error) => self.host.borrow_mut().error(format!("{}", error)),
        }
    }

    fn recall_previous(&mut self) -> bool {
        if self.history.is_empty() {
            return false;
        }
        let position = self
            .history_position
            .map(|position| position.saturating_sub(1))
            .unwrap_or(self.history.len() - 1);
        self.history_position = Some(position);
        self.line = self.history[position].clone();
        true
    }

    fn recall_next(&mut self) -> bool {
        let Some(position) = self.history_position else {
            return false;
        };
        if position + 1 < self.history.len() {
            self.history_position = Some(position + 1);
            self.line = self.history[position + 1].clone();
        } else {
            self.history_position = None;
            self.line.clear();
        }
        true
    }
}

fn source_command(line: &str) -> Option<&str> {
    let remainder = line.strip_prefix("source ")?.trim();
    if remainder.len() >= 2 {
        let bytes = remainder.as_bytes();
        if matches!(
            (bytes[0], bytes[bytes.len() - 1]),
            (b'"', b'"') | (b'\'', b'\'')
        ) {
            return Some(&remainder[1..remainder.len() - 1]);
        }
    }
    (!remainder.is_empty()).then_some(remainder)
}

fn register_functions(engine: &mut Engine, host: Rc<RefCell<HostState>>) {
    for name in ["print", "output"] {
        let output_host = host.clone();
        engine.register_fn(name, move |value: Dynamic| {
            output_host.borrow_mut().output(value.to_string());
        });
    }
    let error_host = host.clone();
    engine.register_fn("eprint", move |value: Dynamic| {
        error_host.borrow_mut().error(value.to_string());
    });

    let read_host = host.clone();
    engine.register_fn("read_file", move |path: ImmutableString| -> String {
        match read_text(read_host.borrow().filesystem, path.as_str()) {
            Ok(text) => text,
            Err(error) => format!("read_file: {:?}", error),
        }
    });

    let write_host = host.clone();
    engine.register_fn(
        "write_file",
        move |path: ImmutableString, contents: ImmutableString| -> bool {
            write_bytes(
                write_host.borrow().filesystem,
                path.as_str(),
                contents.as_bytes(),
                false,
            )
            .is_ok()
        },
    );
    let append_host = host.clone();
    engine.register_fn(
        "append_file",
        move |path: ImmutableString, contents: ImmutableString| -> bool {
            write_bytes(
                append_host.borrow().filesystem,
                path.as_str(),
                contents.as_bytes(),
                true,
            )
            .is_ok()
        },
    );
    let remove_host = host.clone();
    engine.register_fn("remove_file", move |path: ImmutableString| -> bool {
        filesystem_unlink(remove_host.borrow().filesystem, path.as_str()).is_ok()
    });
    let mkdir_host = host.clone();
    engine.register_fn("mkdir", move |path: ImmutableString| -> bool {
        filesystem_create_directory(mkdir_host.borrow().filesystem, path.as_str()).is_ok()
    });
    let rmdir_host = host.clone();
    engine.register_fn("rmdir", move |path: ImmutableString| -> bool {
        filesystem_remove_directory(rmdir_host.borrow().filesystem, path.as_str()).is_ok()
    });
    let rename_host = host.clone();
    engine.register_fn(
        "rename_path",
        move |source: ImmutableString, destination: ImmutableString, replace: bool| -> bool {
            let root = rename_host.borrow().filesystem;
            let flags = if replace {
                FilesystemRenameFlags::REPLACE
            } else {
                FilesystemRenameFlags::empty()
            };
            filesystem_rename(root, source.as_str(), root, destination.as_str(), flags).is_ok()
        },
    );
    let sync_host = host.clone();
    engine.register_fn("sync_filesystem", move || -> bool {
        filesystem_sync(sync_host.borrow().filesystem).is_ok()
    });
    let info_host = host.clone();
    engine.register_fn("filesystem_info", move || -> Dynamic {
        match filesystem_get_info(info_host.borrow().filesystem) {
            Ok(info) => {
                let mut map = Map::new();
                map.insert("total_bytes".into(), filesystem_integer(info.total_bytes));
                map.insert("free_bytes".into(), filesystem_integer(info.free_bytes));
                map.insert(
                    "available_bytes".into(),
                    filesystem_integer(info.available_bytes),
                );
                map.insert(
                    "block_size".into(),
                    Dynamic::from(INT::from(info.block_size)),
                );
                map.insert(
                    "max_name_length".into(),
                    Dynamic::from(INT::from(info.max_name_length)),
                );
                map.insert(
                    "max_path_depth".into(),
                    Dynamic::from(INT::from(info.max_path_depth)),
                );
                map.insert(
                    "read_only".into(),
                    Dynamic::from(
                        info.filesystem_flags()
                            .contains(FilesystemInfoFlags::READ_ONLY),
                    ),
                );
                Dynamic::from(map)
            }
            Err(error) => Dynamic::from(format!("filesystem_info: {:?}", error)),
        }
    });
    let metadata_host = host.clone();
    engine.register_fn("metadata", move |path: ImmutableString| -> Dynamic {
        match filesystem_get_metadata(metadata_host.borrow().filesystem, path.as_str()) {
            Ok(metadata) => Dynamic::from(metadata_map(metadata)),
            Err(error) => Dynamic::from(format!("metadata: {:?}", error)),
        }
    });
    let directory_host = host.clone();
    engine.register_fn("list_directory", move |path: ImmutableString| -> Array {
        let root = directory_host.borrow().filesystem;
        match list_directory(root, path.as_str()) {
            Ok(entries) => entries,
            Err(error) => {
                directory_host
                    .borrow_mut()
                    .error(format!("list_directory: {:?}", error));
                Array::new()
            }
        }
    });
    let list_host = host.clone();
    engine.register_fn("list_files", move || -> Array {
        list_files(list_host.borrow().filesystem)
    });
    let size_host = host.clone();
    engine.register_fn("file_size", move |path: ImmutableString| -> INT {
        file_size(size_host.borrow().filesystem, path.as_str())
            .and_then(|length| INT::try_from(length).map_err(|_| Status::OutOfRange))
            .unwrap_or(-1)
    });
    engine.register_fn("syscall", move |name: ImmutableString| -> bool {
        match name.as_str() {
            "yield" => process_yield().is_ok(),
            _ => false,
        }
    });

    let spawn_host = host.clone();
    engine.register_fn(
        "spawn_elf",
        move |path: ImmutableString, arguments: Array| -> INT {
            spawn_host.borrow_mut().spawn(path.as_str(), arguments)
        },
    );
    let status_host = host.clone();
    engine.register_fn("process_status", move |job_id: INT| -> Dynamic {
        let Some(process) = status_host.borrow().job_process(job_id) else {
            return Dynamic::from(format!("process_status: unknown job {}", job_id));
        };
        process_result("process_status", process_get_info(process))
    });
    let wait_host = host.clone();
    engine.register_fn("wait_process", move |job_id: INT| -> Dynamic {
        let Some(process) = wait_host.borrow().job_process(job_id) else {
            return Dynamic::from(format!("wait_process: unknown job {}", job_id));
        };
        process_result("wait_process", process_wait(process, DEADLINE_INFINITE))
    });
    let terminate_host = host.clone();
    engine.register_fn("terminate_process", move |job_id: INT| -> bool {
        terminate_host
            .borrow()
            .job_process(job_id)
            .is_some_and(|process| process_terminate(process).is_ok())
    });
    let close_host = host.clone();
    engine.register_fn("close_process", move |job_id: INT| -> bool {
        close_host.borrow_mut().close_job(job_id)
    });
    let exec_host = host.clone();
    engine.register_fn(
        "exec_elf",
        move |path: ImmutableString, arguments: Array| -> Dynamic {
            let arguments = match argument_strings(arguments) {
                Ok(arguments) => arguments,
                Err(error) => return Dynamic::from(format!("exec_elf: {}", error)),
            };
            let blob = match encode_arguments(path.as_str(), &arguments) {
                Ok(blob) => blob,
                Err(error) => return Dynamic::from(format!("exec_elf: {}", error)),
            };
            let filesystem = exec_host.borrow().filesystem;
            let process = match create_headless_process(filesystem, path.as_str(), &blob) {
                Ok(process) => process,
                Err(error) => return Dynamic::from(format!("exec_elf: {:?}", error)),
            };
            let result = process_wait(process, DEADLINE_INFINITE);
            let _ = handle_close(process);
            process_result("exec_elf", result)
        },
    );

    let install_host = host.clone();
    engine.register_fn("install_package", move |path: ImmutableString| -> bool {
        let filesystem = install_host.borrow().filesystem;
        match install_package(filesystem, path.as_str()) {
            Ok(()) => true,
            Err(error) => {
                install_host
                    .borrow_mut()
                    .error(format!("install_package: {}", error));
                false
            }
        }
    });
    let uninstall_host = host.clone();
    engine.register_fn("uninstall_app", move |app_id: ImmutableString| -> bool {
        let filesystem = uninstall_host.borrow().filesystem;
        match uninstall_app(filesystem, app_id.as_str()) {
            Ok(()) => true,
            Err(error) => {
                uninstall_host
                    .borrow_mut()
                    .error(format!("uninstall_app: {}", error));
                false
            }
        }
    });
    let installed_host = host.clone();
    engine.register_fn("list_installed", move || -> Array {
        let filesystem = installed_host.borrow().filesystem;
        match load_registry(filesystem) {
            Ok(registry) => installed_array(&registry),
            Err(error) => {
                installed_host
                    .borrow_mut()
                    .error(format!("list_installed: {}", error));
                Array::new()
            }
        }
    });

    let run_host = host;
    engine.register_fn("run", move |app_id: ImmutableString| -> bool {
        run_host.borrow_mut().launch(String::from(app_id.as_str()))
    });
}

fn argument_strings(arguments: Array) -> Result<Vec<String>, &'static str> {
    let mut strings = Vec::with_capacity(arguments.len());
    for value in arguments {
        let Some(value) = value.try_cast::<ImmutableString>() else {
            return Err("arguments must all be strings");
        };
        strings.push(String::from(value.as_str()));
    }
    Ok(strings)
}

fn encode_arguments(path: &str, arguments: &[String]) -> Result<Vec<u8>, &'static str> {
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err("path must be non-empty and contain no NUL bytes");
    }
    if arguments.len().saturating_add(1) > PROCESS_MAX_ARGS {
        return Err("too many arguments");
    }
    let mut length = path.len().checked_add(1).ok_or("arguments are too large")?;
    for argument in arguments {
        if argument.as_bytes().contains(&0) {
            return Err("arguments may not contain NUL bytes");
        }
        length = length
            .checked_add(argument.len())
            .and_then(|length| length.checked_add(1))
            .ok_or("arguments are too large")?;
    }
    if length > PROCESS_MAX_STARTUP_BYTES {
        return Err("arguments exceed the process startup limit");
    }
    let mut blob = Vec::with_capacity(length);
    blob.extend_from_slice(path.as_bytes());
    blob.push(0);
    for argument in arguments {
        blob.extend_from_slice(argument.as_bytes());
        blob.push(0);
    }
    Ok(blob)
}

fn create_headless_process(root: Handle, path: &str, arguments: &[u8]) -> Result<Handle, Status> {
    let executable = filesystem_open(
        root,
        path,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    )?;
    let result = process_create(executable, arguments, &[], &[]);
    let _ = handle_close(executable);
    result
}

fn process_result(operation: &str, result: Result<ProcessInfo, Status>) -> Dynamic {
    match result {
        Ok(info) => Dynamic::from(process_map(info)),
        Err(error) => Dynamic::from(format!("{}: {:?}", operation, error)),
    }
}

fn process_map(info: ProcessInfo) -> Map {
    let mut map = Map::new();
    match info.process_state() {
        Some(ProcessState::Running) => {
            map.insert("state".into(), Dynamic::from("running"));
        }
        Some(ProcessState::Terminated) => match info.termination_cause() {
            Some(ProcessTerminationCause::Exited) => {
                map.insert("state".into(), Dynamic::from("exited"));
                map.insert("exit_code".into(), Dynamic::from(INT::from(info.exit_code)));
            }
            Some(ProcessTerminationCause::Terminated) => {
                map.insert("state".into(), Dynamic::from("terminated"));
            }
            Some(ProcessTerminationCause::Faulted) => {
                map.insert("state".into(), Dynamic::from("faulted"));
                map.insert(
                    "fault".into(),
                    Dynamic::from(fault_name(info.process_fault())),
                );
                map.insert(
                    "fault_code".into(),
                    Dynamic::from(format!("0x{:016x}", info.fault_code)),
                );
                map.insert(
                    "fault_address".into(),
                    Dynamic::from(format!("0x{:016x}", info.fault_address)),
                );
            }
            cause => {
                map.insert("state".into(), Dynamic::from("unknown"));
                map.insert(
                    "termination_cause".into(),
                    Dynamic::from(format!("{:?}", cause)),
                );
            }
        },
        None => {
            map.insert("state".into(), Dynamic::from("unknown"));
            map.insert("raw_state".into(), Dynamic::from(INT::from(info.state)));
        }
    }
    map
}

fn fault_name(fault: Option<ProcessFault>) -> &'static str {
    match fault {
        Some(ProcessFault::None) => "none",
        Some(ProcessFault::PageFault) => "page-fault",
        Some(ProcessFault::GeneralProtection) => "general-protection",
        Some(ProcessFault::InvalidOpcode) => "invalid-opcode",
        Some(ProcessFault::InvalidUserContext) => "invalid-user-context",
        Some(ProcessFault::ResourceLimit) => "resource-limit",
        Some(ProcessFault::Other) => "other",
        None => "unknown",
    }
}

fn install_package(root: Handle, path: &str) -> Result<(), String> {
    let package_bytes = read_bounded(root, path, MAX_INSTALL_PACKAGE_BYTES)
        .map_err(|error| format!("cannot read package: {:?}", error))?;
    let package = Package::parse(&package_bytes)
        .map_err(|error| format!("invalid GKP package: {:?}", error))?;
    let executable_digest = sha256(package.executable);
    let package_digest = sha256(&package_bytes);
    let generation = ExecutableGeneration::new(
        package.app_id,
        executable_digest,
        package.executable.len() as u64,
    )
    .map_err(|error| format!("invalid executable generation: {:?}", error))?;

    let mut registry = load_registry(root)?;
    let old_filename = registry
        .get(package.app_id)
        .map(|entry| entry.executable.filename.clone());
    let provenance = Provenance { package_digest };
    if old_filename.is_some() {
        registry
            .update(
                &package,
                generation.clone(),
                provenance,
                PROTECTED_SYSTEM_IDS,
            )
            .map_err(|error| format!("registry update rejected: {:?}", error))?;
    } else {
        registry
            .install(
                &package,
                generation.clone(),
                provenance,
                PROTECTED_SYSTEM_IDS,
            )
            .map_err(|error| format!("registry install rejected: {:?}", error))?;
    }

    let executable_created = ensure_immutable_file(
        root,
        generation.filename.as_str(),
        package.executable,
        executable_digest,
    )?;
    let mut created_assets = Vec::new();
    for asset in package.assets() {
        let backing_name = seed_backing_name(package.app_id, asset.path);
        match ensure_seed_file(root, backing_name.as_str(), asset.data) {
            Ok(true) => created_assets.push(backing_name),
            Ok(false) => {}
            Err(error) => {
                cleanup_created_files(root, &created_assets);
                if executable_created {
                    let _ = filesystem_unlink(root, generation.filename.as_str());
                }
                return Err(error);
            }
        }
    }

    if let Err((error, rollback_safe)) = publish_registry(root, &registry) {
        if rollback_safe {
            cleanup_created_files(root, &created_assets);
            if executable_created {
                let _ = filesystem_unlink(root, generation.filename.as_str());
            }
        }
        return Err(error);
    }

    if let Some(old_filename) = old_filename {
        if old_filename != generation.filename {
            let _ = filesystem_unlink(root, old_filename.as_str());
        }
    }
    Ok(())
}

fn uninstall_app(root: Handle, app_id: &str) -> Result<(), String> {
    let mut registry = load_registry(root)?;
    let removed = registry
        .remove(app_id, PROTECTED_SYSTEM_IDS)
        .map_err(|error| format!("registry removal rejected: {:?}", error))?;
    publish_registry(root, &registry).map_err(|(error, _)| error)?;
    let _ = filesystem_unlink(root, removed.executable.filename.as_str());
    Ok(())
}

fn load_registry(root: Handle) -> Result<InstalledRegistry, String> {
    match read_bounded(root, INSTALLED_REGISTRY_PATH, MAX_REGISTRY_LEN) {
        Ok(bytes) => InstalledRegistry::parse(&bytes)
            .map_err(|error| format!("installed registry is invalid: {:?}", error)),
        Err(Status::NotFound) => Ok(InstalledRegistry::new()),
        Err(error) => Err(format!("cannot read installed registry: {:?}", error)),
    }
}

fn publish_registry(root: Handle, registry: &InstalledRegistry) -> Result<(), (String, bool)> {
    let old_bytes = match read_bounded(root, INSTALLED_REGISTRY_PATH, MAX_REGISTRY_LEN) {
        Ok(bytes) => Some(bytes),
        Err(Status::NotFound) => None,
        Err(error) => {
            return Err((
                format!("cannot snapshot installed registry: {:?}", error),
                true,
            ))
        }
    };
    let encoded = registry.encode();
    if let Err(error) = write_bytes(root, STAGED_REGISTRY_PATH, &encoded, false) {
        let _ = filesystem_unlink(root, STAGED_REGISTRY_PATH);
        return Err((
            format!("cannot stage installed registry: {:?}", error),
            true,
        ));
    }
    let staged_valid = read_bounded(root, STAGED_REGISTRY_PATH, MAX_REGISTRY_LEN)
        .ok()
        .and_then(|bytes| InstalledRegistry::parse(&bytes).ok())
        .is_some_and(|parsed| parsed == *registry);
    if !staged_valid {
        let _ = filesystem_unlink(root, STAGED_REGISTRY_PATH);
        return Err((
            String::from("staged installed registry did not verify"),
            true,
        ));
    }

    if let Err(error) = write_bytes(root, INSTALLED_REGISTRY_PATH, &encoded, false) {
        let rollback_safe = match old_bytes {
            Some(ref old) => write_bytes(root, INSTALLED_REGISTRY_PATH, old, false).is_ok(),
            None => matches!(
                filesystem_unlink(root, INSTALLED_REGISTRY_PATH),
                Ok(()) | Err(Status::NotFound)
            ),
        };
        let _ = filesystem_unlink(root, STAGED_REGISTRY_PATH);
        return Err((
            format!("cannot publish installed registry: {:?}", error),
            rollback_safe,
        ));
    }
    let _ = filesystem_unlink(root, STAGED_REGISTRY_PATH);
    Ok(())
}

fn ensure_immutable_file(
    root: Handle,
    path: &str,
    bytes: &[u8],
    expected_digest: [u8; 32],
) -> Result<bool, String> {
    match file_digest(root, path) {
        Ok((length, digest)) if length == bytes.len() as u64 && digest == expected_digest => {
            return Ok(false)
        }
        Ok(_) => {
            return Err(String::from(
                "generation filename exists with different contents",
            ))
        }
        Err(Status::NotFound) => {}
        Err(error) => return Err(format!("cannot inspect executable generation: {:?}", error)),
    }
    if let Err(error) = write_bytes(root, path, bytes, false) {
        let _ = filesystem_unlink(root, path);
        return Err(format!("cannot write executable generation: {:?}", error));
    }
    match file_digest(root, path) {
        Ok((length, digest)) if length == bytes.len() as u64 && digest == expected_digest => {
            Ok(true)
        }
        _ => {
            let _ = filesystem_unlink(root, path);
            Err(String::from("executable generation did not verify"))
        }
    }
}

fn ensure_seed_file(root: Handle, path: &str, bytes: &[u8]) -> Result<bool, String> {
    match filesystem_open(root, path, FilesystemOpenFlags::READ) {
        Ok(file) => {
            let _ = handle_close(file);
            Ok(false)
        }
        Err(Status::NotFound) => {
            if let Err(error) = write_bytes(root, path, bytes, false) {
                let _ = filesystem_unlink(root, path);
                Err(format!("cannot write seed asset {}: {:?}", path, error))
            } else {
                Ok(true)
            }
        }
        Err(error) => Err(format!("cannot inspect seed asset {}: {:?}", path, error)),
    }
}

fn seed_backing_name(app_id: &str, virtual_path: &str) -> String {
    format!(
        "{}-seed-{}.dat",
        app_id,
        digest_hex(&sha256(virtual_path.as_bytes()))
    )
}

fn installed_array(registry: &InstalledRegistry) -> Array {
    registry
        .entries()
        .iter()
        .map(|entry| {
            let mut map = Map::new();
            map.insert("app_id".into(), Dynamic::from(entry.app_id.clone()));
            map.insert(
                "display_name".into(),
                Dynamic::from(entry.display_name.clone()),
            );
            map.insert("version".into(), Dynamic::from(entry.version.clone()));
            map.insert("kind".into(), Dynamic::from(format!("{:?}", entry.kind)));
            map.insert(
                "executable".into(),
                Dynamic::from(entry.executable.filename.clone()),
            );
            map.insert(
                "sha256".into(),
                Dynamic::from(digest_hex(&entry.executable.digest)),
            );
            map.insert(
                "package_sha256".into(),
                Dynamic::from(digest_hex(&entry.provenance.package_digest)),
            );
            Dynamic::from(map)
        })
        .collect()
}

fn cleanup_created_files(root: Handle, paths: &[String]) {
    for path in paths {
        let _ = filesystem_unlink(root, path.as_str());
    }
}

fn read_bounded(root: Handle, path: &str, maximum: usize) -> Result<Vec<u8>, Status> {
    let file = filesystem_open(root, path, FilesystemOpenFlags::READ)?;
    let result = (|| {
        let length =
            usize::try_from(filesystem_stat(file)?.length).map_err(|_| Status::OutOfRange)?;
        if length > maximum {
            return Err(Status::OutOfRange);
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = filesystem_read(file, offset as u64, &mut bytes[offset..])?;
            if count == 0 {
                break;
            }
            offset += count;
        }
        bytes.truncate(offset);
        Ok(bytes)
    })();
    let _ = handle_close(file);
    result
}

fn file_digest(root: Handle, path: &str) -> Result<(u64, [u8; 32]), Status> {
    let file = filesystem_open(root, path, FilesystemOpenFlags::READ)?;
    let result = (|| {
        let length = filesystem_stat(file)?.length;
        let mut hasher = Sha256::new();
        let mut buffer = [0; FILE_CHUNK_BYTES];
        let mut offset = 0u64;
        while offset < length {
            let count = filesystem_read(file, offset, &mut buffer)?;
            if count == 0 {
                return Err(Status::Io);
            }
            hasher.update(&buffer[..count]);
            offset = offset.checked_add(count as u64).ok_or(Status::OutOfRange)?;
        }
        Ok((length, hasher.finalize()))
    })();
    let _ = handle_close(file);
    result
}

fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

fn bounded_output(text: String) -> Vec<u8> {
    let mut bytes = text.into_bytes();
    if bytes.len() > MAX_OUTPUT_BYTES {
        bytes.truncate(MAX_OUTPUT_BYTES);
        while core::str::from_utf8(&bytes).is_err() {
            bytes.pop();
        }
    }
    bytes
}

fn read_text(root: Handle, path: &str) -> Result<String, Status> {
    let file = filesystem_open(root, path, FilesystemOpenFlags::READ)?;
    let result = (|| {
        let stat = filesystem_stat(file)?;
        let length = usize::try_from(stat.length).map_err(|_| Status::OutOfRange)?;
        if length > MAX_FILE_BYTES {
            return Err(Status::OutOfRange);
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = filesystem_read(file, offset as u64, &mut bytes[offset..])?;
            if count == 0 {
                break;
            }
            offset += count;
        }
        bytes.truncate(offset);
        String::from_utf8(bytes).map_err(|_| Status::InvalidMessage)
    })();
    let _ = handle_close(file);
    result
}

fn write_bytes(root: Handle, path: &str, bytes: &[u8], append: bool) -> Result<(), Status> {
    let mut flags = FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE;
    if !append {
        flags |= FilesystemOpenFlags::TRUNCATE;
    }
    let file = filesystem_open(root, path, flags)?;
    let result = (|| {
        let mut offset = if append {
            filesystem_stat(file)?.length
        } else {
            0
        };
        for chunk in bytes.chunks(FILE_CHUNK_BYTES) {
            let mut written = 0;
            while written < chunk.len() {
                let count = filesystem_write(file, offset, &chunk[written..])?;
                if count == 0 {
                    return Err(Status::Io);
                }
                written += count;
                offset += count as u64;
            }
        }
        if !append {
            filesystem_truncate(file, bytes.len() as u64)?;
        }
        Ok(())
    })();
    let _ = handle_close(file);
    result
}

fn filesystem_integer(value: u64) -> Dynamic {
    INT::try_from(value)
        .map(Dynamic::from)
        .unwrap_or_else(|_| Dynamic::from(value.to_string()))
}

fn entry_kind(kind: Option<FilesystemEntryKind>) -> &'static str {
    match kind {
        Some(FilesystemEntryKind::File) => "file",
        Some(FilesystemEntryKind::Directory) => "directory",
        None => "unknown",
    }
}

fn metadata_map(metadata: FilesystemMetadata) -> Map {
    let mut time = Map::new();
    time.insert("created_ns".into(), filesystem_integer(metadata.ctime_ns));
    time.insert("modified_ns".into(), filesystem_integer(metadata.mtime_ns));

    let mut map = Map::new();
    map.insert(
        "kind".into(),
        Dynamic::from(entry_kind(metadata.entry_kind())),
    );
    map.insert("identity".into(), filesystem_integer(metadata.stable_id));
    map.insert("mode".into(), Dynamic::from(INT::from(metadata.mode)));
    map.insert("uid".into(), Dynamic::from(INT::from(metadata.uid)));
    map.insert("gid".into(), Dynamic::from(INT::from(metadata.gid)));
    map.insert("policy".into(), Dynamic::from(INT::from(metadata.policy)));
    map.insert("size".into(), filesystem_integer(metadata.size));
    map.insert("time".into(), Dynamic::from(time));
    map
}

fn list_directory(root: Handle, path: &str) -> Result<Array, Status> {
    let (directory, owned) = if path.is_empty() {
        (root, false)
    } else {
        (filesystem_open_directory(root, path)?, true)
    };
    let result = (|| {
        let mut entries = Array::new();
        let mut cookie = 0;
        while entries.len() < MAX_DIRECTORY_ENTRIES {
            let entry = match filesystem_read_directory2(directory, cookie) {
                Ok(entry) => entry,
                Err(Status::EndOfDirectory) => break,
                Err(error) => return Err(error),
            };
            let length = usize::from(entry.name_length).min(entry.name.len());
            let name =
                core::str::from_utf8(&entry.name[..length]).map_err(|_| Status::InvalidMessage)?;
            let metadata = filesystem_get_metadata(directory, name)?;
            let mut map = metadata_map(metadata);
            map.insert("name".into(), Dynamic::from(name.to_string()));
            entries.push(Dynamic::from(map));
            cookie = entry.next_cookie;
        }
        Ok(entries)
    })();
    if owned {
        let _ = handle_close(directory);
    }
    result
}

fn list_files(root: Handle) -> Array {
    let mut files = Array::new();
    let mut cookie = 0;
    while files.len() < MAX_DIRECTORY_ENTRIES {
        let entry = match filesystem_read_directory(root, cookie) {
            Ok(entry) => entry,
            Err(Status::EndOfDirectory) | Err(_) => break,
        };
        let length = usize::from(entry.name_length).min(entry.name.len());
        if let Ok(name) = core::str::from_utf8(&entry.name[..length]) {
            files.push(Dynamic::from(name.to_string()));
        }
        cookie = entry.next_cookie;
    }
    files
}

fn file_size(root: Handle, path: &str) -> Result<u64, Status> {
    let file = filesystem_open(root, path, FilesystemOpenFlags::READ)?;
    let result = filesystem_stat(file).map(|stat| stat.length);
    let _ = handle_close(file);
    result
}
