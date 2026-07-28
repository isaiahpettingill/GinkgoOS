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
    encode_package, generation_filename, sha256, AppKind, AssetInput, ExecutableFormat,
    ExecutableGeneration, InstalledRegistry, Package, PackageInput, Provenance, Sha256,
    MAX_ASSET_COUNT, MAX_ASSET_DATA_LEN, MAX_EXECUTABLE_LEN, MAX_PACKAGE_LEN, MAX_REGISTRY_LEN,
    MAX_TOTAL_ASSET_DATA_LEN,
};
use ginkgo_program_registry::Registry as ProgramRegistry;
use ginkgo_shell_language::{
    CallMode, Host, Integer as INT, Interpreter, List as Array, Map, Value as Dynamic,
};
use ginkgo_terminal_protocol::ConsoleMessage;
use ginkgo_userspace::{
    application_data_create, channel_create, filesystem_create_directory, filesystem_get_info,
    filesystem_get_metadata, filesystem_open, filesystem_open_directory, filesystem_read,
    filesystem_read_directory2, filesystem_remove_directory, filesystem_rename, filesystem_stat,
    filesystem_sync, filesystem_truncate, filesystem_unlink, filesystem_write, handle_close,
    process_create, process_get_info, process_terminate, process_wait, process_yield,
    system_power_cancel, system_power_get_info, system_power_request, FilesystemEntryKind,
    FilesystemInfoFlags, FilesystemMetadata, FilesystemOpenFlags, FilesystemRenameFlags, Handle,
    HandleDisposition, ProcessFault, ProcessInfo, ProcessState, ProcessTerminationCause, Rights,
    Status, SystemPowerAction, SystemPowerFlags, SystemPowerState, DEADLINE_INFINITE,
    PROCESS_MAX_ARGS, PROCESS_MAX_STARTUP_BYTES,
};

use crate::{
    keyboard::{
        BACKSPACE, CANCEL, CLEAR, CURSOR_LEFT, CURSOR_RIGHT, ENTER, HISTORY_NEXT, HISTORY_PREVIOUS,
    },
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
const MAX_INSTALL_PACKAGE_BYTES: usize = MAX_PACKAGE_LEN;
const PACKAGE_MANIFEST_NAME: &str = "package.gkm";
const PACKAGE_ASSETS_DIRECTORY: &str = "assets";
const MAX_PURGE_ENTRIES: usize = 512;
const MAX_PURGE_DEPTH: usize = 32;
const APPLICATIONS_DIRECTORY: &str = "applications";
const APP_DATA_DIRECTORY: &str = "appdata";
const INSTALLED_REGISTRY_PATH: &str = "applications/installed.gki";
const STAGED_REGISTRY_PATH: &str = "applications/installed.gki.new";
const PROGRAM_REGISTRY_PATH: &str = "system/programs.gkr";
const WASM_RUNTIME_PATH: &str = "system/wasm-runtime.elf";
const WABT_TOOL_DIRECTORY: &str = "system/bin/";
const WASM_MAGIC: [u8; 4] = *b"\0asm";
const WASM_CONSOLE_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits() | Rights::WAIT.bits());
const WASM_PREOPEN_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits());
const WASM_RANDOM_RIGHTS: Rights = Rights::READ;
const WABT_TOOL_NAMES: &[&str] = &[
    "spectest-interp",
    "wasm-decompile",
    "wasm-interp",
    "wasm-objdump",
    "wasm-stats",
    "wasm-strip",
    "wasm-validate",
    "wasm2c",
    "wasm2wat",
    "wast2json",
    "wat-desugar",
    "wat2wasm",
];
const PROTECTED_SYSTEM_IDS: &[&str] = &[
    "desktop",
    "help",
    "file-navigator",
    "text-editor",
    "terminal",
    "minimal-client",
    "wasm-runtime",
];

struct CommandSpec {
    canonical_name: &'static str,
    aliases: &'static [&'static str],
    min_args: usize,
    max_args: Option<usize>,
}

impl CommandSpec {
    const fn shell(
        canonical_name: &'static str,
        aliases: &'static [&'static str],
        min_args: usize,
        max_args: Option<usize>,
    ) -> Self {
        Self {
            canonical_name,
            aliases,
            min_args,
            max_args,
        }
    }

    const fn no_arguments(canonical_name: &'static str, aliases: &'static [&'static str]) -> Self {
        Self::shell(canonical_name, aliases, 0, Some(0))
    }

    const fn expression(
        canonical_name: &'static str,
        aliases: &'static [&'static str],
        min_args: usize,
        max_args: Option<usize>,
    ) -> Self {
        Self::shell(canonical_name, aliases, min_args, max_args)
    }
}

static COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec::shell("list_files", &["ls", "dir"], 0, Some(1)),
    CommandSpec::shell("change_directory", &["cd", "chdir"], 1, Some(1)),
    CommandSpec::no_arguments("current_directory", &["pwd", "cwd"]),
    CommandSpec::shell("copy", &["cp"], 2, Some(2)),
    CommandSpec::shell("move", &["mv", "ren", "rename"], 2, Some(2)),
    CommandSpec::shell("remove", &["rm", "del", "delete"], 1, None),
    CommandSpec::shell("make_directory", &["mkdir", "md"], 1, None),
    CommandSpec::shell("remove_directory", &["rmdir", "rd"], 1, None),
    CommandSpec::shell("show_file", &["cat", "type"], 1, None),
    CommandSpec::no_arguments("clear_terminal", &["clear", "cls"]),
    CommandSpec::no_arguments("show_processes", &["ps", "tasks"]),
    CommandSpec::shell("terminate_process", &["kill", "stop"], 1, Some(1)),
    CommandSpec::shell("help", &[], 0, Some(1)),
    CommandSpec::no_arguments("exit", &["quit"]),
    CommandSpec::shell("launch", &[], 1, None),
    CommandSpec::shell("edit", &[], 1, Some(1)),
    CommandSpec::shell("install", &["install_package"], 1, Some(1)),
    CommandSpec::shell("uninstall", &["uninstall_app"], 1, Some(1)),
    CommandSpec::shell("package", &["pack"], 2, Some(6)),
    CommandSpec::shell("unpackage", &["unpack"], 2, Some(2)),
    CommandSpec::no_arguments("installed", &["list_installed"]),
    CommandSpec::expression("print", &["output"], 1, Some(1)),
];

pub struct ChildStream {
    pub app_id: String,
    pub endpoint: Handle,
    pub process: Option<Handle>,
    pub foreground: bool,
    pub announce_close: bool,
}

pub struct HeadlessJob {
    pub id: INT,
    pub process: Handle,
}

pub struct HostState {
    filesystem: Handle,
    desktop: Handle,
    power: Handle,
    random: Handle,
    shell_endpoint: Handle,
    pub pending: VecDeque<PendingSend>,
    pub children: Vec<ChildStream>,
    pub jobs: Vec<HeadlessJob>,
    pub exit_requested: bool,
    next_job_id: INT,
    current_directory: String,
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
        let process = match create_headless_process(
            self.filesystem,
            self.shell_endpoint,
            self.random,
            path,
            &blob,
        ) {
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

    fn spawn_installed(&mut self, app_id: &str, arguments: Array) -> INT {
        if self.jobs.len() >= MAX_JOBS || self.next_job_id == INT::MAX {
            self.error(String::from("spawn_installed: terminal job limit reached"));
            return -1;
        }
        let arguments = match argument_strings(arguments) {
            Ok(arguments) => arguments,
            Err(error) => {
                self.error(format!("spawn_installed: {}", error));
                return -1;
            }
        };
        let process = match create_installed_process(
            self.filesystem,
            self.shell_endpoint,
            self.random,
            app_id,
            &arguments,
        ) {
            Ok(process) => process,
            Err(error) => {
                self.error(format!("spawn_installed: {}", error));
                return -1;
            }
        };
        let id = self.next_job_id;
        self.next_job_id += 1;
        self.jobs.push(HeadlessJob { id, process });
        id
    }

    fn launch_command_terminal(&mut self, app_id: String, arguments: Vec<String>) -> bool {
        if self.children.len() >= MAX_CHILDREN
            || self.pending.len().saturating_add(2) > MAX_PENDING_MESSAGES
        {
            self.error(String::from("launch: terminal launch limit reached"));
            return false;
        }
        let (terminal_endpoint, child_endpoint) = match channel_create() {
            Ok(pair) => pair,
            Err(error) => {
                self.error(format!("launch: channel creation failed: {:?}", error));
                return false;
            }
        };
        let startup =
            match PendingSend::terminal_command(terminal_endpoint, app_id.clone(), arguments) {
                Ok(startup) => startup,
                Err(()) => {
                    let _ = handle_close(terminal_endpoint);
                    let _ = handle_close(child_endpoint);
                    self.error(String::from("launch: command startup data is invalid"));
                    return false;
                }
            };
        let request =
            match PendingSend::launch(self.desktop, String::from("terminal"), child_endpoint) {
                Ok(request) => request,
                Err(()) => {
                    let _ = handle_close(terminal_endpoint);
                    let _ = handle_close(child_endpoint);
                    self.error(String::from("launch: terminal request was too large"));
                    return false;
                }
            };
        self.pending.push_back(startup);
        self.pending.push_back(request);
        self.children.push(ChildStream {
            app_id,
            endpoint: terminal_endpoint,
            process: None,
            foreground: false,
            announce_close: false,
        });
        true
    }

    fn start_path_foreground(&mut self, path: &str, arguments: &[u8]) -> Result<(), String> {
        if self.children.len() >= MAX_CHILDREN || self.foreground_active() {
            return Err(String::from("terminal foreground command limit reached"));
        }
        let (terminal_endpoint, child_endpoint) = channel_create()
            .map_err(|error| format!("cannot create command console: {:?}", error))?;
        let process = create_headless_process(
            self.filesystem,
            child_endpoint,
            self.random,
            path,
            arguments,
        );
        let _ = handle_close(child_endpoint);
        let process = match process {
            Ok(process) => process,
            Err(error) => {
                let _ = handle_close(terminal_endpoint);
                return Err(format!("process creation failed: {:?}", error));
            }
        };
        self.children.push(ChildStream {
            app_id: path.to_string(),
            endpoint: terminal_endpoint,
            process: Some(process),
            foreground: true,
            announce_close: true,
        });
        Ok(())
    }

    fn start_installed_foreground(
        &mut self,
        app_id: &str,
        arguments: &[String],
    ) -> Result<(), String> {
        if self.children.len() >= MAX_CHILDREN || self.foreground_active() {
            return Err(String::from("terminal foreground command limit reached"));
        }
        let (terminal_endpoint, child_endpoint) = channel_create()
            .map_err(|error| format!("cannot create command console: {:?}", error))?;
        let process = create_installed_process(
            self.filesystem,
            child_endpoint,
            self.random,
            app_id,
            arguments,
        );
        let _ = handle_close(child_endpoint);
        let process = match process {
            Ok(process) => process,
            Err(error) => {
                let _ = handle_close(terminal_endpoint);
                return Err(error);
            }
        };
        self.children.push(ChildStream {
            app_id: app_id.to_string(),
            endpoint: terminal_endpoint,
            process: Some(process),
            foreground: true,
            announce_close: true,
        });
        Ok(())
    }

    pub fn foreground_endpoint(&self) -> Option<Handle> {
        self.children
            .iter()
            .find(|child| child.foreground)
            .map(|child| child.endpoint)
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

    fn foreground_active(&self) -> bool {
        self.children.iter().any(|child| child.foreground)
    }

    fn launch(&mut self, app_id: String, foreground: bool, document_path: Option<String>) -> bool {
        let pending_needed = usize::from(document_path.is_some()) + 1;
        if self.children.len() >= MAX_CHILDREN
            || self.pending.len().saturating_add(pending_needed) > MAX_PENDING_MESSAGES
            || (foreground && self.foreground_active())
        {
            self.error(String::from("launch: terminal launch limit reached"));
            return false;
        }
        let (terminal_endpoint, child_endpoint) = match channel_create() {
            Ok(pair) => pair,
            Err(error) => {
                self.error(format!("launch: channel creation failed: {:?}", error));
                return false;
            }
        };
        let document = match document_path {
            Some(path) => match PendingSend::document(terminal_endpoint, path) {
                Ok(document) => Some(document),
                Err(()) => {
                    let _ = handle_close(terminal_endpoint);
                    let _ = handle_close(child_endpoint);
                    self.error(String::from("edit: document request was invalid"));
                    return false;
                }
            },
            None => None,
        };
        let request = match PendingSend::launch(self.desktop, app_id.clone(), child_endpoint) {
            Ok(request) => request,
            Err(()) => {
                let _ = handle_close(terminal_endpoint);
                let _ = handle_close(child_endpoint);
                self.error(String::from("launch: request was too large"));
                return false;
            }
        };
        if let Some(document) = document {
            self.pending.push_back(document);
        }
        self.pending.push_back(request);
        self.children.push(ChildStream {
            app_id,
            endpoint: terminal_endpoint,
            process: None,
            foreground,
            announce_close: true,
        });
        true
    }
}

pub struct Shell {
    interpreter: Interpreter,
    host: Rc<RefCell<HostState>>,
    line: String,
    cursor: usize,
    history: VecDeque<String>,
    history_position: Option<usize>,
}

impl Shell {
    pub fn new(
        filesystem: Handle,
        desktop: Handle,
        power: Handle,
        random: Handle,
        shell_endpoint: Handle,
    ) -> Self {
        let host = Rc::new(RefCell::new(HostState {
            filesystem,
            desktop,
            power,
            random,
            shell_endpoint,
            pending: VecDeque::new(),
            children: Vec::new(),
            jobs: Vec::new(),
            exit_requested: false,
            next_job_id: 1,
            current_directory: String::from("user"),
        }));
        Self {
            interpreter: Interpreter::new(),
            host,
            line: String::new(),
            cursor: 0,
            history: VecDeque::new(),
            history_position: None,
        }
    }

    pub fn run_startup_application(&mut self, app_id: String, arguments: Vec<String>) {
        let values = arguments.into_iter().map(Dynamic::from).collect();
        let result = if let Some(path) = wabt_tool_path(&app_id) {
            execute_path(&mut self.host.borrow_mut(), &path, values, true)
        } else {
            launch_application(&mut self.host.borrow_mut(), &app_id, values, true)
        };
        match result {
            Ok(Dynamic::Unit) => {}
            Ok(value) => self.host.borrow_mut().output(format_terminal_value(&value)),
            Err(error) => self.host.borrow_mut().error(error),
        }
    }

    pub fn host(&self) -> Rc<RefCell<HostState>> {
        self.host.clone()
    }

    pub fn current_line(&self) -> &str {
        &self.line
    }

    pub const fn current_cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_waiting(&self) -> bool {
        self.host.borrow().foreground_active()
    }

    pub fn accept(&mut self, bytes: &[u8]) -> bool {
        if self.host.borrow().foreground_active() {
            return false;
        }
        let mut changed = false;
        for byte in bytes.iter().copied() {
            match byte {
                ENTER => {
                    self.execute_line();
                    changed = true;
                }
                BACKSPACE if self.cursor != 0 => {
                    self.cursor -= 1;
                    self.line.remove(self.cursor);
                    self.history_position = None;
                    changed = true;
                }
                CLEAR => {
                    self.host
                        .borrow_mut()
                        .emit(ConsoleMessage::Output(vec![CLEAR]));
                    changed = true;
                }
                CANCEL => {
                    self.line.clear();
                    self.cursor = 0;
                    self.history_position = None;
                    self.host.borrow_mut().error(String::from("^C"));
                    changed = true;
                }
                HISTORY_PREVIOUS => changed |= self.recall_previous(),
                HISTORY_NEXT => changed |= self.recall_next(),
                CURSOR_LEFT if self.cursor != 0 => {
                    self.cursor -= 1;
                    changed = true;
                }
                CURSOR_RIGHT if self.cursor < self.line.len() => {
                    self.cursor += 1;
                    changed = true;
                }
                0x20..=0x7e if self.line.len() < MAX_LINE_BYTES => {
                    self.line.insert(self.cursor, byte as char);
                    self.cursor += 1;
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
        self.cursor = 0;
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

        let mut runtime_host = TerminalHost {
            state: self.host.clone(),
        };
        match self.interpreter.eval(&source, "<input>", &mut runtime_host) {
            Ok(value) if !value.is_unit() => runtime_host
                .state
                .borrow_mut()
                .output(format_terminal_value(&value)),
            Ok(_) => {}
            Err(error) => runtime_host.state.borrow_mut().error(error.to_string()),
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
        self.cursor = self.line.len();
        true
    }

    fn recall_next(&mut self) -> bool {
        let Some(position) = self.history_position else {
            return false;
        };
        if position + 1 < self.history.len() {
            self.history_position = Some(position + 1);
            self.line = self.history[position + 1].clone();
            self.cursor = self.line.len();
        } else {
            self.history_position = None;
            self.line.clear();
            self.cursor = 0;
        }
        true
    }
}

fn command_argument(value: &Dynamic) -> String {
    value
        .as_string()
        .map(String::from)
        .unwrap_or_else(|| value.to_string())
}

fn resolve_shell_path(current: &str, path: &str) -> Result<String, &'static str> {
    if path.as_bytes().contains(&0) || path.contains('\\') {
        return Err("paths may not contain NUL bytes or backslashes");
    }
    let mut components: Vec<&str> = if path.starts_with('/') {
        Vec::new()
    } else {
        current.split('/').filter(|part| !part.is_empty()).collect()
    };
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err("path escapes the filesystem capability root");
                }
            }
            component => components.push(component),
        }
    }
    Ok(components.join("/"))
}

fn command_error(host: &mut HostState, name: &str, detail: impl core::fmt::Display) -> Dynamic {
    host.error(format!("{}: {}", name, detail));
    Dynamic::from(())
}

fn copy_file(root: Handle, source: &str, destination: &str) -> Result<(), Status> {
    if source == destination || destination.is_empty() {
        return Err(Status::InvalidArgument);
    }
    let source_file = filesystem_open(root, source, FilesystemOpenFlags::READ)?;
    let reservation = match (0..16).find_map(|index| {
        let candidate = format!("{}.ginkgo-copy-{}.tmp", destination, index);
        match filesystem_create_directory(root, &candidate) {
            Ok(()) => Some(Ok(candidate)),
            Err(Status::AlreadyExists) => None,
            Err(error) => Some(Err(error)),
        }
    }) {
        Some(Ok(reservation)) => reservation,
        Some(Err(error)) => {
            let _ = handle_close(source_file);
            return Err(error);
        }
        None => {
            let _ = handle_close(source_file);
            return Err(Status::ResourceLimit);
        }
    };
    let temporary = format!("{}/payload", reservation);
    let temporary_file = match filesystem_open(
        root,
        &temporary,
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE,
    ) {
        Ok(file) => file,
        Err(error) => {
            let _ = handle_close(source_file);
            let _ = filesystem_remove_directory(root, &reservation);
            return Err(error);
        }
    };
    let copy_result = (|| {
        let length = filesystem_stat(source_file)?.length;
        let mut buffer = [0u8; FILE_CHUNK_BYTES];
        let mut offset = 0u64;
        while offset < length {
            let count = filesystem_read(source_file, offset, &mut buffer)?;
            if count == 0 {
                return Err(Status::Io);
            }
            let mut written = 0;
            while written < count {
                let amount = filesystem_write(
                    temporary_file,
                    offset + written as u64,
                    &buffer[written..count],
                )?;
                if amount == 0 {
                    return Err(Status::Io);
                }
                written += amount;
            }
            offset = offset.checked_add(count as u64).ok_or(Status::OutOfRange)?;
        }
        filesystem_truncate(temporary_file, length)?;
        filesystem_sync(temporary_file)
    })();
    let _ = handle_close(temporary_file);
    let _ = handle_close(source_file);
    if let Err(error) = copy_result {
        let _ = filesystem_unlink(root, &temporary);
        let _ = filesystem_remove_directory(root, &reservation);
        return Err(error);
    }
    let result = filesystem_rename(
        root,
        &temporary,
        root,
        destination,
        FilesystemRenameFlags::REPLACE,
    );
    if result.is_err() {
        let _ = filesystem_unlink(root, &temporary);
    }
    let _ = filesystem_remove_directory(root, &reservation);
    result
}

fn execute_path(
    host: &mut HostState,
    target: &str,
    arguments: Array,
    foreground: bool,
) -> Result<Dynamic, String> {
    let path = resolve_shell_path(&host.current_directory, target)
        .map_err(|error| format!("{}: {}", target, error))?;
    if path.is_empty() {
        return Err(format!("{}: executable path is empty", target));
    }
    let string_arguments: Array = arguments
        .into_iter()
        .map(|value| Dynamic::from(command_argument(&value)))
        .collect();
    if !foreground {
        return Ok(Dynamic::from(host.spawn(&path, string_arguments)));
    }
    let arguments =
        argument_strings(string_arguments).map_err(|error| format!("{}: {}", target, error))?;
    let blob =
        encode_arguments(&path, &arguments).map_err(|error| format!("{}: {}", target, error))?;
    host.start_path_foreground(&path, &blob)
        .map_err(|error| format!("{}: {}", target, error))?;
    Ok(Dynamic::Unit)
}

fn dispatch_command(host: &mut HostState, name: &str, arguments: Array) -> Dynamic {
    let Some(spec) = COMMAND_SPECS.iter().find(|spec| {
        spec.canonical_name == name || spec.aliases.iter().any(|alias| *alias == name)
    }) else {
        return command_error(host, name, "unknown builtin");
    };
    let name = spec.canonical_name;
    if arguments.len() < spec.min_args {
        return command_error(
            host,
            name,
            format!(
                "expected at least {} argument(s), received {}",
                spec.min_args,
                arguments.len()
            ),
        );
    }
    if spec
        .max_args
        .is_some_and(|maximum| arguments.len() > maximum)
    {
        return command_error(
            host,
            name,
            format!(
                "expected at most {} argument(s), received {}",
                spec.max_args.unwrap_or(0),
                arguments.len()
            ),
        );
    }

    let values: Vec<String> = arguments.iter().map(command_argument).collect();
    let resolve = |path: &str| resolve_shell_path(&host.current_directory, path);
    match name {
        "list_files" => {
            let path = match values.first() {
                Some(path) => match resolve(path) {
                    Ok(path) => path,
                    Err(error) => return command_error(host, name, error),
                },
                None => host.current_directory.clone(),
            };
            match list_directory(host.filesystem, &path) {
                Ok(entries) => Dynamic::from(entries),
                Err(error) => command_error(host, name, format!("{}: {:?}", path, error)),
            }
        }
        "change_directory" => {
            let path = match resolve(&values[0]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            if !path.is_empty() {
                match filesystem_open_directory(host.filesystem, &path) {
                    Ok(directory) => {
                        let _ = handle_close(directory);
                    }
                    Err(error) => {
                        return command_error(host, name, format!("{}: {:?}", path, error))
                    }
                }
            }
            host.current_directory = path;
            Dynamic::from(())
        }
        "current_directory" => Dynamic::from(if host.current_directory.is_empty() {
            String::from("/")
        } else {
            format!("/{}", host.current_directory)
        }),
        "copy" => {
            let source = match resolve(&values[0]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            let destination = match resolve(&values[1]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            match copy_file(host.filesystem, &source, &destination) {
                Ok(()) => Dynamic::from(true),
                Err(error) => command_error(host, name, format!("{:?}", error)),
            }
        }
        "move" => {
            let source = match resolve(&values[0]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            let destination = match resolve(&values[1]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            match filesystem_rename(
                host.filesystem,
                &source,
                host.filesystem,
                &destination,
                FilesystemRenameFlags::empty(),
            ) {
                Ok(()) => Dynamic::from(true),
                Err(error) => command_error(host, name, format!("{:?}", error)),
            }
        }
        "remove" | "make_directory" | "remove_directory" => {
            let paths: Vec<String> = match values
                .iter()
                .map(|value| resolve(value))
                .collect::<Result<_, _>>()
            {
                Ok(paths) => paths,
                Err(error) => return command_error(host, name, error),
            };
            for path in paths {
                let result = match name {
                    "remove" => filesystem_unlink(host.filesystem, &path),
                    "make_directory" => filesystem_create_directory(host.filesystem, &path),
                    _ => filesystem_remove_directory(host.filesystem, &path),
                };
                if let Err(error) = result {
                    return command_error(host, name, format!("{}: {:?}", path, error));
                }
            }
            Dynamic::from(true)
        }
        "show_file" => {
            let mut text = String::new();
            for value in &values {
                let path = match resolve(value) {
                    Ok(path) => path,
                    Err(error) => return command_error(host, name, error),
                };
                match read_text(host.filesystem, &path) {
                    Ok(contents) => text.push_str(&contents),
                    Err(error) => {
                        return command_error(host, name, format!("{}: {:?}", path, error))
                    }
                }
            }
            Dynamic::from(text)
        }
        "install" => {
            let path = match resolve(&values[0]) {
                Ok(path) => path,
                Err(error) => return command_error(host, name, error),
            };
            match install_package(host.filesystem, &path) {
                Ok(()) => Dynamic::from(true),
                Err(error) => command_error(host, name, error),
            }
        }
        "uninstall" => match uninstall_app(host.filesystem, &values[0]) {
            Ok(()) => Dynamic::from(true),
            Err(error) => command_error(host, name, error),
        },
        "package" => match package_command(host.filesystem, &host.current_directory, &values) {
            Ok(()) => Dynamic::from(true),
            Err(error) => command_error(host, name, error),
        },
        "unpackage" => match unpackage_command(
            host.filesystem,
            &host.current_directory,
            &values[0],
            &values[1],
        ) {
            Ok(()) => Dynamic::from(true),
            Err(error) => command_error(host, name, error),
        },
        "installed" => match load_registry(host.filesystem) {
            Ok(registry) => Dynamic::from(installed_array(&registry)),
            Err(error) => command_error(host, name, error),
        },
        "clear_terminal" => {
            host.emit(ConsoleMessage::Output(vec![CLEAR]));
            Dynamic::from(())
        }
        "show_processes" => {
            let mut processes = Array::new();
            for job in &host.jobs {
                let mut map = match process_get_info(job.process) {
                    Ok(info) => process_map(info),
                    Err(error) => {
                        let mut map = Map::new();
                        map.insert("error".into(), Dynamic::from(format!("{:?}", error)));
                        map
                    }
                };
                map.insert("job_id".into(), Dynamic::from(job.id));
                processes.push(Dynamic::from(map));
            }
            Dynamic::from(processes)
        }
        "terminate_process" => match values[0].parse::<INT>() {
            Ok(id) => Dynamic::from(
                host.job_process(id)
                    .is_some_and(|process| process_terminate(process).is_ok()),
            ),
            Err(_) => command_error(host, name, "job ID must be an integer"),
        },
        "help" => Dynamic::from(command_help(values.first().map(String::as_str))),
        "exit" => {
            host.exit_requested = true;
            Dynamic::Unit
        }
        "launch" | "edit" => command_error(host, name, "invalid builtin dispatch"),
        _ => command_error(host, name, "unknown canonical command"),
    }
}

fn command_help(command: Option<&str>) -> String {
    match command {
        Some("ls" | "dir" | "list_files") => String::from(
            "ls, dir [path]\n    List directory entries as structured values.",
        ),
        Some("cd" | "chdir" | "change_directory") => String::from(
            "cd, chdir <path>\n    Change the logical directory beneath the filesystem capability root.",
        ),
        Some("pwd" | "cwd" | "current_directory") => {
            String::from("pwd, cwd\n    Show the logical current directory.")
        }
        Some("cp" | "copy") => String::from(
            "cp <source> <destination>\n    Atomically copy one file.",
        ),
        Some("mv" | "move" | "ren" | "rename") => String::from(
            "mv, ren, rename <source> <destination>\n    Move or rename without replacing an existing destination.",
        ),
        Some("rm" | "del" | "delete" | "remove") => String::from(
            "rm, del, delete <path>...\n    Remove one or more files.",
        ),
        Some("mkdir" | "md" | "make_directory") => String::from(
            "mkdir, md <path>...\n    Create one or more directories; parents must exist.",
        ),
        Some("rmdir" | "rd" | "remove_directory") => String::from(
            "rmdir, rd <path>...\n    Remove one or more empty directories.",
        ),
        Some("cat" | "type" | "show_file") => String::from(
            "cat, type <path>...\n    Display UTF-8 text files.",
        ),
        Some("clear" | "cls" | "clear_terminal") => {
            String::from("clear, cls\n    Clear terminal scrollback.")
        }
        Some("ps" | "tasks" | "show_processes") => String::from(
            "ps, tasks\n    List jobs started by this terminal.",
        ),
        Some("kill" | "stop" | "terminate_process") => String::from(
            "kill, stop <job-id>\n    Terminate a job started by this terminal.",
        ),
        Some("print" | "output") => String::from(
            "print <expression>\n    Print one Ginkgo shell value.",
        ),
        Some("launch") => String::from(
            "launch <app>, [arguments...]\n    Start an application or WABT tool in a new terminal.",
        ),
        Some("edit") => String::from(
            "edit <path>\n    Open a file beneath /user in a new text editor window and wait for it to close.",
        ),
        Some("exit" | "quit") => String::from("exit, quit\n    Close the terminal."),
        Some("install" | "install_package") => String::from(
            "install <package.gkp>\n    Install or update an application package.",
        ),
        Some("uninstall" | "uninstall_app") => String::from(
            "uninstall <app-id>\n    Remove an installed non-system application. App data is preserved.",
        ),
        Some("package" | "pack") => String::from(
            "package <executable>, <output.gkp>, <app-id>, <display-name>, <version>[, command|graphical]\npackage <source-directory>, <output.gkp>\n    Create a GKP directly or rebuild an unpacked editable package directory.",
        ),
        Some("unpackage" | "unpack") => String::from(
            "unpackage <package.gkp>, <directory>\n    Extract package.gkm, the executable, and assets for editing.",
        ),
        Some("installed" | "list_installed") => String::from(
            "installed\n    List installed application metadata.",
        ),
        Some("help") => String::from("help [command]\n    Show command help."),
        Some(name) if WABT_TOOL_NAMES.contains(&name) => format!(
            "{} [arguments...]\n    Run the bundled WABT 1.0.41 WASI tool with /user mounted as /. See /system/docs/webassembly.md.",
            name
        ),
        Some(name) => format!("help: no registered command named `{}`", name),
        None => String::from(
            "Ginkgo shell\n\nCOMMANDS\n  ls, dir [path]             list directory entries\n  cd, chdir <path>           change logical directory\n  pwd, cwd                   show logical directory\n  cp <source>, <destination> copy a file atomically\n  mv <source>, <destination> move or rename\n  rm, del <path>, ...        remove files\n  mkdir, md <path>, ...      create directories\n  rmdir, rd <path>, ...      remove empty directories\n  cat, type <path>, ...      display text files\n  edit <path>                open a file in the text editor\n  install <package.gkp>      install or update an application\n  uninstall <app-id>         uninstall a non-system application\n  package ...                create or rebuild a GKP package\n  unpackage <gkp>, <dir>     extract a package for editing\n  installed                  list installed applications\n  launch <app>, ...          open an app without blocking this terminal\n  exit, quit                 close the terminal\n  clear, cls                 clear the terminal\n  ps, tasks                  list terminal jobs\n  kill, stop <job-id>        terminate a terminal job\n  print <expression>         print a value\n  help [command]             show this help\n\nSYNTAX\n  command value, value       run a command with comma-separated values\n  $name = value              assign a persistent variable\n  @[value, value]            create a list\n  def name($arg) ... end     define a function\n  alias short = target       define an alias\n  include \"file.gsh\"       evaluate a file once\n  run \"file.gsh\"           evaluate a script every time\n  app-name                   run a command app here and wait\n  launch app-name            run a command app in a new terminal\n  !app                       force an installed application\n  %builtin                   force a builtin\n  /path/program.elf|.wasm    run an executable path\n  *, *.ts, **/*              expand matching paths",
        ),
    }
}

fn table_cell(value: &str, width: usize) -> String {
    let mut cell: String = value.chars().take(width).collect();
    let length = cell.chars().count();
    if value.chars().count() > width && width != 0 {
        cell.pop();
        cell.push('~');
    }
    for _ in length..width {
        cell.push(' ');
    }
    cell
}

fn map_text(map: &Map, key: &str) -> String {
    map.get(key).map_or_else(String::new, Dynamic::to_string)
}

fn format_map_table(values: &[Dynamic]) -> Option<String> {
    let maps: Option<Vec<Map>> = values
        .iter()
        .map(|value| match value {
            Dynamic::Map(map) => Some(map.clone()),
            _ => None,
        })
        .collect();
    let maps = maps?;
    if maps.iter().all(|map| map.contains_key("name")) {
        let name_width = maps
            .iter()
            .map(|map| map_text(map, "name").chars().count())
            .max()
            .unwrap_or(4)
            .clamp(4, 32);
        let mut output = format!(
            "{}  {}  {}\n{}  ----------  ----------",
            table_cell("NAME", name_width),
            table_cell("KIND", 10),
            table_cell("SIZE", 10),
            table_cell("", name_width).replace(' ', "-")
        );
        for map in &maps {
            output.push_str(&format!(
                "\n{}  {}  {}",
                table_cell(&map_text(map, "name"), name_width),
                table_cell(&map_text(map, "kind"), 10),
                table_cell(&map_text(map, "size"), 10),
            ));
        }
        return Some(output);
    }
    if maps.iter().all(|map| map.contains_key("job_id")) {
        let mut output =
            String::from("JOB   STATE       RESULT\n----  ----------  ----------------");
        for map in &maps {
            let result = if map.contains_key("exit_code") {
                map_text(map, "exit_code")
            } else if map.contains_key("fault") {
                map_text(map, "fault")
            } else if map.contains_key("error") {
                map_text(map, "error")
            } else {
                String::new()
            };
            output.push_str(&format!(
                "\n{}  {}  {}",
                table_cell(&map_text(map, "job_id"), 4),
                table_cell(&map_text(map, "state"), 10),
                result
            ));
        }
        return Some(output);
    }
    None
}

fn format_terminal_value(value: &Dynamic) -> String {
    let Dynamic::List(values) = value else {
        return value.to_string();
    };
    if values.is_empty() {
        return String::from("(no entries)");
    }
    format_map_table(&values).unwrap_or_else(|| {
        values
            .iter()
            .map(structured_value_text)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn structured_value_text(value: &Dynamic) -> String {
    match value {
        Dynamic::Map(map) => map.get("name").unwrap_or(value).to_string(),
        _ => value.to_string(),
    }
}

struct TerminalHost {
    state: Rc<RefCell<HostState>>,
}

impl Host for TerminalHost {
    fn call(&mut self, mode: CallMode, name: &str, arguments: Array) -> Result<Dynamic, String> {
        match mode {
            CallMode::AbsolutePath => {
                return execute_path(&mut self.state.borrow_mut(), name, arguments, true);
            }
            CallMode::Application => {
                return launch_application(&mut self.state.borrow_mut(), name, arguments, true);
            }
            CallMode::Builtin => {
                return call_builtin(&mut self.state.borrow_mut(), name, arguments)
            }
            CallMode::Auto => {}
        }

        if name.ends_with(".wasm") || name.ends_with(".elf") {
            return execute_path(&mut self.state.borrow_mut(), name, arguments, true);
        }
        if let Some(path) = wabt_tool_path(name) {
            return execute_path(&mut self.state.borrow_mut(), &path, arguments, true);
        }

        let registered = {
            let state = self.state.borrow();
            resolve_registered_app(state.filesystem, name)?
        };
        if let Some(app) = registered {
            return run_registered_application(&mut self.state.borrow_mut(), app, arguments, true);
        }
        call_builtin(&mut self.state.borrow_mut(), name, arguments)
    }

    fn include(&mut self, path: &str) -> Result<String, String> {
        let state = self.state.borrow();
        let resolved = resolve_shell_path(&state.current_directory, path)
            .map_err(|error| format!("include: {}: {}", path, error))?;
        read_text(state.filesystem, &resolved)
            .map_err(|error| format!("include: /{}: {:?}", resolved, error))
    }

    fn glob(&mut self, pattern: &str) -> Result<Vec<String>, String> {
        let state = self.state.borrow();
        expand_glob(state.filesystem, &state.current_directory, pattern)
            .map_err(|error| format!("glob {}: {:?}", pattern, error))
    }
}

fn wabt_tool_path(name: &str) -> Option<String> {
    WABT_TOOL_NAMES
        .contains(&name)
        .then(|| format!("{}{}", WABT_TOOL_DIRECTORY, name))
}

fn launch_application(
    host: &mut HostState,
    name: &str,
    arguments: Array,
    foreground: bool,
) -> Result<Dynamic, String> {
    let app = resolve_registered_app(host.filesystem, name)?
        .ok_or_else(|| format!("{}: application not found", name))?;
    run_registered_application(host, app, arguments, foreground)
}

enum RegisteredApp {
    Graphical(String),
    Command(String),
}

fn run_registered_application(
    host: &mut HostState,
    app: RegisteredApp,
    arguments: Array,
    foreground: bool,
) -> Result<Dynamic, String> {
    match app {
        RegisteredApp::Graphical(app_id) => {
            if !arguments.is_empty() {
                return Err(format!(
                    "{}: graphical application arguments are not supported",
                    app_id
                ));
            }
            Ok(Dynamic::from(host.launch(app_id, foreground, None)))
        }
        RegisteredApp::Command(app_id) if foreground => {
            let arguments =
                argument_strings(arguments).map_err(|error| format!("{}: {}", app_id, error))?;
            host.start_installed_foreground(&app_id, &arguments)
                .map_err(|error| format!("{}: {}", app_id, error))?;
            Ok(Dynamic::Unit)
        }
        RegisteredApp::Command(app_id) => {
            let arguments =
                argument_strings(arguments).map_err(|error| format!("{}: {}", app_id, error))?;
            Ok(Dynamic::from(
                host.launch_command_terminal(app_id, arguments),
            ))
        }
    }
}

fn resolve_registered_app(root: Handle, name: &str) -> Result<Option<RegisteredApp>, String> {
    let alias = match name {
        "editor" => "text-editor",
        "files" => "file-navigator",
        "demo" => "minimal-client",
        name => name,
    };
    if let Ok(installed) = load_registry(root) {
        if let Some(entry) = installed.get(alias) {
            return Ok(Some(match entry.kind {
                AppKind::Graphical => RegisteredApp::Graphical(alias.to_string()),
                AppKind::Command => RegisteredApp::Command(alias.to_string()),
            }));
        }
    }

    let bytes = match read_bounded(root, PROGRAM_REGISTRY_PATH, MAX_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(Status::NotFound) => return Ok(None),
        Err(error) => return Err(format!("program registry: {:?}", error)),
    };
    let registry =
        ProgramRegistry::parse(&bytes).map_err(|error| format!("program registry: {:?}", error))?;
    Ok(registry.entries().find_map(|entry| {
        let executable = entry.executable_path.rsplit('/').next().unwrap_or("");
        let executable_name = executable.strip_suffix(".elf").unwrap_or(executable);
        (entry.app_id == alias || executable == alias || executable_name == alias)
            .then(|| RegisteredApp::Graphical(entry.app_id.to_string()))
    }))
}

fn builtin_spec(name: &str) -> Option<&'static CommandSpec> {
    COMMAND_SPECS
        .iter()
        .find(|spec| spec.canonical_name == name || spec.aliases.iter().any(|alias| *alias == name))
}

fn require_arguments(
    name: &str,
    arguments: &[Dynamic],
    minimum: usize,
    maximum: usize,
) -> Result<(), String> {
    if arguments.len() < minimum || arguments.len() > maximum {
        return Err(format!(
            "{}: expected {}..={} arguments, received {}",
            name,
            minimum,
            maximum,
            arguments.len()
        ));
    }
    Ok(())
}

fn string_argument<'a>(
    name: &str,
    arguments: &'a [Dynamic],
    index: usize,
) -> Result<&'a str, String> {
    arguments
        .get(index)
        .and_then(Dynamic::as_string)
        .ok_or_else(|| format!("{}: argument {} must be a string", name, index + 1))
}

fn integer_argument(name: &str, arguments: &[Dynamic], index: usize) -> Result<INT, String> {
    arguments
        .get(index)
        .and_then(Dynamic::as_integer)
        .ok_or_else(|| format!("{}: argument {} must be an integer", name, index + 1))
}

fn boolean_argument(name: &str, arguments: &[Dynamic], index: usize) -> Result<bool, String> {
    arguments
        .get(index)
        .and_then(Dynamic::as_bool)
        .ok_or_else(|| format!("{}: argument {} must be a boolean", name, index + 1))
}

fn list_argument(name: &str, arguments: &[Dynamic], index: usize) -> Result<Array, String> {
    arguments
        .get(index)
        .and_then(Dynamic::as_list)
        .cloned()
        .ok_or_else(|| format!("{}: argument {} must be a list", name, index + 1))
}

fn call_builtin(host: &mut HostState, name: &str, arguments: Array) -> Result<Dynamic, String> {
    match name {
        "print" | "output" => {
            require_arguments(name, &arguments, 1, 1)?;
            host.output(format_terminal_value(&arguments[0]));
            return Ok(Dynamic::Unit);
        }
        "eprint" => {
            require_arguments(name, &arguments, 1, 1)?;
            host.error(arguments[0].to_string());
            return Ok(Dynamic::Unit);
        }
        "filter" => {
            require_arguments(name, &arguments, 2, 2)?;
            let values = list_argument(name, &arguments, 0)?;
            let pattern = string_argument(name, &arguments, 1)?;
            return Ok(Dynamic::from(
                values
                    .into_iter()
                    .filter(|value| structured_value_text(value).contains(pattern))
                    .collect::<Array>(),
            ));
        }
        "sort" => {
            require_arguments(name, &arguments, 1, 1)?;
            let mut values = list_argument(name, &arguments, 0)?;
            values.sort_by_key(structured_value_text);
            return Ok(Dynamic::from(values));
        }
        "launch" => {
            require_arguments(name, &arguments, 1, usize::MAX)?;
            let app = string_argument(name, &arguments, 0)?.to_string();
            if wabt_tool_path(&app).is_some() {
                let arguments = argument_strings(arguments[1..].to_vec())
                    .map_err(|error| format!("{}: {}", app, error))?;
                return Ok(Dynamic::from(host.launch_command_terminal(app, arguments)));
            }
            if app.starts_with('/')
                || app.contains('/')
                || app.ends_with(".elf")
                || app.ends_with(".wasm")
            {
                return execute_path(host, &app, arguments[1..].to_vec(), false);
            }
            return launch_application(host, &app, arguments[1..].to_vec(), false);
        }
        "edit" => {
            require_arguments(name, &arguments, 1, 1)?;
            let path = string_argument(name, &arguments, 0)?;
            let resolved = resolve_shell_path(&host.current_directory, path)
                .map_err(|error| format!("edit: {}: {}", path, error))?;
            let document = resolved
                .strip_prefix("user/")
                .filter(|path| !path.is_empty())
                .ok_or_else(|| {
                    String::from("edit: the text editor can only open files under /user")
                })?;
            return Ok(Dynamic::from(host.launch(
                String::from("text-editor"),
                true,
                Some(document.to_string()),
            )));
        }
        _ => {}
    }

    if builtin_spec(name).is_some() {
        return Ok(dispatch_command(host, name, arguments));
    }

    call_system_builtin(host, name, arguments)
}

fn call_system_builtin(
    host: &mut HostState,
    name: &str,
    arguments: Array,
) -> Result<Dynamic, String> {
    match name {
        "read_file" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                read_text(host.filesystem, string_argument(name, &arguments, 0)?)
                    .map_err(|error| format!("read_file: {:?}", error))?,
            ))
        }
        "write_file" | "append_file" => {
            require_arguments(name, &arguments, 2, 2)?;
            let path = string_argument(name, &arguments, 0)?;
            let contents = string_argument(name, &arguments, 1)?;
            Ok(Dynamic::from(
                write_bytes(
                    host.filesystem,
                    path,
                    contents.as_bytes(),
                    name == "append_file",
                )
                .is_ok(),
            ))
        }
        "remove_file" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                filesystem_unlink(host.filesystem, string_argument(name, &arguments, 0)?).is_ok(),
            ))
        }
        "mkdir" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                filesystem_create_directory(host.filesystem, string_argument(name, &arguments, 0)?)
                    .is_ok(),
            ))
        }
        "rmdir" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                filesystem_remove_directory(host.filesystem, string_argument(name, &arguments, 0)?)
                    .is_ok(),
            ))
        }
        "rename_path" => {
            require_arguments(name, &arguments, 3, 3)?;
            let flags = if boolean_argument(name, &arguments, 2)? {
                FilesystemRenameFlags::REPLACE
            } else {
                FilesystemRenameFlags::empty()
            };
            Ok(Dynamic::from(
                filesystem_rename(
                    host.filesystem,
                    string_argument(name, &arguments, 0)?,
                    host.filesystem,
                    string_argument(name, &arguments, 1)?,
                    flags,
                )
                .is_ok(),
            ))
        }
        "sync_filesystem" => {
            require_arguments(name, &arguments, 0, 0)?;
            Ok(Dynamic::from(filesystem_sync(host.filesystem).is_ok()))
        }
        "metadata" => {
            require_arguments(name, &arguments, 1, 1)?;
            filesystem_get_metadata(host.filesystem, string_argument(name, &arguments, 0)?)
                .map(metadata_map)
                .map(Dynamic::from)
                .map_err(|error| format!("metadata: {:?}", error))
        }
        "list_directory" => {
            require_arguments(name, &arguments, 1, 1)?;
            list_directory(host.filesystem, string_argument(name, &arguments, 0)?)
                .map(Dynamic::from)
                .map_err(|error| format!("list_directory: {:?}", error))
        }
        "file_size" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                file_size(host.filesystem, string_argument(name, &arguments, 0)?)
                    .ok()
                    .and_then(|value| INT::try_from(value).ok())
                    .unwrap_or(-1),
            ))
        }
        "syscall" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                string_argument(name, &arguments, 0)? == "yield" && process_yield().is_ok(),
            ))
        }
        _ => call_privileged_builtin(host, name, arguments),
    }
}

fn call_privileged_builtin(
    host: &mut HostState,
    name: &str,
    arguments: Array,
) -> Result<Dynamic, String> {
    match name {
        "power_off" | "reboot" => {
            require_arguments(name, &arguments, 2, 2)?;
            if !boolean_argument(name, &arguments, 0)? {
                return Err(format!("{}: pass true to confirm", name));
            }
            let flags = if boolean_argument(name, &arguments, 1)? {
                SystemPowerFlags::FORCE
            } else {
                SystemPowerFlags::empty()
            };
            let action = if name == "power_off" {
                SystemPowerAction::PowerOff
            } else {
                SystemPowerAction::Reboot
            };
            system_power_request(host.power, action, flags)
                .map(|()| Dynamic::from(true))
                .map_err(|error| format!("{}: {:?}", name, error))
        }
        "cancel_power" => {
            require_arguments(name, &arguments, 0, 0)?;
            Ok(Dynamic::from(system_power_cancel(host.power).is_ok()))
        }
        "power_status" => {
            require_arguments(name, &arguments, 0, 0)?;
            let info = system_power_get_info(host.power)
                .map_err(|error| format!("power_status: {:?}", error))?;
            let state = match info.power_state() {
                Some(SystemPowerState::Idle) => "idle",
                Some(SystemPowerState::Requested) => "requested",
                Some(SystemPowerState::Quiescing) => "quiescing",
                Some(SystemPowerState::Synchronizing) => "synchronizing",
                Some(SystemPowerState::Committing) => "committing",
                Some(SystemPowerState::Canceled) => "canceled",
                Some(SystemPowerState::Failed) => "failed",
                None => "invalid",
            };
            let mut map = Map::new();
            map.insert("state".into(), Dynamic::from(state));
            map.insert("sequence".into(), filesystem_integer(info.sequence));
            map.insert("deadline_ns".into(), filesystem_integer(info.deadline_ns));
            map.insert(
                "failure_status".into(),
                Dynamic::from(INT::from(info.failure_status)),
            );
            Ok(Dynamic::from(map))
        }
        "filesystem_info" => {
            require_arguments(name, &arguments, 0, 0)?;
            let info = filesystem_get_info(host.filesystem)
                .map_err(|error| format!("filesystem_info: {:?}", error))?;
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
            Ok(Dynamic::from(map))
        }
        "spawn_elf" | "spawn_installed" => {
            require_arguments(name, &arguments, 2, 2)?;
            let target = string_argument(name, &arguments, 0)?.to_string();
            let process_arguments = list_argument(name, &arguments, 1)?;
            let id = if name == "spawn_elf" {
                host.spawn(&target, process_arguments)
            } else {
                host.spawn_installed(&target, process_arguments)
            };
            Ok(Dynamic::from(id))
        }
        "process_status" | "wait_process" => {
            require_arguments(name, &arguments, 1, 1)?;
            let id = integer_argument(name, &arguments, 0)?;
            let process = host
                .job_process(id)
                .ok_or_else(|| format!("{}: unknown job {}", name, id))?;
            let result = if name == "process_status" {
                process_get_info(process)
            } else {
                process_wait(process, DEADLINE_INFINITE)
            };
            Ok(process_result(name, result))
        }
        "terminate_process" => {
            require_arguments(name, &arguments, 1, 1)?;
            let id = integer_argument(name, &arguments, 0)?;
            Ok(Dynamic::from(
                host.job_process(id)
                    .is_some_and(|process| process_terminate(process).is_ok()),
            ))
        }
        "close_process" => {
            require_arguments(name, &arguments, 1, 1)?;
            Ok(Dynamic::from(
                host.close_job(integer_argument(name, &arguments, 0)?),
            ))
        }
        "exec_elf" | "exec_installed" => {
            require_arguments(name, &arguments, 2, 2)?;
            let target = string_argument(name, &arguments, 0)?.to_string();
            let process_arguments = argument_strings(list_argument(name, &arguments, 1)?)
                .map_err(|error| format!("{}: {}", name, error))?;
            let process = if name == "exec_elf" {
                let blob = encode_arguments(&target, &process_arguments)
                    .map_err(|error| format!("exec_elf: {}", error))?;
                create_headless_process(
                    host.filesystem,
                    host.shell_endpoint,
                    host.random,
                    &target,
                    &blob,
                )
                .map_err(|error| format!("exec_elf: {:?}", error))?
            } else {
                create_installed_process(
                    host.filesystem,
                    host.shell_endpoint,
                    host.random,
                    &target,
                    &process_arguments,
                )
                .map_err(|error| format!("exec_installed: {}", error))?
            };
            let result = process_wait(process, DEADLINE_INFINITE);
            let _ = handle_close(process);
            Ok(process_result(name, result))
        }
        "install_package" | "uninstall_app" | "purge_app_data" => {
            require_arguments(name, &arguments, 1, 1)?;
            let target = string_argument(name, &arguments, 0)?;
            let result = match name {
                "install_package" => install_package(host.filesystem, target),
                "uninstall_app" => uninstall_app(host.filesystem, target),
                _ => purge_app_data(host.filesystem, target),
            };
            result
                .map(|()| Dynamic::from(true))
                .map_err(|error| format!("{}: {}", name, error))
        }
        "list_installed" => {
            require_arguments(name, &arguments, 0, 0)?;
            load_registry(host.filesystem)
                .map(|registry| Dynamic::from(installed_array(&registry)))
                .map_err(|error| format!("list_installed: {}", error))
        }

        _ => Err(format!("{}: command not found", name)),
    }
}

fn expand_glob(root: Handle, current: &str, pattern: &str) -> Result<Vec<String>, Status> {
    let absolute = pattern.starts_with('/');
    let base = if absolute { "" } else { current };
    let mut candidates = Vec::new();
    collect_glob_candidates(root, base, "", 0, &mut candidates)?;
    let mut matches = Vec::new();
    for relative in candidates {
        let candidate = if absolute {
            format!("/{}", relative)
        } else {
            relative
        };
        if glob_matches(pattern.as_bytes(), candidate.as_bytes()) {
            matches.push(candidate);
        }
    }
    matches.sort();
    Ok(matches)
}

fn collect_glob_candidates(
    root: Handle,
    base: &str,
    relative: &str,
    depth: usize,
    output: &mut Vec<String>,
) -> Result<(), Status> {
    if depth >= MAX_PURGE_DEPTH || output.len() >= 4096 {
        return Ok(());
    }
    let path = match (base.is_empty(), relative.is_empty()) {
        (true, true) => String::new(),
        (false, true) => base.to_string(),
        (true, false) => relative.to_string(),
        (false, false) => format!("{}/{}", base, relative),
    };
    for value in list_directory(root, &path)? {
        let Dynamic::Map(map) = value else { continue };
        let Some(name) = map.get("name").and_then(Dynamic::as_string) else {
            continue;
        };
        let child = if relative.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", relative, name)
        };
        output.push(child.clone());
        if output.len() >= 4096 {
            break;
        }
        if map.get("kind").and_then(Dynamic::as_string) == Some("directory") {
            collect_glob_candidates(root, base, &child, depth + 1, output)?;
        }
    }
    Ok(())
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    fn matches(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        if pattern.starts_with(b"**") {
            let rest = &pattern[2..];
            return matches(rest, text) || (!text.is_empty() && matches(pattern, &text[1..]));
        }
        if pattern[0] == b'*' {
            return matches(&pattern[1..], text)
                || (!text.is_empty() && text[0] != b'/' && matches(pattern, &text[1..]));
        }
        !text.is_empty() && pattern[0] == text[0] && matches(&pattern[1..], &text[1..])
    }
    pattern.len() <= MAX_LINE_BYTES && text.len() <= MAX_LINE_BYTES && matches(pattern, text)
}

fn argument_strings(arguments: Array) -> Result<Vec<String>, &'static str> {
    let mut strings = Vec::with_capacity(arguments.len());
    for value in arguments {
        let Dynamic::String(value) = value else {
            return Err("arguments must all be strings");
        };
        strings.push(value);
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

fn create_headless_process(
    root: Handle,
    console: Handle,
    random: Handle,
    path: &str,
    arguments: &[u8],
) -> Result<Handle, Status> {
    let executable = filesystem_open(
        root,
        path,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    )?;
    let mut magic = [0_u8; WASM_MAGIC.len()];
    let is_wasm = filesystem_read(executable, 0, &mut magic)
        .is_ok_and(|count| count == magic.len() && magic == WASM_MAGIC);
    if !is_wasm {
        let startup_handles = [HandleDisposition::duplicate(console, WASM_CONSOLE_RIGHTS)];
        let result = process_create(executable, arguments, &startup_handles, &[]);
        let _ = handle_close(executable);
        return result;
    }

    let runtime = match filesystem_open(
        root,
        WASM_RUNTIME_PATH,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = handle_close(executable);
            return Err(error);
        }
    };
    let preopen = match filesystem_open_directory(root, "user") {
        Ok(directory) => directory,
        Err(error) => {
            let _ = handle_close(runtime);
            let _ = handle_close(executable);
            return Err(error);
        }
    };
    let startup_handles = [
        HandleDisposition::move_handle(executable, Rights::READ),
        HandleDisposition::duplicate(console, WASM_CONSOLE_RIGHTS),
        HandleDisposition::move_handle(preopen, WASM_PREOPEN_RIGHTS),
        HandleDisposition::duplicate(random, WASM_RANDOM_RIGHTS),
    ];
    let result = process_create(runtime, arguments, &startup_handles, &[]);
    let _ = handle_close(runtime);
    if result.is_err() {
        let _ = handle_close(executable);
        let _ = handle_close(preopen);
    }
    result
}

fn create_installed_process(
    root: Handle,
    console: Handle,
    random: Handle,
    app_id: &str,
    arguments: &[String],
) -> Result<Handle, String> {
    let registry = load_registry(root)?;
    let installed = registry
        .get(app_id)
        .ok_or_else(|| format!("application {} is not installed", app_id))?;
    let path = executable_path(app_id, &installed.executable.filename);
    let expected_length = installed.executable.length;
    let expected_digest = installed.executable.digest;
    let format = installed.executable.format;
    let argument_blob = encode_arguments(&path, arguments)
        .map_err(|error| format!("invalid arguments: {}", error))?;

    let application_data = application_data_create(root, app_id)
        .map_err(|error| format!("cannot mint application-data identity: {:?}", error))?;
    let module = match filesystem_open(
        root,
        &path,
        FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
    ) {
        Ok(executable) => executable,
        Err(error) => {
            let _ = handle_close(application_data);
            return Err(format!("cannot open installed executable: {:?}", error));
        }
    };

    match file_digest_handle(module) {
        Ok((length, digest)) if length == expected_length && digest == expected_digest => {}
        Ok(_) => {
            let _ = handle_close(module);
            let _ = handle_close(application_data);
            return Err(String::from(
                "installed executable length or SHA-256 does not match the registry",
            ));
        }
        Err(error) => {
            let _ = handle_close(module);
            let _ = handle_close(application_data);
            return Err(format!("cannot verify installed executable: {:?}", error));
        }
    }

    match format {
        ExecutableFormat::Elf => {
            let startup_handles = [
                HandleDisposition::move_handle(application_data, Rights::READ),
                HandleDisposition::duplicate(console, WASM_CONSOLE_RIGHTS),
            ];
            let result = process_create(module, &argument_blob, &startup_handles, &[]);
            let _ = handle_close(module);
            if result.is_err() {
                let _ = handle_close(application_data);
            }
            result.map_err(|error| format!("process creation failed: {:?}", error))
        }
        ExecutableFormat::Wasm => {
            let preopen = match filesystem_open_directory(root, &app_data_path(app_id)) {
                Ok(directory) => directory,
                Err(error) => {
                    let _ = handle_close(module);
                    let _ = handle_close(application_data);
                    return Err(format!("cannot open application data: {:?}", error));
                }
            };
            let runtime = match filesystem_open(
                root,
                WASM_RUNTIME_PATH,
                FilesystemOpenFlags::READ | FilesystemOpenFlags::EXECUTE,
            ) {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = handle_close(module);
                    let _ = handle_close(preopen);
                    let _ = handle_close(application_data);
                    return Err(format!("cannot open WASM runtime: {:?}", error));
                }
            };
            let startup_handles = [
                HandleDisposition::move_handle(module, Rights::READ),
                HandleDisposition::duplicate(console, WASM_CONSOLE_RIGHTS),
                HandleDisposition::move_handle(preopen, WASM_PREOPEN_RIGHTS),
                HandleDisposition::duplicate(random, WASM_RANDOM_RIGHTS),
                HandleDisposition::move_handle(application_data, Rights::READ),
            ];
            let result = process_create(runtime, &argument_blob, &startup_handles, &[]);
            let _ = handle_close(runtime);
            if result.is_err() {
                let _ = handle_close(module);
                let _ = handle_close(preopen);
                let _ = handle_close(application_data);
            }
            result.map_err(|error| format!("WASM runtime creation failed: {:?}", error))
        }
    }
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
        Some(ProcessFault::OutOfMemory) => "out-of-memory",
        None => "unknown",
    }
}

struct EditablePackageManifest {
    app_id: String,
    display_name: String,
    version: String,
    kind: AppKind,
    format: ExecutableFormat,
    executable: String,
}

fn package_command(root: Handle, current: &str, arguments: &[String]) -> Result<(), String> {
    match arguments.len() {
        2 => package_editable_directory(root, current, &arguments[0], &arguments[1]),
        5 | 6 => package_executable(root, current, arguments),
        _ => Err(String::from(
            "expected either source-directory, output.gkp or executable, output.gkp, app-id, display-name, version[, command|graphical]",
        )),
    }
}

fn package_executable(root: Handle, current: &str, arguments: &[String]) -> Result<(), String> {
    let executable_path = resolve_shell_path(current, &arguments[0])
        .map_err(|error| format!("invalid executable path: {}", error))?;
    let output_path = resolve_shell_path(current, &arguments[1])
        .map_err(|error| format!("invalid output path: {}", error))?;
    let executable = read_bounded(root, &executable_path, MAX_EXECUTABLE_LEN)
        .map_err(|error| format!("cannot read executable: {:?}", error))?;
    let format = detect_executable_format(&executable_path, &executable)?;
    let kind = parse_app_kind(arguments.get(5).map(String::as_str).unwrap_or("command"))?;
    let input = PackageInput {
        app_id: &arguments[2],
        display_name: &arguments[3],
        version: &arguments[4],
        kind,
        format,
        executable: &executable,
        assets: &[],
    };
    let package = encode_package(&input)
        .map_err(|error| format!("package metadata is invalid: {:?}", error))?;
    write_bytes_synced(root, &output_path, &package)
        .map_err(|error| format!("cannot write package: {:?}", error))
}

fn package_editable_directory(
    root: Handle,
    current: &str,
    source: &str,
    output: &str,
) -> Result<(), String> {
    let source = resolve_shell_path(current, source)
        .map_err(|error| format!("invalid source directory: {}", error))?;
    let output = resolve_shell_path(current, output)
        .map_err(|error| format!("invalid output path: {}", error))?;
    let manifest_path = join_path(&source, PACKAGE_MANIFEST_NAME);
    let manifest_text = read_text_bounded(root, &manifest_path, 8 * 1024)
        .map_err(|error| format!("cannot read {}: {:?}", manifest_path, error))?;
    let manifest = parse_editable_manifest(&manifest_text)?;
    let executable_path = join_path(&source, &manifest.executable);
    let executable = read_bounded(root, &executable_path, MAX_EXECUTABLE_LEN)
        .map_err(|error| format!("cannot read executable: {:?}", error))?;
    let detected = detect_executable_format(&executable_path, &executable)?;
    if detected != manifest.format {
        return Err(String::from(
            "package.gkm format does not match the executable",
        ));
    }

    let assets_root = join_path(&source, PACKAGE_ASSETS_DIRECTORY);
    let mut owned_assets = Vec::new();
    match collect_package_assets(root, &assets_root, "", 0, &mut owned_assets) {
        Ok(()) | Err(Status::NotFound) => {}
        Err(error) => return Err(format!("cannot read package assets: {:?}", error)),
    }
    let asset_inputs: Vec<AssetInput<'_>> = owned_assets
        .iter()
        .map(|(path, data)| AssetInput {
            path: path.as_str(),
            data: data.as_slice(),
        })
        .collect();
    let input = PackageInput {
        app_id: &manifest.app_id,
        display_name: &manifest.display_name,
        version: &manifest.version,
        kind: manifest.kind,
        format: manifest.format,
        executable: &executable,
        assets: &asset_inputs,
    };
    let package = encode_package(&input)
        .map_err(|error| format!("package metadata is invalid: {:?}", error))?;
    write_bytes_synced(root, &output, &package)
        .map_err(|error| format!("cannot write package: {:?}", error))
}

fn unpackage_command(
    root: Handle,
    current: &str,
    package_path: &str,
    destination: &str,
) -> Result<(), String> {
    let package_path = resolve_shell_path(current, package_path)
        .map_err(|error| format!("invalid package path: {}", error))?;
    let destination = resolve_shell_path(current, destination)
        .map_err(|error| format!("invalid destination path: {}", error))?;
    let package_bytes = read_bounded(root, &package_path, MAX_PACKAGE_LEN)
        .map_err(|error| format!("cannot read package: {:?}", error))?;
    let package = Package::parse(&package_bytes)
        .map_err(|error| format!("invalid GKP package: {:?}", error))?;
    let mut created = Vec::new();
    ensure_directory_chain(root, &destination, &mut created)
        .map_err(|error| format!("cannot create destination: {:?}", error))?;

    let executable_name = format!("executable.{}", package.format.extension());
    let executable_path = join_path(&destination, &executable_name);
    write_bytes_synced(root, &executable_path, package.executable)
        .map_err(|error| format!("cannot extract executable: {:?}", error))?;
    let manifest = editable_manifest_text(&package, &executable_name);
    write_bytes_synced(
        root,
        &join_path(&destination, PACKAGE_MANIFEST_NAME),
        manifest.as_bytes(),
    )
    .map_err(|error| format!("cannot write package.gkm: {:?}", error))?;

    for asset in package.assets() {
        let path = join_path(
            &join_path(&destination, PACKAGE_ASSETS_DIRECTORY),
            asset.path,
        );
        if let Some((parent, _)) = path.rsplit_once('/') {
            ensure_directory_chain(root, parent, &mut created)
                .map_err(|error| format!("cannot create asset directory: {:?}", error))?;
        }
        write_bytes_synced(root, &path, asset.data)
            .map_err(|error| format!("cannot extract asset {}: {:?}", asset.path, error))?;
    }
    filesystem_sync(root).map_err(|error| format!("cannot sync extracted package: {:?}", error))
}

fn detect_executable_format(path: &str, bytes: &[u8]) -> Result<ExecutableFormat, String> {
    if bytes.starts_with(b"\0asm") {
        return Ok(ExecutableFormat::Wasm);
    }
    if bytes.starts_with(b"\x7fELF") {
        return Ok(ExecutableFormat::Elf);
    }
    if path.ends_with(".wasm") {
        return Err(String::from(
            ".wasm executable has invalid WebAssembly magic",
        ));
    }
    Err(String::from("executable is neither ELF nor WebAssembly"))
}

fn parse_app_kind(value: &str) -> Result<AppKind, String> {
    match value {
        "command" | "terminal" | "cli" => Ok(AppKind::Command),
        "graphical" | "gui" => Ok(AppKind::Graphical),
        _ => Err(format!(
            "unknown app kind `{}`; use command or graphical",
            value
        )),
    }
}

fn parse_executable_format(value: &str) -> Result<ExecutableFormat, String> {
    match value {
        "elf" => Ok(ExecutableFormat::Elf),
        "wasm" => Ok(ExecutableFormat::Wasm),
        _ => Err(format!("unknown executable format `{}`", value)),
    }
}

fn editable_manifest_text(package: &Package<'_>, executable: &str) -> String {
    format!(
        "app_id={}\ndisplay_name={}\nversion={}\nkind={}\nformat={}\nexecutable={}\n",
        package.app_id,
        package.display_name,
        package.version,
        match package.kind {
            AppKind::Command => "command",
            AppKind::Graphical => "graphical",
        },
        match package.format {
            ExecutableFormat::Elf => "elf",
            ExecutableFormat::Wasm => "wasm",
        },
        executable,
    )
}

fn parse_editable_manifest(text: &str) -> Result<EditablePackageManifest, String> {
    let mut app_id = None;
    let mut display_name = None;
    let mut version = None;
    let mut kind = None;
    let mut format = None;
    let mut executable = None;
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("package.gkm line {} has no `=`", index + 1))?;
        if value.is_empty() {
            return Err(format!("package.gkm field `{}` is empty", key));
        }
        let slot = match key {
            "app_id" => &mut app_id,
            "display_name" => &mut display_name,
            "version" => &mut version,
            "executable" => &mut executable,
            "kind" => {
                if kind.replace(parse_app_kind(value)?).is_some() {
                    return Err(String::from("duplicate package.gkm field `kind`"));
                }
                continue;
            }
            "format" => {
                if format.replace(parse_executable_format(value)?).is_some() {
                    return Err(String::from("duplicate package.gkm field `format`"));
                }
                continue;
            }
            _ => return Err(format!("unknown package.gkm field `{}`", key)),
        };
        if slot.replace(value.to_string()).is_some() {
            return Err(format!("duplicate package.gkm field `{}`", key));
        }
    }
    let executable = executable.ok_or_else(|| String::from("package.gkm is missing executable"))?;
    if !valid_editable_relative_path(&executable) {
        return Err(String::from("package.gkm executable path is unsafe"));
    }
    Ok(EditablePackageManifest {
        app_id: app_id.ok_or_else(|| String::from("package.gkm is missing app_id"))?,
        display_name: display_name
            .ok_or_else(|| String::from("package.gkm is missing display_name"))?,
        version: version.ok_or_else(|| String::from("package.gkm is missing version"))?,
        kind: kind.ok_or_else(|| String::from("package.gkm is missing kind"))?,
        format: format.ok_or_else(|| String::from("package.gkm is missing format"))?,
        executable,
    })
}

fn valid_editable_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn collect_package_assets(
    root: Handle,
    directory: &str,
    relative: &str,
    depth: usize,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), Status> {
    if depth >= MAX_PURGE_DEPTH {
        return Err(Status::OutOfRange);
    }
    let path = if relative.is_empty() {
        directory.to_string()
    } else {
        join_path(directory, relative)
    };
    for entry in list_directory(root, &path)? {
        let Dynamic::Map(map) = entry else {
            return Err(Status::InvalidMessage);
        };
        let name = map
            .get("name")
            .and_then(Dynamic::as_string)
            .ok_or(Status::InvalidMessage)?;
        let child = if relative.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", relative, name)
        };
        match map.get("kind").and_then(Dynamic::as_string) {
            Some("directory") => {
                collect_package_assets(root, directory, &child, depth + 1, output)?
            }
            Some("file") => {
                if output.len() >= MAX_ASSET_COUNT {
                    return Err(Status::OutOfRange);
                }
                let bytes = read_bounded(root, &join_path(directory, &child), MAX_ASSET_DATA_LEN)?;
                let total = output.iter().map(|(_, data)| data.len()).sum::<usize>();
                if total
                    .checked_add(bytes.len())
                    .is_none_or(|size| size > MAX_TOTAL_ASSET_DATA_LEN)
                {
                    return Err(Status::OutOfRange);
                }
                output.push((child, bytes));
            }
            _ => return Err(Status::InvalidMessage),
        }
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(())
}

fn join_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{}/{}", parent, child)
    }
}

fn read_text_bounded(root: Handle, path: &str, maximum: usize) -> Result<String, Status> {
    let bytes = read_bounded(root, path, maximum)?;
    String::from_utf8(bytes).map_err(|_| Status::InvalidMessage)
}

fn install_package(root: Handle, path: &str) -> Result<(), String> {
    let package_bytes = read_bounded(root, path, MAX_INSTALL_PACKAGE_BYTES)
        .map_err(|error| format!("cannot read package: {:?}", error))?;
    let package = Package::parse(&package_bytes)
        .map_err(|error| format!("invalid GKP package: {:?}", error))?;
    let executable_digest = sha256(package.executable);
    let package_digest = sha256(&package_bytes);
    let generation = ExecutableGeneration::new_with_format(
        package.app_id,
        package.format,
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

    let mut created_directories = Vec::new();
    if let Err(error) =
        ensure_directory_chain(root, APPLICATIONS_DIRECTORY, &mut created_directories)
    {
        return Err(format!("cannot create applications directory: {:?}", error));
    }
    let versions_directory = versions_directory(package.app_id);
    if let Err(error) = ensure_directory_chain(root, &versions_directory, &mut created_directories)
    {
        cleanup_created_paths(root, &[], &created_directories);
        return Err(format!("cannot create version directory: {:?}", error));
    }

    let new_executable_path = executable_path(package.app_id, generation.filename.as_str());
    let mut created_files = Vec::new();
    match ensure_immutable_file(
        root,
        &new_executable_path,
        package.executable,
        executable_digest,
    ) {
        Ok(true) => created_files.push(new_executable_path),
        Ok(false) => {}
        Err(error) => {
            cleanup_created_paths(root, &created_files, &created_directories);
            return Err(error);
        }
    }

    let data_directory = app_data_path(package.app_id);
    if let Err(error) = ensure_directory_chain(root, &data_directory, &mut created_directories) {
        cleanup_created_paths(root, &created_files, &created_directories);
        return Err(format!("cannot create app-data directory: {:?}", error));
    }
    for asset in package.assets() {
        let asset_path = format!("{}/{}/{}", APP_DATA_DIRECTORY, package.app_id, asset.path);
        if let Some((parent, _)) = asset_path.rsplit_once('/') {
            if let Err(error) = ensure_directory_chain(root, parent, &mut created_directories) {
                cleanup_created_paths(root, &created_files, &created_directories);
                return Err(format!("cannot create asset directory: {:?}", error));
            }
        }
        match ensure_seed_file(root, &asset_path, asset.data) {
            Ok(true) => created_files.push(asset_path),
            Ok(false) => {}
            Err(error) => {
                cleanup_created_paths(root, &created_files, &created_directories);
                return Err(error);
            }
        }
    }

    if let Err(error) = filesystem_sync(root) {
        cleanup_created_paths(root, &created_files, &created_directories);
        return Err(format!("cannot sync installed files: {:?}", error));
    }
    if let Err((error, safe_to_clean)) = publish_registry(root, &registry) {
        if safe_to_clean {
            cleanup_created_paths(root, &created_files, &created_directories);
        }
        return Err(error);
    }

    if let Some(old_filename) = old_filename {
        if old_filename != generation.filename {
            let old_path = executable_path(package.app_id, &old_filename);
            remove_file_if_present(root, &old_path).map_err(|error| {
                format!(
                    "registry updated but old version cleanup failed: {:?}",
                    error
                )
            })?;
            filesystem_sync(root).map_err(|error| {
                format!(
                    "registry updated but version cleanup did not sync: {:?}",
                    error
                )
            })?;
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

    let executable_path = executable_path(app_id, &removed.executable.filename);
    remove_file_if_present(root, &executable_path).map_err(|error| {
        format!(
            "registry removed but executable cleanup failed: {:?}",
            error
        )
    })?;
    remove_empty_directory(root, &versions_directory(app_id))
        .map_err(|error| format!("registry removed but versions cleanup failed: {:?}", error))?;
    remove_empty_directory(root, &application_directory(app_id)).map_err(|error| {
        format!(
            "registry removed but application cleanup failed: {:?}",
            error
        )
    })?;
    filesystem_sync(root)
        .map_err(|error| format!("registry removed but cleanup did not sync: {:?}", error))?;
    Ok(())
}

fn purge_app_data(root: Handle, app_id: &str) -> Result<(), String> {
    validate_mutable_app_id(app_id)?;
    let path = app_data_path(app_id);
    let mut removals = Vec::new();
    match collect_removals(root, &path, 0, &mut removals) {
        Ok(()) => {}
        Err(Status::NotFound) => return Ok(()),
        Err(error) => return Err(format!("cannot inspect app data: {:?}", error)),
    }
    for removal in removals {
        let result = match removal.kind {
            FilesystemEntryKind::File => filesystem_unlink(root, &removal.path),
            FilesystemEntryKind::Directory => filesystem_remove_directory(root, &removal.path),
        };
        result.map_err(|error| format!("cannot remove {}: {:?}", removal.path, error))?;
    }
    remove_empty_directory(root, APP_DATA_DIRECTORY)
        .map_err(|error| format!("cannot clean app-data root: {:?}", error))?;
    filesystem_sync(root).map_err(|error| format!("cannot sync app-data purge: {:?}", error))?;
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
    let encoded = registry.encode();
    if let Err(error) = write_bytes_synced(root, STAGED_REGISTRY_PATH, &encoded) {
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
    if let Err(error) = filesystem_rename(
        root,
        STAGED_REGISTRY_PATH,
        root,
        INSTALLED_REGISTRY_PATH,
        FilesystemRenameFlags::REPLACE,
    ) {
        let _ = filesystem_unlink(root, STAGED_REGISTRY_PATH);
        return Err((
            format!("cannot publish installed registry: {:?}", error),
            true,
        ));
    }
    filesystem_sync(root).map_err(|error| {
        (
            format!("installed registry published but sync failed: {:?}", error),
            false,
        )
    })
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
    if let Err(error) = write_bytes_synced(root, path, bytes) {
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
            if let Err(error) = write_bytes_synced(root, path, bytes) {
                let _ = filesystem_unlink(root, path);
                Err(format!("cannot write seed asset {}: {:?}", path, error))
            } else {
                Ok(true)
            }
        }
        Err(error) => Err(format!("cannot inspect seed asset {}: {:?}", path, error)),
    }
}

fn application_directory(app_id: &str) -> String {
    format!("{}/{}", APPLICATIONS_DIRECTORY, app_id)
}

fn versions_directory(app_id: &str) -> String {
    format!("{}/{}/versions", APPLICATIONS_DIRECTORY, app_id)
}

fn executable_path(app_id: &str, filename: &str) -> String {
    format!(
        "{}/{}/versions/{}",
        APPLICATIONS_DIRECTORY, app_id, filename
    )
}

fn app_data_path(app_id: &str) -> String {
    format!("{}/{}", APP_DATA_DIRECTORY, app_id)
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
                Dynamic::from(executable_path(&entry.app_id, &entry.executable.filename)),
            );
            map.insert(
                "format".into(),
                Dynamic::from(match entry.executable.format {
                    ExecutableFormat::Elf => "elf",
                    ExecutableFormat::Wasm => "wasm",
                }),
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

struct Removal {
    path: String,
    kind: FilesystemEntryKind,
}

fn validate_mutable_app_id(app_id: &str) -> Result<(), String> {
    generation_filename(app_id, &[0; 32])
        .map_err(|error| format!("invalid application ID: {:?}", error))?;
    if PROTECTED_SYSTEM_IDS.contains(&app_id) {
        return Err(String::from(
            "protected system application data cannot be purged",
        ));
    }
    Ok(())
}

fn ensure_directory_chain(
    root: Handle,
    path: &str,
    created: &mut Vec<String>,
) -> Result<(), Status> {
    let mut current = String::new();
    for component in path.split('/') {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(component);
        match filesystem_create_directory(root, &current) {
            Ok(()) => created.push(current.clone()),
            Err(Status::AlreadyExists) => {
                if filesystem_get_metadata(root, &current)?.entry_kind()
                    != Some(FilesystemEntryKind::Directory)
                {
                    return Err(Status::NotDirectory);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn cleanup_created_paths(root: Handle, files: &[String], directories: &[String]) {
    for path in files.iter().rev() {
        let _ = filesystem_unlink(root, path);
    }
    for path in directories.iter().rev() {
        let _ = filesystem_remove_directory(root, path);
    }
    let _ = filesystem_sync(root);
}

fn remove_file_if_present(root: Handle, path: &str) -> Result<(), Status> {
    match filesystem_unlink(root, path) {
        Ok(()) | Err(Status::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_empty_directory(root: Handle, path: &str) -> Result<(), Status> {
    match filesystem_remove_directory(root, path) {
        Ok(()) | Err(Status::NotFound) | Err(Status::DirectoryNotEmpty) => Ok(()),
        Err(error) => Err(error),
    }
}

fn collect_removals(
    root: Handle,
    path: &str,
    depth: usize,
    removals: &mut Vec<Removal>,
) -> Result<(), Status> {
    if depth >= MAX_PURGE_DEPTH {
        return Err(Status::ResourceLimit);
    }
    let directory = filesystem_open_directory(root, path)?;
    let result = (|| {
        let mut cookie = 0;
        loop {
            let entry = match filesystem_read_directory2(directory, cookie) {
                Ok(entry) => entry,
                Err(Status::EndOfDirectory) => break,
                Err(error) => return Err(error),
            };
            let length = usize::from(entry.name_length).min(entry.name.len());
            let name =
                core::str::from_utf8(&entry.name[..length]).map_err(|_| Status::InvalidMessage)?;
            let child_path = format!("{}/{}", path, name);
            match entry.entry_kind() {
                Some(FilesystemEntryKind::File) => {
                    if removals.len() >= MAX_PURGE_ENTRIES {
                        return Err(Status::ResourceLimit);
                    }
                    removals.push(Removal {
                        path: child_path,
                        kind: FilesystemEntryKind::File,
                    });
                }
                Some(FilesystemEntryKind::Directory) => {
                    collect_removals(root, &child_path, depth + 1, removals)?;
                }
                None => return Err(Status::InvalidMessage),
            }
            cookie = entry.next_cookie;
        }
        if removals.len() >= MAX_PURGE_ENTRIES {
            return Err(Status::ResourceLimit);
        }
        removals.push(Removal {
            path: String::from(path),
            kind: FilesystemEntryKind::Directory,
        });
        Ok(())
    })();
    let _ = handle_close(directory);
    result
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
    let result = file_digest_handle(file);
    let _ = handle_close(file);
    result
}

fn file_digest_handle(file: Handle) -> Result<(u64, [u8; 32]), Status> {
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

fn write_bytes_synced(root: Handle, path: &str, bytes: &[u8]) -> Result<(), Status> {
    let file = filesystem_open(
        root,
        path,
        FilesystemOpenFlags::WRITE | FilesystemOpenFlags::CREATE | FilesystemOpenFlags::TRUNCATE,
    )?;
    let result = (|| {
        let mut offset = 0u64;
        for chunk in bytes.chunks(FILE_CHUNK_BYTES) {
            let mut written = 0;
            while written < chunk.len() {
                let count = filesystem_write(file, offset, &chunk[written..])?;
                if count == 0 {
                    return Err(Status::Io);
                }
                written += count;
                offset = offset.checked_add(count as u64).ok_or(Status::OutOfRange)?;
            }
        }
        filesystem_truncate(file, bytes.len() as u64)?;
        filesystem_sync(file)
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

fn file_size(root: Handle, path: &str) -> Result<u64, Status> {
    let file = filesystem_open(root, path, FilesystemOpenFlags::READ)?;
    let result = filesystem_stat(file).map(|stat| stat.length);
    let _ = handle_close(file);
    result
}
