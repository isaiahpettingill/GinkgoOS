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
    generation_filename, sha256, ExecutableGeneration, InstalledRegistry, Package, Provenance,
    Sha256, MAX_REGISTRY_LEN,
};
use ginkgo_rhai_preprocessor::{CommandRegistry, CommandSpec, PreprocessedSource};
use ginkgo_terminal_protocol::ConsoleMessage;
use ginkgo_userspace::{
    application_data_create, channel_create, filesystem_create_directory, filesystem_get_info,
    filesystem_get_metadata, filesystem_open, filesystem_open_directory, filesystem_read,
    filesystem_read_directory, filesystem_read_directory2, filesystem_remove_directory,
    filesystem_rename, filesystem_stat, filesystem_sync, filesystem_truncate, filesystem_unlink,
    filesystem_write, handle_close, process_create, process_get_info, process_terminate,
    process_wait, process_yield, system_power_cancel, system_power_get_info, system_power_request,
    FilesystemEntryKind, FilesystemInfoFlags, FilesystemMetadata, FilesystemOpenFlags,
    FilesystemRenameFlags, Handle, HandleDisposition, ProcessFault, ProcessInfo, ProcessState,
    ProcessTerminationCause, Rights, Status, SystemPowerAction, SystemPowerFlags, SystemPowerState,
    DEADLINE_INFINITE, PROCESS_MAX_ARGS, PROCESS_MAX_STARTUP_BYTES,
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
const MAX_PURGE_ENTRIES: usize = 512;
const MAX_PURGE_DEPTH: usize = 32;
const APPLICATIONS_DIRECTORY: &str = "applications";
const APP_DATA_DIRECTORY: &str = "appdata";
const INSTALLED_REGISTRY_PATH: &str = "applications/installed.gki";
const STAGED_REGISTRY_PATH: &str = "applications/installed.gki.new";
const PROTECTED_SYSTEM_IDS: &[&str] = &[
    "desktop",
    "file-navigator",
    "text-editor",
    "terminal",
    "minimal-client",
];

static COMMAND_SPECS: &[CommandSpec<'static>] = &[
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
    CommandSpec::expression("print", &["output"], 1, Some(1)),
];

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
    power: Handle,
    shell_endpoint: Handle,
    pub pending: VecDeque<PendingSend>,
    pub children: Vec<ChildStream>,
    pub jobs: Vec<HeadlessJob>,
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
        let process = match create_installed_process(self.filesystem, app_id, &arguments) {
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
    pub fn new(filesystem: Handle, desktop: Handle, power: Handle, shell_endpoint: Handle) -> Self {
        let host = Rc::new(RefCell::new(HostState {
            filesystem,
            desktop,
            power,
            shell_endpoint,
            pending: VecDeque::new(),
            children: Vec::new(),
            jobs: Vec::new(),
            next_job_id: 1,
            current_directory: String::from("user"),
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

        let (script, source_name) = if let Some(path) = source_command(&source) {
            let resolved = {
                let host = self.host.borrow();
                match resolve_shell_path(&host.current_directory, path) {
                    Ok(path) => path,
                    Err(error) => {
                        drop(host);
                        self.host
                            .borrow_mut()
                            .error(format!("source: {}: {}", path, error));
                        return;
                    }
                }
            };
            match read_text(self.host.borrow().filesystem, &resolved) {
                Ok(script) => (script, format!("/{}", resolved)),
                Err(error) => {
                    self.host
                        .borrow_mut()
                        .error(format!("source: /{}: {:?}", resolved, error));
                    return;
                }
            }
        } else {
            (source, String::from("<input>"))
        };

        let registry = CommandRegistry::new(COMMAND_SPECS)
            .expect("the built-in Ginkgo command registry is valid");
        let preprocessed = match registry.preprocess(&script) {
            Ok(preprocessed) => preprocessed,
            Err(error) => {
                self.host.borrow_mut().error(format!(
                    "{}:{}:{}: {}",
                    source_name, error.line, error.column, error.message
                ));
                return;
            }
        };

        match self.engine.eval::<Dynamic>(&preprocessed.source) {
            Ok(value) if !value.is_unit() => {
                self.host.borrow_mut().output(format_terminal_value(&value))
            }
            Ok(_) => {}
            Err(mut error) => {
                let position = error.position();
                error.clear_position();
                self.host.borrow_mut().error(format_rhai_error(
                    &source_name,
                    &script,
                    &preprocessed,
                    position.line(),
                    position.position(),
                    &format!("{}", error),
                ));
            }
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

fn source_offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let line_start = if line <= 1 {
        0
    } else {
        source
            .match_indices('\n')
            .nth(line.saturating_sub(2))
            .map(|(offset, _)| offset + 1)?
    };
    let line_text = source[line_start..].split('\n').next().unwrap_or("");
    let column_offset = line_text
        .char_indices()
        .nth(column.saturating_sub(1))
        .map_or(line_text.len(), |(offset, _)| offset);
    Some(line_start + column_offset)
}

fn source_line_column(source: &str, offset: usize) -> (usize, usize) {
    let safe = offset.min(source.len());
    let prefix = &source[..safe];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, tail)| tail)
        .chars()
        .count()
        + 1;
    (line, column)
}

fn format_rhai_error(
    source_name: &str,
    original: &str,
    preprocessed: &PreprocessedSource,
    generated_line: Option<usize>,
    generated_column: Option<usize>,
    message: &str,
) -> String {
    let sanitized = sanitize_rhai_error(message);
    let Some(generated_offset) = generated_line
        .and_then(|line| source_offset(&preprocessed.source, line, generated_column.unwrap_or(1)))
    else {
        return format!("{}: {}", source_name, sanitized);
    };
    let original_offset = preprocessed
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.generated.start <= generated_offset && generated_offset < mapping.generated.end
        })
        .min_by_key(|mapping| mapping.generated.end - mapping.generated.start)
        .map(|mapping| {
            if mapping.generated.end - mapping.generated.start
                == mapping.original.end - mapping.original.start
            {
                mapping.original.start + generated_offset - mapping.generated.start
            } else {
                mapping.original.start
            }
        })
        .unwrap_or(generated_offset.min(original.len()));
    let (line, column) = source_line_column(original, original_offset);
    format!("{}:{}:{}: {}", source_name, line, column, sanitized)
}

fn sanitize_rhai_error(message: &str) -> String {
    message
        .replace("__ginkgo_pipe_command", "command pipeline")
        .replace("__ginkgo_command", "command")
        .replace("__ginkgo_execute", "executable launch")
        .replace("__ginkgo_shell_string", "shell interpolation")
}

fn command_argument(value: &Dynamic) -> String {
    value
        .clone()
        .try_cast::<ImmutableString>()
        .map(|value| String::from(value.as_str()))
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

fn execute_target(host: &mut HostState, target: &str, arguments: Array) -> Dynamic {
    if target.ends_with(".elf") || target.contains('/') {
        let path = match resolve_shell_path(&host.current_directory, target) {
            Ok(path) if !path.is_empty() => path,
            Ok(_) => return command_error(host, target, "executable path is empty"),
            Err(error) => return command_error(host, target, error),
        };
        let string_arguments = arguments
            .into_iter()
            .map(|value| Dynamic::from(command_argument(&value)))
            .collect();
        return Dynamic::from(host.spawn(&path, string_arguments));
    }

    if !arguments.is_empty() {
        return command_error(
            host,
            target,
            "graphical application arguments are not supported",
        );
    }
    let app_id = match target {
        "edit" | "editor" => "text-editor",
        "files" => "file-navigator",
        "demo" => "minimal-client",
        target => target,
    };
    Dynamic::from(host.launch(String::from(app_id)))
}

fn dispatch_command(host: &mut HostState, name: &str, arguments: Array) -> Dynamic {
    let Some(spec) = COMMAND_SPECS
        .iter()
        .find(|spec| spec.canonical_name == name && spec.canonical_name != "print")
    else {
        return command_error(host, name, "unknown canonical command");
    };
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
            "print <rhai-expression>\n    Evaluate and print one Rhai expression.",
        ),
        Some("help") => String::from("help [command]\n    Show command help."),
        Some(name) => format!("help: no registered command named `{}`", name),
        None => String::from(
            "Ginkgo Rhai shell\n\nCOMMANDS\n  ls, dir [path]             list directory entries\n  cd, chdir <path>           change logical directory\n  pwd, cwd                   show logical directory\n  cp <source> <destination>  copy a file atomically\n  mv, ren <source> <dest>    move or rename\n  rm, del <path>...          remove files\n  mkdir, md <path>...        create directories\n  rmdir, rd <path>...        remove empty directories\n  cat, type <path>...        display text files\n  clear, cls                 clear the terminal\n  ps, tasks                  list terminal jobs\n  kill, stop <job-id>        terminate a terminal job\n  print <expression>         evaluate and print Rhai\n  help [command]             show this help\n\nSYNTAX\n  Shell arguments are strings; use $(expression) for Rhai values.\n  value |> function(args) passes value as the first argument.\n  @edit opens the text editor. @files opens the file navigator.\n  @app-id launches a registered app; @path/program.elf starts a job.\n  Ordinary Rhai remains available, including function-call syntax.\n  source \"file.rhai\" preprocesses and evaluates a script.",
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
        .map(|value| value.clone().try_cast::<Map>())
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
    let Some(values) = value.clone().try_cast::<Array>() else {
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
    value
        .clone()
        .try_cast::<Map>()
        .and_then(|map| map.get("name").cloned())
        .unwrap_or_else(|| value.clone())
        .to_string()
}

fn register_functions(engine: &mut Engine, host: Rc<RefCell<HostState>>) {
    engine.register_fn("__ginkgo_shell_string", move |value: Dynamic| -> String {
        value.to_string()
    });

    let execute_host = host.clone();
    engine.register_fn(
        "__ginkgo_execute",
        move |target: ImmutableString, arguments: Array| -> Dynamic {
            execute_target(&mut execute_host.borrow_mut(), target.as_str(), arguments)
        },
    );

    let command_host = host.clone();
    engine.register_fn(
        "__ginkgo_command",
        move |name: ImmutableString, arguments: Array| -> Dynamic {
            dispatch_command(&mut command_host.borrow_mut(), name.as_str(), arguments)
        },
    );
    let pipe_host = host.clone();
    engine.register_fn(
        "__ginkgo_pipe_command",
        move |name: ImmutableString, input: Dynamic, mut arguments: Array| -> Dynamic {
            arguments.insert(0, input);
            dispatch_command(&mut pipe_host.borrow_mut(), name.as_str(), arguments)
        },
    );

    engine.register_fn(
        "filter",
        move |values: Array, pattern: ImmutableString| -> Array {
            values
                .into_iter()
                .filter(|value| structured_value_text(value).contains(pattern.as_str()))
                .collect()
        },
    );
    engine.register_fn("sort", move |mut values: Array| -> Array {
        values.sort_by_key(structured_value_text);
        values
    });

    for name in ["print", "output"] {
        let output_host = host.clone();
        engine.register_fn(name, move |value: Dynamic| {
            output_host
                .borrow_mut()
                .output(format_terminal_value(&value));
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

    let poweroff_host = host.clone();
    engine.register_fn("power_off", move |confirmed: bool, force: bool| -> bool {
        let mut host = poweroff_host.borrow_mut();
        if !confirmed {
            host.error(String::from(
                "power_off: pass true to confirm machine power-off",
            ));
            return false;
        }
        let flags = if force {
            SystemPowerFlags::FORCE
        } else {
            SystemPowerFlags::empty()
        };
        match system_power_request(host.power, SystemPowerAction::PowerOff, flags) {
            Ok(()) => true,
            Err(error) => {
                host.error(format!("power_off: {:?}", error));
                false
            }
        }
    });

    let reboot_host = host.clone();
    engine.register_fn("reboot", move |confirmed: bool, force: bool| -> bool {
        let mut host = reboot_host.borrow_mut();
        if !confirmed {
            host.error(String::from("reboot: pass true to confirm machine restart"));
            return false;
        }
        let flags = if force {
            SystemPowerFlags::FORCE
        } else {
            SystemPowerFlags::empty()
        };
        match system_power_request(host.power, SystemPowerAction::Reboot, flags) {
            Ok(()) => true,
            Err(error) => {
                host.error(format!("reboot: {:?}", error));
                false
            }
        }
    });

    let cancel_power_host = host.clone();
    engine.register_fn("cancel_power", move || -> bool {
        system_power_cancel(cancel_power_host.borrow().power).is_ok()
    });

    let power_status_host = host.clone();
    engine.register_fn("power_status", move || -> Dynamic {
        match system_power_get_info(power_status_host.borrow().power) {
            Ok(info) => {
                let mut map = Map::new();
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
                map.insert("state".into(), Dynamic::from(state));
                map.insert("sequence".into(), filesystem_integer(info.sequence));
                map.insert("deadline_ns".into(), filesystem_integer(info.deadline_ns));
                map.insert(
                    "failure_status".into(),
                    Dynamic::from(INT::from(info.failure_status)),
                );
                Dynamic::from(map)
            }
            Err(error) => Dynamic::from(format!("power_status: {:?}", error)),
        }
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
    let installed_spawn_host = host.clone();
    engine.register_fn(
        "spawn_installed",
        move |app_id: ImmutableString, arguments: Array| -> INT {
            installed_spawn_host
                .borrow_mut()
                .spawn_installed(app_id.as_str(), arguments)
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
    let installed_exec_host = host.clone();
    engine.register_fn(
        "exec_installed",
        move |app_id: ImmutableString, arguments: Array| -> Dynamic {
            let arguments = match argument_strings(arguments) {
                Ok(arguments) => arguments,
                Err(error) => return Dynamic::from(format!("exec_installed: {}", error)),
            };
            let filesystem = installed_exec_host.borrow().filesystem;
            let process = match create_installed_process(filesystem, app_id.as_str(), &arguments) {
                Ok(process) => process,
                Err(error) => return Dynamic::from(format!("exec_installed: {}", error)),
            };
            let result = process_wait(process, DEADLINE_INFINITE);
            let _ = handle_close(process);
            process_result("exec_installed", result)
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
    let purge_host = host.clone();
    engine.register_fn("purge_app_data", move |app_id: ImmutableString| -> bool {
        let filesystem = purge_host.borrow().filesystem;
        match purge_app_data(filesystem, app_id.as_str()) {
            Ok(()) => true,
            Err(error) => {
                purge_host
                    .borrow_mut()
                    .error(format!("purge_app_data: {}", error));
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

fn create_installed_process(
    root: Handle,
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
    let argument_blob = encode_arguments(&path, arguments)
        .map_err(|error| format!("invalid arguments: {}", error))?;

    let application_data = application_data_create(root, app_id)
        .map_err(|error| format!("cannot mint application-data identity: {:?}", error))?;
    let executable = match filesystem_open(
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

    let verification = file_digest_handle(executable);
    match verification {
        Ok((length, digest)) if length == expected_length && digest == expected_digest => {}
        Ok(_) => {
            let _ = handle_close(executable);
            let _ = handle_close(application_data);
            return Err(String::from(
                "installed executable length or SHA-256 does not match the registry",
            ));
        }
        Err(error) => {
            let _ = handle_close(executable);
            let _ = handle_close(application_data);
            return Err(format!("cannot verify installed executable: {:?}", error));
        }
    }

    let startup_handles = [HandleDisposition::move_handle(
        application_data,
        Rights::READ,
    )];
    let result = process_create(executable, &argument_blob, &startup_handles, &[]);
    let _ = handle_close(executable);
    match result {
        Ok(process) => Ok(process),
        Err(error) => {
            // Move dispositions commit only when process creation succeeds. On
            // failure the identity is still owned by this process and must close.
            let _ = handle_close(application_data);
            Err(format!("process creation failed: {:?}", error))
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
