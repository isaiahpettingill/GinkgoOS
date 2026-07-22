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

use ginkgo_terminal_protocol::ConsoleMessage;
use ginkgo_userspace::{
    channel_create, filesystem_open, filesystem_read, filesystem_read_directory, filesystem_stat,
    filesystem_truncate, filesystem_unlink, filesystem_write, handle_close, process_yield,
    FilesystemOpenFlags, Handle, Status,
};
use rhai::{Array, Dynamic, Engine, ImmutableString, INT};

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
const MAX_OUTPUT_BYTES: usize = 8 * 1024;
const FILE_CHUNK_BYTES: usize = 16 * 1024;

pub struct ChildStream {
    pub app_id: String,
    pub endpoint: Handle,
}

pub struct HostState {
    filesystem: Handle,
    desktop: Handle,
    shell_endpoint: Handle,
    pub pending: VecDeque<PendingSend>,
    pub children: Vec<ChildStream>,
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
    let run_host = host;
    engine.register_fn("run", move |app_id: ImmutableString| -> bool {
        run_host.borrow_mut().launch(String::from(app_id.as_str()))
    });
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
