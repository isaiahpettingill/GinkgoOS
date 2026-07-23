#![no_std]
#![no_main]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use ginkgo_graphics::Rgb;
use ginkgo_terminal_protocol::{
    encode_launch_request, encode_open_document, LaunchRequest, OpenDocument,
};
use ginkgo_userspace::{
    channel_create, channel_write, debug_write, filesystem_open_directory,
    filesystem_read_directory2, filesystem_remove_directory, filesystem_unlink, handle_close,
    process_yield,
    window::{ButtonState, ClientError, Event, WindowClient, WindowOptions},
    FilesystemEntryKind, Handle, HandleDisposition, Rights, Status, WindowTransport,
    WindowTransportError,
};

const UP_USAGE: u16 = 0x52;
const DOWN_USAGE: u16 = 0x51;
const ENTER_USAGE: u16 = 0x28;
const BACKSPACE_USAGE: u16 = 0x2a;
const DELETE_USAGE: u16 = 0x4c;
const MAX_DIRECTORY_ENTRIES: usize = 128;
const MAX_EVENTS_PER_TURN: usize = 32;
const EDITOR_CHANNEL_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits() | Rights::WRITE.bits() | Rights::WAIT.bits() | Rights::TRANSFER.bits(),
);

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(
    window_raw: u64,
    filesystem_raw: u64,
    _arg2: u64,
    _random_raw: u64,
) -> ! {
    let window = parse_handle(window_raw)
        .unwrap_or_else(|| fail(b"file-navigator: invalid window channel\n", 1));
    let filesystem = parse_handle(filesystem_raw)
        .unwrap_or_else(|| fail(b"file-navigator: missing filesystem capability\n", 1));
    let transport = WindowTransport::new(window)
        .unwrap_or_else(|_| fail(b"file-navigator: transport initialization failed\n", 1));
    let mut client = WindowClient::new(transport);
    create_window(&mut client);

    let mut navigator = Navigator::new(filesystem);
    navigator.refresh();
    // No surface exists until the desktop sends the first Configured event.
    let mut redraw = false;

    loop {
        for _ in 0..MAX_EVENTS_PER_TURN {
            let event = match client.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => fail(b"file-navigator: invalid window event\n", 2),
            };
            match event {
                Event::Configured { .. } | Event::Redraw { .. } => redraw = true,
                Event::Keyboard { event, .. } if event.state == ButtonState::Pressed => {
                    match event.usage {
                        UP_USAGE => navigator.move_selection(-1),
                        DOWN_USAGE => navigator.move_selection(1),
                        ENTER_USAGE if !event.repeat => navigator.open_selected(),
                        BACKSPACE_USAGE if !event.repeat => navigator.show_directory(),
                        DELETE_USAGE if !event.repeat => navigator.delete_selected(),
                        _ => continue,
                    }
                    redraw = true;
                }
                Event::CloseRequested { .. } => {
                    navigator.shutdown();
                    destroy_window(&mut client);
                    drop(client);
                    ginkgo_runtime::exit(0);
                }
                Event::WindowCreated { .. }
                | Event::BufferReleased { .. }
                | Event::Pointer { .. }
                | Event::Keyboard { .. }
                | Event::FocusChanged { .. }
                | Event::ClipboardText { .. }
                | Event::RequestFailed { .. } => {}
            }
        }

        if navigator.retry_launch(client.transport().channel()) {
            redraw = true;
        }

        if redraw {
            match submit_frame(&mut client, &navigator) {
                SubmitResult::Submitted => redraw = false,
                SubmitResult::RetryLater => {}
                SubmitResult::Fatal => fail(b"file-navigator: frame submission failed\n", 3),
            }
        }
        let _ = process_yield();
    }
}

fn parse_handle(raw: u64) -> Option<Handle> {
    u32::try_from(raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
}

struct Entry {
    name: String,
    kind: FilesystemEntryKind,
    size: u64,
}

struct DirectoryLevel {
    handle: Handle,
    name: String,
    owned: bool,
}

#[derive(Clone, Copy)]
enum LaunchPhase {
    QueueDocument,
    SendLaunch,
}

struct PendingLaunch {
    sender: Option<Handle>,
    editor_endpoint: Option<Handle>,
    document_bytes: Vec<u8>,
    launch_bytes: Vec<u8>,
    phase: LaunchPhase,
    path: String,
}

impl Drop for PendingLaunch {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = handle_close(sender);
        }
        if let Some(editor_endpoint) = self.editor_endpoint.take() {
            let _ = handle_close(editor_endpoint);
        }
    }
}

enum LaunchProgress {
    Pending,
    Launched,
    Failed(Status),
}

struct Navigator {
    directories: Vec<DirectoryLevel>,
    entries: Vec<Entry>,
    selected: usize,
    pending_launch: Option<PendingLaunch>,
    status: String,
}

impl Navigator {
    fn new(filesystem: Handle) -> Self {
        Self {
            directories: vec![DirectoryLevel {
                handle: filesystem,
                name: String::new(),
                owned: false,
            }],
            entries: Vec::new(),
            selected: 0,
            pending_launch: None,
            status: String::from("Loading filesystem..."),
        }
    }

    fn current_directory(&self) -> Handle {
        self.directories
            .last()
            .map(|directory| directory.handle)
            .unwrap_or(Handle::INVALID)
    }

    fn current_path(&self) -> String {
        let mut path = String::from("/user");
        for directory in self.directories.iter().skip(1) {
            path.push('/');
            path.push_str(&directory.name);
        }
        path
    }

    fn selected_path(&self, name: &str) -> String {
        let mut path = String::new();
        for directory in self.directories.iter().skip(1) {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&directory.name);
        }
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(name);
        path
    }

    fn refresh(&mut self) {
        self.entries.clear();

        let directory = self.current_directory();

        let mut cookie = 0;
        let mut error = None;
        while self.entries.len() < MAX_DIRECTORY_ENTRIES {
            let entry = match filesystem_read_directory2(directory, cookie) {
                Ok(entry) => entry,
                Err(Status::EndOfDirectory) => break,
                Err(status) => {
                    error = Some(format!("Directory error: {:?}", status));
                    break;
                }
            };
            let name_length = usize::from(entry.name_length).min(entry.name.len());
            let name = match core::str::from_utf8(&entry.name[..name_length]) {
                Ok(name) => String::from(name),
                Err(_) => {
                    error = Some(String::from("Directory contains an invalid name"));
                    break;
                }
            };
            let Some(kind) = entry.entry_kind() else {
                error = Some(format!("{} has an unknown file type", name));
                break;
            };
            self.entries.push(Entry {
                name,
                kind,
                size: entry.size,
            });
            cookie = entry.next_cookie;
        }
        if let Some(error) = error {
            self.entries.clear();
            self.selected = 0;
            self.status = error;
            return;
        }
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
        self.status = if self.entries.len() == MAX_DIRECTORY_ENTRIES {
            String::from("Showing first 128 entries")
        } else {
            format!("{} entries", self.entries.len())
        };
    }

    fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }
        if delta < 0 {
            self.selected = self.selected.saturating_sub(1);
        } else {
            self.selected = (self.selected + 1).min(self.entries.len() - 1);
        }
    }

    fn open_selected(&mut self) {
        let Some((name, kind)) = self
            .entries
            .get(self.selected)
            .map(|entry| (entry.name.clone(), entry.kind))
        else {
            return;
        };
        let anchor = self.current_directory();
        if kind == FilesystemEntryKind::Directory {
            match filesystem_open_directory(anchor, &name) {
                Ok(directory) => {
                    self.directories.push(DirectoryLevel {
                        handle: directory,
                        name,
                        owned: true,
                    });
                    self.selected = 0;
                    self.refresh();
                }
                Err(error) => self.status = format!("Open directory failed: {:?}", error),
            }
            return;
        }
        if self.pending_launch.is_some() {
            self.status = String::from("An editor launch is already pending");
            return;
        }

        let path = self.selected_path(&name);
        let document_bytes = match encode_open_document(&OpenDocument { path: path.clone() }) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.status = String::from("Selected path cannot be opened by the editor");
                return;
            }
        };
        let launch_bytes = match encode_launch_request(&LaunchRequest {
            app_id: String::from("text-editor"),
            startup_attachment: 0,
        }) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.status = String::from("Could not encode the editor launch request");
                return;
            }
        };
        let (sender, editor_endpoint) = match channel_create() {
            Ok(pair) => pair,
            Err(error) => {
                self.status = format!("Editor channel creation failed: {:?}", error);
                return;
            }
        };
        self.status = format!("Opening {} in text editor...", path);
        self.pending_launch = Some(PendingLaunch {
            sender: Some(sender),
            editor_endpoint: Some(editor_endpoint),
            document_bytes,
            launch_bytes,
            phase: LaunchPhase::QueueDocument,
            path,
        });
    }

    fn retry_launch(&mut self, desktop: Handle) -> bool {
        let Some(pending) = self.pending_launch.as_mut() else {
            return false;
        };
        let progress = pending.advance(desktop);
        match progress {
            LaunchProgress::Pending => false,
            LaunchProgress::Launched => {
                let path = pending.path.clone();
                self.pending_launch = None;
                self.status = format!("Requested text editor for {}", path);
                true
            }
            LaunchProgress::Failed(error) => {
                self.pending_launch = None;
                self.status = format!("Editor launch failed: {:?}", error);
                true
            }
        }
    }

    fn delete_selected(&mut self) {
        let Some((name, kind)) = self
            .entries
            .get(self.selected)
            .map(|entry| (entry.name.clone(), entry.kind))
        else {
            return;
        };
        let anchor = self.current_directory();
        let result = match kind {
            FilesystemEntryKind::File => filesystem_unlink(anchor, &name),
            FilesystemEntryKind::Directory => filesystem_remove_directory(anchor, &name),
        };
        match result {
            Ok(()) => {
                self.refresh();
                self.status = format!("Deleted {}", name);
            }
            Err(Status::AccessDenied) => {
                self.status = String::from("That entry is owned by the operating system")
            }
            Err(Status::DirectoryNotEmpty) => self.status = String::from("Directory is not empty"),
            Err(error) => self.status = format!("Delete failed: {:?}", error),
        }
    }

    fn show_directory(&mut self) {
        if self.directories.len() <= 1 {
            return;
        }
        if let Some(directory) = self.directories.pop() {
            if directory.owned {
                let _ = handle_close(directory.handle);
            }
        }
        self.selected = 0;
        self.refresh();
    }

    fn shutdown(&mut self) {
        self.pending_launch = None;
        while self.directories.len() > 1 {
            if let Some(directory) = self.directories.pop() {
                if directory.owned {
                    let _ = handle_close(directory.handle);
                }
            }
        }
    }
}

impl PendingLaunch {
    fn advance(&mut self, desktop: Handle) -> LaunchProgress {
        loop {
            let result = match self.phase {
                LaunchPhase::QueueDocument => {
                    let Some(sender) = self.sender else {
                        return LaunchProgress::Failed(Status::InvalidHandle);
                    };
                    channel_write(sender, &self.document_bytes, &[])
                }
                LaunchPhase::SendLaunch => {
                    let Some(editor_endpoint) = self.editor_endpoint else {
                        return LaunchProgress::Failed(Status::InvalidHandle);
                    };
                    let disposition =
                        HandleDisposition::move_handle(editor_endpoint, EDITOR_CHANNEL_RIGHTS);
                    channel_write(desktop, &self.launch_bytes, &[disposition])
                }
            };

            match result {
                Ok(()) => match self.phase {
                    LaunchPhase::QueueDocument => {
                        if let Some(sender) = self.sender.take() {
                            let _ = handle_close(sender);
                        }
                        self.phase = LaunchPhase::SendLaunch;
                    }
                    LaunchPhase::SendLaunch => {
                        // A successful move consumed the endpoint; disarm Drop's cleanup.
                        self.editor_endpoint = None;
                        return LaunchProgress::Launched;
                    }
                },
                Err(Status::ShouldWait) => return LaunchProgress::Pending,
                Err(error) => return LaunchProgress::Failed(error),
            }
        }
    }
}

fn create_window(client: &mut WindowClient<WindowTransport>) {
    let options = WindowOptions {
        title: String::from("Files"),
        preferred_size: ginkgo_userspace::window::Size::new(640, 480),
        minimum_size: Some(ginkgo_userspace::window::Size::new(360, 240)),
        ..WindowOptions::default()
    };
    loop {
        match client.create_window(options.clone()) {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => fail(b"file-navigator: create request failed\n", 1),
        }
    }
}

fn destroy_window(client: &mut WindowClient<WindowTransport>) {
    loop {
        match client.destroy_window() {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => return,
        }
    }
}

enum SubmitResult {
    Submitted,
    RetryLater,
    Fatal,
}

fn submit_frame(client: &mut WindowClient<WindowTransport>, navigator: &Navigator) -> SubmitResult {
    let mut frame = match client.acquire_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => return SubmitResult::RetryLater,
        Err(_) => return SubmitResult::Fatal,
    };
    let mut surface = match frame.pixel_surface() {
        Ok(surface) => surface,
        Err(_) => return SubmitResult::Fatal,
    };
    surface.as_bytes_mut().fill(20);
    surface.draw_text(20, 18, 2, "Files", Rgb::new(110, 231, 183));
    surface.draw_text(
        20,
        50,
        1,
        &format!("Path: {}", navigator.current_path()),
        Rgb::new(245, 190, 90),
    );
    surface.draw_text(20, 68, 1, &navigator.status, Rgb::new(165, 180, 200));

    let available_lines = surface.height().saturating_sub(116) / 18;
    let first = navigator
        .selected
        .saturating_sub(available_lines.saturating_sub(1));
    for (row, (index, entry)) in navigator
        .entries
        .iter()
        .enumerate()
        .skip(first)
        .take(available_lines)
        .enumerate()
    {
        let marker = if index == navigator.selected {
            ">"
        } else {
            " "
        };
        let kind = match entry.kind {
            FilesystemEntryKind::File => "file",
            FilesystemEntryKind::Directory => "dir ",
        };
        let line = format!(
            "{} {:<4} {:<35} {:>8} B",
            marker, kind, entry.name, entry.size
        );
        let color = if index == navigator.selected {
            Rgb::new(110, 231, 183)
        } else {
            Rgb::new(220, 225, 235)
        };
        surface.draw_text(20, 100 + row * 18, 1, &line, color);
    }
    surface.draw_text(
        20,
        surface.height().saturating_sub(22),
        1,
        "Up/Down: select   Enter: enter directory / edit file   Backspace: up   Delete: remove",
        Rgb::new(120, 140, 160),
    );

    match frame.present(Vec::new()) {
        Ok(_) => SubmitResult::Submitted,
        Err(error) if should_wait(&error) => SubmitResult::RetryLater,
        Err(_) => SubmitResult::Fatal,
    }
}

fn should_wait(error: &ClientError<WindowTransportError>) -> bool {
    matches!(
        error,
        ClientError::Transport(WindowTransportError::Syscall(Status::ShouldWait))
    )
}

fn fail(message: &[u8], code: i32) -> ! {
    let _ = debug_write(message);
    ginkgo_runtime::exit(code)
}
