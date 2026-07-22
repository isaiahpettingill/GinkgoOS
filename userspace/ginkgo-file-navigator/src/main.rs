#![no_std]
#![no_main]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use ginkgo_graphics::Rgb;
use ginkgo_userspace::{
    debug_write, filesystem_open, filesystem_open_directory, filesystem_read,
    filesystem_read_directory2, filesystem_remove_directory, filesystem_stat, filesystem_unlink,
    handle_close, process_yield,
    window::{ButtonState, ClientError, Event, WindowClient, WindowOptions},
    FilesystemEntryKind, FilesystemOpenFlags, Handle, Status, WindowTransport,
    WindowTransportError,
};

const UP_USAGE: u16 = 0x52;
const DOWN_USAGE: u16 = 0x51;
const ENTER_USAGE: u16 = 0x28;
const BACKSPACE_USAGE: u16 = 0x2a;
const DELETE_USAGE: u16 = 0x4c;
const MAX_PREVIEW_BYTES: usize = 8 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 128;
const MAX_EVENTS_PER_TURN: usize = 32;

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
                | Event::RequestFailed { .. } => {}
            }
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

struct Preview {
    name: String,
    bytes: Vec<u8>,
    size: u64,
}

struct Navigator {
    directories: Vec<DirectoryLevel>,
    entries: Vec<Entry>,
    selected: usize,
    preview: Option<Preview>,
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
            preview: None,
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
        let mut path = String::from("/");
        for (index, directory) in self.directories.iter().skip(1).enumerate() {
            if index != 0 {
                path.push('/');
            }
            path.push_str(&directory.name);
        }
        path
    }

    fn refresh(&mut self) {
        self.entries.clear();
        self.preview = None;

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
        if self.preview.is_some() || self.entries.is_empty() {
            return;
        }
        if delta < 0 {
            self.selected = self.selected.saturating_sub(1);
        } else {
            self.selected = (self.selected + 1).min(self.entries.len() - 1);
        }
    }

    fn open_selected(&mut self) {
        if self.preview.is_some() {
            return;
        }
        let Some((name, kind, metadata_size)) = self
            .entries
            .get(self.selected)
            .map(|entry| (entry.name.clone(), entry.kind, entry.size))
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

        let file = match filesystem_open(anchor, &name, FilesystemOpenFlags::READ) {
            Ok(file) => file,
            Err(error) => {
                self.status = format!("Open failed: {:?}", error);
                return;
            }
        };
        let result = (|| {
            let stat = filesystem_stat(file)?;
            let length = usize::try_from(stat.length)
                .unwrap_or(usize::MAX)
                .min(MAX_PREVIEW_BYTES);
            let mut bytes = vec![0; length];
            let count = filesystem_read(file, 0, &mut bytes)?;
            bytes.truncate(count);
            Ok::<_, Status>((bytes, stat.length))
        })();
        let _ = handle_close(file);
        match result {
            Ok((bytes, size)) => {
                self.status = if size > MAX_PREVIEW_BYTES as u64 {
                    String::from("Preview truncated to 8 KiB")
                } else {
                    format!("{} bytes read", bytes.len())
                };
                self.preview = Some(Preview {
                    name,
                    bytes,
                    size: metadata_size,
                });
            }
            Err(error) => self.status = format!("Read failed: {:?}", error),
        }
    }

    fn delete_selected(&mut self) {
        if self.preview.is_some() {
            return;
        }
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
        if self.preview.take().is_some() {
            self.status = format!("{} entries", self.entries.len());
            return;
        }
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
        while self.directories.len() > 1 {
            if let Some(directory) = self.directories.pop() {
                if directory.owned {
                    let _ = handle_close(directory.handle);
                }
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
    if let Some(preview) = navigator.preview.as_ref() {
        surface.draw_text(20, 96, 1, &preview.name, Rgb::new(245, 190, 90));
        surface.draw_text(
            20,
            114,
            1,
            &format!("file   metadata size: {} B", preview.size),
            Rgb::new(165, 180, 200),
        );
        let text = printable_preview(&preview.bytes, available_lines.saturating_sub(2), 74);
        surface.draw_text_wrapped(
            20,
            136,
            surface.width().saturating_sub(40),
            1,
            &text,
            Rgb::new(220, 225, 235),
        );
        surface.draw_text(
            20,
            surface.height().saturating_sub(22),
            1,
            "Backspace: file list",
            Rgb::new(120, 140, 160),
        );
    } else {
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
            "Up/Down: select   Enter: open   Backspace: up   Delete: remove",
            Rgb::new(120, 140, 160),
        );
    }

    match frame.present(Vec::new()) {
        Ok(_) => SubmitResult::Submitted,
        Err(error) if should_wait(&error) => SubmitResult::RetryLater,
        Err(_) => SubmitResult::Fatal,
    }
}

fn printable_preview(bytes: &[u8], maximum_lines: usize, columns: usize) -> String {
    let mut output = String::new();
    let mut line = 0;
    let mut column = 0;
    for byte in bytes.iter().copied() {
        if line >= maximum_lines {
            break;
        }
        let character = match byte {
            b'\n' => {
                output.push('\n');
                line += 1;
                column = 0;
                continue;
            }
            b'\r' | b'\t' => ' ',
            0x20..=0x7e => byte as char,
            _ => '.',
        };
        output.push(character);
        column += 1;
        if column >= columns {
            output.push('\n');
            line += 1;
            column = 0;
        }
    }
    output
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
