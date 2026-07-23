#![no_std]
#![no_main]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};

use ginkgo_graphics::Rgb;
use ginkgo_text_editor_core::{Document, DocumentError, MAX_DOCUMENT_BYTES};
use ginkgo_userspace::{
    debug_write, filesystem_open, filesystem_read, filesystem_rename, filesystem_stat,
    filesystem_sync, filesystem_truncate, filesystem_unlink, filesystem_write, handle_close,
    process_yield, random_fill,
    window::{
        ButtonState, ClientError, Event, KeyboardEvent, RequestId, WindowClient, WindowOptions,
    },
    FilesystemOpenFlags, FilesystemRenameFlags, Handle, Status, WindowTransport,
    WindowTransportError,
};

const MAX_EVENTS_PER_TURN: usize = 32;
const FILE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 512;
const MAX_TRANSIENT_RETRIES: usize = 64;
const TEXT_X: usize = 16;
const TEXT_Y: usize = 82;
const CELL_WIDTH: usize = 10;
const CELL_HEIGHT: usize = 17;

const ENTER: u16 = 0x28;
const ESCAPE: u16 = 0x29;
const BACKSPACE: u16 = 0x2a;
const DELETE: u16 = 0x4c;
const RIGHT: u16 = 0x4f;
const LEFT: u16 = 0x50;
const DOWN: u16 = 0x51;
const UP: u16 = 0x52;
const HOME: u16 = 0x4a;
const END: u16 = 0x4d;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Editing,
    OpenPath,
    SaveAsPath,
}

struct Editor {
    filesystem: Handle,
    random: Handle,
    document: Document,
    path: Option<String>,
    mode: Mode,
    path_input: String,
    status: String,
    pending_paste: Option<RequestId>,
    first_visible_line: usize,
}

impl Editor {
    fn new(filesystem: Handle, random: Handle) -> Self {
        Self {
            filesystem,
            random,
            document: Document::new(),
            path: None,
            mode: Mode::Editing,
            path_input: String::new(),
            status: String::from("New document"),
            pending_paste: None,
            first_visible_line: 0,
        }
    }

    fn display_name(&self) -> &str {
        self.path.as_deref().unwrap_or("Untitled")
    }

    fn begin_path(&mut self, mode: Mode) {
        self.mode = mode;
        self.path_input = self.path.clone().unwrap_or_default();
        self.status = match mode {
            Mode::OpenPath => String::from("Enter a relative path to open"),
            Mode::SaveAsPath => String::from("Enter a relative path to save"),
            Mode::Editing => String::new(),
        };
    }

    fn cancel_path(&mut self) {
        self.mode = Mode::Editing;
        self.path_input.clear();
        self.status = String::from("Cancelled");
    }

    fn submit_path(&mut self) {
        let path = self.path_input.clone();
        let result = match self.mode {
            Mode::OpenPath => self.open(&path),
            Mode::SaveAsPath => self.save_to(&path),
            Mode::Editing => return,
        };
        if result.is_ok() {
            self.mode = Mode::Editing;
            self.path_input.clear();
        }
    }

    fn new_document(&mut self, force: bool) {
        if self.document.is_dirty() && !force {
            self.status = String::from("Unsaved changes; use Ctrl+Shift+N to discard them");
            return;
        }
        self.document = Document::new();
        self.path = None;
        self.first_visible_line = 0;
        self.status = String::from("New document");
    }

    fn open(&mut self, path: &str) -> Result<(), ()> {
        if self.document.is_dirty() {
            self.status = String::from("Save or create a new document before opening another");
            return Err(());
        }
        if let Err(message) = validate_path(path) {
            self.status = String::from(message);
            return Err(());
        }
        let file = match retry_status(|| {
            filesystem_open(self.filesystem, path, FilesystemOpenFlags::READ)
        }) {
            Ok(file) => file,
            Err(error) => {
                self.status = format!("Open failed: {:?}", error);
                return Err(());
            }
        };
        let result = (|| {
            let stat = filesystem_stat(file)?;
            let length = usize::try_from(stat.length).map_err(|_| Status::OutOfRange)?;
            if length > MAX_DOCUMENT_BYTES {
                return Err(Status::OutOfRange);
            }
            let mut bytes = vec![0; length];
            let mut offset = 0;
            while offset < bytes.len() {
                let end = (offset + FILE_CHUNK_BYTES).min(bytes.len());
                let count =
                    retry_status(|| filesystem_read(file, offset as u64, &mut bytes[offset..end]))?;
                if count == 0 {
                    return Err(Status::Io);
                }
                offset += count;
            }
            Document::load(&bytes).map_err(|error| match error {
                DocumentError::InvalidUtf8 => Status::InvalidArgument,
                DocumentError::TooLarge { .. } => Status::OutOfRange,
            })
        })();
        let _ = handle_close(file);
        match result {
            Ok(document) => {
                self.document = document;
                self.path = Some(String::from(path));
                self.first_visible_line = 0;
                self.status = format!("Opened {}", path);
                Ok(())
            }
            Err(Status::InvalidArgument) => {
                self.status = String::from("Open failed: file is not valid UTF-8 text");
                Err(())
            }
            Err(Status::OutOfRange) => {
                self.status = format!(
                    "Open failed: files are limited to {} KiB",
                    MAX_DOCUMENT_BYTES / 1024
                );
                Err(())
            }
            Err(error) => {
                self.status = format!("Read failed: {:?}", error);
                Err(())
            }
        }
    }

    fn save(&mut self) {
        if let Some(path) = self.path.clone() {
            let _ = self.save_to(&path);
        } else {
            self.begin_path(Mode::SaveAsPath);
        }
    }

    fn save_to(&mut self, path: &str) -> Result<(), ()> {
        if let Err(message) = validate_path(path) {
            self.status = String::from(message);
            return Err(());
        }
        let temporary = match self.temporary_path(path) {
            Ok(path) => path,
            Err(error) => {
                self.status = format!("Save failed to create a temporary name: {:?}", error);
                return Err(());
            }
        };
        let flags = FilesystemOpenFlags::WRITE
            | FilesystemOpenFlags::CREATE
            | FilesystemOpenFlags::TRUNCATE;
        let file = match retry_status(|| filesystem_open(self.filesystem, &temporary, flags)) {
            Ok(file) => file,
            Err(error) => {
                self.status = format!("Save failed: {:?}", error);
                return Err(());
            }
        };
        let save_result = (|| {
            let bytes = self.document.text().as_bytes();
            let mut offset = 0;
            while offset < bytes.len() {
                let end = (offset + FILE_CHUNK_BYTES).min(bytes.len());
                let count =
                    retry_status(|| filesystem_write(file, offset as u64, &bytes[offset..end]))?;
                if count == 0 {
                    return Err(Status::Io);
                }
                offset += count;
            }
            retry_unit(|| filesystem_truncate(file, bytes.len() as u64))?;
            retry_unit(|| filesystem_sync(file))?;
            Ok(())
        })();
        let _ = handle_close(file);
        if let Err(error) = save_result {
            let _ = filesystem_unlink(self.filesystem, &temporary);
            self.status = format!("Save failed while writing: {:?}", error);
            return Err(());
        }
        if let Err(error) = retry_unit(|| {
            filesystem_rename(
                self.filesystem,
                &temporary,
                self.filesystem,
                path,
                FilesystemRenameFlags::REPLACE,
            )
        }) {
            let _ = filesystem_unlink(self.filesystem, &temporary);
            self.status = format!("Save failed while publishing: {:?}", error);
            return Err(());
        }
        if let Err(error) = retry_unit(|| filesystem_sync(self.filesystem)) {
            self.status = format!("Saved, but filesystem sync failed: {:?}", error);
            return Err(());
        }
        self.path = Some(String::from(path));
        self.document.mark_saved();
        self.status = format!("Saved {} ({} bytes)", path, self.document.len());
        Ok(())
    }

    fn temporary_path(&self, destination: &str) -> Result<String, Status> {
        use core::fmt::Write;

        let mut entropy = [0_u8; 16];
        retry_unit(|| random_fill(self.random, &mut entropy))?;
        let mut leaf = String::from(".ginkgo-save-");
        for byte in entropy {
            write!(&mut leaf, "{:02x}", byte).map_err(|_| Status::OutOfMemory)?;
        }
        let temporary = match destination.rsplit_once('/') {
            Some((parent, _)) => format!("{}/{}", parent, leaf),
            None => leaf,
        };
        if temporary.len() > MAX_PATH_BYTES {
            return Err(Status::OutOfRange);
        }
        Ok(temporary)
    }

    fn run_smoke(&mut self, mode: &str) -> ! {
        const PATH: &str = "text-editor-smoke.txt";
        const CONTENT: &str = "GinkgoOS text editor persistence\nsecond line\n";
        let passed = match mode {
            "save" => {
                self.insert(CONTENT);
                self.save_to(PATH).is_ok()
            }
            "verify" => self.open(PATH).is_ok() && self.document.text() == CONTENT,
            _ => false,
        };
        if passed {
            let marker = if mode == "save" {
                b"text-editor-smoke: saved\n".as_slice()
            } else {
                b"text-editor-smoke: reopened\n".as_slice()
            };
            let _ = debug_write(marker);
            ginkgo_runtime::exit(0)
        }
        let _ = debug_write(b"text-editor-smoke: failure\n");
        ginkgo_runtime::exit(4)
    }

    fn insert(&mut self, text: &str) {
        match self.document.insert_text(text) {
            Ok(true) => self.status = String::from("Modified"),
            Ok(false) => {}
            Err(DocumentError::TooLarge { .. }) => {
                self.status = format!("Document limit is {} KiB", MAX_DOCUMENT_BYTES / 1024)
            }
            Err(DocumentError::InvalidUtf8) => {}
        }
    }

    fn set_clipboard<T: ginkgo_window::Transport>(
        &mut self,
        client: &mut WindowClient<T>,
        cut: bool,
    ) {
        let Some(selected) = self.document.selected_text() else {
            self.status = String::from("Nothing is selected");
            return;
        };
        if selected.len() > ginkgo_window::MAX_CLIPBOARD_BYTES {
            self.status = format!(
                "Selection exceeds the {} KiB clipboard limit",
                ginkgo_window::MAX_CLIPBOARD_BYTES / 1024
            );
            return;
        }
        let text = String::from(selected);
        match client.set_clipboard_text(text) {
            Ok(_) => {
                if cut {
                    self.document.delete_selection();
                    self.status = String::from("Cut selection");
                } else {
                    self.status = String::from("Copied selection");
                }
            }
            Err(_) => self.status = String::from("Clipboard is temporarily unavailable"),
        }
    }

    fn request_paste<T: ginkgo_window::Transport>(&mut self, client: &mut WindowClient<T>) {
        if self.pending_paste.is_some() {
            self.status = String::from("Paste is already pending");
            return;
        }
        match client.request_clipboard_text() {
            Ok(request_id) => {
                self.pending_paste = Some(request_id);
                self.status = String::from("Requesting clipboard...");
            }
            Err(_) => self.status = String::from("Clipboard is temporarily unavailable"),
        }
    }

    fn receive_clipboard(&mut self, request_id: RequestId, text: String) {
        if self.pending_paste != Some(request_id) {
            return;
        }
        self.pending_paste = None;
        if text.is_empty() {
            self.status = String::from("Clipboard is empty");
        } else {
            self.insert(&text);
        }
    }
}

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(
    window_raw: u64,
    filesystem_raw: u64,
    _startup_raw: u64,
    random_raw: u64,
) -> ! {
    let window = parse_handle(window_raw)
        .unwrap_or_else(|| fail(b"text-editor: invalid window channel\n", 1));
    let filesystem = parse_handle(filesystem_raw)
        .unwrap_or_else(|| fail(b"text-editor: missing filesystem capability\n", 1));
    let random = parse_handle(random_raw)
        .unwrap_or_else(|| fail(b"text-editor: missing random capability\n", 1));
    let transport = WindowTransport::new(window)
        .unwrap_or_else(|_| fail(b"text-editor: transport initialization failed\n", 1));
    let mut client = WindowClient::new(transport);
    let mut editor = Editor::new(filesystem, random);
    if let Some(mode) = option_env!("GINKGO_TEXT_EDITOR_SMOKE") {
        editor.run_smoke(mode);
    }
    create_window(&mut client);
    let mut redraw = false;

    loop {
        for _ in 0..MAX_EVENTS_PER_TURN {
            let event = match client.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => fail(b"text-editor: invalid window event\n", 2),
            };
            match event {
                Event::Configured { .. } | Event::Redraw { .. } => redraw = true,
                Event::Keyboard { event, .. } if event.state == ButtonState::Pressed => {
                    if handle_keyboard(&mut editor, &mut client, event) {
                        redraw = true;
                    }
                }
                Event::ClipboardText { request_id, text } => {
                    editor.receive_clipboard(request_id, text);
                    redraw = true;
                }
                Event::CloseRequested { .. } => {
                    if editor.document.is_dirty() {
                        editor.status =
                            String::from("Unsaved changes; save or press Ctrl+Shift+Q to discard");
                        redraw = true;
                    } else {
                        destroy_window(&mut client);
                        drop(client);
                        ginkgo_runtime::exit(0);
                    }
                }
                Event::RequestFailed { request_id, .. }
                    if editor.pending_paste == Some(request_id) =>
                {
                    editor.pending_paste = None;
                    editor.status = String::from("Clipboard request failed");
                    redraw = true;
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
            match submit_frame(&mut client, &mut editor) {
                SubmitResult::Submitted => redraw = false,
                SubmitResult::RetryLater => {}
                SubmitResult::Fatal => fail(b"text-editor: frame submission failed\n", 3),
            }
        }
        let _ = process_yield();
    }
}

fn handle_keyboard(
    editor: &mut Editor,
    client: &mut WindowClient<WindowTransport>,
    event: KeyboardEvent,
) -> bool {
    if event.modifiers.logo || event.modifiers.alt {
        return false;
    }
    if editor.mode != Mode::Editing {
        match event.usage {
            ESCAPE if !event.repeat => editor.cancel_path(),
            ENTER if !event.repeat => editor.submit_path(),
            BACKSPACE => {
                editor.path_input.pop();
            }
            _ => {
                if let Some(byte) = translate_ascii(event) {
                    if editor.path_input.len() < MAX_PATH_BYTES {
                        editor.path_input.push(byte as char);
                    } else {
                        editor.status = String::from("Path is too long");
                    }
                }
            }
        }
        return true;
    }

    if event.modifiers.control {
        match event.usage {
            BACKSPACE => {
                editor.document.delete_word_backward();
            }
            0x04 => editor.document.select_all(),
            0x06 if !event.repeat => editor.set_clipboard(client, false),
            0x11 if !event.repeat => editor.new_document(event.modifiers.shift),
            0x12 if !event.repeat => editor.begin_path(Mode::OpenPath),
            0x14 if event.modifiers.shift && !event.repeat => {
                destroy_window(client);
                ginkgo_runtime::exit(0);
            }
            0x16 if event.modifiers.shift && !event.repeat => editor.begin_path(Mode::SaveAsPath),
            0x16 if !event.repeat => editor.save(),
            0x19 if !event.repeat => editor.request_paste(client),
            0x1b if !event.repeat => editor.set_clipboard(client, true),
            0x1c if !event.repeat => {
                if editor.document.redo() {
                    editor.status = String::from("Redone");
                }
            }
            0x1d if !event.repeat => {
                if editor.document.undo() {
                    editor.status = String::from("Undone");
                }
            }
            _ => return false,
        }
        return true;
    }

    let select = event.modifiers.shift;
    match event.usage {
        LEFT => editor.document.move_left(select),
        RIGHT => editor.document.move_right(select),
        UP => editor.document.move_up(select),
        DOWN => editor.document.move_down(select),
        HOME => editor.document.move_home(select),
        END => editor.document.move_end(select),
        BACKSPACE => editor.document.backspace(),
        DELETE => editor.document.delete(),
        ENTER => {
            editor.insert("\n");
            true
        }
        0x2b => {
            editor.insert("    ");
            true
        }
        _ => {
            if let Some(byte) = translate_ascii(event) {
                editor.insert(core::str::from_utf8(&[byte]).unwrap_or(""));
                true
            } else {
                false
            }
        }
    }
}

fn translate_ascii(event: KeyboardEvent) -> Option<u8> {
    if event.modifiers.control || event.modifiers.alt || event.modifiers.logo {
        return None;
    }
    let shift = event.modifiers.shift;
    let letter_shift = shift ^ event.modifiers.caps_lock;
    match event.usage {
        0x04..=0x1d => {
            let base = if letter_shift { b'A' } else { b'a' };
            Some(base + (event.usage - 0x04) as u8)
        }
        0x1e..=0x27 => {
            const PLAIN: &[u8; 10] = b"1234567890";
            const SHIFTED: &[u8; 10] = b"!@#$%^&*()";
            let index = usize::from(event.usage - 0x1e);
            Some(if shift { SHIFTED[index] } else { PLAIN[index] })
        }
        0x2c => Some(b' '),
        0x2d => Some(if shift { b'_' } else { b'-' }),
        0x2e => Some(if shift { b'+' } else { b'=' }),
        0x2f => Some(if shift { b'{' } else { b'[' }),
        0x30 => Some(if shift { b'}' } else { b']' }),
        0x31 => Some(if shift { b'|' } else { b'\\' }),
        0x33 => Some(if shift { b':' } else { b';' }),
        0x34 => Some(if shift { b'"' } else { b'\'' }),
        0x35 => Some(if shift { b'~' } else { b'`' }),
        0x36 => Some(if shift { b'<' } else { b',' }),
        0x37 => Some(if shift { b'>' } else { b'.' }),
        0x38 => Some(if shift { b'?' } else { b'/' }),
        _ => None,
    }
}

fn submit_frame(client: &mut WindowClient<WindowTransport>, editor: &mut Editor) -> SubmitResult {
    let mut frame = match client.acquire_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => return SubmitResult::RetryLater,
        Err(_) => return SubmitResult::Fatal,
    };
    let mut surface = match frame.pixel_surface() {
        Ok(surface) => surface,
        Err(_) => return SubmitResult::Fatal,
    };
    surface.as_bytes_mut().fill(18);
    let dirty = if editor.document.is_dirty() { " *" } else { "" };
    surface.draw_text(
        16,
        14,
        2,
        &format!("Text Editor — {}{}", editor.display_name(), dirty),
        Rgb::new(110, 231, 183),
    );
    let prompt = match editor.mode {
        Mode::Editing => {
            String::from("Ctrl+N/O/S  Ctrl+X/C/V  Ctrl+Z/Y  Ctrl+Backspace  Shift+arrows")
        }
        Mode::OpenPath => format!("Open: {}_", editor.path_input),
        Mode::SaveAsPath => format!("Save as: {}_", editor.path_input),
    };
    surface.draw_text(16, 48, 1, &prompt, Rgb::new(245, 190, 90));
    surface.draw_text(16, 64, 1, &editor.status, Rgb::new(165, 180, 200));

    if editor.mode == Mode::Editing {
        render_document(&mut surface, editor);
    }
    match frame.present(Vec::new()) {
        Ok(_) => SubmitResult::Submitted,
        Err(error) if should_wait(&error) => SubmitResult::RetryLater,
        Err(_) => SubmitResult::Fatal,
    }
}

fn render_document(surface: &mut ginkgo_graphics::PixelSurface<'_>, editor: &mut Editor) {
    let rows = surface.height().saturating_sub(TEXT_Y + 24) / CELL_HEIGHT;
    let columns = surface.width().saturating_sub(TEXT_X * 2) / CELL_WIDTH;
    let cursor_line = editor.document.text()[..editor.document.cursor()]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    if cursor_line < editor.first_visible_line {
        editor.first_visible_line = cursor_line;
    } else if cursor_line >= editor.first_visible_line.saturating_add(rows.max(1)) {
        editor.first_visible_line = cursor_line.saturating_sub(rows.saturating_sub(1));
    }

    let selection = editor.document.selection_range();
    let mut byte_offset = 0;
    for (line_index, line) in editor.document.text().split('\n').enumerate() {
        let line_bytes = line.len();
        if line_index >= editor.first_visible_line
            && line_index < editor.first_visible_line.saturating_add(rows)
        {
            let row = line_index - editor.first_visible_line;
            let y = TEXT_Y + row * CELL_HEIGHT;
            for (column, (offset, character)) in line.char_indices().take(columns).enumerate() {
                let absolute = byte_offset + offset;
                let selected = selection
                    .as_ref()
                    .is_some_and(|range| range.contains(&absolute));
                if selected {
                    surface.fill_rect(
                        TEXT_X + column * CELL_WIDTH,
                        y,
                        CELL_WIDTH,
                        CELL_HEIGHT,
                        Rgb::new(55, 85, 105),
                    );
                }
                let mut encoded = [0_u8; 4];
                let glyph = character.encode_utf8(&mut encoded);
                surface.draw_text(
                    TEXT_X + column * CELL_WIDTH,
                    y,
                    1,
                    glyph,
                    Rgb::new(225, 230, 238),
                );
            }
            if cursor_line == line_index {
                let line_start = byte_offset;
                let cursor_column = editor.document.text()[line_start..editor.document.cursor()]
                    .chars()
                    .count()
                    .min(columns);
                surface.fill_rect(
                    TEXT_X + cursor_column * CELL_WIDTH,
                    y,
                    2,
                    CELL_HEIGHT,
                    Rgb::new(110, 231, 183),
                );
            }
        }
        byte_offset += line_bytes + 1;
    }
    surface.draw_text(
        16,
        surface.height().saturating_sub(20),
        1,
        &format!(
            "{} bytes  line {}  {}undo  {}redo",
            editor.document.len(),
            cursor_line + 1,
            if editor.document.can_undo() {
                ""
            } else {
                "no "
            },
            if editor.document.can_redo() {
                ""
            } else {
                "no "
            }
        ),
        Rgb::new(120, 140, 160),
    );
}

fn validate_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() {
        return Err("Path cannot be empty");
    }
    if path.len() > MAX_PATH_BYTES {
        return Err("Path is too long");
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("Use a relative file path without a trailing slash");
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("Path contains an invalid component");
    }
    Ok(())
}

fn retry_status<T>(mut operation: impl FnMut() -> Result<T, Status>) -> Result<T, Status> {
    for _ in 0..MAX_TRANSIENT_RETRIES {
        match operation() {
            Err(Status::ShouldWait) => {
                let _ = process_yield();
            }
            result => return result,
        }
    }
    Err(Status::ShouldWait)
}

fn retry_unit(mut operation: impl FnMut() -> Result<(), Status>) -> Result<(), Status> {
    retry_status(&mut operation)
}

fn parse_handle(raw: u64) -> Option<Handle> {
    u32::try_from(raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
}

fn create_window(client: &mut WindowClient<WindowTransport>) {
    let options = WindowOptions {
        title: String::from("Text Editor"),
        preferred_size: ginkgo_userspace::window::Size::new(760, 540),
        minimum_size: Some(ginkgo_userspace::window::Size::new(420, 280)),
        ..WindowOptions::default()
    };
    loop {
        match client.create_window(options.clone()) {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => fail(b"text-editor: create request failed\n", 1),
        }
    }
}

fn destroy_window(client: &mut WindowClient<WindowTransport>) {
    for _ in 0..MAX_TRANSIENT_RETRIES {
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
