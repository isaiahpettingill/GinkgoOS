#![no_std]
#![no_main]

extern crate alloc;

mod keyboard;
mod shell;
mod transport;

use alloc::{collections::VecDeque, format, string::String, vec, vec::Vec};

use ginkgo_graphics::Rgb;
use ginkgo_terminal_protocol::ConsoleMessage;
use ginkgo_userspace::{
    channel_create, debug_write, handle_close, process_yield,
    window::{ButtonState, ClientError, Event, WindowClient, WindowOptions},
    Handle, Status, WindowTransport, WindowTransportError,
};

use crate::{
    shell::Shell,
    transport::{read_console, DrainResult, PendingSend},
};

const MAX_EVENTS_PER_TURN: usize = 32;
const MAX_CHANNEL_MESSAGES_PER_TURN: usize = 32;
const MAX_SCROLLBACK_LINES: usize = 256;
const TEXT_X: usize = 12;
const TEXT_TOP: usize = 12;
const LINE_HEIGHT: usize = 16;
const CHARACTER_WIDTH: usize = 8;

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(window_raw: u64, filesystem_raw: u64, _arg2: u64, power_raw: u64) -> ! {
    let desktop =
        parse_handle(window_raw).unwrap_or_else(|| fail(b"terminal: invalid desktop channel\n", 1));
    let filesystem = parse_handle(filesystem_raw)
        .unwrap_or_else(|| fail(b"terminal: missing filesystem capability\n", 1));
    let power = parse_handle(power_raw)
        .unwrap_or_else(|| fail(b"terminal: missing system-power capability\n", 1));
    let transport = WindowTransport::new(desktop)
        .unwrap_or_else(|_| fail(b"terminal: transport initialization failed\n", 1));
    let mut client = WindowClient::new(transport);
    create_window(&mut client);

    let (terminal_endpoint, shell_endpoint) =
        channel_create().unwrap_or_else(|_| fail(b"terminal: channel creation failed\n", 1));
    let mut shell = Shell::new(filesystem, desktop, power, shell_endpoint);
    let host = shell.host();
    let mut input_pending = VecDeque::new();
    let mut scrollback = VecDeque::new();
    push_line(
        &mut scrollback,
        String::from("Ginkgo Terminal — Rhai shell"),
    );
    push_line(
        &mut scrollback,
        String::from("Use source \"file.rhai\" to run a script."),
    );
    let mut redraw = false;

    loop {
        for _ in 0..MAX_EVENTS_PER_TURN {
            let event = match client.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => fail(b"terminal: invalid desktop event\n", 2),
            };
            match event {
                Event::Configured { .. } | Event::Redraw { .. } => redraw = true,
                Event::Keyboard { event, .. } if event.state == ButtonState::Pressed => {
                    if let Some(byte) = keyboard::translate(event) {
                        let message = ConsoleMessage::Input(vec![byte]);
                        if let Ok(send) = PendingSend::console(terminal_endpoint, &message) {
                            input_pending.push_back(send);
                        }
                    }
                }
                Event::CloseRequested { .. } => {
                    destroy_window(&mut client);
                    let state = host.borrow();
                    close_runtime_handles(
                        terminal_endpoint,
                        shell_endpoint,
                        &state.children,
                        &state.jobs,
                    );
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

        transport::flush(&mut input_pending);
        for _ in 0..MAX_CHANNEL_MESSAGES_PER_TURN {
            match read_console(shell_endpoint) {
                DrainResult::Message(ConsoleMessage::Input(bytes)) => {
                    redraw |= shell.accept(&bytes);
                }
                DrainResult::Message(_) | DrainResult::Invalid => {}
                DrainResult::Empty => break,
                DrainResult::Closed => fail(b"terminal: shell channel closed\n", 3),
            }
        }

        {
            let mut state = host.borrow_mut();
            transport::flush(&mut state.pending);
        }
        for _ in 0..MAX_CHANNEL_MESSAGES_PER_TURN {
            match read_console(terminal_endpoint) {
                DrainResult::Message(message) => {
                    let _ = consume_console(&mut scrollback, message, None);
                    redraw = true;
                }
                DrainResult::Invalid => {
                    push_line(&mut scrollback, String::from("[invalid shell message]"));
                    redraw = true;
                }
                DrainResult::Empty => break,
                DrainResult::Closed => fail(b"terminal: terminal channel closed\n", 3),
            }
        }

        {
            let mut state = host.borrow_mut();
            let mut index = 0;
            while index < state.children.len() {
                let endpoint = state.children[index].endpoint;
                let app_id = state.children[index].app_id.clone();
                let mut closed = false;
                let mut exit_announced = false;
                for _ in 0..MAX_CHANNEL_MESSAGES_PER_TURN {
                    match read_console(endpoint) {
                        DrainResult::Message(message) => {
                            exit_announced |= matches!(&message, ConsoleMessage::Exit(_));
                            closed |= consume_console(&mut scrollback, message, Some(&app_id));
                            redraw = true;
                            if closed {
                                break;
                            }
                        }
                        DrainResult::Invalid => {
                            push_line(
                                &mut scrollback,
                                format!("[{}: invalid console message]", app_id),
                            );
                            redraw = true;
                        }
                        DrainResult::Empty => break,
                        DrainResult::Closed => {
                            closed = true;
                            break;
                        }
                    }
                }
                if closed {
                    let child = state.children.remove(index);
                    let _ = handle_close(child.endpoint);
                    if !exit_announced {
                        push_line(&mut scrollback, format!("[{} exited]", child.app_id));
                    }
                    redraw = true;
                } else {
                    index += 1;
                }
            }
        }

        if redraw {
            match submit_frame(&mut client, &scrollback, shell.current_line()) {
                SubmitResult::Submitted => redraw = false,
                SubmitResult::RetryLater => {}
                SubmitResult::Fatal => fail(b"terminal: frame submission failed\n", 4),
            }
        }
        let _ = process_yield();
    }
}

fn consume_console(
    scrollback: &mut VecDeque<String>,
    message: ConsoleMessage,
    source: Option<&str>,
) -> bool {
    let (bytes, error) = match message {
        ConsoleMessage::Output(bytes) => (bytes, false),
        ConsoleMessage::Error(bytes) => (bytes, true),
        ConsoleMessage::Exit(code) => {
            if let Some(source) = source {
                push_line(scrollback, format!("[{} exited: {}]", source, code));
            }
            return true;
        }
        ConsoleMessage::Input(_) => return false,
    };
    if bytes.as_slice() == [keyboard::CLEAR] {
        scrollback.clear();
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    let prefix = match (source, error) {
        (Some(source), true) => format!("[{} error] ", source),
        (Some(source), false) => format!("[{}] ", source),
        (None, true) => String::from("error: "),
        (None, false) => String::new(),
    };
    let mut first = true;
    for line in text.split('\n') {
        let line_prefix = if first { prefix.as_str() } else { "" };
        push_line(scrollback, format!("{}{}", line_prefix, line));
        first = false;
    }
    false
}

fn push_line(scrollback: &mut VecDeque<String>, line: String) {
    if scrollback.len() == MAX_SCROLLBACK_LINES {
        scrollback.pop_front();
    }
    scrollback.push_back(line);
}

fn parse_handle(raw: u64) -> Option<Handle> {
    u32::try_from(raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
}

fn create_window(client: &mut WindowClient<WindowTransport>) {
    let options = WindowOptions {
        title: String::from("Terminal"),
        preferred_size: ginkgo_userspace::window::Size::new(720, 480),
        minimum_size: Some(ginkgo_userspace::window::Size::new(400, 240)),
        ..WindowOptions::default()
    };
    loop {
        match client.create_window(options.clone()) {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => fail(b"terminal: create request failed\n", 1),
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

fn submit_frame(
    client: &mut WindowClient<WindowTransport>,
    scrollback: &VecDeque<String>,
    input: &str,
) -> SubmitResult {
    let mut frame = match client.acquire_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => return SubmitResult::RetryLater,
        Err(_) => return SubmitResult::Fatal,
    };
    let mut surface = match frame.pixel_surface() {
        Ok(surface) => surface,
        Err(_) => return SubmitResult::Fatal,
    };
    surface.as_bytes_mut().fill(13);

    let columns = surface
        .width()
        .saturating_sub(TEXT_X * 2)
        .checked_div(CHARACTER_WIDTH)
        .unwrap_or(1)
        .max(1);
    let visible_lines = surface
        .height()
        .saturating_sub(TEXT_TOP * 2)
        .checked_div(LINE_HEIGHT)
        .unwrap_or(1)
        .saturating_sub(1);
    let wrapped = visible_scrollback(scrollback, columns, visible_lines);
    for (row, line) in wrapped.iter().enumerate() {
        surface.draw_text(
            TEXT_X,
            TEXT_TOP + row * LINE_HEIGHT,
            1,
            line,
            Rgb::new(205, 214, 225),
        );
    }

    let available = columns.saturating_sub(3);
    let visible_input = ascii_tail(input, available);
    let prompt = format!("> {}_", visible_input);
    surface.draw_text(
        TEXT_X,
        surface.height().saturating_sub(TEXT_TOP + LINE_HEIGHT),
        1,
        &prompt,
        Rgb::new(110, 231, 183),
    );

    match frame.present(Vec::new()) {
        Ok(_) => SubmitResult::Submitted,
        Err(error) if should_wait(&error) => SubmitResult::RetryLater,
        Err(_) => SubmitResult::Fatal,
    }
}

fn visible_scrollback(
    scrollback: &VecDeque<String>,
    columns: usize,
    maximum_lines: usize,
) -> Vec<String> {
    let mut lines = VecDeque::new();
    for line in scrollback {
        if line.is_empty() {
            lines.push_back(String::new());
            if lines.len() > maximum_lines {
                lines.pop_front();
            }
        } else {
            let mut chunk = String::new();
            for character in line.chars() {
                chunk.push(character);
                if chunk.chars().count() == columns {
                    lines.push_back(core::mem::take(&mut chunk));
                    if lines.len() > maximum_lines {
                        lines.pop_front();
                    }
                }
            }
            if !chunk.is_empty() {
                lines.push_back(chunk);
                if lines.len() > maximum_lines {
                    lines.pop_front();
                }
            }
        }
    }
    lines.into_iter().collect()
}

fn ascii_tail(text: &str, maximum: usize) -> &str {
    if text.len() <= maximum {
        text
    } else {
        &text[text.len() - maximum..]
    }
}

fn close_runtime_handles(
    terminal_endpoint: Handle,
    shell_endpoint: Handle,
    children: &[shell::ChildStream],
    jobs: &[shell::HeadlessJob],
) {
    for child in children {
        let _ = handle_close(child.endpoint);
    }
    for job in jobs {
        let _ = handle_close(job.process);
    }
    let _ = handle_close(terminal_endpoint);
    let _ = handle_close(shell_endpoint);
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
