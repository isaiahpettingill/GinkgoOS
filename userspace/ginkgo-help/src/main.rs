#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ginkgo_graphics::{PixelSurface, Rgb};
use ginkgo_userspace::{
    debug_write, process_yield,
    window::{ButtonState, ClientError, Event, WindowClient, WindowOptions},
    Handle, Status, WindowTransport, WindowTransportError,
};

const F11_USAGE: u16 = 0x44;
const MAX_EVENTS_PER_TURN: usize = 32;
const PAGE_MARGIN: usize = 20;
const ROW_TOP: usize = 102;
const ROW_SPACING: usize = 27;
const BODY_LINE_HEIGHT: usize = 18;

const HELP_ROWS: [(&str, &str); 8] = [
    ("Launcher", "META + N"),
    ("Focus window", "META + Left / Right"),
    ("Close window", "META + Q"),
    ("Move window", "META + A / S"),
    ("Resize window", "META + Plus / Minus"),
    ("Align window", "META + L / C / R"),
    ("Fullscreen", "F11 (where supported)"),
    ("Mouse", "Close X / help tray button"),
];

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(channel_raw: u64, _arg1: u64, _arg2: u64, _random_raw: u64) -> ! {
    let Some(channel) = u32::try_from(channel_raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
    else {
        fail(b"help: invalid window channel\n", 1);
    };
    let transport = match WindowTransport::new(channel) {
        Ok(transport) => transport,
        Err(_) => fail(b"help: transport initialization failed\n", 1),
    };
    let mut client = WindowClient::new(transport);
    create_window(&mut client);

    // A drawable surface is not available until the first configuration arrives.
    let mut redraw = false;
    let mut pending_fullscreen_toggle = false;

    loop {
        for _ in 0..MAX_EVENTS_PER_TURN {
            let event = match client.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => fail(b"help: invalid window event\n", 2),
            };
            match event {
                Event::Configured { .. } | Event::Redraw { .. } => redraw = true,
                Event::Keyboard { event, .. }
                    if event.usage == F11_USAGE
                        && event.state == ButtonState::Pressed
                        && !event.repeat =>
                {
                    pending_fullscreen_toggle = true;
                }
                Event::CloseRequested { .. } => {
                    destroy_window(&mut client);
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

        if redraw {
            match submit_frame(&mut client) {
                SubmitResult::Submitted => redraw = false,
                SubmitResult::RetryLater => {}
                SubmitResult::Fatal => fail(b"help: frame submission failed\n", 3),
            }
        }

        if pending_fullscreen_toggle {
            match client.toggle_fullscreen() {
                Ok(_) => pending_fullscreen_toggle = false,
                Err(error) if should_wait(&error) => {}
                Err(_) => fail(b"help: fullscreen request failed\n", 4),
            }
        }

        let _ = process_yield();
    }
}

fn create_window(client: &mut WindowClient<WindowTransport>) {
    let options = WindowOptions {
        title: String::from("Ginkgo Help"),
        preferred_size: ginkgo_userspace::window::Size::new(640, 400),
        minimum_size: Some(ginkgo_userspace::window::Size::new(420, 340)),
        ..WindowOptions::default()
    };
    loop {
        match client.create_window(options.clone()) {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => fail(b"help: create request failed\n", 1),
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

fn submit_frame(client: &mut WindowClient<WindowTransport>) -> SubmitResult {
    let mut frame = match client.acquire_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => return SubmitResult::RetryLater,
        Err(_) => return SubmitResult::Fatal,
    };
    let mut surface = match frame.pixel_surface() {
        Ok(surface) => surface,
        Err(_) => return SubmitResult::Fatal,
    };
    draw_help_page(&mut surface);

    match frame.present(Vec::new()) {
        Ok(_) => SubmitResult::Submitted,
        Err(error) if should_wait(&error) => SubmitResult::RetryLater,
        Err(_) => SubmitResult::Fatal,
    }
}

fn draw_help_page(surface: &mut PixelSurface<'_>) {
    let width = surface.width();
    let height = surface.height();
    surface.clear(Rgb::new(17, 22, 31));

    draw_bounded_text(
        surface,
        PAGE_MARGIN,
        18,
        3,
        15,
        32,
        "Ginkgo desktop controls",
        Rgb::new(110, 231, 183),
    );
    draw_bounded_text(
        surface,
        PAGE_MARGIN,
        62,
        0,
        6,
        9,
        "Window shortcuts and mouse controls",
        Rgb::new(165, 180, 200),
    );

    if width > PAGE_MARGIN.saturating_mul(2) && height > 86 {
        surface.fill_rect(
            PAGE_MARGIN,
            84,
            width.saturating_sub(PAGE_MARGIN.saturating_mul(2)),
            2,
            Rgb::new(52, 65, 82),
        );
    }

    let key_x = (width / 3).max(152);
    let body_bottom = height.saturating_sub(26);
    for (index, (action, control)) in HELP_ROWS.iter().enumerate() {
        let y = ROW_TOP.saturating_add(index.saturating_mul(ROW_SPACING));
        if y.saturating_add(BODY_LINE_HEIGHT) > body_bottom {
            break;
        }
        draw_bounded_text(
            surface,
            PAGE_MARGIN,
            y,
            1,
            10,
            BODY_LINE_HEIGHT,
            action,
            Rgb::new(220, 225, 235),
        );
        draw_bounded_text(
            surface,
            key_x,
            y,
            1,
            10,
            BODY_LINE_HEIGHT,
            control,
            Rgb::new(245, 190, 90),
        );
    }

    draw_bounded_text(
        surface,
        PAGE_MARGIN,
        height.saturating_sub(20),
        0,
        6,
        9,
        "Use the keyboard or the title-bar and tray buttons.",
        Rgb::new(120, 140, 160),
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_bounded_text(
    surface: &mut PixelSurface<'_>,
    x: usize,
    y: usize,
    scale: usize,
    character_width: usize,
    line_height: usize,
    text: &str,
    color: Rgb,
) {
    let width = surface.width();
    let height = surface.height();
    if x >= width || y >= height || line_height > height.saturating_sub(y) {
        return;
    }

    let maximum_characters = width.saturating_sub(x) / character_width.max(1);
    if maximum_characters == 0 {
        return;
    }
    let end = text
        .char_indices()
        .nth(maximum_characters)
        .map_or(text.len(), |(index, _)| index);
    surface.draw_text(x, y, scale, &text[..end], color);
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
