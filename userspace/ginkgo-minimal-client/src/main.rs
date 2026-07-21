#![no_std]
#![no_main]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ginkgo_userspace::{
    debug_write,
    process_yield,
    window::{
        ButtonState, ClientError, Event, WindowClient, WindowOptions,
    },
    Handle, Status, WindowTransport, WindowTransportError,
};

const F11_USAGE: u16 = 0x44;
const INITIAL_FRAMES: usize = 2;
const RELEASE_LIFECYCLE_FRAMES: usize = 4;
const MAX_EVENTS_PER_TURN: usize = 32;

ginkgo_runtime::entry!(process_main);

extern "C" fn process_main(channel_raw: u64, _arg1: u64, _arg2: u64) -> ! {
    let Some(channel) = u32::try_from(channel_raw)
        .ok()
        .map(Handle::from_raw)
        .filter(|handle| handle.is_valid())
    else {
        fail(b"minimal-client: invalid window channel\n", 1);
    };
    let transport = match WindowTransport::new(channel) {
        Ok(transport) => transport,
        Err(_) => fail(b"minimal-client: transport initialization failed\n", 1),
    };
    let mut client = WindowClient::new(transport);
    create_window(&mut client);
    let _ = debug_write(b"minimal-client: create requested\n");

    let mut pending_frames = 0_usize;
    let mut submitted_frames = 0_usize;
    let mut pending_fullscreen_toggle = false;
    let mut lifecycle_reported = false;

    loop {
        for _ in 0..MAX_EVENTS_PER_TURN {
            let event = match client.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => fail(b"minimal-client: invalid window event\n", 2),
            };
            match event {
                Event::Configured { .. } => {
                    pending_frames = pending_frames.max(INITIAL_FRAMES);
                }
                Event::BufferReleased { .. } => {
                    if submitted_frames < RELEASE_LIFECYCLE_FRAMES {
                        pending_frames = pending_frames.saturating_add(1);
                    }
                }
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
                | Event::Redraw { .. }
                | Event::Pointer { .. }
                | Event::Keyboard { .. }
                | Event::FocusChanged { .. }
                | Event::RequestFailed { .. } => {}
            }
        }

        while pending_frames != 0 {
            match submit_frame(&mut client, submitted_frames) {
                SubmitResult::Submitted => {
                    pending_frames -= 1;
                    submitted_frames = submitted_frames.saturating_add(1);
                }
                SubmitResult::RetryLater => break,
                SubmitResult::Fatal => fail(b"minimal-client: frame submission failed\n", 3),
            }
        }

        if pending_fullscreen_toggle {
            match client.toggle_fullscreen() {
                Ok(_) => pending_fullscreen_toggle = false,
                Err(error) if should_wait(&error) => {}
                Err(_) => fail(b"minimal-client: fullscreen request failed\n", 4),
            }
        }

        if submitted_frames >= RELEASE_LIFECYCLE_FRAMES && !lifecycle_reported {
            let _ = debug_write(b"minimal-client: frame lifecycle complete\n");
            lifecycle_reported = true;
        }
        let _ = process_yield();
    }
}

fn create_window(client: &mut WindowClient<WindowTransport>) {
    let options = WindowOptions {
        title: String::from("Ginkgo minimal client"),
        preferred_size: ginkgo_userspace::window::Size::new(480, 320),
        minimum_size: Some(ginkgo_userspace::window::Size::new(240, 160)),
        ..WindowOptions::default()
    };
    loop {
        match client.create_window(options.clone()) {
            Ok(_) => return,
            Err(error) if should_wait(&error) => {
                let _ = process_yield();
            }
            Err(_) => fail(b"minimal-client: create request failed\n", 1),
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

fn submit_frame(client: &mut WindowClient<WindowTransport>, phase: usize) -> SubmitResult {
    let mut frame = match client.acquire_frame() {
        Ok(Some(frame)) => frame,
        Ok(None) => return SubmitResult::RetryLater,
        Err(_) => return SubmitResult::Fatal,
    };
    let mut surface = match frame.pixel_surface() {
        Ok(surface) => surface,
        Err(_) => return SubmitResult::Fatal,
    };
    let width = surface.width();
    let height = surface.height();
    for y in 0..height {
        for x in 0..width {
            let checker = ((x / 24) + (y / 24) + phase) & 1;
            let diagonal = ((x + y + phase * 13) % 97) < 4;
            let color = if diagonal {
                0x00f4_d35e
            } else if checker == 0 {
                0x001d_3557
            } else {
                0x0045_7b9d
            };
            surface.write_raw_pixel(x, y, color);
        }
    }

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
