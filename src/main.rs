#![no_std]
#![no_main]

mod crt;
mod font8x8;
mod framebuffer;
mod limine;

use core::{arch::asm, panic::PanicInfo};
use framebuffer::{FramebufferWriter, Rgb};
use limine::{BaseRevision, FramebufferRequest};

#[used]
#[link_section = ".limine_requests_start"]
static REQUESTS_START: [u64; 4] = limine::REQUESTS_START_MARKER;

#[used]
#[link_section = ".limine_requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new(6);

#[used]
#[link_section = ".limine_requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static REQUESTS_END: [u64; 2] = limine::REQUESTS_END_MARKER;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if !BASE_REVISION.is_supported() {
        halt_forever();
    }

    let Some(response) = FRAMEBUFFER_REQUEST.response() else {
        halt_forever();
    };
    let Some(framebuffer) = response.first() else {
        halt_forever();
    };
    let Some(mut screen) = FramebufferWriter::new(framebuffer) else {
        halt_forever();
    };

    let background = Rgb::new(18, 24, 38);
    let panel = Rgb::new(31, 41, 61);
    let primary = Rgb::new(232, 238, 247);
    let accent = Rgb::new(110, 231, 183);

    screen.clear(background);

    let margin = 48;
    let panel_width = screen.width().saturating_sub(margin * 2);
    screen.fill_rect(margin, margin, panel_width, 180, panel);
    screen.fill_rect(margin, margin, 12, 180, accent);

    screen.draw_text(margin + 40, margin + 38, 4, "Hello, framebuffer!", primary);
    screen.draw_text(
        margin + 40,
        margin + 110,
        2,
        "Rust x86_64 kernel booted by Limine over UEFI.",
        accent,
    );

    halt_forever()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}
