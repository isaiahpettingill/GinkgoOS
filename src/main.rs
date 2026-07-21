#![no_std]
#![no_main]

mod crt;

mod framebuffer;
mod heap;

use core::{panic::PanicInfo, ptr::NonNull};
use framebuffer::{FramebufferWriter, Rgb};
use ginkgo_os::{
    fs::RedoxFs,
    hid::{ApplicationKind, Axis, InputEvent, AXIS_MAX, AXIS_MIN},
    input::{DeviceInputEvent, InputManager},
    io::SerialPort,
    limine::{
        self, BaseRevision, FramebufferRequest, HhdmRequest, MemoryMapRequest, StackSizeRequest,
        TscFrequencyRequest,
    },
    memory::{UsableFrameAllocator, VirtAddr, VirtPage},
    paging::{ActivePageTable, PageTableFlags},
    task::{Scheduler, TaskPoll, TaskState},
    usb::{self, UsbError},
};
use volatile::VolatilePtr;
use x86_64::instructions::{hlt, interrupts};

#[used]
#[link_section = ".limine_requests_start"]
static REQUESTS_START: [u64; 4] = limine::REQUESTS_START_MARKER;

#[used]
#[link_section = ".limine_requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new(6);

#[used]
#[link_section = ".limine_requests"]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new(512 * 1024);

#[used]
#[link_section = ".limine_requests"]
static TSC_FREQUENCY_REQUEST: TscFrequencyRequest = TscFrequencyRequest::new();

#[used]
#[link_section = ".limine_requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".limine_requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[link_section = ".limine_requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static REQUESTS_END: [u64; 2] = limine::REQUESTS_END_MARKER;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    interrupts::disable();

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

    let mut ui = ValidationUi::new(screen.width(), screen.height());
    ui.render(&mut screen);

    let Some(memory_map) = MEMORY_MAP_REQUEST.response() else {
        halt_forever();
    };
    let Some(hhdm) = HHDM_REQUEST.response() else {
        halt_forever();
    };
    let Ok(mut frames) = UsableFrameAllocator::new(memory_map) else {
        halt_forever();
    };
    let Ok(page_table) = (unsafe { ActivePageTable::from_current(hhdm.offset) }) else {
        halt_forever();
    };
    if page_table.reserve_active_frames(&mut frames).is_err() {
        ui.input_status = "Boot failure: could not reserve active page tables";
        ui.render(&mut screen);
        halt_forever();
    }
    let serial = unsafe { SerialPort::new(SerialPort::COM1_BASE) };
    let Ok(fs) = RedoxFs::new() else {
        halt_forever();
    };
    let mut context = KernelContext {
        frames,
        page_table,
        hhdm_offset: hhdm.offset,
        fs,
        serial,
        input: None,
        screen,
        ui,
        paging_verified: false,
        pending_console: [0; CONSOLE_BATCH_CAPACITY],
        pending_console_len: 0,
        pending_input: [0; INPUT_BATCH_CAPACITY],
        pending_input_len: 0,
        log_flush_deadline: 0,
    };
    context.paging_verified = verify_paging(&mut context);
    if !context.paging_verified {
        halt_forever();
    }
    usb::configure_timestamp_frequency(
        TSC_FREQUENCY_REQUEST
            .response()
            .map(|response| response.frequency),
    );
    match unsafe {
        InputManager::initialize(
            &mut context.page_table,
            &mut context.frames,
            context.hhdm_offset,
        )
    } {
        Ok(input) => {
            context.ui.input_available = input.usable_interface_count() != 0;
            context.ui.completion_code = None;
            context.ui.input_status = if context.ui.input_available {
                "USB HID: ready - move the mouse and type below"
            } else if let Some(failure) = input.enumeration_failures().first() {
                context.ui.completion_code = usb_error_completion_code(failure.error);
                usb_error_status(failure.error)
            } else if !input.descriptor_failures().is_empty() {
                "USB HID: report descriptor parsing failed"
            } else {
                "USB HID: controller ready, but no HID interfaces found"
            };
            context.input = Some(input);
        }
        Err(error) => {
            context.ui.input_available = false;
            context.ui.completion_code = usb_error_completion_code(error);
            context.ui.input_status = usb_error_status(error);
        }
    }
    context.ui.render(&mut context.screen);

    let mut scheduler = Scheduler::<KernelContext, 5>::new();
    if scheduler.spawn(filesystem_task).is_err()
        || scheduler.spawn(console_task).is_err()
        || scheduler.spawn(accounting_task).is_err()
        || scheduler.spawn(log_flush_task).is_err()
        || scheduler.spawn(input_task).is_err()
    {
        halt_forever();
    }

    loop {
        scheduler.run_round(&mut context);
        core::hint::spin_loop();
    }
}

struct KernelContext {
    frames: UsableFrameAllocator<'static>,
    page_table: ActivePageTable,
    hhdm_offset: u64,
    fs: RedoxFs,
    serial: Option<SerialPort>,
    input: Option<InputManager>,
    screen: FramebufferWriter<'static>,
    ui: ValidationUi,
    paging_verified: bool,
    pending_console: [u8; CONSOLE_BATCH_CAPACITY],
    pending_console_len: usize,
    pending_input: [u8; INPUT_BATCH_CAPACITY],
    pending_input_len: usize,
    log_flush_deadline: u64,
}

const CONSOLE_BATCH_CAPACITY: usize = 256;
const CONSOLE_FLUSH_THRESHOLD: usize = CONSOLE_BATCH_CAPACITY - 32;
const INPUT_RECORD_SIZE: usize = 24;
const INPUT_BATCH_RECORDS: usize = 512;
const INPUT_BATCH_CAPACITY: usize = INPUT_RECORD_SIZE * INPUT_BATCH_RECORDS;
const INPUT_FLUSH_THRESHOLD: usize = INPUT_RECORD_SIZE * (INPUT_BATCH_RECORDS - 32);
const LOG_FLUSH_DELAY_SECONDS: u64 = 2;
const TEXT_BUFFER_CAPACITY: usize = 512;
const CURSOR_SIZE: usize = 19;
const UI_MARGIN: usize = 40;
const TEXT_TOP: usize = 148;
const TEXT_ORIGIN_X: usize = UI_MARGIN + 20;
const TEXT_ORIGIN_Y: usize = TEXT_TOP + 48;
const TEXT_SCALE: usize = 2;
const TEXT_ADVANCE: usize = 10;
const TEXT_LINE_HEIGHT: usize = 17;

struct ValidationUi {
    text: [u8; TEXT_BUFFER_CAPACITY],
    text_len: usize,
    mouse_x: usize,
    mouse_y: usize,
    width: usize,
    height: usize,
    mouse_pressed: bool,
    input_available: bool,
    input_status: &'static str,
    completion_code: Option<u8>,
    cursor_backing: [u32; CURSOR_SIZE * CURSOR_SIZE],
    cursor_origin_x: usize,
    cursor_origin_y: usize,
    cursor_width: usize,
    cursor_height: usize,
    cursor_visible: bool,
}

impl ValidationUi {
    fn new(width: usize, height: usize) -> Self {
        Self {
            text: [0; TEXT_BUFFER_CAPACITY],
            text_len: 0,
            mouse_x: width / 2,
            mouse_y: height / 2,
            width,
            height,
            mouse_pressed: false,
            input_available: false,
            input_status: "USB HID: initializing...",
            completion_code: None,
            cursor_backing: [0; CURSOR_SIZE * CURSOR_SIZE],
            cursor_origin_x: 0,
            cursor_origin_y: 0,
            cursor_width: 0,
            cursor_height: 0,
            cursor_visible: false,
        }
    }

    fn push_byte(&mut self, byte: u8) -> Option<(usize, usize)> {
        let previous_len = self.text_len;
        if byte == 8 {
            if self.text_len == 0 {
                return None;
            }
            self.text_len -= 1;
        } else if byte == b'\t' {
            for _ in 0..4 {
                let Some(slot) = self.text.get_mut(self.text_len) else {
                    break;
                };
                *slot = b' ';
                self.text_len += 1;
            }
        } else {
            if byte != b'\n' && !(0x20..=0x7e).contains(&byte) {
                return None;
            }
            let slot = self.text.get_mut(self.text_len)?;
            *slot = byte;
            self.text_len += 1;
        }

        (self.text_len != previous_len).then_some((
            self.text_len.min(previous_len),
            self.text_len.max(previous_len),
        ))
    }

    fn move_mouse(&mut self, axis: Axis, value: i32, relative: bool) -> bool {
        let (coordinate, extent) = match axis {
            Axis::X => (&mut self.mouse_x, self.width),
            Axis::Y => (&mut self.mouse_y, self.height),
            _ => return false,
        };
        if extent == 0 {
            return false;
        }
        let next = if relative {
            (*coordinate as i64 + i64::from(value)).clamp(0, extent.saturating_sub(1) as i64)
                as usize
        } else {
            let normalized = i64::from(value)
                .saturating_sub(i64::from(AXIS_MIN))
                .clamp(0, i64::from(AXIS_MAX) - i64::from(AXIS_MIN));
            (normalized * extent.saturating_sub(1) as i64
                / (i64::from(AXIS_MAX) - i64::from(AXIS_MIN))) as usize
        };
        if next == *coordinate {
            return false;
        }
        *coordinate = next;
        true
    }

    fn set_mouse_button(&mut self, pressed: bool) -> bool {
        if self.mouse_pressed == pressed {
            return false;
        }
        self.mouse_pressed = pressed;
        true
    }

    fn refresh_cursor(&mut self, screen: &mut FramebufferWriter<'_>) {
        self.hide_cursor(screen);
        self.show_cursor(screen);
    }

    fn render_status(&mut self, screen: &mut FramebufferWriter<'_>) {
        self.hide_cursor(screen);
        let panel = Rgb::new(31, 41, 61);
        let accent = Rgb::new(110, 231, 183);
        let warning = Rgb::new(251, 191, 36);
        let muted = Rgb::new(148, 163, 184);
        screen.fill_rect(UI_MARGIN + 30, UI_MARGIN + 52, 72 * 5, 10, panel);
        screen.fill_rect(UI_MARGIN + 30, UI_MARGIN + 64, 30 * 5, 10, panel);
        screen.draw_text(
            UI_MARGIN + 30,
            UI_MARGIN + 52,
            1,
            self.input_status,
            if self.input_available {
                accent
            } else {
                warning
            },
        );
        if let Some(code) = self.completion_code {
            let digits = [hex_digit(code >> 4), hex_digit(code & 0x0f)];
            screen.draw_text(
                UI_MARGIN + 30,
                UI_MARGIN + 64,
                1,
                "xHCI completion code: 0x",
                muted,
            );
            let digits = unsafe { core::str::from_utf8_unchecked(&digits) };
            screen.draw_text(UI_MARGIN + 30 + 24 * 5, UI_MARGIN + 64, 1, digits, warning);
        }
        self.show_cursor(screen);
    }

    fn render_text_range(
        &mut self,
        screen: &mut FramebufferWriter<'_>,
        dirty_start: usize,
        dirty_end: usize,
    ) {
        self.hide_cursor(screen);
        let panel = Rgb::new(31, 41, 61);
        let primary = Rgb::new(232, 238, 247);
        let muted = Rgb::new(148, 163, 184);

        if dirty_start == 0 {
            screen.fill_rect(
                TEXT_ORIGIN_X,
                TEXT_ORIGIN_Y,
                12 * TEXT_ADVANCE,
                TEXT_LINE_HEIGHT,
                panel,
            );
        }
        for index in dirty_start..dirty_end {
            let (x, y) = self.text_position(index);
            screen.fill_rect(x, y, TEXT_ADVANCE, TEXT_LINE_HEIGHT, panel);
        }
        for index in dirty_start..self.text_len {
            let byte = self.text[index];
            if byte == b'\n' {
                continue;
            }
            let (x, y) = self.text_position(index);
            let bytes = [byte];
            let glyph = unsafe { core::str::from_utf8_unchecked(&bytes) };
            screen.draw_text(x, y, TEXT_SCALE, glyph, primary);
        }
        if self.text_len == 0 {
            screen.draw_text(
                TEXT_ORIGIN_X,
                TEXT_ORIGIN_Y,
                TEXT_SCALE,
                "Type here...",
                muted,
            );
        }
        self.show_cursor(screen);
    }

    fn text_position(&self, index: usize) -> (usize, usize) {
        let mut x = TEXT_ORIGIN_X;
        let mut y = TEXT_ORIGIN_Y;
        let right = self.width.saturating_sub(TEXT_ORIGIN_X);
        for byte in self.text[..index.min(TEXT_BUFFER_CAPACITY)].iter().copied() {
            match byte {
                b'\n' => {
                    x = TEXT_ORIGIN_X;
                    y = y.saturating_add(TEXT_LINE_HEIGHT);
                }
                b'\r' => x = TEXT_ORIGIN_X,
                _ => {
                    if x != TEXT_ORIGIN_X && x.saturating_add(TEXT_ADVANCE) > right {
                        x = TEXT_ORIGIN_X;
                        y = y.saturating_add(TEXT_LINE_HEIGHT);
                    }
                    x = x.saturating_add(TEXT_ADVANCE);
                }
            }
        }
        if x != TEXT_ORIGIN_X && x.saturating_add(TEXT_ADVANCE) > right {
            x = TEXT_ORIGIN_X;
            y = y.saturating_add(TEXT_LINE_HEIGHT);
        }
        (x, y)
    }

    fn hide_cursor(&mut self, screen: &mut FramebufferWriter<'_>) {
        if !self.cursor_visible {
            return;
        }
        for y in 0..self.cursor_height {
            for x in 0..self.cursor_width {
                screen.write_raw_pixel(
                    self.cursor_origin_x + x,
                    self.cursor_origin_y + y,
                    self.cursor_backing[y * CURSOR_SIZE + x],
                );
            }
        }
        self.cursor_visible = false;
    }

    fn show_cursor(&mut self, screen: &mut FramebufferWriter<'_>) {
        self.cursor_origin_x = self.mouse_x.saturating_sub(CURSOR_SIZE / 2);
        self.cursor_origin_y = self.mouse_y.saturating_sub(CURSOR_SIZE / 2);
        self.cursor_width = CURSOR_SIZE.min(self.width.saturating_sub(self.cursor_origin_x));
        self.cursor_height = CURSOR_SIZE.min(self.height.saturating_sub(self.cursor_origin_y));
        for y in 0..self.cursor_height {
            for x in 0..self.cursor_width {
                self.cursor_backing[y * CURSOR_SIZE + x] = screen
                    .read_raw_pixel(self.cursor_origin_x + x, self.cursor_origin_y + y)
                    .unwrap_or(0);
            }
        }

        let color = if self.mouse_pressed {
            Rgb::new(251, 191, 36)
        } else {
            Rgb::new(110, 231, 183)
        };
        screen.fill_rect(
            self.mouse_x.saturating_sub(1),
            self.mouse_y.saturating_sub(CURSOR_SIZE / 2),
            3,
            CURSOR_SIZE,
            color,
        );
        screen.fill_rect(
            self.mouse_x.saturating_sub(CURSOR_SIZE / 2),
            self.mouse_y.saturating_sub(1),
            CURSOR_SIZE,
            3,
            color,
        );
        self.cursor_visible = true;
    }

    fn render(&mut self, screen: &mut FramebufferWriter<'_>) {
        let background = Rgb::new(18, 24, 38);
        let panel = Rgb::new(31, 41, 61);
        let primary = Rgb::new(232, 238, 247);
        let muted = Rgb::new(148, 163, 184);
        let accent = Rgb::new(110, 231, 183);
        let warning = Rgb::new(251, 191, 36);
        screen.clear(background);
        screen.fill_rect(
            UI_MARGIN,
            UI_MARGIN,
            screen.width().saturating_sub(UI_MARGIN * 2),
            76,
            panel,
        );
        screen.fill_rect(UI_MARGIN, UI_MARGIN, 10, 76, accent);
        screen.draw_text(
            UI_MARGIN + 30,
            UI_MARGIN + 18,
            3,
            "HID input validation",
            primary,
        );
        screen.draw_text(
            UI_MARGIN + 30,
            UI_MARGIN + 52,
            1,
            self.input_status,
            if self.input_available {
                accent
            } else {
                warning
            },
        );
        if let Some(code) = self.completion_code {
            let digits = [hex_digit(code >> 4), hex_digit(code & 0x0f)];
            screen.draw_text(
                UI_MARGIN + 30,
                UI_MARGIN + 64,
                1,
                "xHCI completion code: 0x",
                muted,
            );
            let digits = unsafe { core::str::from_utf8_unchecked(&digits) };
            screen.draw_text(UI_MARGIN + 30 + 24 * 5, UI_MARGIN + 64, 1, digits, warning);
        }

        screen.draw_text(UI_MARGIN, TEXT_TOP, 2, "Keyboard text buffer", muted);
        screen.fill_rect(
            UI_MARGIN,
            TEXT_TOP + 28,
            screen.width().saturating_sub(UI_MARGIN * 2),
            screen.height().saturating_sub(TEXT_TOP + 68),
            panel,
        );
        let text = unsafe { core::str::from_utf8_unchecked(&self.text[..self.text_len]) };
        screen.draw_text_wrapped(
            TEXT_ORIGIN_X,
            TEXT_ORIGIN_Y,
            screen.width().saturating_sub(TEXT_ORIGIN_X * 2),
            TEXT_SCALE,
            text,
            primary,
        );
        if self.text_len == 0 {
            screen.draw_text(
                TEXT_ORIGIN_X,
                TEXT_ORIGIN_Y,
                TEXT_SCALE,
                "Type here...",
                muted,
            );
        }

        self.cursor_visible = false;
        self.show_cursor(screen);
    }
}

fn verify_paging(context: &mut KernelContext) -> bool {
    const SCRATCH_CANDIDATES: [u64; 8] = [
        0xffff_ff00_0000_0000,
        0xffff_fe00_0000_0000,
        0xffff_fd00_0000_0000,
        0xffff_fc00_0000_0000,
        0xffff_fb00_0000_0000,
        0xffff_fa00_0000_0000,
        0xffff_f900_0000_0000,
        0xffff_f800_0000_0000,
    ];
    const TEST_VALUE: u64 = 0x4749_4e4b_474f_4f53;

    let Some(address) = SCRATCH_CANDIDATES.into_iter().find_map(|candidate| {
        let address = VirtAddr::try_new(candidate).ok()?;
        context
            .page_table
            .translate_addr(address)
            .is_none()
            .then_some(address)
    }) else {
        return false;
    };
    let Ok(page) = VirtPage::from_start_address(address) else {
        return false;
    };

    let Ok(Some(frame)) = context.frames.allocate_frame() else {
        return false;
    };
    if unsafe {
        context
            .page_table
            .map_4k(page, frame, PageTableFlags::WRITABLE, &mut context.frames)
    }
    .is_err()
    {
        return false;
    }

    let verified = context
        .hhdm_offset
        .checked_add(frame.start_address().as_u64())
        .map(|direct_address| {
            let Some(direct_pointer) = NonNull::new(direct_address as *mut u64) else {
                return false;
            };
            let Some(mapped_pointer) = NonNull::new(address.as_mut_ptr::<u64>()) else {
                return false;
            };
            unsafe { VolatilePtr::new(direct_pointer) }.write(TEST_VALUE);
            unsafe { VolatilePtr::new(mapped_pointer) }.read() == TEST_VALUE
        })
        .unwrap_or(false);

    let unmapped = unsafe { context.page_table.unmap_4k(page) }
        .map(|unmapped_frame| unmapped_frame == frame)
        .unwrap_or(false);
    verified && unmapped && context.page_table.translate_addr(address).is_none()
}

fn filesystem_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    const MESSAGE: &[u8] = b"GinkgoOS: paging, RedoxFS, devices, and scheduler online\r\n";

    if state.get(0) == Some(0) {
        let file = match context.fs.create("/system.log") {
            Ok(file) => file,
            Err(_) => return TaskPoll::Complete,
        };
        if context.fs.write(file, 0, MESSAGE).is_err() {
            return TaskPoll::Complete;
        }
        state.set(0, 1);
    }

    let offset = state.get(1).unwrap_or(0).min(MESSAGE.len());
    let Some(serial) = context.serial.as_mut() else {
        return TaskPoll::Complete;
    };
    match serial.write_available(&MESSAGE[offset..]) {
        Ok(written) if offset + written < MESSAGE.len() => {
            state.set(1, offset + written);
            TaskPoll::Pending
        }
        Ok(_) | Err(_) => TaskPoll::Complete,
    }
}

fn console_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    if state.get(0) == Some(0) {
        if context.fs.create("/console").is_err() {
            return TaskPoll::Complete;
        }
        state.set(0, 1);
    }

    let Some(serial) = context.serial.as_mut() else {
        return TaskPoll::Complete;
    };
    let byte = match serial.try_read() {
        Ok(Some(byte)) => byte,
        Ok(None) => return TaskPoll::Pending,
        Err(_) => return TaskPoll::Complete,
    };
    let _ = serial.try_write(byte);
    queue_console_byte(context, byte);
    TaskPoll::Pending
}

fn input_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    let Some(input) = context.input.as_mut() else {
        return TaskPoll::Complete;
    };
    let summary = match input.poll() {
        Ok(summary) => summary,
        Err(error) => {
            context.ui.input_available = false;
            context.ui.completion_code = usb_error_completion_code(error);
            context.ui.input_status = usb_error_status(error);
            context.ui.render(&mut context.screen);
            return TaskPoll::Complete;
        }
    };
    if let Some(code) = input.first_transfer_error() {
        context.ui.input_available = false;
        context.ui.completion_code = Some(code);
        context.ui.input_status = "USB HID: interrupt endpoint stopped with a transfer error";
        context.ui.render(&mut context.screen);
        return TaskPoll::Complete;
    }

    let old_cursor = (
        context.ui.mouse_x,
        context.ui.mouse_y,
        context.ui.mouse_pressed,
    );
    let receiving_status = "USB HID: receiving reports - mouse and keyboard active";
    let status_dirty = summary.reports != 0 && context.ui.input_status != receiving_status;
    if status_dirty {
        context.ui.input_status = receiving_status;
        context.ui.completion_code = None;
    }
    if status_dirty {
        context.ui.render_status(&mut context.screen);
    }
    for _ in 0..32 {
        let Some(event) = context.input.as_mut().and_then(InputManager::pop_event) else {
            break;
        };
        if let Some((start, end)) = handle_input_event(context, state, event) {
            context
                .ui
                .render_text_range(&mut context.screen, start, end);
        }
    }
    if old_cursor
        != (
            context.ui.mouse_x,
            context.ui.mouse_y,
            context.ui.mouse_pressed,
        )
    {
        context.ui.refresh_cursor(&mut context.screen);
    }
    TaskPoll::Pending
}

fn handle_input_event(
    context: &mut KernelContext,
    state: &mut TaskState,
    device_event: DeviceInputEvent,
) -> Option<(usize, usize)> {
    let application = context
        .input
        .as_ref()
        .and_then(|input| input.application_kind(device_event.interface));
    let mut text_dirty = None;
    match device_event.event {
        InputEvent::Key { usage, pressed, .. } => {
            if matches!(usage, 0xe1 | 0xe5) {
                let bit = if usage == 0xe1 { 1 } else { 2 };
                let shifts = state.get(1).unwrap_or(0);
                state.set(1, if pressed { shifts | bit } else { shifts & !bit });
            } else if usage == 0x39 && pressed {
                state.set(2, state.get(2).unwrap_or(0) ^ 1);
            } else if pressed {
                let shift = state.get(1).unwrap_or(0) != 0;
                let caps_lock = state.get(2).unwrap_or(0) != 0;
                if let Some(byte) = keyboard_ascii(usage, shift, caps_lock) {
                    if let Some(serial) = context.serial.as_mut() {
                        let _ = serial.try_write(byte);
                    }
                    queue_console_byte(context, byte);
                    text_dirty = context.ui.push_byte(byte);
                }
            }
        }
        InputEvent::Axis {
            axis,
            value,
            relative,
            ..
        } if application == Some(ApplicationKind::Mouse) => {
            let _ = context.ui.move_mouse(axis, value, relative);
        }
        InputEvent::Button {
            button: 1, pressed, ..
        } if application == Some(ApplicationKind::Mouse) => {
            let _ = context.ui.set_mouse_button(pressed);
        }
        _ => {}
    }

    queue_input_record(context, encode_input_event(device_event));
    text_dirty
}

fn queue_console_byte(context: &mut KernelContext, byte: u8) {
    let Some(slot) = context.pending_console.get_mut(context.pending_console_len) else {
        return;
    };
    *slot = byte;
    context.pending_console_len += 1;
    schedule_log_flush(context);
}

fn queue_input_record(context: &mut KernelContext, record: [u8; INPUT_RECORD_SIZE]) {
    let Some(end) = context.pending_input_len.checked_add(INPUT_RECORD_SIZE) else {
        return;
    };
    let Some(destination) = context
        .pending_input
        .get_mut(context.pending_input_len..end)
    else {
        return;
    };
    destination.copy_from_slice(&record);
    context.pending_input_len = end;
    schedule_log_flush(context);
}

fn schedule_log_flush(context: &mut KernelContext) {
    let delay = usb::timestamp_frequency().saturating_mul(LOG_FLUSH_DELAY_SECONDS);
    context.log_flush_deadline = usb::timestamp().saturating_add(delay);
}

fn log_flush_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    let now = usb::timestamp();
    let inactivity_elapsed = context.log_flush_deadline != 0 && now >= context.log_flush_deadline;
    if context.pending_console_len < CONSOLE_FLUSH_THRESHOLD
        && context.pending_input_len < INPUT_FLUSH_THRESHOLD
        && !inactivity_elapsed
    {
        return TaskPoll::Pending;
    }

    if context.pending_console_len != 0
        && append_log(
            &mut context.fs,
            "/console",
            &context.pending_console[..context.pending_console_len],
        )
    {
        context.pending_console_len = 0;
    }
    if context.pending_input_len != 0
        && append_log(
            &mut context.fs,
            "/input",
            &context.pending_input[..context.pending_input_len],
        )
    {
        context.pending_input_len = 0;
    }
    context.log_flush_deadline =
        if context.pending_console_len == 0 && context.pending_input_len == 0 {
            0
        } else {
            now.saturating_add(usb::timestamp_frequency().saturating_mul(LOG_FLUSH_DELAY_SECONDS))
        };
    TaskPoll::Pending
}

fn append_log(fs: &mut RedoxFs, path: &str, bytes: &[u8]) -> bool {
    const LOG_LIMIT: u64 = 64 * 1024;
    let file = match fs.open(path).or_else(|_| fs.create(path)) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let Ok(info) = fs.stat(file) else {
        return false;
    };
    let incoming = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let reset = info.len >= LOG_LIMIT
        || info
            .len
            .checked_add(incoming)
            .is_none_or(|end| end > LOG_LIMIT);
    if reset && fs.truncate(file, 0).is_err() {
        return false;
    }
    let offset = if reset { 0 } else { info.len };
    fs.write(file, offset, bytes).is_ok()
}

fn keyboard_ascii(usage: u16, shift: bool, caps_lock: bool) -> Option<u8> {
    let byte = match usage {
        0x04..=0x1d => b'a' + (usage - 0x04) as u8,
        0x1e..=0x26 => b'1' + (usage - 0x1e) as u8,
        0x27 => b'0',
        0x28 => b'\n',
        0x2a => 8,
        0x2b => b'\t',
        0x2c => b' ',
        0x2d => b'-',
        0x2e => b'=',
        0x2f => b'[',
        0x30 => b']',
        0x31 => b'\\',
        0x33 => b';',
        0x34 => b'\'',
        0x35 => b'`',
        0x36 => b',',
        0x37 => b'.',
        0x38 => b'/',
        _ => return None,
    };
    if byte.is_ascii_lowercase() {
        return Some(if shift ^ caps_lock { byte - 32 } else { byte });
    }
    if !shift {
        return Some(byte);
    }
    Some(match byte {
        b'1'..=b'9' => b"!@#$%^&*("[(byte - b'1') as usize],
        b'0' => b')',
        b'-' => b'_',
        b'=' => b'+',
        b'[' => b'{',
        b']' => b'}',
        b'\\' => b'|',
        b';' => b':',
        b'\'' => b'"',
        b'`' => b'~',
        b',' => b'<',
        b'.' => b'>',
        b'/' => b'?',
        _ => byte,
    })
}

fn encode_input_event(device_event: DeviceInputEvent) -> [u8; INPUT_RECORD_SIZE] {
    let mut record = [0_u8; INPUT_RECORD_SIZE];
    record[..4].copy_from_slice(&device_event.interface.device.to_le_bytes());
    record[4] = device_event.interface.interface;
    let (kind, usage_page, usage, value, raw_value) = match device_event.event {
        InputEvent::Key { usage, pressed, .. } => (1, 0x07, usage, i32::from(pressed), 0),
        InputEvent::Button {
            button, pressed, ..
        } => (2, 0x09, button, i32::from(pressed), 0),
        InputEvent::Axis {
            axis,
            value,
            raw_value,
            relative,
            ..
        } => (
            3 | (u8::from(relative) << 7),
            0x01,
            axis_usage(axis),
            value,
            raw_value,
        ),
        InputEvent::HatSwitch { position, .. } => {
            (4, 0x01, 0x39, position.map_or(-1, i32::from), 0)
        }
        InputEvent::Value {
            usage,
            value,
            relative,
            ..
        } => (
            5 | (u8::from(relative) << 7),
            usage.page,
            usage.id,
            value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
            value,
        ),
    };
    record[5] = kind;
    record[6..8].copy_from_slice(&usage_page.to_le_bytes());
    record[8..10].copy_from_slice(&usage.to_le_bytes());
    record[12..16].copy_from_slice(&value.to_le_bytes());
    record[16..24].copy_from_slice(&raw_value.to_le_bytes());
    record
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + (value - 10),
    }
}

const fn usb_error_completion_code(error: UsbError) -> Option<u8> {
    match error {
        UsbError::CommandFailed(code) | UsbError::TransferFailed(code) => Some(code),
        _ => None,
    }
}

fn usb_error_status(error: UsbError) -> &'static str {
    match error {
        UsbError::Pci(_) => "USB HID: no usable PCI xHCI controller",
        UsbError::Paging(_)
        | UsbError::FrameAllocator(_)
        | UsbError::OutOfFrames
        | UsbError::AddressOverflow
        | UsbError::InvalidMmioBar
        | UsbError::MmioOutOfRange
        | UsbError::UnsupportedDmaAddress => "USB HID: controller memory setup failed",
        UsbError::UnsupportedPageSize | UsbError::InvalidCapability => {
            "USB HID: unsupported xHCI controller capabilities"
        }
        UsbError::ControllerTimeout => "USB HID: xHCI operation timed out",
        UsbError::ControllerError => "USB HID: xHCI controller halted or reported a fatal error",
        UsbError::NoSlots | UsbError::InvalidSlot => "USB HID: xHCI device slot setup failed",
        UsbError::InvalidPort | UsbError::PortDisconnected | UsbError::PortResetFailed => {
            "USB HID: connected root port failed to reset"
        }
        UsbError::RingFull => "USB HID: xHCI transfer ring exhausted",
        UsbError::CommandFailed(_) => "USB HID: xHCI enumeration command failed",
        UsbError::TransferFailed(_) => "USB HID: USB control or input transfer failed",
        UsbError::InvalidEndpoint => "USB HID: interrupt endpoint configuration failed",
        UsbError::Descriptor(_) => "USB HID: USB configuration descriptor was rejected",
        UsbError::TooManyInterfaces => "USB HID: too many HID interfaces",
        UsbError::ReportTooLarge => "USB HID: device report is too large",
    }
}

const fn axis_usage(axis: Axis) -> u16 {
    match axis {
        Axis::X => 0x30,
        Axis::Y => 0x31,
        Axis::Z => 0x32,
        Axis::Rx => 0x33,
        Axis::Ry => 0x34,
        Axis::Rz => 0x35,
        Axis::Slider => 0x36,
        Axis::Dial => 0x37,
        Axis::Wheel => 0x38,
    }
}

fn accounting_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    let ticks = state.get(0).unwrap_or(0).wrapping_add(1);
    state.set(0, ticks);

    if state.get(1) == Some(0) {
        let file = match context.fs.create("/scheduler") {
            Ok(file) => file,
            Err(_) => return TaskPoll::Complete,
        };
        if context.fs.write(file, 0, &ticks.to_le_bytes()).is_err() {
            return TaskPoll::Complete;
        }
        state.set(1, 1);
    }

    TaskPoll::Pending
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt_forever()
}

fn halt_forever() -> ! {
    interrupts::disable();
    loop {
        hlt();
    }
}
