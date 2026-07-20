#![no_std]
#![no_main]

mod crt;
mod font8x8;
mod framebuffer;
mod heap;

use core::{
    arch::asm,
    cell::UnsafeCell,
    mem::MaybeUninit,
    panic::PanicInfo,
    ptr,
};
use framebuffer::{FramebufferWriter, Rgb};
use rust_limine_framebuffer::{
    fs::RedoxFs,
    io::SerialPort,
    limine::{self, BaseRevision, FramebufferRequest, HhdmRequest, MemoryMapRequest},
    memory::{UsableFrameAllocator, VirtAddr, VirtPage},
    paging::{ActivePageTable, PageFlags},
    task::{Scheduler, TaskPoll, TaskState},
};

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
    unsafe { asm!("cli", options(nomem, nostack, preserves_flags)) };

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

    let Some(memory_map) = MEMORY_MAP_REQUEST.response() else {
        halt_forever();
    };
    let Some(hhdm) = HHDM_REQUEST.response() else {
        halt_forever();
    };
    let Ok(frames) = UsableFrameAllocator::new(memory_map) else {
        halt_forever();
    };
    let Ok(page_table) = (unsafe { ActivePageTable::from_current(hhdm.offset) }) else {
        halt_forever();
    };

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
        paging_verified: false,
    };
    context.paging_verified = verify_paging(&mut context);
    if !context.paging_verified {
        halt_forever();
    }

    // Single-core boot calls this exactly once while interrupts are disabled.
    let context = unsafe { KERNEL_CONTEXT.initialize(context) };
    let mut scheduler = Scheduler::<KernelContext, 4>::new();
    if scheduler.spawn(filesystem_task).is_err()
        || scheduler.spawn(console_task).is_err()
        || scheduler.spawn(accounting_task).is_err()
    {
        halt_forever();
    }

    loop {
        scheduler.run_round(context);
        unsafe { asm!("pause", options(nomem, nostack, preserves_flags)) };
    }
}

struct KernelContext {
    frames: UsableFrameAllocator<'static>,
    page_table: ActivePageTable,
    hhdm_offset: u64,
    fs: RedoxFs,
    serial: Option<SerialPort>,
    paging_verified: bool,
}

struct KernelContextStorage(UnsafeCell<MaybeUninit<KernelContext>>);

unsafe impl Sync for KernelContextStorage {}

impl KernelContextStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    /// The caller must initialize this storage exactly once, on the boot CPU,
    /// before sharing or retaining any other reference to its contents.
    unsafe fn initialize(&'static self, context: KernelContext) -> &'static mut KernelContext {
        (&mut *self.0.get()).write(context)
    }
}

static KERNEL_CONTEXT: KernelContextStorage = KernelContextStorage::new();

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
        let address = VirtAddr::new(candidate)?;
        context
            .page_table
            .translate_addr(address)
            .is_none()
            .then_some(address)
    }) else {
        return false;
    };
    let Some(page) = VirtPage::from_start_address(address) else {
        return false;
    };

    let Ok(Some(frame)) = context.frames.allocate_frame() else {
        return false;
    };
    if unsafe {
        context
            .page_table
            .map_4k(page, frame, PageFlags::WRITABLE, &mut context.frames)
    }
    .is_err()
    {
        return false;
    }

    let verified = context
        .hhdm_offset
        .checked_add(frame.start_address().as_u64())
        .map(|direct_address| unsafe {
            ptr::write_volatile(direct_address as *mut u64, TEST_VALUE);
            ptr::read_volatile(address.as_u64() as *const u64) == TEST_VALUE
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

    let Ok(file) = context.fs.open("/console") else {
        return TaskPoll::Complete;
    };
    let Ok(info) = context.fs.stat(file) else {
        return TaskPoll::Complete;
    };
    const CONSOLE_LIMIT: u64 = 64 * 1024;
    if info.len >= CONSOLE_LIMIT && context.fs.truncate(file, 0).is_err() {
        return TaskPoll::Complete;
    }
    let offset = if info.len >= CONSOLE_LIMIT { 0 } else { info.len };
    let _ = context.fs.write(file, offset, &[byte]);
    TaskPoll::Pending
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
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}
