#![no_std]
#![no_main]

mod crt;

mod framebuffer;
mod heap;

extern crate alloc;

use alloc::vec::Vec;
use core::{
    fmt::{self, Write as _},
    panic::PanicInfo,
    ptr::{self, NonNull},
};
use embedded_graphics::{
    image::Image,
    prelude::{Drawable, Point as GraphicsPoint},
};
use embedded_icon::{
    mdi::size24px::{CubeOutline, Magnify},
    NewIcon,
};
use framebuffer::{FramebufferWriter, Rgb};
use ginkgo_desktop::ClientId;
use ginkgo_filesystem::RedoxFs;
use ginkgo_hid::{ApplicationKind, Axis, InputEvent, AXIS_MAX, AXIS_MIN};
use ginkgo_ipc::IpcError;
use ginkgo_kernel::{
    ahci::{AhciDisk, AhciError},
    arch::{self, CpuPrivilegeState, ExternalInterruptState, KernelExit, PrivilegeStackTops},
    audio::AudioDevice,
    block::{BlockDevice, Volume, SECTOR_SIZE},
    desktop_runtime::{DesktopBroker, DesktopBrokerError, DesktopRuntimeEvent},
    entropy::EntropyPool,
    input::{DeviceInputEvent, InputManager},
    io::SerialPort,
    limine::{
        self, BaseRevision, FramebufferRequest, HhdmRequest, MemoryMapRequest, StackSizeRequest,
        TscFrequencyRequest,
    },
    local_apic::LocalApicTimer,
    memory::{UsableFrameAllocator, VirtAddr, VirtPage},
    paging::{ActivePageTable, PageTableFlags},
    process::{Process, ProcessFault, ProcessFaultReason, ProcessId, ProcessState, ProcessTable},
    syscall::{self, DebugSink, SyscallOutcome},
    task::{Scheduler, TaskPoll, TaskState},
    trust::TrustedManifest,
    usb::{self, UsbError},
    virtio_blk::{VirtioBlk, VirtioBlkError},
};
use ginkgo_program_registry::{EntryFlags, Registry};
use ginkgo_window::{
    ButtonState, KeyboardEvent, Modifiers, Point as WindowPoint, PointerButton, PointerEventKind,
};
use redoxfs::Disk;
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

static DESKTOP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-desktop.elf"));
static MINIMAL_CLIENT_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-minimal-client.elf"));
static FILE_NAVIGATOR_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-file-navigator.elf"));
static TERMINAL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-terminal.elf"));
static PROGRAM_REGISTRY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/programs.gkr"));
static TRUST_MANIFEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.manifest"));
static TRUST_SIGNATURE: &[u8; 64] =
    include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.signature"));
static TRUST_PUBLIC_KEY: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.public"));
static PREEMPTION_SMOKE_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-preemption-smoke.elf"));
static GINKGO_SPLASH_RGBA: &[u8; 256 * 256 * 4] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-splash.rgba"));
fn preemption_smoke_enabled() -> bool {
    option_env!("GINKGO_PREEMPTION_SMOKE") == Some("1")
}

const DESKTOP_PATH: &str = "/desktop.elf";
const MINIMAL_CLIENT_PATH: &str = "/minimal-client.elf";
const FILE_NAVIGATOR_PATH: &str = "/file-navigator.elf";
const TERMINAL_PATH: &str = "/terminal.elf";
const PROGRAM_REGISTRY_PATH: &str = "/programs.gkr";
const MAX_EXECUTABLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_LAUNCHER_PROGRAMS: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageError {
    Virtio(VirtioBlkError),
    Ahci(AhciError),
}

enum StorageDisk {
    Virtio(VirtioBlk),
    Ahci(AhciDisk),
}

impl BlockDevice for StorageDisk {
    type Error = StorageError;

    fn capacity_sectors(&self) -> u64 {
        match self {
            Self::Virtio(disk) => disk.capacity_sectors(),
            Self::Ahci(disk) => disk.capacity_sectors(),
        }
    }

    fn read_sectors(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            Self::Virtio(disk) => disk.read_sectors(lba, buffer).map_err(StorageError::Virtio),
            Self::Ahci(disk) => disk.read_sectors(lba, buffer).map_err(StorageError::Ahci),
        }
    }

    fn write_sectors(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Virtio(disk) => disk
                .write_sectors(lba, buffer)
                .map_err(StorageError::Virtio),
            Self::Ahci(disk) => disk.write_sectors(lba, buffer).map_err(StorageError::Ahci),
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Virtio(disk) => disk.flush().map_err(StorageError::Virtio),
            Self::Ahci(disk) => disk.flush().map_err(StorageError::Ahci),
        }
    }
}

fn volume_is_blank<D: BlockDevice>(volume: &mut Volume<D>) -> bool {
    let mut sector = [0_u8; SECTOR_SIZE];
    let sectors = redoxfs::BLOCK_SIZE as usize / SECTOR_SIZE;
    for lba in 0..sectors {
        if volume.read_sectors(lba as u64, &mut sector).is_err()
            || sector.iter().any(|byte| *byte != 0)
        {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
struct ProgramSummary {
    app_id: [u8; 64],
    app_id_len: usize,
    name: [u8; 48],
    name_len: usize,
    path: [u8; 64],
    path_len: usize,
    filesystem: bool,
    process_launch: bool,
}

impl ProgramSummary {
    const EMPTY: Self = Self {
        app_id: [0; 64],
        app_id_len: 0,
        name: [0; 48],
        name_len: 0,
        path: [0; 64],
        path_len: 0,
        filesystem: false,
        process_launch: false,
    };

    fn app_id(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.app_id[..self.app_id_len]) }
    }

    fn name(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.name[..self.name_len]) }
    }

    fn path(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.path[..self.path_len]) }
    }
}

#[derive(Clone, Copy)]
struct ProgramCatalog {
    programs: [ProgramSummary; MAX_LAUNCHER_PROGRAMS],
    len: usize,
}

impl ProgramCatalog {
    const EMPTY: Self = Self {
        programs: [ProgramSummary::EMPTY; MAX_LAUNCHER_PROGRAMS],
        len: 0,
    };

    fn get(&self, index: usize) -> Option<ProgramSummary> {
        self.programs
            .get(index)
            .copied()
            .filter(|_| index < self.len)
    }

    fn find(&self, app_id: &str) -> Option<ProgramSummary> {
        self.programs[..self.len]
            .iter()
            .copied()
            .find(|program| program.app_id() == app_id)
    }
}

fn install_and_load_system_programs<D: Disk>(
    fs: &mut RedoxFs<D>,
) -> Option<(Vec<u8>, ProgramCatalog)> {
    install_system_file(fs, DESKTOP_PATH, DESKTOP_ELF)?;
    install_system_file(fs, MINIMAL_CLIENT_PATH, MINIMAL_CLIENT_ELF)?;
    install_system_file(fs, FILE_NAVIGATOR_PATH, FILE_NAVIGATOR_ELF)?;
    install_system_file(fs, TERMINAL_PATH, TERMINAL_ELF)?;
    install_system_file(fs, PROGRAM_REGISTRY_PATH, PROGRAM_REGISTRY)?;

    let registry_bytes = read_trusted_system_file(fs, PROGRAM_REGISTRY_PATH, 16 * 1024)?;
    let registry = Registry::parse(&registry_bytes).ok()?;
    let desktop = registry.entries().find(|entry| entry.app_id == "desktop")?;
    if desktop.executable_path != DESKTOP_PATH || desktop.is_visible() {
        return None;
    }

    let mut catalog = ProgramCatalog::EMPTY;
    for entry in registry.visible_entries().take(MAX_LAUNCHER_PROGRAMS) {
        let slot = &mut catalog.programs[catalog.len];
        slot.app_id_len = copy_program_string(&mut slot.app_id, entry.app_id)?;
        slot.name_len = copy_program_string(&mut slot.name, entry.display_name)?;
        slot.path_len = copy_program_string(&mut slot.path, entry.executable_path)?;
        slot.filesystem = entry.flags.contains(EntryFlags::FILESYSTEM);
        slot.process_launch = entry.flags.contains(EntryFlags::PROCESS_LAUNCH);
        catalog.len += 1;
    }

    let desktop_image =
        read_trusted_system_file(fs, desktop.executable_path, MAX_EXECUTABLE_BYTES)?;
    Some((desktop_image, catalog))
}

fn read_trusted_system_file<D: Disk>(
    fs: &mut RedoxFs<D>,
    path: &str,
    maximum: usize,
) -> Option<Vec<u8>> {
    let manifest =
        TrustedManifest::verify(TRUST_MANIFEST, TRUST_SIGNATURE, TRUST_PUBLIC_KEY).ok()?;
    let bytes = read_system_file(fs, path, maximum)?;
    manifest.verify_artifact(path, &bytes).ok()?;
    Some(bytes)
}

fn read_system_file<D: Disk>(fs: &mut RedoxFs<D>, path: &str, maximum: usize) -> Option<Vec<u8>> {
    let file = fs.open(path).ok()?;
    let length = usize::try_from(fs.stat(file).ok()?.len).ok()?;
    if length == 0 || length > maximum {
        return None;
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.resize(length, 0);
    (fs.read(file, 0, &mut bytes).ok()? == length).then_some(bytes)
}

fn copy_program_string<const N: usize>(output: &mut [u8; N], value: &str) -> Option<usize> {
    let destination = output.get_mut(..value.len())?;
    destination.copy_from_slice(value.as_bytes());
    Some(value.len())
}

fn install_system_file<D: Disk>(fs: &mut RedoxFs<D>, path: &str, bytes: &[u8]) -> Option<()> {
    let file = fs.open(path).or_else(|_| fs.create(path)).ok()?;
    fs.truncate(file, 0).ok()?;
    (fs.write(file, 0, bytes).ok()? == bytes.len()).then_some(())
}

const PRIVILEGE_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
struct PrivilegeStack([u8; PRIVILEGE_STACK_SIZE]);

static mut RSP0_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut NMI_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut MACHINE_CHECK_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut SYSCALL_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut CPU_PRIVILEGE_STATE: CpuPrivilegeState = CpuPrivilegeState::new();

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
    let Some(mut screen) = (unsafe { framebuffer::from_limine(framebuffer) }) else {
        halt_forever();
    };

    let mut ui = ValidationUi::new(screen.width(), screen.height());
    ui.render_boot_log(&mut screen, "framebuffer: online");

    let Some(memory_map) = MEMORY_MAP_REQUEST.response() else {
        halt_forever();
    };
    let Some(hhdm) = HHDM_REQUEST.response() else {
        halt_forever();
    };
    let Ok(mut frames) = UsableFrameAllocator::new(memory_map) else {
        halt_forever();
    };
    let Ok(mut page_table) = (unsafe { ActivePageTable::from_current(hhdm.offset) }) else {
        halt_forever();
    };
    if page_table.reserve_active_frames(&mut frames).is_err() {
        ui.render_boot_log(&mut screen, "paging: failed to reserve active tables");
        halt_forever();
    }
    let mut serial = unsafe { SerialPort::new(SerialPort::COM1_BASE) };
    let Some(tsc_frequency) = TSC_FREQUENCY_REQUEST
        .response()
        .map(|response| response.frequency)
        .filter(|frequency| *frequency != 0)
    else {
        let mut sink = SerialDebugSink::new(&mut serial);
        let _ = writeln!(sink, "timer: TSC frequency unavailable\r");
        ui.render_boot_log(&mut screen, "timer: TSC frequency unavailable");
        halt_forever();
    };
    let entropy = match EntropyPool::initialize(
        tsc_frequency,
        hhdm.offset ^ (&frames as *const UsableFrameAllocator<'_> as usize as u64),
    ) {
        Ok(entropy) => entropy,
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut serial);
            let _ = writeln!(sink, "entropy: secure initialization failed: {error:?}\r");
            ui.render_boot_log(&mut screen, "entropy: no secure hardware seed");
            halt_forever();
        }
    };
    let timer =
        match unsafe { LocalApicTimer::initialize(&mut page_table, &mut frames, tsc_frequency) } {
            Ok(timer) => timer,
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(sink, "timer: local APIC initialization failed: {error:?}\r");
                ui.render_boot_log(&mut screen, "timer: local APIC initialization failed");
                halt_forever();
            }
        };
    usb::configure_timestamp_frequency(Some(tsc_frequency));
    let storage = match unsafe { VirtioBlk::initialize(&mut frames, hhdm.offset) } {
        Ok(disk) => {
            ui.render_boot_log(&mut screen, "storage: virtio-blk online");
            StorageDisk::Virtio(disk)
        }
        Err(_) => match unsafe { AhciDisk::initialize(&mut page_table, &mut frames) } {
            Ok(disk) => {
                ui.render_boot_log(&mut screen, "storage: AHCI/SATA online");
                StorageDisk::Ahci(disk)
            }
            Err(_) => {
                ui.render_boot_log(&mut screen, "storage: no virtio-blk or AHCI disk");
                halt_forever();
            }
        },
    };
    let Ok(mut volume) = Volume::discover(storage) else {
        ui.render_boot_log(&mut screen, "storage: invalid partition table");
        halt_forever();
    };
    let blank_disk = volume_is_blank(&mut volume);
    let fs_result = if blank_disk {
        RedoxFs::format_disk(volume)
    } else {
        RedoxFs::open_disk(volume)
    };
    let Ok(mut fs) = fs_result else {
        ui.render_boot_log(&mut screen, "redoxfs: persistent disk mount failed");
        halt_forever();
    };
    let Some((desktop_image, catalog)) = install_and_load_system_programs(&mut fs) else {
        ui.render_boot_log(&mut screen, "redoxfs: system program installation failed");
        halt_forever();
    };
    ui.catalog = catalog;
    ui.render_boot_log(&mut screen, "redoxfs: desktop ELF and registry loaded");

    let mut context = KernelContext {
        frames,
        page_table,
        hhdm_offset: hhdm.offset,
        fs,
        serial,
        input: None,
        audio: None,
        timer,
        entropy,
        screen,
        ui,
        paging_verified: false,
        preemption_observed: false,
        preemption_smoke_id: None,
        processes: ProcessTable::new(),
        desktop: None,
        process_clients: Vec::new(),
        next_client_id: 1,
        launch_requested: None,
        launcher_toggle_pending: false,
        pending_console: [0; CONSOLE_BATCH_CAPACITY],
        pending_console_len: 0,
        pending_input: [0; INPUT_BATCH_CAPACITY],
        pending_input_len: 0,
        log_flush_deadline: 0,
    };
    context.paging_verified = verify_paging(&mut context);
    if !context.paging_verified {
        context
            .ui
            .render_boot_log(&mut context.screen, "paging: verification failed");
        halt_forever();
    }
    context
        .ui
        .render_boot_log(&mut context.screen, "paging: mappings verified");

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
    let input_status = context.ui.input_status;
    context
        .ui
        .render_boot_log(&mut context.screen, input_status);

    {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "audio: probing Intel HDA\r");
    }
    match unsafe { AudioDevice::initialize(&mut context.page_table, &mut context.frames) } {
        Ok(audio) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "audio: Intel HDA ready (44.1 kHz S16LE stereo)\r");
            context.audio = Some(audio);
            context
                .ui
                .render_boot_log(&mut context.screen, "audio: Intel HDA ready");
        }
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "audio: Intel HDA unavailable: {error:?}\r");
            context
                .ui
                .render_boot_log(&mut context.screen, "audio: Intel HDA unavailable");
        }
    }

    let cpu_state: &'static mut CpuPrivilegeState =
        unsafe { &mut *ptr::addr_of_mut!(CPU_PRIVILEGE_STATE) };
    if let Err(error) = unsafe {
        arch::initialize_cpu_with_external_interrupts(
            cpu_state,
            privilege_stack_tops(),
            arch::capture_syscall_and_yield,
            ExternalInterruptState::local_apic(context.timer.eoi_register_address()),
        )
    } {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "userspace: CPU initialization failed: {error:?}\r");
        context
            .ui
            .render_boot_log(&mut context.screen, "userspace: CPU initialization failed");
        halt_forever();
    }
    let user_copy_probe = [0x1000_u64, 0x0000_7000_0000_0000]
        .into_iter()
        .find(|address| {
            context
                .page_table
                .translate_addr(VirtAddr::new(*address))
                .is_none()
        })
        .unwrap_or_else(|| halt_forever());
    let mut probe_output = 0_u8;
    if unsafe {
        arch::copy_user_bytes(
            &mut probe_output,
            user_copy_probe as *const u8,
            core::mem::size_of::<u8>(),
        )
    } {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "userspace: user-copy fault probe unexpectedly succeeded\r"
        );
        halt_forever();
    }
    context
        .ui
        .render_boot_log(&mut context.screen, "userspace: SMAP copy fixup verified");
    context.ui.render_splash(&mut context.screen);

    let desktop_randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let mut process = match Process::from_elf_randomized(
        &desktop_image,
        &context.page_table,
        &mut context.frames,
        desktop_randomness,
    ) {
        Ok(process) => process,
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "desktop: ELF load failed: {error:?}\r");
            context
                .ui
                .render_failure(&mut context.screen, "Desktop ELF validation failed");
            halt_forever();
        }
    };
    let (desktop, process_channel) = match DesktopBroker::create(process.handles_mut()) {
        Ok(runtime) => runtime,
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "desktop: bootstrap channel failed: {error:?}\r");
            context
                .ui
                .render_failure(&mut context.screen, "Desktop channel creation failed");
            halt_forever();
        }
    };
    let random_source = process
        .handles_mut()
        .random_source_create()
        .unwrap_or_else(|_| halt_forever());
    process.set_start_arguments([
        u64::from(process_channel.raw()),
        context.screen.width() as u64,
        context.screen.height() as u64,
        u64::from(random_source.raw()),
    ]);
    context.desktop = Some(desktop);

    let process_id = match context.processes.insert(process) {
        Ok(process_id) => process_id,
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "desktop: process insertion failed: {error:?}\r");
            context
                .ui
                .render_failure(&mut context.screen, "Desktop process creation failed");
            halt_forever();
        }
    };
    {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "desktop: loaded {} from RedoxFS pid={}\r",
            DESKTOP_PATH,
            process_id.raw()
        );
    }

    if preemption_smoke_enabled() {
        let smoke_randomness = [
            context.entropy.next_u64(),
            context.entropy.next_u64(),
            context.entropy.next_u64(),
        ];
        let smoke = match Process::from_elf_randomized(
            PREEMPTION_SMOKE_ELF,
            &context.page_table,
            &mut context.frames,
            smoke_randomness,
        ) {
            Ok(process) => process,
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(sink, "scheduler: preemption smoke load failed: {error:?}\r");
                halt_forever();
            }
        };
        match context.processes.insert(smoke) {
            Ok(smoke_id) => {
                context.preemption_smoke_id = Some(smoke_id);
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "scheduler: preemption smoke started pid={}\r",
                    smoke_id.raw()
                );
            }
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "scheduler: preemption smoke insertion failed: {error:?}\r"
                );
                halt_forever();
            }
        }
    }

    let mut scheduler = Scheduler::<KernelContext, 8>::new();
    if scheduler.spawn(filesystem_task).is_err()
        || scheduler.spawn(console_task).is_err()
        || scheduler.spawn(accounting_task).is_err()
        || scheduler.spawn(log_flush_task).is_err()
        || scheduler.spawn(input_task).is_err()
        || scheduler.spawn(audio_task).is_err()
        || scheduler.spawn(desktop_task).is_err()
    {
        halt_forever();
    }
    if scheduler.spawn(process_task).is_err() {
        halt_forever();
    }

    loop {
        scheduler.run_round(&mut context);
        if !context.processes.has_runnable()
            && context.timer.arm_one_shot(KERNEL_IDLE_POLL_NS).is_ok()
        {
            let _ = arch::idle_until_interrupt();
            context.timer.disarm();
        } else {
            core::hint::spin_loop();
        }
    }
}

#[derive(Clone, Copy)]
struct ProcessClient {
    process_id: ProcessId,
    client_id: ClientId,
    may_launch: bool,
}

struct KernelContext {
    frames: UsableFrameAllocator<'static>,
    page_table: ActivePageTable,
    hhdm_offset: u64,
    fs: RedoxFs<Volume<StorageDisk>>,
    serial: Option<SerialPort>,
    input: Option<InputManager>,
    audio: Option<AudioDevice>,
    timer: LocalApicTimer,
    entropy: EntropyPool,
    screen: FramebufferWriter<'static>,
    ui: ValidationUi,
    paging_verified: bool,
    preemption_observed: bool,
    preemption_smoke_id: Option<ProcessId>,
    processes: ProcessTable,
    desktop: Option<DesktopBroker>,
    process_clients: Vec<ProcessClient>,
    next_client_id: u64,
    launch_requested: Option<usize>,
    launcher_toggle_pending: bool,
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
const KERNEL_IDLE_POLL_NS: u64 = 1_000_000;
const TEXT_BUFFER_CAPACITY: usize = 512;
const CURSOR_SIZE: usize = 19;

fn privilege_stack_tops() -> PrivilegeStackTops {
    unsafe fn top(stack: *mut PrivilegeStack) -> u64 {
        unsafe { stack.cast::<u8>().add(PRIVILEGE_STACK_SIZE) as usize as u64 }
    }

    unsafe {
        PrivilegeStackTops {
            rsp0: top(ptr::addr_of_mut!(RSP0_STACK)),
            double_fault: top(ptr::addr_of_mut!(DOUBLE_FAULT_STACK)),
            nmi: top(ptr::addr_of_mut!(NMI_STACK)),
            machine_check: top(ptr::addr_of_mut!(MACHINE_CHECK_STACK)),
            syscall: top(ptr::addr_of_mut!(SYSCALL_STACK)),
        }
    }
}

struct SerialDebugSink<'a> {
    serial: &'a mut Option<SerialPort>,
}

impl<'a> SerialDebugSink<'a> {
    fn new(serial: &'a mut Option<SerialPort>) -> Self {
        Self { serial }
    }
}

impl DebugSink for SerialDebugSink<'_> {
    fn write(&mut self, mut bytes: &[u8]) {
        let Some(serial) = self.serial.as_mut() else {
            return;
        };
        while !bytes.is_empty() {
            match serial.write_available(bytes) {
                Ok(0) | Err(_) => return,
                Ok(written) => bytes = &bytes[written..],
            }
        }
    }
}

impl fmt::Write for SerialDebugSink<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        DebugSink::write(self, text.as_bytes());
        Ok(())
    }
}
const UI_MARGIN: usize = 40;
const LAUNCHER_MAX_WIDTH: usize = 620;
const LAUNCHER_SEARCH_HEIGHT: usize = 58;
const LAUNCHER_ROW_HEIGHT: usize = 66;
const LAUNCHER_GAP: usize = 10;

const fn blend_channel(source: u8, background: u8, alpha: u8) -> u8 {
    let alpha = alpha as u32;
    ((source as u32 * alpha + background as u32 * (255 - alpha) + 127) / 255) as u8
}

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
    desktop_ready: bool,
    desktop_failed: bool,
    launcher_visible: bool,
    catalog: ProgramCatalog,
    launcher_backing: Vec<u32>,
    launcher_backing_geometry: Option<(usize, usize, usize, usize)>,
    cursor_backing: [u32; CURSOR_SIZE * CURSOR_SIZE],
    cursor_origin_x: usize,
    cursor_origin_y: usize,
    cursor_width: usize,
    cursor_height: usize,
    cursor_visible: bool,
    boot_log_line: usize,
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
            desktop_ready: false,
            desktop_failed: false,
            launcher_visible: false,
            catalog: ProgramCatalog::EMPTY,
            launcher_backing: Vec::new(),
            launcher_backing_geometry: None,
            cursor_backing: [0; CURSOR_SIZE * CURSOR_SIZE],
            cursor_origin_x: 0,
            cursor_origin_y: 0,
            cursor_width: 0,
            cursor_height: 0,
            cursor_visible: false,
            boot_log_line: 0,
        }
    }

    fn render_boot_log(&mut self, screen: &mut FramebufferWriter<'_>, message: &'static str) {
        let background = Rgb::new(8, 13, 22);
        let primary = Rgb::new(210, 222, 238);
        let accent = Rgb::new(110, 231, 183);
        if self.boot_log_line == 0 {
            screen.clear(background);
            screen.draw_text(UI_MARGIN, UI_MARGIN, 3, "GinkgoOS kernel", accent);
            screen.draw_text(
                UI_MARGIN,
                UI_MARGIN + 42,
                1,
                "Initializing hardware and protected execution...",
                primary,
            );
        }
        let y = UI_MARGIN + 82 + self.boot_log_line.saturating_mul(22);
        if y + 18 < self.height {
            screen.draw_text(UI_MARGIN, y, 2, message, primary);
            self.boot_log_line += 1;
        }
    }

    fn render_splash(&mut self, screen: &mut FramebufferWriter<'_>) {
        const SPLASH_WIDTH: usize = 256;
        const SPLASH_HEIGHT: usize = 256;
        const BACKGROUND: [u8; 3] = [14, 20, 32];

        screen.clear(Rgb::new(BACKGROUND[0], BACKGROUND[1], BACKGROUND[2]));
        let origin_x = self.width.saturating_sub(SPLASH_WIDTH) / 2;
        let origin_y = self.height.saturating_sub(SPLASH_HEIGHT) / 2;
        for (index, pixel) in GINKGO_SPLASH_RGBA.chunks_exact(4).enumerate() {
            let alpha = pixel[3];
            if alpha == 0 {
                continue;
            }
            let x = origin_x + index % SPLASH_WIDTH;
            let y = origin_y + index / SPLASH_WIDTH;
            let color = if alpha == u8::MAX {
                Rgb::new(pixel[0], pixel[1], pixel[2])
            } else {
                Rgb::new(
                    blend_channel(pixel[0], BACKGROUND[0], alpha),
                    blend_channel(pixel[1], BACKGROUND[1], alpha),
                    blend_channel(pixel[2], BACKGROUND[2], alpha),
                )
            };
            let _ = screen.write_rgb_pixel(x, y, color);
        }
        self.cursor_visible = false;
    }

    fn render_failure(&mut self, screen: &mut FramebufferWriter<'_>, message: &'static str) {
        let background = Rgb::new(28, 14, 20);
        let panel = Rgb::new(65, 28, 38);
        let primary = Rgb::new(255, 230, 235);
        let warning = Rgb::new(251, 113, 133);
        screen.clear(background);
        screen.fill_rect(
            UI_MARGIN,
            self.height / 3,
            self.width.saturating_sub(UI_MARGIN * 2),
            150,
            panel,
        );
        screen.draw_text(
            UI_MARGIN + 30,
            self.height / 3 + 28,
            3,
            "Boot failed",
            warning,
        );
        screen.draw_text(UI_MARGIN + 30, self.height / 3 + 82, 2, message, primary);
        self.cursor_visible = false;
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

    fn render_status(&mut self, _screen: &mut FramebufferWriter<'_>) {}

    fn render_text_range(
        &mut self,
        screen: &mut FramebufferWriter<'_>,
        _dirty_start: usize,
        _dirty_end: usize,
    ) {
        if !self.launcher_visible {
            return;
        }
        self.hide_cursor(screen);
        self.render_launcher_search(screen);
        self.show_cursor(screen);
    }

    fn launcher_geometry(&self) -> (usize, usize, usize, usize) {
        let width = LAUNCHER_MAX_WIDTH.min(self.width.saturating_sub(UI_MARGIN * 2));
        let rows = self.catalog.len.min(MAX_LAUNCHER_PROGRAMS);
        let result_height = rows.saturating_mul(LAUNCHER_ROW_HEIGHT);
        let height = LAUNCHER_SEARCH_HEIGHT.saturating_add(if rows == 0 {
            0
        } else {
            LAUNCHER_GAP + result_height
        });
        let x = self.width.saturating_sub(width) / 2;
        let y = self.height.saturating_sub(height) / 3;
        (x, y, width, height)
    }

    fn launcher_backing_geometry(&self) -> (usize, usize, usize, usize) {
        let (x, y, width, height) = self.launcher_geometry();
        let margin = 6;
        let left = x.saturating_sub(margin);
        let top = y.saturating_sub(margin);
        let right = x
            .saturating_add(width)
            .saturating_add(margin)
            .min(self.width);
        let bottom = y
            .saturating_add(height)
            .saturating_add(margin)
            .min(self.height);
        (
            left,
            top,
            right.saturating_sub(left),
            bottom.saturating_sub(top),
        )
    }

    fn capture_launcher_background(&mut self, screen: &FramebufferWriter<'_>) {
        let geometry = self.launcher_backing_geometry();
        let Some(pixel_count) = geometry.2.checked_mul(geometry.3) else {
            self.launcher_backing_geometry = None;
            return;
        };
        self.launcher_backing.clear();
        if self
            .launcher_backing
            .try_reserve_exact(pixel_count)
            .is_err()
        {
            self.launcher_backing_geometry = None;
            return;
        }
        for y in 0..geometry.3 {
            for x in 0..geometry.2 {
                self.launcher_backing.push(
                    screen
                        .read_raw_pixel(geometry.0 + x, geometry.1 + y)
                        .unwrap_or(0),
                );
            }
        }
        self.launcher_backing_geometry = Some(geometry);
    }

    fn restore_launcher_background(&mut self, screen: &mut FramebufferWriter<'_>) {
        let Some((left, top, width, height)) = self.launcher_backing_geometry.take() else {
            return;
        };
        if self.launcher_backing.len() != width.saturating_mul(height) {
            self.launcher_backing.clear();
            return;
        }
        for y in 0..height {
            for x in 0..width {
                screen.write_raw_pixel(left + x, top + y, self.launcher_backing[y * width + x]);
            }
        }
        self.launcher_backing.clear();
    }

    fn hide_launcher(&mut self, screen: &mut FramebufferWriter<'_>) {
        self.hide_cursor(screen);
        self.restore_launcher_background(screen);
        self.show_cursor(screen);
    }

    fn launcher_program_at(&self, x: usize, y: usize) -> Option<usize> {
        if !self.launcher_visible {
            return None;
        }
        let (launcher_x, launcher_y, width, _) = self.launcher_geometry();
        let results_y = launcher_y + LAUNCHER_SEARCH_HEIGHT + LAUNCHER_GAP;
        if x < launcher_x || x >= launcher_x.saturating_add(width) || y < results_y {
            return None;
        }
        let row = (y - results_y) / LAUNCHER_ROW_HEIGHT;
        (row < self.catalog.len).then_some(row)
    }

    fn render_launcher_search(&self, screen: &mut FramebufferWriter<'_>) {
        let (x, y, width, _) = self.launcher_geometry();
        let border = Rgb::new(232, 238, 247);
        let field = Rgb::new(31, 41, 61);
        let text_color = Rgb::new(232, 238, 247);
        let placeholder = Rgb::new(148, 163, 184);
        screen.fill_rect(x, y, width, LAUNCHER_SEARCH_HEIGHT, border);
        screen.fill_rect(
            x + 4,
            y + 4,
            width.saturating_sub(8),
            LAUNCHER_SEARCH_HEIGHT.saturating_sub(8),
            field,
        );
        let text = unsafe { core::str::from_utf8_unchecked(&self.text[..self.text_len]) };
        screen.draw_text(
            x + 22,
            y + 18,
            2,
            if self.text_len == 0 { "Search" } else { text },
            if self.text_len == 0 {
                placeholder
            } else {
                text_color
            },
        );

        let icon = Magnify::new(placeholder);
        let _ = Image::new(
            &icon,
            GraphicsPoint::new(
                i32::try_from(x + width.saturating_sub(38)).unwrap_or(i32::MAX),
                i32::try_from(y + 17).unwrap_or(i32::MAX),
            ),
        )
        .draw(screen);
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
        screen.clear(Rgb::new(14, 20, 32));
        self.launcher_backing.clear();
        self.launcher_backing_geometry = None;
        self.cursor_visible = false;
        self.show_cursor(screen);
    }

    fn render_content(&mut self, screen: &mut FramebufferWriter<'_>) {
        self.hide_cursor(screen);
        self.capture_launcher_background(screen);
        let (x, y, width, _) = self.launcher_geometry();

        if self.launcher_visible && !self.desktop_failed {
            self.render_launcher_search(screen);
            let rows = self.catalog.len.min(MAX_LAUNCHER_PROGRAMS);
            if rows != 0 {
                let result_y = y + LAUNCHER_SEARCH_HEIGHT + LAUNCHER_GAP;
                let border = Rgb::new(232, 238, 247);
                let panel = Rgb::new(31, 41, 61);
                let accent = Rgb::new(52, 211, 153);
                screen.fill_rect(x, result_y, width, rows * LAUNCHER_ROW_HEIGHT, border);
                for row in 0..rows {
                    let row_y = result_y + row * LAUNCHER_ROW_HEIGHT;
                    screen.fill_rect(
                        x + 4,
                        row_y + 4,
                        width.saturating_sub(8),
                        LAUNCHER_ROW_HEIGHT.saturating_sub(8),
                        panel,
                    );
                    if row != 0 {
                        screen.fill_rect(x, row_y, width, 3, border);
                    }
                    screen.fill_rect(x + 16, row_y + 14, 38, 38, accent);
                    screen.fill_rect(x + 20, row_y + 18, 30, 30, panel);
                    let icon = CubeOutline::new(accent);
                    let _ = Image::new(
                        &icon,
                        GraphicsPoint::new(
                            i32::try_from(x + 23).unwrap_or(i32::MAX),
                            i32::try_from(row_y + 21).unwrap_or(i32::MAX),
                        ),
                    )
                    .draw(screen);
                    if let Some(program) = self.catalog.get(row) {
                        screen.draw_text(x + 72, row_y + 16, 2, program.name(), border);
                        screen.draw_text(
                            x + 72,
                            row_y + 42,
                            1,
                            program.path(),
                            Rgb::new(148, 163, 184),
                        );
                    }
                }
            }
        }
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

fn process_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    let Some(process_id) = context.processes.next_id() else {
        return TaskPoll::Pending;
    };
    let Some(process) = context.processes.get_mut(process_id) else {
        return TaskPoll::Pending;
    };

    match process.state() {
        ProcessState::Ready => {
            unsafe { process.address_space().activate() };
            let mut user_context = *process.context();
            let started_ns = context.timer.clock().now_ns();
            if context
                .timer
                .arm_one_shot(process.limits().cpu_quantum_ns)
                .is_err()
            {
                process.mark_faulted(ProcessFault::new(ProcessFaultReason::InvalidUserContext, 0));
            } else {
                let exit = unsafe { arch::enter_user(&mut user_context) };
                context.timer.disarm();
                match exit {
                    Ok(KernelExit::YieldToKernel) => {
                        let mut sink = SerialDebugSink::new(&mut context.serial);
                        let outcome = syscall::dispatch(
                            process,
                            &mut user_context,
                            context.timer.clock().now_ns(),
                            &context.page_table,
                            &mut context.frames,
                            &mut context.fs,
                            &mut context.audio,
                            &mut context.entropy,
                            &mut sink,
                        );
                        debug_assert!(
                            matches!(outcome, SyscallOutcome::Yield | SyscallOutcome::Blocked)
                                || !process.is_runnable(),
                            "exit syscall must update process state"
                        );
                    }
                    Ok(KernelExit::Preempted) => {
                        process.record_preemption();
                        if !context.preemption_observed {
                            context.preemption_observed = true;
                            let mut sink = SerialDebugSink::new(&mut context.serial);
                            let _ = writeln!(sink, "scheduler: timer preemption verified\r");
                        }
                    }
                    Ok(KernelExit::Fault(fault)) => {
                        let reason = match fault.vector {
                            14 => ProcessFaultReason::PageFault,
                            13 => ProcessFaultReason::GeneralProtection,
                            6 => ProcessFaultReason::InvalidOpcode,
                            vector => {
                                ProcessFaultReason::Other(u16::try_from(vector).unwrap_or(u16::MAX))
                            }
                        };
                        process.mark_faulted(ProcessFault {
                            reason,
                            code: fault.error_code,
                            address: fault.fault_address,
                        });
                    }
                    Ok(KernelExit::ExitToKernel) => {
                        let mut sink = SerialDebugSink::new(&mut context.serial);
                        let _ = writeln!(
                            sink,
                            "userspace: assembly rejected context rip={:#x} rsp={:#x} rflags={:#x}\r",
                            user_context.rip,
                            user_context.rsp,
                            user_context.rflags
                        );
                        process.mark_faulted(ProcessFault::new(
                            ProcessFaultReason::InvalidUserContext,
                            1,
                        ));
                    }
                    Err(error) => {
                        let mut sink = SerialDebugSink::new(&mut context.serial);
                        let _ = writeln!(
                            sink,
                            "userspace: context validation failed: {error:?} rip={:#x} rsp={:#x} rflags={:#x}\r",
                            user_context.rip,
                            user_context.rsp,
                            user_context.rflags
                        );
                        process.mark_faulted(ProcessFault::new(
                            ProcessFaultReason::InvalidUserContext,
                            2,
                        ));
                    }
                }
            }
            *process.context_mut() = user_context;
            let elapsed_ns = context.timer.clock().now_ns().saturating_sub(started_ns);
            process.record_cpu_time(elapsed_ns);
        }
        ProcessState::Blocked => {
            let now_ns = context.timer.clock().now_ns();
            if syscall::poll_blocked(process, now_ns) == syscall::BlockedPoll::Complete {
                unsafe { process.address_space().activate() };
                let _ = syscall::complete_blocked(process);
            }
        }
        ProcessState::Exited(_) | ProcessState::Faulted(_) => {}
    }

    unsafe { context.page_table.activate() };
    let Some(final_state) = context.processes.get(process_id).map(Process::state) else {
        return TaskPoll::Pending;
    };
    if !final_state.is_terminal() {
        return TaskPoll::Pending;
    }

    let preemption_count = context
        .processes
        .get(process_id)
        .map(Process::preemption_count)
        .unwrap_or(0);
    let is_preemption_smoke = context.preemption_smoke_id == Some(process_id);
    let Some(process) = context.processes.take_for_retirement(process_id) else {
        return TaskPoll::Pending;
    };
    let retired = match process.retire() {
        Ok(retired) => retired,
        Err(_) => halt_forever(),
    };
    if let Some(index) = context
        .process_clients
        .iter()
        .position(|known| known.process_id == process_id)
    {
        let client_id = context.process_clients.swap_remove(index).client_id;
        let removed_windows = context
            .desktop
            .as_mut()
            .and_then(|desktop| desktop.cleanup_client(client_id).ok())
            .unwrap_or(0);
        if removed_windows != 0 {
            redraw_desktop(context);
        }
    }

    let mut sink = SerialDebugSink::new(&mut context.serial);
    match retired.final_state() {
        ProcessState::Exited(status) => {
            let _ = writeln!(
                sink,
                "userspace: pid={} exited status={}\r",
                process_id.raw(),
                status
            );
            if is_preemption_smoke {
                context.preemption_smoke_id = None;
                if status == 0 && preemption_count != 0 {
                    let _ = writeln!(
                        sink,
                        "scheduler: preemption smoke passed ({} preemptions)\r",
                        preemption_count
                    );
                } else {
                    let _ = writeln!(
                        sink,
                        "scheduler: preemption smoke failed status={} preemptions={}\r",
                        status, preemption_count
                    );
                    halt_forever();
                }
            }
        }
        ProcessState::Faulted(fault) => {
            let _ = writeln!(
                sink,
                "userspace: pid={} faulted reason={:?} code={} address={:?}\r",
                process_id.raw(),
                fault.reason,
                fault.code,
                fault.address
            );
        }
        ProcessState::Ready | ProcessState::Blocked => {
            unreachable!("live process reached retirement")
        }
    }
    TaskPoll::Pending
}

fn filesystem_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    const MESSAGE: &[u8] = b"GinkgoOS: paging, RedoxFS, devices, and scheduler online\r\n";

    if state.get(0) == Some(0) {
        let file = match context
            .fs
            .open("/system.log")
            .or_else(|_| context.fs.create("/system.log"))
        {
            Ok(file) => file,
            Err(_) => return TaskPoll::Complete,
        };
        if context.fs.truncate(file, 0).is_err() || context.fs.write(file, 0, MESSAGE).is_err() {
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
        if context
            .fs
            .open("/console")
            .or_else(|_| context.fs.create("/console"))
            .is_err()
        {
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

fn launch_program(
    context: &mut KernelContext,
    program: ProgramSummary,
    startup: Option<ginkgo_sysapi::Handle>,
) -> Result<(), ()> {
    context.processes.prepare_insert().map_err(|_| ())?;
    let image =
        read_trusted_system_file(&mut context.fs, program.path(), MAX_EXECUTABLE_BYTES).ok_or(())?;
    let randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let mut process =
        Process::from_elf_randomized(&image, &context.page_table, &mut context.frames, randomness)
            .map_err(|_| ())?;
    let client_id = ClientId::new(context.next_client_id).ok_or(())?;
    context.next_client_id = context.next_client_id.checked_add(1).ok_or(())?;
    context.process_clients.try_reserve(1).map_err(|_| ())?;
    let channel = context
        .desktop
        .as_mut()
        .ok_or(())?
        .connect_client(client_id, process.handles_mut())
        .map_err(|_| ())?;
    let setup = (|| {
        let filesystem = if program.filesystem {
            process
                .handles_mut()
                .filesystem_root_create()
                .map_err(|_| ())?
        } else {
            ginkgo_sysapi::Handle::INVALID
        };
        let startup = match startup {
            Some(startup) => context
                .desktop
                .as_mut()
                .ok_or(())?
                .move_startup_channel(startup, process.handles_mut())
                .map_err(|_| ())?,
            None => ginkgo_sysapi::Handle::INVALID,
        };
        let random_source = process
            .handles_mut()
            .random_source_create()
            .map_err(|_| ())?;
        process.set_start_arguments([
            u64::from(channel.raw()),
            u64::from(filesystem.raw()),
            u64::from(startup.raw()),
            u64::from(random_source.raw()),
        ]);
        context.processes.insert(process).map_err(|_| ())
    })();
    let process_id = match setup {
        Ok(process_id) => process_id,
        Err(()) => {
            if let Some(desktop) = context.desktop.as_mut() {
                let _ = desktop.cleanup_client(client_id);
            }
            return Err(());
        }
    };
    context.process_clients.push(ProcessClient {
        process_id,
        client_id,
        may_launch: program.process_launch,
    });
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(
        sink,
        "launcher: loaded {} pid={} client={}\r",
        program.path(),
        process_id.raw(),
        client_id.get()
    );
    Ok(())
}

fn launch_registered_program(context: &mut KernelContext, program_index: usize) -> Result<(), ()> {
    let program = context.ui.catalog.get(program_index).ok_or(())?;
    launch_program(context, program, None)
}

fn redraw_desktop(context: &mut KernelContext) {
    context.ui.hide_cursor(&mut context.screen);
    if let Some(desktop) = context.desktop.as_ref() {
        let _ = desktop.redraw(&mut context.screen);
    }
    if context.ui.launcher_visible {
        context.ui.render_content(&mut context.screen);
    } else {
        context.ui.show_cursor(&mut context.screen);
    }
}

fn desktop_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    if context.launcher_toggle_pending {
        let result = context
            .desktop
            .as_mut()
            .ok_or(DesktopBrokerError::Ipc(IpcError::PeerClosed))
            .and_then(DesktopBroker::send_toggle_launcher);
        match result {
            Ok(()) => context.launcher_toggle_pending = false,
            Err(DesktopBrokerError::Ipc(IpcError::ShouldWait)) => {}
            Err(_) => context.launcher_toggle_pending = false,
        }
    }

    let event = match context.desktop.as_mut().map(DesktopBroker::poll_desktop) {
        Some(Ok(event)) => event,
        Some(Err(DesktopBrokerError::Ipc(IpcError::PeerClosed))) | None => {
            context.ui.desktop_ready = false;
            context.ui.desktop_failed = true;
            context.ui.launcher_visible = false;
            context.ui.render(&mut context.screen);
            return TaskPoll::Complete;
        }
        Some(Err(_)) => return TaskPoll::Pending,
    };

    if let Some(event) = event {
        match event {
            DesktopRuntimeEvent::ServiceReady => {
                if !context.ui.desktop_ready {
                    context.ui.desktop_ready = true;
                    context.ui.desktop_failed = false;
                    context.ui.render(&mut context.screen);
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(sink, "desktop: protected Rust userland ready\r");
                }
            }
            DesktopRuntimeEvent::LauncherVisibility(visible) => {
                if context.ui.launcher_visible != visible {
                    context.ui.launcher_visible = visible;
                    if visible {
                        context.ui.render_content(&mut context.screen);
                    } else {
                        context.ui.hide_launcher(&mut context.screen);
                    }
                }
            }
            DesktopRuntimeEvent::LaunchRequested {
                requester,
                app_id,
                startup,
            } => {
                let authorized = context
                    .process_clients
                    .iter()
                    .any(|known| known.client_id == requester && known.may_launch);
                let program = authorized
                    .then(|| context.ui.catalog.find(&app_id))
                    .flatten();
                if program
                    .and_then(|program| launch_program(context, program, Some(startup)).ok())
                    .is_none()
                {
                    if let Some(desktop) = context.desktop.as_mut() {
                        desktop.close_startup_channel(startup);
                    }
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(
                        sink,
                        "launcher: rejected app={} requester={}\r",
                        app_id,
                        requester.get()
                    );
                }
            }
            DesktopRuntimeEvent::PlacementsChanged { .. }
            | DesktopRuntimeEvent::WindowDestroyed { .. } => redraw_desktop(context),
            DesktopRuntimeEvent::PresentationQueued { window_id, .. } => {
                context.ui.hide_cursor(&mut context.screen);
                if let Some(desktop) = context.desktop.as_mut() {
                    let _ = desktop.compose_window(&mut context.screen, window_id);
                }
                if context.ui.launcher_visible {
                    context.ui.render_content(&mut context.screen);
                } else {
                    context.ui.show_cursor(&mut context.screen);
                }
            }
            DesktopRuntimeEvent::SurfaceConfigured { .. }
            | DesktopRuntimeEvent::PresentationRejected { .. } => {}
        }
    }

    if let Some(program_index) = context.launch_requested.take() {
        if launch_registered_program(context, program_index).is_err() {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "launcher: failed to start program index={}\r",
                program_index
            );
        } else if context.ui.launcher_visible {
            request_launcher_toggle(context);
        }
    }
    TaskPoll::Pending
}

fn request_launcher_toggle(context: &mut KernelContext) {
    if context.launcher_toggle_pending {
        context.launcher_toggle_pending = false;
        return;
    }
    let result = context
        .desktop
        .as_mut()
        .ok_or(DesktopBrokerError::Ipc(IpcError::PeerClosed))
        .and_then(DesktopBroker::send_toggle_launcher);
    if matches!(result, Err(DesktopBrokerError::Ipc(IpcError::ShouldWait))) {
        context.launcher_toggle_pending = true;
    }
}

fn audio_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    let result = match context.audio.as_mut() {
        Some(audio) => audio.poll(),
        None => return TaskPoll::Pending,
    };
    if let Err(error) = result {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "audio: playback stopped: {error:?}\r");
        context.audio = None;
    }
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
            context.ui.render_status(&mut context.screen);
            return TaskPoll::Complete;
        }
    };
    if let Some(code) = input.first_transfer_error() {
        context.ui.input_available = false;
        context.ui.completion_code = Some(code);
        context.ui.input_status = "USB HID: interrupt endpoint stopped with a transfer error";
        context.ui.render_status(&mut context.screen);
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

fn update_modifier_bits(state: &mut TaskState, word: usize, left: bool, pressed: bool) {
    let bit = if left { 1 } else { 2 };
    let current = state.get(word).unwrap_or(0);
    state.set(
        word,
        if pressed {
            current | bit
        } else {
            current & !bit
        },
    );
}

fn current_modifiers(state: &TaskState) -> Modifiers {
    Modifiers {
        shift: state.get(1).unwrap_or(0) != 0,
        control: state.get(4).unwrap_or(0) != 0,
        alt: state.get(5).unwrap_or(0) != 0,
        logo: state.get(3).unwrap_or(0) != 0,
        caps_lock: state.get(2).unwrap_or(0) != 0,
        num_lock: state.get(6).unwrap_or(0) != 0,
    }
}

fn pointer_button(button: u16) -> Option<PointerButton> {
    Some(match button {
        1 => PointerButton::Primary,
        2 => PointerButton::Secondary,
        3 => PointerButton::Middle,
        other => PointerButton::Other(other),
    })
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
                update_modifier_bits(state, 1, usage == 0xe1, pressed);
            } else if matches!(usage, 0xe0 | 0xe4) {
                update_modifier_bits(state, 4, usage == 0xe0, pressed);
            } else if matches!(usage, 0xe2 | 0xe6) {
                update_modifier_bits(state, 5, usage == 0xe2, pressed);
            } else if matches!(usage, 0xe3 | 0xe7) {
                update_modifier_bits(state, 3, usage == 0xe3, pressed);
            } else if usage == 0x39 && pressed {
                state.set(2, state.get(2).unwrap_or(0) ^ 1);
            } else if usage == 0x53 && pressed {
                state.set(6, state.get(6).unwrap_or(0) ^ 1);
            }

            let logo = state.get(3).unwrap_or(0) != 0;
            if pressed && usage == 0x11 && logo {
                request_launcher_toggle(context);
            } else if context.ui.launcher_visible {
                if pressed && usage == 0x28 && context.ui.catalog.len != 0 {
                    context.launch_requested = Some(0);
                } else if pressed {
                    let modifiers = current_modifiers(state);
                    if let Some(byte) = keyboard_ascii(usage, modifiers.shift, modifiers.caps_lock)
                    {
                        text_dirty = context.ui.push_byte(byte);
                    }
                }
            } else if let Some(desktop) = context.desktop.as_mut() {
                let _ = desktop.send_keyboard_input(KeyboardEvent {
                    usage,
                    state: if pressed {
                        ButtonState::Pressed
                    } else {
                        ButtonState::Released
                    },
                    repeat: false,
                    modifiers: current_modifiers(state),
                });
            }
        }
        InputEvent::Axis {
            axis,
            value,
            relative,
            ..
        } if application == Some(ApplicationKind::Mouse) => {
            if axis == Axis::Wheel {
                if !context.ui.launcher_visible {
                    if let Some(desktop) = context.desktop.as_mut() {
                        let _ = desktop.send_pointer_input(
                            WindowPoint::new(context.ui.mouse_x as i32, context.ui.mouse_y as i32),
                            PointerEventKind::Scrolled {
                                delta: WindowPoint::new(0, value),
                            },
                        );
                    }
                }
            } else if context.ui.move_mouse(axis, value, relative) && !context.ui.launcher_visible {
                if let Some(desktop) = context.desktop.as_mut() {
                    let _ = desktop.send_pointer_input(
                        WindowPoint::new(context.ui.mouse_x as i32, context.ui.mouse_y as i32),
                        PointerEventKind::Moved,
                    );
                }
            }
        }
        InputEvent::Button {
            button, pressed, ..
        } if application == Some(ApplicationKind::Mouse) => {
            if button == 1 {
                let _ = context.ui.set_mouse_button(pressed);
            }
            if context.ui.launcher_visible {
                if button == 1 && pressed {
                    context.launch_requested = context
                        .ui
                        .launcher_program_at(context.ui.mouse_x, context.ui.mouse_y);
                }
            } else if let Some(pointer_button) = pointer_button(button) {
                if let Some(desktop) = context.desktop.as_mut() {
                    let _ = desktop.send_pointer_input(
                        WindowPoint::new(context.ui.mouse_x as i32, context.ui.mouse_y as i32),
                        PointerEventKind::Button {
                            button: pointer_button,
                            state: if pressed {
                                ButtonState::Pressed
                            } else {
                                ButtonState::Released
                            },
                        },
                    );
                }
            }
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

fn append_log<D: Disk>(fs: &mut RedoxFs<D>, path: &str, bytes: &[u8]) -> bool {
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
