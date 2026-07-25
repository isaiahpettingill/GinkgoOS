#![no_std]
#![no_main]

mod crt;

mod framebuffer;
mod heap;

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Write as _},
    mem::MaybeUninit,
    panic::PanicInfo,
    pin::Pin,
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
use ginkgo_filesystem::{FsError, NodeKind, NodeMetadata, RedoxFs, RenameMode};
use ginkgo_hid::{ApplicationKind, Axis, InputEvent, AXIS_MAX, AXIS_MIN};
use ginkgo_ipc::{
    shared_memory_backing_stats, IpcError, SchedulingAuthorityControl, SystemPowerControl,
};
#[cfg(ginkgo_ahci_smoke)]
use ginkgo_kernel::ahci::AhciDisk;
#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
use ginkgo_kernel::async_block::{
    run_device_worker, AsyncBlockDevice, AsyncBlockQueue, BlockBuffer, BlockOperation,
    BlockPriority, BlockRequestId, DeviceWorkerBudget, DmaSegment, QueueConfig, RequestOutcome,
    RequestSpec,
};
#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
use ginkgo_kernel::memory::{DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE};
#[cfg(ginkgo_memory_policy_smoke)]
use ginkgo_kernel::paging::address_space::{
    UserMappingBacking, UserPageMapping, UserPagePermissions,
};
#[cfg(ginkgo_virtio_blk_smoke)]
use ginkgo_kernel::virtio_blk::VirtioBlk;
use ginkgo_kernel::{
    arch::{self, CpuPrivilegeState, ExternalInterruptState, KernelExit, PrivilegeStackTops},
    audio::AudioDevice,
    block::{BlockDevice, Volume, SECTOR_SIZE},
    desktop_runtime::{DesktopBroker, DesktopBrokerError, DesktopRuntimeEvent},
    entropy::EntropyPool,
    fiber::FixedStack,
    fs_executor::{
        FsDirectory, FsExecutor, FsExecutorError, FsJob, FsJobId, FsResult, PollStep,
        FS_JOB_CAPACITY,
    },
    input::{DeviceInputEvent, InputManager},
    io::SerialPort,
    limine::{
        self, BaseRevision, FramebufferRequest, HhdmRequest, MemoryMapRequest, RsdpRequest,
        StackSizeRequest, TscFrequencyRequest,
    },
    local_apic::LocalApicTimer,
    memory::{UsableFrameAllocator, VirtAddr, VirtPage},
    paging::{ActivePageTable, PageTableFlags},
    power::AcpiPower,
    process::{
        BlockedKind, Process, ProcessFault, ProcessFaultReason, ProcessId, ProcessState,
        ProcessTable, ThreadRef, ThreadState, UserPageFaultResolution, PROCESS_TABLE_CAPACITY,
        USER_SCHEDULER_CAPACITY,
    },
    request::{RequestAction, RequestCancelReason, RequestWorkerBudget},
    request_broker::{BrokerCompletion, PreparedRequestBuffer, RequestBroker},
    shared_memory::{SharedFrameArena, SharedMemoryFactory},
    storage::{StorageDisk, StorageDriver},
    syscall::{self, DebugSink, SyscallOutcome},
    task::{Scheduler, TaskPoll, TaskState},
    thread_scheduler::{
        Authority as SchedulerAuthority, RunDisposition, SchedulingClass, ThreadScheduler,
        ThreadState as SchedulerThreadState, DEFAULT_MAX_DONATION_DEPTH, DEFAULT_MAX_DONATION_NS,
    },
    trust::TrustedManifest,
    usb::{self, UsbError},
    wait_runtime::{WaitKind, WaitRuntime, WakeCause},
    writeback::WriteBackDisk,
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
#[link_section = ".limine_requests"]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[link_section = ".limine_requests_end"]
static REQUESTS_END: [u64; 2] = limine::REQUESTS_END_MARKER;

static DESKTOP_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-desktop.elf"));
static MINIMAL_CLIENT_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-minimal-client.elf"));
static FILE_NAVIGATOR_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-file-navigator.elf"));
static TEXT_EDITOR_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-text-editor.elf"));
static TERMINAL_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-terminal.elf"));
static PROGRAM_REGISTRY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/programs.gkr"));
static TRUST_MANIFEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.manifest"));
static TRUST_SIGNATURE: &[u8; 64] =
    include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.signature"));
static TRUST_PUBLIC_KEY: &[u8; 32] =
    include_bytes!(concat!(env!("OUT_DIR"), "/system-trust.public"));
static PREEMPTION_SMOKE_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-preemption-smoke.elf"));
static FRAME_RECLAIM_EXIT_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-frame-reclaim-exit.elf"));
static FRAME_RECLAIM_FAULT_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-frame-reclaim-fault.elf"));
static PROCESS_CAPABILITY_SMOKE_ELF: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ginkgo-process-capability-smoke.elf"
));
static PROCESS_CAPABILITY_MALFORMED_ELF: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ginkgo-process-capability-malformed.elf"
));
static REQUEST_SMOKE_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-request-smoke.elf"));
static THREAD_SMOKE_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-thread-smoke.elf"));
#[cfg(ginkgo_memory_policy_smoke)]
static MEMORY_POLICY_SUCCESS_ELF: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ginkgo-memory-policy-success.elf"
));
#[cfg(ginkgo_memory_policy_smoke)]
static MEMORY_POLICY_GUARD_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-memory-policy-guard.elf"));
#[cfg(ginkgo_memory_policy_smoke)]
static MEMORY_POLICY_PROTECT_FAULT_ELF: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ginkgo-memory-policy-protect-fault.elf"
));
#[cfg(ginkgo_memory_policy_smoke)]
static MEMORY_POLICY_OOM_ELF: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-memory-policy-oom.elf"));
#[cfg(ginkgo_memory_policy_smoke)]
static MEMORY_POLICY_WITNESS_ELF: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ginkgo-memory-policy-witness.elf"
));
static GINKGO_SPLASH_RGBA: &[u8; 256 * 256 * 4] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ginkgo-splash.rgba"));
fn preemption_smoke_enabled() -> bool {
    option_env!("GINKGO_PREEMPTION_SMOKE") == Some("1")
}

fn thread_smoke_enabled() -> bool {
    option_env!("GINKGO_THREAD_SMOKE") == Some("1")
}

fn frame_reclaim_stress_enabled() -> bool {
    option_env!("GINKGO_FRAME_RECLAIM_STRESS") == Some("1")
}

fn filesystem_hierarchy_smoke_enabled() -> bool {
    option_env!("GINKGO_FILESYSTEM_HIERARCHY_SMOKE") == Some("1")
}

fn process_capability_smoke_enabled() -> bool {
    option_env!("GINKGO_PROCESS_CAPABILITY_SMOKE") == Some("1")
}

fn request_smoke_enabled() -> bool {
    option_env!("GINKGO_REQUEST_SMOKE") == Some("1")
}

#[cfg(ginkgo_virtio_blk_smoke)]
fn virtio_blk_smoke_enabled() -> bool {
    true
}

#[cfg(ginkgo_ahci_smoke)]
fn ahci_smoke_enabled() -> bool {
    true
}

fn text_editor_smoke_enabled() -> bool {
    option_env!("GINKGO_TEXT_EDITOR_SMOKE") == Some("1")
}

fn power_smoke_mode() -> Option<&'static str> {
    option_env!("GINKGO_POWER_SMOKE")
}

const SYSTEM_DIRECTORY: &str = "system";
const USER_DIRECTORY: &str = "user";
const DESKTOP_PATH: &str = "/system/desktop.elf";
const MINIMAL_CLIENT_PATH: &str = "/system/minimal-client.elf";
const FILE_NAVIGATOR_PATH: &str = "/system/file-navigator.elf";
const TEXT_EDITOR_PATH: &str = "/system/text-editor.elf";
const TERMINAL_PATH: &str = "/system/terminal.elf";
const PROGRAM_REGISTRY_PATH: &str = "/system/programs.gkr";
const PROCESS_CAPABILITY_SMOKE_PATH: &str = "/system/process-capability-smoke.elf";
const PROCESS_CAPABILITY_MALFORMED_PATH: &str = "/system/process-capability-malformed.elf";
const POWER_SMOKE_PERSIST_PATH: &str = "/power-smoke-persisted";
const POWER_SMOKE_PERSIST_CONTENT: &[u8] = b"sync-before-poweroff\n";
const POWER_SMOKE_REBOOT_PATH: &str = "/power-smoke-rebooted";
const MAX_LAUNCHER_PROGRAMS: usize = 6;
const FRAME_RECLAIM_STRESS_CYCLES: u32 = 512;

#[derive(Clone, Copy)]
struct FrameReclaimBaseline {
    live_frames: u64,
    shared_live_objects: usize,
    shared_logical_bytes: usize,
    shared_mapped_bytes: usize,
    shared_arena_owned_frames: usize,
    shared_arena_free_frames: usize,
}

struct FrameReclaimStress {
    current: Option<ProcessId>,
    pending_completion: Option<(ProcessId, ProcessState)>,
    completed: u32,
    reuse_verified: u32,
    baseline: Option<FrameReclaimBaseline>,
}

#[cfg(ginkgo_memory_policy_smoke)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryPolicyPhase {
    Success,
    Guard,
    ProtectFault,
    Oom,
    Witness,
}

#[cfg(ginkgo_memory_policy_smoke)]
impl MemoryPolicyPhase {
    const fn name(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Guard => "Guard",
            Self::ProtectFault => "ProtectFault",
            Self::Oom => "Oom",
            Self::Witness => "Witness",
        }
    }
}

#[cfg(ginkgo_memory_policy_smoke)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryPolicyCase {
    Low,
    Normal,
    High,
}

#[cfg(ginkgo_memory_policy_smoke)]
impl MemoryPolicyCase {
    const fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

#[cfg(ginkgo_memory_policy_smoke)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryPolicySuccessStage {
    SharedMapped,
    SharedUnmapped,
    AnonymousProtected,
    AnonymousUnmapped,
    Complete,
}

#[cfg(ginkgo_memory_policy_smoke)]
struct MemoryPolicySmoke {
    current: Option<ProcessId>,
    phase: MemoryPolicyPhase,
    pending_completion: Option<(ProcessId, MemoryPolicyPhase)>,
    baseline: FrameReclaimBaseline,
    case: MemoryPolicyCase,
    mapping_base: u64,
    expected_fault_address: u64,
    success_stage: MemoryPolicySuccessStage,
    shared_frame: Option<u64>,
    anonymous_frame: Option<u64>,
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
    flags: EntryFlags,
}

impl ProgramSummary {
    const EMPTY: Self = Self {
        app_id: [0; 64],
        app_id_len: 0,
        name: [0; 48],
        name_len: 0,
        path: [0; 64],
        path_len: 0,
        flags: EntryFlags::EMPTY,
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

#[derive(Clone, Copy)]
enum RegistryLaunchAuthority {
    None,
    OpenDocument,
    AnyRegistered,
}

impl RegistryLaunchAuthority {
    fn for_program(program: ProgramSummary) -> Self {
        if program.flags.contains(EntryFlags::PROCESS_LAUNCH) {
            Self::AnyRegistered
        } else if program.flags.contains(EntryFlags::OPEN_DOCUMENT) {
            Self::OpenDocument
        } else {
            Self::None
        }
    }

    fn allows(self, target_app_id: &str) -> bool {
        match self {
            Self::None => false,
            Self::OpenDocument => target_app_id == "text-editor",
            Self::AnyRegistered => true,
        }
    }
}

fn install_and_load_system_programs<D: Disk>(
    fs: &mut RedoxFs<D>,
    executable_source_limit: usize,
) -> Result<(Vec<u8>, ProgramCatalog), &'static str> {
    let system = ensure_system_directory(fs).ok_or("create system directory")?;
    migrate_legacy_system_files(fs, system).ok_or("migrate legacy system files")?;
    recover_system_installation_space(fs).map_err(|_| "recover system installation space")?;
    ensure_user_directory(fs).ok_or("create user directory")?;
    install_system_file(fs, DESKTOP_PATH, DESKTOP_ELF).map_err(|_| "install desktop")?;
    install_system_file(fs, MINIMAL_CLIENT_PATH, MINIMAL_CLIENT_ELF)
        .map_err(|_| "install minimal client")?;
    install_system_file(fs, FILE_NAVIGATOR_PATH, FILE_NAVIGATOR_ELF)
        .map_err(|_| "install file navigator")?;
    install_system_file(fs, TEXT_EDITOR_PATH, TEXT_EDITOR_ELF)
        .map_err(|_| "install text editor")?;
    install_system_file(fs, TERMINAL_PATH, TERMINAL_ELF).map_err(|_| "install terminal")?;
    install_system_file(fs, PROGRAM_REGISTRY_PATH, PROGRAM_REGISTRY)
        .map_err(|_| "install program registry")?;
    if process_capability_smoke_enabled() {
        install_system_file(
            fs,
            PROCESS_CAPABILITY_SMOKE_PATH,
            PROCESS_CAPABILITY_SMOKE_ELF,
        )
        .map_err(|_| "install process-capability smoke")?;
        install_system_file(
            fs,
            PROCESS_CAPABILITY_MALFORMED_PATH,
            PROCESS_CAPABILITY_MALFORMED_ELF,
        )
        .map_err(|_| "install malformed-process smoke")?;
    }

    fs.sync().map_err(|_| "sync system installation")?;

    let registry_bytes = read_trusted_system_file(fs, PROGRAM_REGISTRY_PATH, 16 * 1024)
        .ok_or("verify program registry")?;
    let registry = Registry::parse(&registry_bytes).map_err(|_| "parse program registry")?;
    let desktop = registry
        .entries()
        .find(|entry| entry.app_id == "desktop")
        .ok_or("find desktop registry entry")?;
    if desktop.executable_path != DESKTOP_PATH || desktop.is_visible() {
        return Err("validate desktop registry entry");
    }

    let mut catalog = ProgramCatalog::EMPTY;
    for entry in registry.visible_entries().take(MAX_LAUNCHER_PROGRAMS) {
        let slot = &mut catalog.programs[catalog.len];
        slot.app_id_len =
            copy_program_string(&mut slot.app_id, entry.app_id).ok_or("copy application id")?;
        slot.name_len = copy_program_string(&mut slot.name, entry.display_name)
            .ok_or("copy application name")?;
        slot.path_len = copy_program_string(&mut slot.path, entry.executable_path)
            .ok_or("copy executable path")?;
        slot.flags = entry.flags;
        catalog.len += 1;
    }

    let desktop_image =
        read_trusted_system_file(fs, desktop.executable_path, executable_source_limit)
            .ok_or("verify desktop executable")?;
    Ok((desktop_image, catalog))
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

fn ensure_system_directory<D: Disk>(
    fs: &mut RedoxFs<D>,
) -> Option<ginkgo_filesystem::DirectoryHandle> {
    ensure_top_level_directory(fs, SYSTEM_DIRECTORY)
}

fn ensure_user_directory<D: Disk>(
    fs: &mut RedoxFs<D>,
) -> Option<ginkgo_filesystem::DirectoryHandle> {
    ensure_top_level_directory(fs, USER_DIRECTORY)
}

fn ensure_top_level_directory<D: Disk>(
    fs: &mut RedoxFs<D>,
    name: &str,
) -> Option<ginkgo_filesystem::DirectoryHandle> {
    let root = fs.root_directory().ok()?;
    match fs.open_directory_at(root, name) {
        Ok(directory) => Some(directory),
        Err(FsError::NotFound) => fs.create_directory_at(root, name).ok(),
        Err(_) => None,
    }
}

fn migrate_legacy_system_files<D: Disk>(
    fs: &mut RedoxFs<D>,
    system: ginkgo_filesystem::DirectoryHandle,
) -> Option<()> {
    let root = fs.root_directory().ok()?;
    for name in [
        "desktop.elf",
        "minimal-client.elf",
        "file-navigator.elf",
        "text-editor.elf",
        "terminal.elf",
        "programs.gkr",
    ] {
        let Ok(legacy) = fs.open_file_at(root, name) else {
            continue;
        };
        if fs.open_file_at(system, name).is_ok() {
            fs.remove(legacy).ok()?;
        } else {
            fs.rename_at(root, name, system, name, RenameMode::NoReplace)
                .ok()?;
        }
    }
    Some(())
}

const MIN_SYSTEM_INSTALLATION_WORKSPACE: u64 = 512 * 1024;

fn recover_system_installation_space<D: Disk>(fs: &mut RedoxFs<D>) -> Result<(), FsError> {
    if fs.filesystem_info()?.free_bytes.unwrap_or(u64::MAX) >= MIN_SYSTEM_INSTALLATION_WORKSPACE {
        return Ok(());
    }

    let artifacts = [
        (DESKTOP_PATH, DESKTOP_ELF),
        (MINIMAL_CLIENT_PATH, MINIMAL_CLIENT_ELF),
        (FILE_NAVIGATOR_PATH, FILE_NAVIGATOR_ELF),
        (TEXT_EDITOR_PATH, TEXT_EDITOR_ELF),
        (TERMINAL_PATH, TERMINAL_ELF),
        (PROGRAM_REGISTRY_PATH, PROGRAM_REGISTRY),
    ];
    let mut replacement_needed = false;
    let mut largest = None;
    for (path, expected) in artifacts {
        let Ok(file) = fs.open(path) else {
            replacement_needed = true;
            continue;
        };
        replacement_needed |= !system_file_matches(fs, file, expected)?;
        let length = fs.stat(file)?.len;
        if length != 0 && largest.is_none_or(|(_, largest_length)| length > largest_length) {
            largest = Some((file, length));
        }
    }

    if replacement_needed {
        let (file, _) = largest.ok_or(FsError::NoSpace)?;
        fs.truncate(file, 0)?;
        fs.sync()?;
    }
    Ok(())
}

fn system_file_matches<D: Disk>(
    fs: &mut RedoxFs<D>,
    file: ginkgo_filesystem::FileHandle,
    expected: &[u8],
) -> Result<bool, FsError> {
    if fs.stat(file)?.len != expected.len() as u64 {
        return Ok(false);
    }

    let mut offset = 0;
    let mut buffer = [0_u8; 4096];
    while offset < expected.len() {
        let count = (expected.len() - offset).min(buffer.len());
        if fs.read(file, offset as u64, &mut buffer[..count])? != count
            || buffer[..count] != expected[offset..offset + count]
        {
            return Ok(false);
        }
        offset += count;
    }
    Ok(true)
}

fn install_system_file<D: Disk>(
    fs: &mut RedoxFs<D>,
    path: &str,
    bytes: &[u8],
) -> Result<(), FsError> {
    let file = match fs.open(path) {
        Ok(file) => {
            if system_file_matches(fs, file, bytes)? {
                return Ok(());
            }
            fs.truncate(file, 0)?;
            fs.sync()?;
            file
        }
        Err(FsError::NotFound) => fs.create(path)?,
        Err(error) => return Err(error),
    };

    if fs.write(file, 0, bytes)? != bytes.len() {
        return Err(FsError::Io);
    }
    fs.sync()
}

const FILESYSTEM_SMOKE_INITIAL_CONTENT: &[u8] = b"GinkgoOS hierarchy smoke: moved\n";
const FILESYSTEM_SMOKE_PERSISTED_CONTENT: &[u8] = b"GinkgoOS hierarchy smoke: persisted\n";
const FILESYSTEM_SMOKE_REPLACED_CONTENT: &[u8] = b"GinkgoOS hierarchy smoke: replaced\n";
const FILESYSTEM_SMOKE_METADATA_LEN: usize = 54;

fn filesystem_smoke_write<D: Disk>(
    fs: &mut RedoxFs<D>,
    file: ginkgo_filesystem::FileHandle,
    bytes: &[u8],
) -> Result<(), &'static str> {
    if fs.write(file, 0, bytes).map_err(|_| "write failed")? != bytes.len() {
        return Err("short write");
    }
    Ok(())
}

fn filesystem_smoke_read<D: Disk>(
    fs: &mut RedoxFs<D>,
    file: ginkgo_filesystem::FileHandle,
    expected: &[u8],
) -> Result<(), &'static str> {
    let mut bytes = [0_u8; 64];
    let output = bytes
        .get_mut(..expected.len())
        .ok_or("smoke content exceeds fixed buffer")?;
    if fs.read(file, 0, output).map_err(|_| "read failed")? != expected.len() || output != expected
    {
        return Err("content mismatch");
    }
    Ok(())
}

fn filesystem_smoke_metadata_bytes(metadata: NodeMetadata) -> [u8; FILESYSTEM_SMOKE_METADATA_LEN] {
    let mut bytes = [0_u8; FILESYSTEM_SMOKE_METADATA_LEN];
    bytes[0..8].copy_from_slice(&metadata.identity.to_le_bytes());
    bytes[8..16].copy_from_slice(&metadata.size.to_le_bytes());
    bytes[16..18].copy_from_slice(&metadata.mode.to_le_bytes());
    bytes[18..22].copy_from_slice(&metadata.policy.to_le_bytes());
    bytes[22..26].copy_from_slice(&metadata.uid.to_le_bytes());
    bytes[26..30].copy_from_slice(&metadata.gid.to_le_bytes());
    bytes[30..38].copy_from_slice(&metadata.ctime.seconds.to_le_bytes());
    bytes[38..42].copy_from_slice(&metadata.ctime.nanoseconds.to_le_bytes());
    bytes[42..50].copy_from_slice(&metadata.mtime.seconds.to_le_bytes());
    bytes[50..54].copy_from_slice(&metadata.mtime.nanoseconds.to_le_bytes());
    bytes
}

fn validate_filesystem_smoke_metadata(
    metadata: NodeMetadata,
    expected_size: usize,
) -> Result<(), &'static str> {
    if metadata.kind != NodeKind::File
        || metadata.size != expected_size as u64
        || metadata.identity == 0
        || metadata.mode & 0o777 != 0o644
        || metadata.policy != 0
        || metadata.uid != 0
        || metadata.gid != 0
        || metadata.ctime.nanoseconds >= 1_000_000_000
        || metadata.mtime.nanoseconds >= 1_000_000_000
    {
        return Err("invalid file metadata");
    }
    Ok(())
}

fn initialize_filesystem_hierarchy_smoke<D: Disk>(
    fs: &mut RedoxFs<D>,
    root: ginkgo_filesystem::DirectoryHandle,
) -> Result<(), &'static str> {
    let suite = fs
        .create_directory_at(root, "filesystem-smoke")
        .map_err(|_| "create suite directory failed")?;
    let source = fs
        .create_directory_at(suite, "source")
        .map_err(|_| "create source directory failed")?;
    let destination = fs
        .create_directory_at(suite, "destination")
        .map_err(|_| "create destination directory failed")?;
    let archive = fs
        .create_directory_at(suite, "archive")
        .map_err(|_| "create archive directory failed")?;
    let sibling = fs
        .create_file_at(root, "filesystem-smoke-sibling")
        .map_err(|_| "create scoped sibling failed")?;
    filesystem_smoke_write(fs, sibling, b"outside delegated directory\n")?;

    let moving = fs
        .create_file_at(source, "payload")
        .map_err(|_| "create moving file failed")?;
    filesystem_smoke_write(fs, moving, FILESYSTEM_SMOKE_INITIAL_CONTENT)?;
    let occupied = fs
        .create_file_at(destination, "current")
        .map_err(|_| "create occupied destination failed")?;
    filesystem_smoke_write(fs, occupied, b"old destination\n")?;

    if fs.rename_at(
        source,
        "payload",
        destination,
        "current",
        RenameMode::NoReplace,
    ) != Err(FsError::AlreadyExists)
    {
        return Err("no-replace did not preserve an occupied destination");
    }
    filesystem_smoke_read(fs, moving, FILESYSTEM_SMOKE_INITIAL_CONTENT)?;
    filesystem_smoke_read(fs, occupied, b"old destination\n")?;
    fs.rename_at(source, "payload", archive, "moved", RenameMode::NoReplace)
        .map_err(|_| "cross-directory move failed")?;

    let replacement = fs
        .create_file_at(destination, "replacement")
        .map_err(|_| "create replacement failed")?;
    filesystem_smoke_write(fs, replacement, FILESYSTEM_SMOKE_PERSISTED_CONTENT)?;
    fs.atomic_replace_file_at(destination, "replacement", destination, "current")
        .map_err(|_| "initial atomic replacement failed")?;
    let mut stale_probe = [0_u8; 1];
    if fs.read(occupied, 0, &mut stale_probe) != Err(FsError::InvalidHandle) {
        return Err("initial replaced handle remained valid");
    }

    let current = fs
        .open_file_at(destination, "current")
        .map_err(|_| "open initialized current file failed")?;
    filesystem_smoke_read(fs, current, FILESYSTEM_SMOKE_PERSISTED_CONTENT)?;
    let metadata = fs
        .file_metadata(current)
        .map_err(|_| "read initialized metadata failed")?;
    validate_filesystem_smoke_metadata(metadata, FILESYSTEM_SMOKE_PERSISTED_CONTENT.len())?;
    let metadata_file = fs
        .create_file_at(suite, "metadata")
        .map_err(|_| "create metadata record failed")?;
    filesystem_smoke_write(
        fs,
        metadata_file,
        &filesystem_smoke_metadata_bytes(metadata),
    )?;
    fs.sync().map_err(|_| "initial sync failed")
}

fn verify_filesystem_hierarchy_smoke<D: Disk>(
    fs: &mut RedoxFs<D>,
    root: ginkgo_filesystem::DirectoryHandle,
    suite: ginkgo_filesystem::DirectoryHandle,
) -> Result<(), &'static str> {
    let source = fs
        .open_directory_at(suite, "source")
        .map_err(|_| "source directory did not persist")?;
    let destination = fs
        .open_directory_at(suite, "destination")
        .map_err(|_| "destination directory did not persist")?;
    let archive = fs
        .open_directory_at(suite, "archive")
        .map_err(|_| "archive directory did not persist")?;
    if fs.open_file_at(source, "payload") != Err(FsError::NotFound) {
        return Err("moved source unexpectedly persisted");
    }
    let moved = fs
        .open_file_at(archive, "moved")
        .map_err(|_| "moved file did not persist")?;
    filesystem_smoke_read(fs, moved, FILESYSTEM_SMOKE_INITIAL_CONTENT)?;
    let current = fs
        .open_file_at(destination, "current")
        .map_err(|_| "current file did not persist")?;
    filesystem_smoke_read(fs, current, FILESYSTEM_SMOKE_PERSISTED_CONTENT)?;
    let metadata = fs
        .file_metadata(current)
        .map_err(|_| "persisted metadata unavailable")?;
    validate_filesystem_smoke_metadata(metadata, FILESYSTEM_SMOKE_PERSISTED_CONTENT.len())?;
    let metadata_file = fs
        .open_file_at(suite, "metadata")
        .map_err(|_| "metadata record did not persist")?;
    filesystem_smoke_read(
        fs,
        metadata_file,
        &filesystem_smoke_metadata_bytes(metadata),
    )?;

    if fs.open_file_at(destination, "filesystem-smoke-sibling") != Err(FsError::NotFound)
        || fs.open_file_at(destination, "../filesystem-smoke-sibling") != Err(FsError::InvalidName)
    {
        return Err("directory capability escaped its namespace");
    }
    let sibling = fs
        .open_file_at(root, "filesystem-smoke-sibling")
        .map_err(|_| "root sibling did not persist")?;
    filesystem_smoke_read(fs, sibling, b"outside delegated directory\n")?;

    let replacement = fs
        .create_file_at(destination, "next")
        .map_err(|_| "create persisted replacement failed")?;
    filesystem_smoke_write(fs, replacement, FILESYSTEM_SMOKE_REPLACED_CONTENT)?;
    fs.atomic_replace_file_at(destination, "next", destination, "current")
        .map_err(|_| "persisted atomic replacement failed")?;
    let mut stale_probe = [0_u8; 1];
    if fs.read(current, 0, &mut stale_probe) != Err(FsError::InvalidHandle) {
        return Err("persisted replaced handle remained valid");
    }
    let replaced = fs
        .open_file_at(destination, "current")
        .map_err(|_| "open persisted replacement failed")?;
    filesystem_smoke_read(fs, replaced, FILESYSTEM_SMOKE_REPLACED_CONTENT)?;
    fs.sync().map_err(|_| "persisted sync failed")
}

fn run_filesystem_hierarchy_smoke<D: Disk>(
    fs: &mut RedoxFs<D>,
) -> Result<&'static str, &'static str> {
    let root = fs.root_directory().map_err(|_| "open root failed")?;
    match fs.open_directory_at(root, "filesystem-smoke") {
        Ok(suite) => {
            verify_filesystem_hierarchy_smoke(fs, root, suite)?;
            Ok("filesystem-smoke: persisted")
        }
        Err(FsError::NotFound) => {
            initialize_filesystem_hierarchy_smoke(fs, root)?;
            Ok("filesystem-smoke: initialized")
        }
        Err(_) => Err("inspect smoke hierarchy failed"),
    }
}

const PRIVILEGE_STACK_SIZE: usize = 64 * 1024;
const FILESYSTEM_STACK_SIZE: usize = 256 * 1024;
const FILESYSTEM_STACK_GUARD_SIZE: usize = 4096;
const FILESYSTEM_STACK_GUARD_BYTE: u8 = 0xa5;

#[repr(C, align(4096))]
struct GuardedFilesystemStack {
    lower_guard: [u8; FILESYSTEM_STACK_GUARD_SIZE],
    stack: FixedStack<FILESYSTEM_STACK_SIZE>,
}

impl GuardedFilesystemStack {
    const fn new() -> Self {
        Self {
            lower_guard: [FILESYSTEM_STACK_GUARD_BYTE; FILESYSTEM_STACK_GUARD_SIZE],
            stack: FixedStack::new(),
        }
    }

    fn guard_intact(&self) -> bool {
        self.lower_guard
            .iter()
            .all(|byte| *byte == FILESYSTEM_STACK_GUARD_BYTE)
    }
}

#[repr(C, align(64))]
struct PrivilegeStack([u8; PRIVILEGE_STACK_SIZE]);

static mut RSP0_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut NMI_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut MACHINE_CHECK_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut SYSCALL_STACK: PrivilegeStack = PrivilegeStack([0; PRIVILEGE_STACK_SIZE]);
static mut CPU_PRIVILEGE_STATE: CpuPrivilegeState = CpuPrivilegeState::new();
static mut FILESYSTEM_STACK: GuardedFilesystemStack = GuardedFilesystemStack::new();
static mut FILESYSTEM_EXECUTOR: MaybeUninit<FsExecutor<'static, FILESYSTEM_STACK_SIZE>> =
    MaybeUninit::uninit();

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
    let cpu_capabilities = arch::cpu_capabilities();
    let Ok(mut frames) =
        UsableFrameAllocator::new(memory_map, cpu_capabilities.physical_address_bits)
    else {
        halt_forever();
    };
    let Ok(mut page_table) = (unsafe { ActivePageTable::from_current(hhdm.offset) }) else {
        halt_forever();
    };
    if page_table.reserve_active_frames(&mut frames).is_err() {
        ui.render_boot_log(&mut screen, "paging: failed to reserve active tables");
        halt_forever();
    }
    if (unsafe { arch::enable_no_execute() }).is_err() {
        ui.render_boot_log(&mut screen, "memory: execute-disable unavailable");
        halt_forever();
    }
    let Ok(kernel_heap) = heap::PageBackedHeap::initialize(&mut page_table, &mut frames) else {
        ui.render_boot_log(
            &mut screen,
            "memory: page-backed heap initialization failed",
        );
        halt_forever();
    };
    let mut serial = unsafe { SerialPort::new(SerialPort::COM1_BASE) };
    {
        let mut sink = SerialDebugSink::new(&mut serial);
        let _ = writeln!(
            sink,
            "memory: page-backed kernel heap online committed={} growths={} available={}\r",
            kernel_heap.committed_bytes(),
            kernel_heap.growth_count(),
            kernel_heap.available_bytes(),
        );
    }
    ui.render_boot_log(&mut screen, "memory: page-backed kernel heap online");

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

    #[allow(unused_mut)]
    let mut timer =
        match unsafe { LocalApicTimer::initialize(&mut page_table, &mut frames, tsc_frequency) } {
            Ok(timer) => timer,
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(sink, "timer: local APIC initialization failed: {error:?}\r");
                ui.render_boot_log(&mut screen, "timer: local APIC initialization failed");
                halt_forever();
            }
        };

    let cpu_state: &'static mut CpuPrivilegeState =
        unsafe { &mut *ptr::addr_of_mut!(CPU_PRIVILEGE_STATE) };
    if let Err(error) = unsafe {
        arch::initialize_cpu_with_external_interrupts(
            cpu_state,
            privilege_stack_tops(),
            arch::capture_syscall_and_yield,
            ExternalInterruptState::local_apic(timer.eoi_register_address()),
        )
    } {
        let mut sink = SerialDebugSink::new(&mut serial);
        let _ = writeln!(sink, "userspace: CPU initialization failed: {error:?}\r");
        ui.render_boot_log(&mut screen, "userspace: CPU initialization failed");
        halt_forever();
    }

    usb::configure_timestamp_frequency(Some(tsc_frequency));
    #[allow(unused_mut)]
    let mut storage =
        match unsafe { StorageDisk::initialize(&mut page_table, &mut frames, tsc_frequency) } {
            Ok(storage) => storage,
            Err(error) => {
                let _ = writeln!(
                    SerialDebugSink::new(&mut serial),
                    "storage: initialization failed: {error:?}\r"
                );
                ui.render_boot_log(&mut screen, "storage: no virtio-blk or AHCI disk");
                halt_forever();
            }
        };
    ui.render_boot_log(
        &mut screen,
        match storage.driver() {
            StorageDriver::Virtio(_) => "storage: virtio-blk online",
            StorageDriver::Ahci(_) => "storage: AHCI/SATA online",
        },
    );

    #[cfg(ginkgo_virtio_blk_smoke)]
    if virtio_blk_smoke_enabled() {
        match storage.driver_mut() {
            StorageDriver::Virtio(disk) => {
                run_virtio_blk_smoke(disk, &mut frames, hhdm.offset, &mut timer, &mut serial)
            }
            StorageDriver::Ahci(_) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(sink, "virtio-blk-smoke: FAIL virtio device unavailable\r");
                halt_forever();
            }
        }
    }

    #[cfg(ginkgo_ahci_smoke)]
    if ahci_smoke_enabled() {
        match storage.driver_mut() {
            StorageDriver::Ahci(disk) => {
                run_ahci_smoke(disk, &mut frames, hhdm.offset, &mut timer, &mut serial)
            }
            StorageDriver::Virtio(_) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(sink, "ahci-smoke: FAIL AHCI device unavailable\r");
                halt_forever();
            }
        }
    }

    let Ok(mut volume) = Volume::discover(storage) else {
        ui.render_boot_log(&mut screen, "storage: invalid partition table");
        halt_forever();
    };
    let blank_disk = volume_is_blank(&mut volume);
    let writeback = WriteBackDisk::try_new(volume, 3_072).unwrap_or_else(|_| halt_forever());
    let fs_result = if blank_disk {
        RedoxFs::format_disk(writeback)
    } else {
        RedoxFs::open_disk(writeback)
    };
    let Ok(mut fs) = fs_result else {
        ui.render_boot_log(&mut screen, "redoxfs: persistent disk mount failed");
        halt_forever();
    };
    match fs.grow_to_disk() {
        Ok(true) => {
            ui.render_boot_log(&mut screen, "redoxfs: expanded to partition capacity");
            let mut sink = SerialDebugSink::new(&mut serial);
            let _ = writeln!(sink, "redoxfs: expanded to partition capacity\r");
        }
        Ok(false) => {}
        Err(_) => {
            ui.render_boot_log(&mut screen, "redoxfs: filesystem expansion failed");
            halt_forever();
        }
    }
    if filesystem_hierarchy_smoke_enabled() {
        let result = run_filesystem_hierarchy_smoke(&mut fs);
        let mut sink = SerialDebugSink::new(&mut serial);
        match result {
            Ok(marker) => {
                let _ = writeln!(sink, "{marker}\r");
                halt_forever();
            }
            Err(detail) => {
                let _ = writeln!(sink, "filesystem-smoke: failure\r");
                let _ = writeln!(sink, "filesystem-smoke-detail: {detail}\r");
                halt_forever();
            }
        }
    }
    let executable_source_limit = usize::try_from(
        ginkgo_kernel::process::ProcessLimits::from_available_memory_bytes(
            frames.available_bytes(),
        )
        .executable_source_bytes,
    )
    .unwrap_or(usize::MAX);
    let (desktop_image, catalog) =
        match install_and_load_system_programs(&mut fs, executable_source_limit) {
            Ok(installed) => installed,
            Err(stage) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(
                    sink,
                    "redoxfs: system program installation failed ({stage})\r"
                );
                ui.render_boot_log(&mut screen, "redoxfs: system program installation failed");
                halt_forever();
            }
        };
    ui.catalog = catalog;
    ui.render_boot_log(&mut screen, "redoxfs: desktop ELF and registry loaded");
    let power_smoke_action = prepare_power_smoke_before_executor(&mut fs, &mut serial);
    let filesystem_root = fs.root_directory().unwrap_or_else(|_| halt_forever());
    let user_directory = fs
        .open_directory_at(filesystem_root, USER_DIRECTORY)
        .unwrap_or_else(|_| halt_forever());
    let filesystem_stack = unsafe { &mut *ptr::addr_of_mut!(FILESYSTEM_STACK) };
    let stack = unsafe { Pin::new_unchecked(&mut filesystem_stack.stack) };
    let mut filesystem_executor = FsExecutor::new(fs, stack);
    if filesystem_executor
        .activate_async_before_start(timer.id())
        .is_err()
    {
        ui.render_boot_log(&mut screen, "storage: async activation failed");
        halt_forever();
    }
    let filesystem_executor = unsafe {
        let slot = ptr::addr_of_mut!(FILESYSTEM_EXECUTOR);
        (*slot).write(filesystem_executor);
        Pin::new_unchecked(&mut *(*slot).as_mut_ptr())
    };

    let acpi_power = RSDP_REQUEST.response().and_then(|response| {
        match unsafe { AcpiPower::discover(response.address, hhdm.offset, tsc_frequency) } {
            Ok(power) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let (sleep_a, sleep_b) = power.sleep_types();
                let (pm1a, pm1b) = power.control_addresses();
                let _ = writeln!(
                    sink,
                    "acpi: reset and S5 power-off ready types={sleep_a}/{sleep_b} pm1={pm1a:#x}/{pm1b:?}\r"
                );
                ui.render_boot_log(&mut screen, "acpi: reset and S5 power-off ready");
                Some(power)
            }
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut serial);
                let _ = writeln!(sink, "acpi: power discovery failed: {error:?}\r");
                ui.render_boot_log(&mut screen, "acpi: machine power unavailable");
                None
            }
        }
    });
    let power_control = SystemPowerControl::new().unwrap_or_else(|_| halt_forever());
    let shared_frame_arena = SharedFrameArena::new().unwrap_or_else(|_| halt_forever());

    let mut context = KernelContext {
        frames,
        shared_frame_arena,
        page_table,
        kernel_heap,
        hhdm_offset: hhdm.offset,
        filesystem_executor,
        filesystem_bridges: core::array::from_fn(|_| None),
        filesystem_root,
        user_directory,
        serial,
        input: None,
        audio: None,
        timer,
        entropy,
        acpi_power,
        power_control,
        launch_quiesced: false,
        power_smoke_action,
        screen,
        ui,
        paging_verified: false,
        preemption_observed: false,
        preemption_smoke_id: None,
        process_capability_smoke_id: None,
        frame_reclaim_stress: frame_reclaim_stress_enabled().then_some(FrameReclaimStress {
            current: None,
            pending_completion: None,
            completed: 0,
            reuse_verified: 0,
            baseline: None,
        }),
        #[cfg(ginkgo_memory_policy_smoke)]
        memory_policy_smoke: None,
        processes: ProcessTable::new(),
        user_scheduler: ThreadScheduler::try_with_default_policy(USER_SCHEDULER_CAPACITY)
            .unwrap_or_else(|_| halt_forever()),
        waits: WaitRuntime::try_new(USER_SCHEDULER_CAPACITY).unwrap_or_else(|_| halt_forever()),
        process_terminations: WaitRuntime::try_new(PROCESS_TABLE_CAPACITY)
            .unwrap_or_else(|_| halt_forever()),
        requests: RequestBroker::try_new().unwrap_or_else(|_| halt_forever()),
        urgent_process_dispatch: false,
        desktop: None,
        desktop_process_id: None,
        focused_process_id: None,
        process_clients: Vec::new(),
        next_client_id: 1,
        launch_requested: None,
        launcher_toggle_pending: false,
        pending_console: [0; CONSOLE_BATCH_CAPACITY],
        pending_console_len: 0,
        pending_input: [0; INPUT_BATCH_CAPACITY],
        pending_input_len: 0,
        pressed_keys: Vec::new(),
        pressed_pointer_buttons: Vec::new(),
        log_flush_deadline: 0,
        writeback_job: None,
        writeback_retry: false,
        system_log_job: None,
        console_log_job: None,
        input_log_job: None,
        accounting_job: None,
        power_job: None,
        power_completion: None,
        system_log_written: false,
        accounting_written: false,
        process_creation_pending: false,
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

    #[cfg(ginkgo_memory_policy_smoke)]
    match prepare_memory_policy_smoke(&mut context) {
        Ok(smoke) => context.memory_policy_smoke = Some(smoke),
        Err(reason) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "ginkgo-memory-policy-smoke: FAIL {reason}\r");
            halt_forever();
        }
    }

    match unsafe {
        InputManager::initialize(
            &mut context.page_table,
            &mut context.frames,
            context.hhdm_offset,
        )
    } {
        Ok(input) => {
            {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                for device in input.topology_snapshot() {
                    let _ = writeln!(
                        sink,
                        "USB topology: root={} route={:05x} depth={} slot={} hub={} ports={} interfaces={}\r",
                        device.path.root_port,
                        device.path.route_string,
                        device.path.depth,
                        device.slot_id,
                        device.is_hub,
                        device.hub_port_count,
                        device.interface_count
                    );
                }
            }
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

    if let Some(input) = context.input.as_mut() {
        match unsafe { input.enable_msi(context.timer.id()) } {
            Ok(()) => {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(sink, "USB HID: xHCI MSI enabled\r");
            }
            Err(error) => {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "USB HID: MSI unavailable, retaining polling fallback: {error:?}\r"
                );
            }
        }
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

    run_memory_policy_smoke_if_enabled(&mut context);

    if power_smoke_mode().is_some() {
        run_power_smoke(&mut context);
    }

    if process_capability_smoke_enabled() {
        if spawn_process_capability_smoke(&mut context).is_err() {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "ginkgo-process-capability-smoke: FAIL kernel launch\r"
            );
            halt_forever();
        }
        run_scheduler(&mut context);
    }

    if request_smoke_enabled() {
        if spawn_request_smoke(&mut context).is_err() {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "ginkgo-request-smoke: FAIL kernel launch\r");
            halt_forever();
        }
        run_scheduler(&mut context);
    }

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
    let power = process
        .handles_mut()
        .system_power_install(&context.power_control)
        .unwrap_or_else(|_| halt_forever());
    process.set_start_arguments([
        u64::from(process_channel.raw()),
        context.screen.width() as u64,
        context.screen.height() as u64,
        u64::from(power.raw()),
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
    context.desktop_process_id = Some(process_id);
    if let Some(process) = context.processes.get_mut(process_id) {
        let _ = process.set_thread_scheduling_class_by_kernel(
            process.main_thread_id(),
            SchedulingClass::Interactive,
        );
    }
    synchronize_process_scheduler(&mut context, process_id);
    context
        .ui
        .render_boot_log(&mut context.screen, "desktop: userspace service started");
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
                synchronize_process_scheduler(&mut context, smoke_id);
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

    if thread_smoke_enabled() {
        let randomness = [
            context.entropy.next_u64(),
            context.entropy.next_u64(),
            context.entropy.next_u64(),
        ];
        let mut smoke = Process::from_elf_randomized(
            THREAD_SMOKE_ELF,
            &context.page_table,
            &mut context.frames,
            randomness,
        )
        .unwrap_or_else(|error| {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "thread-smoke: load failed: {error:?}\r");
            halt_forever();
        });
        let root = smoke
            .handles_mut()
            .filesystem_root_create_with_rights(
                ginkgo_sysapi::Rights::READ
                    | ginkgo_sysapi::Rights::WRITE
                    | ginkgo_sysapi::Rights::EXECUTE,
            )
            .unwrap_or_else(|_| halt_forever());
        let (audio_authority, _) = smoke
            .handles_mut()
            .scheduling_authority_create(ginkgo_sysapi::ThreadSchedulingClass::Audio, true)
            .unwrap_or_else(|_| halt_forever());
        smoke.set_start_arguments6([
            u64::from(root.raw()),
            0,
            0,
            0,
            u64::from(audio_authority.raw()),
            0,
        ]);
        let smoke_id = context.processes.insert(smoke).unwrap_or_else(|error| {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "thread-smoke: insertion failed: {error:?}\r");
            halt_forever();
        });
        synchronize_process_scheduler(&mut context, smoke_id);
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "thread-smoke: started pid={}\r", smoke_id.raw());
    }

    run_scheduler(&mut context)
}

fn prepare_power_smoke_before_executor<D: Disk>(
    filesystem: &mut RedoxFs<D>,
    serial: &mut Option<SerialPort>,
) -> Option<ginkgo_sysapi::SystemPowerAction> {
    let mode = power_smoke_mode()?;
    let action = match mode {
        "sync" => {
            let result = filesystem
                .open(POWER_SMOKE_PERSIST_PATH)
                .or_else(|_| filesystem.create(POWER_SMOKE_PERSIST_PATH))
                .and_then(|file| {
                    filesystem.truncate(file, 0)?;
                    let written = filesystem.write(file, 0, POWER_SMOKE_PERSIST_CONTENT)?;
                    (written == POWER_SMOKE_PERSIST_CONTENT.len())
                        .then_some(())
                        .ok_or(FsError::Io)
                });
            if result.is_err() {
                let _ = writeln!(
                    SerialDebugSink::new(serial),
                    "power-smoke: sync staging failed\r"
                );
                halt_forever();
            }
            let _ = writeln!(
                SerialDebugSink::new(serial),
                "power-smoke: sync-before-poweroff staged\r"
            );
            ginkgo_sysapi::SystemPowerAction::PowerOff
        }
        "verify" => {
            let mut bytes = [0_u8; 64];
            let verified = filesystem
                .open(POWER_SMOKE_PERSIST_PATH)
                .and_then(|file| {
                    filesystem.read(file, 0, &mut bytes[..POWER_SMOKE_PERSIST_CONTENT.len()])
                })
                .is_ok_and(|read| {
                    read == POWER_SMOKE_PERSIST_CONTENT.len()
                        && bytes[..POWER_SMOKE_PERSIST_CONTENT.len()]
                            == *POWER_SMOKE_PERSIST_CONTENT
                });
            if !verified {
                let _ = writeln!(
                    SerialDebugSink::new(serial),
                    "power-smoke: persistence verification failed\r"
                );
                halt_forever();
            }
            let _ = writeln!(
                SerialDebugSink::new(serial),
                "power-smoke: persisted after poweroff\r"
            );
            ginkgo_sysapi::SystemPowerAction::PowerOff
        }
        "cancel" => ginkgo_sysapi::SystemPowerAction::PowerOff,
        "reboot" => {
            if filesystem.open(POWER_SMOKE_REBOOT_PATH).is_ok() {
                ginkgo_sysapi::SystemPowerAction::PowerOff
            } else {
                let created = filesystem.create(POWER_SMOKE_REBOOT_PATH).and_then(|file| {
                    (filesystem.write(file, 0, b"reboot\n")? == 7)
                        .then_some(())
                        .ok_or(FsError::Io)
                });
                if created.is_err() {
                    halt_forever();
                }
                let _ = writeln!(
                    SerialDebugSink::new(serial),
                    "power-smoke: reboot requested\r"
                );
                ginkgo_sysapi::SystemPowerAction::Reboot
            }
        }
        _ => halt_forever(),
    };
    Some(action)
}

fn run_power_smoke(context: &mut KernelContext) -> ! {
    let now_ns = context.timer.clock().now_ns();
    let action = context.power_smoke_action.unwrap_or_else(|| halt_forever());
    if power_smoke_mode() == Some("reboot") && action == ginkgo_sysapi::SystemPowerAction::PowerOff
    {
        let _ = writeln!(
            SerialDebugSink::new(&mut context.serial),
            "power-smoke: reboot observed\r"
        );
    }
    if power_smoke_mode() == Some("cancel") {
        let deadline = now_ns.saturating_add(10_000_000_000);
        context
            .power_control
            .request(
                ginkgo_sysapi::SystemPowerAction::PowerOff,
                ginkgo_sysapi::SystemPowerFlags::empty(),
                deadline,
            )
            .unwrap_or_else(|_| halt_forever());
        context
            .power_control
            .cancel()
            .unwrap_or_else(|_| halt_forever());
        let _ = writeln!(
            SerialDebugSink::new(&mut context.serial),
            "power-smoke: cancellation passed\r"
        );
    }

    context
        .power_control
        .request(
            action,
            ginkgo_sysapi::SystemPowerFlags::empty(),
            now_ns.saturating_add(100_000_000),
        )
        .unwrap_or_else(|_| halt_forever());
    run_scheduler(context)
}

#[cfg(ginkgo_virtio_blk_smoke)]
fn run_virtio_blk_smoke(
    disk: &mut VirtioBlk,
    frames: &mut UsableFrameAllocator<'_>,
    hhdm_offset: u64,
    timer: &mut LocalApicTimer,
    serial: &mut Option<SerialPort>,
) -> ! {
    const BUFFER_BYTES: usize = 16 * 1024;
    const BUFFER_PAGES: usize = BUFFER_BYTES / PAGE_SIZE as usize;
    const TOTAL_PAGES: usize = BUFFER_PAGES * 2;
    const FIRST_LBA: u64 = 64;
    const SECOND_LBA: u64 = FIRST_LBA + (BUFFER_BYTES / SECTOR_SIZE) as u64;

    if let Err(error) = disk.enable_msix(timer.id()) {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "virtio-blk-smoke: FAIL MSI-X {error:?}\r");
        halt_forever();
    }

    let allocated =
        match frames.allocate_contiguous_frames_below(TOTAL_PAGES, DMA_32BIT_ADDRESS_LIMIT) {
            Ok(Some(allocated)) => allocated,
            result => {
                let mut sink = SerialDebugSink::new(serial);
                let _ = writeln!(sink, "virtio-blk-smoke: FAIL DMA allocation {result:?}\r");
                halt_forever();
            }
        };
    let physical = allocated
        .first()
        .map(|frame| frame.start_address().as_u64())
        .unwrap_or_else(|| halt_forever());
    let virtual_address = hhdm_offset
        .checked_add(physical)
        .and_then(|address| usize::try_from(address).ok())
        .unwrap_or_else(|| halt_forever());
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            virtual_address as *mut u8,
            TOTAL_PAGES * PAGE_SIZE as usize,
        )
    };
    for (offset, byte) in bytes[..BUFFER_BYTES].iter_mut().enumerate() {
        *byte = virtio_smoke_pattern(0, offset);
    }
    for (offset, byte) in bytes[BUFFER_BYTES..].iter_mut().enumerate() {
        *byte = virtio_smoke_pattern(1, offset);
    }

    let first_segments = block_smoke_segments::<BUFFER_PAGES>(physical);
    let second_segments = block_smoke_segments::<BUFFER_PAGES>(physical + BUFFER_BYTES as u64);
    let mut queue = AsyncBlockQueue::try_new(
        8,
        1,
        QueueConfig {
            child_bytes: BUFFER_BYTES as u32,
            ..QueueConfig::default()
        },
    )
    .unwrap_or_else(|error| {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "virtio-blk-smoke: FAIL queue {error:?}\r");
        halt_forever();
    });
    let device = queue
        .register_device(AsyncBlockDevice::config(disk))
        .unwrap_or_else(|error| {
            let mut sink = SerialDebugSink::new(serial);
            let _ = writeln!(sink, "virtio-blk-smoke: FAIL register {error:?}\r");
            halt_forever();
        });

    let write_ids = submit_block_smoke_pair(
        &mut queue,
        device,
        timer.clock().now_ns(),
        BlockOperation::Write,
        BUFFER_BYTES as u32,
        FIRST_LBA,
        SECOND_LBA,
        &first_segments,
        &second_segments,
        serial,
        "virtio-blk-smoke",
    );
    drive_block_smoke_pair(
        &mut queue,
        device,
        disk,
        write_ids,
        BUFFER_BYTES as u32,
        timer,
        serial,
        "virtio-blk-smoke",
    );

    bytes.fill(0);
    let read_ids = submit_block_smoke_pair(
        &mut queue,
        device,
        timer.clock().now_ns(),
        BlockOperation::Read,
        BUFFER_BYTES as u32,
        FIRST_LBA,
        SECOND_LBA,
        &first_segments,
        &second_segments,
        serial,
        "virtio-blk-smoke",
    );
    drive_block_smoke_pair(
        &mut queue,
        device,
        disk,
        read_ids,
        BUFFER_BYTES as u32,
        timer,
        serial,
        "virtio-blk-smoke",
    );

    let first_valid = bytes[..BUFFER_BYTES]
        .iter()
        .enumerate()
        .all(|(offset, byte)| *byte == virtio_smoke_pattern(0, offset));
    let second_valid = bytes[BUFFER_BYTES..]
        .iter()
        .enumerate()
        .all(|(offset, byte)| *byte == virtio_smoke_pattern(1, offset));
    if !first_valid || !second_valid {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "virtio-blk-smoke: FAIL readback mismatch\r");
        halt_forever();
    }

    let block = queue.diagnostics();
    let driver = disk.diagnostics();
    let errors = block
        .counters
        .failed_requests
        .saturating_add(block.counters.rejected_submissions)
        .saturating_add(driver.errors);
    let mut sink = SerialDebugSink::new(serial);
    let _ = writeln!(
        sink,
        "virtio-blk-smoke: PASS msix={} interrupts={} queue_hwm={} driver_hwm={} bytes={} errors={} live={} queued={} in_flight={}\r",
        u8::from(driver.msix_enabled),
        driver.interrupts,
        block.counters.in_flight_high_water,
        driver.in_flight_high_water,
        4 * BUFFER_BYTES,
        errors,
        block.live_requests,
        block.queued_requests,
        block.in_flight_commands
    );
    halt_forever()
}

#[cfg(ginkgo_ahci_smoke)]
fn run_ahci_smoke(
    disk: &mut AhciDisk,
    frames: &mut UsableFrameAllocator<'_>,
    hhdm_offset: u64,
    timer: &mut LocalApicTimer,
    serial: &mut Option<SerialPort>,
) -> ! {
    const BUFFER_BYTES: usize = 128 * 1024;
    const BUFFER_PAGES: usize = BUFFER_BYTES / PAGE_SIZE as usize;
    const TOTAL_PAGES: usize = BUFFER_PAGES * 2;
    const FIRST_LBA: u64 = 64;
    const SECOND_LBA: u64 = FIRST_LBA + (BUFFER_BYTES / SECTOR_SIZE) as u64;

    if let Err(error) = disk.enable_msi(timer.id()) {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "ahci-smoke: FAIL MSI {error:?}\r");
        halt_forever();
    }

    let allocated =
        match frames.allocate_contiguous_frames_below(TOTAL_PAGES, DMA_32BIT_ADDRESS_LIMIT) {
            Ok(Some(allocated)) => allocated,
            result => {
                let mut sink = SerialDebugSink::new(serial);
                let _ = writeln!(sink, "ahci-smoke: FAIL DMA allocation {result:?}\r");
                halt_forever();
            }
        };
    let physical = allocated
        .first()
        .map(|frame| frame.start_address().as_u64())
        .unwrap_or_else(|| halt_forever());
    let virtual_address = hhdm_offset
        .checked_add(physical)
        .and_then(|address| usize::try_from(address).ok())
        .unwrap_or_else(|| halt_forever());
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            virtual_address as *mut u8,
            TOTAL_PAGES * PAGE_SIZE as usize,
        )
    };
    for (offset, byte) in bytes[..BUFFER_BYTES].iter_mut().enumerate() {
        *byte = virtio_smoke_pattern(0, offset);
    }
    for (offset, byte) in bytes[BUFFER_BYTES..].iter_mut().enumerate() {
        *byte = virtio_smoke_pattern(1, offset);
    }

    let first_segments = block_smoke_segments::<BUFFER_PAGES>(physical);
    let second_segments = block_smoke_segments::<BUFFER_PAGES>(physical + BUFFER_BYTES as u64);
    let mut queue = AsyncBlockQueue::try_new(
        8,
        1,
        QueueConfig {
            child_bytes: BUFFER_BYTES as u32,
            ..QueueConfig::default()
        },
    )
    .unwrap_or_else(|error| {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "ahci-smoke: FAIL queue {error:?}\r");
        halt_forever();
    });
    let device = queue
        .register_device(AsyncBlockDevice::config(disk))
        .unwrap_or_else(|error| {
            let mut sink = SerialDebugSink::new(serial);
            let _ = writeln!(sink, "ahci-smoke: FAIL register {error:?}\r");
            halt_forever();
        });

    let write_ids = submit_block_smoke_pair(
        &mut queue,
        device,
        timer.clock().now_ns(),
        BlockOperation::Write,
        BUFFER_BYTES as u32,
        FIRST_LBA,
        SECOND_LBA,
        &first_segments,
        &second_segments,
        serial,
        "ahci-smoke",
    );
    drive_block_smoke_pair(
        &mut queue,
        device,
        disk,
        write_ids,
        BUFFER_BYTES as u32,
        timer,
        serial,
        "ahci-smoke",
    );

    bytes.fill(0);
    let read_ids = submit_block_smoke_pair(
        &mut queue,
        device,
        timer.clock().now_ns(),
        BlockOperation::Read,
        BUFFER_BYTES as u32,
        FIRST_LBA,
        SECOND_LBA,
        &first_segments,
        &second_segments,
        serial,
        "ahci-smoke",
    );
    drive_block_smoke_pair(
        &mut queue,
        device,
        disk,
        read_ids,
        BUFFER_BYTES as u32,
        timer,
        serial,
        "ahci-smoke",
    );

    let first_valid = bytes[..BUFFER_BYTES]
        .iter()
        .enumerate()
        .all(|(offset, byte)| *byte == virtio_smoke_pattern(0, offset));
    let second_valid = bytes[BUFFER_BYTES..]
        .iter()
        .enumerate()
        .all(|(offset, byte)| *byte == virtio_smoke_pattern(1, offset));
    if !first_valid || !second_valid {
        let mut sink = SerialDebugSink::new(serial);
        let _ = writeln!(sink, "ahci-smoke: FAIL readback mismatch\r");
        halt_forever();
    }

    let block = queue.diagnostics();
    let driver = disk.diagnostics();
    let errors = block
        .counters
        .failed_requests
        .saturating_add(block.counters.rejected_submissions)
        .saturating_add(driver.errors);
    let mut sink = SerialDebugSink::new(serial);
    let _ = writeln!(
        sink,
        "ahci-smoke: PASS ncq={} depth={} msi={} interrupts={} queue_hwm={} driver_hwm={} prdt_hwm={} bytes={} errors={} quarantined={} live={} queued={} in_flight={}\r",
        u8::from(driver.ncq_enabled),
        driver.negotiated_queue_depth,
        u8::from(driver.msi_enabled),
        driver.interrupts,
        block.counters.in_flight_high_water,
        driver.slot_high_water,
        driver.prdt_high_water,
        4 * BUFFER_BYTES,
        errors,
        driver.quarantines,
        block.live_requests,
        block.queued_requests,
        block.in_flight_commands
    );
    halt_forever()
}

#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
fn submit_block_smoke_pair<const N: usize>(
    queue: &mut AsyncBlockQueue,
    device: ginkgo_kernel::async_block::BlockDeviceId,
    now_ns: u64,
    operation: BlockOperation,
    byte_len: u32,
    first_lba: u64,
    second_lba: u64,
    first_segments: &[DmaSegment; N],
    second_segments: &[DmaSegment; N],
    serial: &mut Option<SerialPort>,
    label: &str,
) -> [BlockRequestId; 2] {
    let deadline_ns = Some(now_ns.saturating_add(5_000_000_000));
    let first_buffer = unsafe {
        BlockBuffer::from_dma_segments(byte_len, first_segments).unwrap_or_else(|_| halt_forever())
    };
    let second_buffer = unsafe {
        BlockBuffer::from_dma_segments(byte_len, second_segments).unwrap_or_else(|_| halt_forever())
    };
    let first = queue.submit(
        now_ns,
        RequestSpec {
            device,
            operation,
            lba: first_lba,
            buffer: Some(first_buffer),
            priority: BlockPriority::Latency,
            deadline_ns,
        },
    );
    let second = queue.submit(
        now_ns,
        RequestSpec {
            device,
            operation,
            lba: second_lba,
            buffer: Some(second_buffer),
            priority: BlockPriority::Latency,
            deadline_ns,
        },
    );
    match (first, second) {
        (Ok(first), Ok(second)) => [first, second],
        (first, second) => {
            let mut sink = SerialDebugSink::new(serial);
            let _ = writeln!(
                sink,
                "{label}: FAIL submit first={first:?} second={second:?}\r"
            );
            halt_forever();
        }
    }
}

#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
fn drive_block_smoke_pair<D: AsyncBlockDevice>(
    queue: &mut AsyncBlockQueue,
    device: ginkgo_kernel::async_block::BlockDeviceId,
    disk: &mut D,
    ids: [BlockRequestId; 2],
    byte_len: u32,
    timer: &mut LocalApicTimer,
    serial: &mut Option<SerialPort>,
    label: &str,
) where
    D::Error: core::fmt::Debug,
{
    let deadline_ns = timer.clock().now_ns().saturating_add(5_000_000_000);
    let mut completed = [false; 2];
    while !completed.iter().all(|done| *done) {
        let now_ns = timer.clock().now_ns();
        if now_ns >= deadline_ns {
            let mut sink = SerialDebugSink::new(serial);
            let _ = writeln!(sink, "{label}: FAIL completion timeout\r");
            halt_forever();
        }
        if let Err(error) = run_device_worker(
            queue,
            device,
            disk,
            now_ns,
            DeviceWorkerBudget {
                completions: 8,
                cancellations: 8,
                submissions: 8,
            },
        ) {
            let mut sink = SerialDebugSink::new(serial);
            let _ = writeln!(sink, "{label}: FAIL worker {error:?}\r");
            halt_forever();
        }
        for (index, id) in ids.iter().copied().enumerate() {
            if completed[index] {
                continue;
            }
            if let Some(completion) = queue.take_completion(id) {
                if completion.outcome != RequestOutcome::Success
                    || completion.bytes_completed != byte_len
                {
                    let mut sink = SerialDebugSink::new(serial);
                    let _ = writeln!(sink, "{label}: FAIL completion {completion:?}\r");
                    halt_forever();
                }
                completed[index] = true;
            }
        }
        if !completed.iter().all(|done| *done) {
            if timer.arm_one_shot(10_000_000).is_err() {
                halt_forever();
            }
            let _ = arch::idle_until_interrupt();
            timer.disarm();
        }
    }
}

#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
fn block_smoke_segments<const N: usize>(physical: u64) -> [DmaSegment; N] {
    core::array::from_fn(|index| DmaSegment {
        physical_address: physical + index as u64 * PAGE_SIZE,
        length: PAGE_SIZE as u32,
    })
}

#[cfg(any(ginkgo_ahci_smoke, ginkgo_virtio_blk_smoke))]
fn virtio_smoke_pattern(buffer: usize, offset: usize) -> u8 {
    (offset as u32)
        .wrapping_mul(31)
        .wrapping_add(buffer as u32 * 0x5d)
        .wrapping_add((offset >> 8) as u32) as u8
}

fn run_memory_policy_smoke_if_enabled(context: &mut KernelContext) {
    #[cfg(not(ginkgo_memory_policy_smoke))]
    let _ = context;

    #[cfg(ginkgo_memory_policy_smoke)]
    {
        let baseline = memory_policy_baseline(context);
        let smoke = context
            .memory_policy_smoke
            .as_mut()
            .expect("memory policy smoke was not prepared");
        smoke.baseline = baseline;
        if spawn_memory_policy_smoke(context).is_err() {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "ginkgo-memory-policy-smoke: FAIL initial launch\r");
            halt_forever();
        }
        run_scheduler(context);
    }
}

fn run_scheduler(context: &mut KernelContext) -> ! {
    let mut scheduler = Scheduler::<KernelContext, 15>::new();
    if scheduler.spawn(filesystem_executor_task).is_err()
        || scheduler.spawn(writeback_task).is_err()
        || scheduler.spawn(filesystem_task).is_err()
        || scheduler.spawn(console_task).is_err()
        || scheduler.spawn(accounting_task).is_err()
        || scheduler.spawn(log_flush_task).is_err()
        || scheduler.spawn(input_task).is_err()
        || scheduler.spawn(audio_task).is_err()
        || scheduler.spawn(desktop_task).is_err()
        || scheduler.spawn(power_task).is_err()
        || scheduler.spawn(request_task).is_err()
        || scheduler.spawn(wait_task).is_err()
        || scheduler.spawn(process_task).is_err()
        || scheduler.spawn(wait_task).is_err()
    {
        halt_forever();
    }
    if scheduler.spawn(urgent_process_task).is_err() {
        halt_forever();
    }

    loop {
        maintain_kernel_heap(context);
        scheduler.run_round(context);
        reclaim_idle_shared_frames(context);
        let now_ns = context.timer.clock().now_ns();
        let next_deadline_ns = match (
            context.waits.next_deadline_ns(),
            context.requests.next_deadline_ns(),
        ) {
            (Some(wait), Some(request)) => Some(wait.min(request)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        };
        let idle_slice_ns = next_deadline_ns
            .map(|deadline| deadline.saturating_sub(now_ns).max(1))
            .unwrap_or(KERNEL_IDLE_POLL_NS)
            .min(KERNEL_IDLE_POLL_NS);
        if !context.processes.has_runnable() && context.timer.arm_one_shot(idle_slice_ns).is_ok() {
            let _ = arch::idle_until_interrupt();
            context.timer.disarm();
        } else {
            core::hint::spin_loop();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelFilesystemOwner {
    Writeback,
    SystemLog,
    ConsoleLog { length: usize },
    InputLog { length: usize },
    Accounting,
    Power,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestFilesystemJob {
    Open { flags: u32 },
    RollbackOpen { status: ginkgo_sysapi::Status },
    Read { requested: usize },
    Write { requested: usize },
    Sync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequestFilesystemBridge {
    request: ginkgo_kernel::request::RequestId,
    job: RequestFilesystemJob,
}

struct PendingProgramLaunch {
    program: ProgramSummary,
    startup: Option<ginkgo_sysapi::Handle>,
}

enum FilesystemBridgeOwner {
    Request(RequestFilesystemBridge),
    Thread {
        thread: ThreadRef,
        continuation: syscall::DirectFilesystemContinuation,
    },
    Kernel(KernelFilesystemOwner),
    ProgramLaunch(PendingProgramLaunch),
}

struct FilesystemBridge {
    id: FsJobId,
    owner: FilesystemBridgeOwner,
}

#[derive(Clone)]
struct ProcessClient {
    process_id: ProcessId,
    client_id: ClientId,
    launch_authority: RegistryLaunchAuthority,
    interactive_authority: SchedulingAuthorityControl,
}

struct KernelContext {
    frames: UsableFrameAllocator<'static>,
    shared_frame_arena: SharedFrameArena,
    page_table: ActivePageTable,
    kernel_heap: heap::PageBackedHeap,
    hhdm_offset: u64,
    filesystem_executor: Pin<&'static mut FsExecutor<'static, FILESYSTEM_STACK_SIZE>>,
    filesystem_bridges: [Option<FilesystemBridge>; FS_JOB_CAPACITY],
    filesystem_root: ginkgo_filesystem::DirectoryHandle,
    user_directory: ginkgo_filesystem::DirectoryHandle,
    serial: Option<SerialPort>,
    input: Option<InputManager>,
    audio: Option<AudioDevice>,
    timer: LocalApicTimer,
    entropy: EntropyPool,
    acpi_power: Option<AcpiPower>,
    power_control: SystemPowerControl,
    launch_quiesced: bool,
    power_smoke_action: Option<ginkgo_sysapi::SystemPowerAction>,
    screen: FramebufferWriter<'static>,
    ui: ValidationUi,
    paging_verified: bool,
    preemption_observed: bool,
    preemption_smoke_id: Option<ProcessId>,
    process_capability_smoke_id: Option<ProcessId>,
    frame_reclaim_stress: Option<FrameReclaimStress>,
    #[cfg(ginkgo_memory_policy_smoke)]
    memory_policy_smoke: Option<MemoryPolicySmoke>,
    processes: ProcessTable,
    user_scheduler: ThreadScheduler<ThreadRef>,
    waits: WaitRuntime<ThreadRef>,
    process_terminations: WaitRuntime<ProcessId>,
    requests: RequestBroker,
    urgent_process_dispatch: bool,
    desktop: Option<DesktopBroker>,
    desktop_process_id: Option<ProcessId>,
    focused_process_id: Option<ProcessId>,
    process_clients: Vec<ProcessClient>,
    next_client_id: u64,
    launch_requested: Option<usize>,
    launcher_toggle_pending: bool,
    pending_console: [u8; CONSOLE_BATCH_CAPACITY],
    pending_console_len: usize,
    pending_input: [u8; INPUT_BATCH_CAPACITY],
    pending_input_len: usize,
    pressed_keys: Vec<(ginkgo_kernel::usb::HidInterfaceId, u16)>,
    pressed_pointer_buttons: Vec<(ginkgo_kernel::usb::HidInterfaceId, u16)>,
    log_flush_deadline: u64,
    writeback_job: Option<FsJobId>,
    writeback_retry: bool,
    system_log_job: Option<FsJobId>,
    console_log_job: Option<FsJobId>,
    input_log_job: Option<FsJobId>,
    accounting_job: Option<FsJobId>,
    power_job: Option<FsJobId>,
    power_completion: Option<Result<FsResult, FsExecutorError>>,
    system_log_written: bool,
    accounting_written: bool,
    process_creation_pending: bool,
}

fn maintain_kernel_heap(context: &mut KernelContext) {
    let minimum_available = heap::scheduler_heap_headroom(context.frames.available_bytes());
    let growth_before = context.kernel_heap.growth_count();
    let result = context.kernel_heap.ensure_headroom(
        minimum_available,
        &mut context.page_table,
        &mut context.frames,
    );
    let may_have_allocated_page_tables = context.kernel_heap.growth_count() != growth_before
        || matches!(
            result,
            Err(heap::HeapGrowError::OutOfFrames
                | heap::HeapGrowError::FrameAllocator(_)
                | heap::HeapGrowError::Mapping(_))
        );
    if may_have_allocated_page_tables {
        // Heap growth can allocate paging structures. Reserve them now so a later
        // process creation does not change live-frame accounting retroactively.
        let _ = context
            .page_table
            .reserve_active_frames(&mut context.frames);
    }
}

/// Returns shared frames released by any task in the completed scheduler round.
///
/// Reclaim is opportunistic: the arena retains exact ownership on failure and a
/// later round retries it. Allocator corruption remains visible through arena and
/// allocator diagnostics without turning an ordinary cleanup attempt into a halt.
fn reclaim_idle_shared_frames(context: &mut KernelContext) {
    if context
        .shared_frame_arena
        .reclaim_idle(&mut context.frames)
        .is_err()
    {
        return;
    }

    let completion = context
        .frame_reclaim_stress
        .as_mut()
        .and_then(|stress| stress.pending_completion.take());
    if let Some((process_id, final_state)) = completion {
        finish_frame_reclaim_stress(context, process_id, final_state);
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    if let Some((process_id, phase)) = context
        .memory_policy_smoke
        .as_mut()
        .and_then(|smoke| smoke.pending_completion.take())
    {
        finish_memory_policy_smoke(context, process_id, phase);
    }
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
const LAUNCHER_POWER_ROWS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LauncherSelection {
    Program(usize),
    PowerOff,
    Reboot,
}

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
    power_confirmation: Option<ginkgo_sysapi::SystemPowerAction>,
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
            power_confirmation: None,
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

    fn render_power_progress(&mut self, screen: &mut FramebufferWriter<'_>, message: &str) {
        let background = Rgb::new(8, 13, 22);
        let panel = Rgb::new(31, 41, 61);
        let primary = Rgb::new(232, 238, 247);
        let accent = Rgb::new(110, 231, 183);
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
            "System power",
            accent,
        );
        screen.draw_text(UI_MARGIN + 30, self.height / 3 + 82, 2, message, primary);
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
        let rows = self
            .catalog
            .len
            .min(MAX_LAUNCHER_PROGRAMS)
            .saturating_add(LAUNCHER_POWER_ROWS);
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

    fn launcher_selection_at(&self, x: usize, y: usize) -> Option<LauncherSelection> {
        if !self.launcher_visible {
            return None;
        }
        let (launcher_x, launcher_y, width, _) = self.launcher_geometry();
        let results_y = launcher_y + LAUNCHER_SEARCH_HEIGHT + LAUNCHER_GAP;
        if x < launcher_x || x >= launcher_x.saturating_add(width) || y < results_y {
            return None;
        }
        let row = (y - results_y) / LAUNCHER_ROW_HEIGHT;
        if row < self.catalog.len {
            Some(LauncherSelection::Program(row))
        } else if row == self.catalog.len {
            Some(LauncherSelection::PowerOff)
        } else if row == self.catalog.len + 1 {
            Some(LauncherSelection::Reboot)
        } else {
            None
        }
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
            let program_rows = self.catalog.len.min(MAX_LAUNCHER_PROGRAMS);
            let rows = program_rows.saturating_add(LAUNCHER_POWER_ROWS);
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
                    } else {
                        let action = if row == program_rows {
                            ginkgo_sysapi::SystemPowerAction::PowerOff
                        } else {
                            ginkgo_sysapi::SystemPowerAction::Reboot
                        };
                        let confirmed = self.power_confirmation == Some(action);
                        let (title, detail) = match (action, confirmed) {
                            (ginkgo_sysapi::SystemPowerAction::PowerOff, false) => {
                                ("Power off", "Orderly shutdown and storage sync")
                            }
                            (ginkgo_sysapi::SystemPowerAction::PowerOff, true) => {
                                ("Confirm power off", "Click again; Escape cancels")
                            }
                            (ginkgo_sysapi::SystemPowerAction::Reboot, false) => {
                                ("Restart", "Orderly restart and storage sync")
                            }
                            (ginkgo_sysapi::SystemPowerAction::Reboot, true) => {
                                ("Confirm restart", "Click again; Escape cancels")
                            }
                        };
                        screen.draw_text(x + 72, row_y + 16, 2, title, border);
                        screen.draw_text(x + 72, row_y + 42, 1, detail, Rgb::new(148, 163, 184));
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
        let _ = context.frames.deallocate_frame(frame);
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

    let reclaimed = match unsafe { context.page_table.unmap_4k(page) } {
        Ok(unmapped_frame) if unmapped_frame == frame => {
            context.frames.deallocate_frame(unmapped_frame).is_ok()
        }
        Ok(_) | Err(_) => false,
    };
    verified && reclaimed && context.page_table.translate_addr(address).is_none()
}

fn scheduler_authority(class: SchedulingClass) -> SchedulerAuthority {
    match class {
        SchedulingClass::Critical => SchedulerAuthority::Kernel,
        SchedulingClass::Audio | SchedulingClass::Interactive => SchedulerAuthority::System,
        SchedulingClass::Normal | SchedulingClass::Background => SchedulerAuthority::User,
    }
}

fn ensure_process_termination_registration(context: &mut KernelContext, process_id: ProcessId) {
    if context
        .process_terminations
        .token_for_key(process_id)
        .is_some()
        || context
            .processes
            .get(process_id)
            .is_none_or(|process| process.state().is_terminal())
    {
        return;
    }

    let token = context
        .process_terminations
        .register(process_id, WaitKind::ProcessTermination, None)
        .unwrap_or_else(|_| halt_forever());
    let observer = context.process_terminations.observer();
    let registered = context
        .processes
        .get(process_id)
        .and_then(|process| process.register_termination_observer(token, &observer).ok())
        .unwrap_or(false);
    if !registered {
        let _ = context.process_terminations.cancel(token);
    }
}

fn synchronize_process_scheduler(context: &mut KernelContext, process_id: ProcessId) {
    ensure_process_termination_registration(context, process_id);
    let mut threads = [None; ginkgo_kernel::process::MAX_THREADS_PER_PROCESS];
    let mut count = 0usize;
    if let Some(process) = context.processes.get(process_id) {
        for thread_id in process.thread_ids() {
            threads[count] = process.thread_state(thread_id).and_then(|state| {
                process.thread_scheduling_class(thread_id).map(|class| {
                    (
                        ThreadRef {
                            process_id,
                            thread_id,
                        },
                        state,
                        class,
                    )
                })
            });
            count += 1;
        }
    }
    let now_ns = context.timer.clock().now_ns();
    for (thread_ref, state, class) in threads[..count].iter().flatten().copied() {
        let snapshot = context.user_scheduler.snapshot(thread_ref);
        let authority = scheduler_authority(class);
        if snapshot
            .is_some_and(|snapshot| snapshot.base_class != class || snapshot.authority != authority)
        {
            context
                .user_scheduler
                .set_base_class_with_authority(thread_ref, class, authority, now_ns)
                .unwrap_or_else(|_| halt_forever());
        }
        match state {
            ThreadState::Ready => match context.user_scheduler.snapshot(thread_ref) {
                None => {
                    context
                        .user_scheduler
                        .add_thread(thread_ref, class, scheduler_authority(class), now_ns)
                        .unwrap_or_else(|_| halt_forever());
                }
                Some(snapshot) if snapshot.state == SchedulerThreadState::Blocked => {
                    let _ = context.user_scheduler.wake(thread_ref, now_ns);
                }
                Some(_) => {}
            },
            ThreadState::Blocked => match context.user_scheduler.snapshot(thread_ref) {
                None => {
                    context
                        .user_scheduler
                        .add_thread(thread_ref, class, scheduler_authority(class), now_ns)
                        .unwrap_or_else(|_| halt_forever());
                    let _ = context.user_scheduler.block(thread_ref);
                }
                Some(snapshot)
                    if matches!(
                        snapshot.state,
                        SchedulerThreadState::Runnable | SchedulerThreadState::Running
                    ) =>
                {
                    let _ = context.user_scheduler.block(thread_ref);
                }
                Some(_) => {}
            },
            ThreadState::Exited(_) | ThreadState::Faulted(_) | ThreadState::Terminated => {
                if context.user_scheduler.snapshot(thread_ref).is_some() {
                    let _ = context.user_scheduler.remove_thread(thread_ref, now_ns);
                }
                let _ = context.waits.cancel_key(thread_ref);
            }
        }
    }
    record_process_scheduler_snapshots(context, process_id);
}

fn record_process_scheduler_snapshots(context: &mut KernelContext, process_id: ProcessId) {
    let mut snapshots = [None; ginkgo_kernel::process::MAX_THREADS_PER_PROCESS];
    let mut count = 0usize;
    if let Some(process) = context.processes.get(process_id) {
        for thread_id in process.thread_ids() {
            let thread_ref = ThreadRef {
                process_id,
                thread_id,
            };
            snapshots[count] = context
                .user_scheduler
                .snapshot(thread_ref)
                .map(|snapshot| (thread_id, snapshot));
            count += 1;
        }
    }
    if let Some(process) = context.processes.get_mut(process_id) {
        for (thread_id, snapshot) in snapshots[..count].iter().flatten().copied() {
            process.record_scheduler_snapshot(thread_id, snapshot);
        }
    }
}

fn runtime_wait_kind(kind: BlockedKind) -> WaitKind {
    match kind {
        BlockedKind::WaitMany => WaitKind::WaitMany,
        BlockedKind::Sleep => WaitKind::Sleep,
        BlockedKind::Join => WaitKind::Join,
        BlockedKind::Request | BlockedKind::Filesystem => WaitKind::Request,
    }
}

fn arm_blocked_thread(context: &mut KernelContext, thread_ref: ThreadRef) -> Result<(), ()> {
    let Some((kind, deadline_ns, existing)) = context
        .processes
        .get(thread_ref.process_id)
        .and_then(|process| process.blocked_wait_spec(thread_ref.thread_id))
    else {
        return Err(());
    };
    if existing.is_some() {
        return Ok(());
    }

    let token = context
        .waits
        .register(thread_ref, runtime_wait_kind(kind), deadline_ns)
        .map_err(|_| ())?;
    let observer = context.waits.observer();
    let registration = context
        .processes
        .get_mut(thread_ref.process_id)
        .ok_or(())?
        .install_blocked_wait_registration(thread_ref.thread_id, token, &observer);
    if let Err(error) = registration {
        let status = error.status();
        let process = context.processes.get_mut(thread_ref.process_id).ok_or(())?;
        if !process.fail_blocked_wait_registration(thread_ref.thread_id, status) {
            let _ = context.waits.cancel(token);
            return Err(());
        }
        let _ = context.waits.notify_dependency(token);
    }
    let _ = context.user_scheduler.clear_deadline(thread_ref);
    Ok(())
}

fn donate_for_blocked_join(context: &mut KernelContext, donor: ThreadRef, now_ns: u64) {
    let Some(process) = context.processes.get(donor.process_id) else {
        return;
    };
    let Some(first_target) = process.blocked_join_target(donor.thread_id) else {
        return;
    };
    let mut chain = [donor; DEFAULT_MAX_DONATION_DEPTH];
    let mut count = 0usize;
    let mut target = Some(first_target);
    while let Some(thread_id) = target {
        if count == chain.len() {
            break;
        }
        chain[count] = ThreadRef {
            process_id: donor.process_id,
            thread_id,
        };
        count += 1;
        target = process.blocked_join_target(thread_id);
    }
    let deadline_ns = process
        .blocked_wait_spec(donor.thread_id)
        .and_then(|(_, deadline, _)| deadline);
    let expires_at_ns = deadline_ns
        .unwrap_or_else(|| now_ns.saturating_add(DEFAULT_MAX_DONATION_NS))
        .min(now_ns.saturating_add(DEFAULT_MAX_DONATION_NS));
    match context
        .user_scheduler
        .donate_chain(donor, &chain[..count], expires_at_ns, now_ns)
    {
        Ok(_) => record_process_scheduler_snapshots(context, donor.process_id),
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "scheduler: donation rejected donor={}:{} depth={} error={error:?}\r",
                donor.process_id.raw(),
                donor.thread_id.raw(),
                count,
            );
        }
    }
}

fn notify_completed_joins(context: &mut KernelContext, process_id: ProcessId) {
    let mut notifications = [None; ginkgo_kernel::process::MAX_THREADS_PER_PROCESS];
    let mut count = 0usize;
    if let Some(process) = context.processes.get(process_id) {
        for target in process.thread_ids() {
            if !process
                .thread_state(target)
                .is_some_and(ThreadState::is_terminal)
                || !context
                    .requests
                    .is_thread_drained(ginkgo_kernel::request::RequestOwner::new(
                        process_id.raw(),
                        target.raw(),
                    ))
            {
                continue;
            }
            let Some(caller) = process.blocked_join_claimant(target) else {
                continue;
            };
            notifications[count] = Some(ThreadRef {
                process_id,
                thread_id: caller,
            });
            count += 1;
        }
    }
    for caller in notifications[..count].iter().flatten().copied() {
        if let Some(token) = context.waits.token_for_key(caller) {
            let _ = context.waits.notify_dependency(token);
        }
    }
}

struct ProcessFilesystemQueue<'a> {
    executor: &'a mut Pin<&'static mut FsExecutor<'static, FILESYSTEM_STACK_SIZE>>,
    bridges: &'a mut [Option<FilesystemBridge>; FS_JOB_CAPACITY],
    root_directory: ginkgo_filesystem::DirectoryHandle,
    thread: ThreadRef,
    process_creation_pending: &'a mut bool,
}

impl syscall::FilesystemJobQueue for ProcessFilesystemQueue<'_> {
    fn root_directory(&self) -> ginkgo_filesystem::DirectoryHandle {
        self.root_directory
    }

    fn enqueue_for_thread(
        &mut self,
        job: FsJob,
        continuation: syscall::DirectFilesystemContinuation,
    ) -> Result<FsJobId, FsExecutorError> {
        let reserves_process_slot = matches!(
            &continuation,
            syscall::DirectFilesystemContinuation::ProcessCreate(_)
        );
        if reserves_process_slot && *self.process_creation_pending {
            return Err(FsExecutorError::ReservedCapacity);
        }
        let id = self
            .executor
            .as_mut()
            .enqueue(job)
            .map_err(|failure| failure.error)?;
        let Some(slot) = self.bridges.get_mut(id.index()) else {
            let _ = self.executor.as_mut().cancel(id);
            return Err(FsExecutorError::Internal);
        };
        if slot.is_some() {
            let _ = self.executor.as_mut().cancel(id);
            return Err(FsExecutorError::Internal);
        }
        if reserves_process_slot {
            *self.process_creation_pending = true;
        }
        *slot = Some(FilesystemBridge {
            id,
            owner: FilesystemBridgeOwner::Thread {
                thread: self.thread,
                continuation,
            },
        });
        Ok(id)
    }
}

fn enqueue_filesystem_job(
    context: &mut KernelContext,
    job: FsJob,
    owner: FilesystemBridgeOwner,
) -> Result<FsJobId, FsExecutorError> {
    let id = context
        .filesystem_executor
        .as_mut()
        .enqueue(job)
        .map_err(|failure| failure.error)?;
    let Some(slot) = context.filesystem_bridges.get_mut(id.index()) else {
        let _ = context.filesystem_executor.as_mut().cancel(id);
        return Err(FsExecutorError::Internal);
    };
    if slot.is_some() {
        let _ = context.filesystem_executor.as_mut().cancel(id);
        return Err(FsExecutorError::Internal);
    }
    *slot = Some(FilesystemBridge { id, owner });
    Ok(id)
}

fn bridge_for_request(
    context: &KernelContext,
    request: ginkgo_kernel::request::RequestId,
) -> Option<FsJobId> {
    context
        .filesystem_bridges
        .iter()
        .flatten()
        .find(|bridge| {
            matches!(
                &bridge.owner,
                FilesystemBridgeOwner::Request(owner) if owner.request == request
            )
        })
        .map(|bridge| bridge.id)
}

fn filesystem_executor_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    if !unsafe { (&*ptr::addr_of!(FILESYSTEM_STACK)).guard_intact() } {
        halt_forever();
    }
    let completed = match context.filesystem_executor.as_mut().poll_step() {
        PollStep::Idle | PollStep::Yielded(_) => return TaskPoll::Pending,
        PollStep::Completed(id) | PollStep::Faulted(id, _) => id,
    };
    let completion = match context
        .filesystem_executor
        .as_mut()
        .take_completion(completed)
    {
        Ok(completion) => completion,
        Err(_) => halt_forever(),
    };
    let bridge = context
        .filesystem_bridges
        .get_mut(completed.index())
        .and_then(Option::take)
        .filter(|bridge| bridge.id == completed)
        .unwrap_or_else(|| halt_forever());
    match bridge.owner {
        FilesystemBridgeOwner::Request(request) => {
            complete_filesystem_request_job(context, request, completion.result);
        }
        FilesystemBridgeOwner::Kernel(owner) => {
            complete_kernel_filesystem_job(context, owner, completion.result);
        }
        FilesystemBridgeOwner::ProgramLaunch(pending) => {
            complete_program_launch(context, pending, completion.result);
        }
        FilesystemBridgeOwner::Thread {
            thread,
            continuation,
        } => complete_direct_filesystem_job(
            context,
            completed,
            thread,
            continuation,
            completion.result,
        ),
    }
    TaskPoll::Pending
}

fn complete_direct_filesystem_job(
    context: &mut KernelContext,
    id: FsJobId,
    thread: ThreadRef,
    continuation: syscall::DirectFilesystemContinuation,
    result: Result<FsResult, FsExecutorError>,
) {
    let reserved_process_slot = matches!(
        &continuation,
        syscall::DirectFilesystemContinuation::ProcessCreate(_)
    );
    if reserved_process_slot {
        context.process_creation_pending = false;
    }
    let mut created_child = None;
    let staged = if let Some(process) = context.processes.get_mut(thread.process_id) {
        if process.blocked_filesystem_id(thread.thread_id) != Some(id) {
            false
        } else {
            unsafe { process.address_space().activate() };
            let outcome = syscall::complete_direct_filesystem(
                process,
                continuation,
                result,
                &context.page_table,
                &mut context.frames,
                &mut context.entropy,
            );
            created_child = outcome.child;
            let staged = process.stage_filesystem_completion(thread.thread_id, id, outcome.status);
            unsafe { context.page_table.activate() };
            staged
        }
    } else {
        false
    };
    if let Some(child) = created_child {
        let child_id = context
            .processes
            .insert(*child)
            .unwrap_or_else(|_| halt_forever());
        synchronize_process_scheduler(context, child_id);
    }
    if !staged {
        return;
    }
    if context
        .processes
        .get(thread.process_id)
        .and_then(|process| process.blocked_wait_spec(thread.thread_id))
        .and_then(|(_, _, token)| token)
        .is_none()
    {
        let _ = arm_blocked_thread(context, thread);
    }
    if let Some(token) = context.waits.token_for_key(thread) {
        let _ = context.waits.notify_dependency(token);
    }
}

fn request_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    let now_ns = context.timer.clock().now_ns();
    context
        .requests
        .run_worker(now_ns, RequestWorkerBudget::DEFAULT);

    if let Some(dispatch) = context.requests.next_dispatch(now_ns) {
        let owner_is_background = context
            .processes
            .get(ProcessId::from_raw(dispatch.owner.process_id))
            .and_then(|process| {
                process.thread_scheduling_class(ginkgo_kernel::process::ThreadId::from_raw(
                    dispatch.owner.thread_id,
                ))
            })
            == Some(SchedulingClass::Background);
        let background_service_due = now_ns >= state.get(0).unwrap_or(0) as u64;
        if owner_is_background
            && matches!(
                dispatch.operation,
                ginkgo_sysapi::RequestOperation::FilesystemRead
                    | ginkgo_sysapi::RequestOperation::FilesystemWrite
                    | ginkgo_sysapi::RequestOperation::FilesystemSync
                    | ginkgo_sysapi::RequestOperation::FilesystemOpen
                    | ginkgo_sysapi::RequestOperation::FilesystemTruncate
                    | ginkgo_sysapi::RequestOperation::FilesystemNamespace
            )
            && !background_service_due
        {
            let _ = context.requests.requeue_active(dispatch.id);
        } else if dispatch.operation == ginkgo_sysapi::RequestOperation::Synthetic
            && dispatch.service_payload.operation_argument != 0
        {
            let _ = context.requests.mark_device_owned(dispatch.id);
            #[cfg(ginkgo_request_smoke)]
            if let Some(device) = dispatch.device {
                const SYNTHETIC_RESET_MODE: u64 = 1 << 63;
                const SYNTHETIC_REMOVE_MODE: u64 = 1 << 62;
                if dispatch.service_payload.operation_argument & SYNTHETIC_RESET_MODE != 0 {
                    context.requests.reset_device(device, now_ns);
                } else if dispatch.service_payload.operation_argument & SYNTHETIC_REMOVE_MODE != 0 {
                    context.requests.remove_device(device, now_ns, true);
                }
            }
        } else {
            let service_result = match dispatch.operation {
                ginkgo_sysapi::RequestOperation::Synthetic => {
                    let (status, bytes) = service_synthetic_request(context, dispatch.id);
                    RequestServiceResult::Complete(status, bytes)
                }
                ginkgo_sysapi::RequestOperation::AudioWrite => {
                    let (status, bytes) = service_audio_request(context, dispatch.id);
                    RequestServiceResult::Complete(status, bytes)
                }
                ginkgo_sysapi::RequestOperation::Nop => {
                    RequestServiceResult::Complete(ginkgo_sysapi::Status::Ok, 0)
                }
                ginkgo_sysapi::RequestOperation::FilesystemRead
                | ginkgo_sysapi::RequestOperation::FilesystemWrite
                | ginkgo_sysapi::RequestOperation::FilesystemSync => {
                    service_filesystem_request(context, dispatch)
                }
                ginkgo_sysapi::RequestOperation::FilesystemOpen => {
                    service_filesystem_open_request(context, dispatch)
                }
                ginkgo_sysapi::RequestOperation::FilesystemTruncate
                | ginkgo_sysapi::RequestOperation::FilesystemNamespace => {
                    RequestServiceResult::Complete(ginkgo_sysapi::Status::InvalidArgument, 0)
                }
            };
            if owner_is_background
                && matches!(
                    dispatch.operation,
                    ginkgo_sysapi::RequestOperation::FilesystemRead
                        | ginkgo_sysapi::RequestOperation::FilesystemWrite
                        | ginkgo_sysapi::RequestOperation::FilesystemSync
                        | ginkgo_sysapi::RequestOperation::FilesystemOpen
                        | ginkgo_sysapi::RequestOperation::FilesystemTruncate
                        | ginkgo_sysapi::RequestOperation::FilesystemNamespace
                )
            {
                state.set(
                    0,
                    usize::try_from(now_ns.saturating_add(100_000_000)).unwrap_or(usize::MAX),
                );
            }
            if let RequestServiceResult::Complete(status, bytes_transferred) = service_result {
                let _ = context.requests.record_completion(BrokerCompletion {
                    id: dispatch.id,
                    status,
                    device_released: true,
                    bytes_transferred,
                    result_flags: ginkgo_sysapi::RequestResultFlags::empty(),
                });
                context
                    .requests
                    .run_worker(context.timer.clock().now_ns(), RequestWorkerBudget::DEFAULT);
            }
        }
    }

    let action = match context.requests.pop_action() {
        Ok(Some(action)) => action,
        Ok(None) => return TaskPoll::Pending,
        Err(_) => return TaskPoll::Pending,
    };
    match action {
        RequestAction::PublishTerminal { id, .. } => {
            copy_copied_request_outputs(context, id);
            let owner = context.requests.owner(id);
            let info = context.requests.info(id);
            if let (Some(owner), Some(info)) = (owner, info) {
                let output = ginkgo_sysapi::RequestSubmitOutput {
                    request: ginkgo_sysapi::Handle::INVALID,
                    state: info.state,
                    result: info.result,
                    result_flags: info.result_flags,
                    bytes_transferred: info.bytes_transferred,
                };
                if let Some(process) = context
                    .processes
                    .get_mut(ProcessId::from_raw(owner.process_id))
                {
                    process.stage_request_completion(
                        ginkgo_kernel::process::ThreadId::from_raw(owner.thread_id),
                        id,
                        output,
                    );
                }
            }
        }
        RequestAction::CancelDevice { id, reason, .. } => {
            service_request_cancellation(context, id, reason);
        }
        RequestAction::ReleaseResources { id, .. } => {
            if let Ok(released) = context.requests.take_external_resources(id) {
                release_request_resources(context, released);
            }
        }
    }
    TaskPoll::Pending
}

fn service_request_cancellation(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
    _reason: RequestCancelReason,
) {
    #[cfg(ginkgo_request_smoke)]
    if _reason == RequestCancelReason::Deadline
        && context.requests.info(id).and_then(|info| info.operation())
            == Some(ginkgo_sysapi::RequestOperation::Synthetic)
    {
        let completion = BrokerCompletion {
            id,
            status: ginkgo_sysapi::Status::Ok,
            device_released: true,
            bytes_transferred: 0,
            result_flags: ginkgo_sysapi::RequestResultFlags::empty(),
        };
        let _ = context.requests.record_completion(completion);
        let _ = context.requests.record_completion(completion);
        context
            .requests
            .run_worker(context.timer.clock().now_ns(), RequestWorkerBudget::DEFAULT);
        return;
    }

    if let Some(job) = bridge_for_request(context, id) {
        let _ = context.filesystem_executor.as_mut().cancel(job);
        if let Ok(completion) = context.filesystem_executor.as_mut().take_completion(job) {
            let bridge = context
                .filesystem_bridges
                .get_mut(job.index())
                .and_then(Option::take)
                .filter(|bridge| bridge.id == job);
            if let Some(FilesystemBridge {
                owner: FilesystemBridgeOwner::Request(owner),
                ..
            }) = bridge
            {
                complete_filesystem_request_job(context, owner, completion.result);
            }
        }
        return;
    }
    let _ = context
        .requests
        .acknowledge_cancel(id, context.timer.clock().now_ns(), true);
}

enum RequestServiceResult {
    Complete(ginkgo_sysapi::Status, u64),
    Requeued,
}

fn filesystem_enqueue_failure(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
    error: FsExecutorError,
    progress: u64,
) -> RequestServiceResult {
    if matches!(
        error,
        FsExecutorError::QueueFull | FsExecutorError::ReservedCapacity
    ) && context.requests.requeue_active(id).is_ok()
    {
        RequestServiceResult::Requeued
    } else {
        RequestServiceResult::Complete(map_fs_executor_error(error), progress)
    }
}

fn service_filesystem_open_request(
    context: &mut KernelContext,
    dispatch: ginkgo_kernel::request::RequestDispatch<
        ginkgo_sysapi::RequestOperation,
        ginkgo_kernel::request_broker::BrokerPayload,
    >,
) -> RequestServiceResult {
    use ginkgo_sysapi::{FilesystemOpenFlags, Status};

    let Some((directory, _is_root, _anchor_rights)) =
        context.requests.directory_target(dispatch.id)
    else {
        return RequestServiceResult::Complete(Status::InvalidHandle, 0);
    };
    let Some(flags) = u32::try_from(dispatch.service_payload.operation_argument)
        .ok()
        .and_then(FilesystemOpenFlags::from_bits)
    else {
        return RequestServiceResult::Complete(Status::InvalidArgument, 0);
    };
    let path = {
        let Some(buffers) = context.requests.buffers(dispatch.id) else {
            return RequestServiceResult::Complete(Status::InvalidHandle, 0);
        };
        let Some(PreparedRequestBuffer::Copied { bytes, .. }) = buffers.first() else {
            return RequestServiceResult::Complete(Status::InvalidArgument, 0);
        };
        let Ok(path) = core::str::from_utf8(bytes) else {
            return RequestServiceResult::Complete(Status::InvalidArgument, 0);
        };
        String::from(path)
    };
    let directory = directory.map_or(FsDirectory::Root, FsDirectory::Handle);
    let owner = FilesystemBridgeOwner::Request(RequestFilesystemBridge {
        request: dispatch.id,
        job: RequestFilesystemJob::Open {
            flags: flags.bits(),
        },
    });
    match enqueue_filesystem_job(
        context,
        FsJob::OpenFileOptions {
            directory,
            path,
            create: flags.contains(FilesystemOpenFlags::CREATE),
            truncate: flags.contains(FilesystemOpenFlags::TRUNCATE),
        },
        owner,
    ) {
        Ok(_) => RequestServiceResult::Requeued,
        Err(error) => filesystem_enqueue_failure(context, dispatch.id, error, 0),
    }
}

fn map_fs_executor_error(error: FsExecutorError) -> ginkgo_sysapi::Status {
    match error {
        FsExecutorError::Filesystem(error) => map_request_fs_error(error),
        FsExecutorError::QueueFull | FsExecutorError::ReservedCapacity => {
            ginkgo_sysapi::Status::ShouldWait
        }
        FsExecutorError::PayloadTooLarge | FsExecutorError::ResultTooLarge => {
            ginkgo_sysapi::Status::OutOfRange
        }
        FsExecutorError::AllocationFailed => ginkgo_sysapi::Status::OutOfMemory,
        FsExecutorError::Canceled => ginkgo_sysapi::Status::Canceled,
        FsExecutorError::Storage(_)
        | FsExecutorError::Writeback(_)
        | FsExecutorError::ExecutorStarted
        | FsExecutorError::UnknownJob
        | FsExecutorError::NotComplete
        | FsExecutorError::Fiber(_)
        | FsExecutorError::FiberFault(_)
        | FsExecutorError::Internal => ginkgo_sysapi::Status::Io,
    }
}

fn map_request_fs_error(error: FsError) -> ginkgo_sysapi::Status {
    use ginkgo_sysapi::Status;
    match error {
        FsError::InvalidName | FsError::TraversalTooDeep => Status::InvalidArgument,
        FsError::AlreadyExists => Status::AlreadyExists,
        FsError::NotFound | FsError::InvalidHandle => Status::NotFound,
        FsError::NoSpace => Status::ResourceLimit,
        FsError::NotDirectory => Status::NotDirectory,
        FsError::IsDirectory => Status::IsDirectory,
        FsError::DirectoryNotEmpty => Status::DirectoryNotEmpty,
        FsError::WouldCycle => Status::InvalidArgument,
        FsError::OffsetOverflow => Status::OutOfRange,
        FsError::Io => Status::Io,
    }
}

fn service_filesystem_request(
    context: &mut KernelContext,
    dispatch: ginkgo_kernel::request::RequestDispatch<
        ginkgo_sysapi::RequestOperation,
        ginkgo_kernel::request_broker::BrokerPayload,
    >,
) -> RequestServiceResult {
    use ginkgo_sysapi::{RequestOperation, Status};

    if dispatch.operation == RequestOperation::FilesystemSync {
        let job = match context.requests.durability_ticket(dispatch.id) {
            Some(Some(ticket)) => FsJob::WaitDurable {
                ticket,
                max_writeback_steps: 1,
            },
            Some(None) => FsJob::Checkpoint,
            None => return RequestServiceResult::Complete(Status::InvalidHandle, 0),
        };
        return match enqueue_filesystem_job(
            context,
            job,
            FilesystemBridgeOwner::Request(RequestFilesystemBridge {
                request: dispatch.id,
                job: RequestFilesystemJob::Sync,
            }),
        ) {
            Ok(_) => RequestServiceResult::Requeued,
            Err(error) => filesystem_enqueue_failure(context, dispatch.id, error, 0),
        };
    }

    let Some(file) = context.requests.file_target(dispatch.id).copied() else {
        return RequestServiceResult::Complete(Status::InvalidHandle, 0);
    };
    let Some(progress) = context.requests.service_offset(dispatch.id) else {
        return RequestServiceResult::Complete(Status::InvalidHandle, 0);
    };
    let Some(total) = context.requests.total_requested_bytes(dispatch.id) else {
        return RequestServiceResult::Complete(Status::InvalidHandle, 0);
    };
    if progress >= total {
        return RequestServiceResult::Complete(Status::Ok, total);
    }
    let amount = usize::try_from((total - progress).min(redoxfs::BLOCK_SIZE))
        .unwrap_or(redoxfs::BLOCK_SIZE as usize);
    let (job, bridge_job) = match dispatch.operation {
        RequestOperation::FilesystemRead => (
            FsJob::ReadChunk {
                file,
                offset: dispatch
                    .service_payload
                    .operation_argument
                    .saturating_add(progress),
                length: amount,
            },
            RequestFilesystemJob::Read { requested: amount },
        ),
        RequestOperation::FilesystemWrite => {
            let mut data = Vec::new();
            if data.try_reserve_exact(amount).is_err() {
                return RequestServiceResult::Complete(Status::OutOfMemory, progress);
            }
            data.resize(amount, 0);
            if let Err(status) =
                read_request_buffer(context, dispatch.id, progress as usize, &mut data)
            {
                return RequestServiceResult::Complete(status, progress);
            }
            (
                FsJob::WriteChunk {
                    file,
                    offset: dispatch
                        .service_payload
                        .operation_argument
                        .saturating_add(progress),
                    data,
                },
                RequestFilesystemJob::Write { requested: amount },
            )
        }
        _ => unreachable!(),
    };
    match enqueue_filesystem_job(
        context,
        job,
        FilesystemBridgeOwner::Request(RequestFilesystemBridge {
            request: dispatch.id,
            job: bridge_job,
        }),
    ) {
        Ok(_) => RequestServiceResult::Requeued,
        Err(error) => filesystem_enqueue_failure(context, dispatch.id, error, progress),
    }
}

fn complete_broker_filesystem_request(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
    status: ginkgo_sysapi::Status,
    bytes_transferred: u64,
) {
    let _ = context.requests.record_completion(BrokerCompletion {
        id,
        status,
        device_released: true,
        bytes_transferred,
        result_flags: ginkgo_sysapi::RequestResultFlags::empty(),
    });
    context
        .requests
        .run_worker(context.timer.clock().now_ns(), RequestWorkerBudget::DEFAULT);
}

fn complete_filesystem_request_job(
    context: &mut KernelContext,
    bridge: RequestFilesystemBridge,
    result: Result<FsResult, FsExecutorError>,
) {
    use ginkgo_sysapi::{FilesystemOpenFlags, Status};

    let id = bridge.request;
    if context.requests.info(id).is_none() {
        return;
    }
    if matches!(&result, Err(FsExecutorError::Canceled)) {
        let _ = context
            .requests
            .acknowledge_cancel(id, context.timer.clock().now_ns(), true);
        context
            .requests
            .run_worker(context.timer.clock().now_ns(), RequestWorkerBudget::DEFAULT);
        return;
    }
    let progress = context.requests.service_offset(id).unwrap_or(0);
    match bridge.job {
        RequestFilesystemJob::RollbackOpen { status } => {
            complete_broker_filesystem_request(context, id, status, 0);
        }
        RequestFilesystemJob::Open { flags } => {
            let flags = FilesystemOpenFlags::from_bits_retain(flags);
            let FsResult::OpenedFile {
                file,
                created,
                directory,
                path,
            } = (match result {
                Ok(result) => result,
                Err(error) => {
                    complete_broker_filesystem_request(
                        context,
                        id,
                        map_fs_executor_error(error),
                        0,
                    );
                    return;
                }
            })
            else {
                complete_broker_filesystem_request(context, id, Status::Io, 0);
                return;
            };
            let Some(owner) = context.requests.owner(id) else {
                return;
            };
            let Some(process) = context
                .processes
                .get_mut(ProcessId::from_raw(owner.process_id))
            else {
                if created {
                    let _ = enqueue_filesystem_job(
                        context,
                        FsJob::Unlink { directory, path },
                        FilesystemBridgeOwner::Request(RequestFilesystemBridge {
                            request: id,
                            job: RequestFilesystemJob::RollbackOpen {
                                status: Status::Canceled,
                            },
                        }),
                    );
                }
                return;
            };
            let mut rights = ginkgo_ipc::Rights::empty();
            if flags.contains(FilesystemOpenFlags::READ) {
                rights |= ginkgo_ipc::Rights::READ;
            }
            if flags.contains(FilesystemOpenFlags::WRITE) {
                rights |= ginkgo_ipc::Rights::WRITE;
            }
            if flags.contains(FilesystemOpenFlags::EXECUTE) {
                rights |= ginkgo_ipc::Rights::EXECUTE
                    | ginkgo_ipc::Rights::DUPLICATE
                    | ginkgo_ipc::Rights::TRANSFER;
            }
            let handle = match process.handles_mut().filesystem_file_create(file, rights) {
                Ok(handle) => handle,
                Err(error) => {
                    let status = error.status();
                    if created {
                        let _ = enqueue_filesystem_job(
                            context,
                            FsJob::Unlink { directory, path },
                            FilesystemBridgeOwner::Request(RequestFilesystemBridge {
                                request: id,
                                job: RequestFilesystemJob::RollbackOpen { status },
                            }),
                        );
                    } else {
                        complete_broker_filesystem_request(context, id, status, 0);
                    }
                    return;
                }
            };
            let mut output = [0_u8; 8];
            output[..4].copy_from_slice(&handle.raw().to_le_bytes());
            let write_result = match context.requests.buffers_mut(id) {
                Some([_, PreparedRequestBuffer::Pinned { pages, .. }]) => {
                    copy_to_pinned_pages(context.hhdm_offset, pages, 0, &output)
                }
                _ => Err(Status::InvalidArgument),
            };
            if let Err(status) = write_result {
                let _ = process.handles_mut().handle_close(handle);
                if created {
                    let _ = enqueue_filesystem_job(
                        context,
                        FsJob::Unlink { directory, path },
                        FilesystemBridgeOwner::Request(RequestFilesystemBridge {
                            request: id,
                            job: RequestFilesystemJob::RollbackOpen { status },
                        }),
                    );
                } else {
                    complete_broker_filesystem_request(context, id, status, 0);
                }
                return;
            }
            complete_broker_filesystem_request(context, id, Status::Ok, 0);
        }
        RequestFilesystemJob::Read { requested } => {
            let bytes = match result {
                Ok(FsResult::Bytes(bytes)) => bytes,
                Ok(_) => {
                    complete_broker_filesystem_request(context, id, Status::Io, progress);
                    return;
                }
                Err(error) => {
                    complete_broker_filesystem_request(
                        context,
                        id,
                        map_fs_executor_error(error),
                        progress,
                    );
                    return;
                }
            };
            let count = bytes.len();
            if let Err(status) = write_request_buffer(context, id, progress as usize, &bytes) {
                complete_broker_filesystem_request(context, id, status, progress);
                return;
            }
            finish_filesystem_chunk(context, id, progress, count, requested);
        }
        RequestFilesystemJob::Write { requested } => {
            let count = match result {
                Ok(FsResult::Count(count)) => count,
                Ok(_) => {
                    complete_broker_filesystem_request(context, id, Status::Io, progress);
                    return;
                }
                Err(error) => {
                    complete_broker_filesystem_request(
                        context,
                        id,
                        map_fs_executor_error(error),
                        progress,
                    );
                    return;
                }
            };
            finish_filesystem_chunk(context, id, progress, count, requested);
        }
        RequestFilesystemJob::Sync => {
            let durability = match result {
                Ok(FsResult::Durability(durability)) => durability,
                Ok(_) => {
                    complete_broker_filesystem_request(context, id, Status::Io, 0);
                    return;
                }
                Err(error) => {
                    complete_broker_filesystem_request(
                        context,
                        id,
                        map_fs_executor_error(error),
                        0,
                    );
                    return;
                }
            };
            if context
                .requests
                .set_durability_ticket(id, durability.ticket)
                .is_err()
            {
                complete_broker_filesystem_request(context, id, Status::Io, 0);
            } else if durability.complete {
                complete_broker_filesystem_request(context, id, Status::Ok, 0);
            } else if context.requests.requeue_active(id).is_err() {
                complete_broker_filesystem_request(context, id, Status::Io, 0);
            }
        }
    }
}

fn finish_filesystem_chunk(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
    progress: u64,
    count: usize,
    requested: usize,
) {
    use ginkgo_sysapi::Status;
    let Ok(next) = context.requests.advance_service_offset(id, count as u64) else {
        complete_broker_filesystem_request(context, id, Status::Io, progress);
        return;
    };
    let total = context.requests.total_requested_bytes(id).unwrap_or(next);
    if next >= total || count == 0 || count < requested {
        complete_broker_filesystem_request(context, id, Status::Ok, next);
    } else if context.requests.requeue_active(id).is_err() {
        complete_broker_filesystem_request(context, id, Status::Io, next);
    }
}

fn write_request_buffer(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
    offset: usize,
    input: &[u8],
) -> Result<(), ginkgo_sysapi::Status> {
    let hhdm_offset = context.hhdm_offset;
    let Some([buffer]) = context.requests.buffers_mut(id) else {
        return Err(ginkgo_sysapi::Status::InvalidHandle);
    };
    match buffer {
        PreparedRequestBuffer::Copied { bytes, .. } => {
            let end = offset
                .checked_add(input.len())
                .ok_or(ginkgo_sysapi::Status::OutOfRange)?;
            let output = bytes
                .get_mut(offset..end)
                .ok_or(ginkgo_sysapi::Status::OutOfRange)?;
            output.copy_from_slice(input);
            Ok(())
        }
        PreparedRequestBuffer::Pinned { pages, .. } => {
            copy_to_pinned_pages(hhdm_offset, pages, offset, input)
        }
        PreparedRequestBuffer::SharedMemory { lease, .. } => lease
            .write(offset, input)
            .map_err(|_| ginkgo_sysapi::Status::Io),
    }
}

fn read_request_buffer(
    context: &KernelContext,
    id: ginkgo_kernel::request::RequestId,
    offset: usize,
    output: &mut [u8],
) -> Result<(), ginkgo_sysapi::Status> {
    let Some([buffer]) = context.requests.buffers(id) else {
        return Err(ginkgo_sysapi::Status::InvalidHandle);
    };
    match buffer {
        PreparedRequestBuffer::Copied { bytes, .. } => {
            let end = offset
                .checked_add(output.len())
                .ok_or(ginkgo_sysapi::Status::OutOfRange)?;
            output.copy_from_slice(
                bytes
                    .get(offset..end)
                    .ok_or(ginkgo_sysapi::Status::OutOfRange)?,
            );
            Ok(())
        }
        PreparedRequestBuffer::Pinned { pages, .. } => {
            copy_from_pinned_pages(context.hhdm_offset, pages, offset, output)
        }
        PreparedRequestBuffer::SharedMemory { lease, .. } => lease
            .read(offset, output)
            .map_err(|_| ginkgo_sysapi::Status::Io),
    }
}

fn copy_to_pinned_pages(
    hhdm_offset: u64,
    pages: &[ginkgo_kernel::paging::address_space::PinnedUserPage],
    mut offset: usize,
    mut input: &[u8],
) -> Result<(), ginkgo_sysapi::Status> {
    for page in pages {
        if offset >= page.byte_length {
            offset -= page.byte_length;
            continue;
        }
        let amount = input.len().min(page.byte_length - offset);
        let address = hhdm_offset
            .checked_add(page.physical_start)
            .and_then(|address| address.checked_add((page.page_offset + offset) as u64))
            .and_then(|address| usize::try_from(address).ok())
            .ok_or(ginkgo_sysapi::Status::OutOfRange)?;
        unsafe {
            ptr::copy_nonoverlapping(input.as_ptr(), address as *mut u8, amount);
        }
        input = &input[amount..];
        offset = 0;
        if input.is_empty() {
            return Ok(());
        }
    }
    Err(ginkgo_sysapi::Status::OutOfRange)
}

fn copy_from_pinned_pages(
    hhdm_offset: u64,
    pages: &[ginkgo_kernel::paging::address_space::PinnedUserPage],
    mut offset: usize,
    mut output: &mut [u8],
) -> Result<(), ginkgo_sysapi::Status> {
    for page in pages {
        if offset >= page.byte_length {
            offset -= page.byte_length;
            continue;
        }
        let amount = output.len().min(page.byte_length - offset);
        let address = hhdm_offset
            .checked_add(page.physical_start)
            .and_then(|address| address.checked_add((page.page_offset + offset) as u64))
            .and_then(|address| usize::try_from(address).ok())
            .ok_or(ginkgo_sysapi::Status::OutOfRange)?;
        unsafe {
            ptr::copy_nonoverlapping(address as *const u8, output.as_mut_ptr(), amount);
        }
        let (_, rest) = output.split_at_mut(amount);
        output = rest;
        offset = 0;
        if output.is_empty() {
            return Ok(());
        }
    }
    Err(ginkgo_sysapi::Status::OutOfRange)
}

fn copy_copied_request_outputs(context: &mut KernelContext, id: ginkgo_kernel::request::RequestId) {
    let Some(owner) = context.requests.owner(id) else {
        return;
    };
    let process_id = ProcessId::from_raw(owner.process_id);
    let Some(process) = context.processes.get_mut(process_id) else {
        return;
    };
    unsafe { process.address_space().activate() };
    if let Some(buffers) = context.requests.buffers(id) {
        for buffer in buffers {
            if let PreparedRequestBuffer::Copied {
                flags,
                user_address,
                bytes,
            } = buffer
            {
                if flags.contains(ginkgo_sysapi::RequestBufferFlags::WRITE) {
                    let _ = process.address_space().copy_to_user(*user_address, bytes);
                }
            }
        }
    }
    unsafe { context.page_table.activate() };
}

fn service_synthetic_request(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
) -> (ginkgo_sysapi::Status, u64) {
    let hhdm_offset = context.hhdm_offset;
    let Some(buffers) = context.requests.buffers_mut(id) else {
        return (ginkgo_sysapi::Status::InvalidHandle, 0);
    };
    let mut transferred = 0_u64;
    let fill = [0xa5_u8; 256];
    for buffer in buffers {
        transferred = transferred.saturating_add(buffer.byte_len() as u64);
        if !buffer
            .flags()
            .contains(ginkgo_sysapi::RequestBufferFlags::WRITE)
        {
            continue;
        }
        match buffer {
            PreparedRequestBuffer::Copied { bytes, .. } => bytes.fill(0xa5),
            PreparedRequestBuffer::Pinned { pages, .. } => {
                for page in pages {
                    let Some(address) = hhdm_offset
                        .checked_add(page.physical_start)
                        .and_then(|address| address.checked_add(page.page_offset as u64))
                    else {
                        return (ginkgo_sysapi::Status::OutOfRange, 0);
                    };
                    let Ok(address) = usize::try_from(address) else {
                        return (ginkgo_sysapi::Status::OutOfRange, 0);
                    };
                    unsafe {
                        ptr::write_bytes(address as *mut u8, 0xa5, page.byte_length);
                    }
                }
            }
            PreparedRequestBuffer::SharedMemory { lease, .. } => {
                let mut offset = 0usize;
                while offset < lease.len() {
                    let amount = (lease.len() - offset).min(fill.len());
                    if lease.write(offset, &fill[..amount]).is_err() {
                        return (ginkgo_sysapi::Status::Io, 0);
                    }
                    offset += amount;
                }
            }
        }
    }
    (ginkgo_sysapi::Status::Ok, transferred)
}

fn service_audio_request(
    context: &mut KernelContext,
    id: ginkgo_kernel::request::RequestId,
) -> (ginkgo_sysapi::Status, u64) {
    let Some(audio) = context.audio.as_mut() else {
        return (ginkgo_sysapi::Status::Io, 0);
    };
    let Some(buffers) = context.requests.buffers(id) else {
        return (ginkgo_sysapi::Status::InvalidHandle, 0);
    };
    let [PreparedRequestBuffer::Copied { bytes, .. }] = buffers else {
        return (ginkgo_sysapi::Status::InvalidArgument, 0);
    };
    match audio.write_pcm(bytes) {
        Ok(written) if written == bytes.len() => (ginkgo_sysapi::Status::Ok, written as u64),
        Ok(_) => (ginkgo_sysapi::Status::ShouldWait, 0),
        Err(_) => (ginkgo_sysapi::Status::Io, 0),
    }
}

fn release_request_resources(
    context: &mut KernelContext,
    released: ginkgo_kernel::request_broker::ReleasedBrokerResources,
) {
    let process_id = ProcessId::from_raw(released.owner.process_id);
    let Some(process) = context.processes.get_mut(process_id) else {
        return;
    };
    unsafe { process.address_space().activate() };
    for buffer in released.buffers {
        match buffer {
            PreparedRequestBuffer::Copied {
                flags,
                user_address,
                bytes,
            } => {
                if flags.contains(ginkgo_sysapi::RequestBufferFlags::WRITE) {
                    let _ = process.address_space().copy_to_user(user_address, &bytes);
                }
            }
            PreparedRequestBuffer::Pinned { pages, .. } => {
                let _ = process.address_space_mut().unpin_user_pages(&pages);
            }
            PreparedRequestBuffer::SharedMemory { .. } => {}
        }
    }
    unsafe { context.page_table.activate() };
}

fn wait_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    const WAIT_WAKE_BUDGET: usize = 32;
    for _ in 0..WAIT_WAKE_BUDGET {
        if !service_one_process_termination(context) {
            break;
        }
    }
    for _ in 0..WAIT_WAKE_BUDGET {
        if !service_one_wait_wake(context) {
            break;
        }
    }
    TaskPoll::Pending
}

fn service_one_process_termination(context: &mut KernelContext) -> bool {
    let now_ns = context.timer.clock().now_ns();
    let Some(wake) = context.process_terminations.next_wake(now_ns) else {
        return false;
    };
    debug_assert_eq!(wake.kind, WaitKind::ProcessTermination);
    let process_id = wake.key;
    if let Some(process) = context.processes.get_mut(process_id) {
        if process.termination_requested() {
            process.mark_terminated();
        }
    }
    synchronize_process_scheduler(context, process_id);
    true
}

fn service_one_wait_wake(context: &mut KernelContext) -> bool {
    let now_ns = context.timer.clock().now_ns();
    let Some(wake) = context.waits.next_wake(now_ns) else {
        return false;
    };
    let thread_ref = wake.key;
    let Some(process) = context.processes.get_mut(thread_ref.process_id) else {
        let _ = context
            .user_scheduler
            .cancel_donations_from(thread_ref, now_ns);
        return true;
    };
    if !process.clear_blocked_wait_registration(thread_ref.thread_id, wake.token) {
        return true;
    }

    if syscall::poll_blocked(process, thread_ref.thread_id, now_ns, &context.requests)
        == syscall::BlockedPoll::Pending
    {
        let _ = arm_blocked_thread(context, thread_ref);
        return true;
    }

    unsafe { process.address_space().activate() };
    let _ = syscall::complete_blocked(process, thread_ref.thread_id, &mut context.frames);
    unsafe { context.page_table.activate() };
    let completed_ns = context.timer.clock().now_ns();
    let _ = context
        .user_scheduler
        .cancel_donations_from(thread_ref, completed_ns);
    record_process_scheduler_snapshots(context, thread_ref.process_id);
    if let Some(snapshot) = context
        .user_scheduler
        .snapshot(thread_ref)
        .filter(|snapshot| snapshot.state == SchedulerThreadState::Blocked)
    {
        let policy = context.user_scheduler.policy(snapshot.effective_class);
        let service_deadline_ns =
            if wake.cause == WakeCause::Deadline && wake.kind == WaitKind::Sleep {
                wake.deadline_ns
                    .unwrap_or(completed_ns)
                    .saturating_add(policy.period_ns)
            } else {
                completed_ns.saturating_add(policy.wake_latency_target_ns)
            };
        let _ = context
            .user_scheduler
            .set_deadline(thread_ref, service_deadline_ns);
        let _ = context.user_scheduler.wake(thread_ref, completed_ns);
        if wake.cause == WakeCause::Deadline {
            context.urgent_process_dispatch = true;
        }
    }
    true
}

fn urgent_process_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    if !context.urgent_process_dispatch {
        return TaskPoll::Pending;
    }
    context.urgent_process_dispatch = false;
    let _ = process_task(context, state);
    process_task(context, state)
}

fn process_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
    let now_ns = context.timer.clock().now_ns();
    let policy_dispatch = context.user_scheduler.next_dispatch(now_ns);
    let (selected, dispatch_quantum_ns, selected_by_policy) =
        if let Some(dispatch) = policy_dispatch {
            (dispatch.key, dispatch.quantum_ns, true)
        } else if let Some(thread_ref) = context.processes.next_terminal_thread() {
            (thread_ref, 0, false)
        } else {
            return TaskPoll::Pending;
        };
    let ThreadRef {
        process_id,
        thread_id,
    } = selected;

    let child_slot_reserved =
        context.processes.prepare_insert().is_ok() && !context.process_creation_pending;
    let mut created_child = None;
    let mut dispatch_elapsed_ns = 0;
    #[cfg(ginkgo_memory_policy_smoke)]
    let mut memory_policy_explicit_yield = false;
    {
        let Some(process) = context.processes.get_mut(process_id) else {
            return TaskPoll::Pending;
        };
        if process.thread(thread_id).is_none() {
            return TaskPoll::Pending;
        }
        if process.termination_requested() {
            process.mark_terminated();
        }

        match process
            .thread_state(thread_id)
            .expect("selected thread disappeared during dispatch")
        {
            ThreadState::Ready => {
                unsafe { process.address_space().activate() };
                let entry_stacks = process
                    .thread_entry_stack_tops(thread_id)
                    .expect("selected thread lost its protected entry stacks");
                let mut user_context = *process
                    .thread_context(thread_id)
                    .expect("selected thread lost its context");
                let started_ns = context.timer.clock().now_ns();
                let mut timer_slice_ns = if selected_by_policy {
                    dispatch_quantum_ns
                } else {
                    process.limits().cpu_quantum_ns
                };
                let next_deadline_ns = match (
                    context.waits.next_deadline_ns(),
                    context.requests.next_deadline_ns(),
                ) {
                    (Some(wait), Some(request)) => Some(wait.min(request)),
                    (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                    (None, None) => None,
                };
                if let Some(deadline_ns) = next_deadline_ns {
                    timer_slice_ns =
                        timer_slice_ns.min(deadline_ns.saturating_sub(started_ns).max(1));
                }
                if context.timer.arm_one_shot(timer_slice_ns).is_err() {
                    process.fault_process(
                        thread_id,
                        ProcessFault::new(ProcessFaultReason::InvalidUserContext, 0),
                    );
                } else {
                    let exit =
                        unsafe { arch::enter_user_on_stacks(&mut user_context, entry_stacks) };
                    context.timer.disarm();
                    match exit {
                        Ok(KernelExit::YieldToKernel) => {
                            let heap_committed = context.kernel_heap.committed_bytes();
                            let heap_available = context.kernel_heap.available_bytes() as u64;
                            debug_assert!(heap_available <= heap_committed);
                            let kernel_heap_stats = syscall::KernelHeapStats {
                                committed_bytes: heap_committed,
                                available_bytes: heap_available,
                                growth_failures: context.kernel_heap.failed_growth_count(),
                            };
                            let syscall_number = user_context.rax;
                            let mut sink = SerialDebugSink::new(&mut context.serial);
                            let mut filesystem_queue = ProcessFilesystemQueue {
                                executor: &mut context.filesystem_executor,
                                bridges: &mut context.filesystem_bridges,
                                root_directory: context.filesystem_root,
                                thread: ThreadRef {
                                    process_id,
                                    thread_id,
                                },
                                process_creation_pending: &mut context.process_creation_pending,
                            };
                            let outcome = syscall::dispatch(
                                process_id,
                                process,
                                thread_id,
                                &mut user_context,
                                context.timer.clock().now_ns(),
                                &context.page_table,
                                &mut context.frames,
                                kernel_heap_stats,
                                &context.shared_frame_arena,
                                &mut filesystem_queue,
                                &mut context.audio,
                                &mut context.entropy,
                                &mut context.requests,
                                !context.launch_quiesced,
                                child_slot_reserved,
                                &mut sink,
                            );
                            debug_assert!(
                                matches!(
                                    &outcome,
                                    SyscallOutcome::Yield
                                        | SyscallOutcome::Blocked
                                        | SyscallOutcome::ThreadExited(_)
                                        | SyscallOutcome::ChildCreated(_)
                                ) || !process.is_runnable(),
                                "exit syscall must update process state"
                            );
                            #[cfg(ginkgo_memory_policy_smoke)]
                            if syscall_number == 0 && matches!(outcome, SyscallOutcome::Yield) {
                                memory_policy_explicit_yield = true;
                            }
                            if matches!(syscall_number, 0 | 55)
                                && matches!(outcome, SyscallOutcome::Yield)
                            {
                                let _ = context.user_scheduler.clear_deadline(ThreadRef {
                                    process_id,
                                    thread_id,
                                });
                            }
                            if let SyscallOutcome::ChildCreated(child) = outcome {
                                created_child = Some(child);
                            }
                        }
                        Ok(KernelExit::Preempted) => {
                            assert!(process.record_thread_preemption(thread_id));
                            if !context.preemption_observed {
                                context.preemption_observed = true;
                                let mut sink = SerialDebugSink::new(&mut context.serial);
                                let _ = writeln!(sink, "scheduler: timer preemption verified\r");
                            }
                        }
                        Ok(KernelExit::Fault(fault)) => {
                            if fault.vector == 14 {
                                let fault_address = fault
                                    .fault_address
                                    .expect("page-fault exit must include CR2");
                                match process.resolve_thread_user_page_fault(
                                    thread_id,
                                    fault_address,
                                    fault.error_code,
                                    user_context.rsp,
                                    &mut context.frames,
                                ) {
                                    UserPageFaultResolution::Resolved { .. } => {}
                                    UserPageFaultResolution::Fault(fault) => {
                                        process.fault_process(thread_id, fault);
                                    }
                                }
                            } else {
                                let reason = match fault.vector {
                                    13 => ProcessFaultReason::GeneralProtection,
                                    6 => ProcessFaultReason::InvalidOpcode,
                                    vector => ProcessFaultReason::Other(
                                        u16::try_from(vector).unwrap_or(u16::MAX),
                                    ),
                                };
                                process.fault_process(
                                    thread_id,
                                    ProcessFault {
                                        reason,
                                        code: fault.error_code,
                                        address: fault.fault_address,
                                    },
                                );
                            }
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
                            process.fault_process(
                                thread_id,
                                ProcessFault::new(ProcessFaultReason::InvalidUserContext, 1),
                            );
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
                            process.fault_process(
                                thread_id,
                                ProcessFault::new(ProcessFaultReason::InvalidUserContext, 2),
                            );
                        }
                    }
                }
                process.record_retirement_context(thread_id, user_context);
                *process
                    .thread_context_mut(thread_id)
                    .expect("selected thread lost its context") = user_context;
                let elapsed_ns = context.timer.clock().now_ns().saturating_sub(started_ns);
                dispatch_elapsed_ns = elapsed_ns;
                assert!(process.record_thread_cpu_time(thread_id, elapsed_ns));
            }
            ThreadState::Blocked => {
                let now_ns = context.timer.clock().now_ns();
                if syscall::poll_blocked(process, thread_id, now_ns, &context.requests)
                    == syscall::BlockedPoll::Complete
                {
                    unsafe { process.address_space().activate() };
                    let _ = syscall::complete_blocked(process, thread_id, &mut context.frames);
                }
            }
            ThreadState::Exited(_) | ThreadState::Faulted(_) | ThreadState::Terminated => {}
        }
    }

    unsafe { context.page_table.activate() };
    if selected_by_policy {
        let thread_ref = ThreadRef {
            process_id,
            thread_id,
        };
        match context
            .processes
            .get(process_id)
            .and_then(|process| process.thread_state(thread_id))
        {
            Some(ThreadState::Ready) => {
                let _ = context.user_scheduler.finish_dispatch(
                    thread_ref,
                    dispatch_elapsed_ns,
                    context.timer.clock().now_ns(),
                    RunDisposition::Runnable,
                );
            }
            Some(ThreadState::Blocked) => {
                let blocked_ns = context.timer.clock().now_ns();
                let _ = context.user_scheduler.finish_dispatch(
                    thread_ref,
                    dispatch_elapsed_ns,
                    blocked_ns,
                    RunDisposition::Blocked,
                );
                donate_for_blocked_join(context, thread_ref, blocked_ns);
                let _ = arm_blocked_thread(context, thread_ref);
            }
            Some(ThreadState::Exited(_) | ThreadState::Faulted(_) | ThreadState::Terminated)
            | None => {
                let _ = context
                    .user_scheduler
                    .remove_thread(thread_ref, context.timer.clock().now_ns());
            }
        }
    }
    synchronize_process_scheduler(context, process_id);
    let mut terminal_request_owners = [None; ginkgo_kernel::process::MAX_THREADS_PER_PROCESS];
    let mut terminal_request_owner_count = 0usize;
    if let Some(process) = context.processes.get(process_id) {
        for local_thread_id in process.thread_ids() {
            if process
                .thread_state(local_thread_id)
                .is_some_and(ThreadState::is_terminal)
            {
                terminal_request_owners[terminal_request_owner_count] =
                    Some(ginkgo_kernel::request::RequestOwner::new(
                        process_id.raw(),
                        local_thread_id.raw(),
                    ));
                terminal_request_owner_count += 1;
            }
        }
    }
    for owner in terminal_request_owners[..terminal_request_owner_count]
        .iter()
        .flatten()
        .copied()
    {
        context
            .requests
            .terminate_thread(owner, context.timer.clock().now_ns());
    }
    notify_completed_joins(context, process_id);
    if let Some(process) = context.processes.get(process_id) {
        for local_thread_id in process.thread_ids() {
            if process
                .thread_state(local_thread_id)
                .is_some_and(|state| state != ThreadState::Blocked)
            {
                let thread_ref = ThreadRef {
                    process_id,
                    thread_id: local_thread_id,
                };
                let _ = context.waits.cancel_key(thread_ref);
                let _ = context
                    .user_scheduler
                    .cancel_donations_from(thread_ref, context.timer.clock().now_ns());
            }
        }
    }
    if let Some(snapshot) = context.user_scheduler.snapshot(ThreadRef {
        process_id,
        thread_id,
    }) {
        if let Some(process) = context.processes.get_mut(process_id) {
            process.record_scheduler_snapshot(thread_id, snapshot);
        }
    }
    loop {
        let detached = context.processes.get(process_id).and_then(|process| {
            (!process.state().is_terminal())
                .then(|| process.next_detached_terminal_thread())
                .flatten()
        });
        let Some(detached) = detached else {
            break;
        };
        let detached_ref = ThreadRef {
            process_id,
            thread_id: detached,
        };
        let detached_owner =
            ginkgo_kernel::request::RequestOwner::new(process_id.raw(), detached.raw());
        context
            .requests
            .terminate_thread(detached_owner, context.timer.clock().now_ns());
        if !context.requests.is_thread_drained(detached_owner) {
            break;
        }
        if context.user_scheduler.snapshot(detached_ref).is_some() {
            let _ = context
                .user_scheduler
                .remove_thread(detached_ref, context.timer.clock().now_ns());
        }
        if context
            .processes
            .get_mut(process_id)
            .expect("process disappeared before detached-thread reap")
            .reap_thread(detached, &mut context.frames)
            .is_err()
        {
            break;
        }
    }
    #[cfg(ginkgo_memory_policy_smoke)]
    if memory_policy_explicit_yield {
        if let Err(reason) = inspect_memory_policy_yield(context, process_id) {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "ginkgo-memory-policy-smoke: FAIL yield inspection {reason}\r"
            );
            halt_forever();
        }
    }
    if let Some(child) = created_child {
        let child_id = context
            .processes
            .insert(*child)
            .expect("reserved child process insertion must succeed");
        synchronize_process_scheduler(context, child_id);
    }
    let Some(final_state) = context.processes.get(process_id).map(Process::state) else {
        return TaskPoll::Pending;
    };
    if !final_state.is_terminal() {
        return TaskPoll::Pending;
    }
    if let Some(process) = context.processes.get(process_id) {
        process.publish_terminal_status();
    }
    context
        .requests
        .terminate_process(process_id.raw(), context.timer.clock().now_ns());
    if !context.requests.is_process_drained(process_id.raw()) {
        return TaskPoll::Pending;
    }

    #[cfg(ginkgo_memory_policy_smoke)]
    let memory_policy_phase = if context
        .memory_policy_smoke
        .as_ref()
        .is_some_and(|smoke| smoke.current == Some(process_id))
    {
        match validate_memory_policy_terminal(context, process_id, final_state) {
            Ok(phase) => Some(phase),
            Err(reason) => {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "ginkgo-memory-policy-smoke: FAIL {reason} state={final_state:?}\r"
                );
                halt_forever();
            }
        }
    } else {
        None
    };
    let preemption_count = context
        .processes
        .get(process_id)
        .map(Process::preemption_count)
        .unwrap_or(0);
    let is_preemption_smoke = context.preemption_smoke_id == Some(process_id);
    let is_process_capability_smoke = context.process_capability_smoke_id == Some(process_id);
    let is_frame_reclaim_stress = context
        .frame_reclaim_stress
        .as_ref()
        .is_some_and(|stress| stress.current == Some(process_id));
    if let Some(process) = context.processes.get(process_id) {
        for thread_id in process.thread_ids() {
            let thread_ref = ThreadRef {
                process_id,
                thread_id,
            };
            if context.user_scheduler.snapshot(thread_ref).is_some() {
                let _ = context
                    .user_scheduler
                    .remove_thread(thread_ref, context.timer.clock().now_ns());
            }
        }
    }
    let _ = context.process_terminations.cancel_key(process_id);
    let Some(process) = context.processes.take_for_retirement(process_id) else {
        return TaskPoll::Pending;
    };
    let retired = match process.retire() {
        Ok(retired) => retired,
        Err(_) => halt_forever(),
    };
    if context.focused_process_id == Some(process_id) {
        context.focused_process_id = None;
    }
    if let Some(index) = context
        .process_clients
        .iter()
        .position(|known| known.process_id == process_id)
    {
        let removed_client = context.process_clients.swap_remove(index);
        removed_client.interactive_authority.revoke();
        let client_id = removed_client.client_id;
        let removed_windows = context
            .desktop
            .as_mut()
            .and_then(|desktop| desktop.cleanup_client(client_id).ok())
            .unwrap_or(0);
        if removed_windows != 0 {
            redraw_desktop(context);
        }
    }

    let retired_state = retired.final_state();
    let mut sink = SerialDebugSink::new(&mut context.serial);
    match retired_state {
        ProcessState::Exited(status) => {
            if !is_frame_reclaim_stress {
                let _ = writeln!(
                    sink,
                    "userspace: pid={} exited status={}\r",
                    process_id.raw(),
                    status
                );
            }
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
            if !is_frame_reclaim_stress {
                let _ = writeln!(
                    sink,
                    "userspace: pid={} faulted reason={:?} code={} address={:?}\r",
                    process_id.raw(),
                    fault.reason,
                    fault.code,
                    fault.address
                );
            }
        }
        ProcessState::Terminated => {
            if !is_frame_reclaim_stress {
                let _ = writeln!(
                    sink,
                    "userspace: pid={} externally terminated\r",
                    process_id.raw()
                );
            }
        }
        ProcessState::Ready | ProcessState::Blocked => {
            unreachable!("live process reached retirement")
        }
    }
    drop(sink);
    match retired.reclaim(&mut context.frames) {
        Ok(reclaimed) => {
            if !is_frame_reclaim_stress {
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "memory: pid={} reclaimed={} live={} free={} shared_live={}\r",
                    process_id.raw(),
                    reclaimed.frames.total_frames(),
                    context.frames.allocated_count(),
                    context.frames.free_count(),
                    shared_memory_backing_stats().live_objects
                );
            }
            if is_process_capability_smoke {
                context.process_capability_smoke_id = None;
                let mut sink = SerialDebugSink::new(&mut context.serial);
                if retired_state == ProcessState::Exited(0) {
                    let _ = writeln!(sink, "ginkgo-process-capability-smoke: PASS\r");
                } else {
                    let _ = writeln!(
                        sink,
                        "ginkgo-process-capability-smoke: FAIL parent state={retired_state:?}\r"
                    );
                }
            }
            if is_frame_reclaim_stress {
                let stress = context
                    .frame_reclaim_stress
                    .as_mut()
                    .expect("frame-reclaim stress state disappeared");
                debug_assert!(stress.pending_completion.is_none());
                stress.pending_completion = Some((process_id, retired_state));
            }
            #[cfg(ginkgo_memory_policy_smoke)]
            if let Some(phase) = memory_policy_phase {
                let smoke = context
                    .memory_policy_smoke
                    .as_mut()
                    .expect("memory policy smoke state disappeared");
                debug_assert!(smoke.pending_completion.is_none());
                smoke.pending_completion = Some((process_id, phase));
            }
        }
        Err(error) => {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "memory: process reclaim invariant failed: {error:?}\r"
            );
            let owner = error.into_process();
            core::mem::forget(owner);
            halt_forever();
        }
    }
    TaskPoll::Pending
}

fn power_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    const PROCESS_GRACE_NS: u64 = 1_000_000_000;

    let info = context.power_control.info();
    let Some(power_state) = info.power_state() else {
        context.power_control.fail(ginkgo_sysapi::Status::Io);
        return TaskPoll::Pending;
    };
    let sequence = usize::try_from(info.sequence).unwrap_or(usize::MAX);
    let phase = power_state as usize;
    let sequence_changed = state.get(0) != Some(sequence);
    let changed = sequence_changed || state.get(1) != Some(phase);
    if changed {
        state.set(0, sequence);
        state.set(1, phase);
        if sequence_changed {
            state.set(2, 0);
            state.set(3, 0);
        }
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "power: state={power_state:?} sequence={} deadline={}\r",
            info.sequence, info.deadline_ns
        );
    }

    match power_state {
        ginkgo_sysapi::SystemPowerState::Idle => {}
        ginkgo_sysapi::SystemPowerState::Requested => {
            if changed {
                let message = match info.power_action() {
                    Some(ginkgo_sysapi::SystemPowerAction::PowerOff) => {
                        "Power off requested; cancellation is still available"
                    }
                    Some(ginkgo_sysapi::SystemPowerAction::Reboot) => {
                        "Restart requested; cancellation is still available"
                    }
                    None => "Invalid power request",
                };
                context
                    .ui
                    .render_power_progress(&mut context.screen, message);
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(sink, "power: request accepted sequence={}\r", info.sequence);
            }
            let now_ns = context.timer.clock().now_ns();
            if now_ns >= info.deadline_ns {
                let acpi_supported =
                    context
                        .acpi_power
                        .as_ref()
                        .is_some_and(|power| match info.power_action() {
                            Some(ginkgo_sysapi::SystemPowerAction::PowerOff) => {
                                power.supports_power_off()
                            }
                            Some(ginkgo_sysapi::SystemPowerAction::Reboot) => {
                                power.supports_reboot()
                            }
                            None => false,
                        });
                if !acpi_supported {
                    context.power_control.fail(ginkgo_sysapi::Status::Io);
                    context.launch_quiesced = false;
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(sink, "power: preflight failed acpi=false\r");
                    redraw_desktop(context);
                    return TaskPoll::Pending;
                }

                context.launch_quiesced = true;
                context.launch_requested = None;
                if context
                    .power_control
                    .begin_quiescing(now_ns.saturating_add(PROCESS_GRACE_NS))
                {
                    let canceled_requests = context.requests.begin_shutdown(now_ns);
                    let close_requested = context
                        .desktop
                        .as_mut()
                        .is_some_and(|desktop| desktop.send_close_all_windows().is_ok());
                    context.ui.render_power_progress(
                        &mut context.screen,
                        "Stopping applications and services...",
                    );
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(
                        sink,
                        "power: launches quiesced orderly-close-requested={close_requested} requests-canceled={canceled_requests}\r"
                    );
                }
            }
        }
        ginkgo_sysapi::SystemPowerState::Quiescing => {
            let now_ns = context.timer.clock().now_ns();
            if now_ns >= info.deadline_ns {
                let terminated = context
                    .processes
                    .force_terminate_all_except(context.desktop_process_id);
                if terminated != 0 {
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(sink, "power: forced termination count={terminated}\r");
                }
                let retained_desktop = context
                    .desktop_process_id
                    .filter(|id| context.processes.get(*id).is_some());
                let non_desktop_processes = context
                    .processes
                    .len()
                    .saturating_sub(usize::from(retained_desktop.is_some()));
                if non_desktop_processes == 0
                    && context.requests.is_system_drained()
                    && context.power_control.begin_synchronizing()
                {
                    state.set(3, 0);
                    context.power_completion = None;
                    context.ui.render_power_progress(
                        &mut context.screen,
                        "Synchronizing filesystem and storage...",
                    );
                }
            }
        }
        ginkgo_sysapi::SystemPowerState::Synchronizing => {
            const SHUTDOWN_DRAIN_STEPS: usize = 4096;
            let phase = state.get(3).unwrap_or(0);
            if context.power_job.is_none() && context.power_completion.is_none() {
                let job = match phase {
                    0 => FsJob::CheckpointAndWait {
                        max_writeback_steps: SHUTDOWN_DRAIN_STEPS,
                    },
                    1 => FsJob::Quiesce,
                    2 => FsJob::ShutdownDrain {
                        max_writeback_steps: SHUTDOWN_DRAIN_STEPS,
                        shutdown_storage: true,
                    },
                    _ => return TaskPoll::Pending,
                };
                if let Ok(id) = enqueue_filesystem_job(
                    context,
                    job,
                    FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::Power),
                ) {
                    context.power_job = Some(id);
                }
                return TaskPoll::Pending;
            }
            let Some(completion) = context.power_completion.take() else {
                return TaskPoll::Pending;
            };
            let complete = match (phase, completion) {
                (0, Ok(FsResult::Durability(durability))) => durability.complete,
                (1, Ok(FsResult::Durability(_))) => true,
                (2, Ok(FsResult::Drain(report))) => report.complete,
                _ => false,
            };
            if !complete {
                context.power_control.fail(ginkgo_sysapi::Status::Io);
                context.ui.render_power_progress(
                    &mut context.screen,
                    "Storage shutdown failed; the system remains stopped",
                );
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "power: durability sequence failed phase={phase}; system remains quiesced\r"
                );
                return TaskPoll::Pending;
            }
            if phase < 2 {
                state.set(3, phase + 1);
                return TaskPoll::Pending;
            }

            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "power: quiesce, checkpoint, drain, and storage shutdown complete\r"
            );
            let _ = writeln!(sink, "power: committing action={:?}\r", info.power_action());
            drop(sink);
            let commit_deadline = context.timer.clock().now_ns().saturating_add(500_000_000);
            if !context.power_control.begin_committing(commit_deadline) {
                return TaskPoll::Pending;
            }
            context.ui.render_power_progress(
                &mut context.screen,
                "Committing firmware power transition...",
            );
            let result =
                context
                    .acpi_power
                    .as_ref()
                    .ok_or(())
                    .and_then(|power| match info.power_action() {
                        Some(ginkgo_sysapi::SystemPowerAction::PowerOff) => {
                            power.power_off().map_err(|_| ())
                        }
                        Some(ginkgo_sysapi::SystemPowerAction::Reboot) => {
                            power.reboot().map_err(|_| ())
                        }
                        None => Err(()),
                    });
            if result.is_err() {
                context.power_control.fail(ginkgo_sysapi::Status::Io);
                context
                    .ui
                    .render_power_progress(&mut context.screen, "Firmware power transition failed");
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(
                    sink,
                    "power: ACPI transition failed after durable shutdown\r"
                );
                drop(sink);
            }
        }
        ginkgo_sysapi::SystemPowerState::Canceled => {
            context.launch_quiesced = false;
            if context.power_job.is_some() {
                return TaskPoll::Pending;
            }
            if state.get(4) != Some(1) {
                context.power_completion = None;
                if let Ok(id) = enqueue_filesystem_job(
                    context,
                    FsJob::Resume,
                    FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::Power),
                ) {
                    context.power_job = Some(id);
                    state.set(4, 1);
                }
                return TaskPoll::Pending;
            }
            if context.power_completion.take().is_none() {
                return TaskPoll::Pending;
            }
            state.set(4, 0);
            context.requests.resume_after_shutdown_cancel();
            if changed {
                redraw_desktop(context);
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(sink, "power: request canceled after filesystem resume\r");
            }
        }
        ginkgo_sysapi::SystemPowerState::Committing => {
            if context.timer.clock().now_ns() >= info.deadline_ns {
                context.power_control.fail(ginkgo_sysapi::Status::TimedOut);
                context.ui.render_power_progress(
                    &mut context.screen,
                    "Firmware power transition timed out; the system remains stopped",
                );
                let mut sink = SerialDebugSink::new(&mut context.serial);
                let _ = writeln!(sink, "power: firmware transition timed out after storage shutdown; system remains quiesced\r");
            }
        }
        ginkgo_sysapi::SystemPowerState::Failed => {}
    }
    TaskPoll::Pending
}

fn complete_kernel_filesystem_job(
    context: &mut KernelContext,
    owner: KernelFilesystemOwner,
    result: Result<FsResult, FsExecutorError>,
) {
    let succeeded = result.is_ok();
    match owner {
        KernelFilesystemOwner::Writeback => {
            context.writeback_job = None;
            context.writeback_retry = matches!(result, Err(FsExecutorError::Writeback(_)));
        }
        KernelFilesystemOwner::SystemLog => {
            context.system_log_job = None;
            context.system_log_written = succeeded;
        }
        KernelFilesystemOwner::ConsoleLog { length } => {
            context.console_log_job = None;
            if succeeded {
                let consumed = length.min(context.pending_console_len);
                context
                    .pending_console
                    .copy_within(consumed..context.pending_console_len, 0);
                context.pending_console_len -= consumed;
            }
        }
        KernelFilesystemOwner::InputLog { length } => {
            context.input_log_job = None;
            if succeeded {
                let consumed = length.min(context.pending_input_len);
                context
                    .pending_input
                    .copy_within(consumed..context.pending_input_len, 0);
                context.pending_input_len -= consumed;
            }
        }
        KernelFilesystemOwner::Accounting => {
            context.accounting_job = None;
            context.accounting_written = succeeded;
        }
        KernelFilesystemOwner::Power => {
            context.power_job = None;
            context.power_completion = Some(result);
        }
    }
}

fn writeback_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    const WRITEBACK_INTERVAL_NS: u64 = 100_000_000;
    let now_ns = context.timer.clock().now_ns();
    let next_ns = state.get(0).unwrap_or(0) as u64;
    if now_ns < next_ns || context.writeback_job.is_some() {
        return TaskPoll::Pending;
    }
    let job = if context.writeback_retry {
        FsJob::RetryWritebackStep
    } else {
        FsJob::WritebackStep
    };
    if let Ok(id) = enqueue_filesystem_job(
        context,
        job,
        FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::Writeback),
    ) {
        context.writeback_job = Some(id);
        let next = now_ns.saturating_add(WRITEBACK_INTERVAL_NS);
        state.set(0, usize::try_from(next).unwrap_or(usize::MAX));
    }
    TaskPoll::Pending
}

fn filesystem_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    const MESSAGE: &[u8] = b"GinkgoOS: paging, RedoxFS, devices, and scheduler online\r\n";

    if !context.system_log_written && context.system_log_job.is_none() {
        if let Ok(id) = enqueue_filesystem_job(
            context,
            FsJob::ReplaceFile {
                path: String::from("/system.log"),
                data: Vec::from(MESSAGE),
            },
            FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::SystemLog),
        ) {
            context.system_log_job = Some(id);
        }
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

fn console_task(context: &mut KernelContext, _state: &mut TaskState) -> TaskPoll {
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

fn discard_unstarted_process(context: &mut KernelContext, process: Process) {
    let retired = match process.retire() {
        Ok(retired) => retired,
        Err(error) => {
            let process = error.into_process();
            core::mem::forget(process);
            halt_forever();
        }
    };
    if let Err(error) = retired.reclaim(&mut context.frames) {
        let owner = error.into_process();
        core::mem::forget(owner);
        halt_forever();
    }
}

fn reject_unstarted_client(
    context: &mut KernelContext,
    client_id: ClientId,
    process: Process,
) -> Result<(), ()> {
    if let Some(desktop) = context.desktop.as_mut() {
        let _ = desktop.cleanup_client(client_id);
    }
    discard_unstarted_process(context, process);
    Err(())
}

fn install_program_workspace(
    user_directory: ginkgo_filesystem::DirectoryHandle,
    process: &mut Process,
    program: ProgramSummary,
) -> Result<ginkgo_sysapi::Handle, ()> {
    let rights = ginkgo_sysapi::Rights::READ | ginkgo_sysapi::Rights::WRITE;
    if program.flags.contains(EntryFlags::FILESYSTEM) {
        let rights = if program.flags.contains(EntryFlags::PROCESS_LAUNCH) {
            rights | ginkgo_sysapi::Rights::EXECUTE
        } else {
            rights
        };
        return process
            .handles_mut()
            .filesystem_root_create_with_rights(rights)
            .map_err(|_| ());
    }

    process
        .handles_mut()
        .filesystem_directory_create(user_directory, rights)
        .map_err(|_| ())
}

fn launch_program(
    context: &mut KernelContext,
    program: ProgramSummary,
    startup: Option<ginkgo_sysapi::Handle>,
) -> Result<(), ()> {
    if context.launch_quiesced || context.process_creation_pending {
        return Err(());
    }
    context.processes.prepare_insert().map_err(|_| ())?;
    let maximum = usize::try_from(
        ginkgo_kernel::process::ProcessLimits::from_available_memory_bytes(
            context.frames.available_bytes(),
        )
        .executable_source_bytes,
    )
    .map_err(|_| ())?
    .min(ginkgo_kernel::fs_executor::WholeFileKind::Elf.maximum());
    let result = enqueue_filesystem_job(
        context,
        FsJob::PrepareProgramLaunch {
            executable_path: String::from(program.path()),
            application_id: String::from(program.app_id()),
            maximum,
        },
        FilesystemBridgeOwner::ProgramLaunch(PendingProgramLaunch { program, startup }),
    );
    if result.is_ok() {
        context.process_creation_pending = true;
    }
    result.map(|_| ()).map_err(|_| ())
}

fn complete_program_launch(
    context: &mut KernelContext,
    pending: PendingProgramLaunch,
    result: Result<FsResult, FsExecutorError>,
) {
    context.process_creation_pending = false;
    let FsResult::ProgramLaunch {
        image,
        application_data,
    } = (match result {
        Ok(result) => result,
        Err(_) => return,
    })
    else {
        return;
    };
    let manifest = match TrustedManifest::verify(TRUST_MANIFEST, TRUST_SIGNATURE, TRUST_PUBLIC_KEY)
    {
        Ok(manifest) => manifest,
        Err(_) => return,
    };
    if manifest
        .verify_artifact(pending.program.path(), &image)
        .is_err()
    {
        return;
    }
    let _ = finish_program_launch(
        context,
        pending.program,
        pending.startup,
        image,
        application_data,
    );
}

fn finish_program_launch(
    context: &mut KernelContext,
    program: ProgramSummary,
    startup: Option<ginkgo_sysapi::Handle>,
    image: Vec<u8>,
    _application_data_directory: ginkgo_filesystem::DirectoryHandle,
) -> Result<(), ()> {
    let randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let mut process =
        Process::from_elf_randomized(&image, &context.page_table, &mut context.frames, randomness)
            .map_err(|_| ())?;
    let application_data = match process
        .handles_mut()
        .application_data_create(program.app_id())
    {
        Ok(handle) => handle,
        Err(_) => {
            discard_unstarted_process(context, process);
            return Err(());
        }
    };
    if process.set_application_data(application_data).is_err() {
        discard_unstarted_process(context, process);
        return Err(());
    }

    let Some(client_id) = ClientId::new(context.next_client_id) else {
        discard_unstarted_process(context, process);
        return Err(());
    };
    let Some(next_client_id) = context.next_client_id.checked_add(1) else {
        discard_unstarted_process(context, process);
        return Err(());
    };
    if context.process_clients.try_reserve(1).is_err() {
        discard_unstarted_process(context, process);
        return Err(());
    }
    let channel = match context.desktop.as_mut().ok_or(()).and_then(|desktop| {
        desktop
            .connect_client(client_id, process.handles_mut())
            .map_err(|_| ())
    }) {
        Ok(channel) => channel,
        Err(()) => {
            discard_unstarted_process(context, process);
            return Err(());
        }
    };
    context.next_client_id = next_client_id;

    let filesystem = match install_program_workspace(context.user_directory, &mut process, program)
    {
        Ok(handle) => handle,
        Err(()) => return reject_unstarted_client(context, client_id, process),
    };
    let startup = match startup {
        Some(startup) => match context.desktop.as_mut().ok_or(()).and_then(|desktop| {
            desktop
                .move_startup_channel(startup, process.handles_mut())
                .map_err(|_| ())
        }) {
            Ok(handle) => handle,
            Err(()) => return reject_unstarted_client(context, client_id, process),
        },
        None => ginkgo_sysapi::Handle::INVALID,
    };
    let auxiliary = if program.app_id() == "terminal" {
        process
            .handles_mut()
            .system_power_install(&context.power_control)
    } else {
        process.handles_mut().random_source_create()
    };
    let auxiliary = match auxiliary {
        Ok(handle) => handle,
        Err(_) => return reject_unstarted_client(context, client_id, process),
    };
    let (interactive_authority, interactive_control) = match process
        .handles_mut()
        .scheduling_authority_create(ginkgo_sysapi::ThreadSchedulingClass::Interactive, false)
    {
        Ok(authority) => authority,
        Err(_) => return reject_unstarted_client(context, client_id, process),
    };
    process.set_start_arguments6([
        u64::from(channel.raw()),
        u64::from(filesystem.raw()),
        u64::from(startup.raw()),
        u64::from(auxiliary.raw()),
        u64::from(interactive_authority.raw()),
        0,
    ]);
    let process_id = context
        .processes
        .insert(process)
        .expect("prepared process insertion must succeed");
    synchronize_process_scheduler(context, process_id);
    context.process_clients.push(ProcessClient {
        process_id,
        client_id,
        launch_authority: RegistryLaunchAuthority::for_program(program),
        interactive_authority: interactive_control,
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

#[cfg(ginkgo_memory_policy_smoke)]
fn memory_policy_baseline(context: &KernelContext) -> FrameReclaimBaseline {
    let shared = shared_memory_backing_stats();
    let arena = context.shared_frame_arena.stats();
    FrameReclaimBaseline {
        live_frames: context.frames.allocated_count(),
        shared_live_objects: shared.live_objects,
        shared_logical_bytes: shared.logical_bytes,
        shared_mapped_bytes: shared.mapped_allocated_bytes,
        shared_arena_owned_frames: arena.owned_frames,
        shared_arena_free_frames: arena.free_frames,
    }
}

#[cfg(ginkgo_memory_policy_smoke)]
const MEMORY_POLICY_STACK_GROWTH_DISTANCE: u64 = 64 * 1024 + 256;

#[cfg(ginkgo_memory_policy_smoke)]
fn prepare_memory_policy_smoke(
    context: &mut KernelContext,
) -> Result<MemoryPolicySmoke, &'static str> {
    use ginkgo_kernel::memory::DMA_32BIT_ADDRESS_LIMIT;

    const HHDM_PATTERN: u64 = 0x4849_4748_4d45_4d21;
    context.frames.smoke_enable_high_policy();
    let initial = context.frames.stats();
    let case = if initial.total_eligible_bytes < 256 * 1024 * 1024 {
        MemoryPolicyCase::Low
    } else if initial.total_eligible_bytes < 1024 * 1024 * 1024 {
        MemoryPolicyCase::Normal
    } else {
        MemoryPolicyCase::High
    };
    let high_memory = initial.above_4g_frames != 0;
    if (case == MemoryPolicyCase::High) != high_memory {
        return Err("RAM class and high-frame availability disagree");
    }
    if high_memory {
        let frame = context
            .frames
            .allocate_frame_at_or_above(DMA_32BIT_ADDRESS_LIMIT)
            .map_err(|_| "high allocation error")?
            .ok_or("high allocation missing")?;
        if frame.start_address().as_u64() < DMA_32BIT_ADDRESS_LIMIT {
            return Err("high allocation below 4GiB");
        }
        let direct = context
            .hhdm_offset
            .checked_add(frame.start_address().as_u64())
            .ok_or("high HHDM address overflow")?;
        let pointer = NonNull::new(direct as *mut u64).ok_or("high HHDM null pointer")?;
        let value = unsafe { VolatilePtr::new(pointer) };
        value.write(HHDM_PATTERN);
        if value.read() != HHDM_PATTERN {
            return Err("high HHDM pattern mismatch");
        }
        context
            .frames
            .deallocate_frame(frame)
            .map_err(|_| "high frame reclaim failed")?;
    } else if initial.highest_usable_address >= DMA_32BIT_ADDRESS_LIMIT
        || initial.highest_issued_address >= DMA_32BIT_ADDRESS_LIMIT
    {
        return Err("low boot reported high usable or issued frame");
    }

    let dma = context
        .frames
        .allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)
        .map_err(|_| "DMA32 allocation error")?
        .ok_or("DMA32 allocation missing")?;
    if dma.start_address().as_u64() >= DMA_32BIT_ADDRESS_LIMIT {
        return Err("DMA32 allocation reached 4GiB");
    }
    context
        .frames
        .deallocate_frame(dma)
        .map_err(|_| "DMA32 reclaim failed")?;

    let stats = context.frames.stats();
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(
        sink,
        "ginkgo-memory-policy-smoke: stats class={} eligible_bytes={} above_4g_frames={} highest_usable={:#x} highest_issued={:#x} dma32={}\r",
        case.name(),
        stats.total_eligible_bytes,
        stats.above_4g_frames,
        stats.highest_usable_address,
        stats.highest_issued_address,
        stats.dma_low_allocations,
    );
    drop(sink);
    Ok(MemoryPolicySmoke {
        current: None,
        phase: MemoryPolicyPhase::Success,
        pending_completion: None,
        baseline: memory_policy_baseline(context),
        case,
        mapping_base: 0,
        expected_fault_address: 0,
        success_stage: MemoryPolicySuccessStage::SharedMapped,
        shared_frame: None,
        anonymous_frame: None,
    })
}

#[cfg(ginkgo_memory_policy_smoke)]
fn spawn_memory_policy_smoke(context: &mut KernelContext) -> Result<(), ()> {
    context.processes.prepare_insert().map_err(|_| ())?;
    let phase = context.memory_policy_smoke.as_ref().ok_or(())?.phase;
    let image = match phase {
        MemoryPolicyPhase::Success => MEMORY_POLICY_SUCCESS_ELF,
        MemoryPolicyPhase::Guard => MEMORY_POLICY_GUARD_ELF,
        MemoryPolicyPhase::ProtectFault => MEMORY_POLICY_PROTECT_FAULT_ELF,
        MemoryPolicyPhase::Oom => MEMORY_POLICY_OOM_ELF,
        MemoryPolicyPhase::Witness => MEMORY_POLICY_WITNESS_ELF,
    };
    let process =
        Process::from_elf(image, &context.page_table, &mut context.frames).map_err(|_| ())?;
    let mapping_base = process.next_mapping_cursor();
    let expected_fault_address = match phase {
        MemoryPolicyPhase::Guard => process.layout().stack_guard_start,
        MemoryPolicyPhase::ProtectFault => mapping_base,
        MemoryPolicyPhase::Oom => process
            .layout()
            .stack_top
            .saturating_sub(MEMORY_POLICY_STACK_GROWTH_DISTANCE),
        MemoryPolicyPhase::Success | MemoryPolicyPhase::Witness => 0,
    };
    let process_id = context
        .processes
        .insert(process)
        .expect("prepared memory policy smoke insertion must succeed");
    synchronize_process_scheduler(context, process_id);
    if phase == MemoryPolicyPhase::Oom {
        context.frames.smoke_fail_next_unrestricted_allocation();
    }
    let smoke = context
        .memory_policy_smoke
        .as_mut()
        .expect("memory policy smoke state disappeared");
    smoke.current = Some(process_id);
    smoke.mapping_base = mapping_base;
    smoke.expected_fault_address = expected_fault_address;
    smoke.success_stage = MemoryPolicySuccessStage::SharedMapped;
    smoke.shared_frame = None;
    smoke.anonymous_frame = None;
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(
        sink,
        "ginkgo-memory-policy-smoke: phase {} START pid={} expected_address={:#x}\r",
        phase.name(),
        process_id.raw(),
        expected_fault_address,
    );
    Ok(())
}

#[cfg(ginkgo_memory_policy_smoke)]
fn validate_smoke_mapping(
    process: &Process,
    address: u64,
) -> Result<Option<UserPageMapping>, &'static str> {
    process
        .address_space()
        .smoke_effective_mapping(address)
        .map_err(|_| "PTE and mapping metadata disagree")
}

#[cfg(ginkgo_memory_policy_smoke)]
fn inspect_memory_policy_yield(
    context: &mut KernelContext,
    process_id: ProcessId,
) -> Result<(), &'static str> {
    use ginkgo_kernel::memory::{DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE};

    let smoke = context
        .memory_policy_smoke
        .as_ref()
        .ok_or("state missing at explicit yield")?;
    if smoke.current != Some(process_id) {
        return Err("unexpected process yielded during smoke");
    }
    let phase = smoke.phase;
    let stage = smoke.success_stage;
    let mapping_base = smoke.mapping_base;
    let case = smoke.case;
    let process = context
        .processes
        .get(process_id)
        .ok_or("yielded process missing")?;

    let (next_stage, shared_frame, anonymous_frame, marker) = match (phase, stage) {
        (MemoryPolicyPhase::Success, MemoryPolicySuccessStage::SharedMapped) => {
            let mapping = validate_smoke_mapping(process, mapping_base)?
                .ok_or("shared mapping missing before unmap")?;
            if mapping.backing != UserMappingBacking::SharedAlias
                || mapping.permissions != UserPagePermissions::READ_WRITE
                || !context
                    .frames
                    .smoke_frame_is_live(mapping.frame.start_address().as_u64())
                || (case == MemoryPolicyCase::High
                    && mapping.frame.start_address().as_u64() < DMA_32BIT_ADDRESS_LIMIT)
            {
                return Err("shared mapping physical backing invalid");
            }
            (
                MemoryPolicySuccessStage::SharedUnmapped,
                Some(mapping.frame.start_address().as_u64()),
                None,
                "shared mapped",
            )
        }
        (MemoryPolicyPhase::Success, MemoryPolicySuccessStage::SharedUnmapped) => {
            if validate_smoke_mapping(process, mapping_base)?.is_some() {
                return Err("shared mapping survived explicit unmap");
            }
            let frame = smoke.shared_frame.ok_or("shared frame identity missing")?;
            if !context.frames.smoke_frame_is_reclaimed(frame) {
                return Err("shared backing was not reclaimed before process retirement");
            }
            (
                MemoryPolicySuccessStage::AnonymousProtected,
                Some(frame),
                None,
                "shared unmapped",
            )
        }
        (MemoryPolicyPhase::Success, MemoryPolicySuccessStage::AnonymousProtected) => {
            let address = mapping_base + PAGE_SIZE;
            let mapping = validate_smoke_mapping(process, address)?
                .ok_or("anonymous mapping missing after protect")?;
            if mapping.backing != UserMappingBacking::OwnedPrivate
                || mapping.permissions != UserPagePermissions::READ_ONLY
                || !context
                    .frames
                    .smoke_frame_is_live(mapping.frame.start_address().as_u64())
                || (case == MemoryPolicyCase::High
                    && mapping.frame.start_address().as_u64() < DMA_32BIT_ADDRESS_LIMIT)
            {
                return Err("anonymous mapping or protected PTE invalid");
            }
            (
                MemoryPolicySuccessStage::AnonymousUnmapped,
                None,
                Some(mapping.frame.start_address().as_u64()),
                "anonymous protected",
            )
        }
        (MemoryPolicyPhase::Success, MemoryPolicySuccessStage::AnonymousUnmapped) => {
            let address = mapping_base + PAGE_SIZE;
            if validate_smoke_mapping(process, address)?.is_some() {
                return Err("anonymous mapping survived explicit unmap");
            }
            let frame = smoke
                .anonymous_frame
                .ok_or("anonymous frame identity missing")?;
            if !context.frames.smoke_frame_is_reclaimed(frame) {
                return Err("anonymous backing was not reclaimed before retirement");
            }
            (
                MemoryPolicySuccessStage::Complete,
                None,
                Some(frame),
                "anonymous reclaimed",
            )
        }
        (MemoryPolicyPhase::ProtectFault, _) => {
            let mapping = validate_smoke_mapping(process, mapping_base)?
                .ok_or("protect-fault mapping missing")?;
            if mapping.backing != UserMappingBacking::OwnedPrivate
                || mapping.permissions != UserPagePermissions::READ_ONLY
                || !context
                    .frames
                    .smoke_frame_is_live(mapping.frame.start_address().as_u64())
            {
                return Err("protect-fault PTE is not effective read-only");
            }
            (stage, None, None, "protect PTE read-only")
        }
        _ => return Err("unexpected explicit yield for smoke phase"),
    };

    let smoke = context
        .memory_policy_smoke
        .as_mut()
        .expect("smoke state disappeared after inspection");
    smoke.success_stage = next_stage;
    if let Some(frame) = shared_frame {
        smoke.shared_frame = Some(frame);
    }
    if let Some(frame) = anonymous_frame {
        smoke.anonymous_frame = Some(frame);
    }
    let frame = shared_frame.or(anonymous_frame).unwrap_or(0);
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let address = if marker.starts_with("anonymous") {
        mapping_base + PAGE_SIZE
    } else {
        mapping_base
    };
    let _ = writeln!(
        sink,
        "ginkgo-memory-policy-smoke: inspect {marker} address={address:#x} frame={frame:#x}\r"
    );
    if marker == "shared unmapped" {
        let _ = writeln!(
            sink,
            "ginkgo-memory-policy-smoke: inspect shared reclaimed address={address:#x} frame={frame:#x}\r"
        );
    }
    Ok(())
}

#[cfg(ginkgo_memory_policy_smoke)]
fn validate_memory_policy_terminal(
    context: &KernelContext,
    process_id: ProcessId,
    state: ProcessState,
) -> Result<MemoryPolicyPhase, &'static str> {
    let smoke = context
        .memory_policy_smoke
        .as_ref()
        .ok_or("state missing")?;
    if smoke.current != Some(process_id) {
        return Err("retired unexpected process");
    }
    let process = context.processes.get(process_id).ok_or("process missing")?;
    let grew_stack = process.usage().private_pages
        > ginkgo_kernel::process::USER_STACK_INITIAL_SIZE / ginkgo_kernel::memory::PAGE_SIZE + 1;
    let exact_fault = |reason, require_write: bool| {
        matches!(
            state,
            ProcessState::Faulted(ProcessFault {
                reason: actual,
                code,
                address: Some(address),
            }) if actual == reason
                && address == smoke.expected_fault_address
                && (!require_write || code & 0b111 == 0b111)
        )
    };
    match smoke.phase {
        MemoryPolicyPhase::Success if state != ProcessState::Exited(0) => {
            Err("mapping process did not exit cleanly")
        }
        MemoryPolicyPhase::Success if !grew_stack => Err("mapping process stack did not grow"),
        MemoryPolicyPhase::Success if smoke.success_stage != MemoryPolicySuccessStage::Complete => {
            Err("mapping process skipped a live inspection stage")
        }
        MemoryPolicyPhase::Guard if !exact_fault(ProcessFaultReason::PageFault, false) => {
            Err("guard process fault reason or address mismatch")
        }
        MemoryPolicyPhase::ProtectFault if !exact_fault(ProcessFaultReason::PageFault, true) => {
            Err("protect-write fault reason, code, or address mismatch")
        }
        MemoryPolicyPhase::Oom if !exact_fault(ProcessFaultReason::OutOfMemory, false) => {
            Err("OOM process fault reason or address mismatch")
        }
        MemoryPolicyPhase::Witness if state != ProcessState::Exited(0) => {
            Err("witness process did not exit cleanly")
        }
        MemoryPolicyPhase::Witness if !grew_stack => Err("witness stack did not grow"),
        phase => Ok(phase),
    }
}

#[cfg(ginkgo_memory_policy_smoke)]
fn finish_memory_policy_smoke(
    context: &mut KernelContext,
    process_id: ProcessId,
    phase: MemoryPolicyPhase,
) {
    let current = memory_policy_baseline(context);
    let smoke = context
        .memory_policy_smoke
        .as_mut()
        .expect("memory policy smoke state disappeared");
    if smoke.current != Some(process_id) || smoke.phase != phase {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "ginkgo-memory-policy-smoke: FAIL completion order\r");
        halt_forever();
    }
    let warmup_complete = phase == MemoryPolicyPhase::Success;
    if !warmup_complete
        && (current.live_frames != smoke.baseline.live_frames
            || current.shared_live_objects != smoke.baseline.shared_live_objects
            || current.shared_logical_bytes != smoke.baseline.shared_logical_bytes
            || current.shared_mapped_bytes != smoke.baseline.shared_mapped_bytes
            || current.shared_arena_owned_frames != smoke.baseline.shared_arena_owned_frames
            || current.shared_arena_free_frames != smoke.baseline.shared_arena_free_frames)
    {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "ginkgo-memory-policy-smoke: FAIL reclaim invariant phase={phase:?} frames={}->{} shared={}->{} arena={}->{}\r",
            smoke.baseline.live_frames,
            current.live_frames,
            smoke.baseline.shared_live_objects,
            current.shared_live_objects,
            smoke.baseline.shared_arena_owned_frames,
            current.shared_arena_owned_frames,
        );
        halt_forever();
    }
    if warmup_complete {
        smoke.baseline = current;
    }
    let expected_address = smoke.expected_fault_address;
    let (reason, address) = match phase {
        MemoryPolicyPhase::Success | MemoryPolicyPhase::Witness => ("Exited", None),
        MemoryPolicyPhase::Guard | MemoryPolicyPhase::ProtectFault => {
            ("PageFault", Some(expected_address))
        }
        MemoryPolicyPhase::Oom => ("OutOfMemory", Some(expected_address)),
    };
    let mut sink = SerialDebugSink::new(&mut context.serial);
    if let Some(address) = address {
        let _ = writeln!(
            sink,
            "ginkgo-memory-policy-smoke: phase {} PASS reason={} address={:#x}\r",
            phase.name(),
            reason,
            address,
        );
    } else {
        let _ = writeln!(
            sink,
            "ginkgo-memory-policy-smoke: phase {} PASS reason={} address=none\r",
            phase.name(),
            reason,
        );
    }
    drop(sink);
    smoke.current = None;
    let next = match phase {
        MemoryPolicyPhase::Success => Some(MemoryPolicyPhase::Guard),
        MemoryPolicyPhase::Guard => Some(MemoryPolicyPhase::ProtectFault),
        MemoryPolicyPhase::ProtectFault => Some(MemoryPolicyPhase::Oom),
        MemoryPolicyPhase::Oom => Some(MemoryPolicyPhase::Witness),
        MemoryPolicyPhase::Witness => None,
    };
    if let Some(next) = next {
        smoke.phase = next;
        if spawn_memory_policy_smoke(context).is_err() {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(sink, "ginkgo-memory-policy-smoke: FAIL phase launch\r");
            halt_forever();
        }
        return;
    }

    let stats = context.frames.stats();
    if (smoke.case != MemoryPolicyCase::High
        && stats.highest_issued_address >= ginkgo_kernel::memory::DMA_32BIT_ADDRESS_LIMIT)
        || (smoke.case == MemoryPolicyCase::High
            && stats.highest_issued_address < ginkgo_kernel::memory::DMA_32BIT_ADDRESS_LIMIT)
    {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "ginkgo-memory-policy-smoke: FAIL final high-memory policy\r"
        );
        halt_forever();
    }
    let case = smoke.case.name();
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(sink, "ginkgo-memory-policy-smoke: {case} PASS\r");
    halt_forever();
}

fn spawn_process_capability_smoke(context: &mut KernelContext) -> Result<(), ()> {
    context.processes.prepare_insert().map_err(|_| ())?;
    let randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let mut process = Process::from_elf_randomized(
        PROCESS_CAPABILITY_SMOKE_ELF,
        &context.page_table,
        &mut context.frames,
        randomness,
    )
    .map_err(|_| ())?;
    let root = match process.handles_mut().filesystem_root_create_with_rights(
        ginkgo_sysapi::Rights::READ | ginkgo_sysapi::Rights::WRITE | ginkgo_sysapi::Rights::EXECUTE,
    ) {
        Ok(root) => root,
        Err(_) => {
            discard_unstarted_process(context, process);
            return Err(());
        }
    };
    process.set_start_arguments([u64::from(root.raw()), 0, 0, 0]);
    let process_id = context
        .processes
        .insert(process)
        .expect("prepared process capability smoke insertion must succeed");
    synchronize_process_scheduler(context, process_id);
    context.process_capability_smoke_id = Some(process_id);
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(
        sink,
        "scheduler: process capability smoke started pid={}\r",
        process_id.raw()
    );
    Ok(())
}

fn spawn_request_smoke(context: &mut KernelContext) -> Result<(), ()> {
    context.processes.prepare_insert().map_err(|_| ())?;
    let randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let mut process = Process::from_elf_randomized(
        REQUEST_SMOKE_ELF,
        &context.page_table,
        &mut context.frames,
        randomness,
    )
    .map_err(|_| ())?;
    let root = match process.handles_mut().filesystem_root_create_with_rights(
        ginkgo_sysapi::Rights::READ | ginkgo_sysapi::Rights::WRITE,
    ) {
        Ok(root) => root,
        Err(_) => {
            discard_unstarted_process(context, process);
            return Err(());
        }
    };
    process.set_start_arguments([u64::from(root.raw()), 0, 0, 0]);
    let process_id = context
        .processes
        .insert(process)
        .expect("prepared request smoke insertion must succeed");
    synchronize_process_scheduler(context, process_id);
    let mut sink = SerialDebugSink::new(&mut context.serial);
    let _ = writeln!(
        sink,
        "scheduler: request smoke started pid={}\r",
        process_id.raw()
    );
    Ok(())
}

fn spawn_frame_reclaim_stress(context: &mut KernelContext) -> Result<(), ()> {
    context.processes.prepare_insert().map_err(|_| ())?;
    let completed = context.frame_reclaim_stress.as_ref().ok_or(())?.completed;
    let image = if completed % 2 == 0 {
        FRAME_RECLAIM_EXIT_ELF
    } else {
        FRAME_RECLAIM_FAULT_ELF
    };
    let randomness = [
        context.entropy.next_u64(),
        context.entropy.next_u64(),
        context.entropy.next_u64(),
    ];
    let fresh_before = context.frames.fresh_issued_count();
    let process =
        Process::from_elf_randomized(image, &context.page_table, &mut context.frames, randomness)
            .map_err(|_| ())?;
    let fresh_after = context.frames.fresh_issued_count();
    if completed > 0 && fresh_after != fresh_before {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "frame-reclaim stress fresh allocation cycle={} fresh={}->{}\r",
            completed, fresh_before, fresh_after
        );
        halt_forever();
    }
    let process_id = context
        .processes
        .insert(process)
        .expect("prepared frame-reclaim stress insertion must succeed");
    synchronize_process_scheduler(context, process_id);
    let stress = context
        .frame_reclaim_stress
        .as_mut()
        .expect("stress state disappeared");
    stress.current = Some(process_id);
    stress.reuse_verified += u32::from(completed > 0);
    Ok(())
}

fn finish_frame_reclaim_stress(
    context: &mut KernelContext,
    process_id: ProcessId,
    final_state: ProcessState,
) {
    let Some(stress) = context.frame_reclaim_stress.as_mut() else {
        return;
    };
    if stress.current != Some(process_id) {
        return;
    }
    let expected_normal_exit = stress.completed % 2 == 0;
    let state_matches = if expected_normal_exit {
        final_state == ProcessState::Exited(0)
    } else {
        matches!(
            final_state,
            ProcessState::Faulted(ProcessFault {
                reason: ProcessFaultReason::InvalidOpcode,
                ..
            })
        )
    };
    if !state_matches {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "frame-reclaim stress unexpected state cycle={} state={final_state:?}\r",
            stress.completed
        );
        halt_forever();
    }

    stress.current = None;
    stress.completed += 1;
    let shared = shared_memory_backing_stats();
    let arena = context.shared_frame_arena.stats();
    let current = FrameReclaimBaseline {
        live_frames: context.frames.allocated_count(),
        shared_live_objects: shared.live_objects,
        shared_logical_bytes: shared.logical_bytes,
        shared_mapped_bytes: shared.mapped_allocated_bytes,
        shared_arena_owned_frames: arena.owned_frames,
        shared_arena_free_frames: arena.free_frames,
    };
    match stress.baseline {
        None => stress.baseline = Some(current),
        Some(baseline)
            if baseline.live_frames != current.live_frames
                || baseline.shared_live_objects != current.shared_live_objects
                || baseline.shared_logical_bytes != current.shared_logical_bytes
                || baseline.shared_mapped_bytes != current.shared_mapped_bytes
                || baseline.shared_arena_owned_frames != current.shared_arena_owned_frames
                || baseline.shared_arena_free_frames != current.shared_arena_free_frames =>
        {
            let mut sink = SerialDebugSink::new(&mut context.serial);
            let _ = writeln!(
                sink,
                "frame-reclaim stress leak cycle={} frames={}->{} shared_objects={}->{} shared_bytes={}->{}\r",
                stress.completed,
                baseline.live_frames,
                current.live_frames,
                baseline.shared_live_objects,
                current.shared_live_objects,
                baseline.shared_mapped_bytes,
                current.shared_mapped_bytes
            );
            halt_forever();
        }
        Some(_) => {}
    }

    if stress.completed == FRAME_RECLAIM_STRESS_CYCLES {
        let baseline = stress.baseline.expect("stress baseline missing");
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "frame-reclaim stress passed cycles={} reuse_checks={} baseline_live={} final_live={} reusable={} baseline_shared={} final_shared={}\r",
            stress.completed,
            stress.reuse_verified,
            baseline.live_frames,
            current.live_frames,
            context.frames.free_count(),
            baseline.shared_live_objects,
            current.shared_live_objects
        );
        return;
    }
    if spawn_frame_reclaim_stress(context).is_err() {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "frame-reclaim stress respawn failed\r");
        halt_forever();
    }
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

fn refresh_process_scheduler_classes(context: &mut KernelContext, process_id: ProcessId) {
    let mut updates = [None; ginkgo_kernel::process::MAX_THREADS_PER_PROCESS];
    let mut count = 0usize;
    if let Some(process) = context.processes.get(process_id) {
        for thread_id in process.thread_ids() {
            updates[count] = process
                .thread_scheduling_class(thread_id)
                .map(|class| (thread_id, class));
            count += 1;
        }
    }
    let now_ns = context.timer.clock().now_ns();
    for (thread_id, class) in updates[..count].iter().flatten().copied() {
        let thread_ref = ThreadRef {
            process_id,
            thread_id,
        };
        if context.user_scheduler.snapshot(thread_ref).is_some() {
            let _ = context.user_scheduler.set_base_class_with_authority(
                thread_ref,
                class,
                scheduler_authority(class),
                now_ns,
            );
        }
    }
}

fn apply_focused_process_policy(context: &mut KernelContext, focused_client: Option<ClientId>) {
    let focused = focused_client.and_then(|client_id| {
        context
            .process_clients
            .iter()
            .find(|known| known.client_id == client_id)
            .map(|known| known.process_id)
    });
    if context.focused_process_id == focused {
        return;
    }
    if let Some(previous) = context.focused_process_id.take() {
        if let Some(client) = context
            .process_clients
            .iter()
            .find(|known| known.process_id == previous)
        {
            client.interactive_authority.revoke();
        }
        if let Some(process) = context.processes.get_mut(previous) {
            process.set_focused_interactive(false);
        }
        refresh_process_scheduler_classes(context, previous);
    }
    if let Some(current) = focused {
        if let Some(client) = context
            .process_clients
            .iter()
            .find(|known| known.process_id == current)
        {
            client.interactive_authority.activate();
        }
        if let Some(process) = context.processes.get_mut(current) {
            process.set_focused_interactive(true);
            context.focused_process_id = Some(current);
        }
        refresh_process_scheduler_classes(context, current);
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

    let mut shared_memory = SharedMemoryFactory::new(
        &context.shared_frame_arena,
        &mut context.frames,
        &context.page_table,
    );
    let event = match context
        .desktop
        .as_mut()
        .map(|desktop| desktop.poll_desktop(&mut shared_memory))
    {
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
                    if text_editor_smoke_enabled() {
                        let result = context
                            .ui
                            .catalog
                            .find("text-editor")
                            .ok_or(())
                            .and_then(|program| launch_program(context, program, None));
                        if result.is_err() {
                            let mut sink = SerialDebugSink::new(&mut context.serial);
                            let _ = writeln!(sink, "text-editor-smoke: failure\r");
                        }
                    }
                }
                let should_start_stress = context
                    .frame_reclaim_stress
                    .as_ref()
                    .is_some_and(|stress| stress.current.is_none() && stress.completed == 0);
                if should_start_stress && spawn_frame_reclaim_stress(context).is_err() {
                    let mut sink = SerialDebugSink::new(&mut context.serial);
                    let _ = writeln!(sink, "frame-reclaim stress failed to start\r");
                    halt_forever();
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
                let authorized = context.process_clients.iter().any(|known| {
                    known.client_id == requester && known.launch_authority.allows(&app_id)
                });
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
            DesktopRuntimeEvent::PlacementsChanged { focused_client, .. } => {
                apply_focused_process_policy(context, focused_client);
                redraw_desktop(context);
            }
            DesktopRuntimeEvent::WindowDestroyed { .. } => redraw_desktop(context),
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

fn request_desktop_power(context: &mut KernelContext, action: ginkgo_sysapi::SystemPowerAction) {
    if context.ui.power_confirmation != Some(action) {
        context.ui.power_confirmation = Some(action);
        redraw_desktop(context);
        return;
    }
    context.ui.power_confirmation = None;
    let deadline = context.timer.clock().now_ns().saturating_add(2_000_000_000);
    if context
        .power_control
        .request(action, ginkgo_sysapi::SystemPowerFlags::empty(), deadline)
        .is_err()
    {
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(sink, "power: desktop request rejected\r");
        redraw_desktop(context);
    }
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

const KEY_REPEAT_DELAY_NS: u64 = 400_000_000;
const KEY_REPEAT_INTERVAL_NS: u64 = 35_000_000;
const KEY_REPEAT_STATE_WORD: usize = 0;
const KEY_REPEAT_DEADLINE_WORD: usize = 7;
const KEY_REPEAT_USAGE_BITS: usize = 17;
const KEY_REPEAT_USAGE_MASK: usize = (1 << KEY_REPEAT_USAGE_BITS) - 1;
const KEY_REPEAT_LAUNCHER_FLAG: usize = 1 << KEY_REPEAT_USAGE_BITS;
const KEY_REPEAT_DEVICE_SHIFT: usize = KEY_REPEAT_USAGE_BITS + 1;
const KEY_REPEAT_INTERFACE_SHIFT: usize = KEY_REPEAT_DEVICE_SHIFT + 32;

fn input_task(context: &mut KernelContext, state: &mut TaskState) -> TaskPoll {
    if context.input.is_none() {
        return TaskPoll::Pending;
    }
    let summary = {
        let (input, frames) = (&mut context.input, &mut context.frames);
        let Some(input) = input.as_mut() else {
            return TaskPoll::Pending;
        };
        input.poll_with_resources(frames, context.hhdm_offset)
    };
    let summary = match summary {
        Ok(summary) => summary,
        Err(error) => {
            context.ui.input_available = false;
            context.ui.completion_code = usb_error_completion_code(error);
            context.ui.input_status = usb_error_status(error);
            context.ui.render_status(&mut context.screen);
            return TaskPoll::Pending;
        }
    };

    let old_cursor = (
        context.ui.mouse_x,
        context.ui.mouse_y,
        context.ui.mouse_pressed,
    );
    let mut disconnected = Vec::new();
    while let Some(interface) = context
        .input
        .as_mut()
        .and_then(InputManager::pop_disconnected)
    {
        disconnected.push(interface);
    }
    for interface in disconnected {
        release_disconnected_input(context, state, interface);
    }

    if summary.interfaces_added != 0 || summary.interfaces_removed != 0 {
        let diagnostics = context
            .input
            .as_ref()
            .map(InputManager::interrupt_diagnostics)
            .unwrap_or_default();
        let mut sink = SerialDebugSink::new(&mut context.serial);
        let _ = writeln!(
            sink,
            "USB hotplug: added={} removed={} live={} interrupts={} watchdog={} deferred={} dropped={} recycled={} frames={}\r",
            summary.interfaces_added,
            summary.interfaces_removed,
            context
                .input
                .as_ref()
                .map_or(0, InputManager::usable_interface_count),
            diagnostics.interrupts_observed,
            diagnostics.watchdog_polls,
            diagnostics.deferred_events,
            diagnostics.dropped_deferred_events,
            context
                .input
                .as_ref()
                .map_or(0, InputManager::recycled_dma_pages),
            context.frames.allocated_count()
        );
    }

    let usable = context
        .input
        .as_ref()
        .is_some_and(|input| input.usable_interface_count() != 0);
    context.ui.input_available = usable;
    let receiving_status = "USB HID: receiving reports - mouse and keyboard active";
    let waiting_status = "USB HID: waiting for a keyboard or pointing device";
    let desired_status = if usable && summary.reports != 0 {
        receiving_status
    } else if usable {
        "USB HID: ready - move the mouse and type below"
    } else {
        waiting_status
    };
    let status_dirty = summary.interfaces_added != 0
        || summary.interfaces_removed != 0
        || context.ui.input_status != desired_status;
    if status_dirty {
        context.ui.input_status = desired_status;
        context.ui.completion_code = None;
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
    if let Some((start, end)) = dispatch_key_repeat(context, state) {
        context
            .ui
            .render_text_range(&mut context.screen, start, end);
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

fn update_pressed<T: Eq + Copy>(pressed: &mut Vec<T>, value: T, is_pressed: bool) {
    if is_pressed {
        if !pressed.contains(&value) {
            pressed.push(value);
        }
    } else {
        pressed.retain(|candidate| *candidate != value);
    }
}

fn refresh_modifier_state(context: &KernelContext, state: &mut TaskState) {
    for (word, left, right) in [
        (1, 0xe1, 0xe5),
        (4, 0xe0, 0xe4),
        (5, 0xe2, 0xe6),
        (3, 0xe3, 0xe7),
    ] {
        let mut bits = 0;
        if context.pressed_keys.iter().any(|(_, usage)| *usage == left) {
            bits |= 1;
        }
        if context
            .pressed_keys
            .iter()
            .any(|(_, usage)| *usage == right)
        {
            bits |= 2;
        }
        state.set(word, bits);
    }
}

fn release_disconnected_input(
    context: &mut KernelContext,
    state: &mut TaskState,
    interface: ginkgo_kernel::usb::HidInterfaceId,
) {
    let released_keys: Vec<u16> = context
        .pressed_keys
        .iter()
        .filter_map(|(owner, usage)| (*owner == interface).then_some(*usage))
        .collect();
    context
        .pressed_keys
        .retain(|(owner, _)| *owner != interface);
    let active_repeat = key_repeat_state(state).map(|(owner, usage, _)| (owner, usage));
    if active_repeat
        .is_some_and(|(owner, usage)| owner == interface && released_keys.contains(&usage))
    {
        cancel_key_repeat(state);
    }
    refresh_modifier_state(context, state);
    let modifiers = current_modifiers(state);
    if let Some(desktop) = context.desktop.as_mut() {
        for usage in released_keys {
            let _ = desktop.send_keyboard_input(KeyboardEvent {
                usage,
                state: ButtonState::Released,
                repeat: false,
                modifiers,
            });
        }
    }

    let released_buttons: Vec<u16> = context
        .pressed_pointer_buttons
        .iter()
        .filter_map(|(owner, button)| (*owner == interface).then_some(*button))
        .collect();
    context
        .pressed_pointer_buttons
        .retain(|(owner, _)| *owner != interface);
    if released_buttons.contains(&1) {
        let primary_still_pressed = context
            .pressed_pointer_buttons
            .iter()
            .any(|(_, button)| *button == 1);
        context.ui.set_mouse_button(primary_still_pressed);
    }
    if let Some(desktop) = context.desktop.as_mut() {
        for button in released_buttons.into_iter().filter_map(pointer_button) {
            let _ = desktop.send_pointer_input(
                WindowPoint::new(context.ui.mouse_x as i32, context.ui.mouse_y as i32),
                PointerEventKind::Button {
                    button,
                    state: ButtonState::Released,
                },
            );
        }
    }
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

fn key_repeat_state(state: &TaskState) -> Option<(ginkgo_kernel::usb::HidInterfaceId, u16, bool)> {
    let encoded = state.get(KEY_REPEAT_STATE_WORD).unwrap_or(0);
    let usage = (encoded & KEY_REPEAT_USAGE_MASK)
        .checked_sub(1)
        .and_then(|usage| u16::try_from(usage).ok())?;
    let device = u32::try_from((encoded >> KEY_REPEAT_DEVICE_SHIFT) & u32::MAX as usize).ok()?;
    let interface = ((encoded >> KEY_REPEAT_INTERFACE_SHIFT) & u8::MAX as usize) as u8;
    Some((
        ginkgo_kernel::usb::HidInterfaceId { device, interface },
        usage,
        encoded & KEY_REPEAT_LAUNCHER_FLAG != 0,
    ))
}

fn arm_key_repeat(
    context: &KernelContext,
    state: &mut TaskState,
    interface: ginkgo_kernel::usb::HidInterfaceId,
    usage: u16,
) {
    let deadline = context
        .timer
        .clock()
        .now_ns()
        .saturating_add(KEY_REPEAT_DELAY_NS);
    let encoded = usize::from(usage) + 1
        | usize::from(context.ui.launcher_visible) * KEY_REPEAT_LAUNCHER_FLAG
        | (interface.device as usize) << KEY_REPEAT_DEVICE_SHIFT
        | (usize::from(interface.interface)) << KEY_REPEAT_INTERFACE_SHIFT;
    state.set(KEY_REPEAT_STATE_WORD, encoded);
    state.set(KEY_REPEAT_DEADLINE_WORD, deadline as usize);
}

fn cancel_key_repeat(state: &mut TaskState) {
    state.set(KEY_REPEAT_STATE_WORD, 0);
    state.set(KEY_REPEAT_DEADLINE_WORD, 0);
}

fn dispatch_key_repeat(
    context: &mut KernelContext,
    state: &mut TaskState,
) -> Option<(usize, usize)> {
    let (interface, usage, launcher_visible) = key_repeat_state(state)?;
    if launcher_visible != context.ui.launcher_visible
        || !context.pressed_keys.contains(&(interface, usage))
    {
        cancel_key_repeat(state);
        return None;
    }
    let now = context.timer.clock().now_ns();
    if now < state.get(KEY_REPEAT_DEADLINE_WORD).unwrap_or(usize::MAX) as u64 {
        return None;
    }
    state.set(
        KEY_REPEAT_DEADLINE_WORD,
        now.saturating_add(KEY_REPEAT_INTERVAL_NS) as usize,
    );
    dispatch_keyboard_event(context, state, usage, true, true)
}

fn dispatch_keyboard_event(
    context: &mut KernelContext,
    state: &TaskState,
    usage: u16,
    pressed: bool,
    repeat: bool,
) -> Option<(usize, usize)> {
    let logo = state.get(3).unwrap_or(0) != 0;
    if pressed && !repeat && usage == 0x11 && logo {
        request_launcher_toggle(context);
    } else if context.ui.launcher_visible {
        if pressed && !repeat && usage == 0x29 && context.ui.power_confirmation.take().is_some() {
            redraw_desktop(context);
        } else if pressed && !repeat && usage == 0x28 && context.ui.catalog.len != 0 {
            context.launch_requested = Some(0);
        } else if pressed {
            let modifiers = current_modifiers(state);
            if let Some(byte) = keyboard_ascii(usage, modifiers.shift, modifiers.caps_lock) {
                return context.ui.push_byte(byte);
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
            repeat,
            modifiers: current_modifiers(state),
        });
    }
    None
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
            let key = (device_event.interface, usage);
            let was_pressed = context.pressed_keys.contains(&key);
            update_pressed(&mut context.pressed_keys, key, pressed);
            refresh_modifier_state(context, state);
            if usage == 0x39 && pressed && !was_pressed {
                state.set(2, state.get(2).unwrap_or(0) ^ 1);
            } else if usage == 0x53 && pressed && !was_pressed {
                state.set(6, state.get(6).unwrap_or(0) ^ 1);
            }

            let active_repeat = key_repeat_state(state).map(|(owner, usage, _)| (owner, usage));
            if !pressed && active_repeat == Some(key) {
                cancel_key_repeat(state);
            }
            let modifiers = current_modifiers(state);
            if modifiers.logo {
                cancel_key_repeat(state);
            } else if pressed && !was_pressed && usage < 0xe0 && usage != 0x39 && usage != 0x53 {
                arm_key_repeat(context, state, device_event.interface, usage);
            }

            text_dirty = dispatch_keyboard_event(context, state, usage, pressed, false);
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
            update_pressed(
                &mut context.pressed_pointer_buttons,
                (device_event.interface, button),
                pressed,
            );
            if button == 1 {
                let _ = context.ui.set_mouse_button(pressed);
            }
            if context.ui.launcher_visible {
                if button == 1 && pressed {
                    match context
                        .ui
                        .launcher_selection_at(context.ui.mouse_x, context.ui.mouse_y)
                    {
                        Some(LauncherSelection::Program(index)) => {
                            context.ui.power_confirmation = None;
                            context.launch_requested = Some(index);
                        }
                        Some(LauncherSelection::PowerOff) => request_desktop_power(
                            context,
                            ginkgo_sysapi::SystemPowerAction::PowerOff,
                        ),
                        Some(LauncherSelection::Reboot) => {
                            request_desktop_power(context, ginkgo_sysapi::SystemPowerAction::Reboot)
                        }
                        None => {
                            context.ui.power_confirmation = None;
                            redraw_desktop(context);
                        }
                    }
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

    if context.pending_console_len != 0 && context.console_log_job.is_none() {
        let length = context
            .pending_console_len
            .min(redoxfs::BLOCK_SIZE as usize);
        let data = Vec::from(&context.pending_console[..length]);
        if let Ok(id) = enqueue_filesystem_job(
            context,
            FsJob::AppendBoundedLog {
                path: String::from("/console"),
                data,
                limit: 64 * 1024,
            },
            FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::ConsoleLog { length }),
        ) {
            context.console_log_job = Some(id);
        }
    }
    if context.pending_input_len != 0 && context.input_log_job.is_none() {
        let length = context.pending_input_len.min(redoxfs::BLOCK_SIZE as usize);
        let data = Vec::from(&context.pending_input[..length]);
        if let Ok(id) = enqueue_filesystem_job(
            context,
            FsJob::AppendBoundedLog {
                path: String::from("/input"),
                data,
                limit: 64 * 1024,
            },
            FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::InputLog { length }),
        ) {
            context.input_log_job = Some(id);
        }
    }
    context.log_flush_deadline =
        if context.pending_console_len == 0 && context.pending_input_len == 0 {
            0
        } else {
            now.saturating_add(usb::timestamp_frequency().saturating_mul(LOG_FLUSH_DELAY_SECONDS))
        };
    TaskPoll::Pending
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

    if !context.accounting_written && context.accounting_job.is_none() {
        if let Ok(id) = enqueue_filesystem_job(
            context,
            FsJob::ReplaceFile {
                path: String::from("/scheduler"),
                data: Vec::from(ticks.to_le_bytes()),
            },
            FilesystemBridgeOwner::Kernel(KernelFilesystemOwner::Accounting),
        ) {
            context.accounting_job = Some(id);
        }
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
