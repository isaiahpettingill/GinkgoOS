use std::{collections::BTreeMap, env, fs, path::PathBuf};

use ginkgo_program_registry::{encode, EncodeEntry, EntryFlags, Registry};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const CODE_OFFSET: usize = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
const LOAD_ADDRESS: u64 = 0x0040_0000;
const PAGE_SIZE: u64 = 4096;

const PROCESS_YIELD: u32 = 0;
const PROCESS_EXIT: u32 = 1;
const HANDLE_CLOSE: u32 = 2;
const CHANNEL_WRITE: u32 = 6;
const CHANNEL_READ: u32 = 7;
const SHARED_MEMORY_CREATE: u32 = 8;
const SHARED_MEMORY_MAP: u32 = 10;
const SHARED_MEMORY_UNMAP: u32 = 11;
const DEBUG_WRITE: u32 = 12;

const SHARED_MEMORY_SIZE: u32 = 4097;
const MAP_PROTECTION_READ_WRITE: u32 = 3;
const STATUS_SHOULD_WAIT: i8 = -8;

// Desktop bootstrap protocol. Every message is exactly eight bytes. LauncherState's
// final byte is the current boolean launcher visibility (0 = hidden, 1 = visible).
const READY_MESSAGE: &[u8; 8] = b"GKREADY\0";
const TOGGLE_LAUNCHER_MESSAGE: &[u8; 8] = b"GKTOGGLE";
const LAUNCHER_STATE_MESSAGE: &[u8; 8] = b"GKLSTAT\0";

const ENTERED: &[u8] = b"ginkgo-userspace-smoke: entered\n";
const ALIAS: &[u8] = b"ginkgo-userspace-smoke: mapped alias\n";
const RESUMED: &[u8] = b"ginkgo-userspace-smoke: resumed\n";
const FAILURE: &[u8] = b"ginkgo-userspace-smoke: failure\n";

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let linker = manifest.join("linker.ld");
    println!("cargo:rerun-if-changed={}", linker.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GINKGO_DESKTOP_ELF");
    println!("cargo:rerun-if-env-changed=GINKGO_MINIMAL_CLIENT_ELF");
    println!("cargo:rustc-link-arg-bin=ginkgo-os=-T{}", linker.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    fs::write(
        out_dir.join("ginkgo-userspace-smoke.elf"),
        build_userspace_smoke_elf(),
    )
    .expect("write ginkgo userspace smoke ELF");
    let desktop = read_userspace_artifact("GINKGO_DESKTOP_ELF").unwrap_or_else(build_desktop_elf);
    let minimal_client = read_userspace_artifact("GINKGO_MINIMAL_CLIENT_ELF")
        .unwrap_or_else(build_userspace_smoke_elf);
    fs::write(out_dir.join("ginkgo-desktop.elf"), desktop).expect("write ginkgo desktop ELF");
    fs::write(out_dir.join("ginkgo-minimal-client.elf"), minimal_client)
        .expect("write Ginkgo minimal client ELF");
    fs::write(out_dir.join("programs.gkr"), build_program_registry())
        .expect("write Ginkgo program registry");
}

fn read_userspace_artifact(variable: &str) -> Option<Vec<u8>> {
    let path = PathBuf::from(env::var_os(variable)?);
    println!("cargo:rerun-if-changed={}", path.display());
    Some(fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {} from {}: {error}",
            variable,
            path.display()
        )
    }))
}

struct Fixup {
    displacement_offset: usize,
    next_instruction: usize,
    label: &'static str,
}

#[derive(Default)]
struct Assembler {
    bytes: Vec<u8>,
    labels: BTreeMap<&'static str, usize>,
    fixups: Vec<Fixup>,
}

impl Assembler {
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u32(&mut self, value: u32) {
        self.emit(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.emit(&value.to_le_bytes());
    }

    fn i8(&mut self, value: i8) {
        self.emit(&value.to_le_bytes());
    }

    fn label(&mut self, name: &'static str) {
        assert!(
            self.labels.insert(name, self.bytes.len()).is_none(),
            "duplicate assembler label: {name}"
        );
    }

    fn rel32(&mut self, instruction_prefix: &[u8], label: &'static str) {
        self.emit(instruction_prefix);
        let displacement_offset = self.bytes.len();
        self.u32(0);
        self.fixups.push(Fixup {
            displacement_offset,
            next_instruction: self.bytes.len(),
            label,
        });
    }

    fn checked_syscall(&mut self, number: u32) {
        self.emit(&[0xb8]); // mov eax, imm32
        self.u32(number);
        self.emit(&[0x0f, 0x05]); // syscall
        self.emit(&[0x48, 0x85, 0xc0]); // test rax, rax
        self.rel32(&[0x0f, 0x85], "failure"); // jne failure
    }

    fn debug_write(&mut self, label: &'static str, length: usize) {
        self.rel32(&[0x48, 0x8d, 0x3d], label); // lea rdi, [rip + label]
        self.emit(&[0xbe]); // mov esi, imm32
        self.u32(u32::try_from(length).expect("debug marker length fits in u32"));
        self.checked_syscall(DEBUG_WRITE);
    }

    fn finish(mut self) -> Vec<u8> {
        for fixup in self.fixups {
            let target = *self
                .labels
                .get(fixup.label)
                .unwrap_or_else(|| panic!("missing assembler label: {}", fixup.label));
            let target = i64::try_from(target).expect("label offset fits in i64");
            let next_instruction =
                i64::try_from(fixup.next_instruction).expect("instruction offset fits in i64");
            let displacement = i32::try_from(target - next_instruction)
                .unwrap_or_else(|_| panic!("rel32 target out of range: {}", fixup.label));
            let end = fixup
                .displacement_offset
                .checked_add(4)
                .expect("fixup range does not overflow");
            self.bytes[fixup.displacement_offset..end].copy_from_slice(&displacement.to_le_bytes());
        }
        self.bytes
    }
}

fn emit_userspace_smoke_code() -> Vec<u8> {
    let mut assembler = Assembler::default();

    assembler.label("entry");
    assembler.emit(&[0x48, 0x83, 0xe4, 0xf0]); // and rsp, -16
    assembler.emit(&[0x48, 0x83, 0xec, 0x30]); // sub rsp, 48
    assembler.debug_write("entered", ENTERED.len());

    // SharedMemoryCreate(4097, &handle_output).
    assembler.emit(&[0xbf]); // mov edi, imm32
    assembler.u32(SHARED_MEMORY_SIZE);
    assembler.emit(&[0x48, 0x8d, 0x34, 0x24]); // lea rsi, [rsp]
    assembler.checked_syscall(SHARED_MEMORY_CREATE);
    assembler.emit(&[0x44, 0x8b, 0x24, 0x24]); // mov r12d, [rsp]

    // Build SharedMemoryMapArgs at rsp + 16 and leave rsp + 8 for the output.
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x10]); // mov qword [rsp + 16], 0
    assembler.u32(0);
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x18]); // mov qword [rsp + 24], 0
    assembler.u32(0);
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x20]); // mov qword [rsp + 32], 4097
    assembler.u32(SHARED_MEMORY_SIZE);
    assembler.emit(&[0xc7, 0x44, 0x24, 0x28]); // mov dword [rsp + 40], RW
    assembler.u32(MAP_PROTECTION_READ_WRITE);
    assembler.emit(&[0xc7, 0x44, 0x24, 0x2c]); // mov dword [rsp + 44], no flags
    assembler.u32(0);

    // SharedMemoryMap(handle, &args, &output).
    assembler.emit(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    assembler.emit(&[0x48, 0x8d, 0x74, 0x24, 0x10]); // lea rsi, [rsp + 16]
    assembler.emit(&[0x48, 0x8d, 0x54, 0x24, 0x08]); // lea rdx, [rsp + 8]
    assembler.checked_syscall(SHARED_MEMORY_MAP);
    assembler.emit(&[0x4c, 0x8b, 0x6c, 0x24, 0x08]); // mov r13, [rsp + 8]

    // Copy the inline marker through the writable mapping.
    assembler.rel32(&[0x48, 0x8d, 0x35], "alias"); // lea rsi, [rip + alias]
    assembler.emit(&[0x4c, 0x89, 0xef]); // mov rdi, r13
    assembler.emit(&[0xb9]); // mov ecx, imm32
    assembler.u32(u32::try_from(ALIAS.len()).expect("alias marker length fits in u32"));
    assembler.emit(&[0xfc, 0xf3, 0xa4]); // cld; rep movsb

    // DebugWrite(mapped_alias, marker_length).
    assembler.emit(&[0x4c, 0x89, 0xef]); // mov rdi, r13
    assembler.emit(&[0xbe]); // mov esi, imm32
    assembler.u32(u32::try_from(ALIAS.len()).expect("alias marker length fits in u32"));
    assembler.checked_syscall(DEBUG_WRITE);

    assembler.checked_syscall(PROCESS_YIELD);
    assembler.debug_write("resumed", RESUMED.len());

    // Close the object handle while its mapping lease remains alive.
    assembler.emit(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    assembler.checked_syscall(HANDLE_CLOSE);

    // The alias must remain readable after the last handle is closed.
    assembler.emit(&[0x4c, 0x89, 0xef]); // mov rdi, r13
    assembler.emit(&[0xbe]); // mov esi, imm32
    assembler.u32(u32::try_from(ALIAS.len()).expect("alias marker length fits in u32"));
    assembler.checked_syscall(DEBUG_WRITE);

    // SharedMemoryUnmap(mapped_alias, 4097).
    assembler.emit(&[0x4c, 0x89, 0xef]); // mov rdi, r13
    assembler.emit(&[0xbe]); // mov esi, imm32
    assembler.u32(SHARED_MEMORY_SIZE);
    assembler.checked_syscall(SHARED_MEMORY_UNMAP);

    assembler.emit(&[0x31, 0xff]); // xor edi, edi
    assembler.checked_syscall(PROCESS_EXIT);
    assembler.emit(&[0x0f, 0x0b]); // ud2 if a successful exit unexpectedly returns

    assembler.label("failure");
    assembler.rel32(&[0x48, 0x8d, 0x3d], "failure_marker"); // lea rdi, [rip + marker]
    assembler.emit(&[0xbe]); // mov esi, imm32
    assembler.u32(u32::try_from(FAILURE.len()).expect("failure marker length fits in u32"));
    assembler.emit(&[0xb8]); // mov eax, DebugWrite
    assembler.u32(DEBUG_WRITE);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.emit(&[0xbf]); // mov edi, 1
    assembler.u32(1);
    assembler.emit(&[0xb8]); // mov eax, ProcessExit
    assembler.u32(PROCESS_EXIT);
    assembler.emit(&[0x0f, 0x05, 0x0f, 0x0b]); // syscall; ud2

    assembler.label("entered");
    assembler.emit(ENTERED);
    assembler.label("alias");
    assembler.emit(ALIAS);
    assembler.label("resumed");
    assembler.emit(RESUMED);
    assembler.label("failure_marker");
    assembler.emit(FAILURE);

    assembler.finish()
}

fn emit_desktop_code() -> Vec<u8> {
    let mut assembler = Assembler::default();

    assembler.label("desktop_entry");
    assembler.emit(&[0x48, 0x83, 0xe4, 0xf0]); // and rsp, -16
    assembler.emit(&[0x48, 0x83, 0xec, 0x70]); // sub rsp, 112
    assembler.emit(&[0x41, 0x89, 0xfc]); // mov r12d, edi (bootstrap channel)
    assembler.emit(&[0x45, 0x31, 0xed]); // xor r13d, r13d (launcher hidden)

    // ChannelWriteArgs at rsp points at the inline Ready message.
    assembler.rel32(&[0x48, 0x8d, 0x05], "desktop_ready"); // lea rax, [rip + ready]
    assembler.emit(&[0x48, 0x89, 0x04, 0x24]); // mov [rsp], rax
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x08]); // byte_count = 8
    assembler.u32(READY_MESSAGE.len() as u32);
    for offset in [0x10, 0x18, 0x20] {
        assembler.emit(&[0x48, 0xc7, 0x44, 0x24, offset]);
        assembler.u32(0);
    }

    // Retry Ready until it has been sent. This process intentionally never exits.
    assembler.label("desktop_ready_write");
    assembler.emit(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    assembler.emit(&[0x48, 0x89, 0xe6]); // mov rsi, rsp
    assembler.emit(&[0xb8]); // mov eax, ChannelWrite
    assembler.u32(CHANNEL_WRITE);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.emit(&[0x48, 0x85, 0xc0]); // test rax, rax
    assembler.rel32(&[0x0f, 0x84], "desktop_setup_read"); // je setup_read
    assembler.emit(&[0xb8]); // mov eax, ProcessYield
    assembler.u32(PROCESS_YIELD);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.rel32(&[0xe9], "desktop_ready_write"); // jmp ready_write

    assembler.label("desktop_setup_read");
    // ChannelReadArgs at rsp + 40 use an eight-byte buffer at rsp + 88,
    // no handle buffer, and ChannelReadOutput at rsp + 96.
    assembler.emit(&[0x48, 0x8d, 0x44, 0x24, 0x58]); // lea rax, [rsp + 88]
    assembler.emit(&[0x48, 0x89, 0x44, 0x24, 0x28]); // bytes_address
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x30]); // byte_capacity = 8
    assembler.u32(TOGGLE_LAUNCHER_MESSAGE.len() as u32);
    for offset in [0x38, 0x40] {
        assembler.emit(&[0x48, 0xc7, 0x44, 0x24, offset]);
        assembler.u32(0);
    }
    assembler.emit(&[0x48, 0x8d, 0x44, 0x24, 0x60]); // lea rax, [rsp + 96]
    assembler.emit(&[0x48, 0x89, 0x44, 0x24, 0x48]); // output_address
    assembler.emit(&[0x48, 0xc7, 0x44, 0x24, 0x50]); // flags and reserved = 0
    assembler.u32(0);

    // LauncherState is built in a separate eight-byte buffer at rsp + 104.
    assembler.emit(&[0x48, 0xb8]); // movabs rax, LauncherState template
    assembler.u64(u64::from_le_bytes(*LAUNCHER_STATE_MESSAGE));
    assembler.emit(&[0x48, 0x89, 0x44, 0x24, 0x68]); // mov [rsp + 104], rax

    assembler.label("desktop_read");
    assembler.emit(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    assembler.emit(&[0x48, 0x8d, 0x74, 0x24, 0x28]); // lea rsi, [rsp + 40]
    assembler.emit(&[0xb8]); // mov eax, ChannelRead
    assembler.u32(CHANNEL_READ);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.emit(&[0x48, 0x83, 0xf8]); // cmp rax, ShouldWait
    assembler.i8(STATUS_SHOULD_WAIT);
    assembler.rel32(&[0x0f, 0x84], "desktop_read_yield"); // je read_yield
    assembler.emit(&[0x48, 0x85, 0xc0]); // test rax, rax
    assembler.rel32(&[0x0f, 0x85], "desktop_read_yield"); // unexpected errors also retry

    assembler.emit(&[0x83, 0x7c, 0x24, 0x60, 0x08]); // cmp byte_count, 8
    assembler.rel32(&[0x0f, 0x85], "desktop_read"); // jne read
    assembler.emit(&[0x48, 0xb8]); // movabs rax, ToggleLauncher
    assembler.u64(u64::from_le_bytes(*TOGGLE_LAUNCHER_MESSAGE));
    assembler.emit(&[0x48, 0x39, 0x44, 0x24, 0x58]); // cmp [rsp + 88], rax
    assembler.rel32(&[0x0f, 0x85], "desktop_read"); // jne read

    assembler.emit(&[0x41, 0x80, 0xf5, 0x01]); // xor r13b, 1
    assembler.emit(&[0x44, 0x88, 0x6c, 0x24, 0x6f]); // state[7] = r13b
    assembler.emit(&[0x48, 0x8d, 0x44, 0x24, 0x68]); // lea rax, [rsp + 104]
    assembler.emit(&[0x48, 0x89, 0x04, 0x24]); // write args bytes_address = rax

    assembler.label("desktop_state_write");
    assembler.emit(&[0x44, 0x89, 0xe7]); // mov edi, r12d
    assembler.emit(&[0x48, 0x89, 0xe6]); // mov rsi, rsp
    assembler.emit(&[0xb8]); // mov eax, ChannelWrite
    assembler.u32(CHANNEL_WRITE);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.emit(&[0x48, 0x85, 0xc0]); // test rax, rax
    assembler.rel32(&[0x0f, 0x84], "desktop_read"); // je read
    assembler.emit(&[0xb8]); // mov eax, ProcessYield
    assembler.u32(PROCESS_YIELD);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.rel32(&[0xe9], "desktop_state_write"); // jmp state_write

    assembler.label("desktop_read_yield");
    assembler.emit(&[0xb8]); // mov eax, ProcessYield
    assembler.u32(PROCESS_YIELD);
    assembler.emit(&[0x0f, 0x05]); // syscall
    assembler.rel32(&[0xe9], "desktop_read"); // jmp read

    assembler.label("desktop_ready");
    assembler.emit(READY_MESSAGE);

    assembler.finish()
}

fn build_userspace_smoke_elf() -> Vec<u8> {
    build_userspace_elf(emit_userspace_smoke_code(), "smoke")
}

fn build_desktop_elf() -> Vec<u8> {
    build_userspace_elf(emit_desktop_code(), "desktop")
}

fn build_userspace_elf(code: Vec<u8>, artifact: &str) -> Vec<u8> {
    let file_size = CODE_OFFSET
        .checked_add(code.len())
        .unwrap_or_else(|| panic!("{artifact} ELF size does not overflow"));
    let file_size_u64 =
        u64::try_from(file_size).unwrap_or_else(|_| panic!("{artifact} ELF size fits in u64"));
    let entry = LOAD_ADDRESS
        .checked_add(u64::try_from(CODE_OFFSET).expect("code offset fits in u64"))
        .expect("smoke ELF entry does not overflow");

    let mut elf = Vec::with_capacity(file_size);
    elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    elf.extend_from_slice(&[0; 8]);
    push_u16(&mut elf, 2); // ET_EXEC
    push_u16(&mut elf, 62); // EM_X86_64
    push_u32(&mut elf, 1); // EV_CURRENT
    push_u64(&mut elf, entry);
    push_u64(&mut elf, ELF_HEADER_SIZE as u64); // e_phoff
    push_u64(&mut elf, 0); // e_shoff
    push_u32(&mut elf, 0); // e_flags
    push_u16(&mut elf, ELF_HEADER_SIZE as u16);
    push_u16(&mut elf, PROGRAM_HEADER_SIZE as u16);
    push_u16(&mut elf, 1); // e_phnum
    push_u16(&mut elf, 0); // e_shentsize
    push_u16(&mut elf, 0); // e_shnum
    push_u16(&mut elf, 0); // e_shstrndx
    assert_eq!(elf.len(), ELF_HEADER_SIZE);

    push_u32(&mut elf, 1); // PT_LOAD
    push_u32(&mut elf, 5); // PF_R | PF_X
    push_u64(&mut elf, 0); // p_offset
    push_u64(&mut elf, LOAD_ADDRESS);
    push_u64(&mut elf, LOAD_ADDRESS); // p_paddr
    push_u64(&mut elf, file_size_u64);
    push_u64(&mut elf, file_size_u64);
    push_u64(&mut elf, PAGE_SIZE);
    assert_eq!(elf.len(), CODE_OFFSET);

    elf.extend_from_slice(&code);
    assert_eq!(elf.len(), file_size);
    validate_userspace_elf(&elf);
    elf
}

fn validate_userspace_elf(elf: &[u8]) {
    assert_eq!(&elf[0..4], b"\x7fELF");
    assert_eq!(&elf[4..8], &[2, 1, 1, 0]);
    assert_eq!(read_u16(elf, 16), 2); // ET_EXEC
    assert_eq!(read_u16(elf, 18), 62); // EM_X86_64
    assert_eq!(read_u32(elf, 20), 1); // EV_CURRENT
    assert_eq!(read_u16(elf, 52) as usize, ELF_HEADER_SIZE);
    assert_eq!(read_u16(elf, 54) as usize, PROGRAM_HEADER_SIZE);
    assert_eq!(read_u16(elf, 56), 1);
    assert_eq!(read_u16(elf, 60), 0);

    let program_header_offset =
        usize::try_from(read_u64(elf, 32)).expect("program header offset fits in usize");
    let program_header_end = program_header_offset
        .checked_add(PROGRAM_HEADER_SIZE)
        .expect("program header range does not overflow");
    assert_eq!(program_header_offset, ELF_HEADER_SIZE);
    assert_eq!(program_header_end, CODE_OFFSET);
    assert!(program_header_end <= elf.len());

    let ph = program_header_offset;
    let flags = read_u32(elf, ph + 4);
    let segment_offset = read_u64(elf, ph + 8);
    let virtual_address = read_u64(elf, ph + 16);
    let file_size = read_u64(elf, ph + 32);
    let memory_size = read_u64(elf, ph + 40);
    let alignment = read_u64(elf, ph + 48);
    let entry = read_u64(elf, 24);

    assert_eq!(read_u32(elf, ph), 1); // PT_LOAD
    assert_eq!(flags, 5); // readable and executable, never writable
    assert_eq!(flags & 3, 1); // no W+X
    assert!(alignment >= PAGE_SIZE && alignment.is_power_of_two());
    assert_eq!(segment_offset % alignment, virtual_address % alignment);
    assert!(file_size <= memory_size);
    let file_end = segment_offset
        .checked_add(file_size)
        .expect("segment file range does not overflow");
    assert_eq!(
        file_end,
        u64::try_from(elf.len()).expect("ELF length fits in u64")
    );
    let virtual_end = virtual_address
        .checked_add(memory_size)
        .expect("segment virtual range does not overflow");
    assert!(entry >= virtual_address && entry < virtual_end);
    assert_ne!(flags & 1, 0); // entry is in an executable segment
    assert_eq!(entry, LOAD_ADDRESS + CODE_OFFSET as u64);
    assert!(u64::try_from(elf.len()).expect("ELF length fits in u64") <= PAGE_SIZE);
}

fn build_program_registry() -> Vec<u8> {
    let registry = encode(&[
        EncodeEntry {
            app_id: "desktop",
            display_name: "Ginkgo Desktop",
            executable_path: "/desktop.elf",
            flags: EntryFlags::HIDDEN,
        },
        EncodeEntry {
            app_id: "minimal-client",
            display_name: "Ginkgo Demo",
            executable_path: "/minimal-client.elf",
            flags: EntryFlags::EMPTY,
        },
    ])
    .expect("desktop registry metadata is valid");
    let parsed = Registry::parse(&registry).expect("generated program registry is valid");
    let desktop = parsed
        .entries()
        .next()
        .expect("desktop registry entry exists");
    assert_eq!(desktop.app_id, "desktop");
    assert_eq!(desktop.executable_path, "/desktop.elf");
    assert!(!desktop.is_visible());
    registry
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 range"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 range"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 range"))
}
