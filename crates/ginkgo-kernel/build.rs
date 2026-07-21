use std::{collections::BTreeMap, env, fs, path::PathBuf};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const CODE_OFFSET: usize = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
const LOAD_ADDRESS: u64 = 0x0040_0000;
const PAGE_SIZE: u64 = 4096;

const PROCESS_YIELD: u32 = 0;
const PROCESS_EXIT: u32 = 1;
const HANDLE_CLOSE: u32 = 2;
const SHARED_MEMORY_CREATE: u32 = 8;
const SHARED_MEMORY_MAP: u32 = 10;
const SHARED_MEMORY_UNMAP: u32 = 11;
const DEBUG_WRITE: u32 = 12;

const SHARED_MEMORY_SIZE: u32 = 4097;
const MAP_PROTECTION_READ_WRITE: u32 = 3;

const ENTERED: &[u8] = b"ginkgo-userspace-smoke: entered\n";
const ALIAS: &[u8] = b"ginkgo-userspace-smoke: mapped alias\n";
const RESUMED: &[u8] = b"ginkgo-userspace-smoke: resumed\n";
const FAILURE: &[u8] = b"ginkgo-userspace-smoke: failure\n";

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let linker = manifest.join("linker.ld");
    println!("cargo:rerun-if-changed={}", linker.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg-bin=ginkgo-os=-T{}", linker.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let elf = build_userspace_smoke_elf();
    fs::write(out_dir.join("ginkgo-userspace-smoke.elf"), elf)
        .expect("write ginkgo userspace smoke ELF");
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

fn build_userspace_smoke_elf() -> Vec<u8> {
    let code = emit_userspace_smoke_code();
    let file_size = CODE_OFFSET
        .checked_add(code.len())
        .expect("smoke ELF size does not overflow");
    let file_size_u64 = u64::try_from(file_size).expect("smoke ELF size fits in u64");
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
    validate_userspace_smoke_elf(&elf);
    elf
}

fn validate_userspace_smoke_elf(elf: &[u8]) {
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
