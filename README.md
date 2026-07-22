# GinkgoOS

A `no_std` x86-64 kernel written in Rust and booted through Limine over UEFI. GinkgoOS boots through an on-screen kernel log and splash into a persistent protected ring-3 desktop service with a program-registry-backed launcher. The kernel also includes framebuffer output, physical frame allocation, isolated userspace address spaces, syscalls and capability IPC, shared-memory mappings, checked device-I/O capabilities, polling xHCI USB HID input, polling Intel HDA audio, a kernel-adapted RedoxFS filesystem, and cooperative task/process scheduling.

## What is included

- Nightly Rust and the built-in `x86_64-unknown-none` target
- Limine framebuffer, memory-map, and higher-half direct-map requests
- Allocate-only 4 KiB physical frame allocation from usable memory
- `x86_64`-backed address types, active page-table translation, mapping, and unmapping
- Generation-tagged processes with isolated lower-half page tables and supervisor-only shared kernel mappings
- Strict ELF64 `ET_EXEC` loading, guarded user stacks, x86-64 ring-3 entry, and contained user faults
- `SYSCALL`/`SYSRET` dispatch plus `no_std` userspace stubs for processes, handles, channels, waits, shared memory, files, directories, and debug output
- Rights-checked shared-memory map/unmap with mapping leases that survive source-handle closure
- `x86_64` port I/O plus `volatile`-backed checked MMIO capabilities
- A nonblocking serial device built on `uart_16550`
- General PCI class discovery, a polling xHCI USB host controller, and polling Intel HDA output
- USB HID keyboards, mice, joysticks, and gamepads, including DragonRise Generic USB Joystick reports
- Descriptor-driven keyboard, button, axis, wheel, and hat-switch events in a bounded kernel input queue
- Process-local capability handles and bounded bidirectional datagram channels with atomic, rights-attenuating handle transfer
- Heap-backed shared-memory capabilities and protected two-buffer window pools
- A software compositor with clipping, hardware-format conversion, ARGB source-over blending, and complete-scene publication
- Production Rust desktop-service, file-navigator, and minimal-client ELFs built in the nested userspace workspace
- A persistent protected userspace desktop service and `META+N` launcher
- A strictly validated, versioned `.gkr` executable registry with hidden system entries
- A transport-independent scrolling desktop policy and application window protocol
- Packed bitmap-font rendering and a validated, versioned `.gkf` format
- Persistent RedoxFS transactions over a bounded-polling legacy ATA PIO disk backend
- Talc-backed dynamic allocation for RedoxFS and future kernel services
- Fixed-capacity round-robin cooperative task scheduling
- A high-half ELF linker script
- Embedded-graphics draw targets for volatile hardware framebuffers and ordinary XRGB/ARGB window RAM
- UEFI ISO and no-ISO QEMU boot targets

The scheduler is deliberately stackless and cooperative: each kernel task performs one bounded step, stores its continuation in `TaskState`, and returns to yield. A process task enters ring 3 until the application makes one syscall or faults, dispatches that syscall while the process CR3 remains active, restores the kernel CR3, and then yields to the next scheduler turn. USB input and Intel HDA audio follow the same model and poll their DMA rings without interrupts. The kernel does not yet provide independent kernel-task stacks, timer preemption, external interrupt delivery, SMP, or blocking waits.

### IPC groundwork

Each process owns a `ginkgo-ipc::HandleTable`. Handles are opaque generation-tagged integers carrying explicit rights. Channel endpoints are asynchronous and bidirectional, preserve datagram boundaries and ordering, and maintain a bounded queue in each direction. Messages carry up to 16 KiB and 16 atomically moved handles. Transfer dispositions can reduce the rights installed in the receiver; validation, queueing, and source-handle consumption remain atomic, so failed writes leave every source handle unchanged. Level-triggered `READABLE`, `WRITABLE`, and `PEER_CLOSED` state supports nonblocking wait-many scans under the current cooperative scheduler.

The same capability table holds zero-filled shared-memory objects and protected window client/manager endpoints. Production windows use two equal buffer slots per surface generation. A presented slot remains unavailable until its matching `BufferReleased` event; failed composition does not change ownership or emit a release. Resize is generation-staged: the compositor keeps the old displayed frame until the first frame from the new generation is successfully published, then retires the old pool and releases its final buffer.

Shared-memory objects are page-aligned, page-rounded, zero-filled heap allocations with a distinct logical length. Processes may map them read-only or read-write only when the capability has the corresponding `MAP`, `READ`, and optional `WRITE` rights. Each mapping retains an owning lease, so closing or transferring the source handle cannot invalidate a live alias; unmapping or retiring the process releases that lease only after its PTEs are unreachable. Window capabilities protect lifecycle and management authority, not pixel immutability: a holder of a writable alias can still violate the presentation contract by modifying an in-flight buffer before its `BufferReleased` event.

`ginkgo-sysapi` defines append-only syscall numbers and fixed-layout argument blocks alongside the handle, rights, object type, signal, status, wait, mapping, filesystem, and RPC-header contracts. Filesystem syscalls cover open/create, positional read/write, stat, root-directory enumeration, truncate, and unlink. Files and the filesystem root are generation-protected process-local capabilities; only registry entries carrying `EntryFlags::FILESYSTEM` receive a root capability, and file capabilities cannot be duplicated or transferred. Kernel-owned executables, the registry, and kernel logs remain readable but reject userspace write, truncate, and unlink operations. Structured messages use a 24-byte `zerocopy` RPC header followed by a `postcard` payload; the kernel channel remains unaware of application protocols. `ginkgo-userspace` exposes inline x86-64 syscall stubs, ergonomic wrappers, the codec, and the transport-independent window facade without pulling in the kernel handle backend. Wait-many currently performs one nonblocking signal poll; scheduler wait queues and deadline-aware blocking remain future work.

### Protected userspace execution

At boot, after device initialization has installed its kernel mappings, GinkgoOS installs `/desktop.elf`, `/file-navigator.elf`, `/minimal-client.elf`, and `/programs.gkr` into RedoxFS and reads them back through the filesystem adapter. It validates the registry and desktop ELF, then creates an isolated page-table root for the desktop process. The process root starts with an empty lower half and clones only the kernel higher-half topology, clearing `USER_ACCESSIBLE` on every cloned P4 entry even when Limine supplied permissive flags. User mappings reject the zero page, noncanonical or higher-half addresses, writable-executable pages, overlaps, and permission-invalid copies.

The dependency-free ELF loader accepts only little-endian x86-64 `ET_EXEC` images in the Ginkgo executable profile. It validates every program header, mapped range, page overlap, permission, entry point, and stack/guard collision before installing image pages. Each process owns its address space, generation-tagged identity, register and x87/SSE state, capability table, shared mappings, and detailed exit/fault state.

The x86-64 entry path installs a GDT, TSS, IDT, `STAR`/`LSTAR`/`FMASK`, and five distinct 64 KiB supervisor stacks for RSP0, syscall entry, double fault, NMI, and machine check. Synchronous user exceptions are contained and returned to the process scheduler; kernel faults and unrecoverable exception classes fail stop. Every syscall immediately switches away from the untrusted user RSP, captures the complete user context, and returns to scheduler-side dispatch. Return through `SYSRETQ` revalidates canonical RIP/RSP, flags, and floating-point state.

Normal Makefile builds first compile the production Rust `ginkgo-desktop-service`, `ginkgo-file-navigator`, and `ginkgo-minimal-client` release ELFs from the independent `userspace/` workspace. The kernel build consumes and embeds those artifacts with the generated registry; they become `/desktop.elf`, `/file-navigator.elf`, `/minimal-client.elf`, and `/programs.gkr` in the boot filesystem. The desktop receives only one bootstrap channel plus the display dimensions. Every launched app receives its per-app desktop channel, while only registry-authorized apps receive a filesystem-root capability. The service remains resident, announces readiness, owns launcher and window policy, polls bounded channels cooperatively, and yields when idle. A successful serial trace includes:

```text
desktop: loaded /desktop.elf from RedoxFS pid=...
desktop: protected Rust userland ready
```

The build script retains generated smoke ELFs for focused execution testing, but they are not the production binaries used by normal Makefile builds.

Current execution limitations are intentional and explicit:

- Scheduling is single-core and cooperative. A process that never makes a syscall can monopolize the CPU until timer preemption exists.
- Interrupts remain disabled while userspace runs; there is no external IRQ entry or asynchronous preemption path yet.
- Wait-many is a single nonblocking poll, not a scheduler-backed blocking operation.
- SMAP is not enabled because checked user-copy operations do not yet have exception-fixup support.
- x87/SSE/SSE2 state is isolated with FXSAVE/FXRSTOR; AVX/XSAVE is intentionally unavailable.
- The physical allocator is monotonic, so retired process frames are accounted for but not recycled.
- Early shared-memory and capability allocation still depends on the fixed bootstrap kernel heap.

### Window system and desktop

`ginkgo-window` defines the version-checked desktop protocol and client state machine used over per-app capability channels. Configurations carry separate logical and pixel sizes, normalized scale factors, fixed XRGB/ARGB formats, generation-tagged protected two-buffer pools, and transferred shared-memory handles. Presenting consumes a frame; the client cannot reacquire that slot until the server sends its matching `BufferReleased`. Rejected presents restore the slot, and generation-staged resize preserves the old displayed frame until the first new-generation present succeeds.

The production `ginkgo-desktop-service` runs `ginkgo-desktop` policy in ring 3 and drives channel requests, protected surface allocation, placements, focus, and buffer lifecycle through the kernel broker. The integrated path provides server decorations, pointer focus, focused keyboard/pointer input routing, fullscreen with layout restoration, scrolling columns, and clipping. The compositor builds each frame in a RAM backbuffer, then publishes the completed scene through packed framebuffer writes before completing the presentation and advancing `BufferReleased` ownership.

`ginkgo-fonts` provides sorted packed one-bit bitmap glyphs, kerning, allocation-free rendering through `embedded-graphics`, and strict parsing of a versioned little-endian `.gkf` representation. YAFF and BDF importers remain future host-side tooling; applications can already embed validated `.gkf` bytes or construct normalized fonts from converter output.

The registry contains the hidden `Ginkgo Desktop` service plus visible `Files` and `Ginkgo Demo` applications. `Files` lists the persistent root directory, moves selection with Up/Down, previews a file with Enter, returns with Backspace, and removes non-system files with Delete. Boot stops at an empty desktop until the user launches an app. The demo draws a steady centered “Hello World” surface, and `F11` toggles fullscreen. Normal panes have desktop margins while fullscreen remains edge-to-edge. `META+N` toggles the registry-backed launcher, whose search and app rows use the embedded-icon `Magnify` and `CubeOutline` drawables and bounded background save/restore.

Currently integrated pane bindings are `META+Left/Right` for focus, `META+Q` to close the focused application, `META+A/S` to move the focused pane left/right, `META+=/-` to adjust its width in 5% steps, and `META+L/C/R` to align it left/center/right. Columns form a horizontally scrolling workspace, so additional running applications can be off-screen; use the focus bindings to navigate them. The remaining desktop hotkey work is tracked in #5.

### USB HID input

At boot, GinkgoOS discovers the first PCI xHCI controller, enumerates directly attached root-port devices, configures each HID interrupt-IN endpoint, and parses its report descriptor. `InputManager` normalizes reports into device-tagged `InputEvent` values for keyboard keys, mouse buttons and relative axes, joystick/gamepad buttons, absolute axes, wheels, and hat switches. The desktop tracks relative mice and absolute USB tablets, displays mouse-button state through the cursor color, tracks left/right Shift and Logo keys, and routes `META+N` to the protected desktop service. Launcher text input supports Shift, Caps Lock, Enter, Tab, and Backspace. Every normalized event is recorded in `/input`; filesystem streams are flushed in batches so RedoxFS transactions do not stall USB polling. Report IDs and packed, signed, or non-byte-aligned fields are supported.

Input is currently limited to devices attached directly to xHCI root ports at boot. USB hubs and hotplug re-enumeration are not implemented yet. Enumeration failures are isolated per port so one malformed or unsupported device does not disable other input devices.

### Intel HDA audio

At boot, GinkgoOS discovers the first PCI class `04:03:00` High Definition Audio controller, maps BAR0 uncached, enumerates all reported codecs and audio function groups, searches each analog pin's connection graph, powers and configures the selected route, and starts a 32-period DMA output stream. Connected headphones, fixed speakers, and desktop line-out are preferred in that order. The driver uses bounded polling rather than external interrupts and rejects DMA addresses above 4 GiB when a controller lacks 64-bit addressing.

The fixed initial PCM contract is 44,100 Hz, signed 16-bit little-endian, stereo interleaved. Userspace submits frame-aligned chunks of at most 16 KiB with `ginkgo_userspace::audio_write`; `Status::ShouldWait` means the 128 KiB queue is full and the complete chunk should be retried after yielding. QEMU's `8086:293e` controller receives a short boot-time test tone, while physical hardware starts silently.

The default QEMU flags attach `ich9-intel-hda` and `hda-output` to an explicit `dsound` backend on Windows or `sdl` elsewhere. Override `QEMU_AUDIO_FLAGS`, for example with `-audiodev wav,id=ginkgo-audio,path=build/ginkgo-audio.wav`, for deterministic capture. The current implementation uses the HDA immediate-command interface and one output stream; CORB/RIRB transport, format negotiation, resampling, input, jack-change notifications, and multiple-card selection remain future work.

### Filesystem architecture

The kernel uses the RedoxFS 0.9.1 transaction engine and filesystem format, adapted from upstream commit `99bc185bf8ad8bd6f4d2562c424d800c2a3d310b`. The filesystem adapter is generic over its `Disk` implementation. Host tests retain an in-memory backend, while the boot kernel claims the legacy primary-master ATA device, validates its LBA28 capacity, and performs bounded polling PIO transfers in 512-byte sectors. A blank disk is formatted once; later boots reopen the existing unencrypted image. Trusted embedded executables and the registry are refreshed on every boot without deleting ordinary files.

The default QEMU targets attach `build/ginkgo-redoxfs.img` with writethrough caching. `make clean` preserves this image, `make reset-fs` deletes it, and the deliberately destructive `make distclean` removes the entire build directory. The current hardware driver supports only a legacy primary-master ATA disk; AHCI, NVMe, virtio-blk, partitions, and encrypted RedoxFS images are not yet supported.

## Dependencies

On CachyOS or Arch Linux:

```sh
sudo pacman -S --needed rustup make curl xorriso qemu-system-x86 sccache
rustup default nightly
```

Nightly is currently required for `allocator_api`, which the kernel IPC backend uses to keep syscall-reachable `Arc` allocation fallible. Both Cargo workspaces use `sccache` as their `rustc-wrapper`; install it before building. The Makefile downloads pinned Limine boot files and an OVMF firmware image automatically.

On Debian or Ubuntu, install equivalent packages:

```sh
sudo apt install make curl xorriso qemu-system-x86 sccache
```

Install Rust through rustup, then ensure `cargo` is in `PATH`.

## Run it

```sh
make run
```

The first run downloads Limine and OVMF, builds the kernel, creates `build/ginkgo-os.iso`, creates a persistent 16 MiB `build/ginkgo-redoxfs.img` if needed, and starts QEMU. The default `pc` machine attaches that image as the primary ATA disk plus an xHCI USB keyboard and tablet. Subsequent runs reuse the same filesystem image.

To boot directly from a QEMU virtual FAT disk without creating an ISO or requiring `xorriso`:

```sh
make no-iso
```

This stages the kernel, Limine configuration, and UEFI loader under `build/no_iso_root`, then boots that disposable directory as a QEMU virtual FAT disk. QEMU may write FAT metadata back to the staging directory. This target is intended for development; use the ISO target when producing bootable media.

Build without running:

```sh
make iso
```

On Windows, ISO creation and emulation can be split between WSL and native Windows tools. First create the ISO in WSL:

```sh
cd /mnt/k/repos/GinkgoOS
sudo apt install xorriso
make iso
```

Then boot that existing ISO from PowerShell with native Windows QEMU on `PATH`:

```powershell
cd K:\repos\GinkgoOS
make qemu
```

The `qemu` target does not build or modify the ISO.

Type-check the kernel:

```sh
make check
```

## Project structure

```text
crates/ginkgo-kernel/         boot binary, process/ELF/syscall runtime, hardware, scheduler, and compositor
crates/ginkgo-userspace/      no_std syscall wrappers, IPC codec, and window facade
crates/ginkgo-ipc/            channels, capabilities, shared memory, and protected window buffers
crates/ginkgo-program-registry/ validated no_std `.gkr` parser and host encoder
crates/ginkgo-window/         desktop protocol and transport-independent window client state machine
crates/ginkgo-scroll-layout/  pure scrolling workspace, placement, and fullscreen policy
crates/ginkgo-desktop/        transport-independent desktop service policy and runtime actions
crates/ginkgo-fonts/          packed bitmap fonts, rendering, and validated `.gkf` parsing
crates/ginkgo-hid/            transport-independent HID descriptor parser and report decoder
crates/ginkgo-filesystem/     generic RedoxFS adapter plus host memory-disk backend
crates/ginkgo-graphics/       hardware framebuffer and ordinary RAM pixel draw targets
crates/ginkgo-sysapi/         fixed-layout handles, rights, object types, signals, statuses, waits, and RPC header
userspace/                    nested production workspace for the desktop service, file navigator, minimal client, runtime, and ELF validator
vendor/redoxfs/               pinned no_std GinkgoOS adaptation of RedoxFS
limine.conf                 Limine menu entry
Makefile                    kernel build, ISO, and QEMU automation
```

## Hardware boot

The generated ISO is UEFI bootable. Write it to disposable media, not a disk containing data you care about:

```sh
sudo dd if=build/ginkgo-os.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Disable Secure Boot unless you sign the Limine EFI executable and configure its integrity policy.

## Desktop bootstrap

The normal Makefile pipeline builds the nested userspace workspace first and passes its production ELFs into the kernel build for embedding. At boot, `crates/ginkgo-kernel/src/main.rs` installs and reopens `/desktop.elf`, `/file-navigator.elf`, `/minimal-client.elf`, and `/programs.gkr` through RedoxFS, validates the registry, loads the desktop, and gives it a minimal cross-table bootstrap channel. Registered apps are loaded on demand with their own attenuated desktop channels and explicitly granted capabilities. Startup deliberately progresses through three visual phases:

1. An append-only kernel initialization log.
2. A splash screen while protected userland starts.
3. The empty desktop after its readiness message arrives; applications start only from an explicit launcher action.

Runtime status and launcher transitions use bounded dirty-region redraws and bounded background restoration. Solid 32-bpp framebuffer fills and completed compositor scenes use packed volatile writes rather than byte-at-a-time publication.

The next sensible milestones include nested directories and richer file management, the broader desktop hotkey work tracked in #5, scheduler-backed blocking waits, xHCI interrupt delivery and USB hotplug/hubs, timer preemption, SMP, frame deallocation, and a panic screen with serial diagnostics.
