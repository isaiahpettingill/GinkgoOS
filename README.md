# GinkgoOS

A `no_std` x86-64 kernel written in Rust and booted through Limine over UEFI. GinkgoOS boots through an on-screen kernel log and Ginkgo splash into a persistent protected ring-3 desktop service with a program-registry-backed launcher. The kernel also includes framebuffer output, physical frame allocation, isolated userspace address spaces, syscalls and capability IPC, shared-memory mappings, checked device-I/O capabilities, interrupt-assisted xHCI USB HID input, polling Intel HDA audio, a kernel-adapted RedoxFS filesystem, timer-preempted userspace, deadline-aware blocking waits, and cooperative bounded kernel tasks.

## What is included

- Nightly Rust and the built-in `x86_64-unknown-none` target
- Limine framebuffer, memory-map, and higher-half direct-map requests
- CPUID-width-aware, reclaiming 4 KiB physical-frame allocation with exact ownership, reservation tracking, full-width RAM statistics, and DMA-low failure accounting
- `x86_64`-backed address types, active four-level page-table translation, mapping, and unmapping
- Generation-tagged processes with isolated lower-half page tables and supervisor-only shared kernel mappings
- Strict ELF64 `ET_EXEC` compatibility plus randomized static `ET_DYN`, guarded randomized user stacks, x86-64 ring-3 entry, and contained user faults
- `SYSCALL`/`SYSRET` dispatch plus `no_std` userspace stubs for processes, handles, channels, waits, shared memory, files, directories, and debug output
- Rights-checked shared-memory map/unmap with mapping leases that survive source-handle closure
- Zero-filled private anonymous mappings with quota accounting, exact unmap/reclaim, and syscall-backed growable userspace Talc heaps
- `x86_64` port I/O plus `volatile`-backed checked MMIO capabilities
- A nonblocking serial device built on `uart_16550`
- General PCI class discovery, interrupt-assisted xHCI with hubs/hotplug, and polling Intel HDA output
- USB HID keyboards, mice, joysticks, and gamepads, including DragonRise Generic USB Joystick reports
- Descriptor-driven keyboard, button, axis, wheel, and hat-switch events in a bounded kernel input queue
- Process-local capability handles and bounded bidirectional datagram channels with atomic, rights-attenuating handle transfer
- Physical-frame-backed shared-memory capabilities and protected two-buffer window pools
- A software compositor with clipping, hardware-format conversion, ARGB source-over blending, and complete-scene publication
- Production Rust desktop-service, file-navigator, and minimal-client ELFs built in the nested userspace workspace
- A persistent protected userspace desktop service and `META+N` launcher
- A strictly validated, versioned `.gkr` executable registry with hidden system entries
- A transport-independent scrolling desktop policy and application window protocol
- Packed bitmap-font rendering and a validated, versioned `.gkf` format
- Persistent RedoxFS transactions on GPT/MBR volumes over bounded-polling virtio-blk or AHCI/SATA
- Talc-backed allocation that transitions from a bounded bootstrap arena to a growable page-backed kernel heap
- Single-core round-robin userspace scheduling with local-APIC timer preemption
- Hardware-seeded kernel CSPRNG with process-local random capabilities
- SMAP user-copy protection with recoverable page-fault fixups
- Ed25519-authenticated system manifests and per-process handle/memory/traffic/process-slot quotas
- Monotonic time, deadline-aware blocking waits, and interrupt-backed kernel idle
- Fixed-capacity stackless cooperative scheduling for bounded kernel tasks
- A high-half ELF linker script
- Embedded-graphics draw targets for volatile hardware framebuffers and ordinary XRGB/ARGB window RAM
- UEFI ISO and no-ISO QEMU boot targets with a 1920×1080 preferred mode and larger default UI font

Kernel tasks remain deliberately stackless and cooperative: each task performs one bounded step, stores its continuation in `TaskState`, and returns to yield. Userspace is preemptive: the process task arms a calibrated local-APIC one-shot timer before entering ring 3, and a 10 ms quantum captures the complete user context before returning to the scheduler. Syscalls and interrupt returns use protected per-CPU stacks, while `IRETQ` preserves asynchronously interrupted `RCX` and `R11`. Blocked waits retain kernel-owned requests and are polled in bounded scheduler steps until a signal or absolute monotonic deadline completes them. When no process is runnable, a short interrupt-backed `HLT` replaces busy spinning. xHCI uses a dedicated MSI vector to signal its bounded task-context event drain, with a polling watchdog fallback. Intel HDA remains polling; general device IRQ routing, independent kernel-task stacks, and SMP are not yet provided.

### IPC groundwork

Each process owns a `ginkgo-ipc::HandleTable`. Handles are opaque generation-tagged integers carrying explicit rights. Channel endpoints are asynchronous and bidirectional, preserve datagram boundaries and ordering, and maintain a bounded queue in each direction. Messages carry up to 16 KiB and 16 atomically moved handles. Transfer dispositions can reduce the rights installed in the receiver; validation, queueing, and source-handle consumption remain atomic, so failed writes leave every source handle unchanged. Level-triggered `READABLE`, `WRITABLE`, and `PEER_CLOSED` state supports bounded wait-many scans and scheduler-backed process blocking.

The same capability table holds zero-filled shared-memory objects and protected window client/manager endpoints. Production windows use two equal buffer slots per surface generation. A presented slot remains unavailable until its matching `BufferReleased` event; failed composition does not change ownership or emit a release. Resize is generation-staged: the compositor keeps the old displayed frame until the first frame from the new generation is successfully published, then retires the old pool and releases its final buffer.

Shared-memory objects own stable, distinct, page-rounded physical frames, are zero-filled on creation, and expose a distinct logical length. Processes may map them read-only or read-write only when the capability has the corresponding `MAP`, `READ`, and optional `WRITE` rights. Each mapping retains an owning lease, so closing or transferring the source handle cannot invalidate a live alias; unmapping or retiring the process releases that lease only after its PTEs are unreachable. Window capabilities protect lifecycle and management authority, not pixel immutability: a holder of a writable alias can still violate the presentation contract by modifying an in-flight buffer before its `BufferReleased` event.

`ginkgo-sysapi` defines append-only syscall numbers and fixed-layout argument blocks alongside the handle, rights, object type, signal, status, wait, mapping, filesystem, and RPC-header contracts. Filesystem syscalls cover open/create, positional read/write, stat, root-directory enumeration, truncate, and unlink. Files and the filesystem root are generation-protected process-local capabilities; only registry entries carrying `EntryFlags::FILESYSTEM` receive a root capability, and file capabilities cannot be duplicated or transferred. The entire top-level `/system` subtree is immutable to userspace: it remains readable, but open-for-write, create, truncate, unlink, directory mutation, and rename sources or targets are rejected. Legacy trusted artifact and kernel-log names at the filesystem root remain protected, while authorized root-capability holders can still mutate user-installed `applications` and per-application `appdata`. Structured messages use a 24-byte `zerocopy` RPC header followed by a `postcard` payload; the kernel channel remains unaware of application protocols. `ginkgo-userspace` exposes inline x86-64 syscall stubs, ergonomic wrappers, monotonic time, the codec, and the transport-independent window facade without pulling in the kernel handle backend. Wait-many validates and copies its complete request before blocking, retains only kernel-owned state, and resumes after a requested signal or absolute monotonic deadline. Ready signals take precedence over timeout at the same scheduler scan. `MemoryGetInfo` returns a versioned system-and-caller checkpoint with physical-frame, kernel-heap, RAM-derived process-limit, usage, and failure counters.

### Protected userspace execution

At boot, after device initialization has installed its kernel mappings, GinkgoOS ensures `/system` exists, installs `/system/desktop.elf`, `/system/file-navigator.elf`, `/system/terminal.elf`, `/system/minimal-client.elf`, and `/system/programs.gkr` into RedoxFS, and reads them back through the filesystem adapter. An Ed25519-signed manifest authenticates each `/system` path, length, and SHA-256 digest before registry parsing or executable loading. It then validates the registry and desktop ELF and creates an isolated page-table root for the desktop process. The process root starts with an empty lower half and clones only the kernel higher-half topology, clearing `USER_ACCESSIBLE` on every cloned P4 entry even when Limine supplied permissive flags. User mappings reject the zero page, noncanonical or higher-half addresses, writable-executable pages, overlaps, and permission-invalid copies.

The dependency-free ELF loader accepts little-endian x86-64 `ET_EXEC` compatibility images and static position-independent `ET_DYN` images in the Ginkgo executable profile. Compatible PIE images, stacks, and automatic shared mappings receive independent randomized placement. It validates every program header, mapped range, page overlap, permission, entry point, and stack/guard collision before installing image pages. Each process owns its address space, generation-tagged identity, register and x87/SSE state, capability table, shared mappings, resource accounting, and detailed exit/fault state.

The x86-64 entry path installs a GDT, TSS, IDT, `STAR`/`LSTAR`/`FMASK`, and five distinct 64 KiB supervisor stacks for RSP0, syscall entry, double fault, NMI, and machine check. Synchronous user exceptions are contained and returned to the process scheduler; kernel faults and unrecoverable exception classes fail stop. Every syscall immediately switches away from the untrusted user RSP, captures the complete user context, and returns to scheduler-side dispatch. Local-APIC timer interrupts capture asynchronous ring-3 state on RSP0 and acknowledge EOI without calling Rust. Return through `IRETQ` revalidates canonical RIP/RSP, flags, and floating-point state while preserving arbitrary interrupted `RCX` and `R11` values.

Normal Makefile builds first compile the production Rust `ginkgo-desktop-service`, `ginkgo-file-navigator`, `ginkgo-terminal`, and `ginkgo-minimal-client` release ELFs from the independent `userspace/` workspace. The kernel build consumes and embeds those artifacts with the generated registry; they become `/system/desktop.elf`, `/system/file-navigator.elf`, `/system/terminal.elf`, `/system/minimal-client.elf`, and `/system/programs.gkr` in the boot filesystem. The desktop receives only one bootstrap channel plus the display dimensions. Every launched app receives its per-app desktop channel, while only registry-authorized apps receive a filesystem-root capability. The service remains resident, announces readiness, owns launcher and window policy, polls bounded channels cooperatively, and yields when idle. A successful serial trace includes:

```text
desktop: loaded /system/desktop.elf from RedoxFS pid=...
desktop: protected Rust userland ready
```

The build script retains generated smoke ELFs for focused execution testing, but they are not production binaries used by normal Makefile builds. Setting `GINKGO_PREEMPTION_SMOKE=1` launches an opt-in probe that verifies forced preemption, `RCX`/`R11` preservation, concurrent desktop progress, monotonic time, and finite blocked-wait timeout in QEMU. `make frame-reclaim-smoke` runs 512 real scheduler launch/retirement cycles, alternating clean exits and invalid-opcode faults while exercising shared-memory leases, and requires physical-frame and IPC backing counts to return to a stable post-warmup baseline. `make process-capability-smoke` builds the Rust `no_std` userspace probe and enables `GINKGO_PROCESS_CAPABILITY_SMOKE=1`; the kernel installs its test artifacts and launches the parent with only a read/execute filesystem-root capability. The parent exercises file-based creation, NUL startup data, startup-handle transfer, wait/info, fault reporting, termination, malformed-ELF atomicity, and execute-right denial through real syscalls. Setting `GINKGO_FILESYSTEM_HIERARCHY_SMOKE=1` runs a bounded adapter-level hierarchy check immediately after RedoxFS mounts and before desktop launch.

Current execution limitations are intentional and explicit:

- Scheduling is single-core; SMP and CPU migration are not implemented.
- The local-APIC timer and xHCI MSI have dedicated external interrupt entries; other device drivers still poll, and general I/O-APIC routing is not implemented.
- Blocked waits use bounded scheduler polling rather than per-object kernel wait queues.
- SMAP is enabled when supported; one CPU-local fixup contains faults during explicitly bracketed user copies.
- XSAVE-capable CPUs preserve enabled x87/SSE/AVX state (including AVX2's YMM state) across every userspace transition; legacy CPUs use FXSAVE, and default system images retain an SSE2 baseline.
- Physical reclamation is single-core: process roots are recycled only after switching back to the kernel CR3; future SMP requires remote TLB shootdown before reuse.
- CPUID physical-address width constrains usable Limine RAM; allocation can use frames above 4 GiB when the platform reports them. The kernel remains on four-level paging, so its active virtual-address contract is 48-bit even on LA57-capable CPUs.
- Kernel allocations use a growable page-backed arena after early boot; the original bounded bootstrap arena remains mapped so pre-transition allocations stay valid.
- Dynamic linking, runtime ELF relocations, signed rollback prevention, encrypted storage, and hardware-backed key sealing are not yet provided.

See [`SECURITY.md`](SECURITY.md) for the threat model, trust/update policy, resource ceilings, CPU-feature audit, and unsupported hardware assumptions.

### Window system and desktop

`ginkgo-window` defines the version-checked desktop protocol and client state machine used over per-app capability channels. Configurations carry separate logical and pixel sizes, normalized scale factors, fixed XRGB/ARGB formats, generation-tagged protected two-buffer pools, and transferred shared-memory handles. Presenting consumes a frame; the client cannot reacquire that slot until the server sends its matching `BufferReleased`. Rejected presents restore the slot, and generation-staged resize preserves the old displayed frame until the first new-generation present succeeds.

The production `ginkgo-desktop-service` runs `ginkgo-desktop` policy in ring 3 and drives channel requests, protected surface allocation, placements, focus, and buffer lifecycle through the kernel broker. The integrated path provides server decorations, pointer focus, focused keyboard/pointer input routing, fullscreen with layout restoration, scrolling columns, and clipping. The compositor builds each frame in a RAM backbuffer, then publishes the completed scene through packed framebuffer writes before completing the presentation and advancing `BufferReleased` ownership.

`ginkgo-fonts` provides sorted packed one-bit bitmap glyphs, kerning, allocation-free rendering through `embedded-graphics`, and strict parsing of a versioned little-endian `.gkf` representation. YAFF and BDF importers remain future host-side tooling; applications can already embed validated `.gkf` bytes or construct normalized fonts from converter output.

The registry contains the hidden `Ginkgo Desktop` service plus visible `Files` and `Ginkgo Demo` applications. `Files` lists the persistent root directory, moves selection with Up/Down, previews a file with Enter, returns with Backspace, and removes non-system files with Delete. Boot stops at an empty desktop until the user launches an app. The demo draws a steady centered “Hello World” surface, and `F11` toggles fullscreen. Normal panes have desktop margins while fullscreen remains edge-to-edge. `META+N` toggles the registry-backed launcher, whose search and app rows use the embedded-icon `Magnify` and `CubeOutline` drawables and bounded background save/restore.

Currently integrated pane bindings are `META+Left/Right` for focus, `META+Q` to close the focused application, `META+A/S` to move the focused pane left/right, `META+=/-` to adjust its width in 5% steps, and `META+L/C/R` to align it left/center/right. Columns form a horizontally scrolling workspace, so additional running applications can be off-screen; use the focus bindings to navigate them. The remaining desktop hotkey work is tracked in #5.

### USB HID input

At boot, GinkgoOS discovers the first PCI xHCI controller, traverses USB 2 and USB 3 hubs, configures HID interrupt-IN endpoints, and parses their report descriptors. `InputManager` normalizes reports into device-tagged `InputEvent` values for keyboard keys, mouse buttons and relative axes, joystick/gamepad buttons, absolute axes, wheels, and hat switches. The desktop tracks relative mice and absolute USB tablets, displays mouse-button state through the cursor color, tracks left/right Shift and Logo keys, and routes `META+N` to the protected desktop service. Launcher text input supports Shift, Caps Lock, Enter, Tab, and Backspace. Every normalized event is recorded in `/input`; filesystem streams are flushed in batches so RedoxFS transactions do not stall USB event handling. Report IDs and packed, signed, or non-byte-aligned fields are supported.

The xHCI driver tracks five-tier route strings, powers and resets hub ports, handles root and downstream connect/disconnect events, and tears down descendants before disabling their slots. Runtime-added HID interfaces receive fresh decoders without restarting the desktop; disconnect removes queued events and clears stale held state. A bounded deferred-event queue prevents synchronous commands from discarding unrelated HID or port-change completions. MSI wakes the event path, while a watchdog poll preserves operation on hardware without usable MSI. Topology, path-aware failures, interrupt counts, and fallback activity are retained for diagnostics. Failures remain isolated per path so one malformed hub port or endpoint does not disable unrelated devices.

### Intel HDA audio

At boot, GinkgoOS discovers the first PCI class `04:03:00` High Definition Audio controller, maps BAR0 uncached, enumerates all reported codecs and audio function groups, searches each analog pin's connection graph, powers and configures the selected route, and starts a 32-period DMA output stream. Connected headphones, fixed speakers, and desktop line-out are preferred in that order. The driver uses bounded polling rather than external interrupts and rejects DMA addresses above 4 GiB when a controller lacks 64-bit addressing.

The fixed initial PCM contract is 44,100 Hz, signed 16-bit little-endian, stereo interleaved. Userspace submits frame-aligned chunks of at most 16 KiB with `ginkgo_userspace::audio_write`; `Status::ShouldWait` means the 128 KiB queue is full and the complete chunk should be retried after yielding. Hardware starts with silent DMA periods and remains silent until userspace submits PCM.

The default QEMU flags attach `ich9-intel-hda` and `hda-output` to an explicit `dsound` backend on Windows or `sdl` elsewhere. Override `QEMU_AUDIO_FLAGS`, for example with `-audiodev wav,id=ginkgo-audio,path=build/ginkgo-audio.wav`, for deterministic capture. The current implementation uses the HDA immediate-command interface and one output stream; CORB/RIRB transport, format negotiation, resampling, input, jack-change notifications, and multiple-card selection remain future work.

### Filesystem architecture

The kernel uses the RedoxFS 0.9.1 transaction engine and filesystem format, adapted from upstream commit `99bc185bf8ad8bd6f4d2562c424d800c2a3d310b`. A common 512-byte-sector block interface provides bounded reads, writes, capacity reporting, and explicit flushes. Boot prefers PCI-discovered transitional `virtio-blk` and falls back to PCI AHCI/SATA. Both drivers use bounded polling, validate transfer ranges, and propagate controller and device errors rather than waiting indefinitely.

Storage discovery validates GPT header and partition-array CRCs and bounds, understands protective and legacy MBRs, and mounts the first usable partition. Media with no partition table remains supported as a whole-disk volume. RedoxFS writes explicitly flush the selected block device before completion. A blank selected volume is formatted once; later boots reopen it, while trusted embedded programs are refreshed without deleting ordinary files.

The default QEMU targets attach the persistent GPT image `build/ginkgo-redoxfs.img` through `virtio-blk` with writethrough caching. `make clean` preserves this image, `make reset-fs` deletes it, and the deliberately destructive `make distclean` removes the entire build directory. The filesystem smoke copies that GPT image to the dedicated disposable `build/filesystem-hierarchy-smoke.img`; `make clean` removes the copy and its boot staging tree without touching the persistent source image. AHCI provides the modern physical SATA path; NVMe and USB mass storage remain separate future phases.

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

The first run downloads Limine and OVMF, builds the kernel, creates `build/ginkgo-os.iso`, creates a persistent 16 MiB GPT `build/ginkgo-redoxfs.img` if needed, and starts QEMU. The default `pc` machine attaches that image through transitional `virtio-blk` plus an xHCI USB hub containing a keyboard and tablet. Subsequent runs reuse the same filesystem image.

Run `make usb-smoke` for automated headless QEMU/QMP coverage. The test verifies hub enumeration, MSI delivery, disconnect with an outstanding HID transfer, repeated keyboard reconnects, and restoration of the live-interface baseline while an unrelated tablet remains active. Run `make frame-reclaim-smoke` to stress normal exits, faults, shared-memory final-owner release, and frame reuse across 512 sequential processes. Run `make process-capability-smoke` for deterministic issue #8 coverage; its bounded headless harness accepts exactly one `ginkgo-process-capability-smoke: PASS` marker, emitted only after the parent exits and normal process reclamation succeeds.

Run `make filesystem-smoke` for deterministic persistence coverage of the hierarchy adapter. The target builds the opt-in `GINKGO_FILESYSTEM_HIERARCHY_SMOKE=1` kernel, creates a fresh dedicated 32 MiB GPT disk, and boots that disk twice in headless QEMU with a 60-second timeout per boot. The first boot must emit exactly `filesystem-smoke: initialized`; the second must emit exactly `filesystem-smoke: persisted`; either boot emitting `filesystem-smoke: failure` fails the harness. The kernel checks nested creation, content, no-replace and cross-directory moves, atomic replacement, persisted metadata, directory-capability isolation from siblings and traversal, stale-handle rejection, and explicit sync.

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

The normal Makefile pipeline builds the nested userspace workspace first and passes its production ELFs into the kernel build for embedding. At boot, `crates/ginkgo-kernel/src/main.rs` installs and reopens `/system/desktop.elf`, `/system/file-navigator.elf`, `/system/terminal.elf`, `/system/minimal-client.elf`, and `/system/programs.gkr` through RedoxFS, validates the registry, loads the desktop, and gives it a minimal cross-table bootstrap channel. Registered apps are loaded on demand with their own attenuated desktop channels and explicitly granted capabilities. Startup deliberately progresses through three visual phases:

1. An append-only kernel initialization log.
2. The embedded `Ginkgo.png` splash while protected userland starts.
3. The empty desktop after its readiness message arrives; applications start only from an explicit launcher action.

Runtime status and launcher transitions use bounded dirty-region redraws and bounded background restoration. Solid 32-bpp framebuffer fills and completed compositor scenes use packed volatile writes rather than byte-at-a-time publication.

The next sensible milestones include richer file management, the broader desktop hotkey work tracked in #5, general device IRQ routing, SMP, and a panic screen with serial diagnostics.
