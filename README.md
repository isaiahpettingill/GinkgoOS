# GinkgoOS

A `no_std` x86-64 kernel written in Rust and booted through Limine over UEFI. GinkgoOS currently includes framebuffer output, physical frame allocation, isolated userspace address spaces, ring-3 execution and syscalls, capability-backed shared-memory mappings, checked device-I/O capabilities, polling xHCI USB HID input, a kernel-adapted RedoxFS filesystem, and cooperative task/process scheduling.

## What is included

- Nightly Rust and the built-in `x86_64-unknown-none` target
- Limine framebuffer, memory-map, and higher-half direct-map requests
- Allocate-only 4 KiB physical frame allocation from usable memory
- `x86_64`-backed address types, active page-table translation, mapping, and unmapping
- Generation-tagged processes with isolated lower-half page tables and supervisor-only shared kernel mappings
- Strict ELF64 `ET_EXEC` loading, guarded user stacks, x86-64 ring-3 entry, and contained user faults
- `SYSCALL`/`SYSRET` dispatch plus `no_std` userspace stubs for processes, handles, channels, waits, shared memory, and debug output
- Rights-checked shared-memory map/unmap with mapping leases that survive source-handle closure
- `x86_64` port I/O plus `volatile`-backed checked MMIO capabilities
- A nonblocking serial device built on `uart_16550`
- PCI discovery and a polling xHCI USB host controller
- USB HID keyboards, mice, joysticks, and gamepads, including DragonRise Generic USB Joystick reports
- Descriptor-driven keyboard, button, axis, wheel, and hat-switch events in a bounded kernel input queue
- Process-local capability handles and bounded bidirectional datagram channels with atomic, rights-attenuating handle transfer
- Heap-backed shared-memory capabilities and protected multi-buffered window lifecycles
- A software compositor with clipping, hardware-format conversion, and ARGB source-over blending
- A transport-independent scrolling desktop policy and application window protocol
- Packed bitmap-font rendering and a validated, versioned `.gkf` format
- RedoxFS transactions and on-disk format over a volatile memory-backed block device
- Talc-backed dynamic allocation for RedoxFS and future kernel services
- Fixed-capacity round-robin cooperative task scheduling
- A high-half ELF linker script
- Embedded-graphics draw targets for volatile hardware framebuffers and ordinary XRGB/ARGB window RAM
- UEFI ISO and no-ISO QEMU boot targets

The scheduler is deliberately stackless and cooperative: each kernel task performs one bounded step, stores its continuation in `TaskState`, and returns to yield. A process task enters ring 3 until the application makes one syscall or faults, dispatches that syscall while the process CR3 remains active, restores the kernel CR3, and then yields to the next scheduler turn. USB input follows the same model and polls xHCI without interrupts. The kernel does not yet provide independent kernel-task stacks, timer preemption, external interrupt delivery, SMP, or blocking waits.

### IPC groundwork

`ginkgo-ipc::HandleTable` models the capability table that will belong to each future process. Handles are opaque generation-tagged integers carrying explicit rights. Channel endpoints are asynchronous and bidirectional, preserve datagram boundaries and ordering, and maintain a bounded queue in each direction. Messages carry up to 16 KiB and 16 atomically moved handles. Transfer dispositions can reduce the rights installed in the receiver; validation, queueing, and source-handle consumption remain atomic, so failed writes leave every source handle unchanged. Level-triggered `READABLE`, `WRITABLE`, and `PEER_CLOSED` state supports nonblocking wait-many scans under the current cooperative scheduler.

The same capability table now models zero-filled shared-memory objects and protected window client/manager endpoints. Each surface generation uses at least two equal buffer slots. A submitted slot remains unavailable until the compositor successfully copies it, a later successful presentation or pool retirement produces its single bounded `WindowRelease`, and the client reads that release to reclaim ownership. Failed composition does not change ownership or emit a release. Endpoint closure reports `PEER_CLOSED`, and old generations can be retired after pending work completes.

Shared-memory objects are page-aligned, page-rounded, zero-filled heap allocations with a distinct logical length. Processes may map them read-only or read-write only when the capability has the corresponding `MAP`, `READ`, and optional `WRITE` rights. Each mapping retains an owning lease, so closing or transferring the source handle cannot invalidate a live alias; unmapping or retiring the process releases that lease only after its PTEs are unreachable. Window capabilities protect lifecycle and management authority, not pixel immutability: a holder of a writable alias can still violate the presentation contract by modifying an in-flight buffer before its `BufferReleased` event.

`ginkgo-sysapi` defines fixed-layout syscall numbers and argument blocks alongside the handle, rights, object type, signal, status, wait, mapping, and RPC-header contracts. Structured messages use a 24-byte `zerocopy` RPC header followed by a `postcard` payload; the kernel channel remains unaware of application protocols. `ginkgo-userspace` exposes inline x86-64 syscall stubs, ergonomic wrappers, the codec, and the transport-independent window facade without pulling in the kernel handle backend. Wait-many currently performs one nonblocking signal poll; scheduler wait queues and deadline-aware blocking remain future work.

### Protected userspace execution

At boot, after device initialization has installed its kernel mappings, GinkgoOS creates an isolated page-table root for a generated smoke-test process. The process root starts with an empty lower half and clones only the kernel higher-half topology, clearing `USER_ACCESSIBLE` on every cloned P4 entry even when Limine supplied permissive flags. User mappings reject the zero page, noncanonical or higher-half addresses, writable-executable pages, overlaps, and permission-invalid copies.

The dependency-free ELF loader accepts only little-endian x86-64 `ET_EXEC` images in the Ginkgo executable profile. It validates every program header, mapped range, page overlap, permission, entry point, and stack/guard collision before installing image pages. Each process owns its address space, generation-tagged identity, register and x87/SSE state, capability table, shared mappings, and detailed exit/fault state.

The x86-64 entry path installs a GDT, TSS, IDT, `STAR`/`LSTAR`/`FMASK`, and five distinct 64 KiB supervisor stacks for RSP0, syscall entry, double fault, NMI, and machine check. Synchronous user exceptions are contained and returned to the process scheduler; kernel faults and unrecoverable exception classes fail stop. Every syscall immediately switches away from the untrusted user RSP, captures the complete user context, and returns to scheduler-side dispatch. Return through `SYSRETQ` revalidates canonical RIP/RSP, flags, and floating-point state.

`crates/ginkgo-kernel/build.rs` generates a minimal ELF used as the boot smoke test. It proves ring-3 entry, debug output, shared-memory creation, a 4097-byte read-write mapping, access through the mapped alias, cooperative yield/resume, mapping-lease survival after closing the source handle, unmapping, and clean process exit. A successful serial trace includes:

```text
userspace: loaded pid=...
ginkgo-userspace-smoke: entered
ginkgo-userspace-smoke: mapped alias
ginkgo-userspace-smoke: resumed
ginkgo-userspace-smoke: mapped alias
userspace: pid=... exited status=0
```

Current execution limitations are intentional and explicit:

- Scheduling is single-core and cooperative. A process that never makes a syscall can monopolize the CPU until timer preemption exists.
- Interrupts remain disabled while userspace runs; there is no external IRQ entry or asynchronous preemption path yet.
- Wait-many is a single nonblocking poll, not a scheduler-backed blocking operation.
- SMAP is not enabled because checked user-copy operations do not yet have exception-fixup support.
- x87/SSE/SSE2 state is isolated with FXSAVE/FXRSTOR; AVX/XSAVE is intentionally unavailable.
- The physical allocator is monotonic, so retired process frames are accounted for but not recycled.
- Early shared-memory and capability allocation still depends on the fixed bootstrap kernel heap.

### Window-system groundwork

`ginkgo-window` defines a version-checked serialized desktop protocol and a transport-independent client state machine. Configurations carry separate logical and pixel sizes, normalized rational scale factors, fixed XRGB/ARGB formats, generation-tagged surface pools, and attached-handle indices that are consumed before events reach applications. Frames provide raw bytes or a validated `PixelSurface`; presenting consumes the frame, and a slot cannot be reacquired until its matching `BufferReleased` event arrives. Rejected presentations restore their slot, while old resize generations remain alive until all accepted buffers are released.

`ginkgo-scroll-layout` implements one-window-per-column workspaces, focus and movement, viewport scrolling, proportional widths, decorations, clipping, and fullscreen restoration without hardware or process dependencies. `ginkgo-desktop` applies that policy to requests and emits explicit runtime actions for future channel, allocator, and compositor integration. `ginkgo-kernel::compositor` redraws ordered retained windows from protected buffers, clips them to the framebuffer, converts fixed window pixels into arbitrary hardware channel masks, blends ARGB, and completes a pending presentation only after the redraw succeeds.

`ginkgo-fonts` provides sorted packed one-bit bitmap glyphs, kerning, allocation-free rendering through `embedded-graphics`, and strict parsing of a versioned little-endian `.gkf` representation. YAFF and BDF importers remain future host-side tooling; applications can already embed validated `.gkf` bytes or construct normalized fonts from converter output.

These components are host-tested foundations rather than a boot-time desktop. The running kernel now executes the protected userspace smoke process alongside its direct framebuffer validation UI. Wiring a persistent userspace desktop service to the existing protocol, layout policy, and compositor remains the next window-system integration step.

### USB HID input

At boot, GinkgoOS discovers the first PCI xHCI controller, enumerates directly attached root-port devices, configures each HID interrupt-IN endpoint, and parses its report descriptor. `InputManager` normalizes reports into device-tagged `InputEvent` values for keyboard keys, mouse buttons and relative axes, joystick/gamepad buttons, absolute axes, wheels, and hat switches. The embedded-graphics validation UI tracks relative mice and absolute USB tablets, displays mouse-button state through the cursor color, and provides a wrapped ProFont keyboard text buffer with Shift, Caps Lock, Enter, Tab, and Backspace handling. USB keyboard presses also feed the serial and `/console` path, and every normalized event is recorded in `/input`; both filesystem streams are flushed in batches so RedoxFS transactions do not stall USB polling. Report IDs and packed, signed, or non-byte-aligned fields are supported.

Input is currently limited to devices attached directly to xHCI root ports at boot. USB hubs and hotplug re-enumeration are not implemented yet. Enumeration failures are isolated per port so one malformed or unsupported device does not disable other input devices.

### Filesystem architecture

The kernel uses the RedoxFS 0.9.1 transaction engine and filesystem format, adapted from upstream commit `99bc185bf8ad8bd6f4d2562c424d800c2a3d310b`. A host build script formats a deterministic 2 MiB seed image. At boot, the kernel copies that image into memory, opens it through a GinkgoOS `Disk` implementation, and performs normal RedoxFS node transactions.

The current adapter intentionally supports unencrypted images only. Persistence across reboot requires replacing the memory disk with a block-device driver; the filesystem-facing code does not need to change.

## Dependencies

On CachyOS or Arch Linux:

```sh
sudo pacman -S --needed rustup make curl xorriso qemu-system-x86
rustup default nightly
```

Nightly is currently required for `allocator_api`, which the kernel IPC backend uses to keep syscall-reachable `Arc` allocation fallible. The Makefile downloads pinned Limine boot files and an OVMF firmware image automatically.

On Debian or Ubuntu, install equivalent packages:

```sh
sudo apt install make curl xorriso qemu-system-x86
```

Install Rust through rustup, then ensure `cargo` is in `PATH`.

## Run it

```sh
make run
```

The first run downloads Limine and OVMF, builds the kernel, creates `build/ginkgo-os.iso`, and starts QEMU. The default QEMU configuration attaches an xHCI USB keyboard and tablet so the HID path is exercised.

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
crates/ginkgo-window/         desktop protocol and transport-independent window client state machine
crates/ginkgo-scroll-layout/  pure scrolling workspace, placement, and fullscreen policy
crates/ginkgo-desktop/        transport-independent desktop service policy and runtime actions
crates/ginkgo-fonts/          packed bitmap fonts, rendering, and validated `.gkf` parsing
crates/ginkgo-hid/            transport-independent HID descriptor parser and report decoder
crates/ginkgo-filesystem/     RedoxFS memory-disk adapter and deterministic seed-image build
crates/ginkgo-graphics/       hardware framebuffer and ordinary RAM pixel draw targets
crates/ginkgo-sysapi/         fixed-layout handles, rights, object types, signals, statuses, waits, and RPC header
vendor/redoxfs/            pinned no_std GinkgoOS adaptation of RedoxFS
limine.conf                 Limine menu entry
Makefile                    kernel build, ISO, and QEMU automation
```

## Hardware boot

The generated ISO is UEFI bootable. Write it to disposable media, not a disk containing data you care about:

```sh
sudo dd if=build/ginkgo-os.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Disable Secure Boot unless you sign the Limine EFI executable and configure its integrity policy.

## First code to change

The visible output is in `crates/ginkgo-kernel/src/main.rs`:

```rust
screen.draw_text(margin + 40, margin + 38, 4, "Hello, framebuffer!", primary);
```

The next sensible milestones are a userspace desktop runtime, scheduler-backed blocking waits, xHCI interrupt delivery and USB hotplug/hubs, timer preemption, SMP, frame deallocation, and a panic screen with serial diagnostics.
