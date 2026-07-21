# GinkgoOS

A `no_std` x86-64 kernel written in Rust and booted through Limine over UEFI. The current groundwork includes framebuffer output, physical frame allocation, active page-table management, checked device-I/O capabilities, polling xHCI USB HID input, a kernel-adapted RedoxFS filesystem, and cooperative task scheduling.

## What is included

- Stable Rust and the built-in `x86_64-unknown-none` target
- Limine framebuffer, memory-map, and higher-half direct-map requests
- Allocate-only 4 KiB physical frame allocation from usable memory
- `x86_64`-backed address types, active page-table translation, mapping, and unmapping
- `x86_64` port I/O plus `volatile`-backed checked MMIO capabilities
- A nonblocking serial device built on `uart_16550`
- PCI discovery and a polling xHCI USB host controller
- USB HID keyboards, mice, joysticks, and gamepads, including DragonRise Generic USB Joystick reports
- Descriptor-driven keyboard, button, axis, wheel, and hat-switch events in a bounded kernel input queue
- Process-local capability handles and bounded bidirectional datagram channels with atomic handle transfer
- RedoxFS transactions and on-disk format over a volatile memory-backed block device
- Talc-backed dynamic allocation for RedoxFS and future kernel services
- Fixed-capacity round-robin cooperative task scheduling
- A high-half ELF linker script
- An embedded-graphics RGB draw target with ProFont text rendering
- UEFI ISO and no-ISO QEMU boot targets

The scheduler is deliberately stackless and cooperative: each task performs one bounded step, stores its continuation in `TaskState`, and returns to yield. USB input follows the same model and polls xHCI without interrupts. The kernel does not yet provide independent task stacks, timer preemption, userspace, interrupts, SMP, or blocking waits.

### IPC groundwork

`ginkgo-ipc::HandleTable` models the capability table that will belong to each future process. Handles are opaque generation-tagged integers carrying explicit rights. Channel endpoints are asynchronous and bidirectional, preserve datagram boundaries and ordering, and maintain a bounded queue in each direction. Messages carry up to 16 KiB and 16 atomically moved handles; failed writes leave all source handles unchanged. Level-triggered `READABLE`, `WRITABLE`, and `PEER_CLOSED` state supports nonblocking wait-many scans under the current cooperative scheduler.

`ginkgo-sysapi` defines the fixed-layout handle, rights, signal, status, wait, and RPC-header contract shared with future userspace. Structured messages use a 24-byte `zerocopy` RPC header followed by a `postcard` payload; the kernel channel remains unaware of application protocols. `ginkgo-userspace` currently exposes this ABI and codec without pulling in the kernel channel backend. Actual syscall entry and blocking waits remain future work because GinkgoOS does not yet have userspace, process isolation, or stackful threads.

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
rustup default stable
```

The Makefile downloads pinned Limine boot files and an OVMF firmware image automatically.

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
crates/ginkgo-kernel/      boot binary, hardware, memory, USB transport, input queue, and scheduler
crates/ginkgo-userspace/   no_std userspace ABI and IPC-codec facade
crates/ginkgo-ipc/         postcard/zerocopy framing plus the kernel channel and handle backend
crates/ginkgo-hid/         transport-independent HID descriptor parser and report decoder
crates/ginkgo-filesystem/  RedoxFS memory-disk adapter and deterministic seed-image build
crates/ginkgo-graphics/    framebuffer draw target, RGB pixel packing, shapes, and ProFont text
crates/ginkgo-sysapi/      fixed-layout handles, rights, signals, statuses, waits, and RPC header
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

The next sensible milestones are exception/interrupt handling, xHCI interrupt delivery and USB hotplug/hubs, a timer-driven stackful scheduler, frame deallocation, and a panic screen with serial diagnostics.
