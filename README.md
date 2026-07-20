# GinkgoOS

A `no_std` x86-64 kernel written in Rust and booted through Limine over UEFI. The current groundwork includes framebuffer output, physical frame allocation, active page-table management, checked device-I/O capabilities, a kernel-adapted RedoxFS filesystem, and cooperative task scheduling.

## What is included

- Stable Rust and the built-in `x86_64-unknown-none` target
- Limine framebuffer, memory-map, and higher-half direct-map requests
- Allocate-only 4 KiB physical frame allocation from usable memory
- Active four-level x86-64 page translation, mapping, and unmapping
- Checked x86 port-I/O and volatile MMIO region capabilities
- A nonblocking 16550 serial input/output device
- RedoxFS transactions and on-disk format over a volatile memory-backed block device
- Talc-backed dynamic allocation for RedoxFS and future kernel services
- Fixed-capacity round-robin cooperative task scheduling
- A high-half ELF linker script
- A pitch-aware RGB framebuffer writer and public-domain 8×8 font
- UEFI ISO and no-ISO QEMU boot targets

The scheduler is deliberately stackless and cooperative: each task performs one bounded step, stores its continuation in `TaskState`, and returns to yield. It does not yet provide independent task stacks, timer preemption, userspace, interrupts, SMP, or blocking waits.

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

The first run downloads Limine and OVMF, builds the kernel, creates `build/rust-limine-framebuffer.iso`, and starts QEMU.

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
src/main.rs         boot flow, paging smoke test, and initial kernel tasks
src/lib.rs          reusable no_std kernel subsystem facade
src/limine.rs       boot-protocol requests and validated response wrappers
src/memory.rs       address types and usable physical-frame allocator
src/paging.rs       active x86-64 four-level page-table management
src/io.rs           checked port I/O, MMIO, and nonblocking serial device
src/fs.rs           RedoxFS memory-disk and kernel API adapter
src/heap.rs         Talc bootstrap heap
src/task.rs         cooperative round-robin task scheduler
src/framebuffer.rs  pixel, rectangle, font, and text rendering
src/font8x8.rs      public-domain ASCII bitmap font
src/crt.rs          freestanding memory routines LLVM may call
linker.ld            high-half ELF layout and request retention
limine.conf          Limine menu entry
build.rs             deterministic RedoxFS seed-image formatter
vendor/redoxfs/       pinned, no_std GinkgoOS adaptation of RedoxFS
Makefile             build, ISO, and QEMU automation
```

## Hardware boot

The generated ISO is UEFI bootable. Write it to disposable media, not a disk containing data you care about:

```sh
sudo dd if=build/rust-limine-framebuffer.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

Disable Secure Boot unless you sign the Limine EFI executable and configure its integrity policy.

## First code to change

The visible output is in `src/main.rs`:

```rust
screen.draw_text(margin + 40, margin + 38, 4, "Hello, framebuffer!", primary);
```

The next sensible milestones are exception/interrupt handling, a timer-driven stackful scheduler, frame deallocation, device discovery, and a panic screen with serial diagnostics.
