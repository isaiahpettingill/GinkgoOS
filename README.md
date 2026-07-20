# Rust + Limine framebuffer kernel template

A minimal, dependency-free `no_std` x86-64 kernel written in Rust. Limine boots it through UEFI, supplies a linear framebuffer, and the kernel renders text directly into that framebuffer.

## What is included

- Stable Rust and the built-in `x86_64-unknown-none` target
- Limine boot-protocol declarations for the framebuffer request
- A high-half ELF linker script
- A pitch-aware RGB framebuffer writer
- A public-domain 8×8 ASCII bitmap font
- A UEFI-only bootable ISO target
- A QEMU + OVMF run target

No assembly source is required yet. The only inline assembly is the final `cli; hlt` loop.

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
src/main.rs         kernel entry point and Limine requests
src/limine.rs       minimal boot-protocol structs
src/framebuffer.rs  pixel, rectangle, font, and text rendering
src/font8x8.rs      public-domain ASCII bitmap font
src/crt.rs          freestanding memory routines LLVM may call
linker.ld            high-half ELF layout and request retention
limine.conf          Limine menu entry
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

The next sensible milestones are serial logging, a panic screen, memory-map acquisition, and a physical-frame allocator.
