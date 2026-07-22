SHELL := /bin/sh

IMAGE_NAME := ginkgo-os
BUILD_DIR := build
ISO_ROOT := $(BUILD_DIR)/iso_root
NO_ISO_ROOT := $(BUILD_DIR)/no_iso_root
KERNEL := target/x86_64-unknown-none/debug/ginkgo-os
USERSPACE_MANIFEST := userspace/Cargo.toml
USERSPACE_TARGET := userspace/target/x86_64-unknown-none/release
DESKTOP_ELF := $(USERSPACE_TARGET)/ginkgo-desktop-service
MINIMAL_CLIENT_ELF := $(USERSPACE_TARGET)/ginkgo-minimal-client
FILE_NAVIGATOR_ELF := $(USERSPACE_TARGET)/ginkgo-file-navigator
TERMINAL_ELF := $(USERSPACE_TARGET)/ginkgo-terminal
FS_IMAGE := $(BUILD_DIR)/ginkgo-redoxfs.img
FS_IMAGE_SIZE_MB ?= 16
ISO := $(BUILD_DIR)/$(IMAGE_NAME).iso

LIMINE_VERSION ?= v12.5.1
LIMINE_DIR := $(BUILD_DIR)/limine-binary
LIMINE_ARCHIVE := $(BUILD_DIR)/limine-binary.tar.gz
LIMINE_URL := https://github.com/Limine-Bootloader/Limine/releases/download/$(LIMINE_VERSION)/limine-binary.tar.gz

OVMF_DIR := $(BUILD_DIR)/edk2-ovmf-bins
OVMF_ARCHIVE := $(BUILD_DIR)/edk2-ovmf-bins.tar.gz
OVMF_URL := https://github.com/osdev0/edk2-ovmf-stable-bins/releases/latest/download/edk2-ovmf-bins.tar.gz
OVMF_CODE := $(OVMF_DIR)/ovmf-code-x86_64.fd

XORRISO ?= xorriso
ifeq ($(OS),Windows_NT)
WINDOWS_USERPROFILE := $(subst \,/,$(USERPROFILE))
SCOOP_ROOT ?= $(if $(SCOOP),$(subst \,/,$(SCOOP)),$(WINDOWS_USERPROFILE)/scoop)
QEMU ?= $(SCOOP_ROOT)/apps/qemu/current/qemu-system-x86_64.exe
QEMU_AUDIO_FLAGS ?= -audiodev dsound,id=ginkgo-audio
else
QEMU ?= qemu-system-x86_64
QEMU_AUDIO_FLAGS ?= -audiodev sdl,id=ginkgo-audio
endif
QEMU_FLAGS ?= -m 512M -M pc,i8042=off -serial stdio -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0 $(QEMU_AUDIO_FLAGS) -device ich9-intel-hda -device hda-output,audiodev=ginkgo-audio -no-reboot -no-shutdown

.PHONY: all userspace kernel iso qemu no-iso run check clean distclean reset-fs

all: iso

userspace:
	cargo build --manifest-path $(USERSPACE_MANIFEST) --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-minimal-client -p ginkgo-file-navigator -p ginkgo-terminal

kernel: userspace
	GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os

$(LIMINE_DIR)/BOOTX64.EFI:
	mkdir -p $(BUILD_DIR)
	curl -fL $(LIMINE_URL) -o $(LIMINE_ARCHIVE)
	rm -rf $(LIMINE_DIR)
	tar -xzf $(LIMINE_ARCHIVE) -C $(BUILD_DIR)

$(OVMF_CODE):
	mkdir -p $(BUILD_DIR)
	curl -fL $(OVMF_URL) -o $(OVMF_ARCHIVE)
	rm -rf $(OVMF_DIR)
	tar -xzf $(OVMF_ARCHIVE) -C $(BUILD_DIR)

iso: $(ISO)

$(ISO): kernel $(LIMINE_DIR)/BOOTX64.EFI limine.conf
	rm -rf $(ISO_ROOT)
	mkdir -p $(ISO_ROOT)/boot/limine $(ISO_ROOT)/EFI/BOOT
	cp $(KERNEL) $(ISO_ROOT)/boot/kernel
	cp limine.conf $(ISO_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/limine-uefi-cd.bin $(ISO_ROOT)/boot/limine/
	cp $(LIMINE_DIR)/BOOTX64.EFI $(ISO_ROOT)/EFI/BOOT/
	$(XORRISO) -as mkisofs -R -r -J \
		--efi-boot boot/limine/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		$(ISO_ROOT) -o $(ISO)

$(FS_IMAGE):
	mkdir -p $(BUILD_DIR)
	dd if=/dev/zero of=$(FS_IMAGE) bs=1M count=$(FS_IMAGE_SIZE_MB)

qemu: $(OVMF_CODE) $(FS_IMAGE)
	@test -f $(ISO) || { echo "Missing $(ISO); create it first with 'make iso' (WSL is supported)."; exit 1; }
	"$(QEMU)" $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive if=none,id=ginkgo-fs,format=raw,cache=writethrough,file=$(FS_IMAGE) \
		-device ide-hd,drive=ginkgo-fs,bus=ide.0,unit=0 \
		-cdrom $(ISO) -boot d

no-iso: kernel $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE) $(FS_IMAGE) limine.conf
	rm -rf $(NO_ISO_ROOT)
	mkdir -p $(NO_ISO_ROOT)/boot/limine $(NO_ISO_ROOT)/EFI/BOOT
	cp $(KERNEL) $(NO_ISO_ROOT)/boot/kernel
	cp limine.conf $(NO_ISO_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(NO_ISO_ROOT)/EFI/BOOT/
	"$(QEMU)" $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive if=none,id=ginkgo-fs,format=raw,cache=writethrough,file=$(FS_IMAGE) \
		-device ide-hd,drive=ginkgo-fs,bus=ide.0,unit=0 \
		-drive if=none,id=ginkgo-boot,format=raw,file=fat:rw:$(NO_ISO_ROOT) \
		-device ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0 -boot c

run: $(OVMF_CODE) $(ISO) $(FS_IMAGE)
	"$(QEMU)" $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive if=none,id=ginkgo-fs,format=raw,cache=writethrough,file=$(FS_IMAGE) \
		-device ide-hd,drive=ginkgo-fs,bus=ide.0,unit=0 \
		-cdrom $(ISO) -boot d

check: userspace
	GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo check -p ginkgo-kernel --bin ginkgo-os

clean:
	cargo clean
	rm -rf $(ISO_ROOT) $(NO_ISO_ROOT) $(ISO)

reset-fs:
	rm -f $(FS_IMAGE)

# Deliberately destructive: unlike clean, distclean also removes persistent data.
distclean: clean
	rm -rf $(BUILD_DIR)
