SHELL := /bin/sh

IMAGE_NAME := ginkgo-os
BUILD_DIR := build
ISO_ROOT := $(BUILD_DIR)/iso_root
NO_ISO_ROOT := $(BUILD_DIR)/no_iso_root
USB_SMOKE_ROOT := $(BUILD_DIR)/usb_smoke_root
FRAME_RECLAIM_ROOT := $(BUILD_DIR)/frame_reclaim_root
FILESYSTEM_SMOKE_ROOT := $(BUILD_DIR)/filesystem_smoke_root
FILESYSTEM_SMOKE_DISK := $(BUILD_DIR)/filesystem-hierarchy-smoke.img
TEXT_EDITOR_SAVE_ROOT := $(BUILD_DIR)/text_editor_save_root
TEXT_EDITOR_VERIFY_ROOT := $(BUILD_DIR)/text_editor_verify_root
TEXT_EDITOR_SMOKE_DISK := $(BUILD_DIR)/text-editor-smoke.img
PROCESS_CAPABILITY_SMOKE_ROOT := $(BUILD_DIR)/process_capability_smoke_root
PROCESS_CAPABILITY_SMOKE_DISK := $(BUILD_DIR)/process-capability-smoke.img
POWER_SYNC_ROOT := $(BUILD_DIR)/power_sync_root
POWER_VERIFY_ROOT := $(BUILD_DIR)/power_verify_root
POWER_CANCEL_ROOT := $(BUILD_DIR)/power_cancel_root
POWER_REBOOT_ROOT := $(BUILD_DIR)/power_reboot_root
POWER_PERSIST_DISK := $(BUILD_DIR)/power-persist-smoke.img
POWER_CANCEL_DISK := $(BUILD_DIR)/power-cancel-smoke.img
POWER_REBOOT_DISK := $(BUILD_DIR)/power-reboot-smoke.img
KERNEL := target/x86_64-unknown-none/debug/ginkgo-os
USERSPACE_MANIFEST := userspace/Cargo.toml
USERSPACE_TARGET := userspace/target/x86_64-unknown-none/release
DESKTOP_ELF := $(USERSPACE_TARGET)/ginkgo-desktop-service
MINIMAL_CLIENT_ELF := $(USERSPACE_TARGET)/ginkgo-minimal-client
FILE_NAVIGATOR_ELF := $(USERSPACE_TARGET)/ginkgo-file-navigator
TEXT_EDITOR_ELF := $(USERSPACE_TARGET)/ginkgo-text-editor
TERMINAL_ELF := $(USERSPACE_TARGET)/ginkgo-terminal
PROCESS_CAPABILITY_SMOKE_ELF := $(USERSPACE_TARGET)/ginkgo-process-capability-smoke
FS_IMAGE := $(BUILD_DIR)/ginkgo-redoxfs.img
FS_IMAGE_SIZE_MB ?= 32
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
PYTHON ?= python3
ifeq ($(OS),Windows_NT)
WINDOWS_USERPROFILE := $(subst \,/,$(USERPROFILE))
SCOOP_ROOT ?= $(if $(SCOOP),$(subst \,/,$(SCOOP)),$(WINDOWS_USERPROFILE)/scoop)
QEMU ?= $(SCOOP_ROOT)/apps/qemu/current/qemu-system-x86_64.exe
QEMU_AUDIO_FLAGS ?= -audiodev dsound,id=ginkgo-audio
else
QEMU ?= qemu-system-x86_64
QEMU_AUDIO_FLAGS ?= -audiodev sdl,id=ginkgo-audio
endif
QEMU_FLAGS ?= -cpu max -m 512M -M pc,i8042=off -serial stdio -device qemu-xhci,id=xhci,msi=on,msix=off -device usb-hub,id=ginkgo-hub,bus=xhci.0,port=1 -device usb-kbd,bus=xhci.0,port=1.1 -device usb-tablet,bus=xhci.0,port=1.2 $(QEMU_AUDIO_FLAGS) -device ich9-intel-hda -device hda-output,audiodev=ginkgo-audio

.PHONY: all userspace kernel iso qemu no-iso run usb-smoke frame-reclaim-smoke filesystem-smoke text-editor-smoke process-capability-smoke power-smoke check clean distclean reset-fs FORCE

all: iso

userspace:
	cargo build --manifest-path $(USERSPACE_MANIFEST) --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-minimal-client -p ginkgo-file-navigator -p ginkgo-text-editor -p ginkgo-terminal -p ginkgo-process-capability-smoke

kernel: userspace
	GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os

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

FORCE:

$(FS_IMAGE): tools/create_gpt_disk.py FORCE
	mkdir -p $(BUILD_DIR)
	$(PYTHON) tools/create_gpt_disk.py $(FS_IMAGE) --size-mb $(FS_IMAGE_SIZE_MB)

qemu: $(OVMF_CODE) $(FS_IMAGE)
	@test -f $(ISO) || { echo "Missing $(ISO); create it first with 'make iso' (WSL is supported)."; exit 1; }
	"$(QEMU)" $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive if=none,id=ginkgo-fs,format=raw,cache=writethrough,file=$(FS_IMAGE) \
		-device virtio-blk-pci,disable-modern=on,drive=ginkgo-fs \
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
		-device virtio-blk-pci,disable-modern=on,drive=ginkgo-fs \
		-drive if=none,id=ginkgo-boot,format=raw,file=fat:rw:$(NO_ISO_ROOT) \
		-device ide-hd,drive=ginkgo-boot,bus=ide.1,unit=0 -boot c

run: $(OVMF_CODE) $(ISO) $(FS_IMAGE)
	"$(QEMU)" $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive if=none,id=ginkgo-fs,format=raw,cache=writethrough,file=$(FS_IMAGE) \
		-device virtio-blk-pci,disable-modern=on,drive=ginkgo-fs \
		-cdrom $(ISO) -boot d

usb-smoke: kernel $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE) $(FS_IMAGE)
	rm -rf $(USB_SMOKE_ROOT)
	mkdir -p $(USB_SMOKE_ROOT)/boot/limine $(USB_SMOKE_ROOT)/EFI/BOOT
	cp $(KERNEL) $(USB_SMOKE_ROOT)/boot/kernel
	cp limine.conf $(USB_SMOKE_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(USB_SMOKE_ROOT)/EFI/BOOT/
	$(PYTHON) tools/qemu_usb_hotplug_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --disk $(FS_IMAGE) --boot-root $(USB_SMOKE_ROOT)

frame-reclaim-smoke: userspace $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE) $(FS_IMAGE)
	GINKGO_FRAME_RECLAIM_STRESS=1 GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(FRAME_RECLAIM_ROOT)
	mkdir -p $(FRAME_RECLAIM_ROOT)/boot/limine $(FRAME_RECLAIM_ROOT)/EFI/BOOT
	cp $(KERNEL) $(FRAME_RECLAIM_ROOT)/boot/kernel
	cp limine.conf $(FRAME_RECLAIM_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(FRAME_RECLAIM_ROOT)/EFI/BOOT/
	$(PYTHON) tools/qemu_frame_reclaim_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --disk $(FS_IMAGE) --boot-root $(FRAME_RECLAIM_ROOT)

process-capability-smoke: userspace $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE) $(FS_IMAGE)
	GINKGO_PROCESS_CAPABILITY_SMOKE=1 GINKGO_PROCESS_CAPABILITY_SMOKE_ELF="$(abspath $(PROCESS_CAPABILITY_SMOKE_ELF))" GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(PROCESS_CAPABILITY_SMOKE_ROOT)
	mkdir -p $(PROCESS_CAPABILITY_SMOKE_ROOT)/boot/limine $(PROCESS_CAPABILITY_SMOKE_ROOT)/EFI/BOOT
	cp $(KERNEL) $(PROCESS_CAPABILITY_SMOKE_ROOT)/boot/kernel
	cp limine.conf $(PROCESS_CAPABILITY_SMOKE_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(PROCESS_CAPABILITY_SMOKE_ROOT)/EFI/BOOT/
	rm -f $(PROCESS_CAPABILITY_SMOKE_DISK)
	$(PYTHON) tools/create_gpt_disk.py $(PROCESS_CAPABILITY_SMOKE_DISK) --size-mb 32
	$(PYTHON) tools/qemu_process_capability_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --disk $(PROCESS_CAPABILITY_SMOKE_DISK) --boot-root $(PROCESS_CAPABILITY_SMOKE_ROOT)

power-smoke: userspace $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE)
	GINKGO_POWER_SMOKE=sync GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(POWER_SYNC_ROOT)
	mkdir -p $(POWER_SYNC_ROOT)/boot/limine $(POWER_SYNC_ROOT)/EFI/BOOT
	cp $(KERNEL) $(POWER_SYNC_ROOT)/boot/kernel
	cp limine.conf $(POWER_SYNC_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(POWER_SYNC_ROOT)/EFI/BOOT/
	GINKGO_POWER_SMOKE=verify GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(POWER_VERIFY_ROOT)
	cp -r $(POWER_SYNC_ROOT) $(POWER_VERIFY_ROOT)
	cp $(KERNEL) $(POWER_VERIFY_ROOT)/boot/kernel
	GINKGO_POWER_SMOKE=cancel GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(POWER_CANCEL_ROOT)
	cp -r $(POWER_SYNC_ROOT) $(POWER_CANCEL_ROOT)
	cp $(KERNEL) $(POWER_CANCEL_ROOT)/boot/kernel
	GINKGO_POWER_SMOKE=reboot GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(POWER_REBOOT_ROOT)
	cp -r $(POWER_SYNC_ROOT) $(POWER_REBOOT_ROOT)
	cp $(KERNEL) $(POWER_REBOOT_ROOT)/boot/kernel
	rm -f $(POWER_PERSIST_DISK) $(POWER_CANCEL_DISK) $(POWER_REBOOT_DISK)
	$(PYTHON) tools/create_gpt_disk.py $(POWER_PERSIST_DISK) --size-mb 32
	$(PYTHON) tools/create_gpt_disk.py $(POWER_CANCEL_DISK) --size-mb 32
	$(PYTHON) tools/create_gpt_disk.py $(POWER_REBOOT_DISK) --size-mb 32
	$(PYTHON) tools/qemu_power_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --sync-root $(POWER_SYNC_ROOT) --verify-root $(POWER_VERIFY_ROOT) --cancel-root $(POWER_CANCEL_ROOT) --reboot-root $(POWER_REBOOT_ROOT) --persist-disk $(POWER_PERSIST_DISK) --cancel-disk $(POWER_CANCEL_DISK) --reboot-disk $(POWER_REBOOT_DISK)
	$(MAKE) process-capability-smoke

filesystem-smoke: userspace $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE)
	GINKGO_FILESYSTEM_HIERARCHY_SMOKE=1 GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(FILESYSTEM_SMOKE_ROOT)
	mkdir -p $(FILESYSTEM_SMOKE_ROOT)/boot/limine $(FILESYSTEM_SMOKE_ROOT)/EFI/BOOT
	cp $(KERNEL) $(FILESYSTEM_SMOKE_ROOT)/boot/kernel
	cp limine.conf $(FILESYSTEM_SMOKE_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(FILESYSTEM_SMOKE_ROOT)/EFI/BOOT/
	rm -f $(FILESYSTEM_SMOKE_DISK)
	$(PYTHON) tools/create_gpt_disk.py $(FILESYSTEM_SMOKE_DISK) --size-mb 32
	$(PYTHON) tools/qemu_filesystem_hierarchy_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --disk $(FILESYSTEM_SMOKE_DISK) --boot-root $(FILESYSTEM_SMOKE_ROOT)

text-editor-smoke: userspace $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE)
	GINKGO_TEXT_EDITOR_SMOKE=save cargo build --manifest-path $(USERSPACE_MANIFEST) --release --target x86_64-unknown-none -p ginkgo-text-editor
	GINKGO_TEXT_EDITOR_SMOKE=1 GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(TEXT_EDITOR_SAVE_ROOT)
	mkdir -p $(TEXT_EDITOR_SAVE_ROOT)/boot/limine $(TEXT_EDITOR_SAVE_ROOT)/EFI/BOOT
	cp $(KERNEL) $(TEXT_EDITOR_SAVE_ROOT)/boot/kernel
	cp limine.conf $(TEXT_EDITOR_SAVE_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(TEXT_EDITOR_SAVE_ROOT)/EFI/BOOT/
	GINKGO_TEXT_EDITOR_SMOKE=verify cargo build --manifest-path $(USERSPACE_MANIFEST) --release --target x86_64-unknown-none -p ginkgo-text-editor
	GINKGO_TEXT_EDITOR_SMOKE=1 GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo build -p ginkgo-kernel --bin ginkgo-os
	rm -rf $(TEXT_EDITOR_VERIFY_ROOT)
	cp -r $(TEXT_EDITOR_SAVE_ROOT) $(TEXT_EDITOR_VERIFY_ROOT)
	cp $(KERNEL) $(TEXT_EDITOR_VERIFY_ROOT)/boot/kernel
	rm -f $(TEXT_EDITOR_SMOKE_DISK)
	$(PYTHON) tools/create_gpt_disk.py $(TEXT_EDITOR_SMOKE_DISK) --size-mb 32
	$(PYTHON) tools/qemu_text_editor_test.py --qemu "$(QEMU)" --ovmf $(OVMF_CODE) --disk $(TEXT_EDITOR_SMOKE_DISK) --save-root $(TEXT_EDITOR_SAVE_ROOT) --verify-root $(TEXT_EDITOR_VERIFY_ROOT)

check: userspace
	GINKGO_DESKTOP_ELF="$(abspath $(DESKTOP_ELF))" GINKGO_MINIMAL_CLIENT_ELF="$(abspath $(MINIMAL_CLIENT_ELF))" GINKGO_FILE_NAVIGATOR_ELF="$(abspath $(FILE_NAVIGATOR_ELF))" GINKGO_TEXT_EDITOR_ELF="$(abspath $(TEXT_EDITOR_ELF))" GINKGO_TERMINAL_ELF="$(abspath $(TERMINAL_ELF))" cargo check -p ginkgo-kernel --bin ginkgo-os

clean:
	cargo clean
	rm -rf $(ISO_ROOT) $(NO_ISO_ROOT) $(USB_SMOKE_ROOT) $(FRAME_RECLAIM_ROOT) $(FILESYSTEM_SMOKE_ROOT) $(FILESYSTEM_SMOKE_DISK) $(TEXT_EDITOR_SAVE_ROOT) $(TEXT_EDITOR_VERIFY_ROOT) $(TEXT_EDITOR_SMOKE_DISK) $(PROCESS_CAPABILITY_SMOKE_ROOT) $(PROCESS_CAPABILITY_SMOKE_DISK) $(POWER_SYNC_ROOT) $(POWER_VERIFY_ROOT) $(POWER_CANCEL_ROOT) $(POWER_REBOOT_ROOT) $(POWER_PERSIST_DISK) $(POWER_CANCEL_DISK) $(POWER_REBOOT_DISK) $(ISO)

reset-fs:
	rm -f $(FS_IMAGE)

# Deliberately destructive: unlike clean, distclean also removes persistent data.
distclean: clean
	rm -rf $(BUILD_DIR)
