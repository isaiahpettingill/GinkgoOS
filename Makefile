SHELL := /bin/sh

IMAGE_NAME := ginkgo-os
BUILD_DIR := build
ISO_ROOT := $(BUILD_DIR)/iso_root
NO_ISO_ROOT := $(BUILD_DIR)/no_iso_root
KERNEL := target/x86_64-unknown-none/debug/ginkgo-os
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
QEMU ?= qemu-system-x86_64
QEMU_FLAGS ?= -m 512M -M q35 -serial stdio -device qemu-xhci,id=xhci -device usb-kbd,bus=xhci.0 -device usb-tablet,bus=xhci.0 -no-reboot -no-shutdown

.PHONY: all kernel iso qemu no-iso run check clean distclean

all: iso

kernel:
	cargo build

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

qemu: $(OVMF_CODE)
	@test -f $(ISO) || { echo "Missing $(ISO); create it first with 'make iso' (WSL is supported)."; exit 1; }
	$(QEMU) $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-cdrom $(ISO) -boot d

no-iso: kernel $(LIMINE_DIR)/BOOTX64.EFI $(OVMF_CODE) limine.conf
	rm -rf $(NO_ISO_ROOT)
	mkdir -p $(NO_ISO_ROOT)/boot/limine $(NO_ISO_ROOT)/EFI/BOOT
	cp $(KERNEL) $(NO_ISO_ROOT)/boot/kernel
	cp limine.conf $(NO_ISO_ROOT)/boot/limine/limine.conf
	cp $(LIMINE_DIR)/BOOTX64.EFI $(NO_ISO_ROOT)/EFI/BOOT/
	$(QEMU) $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-drive file=fat:rw:$(NO_ISO_ROOT),format=raw -boot c

run: $(OVMF_CODE) $(ISO)
	$(QEMU) $(QEMU_FLAGS) \
		-drive if=pflash,unit=0,format=raw,file=$(OVMF_CODE),readonly=on \
		-cdrom $(ISO) -boot d

check:
	cargo check

clean:
	cargo clean
	rm -rf $(ISO_ROOT) $(NO_ISO_ROOT) $(ISO)

distclean: clean
	rm -rf $(BUILD_DIR)
