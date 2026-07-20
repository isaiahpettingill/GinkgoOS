//! Polling xHCI USB HID transport.
//!
//! The implementation deliberately stops at raw HID report transport.  It
//! enumerates root-port devices, retains every HID report descriptor, and
//! continuously recycles one interrupt-IN transfer per HID interface.  Policy
//! and report interpretation belong in a higher layer.

use alloc::vec::Vec;
use core::{
    arch::{asm, x86_64::__cpuid},
    cmp,
    hint::spin_loop,
    ptr,
    sync::atomic::{compiler_fence, AtomicU64, Ordering},
};

use crate::{
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageFlags},
    pci::{self, PciBar, PciDevice, PciError},
};

pub const MAX_DEVICES: usize = 16;
pub const MAX_HID_INTERFACES: usize = 32;
pub const MAX_CONFIGURATION_DESCRIPTOR: usize = 4096;
pub const MAX_REPORT_DESCRIPTOR: usize = 4096;
pub const MAX_REPORT_SIZE: usize = 1024;
pub const MAX_REPORTS_PER_POLL: usize = 64;

const MAX_MMIO_SIZE: u64 = 16 * 1024 * 1024;
const RING_TRBS: usize = 256;
const RING_LINK_INDEX: usize = RING_TRBS - 1;
const WAIT_SECONDS: u64 = 5;
const FALLBACK_TSC_FREQUENCY: u64 = 1_000_000_000;
static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(FALLBACK_TSC_FREQUENCY);
const POLL_EVENT_BUDGET: usize = 256;
const MAX_EXTENDED_CAPABILITIES: usize = 64;

const USBCMD_RUN_STOP: u32 = 1 << 0;
const USBCMD_HOST_CONTROLLER_RESET: u32 = 1 << 1;
const USBSTS_HOST_CONTROLLER_HALTED: u32 = 1 << 0;
const USBSTS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USBSTS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const USBSTS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
const PORTSC_CURRENT_CONNECT_STATUS: u32 = 1 << 0;
const PORTSC_PORT_ENABLED: u32 = 1 << 1;
const PORTSC_PORT_RESET: u32 = 1 << 4;
const PORTSC_PORT_POWER: u32 = 1 << 9;
const PORTSC_WARM_PORT_RESET: u32 = 1 << 31;

const TRB_TYPE_NORMAL: u32 = 1;
const TRB_TYPE_SETUP_STAGE: u32 = 2;
const TRB_TYPE_DATA_STAGE: u32 = 3;
const TRB_TYPE_STATUS_STAGE: u32 = 4;
const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_ENABLE_SLOT_COMMAND: u32 = 9;
const TRB_TYPE_DISABLE_SLOT_COMMAND: u32 = 10;
const TRB_TYPE_ADDRESS_DEVICE_COMMAND: u32 = 11;
const TRB_TYPE_CONFIGURE_ENDPOINT_COMMAND: u32 = 12;
const TRB_TYPE_EVALUATE_CONTEXT_COMMAND: u32 = 13;
const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
const TRB_TYPE_COMMAND_COMPLETION_EVENT: u32 = 33;
const TRB_TYPE_PORT_STATUS_CHANGE_EVENT: u32 = 34;

const COMPLETION_SUCCESS: u8 = 1;
const COMPLETION_SHORT_PACKET: u8 = 13;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    TooShort,
    InvalidLength,
    InvalidType,
    LengthOverflow,
    TooLarge,
    MissingConfigurationValue,
    MissingHidReportDescriptor,
    MissingInterruptInEndpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbError {
    Pci(PciError),
    Paging(MapError),
    FrameAllocator(FrameAllocatorError),
    OutOfFrames,
    AddressOverflow,
    InvalidMmioBar,
    MmioOutOfRange,
    UnsupportedPageSize,
    UnsupportedDmaAddress,
    InvalidCapability,
    ControllerTimeout,
    ControllerError,
    NoSlots,
    InvalidPort,
    PortDisconnected,
    PortResetFailed,
    RingFull,
    CommandFailed(u8),
    TransferFailed(u8),
    InvalidSlot,
    InvalidEndpoint,
    Descriptor(DescriptorError),
    TooManyInterfaces,
    ReportTooLarge,
}

impl From<PciError> for UsbError {
    fn from(error: PciError) -> Self {
        Self::Pci(error)
    }
}

impl From<MapError> for UsbError {
    fn from(error: MapError) -> Self {
        Self::Paging(error)
    }
}

impl From<FrameAllocatorError> for UsbError {
    fn from(error: FrameAllocatorError) -> Self {
        Self::FrameAllocator(error)
    }
}

impl From<DescriptorError> for UsbError {
    fn from(error: DescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct HidInterfaceId {
    pub device: u32,
    pub interface: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HidInterfaceKind {
    Keyboard,
    Mouse,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HidInterfaceInfo {
    pub id: HidInterfaceId,
    pub slot_id: u8,
    pub root_port: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoint_address: u8,
    pub kind: HidInterfaceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HidReport {
    pub interface: HidInterfaceId,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortFailure {
    pub root_port: u8,
    pub error: UsbError,
}

/// A polling USB host.  It owns the xHCI controller and all DMA rings.
pub struct UsbHost {
    controller: Xhci,
    devices: Vec<UsbDevice>,
    failures: Vec<PortFailure>,
    next_device_id: u32,
}

impl UsbHost {
    /// Claims the first PCI xHCI controller and enumerates connected root ports.
    ///
    /// # Safety
    ///
    /// The caller must guarantee exclusive ownership of PCI configuration
    /// mechanism #1, the selected xHCI controller, and the fixed virtual MMIO
    /// mapping established by this function.  The supplied HHDM must map every
    /// frame returned by `frames` as coherent DMA memory.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<Self, UsbError> {
        let (pci_device, bar) = pci::claim_xhci()?;
        let controller = Xhci::initialize(page_table, frames, hhdm_offset, pci_device, bar)?;
        let mut host = Self {
            controller,
            devices: Vec::new(),
            failures: Vec::new(),
            next_device_id: 1,
        };

        // Enumerate USB 2 speeds first.  This makes boot keyboards and QEMU's
        // common USB tablet/keyboard setup available before slower SS probing.
        for usb2_pass in [true, false] {
            for port in 1..=host.controller.max_ports {
                let status = match host.controller.port_status(port) {
                    Ok(status) => status,
                    Err(error) => {
                        host.record_failure(port, error);
                        continue;
                    }
                };
                if status & PORTSC_CURRENT_CONNECT_STATUS == 0 {
                    continue;
                }
                let speed = ((status >> 10) & 0x0f) as u8;
                if (speed <= 3) != usb2_pass {
                    continue;
                }
                if host.devices.len() >= MAX_DEVICES {
                    break;
                }
                match host.enumerate_port(port, frames, hhdm_offset) {
                    Ok(device) => host.devices.push(device),
                    Err(error) => host.record_failure(port, error),
                }
            }
        }

        // No interrupt transfer is queued until all command/control traffic is
        // complete, so synchronous command waits cannot consume HID reports.
        for device in &mut host.devices {
            for interface in &mut device.interfaces {
                interface.queue_next()?;
                host.controller
                    .ring_doorbell(device.slot_id, interface.endpoint_id)?;
            }
        }

        Ok(host)
    }

    pub fn controller_pci_device(&self) -> PciDevice {
        self.controller.pci_device
    }

    pub fn interface_count(&self) -> usize {
        self.devices
            .iter()
            .map(|device| device.interfaces.len())
            .sum()
    }

    pub fn interface_info(&self, index: usize) -> Option<&HidInterfaceInfo> {
        let mut remaining = index;
        for device in &self.devices {
            if remaining < device.interfaces.len() {
                return device
                    .interfaces
                    .get(remaining)
                    .map(|interface| &interface.info);
            }
            remaining -= device.interfaces.len();
        }
        None
    }

    pub fn report_descriptor(&self, id: HidInterfaceId) -> Option<&[u8]> {
        self.find_interface(id)
            .map(|interface| interface.report_descriptor.as_slice())
    }

    pub fn enumeration_failures(&self) -> &[PortFailure] {
        &self.failures
    }

    /// Returns the completion code that retired an interface's input endpoint.
    pub fn interface_transfer_error(&self, id: HidInterfaceId) -> Option<u8> {
        self.find_interface(id)
            .and_then(|interface| interface.transfer_error)
    }

    /// Drains a bounded number of xHCI events and immediately requeues every
    /// completed interrupt-IN transfer.  No interrupt or timer is required.
    pub fn poll(&mut self) -> Result<Vec<HidReport>, UsbError> {
        self.controller.check_running()?;
        let mut reports = Vec::new();
        for _ in 0..POLL_EVENT_BUDGET {
            let Some(event) = self.controller.next_event()? else {
                break;
            };
            match event.trb_type() {
                TRB_TYPE_TRANSFER_EVENT => {
                    let completion = event.completion_code();
                    let slot_id = (event.dword[3] >> 24) as u8;
                    let endpoint_id = ((event.dword[3] >> 16) & 0x1f) as u8;
                    let residual = (event.dword[2] & 0x00ff_ffff) as usize;

                    let Some((device_index, interface_index)) =
                        self.find_endpoint_indexes(slot_id, endpoint_id)
                    else {
                        continue;
                    };
                    if completion != COMPLETION_SUCCESS && completion != COMPLETION_SHORT_PACKET {
                        if let Some(interface) = self
                            .devices
                            .get_mut(device_index)
                            .and_then(|device| device.interfaces.get_mut(interface_index))
                        {
                            interface.transfer_error = Some(completion);
                        }
                        continue;
                    }

                    let (id, bytes, doorbell_slot, doorbell_endpoint) = {
                        let device = self
                            .devices
                            .get_mut(device_index)
                            .ok_or(UsbError::InvalidSlot)?;
                        let interface = device
                            .interfaces
                            .get_mut(interface_index)
                            .ok_or(UsbError::InvalidEndpoint)?;
                        let completed_pointer = event.parameter() & !0x0f;
                        if completed_pointer != interface.queued_trb {
                            continue;
                        }
                        let actual = interface.buffer_len.saturating_sub(residual);
                        let actual = cmp::min(actual, interface.buffer_len);
                        let bytes = interface.buffer.read_bytes(actual)?;
                        let id = interface.info.id;
                        interface.queue_next()?;
                        (id, bytes, device.slot_id, interface.endpoint_id)
                    };
                    self.controller
                        .ring_doorbell(doorbell_slot, doorbell_endpoint)?;
                    if reports.len() < MAX_REPORTS_PER_POLL {
                        reports.push(HidReport {
                            interface: id,
                            bytes,
                        });
                    }
                }
                TRB_TYPE_PORT_STATUS_CHANGE_EVENT => {
                    // Hotplug policy is intentionally left to a future layer.
                    // Reading PORTSC acknowledges no destructive state here;
                    // initialization still reports every originally failed port.
                }
                _ => {}
            }
        }
        Ok(reports)
    }

    fn record_failure(&mut self, port: u8, error: UsbError) {
        if self.failures.len() < self.controller.max_ports as usize {
            self.failures.push(PortFailure {
                root_port: port,
                error,
            });
        }
    }

    fn find_interface(&self, id: HidInterfaceId) -> Option<&HidInterfaceState> {
        self.devices
            .iter()
            .flat_map(|device| device.interfaces.iter())
            .find(|interface| interface.info.id == id)
    }

    fn find_endpoint_indexes(&self, slot: u8, endpoint: u8) -> Option<(usize, usize)> {
        for (device_index, device) in self.devices.iter().enumerate() {
            if device.slot_id != slot {
                continue;
            }
            for (interface_index, interface) in device.interfaces.iter().enumerate() {
                if interface.endpoint_id == endpoint {
                    return Some((device_index, interface_index));
                }
            }
        }
        None
    }

    fn enumerate_port(
        &mut self,
        port: u8,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<UsbDevice, UsbError> {
        let speed = self.controller.reset_port(port)?;
        let slot_type = *self
            .controller
            .port_slot_types
            .get(usize::from(port - 1))
            .unwrap_or(&0);
        let slot_id = self.controller.enable_slot(slot_type)?;
        if slot_id == 0 || slot_id > self.controller.max_slots {
            return Err(UsbError::InvalidSlot);
        }

        let result = self.enumerate_slot(port, speed, slot_id, frames, hhdm_offset);
        if result.is_err() {
            let _ = self.controller.disable_slot(slot_id);
            let _ = self.controller.set_dcbaa_entry(slot_id, 0);
        }
        result
    }

    fn enumerate_slot(
        &mut self,
        port: u8,
        speed: u8,
        slot_id: u8,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<UsbDevice, UsbError> {
        let output_context = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
        let input_context = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
        let control_buffer = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
        let ep0_page = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
        let ep0_ring = ProducerRing::new(ep0_page)?;

        self.controller
            .set_dcbaa_entry(slot_id, output_context.physical)?;
        build_address_context(
            &input_context,
            self.controller.context_size,
            port,
            speed,
            initial_ep0_packet_size(speed),
            ep0_ring.physical(),
        )?;
        self.controller
            .address_device(slot_id, input_context.physical)?;

        let mut device = UsbDevice {
            _output_context: output_context,
            input_context,
            control_buffer,
            ep0_ring,
            slot_id,
            interfaces: Vec::new(),
        };

        let first = self
            .controller
            .control_in(&mut device, 0x80, 6, 0x0100, 0, 8)?;
        if first.len() < 8 || first[1] != 1 {
            return Err(DescriptorError::InvalidType.into());
        }
        let packet_size = descriptor_ep0_packet_size(speed, first[7])?;
        if packet_size != initial_ep0_packet_size(speed) {
            update_ep0_context(
                &device.input_context,
                &device._output_context,
                self.controller.context_size,
                packet_size,
            )?;
            self.controller
                .evaluate_context(slot_id, device.input_context.physical)?;
        }

        let device_descriptor = self
            .controller
            .control_in(&mut device, 0x80, 6, 0x0100, 0, 18)?;
        if device_descriptor.len() < 18 || device_descriptor[0] < 18 || device_descriptor[1] != 1 {
            return Err(DescriptorError::InvalidType.into());
        }
        let vendor_id = u16::from_le_bytes([device_descriptor[8], device_descriptor[9]]);
        let product_id = u16::from_le_bytes([device_descriptor[10], device_descriptor[11]]);

        let config_header = self
            .controller
            .control_in(&mut device, 0x80, 6, 0x0200, 0, 9)?;
        if config_header.len() < 9 || config_header[1] != 2 {
            return Err(DescriptorError::InvalidType.into());
        }
        let total_length = usize::from(u16::from_le_bytes([config_header[2], config_header[3]]));
        if total_length < 9 || total_length > MAX_CONFIGURATION_DESCRIPTOR {
            return Err(DescriptorError::TooLarge.into());
        }
        let configuration =
            self.controller
                .control_in(&mut device, 0x80, 6, 0x0200, 0, total_length)?;
        let parsed = parse_configuration_descriptor(&configuration)?;
        if parsed.interfaces.len() + self.interface_count() > MAX_HID_INTERFACES {
            return Err(UsbError::TooManyInterfaces);
        }

        self.controller.control_no_data(
            &mut device,
            0x00,
            9,
            u16::from(parsed.configuration_value),
            0,
        )?;

        let device_id = self.next_device_id;
        self.next_device_id = self.next_device_id.wrapping_add(1);
        let mut endpoint_states = Vec::new();
        for hid in parsed.interfaces {
            let report_descriptor = self.controller.control_in(
                &mut device,
                0x81,
                6,
                0x2200,
                u16::from(hid.interface_number),
                hid.report_descriptor_length,
            )?;
            if report_descriptor.is_empty() {
                return Err(DescriptorError::MissingHidReportDescriptor.into());
            }

            // SET_PROTOCOL is defined only by the HID boot-interface subclass.
            // Sending it to a generic joystick can stall and halt endpoint zero.
            if hid.subclass == 1 && matches!(hid.protocol, 1 | 2) {
                self.controller.control_no_data(
                    &mut device,
                    0x21,
                    0x0b,
                    1,
                    u16::from(hid.interface_number),
                )?;
            }

            let endpoint_id = endpoint_id(hid.endpoint_address)?;
            let ring_page = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
            let ring = ProducerRing::new(ring_page)?;
            let buffer = DmaPage::allocate(frames, hhdm_offset, self.controller.address_64)?;
            let buffer_len = hid.max_esit_payload;
            if buffer_len == 0 || buffer_len > MAX_REPORT_SIZE || buffer_len > PAGE_SIZE as usize {
                return Err(UsbError::ReportTooLarge);
            }
            let kind = match (hid.subclass, hid.protocol) {
                (1, 1) => HidInterfaceKind::Keyboard,
                (1, 2) => HidInterfaceKind::Mouse,
                _ => HidInterfaceKind::Other,
            };
            endpoint_states.push(HidInterfaceState {
                info: HidInterfaceInfo {
                    id: HidInterfaceId {
                        device: device_id,
                        interface: hid.interface_number,
                    },
                    slot_id,
                    root_port: port,
                    vendor_id,
                    product_id,
                    interface_subclass: hid.subclass,
                    interface_protocol: hid.protocol,
                    endpoint_address: hid.endpoint_address,
                    kind,
                },
                report_descriptor,
                endpoint_id,
                interval: endpoint_interval(speed, hid.interval),
                max_packet_size: hid.max_packet_size,
                max_burst: hid.max_burst,
                max_esit_payload: hid.max_esit_payload,
                ring,
                buffer,
                buffer_len,
                queued_trb: 0,
                transfer_error: None,
            });
        }

        if !endpoint_states.is_empty() {
            build_configure_endpoint_context(
                &device.input_context,
                &device._output_context,
                self.controller.context_size,
                &endpoint_states,
            )?;
            self.controller
                .configure_endpoint(slot_id, device.input_context.physical)?;
        }
        device.interfaces = endpoint_states;
        Ok(device)
    }
}

struct UsbDevice {
    _output_context: DmaPage,
    input_context: DmaPage,
    control_buffer: DmaPage,
    ep0_ring: ProducerRing,
    slot_id: u8,
    interfaces: Vec<HidInterfaceState>,
}

struct HidInterfaceState {
    info: HidInterfaceInfo,
    report_descriptor: Vec<u8>,
    endpoint_id: u8,
    interval: u8,
    max_packet_size: u16,
    max_burst: u8,
    max_esit_payload: usize,
    ring: ProducerRing,
    buffer: DmaPage,
    buffer_len: usize,
    queued_trb: u64,
    transfer_error: Option<u8>,
}

impl HidInterfaceState {
    fn queue_next(&mut self) -> Result<(), UsbError> {
        let status = u32::try_from(self.buffer_len).map_err(|_| UsbError::ReportTooLarge)?;
        let trb = Trb::new(
            self.buffer.physical,
            status,
            trb_control(TRB_TYPE_NORMAL) | (1 << 5) | (1 << 2),
        );
        self.queued_trb = self.ring.enqueue(trb)?;
        Ok(())
    }
}

struct Xhci {
    mmio: Mmio,
    pci_device: PciDevice,
    operational: usize,
    runtime: usize,
    doorbells: usize,
    max_slots: u8,
    max_ports: u8,
    context_size: usize,
    address_64: bool,
    port_slot_types: Vec<u8>,
    dcbaa: DmaPage,
    command_ring: ProducerRing,
    event_ring: EventRing,
    _erst: DmaPage,
    _scratchpad_array: Option<DmaPage>,
    _scratchpads: Vec<DmaPage>,
}

impl Xhci {
    unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
        pci_device: PciDevice,
        bar: PciBar,
    ) -> Result<Self, UsbError> {
        let mut mmio = map_mmio_bar(page_table, frames, bar)?;
        let capability_length = usize::from(mmio.read_u8(0)?);
        if capability_length < 0x20 {
            return Err(UsbError::InvalidCapability);
        }
        let hcsparams1 = mmio.read_u32(0x04)?;
        let hcsparams2 = mmio.read_u32(0x08)?;
        let hccparams1 = mmio.read_u32(0x10)?;
        let max_slots_hardware = hcsparams1 as u8;
        let max_ports = (hcsparams1 >> 24) as u8;
        if max_slots_hardware == 0 || max_ports == 0 {
            return Err(UsbError::InvalidCapability);
        }
        let max_slots = cmp::min(max_slots_hardware, MAX_DEVICES as u8);
        let context_size = if hccparams1 & (1 << 2) != 0 { 64 } else { 32 };
        let address_64 = hccparams1 & 1 != 0;
        let doorbells =
            usize::try_from(mmio.read_u32(0x14)? & !3).map_err(|_| UsbError::AddressOverflow)?;
        let runtime =
            usize::try_from(mmio.read_u32(0x18)? & !0x1f).map_err(|_| UsbError::AddressOverflow)?;
        let operational = capability_length;
        mmio.check(operational + 0x400 + (usize::from(max_ports) - 1) * 0x10, 4)?;
        mmio.check(runtime + 0x38, 8)?;
        mmio.check(doorbells + usize::from(max_slots) * 4, 4)?;

        let mut port_slot_types = vec_with_value(usize::from(max_ports), 0_u8);
        process_extended_capabilities(&mut mmio, hccparams1, max_ports, &mut port_slot_types)?;

        let command = mmio.read_u32(operational)?;
        mmio.write_u32(operational, command & !USBCMD_RUN_STOP)?;
        wait_for_bit(
            &mut mmio,
            operational + 0x04,
            USBSTS_HOST_CONTROLLER_HALTED,
            true,
        )?;
        mmio.write_u32(
            operational,
            (command & !USBCMD_RUN_STOP) | USBCMD_HOST_CONTROLLER_RESET,
        )?;
        wait_for_bit(&mut mmio, operational, USBCMD_HOST_CONTROLLER_RESET, false)?;
        wait_for_bit(
            &mut mmio,
            operational + 0x04,
            USBSTS_CONTROLLER_NOT_READY,
            false,
        )?;

        if mmio.read_u32(operational + 0x08)? & 1 == 0 {
            return Err(UsbError::UnsupportedPageSize);
        }

        let dcbaa = DmaPage::allocate(frames, hhdm_offset, address_64)?;
        let command_page = DmaPage::allocate(frames, hhdm_offset, address_64)?;
        let command_ring = ProducerRing::new(command_page)?;
        let event_page = DmaPage::allocate(frames, hhdm_offset, address_64)?;
        let event_ring = EventRing::new(event_page);
        let erst = DmaPage::allocate(frames, hhdm_offset, address_64)?;
        erst.write_u64(0, event_ring.physical())?;
        erst.write_u32(8, RING_TRBS as u32)?;
        erst.write_u32(12, 0)?;

        let scratchpad_count = (((hcsparams2 >> 21) & 0x1f) << 5) | ((hcsparams2 >> 27) & 0x1f);
        let mut scratchpad_array = None;
        let mut scratchpads = Vec::new();
        if scratchpad_count != 0 {
            if scratchpad_count > 512 {
                return Err(UsbError::InvalidCapability);
            }
            let array = DmaPage::allocate(frames, hhdm_offset, address_64)?;
            for index in 0..scratchpad_count as usize {
                let page = DmaPage::allocate(frames, hhdm_offset, address_64)?;
                array.write_u64(index * 8, page.physical)?;
                scratchpads.push(page);
            }
            dcbaa.write_u64(0, array.physical)?;
            scratchpad_array = Some(array);
        }

        mmio.write_u64(operational + 0x30, dcbaa.physical)?;
        mmio.write_u64(operational + 0x18, command_ring.physical() | 1)?;
        mmio.write_u32(operational + 0x38, u32::from(max_slots))?;

        let interrupter = runtime + 0x20;
        mmio.write_u32(interrupter + 0x00, 1)?; // clear IP, leave IE disabled
        mmio.write_u32(interrupter + 0x08, 1)?;
        mmio.write_u64(interrupter + 0x10, erst.physical)?;
        mmio.write_u64(interrupter + 0x18, event_ring.physical())?;

        // Keep the global interrupt enable clear: this driver only polls the
        // event ring and never installs an interrupt handler.
        let start = (mmio.read_u32(operational)? & !(1 << 2)) | USBCMD_RUN_STOP;
        mmio.write_u32(operational, start)?;
        wait_for_bit(
            &mut mmio,
            operational + 0x04,
            USBSTS_HOST_CONTROLLER_HALTED,
            false,
        )?;

        Ok(Self {
            mmio,
            pci_device,
            operational,
            runtime,
            doorbells,
            max_slots,
            max_ports,
            context_size,
            address_64,
            port_slot_types,
            dcbaa,
            command_ring,
            event_ring,
            _erst: erst,
            _scratchpad_array: scratchpad_array,
            _scratchpads: scratchpads,
        })
    }

    fn check_running(&mut self) -> Result<(), UsbError> {
        let status = self.mmio.read_u32(self.operational + 0x04)?;
        if status
            & (USBSTS_HOST_CONTROLLER_HALTED
                | USBSTS_HOST_SYSTEM_ERROR
                | USBSTS_HOST_CONTROLLER_ERROR)
            != 0
        {
            return Err(UsbError::ControllerError);
        }
        Ok(())
    }

    fn port_status(&mut self, port: u8) -> Result<u32, UsbError> {
        let offset = self.port_offset(port)?;
        self.mmio.read_u32(offset)
    }

    fn reset_port(&mut self, port: u8) -> Result<u8, UsbError> {
        let offset = self.port_offset(port)?;
        let mut status = self.mmio.read_u32(offset)?;
        if status & PORTSC_CURRENT_CONNECT_STATUS == 0 {
            return Err(UsbError::PortDisconnected);
        }
        if status & PORTSC_PORT_POWER == 0 {
            self.mmio.write_u32(offset, PORTSC_PORT_POWER)?;
            for _ in 0..10_000 {
                spin_loop();
            }
            status = self.mmio.read_u32(offset)?;
        }
        let speed = ((status >> 10) & 0x0f) as u8;
        if speed >= 4 {
            if status & PORTSC_PORT_ENABLED == 0 {
                self.mmio.write_u32(
                    offset,
                    (status & PORTSC_PORT_POWER) | PORTSC_WARM_PORT_RESET,
                )?;
                self.wait_port_reset(offset, PORTSC_WARM_PORT_RESET)?;
            }
        } else {
            self.mmio
                .write_u32(offset, (status & PORTSC_PORT_POWER) | PORTSC_PORT_RESET)?;
            self.wait_port_reset(offset, PORTSC_PORT_RESET)?;
        }
        status = self.mmio.read_u32(offset)?;
        if status & PORTSC_CURRENT_CONNECT_STATUS == 0 {
            return Err(UsbError::PortDisconnected);
        }
        if status & PORTSC_PORT_ENABLED == 0 {
            return Err(UsbError::PortResetFailed);
        }
        let speed = ((status >> 10) & 0x0f) as u8;
        if speed == 0 {
            return Err(UsbError::PortResetFailed);
        }
        Ok(speed)
    }

    fn wait_port_reset(&mut self, offset: usize, bit: u32) -> Result<(), UsbError> {
        let deadline = wait_deadline();
        while timestamp() < deadline {
            if self.mmio.read_u32(offset)? & bit == 0 {
                return Ok(());
            }
            spin_loop();
        }
        Err(UsbError::ControllerTimeout)
    }

    fn port_offset(&self, port: u8) -> Result<usize, UsbError> {
        if port == 0 || port > self.max_ports {
            return Err(UsbError::InvalidPort);
        }
        Ok(self.operational + 0x400 + (usize::from(port) - 1) * 0x10)
    }

    fn set_dcbaa_entry(&self, slot: u8, value: u64) -> Result<(), UsbError> {
        if slot == 0 || slot > self.max_slots {
            return Err(UsbError::InvalidSlot);
        }
        self.dcbaa.write_u64(usize::from(slot) * 8, value)
    }

    fn ring_doorbell(&mut self, slot: u8, target: u8) -> Result<(), UsbError> {
        if slot > self.max_slots || target > 31 {
            return Err(UsbError::InvalidEndpoint);
        }
        self.mmio
            .write_u32(self.doorbells + usize::from(slot) * 4, u32::from(target))
    }

    fn enable_slot(&mut self, slot_type: u8) -> Result<u8, UsbError> {
        let trb = Trb::new(
            0,
            0,
            trb_control(TRB_TYPE_ENABLE_SLOT_COMMAND) | (u32::from(slot_type & 0x1f) << 16),
        );
        let completion = self.command(trb)?;
        Ok((completion.dword[3] >> 24) as u8)
    }

    fn disable_slot(&mut self, slot: u8) -> Result<(), UsbError> {
        let trb = Trb::new(
            0,
            0,
            trb_control(TRB_TYPE_DISABLE_SLOT_COMMAND) | (u32::from(slot) << 24),
        );
        self.command(trb).map(|_| ())
    }

    fn address_device(&mut self, slot: u8, input_context: u64) -> Result<(), UsbError> {
        let trb = Trb::new(
            input_context,
            0,
            trb_control(TRB_TYPE_ADDRESS_DEVICE_COMMAND) | (u32::from(slot) << 24),
        );
        self.command(trb).map(|_| ())
    }

    fn evaluate_context(&mut self, slot: u8, input_context: u64) -> Result<(), UsbError> {
        let trb = Trb::new(
            input_context,
            0,
            trb_control(TRB_TYPE_EVALUATE_CONTEXT_COMMAND) | (u32::from(slot) << 24),
        );
        self.command(trb).map(|_| ())
    }

    fn configure_endpoint(&mut self, slot: u8, input_context: u64) -> Result<(), UsbError> {
        let trb = Trb::new(
            input_context,
            0,
            trb_control(TRB_TYPE_CONFIGURE_ENDPOINT_COMMAND) | (u32::from(slot) << 24),
        );
        self.command(trb).map(|_| ())
    }

    fn command(&mut self, trb: Trb) -> Result<Trb, UsbError> {
        let pointer = self.command_ring.enqueue(trb)?;
        self.ring_doorbell(0, 0)?;
        let deadline = wait_deadline();
        while timestamp() < deadline {
            if let Some(event) = self.next_event()? {
                if event.trb_type() != TRB_TYPE_COMMAND_COMPLETION_EVENT {
                    continue;
                }
                if event.parameter() & !0x0f != pointer & !0x0f {
                    continue;
                }
                let completion = event.completion_code();
                if completion != COMPLETION_SUCCESS {
                    return Err(UsbError::CommandFailed(completion));
                }
                return Ok(event);
            }
            spin_loop();
        }
        Err(UsbError::ControllerTimeout)
    }

    fn next_event(&mut self) -> Result<Option<Trb>, UsbError> {
        let Some(event) = self.event_ring.next()? else {
            return Ok(None);
        };
        let interrupter = self.runtime + 0x20;
        self.mmio.write_u64(
            interrupter + 0x18,
            self.event_ring.dequeue_pointer() | (1 << 3),
        )?;
        Ok(Some(event))
    }

    fn control_in(
        &mut self,
        device: &mut UsbDevice,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: usize,
    ) -> Result<Vec<u8>, UsbError> {
        if length > PAGE_SIZE as usize {
            return Err(UsbError::ReportTooLarge);
        }
        device.control_buffer.clear();
        let actual =
            self.control_transfer(device, request_type, request, value, index, length, true)?;
        device.control_buffer.read_bytes(actual)
    }

    fn control_no_data(
        &mut self,
        device: &mut UsbDevice,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
    ) -> Result<(), UsbError> {
        self.control_transfer(device, request_type, request, value, index, 0, false)
            .map(|_| ())
    }

    fn control_transfer(
        &mut self,
        device: &mut UsbDevice,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: usize,
        data_in: bool,
    ) -> Result<usize, UsbError> {
        let length_u16 = u16::try_from(length).map_err(|_| UsbError::ReportTooLarge)?;
        let setup_low =
            u32::from(request_type) | (u32::from(request) << 8) | (u32::from(value) << 16);
        let setup_high = u32::from(index) | (u32::from(length_u16) << 16);
        let transfer_type = if length == 0 {
            0
        } else if data_in {
            3
        } else {
            2
        };
        let setup = Trb {
            dword: [
                setup_low,
                setup_high,
                8,
                trb_control(TRB_TYPE_SETUP_STAGE) | (1 << 6) | (transfer_type << 16),
            ],
        };
        // Withhold ownership of the first TRB until the complete control TD is
        // present. A running endpoint may otherwise consume Setup before the
        // Data and Status stages have been published.
        let unpublished_setup = device.ep0_ring.enqueue_unpublished(setup)?;

        let data_pointer = if length != 0 {
            let pointer = device.ep0_ring.enqueue(Trb::new(
                device.control_buffer.physical,
                length as u32,
                trb_control(TRB_TYPE_DATA_STAGE) | ((data_in as u32) << 16) | (1 << 5) | (1 << 2),
            ))?;
            Some(pointer)
        } else {
            None
        };
        let status_direction_in = length == 0 || !data_in;
        let status_pointer = device.ep0_ring.enqueue(Trb::new(
            0,
            0,
            trb_control(TRB_TYPE_STATUS_STAGE) | ((status_direction_in as u32) << 16) | (1 << 5),
        ))?;
        device.ep0_ring.publish(unpublished_setup)?;
        self.ring_doorbell(device.slot_id, 1)?;

        let mut actual = length;
        let mut data_complete = data_pointer.is_none();
        let mut status_complete = false;
        let deadline = wait_deadline();
        while timestamp() < deadline {
            if let Some(event) = self.next_event()? {
                if event.trb_type() != TRB_TYPE_TRANSFER_EVENT
                    || (event.dword[3] >> 24) as u8 != device.slot_id
                    || ((event.dword[3] >> 16) & 0x1f) != 1
                {
                    continue;
                }
                let completion = event.completion_code();
                if completion != COMPLETION_SUCCESS && completion != COMPLETION_SHORT_PACKET {
                    return Err(UsbError::TransferFailed(completion));
                }
                let pointer = event.parameter() & !0x0f;
                if data_pointer.map(|value| value & !0x0f) == Some(pointer) {
                    let residual = (event.dword[2] & 0x00ff_ffff) as usize;
                    actual = length.saturating_sub(residual);
                    data_complete = true;
                }
                if status_pointer & !0x0f == pointer {
                    status_complete = true;
                }
                if data_complete && status_complete {
                    return Ok(cmp::min(actual, length));
                }
            }
            spin_loop();
        }
        Err(UsbError::ControllerTimeout)
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
struct Trb {
    dword: [u32; 4],
}

impl Trb {
    fn new(parameter: u64, status: u32, control: u32) -> Self {
        Self {
            dword: [parameter as u32, (parameter >> 32) as u32, status, control],
        }
    }

    fn parameter(self) -> u64 {
        u64::from(self.dword[0]) | (u64::from(self.dword[1]) << 32)
    }

    fn trb_type(self) -> u32 {
        (self.dword[3] >> 10) & 0x3f
    }

    fn completion_code(self) -> u8 {
        (self.dword[2] >> 24) as u8
    }
}

fn trb_control(trb_type: u32) -> u32 {
    trb_type << 10
}

struct UnpublishedTrb {
    index: usize,
    control: u32,
}

struct ProducerRing {
    page: DmaPage,
    enqueue_index: usize,
    cycle: bool,
}

impl ProducerRing {
    fn new(page: DmaPage) -> Result<Self, UsbError> {
        let mut ring = Self {
            page,
            enqueue_index: 0,
            cycle: true,
        };
        ring.write_link()?;
        Ok(ring)
    }

    fn physical(&self) -> u64 {
        self.page.physical
    }

    fn enqueue(&mut self, trb: Trb) -> Result<u64, UsbError> {
        self.enqueue_with_cycle(trb, self.cycle)
    }

    fn enqueue_unpublished(&mut self, trb: Trb) -> Result<UnpublishedTrb, UsbError> {
        let producer_cycle = self.cycle;
        let index = self.enqueue_index;
        let mut unpublished = trb;
        unpublished.dword[3] = (unpublished.dword[3] & !1) | u32::from(!producer_cycle);
        self.write_and_advance(index, unpublished)?;
        Ok(UnpublishedTrb {
            index,
            control: (trb.dword[3] & !1) | u32::from(producer_cycle),
        })
    }

    fn publish(&self, unpublished: UnpublishedTrb) -> Result<(), UsbError> {
        compiler_fence(Ordering::Release);
        self.page
            .write_u32(unpublished.index * 16 + 12, unpublished.control)
    }

    fn enqueue_with_cycle(&mut self, mut trb: Trb, cycle: bool) -> Result<u64, UsbError> {
        let index = self.enqueue_index;
        trb.dword[3] = (trb.dword[3] & !1) | u32::from(cycle);
        self.write_and_advance(index, trb)?;
        Ok(self.page.physical + (index * 16) as u64)
    }

    fn write_and_advance(&mut self, index: usize, trb: Trb) -> Result<(), UsbError> {
        if index >= RING_LINK_INDEX {
            return Err(UsbError::RingFull);
        }
        self.page.write_trb(index, trb)?;
        self.enqueue_index += 1;
        if self.enqueue_index == RING_LINK_INDEX {
            self.write_link()?;
            self.enqueue_index = 0;
            self.cycle = !self.cycle;
        }
        Ok(())
    }

    fn write_link(&mut self) -> Result<(), UsbError> {
        let link = Trb::new(
            self.page.physical,
            0,
            trb_control(TRB_TYPE_LINK) | (1 << 1) | u32::from(self.cycle),
        );
        self.page.write_trb(RING_LINK_INDEX, link)
    }
}

struct EventRing {
    page: DmaPage,
    dequeue_index: usize,
    cycle: bool,
}

impl EventRing {
    fn new(page: DmaPage) -> Self {
        Self {
            page,
            dequeue_index: 0,
            cycle: true,
        }
    }

    fn physical(&self) -> u64 {
        self.page.physical
    }

    fn dequeue_pointer(&self) -> u64 {
        self.page.physical + (self.dequeue_index * 16) as u64
    }

    fn next(&mut self) -> Result<Option<Trb>, UsbError> {
        let control = self.page.read_u32(self.dequeue_index * 16 + 12)?;
        if (control & 1 != 0) != self.cycle {
            return Ok(None);
        }
        compiler_fence(Ordering::Acquire);
        let event = self.page.read_trb(self.dequeue_index)?;
        self.dequeue_index += 1;
        if self.dequeue_index == RING_TRBS {
            self.dequeue_index = 0;
            self.cycle = !self.cycle;
        }
        Ok(Some(event))
    }
}

struct DmaPage {
    physical: u64,
    virtual_pointer: *mut u8,
}

impl DmaPage {
    fn allocate(
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
        address_64: bool,
    ) -> Result<Self, UsbError> {
        let frame = frames.allocate_frame()?.ok_or(UsbError::OutOfFrames)?;
        let physical = frame.start_address().as_u64();
        if !address_64 && physical.checked_add(PAGE_SIZE - 1).unwrap_or(u64::MAX) > u32::MAX as u64
        {
            return Err(UsbError::UnsupportedDmaAddress);
        }
        let virtual_address = hhdm_offset
            .checked_add(physical)
            .ok_or(UsbError::AddressOverflow)?;
        VirtAddr::new(virtual_address).ok_or(UsbError::AddressOverflow)?;
        let virtual_pointer =
            usize::try_from(virtual_address).map_err(|_| UsbError::AddressOverflow)? as *mut u8;
        // SAFETY: The initialization contract says HHDM covers allocated
        // frames.  This newly allocated frame has no other Rust references.
        unsafe { ptr::write_bytes(virtual_pointer, 0, PAGE_SIZE as usize) };
        Ok(Self {
            physical,
            virtual_pointer,
        })
    }

    fn clear(&self) {
        // SAFETY: This page remains exclusively owned by this DMA object.  The
        // caller only clears it when the controller has no outstanding use.
        unsafe { ptr::write_bytes(self.virtual_pointer, 0, PAGE_SIZE as usize) };
        compiler_fence(Ordering::Release);
    }

    fn check(&self, offset: usize, length: usize) -> Result<(), UsbError> {
        if offset
            .checked_add(length)
            .filter(|end| *end <= PAGE_SIZE as usize)
            .is_none()
        {
            Err(UsbError::AddressOverflow)
        } else {
            Ok(())
        }
    }

    fn read_u32(&self, offset: usize) -> Result<u32, UsbError> {
        self.check(offset, 4)?;
        if offset & 3 != 0 {
            return Err(UsbError::AddressOverflow);
        }
        // SAFETY: Bounds and alignment were checked; volatile access prevents
        // the compiler from caching controller-owned DMA memory.
        Ok(unsafe { ptr::read_volatile(self.virtual_pointer.add(offset).cast::<u32>()) })
    }

    fn write_u32(&self, offset: usize, value: u32) -> Result<(), UsbError> {
        self.check(offset, 4)?;
        if offset & 3 != 0 {
            return Err(UsbError::AddressOverflow);
        }
        unsafe { ptr::write_volatile(self.virtual_pointer.add(offset).cast::<u32>(), value) };
        Ok(())
    }

    fn write_u64(&self, offset: usize, value: u64) -> Result<(), UsbError> {
        self.check(offset, 8)?;
        if offset & 7 != 0 {
            return Err(UsbError::AddressOverflow);
        }
        unsafe { ptr::write_volatile(self.virtual_pointer.add(offset).cast::<u64>(), value) };
        Ok(())
    }

    fn write_trb(&self, index: usize, trb: Trb) -> Result<(), UsbError> {
        let offset = index.checked_mul(16).ok_or(UsbError::AddressOverflow)?;
        self.check(offset, 16)?;
        let pointer = unsafe { self.virtual_pointer.add(offset).cast::<u32>() };
        // Publish cycle/control last.  x86 DMA is coherent; the compiler fence
        // supplies the ordering required around volatile stores.
        unsafe {
            ptr::write_volatile(pointer, trb.dword[0]);
            ptr::write_volatile(pointer.add(1), trb.dword[1]);
            ptr::write_volatile(pointer.add(2), trb.dword[2]);
        }
        compiler_fence(Ordering::Release);
        unsafe { ptr::write_volatile(pointer.add(3), trb.dword[3]) };
        Ok(())
    }

    fn read_trb(&self, index: usize) -> Result<Trb, UsbError> {
        let offset = index.checked_mul(16).ok_or(UsbError::AddressOverflow)?;
        self.check(offset, 16)?;
        let pointer = unsafe { self.virtual_pointer.add(offset).cast::<u32>() };
        Ok(Trb {
            dword: unsafe {
                [
                    ptr::read_volatile(pointer),
                    ptr::read_volatile(pointer.add(1)),
                    ptr::read_volatile(pointer.add(2)),
                    ptr::read_volatile(pointer.add(3)),
                ]
            },
        })
    }

    fn read_bytes(&self, length: usize) -> Result<Vec<u8>, UsbError> {
        self.check(0, length)?;
        compiler_fence(Ordering::Acquire);
        let mut bytes = Vec::with_capacity(length);
        for index in 0..length {
            bytes.push(unsafe { ptr::read_volatile(self.virtual_pointer.add(index)) });
        }
        Ok(bytes)
    }
}

struct Mmio {
    base: *mut u8,
    length: usize,
}

impl Mmio {
    fn check(&self, offset: usize, width: usize) -> Result<(), UsbError> {
        if offset
            .checked_add(width)
            .filter(|end| *end <= self.length)
            .is_none()
        {
            Err(UsbError::MmioOutOfRange)
        } else {
            Ok(())
        }
    }

    fn read_u8(&mut self, offset: usize) -> Result<u8, UsbError> {
        self.check(offset, 1)?;
        Ok(unsafe { ptr::read_volatile(self.base.add(offset).cast_const()) })
    }

    fn read_u32(&mut self, offset: usize) -> Result<u32, UsbError> {
        self.check(offset, 4)?;
        if (self.base as usize + offset) & 3 != 0 {
            return Err(UsbError::InvalidMmioBar);
        }
        Ok(unsafe { ptr::read_volatile(self.base.add(offset).cast::<u32>().cast_const()) })
    }

    fn write_u32(&mut self, offset: usize, value: u32) -> Result<(), UsbError> {
        self.check(offset, 4)?;
        if (self.base as usize + offset) & 3 != 0 {
            return Err(UsbError::InvalidMmioBar);
        }
        unsafe { ptr::write_volatile(self.base.add(offset).cast::<u32>(), value) };
        Ok(())
    }

    fn write_u64(&mut self, offset: usize, value: u64) -> Result<(), UsbError> {
        self.check(offset, 8)?;
        if (self.base as usize + offset) & 3 != 0 {
            return Err(UsbError::InvalidMmioBar);
        }
        // xHCI requires 64-bit pointer registers to be programmed as low then
        // high dword writes; not every PCI host bridge accepts qword MMIO stores.
        self.write_u32(offset, value as u32)?;
        self.write_u32(offset + 4, (value >> 32) as u32)
    }
}

unsafe fn map_mmio_bar(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    bar: PciBar,
) -> Result<Mmio, UsbError> {
    if bar.size == 0 || bar.size > MAX_MMIO_SIZE {
        return Err(UsbError::InvalidMmioBar);
    }
    let physical_page = bar.physical_address & !(PAGE_SIZE - 1);
    let page_offset = bar.physical_address - physical_page;
    let mapped_length = page_offset
        .checked_add(bar.size)
        .and_then(|value| value.checked_add(PAGE_SIZE - 1))
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or(UsbError::AddressOverflow)?;
    let candidates = [
        0xffff_c000_0000_0000_u64,
        0xffff_d000_0000_0000,
        0xffff_e000_0000_0000,
        0xffff_f000_0000_0000,
        0xffff_ff00_0000_0000,
    ];
    let mut selected = None;
    'candidate: for base in candidates {
        let mut offset = 0;
        while offset < mapped_length {
            let address = VirtAddr::new(base + offset).ok_or(UsbError::AddressOverflow)?;
            if page_table.translate_addr(address).is_some() {
                continue 'candidate;
            }
            offset += PAGE_SIZE;
        }
        selected = Some(base);
        break;
    }
    let virtual_page = selected.ok_or(UsbError::InvalidMmioBar)?;
    let flags = PageFlags::WRITABLE.union(PageFlags::CACHE_DISABLE);
    let mut offset = 0;
    while offset < mapped_length {
        let physical_address = PhysAddr::new(
            physical_page
                .checked_add(offset)
                .ok_or(UsbError::AddressOverflow)?,
        )
        .ok_or(UsbError::AddressOverflow)?;
        let frame =
            PhysFrame::from_start_address(physical_address).ok_or(UsbError::InvalidMmioBar)?;
        let virtual_address = VirtAddr::new(
            virtual_page
                .checked_add(offset)
                .ok_or(UsbError::AddressOverflow)?,
        )
        .ok_or(UsbError::AddressOverflow)?;
        let page = VirtPage::from_start_address(virtual_address).ok_or(UsbError::InvalidMmioBar)?;
        page_table.map_4k(page, frame, flags, frames)?;
        offset += PAGE_SIZE;
    }
    let base = usize::try_from(virtual_page + page_offset).map_err(|_| UsbError::AddressOverflow)?
        as *mut u8;
    let length = usize::try_from(bar.size).map_err(|_| UsbError::AddressOverflow)?;
    Ok(Mmio { base, length })
}

/// Calibrates polling deadlines from Limine or architectural CPUID leaves.
pub fn configure_timestamp_frequency(reported_frequency: Option<u64>) {
    let frequency = reported_frequency
        .filter(|frequency| *frequency != 0)
        .or_else(detect_timestamp_frequency)
        .unwrap_or(FALLBACK_TSC_FREQUENCY);
    TSC_FREQUENCY.store(frequency, Ordering::Relaxed);
}

fn detect_timestamp_frequency() -> Option<u64> {
    let maximum_leaf = __cpuid(0).eax;
    if maximum_leaf >= 0x15 {
        let ratio = __cpuid(0x15);
        if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
            return u64::from(ratio.ecx)
                .checked_mul(u64::from(ratio.ebx))
                .map(|frequency| frequency / u64::from(ratio.eax))
                .filter(|frequency| *frequency != 0);
        }
    }
    if maximum_leaf >= 0x16 {
        let processor_frequency = __cpuid(0x16).eax;
        if processor_frequency != 0 {
            return Some(u64::from(processor_frequency) * 1_000_000);
        }
    }
    None
}

fn timestamp() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    u64::from(low) | (u64::from(high) << 32)
}

fn wait_deadline() -> u64 {
    let cycles = TSC_FREQUENCY
        .load(Ordering::Relaxed)
        .saturating_mul(WAIT_SECONDS);
    timestamp().saturating_add(cycles)
}

fn wait_for_bit(mmio: &mut Mmio, register: usize, mask: u32, set: bool) -> Result<(), UsbError> {
    let deadline = wait_deadline();
    while timestamp() < deadline {
        if (mmio.read_u32(register)? & mask != 0) == set {
            return Ok(());
        }
        spin_loop();
    }
    Err(UsbError::ControllerTimeout)
}

fn process_extended_capabilities(
    mmio: &mut Mmio,
    hccparams1: u32,
    max_ports: u8,
    port_slot_types: &mut [u8],
) -> Result<(), UsbError> {
    let mut offset =
        usize::try_from((hccparams1 >> 16) & 0xffff).map_err(|_| UsbError::AddressOverflow)? * 4;
    for _ in 0..MAX_EXTENDED_CAPABILITIES {
        if offset == 0 {
            return Ok(());
        }
        let header = mmio.read_u32(offset)?;
        match header & 0xff {
            1 => {
                mmio.write_u32(offset, header | (1 << 24))?;
                if header & (1 << 16) != 0 {
                    let deadline = wait_deadline();
                    while timestamp() < deadline {
                        if mmio.read_u32(offset)? & (1 << 16) == 0 {
                            break;
                        }
                        spin_loop();
                    }
                    if mmio.read_u32(offset)? & (1 << 16) != 0 {
                        return Err(UsbError::ControllerTimeout);
                    }
                }
                // Disable legacy SMI generation after ownership transfer.
                mmio.write_u32(offset + 4, 0)?;
            }
            2 => {
                let ports = mmio.read_u32(offset + 8)?;
                let slot_type = (mmio.read_u32(offset + 12)? & 0x1f) as u8;
                let first = (ports & 0xff) as u8;
                let count = ((ports >> 8) & 0xff) as u8;
                for port in first..first.saturating_add(count) {
                    if port != 0 && port <= max_ports {
                        if let Some(value) = port_slot_types.get_mut(usize::from(port - 1)) {
                            *value = slot_type;
                        }
                    }
                }
            }
            _ => {}
        }
        let next = ((header >> 8) & 0xff) as usize * 4;
        if next == 0 {
            return Ok(());
        }
        offset = offset.checked_add(next).ok_or(UsbError::AddressOverflow)?;
    }
    Err(UsbError::InvalidCapability)
}

fn initial_ep0_packet_size(speed: u8) -> u16 {
    match speed {
        3 => 64,
        4 | 5 => 512,
        _ => 8,
    }
}

fn descriptor_ep0_packet_size(speed: u8, encoded: u8) -> Result<u16, UsbError> {
    let size = if speed >= 4 {
        1_u16
            .checked_shl(u32::from(encoded))
            .ok_or(UsbError::Descriptor(DescriptorError::InvalidLength))?
    } else {
        u16::from(encoded)
    };
    if matches!(size, 8 | 16 | 32 | 64 | 512) {
        Ok(size)
    } else {
        Err(DescriptorError::InvalidLength.into())
    }
}

fn build_address_context(
    input: &DmaPage,
    context_size: usize,
    port: u8,
    speed: u8,
    packet_size: u16,
    ep0_ring: u64,
) -> Result<(), UsbError> {
    input.clear();
    input.write_u32(4, 0x3)?;
    let slot = context_size;
    input.write_u32(slot, (u32::from(speed) << 20) | (1 << 27))?;
    input.write_u32(slot + 4, u32::from(port) << 16)?;
    let ep0 = context_size * 2;
    input.write_u32(
        ep0 + 4,
        (3 << 1) | (4 << 3) | (u32::from(packet_size) << 16),
    )?;
    input.write_u32(ep0 + 8, (ep0_ring as u32) | 1)?;
    input.write_u32(ep0 + 12, (ep0_ring >> 32) as u32)?;
    input.write_u32(ep0 + 16, 8)?;
    Ok(())
}

fn update_ep0_context(
    input: &DmaPage,
    output: &DmaPage,
    context_size: usize,
    packet_size: u16,
) -> Result<(), UsbError> {
    input.clear();
    input.write_u32(4, 1 << 1)?;
    let source = context_size;
    let target = context_size * 2;
    for word in 0..context_size / 4 {
        input.write_u32(target + word * 4, output.read_u32(source + word * 4)?)?;
    }
    let dword1 = input.read_u32(target + 4)?;
    input.write_u32(
        target + 4,
        (dword1 & 0x0000_ffff) | (u32::from(packet_size) << 16),
    )
}

fn build_configure_endpoint_context(
    input: &DmaPage,
    output: &DmaPage,
    context_size: usize,
    interfaces: &[HidInterfaceState],
) -> Result<(), UsbError> {
    input.clear();
    let mut add_flags = 1_u32;
    let mut last_context = 1_u8;
    for interface in interfaces {
        if interface.endpoint_id == 0 || interface.endpoint_id > 31 {
            return Err(UsbError::InvalidEndpoint);
        }
        add_flags |= 1_u32 << interface.endpoint_id;
        last_context = cmp::max(last_context, interface.endpoint_id);
    }
    input.write_u32(4, add_flags)?;
    for word in 0..context_size / 4 {
        input.write_u32(context_size + word * 4, output.read_u32(word * 4)?)?;
    }
    let slot0 = input.read_u32(context_size)?;
    input.write_u32(
        context_size,
        (slot0 & !(0x1f << 27)) | (u32::from(last_context) << 27),
    )?;

    for interface in interfaces {
        let offset = (usize::from(interface.endpoint_id) + 1) * context_size;
        input.write_u32(offset, u32::from(interface.interval) << 16)?;
        input.write_u32(
            offset + 4,
            (3 << 1)
                | (7 << 3)
                | (u32::from(interface.max_burst) << 8)
                | (u32::from(interface.max_packet_size) << 16),
        )?;
        input.write_u32(offset + 8, (interface.ring.physical() as u32) | 1)?;
        input.write_u32(offset + 12, (interface.ring.physical() >> 32) as u32)?;
        input.write_u32(
            offset + 16,
            (interface.max_esit_payload as u32) | ((interface.max_esit_payload as u32) << 16),
        )?;
    }
    Ok(())
}

fn endpoint_id(endpoint_address: u8) -> Result<u8, UsbError> {
    if endpoint_address & 0x80 == 0 {
        return Err(UsbError::InvalidEndpoint);
    }
    let number = endpoint_address & 0x0f;
    if number == 0 || number > 15 {
        return Err(UsbError::InvalidEndpoint);
    }
    Ok(number * 2 + 1)
}

fn endpoint_interval(speed: u8, interval: u8) -> u8 {
    if speed >= 3 {
        interval.saturating_sub(1).min(15)
    } else {
        let frames = cmp::max(interval, 1) as u16;
        let microframes = frames * 8;
        let mut exponent = 0_u8;
        let mut value = 1_u16;
        while value <= microframes / 2 && exponent < 15 {
            value <<= 1;
            exponent += 1;
        }
        exponent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedHidInterface {
    interface_number: u8,
    subclass: u8,
    protocol: u8,
    report_descriptor_length: usize,
    endpoint_address: u8,
    max_packet_size: u16,
    max_burst: u8,
    max_esit_payload: usize,
    interval: u8,
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedConfiguration {
    configuration_value: u8,
    interfaces: Vec<ParsedHidInterface>,
}

fn parse_configuration_descriptor(bytes: &[u8]) -> Result<ParsedConfiguration, DescriptorError> {
    if bytes.len() < 9 {
        return Err(DescriptorError::TooShort);
    }
    if bytes[0] < 9 || bytes[1] != 2 {
        return Err(DescriptorError::InvalidType);
    }
    let declared = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if declared < 9 || declared > bytes.len() {
        return Err(DescriptorError::InvalidLength);
    }
    let configuration_value = bytes[5];
    if configuration_value == 0 {
        return Err(DescriptorError::MissingConfigurationValue);
    }

    #[derive(Clone, Copy)]
    struct Pending {
        number: u8,
        subclass: u8,
        protocol: u8,
        report_length: Option<usize>,
        endpoint: Option<(u8, u16, u8, usize, u8)>,
    }

    fn finish(
        pending: Option<Pending>,
        interfaces: &mut Vec<ParsedHidInterface>,
    ) -> Result<(), DescriptorError> {
        let Some(pending) = pending else {
            return Ok(());
        };
        let report_descriptor_length = pending
            .report_length
            .ok_or(DescriptorError::MissingHidReportDescriptor)?;
        let (endpoint_address, max_packet_size, max_burst, max_esit_payload, interval) = pending
            .endpoint
            .ok_or(DescriptorError::MissingInterruptInEndpoint)?;
        interfaces.push(ParsedHidInterface {
            interface_number: pending.number,
            subclass: pending.subclass,
            protocol: pending.protocol,
            report_descriptor_length,
            endpoint_address,
            max_packet_size,
            max_burst,
            max_esit_payload,
            interval,
        });
        Ok(())
    }

    let mut interfaces = Vec::new();
    let mut pending = None;
    let mut offset = 0;
    while offset < declared {
        if declared - offset < 2 {
            return Err(DescriptorError::TooShort);
        }
        let length = usize::from(bytes[offset]);
        if length < 2 {
            return Err(DescriptorError::InvalidLength);
        }
        let end = offset
            .checked_add(length)
            .ok_or(DescriptorError::LengthOverflow)?;
        if end > declared {
            return Err(DescriptorError::TooShort);
        }
        let descriptor = &bytes[offset..end];
        match descriptor[1] {
            4 => {
                finish(pending.take(), &mut interfaces)?;
                if length < 9 {
                    return Err(DescriptorError::InvalidLength);
                }
                if descriptor[5] == 3 && descriptor[3] == 0 {
                    pending = Some(Pending {
                        number: descriptor[2],
                        subclass: descriptor[6],
                        protocol: descriptor[7],
                        report_length: None,
                        endpoint: None,
                    });
                }
            }
            0x21 => {
                if let Some(current) = pending.as_mut() {
                    if length < 6 {
                        return Err(DescriptorError::InvalidLength);
                    }
                    let count = usize::from(descriptor[5]);
                    let required = 6_usize
                        .checked_add(
                            count
                                .checked_mul(3)
                                .ok_or(DescriptorError::LengthOverflow)?,
                        )
                        .ok_or(DescriptorError::LengthOverflow)?;
                    if required > length {
                        return Err(DescriptorError::InvalidLength);
                    }
                    for item in 0..count {
                        let item_offset = 6 + item * 3;
                        if descriptor[item_offset] == 0x22 {
                            let report_length = usize::from(u16::from_le_bytes([
                                descriptor[item_offset + 1],
                                descriptor[item_offset + 2],
                            ]));
                            if report_length == 0 || report_length > MAX_REPORT_DESCRIPTOR {
                                return Err(DescriptorError::TooLarge);
                            }
                            current.report_length = Some(report_length);
                        }
                    }
                }
            }
            5 => {
                if let Some(current) = pending.as_mut() {
                    if length < 7 {
                        return Err(DescriptorError::InvalidLength);
                    }
                    let address = descriptor[2];
                    let attributes = descriptor[3] & 3;
                    if address & 0x80 != 0 && attributes == 3 && current.endpoint.is_none() {
                        let encoded = u16::from_le_bytes([descriptor[4], descriptor[5]]);
                        let packet = encoded & 0x07ff;
                        let max_burst = ((encoded >> 11) & 3) as u8;
                        if packet == 0 || max_burst == 3 {
                            return Err(DescriptorError::InvalidLength);
                        }
                        let payload = usize::from(packet)
                            .checked_mul(usize::from(max_burst) + 1)
                            .ok_or(DescriptorError::LengthOverflow)?;
                        current.endpoint =
                            Some((address, packet, max_burst, payload, descriptor[6]));
                    }
                }
            }
            0x30 => {
                if length < 6 {
                    return Err(DescriptorError::InvalidLength);
                }
                if let Some(current) = pending.as_mut() {
                    if let Some((_, _, max_burst, payload, _)) = current.endpoint.as_mut() {
                        let bytes_per_interval =
                            usize::from(u16::from_le_bytes([descriptor[4], descriptor[5]]));
                        if descriptor[2] > 15 {
                            return Err(DescriptorError::InvalidLength);
                        }
                        *max_burst = descriptor[2];
                        if bytes_per_interval != 0 {
                            *payload = bytes_per_interval;
                        }
                    }
                }
            }
            _ => {}
        }
        offset = end;
    }
    finish(pending, &mut interfaces)?;
    Ok(ParsedConfiguration {
        configuration_value,
        interfaces,
    })
}

fn vec_with_value<T: Clone>(length: usize, value: T) -> Vec<T> {
    let mut result = Vec::with_capacity(length);
    result.resize(length, value);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trb_fields_round_trip() {
        let trb = Trb::new(0x1234_5678_9abc_def0, 0x1122, trb_control(12));
        assert_eq!(trb.parameter(), 0x1234_5678_9abc_def0);
        assert_eq!(trb.trb_type(), 12);
    }

    #[test]
    fn parses_keyboard_and_joystick_hid_interfaces() {
        let descriptor = [
            9, 2, 59, 0, 2, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 1, 3, 1, 1, 0, // keyboard interface
            9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0, // HID
            7, 5, 0x81, 3, 8, 0, 10, // endpoint
            9, 4, 1, 0, 1, 3, 0, 0, 0, // generic HID interface
            9, 0x21, 0x11, 0x01, 0, 1, 0x22, 48, 0, // HID
            7, 5, 0x82, 3, 16, 0, 4, // endpoint
        ];
        let parsed = parse_configuration_descriptor(&descriptor).unwrap();
        assert_eq!(parsed.configuration_value, 1);
        assert_eq!(parsed.interfaces.len(), 2);
        assert_eq!(parsed.interfaces[0].report_descriptor_length, 63);
        assert_eq!(parsed.interfaces[1].endpoint_address, 0x82);
    }

    #[test]
    fn rejects_zero_length_descriptor_without_looping() {
        let descriptor = [9, 2, 11, 0, 0, 1, 0, 0x80, 50, 0, 4];
        assert_eq!(
            parse_configuration_descriptor(&descriptor),
            Err(DescriptorError::InvalidLength)
        );
    }

    #[test]
    fn publishes_a_complete_td_by_releasing_its_first_trb_last() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);

        let mut backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let page = DmaPage {
            physical: 0x1000,
            virtual_pointer: backing.0.as_mut_ptr(),
        };
        let mut ring = ProducerRing::new(page).unwrap();
        let first = ring
            .enqueue_unpublished(Trb::new(1, 2, trb_control(TRB_TYPE_SETUP_STAGE)))
            .unwrap();
        ring.enqueue(Trb::new(3, 4, trb_control(TRB_TYPE_DATA_STAGE)))
            .unwrap();
        ring.enqueue(Trb::new(5, 6, trb_control(TRB_TYPE_STATUS_STAGE)))
            .unwrap();

        assert_eq!(ring.page.read_u32(12).unwrap() & 1, 0);
        assert_eq!(ring.page.read_u32(28).unwrap() & 1, 1);
        assert_eq!(ring.page.read_u32(44).unwrap() & 1, 1);
        ring.publish(first).unwrap();
        assert_eq!(ring.page.read_u32(12).unwrap() & 1, 1);
    }

    #[test]
    fn endpoint_ids_follow_xhci_direction_encoding() {
        assert_eq!(endpoint_id(0x81), Ok(3));
        assert_eq!(endpoint_id(0x8f), Ok(31));
        assert_eq!(endpoint_id(0x01), Err(UsbError::InvalidEndpoint));
    }
}
