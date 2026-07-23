//! xHCI USB HID transport with hubs, hotplug, and optional MSI delivery.
//!
//! The implementation stops at raw HID report transport. It tracks a bounded
//! five-tier topology, retains every HID report descriptor, and continuously
//! recycles one interrupt-IN transfer per HID interface. Policy and report
//! interpretation belong in a higher layer.

use alloc::{collections::VecDeque, vec::Vec};
use bitflags::bitflags;
use core::{
    arch::x86_64::{__cpuid, _rdtsc},
    cmp,
    hint::spin_loop,
    ptr::{self, NonNull},
    sync::atomic::{compiler_fence, AtomicU64, Ordering},
};
use volatile::VolatilePtr;

use crate::{
    arch::{take_xhci_interrupt_pending, XHCI_VECTOR},
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        DMA_32BIT_ADDRESS_LIMIT, PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageTableFlags},
    pci::{self, PciBar, PciConfig, PciDevice, PciError},
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
const DEFERRED_EVENT_INITIAL_CAPACITY: usize = RING_TRBS;
const LIFECYCLE_EVENT_CAPACITY: usize = 128;
const FAILURE_CAPACITY: usize = 128;
const MAX_HUB_DEPTH: u8 = 5;
const HUB_PORTS_PER_POLL: usize = 4;
const INTERRUPT_WATCHDOG_POLLS: u64 = 64;
const MAX_EXTENDED_CAPABILITIES: usize = 64;

const PORTSC_CHANGE_BITS: u32 =
    (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
const PORTSC_WRITE_PRESERVE: u32 = (1 << 9) | (3 << 14) | (7 << 25);

const USB_REQUEST_GET_STATUS: u8 = 0;
const USB_REQUEST_CLEAR_FEATURE: u8 = 1;
const USB_REQUEST_SET_FEATURE: u8 = 3;
const USB_REQUEST_GET_DESCRIPTOR: u8 = 6;
const USB_PORT_FEATURE_RESET: u16 = 4;
const USB_PORT_FEATURE_POWER: u16 = 8;
const USB_PORT_STATUS_CONNECTION: u16 = 1 << 0;
const USB_PORT_STATUS_ENABLE: u16 = 1 << 1;
const USB_PORT_STATUS_RESET: u16 = 1 << 4;
const USB_PORT_STATUS_LOW_SPEED: u16 = 1 << 9;
const USB_PORT_STATUS_HIGH_SPEED: u16 = 1 << 10;

const USBCMD_RUN_STOP: u32 = 1 << 0;
const USBCMD_HOST_CONTROLLER_RESET: u32 = 1 << 1;
const USBSTS_HOST_CONTROLLER_HALTED: u32 = 1 << 0;
const USBSTS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USBSTS_CONTROLLER_NOT_READY: u32 = 1 << 11;
const USBSTS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;
bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PortStatus: u32 {
        const CURRENT_CONNECT_STATUS = 1 << 0;
        const PORT_ENABLED = 1 << 1;
        const PORT_RESET = 1 << 4;
        const PORT_POWER = 1 << 9;
        const WARM_PORT_RESET = 1 << 31;
    }
}

impl PortStatus {
    fn speed(self) -> u8 {
        ((self.bits() >> 10) & 0x0f) as u8
    }
}

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

/// A stable, controller-independent USB topology path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct UsbPath {
    pub root_port: u8,
    /// xHCI's packed four-bit downstream port numbers.
    pub route_string: u32,
    pub depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TopologyFailure {
    pub path: UsbPath,
    pub error: UsbError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsbLifecycleEvent {
    InterfaceAdded(HidInterfaceInfo),
    InterfaceRemoved(HidInterfaceInfo),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbTopologyEntry {
    pub path: UsbPath,
    pub slot_id: u8,
    pub parent_slot_id: Option<u8>,
    pub parent_port: Option<u8>,
    pub speed: u8,
    pub is_hub: bool,
    pub hub_port_count: u8,
    pub interface_count: usize,
}

impl UsbPath {
    pub const fn root(root_port: u8) -> Self {
        Self {
            root_port,
            route_string: 0,
            depth: 0,
        }
    }

    pub fn child(self, port: u8) -> Result<Self, UsbError> {
        if self.depth >= MAX_HUB_DEPTH || port == 0 || port > 15 {
            return Err(UsbError::InvalidPort);
        }
        let shift = u32::from(self.depth) * 4;
        Ok(Self {
            root_port: self.root_port,
            route_string: self.route_string | (u32::from(port) << shift),
            depth: self.depth + 1,
        })
    }

    fn is_descendant_of(self, ancestor: Self) -> bool {
        if self.root_port != ancestor.root_port || self.depth < ancestor.depth {
            return false;
        }
        let bits = u32::from(ancestor.depth) * 4;
        let mask = if bits == 0 { 0 } else { (1_u32 << bits) - 1 };
        self.route_string & mask == ancestor.route_string & mask
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XhciInterruptDiagnostics {
    pub msi_enabled: bool,
    pub interrupts_observed: u64,
    pub watchdog_polls: u64,
    pub deferred_events: usize,
    pub dropped_deferred_events: u64,
}

/// An xHCI USB host with bounded polling and optional MSI event delivery.
pub struct UsbHost {
    controller: Xhci,
    devices: Vec<UsbDevice>,
    failures: Vec<PortFailure>,
    topology_failures: Vec<TopologyFailure>,
    lifecycle_events: VecDeque<UsbLifecycleEvent>,
    next_device_id: u32,
    root_cursor: u8,
    poll_sequence: u64,
    hub_cursor: usize,
    dma_pool: UsbDmaPool,
    quarantined_slots: Vec<u8>,
    quarantined_devices: Vec<UsbDevice>,
}

impl UsbHost {
    /// Claims xHCI and enumerates connected root ports and hub descendants.
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
            topology_failures: Vec::new(),
            lifecycle_events: VecDeque::with_capacity(LIFECYCLE_EVENT_CAPACITY),
            next_device_id: 1,
            root_cursor: 1,
            poll_sequence: 0,
            hub_cursor: 0,
            dma_pool: UsbDmaPool::new(),
            quarantined_slots: Vec::new(),
            quarantined_devices: Vec::new(),
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
                if !status.contains(PortStatus::CURRENT_CONNECT_STATUS) {
                    continue;
                }
                let speed = status.speed();
                if (speed <= 3) != usb2_pass {
                    continue;
                }
                if host.slot_capacity_reached() {
                    break;
                }
                match host.enumerate_port(port, frames, hhdm_offset) {
                    Ok(device) => host.add_device(device, false)?,
                    Err(error) => host.record_path_failure(UsbPath::root(port), error),
                }
            }
        }

        // Breadth-first hub scans make boot-time QEMU hub topologies available
        // before interrupt endpoints begin continuously producing reports.
        host.enumerate_initial_hubs(frames, hhdm_offset);

        for device in &mut host.devices {
            for interface in &mut device.interfaces {
                if !interface.active {
                    continue;
                }
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
            .map(|device| {
                device
                    .interfaces
                    .iter()
                    .filter(|interface| interface.active)
                    .count()
            })
            .sum()
    }

    pub fn interface_info(&self, index: usize) -> Option<&HidInterfaceInfo> {
        self.devices
            .iter()
            .flat_map(|device| device.interfaces.iter())
            .filter(|interface| interface.active)
            .nth(index)
            .map(|interface| &interface.info)
    }

    pub fn report_descriptor(&self, id: HidInterfaceId) -> Option<&[u8]> {
        self.find_interface(id)
            .map(|interface| interface.report_descriptor.as_slice())
    }

    pub fn enumeration_failures(&self) -> &[PortFailure] {
        &self.failures
    }

    pub fn topology_failures(&self) -> &[TopologyFailure] {
        &self.topology_failures
    }

    pub fn topology_snapshot(&self) -> Vec<UsbTopologyEntry> {
        self.devices
            .iter()
            .map(|device| UsbTopologyEntry {
                path: device.path,
                slot_id: device.slot_id,
                parent_slot_id: device.parent_slot_id,
                parent_port: device.parent_port,
                speed: device.speed,
                is_hub: device.hub.is_some(),
                hub_port_count: device.hub.as_ref().map_or(0, |hub| hub.ports),
                interface_count: device
                    .interfaces
                    .iter()
                    .filter(|interface| interface.active)
                    .count(),
            })
            .collect()
    }

    pub fn pop_lifecycle_event(&mut self) -> Option<UsbLifecycleEvent> {
        self.lifecycle_events.pop_front()
    }

    pub fn recycled_dma_pages(&self) -> usize {
        self.dma_pool.len()
    }

    pub fn interrupt_diagnostics(&self) -> XhciInterruptDiagnostics {
        XhciInterruptDiagnostics {
            msi_enabled: self.controller.msi_enabled,
            interrupts_observed: self.controller.interrupts_observed,
            watchdog_polls: self.controller.watchdog_polls,
            deferred_events: self.controller.deferred_events.len(),
            dropped_deferred_events: 0,
        }
    }

    /// Programs one xHCI MSI and enables the xHCI primary interrupter.
    ///
    /// # Safety
    ///
    /// The caller must provide exclusive PCI mechanism #1 access and ensure the
    /// IDT/APIC path for [`XHCI_VECTOR`] is active for `destination_apic_id`.
    pub unsafe fn enable_msi(&mut self, destination_apic_id: u8) -> Result<(), UsbError> {
        let mut config = PciConfig::new()?;
        config.configure_msi(self.controller.pci_device, destination_apic_id, XHCI_VECTOR)?;
        self.controller.enable_interrupts()?;
        Ok(())
    }

    /// Returns the completion code that retired an interface's input endpoint.
    pub fn interface_transfer_error(&self, id: HidInterfaceId) -> Option<u8> {
        self.devices
            .iter()
            .flat_map(|device| device.interfaces.iter())
            .find(|interface| interface.info.id == id)
            .and_then(|interface| interface.transfer_error)
    }

    /// Polling-compatible event drain. Disconnects are handled immediately, but
    /// newly connected devices wait for [`Self::poll_with_resources`] because
    /// xHCI slot setup requires DMA frames.
    pub fn poll(&mut self) -> Result<Vec<HidReport>, UsbError> {
        self.poll_events(None)
    }

    /// Drains events and performs bounded runtime root/hub enumeration.
    pub fn poll_with_resources(
        &mut self,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<Vec<HidReport>, UsbError> {
        self.poll_events(Some((frames, hhdm_offset)))
    }

    fn poll_events(
        &mut self,
        mut resources: Option<(&mut UsableFrameAllocator<'_>, u64)>,
    ) -> Result<Vec<HidReport>, UsbError> {
        self.controller.check_running()?;
        self.poll_sequence = self.poll_sequence.wrapping_add(1);
        let interrupt_pending = take_xhci_interrupt_pending();
        if interrupt_pending {
            self.controller.interrupts_observed =
                self.controller.interrupts_observed.saturating_add(1);
        }
        let watchdog =
            !self.controller.msi_enabled || self.poll_sequence % INTERRUPT_WATCHDOG_POLLS == 0;
        if watchdog && self.controller.msi_enabled && !interrupt_pending {
            self.controller.watchdog_polls = self.controller.watchdog_polls.saturating_add(1);
        }

        let mut reports = Vec::new();
        if interrupt_pending || watchdog || !self.controller.deferred_events.is_empty() {
            for _ in 0..POLL_EVENT_BUDGET {
                let Some(event) = self.controller.next_event()? else {
                    break;
                };
                self.process_event(event, &mut reports)?;
            }
        }

        if self.controller.msi_enabled {
            self.controller.ack_primary_interrupter()?;
        }
        self.retry_quarantined_devices();

        match resources.as_mut() {
            Some((frames, hhdm)) => self.watch_root_port(Some((&mut **frames, *hhdm)))?,
            None => self.watch_root_port(None)?,
        }
        match resources.as_mut() {
            Some((frames, hhdm)) => self.poll_hub_ports(Some((&mut **frames, *hhdm))),
            None => self.poll_hub_ports(None),
        };
        Ok(reports)
    }

    fn process_event(&mut self, event: Trb, reports: &mut Vec<HidReport>) -> Result<(), UsbError> {
        match event.trb_type() {
            TRB_TYPE_TRANSFER_EVENT => {
                let completion = event.completion_code();
                let slot_id = (event.dword[3] >> 24) as u8;
                let endpoint_id = ((event.dword[3] >> 16) & 0x1f) as u8;
                let residual = (event.dword[2] & 0x00ff_ffff) as usize;
                let Some((device_index, interface_index)) =
                    self.find_endpoint_indexes(slot_id, endpoint_id)
                else {
                    return Ok(()); // completion from a disabled/removed slot
                };
                if completion != COMPLETION_SUCCESS && completion != COMPLETION_SHORT_PACKET {
                    let interface = &mut self.devices[device_index].interfaces[interface_index];
                    if let Some(removed) = retire_interface(interface, completion) {
                        self.push_lifecycle(UsbLifecycleEvent::InterfaceRemoved(removed));
                    }
                    return Ok(());
                }
                let (id, bytes, doorbell_slot, doorbell_endpoint) = {
                    let device = &mut self.devices[device_index];
                    let interface = &mut device.interfaces[interface_index];
                    if event.parameter() & !0x0f != interface.queued_trb {
                        return Ok(());
                    }
                    let actual = cmp::min(
                        interface.buffer_len.saturating_sub(residual),
                        interface.buffer_len,
                    );
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
                let port = ((event.parameter() >> 24) & 0xff) as u8;
                if port != 0 && port <= self.controller.max_ports {
                    self.service_root_port(port, None)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn slot_capacity_reached(&self) -> bool {
        self.devices.len() + self.quarantined_slots.len() + self.quarantined_devices.len()
            >= MAX_DEVICES
    }

    fn record_failure(&mut self, port: u8, error: UsbError) {
        self.record_path_failure(UsbPath::root(port), error);
    }

    fn record_path_failure(&mut self, path: UsbPath, error: UsbError) {
        if self.topology_failures.len() == FAILURE_CAPACITY {
            self.topology_failures.remove(0);
        }
        self.topology_failures.push(TopologyFailure { path, error });
        if path.depth == 0 {
            if self.failures.len() == FAILURE_CAPACITY {
                self.failures.remove(0);
            }
            self.failures.push(PortFailure {
                root_port: path.root_port,
                error,
            });
        }
    }

    fn push_lifecycle(&mut self, event: UsbLifecycleEvent) {
        push_bounded(&mut self.lifecycle_events, LIFECYCLE_EVENT_CAPACITY, event);
    }

    fn add_device(&mut self, device: UsbDevice, activate: bool) -> Result<(), UsbError> {
        let path = device.path;
        self.devices.push(device);
        let index = self.devices.len() - 1;
        if activate {
            let activation = (|| -> Result<(), UsbError> {
                let device = &mut self.devices[index];
                for interface in &mut device.interfaces {
                    if !interface.active {
                        continue;
                    }
                    interface.queue_next()?;
                    self.controller
                        .ring_doorbell(device.slot_id, interface.endpoint_id)?;
                }
                Ok(())
            })();
            if let Err(error) = activation {
                self.teardown_path(path);
                return Err(error);
            }
        }
        let added: Vec<HidInterfaceInfo> = self.devices[index]
            .interfaces
            .iter()
            .filter(|interface| interface.active)
            .map(|interface| interface.info.clone())
            .collect();
        for info in added {
            self.push_lifecycle(UsbLifecycleEvent::InterfaceAdded(info));
        }
        Ok(())
    }

    fn watch_root_port(
        &mut self,
        resources: Option<(&mut UsableFrameAllocator<'_>, u64)>,
    ) -> Result<(), UsbError> {
        let port = self.root_cursor.max(1);
        self.root_cursor = if port >= self.controller.max_ports {
            1
        } else {
            port + 1
        };
        self.service_root_port(port, resources)
    }

    fn service_root_port(
        &mut self,
        port: u8,
        resources: Option<(&mut UsableFrameAllocator<'_>, u64)>,
    ) -> Result<(), UsbError> {
        let status = self.controller.port_status_and_ack(port)?;
        let path = UsbPath::root(port);
        let present = self.devices.iter().any(|device| device.path == path);
        if !status.contains(PortStatus::CURRENT_CONNECT_STATUS) {
            if present {
                self.teardown_path(path);
            }
            return Ok(());
        }
        if present || self.slot_capacity_reached() {
            return Ok(());
        }
        let Some((frames, hhdm_offset)) = resources else {
            return Ok(());
        };
        match self.enumerate_port(port, frames, hhdm_offset) {
            Ok(device) => self.add_device(device, true),
            Err(error) => {
                self.record_path_failure(path, error);
                Ok(())
            }
        }
    }

    fn enumerate_initial_hubs(&mut self, frames: &mut UsableFrameAllocator<'_>, hhdm_offset: u64) {
        let mut hub_index = 0;
        while hub_index < self.devices.len() && !self.slot_capacity_reached() {
            let ports = self.devices[hub_index]
                .hub
                .as_ref()
                .map_or(0, |hub| hub.ports);
            for port in 1..=ports {
                if self.slot_capacity_reached() {
                    break;
                }
                self.inspect_hub_port(hub_index, port, Some((&mut *frames, hhdm_offset)), false);
            }
            hub_index += 1;
        }
    }

    fn poll_hub_ports(&mut self, mut resources: Option<(&mut UsableFrameAllocator<'_>, u64)>) {
        for _ in 0..HUB_PORTS_PER_POLL {
            let Some((hub_index, port)) = self.next_hub_port() else {
                break;
            };
            match resources.as_mut() {
                Some((frames, hhdm)) => {
                    self.inspect_hub_port(hub_index, port, Some((&mut **frames, *hhdm)), true)
                }
                None => self.inspect_hub_port(hub_index, port, None, true),
            }
        }
    }

    fn next_hub_port(&mut self) -> Option<(usize, u8)> {
        if self.devices.is_empty() {
            return None;
        }
        for offset in 0..self.devices.len() {
            let index = (self.hub_cursor + offset) % self.devices.len();
            let Some(hub) = self.devices[index].hub.as_mut() else {
                continue;
            };
            if hub.ports == 0 {
                continue;
            }
            let port = hub.next_port.clamp(1, hub.ports);
            hub.next_port = if port == hub.ports { 1 } else { port + 1 };
            self.hub_cursor = (index + 1) % self.devices.len();
            return Some((index, port));
        }
        None
    }

    fn inspect_hub_port(
        &mut self,
        hub_index: usize,
        port: u8,
        resources: Option<(&mut UsableFrameAllocator<'_>, u64)>,
        activate: bool,
    ) {
        let Some(hub_device) = self.devices.get(hub_index) else {
            return;
        };
        let parent_slot = hub_device.slot_id;
        let parent_path = hub_device.path;
        let parent_speed = hub_device.speed;
        let path = match parent_path.child(port) {
            Ok(path) => path,
            Err(error) => {
                self.record_path_failure(parent_path, error);
                return;
            }
        };
        let status = {
            let (controller, devices) = (&mut self.controller, &mut self.devices);
            let Some(device) = devices.get_mut(hub_index) else {
                return;
            };
            match controller.hub_port_status(device, port) {
                Ok(status) => status,
                Err(error) => {
                    self.record_path_failure(path, error);
                    return;
                }
            }
        };
        let child = self.devices.iter().any(|device| {
            device.parent_slot_id == Some(parent_slot) && device.parent_port == Some(port)
        });
        if !status.connected() {
            if child {
                self.teardown_path(path);
            }
            return;
        }
        if child || self.slot_capacity_reached() {
            return;
        }
        let Some((frames, hhdm_offset)) = resources else {
            return;
        };
        let speed = {
            let (controller, devices) = (&mut self.controller, &mut self.devices);
            let Some(device) = devices.get_mut(hub_index) else {
                return;
            };
            match controller.reset_hub_port(device, port, parent_speed) {
                Ok(speed) => speed,
                Err(error) => {
                    self.record_path_failure(path, error);
                    return;
                }
            }
        };
        let parent = &self.devices[hub_index];
        let tt = derive_child_tt(
            parent.speed,
            parent.slot_id,
            parent
                .hub
                .as_ref()
                .filter(|hub| !hub.superspeed)
                .map(|hub| hub.protocol),
            parent.tt,
            port,
            speed,
        );
        match self.enumerate_slot_at(
            path,
            speed,
            Some(parent_slot),
            Some(port),
            tt,
            frames,
            hhdm_offset,
        ) {
            Ok(device) => {
                if let Err(error) = self.add_device(device, activate) {
                    self.record_path_failure(path, error);
                }
            }
            Err(error) => self.record_path_failure(path, error),
        }
    }

    fn teardown_path(&mut self, path: UsbPath) {
        let entries: Vec<(UsbPath, u8)> = self
            .devices
            .iter()
            .map(|device| (device.path, device.slot_id))
            .collect();
        for slot in teardown_slot_order(&entries, path) {
            let Some(index) = self
                .devices
                .iter()
                .position(|device| device.slot_id == slot)
            else {
                continue;
            };
            if let Err(error) = self.controller.disable_slot(slot) {
                let failed_path = self.devices[index].path;
                self.record_path_failure(failed_path, error);
                break;
            }
            if let Err(error) = self.controller.set_dcbaa_entry(slot, 0) {
                self.record_path_failure(self.devices[index].path, error);
            }
            // DISABLE_SLOT completion is the ownership boundary: after it, stale
            // transfer events may be ignored and all software state can be dropped.
            let device = self.devices.remove(index);
            for interface in &device.interfaces {
                if interface.active {
                    self.push_lifecycle(UsbLifecycleEvent::InterfaceRemoved(
                        interface.info.clone(),
                    ));
                }
            }
            self.recycle_device(device);
        }
    }

    fn recycle_device(&mut self, device: UsbDevice) {
        for page in device.into_dma_pages() {
            self.dma_pool.recycle(page);
        }
    }

    fn retry_quarantined_devices(&mut self) {
        let mut slot_index = 0;
        while slot_index < self.quarantined_slots.len() {
            let slot = self.quarantined_slots[slot_index];
            if self.controller.disable_slot(slot).is_err() {
                slot_index += 1;
                continue;
            }
            let _ = self.controller.set_dcbaa_entry(slot, 0);
            self.quarantined_slots.remove(slot_index);
        }

        let mut index = 0;
        while index < self.quarantined_devices.len() {
            let slot = self.quarantined_devices[index].slot_id;
            if self.controller.disable_slot(slot).is_err() {
                index += 1;
                continue;
            }
            let _ = self.controller.set_dcbaa_entry(slot, 0);
            let device = self.quarantined_devices.remove(index);
            self.recycle_device(device);
        }
    }

    fn find_interface(&self, id: HidInterfaceId) -> Option<&HidInterfaceState> {
        self.devices
            .iter()
            .flat_map(|device| device.interfaces.iter())
            .find(|interface| interface.active && interface.info.id == id)
    }

    fn find_endpoint_indexes(&self, slot: u8, endpoint: u8) -> Option<(usize, usize)> {
        for (device_index, device) in self.devices.iter().enumerate() {
            if device.slot_id != slot {
                continue;
            }
            for (interface_index, interface) in device.interfaces.iter().enumerate() {
                if interface.active && interface.endpoint_id == endpoint {
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
        self.enumerate_slot_at(
            UsbPath::root(port),
            speed,
            None,
            None,
            None,
            frames,
            hhdm_offset,
        )
    }

    fn enumerate_slot_at(
        &mut self,
        path: UsbPath,
        speed: u8,
        parent_slot_id: Option<u8>,
        parent_port: Option<u8>,
        tt: Option<TtInfo>,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<UsbDevice, UsbError> {
        let slot_type = *self
            .controller
            .port_slot_types
            .get(usize::from(path.root_port - 1))
            .unwrap_or(&0);
        let slot_id = self.controller.enable_slot(slot_type)?;
        if slot_id == 0 || slot_id > self.controller.max_slots {
            if slot_id != 0 {
                let _ = self.controller.disable_slot(slot_id);
            }
            return Err(UsbError::InvalidSlot);
        }
        match self.enumerate_slot(
            path,
            speed,
            slot_id,
            parent_slot_id,
            parent_port,
            tt,
            frames,
            hhdm_offset,
        ) {
            Ok(device) => Ok(device),
            Err(EnumerationFailure::BeforeDevice(error)) => {
                if self.controller.disable_slot(slot_id).is_ok() {
                    let _ = self.controller.set_dcbaa_entry(slot_id, 0);
                } else {
                    self.quarantined_slots.push(slot_id);
                }
                Err(error)
            }
            Err(EnumerationFailure::Device(error, device)) => {
                if self.controller.disable_slot(slot_id).is_ok() {
                    let _ = self.controller.set_dcbaa_entry(slot_id, 0);
                    self.recycle_device(device);
                } else {
                    self.quarantined_devices.push(device);
                }
                Err(error)
            }
        }
    }

    fn acquire_device_storage(
        &mut self,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<DeviceStorage, UsbError> {
        let mut pages = Vec::with_capacity(4);
        for _ in 0..4 {
            match self
                .dma_pool
                .acquire(frames, hhdm_offset, self.controller.address_64)
            {
                Ok(page) => pages.push(page),
                Err(error) => {
                    for page in pages {
                        self.dma_pool.recycle(page);
                    }
                    return Err(error);
                }
            }
        }
        let ep0_page = pages.pop().ok_or(UsbError::OutOfFrames)?;
        let ep0_ring = match ProducerRing::new_recoverable(ep0_page) {
            Ok(ring) => ring,
            Err((error, page)) => {
                self.dma_pool.recycle(page);
                for page in pages {
                    self.dma_pool.recycle(page);
                }
                return Err(error);
            }
        };
        let control_buffer = pages.pop().ok_or(UsbError::OutOfFrames)?;
        let input_context = pages.pop().ok_or(UsbError::OutOfFrames)?;
        let output_context = pages.pop().ok_or(UsbError::OutOfFrames)?;
        Ok(DeviceStorage {
            output_context,
            input_context,
            control_buffer,
            ep0_ring,
        })
    }

    fn enumerate_slot(
        &mut self,
        path: UsbPath,
        speed: u8,
        slot_id: u8,
        parent_slot_id: Option<u8>,
        parent_port: Option<u8>,
        tt: Option<TtInfo>,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<UsbDevice, EnumerationFailure> {
        let DeviceStorage {
            output_context,
            input_context,
            control_buffer,
            ep0_ring,
        } = self
            .acquire_device_storage(frames, hhdm_offset)
            .map_err(EnumerationFailure::BeforeDevice)?;

        let mut device = UsbDevice {
            _output_context: output_context,
            input_context,
            control_buffer,
            ep0_ring,
            slot_id,
            path,
            parent_slot_id,
            parent_port,
            speed,
            tt,
            hub: None,
            interfaces: Vec::new(),
        };

        let setup = (|| -> Result<(), UsbError> {
            self.controller
                .set_dcbaa_entry(slot_id, device._output_context.physical)?;
            build_address_context(
                &device.input_context,
                self.controller.context_size,
                AddressContext {
                    path,
                    speed,
                    packet_size: initial_ep0_packet_size(speed),
                    ep0_ring: device.ep0_ring.physical(),
                    tt,
                },
            )?;
            self.controller
                .address_device(slot_id, device.input_context.physical)
        })();
        if let Err(error) = setup {
            return Err(EnumerationFailure::Device(error, device));
        }

        match self.populate_device(&mut device, frames, hhdm_offset) {
            Ok(()) => Ok(device),
            Err(error) => Err(EnumerationFailure::Device(error, device)),
        }
    }

    fn populate_device(
        &mut self,
        device: &mut UsbDevice,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<(), UsbError> {
        let slot_id = device.slot_id;
        let path = device.path;
        let speed = device.speed;
        let first = self.controller.control_in(device, 0x80, 6, 0x0100, 0, 8)?;
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

        let device_descriptor = self.controller.control_in(device, 0x80, 6, 0x0100, 0, 18)?;
        if device_descriptor.len() < 18 || device_descriptor[0] < 18 || device_descriptor[1] != 1 {
            return Err(DescriptorError::InvalidType.into());
        }
        let vendor_id = u16::from_le_bytes([device_descriptor[8], device_descriptor[9]]);
        let product_id = u16::from_le_bytes([device_descriptor[10], device_descriptor[11]]);

        let config_header = self.controller.control_in(device, 0x80, 6, 0x0200, 0, 9)?;
        if config_header.len() < 9 || config_header[1] != 2 {
            return Err(DescriptorError::InvalidType.into());
        }
        let total_length = usize::from(u16::from_le_bytes([config_header[2], config_header[3]]));
        if total_length < 9 || total_length > MAX_CONFIGURATION_DESCRIPTOR {
            return Err(DescriptorError::TooLarge.into());
        }
        let configuration = self
            .controller
            .control_in(device, 0x80, 6, 0x0200, 0, total_length)?;
        let parsed = parse_configuration_descriptor(&configuration)?;
        let hub_protocol = if device_descriptor[4] == 9 {
            Some(device_descriptor[6])
        } else {
            parsed.hub_protocol
        };
        if parsed.interfaces.len() + self.interface_count() > MAX_HID_INTERFACES {
            return Err(UsbError::TooManyInterfaces);
        }

        self.controller.control_no_data(
            device,
            0x00,
            9,
            u16::from(parsed.configuration_value),
            0,
        )?;

        if let Some(protocol) = hub_protocol {
            let hub = self
                .controller
                .initialize_hub(device, speed >= 4, protocol)?;
            update_hub_slot_context(
                &device.input_context,
                &device._output_context,
                self.controller.context_size,
                speed,
                hub,
            )?;
            self.controller
                .evaluate_context(slot_id, device.input_context.physical)?;
            device.hub = Some(hub);
        }

        let device_id = self.next_device_id;
        self.next_device_id = self.next_device_id.wrapping_add(1);
        for hid in parsed.interfaces {
            let report_descriptor = self.controller.control_in(
                device,
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
                    device,
                    0x21,
                    0x0b,
                    1,
                    u16::from(hid.interface_number),
                )?;
            }

            let endpoint_id = endpoint_id(hid.endpoint_address)?;
            let buffer_len = hid.max_esit_payload;
            if buffer_len == 0 || buffer_len > MAX_REPORT_SIZE || buffer_len > PAGE_SIZE as usize {
                return Err(UsbError::ReportTooLarge);
            }
            let ring_page =
                self.dma_pool
                    .acquire(frames, hhdm_offset, self.controller.address_64)?;
            let ring = match ProducerRing::new_recoverable(ring_page) {
                Ok(ring) => ring,
                Err((error, page)) => {
                    self.dma_pool.recycle(page);
                    return Err(error);
                }
            };
            let buffer =
                match self
                    .dma_pool
                    .acquire(frames, hhdm_offset, self.controller.address_64)
                {
                    Ok(buffer) => buffer,
                    Err(error) => {
                        self.dma_pool.recycle(ring.into_inner());
                        return Err(error);
                    }
                };
            let kind = match (hid.subclass, hid.protocol) {
                (1, 1) => HidInterfaceKind::Keyboard,
                (1, 2) => HidInterfaceKind::Mouse,
                _ => HidInterfaceKind::Other,
            };
            device.interfaces.push(HidInterfaceState {
                info: HidInterfaceInfo {
                    id: HidInterfaceId {
                        device: device_id,
                        interface: hid.interface_number,
                    },
                    slot_id,
                    root_port: path.root_port,
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
                active: true,
            });
        }

        if !device.interfaces.is_empty() {
            build_configure_endpoint_context(
                &device.input_context,
                &device._output_context,
                self.controller.context_size,
                &device.interfaces,
            )?;
            self.controller
                .configure_endpoint(slot_id, device.input_context.physical)?;
        }
        Ok(())
    }
}

enum EnumerationFailure {
    BeforeDevice(UsbError),
    Device(UsbError, UsbDevice),
}

struct DeviceStorage {
    output_context: DmaPage,
    input_context: DmaPage,
    control_buffer: DmaPage,
    ep0_ring: ProducerRing,
}

struct UsbDevice {
    _output_context: DmaPage,
    input_context: DmaPage,
    control_buffer: DmaPage,
    ep0_ring: ProducerRing,
    slot_id: u8,
    path: UsbPath,
    parent_slot_id: Option<u8>,
    parent_port: Option<u8>,
    speed: u8,
    tt: Option<TtInfo>,
    hub: Option<HubState>,
    interfaces: Vec<HidInterfaceState>,
}

impl UsbDevice {
    fn into_dma_pages(self) -> Vec<DmaPage> {
        let UsbDevice {
            _output_context,
            input_context,
            control_buffer,
            ep0_ring,
            interfaces,
            ..
        } = self;
        let mut pages = Vec::with_capacity(4 + interfaces.len() * 2);
        pages.push(_output_context);
        pages.push(input_context);
        pages.push(control_buffer);
        pages.push(ep0_ring.into_inner());
        for interface in interfaces {
            pages.push(interface.ring.into_inner());
            pages.push(interface.buffer);
        }
        pages
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TtInfo {
    hub_slot_id: u8,
    port: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HubState {
    ports: u8,
    superspeed: bool,
    protocol: u8,
    characteristics: u16,
    next_port: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HubPortStatus {
    status: u16,
    change: u16,
}

impl HubPortStatus {
    fn connected(self) -> bool {
        self.status & USB_PORT_STATUS_CONNECTION != 0
    }
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
    active: bool,
}

fn retire_interface(interface: &mut HidInterfaceState, completion: u8) -> Option<HidInterfaceInfo> {
    if !interface.active {
        return None;
    }
    interface.transfer_error = Some(completion);
    interface.active = false;
    Some(interface.info.clone())
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
    deferred_events: VecDeque<Trb>,
    msi_enabled: bool,
    interrupts_observed: u64,
    watchdog_polls: u64,
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
            deferred_events: VecDeque::with_capacity(DEFERRED_EVENT_INITIAL_CAPACITY),
            msi_enabled: false,
            interrupts_observed: 0,
            watchdog_polls: 0,
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

    fn port_status(&mut self, port: u8) -> Result<PortStatus, UsbError> {
        let offset = self.port_offset(port)?;
        self.mmio.read_u32(offset).map(PortStatus::from_bits_retain)
    }

    fn port_status_and_ack(&mut self, port: u8) -> Result<PortStatus, UsbError> {
        let offset = self.port_offset(port)?;
        let raw = self.mmio.read_u32(offset)?;
        let changes = raw & PORTSC_CHANGE_BITS;
        if changes != 0 {
            self.mmio
                .write_u32(offset, (raw & PORTSC_WRITE_PRESERVE) | changes)?;
        }
        Ok(PortStatus::from_bits_retain(raw))
    }

    fn enable_interrupts(&mut self) -> Result<(), UsbError> {
        let interrupter = self.runtime + 0x20;
        self.mmio.write_u32(interrupter, iman_write_value(true))?;
        let command = self.mmio.read_u32(self.operational)?;
        self.mmio.write_u32(self.operational, command | (1 << 2))?;
        self.msi_enabled = true;
        Ok(())
    }

    fn ack_primary_interrupter(&mut self) -> Result<(), UsbError> {
        self.mmio
            .write_u32(self.runtime + 0x20, iman_write_value(true))
    }

    fn reset_port(&mut self, port: u8) -> Result<u8, UsbError> {
        let offset = self.port_offset(port)?;
        let mut status = PortStatus::from_bits_retain(self.mmio.read_u32(offset)?);
        if !status.contains(PortStatus::CURRENT_CONNECT_STATUS) {
            return Err(UsbError::PortDisconnected);
        }
        if !status.contains(PortStatus::PORT_POWER) {
            self.mmio.write_u32(offset, PortStatus::PORT_POWER.bits())?;
            for _ in 0..10_000 {
                spin_loop();
            }
            status = PortStatus::from_bits_retain(self.mmio.read_u32(offset)?);
        }
        let speed = status.speed();
        if speed >= 4 {
            if !status.contains(PortStatus::PORT_ENABLED) {
                self.mmio.write_u32(
                    offset,
                    (status & PortStatus::PORT_POWER | PortStatus::WARM_PORT_RESET).bits(),
                )?;
                self.wait_port_reset(offset, PortStatus::WARM_PORT_RESET)?;
            }
        } else {
            self.mmio.write_u32(
                offset,
                (status & PortStatus::PORT_POWER | PortStatus::PORT_RESET).bits(),
            )?;
            self.wait_port_reset(offset, PortStatus::PORT_RESET)?;
        }
        status = PortStatus::from_bits_retain(self.mmio.read_u32(offset)?);
        if !status.contains(PortStatus::CURRENT_CONNECT_STATUS) {
            return Err(UsbError::PortDisconnected);
        }
        if !status.contains(PortStatus::PORT_ENABLED) {
            return Err(UsbError::PortResetFailed);
        }
        let speed = status.speed();
        if speed == 0 {
            return Err(UsbError::PortResetFailed);
        }
        Ok(speed)
    }

    fn wait_port_reset(&mut self, offset: usize, bit: PortStatus) -> Result<(), UsbError> {
        let deadline = wait_deadline();
        while timestamp() < deadline {
            let status = PortStatus::from_bits_retain(self.mmio.read_u32(offset)?);
            if !status.intersects(bit) {
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
            self.reserve_deferred_slot()?;
            if let Some(event) = self.next_hardware_event()? {
                if event.trb_type() != TRB_TYPE_COMMAND_COMPLETION_EVENT
                    || event.parameter() & !0x0f != pointer & !0x0f
                {
                    self.defer_event(event);
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
        if let Some(event) = self.deferred_events.pop_front() {
            return Ok(Some(event));
        }
        self.next_hardware_event()
    }

    fn next_hardware_event(&mut self) -> Result<Option<Trb>, UsbError> {
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

    fn reserve_deferred_slot(&mut self) -> Result<(), UsbError> {
        reserve_lossless_slot(&mut self.deferred_events)
    }

    fn defer_event(&mut self, event: Trb) {
        // Every synchronous wait reserves before dequeuing from hardware. Thus
        // this push cannot allocate or lose a completion after xHCI ownership
        // has advanced, even if growing the queue would otherwise fail.
        debug_assert!(self.deferred_events.len() < self.deferred_events.capacity());
        defer_lossless(&mut self.deferred_events, event);
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
            self.reserve_deferred_slot()?;
            if let Some(event) = self.next_hardware_event()? {
                if event.trb_type() != TRB_TYPE_TRANSFER_EVENT
                    || (event.dword[3] >> 24) as u8 != device.slot_id
                    || ((event.dword[3] >> 16) & 0x1f) != 1
                {
                    self.defer_event(event);
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

    fn initialize_hub(
        &mut self,
        device: &mut UsbDevice,
        superspeed: bool,
        protocol: u8,
    ) -> Result<HubState, UsbError> {
        let descriptor_type: u8 = if superspeed { 0x2a } else { 0x29 };
        let minimum = if superspeed { 12 } else { 7 };
        let mut bytes = self.control_in(
            device,
            0xa0,
            USB_REQUEST_GET_DESCRIPTOR,
            u16::from(descriptor_type) << 8,
            0,
            minimum,
        )?;
        let declared = bytes.first().copied().map(usize::from).unwrap_or(0);
        if declared > bytes.len() && declared <= u8::MAX as usize {
            bytes = self.control_in(
                device,
                0xa0,
                USB_REQUEST_GET_DESCRIPTOR,
                u16::from(descriptor_type) << 8,
                0,
                declared,
            )?;
        }
        let descriptor = parse_hub_descriptor(&bytes, superspeed)?;
        for port in 1..=descriptor.ports {
            self.control_no_data(
                device,
                0x23,
                USB_REQUEST_SET_FEATURE,
                USB_PORT_FEATURE_POWER,
                u16::from(port),
            )?;
        }
        let delay_cycles =
            timestamp_frequency().saturating_mul(u64::from(descriptor.power_good_ms)) / 1_000;
        let deadline = timestamp().saturating_add(delay_cycles);
        while timestamp() < deadline {
            spin_loop();
        }
        Ok(HubState {
            ports: descriptor.ports,
            superspeed,
            protocol,
            characteristics: descriptor.characteristics,
            next_port: 1,
        })
    }

    fn hub_port_status(
        &mut self,
        device: &mut UsbDevice,
        port: u8,
    ) -> Result<HubPortStatus, UsbError> {
        let bytes = self.control_in(device, 0xa3, USB_REQUEST_GET_STATUS, 0, u16::from(port), 4)?;
        let status = parse_hub_port_status(&bytes)?;
        let superspeed = device.hub.as_ref().is_some_and(|hub| hub.superspeed);
        for bit in 0..16 {
            if status.change & (1 << bit) == 0 {
                continue;
            }
            let Some(feature) = hub_change_feature(superspeed, bit) else {
                continue;
            };
            self.control_no_data(
                device,
                0x23,
                USB_REQUEST_CLEAR_FEATURE,
                feature,
                u16::from(port),
            )?;
        }
        Ok(status)
    }

    fn reset_hub_port(
        &mut self,
        device: &mut UsbDevice,
        port: u8,
        parent_speed: u8,
    ) -> Result<u8, UsbError> {
        self.control_no_data(
            device,
            0x23,
            USB_REQUEST_SET_FEATURE,
            USB_PORT_FEATURE_RESET,
            u16::from(port),
        )?;
        let deadline = wait_deadline();
        while timestamp() < deadline {
            let status = self.hub_port_status(device, port)?;
            if !status.connected() {
                return Err(UsbError::PortDisconnected);
            }
            if status.status & USB_PORT_STATUS_RESET == 0
                && status.status & USB_PORT_STATUS_ENABLE != 0
            {
                return Ok(hub_child_speed(status, parent_speed));
            }
            spin_loop();
        }
        Err(UsbError::PortResetFailed)
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
        Self::new_recoverable(page).map_err(|(error, _)| error)
    }

    fn new_recoverable(page: DmaPage) -> Result<Self, (UsbError, DmaPage)> {
        let mut ring = Self {
            page,
            enqueue_index: 0,
            cycle: true,
        };
        if let Err(error) = ring.write_link() {
            return Err((error, ring.page));
        }
        Ok(ring)
    }

    fn physical(&self) -> u64 {
        self.page.physical
    }

    fn into_inner(self) -> DmaPage {
        self.page
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

struct UsbDmaPool {
    pages: Vec<DmaPage>,
}

impl UsbDmaPool {
    const fn new() -> Self {
        Self { pages: Vec::new() }
    }

    fn acquire(
        &mut self,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
        address_64: bool,
    ) -> Result<DmaPage, UsbError> {
        if let Some(page) = self.take_recycled() {
            Ok(page)
        } else {
            DmaPage::allocate(frames, hhdm_offset, address_64)
        }
    }

    fn take_recycled(&mut self) -> Option<DmaPage> {
        let page = self.pages.pop()?;
        page.clear();
        Some(page)
    }

    fn recycle(&mut self, page: DmaPage) {
        self.pages.push(page);
    }

    fn len(&self) -> usize {
        self.pages.len()
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
        let frame = if address_64 {
            frames.allocate_frame()?
        } else {
            frames.allocate_frame_below(DMA_32BIT_ADDRESS_LIMIT)?
        }
        .ok_or(UsbError::OutOfFrames)?;
        let physical = frame.start_address().as_u64();
        let virtual_address = hhdm_offset
            .checked_add(physical)
            .ok_or(UsbError::AddressOverflow)?;
        VirtAddr::try_new(virtual_address).map_err(|_| UsbError::AddressOverflow)?;
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
        let pointer =
            unsafe { NonNull::new_unchecked(self.virtual_pointer.add(offset).cast::<u32>()) };
        Ok(unsafe { VolatilePtr::new(pointer) }.read())
    }

    fn write_u32(&self, offset: usize, value: u32) -> Result<(), UsbError> {
        self.check(offset, 4)?;
        if offset & 3 != 0 {
            return Err(UsbError::AddressOverflow);
        }
        let pointer =
            unsafe { NonNull::new_unchecked(self.virtual_pointer.add(offset).cast::<u32>()) };
        unsafe { VolatilePtr::new(pointer) }.write(value);
        Ok(())
    }

    fn write_u64(&self, offset: usize, value: u64) -> Result<(), UsbError> {
        self.check(offset, 8)?;
        if offset & 7 != 0 {
            return Err(UsbError::AddressOverflow);
        }
        let pointer =
            unsafe { NonNull::new_unchecked(self.virtual_pointer.add(offset).cast::<u64>()) };
        unsafe { VolatilePtr::new(pointer) }.write(value);
        Ok(())
    }

    fn write_trb(&self, index: usize, trb: Trb) -> Result<(), UsbError> {
        let offset = index.checked_mul(16).ok_or(UsbError::AddressOverflow)?;
        self.check(offset, 16)?;
        let pointer =
            unsafe { NonNull::new_unchecked(self.virtual_pointer.add(offset).cast::<u32>()) };
        // Publish cycle/control last. x86 DMA is coherent; the compiler fence
        // supplies the ordering required around the volatile stores.
        for (word, value) in trb.dword[..3].iter().copied().enumerate() {
            let pointer = unsafe { NonNull::new_unchecked(pointer.as_ptr().add(word)) };
            unsafe { VolatilePtr::new(pointer) }.write(value);
        }
        compiler_fence(Ordering::Release);
        let control = unsafe { NonNull::new_unchecked(pointer.as_ptr().add(3)) };
        unsafe { VolatilePtr::new(control) }.write(trb.dword[3]);
        Ok(())
    }

    fn read_trb(&self, index: usize) -> Result<Trb, UsbError> {
        let offset = index.checked_mul(16).ok_or(UsbError::AddressOverflow)?;
        self.check(offset, 16)?;
        let pointer =
            unsafe { NonNull::new_unchecked(self.virtual_pointer.add(offset).cast::<u32>()) };
        let read_word = |index| {
            let pointer = unsafe { NonNull::new_unchecked(pointer.as_ptr().add(index)) };
            unsafe { VolatilePtr::new(pointer) }.read()
        };
        Ok(Trb {
            dword: [read_word(0), read_word(1), read_word(2), read_word(3)],
        })
    }

    fn read_bytes(&self, length: usize) -> Result<Vec<u8>, UsbError> {
        self.check(0, length)?;
        compiler_fence(Ordering::Acquire);
        let mut bytes = Vec::with_capacity(length);
        for index in 0..length {
            let pointer = unsafe { NonNull::new_unchecked(self.virtual_pointer.add(index)) };
            bytes.push(unsafe { VolatilePtr::new(pointer) }.read());
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
        let pointer = unsafe { NonNull::new_unchecked(self.base.add(offset)) };
        Ok(unsafe { VolatilePtr::new(pointer) }.read())
    }

    fn read_u32(&mut self, offset: usize) -> Result<u32, UsbError> {
        self.check(offset, 4)?;
        if (self.base as usize + offset) & 3 != 0 {
            return Err(UsbError::InvalidMmioBar);
        }
        let pointer = unsafe { NonNull::new_unchecked(self.base.add(offset).cast::<u32>()) };
        Ok(unsafe { VolatilePtr::new(pointer) }.read())
    }

    fn write_u32(&mut self, offset: usize, value: u32) -> Result<(), UsbError> {
        self.check(offset, 4)?;
        if (self.base as usize + offset) & 3 != 0 {
            return Err(UsbError::InvalidMmioBar);
        }
        let pointer = unsafe { NonNull::new_unchecked(self.base.add(offset).cast::<u32>()) };
        unsafe { VolatilePtr::new(pointer) }.write(value);
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
            let address =
                VirtAddr::try_new(base + offset).map_err(|_| UsbError::AddressOverflow)?;
            if page_table.translate_addr(address).is_some() {
                continue 'candidate;
            }
            offset += PAGE_SIZE;
        }
        selected = Some(base);
        break;
    }
    let virtual_page = selected.ok_or(UsbError::InvalidMmioBar)?;
    let flags = PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    let mut offset = 0;
    while offset < mapped_length {
        let physical_address = PhysAddr::try_new(
            physical_page
                .checked_add(offset)
                .ok_or(UsbError::AddressOverflow)?,
        )
        .map_err(|_| UsbError::AddressOverflow)?;
        let frame = PhysFrame::from_start_address(physical_address)
            .map_err(|_| UsbError::InvalidMmioBar)?;
        let virtual_address = VirtAddr::try_new(
            virtual_page
                .checked_add(offset)
                .ok_or(UsbError::AddressOverflow)?,
        )
        .map_err(|_| UsbError::AddressOverflow)?;
        let page =
            VirtPage::from_start_address(virtual_address).map_err(|_| UsbError::InvalidMmioBar)?;
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

pub fn timestamp() -> u64 {
    unsafe { _rdtsc() }
}

pub fn timestamp_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
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

#[derive(Clone, Copy)]
struct AddressContext {
    path: UsbPath,
    speed: u8,
    packet_size: u16,
    ep0_ring: u64,
    tt: Option<TtInfo>,
}

fn build_address_context(
    input: &DmaPage,
    context_size: usize,
    address: AddressContext,
) -> Result<(), UsbError> {
    input.clear();
    input.write_u32(4, 0x3)?;
    let slot = context_size;
    input.write_u32(
        slot,
        (address.path.route_string & 0x000f_ffff) | (u32::from(address.speed) << 20) | (1 << 27),
    )?;
    input.write_u32(slot + 4, u32::from(address.path.root_port) << 16)?;
    input.write_u32(
        slot + 8,
        u32::from(address.tt.map_or(0, |tt| tt.hub_slot_id))
            | (u32::from(address.tt.map_or(0, |tt| tt.port)) << 8),
    )?;
    let ep0 = context_size * 2;
    input.write_u32(
        ep0 + 4,
        (3 << 1) | (4 << 3) | (u32::from(address.packet_size) << 16),
    )?;
    input.write_u32(ep0 + 8, (address.ep0_ring as u32) | 1)?;
    input.write_u32(ep0 + 12, (address.ep0_ring >> 32) as u32)?;
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

fn update_hub_slot_context(
    input: &DmaPage,
    output: &DmaPage,
    context_size: usize,
    speed: u8,
    hub: HubState,
) -> Result<(), UsbError> {
    input.clear();
    input.write_u32(4, 1)?;
    let target = context_size;
    for word in 0..context_size / 4 {
        input.write_u32(target + word * 4, output.read_u32(word * 4)?)?;
    }
    let dword0 = input.read_u32(target)?;
    let mtt = speed == 3 && hub.protocol == 2;
    input.write_u32(
        target,
        (dword0 & !(1 << 25)) | (u32::from(mtt) << 25) | (1 << 26),
    )?;
    let dword1 = input.read_u32(target + 4)?;
    input.write_u32(
        target + 4,
        (dword1 & 0x00ff_ffff) | (u32::from(hub.ports) << 24),
    )?;
    let dword2 = input.read_u32(target + 8)?;
    let ttt = if speed == 3 {
        (hub.characteristics >> 5) & 0x3
    } else {
        0
    };
    input.write_u32(target + 8, (dword2 & !(0x3 << 16)) | (u32::from(ttt) << 16))
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
    hub_protocol: Option<u8>,
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
    let mut hub_protocol = None;
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
                if descriptor[5] == 9 && descriptor[3] == 0 {
                    hub_protocol = Some(descriptor[7]);
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
        hub_protocol,
        interfaces,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedHubDescriptor {
    ports: u8,
    characteristics: u16,
    power_good_ms: u16,
}

fn parse_hub_descriptor(
    bytes: &[u8],
    superspeed: bool,
) -> Result<ParsedHubDescriptor, DescriptorError> {
    let minimum = if superspeed { 12 } else { 7 };
    let expected_type = if superspeed { 0x2a } else { 0x29 };
    if bytes.len() < minimum {
        return Err(DescriptorError::TooShort);
    }
    let declared = usize::from(bytes[0]);
    if declared < minimum || declared > bytes.len() {
        return Err(DescriptorError::InvalidLength);
    }
    if bytes[1] != expected_type {
        return Err(DescriptorError::InvalidType);
    }
    let ports = bytes[2];
    if ports == 0 {
        return Err(DescriptorError::InvalidLength);
    }
    Ok(ParsedHubDescriptor {
        ports,
        characteristics: u16::from_le_bytes([bytes[3], bytes[4]]),
        power_good_ms: u16::from(bytes[5]).saturating_mul(2),
    })
}

fn parse_hub_port_status(bytes: &[u8]) -> Result<HubPortStatus, UsbError> {
    if bytes.len() < 4 {
        return Err(DescriptorError::TooShort.into());
    }
    Ok(HubPortStatus {
        status: u16::from_le_bytes([bytes[0], bytes[1]]),
        change: u16::from_le_bytes([bytes[2], bytes[3]]),
    })
}

fn derive_child_tt(
    parent_speed: u8,
    parent_slot_id: u8,
    parent_usb2_hub_protocol: Option<u8>,
    inherited_tt: Option<TtInfo>,
    port: u8,
    child_speed: u8,
) -> Option<TtInfo> {
    if child_speed > 2 {
        return None;
    }
    if let (3, Some(protocol)) = (parent_speed, parent_usb2_hub_protocol) {
        Some(TtInfo {
            hub_slot_id: parent_slot_id,
            port: if protocol == 2 { port } else { 0 },
        })
    } else {
        inherited_tt
    }
}

fn hub_child_speed(status: HubPortStatus, parent_speed: u8) -> u8 {
    if parent_speed >= 4 {
        parent_speed
    } else if status.status & USB_PORT_STATUS_HIGH_SPEED != 0 {
        3
    } else if status.status & USB_PORT_STATUS_LOW_SPEED != 0 {
        2
    } else {
        1
    }
}

fn hub_change_feature(superspeed: bool, change_bit: u16) -> Option<u16> {
    if !superspeed {
        return (change_bit <= 4).then_some(16 + change_bit);
    }
    match change_bit {
        0 => Some(16),
        3 => Some(19),
        4 => Some(20),
        5 => Some(29),
        6 => Some(25),
        7 => Some(26),
        _ => None,
    }
}

fn reserve_lossless_slot(queue: &mut VecDeque<Trb>) -> Result<(), UsbError> {
    if queue.len() == queue.capacity() {
        queue.try_reserve(1).map_err(|_| UsbError::RingFull)?;
    }
    Ok(())
}

fn defer_lossless(queue: &mut VecDeque<Trb>, event: Trb) {
    queue.push_back(event);
}

const fn iman_write_value(interrupt_enable: bool) -> u32 {
    1 | ((interrupt_enable as u32) << 1)
}

fn teardown_slot_order(entries: &[(UsbPath, u8)], path: UsbPath) -> Vec<u8> {
    let mut slots: Vec<(u8, u8)> = entries
        .iter()
        .filter(|(candidate, _)| candidate.is_descendant_of(path))
        .map(|(candidate, slot)| (candidate.depth, *slot))
        .collect();
    slots.sort_unstable_by(|left, right| right.cmp(left));
    slots.into_iter().map(|(_, slot)| slot).collect()
}

fn push_bounded<T>(queue: &mut VecDeque<T>, capacity: usize, value: T) -> bool {
    let dropped = queue.len() == capacity;
    if dropped {
        queue.pop_front();
    }
    if capacity != 0 {
        queue.push_back(value);
    }
    dropped
}

fn vec_with_value<T: Clone>(length: usize, value: T) -> Vec<T> {
    let mut result = Vec::with_capacity(length);
    result.resize(length, value);
    result
}

#[cfg(test)]
mod tests {
    use alloc::vec;

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

    #[test]
    fn route_strings_pack_five_tiers_in_parent_first_order() {
        let root = UsbPath::root(4);
        let path = root
            .child(2)
            .unwrap()
            .child(15)
            .unwrap()
            .child(3)
            .unwrap()
            .child(4)
            .unwrap()
            .child(5)
            .unwrap();
        assert_eq!(path.route_string, 0x5_4_3_f_2);
        assert_eq!(path.depth, 5);
        assert_eq!(path.child(1), Err(UsbError::InvalidPort));
        assert_eq!(root.child(0), Err(UsbError::InvalidPort));
        assert_eq!(root.child(16), Err(UsbError::InvalidPort));
    }

    #[test]
    fn descendant_matching_does_not_cross_sibling_routes() {
        let hub = UsbPath::root(1).child(2).unwrap();
        let child = hub.child(3).unwrap();
        let grandchild = child.child(4).unwrap();
        let sibling = hub.child(5).unwrap();
        assert!(hub.is_descendant_of(hub));
        assert!(grandchild.is_descendant_of(hub));
        assert!(!sibling.is_descendant_of(child));
        assert!(!UsbPath::root(2).is_descendant_of(UsbPath::root(1)));
    }

    #[test]
    fn parses_usb2_and_usb3_hub_descriptors() {
        let usb2 = [9, 0x29, 4, 0, 0, 25, 0, 0, 0xff];
        assert_eq!(
            parse_hub_descriptor(&usb2, false),
            Ok(ParsedHubDescriptor {
                ports: 4,
                characteristics: 0,
                power_good_ms: 50,
            })
        );
        let usb3 = [12, 0x2a, 8, 0, 0, 10, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_hub_descriptor(&usb3, true),
            Ok(ParsedHubDescriptor {
                ports: 8,
                characteristics: 0,
                power_good_ms: 20,
            })
        );
    }

    #[test]
    fn rejects_truncated_or_mismatched_hub_descriptors() {
        assert_eq!(
            parse_hub_descriptor(&[9, 0x29, 4, 0, 0, 1, 0], false),
            Err(DescriptorError::InvalidLength)
        );
        assert_eq!(
            parse_hub_descriptor(&[12, 0x29, 4, 0, 0, 1, 0, 0, 0, 0, 0, 0], true),
            Err(DescriptorError::InvalidType)
        );
        assert_eq!(
            parse_hub_descriptor(&[7, 0x29, 0, 0, 0, 1, 0], false),
            Err(DescriptorError::InvalidLength)
        );
    }

    #[test]
    fn recognizes_hub_interfaces_without_requiring_hid_descriptors() {
        let descriptor = [
            9, 2, 18, 0, 1, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 0, 9, 0, 0, 0, // hub interface
        ];
        let parsed = parse_configuration_descriptor(&descriptor).unwrap();
        assert_eq!(parsed.hub_protocol, Some(0));
        assert!(parsed.interfaces.is_empty());
    }

    #[test]
    fn hub_port_status_and_speed_are_decoded_without_hardware() {
        let status = parse_hub_port_status(&[0x03, 0x04, 0x11, 0]).unwrap();
        assert!(status.connected());
        assert_eq!(status.change, 0x11);
        assert_eq!(hub_child_speed(status, 3), 3);
        assert_eq!(hub_child_speed(status, 4), 4);
        let low = HubPortStatus {
            status: USB_PORT_STATUS_CONNECTION | USB_PORT_STATUS_LOW_SPEED,
            change: 0,
        };
        assert_eq!(hub_child_speed(low, 3), 2);
    }

    #[test]
    fn maps_usb2_and_usb3_change_bits_to_class_features() {
        assert_eq!(hub_change_feature(false, 0), Some(16));
        assert_eq!(hub_change_feature(false, 4), Some(20));
        assert_eq!(hub_change_feature(false, 5), None);
        assert_eq!(hub_change_feature(true, 5), Some(29));
        assert_eq!(hub_change_feature(true, 6), Some(25));
        assert_eq!(hub_change_feature(true, 7), Some(26));
    }

    #[test]
    fn child_address_context_contains_route_and_parent_hub_fields() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let input = DmaPage {
            physical: 0x1000,
            virtual_pointer: backing.0.as_mut_ptr(),
        };
        let path = UsbPath::root(7).child(2).unwrap().child(3).unwrap();
        build_address_context(
            &input,
            32,
            AddressContext {
                path,
                speed: 2,
                packet_size: 8,
                ep0_ring: 0x3000,
                tt: Some(TtInfo {
                    hub_slot_id: 11,
                    port: 3,
                }),
            },
        )
        .unwrap();
        assert_eq!(input.read_u32(32).unwrap() & 0x000f_ffff, 0x32);
        assert_eq!((input.read_u32(32).unwrap() >> 20) & 0xf, 2);
        assert_eq!((input.read_u32(36).unwrap() >> 16) as u8, 7);
        assert_eq!(input.read_u32(40).unwrap() & 0xffff, 0x030b);
    }

    #[test]
    fn hub_slot_update_preserves_route_and_sets_hub_port_count() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut input_backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut output_backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let input = DmaPage {
            physical: 0x1000,
            virtual_pointer: input_backing.0.as_mut_ptr(),
        };
        let output = DmaPage {
            physical: 0x2000,
            virtual_pointer: output_backing.0.as_mut_ptr(),
        };
        output.write_u32(0, 0x12345 | (3 << 20)).unwrap();
        output.write_u32(4, 5 << 16).unwrap();
        update_hub_slot_context(
            &input,
            &output,
            32,
            3,
            HubState {
                ports: 8,
                superspeed: false,
                protocol: 2,
                characteristics: 3 << 5,
                next_port: 1,
            },
        )
        .unwrap();
        assert_eq!(input.read_u32(32).unwrap() & 0x000f_ffff, 0x12345);
        assert_ne!(input.read_u32(32).unwrap() & (1 << 25), 0);
        assert_ne!(input.read_u32(32).unwrap() & (1 << 26), 0);
        assert_eq!((input.read_u32(36).unwrap() >> 24) as u8, 8);
        assert_eq!((input.read_u32(40).unwrap() >> 16) & 3, 3);
    }

    #[test]
    fn tt_targets_follow_single_multi_and_inherited_semantics() {
        let inherited = TtInfo {
            hub_slot_id: 7,
            port: 2,
        };
        assert_eq!(
            derive_child_tt(3, 11, Some(1), None, 4, 1),
            Some(TtInfo {
                hub_slot_id: 11,
                port: 0,
            })
        );
        assert_eq!(
            derive_child_tt(3, 11, Some(2), None, 4, 1),
            Some(TtInfo {
                hub_slot_id: 11,
                port: 4,
            })
        );
        assert_eq!(
            derive_child_tt(1, 12, Some(0), Some(inherited), 5, 2),
            Some(inherited)
        );
        assert_eq!(derive_child_tt(3, 11, Some(2), None, 4, 3), None);
        assert_eq!(derive_child_tt(4, 11, None, Some(inherited), 4, 4), None);
    }

    #[test]
    fn high_speed_child_context_keeps_tt_fields_zero() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let input = DmaPage {
            physical: 0x1000,
            virtual_pointer: backing.0.as_mut_ptr(),
        };
        build_address_context(
            &input,
            32,
            AddressContext {
                path: UsbPath::root(1).child(2).unwrap(),
                speed: 3,
                packet_size: 64,
                ep0_ring: 0x2000,
                tt: None,
            },
        )
        .unwrap();
        assert_eq!(input.read_u32(40).unwrap() & 0x0003_ffff, 0);
    }

    #[test]
    fn non_high_speed_hub_context_clears_mtt_and_ttt() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut input_backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut output_backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let input = DmaPage {
            physical: 0x1000,
            virtual_pointer: input_backing.0.as_mut_ptr(),
        };
        let output = DmaPage {
            physical: 0x2000,
            virtual_pointer: output_backing.0.as_mut_ptr(),
        };
        output.write_u32(0, 1 << 25).unwrap();
        output.write_u32(8, 3 << 16).unwrap();
        update_hub_slot_context(
            &input,
            &output,
            32,
            4,
            HubState {
                ports: 4,
                superspeed: true,
                protocol: 2,
                characteristics: 3 << 5,
                next_port: 1,
            },
        )
        .unwrap();
        assert_eq!(input.read_u32(32).unwrap() & (1 << 25), 0);
        assert_eq!(input.read_u32(40).unwrap() & (3 << 16), 0);
    }

    #[test]
    fn deferred_transfer_events_are_lossless_and_fifo() {
        let mut queue = VecDeque::with_capacity(DEFERRED_EVENT_INITIAL_CAPACITY);
        for index in 0..(RING_TRBS * 4) {
            reserve_lossless_slot(&mut queue).unwrap();
            defer_lossless(
                &mut queue,
                Trb::new(index as u64, 0, trb_control(TRB_TYPE_TRANSFER_EVENT)),
            );
        }
        assert_eq!(queue.len(), RING_TRBS * 4);
        for index in 0..(RING_TRBS * 4) {
            let event = queue.pop_front().unwrap();
            assert_eq!(event.trb_type(), TRB_TYPE_TRANSFER_EVENT);
            assert_eq!(event.parameter(), index as u64);
        }
    }

    #[test]
    fn iman_writes_clear_pending_and_preserve_requested_enable_state() {
        assert_eq!(iman_write_value(false), 1);
        assert_eq!(iman_write_value(true), 3);
    }

    #[test]
    fn dma_pool_reuses_and_clears_the_same_page_repeatedly() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut backing = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut pool = UsbDmaPool::new();
        pool.recycle(DmaPage {
            physical: 0x5000,
            virtual_pointer: backing.0.as_mut_ptr(),
        });
        for _ in 0..128 {
            let page = pool.take_recycled().unwrap();
            assert_eq!(page.physical, 0x5000);
            assert_eq!(page.read_u32(0).unwrap(), 0);
            page.write_u32(0, 0xfeed_beef).unwrap();
            pool.recycle(page);
        }
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn complete_device_returns_all_dma_pages_and_retires_interface_once() {
        #[repr(align(4096))]
        struct AlignedPage([u8; PAGE_SIZE as usize]);
        let mut output = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut input = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut control = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut ep0 = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut endpoint = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let mut report = alloc::boxed::Box::new(AlignedPage([0; PAGE_SIZE as usize]));
        let page = |physical, backing: &mut AlignedPage| DmaPage {
            physical,
            virtual_pointer: backing.0.as_mut_ptr(),
        };
        let info = HidInterfaceInfo {
            id: HidInterfaceId {
                device: 1,
                interface: 0,
            },
            slot_id: 1,
            root_port: 1,
            vendor_id: 1,
            product_id: 2,
            interface_subclass: 1,
            interface_protocol: 1,
            endpoint_address: 0x81,
            kind: HidInterfaceKind::Keyboard,
        };
        let mut interface = HidInterfaceState {
            info: info.clone(),
            report_descriptor: vec![0],
            endpoint_id: 3,
            interval: 1,
            max_packet_size: 8,
            max_burst: 0,
            max_esit_payload: 8,
            ring: ProducerRing::new(page(0x5000, &mut endpoint)).unwrap(),
            buffer: page(0x6000, &mut report),
            buffer_len: 8,
            queued_trb: 0,
            transfer_error: None,
            active: true,
        };
        assert_eq!(retire_interface(&mut interface, 6), Some(info));
        assert_eq!(retire_interface(&mut interface, 6), None);
        assert!(!interface.active);
        assert_eq!(interface.transfer_error, Some(6));

        let device = UsbDevice {
            _output_context: page(0x1000, &mut output),
            input_context: page(0x2000, &mut input),
            control_buffer: page(0x3000, &mut control),
            ep0_ring: ProducerRing::new(page(0x4000, &mut ep0)).unwrap(),
            slot_id: 1,
            path: UsbPath::root(1),
            parent_slot_id: None,
            parent_port: None,
            speed: 3,
            tt: None,
            hub: None,
            interfaces: vec![interface],
        };
        let pages = device.into_dma_pages();
        assert_eq!(pages.len(), 6);
        assert_eq!(
            pages.iter().map(|page| page.physical).collect::<Vec<_>>(),
            vec![0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000]
        );
    }

    #[test]
    fn teardown_model_is_child_first_and_scoped_to_one_subtree() {
        let root = UsbPath::root(1);
        let hub = root.child(2).unwrap();
        let child = hub.child(3).unwrap();
        let sibling = root.child(4).unwrap();
        let entries = [(root, 1), (hub, 2), (child, 3), (sibling, 4)];
        assert_eq!(teardown_slot_order(&entries, hub), vec![3, 2]);
        assert_eq!(teardown_slot_order(&entries, root), vec![3, 4, 2, 1]);
    }

    #[test]
    fn bounded_queue_preserves_recent_events_and_reports_drops() {
        let mut queue = VecDeque::new();
        assert!(!push_bounded(&mut queue, 2, 1));
        assert!(!push_bounded(&mut queue, 2, 2));
        assert!(push_bounded(&mut queue, 2, 3));
        assert_eq!(queue.into_iter().collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn lifecycle_model_reconnects_without_leaking_live_interfaces() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Event {
            Added(u32),
            Removed(u32),
        }
        let mut live = Vec::new();
        let mut events = VecDeque::new();
        for id in 1..=8 {
            live.push(id);
            push_bounded(&mut events, 32, Event::Added(id));
            let removed = live.remove(0);
            push_bounded(&mut events, 32, Event::Removed(removed));
        }
        assert!(live.is_empty());
        assert_eq!(events.len(), 16);
        assert_eq!(events.front(), Some(&Event::Added(1)));
        assert_eq!(events.back(), Some(&Event::Removed(8)));
    }
}
