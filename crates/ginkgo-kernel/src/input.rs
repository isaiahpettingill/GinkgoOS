//! Kernel HID input manager.
//!
//! This module binds the polling xHCI transport to the transport-independent
//! HID report decoder and retains a bounded queue of normalized input events.

use alloc::{collections::VecDeque, vec::Vec};

use ginkgo_hid::{
    ApplicationKind, DecodeError, DescriptorError as HidDescriptorError, DeviceLayout, EventBuffer,
    InputEvent, ReportDecoder,
};

use crate::{
    memory::UsableFrameAllocator,
    paging::ActivePageTable,
    usb::{
        HidInterfaceId, HidInterfaceInfo, PortFailure, TopologyFailure, UsbError, UsbHost,
        UsbLifecycleEvent, UsbTopologyEntry, XhciInterruptDiagnostics,
    },
};

/// Maximum number of decoded events retained until a kernel consumer reads them.
pub const INPUT_QUEUE_CAPACITY: usize = 256;
const EVENTS_PER_REPORT: usize = 64;

/// A normalized event tagged with the USB interface that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInputEvent {
    pub interface: HidInterfaceId,
    pub event: InputEvent,
}

/// A HID interface whose report descriptor could not be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorFailure {
    pub interface: HidInterfaceId,
    pub error: HidDescriptorError,
}

/// Summary of work completed by one nonblocking input poll.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollSummary {
    pub reports: usize,
    pub events: usize,
    pub dropped_events: usize,
    pub malformed_reports: usize,
    pub interfaces_added: usize,
    pub interfaces_removed: usize,
}

struct DecoderEntry {
    interface: HidInterfaceId,
    decoder: ReportDecoder,
}

/// Owns the USB host controller, HID decoders, and the kernel input event queue.
pub struct InputManager {
    host: UsbHost,
    decoders: Vec<DecoderEntry>,
    descriptor_failures: Vec<DescriptorFailure>,
    events: VecDeque<DeviceInputEvent>,
    dropped_events: usize,
    malformed_reports: usize,
    disconnected: VecDeque<HidInterfaceId>,
}

impl InputManager {
    /// Claims xHCI, enumerates connected root-port HID devices, and parses each
    /// input report descriptor.
    ///
    /// Interfaces with unsupported or malformed report descriptors are reported
    /// through [`Self::descriptor_failures`] without preventing other devices
    /// from working.
    ///
    /// # Safety
    ///
    /// The caller must satisfy [`UsbHost::initialize`]'s exclusive PCI, xHCI,
    /// MMIO mapping, and coherent HHDM DMA requirements.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<Self, UsbError> {
        let host = UsbHost::initialize(page_table, frames, hhdm_offset)?;
        let mut decoders = Vec::new();
        let mut descriptor_failures = Vec::new();

        for index in 0..host.interface_count() {
            let Some(info) = host.interface_info(index) else {
                continue;
            };
            let Some(descriptor) = host.report_descriptor(info.id) else {
                continue;
            };
            match DeviceLayout::parse(descriptor) {
                Ok(mut layout) => {
                    if info.vendor_id == 0x0079 && info.product_id == 0x0006 {
                        layout.apply_dragonrise_0079_0006_quirks();
                    }
                    decoders.push(DecoderEntry {
                        interface: info.id,
                        decoder: ReportDecoder::new(layout),
                    });
                }
                Err(error) => descriptor_failures.push(DescriptorFailure {
                    interface: info.id,
                    error,
                }),
            }
        }

        Ok(Self {
            host,
            decoders,
            descriptor_failures,
            events: VecDeque::with_capacity(INPUT_QUEUE_CAPACITY),
            dropped_events: 0,
            malformed_reports: 0,
            disconnected: VecDeque::new(),
        })
    }

    /// Polls xHCI once, decodes all completed reports, and queues state changes.
    /// This compatibility method cannot enumerate newly attached devices because
    /// runtime slot setup requires access to the physical frame allocator.
    pub fn poll(&mut self) -> Result<PollSummary, UsbError> {
        let reports = self.host.poll()?;
        self.process_poll(reports)
    }

    /// Polls xHCI with the resources required for runtime device enumeration.
    pub fn poll_with_resources(
        &mut self,
        frames: &mut UsableFrameAllocator<'_>,
        hhdm_offset: u64,
    ) -> Result<PollSummary, UsbError> {
        let reports = self.host.poll_with_resources(frames, hhdm_offset)?;
        self.process_poll(reports)
    }

    fn process_poll(
        &mut self,
        reports: Vec<crate::usb::HidReport>,
    ) -> Result<PollSummary, UsbError> {
        let mut summary = PollSummary {
            reports: reports.len(),
            ..PollSummary::default()
        };
        while let Some(event) = self.host.pop_lifecycle_event() {
            match event {
                UsbLifecycleEvent::InterfaceAdded(info) => {
                    self.install_decoder(&info);
                    summary.interfaces_added += 1;
                }
                UsbLifecycleEvent::InterfaceRemoved(info) => {
                    self.remove_interface(info.id);
                    summary.interfaces_removed += 1;
                }
            }
        }

        for report in reports {
            let Some(decoder) = self
                .decoders
                .iter_mut()
                .find(|entry| entry.interface == report.interface)
            else {
                continue;
            };

            let mut decoded = EventBuffer::<EVENTS_PER_REPORT>::new();
            match decoder.decoder.decode_into(&report.bytes, &mut decoded) {
                Ok(result) => {
                    summary.dropped_events += result.dropped;
                    self.dropped_events += result.dropped;
                    for event in decoded.iter() {
                        if self.events.len() == INPUT_QUEUE_CAPACITY {
                            self.dropped_events += 1;
                            summary.dropped_events += 1;
                            continue;
                        }
                        self.events.push_back(DeviceInputEvent {
                            interface: report.interface,
                            event,
                        });
                        summary.events += 1;
                    }
                }
                Err(
                    DecodeError::MissingReportId
                    | DecodeError::UnknownReportId(_)
                    | DecodeError::ReportTooShort { .. },
                ) => {
                    self.malformed_reports += 1;
                    summary.malformed_reports += 1;
                }
            }
        }

        Ok(summary)
    }

    fn install_decoder(&mut self, info: &HidInterfaceInfo) {
        if self.decoders.iter().any(|entry| entry.interface == info.id)
            || self
                .descriptor_failures
                .iter()
                .any(|failure| failure.interface == info.id)
        {
            return;
        }
        let Some(descriptor) = self.host.report_descriptor(info.id) else {
            return;
        };
        match DeviceLayout::parse(descriptor) {
            Ok(mut layout) => {
                if info.vendor_id == 0x0079 && info.product_id == 0x0006 {
                    layout.apply_dragonrise_0079_0006_quirks();
                }
                self.decoders.push(DecoderEntry {
                    interface: info.id,
                    decoder: ReportDecoder::new(layout),
                });
            }
            Err(error) => self.descriptor_failures.push(DescriptorFailure {
                interface: info.id,
                error,
            }),
        }
    }

    fn remove_interface(&mut self, id: HidInterfaceId) {
        self.decoders.retain(|entry| entry.interface != id);
        self.descriptor_failures
            .retain(|failure| failure.interface != id);
        self.events.retain(|event| event.interface != id);
        if !self.disconnected.contains(&id) {
            self.disconnected.push_back(id);
        }
    }

    /// Removes the oldest queued input event.
    pub fn pop_event(&mut self) -> Option<DeviceInputEvent> {
        self.events.pop_front()
    }

    pub fn pop_disconnected(&mut self) -> Option<HidInterfaceId> {
        self.disconnected.pop_front()
    }

    pub fn queued_events(&self) -> usize {
        self.events.len()
    }

    pub fn dropped_events(&self) -> usize {
        self.dropped_events
    }

    pub fn malformed_reports(&self) -> usize {
        self.malformed_reports
    }

    pub fn interface_count(&self) -> usize {
        self.host.interface_count()
    }

    pub fn usable_interface_count(&self) -> usize {
        self.decoders.len()
    }

    pub fn interface_info(&self, index: usize) -> Option<&HidInterfaceInfo> {
        self.host.interface_info(index)
    }

    /// Returns the first recognized HID application kind for an interface.
    pub fn application_kind(&self, interface: HidInterfaceId) -> Option<ApplicationKind> {
        self.decoders
            .iter()
            .find(|entry| entry.interface == interface)
            .and_then(|entry| entry.decoder.layout().primary_application_kind())
    }

    pub fn descriptor_failures(&self) -> &[DescriptorFailure] {
        &self.descriptor_failures
    }

    pub fn enumeration_failures(&self) -> &[PortFailure] {
        self.host.enumeration_failures()
    }

    /// Enables interrupt-assisted xHCI event delivery after the IDT is active.
    ///
    /// # Safety
    ///
    /// The caller must ensure the destination local APIC and xHCI IDT vector are active.
    pub unsafe fn enable_msi(&mut self, destination_apic_id: u8) -> Result<(), UsbError> {
        unsafe { self.host.enable_msi(destination_apic_id) }
    }

    pub fn topology_snapshot(&self) -> Vec<UsbTopologyEntry> {
        self.host.topology_snapshot()
    }

    pub fn topology_failures(&self) -> &[TopologyFailure] {
        self.host.topology_failures()
    }

    pub fn interrupt_diagnostics(&self) -> XhciInterruptDiagnostics {
        self.host.interrupt_diagnostics()
    }

    pub fn recycled_dma_pages(&self) -> usize {
        self.host.recycled_dma_pages()
    }

    pub fn first_transfer_error(&self) -> Option<u8> {
        (0..self.host.interface_count()).find_map(|index| {
            let id = self.host.interface_info(index)?.id;
            self.host.interface_transfer_error(id)
        })
    }
}
