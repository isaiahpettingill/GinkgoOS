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
    usb::{HidInterfaceId, HidInterfaceInfo, PortFailure, UsbError, UsbHost},
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
        })
    }

    /// Polls xHCI once, decodes all completed reports, and queues state changes.
    /// This method does not wait for input and is suitable for a cooperative task.
    pub fn poll(&mut self) -> Result<PollSummary, UsbError> {
        let reports = self.host.poll()?;
        let mut summary = PollSummary {
            reports: reports.len(),
            ..PollSummary::default()
        };

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

    /// Removes the oldest queued input event.
    pub fn pop_event(&mut self) -> Option<DeviceInputEvent> {
        self.events.pop_front()
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

    pub fn first_transfer_error(&self) -> Option<u8> {
        (0..self.host.interface_count()).find_map(|index| {
            let id = self.host.interface_info(index)?.id;
            self.host.interface_transfer_error(id)
        })
    }
}
