//! Polling Intel High Definition Audio output for the cooperative kernel.
//!
//! Call [`AudioDevice::poll`] frequently; it performs at most 32 period
//! refills and never waits. Initialization uses bounded polling timeouts.

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::{
    hint::spin_loop,
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

use crate::{
    io::{IoError, MmioRegion},
    memory::{
        FrameAllocatorError, PhysAddr, PhysFrame, UsableFrameAllocator, VirtAddr, VirtPage,
        PAGE_SIZE,
    },
    paging::{ActivePageTable, MapError, PageTableFlags},
    pci::{PciBar, PciConfig, PciError},
};

const MAX_MMIO_SIZE: u64 = 0x20_0000;
const WAIT: usize = 1_000_000;
const VERB_WAIT: usize = 100_000;
const MAX_WIDGETS: usize = 256;
const BDL_ENTRIES: usize = 32;
const PERIOD_BYTES: usize = 2048;
const QUEUE_BYTES: usize = 128 * 1024;
const FRAME_BYTES: usize = 4;
const STREAM_TAG: u8 = 1;
// Base 44.1 kHz, x1 /1, 16-bit, two channels.
const FORMAT_44K1_S16_STEREO: u16 = 0x4011;

const GCAP: usize = 0x00;
const GCTL: usize = 0x08;
const STATESTS: usize = 0x0e;
const ICOI: usize = 0x60;
const ICII: usize = 0x64;
const ICIS: usize = 0x68;
const STREAM_BASE: usize = 0x80;
const STREAM_STRIDE: usize = 0x20;
const ICIS_BUSY: u16 = 1;
const ICIS_VALID: u16 = 2;
const SD_RESET: u8 = 1;
const SD_RUN: u8 = 2;
const SD_STATUS_W1C: u8 = 0x1c;

const PARAM_NODE_COUNT: u8 = 0x04;
const PARAM_FG_TYPE: u8 = 0x05;
const PARAM_WIDGET_CAPS: u8 = 0x09;
const PARAM_PIN_CAPS: u8 = 0x0c;
const PARAM_IN_AMP_CAPS: u8 = 0x0d;
const PARAM_CONN_LEN: u8 = 0x0e;
const PARAM_OUT_AMP_CAPS: u8 = 0x12;
const AUDIO_OUTPUT: u8 = 0;
const MIXER: u8 = 2;
const SELECTOR: u8 = 3;
const PIN: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioError {
    Pci(PciError),
    Io(IoError),
    Mapping(MapError),
    FrameAllocator(FrameAllocatorError),
    ControllerNotFound,
    InvalidBar,
    AddressOverflow,
    OutOfFrames,
    UnsupportedDmaAddress,
    ControllerTimeout,
    StreamTimeout,
    VerbTimeout,
    NoCodec,
    MalformedCodec,
    NoAnalogOutput,
    NoOutputStream,
    InvalidPcmAlignment,
    StreamFault,
}

impl From<PciError> for AudioError {
    fn from(value: PciError) -> Self {
        Self::Pci(value)
    }
}
impl From<IoError> for AudioError {
    fn from(value: IoError) -> Self {
        Self::Io(value)
    }
}
impl From<MapError> for AudioError {
    fn from(value: MapError) -> Self {
        Self::Mapping(value)
    }
}
impl From<FrameAllocatorError> for AudioError {
    fn from(value: FrameAllocatorError) -> Self {
        Self::FrameAllocator(value)
    }
}

struct DmaPage {
    physical: u64,
    pointer: *mut u8,
}

impl DmaPage {
    fn allocate(
        frames: &mut UsableFrameAllocator<'_>,
        hhdm: u64,
        supports_64_bit: bool,
    ) -> Result<Self, AudioError> {
        let frame = frames.allocate_frame()?.ok_or(AudioError::OutOfFrames)?;
        let physical = frame.start_address().as_u64();
        if !supports_64_bit
            && physical.checked_add(PAGE_SIZE - 1).unwrap_or(u64::MAX) > u64::from(u32::MAX)
        {
            return Err(AudioError::UnsupportedDmaAddress);
        }
        let virtual_address = hhdm
            .checked_add(physical)
            .ok_or(AudioError::AddressOverflow)?;
        VirtAddr::try_new(virtual_address).map_err(|_| AudioError::AddressOverflow)?;
        let pointer =
            usize::try_from(virtual_address).map_err(|_| AudioError::AddressOverflow)? as *mut u8;
        // SAFETY: This newly allocated HHDM frame is exclusively owned here.
        unsafe { ptr::write_bytes(pointer, 0, PAGE_SIZE as usize) };
        Ok(Self { physical, pointer })
    }

    fn write_u32(&self, offset: usize, value: u32) -> Result<(), AudioError> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .filter(|end| *end <= PAGE_SIZE as usize)
                .is_none()
        {
            return Err(AudioError::AddressOverflow);
        }
        // SAFETY: Alignment, bounds, and exclusive ownership were checked.
        unsafe { ptr::write_volatile(self.pointer.add(offset).cast(), value) };
        Ok(())
    }

    fn fill_period(&self, data: &[u8]) -> Result<(), AudioError> {
        if data.len() > PERIOD_BYTES {
            return Err(AudioError::AddressOverflow);
        }
        // SAFETY: The caller only refills a completed period; both ranges fit.
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.pointer, data.len());
            ptr::write_bytes(self.pointer.add(data.len()), 0, PERIOD_BYTES - data.len());
        }
        compiler_fence(Ordering::Release);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Widget {
    nid: u8,
    kind: u8,
    caps: u32,
    connections: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Route {
    // Ordered pin -> intermediate widgets -> converter.
    nodes: Vec<u8>,
    // Input index at each node except the converter.
    selectors: Vec<u8>,
}

struct Output {
    codec: u8,
    afg: u8,
    pin: u8,
    pin_caps: u32,
    widgets: Vec<Widget>,
    route: Route,
}

/// Exclusively owns one HDA controller and one cyclic playback stream.
pub struct AudioDevice {
    mmio: MmioRegion,
    stream: usize,
    bdl: DmaPage,
    periods: Vec<DmaPage>,
    queue: VecDeque<u8>,
    last_period: usize,
    running: bool,
}

impl AudioDevice {
    /// Discovers the first PCI class 04/03/00 device and starts silent playback.
    ///
    /// # Safety
    ///
    /// The caller must provide exclusive PCI, BAR0, active-page-table, allocator,
    /// and controller ownership. The HHDM must cover every allocated DMA frame.
    pub unsafe fn initialize(
        page_table: &mut ActivePageTable,
        frames: &mut UsableFrameAllocator<'_>,
    ) -> Result<Self, AudioError> {
        let mut pci = unsafe { PciConfig::new()? };
        let device = pci
            .find_first(0x04, 0x03, Some(0))?
            .ok_or(AudioError::ControllerNotFound)?;
        let bar = pci.probe_bar0(device)?;
        pci.enable_memory_and_bus_mastering(device)?;
        let mut mmio = unsafe { map_bar0(page_table, frames, bar)? };
        let capabilities = mmio.read_u16(GCAP)?;
        reset_controller(&mut mmio)?;
        wait_for_codec(&mut mmio)?;

        let inputs = usize::from((capabilities >> 8) & 0xf);
        let outputs = usize::from((capabilities >> 12) & 0xf);
        let bidirectional = usize::from((capabilities >> 3) & 0x1f);
        let (descriptor, bidirectional_output) = if outputs != 0 {
            (inputs, false)
        } else if bidirectional != 0 {
            (inputs + outputs, true)
        } else {
            return Err(AudioError::NoOutputStream);
        };
        let stream = STREAM_BASE
            .checked_add(
                descriptor
                    .checked_mul(STREAM_STRIDE)
                    .ok_or(AudioError::AddressOverflow)?,
            )
            .ok_or(AudioError::AddressOverflow)?;
        if stream
            .checked_add(STREAM_STRIDE)
            .filter(|end| *end <= mmio.len())
            .is_none()
        {
            return Err(AudioError::InvalidBar);
        }
        reset_stream(&mut mmio, stream)?;

        let output = select_output(&mut mmio)?;
        configure_path(&mut mmio, &output)?;

        let hhdm = page_table.hhdm_offset().as_u64();
        let address_64 = capabilities & 1 != 0;
        let bdl = DmaPage::allocate(frames, hhdm, address_64)?;
        let mut periods = Vec::with_capacity(BDL_ENTRIES);
        for _ in 0..BDL_ENTRIES {
            periods.push(DmaPage::allocate(frames, hhdm, address_64)?);
        }
        for (index, period) in periods.iter().enumerate() {
            let entry = index * 16;
            bdl.write_u32(entry, period.physical as u32)?;
            bdl.write_u32(entry + 4, (period.physical >> 32) as u32)?;
            bdl.write_u32(entry + 8, PERIOD_BYTES as u32)?;
            bdl.write_u32(entry + 12, 1)?; // IOC updates BCIS; IRQ enable remains off.
        }
        compiler_fence(Ordering::Release);
        program_stream(&mut mmio, stream, bdl.physical, bidirectional_output)?;

        let mut result = Self {
            mmio,
            stream,
            bdl,
            periods,
            queue: VecDeque::with_capacity(QUEUE_BYTES),
            last_period: 0,
            running: false,
        };
        // Allocation zeroed every complete period before RUN is asserted.
        result.set_run(true)?;
        result.running = true;
        Ok(result)
    }

    /// Queues 44.1 kHz interleaved little-endian S16 stereo PCM.
    ///
    /// A short return means the bounded queue filled; retry the suffix later.
    pub fn write_pcm(&mut self, bytes: &[u8]) -> Result<usize, AudioError> {
        if bytes.len() % FRAME_BYTES != 0 {
            return Err(AudioError::InvalidPcmAlignment);
        }
        let available = QUEUE_BYTES.saturating_sub(self.queue.len());
        let accepted = bytes.len().min(available) / FRAME_BYTES * FRAME_BYTES;
        self.queue.extend(bytes[..accepted].iter().copied());
        Ok(accepted)
    }

    /// Reclaims completed periods and supplies queued PCM, padding with silence.
    pub fn poll(&mut self) -> Result<(), AudioError> {
        if !self.running {
            return Ok(());
        }
        let status = self.mmio.read_u8(self.stream + 3)?;
        if status & SD_STATUS_W1C != 0 {
            self.mmio
                .write_u8(self.stream + 3, status & SD_STATUS_W1C)?;
        }
        if status & 0x18 != 0 {
            return Err(AudioError::StreamFault);
        }
        let position = self.mmio.read_u32(self.stream + 4)? as usize;
        let current = (position / PERIOD_BYTES) % BDL_ENTRIES;
        let mut count = (current + BDL_ENTRIES - self.last_period) % BDL_ENTRIES;
        count = count.min(BDL_ENTRIES);
        while count != 0 {
            let index = self.last_period;
            self.refill(index)?;
            self.last_period = (self.last_period + 1) % BDL_ENTRIES;
            count -= 1;
        }
        Ok(())
    }

    pub fn queued_bytes(&self) -> usize {
        self.queue.len()
    }

    pub fn available_bytes(&self) -> usize {
        QUEUE_BYTES - self.queue.len()
    }

    fn refill(&mut self, index: usize) -> Result<(), AudioError> {
        let count = PERIOD_BYTES.min(self.queue.len()) / FRAME_BYTES * FRAME_BYTES;
        let mut data = [0_u8; PERIOD_BYTES];
        for byte in &mut data[..count] {
            *byte = self.queue.pop_front().expect("bounded by queue length");
        }
        self.periods[index].fill_period(&data[..count])
    }

    fn set_run(&mut self, run: bool) -> Result<(), AudioError> {
        let mut control = self.mmio.read_u8(self.stream)?;
        if run {
            control |= SD_RUN;
        } else {
            control &= !SD_RUN;
        }
        self.mmio.write_u8(self.stream, control)?;
        Ok(())
    }
}

impl Drop for AudioDevice {
    fn drop(&mut self) {
        let _ = self.set_run(false);
        self.running = false;
        compiler_fence(Ordering::SeqCst);
        // The monotonic allocator cannot accept these pages back. Keeping them
        // owned avoids reuse while posted DMA writes could still exist.
        let _ = self.bdl.physical;
    }
}

unsafe fn map_bar0(
    page_table: &mut ActivePageTable,
    frames: &mut UsableFrameAllocator<'_>,
    bar: PciBar,
) -> Result<MmioRegion, AudioError> {
    if bar.size < 0x100 || bar.size > MAX_MMIO_SIZE {
        return Err(AudioError::InvalidBar);
    }
    let physical_page = bar.physical_address & !(PAGE_SIZE - 1);
    let page_offset = bar.physical_address - physical_page;
    let mapped_length = page_offset
        .checked_add(bar.size)
        .and_then(|length| length.checked_add(PAGE_SIZE - 1))
        .map(|length| length & !(PAGE_SIZE - 1))
        .ok_or(AudioError::AddressOverflow)?;
    let candidates = [
        0xffff_a000_0000_0000_u64,
        0xffff_a100_0000_0000,
        0xffff_a200_0000_0000,
        0xffff_a300_0000_0000,
    ];
    let mut chosen = None;
    'candidate: for base in candidates {
        let mut offset = 0;
        while offset < mapped_length {
            let address = VirtAddr::try_new(
                base.checked_add(offset)
                    .ok_or(AudioError::AddressOverflow)?,
            )
            .map_err(|_| AudioError::AddressOverflow)?;
            if page_table.translate_addr(address).is_some() {
                continue 'candidate;
            }
            offset += PAGE_SIZE;
        }
        chosen = Some(base);
        break;
    }
    let virtual_base = chosen.ok_or(AudioError::InvalidBar)?;
    let flags = PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    let mut offset = 0;
    while offset < mapped_length {
        let physical = PhysAddr::try_new(
            physical_page
                .checked_add(offset)
                .ok_or(AudioError::AddressOverflow)?,
        )
        .map_err(|_| AudioError::AddressOverflow)?;
        let frame = PhysFrame::from_start_address(physical).map_err(|_| AudioError::InvalidBar)?;
        let virtual_address = VirtAddr::try_new(
            virtual_base
                .checked_add(offset)
                .ok_or(AudioError::AddressOverflow)?,
        )
        .map_err(|_| AudioError::AddressOverflow)?;
        let page =
            VirtPage::from_start_address(virtual_address).map_err(|_| AudioError::InvalidBar)?;
        unsafe { page_table.map_4k(page, frame, flags, frames)? };
        offset += PAGE_SIZE;
    }
    let address = virtual_base
        .checked_add(page_offset)
        .ok_or(AudioError::AddressOverflow)?;
    let pointer = usize::try_from(address).map_err(|_| AudioError::AddressOverflow)? as *mut u8;
    let length = usize::try_from(bar.size).map_err(|_| AudioError::AddressOverflow)?;
    // SAFETY: The entire exclusively claimed BAR was mapped NO_CACHE above.
    unsafe { MmioRegion::from_raw_parts(pointer, length) }.ok_or(AudioError::InvalidBar)
}

fn bounded<F>(iterations: usize, mut predicate: F, error: AudioError) -> Result<(), AudioError>
where
    F: FnMut() -> Result<bool, AudioError>,
{
    for _ in 0..iterations {
        if predicate()? {
            return Ok(());
        }
        spin_loop();
    }
    Err(error)
}

fn reset_controller(mmio: &mut MmioRegion) -> Result<(), AudioError> {
    let value = mmio.read_u32(GCTL)?;
    mmio.write_u32(GCTL, value & !1)?;
    bounded(
        WAIT,
        || Ok(mmio.read_u32(GCTL)? & 1 == 0),
        AudioError::ControllerTimeout,
    )?;
    // HDA requires CRST to remain deasserted for at least 100 microseconds.
    // GinkgoOS has no timer service yet, so use a deliberately conservative
    // bounded delay before codec reset release.
    for _ in 0..100_000 {
        spin_loop();
    }
    mmio.write_u32(GCTL, value | 1)?;
    bounded(
        WAIT,
        || Ok(mmio.read_u32(GCTL)? & 1 != 0),
        AudioError::ControllerTimeout,
    )
}

fn wait_for_codec(mmio: &mut MmioRegion) -> Result<(), AudioError> {
    bounded(
        WAIT,
        || Ok(mmio.read_u16(STATESTS)? & 0x7fff != 0),
        AudioError::NoCodec,
    )
}

fn reset_stream(mmio: &mut MmioRegion, stream: usize) -> Result<(), AudioError> {
    let stopped = mmio.read_u8(stream)? & !SD_RUN;
    mmio.write_u8(stream, stopped)?;
    mmio.write_u8(stream, stopped | SD_RESET)?;
    bounded(
        WAIT,
        || Ok(mmio.read_u8(stream)? & SD_RESET != 0),
        AudioError::StreamTimeout,
    )?;
    mmio.write_u8(stream, stopped & !SD_RESET)?;
    bounded(
        WAIT,
        || Ok(mmio.read_u8(stream)? & SD_RESET == 0),
        AudioError::StreamTimeout,
    )?;
    mmio.write_u8(stream + 3, SD_STATUS_W1C)?;
    Ok(())
}

fn verb(mmio: &mut MmioRegion, codec: u8, nid: u8, payload: u32) -> Result<u32, AudioError> {
    bounded(
        VERB_WAIT,
        || Ok(mmio.read_u16(ICIS)? & ICIS_BUSY == 0),
        AudioError::VerbTimeout,
    )?;
    // IRV is W1C: clear only that bit, never write a cached ICIS value back.
    if mmio.read_u16(ICIS)? & ICIS_VALID != 0 {
        mmio.write_u16(ICIS, ICIS_VALID)?;
    }
    let command = (u32::from(codec) << 28) | (u32::from(nid) << 20) | (payload & 0xfffff);
    mmio.write_u32(ICOI, command)?;
    mmio.write_u16(ICIS, ICIS_BUSY)?;
    bounded(
        VERB_WAIT,
        || Ok(mmio.read_u16(ICIS)? & ICIS_VALID != 0),
        AudioError::VerbTimeout,
    )?;
    let response = mmio.read_u32(ICII)?;
    mmio.write_u16(ICIS, ICIS_VALID)?;
    Ok(response)
}

fn parameter(mmio: &mut MmioRegion, codec: u8, nid: u8, id: u8) -> Result<u32, AudioError> {
    verb(mmio, codec, nid, 0xf0000 | u32::from(id))
}

fn set(mmio: &mut MmioRegion, codec: u8, nid: u8, payload: u32) -> Result<(), AudioError> {
    verb(mmio, codec, nid, payload).map(|_| ())
}

fn node_range(response: u32) -> Result<(u16, u16), AudioError> {
    let start = ((response >> 16) & 0xff) as u16;
    let count = (response & 0xff) as u16;
    let end = start.checked_add(count).ok_or(AudioError::MalformedCodec)?;
    if end > MAX_WIDGETS as u16 {
        return Err(AudioError::MalformedCodec);
    }
    Ok((start, end))
}

fn select_output(mmio: &mut MmioRegion) -> Result<Output, AudioError> {
    let state = mmio.read_u16(STATESTS)? & 0x7fff;
    let mut best: Option<(u8, Output)> = None;
    for codec in 0_u8..15 {
        if state & (1 << codec) == 0 {
            continue;
        }
        let (fg_start, fg_end) = node_range(parameter(mmio, codec, 0, PARAM_NODE_COUNT)?)?;
        for afg_value in fg_start..fg_end {
            let afg = afg_value as u8;
            if parameter(mmio, codec, afg, PARAM_FG_TYPE)? & 0xff != 1 {
                continue;
            }
            let (start, end) = node_range(parameter(mmio, codec, afg, PARAM_NODE_COUNT)?)?;
            let mut widgets = Vec::with_capacity(usize::from(end - start));
            for nid_value in start..end {
                let nid = nid_value as u8;
                let caps = parameter(mmio, codec, nid, PARAM_WIDGET_CAPS)?;
                widgets.push(Widget {
                    nid,
                    kind: ((caps >> 20) & 0xf) as u8,
                    caps,
                    connections: connections(mmio, codec, nid)?,
                });
            }
            for pin in widgets.iter().filter(|widget| widget.kind == PIN) {
                if pin.caps & (1 << 9) != 0 {
                    continue;
                }
                let pin_caps = parameter(mmio, codec, pin.nid, PARAM_PIN_CAPS)?;
                if pin_caps & (1 << 4) == 0 {
                    continue;
                }
                let Some(route) = search_route(pin.nid, &widgets) else {
                    continue;
                };
                let config = verb(mmio, codec, pin.nid, 0xf1c00)?;
                if config >> 30 & 3 == 1 {
                    continue;
                }
                let device = config >> 20 & 0xf;
                let disconnected = pin_caps & (1 << 5) != 0
                    && verb(mmio, codec, pin.nid, 0xf0900)? & (1 << 31) == 0;
                let mut rank = match device {
                    2 => 0, // headphone
                    1 => 1, // speaker
                    0 => 2, // line out
                    _ => 3, // QEMU hda-output and minimally described analog pins
                };
                if disconnected {
                    rank += 8;
                }
                if best.as_ref().map_or(true, |(old, _)| rank < *old) {
                    best = Some((
                        rank,
                        Output {
                            codec,
                            afg,
                            pin: pin.nid,
                            pin_caps,
                            widgets: widgets.clone(),
                            route,
                        },
                    ));
                }
            }
        }
    }
    best.map(|(_, output)| output)
        .ok_or(AudioError::NoAnalogOutput)
}

fn connections(mmio: &mut MmioRegion, codec: u8, nid: u8) -> Result<Vec<u8>, AudioError> {
    let info = parameter(mmio, codec, nid, PARAM_CONN_LEN)?;
    let long = info & 0x80 != 0;
    let count = (info & 0x7f) as usize;
    let per_response = if long { 2 } else { 4 };
    let mut encoded = Vec::with_capacity(count);
    let mut index = 0;
    while index < count {
        let response = verb(mmio, codec, nid, 0xf0200 | index as u32)?;
        for slot in 0..per_response.min(count - index) {
            encoded.push(if long {
                ((response >> (slot * 16)) & 0xffff) as u16
            } else {
                ((response >> (slot * 8)) & 0xff) as u16
            });
        }
        index += per_response;
    }
    expand_connections(&encoded, long)
}

fn expand_connections(entries: &[u16], long: bool) -> Result<Vec<u8>, AudioError> {
    let range_bit = if long { 0x8000 } else { 0x80 };
    let value_mask = if long { 0x7fff } else { 0x7f };
    let mut result = Vec::new();
    for &entry in entries {
        let value = entry & value_mask;
        if value > u16::from(u8::MAX) {
            return Err(AudioError::MalformedCodec);
        }
        let value = value as u8;
        if entry & range_bit != 0 {
            let previous = *result.last().ok_or(AudioError::MalformedCodec)?;
            if value <= previous {
                return Err(AudioError::MalformedCodec);
            }
            result.extend(previous + 1..=value);
        } else {
            result.push(value);
        }
        if result.len() > MAX_WIDGETS {
            return Err(AudioError::MalformedCodec);
        }
    }
    Ok(result)
}

fn search_route(pin: u8, widgets: &[Widget]) -> Option<Route> {
    fn visit(nid: u8, widgets: &[Widget], visited: &mut [bool; 256]) -> Option<Route> {
        if visited[usize::from(nid)] {
            return None;
        }
        visited[usize::from(nid)] = true;
        let widget = widgets.iter().find(|widget| widget.nid == nid)?;
        if widget.kind == AUDIO_OUTPUT {
            visited[usize::from(nid)] = false;
            return Some(Route {
                nodes: vec![nid],
                selectors: Vec::new(),
            });
        }
        if widget.kind != PIN && widget.kind != SELECTOR && widget.kind != MIXER {
            visited[usize::from(nid)] = false;
            return None;
        }
        for (selector, &source) in widget.connections.iter().enumerate() {
            if let Some(mut route) = visit(source, widgets, visited) {
                route.nodes.insert(0, nid);
                route.selectors.insert(0, selector as u8);
                visited[usize::from(nid)] = false;
                return Some(route);
            }
        }
        visited[usize::from(nid)] = false;
        None
    }
    visit(pin, widgets, &mut [false; 256])
}

fn configure_path(mmio: &mut MmioRegion, output: &Output) -> Result<(), AudioError> {
    set(mmio, output.codec, output.afg, 0x70500)?;
    wait_d0(mmio, output.codec, output.afg)?;
    let afg_amp = parameter(mmio, output.codec, output.afg, PARAM_OUT_AMP_CAPS)?;
    for &nid in &output.route.nodes {
        set(mmio, output.codec, nid, 0x70500)?;
        wait_d0(mmio, output.codec, nid)?;
    }
    for (&nid, &selector) in output.route.nodes.iter().zip(&output.route.selectors) {
        set(mmio, output.codec, nid, 0x70100 | u32::from(selector))?;
        let widget = output
            .widgets
            .iter()
            .find(|widget| widget.nid == nid)
            .ok_or(AudioError::MalformedCodec)?;
        if widget.caps & (1 << 1) != 0 {
            let caps = if widget.caps & (1 << 3) != 0 {
                parameter(mmio, output.codec, nid, PARAM_IN_AMP_CAPS)?
            } else {
                parameter(mmio, output.codec, output.afg, PARAM_IN_AMP_CAPS)?
            };
            let zero_db = ((caps >> 8) & 0x7f).min(caps & 0x7f);
            set(
                mmio,
                output.codec,
                nid,
                0x37000 | (u32::from(selector) << 8) | zero_db,
            )?;
        }
    }
    for &nid in &output.route.nodes {
        let widget = output
            .widgets
            .iter()
            .find(|widget| widget.nid == nid)
            .ok_or(AudioError::MalformedCodec)?;
        if widget.caps & (1 << 2) != 0 {
            let caps = if widget.caps & (1 << 3) != 0 {
                parameter(mmio, output.codec, nid, PARAM_OUT_AMP_CAPS)?
            } else {
                afg_amp
            };
            let zero_db = (caps & 0x7f).min((caps >> 8) & 0x7f);
            set(mmio, output.codec, nid, 0x3b000 | zero_db)?;
        }
    }
    let converter = *output
        .route
        .nodes
        .last()
        .ok_or(AudioError::MalformedCodec)?;
    set(
        mmio,
        output.codec,
        converter,
        0x20000 | u32::from(FORMAT_44K1_S16_STEREO),
    )?;
    set(
        mmio,
        output.codec,
        converter,
        0x70600 | (u32::from(STREAM_TAG) << 4),
    )?;
    set(mmio, output.codec, output.pin, 0x70740)?;
    if output.pin_caps & (1 << 16) != 0 {
        set(mmio, output.codec, output.pin, 0x70c02)?;
    }
    Ok(())
}

fn wait_d0(mmio: &mut MmioRegion, codec: u8, nid: u8) -> Result<(), AudioError> {
    bounded(
        VERB_WAIT,
        || Ok(verb(mmio, codec, nid, 0xf0500)? & 0xf == 0),
        AudioError::VerbTimeout,
    )
}

fn program_stream(
    mmio: &mut MmioRegion,
    stream: usize,
    bdl: u64,
    bidirectional_output: bool,
) -> Result<(), AudioError> {
    mmio.write_u32(stream + 0x08, (BDL_ENTRIES * PERIOD_BYTES) as u32)?;
    mmio.write_u16(stream + 0x0c, (BDL_ENTRIES - 1) as u16)?;
    mmio.write_u16(stream + 0x12, FORMAT_44K1_S16_STEREO)?;
    mmio.write_u32(stream + 0x18, bdl as u32)?;
    mmio.write_u32(stream + 0x1c, (bdl >> 32) as u32)?;
    // SDCTL is 24 bits; a u32 store would accidentally write W1C SDSTS.
    mmio.write_u16(stream, 0)?;
    let direction = if bidirectional_output { 1 << 3 } else { 0 };
    mmio.write_u8(stream + 2, (STREAM_TAG << 4) | direction)?;
    mmio.write_u8(stream + 3, SD_STATUS_W1C)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_fields_are_correct() {
        assert_eq!(FORMAT_44K1_S16_STEREO, 0x4011);
        assert_ne!(FORMAT_44K1_S16_STEREO & (1 << 14), 0);
        assert_eq!((FORMAT_44K1_S16_STEREO >> 4) & 7, 1);
        assert_eq!(FORMAT_44K1_S16_STEREO & 0xf, 1);
    }

    #[test]
    fn connection_ranges_expand() {
        assert_eq!(
            expand_connections(&[2, 0x85, 9], false),
            Ok(vec![2, 3, 4, 5, 9])
        );
        assert_eq!(
            expand_connections(&[0x22, 0x8025], true),
            Ok(vec![0x22, 0x23, 0x24, 0x25])
        );
        assert_eq!(
            expand_connections(&[0x82], false),
            Err(AudioError::MalformedCodec)
        );
    }

    #[test]
    fn route_search_tries_all_inputs_and_breaks_cycles() {
        let widgets = vec![
            Widget {
                nid: 5,
                kind: PIN,
                caps: 0,
                connections: vec![6, 7],
            },
            Widget {
                nid: 6,
                kind: SELECTOR,
                caps: 0,
                connections: vec![5],
            },
            Widget {
                nid: 7,
                kind: MIXER,
                caps: 0,
                connections: vec![8],
            },
            Widget {
                nid: 8,
                kind: AUDIO_OUTPUT,
                caps: 0,
                connections: vec![],
            },
        ];
        assert_eq!(
            search_route(5, &widgets),
            Some(Route {
                nodes: vec![5, 7, 8],
                selectors: vec![1, 0],
            })
        );
    }
}
