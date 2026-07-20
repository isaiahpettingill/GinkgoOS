//! Transport-independent USB HID input report parsing and decoding.
//!
//! Descriptor parsing allocates metadata once. [`ReportDecoder::decode_into`]
//! performs no allocation and can write into a fixed-capacity [`EventBuffer`]
//! or any other caller-provided [`EventSink`].

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Maximum number of application collections accepted in one descriptor.
pub const MAX_APPLICATIONS: usize = 32;
/// Maximum number of distinct input report layouts accepted in one descriptor.
pub const MAX_REPORTS: usize = 255;
/// Maximum number of non-constant input fields accepted in one descriptor.
pub const MAX_INPUT_FIELDS: usize = 256;
/// Maximum total number of input field elements accepted in one descriptor.
pub const MAX_INPUT_ELEMENTS: usize = 1024;
/// Maximum input report size, excluding a report-ID byte, in bits.
pub const MAX_REPORT_BITS: usize = 16 * 1024;
/// Minimum normalized value for an absolute axis.
pub const AXIS_MIN: i32 = -32_767;
/// Maximum normalized value for an absolute axis.
pub const AXIS_MAX: i32 = 32_767;

const MAX_COLLECTION_DEPTH: usize = 32;
const MAX_GLOBAL_STACK_DEPTH: usize = 16;

/// A HID usage, identified by its usage page and usage ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// HID usage page.
    pub page: u16,
    /// Usage ID within `page`.
    pub id: u16,
}

impl Usage {
    /// Creates a usage from a page and ID.
    pub const fn new(page: u16, id: u16) -> Self {
        Self { page, id }
    }
}

/// The semantic kind of a HID application collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationKind {
    /// Generic Desktop Keyboard application.
    Keyboard,
    /// Generic Desktop Mouse application.
    Mouse,
    /// Generic Desktop Joystick application.
    Joystick,
    /// Generic Desktop Game Pad application.
    Gamepad,
    /// An application collection not recognized by this module.
    Other,
}

/// Metadata for one HID application collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationCollection {
    usage: Option<Usage>,
    kind: ApplicationKind,
}

impl ApplicationCollection {
    /// Returns the usage which declared this collection, if present.
    pub const fn usage(&self) -> Option<Usage> {
        self.usage
    }

    /// Returns the collection's recognized semantic kind.
    pub const fn kind(&self) -> ApplicationKind {
        self.kind
    }
}

/// The flags attached to a HID Input main item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldFlags(u16);

impl FieldFlags {
    /// Returns the flags as encoded by the descriptor.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether this is a constant field rather than device data.
    pub const fn is_constant(self) -> bool {
        self.0 & 1 != 0
    }

    /// Returns whether each element has its own usage.
    pub const fn is_variable(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Returns whether values are relative deltas instead of absolute state.
    pub const fn is_relative(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Returns whether out-of-range values represent a null state.
    pub const fn has_null_state(self) -> bool {
        self.0 & (1 << 6) != 0
    }
}

/// One non-constant HID input field within a report.
///
/// A variable field has `count` independently decoded elements. An array field
/// has `count` selectors, such as the six key slots in a boot keyboard report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputField {
    bit_offset: usize,
    bit_size: u8,
    count: usize,
    logical_min: i64,
    logical_max: i64,
    flags: FieldFlags,
    usages: Vec<Usage>,
    usage_min: Option<Usage>,
    usage_max: Option<Usage>,
    default_usage_page: u16,
    application: Option<usize>,
}

impl InputField {
    /// Returns the zero-based bit offset from the beginning of the report data.
    pub const fn bit_offset(&self) -> usize {
        self.bit_offset
    }

    /// Returns the width of each element in bits.
    pub const fn bit_size(&self) -> u8 {
        self.bit_size
    }

    /// Returns the number of elements in this field.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the descriptor's logical minimum.
    pub const fn logical_min(&self) -> i64 {
        self.logical_min
    }

    /// Returns the descriptor's logical maximum.
    pub const fn logical_max(&self) -> i64 {
        self.logical_max
    }

    /// Returns the Input item flags.
    pub const fn flags(&self) -> FieldFlags {
        self.flags
    }

    /// Returns the application collection index associated with this field.
    pub const fn application(&self) -> Option<usize> {
        self.application
    }

    /// Returns the explicitly declared usages.
    pub fn usages(&self) -> &[Usage] {
        &self.usages
    }

    /// Returns the declared usage range, if the field used Usage Minimum and
    /// Usage Maximum local items.
    pub const fn usage_range(&self) -> Option<(Usage, Usage)> {
        match (self.usage_min, self.usage_max) {
            (Some(minimum), Some(maximum)) => Some((minimum, maximum)),
            _ => None,
        }
    }

    /// Resolves the usage assigned to a variable element.
    pub fn usage_for_element(&self, index: usize) -> Option<Usage> {
        if index >= self.count {
            return None;
        }
        if let (Some(minimum), Some(maximum)) = (self.usage_min, self.usage_max) {
            if minimum.page == maximum.page {
                let id = usize::from(minimum.id)
                    .saturating_add(index)
                    .min(usize::from(maximum.id));
                return Some(Usage::new(minimum.page, id as u16));
            }
        }
        self.usages
            .get(index)
            .copied()
            .or_else(|| self.usages.last().copied())
    }

    fn array_usage(&self, raw: u32) -> Option<Usage> {
        let usage = if raw > u32::from(u16::MAX) {
            Usage::new((raw >> 16) as u16, raw as u16)
        } else {
            Usage::new(self.default_usage_page, raw as u16)
        };

        if let (Some(minimum), Some(maximum)) = (self.usage_min, self.usage_max) {
            if usage.page != minimum.page
                || usage.page != maximum.page
                || usage.id < minimum.id
                || usage.id > maximum.id
            {
                return None;
            }
        }
        Some(usage)
    }
}

/// The input layout for one report ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportLayout {
    report_id: u8,
    input_bits: usize,
    fields: Vec<InputField>,
}

impl ReportLayout {
    /// Returns the report ID, or zero when the descriptor has no report IDs.
    pub const fn report_id(&self) -> u8 {
        self.report_id
    }

    /// Returns the number of input bits following any report-ID byte.
    pub const fn input_bits(&self) -> usize {
        self.input_bits
    }

    /// Returns the required number of input bytes following any report-ID byte.
    pub const fn input_bytes(&self) -> usize {
        self.input_bits.div_ceil(8)
    }

    /// Returns all non-constant fields in descriptor order.
    pub fn fields(&self) -> &[InputField] {
        &self.fields
    }
}

/// Parsed input-relevant metadata from a HID report descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceLayout {
    applications: Vec<ApplicationCollection>,
    reports: Vec<ReportLayout>,
    uses_report_ids: bool,
}

impl DeviceLayout {
    /// Parses a HID report descriptor into input report layouts.
    pub fn parse(descriptor: &[u8]) -> Result<Self, DescriptorError> {
        DescriptorParser::new(descriptor).parse()
    }

    /// Returns the application collections in descriptor order.
    pub fn applications(&self) -> &[ApplicationCollection] {
        &self.applications
    }

    /// Returns all input report layouts.
    pub fn reports(&self) -> &[ReportLayout] {
        &self.reports
    }

    /// Returns whether incoming reports begin with a report-ID byte.
    pub const fn uses_report_ids(&self) -> bool {
        self.uses_report_ids
    }

    /// Finds an input report layout by its ID. Use zero for descriptors without
    /// report IDs.
    pub fn report(&self, report_id: u8) -> Option<&ReportLayout> {
        self.reports
            .iter()
            .find(|report| report.report_id == report_id)
    }

    /// Returns the first recognized application kind, if one exists.
    pub fn primary_application_kind(&self) -> Option<ApplicationKind> {
        self.applications
            .iter()
            .map(ApplicationCollection::kind)
            .find(|kind| *kind != ApplicationKind::Other)
    }

    /// Applies the axis-usage workaround needed by DragonRise 0079:0006
    /// controllers, whose descriptor reuses Generic Desktop X for several
    /// distinct absolute axes. Duplicate axes are assigned deterministically to
    /// the next unused conventional joystick axis.
    pub fn apply_dragonrise_0079_0006_quirks(&mut self) {
        const AXES: [u16; 9] = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let application_kinds: Vec<_> = self
            .applications
            .iter()
            .map(ApplicationCollection::kind)
            .collect();

        for report in &mut self.reports {
            let mut used = [false; AXES.len()];
            for field in &mut report.fields {
                let is_controller = field
                    .application
                    .and_then(|index| application_kinds.get(index))
                    .is_some_and(|kind| {
                        matches!(kind, ApplicationKind::Joystick | ApplicationKind::Gamepad)
                    });
                if !is_controller || !field.flags.is_variable() {
                    continue;
                }

                for element in 0..field.count {
                    let Some(usage) = field.usage_for_element(element) else {
                        continue;
                    };
                    if usage.page != 0x01 {
                        continue;
                    }
                    let Some(mut axis_index) = AXES.iter().position(|axis| *axis == usage.id)
                    else {
                        continue;
                    };
                    if used[axis_index] {
                        let Some(unused) = used.iter().position(|in_use| !*in_use) else {
                            continue;
                        };
                        axis_index = unused;
                    }
                    while field.usages.len() <= element {
                        field.usages.push(usage);
                    }
                    field.usages[element] = Usage::new(0x01, AXES[axis_index]);
                    used[axis_index] = true;
                }
            }
        }
    }
}

/// Parses a HID report descriptor into a [`DeviceLayout`].
pub fn parse_report_descriptor(descriptor: &[u8]) -> Result<DeviceLayout, DescriptorError> {
    DeviceLayout::parse(descriptor)
}

/// The category of a report descriptor parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorErrorKind {
    /// An item extends beyond the descriptor bytes.
    TruncatedItem,
    /// A report ID item specified the reserved ID zero.
    InvalidReportId,
    /// Report-ID and unnumbered input fields were mixed.
    MixedReportIds,
    /// A Pop global item had no matching Push item.
    GlobalStackUnderflow,
    /// The global Push stack exceeded its fixed safety limit.
    GlobalStackOverflow,
    /// An End Collection item had no matching Collection item.
    CollectionStackUnderflow,
    /// One or more Collection items were not closed.
    UnclosedCollection,
    /// Collection nesting exceeded its fixed safety limit.
    CollectionDepthExceeded,
    /// The descriptor exceeded an input layout safety limit.
    LayoutLimitExceeded,
    /// A data field had a zero or unsupported element width.
    InvalidReportSize,
    /// Arithmetic while constructing the report layout overflowed.
    ReportSizeOverflow,
}

/// A report descriptor parsing error with its descriptor byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorError {
    /// Offset of the item which caused the error.
    pub offset: usize,
    /// Category of the parsing failure.
    pub kind: DescriptorErrorKind,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HID descriptor error {:?} at byte {}",
            self.kind, self.offset
        )
    }
}

/// A normalized Generic Desktop axis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Axis {
    /// X axis.
    X,
    /// Y axis.
    Y,
    /// Z axis.
    Z,
    /// Rotation around X.
    Rx,
    /// Rotation around Y.
    Ry,
    /// Rotation around Z.
    Rz,
    /// Slider axis.
    Slider,
    /// Dial axis.
    Dial,
    /// Wheel axis.
    Wheel,
}

/// A semantic input state change emitted while decoding a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEvent {
    /// A Keyboard-page key changed state.
    Key {
        /// Application collection index, when known.
        application: Option<usize>,
        /// Keyboard-page usage ID.
        usage: u16,
        /// New key state.
        pressed: bool,
    },
    /// A Button-page control changed state.
    Button {
        /// Application collection index, when known.
        application: Option<usize>,
        /// One-based Button-page usage ID.
        button: u16,
        /// New button state.
        pressed: bool,
    },
    /// A Generic Desktop axis changed or produced a relative delta.
    Axis {
        /// Application collection index, when known.
        application: Option<usize>,
        /// Semantic axis.
        axis: Axis,
        /// Absolute value mapped to [`AXIS_MIN`] through [`AXIS_MAX`], or the
        /// unscaled delta for a relative field.
        value: i32,
        /// Value extracted according to the descriptor's logical signedness.
        raw_value: i64,
        /// Whether `value` is a relative delta.
        relative: bool,
    },
    /// A Generic Desktop Hat Switch changed state.
    HatSwitch {
        /// Application collection index, when known.
        application: Option<usize>,
        /// Zero-based hat position, or `None` for the null position.
        position: Option<u8>,
    },
    /// A variable field without a more specific mapping changed.
    Value {
        /// Application collection index, when known.
        application: Option<usize>,
        /// HID usage assigned to the field element.
        usage: Usage,
        /// Extracted logical value.
        value: i64,
        /// Whether `value` is a relative delta.
        relative: bool,
    },
}

/// Receives decoded events without requiring allocation.
pub trait EventSink {
    /// Adds an event. Returns `false` when the event could not be retained.
    fn push(&mut self, event: InputEvent) -> bool;
}

impl<F> EventSink for F
where
    F: FnMut(InputEvent),
{
    fn push(&mut self, event: InputEvent) -> bool {
        self(event);
        true
    }
}

/// A reusable fixed-capacity event sink suitable for polling paths.
pub struct EventBuffer<const N: usize> {
    events: [Option<InputEvent>; N],
    len: usize,
    dropped: usize,
}

impl<const N: usize> EventBuffer<N> {
    /// Creates an empty event buffer.
    pub const fn new() -> Self {
        Self {
            events: [None; N],
            len: 0,
            dropped: 0,
        }
    }

    /// Removes all retained events and resets the dropped-event count.
    pub fn clear(&mut self) {
        for event in &mut self.events[..self.len] {
            *event = None;
        }
        self.len = 0;
        self.dropped = 0;
    }

    /// Returns the number of retained events.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the buffer is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the compile-time event capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of events rejected since the last [`Self::clear`].
    pub const fn dropped(&self) -> usize {
        self.dropped
    }

    /// Returns a retained event by index.
    pub fn get(&self, index: usize) -> Option<InputEvent> {
        self.events.get(index).copied().flatten()
    }

    /// Iterates over retained events in emission order.
    pub fn iter(&self) -> impl Iterator<Item = InputEvent> + '_ {
        self.events[..self.len].iter().copied().flatten()
    }
}

impl<const N: usize> EventSink for EventBuffer<N> {
    fn push(&mut self, event: InputEvent) -> bool {
        if self.len == N {
            self.dropped += 1;
            return false;
        }
        self.events[self.len] = Some(event);
        self.len += 1;
        true
    }
}

impl<const N: usize> Default for EventBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of one report decode operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeResult {
    /// Number of events accepted by the sink.
    pub emitted: usize,
    /// Number of events rejected by the sink.
    pub dropped: usize,
}

/// A report decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// A numbered-report descriptor received an empty packet.
    MissingReportId,
    /// No input layout exists for the packet's report ID.
    UnknownReportId(u8),
    /// The packet did not contain all bits required by its input layout.
    ReportTooShort {
        /// Required packet bytes, including any report-ID byte.
        expected: usize,
        /// Actual packet bytes.
        actual: usize,
    },
}

/// Stateful, allocation-free-at-poll-time HID input report decoder.
///
/// Construction allocates state for every parsed field element. Subsequent
/// calls to [`Self::decode_into`] do not allocate and emit only state changes;
/// nonzero relative fields are emitted on every report.
pub struct ReportDecoder {
    layout: DeviceLayout,
    states: Vec<Vec<FieldState>>,
}

impl ReportDecoder {
    /// Creates a decoder and allocates its persistent field state.
    pub fn new(layout: DeviceLayout) -> Self {
        let mut states = Vec::with_capacity(layout.reports.len());
        for report in &layout.reports {
            let mut report_states = Vec::with_capacity(report.fields.len());
            for field in &report.fields {
                report_states.push(FieldState {
                    values: alloc::vec![0; field.count],
                    initialized: alloc::vec![false; field.count],
                });
            }
            states.push(report_states);
        }
        Self { layout, states }
    }

    /// Parses a descriptor and creates a stateful decoder.
    pub fn from_descriptor(descriptor: &[u8]) -> Result<Self, DescriptorError> {
        DeviceLayout::parse(descriptor).map(Self::new)
    }

    /// Returns the parsed device layout owned by this decoder.
    pub const fn layout(&self) -> &DeviceLayout {
        &self.layout
    }

    /// Decodes an input report and writes semantic changes to `sink`.
    ///
    /// For descriptors using report IDs, `report[0]` is the report ID and field
    /// bit offsets begin at `report[1]`. Longer packets are accepted.
    pub fn decode_into<S: EventSink>(
        &mut self,
        report: &[u8],
        sink: &mut S,
    ) -> Result<DecodeResult, DecodeError> {
        let (report_id, payload) = if self.layout.uses_report_ids {
            let (&report_id, payload) = report.split_first().ok_or(DecodeError::MissingReportId)?;
            (report_id, payload)
        } else {
            (0, report)
        };

        let report_index = self
            .layout
            .reports
            .iter()
            .position(|layout| layout.report_id == report_id)
            .ok_or(DecodeError::UnknownReportId(report_id))?;
        let required = self.layout.reports[report_index].input_bytes();
        if payload.len() < required {
            return Err(DecodeError::ReportTooShort {
                expected: required + usize::from(self.layout.uses_report_ids),
                actual: report.len(),
            });
        }

        let fields = &self.layout.reports[report_index].fields;
        let states = &mut self.states[report_index];
        let mut result = DecodeResult {
            emitted: 0,
            dropped: 0,
        };
        for (field, state) in fields.iter().zip(states) {
            decode_field(field, state, payload, sink, &mut result);
        }
        Ok(result)
    }

    /// Returns the last raw value for a field element.
    pub fn field_value(
        &self,
        report_id: u8,
        field_index: usize,
        element_index: usize,
    ) -> Option<i64> {
        let report_index = self
            .layout
            .reports
            .iter()
            .position(|report| report.report_id == report_id)?;
        self.states
            .get(report_index)?
            .get(field_index)?
            .values
            .get(element_index)
            .copied()
    }

    /// Returns whether a Keyboard- or Button-page usage is currently active.
    pub fn is_active(&self, usage: Usage) -> bool {
        if usage.page != 0x07 && usage.page != 0x09 {
            return false;
        }
        for (report, report_states) in self.layout.reports.iter().zip(&self.states) {
            for (field, state) in report.fields.iter().zip(report_states) {
                if field.flags.is_variable() {
                    for (index, &value) in state.values.iter().enumerate() {
                        if field.usage_for_element(index) == Some(usage) && value != 0 {
                            return true;
                        }
                    }
                } else if state
                    .values
                    .iter()
                    .any(|&value| value > 0 && field.array_usage(value as u32) == Some(usage))
                {
                    return true;
                }
            }
        }
        false
    }
}

struct FieldState {
    values: Vec<i64>,
    initialized: Vec<bool>,
}

fn decode_field<S: EventSink>(
    field: &InputField,
    state: &mut FieldState,
    payload: &[u8],
    sink: &mut S,
    result: &mut DecodeResult,
) {
    if field.flags.is_variable() {
        decode_variable_field(field, state, payload, sink, result);
    } else {
        decode_array_field(field, state, payload, sink, result);
    }
}

fn decode_variable_field<S: EventSink>(
    field: &InputField,
    state: &mut FieldState,
    payload: &[u8],
    sink: &mut S,
    result: &mut DecodeResult,
) {
    for index in 0..field.count {
        let offset = field.bit_offset + index * usize::from(field.bit_size);
        let raw = read_bits(payload, offset, field.bit_size);
        let value = logical_value(raw, field.bit_size, field.logical_min);
        let old_value = state.values[index];
        let was_initialized = state.initialized[index];
        state.values[index] = value;
        state.initialized[index] = true;

        let Some(usage) = field.usage_for_element(index) else {
            continue;
        };
        let should_emit = if field.flags.is_relative() {
            value != 0
        } else {
            value != old_value || (!was_initialized && usage.page == 0x01)
        };
        if !should_emit {
            continue;
        }
        let event = event_for_value(field, usage, value);
        emit(sink, result, event);
    }
}

fn decode_array_field<S: EventSink>(
    field: &InputField,
    state: &mut FieldState,
    payload: &[u8],
    sink: &mut S,
    result: &mut DecodeResult,
) {
    if field.default_usage_page == 0x07 {
        if (0..field.count)
            .map(|index| read_array_value(field, payload, index))
            .any(is_keyboard_error_usage)
        {
            return;
        }

        for (index, &old) in state.values.iter().enumerate() {
            if old == 0 || state.values[..index].contains(&old) {
                continue;
            }
            if !report_array_contains(field, payload, old) {
                if let Some(usage) = field.array_usage(old as u32) {
                    emit(
                        sink,
                        result,
                        InputEvent::Key {
                            application: field.application,
                            usage: usage.id,
                            pressed: false,
                        },
                    );
                }
            }
        }

        for index in 0..field.count {
            let value = read_array_value(field, payload, index);
            let already_in_report =
                (0..index).any(|earlier| read_array_value(field, payload, earlier) == value);
            if value == 0 || already_in_report || state.values.contains(&value) {
                continue;
            }
            if let Some(usage) = field.array_usage(value as u32) {
                emit(
                    sink,
                    result,
                    InputEvent::Key {
                        application: field.application,
                        usage: usage.id,
                        pressed: true,
                    },
                );
            }
        }
    }

    for index in 0..field.count {
        state.values[index] = read_array_value(field, payload, index);
    }
}

fn report_array_contains(field: &InputField, payload: &[u8], wanted: i64) -> bool {
    (0..field.count).any(|index| read_array_value(field, payload, index) == wanted)
}

fn read_array_value(field: &InputField, payload: &[u8], index: usize) -> i64 {
    let offset = field.bit_offset + index * usize::from(field.bit_size);
    let raw = read_bits(payload, offset, field.bit_size);
    logical_value(raw, field.bit_size, field.logical_min)
}

fn is_keyboard_error_usage(value: i64) -> bool {
    (1..=3).contains(&value)
}

fn event_for_value(field: &InputField, usage: Usage, value: i64) -> InputEvent {
    if usage.page == 0x07 {
        return InputEvent::Key {
            application: field.application,
            usage: usage.id,
            pressed: value != 0,
        };
    }
    if usage.page == 0x09 {
        return InputEvent::Button {
            application: field.application,
            button: usage.id,
            pressed: value != 0,
        };
    }
    if usage.page == 0x01 && usage.id == 0x39 {
        return InputEvent::HatSwitch {
            application: field.application,
            position: hat_position(field, value),
        };
    }
    if usage.page == 0x01 {
        if let Some(axis) = axis_for_usage(usage.id) {
            let relative = field.flags.is_relative();
            return InputEvent::Axis {
                application: field.application,
                axis,
                value: if relative {
                    clamp_i64_to_i32(value)
                } else {
                    normalize_axis(value, field.logical_min, field.logical_max)
                },
                raw_value: value,
                relative,
            };
        }
    }

    InputEvent::Value {
        application: field.application,
        usage,
        value,
        relative: field.flags.is_relative(),
    }
}

fn emit<S: EventSink>(sink: &mut S, result: &mut DecodeResult, event: InputEvent) {
    if sink.push(event) {
        result.emitted += 1;
    } else {
        result.dropped += 1;
    }
}

fn axis_for_usage(usage: u16) -> Option<Axis> {
    match usage {
        0x30 => Some(Axis::X),
        0x31 => Some(Axis::Y),
        0x32 => Some(Axis::Z),
        0x33 => Some(Axis::Rx),
        0x34 => Some(Axis::Ry),
        0x35 => Some(Axis::Rz),
        0x36 => Some(Axis::Slider),
        0x37 => Some(Axis::Dial),
        0x38 => Some(Axis::Wheel),
        _ => None,
    }
}

fn hat_position(field: &InputField, value: i64) -> Option<u8> {
    if value < field.logical_min || value > field.logical_max {
        return None;
    }
    let position = value - field.logical_min;
    u8::try_from(position).ok().filter(|position| *position < 8)
}

fn normalize_axis(value: i64, minimum: i64, maximum: i64) -> i32 {
    if maximum <= minimum {
        return 0;
    }
    let value = value.clamp(minimum, maximum);
    let span = maximum - minimum;
    let scaled = (value - minimum) * i64::from(AXIS_MAX - AXIS_MIN);
    (i64::from(AXIS_MIN) + (scaled + span / 2) / span) as i32
}

fn clamp_i64_to_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

fn read_bits(bytes: &[u8], bit_offset: usize, bit_size: u8) -> u32 {
    let mut value = 0u32;
    for bit in 0..usize::from(bit_size) {
        let source = bit_offset + bit;
        let source_bit = (bytes[source / 8] >> (source % 8)) & 1;
        value |= u32::from(source_bit) << bit;
    }
    value
}

fn logical_value(raw: u32, bit_size: u8, logical_minimum: i64) -> i64 {
    if logical_minimum >= 0 {
        return i64::from(raw);
    }
    if bit_size == 32 {
        return i64::from(raw as i32);
    }
    let shift = 32 - u32::from(bit_size);
    i64::from(((raw << shift) as i32) >> shift)
}

#[derive(Clone, Copy)]
struct ItemValue {
    raw: u32,
    size: u8,
}

impl ItemValue {
    const ZERO: Self = Self { raw: 0, size: 0 };

    fn signed(self) -> i64 {
        match self.size {
            1 => i64::from(self.raw as u8 as i8),
            2 => i64::from(self.raw as u16 as i16),
            4 => i64::from(self.raw as i32),
            _ => 0,
        }
    }

    fn unsigned(self) -> i64 {
        i64::from(self.raw)
    }
}

#[derive(Clone, Copy)]
struct GlobalState {
    usage_page: u16,
    logical_min: ItemValue,
    logical_max: ItemValue,
    report_size: u32,
    report_count: u32,
    report_id: u8,
}

impl GlobalState {
    const fn new() -> Self {
        Self {
            usage_page: 0,
            logical_min: ItemValue::ZERO,
            logical_max: ItemValue::ZERO,
            report_size: 0,
            report_count: 0,
            report_id: 0,
        }
    }
}

struct LocalState {
    usages: Vec<Usage>,
    usage_min: Option<Usage>,
    usage_max: Option<Usage>,
}

impl LocalState {
    fn new() -> Self {
        Self {
            usages: Vec::new(),
            usage_min: None,
            usage_max: None,
        }
    }

    fn clear(&mut self) {
        self.usages.clear();
        self.usage_min = None;
        self.usage_max = None;
    }

    fn first_usage(&self) -> Option<Usage> {
        self.usages.first().copied().or(self.usage_min)
    }
}

struct CollectionFrame {
    application: Option<usize>,
}

struct DescriptorParser<'a> {
    descriptor: &'a [u8],
    cursor: usize,
    item_offset: usize,
    global: GlobalState,
    global_stack: Vec<GlobalState>,
    local: LocalState,
    collections: Vec<CollectionFrame>,
    applications: Vec<ApplicationCollection>,
    reports: Vec<ReportLayout>,
    input_elements: usize,
    uses_report_ids: bool,
}

impl<'a> DescriptorParser<'a> {
    fn new(descriptor: &'a [u8]) -> Self {
        Self {
            descriptor,
            cursor: 0,
            item_offset: 0,
            global: GlobalState::new(),
            global_stack: Vec::new(),
            local: LocalState::new(),
            collections: Vec::new(),
            applications: Vec::new(),
            reports: Vec::new(),
            input_elements: 0,
            uses_report_ids: false,
        }
    }

    fn parse(mut self) -> Result<DeviceLayout, DescriptorError> {
        while self.cursor < self.descriptor.len() {
            self.item_offset = self.cursor;
            let prefix = self.take_byte()?;
            if prefix == 0xfe {
                let length = usize::from(self.take_byte()?);
                let _long_tag = self.take_byte()?;
                self.take_bytes(length)?;
                continue;
            }

            let size = match prefix & 0x03 {
                3 => 4,
                size => usize::from(size),
            };
            let item_type = (prefix >> 2) & 0x03;
            let tag = prefix >> 4;
            let data = self.take_bytes(size)?;
            let value = ItemValue {
                raw: unsigned_item(data),
                size: size as u8,
            };

            match item_type {
                0 => self.main_item(tag, value)?,
                1 => self.global_item(tag, value)?,
                2 => self.local_item(tag, value),
                _ => {}
            }
        }

        if !self.collections.is_empty() {
            return Err(self.error(DescriptorErrorKind::UnclosedCollection));
        }
        let has_unnumbered_data = self
            .reports
            .iter()
            .any(|report| report.report_id == 0 && report.input_bits != 0);
        if self.uses_report_ids && has_unnumbered_data {
            return Err(self.error(DescriptorErrorKind::MixedReportIds));
        }
        self.reports.retain(|report| report.input_bits != 0);

        Ok(DeviceLayout {
            applications: self.applications,
            reports: self.reports,
            uses_report_ids: self.uses_report_ids,
        })
    }

    fn main_item(&mut self, tag: u8, value: ItemValue) -> Result<(), DescriptorError> {
        match tag {
            8 => self.input_item(value.raw as u16)?,
            10 => self.begin_collection(value.raw as u8)?,
            12 => self.end_collection()?,
            _ => {}
        }
        self.local.clear();
        Ok(())
    }

    fn global_item(&mut self, tag: u8, value: ItemValue) -> Result<(), DescriptorError> {
        match tag {
            0 => self.global.usage_page = value.raw as u16,
            1 => self.global.logical_min = value,
            2 => self.global.logical_max = value,
            7 => self.global.report_size = value.raw,
            8 => {
                if value.raw == 0 || value.raw > u32::from(u8::MAX) {
                    return Err(self.error(DescriptorErrorKind::InvalidReportId));
                }
                self.global.report_id = value.raw as u8;
                self.uses_report_ids = true;
            }
            9 => self.global.report_count = value.raw,
            10 => {
                if self.global_stack.len() == MAX_GLOBAL_STACK_DEPTH {
                    return Err(self.error(DescriptorErrorKind::GlobalStackOverflow));
                }
                self.global_stack.push(self.global);
            }
            11 => {
                self.global = self
                    .global_stack
                    .pop()
                    .ok_or_else(|| self.error(DescriptorErrorKind::GlobalStackUnderflow))?;
            }
            _ => {}
        }
        Ok(())
    }

    fn local_item(&mut self, tag: u8, value: ItemValue) {
        match tag {
            0 => {
                let page = if value.size == 4 {
                    (value.raw >> 16) as u16
                } else {
                    self.global.usage_page
                };
                self.local.usages.push(Usage::new(page, value.raw as u16));
            }
            1 => self.local.usage_min = Some(self.decode_usage(value)),
            2 => self.local.usage_max = Some(self.decode_usage(value)),
            _ => {}
        }
    }

    fn decode_usage(&self, value: ItemValue) -> Usage {
        if value.size == 4 {
            Usage::new((value.raw >> 16) as u16, value.raw as u16)
        } else {
            Usage::new(self.global.usage_page, value.raw as u16)
        }
    }

    fn input_item(&mut self, flags: u16) -> Result<(), DescriptorError> {
        let bit_size = usize::try_from(self.global.report_size)
            .map_err(|_| self.error(DescriptorErrorKind::InvalidReportSize))?;
        let count = usize::try_from(self.global.report_count)
            .map_err(|_| self.error(DescriptorErrorKind::LayoutLimitExceeded))?;
        if bit_size == 0 || bit_size > 32 {
            return Err(self.error(DescriptorErrorKind::InvalidReportSize));
        }
        let field_bits = bit_size
            .checked_mul(count)
            .ok_or_else(|| self.error(DescriptorErrorKind::ReportSizeOverflow))?;
        let report_index = self.report_index(self.global.report_id)?;
        let bit_offset = self.reports[report_index].input_bits;
        let input_bits = bit_offset
            .checked_add(field_bits)
            .ok_or_else(|| self.error(DescriptorErrorKind::ReportSizeOverflow))?;
        if input_bits > MAX_REPORT_BITS {
            return Err(self.error(DescriptorErrorKind::LayoutLimitExceeded));
        }
        self.reports[report_index].input_bits = input_bits;

        let field_flags = FieldFlags(flags);
        if field_flags.is_constant() || count == 0 {
            return Ok(());
        }
        let total_fields: usize = self.reports.iter().map(|report| report.fields.len()).sum();
        if total_fields == MAX_INPUT_FIELDS
            || self.input_elements.saturating_add(count) > MAX_INPUT_ELEMENTS
        {
            return Err(self.error(DescriptorErrorKind::LayoutLimitExceeded));
        }
        self.input_elements += count;

        let logical_min = self.global.logical_min.signed();
        let logical_max = if logical_min < 0 {
            self.global.logical_max.signed()
        } else {
            self.global.logical_max.unsigned()
        };
        let application = self
            .collections
            .last()
            .and_then(|collection| collection.application);
        self.reports[report_index].fields.push(InputField {
            bit_offset,
            bit_size: bit_size as u8,
            count,
            logical_min,
            logical_max,
            flags: field_flags,
            usages: self.local.usages.clone(),
            usage_min: self.local.usage_min,
            usage_max: self.local.usage_max,
            default_usage_page: self.global.usage_page,
            application,
        });
        Ok(())
    }

    fn report_index(&mut self, report_id: u8) -> Result<usize, DescriptorError> {
        if let Some(index) = self
            .reports
            .iter()
            .position(|report| report.report_id == report_id)
        {
            return Ok(index);
        }
        if self.reports.len() == MAX_REPORTS {
            return Err(self.error(DescriptorErrorKind::LayoutLimitExceeded));
        }
        self.reports.push(ReportLayout {
            report_id,
            input_bits: 0,
            fields: Vec::new(),
        });
        Ok(self.reports.len() - 1)
    }

    fn begin_collection(&mut self, collection_type: u8) -> Result<(), DescriptorError> {
        if self.collections.len() == MAX_COLLECTION_DEPTH {
            return Err(self.error(DescriptorErrorKind::CollectionDepthExceeded));
        }
        let inherited_application = self
            .collections
            .last()
            .and_then(|collection| collection.application);
        let application = if collection_type == 1 {
            if self.applications.len() == MAX_APPLICATIONS {
                return Err(self.error(DescriptorErrorKind::LayoutLimitExceeded));
            }
            let usage = self.local.first_usage();
            let index = self.applications.len();
            self.applications.push(ApplicationCollection {
                usage,
                kind: classify_application(usage),
            });
            Some(index)
        } else {
            inherited_application
        };
        self.collections.push(CollectionFrame { application });
        Ok(())
    }

    fn end_collection(&mut self) -> Result<(), DescriptorError> {
        self.collections
            .pop()
            .ok_or_else(|| self.error(DescriptorErrorKind::CollectionStackUnderflow))?;
        Ok(())
    }

    fn take_byte(&mut self) -> Result<u8, DescriptorError> {
        let byte = self
            .descriptor
            .get(self.cursor)
            .copied()
            .ok_or_else(|| self.error(DescriptorErrorKind::TruncatedItem))?;
        self.cursor += 1;
        Ok(byte)
    }

    fn take_bytes(&mut self, count: usize) -> Result<&'a [u8], DescriptorError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| self.error(DescriptorErrorKind::TruncatedItem))?;
        let bytes = self
            .descriptor
            .get(self.cursor..end)
            .ok_or_else(|| self.error(DescriptorErrorKind::TruncatedItem))?;
        self.cursor = end;
        Ok(bytes)
    }

    const fn error(&self, kind: DescriptorErrorKind) -> DescriptorError {
        DescriptorError {
            offset: self.item_offset,
            kind,
        }
    }
}

fn classify_application(usage: Option<Usage>) -> ApplicationKind {
    match usage {
        Some(Usage {
            page: 0x01,
            id: 0x02,
        }) => ApplicationKind::Mouse,
        Some(Usage {
            page: 0x01,
            id: 0x04,
        }) => ApplicationKind::Joystick,
        Some(Usage {
            page: 0x01,
            id: 0x05,
        }) => ApplicationKind::Gamepad,
        Some(Usage {
            page: 0x01,
            id: 0x06,
        }) => ApplicationKind::Keyboard,
        _ => ApplicationKind::Other,
    }
}

fn unsigned_item(bytes: &[u8]) -> u32 {
    bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u32::from(*byte) << (index * 8))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const BOOT_KEYBOARD_DESCRIPTOR: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x06, // Usage (Keyboard)
        0xa1, 0x01, // Collection (Application)
        0x05, 0x07, // Usage Page (Keyboard)
        0x19, 0xe0, // Usage Minimum (Left Control)
        0x29, 0xe7, // Usage Maximum (Right GUI)
        0x15, 0x00, // Logical Minimum (0)
        0x25, 0x01, // Logical Maximum (1)
        0x75, 0x01, // Report Size (1)
        0x95, 0x08, // Report Count (8)
        0x81, 0x02, // Input (Data, Variable, Absolute)
        0x95, 0x01, // Report Count (1)
        0x75, 0x08, // Report Size (8)
        0x81, 0x01, // Input (Constant)
        0x95, 0x06, // Report Count (6)
        0x75, 0x08, // Report Size (8)
        0x15, 0x00, // Logical Minimum (0)
        0x25, 0x65, // Logical Maximum (101)
        0x05, 0x07, // Usage Page (Keyboard)
        0x19, 0x00, // Usage Minimum (Reserved)
        0x29, 0x65, // Usage Maximum (Keyboard Application)
        0x81, 0x00, // Input (Data, Array, Absolute)
        0xc0, // End Collection
    ];

    const BOOT_MOUSE_DESCRIPTOR: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x02, // Usage (Mouse)
        0xa1, 0x01, // Collection (Application)
        0x09, 0x01, // Usage (Pointer)
        0xa1, 0x00, // Collection (Physical)
        0x05, 0x09, // Usage Page (Button)
        0x19, 0x01, // Usage Minimum (1)
        0x29, 0x03, // Usage Maximum (3)
        0x15, 0x00, // Logical Minimum (0)
        0x25, 0x01, // Logical Maximum (1)
        0x95, 0x03, // Report Count (3)
        0x75, 0x01, // Report Size (1)
        0x81, 0x02, // Input (Data, Variable, Absolute)
        0x95, 0x01, // Report Count (1)
        0x75, 0x05, // Report Size (5)
        0x81, 0x01, // Input (Constant)
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x30, // Usage (X)
        0x09, 0x31, // Usage (Y)
        0x09, 0x38, // Usage (Wheel)
        0x15, 0x81, // Logical Minimum (-127)
        0x25, 0x7f, // Logical Maximum (127)
        0x75, 0x08, // Report Size (8)
        0x95, 0x03, // Report Count (3)
        0x81, 0x06, // Input (Data, Variable, Relative)
        0xc0, // End Collection
        0xc0, // End Collection
    ];

    const DRAGONRISE_STYLE_DESCRIPTOR: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x04, // Usage (Joystick)
        0xa1, 0x01, // Collection (Application)
        0x15, 0x00, // Logical Minimum (0)
        0x26, 0xff, 0x00, // Logical Maximum (255)
        0x75, 0x08, // Report Size (8)
        0x95, 0x05, // Report Count (5)
        0x09, 0x30, // Usage (X)
        0x09, 0x31, // Usage (Y)
        0x09, 0x32, // Usage (Z)
        0x09, 0x35, // Usage (Rz)
        0x09, 0x36, // Usage (Slider)
        0x81, 0x02, // Input (Data, Variable, Absolute)
        0x15, 0x00, // Logical Minimum (0)
        0x25, 0x07, // Logical Maximum (7)
        0x35, 0x00, // Physical Minimum (0)
        0x46, 0x3b, 0x01, // Physical Maximum (315)
        0x65, 0x14, // Unit (Degrees)
        0x75, 0x04, // Report Size (4)
        0x95, 0x01, // Report Count (1)
        0x09, 0x39, // Usage (Hat Switch)
        0x81, 0x42, // Input (Data, Variable, Absolute, Null)
        0x65, 0x00, // Unit (None)
        0x05, 0x09, // Usage Page (Button)
        0x19, 0x01, // Usage Minimum (1)
        0x29, 0x0c, // Usage Maximum (12)
        0x15, 0x00, // Logical Minimum (0)
        0x25, 0x01, // Logical Maximum (1)
        0x75, 0x01, // Report Size (1)
        0x95, 0x0c, // Report Count (12)
        0x81, 0x02, // Input (Data, Variable, Absolute)
        0xc0, // End Collection
    ];

    #[test]
    fn parses_and_decodes_boot_keyboard_arrays() {
        let layout = DeviceLayout::parse(BOOT_KEYBOARD_DESCRIPTOR).unwrap();
        assert_eq!(
            layout.primary_application_kind(),
            Some(ApplicationKind::Keyboard)
        );
        assert!(!layout.uses_report_ids());
        assert_eq!(layout.report(0).unwrap().input_bytes(), 8);
        assert_eq!(layout.report(0).unwrap().fields().len(), 2);
        assert_eq!(layout.report(0).unwrap().fields()[1].bit_offset(), 16);

        let mut decoder = ReportDecoder::new(layout);
        let mut events = EventBuffer::<8>::new();
        assert_eq!(
            decoder
                .decode_into(&[0x02, 0, 0x04, 0, 0, 0, 0, 0], &mut events)
                .unwrap(),
            DecodeResult {
                emitted: 2,
                dropped: 0
            }
        );
        assert_eq!(
            events.iter().collect::<Vec<_>>(),
            vec![
                InputEvent::Key {
                    application: Some(0),
                    usage: 0xe1,
                    pressed: true,
                },
                InputEvent::Key {
                    application: Some(0),
                    usage: 0x04,
                    pressed: true,
                },
            ]
        );
        assert!(decoder.is_active(Usage::new(0x07, 0x04)));

        events.clear();
        decoder
            .decode_into(&[0, 0, 0x05, 0, 0, 0, 0, 0], &mut events)
            .unwrap();
        assert_eq!(
            events.iter().collect::<Vec<_>>(),
            vec![
                InputEvent::Key {
                    application: Some(0),
                    usage: 0xe1,
                    pressed: false,
                },
                InputEvent::Key {
                    application: Some(0),
                    usage: 0x04,
                    pressed: false,
                },
                InputEvent::Key {
                    application: Some(0),
                    usage: 0x05,
                    pressed: true,
                },
            ]
        );

        events.clear();
        decoder
            .decode_into(&[0, 0, 1, 1, 1, 1, 1, 1], &mut events)
            .unwrap();
        assert!(events.is_empty());
        assert!(decoder.is_active(Usage::new(0x07, 0x05)));
    }

    #[test]
    fn decodes_boot_mouse_buttons_and_signed_relative_axes() {
        let layout = DeviceLayout::parse(BOOT_MOUSE_DESCRIPTOR).unwrap();
        assert_eq!(
            layout.primary_application_kind(),
            Some(ApplicationKind::Mouse)
        );
        assert_eq!(layout.report(0).unwrap().input_bytes(), 4);

        let mut decoder = ReportDecoder::new(layout);
        let mut events = EventBuffer::<8>::new();
        decoder
            .decode_into(&[0b0000_0101, 5, 0xfd, 1], &mut events)
            .unwrap();
        assert_eq!(
            events.iter().collect::<Vec<_>>(),
            vec![
                InputEvent::Button {
                    application: Some(0),
                    button: 1,
                    pressed: true,
                },
                InputEvent::Button {
                    application: Some(0),
                    button: 3,
                    pressed: true,
                },
                InputEvent::Axis {
                    application: Some(0),
                    axis: Axis::X,
                    value: 5,
                    raw_value: 5,
                    relative: true,
                },
                InputEvent::Axis {
                    application: Some(0),
                    axis: Axis::Y,
                    value: -3,
                    raw_value: -3,
                    relative: true,
                },
                InputEvent::Axis {
                    application: Some(0),
                    axis: Axis::Wheel,
                    value: 1,
                    raw_value: 1,
                    relative: true,
                },
            ]
        );

        events.clear();
        decoder.decode_into(&[0, 0, 0, 0], &mut events).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events.get(0),
            Some(InputEvent::Button {
                application: Some(0),
                button: 1,
                pressed: false,
            })
        );
        assert_eq!(
            events.get(1),
            Some(InputEvent::Button {
                application: Some(0),
                button: 3,
                pressed: false,
            })
        );
    }

    #[test]
    fn decodes_dragonrise_style_axes_hat_and_packed_buttons() {
        let layout = DeviceLayout::parse(DRAGONRISE_STYLE_DESCRIPTOR).unwrap();
        assert_eq!(
            layout.primary_application_kind(),
            Some(ApplicationKind::Joystick)
        );
        let report = layout.report(0).unwrap();
        assert_eq!(report.input_bits(), 56);
        assert_eq!(report.input_bytes(), 7);
        assert_eq!(report.fields()[1].bit_offset(), 40);
        assert_eq!(report.fields()[2].bit_offset(), 44);
        assert_eq!(
            report.fields()[2].usage_for_element(11),
            Some(Usage::new(9, 12))
        );

        let mut decoder = ReportDecoder::new(layout);
        let mut events = EventBuffer::<16>::new();
        decoder
            .decode_into(&[0, 127, 255, 64, 192, 0x12, 0x80], &mut events)
            .unwrap();
        let decoded = events.iter().collect::<Vec<_>>();
        assert!(decoded.contains(&InputEvent::Axis {
            application: Some(0),
            axis: Axis::Y,
            value: -128,
            raw_value: 127,
            relative: false,
        }));
        assert!(decoded.contains(&InputEvent::Axis {
            application: Some(0),
            axis: Axis::Z,
            value: AXIS_MAX,
            raw_value: 255,
            relative: false,
        }));
        assert!(decoded.contains(&InputEvent::HatSwitch {
            application: Some(0),
            position: Some(2),
        }));
        assert!(decoded.contains(&InputEvent::Button {
            application: Some(0),
            button: 1,
            pressed: true,
        }));
        assert!(decoded.contains(&InputEvent::Button {
            application: Some(0),
            button: 12,
            pressed: true,
        }));
        assert!(decoder.is_active(Usage::new(0x09, 12)));

        events.clear();
        decoder
            .decode_into(&[0, 127, 255, 64, 192, 0x0f, 0], &mut events)
            .unwrap();
        assert!(events.iter().any(|event| event
            == InputEvent::HatSwitch {
                application: Some(0),
                position: None,
            }));
        assert!(!decoder.is_active(Usage::new(0x09, 12)));
    }

    #[test]
    fn fixes_duplicate_axes_on_dragonrise_0079_0006() {
        let descriptor = [
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x04, // Usage (Joystick)
            0xa1, 0x01, // Collection (Application)
            0x15, 0x00, // Logical Minimum (0)
            0x26, 0xff, 0x00, // Logical Maximum (255)
            0x75, 0x08, // Report Size (8)
            0x95, 0x05, // Report Count (5)
            0x09, 0x30, // Usage (X)
            0x09, 0x30, // Usage (X)
            0x09, 0x30, // Usage (X)
            0x09, 0x30, // Usage (X)
            0x09, 0x31, // Usage (Y)
            0x81, 0x02, // Input (Data, Variable, Absolute)
            0xc0,
        ];
        let mut layout = DeviceLayout::parse(&descriptor).unwrap();
        layout.apply_dragonrise_0079_0006_quirks();
        let field = &layout.report(0).unwrap().fields()[0];
        assert_eq!(
            (0..5)
                .map(|index| field.usage_for_element(index).unwrap().id)
                .collect::<Vec<_>>(),
            &[0x30, 0x31, 0x32, 0x33, 0x34]
        );

        let mut decoder = ReportDecoder::new(layout);
        let mut events = EventBuffer::<8>::new();
        decoder.decode_into(&[0; 5], &mut events).unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn handles_report_ids_and_non_byte_aligned_signed_fields() {
        let descriptor = [
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x05, // Usage (Game Pad)
            0xa1, 0x01, // Collection (Application)
            0x85, 0x07, // Report ID (7)
            0x75, 0x04, // Report Size (4)
            0x95, 0x01, // Report Count (1)
            0x81, 0x01, // Input (Constant)
            0x16, 0x00, 0xf8, // Logical Minimum (-2048)
            0x26, 0xff, 0x07, // Logical Maximum (2047)
            0x09, 0x30, // Usage (X)
            0x75, 0x0c, // Report Size (12)
            0x95, 0x01, // Report Count (1)
            0x81, 0x02, // Input (Data, Variable, Absolute)
            0xc0,
        ];
        let layout = DeviceLayout::parse(&descriptor).unwrap();
        assert!(layout.uses_report_ids());
        assert_eq!(layout.report(7).unwrap().fields()[0].bit_offset(), 4);
        assert_eq!(layout.report(7).unwrap().input_bytes(), 2);

        let mut decoder = ReportDecoder::new(layout);
        let mut events = EventBuffer::<2>::new();
        decoder.decode_into(&[7, 0x00, 0x80], &mut events).unwrap();
        assert_eq!(
            events.get(0),
            Some(InputEvent::Axis {
                application: Some(0),
                axis: Axis::X,
                value: AXIS_MIN,
                raw_value: -2048,
                relative: false,
            })
        );
        assert_eq!(
            decoder.decode_into(&[8, 0, 0], &mut events),
            Err(DecodeError::UnknownReportId(8))
        );
        assert_eq!(
            decoder.decode_into(&[7, 0], &mut events),
            Err(DecodeError::ReportTooShort {
                expected: 3,
                actual: 2,
            })
        );
    }

    #[test]
    fn reports_event_buffer_overflow_without_losing_decoder_state() {
        let mut decoder = ReportDecoder::from_descriptor(BOOT_MOUSE_DESCRIPTOR).unwrap();
        let mut events = EventBuffer::<1>::new();
        let result = decoder
            .decode_into(&[0b0000_0101, 1, 1, 1], &mut events)
            .unwrap();
        assert_eq!(result.emitted, 1);
        assert_eq!(result.dropped, 4);
        assert_eq!(events.dropped(), 4);
        assert!(decoder.is_active(Usage::new(0x09, 1)));
        assert!(decoder.is_active(Usage::new(0x09, 3)));
    }

    #[test]
    fn rejects_truncated_and_mixed_report_id_descriptors() {
        assert_eq!(
            DeviceLayout::parse(&[0x05]).unwrap_err().kind,
            DescriptorErrorKind::TruncatedItem
        );

        let mixed = [
            0x05, 0x01, 0x09, 0x04, 0xa1, 0x01, 0x75, 0x08, 0x95, 0x01, 0x09, 0x30, 0x81, 0x02,
            0x85, 0x01, 0x09, 0x31, 0x81, 0x02, 0xc0,
        ];
        assert_eq!(
            DeviceLayout::parse(&mixed).unwrap_err().kind,
            DescriptorErrorKind::MixedReportIds
        );
    }
}
