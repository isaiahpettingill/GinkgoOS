//! Structured protocol between the userspace desktop service and kernel broker.
//!
//! Every packet carries an identity and version so an endpoint cannot silently
//! interpret a packet from another protocol. Channel handles are out-of-band;
//! attachment indices in the payload are valid only after [`RuntimePacket::validate`]
//! has checked the actual attachment count supplied by the transport.

use alloc::vec::Vec;

use ginkgo_window::{
    BufferId, ConfigurationError, Generation, KeyboardEvent, Point, PointerEventKind, Rect,
    RequestId, ServerErrorCode, SurfaceConfiguration, WindowId, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::{ClientId, WindowPlacement};

/// Stable protocol ID for desktop-service/kernel-broker traffic (`GKDR`).
pub const RUNTIME_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GKDR");
/// Current version of the desktop runtime protocol.
///
/// Existing variants and fields are append-only within a version.
pub const RUNTIME_PROTOCOL_VERSION: u16 = 1;
/// Maximum encoded packet size, matching the channel transport limit.
pub const MAX_RUNTIME_PACKET_BYTES: usize = 16 * 1024;
/// Maximum number of placements accepted in one replacement set.
pub const MAX_RUNTIME_PLACEMENTS: usize = 128;
/// Maximum number of damage rectangles accepted for one presentation.
pub const MAX_RUNTIME_DAMAGE_RECTS: usize = 256;

/// Endpoint that originated a runtime packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSender {
    DesktopService,
    KernelBroker,
}

/// Zero-based index into the handles attached to a channel message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AttachmentIndex(u8);

impl AttachmentIndex {
    pub const fn new(index: u8) -> Self {
        Self(index)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Signed output rectangle used by compositor placement commands.
///
/// This is an explicit wire type because scrolling placements require `i64`
/// origins while `ginkgo-window::Rect` deliberately uses `i32` origins.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PlacementRect {
    pub x: i64,
    pub y: i64,
    pub width: u32,
    pub height: u32,
}

impl PlacementRect {
    pub const fn new(x: i64, y: i64, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    fn checked_right(self) -> Option<i64> {
        self.x.checked_add(i64::from(self.width))
    }

    fn checked_bottom(self) -> Option<i64> {
        self.y.checked_add(i64::from(self.height))
    }

    fn contains(self, child: Self) -> bool {
        let (Some(right), Some(bottom), Some(child_right), Some(child_bottom)) = (
            self.checked_right(),
            self.checked_bottom(),
            child.checked_right(),
            child.checked_bottom(),
        ) else {
            return false;
        };
        child.x >= self.x && child.y >= self.y && child_right <= right && child_bottom <= bottom
    }
}

impl From<ginkgo_scroll_layout::Rect> for PlacementRect {
    fn from(rect: ginkgo_scroll_layout::Rect) -> Self {
        Self::new(rect.x, rect.y, rect.width, rect.height)
    }
}

/// Complete compositor placement for one window.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimePlacement {
    pub window_id: WindowId,
    pub outer: PlacementRect,
    pub client: PlacementRect,
    pub visible: Option<PlacementRect>,
    pub focused: bool,
    pub decorated: bool,
}

impl From<WindowPlacement> for RuntimePlacement {
    fn from(placement: WindowPlacement) -> Self {
        Self {
            window_id: placement.window_id,
            outer: placement.outer.into(),
            client: placement.client.into(),
            visible: placement.visible.map(Into::into),
            focused: placement.focused,
            decorated: placement.decorated,
        }
    }
}

/// Broker disposition for a submitted frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PresentationResult {
    Accepted,
    Rejected(ServerErrorCode),
}

/// Runtime messages carried inside a [`RuntimePacket`].
///
/// The sender restrictions documented on each group are enforced by
/// [`RuntimeMessage::validate`], not merely by convention.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RuntimeMessage {
    // Desktop service -> kernel broker.
    ServiceReady {
        window_protocol_version: u16,
    },
    LauncherVisibility {
        visible: bool,
    },
    Configure {
        client_id: ClientId,
        window_id: WindowId,
        configuration: SurfaceConfiguration,
    },
    DestroyWindow {
        client_id: ClientId,
        window_id: WindowId,
    },
    SetPlacements {
        placements: Vec<RuntimePlacement>,
    },
    Present {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        damage: Vec<Rect>,
    },

    // Kernel broker -> desktop service.
    ToggleLauncher,
    ClientConnected {
        client_id: ClientId,
        channel_attachment: AttachmentIndex,
    },
    SurfaceReady {
        client_id: ClientId,
        window_id: WindowId,
        generation: Generation,
        surface_attachment: AttachmentIndex,
    },
    PresentResult {
        client_id: ClientId,
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        result: PresentationResult,
    },
    BufferReleased {
        client_id: ClientId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        present_request_id: RequestId,
    },
    PointerInput {
        position: Point,
        kind: PointerEventKind,
    },
    KeyboardInput {
        event: KeyboardEvent,
    },
}

impl RuntimeMessage {
    /// Returns the exact number of out-of-band attachments this message requires.
    pub const fn required_attachment_count(&self) -> usize {
        match self {
            Self::ClientConnected { .. } | Self::SurfaceReady { .. } => 1,
            _ => 0,
        }
    }

    /// Validates message direction, attachment use, geometry, and bounded lists.
    pub fn validate(
        &self,
        sender: RuntimeSender,
        attachment_count: usize,
    ) -> Result<(), RuntimeValidationError> {
        let expected_sender = match self {
            Self::ServiceReady { .. }
            | Self::LauncherVisibility { .. }
            | Self::Configure { .. }
            | Self::DestroyWindow { .. }
            | Self::SetPlacements { .. }
            | Self::Present { .. } => RuntimeSender::DesktopService,
            Self::ToggleLauncher
            | Self::ClientConnected { .. }
            | Self::SurfaceReady { .. }
            | Self::PresentResult { .. }
            | Self::BufferReleased { .. }
            | Self::PointerInput { .. }
            | Self::KeyboardInput { .. } => RuntimeSender::KernelBroker,
        };
        if sender != expected_sender {
            return Err(RuntimeValidationError::UnexpectedSender {
                expected: expected_sender,
                actual: sender,
            });
        }

        let expected_attachments = self.required_attachment_count();
        if attachment_count != expected_attachments {
            return Err(RuntimeValidationError::AttachmentCount {
                expected: expected_attachments,
                actual: attachment_count,
            });
        }
        match self {
            Self::ClientConnected {
                channel_attachment, ..
            } => validate_attachment(*channel_attachment, attachment_count)?,
            Self::SurfaceReady {
                surface_attachment, ..
            } => validate_attachment(*surface_attachment, attachment_count)?,
            _ => {}
        }

        match self {
            Self::ServiceReady {
                window_protocol_version,
            } if *window_protocol_version != PROTOCOL_VERSION => {
                Err(RuntimeValidationError::WindowProtocolVersion {
                    expected: PROTOCOL_VERSION,
                    actual: *window_protocol_version,
                })
            }
            Self::Configure { configuration, .. } => configuration
                .validate()
                .map_err(RuntimeValidationError::InvalidConfiguration),
            Self::SetPlacements { placements } => validate_placements(placements),
            Self::Present { damage, .. } => validate_damage(damage),
            Self::KeyboardInput { event } if !(1..=0x00e7).contains(&event.usage) => {
                Err(RuntimeValidationError::InvalidKeyboardUsage(event.usage))
            }
            _ => Ok(()),
        }
    }
}

/// Versioned envelope for every desktop runtime message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimePacket {
    pub protocol_id: u32,
    pub protocol_version: u16,
    pub message: RuntimeMessage,
}

impl RuntimePacket {
    pub const fn new(message: RuntimeMessage) -> Self {
        Self {
            protocol_id: RUNTIME_PROTOCOL_ID,
            protocol_version: RUNTIME_PROTOCOL_VERSION,
            message,
        }
    }

    /// Validates the envelope and its message against transport metadata.
    pub fn validate(
        &self,
        sender: RuntimeSender,
        attachment_count: usize,
    ) -> Result<(), RuntimeValidationError> {
        if self.protocol_id != RUNTIME_PROTOCOL_ID {
            return Err(RuntimeValidationError::ProtocolId {
                expected: RUNTIME_PROTOCOL_ID,
                actual: self.protocol_id,
            });
        }
        if self.protocol_version != RUNTIME_PROTOCOL_VERSION {
            return Err(RuntimeValidationError::ProtocolVersion {
                expected: RUNTIME_PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        self.message.validate(sender, attachment_count)
    }

    /// Serializes a packet with postcard without requiring `std`.
    ///
    /// Call [`Self::encode_validated`] at a transport boundary. This lower-level
    /// helper remains useful for constructing malformed packets in tests.
    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    /// Validates and serializes a packet for transmission.
    pub fn encode_validated(
        &self,
        sender: RuntimeSender,
        attachment_count: usize,
    ) -> Result<Vec<u8>, RuntimeEncodeError> {
        self.validate(sender, attachment_count)
            .map_err(RuntimeEncodeError::Validation)?;
        let bytes = self.encode().map_err(RuntimeEncodeError::Postcard)?;
        if bytes.len() > MAX_RUNTIME_PACKET_BYTES {
            return Err(RuntimeEncodeError::PacketTooLarge {
                maximum: MAX_RUNTIME_PACKET_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }

    /// Decodes and strictly validates a packet before returning it.
    pub fn decode(
        bytes: &[u8],
        sender: RuntimeSender,
        attachment_count: usize,
    ) -> Result<Self, RuntimeDecodeError> {
        if bytes.len() > MAX_RUNTIME_PACKET_BYTES {
            return Err(RuntimeDecodeError::PacketTooLarge {
                maximum: MAX_RUNTIME_PACKET_BYTES,
                actual: bytes.len(),
            });
        }
        let packet: Self = postcard::from_bytes(bytes).map_err(RuntimeDecodeError::Postcard)?;
        packet
            .validate(sender, attachment_count)
            .map_err(RuntimeDecodeError::Validation)?;
        Ok(packet)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementValidationError {
    EmptyOuter,
    EmptyClient,
    EmptyVisible,
    CoordinateOverflow,
    ClientOutsideOuter,
    VisibleOutsideOuter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeValidationError {
    ProtocolId {
        expected: u32,
        actual: u32,
    },
    ProtocolVersion {
        expected: u16,
        actual: u16,
    },
    WindowProtocolVersion {
        expected: u16,
        actual: u16,
    },
    UnexpectedSender {
        expected: RuntimeSender,
        actual: RuntimeSender,
    },
    AttachmentCount {
        expected: usize,
        actual: usize,
    },
    AttachmentOutOfRange {
        index: AttachmentIndex,
        attachment_count: usize,
    },
    InvalidConfiguration(ConfigurationError),
    TooManyPlacements {
        maximum: usize,
        actual: usize,
    },
    DuplicatePlacement(WindowId),
    MultipleFocusedPlacements,
    InvalidPlacement {
        index: usize,
        error: PlacementValidationError,
    },
    TooManyDamageRects {
        maximum: usize,
        actual: usize,
    },
    InvalidDamageRect {
        index: usize,
    },
    InvalidKeyboardUsage(u16),
}

#[derive(Debug)]
pub enum RuntimeEncodeError {
    PacketTooLarge { maximum: usize, actual: usize },
    Postcard(postcard::Error),
    Validation(RuntimeValidationError),
}

#[derive(Debug)]
pub enum RuntimeDecodeError {
    PacketTooLarge { maximum: usize, actual: usize },
    Postcard(postcard::Error),
    Validation(RuntimeValidationError),
}

fn validate_attachment(
    index: AttachmentIndex,
    attachment_count: usize,
) -> Result<(), RuntimeValidationError> {
    if usize::from(index.get()) >= attachment_count {
        return Err(RuntimeValidationError::AttachmentOutOfRange {
            index,
            attachment_count,
        });
    }
    Ok(())
}

fn validate_placements(placements: &[RuntimePlacement]) -> Result<(), RuntimeValidationError> {
    if placements.len() > MAX_RUNTIME_PLACEMENTS {
        return Err(RuntimeValidationError::TooManyPlacements {
            maximum: MAX_RUNTIME_PLACEMENTS,
            actual: placements.len(),
        });
    }
    let mut focused = false;
    for (index, placement) in placements.iter().enumerate() {
        validate_placement(*placement)
            .map_err(|error| RuntimeValidationError::InvalidPlacement { index, error })?;
        if placements[..index]
            .iter()
            .any(|other| other.window_id == placement.window_id)
        {
            return Err(RuntimeValidationError::DuplicatePlacement(
                placement.window_id,
            ));
        }
        if placement.focused {
            if focused {
                return Err(RuntimeValidationError::MultipleFocusedPlacements);
            }
            focused = true;
        }
    }
    Ok(())
}

fn validate_placement(placement: RuntimePlacement) -> Result<(), PlacementValidationError> {
    if placement.outer.is_empty() {
        return Err(PlacementValidationError::EmptyOuter);
    }
    if placement.client.is_empty() {
        return Err(PlacementValidationError::EmptyClient);
    }
    if placement.outer.checked_right().is_none()
        || placement.outer.checked_bottom().is_none()
        || placement.client.checked_right().is_none()
        || placement.client.checked_bottom().is_none()
        || placement.visible.is_some_and(|visible| {
            visible.checked_right().is_none() || visible.checked_bottom().is_none()
        })
    {
        return Err(PlacementValidationError::CoordinateOverflow);
    }
    if !placement.outer.contains(placement.client) {
        return Err(PlacementValidationError::ClientOutsideOuter);
    }
    if let Some(visible) = placement.visible {
        if visible.is_empty() {
            return Err(PlacementValidationError::EmptyVisible);
        }
        if !placement.outer.contains(visible) {
            return Err(PlacementValidationError::VisibleOutsideOuter);
        }
    }
    Ok(())
}

fn validate_damage(damage: &[Rect]) -> Result<(), RuntimeValidationError> {
    if damage.len() > MAX_RUNTIME_DAMAGE_RECTS {
        return Err(RuntimeValidationError::TooManyDamageRects {
            maximum: MAX_RUNTIME_DAMAGE_RECTS,
            actual: damage.len(),
        });
    }
    for (index, rect) in damage.iter().enumerate() {
        if rect.size.is_empty() || rect.origin.x < 0 || rect.origin.y < 0 {
            return Err(RuntimeValidationError::InvalidDamageRect { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ginkgo_window::{
        ButtonState, Modifiers, PixelFormat, PointerButton, ScaleFactor, Size, MIN_BUFFER_SLOTS,
    };

    use super::*;

    fn client_id(value: u64) -> ClientId {
        ClientId::new(value).unwrap()
    }

    fn request_id(value: u64) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn window_id(value: u64) -> WindowId {
        WindowId::new(value).unwrap()
    }

    fn generation(value: u32) -> Generation {
        Generation::new(value).unwrap()
    }

    fn configuration() -> SurfaceConfiguration {
        SurfaceConfiguration {
            logical_size: Size::new(4, 2),
            pixel_size: Size::new(6, 3),
            stride: 24,
            format: PixelFormat::Xrgb8888,
            scale: ScaleFactor::new(3, 2).unwrap(),
            generation: generation(1),
            buffer_count: MIN_BUFFER_SLOTS,
        }
    }

    fn placement(id: u64) -> RuntimePlacement {
        RuntimePlacement {
            window_id: window_id(id),
            outer: PlacementRect::new(-10, 0, 100, 80),
            client: PlacementRect::new(-6, 20, 92, 56),
            visible: Some(PlacementRect::new(0, 0, 90, 80)),
            focused: false,
            decorated: true,
        }
    }

    fn round_trip(message: RuntimeMessage, sender: RuntimeSender, attachments: usize) {
        let packet = RuntimePacket::new(message);
        let encoded = packet.encode_validated(sender, attachments).unwrap();
        let decoded = RuntimePacket::decode(&encoded, sender, attachments).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn all_runtime_messages_are_postcard_round_trip_safe() {
        let pointer_kind = PointerEventKind::Button {
            button: PointerButton::Primary,
            state: ButtonState::Pressed,
        };
        let keyboard = KeyboardEvent {
            usage: 4,
            state: ButtonState::Pressed,
            repeat: false,
            modifiers: Modifiers::default(),
        };
        let service_messages = vec![
            RuntimeMessage::ServiceReady {
                window_protocol_version: PROTOCOL_VERSION,
            },
            RuntimeMessage::LauncherVisibility { visible: true },
            RuntimeMessage::Configure {
                client_id: client_id(1),
                window_id: window_id(2),
                configuration: configuration(),
            },
            RuntimeMessage::DestroyWindow {
                client_id: client_id(1),
                window_id: window_id(2),
            },
            RuntimeMessage::SetPlacements {
                placements: vec![placement(2)],
            },
            RuntimeMessage::Present {
                client_id: client_id(1),
                request_id: request_id(3),
                window_id: window_id(2),
                generation: generation(1),
                buffer_id: BufferId::new(0),
                damage: vec![Rect::new(Point::new(0, 0), Size::new(4, 2))],
            },
        ];
        for message in service_messages {
            round_trip(message, RuntimeSender::DesktopService, 0);
        }

        let broker_messages = vec![
            RuntimeMessage::ToggleLauncher,
            RuntimeMessage::ClientConnected {
                client_id: client_id(1),
                channel_attachment: AttachmentIndex::new(0),
            },
            RuntimeMessage::SurfaceReady {
                client_id: client_id(1),
                window_id: window_id(2),
                generation: generation(1),
                surface_attachment: AttachmentIndex::new(0),
            },
            RuntimeMessage::PresentResult {
                client_id: client_id(1),
                request_id: request_id(3),
                window_id: window_id(2),
                generation: generation(1),
                buffer_id: BufferId::new(0),
                result: PresentationResult::Accepted,
            },
            RuntimeMessage::BufferReleased {
                client_id: client_id(1),
                window_id: window_id(2),
                generation: generation(1),
                buffer_id: BufferId::new(0),
                present_request_id: request_id(3),
            },
            RuntimeMessage::PointerInput {
                position: Point::new(10, 20),
                kind: pointer_kind,
            },
            RuntimeMessage::KeyboardInput { event: keyboard },
        ];
        for message in broker_messages {
            let attachments = message.required_attachment_count();
            round_trip(message, RuntimeSender::KernelBroker, attachments);
        }
    }

    #[test]
    fn envelope_direction_and_attachments_are_strictly_validated() {
        let mut packet = RuntimePacket::new(RuntimeMessage::ToggleLauncher);
        assert!(matches!(
            packet.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::UnexpectedSender { .. })
        ));
        packet.protocol_id ^= 1;
        assert!(matches!(
            packet.validate(RuntimeSender::KernelBroker, 0),
            Err(RuntimeValidationError::ProtocolId { .. })
        ));
        packet.protocol_id = RUNTIME_PROTOCOL_ID;
        packet.protocol_version += 1;
        assert!(matches!(
            packet.validate(RuntimeSender::KernelBroker, 0),
            Err(RuntimeValidationError::ProtocolVersion { .. })
        ));

        let attached = RuntimePacket::new(RuntimeMessage::ClientConnected {
            client_id: client_id(1),
            channel_attachment: AttachmentIndex::new(0),
        });
        assert_eq!(
            attached.validate(RuntimeSender::KernelBroker, 0),
            Err(RuntimeValidationError::AttachmentCount {
                expected: 1,
                actual: 0,
            })
        );
        assert_eq!(
            attached.validate(RuntimeSender::KernelBroker, 2),
            Err(RuntimeValidationError::AttachmentCount {
                expected: 1,
                actual: 2,
            })
        );

        let bad_index = RuntimePacket::new(RuntimeMessage::ClientConnected {
            client_id: client_id(1),
            channel_attachment: AttachmentIndex::new(1),
        });
        assert!(matches!(
            bad_index.validate(RuntimeSender::KernelBroker, 1),
            Err(RuntimeValidationError::AttachmentOutOfRange { .. })
        ));
        assert!(matches!(
            bad_index.encode_validated(RuntimeSender::KernelBroker, 1),
            Err(RuntimeEncodeError::Validation(
                RuntimeValidationError::AttachmentOutOfRange { .. }
            ))
        ));

        let oversized = vec![0; MAX_RUNTIME_PACKET_BYTES + 1];
        assert!(matches!(
            RuntimePacket::decode(&oversized, RuntimeSender::KernelBroker, 0),
            Err(RuntimeDecodeError::PacketTooLarge { .. })
        ));
    }

    #[test]
    fn invalid_ids_fail_during_postcard_decode() {
        let packet_with_id = |value| {
            RuntimePacket::new(RuntimeMessage::ClientConnected {
                client_id: client_id(value),
                channel_attachment: AttachmentIndex::new(0),
            })
            .encode()
            .unwrap()
        };
        let mut malformed = packet_with_id(1);
        let different_id = packet_with_id(2);
        let differing_offsets: Vec<_> = malformed
            .iter()
            .zip(&different_id)
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();
        assert_eq!(differing_offsets.len(), 1);
        malformed[differing_offsets[0]] = 0;

        assert!(matches!(
            RuntimePacket::decode(&malformed, RuntimeSender::KernelBroker, 1),
            Err(RuntimeDecodeError::Postcard(_))
        ));
    }

    #[test]
    fn configurations_and_window_protocol_version_are_validated() {
        let ready = RuntimeMessage::ServiceReady {
            window_protocol_version: PROTOCOL_VERSION + 1,
        };
        assert!(matches!(
            ready.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::WindowProtocolVersion { .. })
        ));

        let mut invalid = configuration();
        invalid.buffer_count = MIN_BUFFER_SLOTS - 1;
        let configure = RuntimeMessage::Configure {
            client_id: client_id(1),
            window_id: window_id(2),
            configuration: invalid,
        };
        assert_eq!(
            configure.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::InvalidConfiguration(
                ConfigurationError::TooFewBuffers
            ))
        );
    }

    #[test]
    fn placements_reject_invalid_geometry_duplicates_and_multiple_focus() {
        let mut invalid = placement(1);
        invalid.client.x = invalid.outer.x - 1;
        let message = RuntimeMessage::SetPlacements {
            placements: vec![invalid],
        };
        assert_eq!(
            message.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::InvalidPlacement {
                index: 0,
                error: PlacementValidationError::ClientOutsideOuter,
            })
        );

        let duplicate = RuntimeMessage::SetPlacements {
            placements: vec![placement(1), placement(1)],
        };
        assert_eq!(
            duplicate.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::DuplicatePlacement(window_id(1)))
        );

        let mut first = placement(1);
        first.focused = true;
        let mut second = placement(2);
        second.focused = true;
        let multiple_focus = RuntimeMessage::SetPlacements {
            placements: vec![first, second],
        };
        assert_eq!(
            multiple_focus.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::MultipleFocusedPlacements)
        );
    }

    #[test]
    fn input_and_damage_validation_reject_malformed_values() {
        let present = RuntimeMessage::Present {
            client_id: client_id(1),
            request_id: request_id(2),
            window_id: window_id(3),
            generation: generation(1),
            buffer_id: BufferId::new(0),
            damage: vec![Rect::new(Point::new(-1, 0), Size::new(1, 1))],
        };
        assert_eq!(
            present.validate(RuntimeSender::DesktopService, 0),
            Err(RuntimeValidationError::InvalidDamageRect { index: 0 })
        );

        let keyboard = RuntimeMessage::KeyboardInput {
            event: KeyboardEvent {
                usage: 0,
                state: ButtonState::Released,
                repeat: false,
                modifiers: Modifiers::default(),
            },
        };
        assert_eq!(
            keyboard.validate(RuntimeSender::KernelBroker, 0),
            Err(RuntimeValidationError::InvalidKeyboardUsage(0))
        );
    }
}
