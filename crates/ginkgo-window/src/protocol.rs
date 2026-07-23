use alloc::{string::String, vec, vec::Vec};

use ginkgo_graphics::{PixelFormat as GraphicsPixelFormat, SurfaceError, SurfaceLayout};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Point, Rect, ScaleFactor, Size};

/// Current version of the window protocol.
///
/// Existing enum variants and fields are append-only within a protocol version.
pub const PROTOCOL_VERSION: u16 = 4;
/// Maximum UTF-8 payload carried by one clipboard protocol message.
pub const MAX_CLIPBOARD_BYTES: usize = 4 * 1024;
/// Minimum number of buffers in a configured surface pool.
pub const MIN_BUFFER_SLOTS: u8 = 2;

macro_rules! nonzero_id {
    ($name:ident, $raw:ty, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($raw);

        impl $name {
            pub const fn new(value: $raw) -> Option<Self> {
                if value == 0 {
                    None
                } else {
                    Some(Self(value))
                }
            }

            pub const fn get(self) -> $raw {
                self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <$raw>::deserialize(deserializer)?;
                Self::new(value).ok_or_else(|| {
                    serde::de::Error::custom(concat!($description, " must be non-zero"))
                })
            }
        }
    };
}

nonzero_id!(RequestId, u64, "A client-generated request identifier.");
nonzero_id!(WindowId, u64, "A server-generated window identifier.");
nonzero_id!(
    Generation,
    u32,
    "A monotonically increasing surface generation."
);

/// Zero-based index of a buffer slot within one surface generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BufferId(u8);

impl BufferId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Window-system pixel formats supported by `ginkgo-graphics::PixelSurface`.
///
/// These are presentation formats, not arbitrary hardware framebuffer layouts.
/// Explicit numeric serialization keeps existing values stable when variants
/// are appended in a future protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PixelFormat {
    /// `0x00RRGGBB`, stored as `[B, G, R, 0]`.
    Xrgb8888,
    /// `0xAARRGGBB`, stored as `[B, G, R, A]`.
    Argb8888,
}

impl PixelFormat {
    pub const fn bytes_per_pixel(self) -> u8 {
        4
    }

    pub const fn minimum_stride(self, width: u32) -> Option<u32> {
        width.checked_mul(self.bytes_per_pixel() as u32)
    }

    pub const fn to_graphics(self) -> GraphicsPixelFormat {
        match self {
            Self::Xrgb8888 => GraphicsPixelFormat::Xrgb8888,
            Self::Argb8888 => GraphicsPixelFormat::Argb8888,
        }
    }

    const fn wire_value(self) -> u8 {
        match self {
            Self::Xrgb8888 => 1,
            Self::Argb8888 => 2,
        }
    }

    const fn from_wire_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Xrgb8888),
            2 => Some(Self::Argb8888),
            _ => None,
        }
    }
}

impl From<PixelFormat> for GraphicsPixelFormat {
    fn from(format: PixelFormat) -> Self {
        format.to_graphics()
    }
}

impl Serialize for PixelFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.wire_value())
    }
}

impl<'de> Deserialize<'de> for PixelFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::from_wire_value(value).ok_or_else(|| serde::de::Error::custom("unknown pixel format"))
    }
}

/// Options sent when creating a window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowOptions {
    pub title: String,
    pub preferred_size: Size,
    pub minimum_size: Option<Size>,
    pub maximum_size: Option<Size>,
    pub scale_factor: Option<ScaleFactor>,
    pub preferred_formats: Vec<PixelFormat>,
    pub resizable: bool,
    pub decorations: bool,
    pub transparent: bool,
    pub fullscreen: bool,
}

impl WindowOptions {
    pub fn validate(&self) -> Result<(), WindowOptionsError> {
        if self.preferred_size.is_empty() {
            return Err(WindowOptionsError::EmptyPreferredSize);
        }
        if self.preferred_formats.is_empty() {
            return Err(WindowOptionsError::NoPixelFormats);
        }
        if self.minimum_size.is_some_and(Size::is_empty)
            || self.maximum_size.is_some_and(Size::is_empty)
        {
            return Err(WindowOptionsError::EmptyConstraint);
        }
        if let (Some(minimum), Some(maximum)) = (self.minimum_size, self.maximum_size) {
            if minimum.width > maximum.width || minimum.height > maximum.height {
                return Err(WindowOptionsError::InvertedConstraints);
            }
        }
        if let Some(minimum) = self.minimum_size {
            if self.preferred_size.width < minimum.width
                || self.preferred_size.height < minimum.height
            {
                return Err(WindowOptionsError::PreferredSizeOutsideConstraints);
            }
        }
        if let Some(maximum) = self.maximum_size {
            if self.preferred_size.width > maximum.width
                || self.preferred_size.height > maximum.height
            {
                return Err(WindowOptionsError::PreferredSizeOutsideConstraints);
            }
        }
        Ok(())
    }
}

impl Default for WindowOptions {
    fn default() -> Self {
        Self {
            title: String::new(),
            preferred_size: Size::new(800, 600),
            minimum_size: None,
            maximum_size: None,
            scale_factor: None,
            preferred_formats: vec![PixelFormat::Xrgb8888, PixelFormat::Argb8888],
            resizable: true,
            decorations: true,
            transparent: false,
            fullscreen: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowOptionsError {
    EmptyPreferredSize,
    NoPixelFormats,
    EmptyConstraint,
    InvertedConstraints,
    PreferredSizeOutsideConstraints,
}

/// Public, transport-independent description of a shared surface pool.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SurfaceConfiguration {
    pub logical_size: Size,
    pub pixel_size: Size,
    pub stride: u32,
    pub format: PixelFormat,
    pub scale: ScaleFactor,
    pub generation: Generation,
    pub buffer_count: u8,
}

impl SurfaceConfiguration {
    pub fn validate(self) -> Result<(), ConfigurationError> {
        if self.logical_size.is_empty() {
            return Err(ConfigurationError::EmptyLogicalSize);
        }
        if self.pixel_size.is_empty() {
            return Err(ConfigurationError::EmptyPixelSize);
        }
        if self.scale.scale_size(self.logical_size) != Some(self.pixel_size) {
            return Err(ConfigurationError::PixelSizeMismatch);
        }
        if self.buffer_count < MIN_BUFFER_SLOTS {
            return Err(ConfigurationError::TooFewBuffers);
        }
        self.graphics_layout()?
            .required_bytes()
            .map_err(map_surface_error)?;
        self.required_surface_bytes()
            .ok_or(ConfigurationError::LayoutOverflow)?;
        Ok(())
    }

    pub fn graphics_layout(self) -> Result<SurfaceLayout, ConfigurationError> {
        let width = usize::try_from(self.pixel_size.width)
            .map_err(|_| ConfigurationError::LayoutOverflow)?;
        let height = usize::try_from(self.pixel_size.height)
            .map_err(|_| ConfigurationError::LayoutOverflow)?;
        let stride =
            usize::try_from(self.stride).map_err(|_| ConfigurationError::LayoutOverflow)?;
        Ok(SurfaceLayout::new(
            width,
            height,
            stride,
            self.format.into(),
        ))
    }

    pub fn bytes_per_buffer(self) -> Option<usize> {
        self.graphics_layout().ok()?.required_bytes().ok()
    }

    pub fn required_surface_bytes(self) -> Option<usize> {
        self.bytes_per_buffer()?
            .checked_mul(usize::from(self.buffer_count))
    }
}

fn map_surface_error(error: SurfaceError) -> ConfigurationError {
    match error {
        SurfaceError::ZeroDimension => ConfigurationError::EmptyPixelSize,
        SurfaceError::StrideTooSmall { .. } => ConfigurationError::StrideTooSmall,
        SurfaceError::DimensionTooLarge
        | SurfaceError::LayoutOverflow
        | SurfaceError::BufferTooSmall { .. } => ConfigurationError::LayoutOverflow,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    EmptyLogicalSize,
    EmptyPixelSize,
    PixelSizeMismatch,
    TooFewBuffers,
    StrideTooSmall,
    LayoutOverflow,
    SurfaceTooShort,
}

/// Validation failures for a size-related client request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    EmptyPreferredSize,
    EmptyMinimumSize,
    EmptyMaximumSize,
    ClipboardTooLarge,
}

/// A transport attachment reference carried only by a wire `Configured` event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Configured {
    pub window_id: WindowId,
    pub configuration: SurfaceConfiguration,
    pub surface_handle_index: u16,
}

/// Requests serialized from a client to the window server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WireRequest {
    CreateWindow {
        protocol_version: u16,
        request_id: RequestId,
        options: WindowOptions,
    },
    DestroyWindow {
        request_id: RequestId,
        window_id: WindowId,
    },
    RequestSize {
        request_id: RequestId,
        window_id: WindowId,
        preferred_size: Size,
    },
    SetMinimumSize {
        request_id: RequestId,
        window_id: WindowId,
        minimum_size: Option<Size>,
    },
    SetMaximumSize {
        request_id: RequestId,
        window_id: WindowId,
        maximum_size: Option<Size>,
    },
    SetFullscreen {
        request_id: RequestId,
        window_id: WindowId,
        fullscreen: bool,
    },
    ToggleFullscreen {
        request_id: RequestId,
        window_id: WindowId,
    },
    Present {
        request_id: RequestId,
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        damage: Vec<Rect>,
    },
    SetClipboardText {
        request_id: RequestId,
        window_id: WindowId,
        text: String,
    },
    RequestClipboardText {
        request_id: RequestId,
        window_id: WindowId,
    },
}

/// State of a keyboard key or pointer button.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ButtonState {
    Released,
    Pressed,
}

/// A pointer button independent of any particular HID transport.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PointerButton {
    Primary,
    Secondary,
    Middle,
    Other(u16),
}

/// The action represented by a pointer event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PointerEventKind {
    Moved,
    Button {
        button: PointerButton,
        state: ButtonState,
    },
    Scrolled {
        delta: Point,
    },
}

/// Pointer input in window-local logical coordinates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PointerEvent {
    pub position: Point,
    pub kind: PointerEventKind,
}

/// Modifier state accompanying a keyboard event.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Modifiers {
    pub shift: bool,
    pub control: bool,
    pub alt: bool,
    pub logo: bool,
    pub caps_lock: bool,
    pub num_lock: bool,
}

/// Keyboard-page HID usage input delivered to a window.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyboardEvent {
    pub usage: u16,
    pub state: ButtonState,
    pub repeat: bool,
    pub modifiers: Modifiers,
}

/// Events serialized from the window server to a client.
///
/// This is deliberately separate from [`Event`]: transport attachment indices
/// must never escape into application-facing events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WireEvent {
    WindowCreated {
        protocol_version: u16,
        request_id: RequestId,
        window_id: WindowId,
    },
    Configured(Configured),
    BufferReleased {
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        present_request_id: RequestId,
    },
    Redraw {
        window_id: WindowId,
        damage: Vec<Rect>,
    },
    Pointer {
        window_id: WindowId,
        event: PointerEvent,
    },
    Keyboard {
        window_id: WindowId,
        event: KeyboardEvent,
    },
    CloseRequested {
        window_id: WindowId,
    },
    FocusChanged {
        window_id: WindowId,
        focused: bool,
    },
    ClipboardText {
        request_id: RequestId,
        text: String,
    },
    RequestFailed {
        request_id: RequestId,
        code: ServerErrorCode,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ServerErrorCode {
    InvalidRequest,
    Unsupported,
    OutOfResources,
    WindowGone,
}

/// Application-facing events after transport metadata and state transitions
/// have been handled by the client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Event {
    WindowCreated {
        request_id: RequestId,
        window_id: WindowId,
    },
    Configured {
        window_id: WindowId,
        configuration: SurfaceConfiguration,
    },
    BufferReleased {
        window_id: WindowId,
        generation: Generation,
        buffer_id: BufferId,
        present_request_id: RequestId,
    },
    Redraw {
        window_id: WindowId,
        damage: Vec<Rect>,
    },
    Pointer {
        window_id: WindowId,
        event: PointerEvent,
    },
    Keyboard {
        window_id: WindowId,
        event: KeyboardEvent,
    },
    CloseRequested {
        window_id: WindowId,
    },
    FocusChanged {
        window_id: WindowId,
        focused: bool,
    },
    ClipboardText {
        request_id: RequestId,
        text: String,
    },
    RequestFailed {
        request_id: RequestId,
        code: ServerErrorCode,
    },
}
