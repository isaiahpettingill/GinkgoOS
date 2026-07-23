use alloc::vec::Vec;

use ginkgo_ipc::ginkgo_sysapi::RpcHeader;
use ginkgo_ipc::{decode_structured, encode_structured, RpcFlags, StructuredMessageError};

use crate::{RequestId, WireEvent, WireRequest};

/// Stable RPC protocol identifier for the Ginkgo window protocol (`GWND`).
pub const WINDOW_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GWND");
/// RPC method carrying a postcard-encoded [`WireRequest`].
pub const WINDOW_REQUEST_METHOD_ID: u32 = 1;
/// RPC method carrying a postcard-encoded [`WireEvent`].
pub const WINDOW_EVENT_METHOD_ID: u32 = 2;

/// Strict window-channel framing or attachment validation failure.
#[derive(Debug)]
pub enum ChannelCodecError {
    Framing(StructuredMessageError),
    WrongProtocol { expected: u32, received: u32 },
    WrongMethod { expected: u32, received: u32 },
    WrongFlags { expected: u32, received: u32 },
    TransactionMismatch { expected: u64, received: u64 },
    AttachmentCountMismatch { expected: usize, received: usize },
    InvalidSurfaceHandleIndex { received: u16 },
}

impl From<StructuredMessageError> for ChannelCodecError {
    fn from(error: StructuredMessageError) -> Self {
        Self::Framing(error)
    }
}

impl WireRequest {
    /// Returns the request identifier which must also be used as the RPC
    /// transaction identifier.
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::CreateWindow { request_id, .. }
            | Self::DestroyWindow { request_id, .. }
            | Self::RequestSize { request_id, .. }
            | Self::SetMinimumSize { request_id, .. }
            | Self::SetMaximumSize { request_id, .. }
            | Self::SetFullscreen { request_id, .. }
            | Self::ToggleFullscreen { request_id, .. }
            | Self::Present { request_id, .. }
            | Self::SetClipboardText { request_id, .. }
            | Self::RequestClipboardText { request_id, .. } => *request_id,
        }
    }
}

impl WireEvent {
    /// Returns the request associated with a solicited event. Unsolicited
    /// configuration and input events return `None`.
    pub const fn request_id(&self) -> Option<RequestId> {
        match self {
            Self::WindowCreated { request_id, .. }
            | Self::ClipboardText { request_id, .. }
            | Self::RequestFailed { request_id, .. } => Some(*request_id),
            Self::BufferReleased {
                present_request_id, ..
            } => Some(*present_request_id),
            Self::Configured(_)
            | Self::Redraw { .. }
            | Self::Pointer { .. }
            | Self::Keyboard { .. }
            | Self::CloseRequested { .. }
            | Self::FocusChanged { .. } => None,
        }
    }

    const fn rpc_flags(&self) -> RpcFlags {
        match self {
            Self::RequestFailed { .. } => {
                RpcFlags::from_bits_retain(RpcFlags::RESPONSE.bits() | RpcFlags::ERROR.bits())
            }
            Self::WindowCreated { .. }
            | Self::BufferReleased { .. }
            | Self::ClipboardText { .. } => RpcFlags::RESPONSE,
            Self::Configured(_)
            | Self::Redraw { .. }
            | Self::Pointer { .. }
            | Self::Keyboard { .. }
            | Self::CloseRequested { .. }
            | Self::FocusChanged { .. } => RpcFlags::ONE_WAY,
        }
    }

    const fn transaction_id(&self) -> u64 {
        match self.request_id() {
            Some(request_id) => request_id.get(),
            None => 0,
        }
    }

    const fn attachment_count(&self) -> usize {
        match self {
            Self::Configured(_) => 1,
            _ => 0,
        }
    }
}

/// Encodes one request as an `RpcHeader` followed by its postcard payload.
pub fn encode_request(request: &WireRequest) -> Result<Vec<u8>, ChannelCodecError> {
    let header = RpcHeader::new(
        request.request_id().get(),
        WINDOW_PROTOCOL_ID,
        WINDOW_REQUEST_METHOD_ID,
        RpcFlags::empty(),
    );
    encode_structured(header, request).map_err(Into::into)
}

/// Decodes and strictly validates one request channel message.
pub fn decode_request(
    message: &[u8],
    attachment_count: usize,
) -> Result<WireRequest, ChannelCodecError> {
    let (header, request) = decode_structured::<WireRequest>(message)?;
    validate_common_header(&header, WINDOW_REQUEST_METHOD_ID)?;
    validate_flags(&header, RpcFlags::empty())?;
    validate_transaction(&header, request.request_id().get())?;
    validate_attachment_count(0, attachment_count)?;
    Ok(request)
}

/// Encodes one event as an `RpcHeader` followed by its postcard payload.
pub fn encode_event(event: &WireEvent) -> Result<Vec<u8>, ChannelCodecError> {
    let header = RpcHeader::new(
        event.transaction_id(),
        WINDOW_PROTOCOL_ID,
        WINDOW_EVENT_METHOD_ID,
        event.rpc_flags(),
    );
    encode_structured(header, event).map_err(Into::into)
}

/// Decodes and strictly validates one event channel message.
pub fn decode_event(
    message: &[u8],
    attachment_count: usize,
) -> Result<WireEvent, ChannelCodecError> {
    let (header, event) = decode_structured::<WireEvent>(message)?;
    validate_common_header(&header, WINDOW_EVENT_METHOD_ID)?;
    validate_flags(&header, event.rpc_flags())?;
    validate_transaction(&header, event.transaction_id())?;
    validate_attachment_count(event.attachment_count(), attachment_count)?;
    if let WireEvent::Configured(configured) = &event {
        if configured.surface_handle_index != 0 {
            return Err(ChannelCodecError::InvalidSurfaceHandleIndex {
                received: configured.surface_handle_index,
            });
        }
    }
    Ok(event)
}

/// Explicitly named alias useful at call sites that handle multiple codecs.
pub use decode_event as decode_channel_event;
/// Explicitly named alias useful at call sites that handle multiple codecs.
pub use decode_request as decode_channel_request;
/// Explicitly named alias useful at call sites that handle multiple codecs.
pub use encode_event as encode_channel_event;
/// Explicitly named alias useful at call sites that handle multiple codecs.
pub use encode_request as encode_channel_request;

fn validate_common_header(
    header: &RpcHeader,
    expected_method: u32,
) -> Result<(), ChannelCodecError> {
    if header.protocol_id != WINDOW_PROTOCOL_ID {
        return Err(ChannelCodecError::WrongProtocol {
            expected: WINDOW_PROTOCOL_ID,
            received: header.protocol_id,
        });
    }
    if header.method_id != expected_method {
        return Err(ChannelCodecError::WrongMethod {
            expected: expected_method,
            received: header.method_id,
        });
    }
    Ok(())
}

fn validate_flags(header: &RpcHeader, expected: RpcFlags) -> Result<(), ChannelCodecError> {
    if header.flags != expected.bits() {
        return Err(ChannelCodecError::WrongFlags {
            expected: expected.bits(),
            received: header.flags,
        });
    }
    Ok(())
}

fn validate_transaction(header: &RpcHeader, expected: u64) -> Result<(), ChannelCodecError> {
    if header.transaction_id != expected {
        return Err(ChannelCodecError::TransactionMismatch {
            expected,
            received: header.transaction_id,
        });
    }
    Ok(())
}

fn validate_attachment_count(expected: usize, received: usize) -> Result<(), ChannelCodecError> {
    if received != expected {
        return Err(ChannelCodecError::AttachmentCountMismatch { expected, received });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use ginkgo_ipc::ginkgo_sysapi::RPC_HEADER_SIZE;

    use super::*;
    use crate::{
        BufferId, Configured, Generation, PixelFormat, ScaleFactor, ServerErrorCode, Size,
        SurfaceConfiguration, WindowId, WindowOptions, PROTOCOL_VERSION,
    };

    fn request_id(value: u64) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn window_id(value: u64) -> WindowId {
        WindowId::new(value).unwrap()
    }

    fn request() -> WireRequest {
        WireRequest::CreateWindow {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id(42),
            options: WindowOptions {
                title: String::from("Codec test"),
                ..WindowOptions::default()
            },
        }
    }

    fn configuration() -> SurfaceConfiguration {
        SurfaceConfiguration {
            logical_size: Size::new(4, 2),
            pixel_size: Size::new(4, 2),
            stride: 16,
            format: PixelFormat::Xrgb8888,
            scale: ScaleFactor::new(1, 1).unwrap(),
            generation: Generation::new(3).unwrap(),
            buffer_count: 2,
        }
    }

    fn replace_u32(message: &mut [u8], offset: usize, value: u32) {
        message[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn replace_u64(message: &mut [u8], offset: usize, value: u64) {
        message[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn request_ids_are_available_for_every_request_variant() {
        let id = request_id(9);
        let window = window_id(5);
        let requests = [
            WireRequest::CreateWindow {
                protocol_version: PROTOCOL_VERSION,
                request_id: id,
                options: WindowOptions::default(),
            },
            WireRequest::DestroyWindow {
                request_id: id,
                window_id: window,
            },
            WireRequest::RequestSize {
                request_id: id,
                window_id: window,
                preferred_size: Size::new(1, 1),
            },
            WireRequest::SetMinimumSize {
                request_id: id,
                window_id: window,
                minimum_size: None,
            },
            WireRequest::SetMaximumSize {
                request_id: id,
                window_id: window,
                maximum_size: None,
            },
            WireRequest::SetFullscreen {
                request_id: id,
                window_id: window,
                fullscreen: true,
            },
            WireRequest::ToggleFullscreen {
                request_id: id,
                window_id: window,
            },
            WireRequest::Present {
                request_id: id,
                window_id: window,
                generation: Generation::new(1).unwrap(),
                buffer_id: BufferId::new(0),
                damage: Vec::new(),
            },
            WireRequest::SetClipboardText {
                request_id: id,
                window_id: window,
                text: String::from("copied"),
            },
            WireRequest::RequestClipboardText {
                request_id: id,
                window_id: window,
            },
        ];

        assert!(requests.iter().all(|request| request.request_id() == id));
    }

    #[test]
    fn request_frame_round_trips_with_strict_header_and_no_attachments() {
        let request = request();
        let bytes = encode_request(&request).unwrap();

        assert!(bytes.len() > RPC_HEADER_SIZE);
        assert_eq!(decode_request(&bytes, 0).unwrap(), request);
        assert!(matches!(
            decode_request(&bytes, 1),
            Err(ChannelCodecError::AttachmentCountMismatch {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn request_decoder_rejects_protocol_method_flags_and_transaction_changes() {
        let cases = [
            (8, 0xfeed_beef_u32, "protocol"),
            (12, WINDOW_EVENT_METHOD_ID, "method"),
            (16, RpcFlags::ONE_WAY.bits(), "flags"),
        ];
        for (offset, value, kind) in cases {
            let mut bytes = encode_request(&request()).unwrap();
            replace_u32(&mut bytes, offset, value);
            let error = decode_request(&bytes, 0).unwrap_err();
            assert!(matches!(
                (kind, error),
                ("protocol", ChannelCodecError::WrongProtocol { .. })
                    | ("method", ChannelCodecError::WrongMethod { .. })
                    | ("flags", ChannelCodecError::WrongFlags { .. })
            ));
        }

        let mut bytes = encode_request(&request()).unwrap();
        replace_u64(&mut bytes, 0, 43);
        assert!(matches!(
            decode_request(&bytes, 0),
            Err(ChannelCodecError::TransactionMismatch {
                expected: 42,
                received: 43
            })
        ));
    }

    #[test]
    fn event_framing_distinguishes_responses_errors_and_one_way_events() {
        let response = WireEvent::WindowCreated {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id(11),
            window_id: window_id(7),
        };
        let error = WireEvent::RequestFailed {
            request_id: request_id(12),
            code: ServerErrorCode::InvalidRequest,
        };
        let clipboard = WireEvent::ClipboardText {
            request_id: request_id(13),
            text: String::from("copied"),
        };
        let one_way = WireEvent::CloseRequested {
            window_id: window_id(7),
        };

        for event in [response, error, clipboard, one_way] {
            let bytes = encode_event(&event).unwrap();
            assert_eq!(decode_event(&bytes, 0).unwrap(), event);
        }
    }

    #[test]
    fn event_decoder_rejects_wrong_transaction_and_flags_for_event_kind() {
        let event = WireEvent::CloseRequested {
            window_id: window_id(7),
        };
        let mut bytes = encode_event(&event).unwrap();
        replace_u64(&mut bytes, 0, 9);
        assert!(matches!(
            decode_event(&bytes, 0),
            Err(ChannelCodecError::TransactionMismatch {
                expected: 0,
                received: 9
            })
        ));

        let mut bytes = encode_event(&event).unwrap();
        replace_u32(&mut bytes, 16, RpcFlags::RESPONSE.bits());
        assert!(matches!(
            decode_event(&bytes, 0),
            Err(ChannelCodecError::WrongFlags { .. })
        ));
    }

    #[test]
    fn configured_requires_one_attachment_at_index_zero() {
        let event = WireEvent::Configured(Configured {
            window_id: window_id(7),
            configuration: configuration(),
            surface_handle_index: 0,
        });
        let bytes = encode_event(&event).unwrap();
        assert_eq!(decode_event(&bytes, 1).unwrap(), event);
        for count in [0, 2] {
            assert!(matches!(
                decode_event(&bytes, count),
                Err(ChannelCodecError::AttachmentCountMismatch { expected: 1, received })
                    if received == count
            ));
        }

        let invalid = WireEvent::Configured(Configured {
            window_id: window_id(7),
            configuration: configuration(),
            surface_handle_index: 1,
        });
        let bytes = encode_event(&invalid).unwrap();
        assert!(matches!(
            decode_event(&bytes, 1),
            Err(ChannelCodecError::InvalidSurfaceHandleIndex { received: 1 })
        ));
    }

    #[test]
    fn non_configured_events_reject_attachments_and_malformed_frames() {
        let event = WireEvent::CloseRequested {
            window_id: window_id(7),
        };
        let bytes = encode_event(&event).unwrap();
        assert!(matches!(
            decode_event(&bytes, 1),
            Err(ChannelCodecError::AttachmentCountMismatch {
                expected: 0,
                received: 1
            })
        ));
        assert!(matches!(
            decode_event(&bytes[..RPC_HEADER_SIZE - 1], 0),
            Err(ChannelCodecError::Framing(
                StructuredMessageError::HeaderTooShort
            ))
        ));

        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            decode_event(&trailing, 0),
            Err(ChannelCodecError::Framing(
                StructuredMessageError::PayloadLengthMismatch
            ))
        ));
    }
}
