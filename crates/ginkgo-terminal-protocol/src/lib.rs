#![no_std]

//! Shared wire protocol for terminal console traffic and application launches.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use ginkgo_ipc::ginkgo_sysapi::{RpcHeader, RPC_HEADER_SIZE};
use ginkgo_ipc::{decode_structured, encode_structured, RpcFlags, StructuredMessageError};
use serde::{Deserialize, Serialize};

/// Stable RPC protocol identifier for terminal console messages (`GCON`).
pub const CONSOLE_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GCON");
/// Stable RPC protocol identifier for terminal launch requests (`GLCH`).
pub const LAUNCH_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GLCH");
/// Stable RPC protocol identifier for document startup messages (`GDOC`).
pub const DOCUMENT_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GDOC");
/// Stable RPC protocol identifier for terminal startup commands (`GTSC`).
pub const TERMINAL_STARTUP_PROTOCOL_ID: u32 = u32::from_le_bytes(*b"GTSC");
/// Current wire version for [`TerminalStartupCommand`].
pub const TERMINAL_STARTUP_VERSION: u16 = 1;
/// RPC method carrying a postcard-encoded [`ConsoleMessage`].
pub const CONSOLE_MESSAGE_METHOD_ID: u32 = 1;
/// RPC method carrying a postcard-encoded [`LaunchRequest`].
pub const LAUNCH_REQUEST_METHOD_ID: u32 = 1;
/// RPC method carrying a postcard-encoded [`OpenDocument`].
pub const OPEN_DOCUMENT_METHOD_ID: u32 = 1;
/// RPC method carrying a postcard-encoded [`TerminalStartupCommand`].
pub const TERMINAL_STARTUP_COMMAND_METHOD_ID: u32 = 1;
/// Maximum application identifier length accepted by the program registry.
pub const MAX_APP_ID_LEN: usize = 255;
/// Maximum UTF-8 byte length accepted for an [`OpenDocument`] path.
pub const MAX_DOCUMENT_PATH_BYTES: usize = 512;
/// Maximum number of arguments accepted in a [`TerminalStartupCommand`].
pub const MAX_TERMINAL_STARTUP_ARGUMENTS: usize = 32;
/// Maximum combined UTF-8 byte length of terminal startup arguments.
pub const MAX_TERMINAL_STARTUP_ARGUMENT_BYTES: usize = 16 * 1024;

const TRANSACTION_ID: u64 = 0;
const CONSOLE_ATTACHMENT_COUNT: usize = 0;
const LAUNCH_ATTACHMENT_COUNT: usize = 1;
const DOCUMENT_ATTACHMENT_COUNT: usize = 0;
const TERMINAL_STARTUP_ATTACHMENT_COUNT: usize = 0;
const STARTUP_ATTACHMENT_INDEX: u16 = 0;

/// One message on a terminal console channel.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ConsoleMessage {
    Input(Vec<u8>),
    Output(Vec<u8>),
    Error(Vec<u8>),
    Exit(i32),
}

/// Requests that a terminal launch an application using one attached startup channel.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LaunchRequest {
    pub app_id: String,
    pub startup_attachment: u16,
}

/// Requests that a text editor open one document over its existing startup channel.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct OpenDocument {
    pub path: String,
}

/// Versioned command asking a terminal to start an installed application.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TerminalStartupCommand {
    pub version: u16,
    pub app_id: String,
    pub arguments: Vec<String>,
}

/// Strict terminal protocol framing, attachment, or payload validation failure.
#[derive(Debug)]
pub enum ProtocolCodecError {
    Framing(StructuredMessageError),
    WrongProtocol { expected: u32, received: u32 },
    WrongMethod { expected: u32, received: u32 },
    WrongFlags { expected: u32, received: u32 },
    TransactionMismatch { expected: u64, received: u64 },
    AttachmentCountMismatch { expected: usize, received: usize },
    InvalidAppId,
    InvalidDocumentPath,
    InvalidStartupAttachment { received: u16 },
    UnsupportedTerminalStartupVersion { expected: u16, received: u16 },
    TooManyTerminalStartupArguments { maximum: usize, received: usize },
    TerminalStartupArgumentsTooLarge { maximum: usize, received: usize },
    TerminalStartupArgumentContainsNul { index: usize },
}

impl From<StructuredMessageError> for ProtocolCodecError {
    fn from(error: StructuredMessageError) -> Self {
        Self::Framing(error)
    }
}

/// Returns whether `bytes` contains a complete RPC header identifying the launch protocol.
///
/// This is a protocol sniff only; use [`decode_launch_request`] for full frame validation.
pub fn is_launch_message(bytes: &[u8]) -> bool {
    bytes.len() >= RPC_HEADER_SIZE && bytes[8..12] == LAUNCH_PROTOCOL_ID.to_le_bytes()
}

/// Encodes one console message as an `RpcHeader` followed by its postcard payload.
pub fn encode_console_message(message: &ConsoleMessage) -> Result<Vec<u8>, ProtocolCodecError> {
    encode_structured(
        RpcHeader::new(
            TRANSACTION_ID,
            CONSOLE_PROTOCOL_ID,
            CONSOLE_MESSAGE_METHOD_ID,
            RpcFlags::ONE_WAY,
        ),
        message,
    )
    .map_err(Into::into)
}

/// Decodes and strictly validates one console channel message.
pub fn decode_console_message(
    bytes: &[u8],
    attachment_count: usize,
) -> Result<ConsoleMessage, ProtocolCodecError> {
    let (header, message) = decode_structured::<ConsoleMessage>(bytes)?;
    validate_header(&header, CONSOLE_PROTOCOL_ID, CONSOLE_MESSAGE_METHOD_ID)?;
    validate_attachment_count(CONSOLE_ATTACHMENT_COUNT, attachment_count)?;
    Ok(message)
}

/// Encodes one validated launch request as an `RpcHeader` followed by its postcard payload.
pub fn encode_launch_request(request: &LaunchRequest) -> Result<Vec<u8>, ProtocolCodecError> {
    validate_launch_request(request)?;
    encode_structured(
        RpcHeader::new(
            TRANSACTION_ID,
            LAUNCH_PROTOCOL_ID,
            LAUNCH_REQUEST_METHOD_ID,
            RpcFlags::ONE_WAY,
        ),
        request,
    )
    .map_err(Into::into)
}

/// Decodes and strictly validates one launch request with exactly one attachment.
pub fn decode_launch_request(
    bytes: &[u8],
    attachment_count: usize,
) -> Result<LaunchRequest, ProtocolCodecError> {
    let (header, request) = decode_structured::<LaunchRequest>(bytes)?;
    validate_header(&header, LAUNCH_PROTOCOL_ID, LAUNCH_REQUEST_METHOD_ID)?;
    validate_attachment_count(LAUNCH_ATTACHMENT_COUNT, attachment_count)?;
    validate_launch_request(&request)?;
    Ok(request)
}

/// Encodes one validated document startup message as an `RpcHeader` and postcard payload.
pub fn encode_open_document(document: &OpenDocument) -> Result<Vec<u8>, ProtocolCodecError> {
    validate_open_document(document)?;
    encode_structured(
        RpcHeader::new(
            TRANSACTION_ID,
            DOCUMENT_PROTOCOL_ID,
            OPEN_DOCUMENT_METHOD_ID,
            RpcFlags::ONE_WAY,
        ),
        document,
    )
    .map_err(Into::into)
}

/// Decodes and strictly validates one document startup message with no attachments.
pub fn decode_open_document(
    bytes: &[u8],
    attachment_count: usize,
) -> Result<OpenDocument, ProtocolCodecError> {
    let (header, document) = decode_structured::<OpenDocument>(bytes)?;
    validate_header(&header, DOCUMENT_PROTOCOL_ID, OPEN_DOCUMENT_METHOD_ID)?;
    validate_attachment_count(DOCUMENT_ATTACHMENT_COUNT, attachment_count)?;
    validate_open_document(&document)?;
    Ok(document)
}

/// Encodes one validated terminal startup command as an `RpcHeader` and postcard payload.
pub fn encode_terminal_startup_command(
    command: &TerminalStartupCommand,
) -> Result<Vec<u8>, ProtocolCodecError> {
    validate_terminal_startup_command(command)?;
    encode_structured(
        RpcHeader::new(
            TRANSACTION_ID,
            TERMINAL_STARTUP_PROTOCOL_ID,
            TERMINAL_STARTUP_COMMAND_METHOD_ID,
            RpcFlags::ONE_WAY,
        ),
        command,
    )
    .map_err(Into::into)
}

/// Decodes and strictly validates one terminal startup command with no attachments.
pub fn decode_terminal_startup_command(
    bytes: &[u8],
    attachment_count: usize,
) -> Result<TerminalStartupCommand, ProtocolCodecError> {
    let (header, command) = decode_structured::<TerminalStartupCommand>(bytes)?;
    validate_header(
        &header,
        TERMINAL_STARTUP_PROTOCOL_ID,
        TERMINAL_STARTUP_COMMAND_METHOD_ID,
    )?;
    validate_attachment_count(TERMINAL_STARTUP_ATTACHMENT_COUNT, attachment_count)?;
    validate_terminal_startup_command(&command)?;
    Ok(command)
}

fn validate_header(
    header: &RpcHeader,
    expected_protocol: u32,
    expected_method: u32,
) -> Result<(), ProtocolCodecError> {
    if header.protocol_id != expected_protocol {
        return Err(ProtocolCodecError::WrongProtocol {
            expected: expected_protocol,
            received: header.protocol_id,
        });
    }
    if header.method_id != expected_method {
        return Err(ProtocolCodecError::WrongMethod {
            expected: expected_method,
            received: header.method_id,
        });
    }
    if header.flags != RpcFlags::ONE_WAY.bits() {
        return Err(ProtocolCodecError::WrongFlags {
            expected: RpcFlags::ONE_WAY.bits(),
            received: header.flags,
        });
    }
    if header.transaction_id != TRANSACTION_ID {
        return Err(ProtocolCodecError::TransactionMismatch {
            expected: TRANSACTION_ID,
            received: header.transaction_id,
        });
    }
    Ok(())
}

fn validate_attachment_count(expected: usize, received: usize) -> Result<(), ProtocolCodecError> {
    if received != expected {
        return Err(ProtocolCodecError::AttachmentCountMismatch { expected, received });
    }
    Ok(())
}

fn validate_launch_request(request: &LaunchRequest) -> Result<(), ProtocolCodecError> {
    if !valid_app_id(&request.app_id) {
        return Err(ProtocolCodecError::InvalidAppId);
    }
    if request.startup_attachment != STARTUP_ATTACHMENT_INDEX {
        return Err(ProtocolCodecError::InvalidStartupAttachment {
            received: request.startup_attachment,
        });
    }
    Ok(())
}

fn validate_open_document(document: &OpenDocument) -> Result<(), ProtocolCodecError> {
    if !valid_document_path(&document.path) {
        return Err(ProtocolCodecError::InvalidDocumentPath);
    }
    Ok(())
}

fn validate_terminal_startup_command(
    command: &TerminalStartupCommand,
) -> Result<(), ProtocolCodecError> {
    if command.version != TERMINAL_STARTUP_VERSION {
        return Err(ProtocolCodecError::UnsupportedTerminalStartupVersion {
            expected: TERMINAL_STARTUP_VERSION,
            received: command.version,
        });
    }
    if !valid_app_id(&command.app_id) {
        return Err(ProtocolCodecError::InvalidAppId);
    }
    if command.arguments.len() > MAX_TERMINAL_STARTUP_ARGUMENTS {
        return Err(ProtocolCodecError::TooManyTerminalStartupArguments {
            maximum: MAX_TERMINAL_STARTUP_ARGUMENTS,
            received: command.arguments.len(),
        });
    }

    let mut total_bytes = 0usize;
    for (index, argument) in command.arguments.iter().enumerate() {
        if argument.contains('\0') {
            return Err(ProtocolCodecError::TerminalStartupArgumentContainsNul { index });
        }
        total_bytes = total_bytes.checked_add(argument.len()).ok_or(
            ProtocolCodecError::TerminalStartupArgumentsTooLarge {
                maximum: MAX_TERMINAL_STARTUP_ARGUMENT_BYTES,
                received: usize::MAX,
            },
        )?;
    }
    if total_bytes > MAX_TERMINAL_STARTUP_ARGUMENT_BYTES {
        return Err(ProtocolCodecError::TerminalStartupArgumentsTooLarge {
            maximum: MAX_TERMINAL_STARTUP_ARGUMENT_BYTES,
            received: total_bytes,
        });
    }

    Ok(())
}

fn valid_document_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_DOCUMENT_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains(['\\', '\0'])
    {
        return false;
    }

    path.split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_app_id(app_id: &str) -> bool {
    if app_id.is_empty() || app_id.len() > MAX_APP_ID_LEN {
        return false;
    }

    app_id.split('.').all(|component| {
        let bytes = component.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    fn launch_request() -> LaunchRequest {
        LaunchRequest {
            app_id: "org.ginkgo.shell-2".to_string(),
            startup_attachment: 0,
        }
    }

    fn open_document(path: &str) -> OpenDocument {
        OpenDocument {
            path: path.to_string(),
        }
    }

    fn terminal_startup_command(arguments: Vec<String>) -> TerminalStartupCommand {
        TerminalStartupCommand {
            version: TERMINAL_STARTUP_VERSION,
            app_id: "org.ginkgo.shell-2".to_string(),
            arguments,
        }
    }

    fn encode_unvalidated_terminal_startup_command(command: &TerminalStartupCommand) -> Vec<u8> {
        encode_structured(
            RpcHeader::new(
                0,
                TERMINAL_STARTUP_PROTOCOL_ID,
                TERMINAL_STARTUP_COMMAND_METHOD_ID,
                RpcFlags::ONE_WAY,
            ),
            command,
        )
        .unwrap()
    }

    fn encode_unvalidated_open_document(document: &OpenDocument) -> Vec<u8> {
        encode_structured(
            RpcHeader::new(
                0,
                DOCUMENT_PROTOCOL_ID,
                OPEN_DOCUMENT_METHOD_ID,
                RpcFlags::ONE_WAY,
            ),
            document,
        )
        .unwrap()
    }

    fn replace_u32(message: &mut [u8], offset: usize, value: u32) {
        message[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn replace_u64(message: &mut [u8], offset: usize, value: u64) {
        message[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn console_variants_round_trip_with_strict_header_and_no_attachments() {
        let messages = [
            ConsoleMessage::Input(vec![0, b'a', 0xff]),
            ConsoleMessage::Output(vec![b'o', b'k']),
            ConsoleMessage::Error(vec![b'e', b'r', b'r']),
            ConsoleMessage::Exit(-7),
        ];

        for message in messages {
            let bytes = encode_console_message(&message).unwrap();
            assert_eq!(decode_console_message(&bytes, 0).unwrap(), message);
            assert!(matches!(
                decode_console_message(&bytes, 1),
                Err(ProtocolCodecError::AttachmentCountMismatch {
                    expected: 0,
                    received: 1
                })
            ));
        }
    }

    #[test]
    fn console_decoder_rejects_header_changes() {
        let original = encode_console_message(&ConsoleMessage::Exit(0)).unwrap();
        let u32_cases = [
            (8, LAUNCH_PROTOCOL_ID, "protocol"),
            (12, 99, "method"),
            (16, RpcFlags::RESPONSE.bits(), "flags"),
        ];
        for (offset, value, kind) in u32_cases {
            let mut bytes = original.clone();
            replace_u32(&mut bytes, offset, value);
            let error = decode_console_message(&bytes, 0).unwrap_err();
            assert!(matches!(
                (kind, error),
                ("protocol", ProtocolCodecError::WrongProtocol { .. })
                    | ("method", ProtocolCodecError::WrongMethod { .. })
                    | ("flags", ProtocolCodecError::WrongFlags { .. })
            ));
        }

        let mut bytes = original;
        replace_u64(&mut bytes, 0, 1);
        assert!(matches!(
            decode_console_message(&bytes, 0),
            Err(ProtocolCodecError::TransactionMismatch {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn launch_request_round_trips_and_is_detectable() {
        let request = launch_request();
        let bytes = encode_launch_request(&request).unwrap();

        assert!(is_launch_message(&bytes));
        assert_eq!(decode_launch_request(&bytes, 1).unwrap(), request);
        assert!(!is_launch_message(
            &encode_console_message(&ConsoleMessage::Exit(0)).unwrap()
        ));
        assert!(!is_launch_message(&bytes[..RPC_HEADER_SIZE - 1]));
    }

    #[test]
    fn launch_decoder_requires_exactly_one_attachment() {
        let bytes = encode_launch_request(&launch_request()).unwrap();
        for count in [0, 2] {
            assert!(matches!(
                decode_launch_request(&bytes, count),
                Err(ProtocolCodecError::AttachmentCountMismatch {
                    expected: 1,
                    received
                }) if received == count
            ));
        }
    }

    #[test]
    fn launch_codec_rejects_nonzero_attachment_index() {
        let request = LaunchRequest {
            startup_attachment: 1,
            ..launch_request()
        };
        assert!(matches!(
            encode_launch_request(&request),
            Err(ProtocolCodecError::InvalidStartupAttachment { received: 1 })
        ));

        let bytes = encode_structured(
            RpcHeader::new(
                0,
                LAUNCH_PROTOCOL_ID,
                LAUNCH_REQUEST_METHOD_ID,
                RpcFlags::ONE_WAY,
            ),
            &request,
        )
        .unwrap();
        assert!(matches!(
            decode_launch_request(&bytes, 1),
            Err(ProtocolCodecError::InvalidStartupAttachment { received: 1 })
        ));
    }

    #[test]
    fn launch_codec_enforces_registry_app_id_syntax() {
        let invalid = [
            "",
            ".org.ginkgo",
            "org..ginkgo",
            "org.ginkgo.",
            "Org.ginkgo.files",
            "org.ginkgo.file_system",
            "org.ginkgo.-files",
            "org.ginkgo.files-",
            "org.ginkgo.café",
        ];

        for app_id in invalid {
            let request = LaunchRequest {
                app_id: app_id.to_string(),
                startup_attachment: 0,
            };
            assert!(
                matches!(
                    encode_launch_request(&request),
                    Err(ProtocolCodecError::InvalidAppId)
                ),
                "accepted {app_id:?}"
            );
        }

        let oversized_component = "a".repeat(64);
        let oversized_id = "a.".repeat(128);
        for app_id in [oversized_component, oversized_id] {
            let request = LaunchRequest {
                app_id,
                startup_attachment: 0,
            };
            assert!(matches!(
                encode_launch_request(&request),
                Err(ProtocolCodecError::InvalidAppId)
            ));
        }
    }

    #[test]
    fn launch_decoder_revalidates_untrusted_payload() {
        let request = LaunchRequest {
            app_id: "invalid_id".to_string(),
            startup_attachment: 0,
        };
        let bytes = encode_structured(
            RpcHeader::new(
                0,
                LAUNCH_PROTOCOL_ID,
                LAUNCH_REQUEST_METHOD_ID,
                RpcFlags::ONE_WAY,
            ),
            &request,
        )
        .unwrap();

        assert!(matches!(
            decode_launch_request(&bytes, 1),
            Err(ProtocolCodecError::InvalidAppId)
        ));
    }

    #[test]
    fn launch_decoder_rejects_header_changes() {
        let original = encode_launch_request(&launch_request()).unwrap();
        let u32_cases = [
            (8, CONSOLE_PROTOCOL_ID, "protocol"),
            (12, 99, "method"),
            (16, RpcFlags::empty().bits(), "flags"),
        ];
        for (offset, value, kind) in u32_cases {
            let mut bytes = original.clone();
            replace_u32(&mut bytes, offset, value);
            let error = decode_launch_request(&bytes, 1).unwrap_err();
            assert!(matches!(
                (kind, error),
                ("protocol", ProtocolCodecError::WrongProtocol { .. })
                    | ("method", ProtocolCodecError::WrongMethod { .. })
                    | ("flags", ProtocolCodecError::WrongFlags { .. })
            ));
        }

        let mut bytes = original;
        replace_u64(&mut bytes, 0, 12);
        assert!(matches!(
            decode_launch_request(&bytes, 1),
            Err(ProtocolCodecError::TransactionMismatch {
                expected: 0,
                received: 12
            })
        ));
    }

    #[test]
    fn open_document_round_trips_unicode_relative_paths() {
        for path in ["notes.txt", "docs/design/overview.md", "資料/設計書.md"] {
            let document = open_document(path);
            let bytes = encode_open_document(&document).unwrap();

            assert_eq!(decode_open_document(&bytes, 0).unwrap(), document);
        }
    }

    #[test]
    fn open_document_codec_accepts_exact_path_byte_limit() {
        let document = OpenDocument {
            path: "a".repeat(MAX_DOCUMENT_PATH_BYTES),
        };
        let bytes = encode_open_document(&document).unwrap();

        assert_eq!(decode_open_document(&bytes, 0).unwrap(), document);
    }

    #[test]
    fn open_document_codec_rejects_invalid_paths_on_encode_and_decode() {
        let oversized = "a".repeat(MAX_DOCUMENT_PATH_BYTES + 1);
        let invalid = [
            "",
            "/absolute.txt",
            "trailing/",
            "dir\\file.txt",
            "nul\0file.txt",
            "dir//file.txt",
            ".",
            "..",
            "./file.txt",
            "dir/./file.txt",
            "../file.txt",
            "dir/../file.txt",
            oversized.as_str(),
        ];

        for path in invalid {
            let document = open_document(path);
            assert!(
                matches!(
                    encode_open_document(&document),
                    Err(ProtocolCodecError::InvalidDocumentPath)
                ),
                "encoded invalid path {path:?}"
            );

            let bytes = encode_unvalidated_open_document(&document);
            assert!(
                matches!(
                    decode_open_document(&bytes, 0),
                    Err(ProtocolCodecError::InvalidDocumentPath)
                ),
                "decoded invalid path {path:?}"
            );
        }
    }

    #[test]
    fn open_document_decoder_requires_zero_attachments() {
        let bytes = encode_open_document(&open_document("notes.txt")).unwrap();

        for count in [1, 2] {
            assert!(matches!(
                decode_open_document(&bytes, count),
                Err(ProtocolCodecError::AttachmentCountMismatch {
                    expected: 0,
                    received
                }) if received == count
            ));
        }
    }

    #[test]
    fn open_document_decoder_rejects_header_changes() {
        let original = encode_open_document(&open_document("notes.txt")).unwrap();
        let u32_cases = [
            (8, LAUNCH_PROTOCOL_ID, "protocol"),
            (12, 99, "method"),
            (16, RpcFlags::RESPONSE.bits(), "flags"),
        ];
        for (offset, value, kind) in u32_cases {
            let mut bytes = original.clone();
            replace_u32(&mut bytes, offset, value);
            let error = decode_open_document(&bytes, 0).unwrap_err();
            assert!(matches!(
                (kind, error),
                ("protocol", ProtocolCodecError::WrongProtocol { .. })
                    | ("method", ProtocolCodecError::WrongMethod { .. })
                    | ("flags", ProtocolCodecError::WrongFlags { .. })
            ));
        }

        let mut bytes = original;
        replace_u64(&mut bytes, 0, 1);
        assert!(matches!(
            decode_open_document(&bytes, 0),
            Err(ProtocolCodecError::TransactionMismatch {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn terminal_startup_command_round_trips_unicode_arguments() {
        let command = terminal_startup_command(vec![
            "--title".to_string(),
            "Ginkgo notes".to_string(),
            "資料/設計書.md".to_string(),
        ]);
        let bytes = encode_terminal_startup_command(&command).unwrap();

        assert_eq!(decode_terminal_startup_command(&bytes, 0).unwrap(), command);
    }

    #[test]
    fn terminal_startup_codec_accepts_argument_limits() {
        let command =
            terminal_startup_command(vec!["x".to_string(); MAX_TERMINAL_STARTUP_ARGUMENTS]);
        let bytes = encode_terminal_startup_command(&command).unwrap();
        assert_eq!(decode_terminal_startup_command(&bytes, 0).unwrap(), command);

        let command =
            terminal_startup_command(vec!["a".repeat(MAX_TERMINAL_STARTUP_ARGUMENT_BYTES)]);
        assert!(validate_terminal_startup_command(&command).is_ok());
    }

    #[test]
    fn terminal_startup_encoder_rejects_arguments_over_total_byte_limit() {
        let command =
            terminal_startup_command(vec!["a".repeat(MAX_TERMINAL_STARTUP_ARGUMENT_BYTES + 1)]);

        assert!(matches!(
            encode_terminal_startup_command(&command),
            Err(ProtocolCodecError::TerminalStartupArgumentsTooLarge {
                maximum: MAX_TERMINAL_STARTUP_ARGUMENT_BYTES,
                received
            }) if received == MAX_TERMINAL_STARTUP_ARGUMENT_BYTES + 1
        ));
    }

    #[test]
    fn terminal_startup_codec_rejects_invalid_payloads_on_encode_and_decode() {
        let cases = [
            (
                TerminalStartupCommand {
                    version: TERMINAL_STARTUP_VERSION + 1,
                    ..terminal_startup_command(vec![])
                },
                "version",
            ),
            (
                TerminalStartupCommand {
                    app_id: "invalid_id".to_string(),
                    ..terminal_startup_command(vec![])
                },
                "app_id",
            ),
            (
                terminal_startup_command(vec![String::new(); MAX_TERMINAL_STARTUP_ARGUMENTS + 1]),
                "count",
            ),
            (
                terminal_startup_command(vec!["bad\0argument".to_string()]),
                "nul",
            ),
        ];

        for (command, kind) in cases {
            let encode_error = encode_terminal_startup_command(&command).unwrap_err();
            assert!(
                matches!(
                    (kind, &encode_error),
                    (
                        "version",
                        ProtocolCodecError::UnsupportedTerminalStartupVersion { .. }
                    ) | ("app_id", ProtocolCodecError::InvalidAppId)
                        | (
                            "count",
                            ProtocolCodecError::TooManyTerminalStartupArguments { .. }
                        )
                        | (
                            "nul",
                            ProtocolCodecError::TerminalStartupArgumentContainsNul { index: 0 }
                        )
                ),
                "wrong encode error for {kind}: {encode_error:?}"
            );

            let bytes = encode_unvalidated_terminal_startup_command(&command);
            let decode_error = decode_terminal_startup_command(&bytes, 0).unwrap_err();
            assert!(
                matches!(
                    (kind, &decode_error),
                    (
                        "version",
                        ProtocolCodecError::UnsupportedTerminalStartupVersion { .. }
                    ) | ("app_id", ProtocolCodecError::InvalidAppId)
                        | (
                            "count",
                            ProtocolCodecError::TooManyTerminalStartupArguments { .. }
                        )
                        | (
                            "nul",
                            ProtocolCodecError::TerminalStartupArgumentContainsNul { index: 0 }
                        )
                ),
                "wrong decode error for {kind}: {decode_error:?}"
            );
        }
    }

    #[test]
    fn terminal_startup_decoder_requires_zero_attachments() {
        let bytes = encode_terminal_startup_command(&terminal_startup_command(vec![])).unwrap();

        assert!(matches!(
            decode_terminal_startup_command(&bytes, 1),
            Err(ProtocolCodecError::AttachmentCountMismatch {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn terminal_startup_decoder_rejects_header_changes() {
        let original = encode_terminal_startup_command(&terminal_startup_command(vec![])).unwrap();
        let u32_cases = [
            (8, LAUNCH_PROTOCOL_ID, "protocol"),
            (12, 99, "method"),
            (16, RpcFlags::RESPONSE.bits(), "flags"),
        ];
        for (offset, value, kind) in u32_cases {
            let mut bytes = original.clone();
            replace_u32(&mut bytes, offset, value);
            let error = decode_terminal_startup_command(&bytes, 0).unwrap_err();
            assert!(matches!(
                (kind, error),
                ("protocol", ProtocolCodecError::WrongProtocol { .. })
                    | ("method", ProtocolCodecError::WrongMethod { .. })
                    | ("flags", ProtocolCodecError::WrongFlags { .. })
            ));
        }

        let mut bytes = original;
        replace_u64(&mut bytes, 0, 1);
        assert!(matches!(
            decode_terminal_startup_command(&bytes, 0),
            Err(ProtocolCodecError::TransactionMismatch {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn malformed_structured_frames_are_rejected() {
        assert!(matches!(
            decode_console_message(&[0; RPC_HEADER_SIZE - 1], 0),
            Err(ProtocolCodecError::Framing(
                StructuredMessageError::HeaderTooShort
            ))
        ));

        let mut bytes = encode_launch_request(&launch_request()).unwrap();
        bytes.push(0);
        assert!(matches!(
            decode_launch_request(&bytes, 1),
            Err(ProtocolCodecError::Framing(
                StructuredMessageError::PayloadLengthMismatch
            ))
        ));
    }
}
