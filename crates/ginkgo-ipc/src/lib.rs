#![no_std]

//! Zircon-style channels and the shared structured-message wire codec.

extern crate alloc;

use alloc::vec::Vec;

use ginkgo_sysapi::{RpcHeader, CHANNEL_MAX_BYTES, RPC_HEADER_SIZE};
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, IntoBytes};

pub use ginkgo_sysapi;
pub use ginkgo_sysapi::{
    Handle, MessageInfo, ObjectType, Rights, RpcFlags, Signals, Status, WaitItem,
};

#[cfg(feature = "kernel")]
mod kernel;
#[cfg(feature = "kernel")]
pub use kernel::*;

/// Structured-message framing or postcard payload failure.
#[derive(Debug)]
pub enum StructuredMessageError {
    HeaderTooShort,
    PayloadTooLarge,
    PayloadLengthMismatch,
    Postcard(postcard::Error),
}

impl From<postcard::Error> for StructuredMessageError {
    fn from(error: postcard::Error) -> Self {
        Self::Postcard(error)
    }
}

/// Encodes a zerocopy RPC header followed by a postcard payload.
pub fn encode_structured<T: Serialize + ?Sized>(
    mut header: RpcHeader,
    value: &T,
) -> Result<Vec<u8>, StructuredMessageError> {
    let payload = postcard::to_allocvec(value)?;
    let total = RPC_HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(StructuredMessageError::PayloadTooLarge)?;
    if total > CHANNEL_MAX_BYTES {
        return Err(StructuredMessageError::PayloadTooLarge);
    }
    header.payload_length =
        u32::try_from(payload.len()).map_err(|_| StructuredMessageError::PayloadTooLarge)?;

    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(header.as_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

/// Decodes a zerocopy RPC header and borrows its postcard payload.
pub fn decode_structured<'a, T: Deserialize<'a>>(
    message: &'a [u8],
) -> Result<(RpcHeader, T), StructuredMessageError> {
    if message.len() < RPC_HEADER_SIZE {
        return Err(StructuredMessageError::HeaderTooShort);
    }
    let (header, payload) =
        RpcHeader::read_from_prefix(message).map_err(|_| StructuredMessageError::HeaderTooShort)?;
    if header.payload_length as usize != payload.len() {
        return Err(StructuredMessageError::PayloadLengthMismatch);
    }
    let value = postcard::from_bytes(payload)?;
    Ok((header, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct OpenRequest<'a> {
        path: &'a str,
        options: u32,
    }

    #[test]
    fn postcard_payload_round_trips_after_zerocopy_header() {
        let header = RpcHeader::new(42, 7, 3, RpcFlags::empty());
        let request = OpenRequest {
            path: "/System/config",
            options: 1,
        };
        let bytes = encode_structured(header, &request).unwrap();
        let (decoded_header, decoded): (RpcHeader, OpenRequest<'_>) =
            decode_structured(&bytes).unwrap();

        assert_eq!(decoded_header.transaction_id, 42);
        assert_eq!(decoded_header.protocol_id, 7);
        assert_eq!(decoded_header.method_id, 3);
        assert_eq!(
            decoded_header.payload_length as usize,
            bytes.len() - RPC_HEADER_SIZE
        );
        assert_eq!(decoded, request);
    }

    #[test]
    fn rejects_truncated_and_mismatched_frames() {
        assert!(matches!(
            decode_structured::<OpenRequest<'_>>(&[0; RPC_HEADER_SIZE - 1]),
            Err(StructuredMessageError::HeaderTooShort)
        ));

        let mut bytes = encode_structured(
            RpcHeader::new(1, 2, 3, RpcFlags::empty()),
            &OpenRequest {
                path: "/x",
                options: 0,
            },
        )
        .unwrap();
        bytes.push(0);
        assert!(matches!(
            decode_structured::<OpenRequest<'_>>(&bytes),
            Err(StructuredMessageError::PayloadLengthMismatch)
        ));
    }
}
