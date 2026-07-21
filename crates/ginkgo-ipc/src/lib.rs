#![no_std]
#![cfg_attr(feature = "kernel", feature(allocator_api))]

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
    OutOfMemory,
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
    let maximum_payload = CHANNEL_MAX_BYTES - RPC_HEADER_SIZE;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(maximum_payload)
        .map_err(|_| StructuredMessageError::OutOfMemory)?;
    payload.resize(maximum_payload, 0);
    let payload_len = match postcard::to_slice(value, &mut payload) {
        Ok(payload) => payload.len(),
        Err(postcard::Error::SerializeBufferFull) => {
            return Err(StructuredMessageError::PayloadTooLarge);
        }
        Err(error) => return Err(StructuredMessageError::Postcard(error)),
    };
    payload.truncate(payload_len);

    let total = RPC_HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(StructuredMessageError::PayloadTooLarge)?;
    header.payload_length =
        u32::try_from(payload_len).map_err(|_| StructuredMessageError::PayloadTooLarge)?;

    let mut message = Vec::new();
    message
        .try_reserve_exact(total)
        .map_err(|_| StructuredMessageError::OutOfMemory)?;
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
