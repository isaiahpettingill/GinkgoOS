#![no_std]

//! Shared foundations for future GinkgoOS userspace programs.
//!
//! Actual syscall stubs will be added once the kernel has a userspace entry
//! path. For now this crate exposes the stable ABI and structured IPC codec
//! without depending on kernel implementation details.

pub use ginkgo_ipc::{decode_structured, encode_structured, StructuredMessageError};
pub use ginkgo_sysapi::*;
pub use ginkgo_window as window;
