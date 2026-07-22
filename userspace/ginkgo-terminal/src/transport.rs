extern crate alloc;

use alloc::{collections::VecDeque, string::String, vec, vec::Vec};
use core::mem::MaybeUninit;

use ginkgo_terminal_protocol::{
    decode_console_message, encode_console_message, encode_launch_request, ConsoleMessage,
    LaunchRequest,
};
use ginkgo_userspace::{
    channel_read, channel_write, handle_close, DispositionOperation, Handle, HandleDisposition,
    Rights, Status, CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES,
};

const CHILD_CHANNEL_RIGHTS: Rights = Rights::from_bits_retain(
    Rights::READ.bits() | Rights::WRITE.bits() | Rights::WAIT.bits() | Rights::TRANSFER.bits(),
);

pub struct PendingSend {
    channel: Handle,
    bytes: Vec<u8>,
    moved_handle: Option<Handle>,
}

impl PendingSend {
    pub fn console(channel: Handle, message: &ConsoleMessage) -> Result<Self, ()> {
        Ok(Self {
            channel,
            bytes: encode_console_message(message).map_err(|_| ())?,
            moved_handle: None,
        })
    }

    pub fn launch(desktop: Handle, app_id: String, child_endpoint: Handle) -> Result<Self, ()> {
        let request = LaunchRequest {
            app_id,
            startup_attachment: 0,
        };
        Ok(Self {
            channel: desktop,
            bytes: encode_launch_request(&request).map_err(|_| ())?,
            moved_handle: Some(child_endpoint),
        })
    }
}

pub fn flush(queue: &mut VecDeque<PendingSend>) -> bool {
    let mut changed = false;
    while let Some(pending) = queue.front() {
        let disposition = pending.moved_handle.map(|handle| HandleDisposition {
            handle,
            operation: DispositionOperation::Move,
            rights: CHILD_CHANNEL_RIGHTS,
            reserved: 0,
        });
        let dispositions = disposition.as_slice();
        match channel_write(pending.channel, &pending.bytes, dispositions) {
            Ok(()) => {
                queue.pop_front();
                changed = true;
            }
            Err(Status::ShouldWait) => break,
            Err(_) => {
                if let Some(handle) = pending.moved_handle {
                    let _ = handle_close(handle);
                }
                queue.pop_front();
                changed = true;
            }
        }
    }
    changed
}

pub enum DrainResult {
    Empty,
    Closed,
    Message(ConsoleMessage),
    Invalid,
}

pub fn read_console(channel: Handle) -> DrainResult {
    let mut bytes = vec![0; CHANNEL_MAX_BYTES];
    let mut handles = [MaybeUninit::uninit(); CHANNEL_MAX_HANDLES];
    let info = match channel_read(channel, &mut bytes, &mut handles) {
        Ok(info) => info,
        Err(Status::ShouldWait) => return DrainResult::Empty,
        Err(Status::PeerClosed) | Err(Status::InvalidHandle) => return DrainResult::Closed,
        Err(_) => return DrainResult::Invalid,
    };
    bytes.truncate(info.byte_count as usize);
    if info.handle_count != 0 {
        for handle in handles.iter().take(info.handle_count as usize) {
            // SAFETY: channel_read initialized the reported prefix.
            let received = unsafe { handle.assume_init() };
            let _ = handle_close(received.handle);
        }
        return DrainResult::Invalid;
    }
    match decode_console_message(&bytes, 0) {
        Ok(message) => DrainResult::Message(message),
        Err(_) => DrainResult::Invalid,
    }
}
