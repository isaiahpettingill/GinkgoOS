use alloc::vec::Vec;
use core::convert::Infallible;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::NonNull;

use ginkgo_window::{
    decode_event, encode_request, ChannelCodecError, ConfigurationError, Received, SharedSurface,
    Transport, WireEvent, WireRequest,
};

use crate::{
    channel_read, channel_write, handle_close, shared_memory_get_size, shared_memory_map,
    shared_memory_unmap, Handle, MapFlags, MapProtection, ObjectType, ReceivedHandle, Rights,
    Status, SyscallResult, CHANNEL_MAX_BYTES, CHANNEL_MAX_HANDLES,
};

const SURFACE_RIGHTS: Rights =
    Rights::from_bits_retain(Rights::READ.bits() | Rights::WRITE.bits() | Rights::MAP.bits());

type CloseFn = fn(Handle) -> SyscallResult<()>;
type UnmapFn = unsafe fn(NonNull<u8>, usize) -> SyscallResult<()>;

/// Invalid attachment metadata on a received window event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowAttachmentError {
    UnexpectedCount { expected: usize, received: usize },
    InvalidSurfaceHandleIndex { received: u16 },
    InvalidHandle,
    NonzeroReserved { received: u32 },
    WrongObjectType { received: ObjectType },
    UnknownRights { received: u32 },
    MissingSurfaceRights { required: Rights, received: Rights },
    ManageRight,
}

/// Failure while framing, receiving, or mapping a window protocol message.
#[derive(Debug)]
pub enum WindowTransportError {
    InvalidChannelHandle,
    Syscall(Status),
    Codec(ChannelCodecError),
    Attachments(WindowAttachmentError),
    InvalidConfiguration(ConfigurationError),
    SurfaceTooLarge,
    SurfaceTooShort { required: usize, available: u64 },
}

impl From<Status> for WindowTransportError {
    fn from(status: Status) -> Self {
        Self::Syscall(status)
    }
}

impl From<ChannelCodecError> for WindowTransportError {
    fn from(error: ChannelCodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<WindowAttachmentError> for WindowTransportError {
    fn from(error: WindowAttachmentError) -> Self {
        Self::Attachments(error)
    }
}

/// Validates event attachment counts, object type, rights, and reserved fields.
///
/// `Configured` is the only event allowed to carry a handle. It must carry
/// exactly one shared-memory handle at index zero with `READ | WRITE | MAP` and
/// without `MANAGE`. Other known rights may be present.
pub fn validate_window_event_attachments(
    event: &WireEvent,
    handles: &[ReceivedHandle],
) -> Result<(), WindowAttachmentError> {
    let WireEvent::Configured(configured) = event else {
        return validate_count(0, handles.len());
    };

    validate_count(1, handles.len())?;
    if configured.surface_handle_index != 0 {
        return Err(WindowAttachmentError::InvalidSurfaceHandleIndex {
            received: configured.surface_handle_index,
        });
    }

    let received = handles[0];
    if !received.handle.is_valid() {
        return Err(WindowAttachmentError::InvalidHandle);
    }
    if received.reserved != 0 {
        return Err(WindowAttachmentError::NonzeroReserved {
            received: received.reserved,
        });
    }
    if received.object_type != ObjectType::SharedMemory {
        return Err(WindowAttachmentError::WrongObjectType {
            received: received.object_type,
        });
    }
    let unknown_rights = received.rights.bits() & !Rights::all().bits();
    if unknown_rights != 0 {
        return Err(WindowAttachmentError::UnknownRights {
            received: received.rights.bits(),
        });
    }
    if !received.rights.contains(SURFACE_RIGHTS) {
        return Err(WindowAttachmentError::MissingSurfaceRights {
            required: SURFACE_RIGHTS,
            received: received.rights,
        });
    }
    if received.rights.contains(Rights::MANAGE) {
        return Err(WindowAttachmentError::ManageRight);
    }
    Ok(())
}

fn validate_count(expected: usize, received: usize) -> Result<(), WindowAttachmentError> {
    if received != expected {
        return Err(WindowAttachmentError::UnexpectedCount { expected, received });
    }
    Ok(())
}

/// A writable mapping of one complete configured shared surface pool.
pub struct MappedSurface {
    handle: Handle,
    address: NonNull<u8>,
    length: usize,
    unmap: UnmapFn,
    close: CloseFn,
}

impl MappedSurface {
    fn from_mapping(handle: Handle, address: NonNull<u8>, length: usize) -> Self {
        Self::from_mapping_with(handle, address, length, shared_memory_unmap, handle_close)
    }

    fn from_mapping_with(
        handle: Handle,
        address: NonNull<u8>,
        length: usize,
        unmap: UnmapFn,
        close: CloseFn,
    ) -> Self {
        Self {
            handle,
            address,
            length,
            unmap,
            close,
        }
    }
}

impl SharedSurface for MappedSurface {
    type Error = Infallible;

    fn len(&self) -> usize {
        self.length
    }

    fn bytes_mut(&mut self) -> Result<&mut [u8], Self::Error> {
        // SAFETY: this type exclusively owns a live writable mapping for its
        // entire lifetime. It is not Clone, and this mutable borrow prevents
        // overlapping slices from being produced through this API.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length) })
    }
}

impl Drop for MappedSurface {
    fn drop(&mut self) {
        // SAFETY: this exact range was installed when the surface was created,
        // and Drop has exclusive access so no safe borrows into it remain.
        let _ = unsafe { (self.unmap)(self.address, self.length) };
        let _ = (self.close)(self.handle);
    }
}

/// Syscall-backed channel transport for [`ginkgo_window::WindowClient`].
pub struct WindowTransport {
    channel: Handle,
    close: CloseFn,
}

impl WindowTransport {
    /// Takes ownership of a channel endpoint.
    pub fn new(channel: Handle) -> Result<Self, WindowTransportError> {
        if !channel.is_valid() {
            return Err(WindowTransportError::InvalidChannelHandle);
        }
        Ok(Self {
            channel,
            close: handle_close,
        })
    }

    /// Returns the owned channel value without transferring its ownership.
    pub const fn channel(&self) -> Handle {
        self.channel
    }

    /// Returns the channel to the caller without closing it.
    pub fn into_channel(self) -> Handle {
        let this = ManuallyDrop::new(self);
        this.channel
    }
}

impl Transport for WindowTransport {
    type Error = WindowTransportError;
    type Surface = MappedSurface;

    fn send(&mut self, request: &WireRequest) -> Result<(), Self::Error> {
        let message = encode_request(request)?;
        channel_write(self.channel, &message, &[])?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<Received<Self::Surface>>, Self::Error> {
        let mut bytes = [0_u8; CHANNEL_MAX_BYTES];
        let mut uninitialized_handles =
            [MaybeUninit::<ReceivedHandle>::uninit(); CHANNEL_MAX_HANDLES];
        let message = match channel_read(self.channel, &mut bytes, &mut uninitialized_handles) {
            Ok(message) => message,
            Err(Status::ShouldWait) => return Ok(None),
            Err(status) => return Err(status.into()),
        };

        let byte_count = message.byte_count as usize;
        let handle_count = usize::from(message.handle_count);
        let mut handles = Vec::with_capacity(handle_count);
        for handle in &uninitialized_handles[..handle_count] {
            // SAFETY: channel_read guarantees exactly handle_count entries were
            // initialized after a successful call.
            handles.push(unsafe { handle.assume_init() });
        }

        let event = match decode_event(&bytes[..byte_count], handle_count) {
            Ok(event) => event,
            Err(error) => {
                close_received_handles(&handles);
                return Err(error.into());
            }
        };
        if let Err(error) = validate_window_event_attachments(&event, &handles) {
            close_received_handles(&handles);
            return Err(error.into());
        }

        let surfaces = match event {
            WireEvent::Configured(ref configured) => alloc::vec![map_configured_surface(
                configured.configuration,
                handles[0].handle,
            )?],
            _ => Vec::new(),
        };
        Ok(Some(Received::new(event, surfaces)))
    }
}

impl Drop for WindowTransport {
    fn drop(&mut self) {
        let _ = (self.close)(self.channel);
    }
}

fn map_configured_surface(
    configuration: ginkgo_window::SurfaceConfiguration,
    handle: Handle,
) -> Result<MappedSurface, WindowTransportError> {
    let pending = PendingHandle::new(handle);
    configuration
        .validate()
        .map_err(WindowTransportError::InvalidConfiguration)?;
    let length = configuration
        .required_surface_bytes()
        .ok_or(WindowTransportError::SurfaceTooLarge)?;
    if length > isize::MAX as usize {
        return Err(WindowTransportError::SurfaceTooLarge);
    }

    let available = shared_memory_get_size(handle)?;
    if u64::try_from(length).map_or(true, |required| available < required) {
        return Err(WindowTransportError::SurfaceTooShort {
            required: length,
            available,
        });
    }

    // SAFETY: attachment validation established MAP authority. The resulting
    // range is exclusively owned by MappedSurface and uses no fixed address.
    let address = unsafe {
        shared_memory_map(
            handle,
            0,
            length,
            None,
            MapProtection::READ | MapProtection::WRITE,
            MapFlags::empty(),
        )
    }?;
    Ok(MappedSurface::from_mapping(
        pending.release(),
        address,
        length,
    ))
}

struct PendingHandle {
    handle: Handle,
}

impl PendingHandle {
    const fn new(handle: Handle) -> Self {
        Self { handle }
    }

    fn release(self) -> Handle {
        let this = ManuallyDrop::new(self);
        this.handle
    }
}

impl Drop for PendingHandle {
    fn drop(&mut self) {
        if self.handle.is_valid() {
            let _ = handle_close(self.handle);
        }
    }
}

fn close_received_handles(handles: &[ReceivedHandle]) {
    close_received_handles_with(handles, handle_close);
}

fn close_received_handles_with(handles: &[ReceivedHandle], close: CloseFn) {
    for received in handles {
        if received.handle.is_valid() {
            let _ = close(received.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use ginkgo_window::{
        Configured, Generation, PixelFormat, ScaleFactor, Size, SurfaceConfiguration, WindowId,
    };

    static CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DROP_STAGE: AtomicUsize = AtomicUsize::new(0);

    fn window_id() -> WindowId {
        WindowId::new(8).unwrap()
    }

    fn configuration() -> SurfaceConfiguration {
        SurfaceConfiguration {
            logical_size: Size::new(4, 2),
            pixel_size: Size::new(4, 2),
            stride: 16,
            format: PixelFormat::Xrgb8888,
            scale: ScaleFactor::new(1, 1).unwrap(),
            generation: Generation::new(1).unwrap(),
            buffer_count: 2,
        }
    }

    fn configured() -> WireEvent {
        WireEvent::Configured(Configured {
            window_id: window_id(),
            configuration: configuration(),
            surface_handle_index: 0,
        })
    }

    fn received_handle(object_type: ObjectType, rights: Rights) -> ReceivedHandle {
        ReceivedHandle {
            handle: Handle::from_raw(10),
            rights,
            object_type,
            reserved: 0,
        }
    }

    fn fake_close(_: Handle) -> SyscallResult<()> {
        CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    unsafe fn fake_unmap(_: NonNull<u8>, _: usize) -> SyscallResult<()> {
        assert_eq!(DROP_STAGE.swap(1, Ordering::SeqCst), 0);
        Ok(())
    }

    fn ordered_close(_: Handle) -> SyscallResult<()> {
        assert_eq!(DROP_STAGE.swap(2, Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn configured_accepts_exactly_one_attenuated_shared_memory_handle() {
        let handle = received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS);
        assert_eq!(
            validate_window_event_attachments(&configured(), &[handle]),
            Ok(())
        );

        let extra_known_rights = SURFACE_RIGHTS | Rights::WAIT | Rights::TRANSFER;
        let handle = received_handle(ObjectType::SharedMemory, extra_known_rights);
        assert_eq!(
            validate_window_event_attachments(&configured(), &[handle]),
            Ok(())
        );
    }

    #[test]
    fn every_non_configured_event_rejects_handles() {
        let event = WireEvent::CloseRequested {
            window_id: window_id(),
        };
        let handle = received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS);
        assert_eq!(
            validate_window_event_attachments(&event, &[handle]),
            Err(WindowAttachmentError::UnexpectedCount {
                expected: 0,
                received: 1,
            })
        );
    }

    #[test]
    fn configured_rejects_wrong_count_index_type_and_metadata() {
        assert_eq!(
            validate_window_event_attachments(&configured(), &[]),
            Err(WindowAttachmentError::UnexpectedCount {
                expected: 1,
                received: 0,
            })
        );
        let two = [
            received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS),
            received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS),
        ];
        assert_eq!(
            validate_window_event_attachments(&configured(), &two),
            Err(WindowAttachmentError::UnexpectedCount {
                expected: 1,
                received: 2,
            })
        );

        let invalid_index = WireEvent::Configured(Configured {
            window_id: window_id(),
            configuration: configuration(),
            surface_handle_index: 1,
        });
        assert_eq!(
            validate_window_event_attachments(&invalid_index, &two[..1]),
            Err(WindowAttachmentError::InvalidSurfaceHandleIndex { received: 1 })
        );

        let invalid = ReceivedHandle {
            handle: Handle::INVALID,
            ..two[0]
        };
        assert_eq!(
            validate_window_event_attachments(&configured(), &[invalid]),
            Err(WindowAttachmentError::InvalidHandle)
        );
        let reserved = ReceivedHandle {
            reserved: 9,
            ..two[0]
        };
        assert_eq!(
            validate_window_event_attachments(&configured(), &[reserved]),
            Err(WindowAttachmentError::NonzeroReserved { received: 9 })
        );
        let channel = received_handle(ObjectType::Channel, SURFACE_RIGHTS);
        assert_eq!(
            validate_window_event_attachments(&configured(), &[channel]),
            Err(WindowAttachmentError::WrongObjectType {
                received: ObjectType::Channel
            })
        );
    }

    #[test]
    fn configured_requires_read_write_map_and_forbids_manage() {
        for missing in [Rights::READ, Rights::WRITE, Rights::MAP] {
            let rights = SURFACE_RIGHTS.difference(missing);
            let handle = received_handle(ObjectType::SharedMemory, rights);
            assert!(matches!(
                validate_window_event_attachments(&configured(), &[handle]),
                Err(WindowAttachmentError::MissingSurfaceRights { .. })
            ));
        }

        let handle = received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS | Rights::MANAGE);
        assert_eq!(
            validate_window_event_attachments(&configured(), &[handle]),
            Err(WindowAttachmentError::ManageRight)
        );

        let unknown = Rights::from_bits_retain(SURFACE_RIGHTS.bits() | (1 << 31));
        let handle = received_handle(ObjectType::SharedMemory, unknown);
        assert_eq!(
            validate_window_event_attachments(&configured(), &[handle]),
            Err(WindowAttachmentError::UnknownRights {
                received: unknown.bits()
            })
        );
    }

    #[test]
    fn cleanup_closes_every_valid_unexpected_handle() {
        CLOSE_COUNT.store(0, Ordering::SeqCst);
        let handles = vec![
            received_handle(ObjectType::Channel, Rights::READ),
            ReceivedHandle {
                handle: Handle::INVALID,
                rights: Rights::empty(),
                object_type: ObjectType::Channel,
                reserved: 0,
            },
            ReceivedHandle {
                handle: Handle::from_raw(12),
                ..received_handle(ObjectType::SharedMemory, SURFACE_RIGHTS)
            },
        ];
        close_received_handles_with(&handles, fake_close);
        assert_eq!(CLOSE_COUNT.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn mapped_surface_exposes_full_mapping_then_unmaps_before_closing() {
        let mut bytes = vec![0_u8; configuration().required_surface_bytes().unwrap()];
        DROP_STAGE.store(0, Ordering::SeqCst);
        {
            let address = NonNull::new(bytes.as_mut_ptr()).unwrap();
            let mut surface = MappedSurface::from_mapping_with(
                Handle::from_raw(20),
                address,
                bytes.len(),
                fake_unmap,
                ordered_close,
            );
            assert_eq!(surface.len(), bytes.len());
            surface.bytes_mut().unwrap()[bytes.len() - 1] = 0x5a;
        }
        assert_eq!(bytes[bytes.len() - 1], 0x5a);
        assert_eq!(DROP_STAGE.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn transport_rejects_an_invalid_channel_handle() {
        assert!(matches!(
            WindowTransport::new(Handle::INVALID),
            Err(WindowTransportError::InvalidChannelHandle)
        ));
    }
}
