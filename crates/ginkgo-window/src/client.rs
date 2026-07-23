use alloc::{string::String, vec, vec::Vec};

use ginkgo_graphics::{PixelSurface, SurfaceError};

use crate::{
    BufferId, ConfigurationError, Configured, Event, Generation, Rect, RequestId,
    RequestValidationError, Size, SurfaceConfiguration, WindowId, WindowOptions,
    WindowOptionsError, WireEvent, WireRequest, MAX_CLIPBOARD_BYTES, PROTOCOL_VERSION,
};

/// One received protocol event and its transport-provided surface attachments.
pub struct Received<S> {
    pub event: WireEvent,
    pub surface_handles: Vec<S>,
}

impl<S> Received<S> {
    pub fn new(event: WireEvent, surface_handles: Vec<S>) -> Self {
        Self {
            event,
            surface_handles,
        }
    }
}

/// A mapped shared-memory surface supplied by a transport implementation.
///
/// A syscall-backed implementation can map a received VM object lazily. Tests
/// and pre-syscall clients can simply use an owned byte vector.
pub trait SharedSurface {
    type Error;

    fn len(&self) -> usize;
    fn bytes_mut(&mut self) -> Result<&mut [u8], Self::Error>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Transport operations needed by the window state machine.
pub trait Transport {
    type Error;
    type Surface: SharedSurface;

    fn send(&mut self, request: &WireRequest) -> Result<(), Self::Error>;
    fn receive(&mut self) -> Result<Option<Received<Self::Surface>>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    CreateAlreadyPending,
    WindowAlreadyCreated,
    NoWindow,
    UnexpectedCreateReply {
        expected: Option<RequestId>,
        received: RequestId,
    },
    ProtocolVersionMismatch {
        expected: u16,
        received: u16,
    },
    WrongWindow {
        expected: WindowId,
        received: WindowId,
    },
    MissingSurfaceHandle {
        index: u16,
    },
    InvalidConfiguration(ConfigurationError),
    StaleGeneration {
        current: Generation,
        received: Generation,
    },
    UnknownGeneration(Generation),
    UnknownBuffer {
        generation: Generation,
        buffer_id: BufferId,
    },
    BufferNotPresented {
        generation: Generation,
        buffer_id: BufferId,
    },
    PresentRequestMismatch {
        expected: RequestId,
        received: RequestId,
    },
    RequestIdExhausted,
    ClipboardTooLarge,
}

#[derive(Debug)]
pub enum ClientError<E> {
    Transport(E),
    InvalidOptions(WindowOptionsError),
    InvalidRequest(RequestValidationError),
    Protocol(ProtocolError),
}

impl<E> From<ProtocolError> for ClientError<E> {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug)]
pub enum SurfaceAccessError<E> {
    Surface(E),
    SurfaceTooShort,
    InvalidConfiguration(ConfigurationError),
    InvalidPixelSurface(SurfaceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BufferState {
    Available,
    Acquired,
    Presented(RequestId),
}

struct BufferPool<S> {
    configuration: SurfaceConfiguration,
    surface: S,
    buffers: Vec<BufferState>,
}

impl<S> BufferPool<S> {
    fn has_presented_buffers(&self) -> bool {
        self.buffers
            .iter()
            .any(|state| matches!(state, BufferState::Presented(_)))
    }
}

/// Transport-independent state for one window connection.
pub struct WindowClient<T: Transport> {
    transport: T,
    next_request_id: Option<RequestId>,
    pending_create: Option<RequestId>,
    window_id: Option<WindowId>,
    active_generation: Option<Generation>,
    pools: Vec<BufferPool<T::Surface>>,
}

impl<T: Transport> WindowClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_request_id: RequestId::new(1),
            pending_create: None,
            window_id: None,
            active_generation: None,
            pools: Vec::new(),
        }
    }

    pub const fn window_id(&self) -> Option<WindowId> {
        self.window_id
    }

    pub fn active_configuration(&self) -> Option<SurfaceConfiguration> {
        let generation = self.active_generation?;
        self.pool(generation).map(|pool| pool.configuration)
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn create_window(
        &mut self,
        options: WindowOptions,
    ) -> Result<RequestId, ClientError<T::Error>> {
        options.validate().map_err(ClientError::InvalidOptions)?;
        if self.pending_create.is_some() {
            return Err(ProtocolError::CreateAlreadyPending.into());
        }
        if self.window_id.is_some() {
            return Err(ProtocolError::WindowAlreadyCreated.into());
        }

        let request_id = self.allocate_request_id()?;
        self.transport
            .send(&WireRequest::CreateWindow {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                options,
            })
            .map_err(ClientError::Transport)?;
        self.pending_create = Some(request_id);
        Ok(request_id)
    }

    pub fn destroy_window(&mut self) -> Result<RequestId, ClientError<T::Error>> {
        self.send_window_request(|request_id, window_id| WireRequest::DestroyWindow {
            request_id,
            window_id,
        })
    }

    /// Requests a new logical size. The active size changes only after a
    /// subsequent [`Event::Configured`].
    pub fn request_size(
        &mut self,
        preferred_size: Size,
    ) -> Result<RequestId, ClientError<T::Error>> {
        if preferred_size.is_empty() {
            return Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyPreferredSize,
            ));
        }
        self.send_window_request(|request_id, window_id| WireRequest::RequestSize {
            request_id,
            window_id,
            preferred_size,
        })
    }

    pub fn set_minimum_size(
        &mut self,
        minimum_size: Option<Size>,
    ) -> Result<RequestId, ClientError<T::Error>> {
        if minimum_size.is_some_and(Size::is_empty) {
            return Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyMinimumSize,
            ));
        }
        self.send_window_request(|request_id, window_id| WireRequest::SetMinimumSize {
            request_id,
            window_id,
            minimum_size,
        })
    }

    pub fn set_maximum_size(
        &mut self,
        maximum_size: Option<Size>,
    ) -> Result<RequestId, ClientError<T::Error>> {
        if maximum_size.is_some_and(Size::is_empty) {
            return Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyMaximumSize,
            ));
        }
        self.send_window_request(|request_id, window_id| WireRequest::SetMaximumSize {
            request_id,
            window_id,
            maximum_size,
        })
    }

    pub fn set_fullscreen(&mut self, fullscreen: bool) -> Result<RequestId, ClientError<T::Error>> {
        self.send_window_request(|request_id, window_id| WireRequest::SetFullscreen {
            request_id,
            window_id,
            fullscreen,
        })
    }

    pub fn toggle_fullscreen(&mut self) -> Result<RequestId, ClientError<T::Error>> {
        self.send_window_request(|request_id, window_id| WireRequest::ToggleFullscreen {
            request_id,
            window_id,
        })
    }

    /// Replaces the shared desktop clipboard with bounded UTF-8 text.
    pub fn set_clipboard_text(&mut self, text: String) -> Result<RequestId, ClientError<T::Error>> {
        if text.len() > MAX_CLIPBOARD_BYTES {
            return Err(ClientError::InvalidRequest(
                RequestValidationError::ClipboardTooLarge,
            ));
        }
        self.send_window_request(|request_id, window_id| WireRequest::SetClipboardText {
            request_id,
            window_id,
            text,
        })
    }

    /// Requests the current shared desktop clipboard text.
    pub fn request_clipboard_text(&mut self) -> Result<RequestId, ClientError<T::Error>> {
        self.send_window_request(|request_id, window_id| WireRequest::RequestClipboardText {
            request_id,
            window_id,
        })
    }

    /// Receives and processes at most one wire event.
    pub fn poll_event(&mut self) -> Result<Option<Event>, ClientError<T::Error>> {
        let received = self.transport.receive().map_err(ClientError::Transport)?;
        received
            .map(|received| self.process_received(received))
            .transpose()
    }

    /// Processes an already-received event, useful for transports that integrate
    /// receiving into a larger event loop.
    pub fn process_received(
        &mut self,
        received: Received<T::Surface>,
    ) -> Result<Event, ClientError<T::Error>> {
        let Received {
            event,
            surface_handles,
        } = received;
        match event {
            WireEvent::WindowCreated {
                protocol_version,
                request_id,
                window_id,
            } => {
                if self.pending_create != Some(request_id) {
                    return Err(ProtocolError::UnexpectedCreateReply {
                        expected: self.pending_create,
                        received: request_id,
                    }
                    .into());
                }
                if protocol_version != PROTOCOL_VERSION {
                    self.pending_create = None;
                    return Err(ProtocolError::ProtocolVersionMismatch {
                        expected: PROTOCOL_VERSION,
                        received: protocol_version,
                    }
                    .into());
                }
                if self.window_id.is_some() {
                    return Err(ProtocolError::WindowAlreadyCreated.into());
                }
                self.pending_create = None;
                self.window_id = Some(window_id);
                Ok(Event::WindowCreated {
                    request_id,
                    window_id,
                })
            }
            WireEvent::Configured(configured) => {
                self.apply_configuration(configured, surface_handles)
            }
            WireEvent::BufferReleased {
                window_id,
                generation,
                buffer_id,
                present_request_id,
            } => {
                self.validate_window(window_id)?;
                self.release_buffer(generation, buffer_id, present_request_id)?;
                Ok(Event::BufferReleased {
                    window_id,
                    generation,
                    buffer_id,
                    present_request_id,
                })
            }
            WireEvent::Redraw { window_id, damage } => {
                self.validate_window(window_id)?;
                Ok(Event::Redraw { window_id, damage })
            }
            WireEvent::Pointer { window_id, event } => {
                self.validate_window(window_id)?;
                Ok(Event::Pointer { window_id, event })
            }
            WireEvent::Keyboard { window_id, event } => {
                self.validate_window(window_id)?;
                Ok(Event::Keyboard { window_id, event })
            }
            WireEvent::CloseRequested { window_id } => {
                self.validate_window(window_id)?;
                Ok(Event::CloseRequested { window_id })
            }
            WireEvent::FocusChanged { window_id, focused } => {
                self.validate_window(window_id)?;
                Ok(Event::FocusChanged { window_id, focused })
            }
            WireEvent::ClipboardText { request_id, text } => {
                if text.len() > MAX_CLIPBOARD_BYTES {
                    return Err(ProtocolError::ClipboardTooLarge.into());
                }
                Ok(Event::ClipboardText { request_id, text })
            }
            WireEvent::RequestFailed { request_id, code } => {
                if self.pending_create == Some(request_id) {
                    self.pending_create = None;
                }
                self.fail_present_request(request_id);
                Ok(Event::RequestFailed { request_id, code })
            }
        }
    }

    /// Acquires an available slot from the newest generation.
    ///
    /// `Ok(None)` means every current slot is acquired or awaiting an explicit
    /// `BufferReleased` event. Retired generations are never acquired.
    pub fn acquire_frame(&mut self) -> Result<Option<Frame<'_, T>>, ProtocolError> {
        let generation = self.active_generation.ok_or(ProtocolError::NoWindow)?;
        let pool_index = self
            .pools
            .iter()
            .position(|pool| pool.configuration.generation == generation)
            .ok_or(ProtocolError::UnknownGeneration(generation))?;
        let Some(buffer_index) = self.pools[pool_index]
            .buffers
            .iter()
            .position(|state| *state == BufferState::Available)
        else {
            return Ok(None);
        };
        self.pools[pool_index].buffers[buffer_index] = BufferState::Acquired;
        let configuration = self.pools[pool_index].configuration;
        let buffer_id = BufferId::new(buffer_index as u8);
        Ok(Some(Frame {
            client: self,
            generation,
            buffer_id,
            configuration,
            finished: false,
        }))
    }

    fn apply_configuration(
        &mut self,
        configured: Configured,
        mut surface_handles: Vec<T::Surface>,
    ) -> Result<Event, ClientError<T::Error>> {
        self.validate_window(configured.window_id)?;
        configured
            .configuration
            .validate()
            .map_err(ProtocolError::InvalidConfiguration)?;

        if let Some(current) = self.active_generation {
            if configured.configuration.generation <= current {
                return Err(ProtocolError::StaleGeneration {
                    current,
                    received: configured.configuration.generation,
                }
                .into());
            }
        }

        let handle_index = usize::from(configured.surface_handle_index);
        if handle_index >= surface_handles.len() {
            return Err(ProtocolError::MissingSurfaceHandle {
                index: configured.surface_handle_index,
            }
            .into());
        }
        let surface = surface_handles.swap_remove(handle_index);
        let required = configured.configuration.required_surface_bytes().ok_or(
            ProtocolError::InvalidConfiguration(ConfigurationError::LayoutOverflow),
        )?;
        if surface.len() < required {
            return Err(
                ProtocolError::InvalidConfiguration(ConfigurationError::SurfaceTooShort).into(),
            );
        }

        // Available slots in an old generation no longer matter. Keep the pool
        // only if the server still owes releases for presented slots.
        self.pools.retain(BufferPool::has_presented_buffers);
        self.pools.push(BufferPool {
            configuration: configured.configuration,
            surface,
            buffers: vec![
                BufferState::Available;
                usize::from(configured.configuration.buffer_count)
            ],
        });
        self.active_generation = Some(configured.configuration.generation);

        Ok(Event::Configured {
            window_id: configured.window_id,
            configuration: configured.configuration,
        })
    }

    fn release_buffer(
        &mut self,
        generation: Generation,
        buffer_id: BufferId,
        present_request_id: RequestId,
    ) -> Result<(), ProtocolError> {
        let pool_index = self
            .pools
            .iter()
            .position(|pool| pool.configuration.generation == generation)
            .ok_or(ProtocolError::UnknownGeneration(generation))?;
        let state = self.pools[pool_index]
            .buffers
            .get_mut(usize::from(buffer_id.get()))
            .ok_or(ProtocolError::UnknownBuffer {
                generation,
                buffer_id,
            })?;
        match *state {
            BufferState::Presented(expected) if expected == present_request_id => {
                *state = BufferState::Available;
            }
            BufferState::Presented(expected) => {
                return Err(ProtocolError::PresentRequestMismatch {
                    expected,
                    received: present_request_id,
                });
            }
            BufferState::Available | BufferState::Acquired => {
                return Err(ProtocolError::BufferNotPresented {
                    generation,
                    buffer_id,
                });
            }
        }

        if self.active_generation != Some(generation)
            && !self.pools[pool_index].has_presented_buffers()
        {
            self.pools.remove(pool_index);
        }
        Ok(())
    }

    fn fail_present_request(&mut self, request_id: RequestId) {
        for pool in &mut self.pools {
            for state in &mut pool.buffers {
                if *state == BufferState::Presented(request_id) {
                    *state = BufferState::Available;
                }
            }
        }

        let active_generation = self.active_generation;
        self.pools.retain(|pool| {
            Some(pool.configuration.generation) == active_generation || pool.has_presented_buffers()
        });
    }

    fn validate_window(&self, received: WindowId) -> Result<(), ProtocolError> {
        let expected = self.window_id.ok_or(ProtocolError::NoWindow)?;
        if received != expected {
            return Err(ProtocolError::WrongWindow { expected, received });
        }
        Ok(())
    }

    fn send_window_request<F>(&mut self, build: F) -> Result<RequestId, ClientError<T::Error>>
    where
        F: FnOnce(RequestId, WindowId) -> WireRequest,
    {
        let window_id = self.window_id.ok_or(ProtocolError::NoWindow)?;
        let request_id = self.allocate_request_id()?;
        self.transport
            .send(&build(request_id, window_id))
            .map_err(ClientError::Transport)?;
        Ok(request_id)
    }

    fn allocate_request_id(&mut self) -> Result<RequestId, ProtocolError> {
        let request_id = self
            .next_request_id
            .ok_or(ProtocolError::RequestIdExhausted)?;
        self.next_request_id = request_id.get().checked_add(1).and_then(RequestId::new);
        Ok(request_id)
    }

    fn pool(&self, generation: Generation) -> Option<&BufferPool<T::Surface>> {
        self.pools
            .iter()
            .find(|pool| pool.configuration.generation == generation)
    }

    fn pool_mut(&mut self, generation: Generation) -> Option<&mut BufferPool<T::Surface>> {
        self.pools
            .iter_mut()
            .find(|pool| pool.configuration.generation == generation)
    }
}

/// Exclusive access to one acquired buffer slot.
///
/// Dropping an unpresented frame makes its slot available again. [`present`](Self::present)
/// consumes the frame so callers cannot mutate or submit it twice.
pub struct Frame<'a, T: Transport> {
    client: &'a mut WindowClient<T>,
    generation: Generation,
    buffer_id: BufferId,
    configuration: SurfaceConfiguration,
    finished: bool,
}

impl<T: Transport> Frame<'_, T> {
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn buffer_id(&self) -> BufferId {
        self.buffer_id
    }

    pub const fn configuration(&self) -> SurfaceConfiguration {
        self.configuration
    }

    /// Returns this slot's complete byte range, including row padding.
    pub fn bytes_mut(
        &mut self,
    ) -> Result<&mut [u8], SurfaceAccessError<<T::Surface as SharedSurface>::Error>> {
        let bytes_per_buffer = self
            .configuration
            .bytes_per_buffer()
            .ok_or(SurfaceAccessError::SurfaceTooShort)?;
        let start = usize::from(self.buffer_id.get())
            .checked_mul(bytes_per_buffer)
            .ok_or(SurfaceAccessError::SurfaceTooShort)?;
        let end = start
            .checked_add(bytes_per_buffer)
            .ok_or(SurfaceAccessError::SurfaceTooShort)?;
        let pool = self
            .client
            .pool_mut(self.generation)
            .ok_or(SurfaceAccessError::SurfaceTooShort)?;
        let surface = pool
            .surface
            .bytes_mut()
            .map_err(SurfaceAccessError::Surface)?;
        surface
            .get_mut(start..end)
            .ok_or(SurfaceAccessError::SurfaceTooShort)
    }

    /// Borrows this slot as a validated `ginkgo-graphics` draw target.
    ///
    /// The returned surface exclusively borrows the frame, so another mutable
    /// byte or draw-target borrow cannot overlap it.
    pub fn pixel_surface(
        &mut self,
    ) -> Result<PixelSurface<'_>, SurfaceAccessError<<T::Surface as SharedSurface>::Error>> {
        let layout = self
            .configuration
            .graphics_layout()
            .map_err(SurfaceAccessError::InvalidConfiguration)?;
        let bytes = self.bytes_mut()?;
        PixelSurface::new(bytes, layout).map_err(SurfaceAccessError::InvalidPixelSurface)
    }

    /// Submits this slot and keeps it unavailable until the matching release.
    pub fn present(mut self, damage: Vec<Rect>) -> Result<RequestId, ClientError<T::Error>> {
        let window_id = self.client.window_id.ok_or(ProtocolError::NoWindow)?;
        let request_id = self.client.allocate_request_id()?;
        let request = WireRequest::Present {
            request_id,
            window_id,
            generation: self.generation,
            buffer_id: self.buffer_id,
            damage,
        };
        self.client
            .transport
            .send(&request)
            .map_err(ClientError::Transport)?;

        let pool = self
            .client
            .pool_mut(self.generation)
            .ok_or(ProtocolError::UnknownGeneration(self.generation))?;
        let state = pool
            .buffers
            .get_mut(usize::from(self.buffer_id.get()))
            .ok_or(ProtocolError::UnknownBuffer {
                generation: self.generation,
                buffer_id: self.buffer_id,
            })?;
        *state = BufferState::Presented(request_id);
        self.finished = true;
        Ok(request_id)
    }
}

impl<T: Transport> Drop for Frame<'_, T> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(pool) = self.client.pool_mut(self.generation) {
            if let Some(state) = pool.buffers.get_mut(usize::from(self.buffer_id.get())) {
                if *state == BufferState::Acquired {
                    *state = BufferState::Available;
                }
            }
        }
    }
}
